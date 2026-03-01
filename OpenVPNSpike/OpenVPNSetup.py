#!/usr/bin/env python3
"""
MiniNet topology with OpenVPN L2 bridge (tap mode).

INSTRUCTOR Linux setup needs:
    Python 3, openvswitch-switch, mininet, openvpn, easy-rsa

INSTRUCTOR setup steps (one-time):
    1. Run this script with --setup to generate the CA, server certs and server config.
    2. Run with --gen-client <name> to generate a .ovpn file for each trainee.
    3. Run normally (no flags) to start the OpenVPN server + MiniNet topology.

TRAINEE setup:
    1. Receive their .ovpn file from the instructor.
    2. Connect:  sudo openvpn --config <name>.ovpn
    3. Scan the VPN subnet with nmap.

Usage:
    sudo python3 OpenVPNSetup.py --setup
    sudo python3 OpenVPNSetup.py --gen-client <trainee-name>
    sudo python3 OpenVPNSetup.py [--subnet <subnet>] [--hosts <n>] [--port <port>]

Defaults:
    --subnet : 192.168.100.0/24  (VPN + MiniNet subnet)
    --hosts  : 3
    --port   : 1194
"""

import argparse
import os
import sys
import subprocess
import time
import ipaddress

from mininet.net import Mininet
from mininet.node import Controller, OVSBridge
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

BASE_DIR       = '/etc/openvpn/rodeo'
EASY_RSA_DIR   = f'{BASE_DIR}/easy-rsa'
PKI_DIR        = f'{EASY_RSA_DIR}/pki'
SERVER_CONF    = f'{BASE_DIR}/server.conf'
CLIENT_DIR     = f'{BASE_DIR}/clients'
LOG_FILE       = '/var/log/openvpn-rodeo.log'
STATUS_FILE    = '/var/run/openvpn-rodeo-status.log'
TAP_IFACE      = 'tap0'           # OpenVPN TAP interface (L2, same as ZeroTier zt* iface)
OPENVPN_PID    = '/var/run/openvpn-rodeo.pid'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def run(cmd, check=True, capture=False):
    info(f'*** Running: {cmd}\n')
    result = subprocess.run(
        cmd, shell=True,
        capture_output=capture,
        text=True
    )
    if check and result.returncode != 0:
        stderr = result.stderr if capture else ''
        error(f'Command failed: {cmd}\n{stderr}\n')
        sys.exit(1)
    return result


def get_base_ip(subnet):
    """'192.168.100.0/24' -> '192.168.100'"""
    return '.'.join(subnet.split('/')[0].split('.')[:3])


def get_server_ip(subnet):
    """Return .1 address for the OpenVPN server inside the subnet."""
    net = ipaddress.IPv4Network(subnet, strict=False)
    return str(list(net.hosts())[0])          # first usable host = .1


def get_netmask(subnet):
    return str(ipaddress.IPv4Network(subnet, strict=False).netmask)


# ---------------------------------------------------------------------------
# One-time PKI / server setup
# ---------------------------------------------------------------------------

def setup_pki(server_ip_or_hostname):
    """
    Generate CA, server certificate and server config.
    Safe to re-run — skips steps that are already done.
    """
    info('*** Setting up PKI with easy-rsa\n')

    os.makedirs(BASE_DIR, exist_ok=True)
    os.makedirs(CLIENT_DIR, exist_ok=True)

    # Install easy-rsa into our working dir if not already there
    if not os.path.isdir(EASY_RSA_DIR):
        run(f'make-cadir {EASY_RSA_DIR}')

    vars_file = f'{EASY_RSA_DIR}/vars'
    if not os.path.exists(vars_file):
        with open(vars_file, 'w') as f:
            f.write('set_var EASYRSA_ALGO ec\n')
            f.write('set_var EASYRSA_DIGEST sha512\n')
            f.write('set_var EASYRSA_CERT_EXPIRE 3650\n')

    easyrsa = f'{EASY_RSA_DIR}/easyrsa'

    # Initialise PKI
    if not os.path.isdir(PKI_DIR):
        run(f'cd {EASY_RSA_DIR} && {easyrsa} init-pki')

    # Build CA (no password, non-interactive)
    if not os.path.exists(f'{PKI_DIR}/ca.crt'):
        run(f'cd {EASY_RSA_DIR} && {easyrsa} --batch build-ca nopass')

    # Generate server key+cert
    if not os.path.exists(f'{PKI_DIR}/issued/server.crt'):
        run(f'cd {EASY_RSA_DIR} && {easyrsa} --batch build-server-full server nopass')

    # Generate TLS auth key (replay-attack protection)
    tls_key = f'{BASE_DIR}/ta.key'
    if not os.path.exists(tls_key):
        run(f'openvpn --genkey secret {tls_key}')

    info('*** PKI ready\n')
    write_server_conf(server_ip_or_hostname)
    info(f'\n*** Setup complete.\n'
         f'    Server config : {SERVER_CONF}\n'
         f'    Generate trainee files with: sudo python3 {sys.argv[0]} --gen-client <name>\n')


def write_server_conf(server_ip_or_hostname, subnet='192.168.100.0/24', port=1194):
    """Write the OpenVPN server config file."""
    netmask  = get_netmask(subnet)
    base_ip  = get_base_ip(subnet)
    # Server gets .1, clients get .10+
    server_pool_start = f'{base_ip}.150'
    server_pool_end   = f'{base_ip}.259'

    conf = f"""# Project Rodeo — OpenVPN server config (TAP / L2 bridge mode)
                port {port}
                proto udp
                dev {TAP_IFACE}
                dev-type tap

                ca      {PKI_DIR}/ca.crt
                cert    {PKI_DIR}/issued/server.crt
                key     {PKI_DIR}/private/server.key
                tls-auth {BASE_DIR}/ta.key 0

                server-bridge {get_server_ip(subnet)} {netmask} {server_pool_start} {server_pool_end}

                # Keep TAP interface up between client connections
                persist-tun
                persist-key

                # Logging
                status  {STATUS_FILE} 10
                log     {LOG_FILE}
                verb    3

                # Hardening
                tls-version-min 1.2
                cipher AES-256-GCM
                auth SHA256

                # Keepalive: ping every 10s, restart after 120s silence
                keepalive 10 120

                # Write PID so we can stop the server cleanly
                writepid {OPENVPN_PID}
            """
    with open(SERVER_CONF, 'w') as f:
        f.write(conf)
    info(f'*** Server config written to {SERVER_CONF}\n')


# ---------------------------------------------------------------------------
# Per-trainee .ovpn generation
# ---------------------------------------------------------------------------

def gen_client(name, server_ip_or_hostname, port=1194):
    """Generate a client certificate and bundle a .ovpn file."""
    easyrsa = f'{EASY_RSA_DIR}/easyrsa'

    if not os.path.isdir(PKI_DIR):
        error('PKI not initialised. Run with --setup first.\n')
        sys.exit(1)

    cert_path = f'{PKI_DIR}/issued/{name}.crt'
    if not os.path.exists(cert_path):
        run(f'cd {EASY_RSA_DIR} && {easyrsa} --batch build-client-full {name} nopass')
    else:
        info(f'*** Certificate for {name} already exists, reusing.\n')

    # Read the individual files
    def read(path):
        with open(path) as f:
            return f.read().strip()

    ca      = read(f'{PKI_DIR}/ca.crt')
    cert    = read(cert_path)
    key     = read(f'{PKI_DIR}/private/{name}.key')
    tls_key = read(f'{BASE_DIR}/ta.key')

    ovpn = f"""# Project Rodeo — Trainee config for: {name}
                client
                dev tap
                dev-type tap
                proto udp
                remote {server_ip_or_hostname} {port}

                resolv-retry infinite
                nobind
                persist-key
                persist-tun

                cipher AES-256-GCM
                auth SHA256
                tls-version-min 1.2
                key-direction 1

                verb 3

                <ca>
                {ca}
                </ca>

                <cert>
                {cert}
                </cert>

                <key>
                {key}
                </key>

                <tls-auth>
                {tls_key}
                </tls-auth>
            """
    out_path = f'{CLIENT_DIR}/{name}.ovpn'
    with open(out_path, 'w') as f:
        f.write(ovpn)

    info(f'*** .ovpn file written to {out_path}\n')
    info(f'    Distribute this file to trainee "{name}".\n')


# ---------------------------------------------------------------------------
# Start / stop OpenVPN server
# ---------------------------------------------------------------------------

def start_openvpn():
    """Start the OpenVPN server as a background daemon."""
    if not os.path.exists(SERVER_CONF):
        error(f'Server config not found at {SERVER_CONF}. Run --setup first.\n')
        sys.exit(1)

    info('*** Starting OpenVPN server\n')
    run(f'openvpn --config {SERVER_CONF} --daemon')

    # Wait for the TAP interface to appear (up to 10 s)
    for _ in range(20):
        result = subprocess.run(['ip', 'link', 'show', TAP_IFACE],
                                capture_output=True, text=True)
        if result.returncode == 0:
            info(f'*** TAP interface {TAP_IFACE} is up\n')
            return
        time.sleep(0.5)

    error(f'TAP interface {TAP_IFACE} did not appear. Check {LOG_FILE}.\n')
    sys.exit(1)


def stop_openvpn():
    """Stop the OpenVPN daemon gracefully."""
    if os.path.exists(OPENVPN_PID):
        run(f'kill $(cat {OPENVPN_PID})', check=False)
        run(f'rm -f {OPENVPN_PID}', check=False)
    else:
        run('pkill -f "openvpn --config"', check=False)
    info('*** OpenVPN server stopped\n')


# ---------------------------------------------------------------------------
# MiniNet topology  (same logic as ZeroTierSetup.py, TAP iface replaces zt*)
# ---------------------------------------------------------------------------

def build_topo(subnet, num_hosts):
    base_ip = get_base_ip(subnet)
    prefix  = subnet.split('/')[1]

    net = Mininet(controller=Controller, link=TCLink, switch=OVSBridge)

    info('*** Adding controller\n')
    c0 = net.addController('c0')

    info('*** Adding OVS switch\n')
    s1 = net.addSwitch('s1', cls=OVSBridge, failMode='standalone')

    info(f'*** Adding {num_hosts} hosts\n')
    hosts = []
    for i in range(1, num_hosts + 1):
        ip  = f'{base_ip}.{2 + i}/{prefix}'
        mac = f'00:00:00:00:00:{i:02x}'
        h   = net.addHost(f'h{i}', ip=ip, mac=mac)
        hosts.append(h)
        net.addLink(h, s1)

    info('*** Starting MiniNet\n')
    net.build()
    c0.start()
    s1.start([c0])

    # Bridge the OpenVPN TAP interface into OVS —
    # this is the L2 bridge that makes MiniNet hosts visible on the VPN.
    info(f'*** Bridging OVS switch s1 <-> OpenVPN TAP interface {TAP_IFACE}\n')
    run(f'ovs-vsctl add-port s1 {TAP_IFACE}')
    run(f'ip link set {TAP_IFACE} promisc on')
    run(f'ip link set {TAP_IFACE} up')

    info('\n*** Hosts and their IPs:\n')
    for h in hosts:
        info(f'    {h.name}: {h.IP()}\n')

    info('\n*** Bridge status:\n')
    run('ovs-vsctl show', check=False)

    info('\n*** Starting CLI — type "exit" or Ctrl-D to stop\n')
    CLI(net)

    info('*** Stopping MiniNet\n')
    run(f'ovs-vsctl del-port s1 {TAP_IFACE}', check=False)
    run(f'ip link set {TAP_IFACE} promisc off', check=False)
    net.stop()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if os.geteuid() != 0:
        print('This script must be run as root (sudo).', file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description='MiniNet + OpenVPN L2 bridge — Project Rodeo')
    parser.add_argument('--setup', action='store_true',
                        help='One-time PKI and server config generation.')
    parser.add_argument('--gen-client', metavar='NAME',
                        help='Generate a .ovpn file for a trainee.')
    parser.add_argument('--server-ip', default='YOUR_SERVER_IP',
                        help='Public IP or hostname of the instructor machine.')
    parser.add_argument('--subnet', default='192.168.100.0/24',
                        help='VPN + MiniNet subnet (default: 192.168.100.0/24).')
    parser.add_argument('--hosts', type=int, default=3,
                        help='Number of MiniNet hosts (default: 3).')
    parser.add_argument('--port', type=int, default=1194,
                        help='OpenVPN UDP port (default: 1194).')
    args = parser.parse_args()

    setLogLevel('info')

    if args.setup:
        setup_pki(args.server_ip)
        return

    if args.gen_client:
        gen_client(args.gen_client, args.server_ip, args.port)
        return

    # Normal run: start OpenVPN server, then MiniNet
    try:
        start_openvpn()
        build_topo(args.subnet, args.hosts)
    finally:
        stop_openvpn()


if __name__ == '__main__':
    main()
