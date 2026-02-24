#!/usr/bin/env python3
"""
MiniNet topology with ZeroTier L2 bridge.

INSTRUCTOR Linux setup needs Python, Openvswitch, Mininet.

BOTH INSTRUCTOR and TRAINEE need ZeroTier installed

Connect BOTH the INSTRUCTOR and the TRAINEE to the same ZeroTier network.

Accept/Authorize BOTH the INSTRUCTOR and the TRAINEE connections in ZeroTier Central

Enable "Allow Ethernet Bridging" on INSTRUCTOR connection in ZeroTier Central.

Usage:
    sudo python3 mininet_zerotier.py [--zt-iface <iface>] [--subnet <subnet>] [--hosts <n>]

Defaults:
    --zt-iface  : auto-detected (first zt* interface found)
    --subnet    : 192.168.100.0/24  (must match your ZeroTier network range)
    --hosts     : 3
"""

import argparse
import os
import sys
import subprocess

from mininet.net import Mininet
from mininet.node import Controller, OVSBridge
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.log import setLogLevel, info, error


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def find_zerotier_iface():
    """Return the first zt* interface found, or None."""
    result = subprocess.run(['ip', 'link', 'show'], capture_output=True, text=True)
    for line in result.stdout.splitlines():
        if ': zt' in line:
            # Line looks like: "4: ztxxxxxxxx: <...>"
            iface = line.split(': ')[1].split(':')[0].strip()
            return iface
    return None


def run(cmd, check=True):
    info(f'*** Running: {cmd}\n')
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    if check and result.returncode != 0:
        error(f'Command failed: {cmd}\n{result.stderr}\n')
    return result


def get_base_ip(subnet):
    """Return base IP from a CIDR subnet string, e.g. '192.168.100.0/24' -> '192.168.100'."""
    return '.'.join(subnet.split('/')[0].split('.')[:3])


# ---------------------------------------------------------------------------
# Topology
# ---------------------------------------------------------------------------

def build_topo(zt_iface, subnet, num_hosts):
    base_ip = get_base_ip(subnet)
    prefix = subnet.split('/')[1]

    net = Mininet(controller=Controller, link=TCLink, switch=OVSBridge)

    info('*** Adding controller\n')
    c0 = net.addController('c0')

    info('*** Adding OVS switch\n')
    s1 = net.addSwitch('s1', cls=OVSBridge, failMode='standalone')

    info(f'*** Adding {num_hosts} hosts\n')
    hosts = []
    for i in range(1, num_hosts + 1):
        ip = f'{base_ip}.{10 + i}/{prefix}'
        h = net.addHost(f'h{i}', ip=ip, mac=f'00:00:00:00:00:{i:02x}')
        hosts.append(h)
        net.addLink(h, s1)

    info('*** Starting network\n')
    net.build()
    c0.start()
    s1.start([c0])

    # Patch the ZeroTier interface into OVS so MiniNet hosts appear on the
    # ZeroTier L2 network.
    info(f'*** Bridging OVS switch s1 <-> ZeroTier interface {zt_iface}\n')
    run(f'ovs-vsctl add-port s1 {zt_iface}')

    # Enable promiscuous mode so the ZeroTier interface accepts frames from
    # MiniNet's virtual MACs, not just its own MAC address.
    run(f'ip link set {zt_iface} promisc on')
    run(f'ip link set {zt_iface} up')

    # Bring ZeroTier iface up inside OVS (it should already be, but just in case)
    run(f'ip link set {zt_iface} up')

    info('\n*** Hosts and their IPs:\n')
    for h in hosts:
        info(f'    {h.name}: {h.IP()}\n')

    info('\n*** Bridge status:\n')
    run('ovs-vsctl show', check=False)

    info('\n*** Starting CLI — type "exit" or Ctrl-D to stop\n')
    CLI(net)

    info('*** Stopping network\n')
    # Remove ZeroTier port before teardown to avoid OVS complaints
    run(f'ovs-vsctl del-port s1 {zt_iface}', check=False)
    # Restore normal (non-promiscuous) mode on exit.
    run(f'ip link set {zt_iface} promisc off', check=False)
    net.stop()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    if os.geteuid() != 0:
        print('This script must be run as root (sudo).', file=sys.stderr)
        sys.exit(1)

    parser = argparse.ArgumentParser(description='MiniNet + ZeroTier L2 bridge')
    parser.add_argument('--zt-iface', default=None,
                        help='ZeroTier interface name (e.g. ztxxxxxxxx). Auto-detected if omitted.')
    parser.add_argument('--subnet', default='192.168.100.0/24',
                        help='Subnet for MiniNet hosts. Must match your ZeroTier network range.')
    parser.add_argument('--hosts', type=int, default=3,
                        help='Number of MiniNet hosts to create (default: 3).')
    args = parser.parse_args()

    setLogLevel('info')

    # Resolve ZeroTier interface
    zt_iface = args.zt_iface or find_zerotier_iface()
    if not zt_iface:
        error('Could not find a ZeroTier interface (zt*). '
              'Is zerotier-one running and joined to a network?\n')
        sys.exit(1)

    info(f'*** Using ZeroTier interface: {zt_iface}\n')
    info(f'*** Subnet: {args.subnet}\n')
    info(f'*** Hosts: {args.hosts}\n\n')

    build_topo(zt_iface, args.subnet, args.hosts)


if __name__ == '__main__':
    main()