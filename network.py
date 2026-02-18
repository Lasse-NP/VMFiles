#!/usr/bin/env python3
"""
Universal Mininet Virtual Network with OS Fingerprint Spoofing
and Automatic Bridging to Host Network over OVS.

Features:
 - Auto-detects VM network interface, IP, prefix, gateway
 - Graceful fallback to user input when detection fails
 - Safely moves L3 from NIC to OVS bridge (no route deletion)
 - Creates internal OVS gateway (10.0.0.254/24)
 - Automatically assigns default routes to Mininet hosts
 - Enables necessary forwarding sysctls
 - Saves + restores iptables state
 - Fully restores all VM network state on exit

Usage:
   sudo python3 network.py [--topo star|linear|tree] [--verbose]
"""

import argparse
import sys
import os
import time
import subprocess
import threading
import re
import shlex
import tempfile
import shutil

from mininet.net import Mininet
from mininet.node import OVSSwitch
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.topo import Topo


# ==============================================================================
# OS FINGERPRINT PROFILES
# ==============================================================================

OS_PROFILES = {
    "windows_server_2019": {
        "ttl": 128,
        "tcp_window": 65535,
        "os_label": "Windows Server 2019",
        "services": [
            (80, "http", "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"),
            (135, "raw", ""),
            (139, "raw", ""),
            (445, "raw", ""),
            (3389, "raw", ""),
        ],
    },
    "ubuntu_22": {
        "ttl": 64,
        "tcp_window": 29200,
        "os_label": "Ubuntu 22.04 LTS",
        "services": [
            (22, "ssh", "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
            (80, "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52\r\nContent-Length: 0\r\n\r\n"),
            (3306, "raw", ""),
        ],
    },
    "centos_7": {
        "ttl": 64,
        "tcp_window": 14600,
        "os_label": "CentOS 7",
        "services": [
            (22, "ssh", "SSH-2.0-OpenSSH_7.4\r\n"),
            (80, "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6\r\nContent-Length: 0\r\n\r\n"),
            (443, "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "cisco_ios": {
        "ttl": 255,
        "tcp_window": 4128,
        "os_label": "Cisco IOS 15.x",
        "services": [
            (23, "raw", "\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f"),
            (80, "http", "HTTP/1.1 200 OK\r\nServer: cisco-IOS\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "freebsd_13": {
        "ttl": 64,
        "tcp_window": 65535,
        "os_label": "FreeBSD 13",
        "services": [
            (22, "ssh", "SSH-2.0-OpenSSH_9.0 FreeBSD\r\n"),
            (80, "http", "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "android_device": {
        "ttl": 64,
        "tcp_window": 65700,
        "os_label": "Android 12",
        "services": [
            (5555, "raw", "CNXN\x00\x00\x00\x01"),
            (8080, "http", "HTTP/1.1 200 OK\r\nServer: BaseHTTP/0.6 Python\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "macos_ventura": {
        "ttl": 64,
        "tcp_window": 65535,
        "os_label": "macOS Ventura 13",
        "services": [
            (22, "ssh", "SSH-2.0-OpenSSH_9.0\r\n"),
            (548, "raw", ""),
            (5900, "raw", "RFB 003.889\n"),
        ],
    },
    "windows_10": {
        "ttl": 128,
        "tcp_window": 64240,
        "os_label": "Windows 10",
        "services": [
            (80, "http", "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"),
            (135, "raw", ""),
            (445, "raw", ""),
        ],
    },
}


# ==============================================================================
# TOPOLOGIES
# ==============================================================================

class StarTopo(Topo):
    def build(self, n_hosts=8):
        s = self.addSwitch("s1")
        for i in range(1, n_hosts + 1):
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, s)

class LinearTopo(Topo):
    def build(self, n_hosts=8):
        switches = []
        for i in range(1, n_hosts + 1):
            s = self.addSwitch(f"s{i}")
            switches.append(s)
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, s)
        for i in range(len(switches) - 1):
            self.addLink(switches[i], switches[i + 1])

class TreeTopo(Topo):
    def build(self, n_hosts=8):
        core = self.addSwitch("s0")
        s1 = self.addSwitch("s1")
        s2 = self.addSwitch("s2")
        self.addLink(core, s1)
        self.addLink(core, s2)
        half = n_hosts // 2
        for i in range(1, half + 1):
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, s1)
        for i in range(half + 1, n_hosts + 1):
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, s2)


# ==============================================================================
# HELPER FUNCTIONS
# ==============================================================================

def run(cmd):
    return subprocess.run(shlex.split(cmd), capture_output=True, text=True).stdout.strip()

def safe_run(cmd):
    subprocess.run(shlex.split(cmd), capture_output=True, text=True)

def detect_primary_iface():
    """Try several methods; fallback to user input."""
    # First try route-get
    out = run("ip route get 1.1.1.1")
    m = re.search(r"dev (\S+)", out)
    if m:
        return m.group(1)

    # Fallback to first non-virtual NIC
    out = run("ip -o link show")
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 2:
            continue
        iface = parts[1].strip()
        if iface.startswith(("lo", "virbr", "docker", "veth", "br-", "ovs")):
            continue
        return iface

    # Last fallback: ask user
    print("\nCould not auto-detect primary interface.")
    iface = input("Enter your primary NIC name (e.g., enp0s3): ").strip()
    return iface

def detect_ip_and_prefix(iface):
    out = run(f"ip -4 addr show dev {iface}")
    m = re.search(r"inet (\d+\.\d+\.\d+\.\d+)/(\d+)", out)
    if m:
        return m.group(1), int(m.group(2))
    print(f"\nFailed to detect IP for {iface}.")
    ip = input("Enter IPv4 address (e.g., 192.168.0.130): ").strip()
    pre = int(input("Enter prefix length (e.g., 24): "))
    return ip, pre

def detect_gateway_for_iface(iface):
    out = run("ip route show default")
    for line in out.splitlines():
        if f" dev {iface} " in line:
            parts = line.split()
            if "via" in parts:
                return parts[parts.index("via") + 1]
    print("\nCould not auto-detect default gateway.")
    return input("Enter default gateway (e.g., 192.168.0.1): ").strip()

def save_iptables():
    tmp = tempfile.mkstemp(prefix="iptables_", suffix=".save")[1]
    rules = run("iptables-save")
    with open(tmp, "w") as f:
        f.write(rules)
    return tmp

def restore_iptables(path):
    if os.path.exists(path):
        safe_run(f"iptables-restore {path}")


# ==============================================================================
# SERVICE LISTENER CREATOR
# ==============================================================================

LISTENER_SCRIPT = """\
#!/usr/bin/env python3
import socket, threading, sys, signal

banner = {banner!r}
port = {port}

def handle(c):
    try:
        if banner:
            c.sendall(banner.encode() if isinstance(banner, str) else banner)
        c.recv(1024)
    except:
        pass
    finally:
        c.close()

s = socket.socket()
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("0.0.0.0", port))
s.listen(20)

def stop(sig, frame):
    s.close()
    sys.exit(0)

signal.signal(signal.SIGTERM, stop)
signal.signal(signal.SIGINT, stop)

while True:
    try:
        c, _ = s.accept()
        threading.Thread(target=handle, args=(c,), daemon=True).start()
    except:
        break
"""

def start_services(host, profile, tmp_dir):
    pids = []
    for port, proto, banner in profile["services"]:
        script = LISTENER_SCRIPT.format(port=port, banner=banner)
        path = os.path.join(tmp_dir, f"{host.name}_{port}.py")
        with open(path, "w") as f:
            f.write(script)
        pid = host.cmd(f"python3 {path} &>/tmp/{host.name}_{port}.log & echo $!").strip()
        if pid.isdigit():
            pids.append(int(pid))
        info(f" → {host.name}:{port}/{proto} (pid {pid})\n")
    return pids


# ==============================================================================
# MAIN NETWORK BUILD
# ==============================================================================

def build_network(topo_name="star", verbose=False):
    if os.geteuid() != 0:
        error("This script must be run with sudo.\n")
        sys.exit(1)

    setLogLevel("info" if verbose else "warning")

    profiles = list(OS_PROFILES.items())
    n_hosts = len(profiles)

    info(f"\n[+] Building topology '{topo_name}' with {n_hosts} hosts\n")

    topo = {"star": StarTopo, "linear": LinearTopo, "tree": TreeTopo}[topo_name](n_hosts=n_hosts)
    net = Mininet(topo=topo, switch=OVSSwitch, controller=None, autoSetMacs=True)
    net.start()

    tmp_dir = tempfile.mkdtemp(prefix="mininet_services_")
    ipt_backup = save_iptables()

    # ----------------------------------------------------------------------
    # DETECT PRIMARY NIC, IP, PREFIX, GATEWAY
    # ----------------------------------------------------------------------
    VM_IFACE = detect_primary_iface()
    orig_ip, orig_pre = detect_ip_and_prefix(VM_IFACE)
    orig_gw = detect_gateway_for_iface(VM_IFACE)

    info(f"[+] Primary NIC: {VM_IFACE}  ({orig_ip}/{orig_pre})  gw={orig_gw}\n")

    # ----------------------------------------------------------------------
    # PREPARE SWITCH
    # ----------------------------------------------------------------------
    primary_switch = net.switches[0].name
    info(f"[+] Using primary switch: {primary_switch}\n")

    # Make switch a pure L2 device
    safe_run(f"ovs-vsctl del-controller {primary_switch}")
    safe_run(f"ovs-vsctl set-fail-mode {primary_switch} standalone")
    safe_run(f"ovs-ofctl del-flows {primary_switch}")
    safe_run(f"ovs-ofctl add-flow {primary_switch} priority=0,actions=NORMAL")

    # ----------------------------------------------------------------------
    # MOVE L3 FROM NIC → SWITCH
    # ----------------------------------------------------------------------
    info(f"[+] Bridging {VM_IFACE} into {primary_switch}\n")
    safe_run(f"ovs-vsctl add-port {primary_switch} {VM_IFACE}")

    # Remove IP from NIC
    safe_run(f"ip addr flush dev {VM_IFACE}")

    # Assign original LAN IP to the switch itself
    safe_run(f"ip addr add {orig_ip}/{orig_pre} dev {primary_switch}")
    safe_run(f"ip link set {primary_switch} up")

    # Replace default route atomically
    safe_run(f"ip route replace default via {orig_gw} dev {primary_switch}")

    # ----------------------------------------------------------------------
    # CREATE INTERNAL MININET GATEWAY
    # ----------------------------------------------------------------------
    gw_port = f"{primary_switch}-gw"
    info(f"[+] Creating internal gateway {gw_port} = 10.0.0.254/24\n")
    safe_run(f"ovs-vsctl add-port {primary_switch} {gw_port} -- set Interface {gw_port} type=internal")
    safe_run(f"ip link set {gw_port} up")
    safe_run(f"ip addr add 10.0.0.254/24 dev {gw_port}")

    # Kernel forwarding knobs
    safe_run("sysctl -w net.ipv4.ip_forward=1")
    safe_run("sysctl -w net.ipv4.conf.all.rp_filter=0")
    safe_run(f"sysctl -w net.ipv4.conf.{VM_IFACE}.rp_filter=0")
    safe_run(f"sysctl -w net.ipv4.conf.{primary_switch}.rp_filter=0")
    safe_run("sysctl -w net.bridge.bridge-nf-call-iptables=0 2>/dev/null || true")
    safe_run("sysctl -w net.bridge.bridge-nf-call-arptables=0 2>/dev/null || true")

    # Open FORWARD chain
    safe_run("iptables -P FORWARD ACCEPT")
    safe_run("iptables -F FORWARD")

    # ----------------------------------------------------------------------
    # CONFIGURE HOSTS
    # ----------------------------------------------------------------------
    host_map = {}

    for i, (pname, profile) in enumerate(profiles, start=1):
        h = net.get(f"h{i}")
        ip = h.IP()
        info(f"\n[+] Host {h.name} ({ip}) → {profile['os_label']}\n")

        # Apply OS fingerprint tweaks
        h.cmd(f"sysctl -w net.ipv4.ip_default_ttl={profile['ttl']}")
        h.cmd(f"sysctl -w net.ipv4.tcp_rmem='4096 {profile['tcp_window']} {profile['tcp_window'] * 4}'")
        h.cmd(f"sysctl -w net.core.rmem_default={profile['tcp_window']}")
        h.cmd(f"sysctl -w net.core.rmem_max={profile['tcp_window'] * 4}")
        h.cmd(f"sysctl -w net.ipv4.icmp_echo_ignore_all=0")

        # Assign default route to gateway
        h.cmd("ip route add default via 10.0.0.254")

        # Start services
        pids = start_services(h, profile, tmp_dir)

        host_map[h.name] = {
            "ip": ip,
            "profile": pname,
            "label": profile["os_label"],
            "ports": [s[0] for s in profile["services"]],
            "pids": pids,
        }

    # ----------------------------------------------------------------------
    # CONNECTIVITY CHECK
    # ----------------------------------------------------------------------
    info("\n[+] Checking Mininet internal routing\n")
    for hname in host_map:
        h = net.get(hname)
        out = h.cmd("ping -c1 -W1 10.0.0.254")
        if "1 received" in out:
            info(f" ✓ {hname} → 10.0.0.254 OK\n")
        else:
            info(f" ✗ {hname} → 10.0.0.254 FAILED\n")

    # ----------------------------------------------------------------------
    # PRINT HELP FOR WINDOWS
    # ----------------------------------------------------------------------
    print("\n============================================================")
    print(" Mininet Hosts:")
    print("============================================================")
    for hname, d in host_map.items():
        print(f"{hname:<6} {d['ip']:<15} {d['label']:<25} ports={d['ports']}")
    print("============================================================")

    print(f"""
From your Windows machine, enable ICMP echo and run:

    route -p add 10.0.0.0 mask 255.255.255.0 {orig_ip}

Then scan:

    nmap -sn 10.0.0.0/24
    nmap -O -sV -T4 10.0.0.0/24
""")

    print("Entering Mininet CLI. Type exit or Ctrl-D to quit.\n")
    CLI(net)

    # ----------------------------------------------------------------------
    # CLEANUP
    # ----------------------------------------------------------------------
    info("\n[+] Cleaning up...\n")
    for hname, d in host_map.items():
        h = net.get(hname)
        for pid in d["pids"]:
            h.cmd(f"kill {pid} 2>/dev/null")

    # Remove gateway port
    safe_run(f"ovs-vsctl del-port {primary_switch} {gw_port}")

    # Remove physical NIC from switch
    safe_run(f"ovs-vsctl del-port {primary_switch} {VM_IFACE}")

    # Restore NIC addressing
    safe_run(f"ip addr flush dev {VM_IFACE}")
    safe_run(f"ip addr add {orig_ip}/{orig_pre} dev {VM_IFACE}")
    safe_run(f"ip link set {VM_IFACE} up")
    safe_run(f"ip route replace default via {orig_gw} dev {VM_IFACE}")

    # Restore iptables
    restore_iptables(ipt_backup)
    try:
        os.remove(ipt_backup)
    except:
        pass

    net.stop()
    safe_run("mn --clean")

    shutil.rmtree(tmp_dir, ignore_errors=True)
    print("[+] Cleanup complete. Goodbye.")


# ==============================================================================
# ENTRY POINT
# ==============================================================================

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Universal Mininet virtual network with OS fingerprint spoofing")
    parser.add_argument("--topo", choices=["star", "linear", "tree"], default="star")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args()

    build_network(topo_name=args.topo, verbose=args.verbose)