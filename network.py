#!/usr/bin/env python3
"""
Mininet Virtual Network with OS Fingerprint Spoofing
Builds a virtual network of hosts with different OS fingerprints, scannable by Nmap.

Requirements:
    sudo apt install mininet nmap python3-pip
    sudo pip3 install mininet

Usage:
    sudo python3 Network.py [--topo star|linear|tree] [--verbose]
"""

import argparse
import sys
import os
import time
import subprocess
import threading
from mininet.net import Mininet
from mininet.node import OVSSwitch, Controller
from mininet.link import Link
from mininet.log import setLogLevel, info, error
from mininet.cli import CLI
from mininet.topo import Topo

# ── OS Fingerprint profiles ────────────────────────────────────────────────────
# Each profile defines:
#   ttl        : IP TTL value (Linux≈64, Windows≈128, Cisco≈255, BSD≈64)
#   tcp_window : TCP window size
#   os_label   : human-readable label
#   services   : list of (port, protocol) tuples to open
#   banner     : optional banner string for banner-grab fingerprinting

OS_PROFILES = {
    "windows_server_2019": {
        "ttl": 128,
        "tcp_window": 65535,
        "os_label": "Windows Server 2019",
        "services": [
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"),
            (135,  "raw",   ""),          # RPC endpoint mapper
            (139,  "raw",   ""),          # NetBIOS
            (445,  "raw",   ""),          # SMB
            (3389, "raw",   ""),          # RDP
        ],
    },
    "ubuntu_22": {
        "ttl": 64,
        "tcp_window": 29200,
        "os_label": "Ubuntu 22.04 LTS",
        "services": [
            (22,   "ssh",   "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"),
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.52 (Ubuntu)\r\nContent-Length: 0\r\n\r\n"),
            (3306, "raw",   ""),          # MySQL
        ],
    },
    "centos_7": {
        "ttl": 64,
        "tcp_window": 14600,
        "os_label": "CentOS 7",
        "services": [
            (22,   "ssh",   "SSH-2.0-OpenSSH_7.4\r\n"),
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6 (CentOS)\r\nContent-Length: 0\r\n\r\n"),
            (443,  "http",  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.6 (CentOS)\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "cisco_ios": {
        "ttl": 255,
        "tcp_window": 4128,
        "os_label": "Cisco IOS 15.x",
        "services": [
            (23,   "raw",   "\xff\xfb\x01\xff\xfb\x03\xff\xfd\x18\xff\xfd\x1f"),  # Telnet IAC
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: cisco-IOS\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "freebsd_13": {
        "ttl": 64,
        "tcp_window": 65535,
        "os_label": "FreeBSD 13",
        "services": [
            (22,   "ssh",   "SSH-2.0-OpenSSH_9.0 FreeBSD-20221006\r\n"),
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: Apache/2.4.54 (FreeBSD)\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "android_device": {
        "ttl": 64,
        "tcp_window": 65700,
        "os_label": "Android 12",
        "services": [
            (5555, "raw",   "CNXN\x00\x00\x00\x01"),  # ADB banner
            (8080, "http",  "HTTP/1.1 200 OK\r\nServer: BaseHTTP/0.6 Python/3.10\r\nContent-Length: 0\r\n\r\n"),
        ],
    },
    "macos_ventura": {
        "ttl": 64,
        "tcp_window": 65535,
        "os_label": "macOS Ventura 13",
        "services": [
            (22,   "ssh",   "SSH-2.0-OpenSSH_9.0\r\n"),
            (548,  "raw",   ""),          # AFP
            (5900, "raw",   "RFB 003.889\n"),  # VNC
        ],
    },
    "windows_10": {
        "ttl": 128,
        "tcp_window": 64240,
        "os_label": "Windows 10",
        "services": [
            (80,   "http",  "HTTP/1.1 200 OK\r\nServer: Microsoft-IIS/10.0\r\nContent-Length: 0\r\n\r\n"),
            (135,  "raw",   ""),
            (445,  "raw",   ""),
        ],
    },
}


# ── Topology definitions ───────────────────────────────────────────────────────

class StarTopo(Topo):
    """All hosts connected to a single switch."""
    def build(self, n_hosts=8):
        switch = self.addSwitch("s1")
        for i in range(1, n_hosts + 1):
            host = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(host, switch)


class LinearTopo(Topo):
    """Hosts connected in a chain: h1-s1-s2-h2 ..."""
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
    """Two-tier tree: core switch → edge switches → hosts."""
    def build(self, n_hosts=8):
        core = self.addSwitch("s0")
        edge1 = self.addSwitch("s1")
        edge2 = self.addSwitch("s2")
        self.addLink(core, edge1)
        self.addLink(core, edge2)
        half = n_hosts // 2
        for i in range(1, half + 1):
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, edge1)
        for i in range(half + 1, n_hosts + 1):
            h = self.addHost(f"h{i}", ip=f"10.0.0.{i}/24")
            self.addLink(h, edge2)


# ── Service emulation ──────────────────────────────────────────────────────────

LISTENER_SCRIPT = """\
#!/usr/bin/env python3
import socket, threading, sys, os, signal

banner = {banner!r}
port   = {port}

def handle(conn):
    try:
        if banner:
            conn.sendall(banner if isinstance(banner, bytes) else banner.encode())
        conn.recv(1024)
    except Exception:
        pass
    finally:
        conn.close()

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
server.bind(('0.0.0.0', port))
server.listen(50)

def stopper(sig, frame):
    server.close()
    sys.exit(0)

signal.signal(signal.SIGTERM, stopper)
signal.signal(signal.SIGINT,  stopper)

while True:
    try:
        conn, _ = server.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()
    except OSError:
        break
"""


def apply_os_fingerprint(host, profile):
    """
    Apply kernel-level tweaks to make a Mininet host respond with a given
    OS fingerprint (TTL, TCP window size, TCP options).
    """
    ttl    = profile["ttl"]
    window = profile["tcp_window"]
    label  = profile["os_label"]

    info(f"  [*] {host.name}: applying fingerprint → {label}\n")

    # Set default TTL
    host.cmd(f"sysctl -w net.ipv4.ip_default_ttl={ttl}")

    # TCP window / rmem
    host.cmd(f"sysctl -w net.ipv4.tcp_rmem='4096 {window} {window * 4}'")
    host.cmd(f"sysctl -w net.core.rmem_default={window}")
    host.cmd(f"sysctl -w net.core.rmem_max={window * 4}")

    # Disable timestamps for some profiles (Windows-style)
    if ttl == 128:
        host.cmd("sysctl -w net.ipv4.tcp_timestamps=0")
        host.cmd("sysctl -w net.ipv4.tcp_sack=1")
    else:
        host.cmd("sysctl -w net.ipv4.tcp_timestamps=1")

    # Enable ICMP responses
    host.cmd("sysctl -w net.ipv4.icmp_echo_ignore_all=0")


def start_services(host, profile, tmp_dir):
    """Spawn a tiny TCP listener for every service in the profile."""
    pids = []
    for svc in profile["services"]:
        port, proto, banner = svc
        script_path = os.path.join(tmp_dir, f"{host.name}_port{port}.py")
        script = LISTENER_SCRIPT.format(banner=banner, port=port)
        with open(script_path, "w") as f:
            f.write(script)
        pid = host.cmd(f"python3 {script_path} &>/tmp/{host.name}_{port}.log & echo $!")
        pid = pid.strip()
        if pid.isdigit():
            pids.append(int(pid))
            info(f"    → {host.name}:{port}/{proto} (pid {pid})\n")
    return pids


# ── Main ────────────────────────────────────────────────────────��──────────────

def build_network(topo_name="star", verbose=False):
    if os.geteuid() != 0:
        error("ERROR: This script must be run as root (sudo).\n")
        sys.exit(1)

    setLogLevel("info" if verbose else "warning")

    profiles = list(OS_PROFILES.items())
    n_hosts  = len(profiles)

    info(f"\n[+] Building '{topo_name}' topology with {n_hosts} hosts\n")

    # Select topology
    if topo_name == "star":
        topo = StarTopo(n_hosts=n_hosts)
    elif topo_name == "linear":
        topo = LinearTopo(n_hosts=n_hosts)
    else:
        topo = TreeTopo(n_hosts=n_hosts)

    # ── Key change: no external controller ──
    # We use OVSSwitch in standalone mode (no controller) so the switch
    # behaves as a normal L2 learning switch. This ensures ALL traffic
    # (including traffic from outside the VM) is forwarded correctly.
    net = Mininet(
        topo=topo,
        switch=OVSSwitch,
        controller=None,       # No OpenFlow controller
        autoSetMacs=True,
    )
    net.start()

    # ── Configure every switch to use normal L2 forwarding ──
    for switch in net.switches:
        info(f"[+] Setting {switch.name} to standalone mode with NORMAL forwarding\n")
        # Remove any controller association
        subprocess.run(["ovs-vsctl", "del-controller", switch.name], check=False)
        # Set fail-mode to standalone (normal L2 switch behaviour)
        subprocess.run(["ovs-vsctl", "set-fail-mode", switch.name, "standalone"], check=False)
        # Add catch-all flow rule for normal MAC-learning forwarding
        subprocess.run(["ovs-ofctl", "del-flows", switch.name], check=False)
        subprocess.run(["ovs-ofctl", "add-flow", switch.name, "priority=0,actions=NORMAL"], check=False)

    # ── Bridge the physical interface into OVS ──
    # This allows external machines (e.g. your Windows host) to reach
    # the Mininet hosts at layer 2 through the VM's physical NIC.
    VM_IFACE = "enp0s3"
    info(f"\n[+] Bridging {VM_IFACE} into OVS switch s1\n")

    # Save current IP config before moving the interface
    result = subprocess.run(
        ["ip", "-4", "addr", "show", "dev", VM_IFACE],
        capture_output=True, text=True
    )
    info(f"    Current {VM_IFACE} config: {result.stdout.strip()}\n")

    # Add the physical NIC as a port on s1
    subprocess.run(["ovs-vsctl", "add-port", "s1", VM_IFACE], check=False)

    # Remove IP from the physical interface (it's now just a switch port)
    subprocess.run(["ip", "addr", "flush", "dev", VM_IFACE], check=False)

    # Bring up the bridge internal interface with the VM's IP
    subprocess.run(["ip", "addr", "add", "192.168.0.27/24", "dev", "s1"], check=False)
    subprocess.run(["ip", "link", "set", "s1", "up"], check=False)

    # Re-add default route via the bridge
    subprocess.run(["ip", "route", "del", "default"], capture_output=True, check=False)
    subprocess.run(["ip", "route", "add", "default", "via", "192.168.0.1", "dev", "s1"], check=False)

    # Enable IP forwarding on the VM
    subprocess.run(["sysctl", "-w", "net.ipv4.ip_forward=1"], check=False)

    # Allow all forwarding in iptables
    subprocess.run(["iptables", "-P", "FORWARD", "ACCEPT"], check=False)
    subprocess.run(["iptables", "-F", "FORWARD"], check=False)

    info(f"[+] Bridge setup complete. VM reachable at 192.168.0.27 via s1\n")

    tmp_dir = "/tmp/mininet_services"
    os.makedirs(tmp_dir, exist_ok=True)

    # Assign profiles and start services
    info("\n[+] Configuring host fingerprints and services\n")
    host_map = {}
    for i, (profile_name, profile) in enumerate(profiles):
        host = net.get(f"h{i + 1}")
        ip   = host.IP()
        info(f"\n  Host h{i+1} ({ip}) → {profile['os_label']}\n")
        apply_os_fingerprint(host, profile)
        pids = start_services(host, profile, tmp_dir)
        host_map[host.name] = {
            "ip":      ip,
            "profile": profile_name,
            "label":   profile["os_label"],
            "ports":   [s[0] for s in profile["services"]],
            "pids":    pids,
        }

    time.sleep(1)  # let listeners bind

    # ── Verify internal connectivity ──
    info("\n[+] Verifying internal connectivity...\n")
    for i, (profile_name, profile) in enumerate(profiles):
        host = net.get(f"h{i + 1}")
        # Ping another host to prime the MAC learning table
        target_idx = (i + 1) % n_hosts + 1
        result = host.cmd(f"ping -c 1 -W 1 10.0.0.{target_idx}")
        if "1 received" in result:
            info(f"  ✓ {host.name} → 10.0.0.{target_idx} OK\n")
        else:
            info(f"  ✗ {host.name} → 10.0.0.{target_idx} FAILED\n")

    # Print summary table
    print("\n" + "=" * 65)
    print(f"{'Host':<6} {'IP':<14} {'OS Fingerprint':<25} {'Ports'}")
    print("=" * 65)
    for name, info_d in host_map.items():
        ports = ", ".join(str(p) for p in info_d["ports"])
        print(f"{name:<6} {info_d['ip']:<14} {info_d['label']:<25} {ports}")
    print("=" * 65)

    # Print Nmap commands
    subnet = "10.0.0.0/24"
    print(f"""
Scan from your Windows host:
  # Quick ping sweep:
  nmap -sn {subnet}

  # OS fingerprint + service version scan:
  nmap -O -sV -T4 {subnet}

  # Aggressive scan (all ports):
  nmap -A -T4 {subnet}

Scan from inside Mininet CLI:
  mininet> h1 nmap -O -sV 10.0.0.0/24

Open Mininet CLI → type 'exit' or Ctrl-D to stop the network.
""")

    CLI(net)

    # Cleanup
    info("\n[+] Stopping network...\n")
    for name, info_d in host_map.items():
        host = net.get(name)
        for pid in info_d["pids"]:
            host.cmd(f"kill {pid} 2>/dev/null")

    # Restore enp0s3 before stopping
    subprocess.run(["ovs-vsctl", "del-port", "s1", VM_IFACE], check=False)
    subprocess.run(["ip", "addr", "add", "192.168.0.27/24", "dev", VM_IFACE], check=False)
    subprocess.run(["ip", "link", "set", VM_IFACE, "up"], check=False)
    subprocess.run(["ip", "route", "add", "default", "via", "192.168.0.1", "dev", VM_IFACE], check=False)

    net.stop()
    subprocess.run(["mn", "--clean"], capture_output=True)
    print("[+] Network stopped and cleaned up.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Mininet virtual network with OS fingerprint spoofing"
    )
    parser.add_argument(
        "--topo",
        choices=["star", "linear", "tree"],
        default="star",
        help="Network topology (default: star)",
    )
    parser.add_argument(
        "--verbose", action="store_true", help="Enable verbose Mininet logging"
    )
    args = parser.parse_args()
    build_network(topo_name=args.topo, verbose=args.verbose)