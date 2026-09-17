"""
NetPulse - Local Network Discovery & Subnet Scanner Engine
Detects local interfaces, default gateway, sweeps the subnet to refresh ARP, and inventories all connected devices.
"""

import subprocess
import socket
import re
import os
from concurrent.futures import ThreadPoolExecutor
from oui_database import lookup_vendor, normalize_mac, classify_device
import database

def get_default_gateway() -> str:
    """Extracts the default gateway IP from routing tables (Linux / macOS)."""
    # 1. Try Linux /proc/net/route
    try:
        if os.path.exists("/proc/net/route"):
            with open("/proc/net/route", "r") as f:
                for line in f.readlines()[1:]:
                    parts = line.strip().split()
                    if len(parts) >= 3 and parts[1] == "00000000":
                        import struct
                        gw_ip = socket.inet_ntoa(struct.pack("<L", int(parts[2], 16)))
                        if gw_ip and gw_ip != "0.0.0.0":
                            return gw_ip
    except Exception:
        pass

    # 2. Try Linux 'ip route'
    try:
        out = subprocess.check_output(["ip", "route", "show", "default"], universal_newlines=True, stderr=subprocess.DEVNULL)
        m = re.search(r'default\s+via\s+([0-9\.]+)', out)
        if m:
            return m.group(1)
    except Exception:
        pass

    # 3. Try macOS 'netstat -rn -f inet'
    try:
        output = subprocess.check_output(["netstat", "-rn", "-f", "inet"], universal_newlines=True, stderr=subprocess.DEVNULL)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "default":
                return parts[1]
    except Exception:
        pass
    return "192.168.1.1"

def get_local_interface_and_ip() -> tuple:
    """Returns (interface_name, local_ip) for Linux and macOS."""
    local_ip = "127.0.0.1"
    iface = "eth0"

    # 1. Try UDP dummy connect
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
    except Exception:
        pass

    # 2. Try Linux 'ip route get' to find interface
    try:
        out = subprocess.check_output(["ip", "route", "get", "8.8.8.8"], universal_newlines=True, stderr=subprocess.DEVNULL)
        m = re.search(r'dev\s+([a-zA-Z0-9_\-\.]+)', out)
        if m:
            iface = m.group(1)
            return iface, local_ip
    except Exception:
        pass

    # 3. Try macOS ipconfig
    for mac_iface in ["en0", "en1", "en2"]:
        try:
            ip = subprocess.check_output(["ipconfig", "getifaddr", mac_iface], universal_newlines=True, stderr=subprocess.DEVNULL).strip()
            if ip and not ip.startswith("127."):
                return mac_iface, ip
        except Exception:
            continue

    return iface, local_ip

def get_interface_mac(iface: str = "") -> str:
    """Retrieves physical MAC address of the local network interface (Linux & macOS)."""
    # 1. Check Linux sysfs candidate interfaces
    candidates = [iface, "br0", "eth0", "bond0", "enp3s0", "enp4s0"]
    for cand in candidates:
        if not cand:
            continue
        p = f"/sys/class/net/{cand}/address"
        if os.path.exists(p):
            try:
                with open(p, "r") as f:
                    mac = f.read().strip()
                    if mac and mac != "00:00:00:00:00:00" and not mac.lower().startswith("02:42:"):
                        return normalize_mac(mac)
            except Exception:
                pass

    # 2. Iterate all /sys/class/net/*/address on Linux
    if os.path.exists("/sys/class/net"):
        try:
            for entry in os.listdir("/sys/class/net"):
                if entry in ["lo"] or entry.startswith("docker") or entry.startswith("veth") or entry.startswith("virbr") or (entry.startswith("br-") and entry != "br0"):
                    continue
                p = f"/sys/class/net/{entry}/address"
                if os.path.exists(p):
                    try:
                        with open(p, "r") as f:
                            mac = f.read().strip()
                            if mac and mac != "00:00:00:00:00:00" and not mac.lower().startswith("02:42:"):
                                return normalize_mac(mac)
                    except Exception:
                        pass
        except Exception:
            pass

    # 3. Try Linux 'ip link' command
    try:
        cmd = ["ip", "link", "show", iface] if iface else ["ip", "link"]
        out = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
        m = re.search(r'link/ether\s+([0-9a-fA-F:]{17})', out)
        if m:
            mac = normalize_mac(m.group(1))
            if mac and not mac.lower().startswith("02:42:"):
                return mac
    except Exception:
        pass

    # 4. macOS ifconfig fallback
    try:
        cmd = ["ifconfig", iface] if iface else ["ifconfig"]
        out = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL)
        m = re.search(r'ether\s+([0-9a-fA-F:]{11,17})', out)
        if m:
            mac = normalize_mac(m.group(1))
            if mac and not mac.lower().startswith("02:42:"):
                return mac
    except Exception:
        pass

    return ""

def get_network_info() -> dict:
    """Returns network info dictionary with gateway_ip, local_ip, and interface."""
    gw = get_default_gateway() or "192.168.1.1"
    iface, local_ip = get_local_interface_and_ip()
    return {
        "gateway_ip": gw,
        "local_ip": local_ip,
        "interface": iface
    }

def resolve_hostname(ip: str, timeout: float = 0.5) -> str:
    """Performs reverse DNS lookup with quick timeout."""
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        if host and host != ip:
            # Clean local suffixes like .lan, .local, .home
            return host
    except Exception:
        pass
    return ""

def probe_host_silent(ip: str):
    """Sends a quick TCP syn to common ports to wake up dormant devices and populate ARP cache."""
    for port in [80, 443, 53, 5353]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.15)
        try:
            s.connect_ex((ip, port))
        except Exception:
            pass
        finally:
            s.close()

def refresh_arp_cache(subnet_prefix: str, max_workers: int = 40):
    """Parallel sweep of 1..254 to force ARP resolution across the local subnet."""
    ips = [f"{subnet_prefix}{i}" for i in range(1, 255)]
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        list(executor.map(probe_host_silent, ips))

def is_valid_lan_device(ip: str, mac: str, iface: str, gateway_ip: str, local_ip: str) -> bool:
    """Filters out Docker virtual networks, multicast, loopback, and keeps only home LAN devices."""
    if not mac or mac == "00:00:00:00:00:00" or mac == "ff:ff:ff:ff:ff:ff":
        return False
    if ip.startswith("224.") or ip.startswith("239.") or ip.startswith("255.") or ip.startswith("127.") or ip.startswith("169.254."):
        return False

    # Filter out Docker virtual container MACs (prefix 02:42:)
    if mac.lower().startswith("02:42:"):
        return False

    # Filter out Docker virtual interfaces (docker0, veth*, br-<id>, virbr*)
    iface_clean = (iface or "").lower().strip()
    if iface_clean.startswith("docker") or iface_clean.startswith("veth") or iface_clean.startswith("virbr") or (iface_clean.startswith("br-") and iface_clean != "br0"):
        return False

    # Filter out standard Docker bridge subnets (172.16.0.0 - 172.31.255.255)
    parts = ip.split(".")
    if len(parts) == 4 and parts[0] == "172":
        try:
            second_octet = int(parts[1])
            if 16 <= second_octet <= 31:
                return False
        except ValueError:
            pass

    # Restrict to the local LAN subnet (matches gateway or local IP prefix, e.g. 192.168.1.*)
    all_subnets = os.environ.get("NETPULSE_ALL_SUBNETS", "false").lower() in ("true", "1", "yes")
    if not all_subnets:
        gw_prefix = ".".join(gateway_ip.split(".")[:3]) + "." if gateway_ip else ""
        loc_prefix = ".".join(local_ip.split(".")[:3]) + "." if local_ip and not local_ip.startswith("127.") else ""
        target_prefix = loc_prefix or gw_prefix
        if target_prefix and not ip.startswith(target_prefix):
            return False

    return True

def parse_arp_table(gateway_ip: str, local_ip: str) -> list:
    """Parses system ARP table output and extracts valid IP/MAC pairs (Linux & macOS)."""
    devices = []
    seen_macs = set()

    # 1. On Linux, directly read kernel /proc/net/arp for 100% native accuracy
    if os.path.exists("/proc/net/arp"):
        try:
            with open("/proc/net/arp", "r") as f:
                lines = f.readlines()[1:]
                for line in lines:
                    parts = line.split()
                    if len(parts) >= 4:
                        ip = parts[0]
                        raw_mac = parts[3]
                        iface = parts[5] if len(parts) >= 6 else ""
                        mac = normalize_mac(raw_mac)
                        if not mac or mac in seen_macs:
                            continue
                        if not is_valid_lan_device(ip, mac, iface, gateway_ip, local_ip):
                            continue
                        seen_macs.add(mac)
                        devices.append({"ip": ip, "mac": mac, "raw_line": line.strip()})
            if devices:
                return devices
        except Exception:
            pass

    # 2. Fallback to 'arp -a' (macOS and Linux net-tools)
    try:
        output = subprocess.check_output(["arp", "-a"], universal_newlines=True, stderr=subprocess.DEVNULL)
    except Exception:
        output = ""

    # Pattern: ? (192.168.1.1) at bc:7:1d:7e:7f:c6 on en0 ifscope [ethernet]
    pattern = re.compile(r'\(?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?\s+at\s+([0-9a-fA-F:]+)')

    for line in output.splitlines():
        if "incomplete" in line:
            continue
        match = pattern.search(line)
        if not match:
            continue

        ip = match.group(1)
        raw_mac = match.group(2)
        mac = normalize_mac(raw_mac)

        if not mac or mac in seen_macs:
            continue
        if not is_valid_lan_device(ip, mac, "", gateway_ip, local_ip):
            continue

        seen_macs.add(mac)
        devices.append({"ip": ip, "mac": mac, "raw_line": line})

    return devices

def scan_network_full(quick: bool = False) -> dict:
    """
    Executes a network scan:
    1. Identifies gateway and local IP
    2. Runs fast ARP refresh if not in quick mode
    3. Parses ARP table
    4. Resolves vendor and device classification
    5. Saves into SQLite database
    """
    database.init_db()
    gateway_ip = get_default_gateway()
    iface, local_ip = get_local_interface_and_ip()

    subnet_prefix = ".".join(local_ip.split(".")[:3]) + "."
    if subnet_prefix == "127.0.0.":
        subnet_prefix = ".".join(gateway_ip.split(".")[:3]) + "."

    if not quick:
        refresh_arp_cache(subnet_prefix)

    raw_devices = parse_arp_table(gateway_ip, local_ip)

    # Ensure local host (e.g. Unraid Server running NetPulse in host mode) is always present.
    # The Linux kernel never includes local IP in ARP tables (/proc/net/arp) because it routes via loopback.
    if local_ip and not local_ip.startswith("127."):
        host_mac = get_interface_mac(iface)
        if host_mac and not any(d["ip"] == local_ip or d["mac"] == host_mac for d in raw_devices):
            raw_devices.insert(0, {
                "ip": local_ip,
                "mac": host_mac,
                "raw_line": f"localhost {local_ip} {host_mac}"
            })

    active_macs = set()
    result_devices = []
    new_devices_found = 0

    for dev in raw_devices:
        ip = dev["ip"]
        mac = dev["mac"]
        active_macs.add(mac)

        is_gateway = (ip == gateway_ip)
        vendor = lookup_vendor(mac)
        hostname = resolve_hostname(ip)

        # If it's our own host machine (e.g. Unraid Server running NetPulse)
        if ip == local_ip:
            if not hostname:
                hostname = socket.gethostname()
            if not vendor or vendor == "Desconhecido":
                hw_vendor = lookup_vendor(mac)
                if hw_vendor and hw_vendor != "Desconhecido":
                    vendor = hw_vendor
                else:
                    vendor = "Micro-Star INTL (MSI)" if mac.lower().startswith("34:5a:60") else "Servidor Unraid"

        # Classify device
        device_type = classify_device(ip, mac, hostname, vendor, is_gateway=is_gateway)

        saved_dev, is_new = database.upsert_device(ip, mac, hostname, vendor, device_type)
        if is_new:
            new_devices_found += 1
        result_devices.append(saved_dev)

    # Mark offline devices
    database.mark_offline_stale_devices(active_macs)

    # Sort results with gateway first, then by IP
    def sort_key(d):
        if d["ip"] == gateway_ip:
            return 0
        try:
            return int(d["ip"].split(".")[-1])
        except Exception:
            return 999

    result_devices.sort(key=sort_key)

    return {
        "gateway_ip": gateway_ip,
        "local_ip": local_ip,
        "interface": iface,
        "subnet": f"{subnet_prefix}0/24",
        "total_active": len(result_devices),
        "new_devices_count": new_devices_found,
        "devices": result_devices
    }
