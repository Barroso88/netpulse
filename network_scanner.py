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
    """Extracts the default gateway IP from macOS routing tables."""
    try:
        output = subprocess.check_output(["netstat", "-rn", "-f", "inet"], universal_newlines=True)
        for line in output.splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[0] == "default":
                return parts[1]
    except Exception:
        pass
    return "192.168.1.1"

def get_local_interface_and_ip() -> tuple:
    """Returns (interface_name, local_ip)."""
    # Try macOS ipconfig getifaddr en0
    for iface in ["en0", "en1", "en2"]:
        try:
            ip = subprocess.check_output(["ipconfig", "getifaddr", iface], universal_newlines=True).strip()
            if ip and not ip.startswith("127."):
                return iface, ip
        except Exception:
            continue

    # Fallback via dummy UDP socket connection
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return "en0", local_ip
    except Exception:
        return "en0", "127.0.0.1"

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

def parse_arp_table(gateway_ip: str, local_ip: str) -> list:
    """Parses system ARP table output and extracts valid IP/MAC pairs."""
    try:
        output = subprocess.check_output(["arp", "-a"], universal_newlines=True)
    except Exception:
        return []

    devices = []
    # Pattern: ? (192.168.1.1) at bc:7:1d:7e:7f:c6 on en0 ifscope [ethernet]
    pattern = re.compile(r'\(?([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)\)?\s+at\s+([0-9a-fA-F:]+)')

    seen_macs = set()
    for line in output.splitlines():
        if "incomplete" in line:
            continue
        match = pattern.search(line)
        if not match:
            continue

        ip = match.group(1)
        raw_mac = match.group(2)
        mac = normalize_mac(raw_mac)

        # Ignore broadcast and multicast
        if not mac or mac in seen_macs or mac == "ff:ff:ff:ff:ff:ff":
            continue
        if ip.startswith("224.") or ip.startswith("239.") or ip.startswith("255."):
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

        # If it's our own machine
        if ip == local_ip:
            if not hostname:
                hostname = socket.gethostname()

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
