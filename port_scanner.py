"""
NetPulse - Fast Concurrent Port Scanner & Service Auditor
Scans common TCP ports on local devices to identify open services and assess network security.
"""

import socket
from concurrent.futures import ThreadPoolExecutor

# Common services and security categorization
COMMON_PORTS = {
    21: {"service": "FTP", "desc": "File Transfer Protocol", "risk": "medium"},
    22: {"service": "SSH", "desc": "Secure Shell Remote Login", "risk": "low"},
    23: {"service": "Telnet", "desc": "Unencrypted Telnet (Vulnerável)", "risk": "high"},
    25: {"service": "SMTP", "desc": "Simple Mail Transfer", "risk": "low"},
    53: {"service": "DNS", "desc": "Domain Name System", "risk": "low"},
    80: {"service": "HTTP", "desc": "Web Server / Dashboard", "risk": "info"},
    443: {"service": "HTTPS", "desc": "Secure Web Server", "risk": "info"},
    445: {"service": "SMB", "desc": "Windows File Sharing / Samba", "risk": "medium"},
    548: {"service": "AFP", "desc": "Apple Filing Protocol", "risk": "low"},
    554: {"service": "RTSP", "desc": "Real Time Streaming (Câmara IP)", "risk": "info"},
    631: {"service": "IPP", "desc": "Internet Printing Protocol", "risk": "info"},
    1883: {"service": "MQTT", "desc": "IoT Message Broker", "risk": "info"},
    3306: {"service": "MySQL", "desc": "MySQL Database Server", "risk": "medium"},
    3389: {"service": "RDP", "desc": "Remote Desktop Protocol", "risk": "medium"},
    5000: {"service": "UPnP / Synology", "desc": "Media Server / NAS Web", "risk": "info"},
    5353: {"service": "mDNS", "desc": "Multicast DNS / Bonjour", "risk": "info"},
    8000: {"service": "HTTP-Alt", "desc": "Web Development Server", "risk": "info"},
    8080: {"service": "HTTP-Proxy", "desc": "Alternative Web Server", "risk": "info"},
    8443: {"service": "HTTPS-Alt", "desc": "Alternative HTTPS / Admin UI", "risk": "info"},
    9000: {"service": "Portainer/Sonar", "desc": "Container / Management UI", "risk": "info"},
    9100: {"service": "RAW Print", "desc": "Direct Printer Port", "risk": "info"}
}

def probe_port(ip: str, port: int, timeout: float = 0.6) -> dict:
    """Probes a single TCP port using a non-blocking connect socket."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        res = s.connect_ex((ip, port))
        if res == 0:
            meta = COMMON_PORTS.get(port, {"service": f"Port-{port}", "desc": "Custom Port", "risk": "info"})
            return {
                "port": port,
                "open": True,
                "service": meta["service"],
                "description": meta["desc"],
                "risk": meta["risk"]
            }
    except Exception:
        pass
    finally:
        s.close()
    return None

def scan_device_ports(ip: str, port_list: list = None, max_workers: int = 25) -> list:
    """
    Scans a given list of ports (or all COMMON_PORTS) concurrently.
    Returns list of open port dicts.
    """
    if port_list is None:
        port_list = list(COMMON_PORTS.keys())

    open_ports = []
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(probe_port, ip, p) for p in port_list]
        for f in futures:
            res = f.result()
            if res:
                open_ports.append(res)

    open_ports.sort(key=lambda x: x["port"])
    return open_ports
