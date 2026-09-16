"""
NetPulse - Network Tools Suite
Contains high-performance implementations for:
1. Wake-on-LAN (WoL) Magic Packet transmission
2. Parallel DNS Benchmark against top public & local resolvers
"""

import re
import time
import socket
import struct
from concurrent.futures import ThreadPoolExecutor

def send_wake_on_lan(mac_address: str, broadcast_ip: str = "255.255.255.255", port: int = 9) -> dict:
    """
    Sends a Wake-on-LAN (WoL) Magic Packet to wake sleeping computers or servers.
    The magic packet consists of 6 bytes of 0xFF followed by 16 repetitions of the target MAC.
    """
    clean_mac = re.sub(r'[^a-fA-F0-9]', '', mac_address)
    if len(clean_mac) != 12:
        raise ValueError(f"Endereço MAC inválido: {mac_address}")

    mac_bytes = bytes.fromhex(clean_mac)
    magic_packet = b'\xff' * 6 + mac_bytes * 16

    # Broadcast on port 9 (Discard) and port 7 (Echo) for maximum router/NIC compatibility
    ports_sent = []
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        for p in [port, 7]:
            try:
                s.sendto(magic_packet, (broadcast_ip, p))
                ports_sent.append(p)
            except Exception:
                pass

    return {
        "success": True,
        "mac": mac_address,
        "broadcast": broadcast_ip,
        "ports": ports_sent,
        "message": f"Pacote Mágico WoL transmitido para {mac_address.upper()}"
    }

def build_dns_query(domain: str, query_id: int = 0x1a2b) -> bytes:
    """
    Builds a raw DNS query packet for an A record using RFC 1035 wire format.
    Standard Python struct, zero external dependencies.
    """
    # Header: ID (16b), Flags 0x0100 (Standard query, Recursion desired), QDCOUNT=1, ANCOUNT=0, NSCOUNT=0, ARCOUNT=0
    header = struct.pack("!HHHHHH", query_id, 0x0100, 1, 0, 0, 0)
    # Question: Domain name formatted as length-prefixed labels
    qname = b"".join(bytes([len(part)]) + part.encode("ascii") for part in domain.split(".")) + b"\x00"
    # QTYPE=1 (A), QCLASS=1 (IN)
    footer = struct.pack("!HH", 1, 1)
    return header + qname + footer

def test_single_dns_server(server_meta: dict, domains: list = None, timeout: float = 0.8) -> dict:
    """
    Resolves domains through a specific DNS server over UDP port 53 and measures response RTT.
    """
    if domains is None:
        domains = ["google.com", "cloudflare.com", "apple.com"]

    ip = server_meta["ip"]
    latencies = []
    successes = 0

    for idx, domain in enumerate(domains):
        query_id = 0x1000 + idx
        query_pkt = build_dns_query(domain, query_id)
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(timeout)

        t0 = time.perf_counter()
        try:
            s.sendto(query_pkt, (ip, 53))
            resp, _ = s.recvfrom(512)
            t1 = time.perf_counter()
            rtt = (t1 - t0) * 1000.0
            # Validate transaction ID
            if len(resp) >= 12 and struct.unpack("!H", resp[:2])[0] == query_id:
                latencies.append(rtt)
                successes += 1
        except Exception:
            pass
        finally:
            s.close()
        time.sleep(0.01)

    is_online = successes > 0
    avg_ms = round(sum(latencies) / len(latencies), 2) if latencies else None
    min_ms = round(min(latencies), 2) if latencies else None

    return {
        "id": server_meta["id"],
        "name": server_meta["name"],
        "provider": server_meta["provider"],
        "ip": ip,
        "features": server_meta.get("features", []),
        "icon": server_meta.get("icon", "globe"),
        "is_online": is_online,
        "avg_ms": avg_ms,
        "min_ms": min_ms,
        "success_rate": round((successes / len(domains)) * 100, 1) if domains else 0.0,
        "samples": [round(x, 2) for x in latencies]
    }

def benchmark_dns_servers(gateway_ip: str = "192.168.1.1") -> dict:
    """
    Executes a parallel DNS benchmark across the local router and top public DNS resolvers.
    """
    if not gateway_ip or gateway_ip == "127.0.0.1":
        gateway_ip = "192.168.1.1"

    candidates = [
        {
            "id": "router",
            "name": "Router Local (MEO)",
            "provider": "Gateway ISP",
            "ip": gateway_ip,
            "features": ["DNS do Operador", "Sem Filtros"],
            "icon": "router"
        },
        {
            "id": "cloudflare",
            "name": "Cloudflare Primary",
            "provider": "Cloudflare",
            "ip": "1.1.1.1",
            "features": ["Ultra Rápido", "Privacidade 100% (Sem Logs)"],
            "icon": "zap"
        },
        {
            "id": "cloudflare-security",
            "name": "Cloudflare Security",
            "provider": "Cloudflare (1.1.1.2)",
            "ip": "1.1.1.2",
            "features": ["Bloqueio de Malware", "Anti-Phishing"],
            "icon": "shield-check"
        },
        {
            "id": "google",
            "name": "Google Public DNS",
            "provider": "Google",
            "ip": "8.8.8.8",
            "features": ["Anycast Global", "Alta Fiabilidade"],
            "icon": "globe"
        },
        {
            "id": "quad9",
            "name": "Quad9 Security",
            "provider": "Quad9",
            "ip": "9.9.9.9",
            "features": ["Inteligência de Ameaças", "Privacidade na Suíça"],
            "icon": "shield-alert"
        },
        {
            "id": "adguard",
            "name": "AdGuard DNS",
            "provider": "AdGuard",
            "ip": "94.140.14.14",
            "features": ["Bloqueio de Anúncios", "Sem Rastreadores"],
            "icon": "ban"
        },
        {
            "id": "opendns",
            "name": "OpenDNS / Cisco",
            "provider": "Cisco",
            "ip": "208.67.222.222",
            "features": ["Proteção Cisco Talos", "Confiável"],
            "icon": "server"
        },
        {
            "id": "controld",
            "name": "Control D",
            "provider": "Control D",
            "ip": "76.76.2.0",
            "features": ["Sem Logs", "Alta Performance"],
            "icon": "cpu"
        }
    ]

    with ThreadPoolExecutor(max_workers=8) as executor:
        results = list(executor.map(test_single_dns_server, candidates))

    # Sort: online first, then lowest avg_ms
    def sort_key(s):
        if not s["is_online"] or s["avg_ms"] is None:
            return 99999.0
        return s["avg_ms"]

    results.sort(key=sort_key)

    # Determine fastest
    fastest = results[0] if results and results[0]["is_online"] else None
    
    # Calculate comparative savings compared to router
    router_result = next((r for r in results if r["id"] == "router"), None)
    router_ms = router_result["avg_ms"] if (router_result and router_result["is_online"]) else None

    comparison_summary = ""
    if fastest and router_ms and fastest["id"] != "router" and fastest["avg_ms"] < router_ms:
        diff_pct = round(((router_ms - fastest["avg_ms"]) / router_ms) * 100, 0)
        comparison_summary = f"{fastest['name']} é {int(diff_pct)}% mais rápido que o router ({fastest['avg_ms']}ms vs {router_ms}ms)."
    elif fastest and fastest["id"] == "router":
        comparison_summary = f"O seu router atual é o mais rápido ({fastest['avg_ms']}ms) devido à cache local."

    return {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        "gateway_ip": gateway_ip,
        "fastest_id": fastest["id"] if fastest else None,
        "fastest_name": fastest["name"] if fastest else None,
        "comparison_summary": comparison_summary,
        "servers": results
    }
