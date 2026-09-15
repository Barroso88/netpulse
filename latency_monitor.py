"""
NetPulse - Router Latency & Connection Health Monitor
Measures round-trip time (RTT), jitter, and packet reliability to default gateway and DNS servers.
"""

import time
import socket
import statistics
import subprocess
import database

import re

def measure_ping_socket(host: str, port: int = 80, count: int = 2, timeout: float = 0.5) -> dict:
    """
    Measures network latency in milliseconds.
    Uses native ICMP ping on macOS for real low-latency metrics (~3-10ms), falling back to TCP connect.
    """
    latencies = []
    # 1. Try native ICMP ping (fast count packets test with 0.2s interval and 1s timeout)
    try:
        cmd = ["ping", "-c", str(count), "-i", "0.2", "-W", "1000", host]
        out = subprocess.check_output(cmd, universal_newlines=True, stderr=subprocess.DEVNULL, timeout=2.0)
        for line in out.splitlines():
            m = re.search(r'time=([0-9\.]+)\s*ms', line)
            if m:
                latencies.append(float(m.group(1)))
    except Exception:
        pass

    # 2. Fallback to smart TCP probe if ICMP ping was blocked (e.g. Amazon Echo blocks ICMP)
    if not latencies:
        candidate_ports = [4070, 8123, 80, 443, 445, 8008, 62078, 22, 53, 5000, 7000]
        if port not in candidate_ports:
            candidate_ports.insert(0, port)
        active_port = None
        for p in candidate_ports:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.25)
            try:
                s.connect((host, p))
                active_port = p
                s.close()
                break
            except ConnectionRefusedError:
                active_port = p
                break
            except Exception:
                pass
            finally:
                s.close()

        if active_port:
            for _ in range(count):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(timeout)
                t0 = time.perf_counter()
                try:
                    s.connect((host, active_port))
                    t1 = time.perf_counter()
                    latencies.append((t1 - t0) * 1000.0)
                except ConnectionRefusedError:
                    t1 = time.perf_counter()
                    latencies.append((t1 - t0) * 1000.0)
                except Exception:
                    pass
                finally:
                    s.close()
                time.sleep(0.02)

    if not latencies:
        return {"avg_ms": None, "min_ms": None, "max_ms": None, "jitter_ms": 0.0, "loss_pct": 100.0}

    avg_lat = statistics.mean(latencies)
    min_lat = min(latencies)
    max_lat = max(latencies)
    jitter = statistics.stdev(latencies) if len(latencies) > 1 else 0.0
    loss_pct = ((count - len(latencies)) / count) * 100.0 if len(latencies) < count else 0.0

    return {
        "avg_ms": round(avg_lat, 2),
        "min_ms": round(min_lat, 2),
        "max_ms": round(max_lat, 2),
        "jitter_ms": round(jitter, 2),
        "loss_pct": round(max(0.0, loss_pct), 1),
        "samples": [round(x, 2) for x in latencies]
    }

def check_router_and_internet_health(gateway_ip: str) -> dict:
    """
    Performs simultaneous latency tests to:
    1. Local Router Gateway (LAN Latency)
    2. Cloudflare Primary DNS 1.1.1.1 (WAN Latency)
    3. Google DNS 8.8.8.8 (WAN Fallback)
    Saves metrics to SQLite.
    """
    if not gateway_ip or gateway_ip == "127.0.0.1":
        gateway_ip = "192.168.1.1"

    gw_stats = measure_ping_socket(gateway_ip, port=80, count=2)
    dns_stats = measure_ping_socket("1.1.1.1", port=53, count=2)
    if dns_stats["avg_ms"] is None:
        dns_stats = measure_ping_socket("8.8.8.8", port=53, count=2)

    gw_ms = gw_stats["avg_ms"] if gw_stats["avg_ms"] is not None else 0.0
    dns_ms = dns_stats["avg_ms"] if dns_stats["avg_ms"] is not None else 0.0
    jitter = gw_stats["jitter_ms"]
    loss = gw_stats["loss_pct"]

    if gw_stats["avg_ms"] is not None or dns_stats["avg_ms"] is not None:
        database.add_latency_sample(gateway_ip, gw_ms, dns_ms, jitter, loss)

    # Health status evaluation
    if gw_ms > 0 and gw_ms < 15:
        health_lan = "Excelente"
    elif gw_ms >= 15 and gw_ms < 50:
        health_lan = "Bom"
    elif gw_ms >= 50:
        health_lan = "Instável / Elevado"
    else:
        health_lan = "Sem Resposta"

    return {
        "gateway_ip": gateway_ip,
        "router_latency": gw_stats,
        "internet_latency": dns_stats,
        "health_assessment": health_lan,
        "is_online": (dns_stats["avg_ms"] is not None)
    }

