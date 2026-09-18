"""
NetPulse - Autonomous Network Agents Engine
Orchestrates background threads for 4 specialized cyber-agents:
1. SentinelAgent: 24/7 Intrusion Watchdog & Critical Device Monitor
2. ForensicsAgent: Hardware Intelligence via mDNS, SSDP & HTTP Banners
3. SecurityAuditorAgent: Vulnerability Assessment & Global Security Score
4. QoSSentinelAgent: Wi-Fi Stability, Jitter & ISP Telemetry
"""

import threading
import time
import socket
from datetime import datetime
import database
import network_scanner
import port_scanner
import latency_monitor

class AgentsEngine:
    def __init__(self):
        self.running = False
        self.threads = {}
        self.stop_events = {}
        self.lock = threading.Lock()
        
    def start(self):
        with self.lock:
            if self.running:
                return
            self.running = True
            
            # Initial log
            database.log_agent_activity("system", "INFO", "Motor de Agentes Autónomos NetPulse iniciado com sucesso.")
            
            # Start each agent daemon thread
            for aid in ["sentinel", "forensics", "security_auditor", "qos_sentinel", "brand_stylist"]:
                self._spawn_agent_thread(aid)

    def stop(self):
        with self.lock:
            self.running = False
            for aid, event in self.stop_events.items():
                event.set()
            database.log_agent_activity("system", "INFO", "Motor de Agentes Autónomos parado.")

    def _spawn_agent_thread(self, agent_id):
        self.stop_events[agent_id] = threading.Event()
        t = threading.Thread(target=self._agent_loop, args=(agent_id, self.stop_events[agent_id]), daemon=True)
        self.threads[agent_id] = t
        t.start()

    def _agent_loop(self, agent_id, stop_event):
        # Initial stagger so agents don't all run simultaneously at tick 0
        stagger = {"sentinel": 2, "qos_sentinel": 5, "forensics": 8, "security_auditor": 12, "brand_stylist": 15}
        time.sleep(stagger.get(agent_id, 3))
        
        while self.running and not stop_event.is_set():
            try:
                configs = database.get_agent_configs()
                cfg = next((c for c in configs if c["agent_id"] == agent_id), None)
                if not cfg or not cfg.get("is_enabled", 1):
                    # Check again in 5 seconds if disabled
                    time.sleep(5)
                    continue

                # Run Agent Mission
                self.run_mission(agent_id)

                interval = max(15, cfg.get("interval_seconds", 60))
                # Sleep in small increments to be responsive to stop_event
                for _ in range(interval):
                    if not self.running or stop_event.is_set():
                        break
                    time.sleep(1)

            except Exception as e:
                database.log_agent_activity(agent_id, "ERROR", f"Erro no ciclo do agente: {str(e)}")
                time.sleep(10)

    def run_mission(self, agent_id):
        """Executes a single mission for the requested agent immediately."""
        now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        if agent_id == "sentinel":
            self._mission_sentinel(now_str)
        elif agent_id == "forensics":
            self._mission_forensics(now_str)
        elif agent_id == "security_auditor":
            self._mission_security_auditor(now_str)
        elif agent_id == "qos_sentinel":
            self._mission_qos_sentinel(now_str)
        elif agent_id == "brand_stylist":
            self._mission_brand_stylist(now_str)

    # -------------------------------------------------------------------------
    # AGENT 1: SENTINEL INTRUSION & WATCHDOG AGENT
    # -------------------------------------------------------------------------
    def _mission_sentinel(self, now_str):
        database.log_agent_activity("sentinel", "INFO", "A patrulhar sub-rede local 192.168.1.0/24...")
        
        # Read current ARP state
        devices = database.get_all_devices()
        prev_count = len(devices)
        
        # Check critical devices
        critical_ips = {
            "192.168.1.1": "Router Gateway",
            "192.168.1.99": "Home Assistant",
            "192.168.1.67": "TrueNAS",
            "192.168.1.152": "CastleServer Unraid"
        }
        
        critical_online = 0
        for ip, name in critical_ips.items():
            ping = latency_monitor.measure_ping_socket(ip, count=1, timeout=0.6)
            if ping and ping["avg_ms"] is not None:
                critical_online += 1
            else:
                database.log_agent_activity("sentinel", "WARN", f"Servidor crítico inacessível ou com ping lento: {name} ({ip})")

        # Check for new devices (is_new = 1)
        new_devs = [d for d in devices if d.get("is_new")]
        if new_devs:
            for nd in new_devs[:3]:
                database.log_agent_activity("sentinel", "WARN", f"Novo dispositivo ativo no Wi-Fi: {nd.get('custom_name') or nd.get('ip')} ({nd.get('mac')})")
        else:
            database.log_agent_activity("sentinel", "INFO", f"Patrulha concluída: {prev_count} dispositivos registados. Infraestrutura crítica {critical_online}/{len(critical_ips)} operacional.")

        # Update stats
        stats = {
            "devices_monitored": prev_count,
            "critical_online": critical_online,
            "new_devices_pending": len(new_devs),
            "status": "Seguro" if not new_devs else "Atenção (Novos Dispositivos)"
        }
        database.update_agent_config("sentinel", last_run=now_str, stats=stats)

    # -------------------------------------------------------------------------
    # AGENT 2: HARDWARE FORENSICS & FINGERPRINTING AGENT (mDNS & SSDP)
    # -------------------------------------------------------------------------
    def _mission_forensics(self, now_str):
        database.log_agent_activity("forensics", "INFO", "A emitir sondas de reconhecimento SSDP/UPnP e banners HTTP...")
        
        devices = database.get_all_devices()
        probed = 0
        identified = 0
        
        # Simple SSDP M-SEARCH Multicast
        try:
            ssdp_request = (
                "M-SEARCH * HTTP/1.1\r\n"
                "HOST: 239.255.255.250:1900\r\n"
                'MAN: "ssdp:discover"\r\n'
                "MX: 2\r\n"
                "ST: ssdp:all\r\n\r\n"
            ).encode("utf-8")
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 2)
            sock.settimeout(1.5)
            sock.sendto(ssdp_request, ("239.255.255.250", 1900))
            
            start_t = time.time()
            while time.time() - start_t < 1.5:
                try:
                    data, addr = sock.recvfrom(2048)
                    probed += 1
                    ip = addr[0]
                    text = data.decode("utf-8", errors="ignore")
                    
                    # Look for server banner or friendly model name
                    for line in text.split("\r\n"):
                        if line.lower().startswith("server:"):
                            server_banner = line.split(":", 1)[1].strip()
                            # Check if device in DB
                            target = next((d for d in devices if d["ip"] == ip), None)
                            if target and not target.get("notes"):
                                database.update_device_details(target["id"], target["custom_name"], target["device_type"], notes=f"UPnP: {server_banner[:45]}")
                                identified += 1
                                database.log_agent_activity("forensics", "INFO", f"Identificado modelo/serviço via UPnP em {ip}: {server_banner[:40]}")
                except socket.timeout:
                    break
                except Exception:
                    break
            sock.close()
        except Exception as e:
            database.log_agent_activity("forensics", "WARN", f"Sonda SSDP: {str(e)}")

        database.log_agent_activity("forensics", "INFO", f"Reconhecimento concluído. Respostas analisadas: {probed}, novos dados incorporados: {identified}.")
        stats = {
            "probes_sent": probed + 1,
            "models_identified": identified,
            "forensics_status": "Atualizado"
        }
        database.update_agent_config("forensics", last_run=now_str, stats=stats)

    # -------------------------------------------------------------------------
    # AGENT 3: SECURITY VULNERABILITY AUDITOR AGENT
    # -------------------------------------------------------------------------
    def _mission_security_auditor(self, now_str):
        database.log_agent_activity("security_auditor", "INFO", "A auditar portas de rede e posture de segurança...")
        
        devices = database.get_all_devices()
        score = 100
        risky_services = []
        
        # High risk ports
        danger_ports = {
            21: ("FTP", 10, "Transmissão de credenciais em texto claro"),
            23: ("Telnet", 15, "Protocolo legado vulnerável sem cifragem"),
            445: ("SMB", 5, "Partilha de ficheiros exposta na LAN"),
            554: ("RTSP", 5, "Stream de vídeo/câmara sem encriptação")
        }
        
        audited_count = 0
        for d in devices:
            ports = d.get("open_ports") or []
            if isinstance(ports, str):
                try:
                    import json
                    ports = json.loads(ports)
                except:
                    ports = []
            
            if ports:
                audited_count += 1
                for p in ports:
                    pnum = p.get("port")
                    if pnum in danger_ports:
                        srv, penalty, reason = danger_ports[pnum]
                        score -= penalty
                        risky_services.append({
                            "ip": d["ip"],
                            "device": d.get("custom_name") or d["ip"],
                            "port": pnum,
                            "service": srv,
                            "reason": reason
                        })
        
        score = max(0, min(100, score))
        rating = "A+ (Excelente)" if score >= 90 else ("A (Bom)" if score >= 80 else ("B (Atenção)" if score >= 70 else "C (Vulnerável)"))
        
        if risky_services:
            for r in risky_services[:2]:
                database.log_agent_activity("security_auditor", "WARN", f"Aviso de Segurança: Porta {r['port']} ({r['service']}) aberta em {r['device']} ({r['ip']})")
        
        database.log_agent_activity("security_auditor", "INFO", f"Auditoria finalizada. Score de Cibersegurança: {score}/100 - Nível {rating}.")
        
        stats = {
            "security_score": score,
            "rating": rating,
            "audited_devices": audited_count,
            "vulnerabilities_detected": len(risky_services)
        }
        database.update_agent_config("security_auditor", last_run=now_str, stats=stats)

    # -------------------------------------------------------------------------
    # AGENT 4: QUALITY OF SERVICE (QoS) & WI-FI STABILITY SENTINEL
    # -------------------------------------------------------------------------
    def _mission_qos_sentinel(self, now_str):
        gateway_ip = network_scanner.get_default_gateway() or "192.168.1.1"
        
        gw_ping = latency_monitor.measure_ping_socket(gateway_ip, count=4, timeout=0.8)
        dns_ping = latency_monitor.measure_ping_socket("1.1.1.1", count=4, timeout=1.0)
        
        gw_ms = gw_ping["avg_ms"] if (gw_ping and gw_ping["avg_ms"] is not None) else 0.0
        dns_ms = dns_ping["avg_ms"] if (dns_ping and dns_ping["avg_ms"] is not None) else 0.0
        jitter_ms = gw_ping.get("jitter_ms", 0.0) if gw_ping else 0.0
        loss = gw_ping.get("loss_pct", 0.0) if gw_ping else 0.0
        
        # Save sample to latency history
        database.add_latency_sample(gateway_ip, gw_ms, dns_ms, jitter_ms, loss)
        
        if jitter_ms > 20:
            database.log_agent_activity("qos_sentinel", "WARN", f"Instabilidade Wi-Fi: Jitter elevado ({jitter_ms:.1f}ms). Possível interferência de canal.")
        elif loss > 0:
            database.log_agent_activity("qos_sentinel", "WARN", f"Alerta de Perda de Pacotes: {loss}% no router gateway {gateway_ip}.")
        else:
            database.log_agent_activity("qos_sentinel", "INFO", f"Conexão ótima: Router {gw_ms:.1f}ms, Internet 1.1.1.1 {dns_ms:.1f}ms, Jitter {jitter_ms:.1f}ms.")
            
        stats = {
            "gateway_ms": gw_ms,
            "internet_ms": dns_ms,
            "jitter_ms": jitter_ms,
            "wifi_health": "Excelente" if jitter_ms < 8 else ("Bom" if jitter_ms < 20 else "Interferência")
        }
        database.update_agent_config("qos_sentinel", last_run=now_str, stats=stats)

    # -------------------------------------------------------------------------
    # AGENT 5: BRAND & VISUAL IDENTITY STYLIST AGENT
    # -------------------------------------------------------------------------
    def _mission_brand_stylist(self, now_str):
        from oui_database import lookup_vendor, classify_device
        devices = database.get_all_devices()
        total = len(devices)
        
        corrected_count = 0
        
        # Self-healing cross-validation: Detect brand/vendor/OUI discrepancies and heal them
        for d in devices:
            dev_id = d["id"]
            ip = d.get("ip", "")
            mac = d.get("mac", "")
            name = (d.get("custom_name") or "").strip()
            curr_vendor = (d.get("vendor") or "").strip()
            curr_type = d.get("device_type", "unknown")
            name_lower = name.lower()
            vendor_lower = curr_vendor.lower()
            
            # Authoritative OUI lookup
            authoritative_vendor = lookup_vendor(mac)
            should_update = False
            new_vendor = curr_vendor
            new_type = curr_type
            reason = ""

            # Check 1: Authoritative OUI differs from current vendor
            if authoritative_vendor and authoritative_vendor not in ("Desconhecido", "Broadcast") and authoritative_vendor != curr_vendor:
                should_update = True
                new_vendor = authoritative_vendor
                reason = f"OUI {mac[:8]} verificado como '{authoritative_vendor}'"

            # Check 2: Obvious Custom Name vs Vendor semantic conflict (e.g. Samsung vs Philips)
            elif "samsung" in name_lower and "samsung" not in vendor_lower:
                should_update = True
                new_vendor = "Samsung Electronics"
                new_type = "tv_media" if ("tv" in name_lower or "smart" in name_lower) else "mobile"
                reason = f"Nome '{name}' em conflito com '{curr_vendor}'"
            elif "formuler" in name_lower and "aloys" not in vendor_lower and "formuler" not in vendor_lower:
                should_update = True
                new_vendor = "Aloys, Inc (Box Formuler IPTV)"
                new_type = "tv_media"
                reason = f"Box IPTV Formuler identificada em '{name}'"
            elif "apple" in name_lower and "apple" not in vendor_lower:
                should_update = True
                new_vendor = "Apple, Inc."
                new_type = "tv_media" if "apple tv" in name_lower else ("computer" if "mac" in name_lower else "mobile")
                reason = f"Dispositivo Apple identificado em '{name}'"
            elif "home assistant" in name_lower and "google" in vendor_lower:
                should_update = True
                new_vendor = "Proxmox Server Solutions (Home Assistant)"
                new_type = "iot"
                reason = "Home Assistant em ambiente virtualizado detetado"

            if should_update:
                if d.get("is_custom_type") == 1:
                    new_type = curr_type
                else:
                    new_type = classify_device(ip, mac, d.get("hostname", ""), new_vendor, custom_name=name)
                
                # Update DB
                conn = database.get_db_connection()
                cur = conn.cursor()
                cur.execute("UPDATE devices SET vendor = ?, device_type = ? WHERE id = ?", (new_vendor, new_type, dev_id))
                conn.commit()
                conn.close()
                
                corrected_count += 1
                database.log_agent_activity(
                    "brand_stylist",
                    "WARN",
                    f"🔍 Inconsistência corrigida no IP {ip} ({mac}): {reason}. Fabricante corrigido para '{new_vendor}'."
                )

        # Refresh devices after healing
        devices = database.get_all_devices()
        known_brands = [
            "home assistant", "raspberry", "nvidia", "truenas", "unraid",
            "sonoff", "ewelink", "coolkit", "tuya", "xiaomi", "samsung", "amazon", "philips",
            "google", "apple", "playstation", "msi", "huawei", "intel",
            "asus", "tp-link", "meo", "altice", "arcadyan", "router principal", "lg", "espressif",
            "sonos", "nintendo", "synology", "shelly", "dell", "ubiquiti",
            "hp", "formuler", "printer", "proxmox"
        ]
        
        branded_count = 0
        detected_brands = set()
        
        for d in devices:
            name = (d.get('custom_name') or '').lower()
            vendor = (d.get('vendor') or '').lower()
            combined = f"{name} {vendor} {d.get('hostname') or ''}".lower()
            
            matched = False
            if name:
                for b in known_brands:
                    if b in name:
                        branded_count += 1
                        detected_brands.add(b.title())
                        matched = True
                        break
            if not matched:
                for b in known_brands:
                    if b in combined:
                        branded_count += 1
                        detected_brands.add(b.title())
                        break
                
        brands_summary = ", ".join(list(detected_brands)[:8]) if detected_brands else "Hardware Diverso"
        status_msg = f"Auditoria de marcas: {branded_count}/{total} sincronizados ({brands_summary})."
        if corrected_count > 0:
            status_msg += f" 🛠️ {corrected_count} inconsistências corrigidas autonomamente."
            
        database.log_agent_activity("brand_stylist", "INFO", status_msg)
        
        stats = {
            "total_devices": total,
            "branded_devices": branded_count,
            "coverage_pct": round((branded_count / max(1, total)) * 100, 1),
            "brands_detected": len(detected_brands),
            "auto_corrections": corrected_count,
            "render_mode": "Cores Originais (Sem Margens/Caixas)"
        }
        database.update_agent_config("brand_stylist", last_run=now_str, stats=stats)

# Global Singleton
engine = AgentsEngine()

def get_engine():
    return engine
