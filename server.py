"""
NetPulse - Main HTTP Server & REST API
Multi-threaded, zero-dependency REST server serving the frontend SPA and network services.
"""

import http.server
import json
import urllib.parse
import os
import mimetypes
import sys
import threading
import time

import database
import network_scanner
import port_scanner
import latency_monitor
import speedtest_engine
import agents_engine

PORT = int(os.environ.get("PORT", 8888))
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

class NetPulseHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_json(self, data, status=200):
        body = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # REST API Routes
        if path == "/api/devices":
            devices = database.get_all_devices()
            gateway_ip = network_scanner.get_default_gateway()
            iface, local_ip = network_scanner.get_local_interface_and_ip()
            return self.send_json({
                "devices": devices,
                "network_info": {
                    "gateway_ip": gateway_ip,
                    "local_ip": local_ip,
                    "interface": iface
                }
            })

        elif path == "/api/router-latency":
            gateway_ip = network_scanner.get_default_gateway()
            health = latency_monitor.check_router_and_internet_health(gateway_ip)
            history = database.get_recent_latency(limit=25)
            health["history"] = history
            return self.send_json(health)

        elif path == "/api/latency-history":
            history = database.get_recent_latency(limit=30)
            return self.send_json({"history": history})

        elif path == "/api/speedtest-history":
            history = database.get_recent_speedtests(limit=10)
            return self.send_json({"speedtests": history})

        elif path == "/api/alerts":
            alerts = database.get_alerts(unread_only=False, limit=50)
            return self.send_json({"alerts": alerts})

        elif path == "/api/agents":
            configs = database.get_agent_configs()
            return self.send_json({"agents": configs})

        elif path == "/api/agents/logs":
            logs = database.get_recent_agent_logs(limit=60)
            return self.send_json({"logs": logs})

        elif path.startswith("/api/devices/") and path.endswith("/ping"):
            parts = path.split("/")
            try:
                device_id = int(parts[3])
                devices = database.get_all_devices()
                target = next((d for d in devices if d["id"] == device_id), None)
                if not target:
                    return self.send_json({"error": "Dispositivo não encontrado"}, 404)
                
                ping_res = latency_monitor.measure_ping_socket(target["ip"], count=3)
                return self.send_json({"device_id": device_id, "ip": target["ip"], "ping": ping_res})
            except Exception as e:
                return self.send_json({"error": str(e)}, 500)

        # Serve static frontend files
        if path == "/" or path == "/index.html":
            return self.serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html")
        else:
            rel_path = path.lstrip("/")
            file_path = os.path.join(STATIC_DIR, rel_path)
            if os.path.exists(file_path) and os.path.isfile(file_path):
                mime, _ = mimetypes.guess_type(file_path)
                return self.serve_file(file_path, mime or "application/octet-stream")

        self.send_error(404, "Ficheiro não encontrado")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        # Read JSON body
        content_len = int(self.headers.get("Content-Length", 0))
        body_data = {}
        if content_len > 0:
            raw_body = self.rfile.read(content_len).decode("utf-8")
            try:
                body_data = json.loads(raw_body)
            except Exception:
                pass

        if path == "/api/scan":
            quick = body_data.get("quick", False)
            scan_result = network_scanner.scan_network_full(quick=quick)
            return self.send_json(scan_result)

        elif path == "/api/speedtest":
            res = speedtest_engine.run_speedtest()
            return self.send_json(res)

        elif path.startswith("/api/devices/") and path.endswith("/edit"):
            parts = path.split("/")
            try:
                device_id = int(parts[3])
                custom_name = body_data.get("custom_name")
                device_type = body_data.get("device_type")
                notes = body_data.get("notes")
                database.update_device_details(device_id, custom_name=custom_name, device_type=device_type, notes=notes)
                return self.send_json({"success": True, "device_id": device_id})
            except Exception as e:
                return self.send_json({"error": str(e)}, 500)

        elif path.startswith("/api/devices/") and path.endswith("/trust"):
            parts = path.split("/")
            try:
                device_id = int(parts[3])
                database.update_device_details(device_id, is_trusted=True)
                return self.send_json({"success": True, "device_id": device_id})
            except Exception as e:
                return self.send_json({"error": str(e)}, 500)

        elif path.startswith("/api/devices/") and path.endswith("/scan-ports"):
            parts = path.split("/")
            try:
                device_id = int(parts[3])
                devices = database.get_all_devices()
                target = next((d for d in devices if d["id"] == device_id), None)
                if not target:
                    return self.send_json({"error": "Dispositivo não encontrado"}, 404)

                open_ports = port_scanner.scan_device_ports(target["ip"])
                database.update_device_ports(device_id, open_ports)
                return self.send_json({"device_id": device_id, "ip": target["ip"], "open_ports": open_ports})
            except Exception as e:
                return self.send_json({"error": str(e)}, 500)

        elif path == "/api/alerts/mark-read":
            database.mark_alerts_as_read()
            return self.send_json({"success": True})

        elif path.startswith("/api/agents/") and path.endswith("/toggle"):
            # /api/agents/<agent_id>/toggle
            parts = path.split("/")
            try:
                agent_id = parts[3]
                is_enabled = bool(body_data.get("is_enabled", False))
                database.update_agent_config(agent_id, is_enabled=is_enabled)
                return self.send_json({"success": True, "agent_id": agent_id, "is_enabled": is_enabled})
            except Exception as e:
                return self.send_json({"error": str(e)}, 500)

        elif path.startswith("/api/agents/") and path.endswith("/run"):
            # /api/agents/<agent_id>/run
            parts = path.split("/")
            try:
                agent_id = parts[3]
                threading.Thread(target=agents_engine.get_engine().run_mission, args=(agent_id,), daemon=True).start()
                return self.send_json({"success": True, "agent_id": agent_id, "message": "Missão iniciada com sucesso"})
            except Exception as e:
                return self.send_json({"error": str(e)}, 500)

        self.send_error(404, "Endpoint não encontrado")

    def serve_file(self, file_path, content_type):
        try:
            with open(file_path, "rb") as f:
                content = f.read()
            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.send_header("Connection", "close")
            self.send_header("Cache-Control", "no-cache, must-revalidate")
            self.end_headers()
            self.wfile.write(content)
            self.close_connection = True
        except Exception as e:
            self.send_error(500, f"Erro ao ler ficheiro: {e}")

def background_monitor():
    """Background task running periodic latency health checks every 30 seconds."""
    while True:
        try:
            gw = network_scanner.get_default_gateway()
            if gw:
                latency_monitor.check_router_and_internet_health(gw)
        except Exception:
            pass
        time.sleep(30)

def main():
    database.init_db()
    # Initial quick scan on startup to populate devices immediately
    print("[NetPulse] Inicializando base de dados e inventário de rede...")
    try:
        network_scanner.scan_network_full(quick=True)
    except Exception as e:
        print(f"[NetPulse] Aviso durante varrimento inicial: {e}")

    # Start autonomous agents engine
    try:
        agents_engine.get_engine().start()
        print("[NetPulse] 🤖 Agentes Autónomos iniciados com sucesso.")
    except Exception as e:
        print(f"[NetPulse] Erro ao iniciar agentes: {e}")

    # Start background latency monitor thread
    bg_thread = threading.Thread(target=background_monitor, daemon=True)
    bg_thread.start()

    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), NetPulseHandler)
    print(f"============================================================")
    print(f"  ⚡ NetPulse - Network Analyzer & Sentinel WebApp")
    print(f"  🚀 Servidor ativo em: http://localhost:{PORT}")
    print(f"  🌐 Acessível na rede em: http://{network_scanner.get_local_interface_and_ip()[1]}:{PORT}")
    print(f"============================================================")
    
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[NetPulse] Servidor encerrado.")
        server.server_close()

if __name__ == "__main__":
    main()
