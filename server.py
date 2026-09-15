"""
NetPulse - Main HTTP Server & REST API
Multi-threaded, zero-dependency REST server serving the frontend SPA and network services.
Supports Dual-Engine Database (PostgreSQL / SQLite), Authentication & Security Hardening.
"""

import http.server
import json
import urllib.parse
import os
import mimetypes
import sys
import threading
import time
import secrets
from datetime import datetime, date

import database
import network_scanner
import port_scanner
import latency_monitor
import speedtest_engine
import agents_engine

PORT = int(os.environ.get("PORT", 8888))
STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")

# Authentication configuration
AUTH_PASSWORD = (os.environ.get("NETPULSE_AUTH_PASSWORD") or os.environ.get("NETPULSE_AUTH_PASS") or "").strip()
AUTH_ENABLED = bool(AUTH_PASSWORD)

ACTIVE_SESSIONS = {}   # token -> expiry_timestamp
LOGIN_ATTEMPTS = {}    # ip -> [attempt_timestamps]

def json_serial(obj):
    if isinstance(obj, (datetime, date)):
        return obj.strftime("%Y-%m-%d %H:%M:%S")
    raise TypeError(f"Type {type(obj)} not serializable")

class NetPulseHandler(http.server.SimpleHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_json(self, data, status=200, extra_headers=None):
        body = json.dumps(data, default=json_serial, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        
        # Security hardening headers
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-XSS-Protection", "1; mode=block")
        self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
        
        if extra_headers:
            for k, v in extra_headers.items():
                self.send_header(k, v)
                
        self.end_headers()
        self.wfile.write(body)
        self.close_connection = True

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()

    def check_authenticated(self):
        if not AUTH_ENABLED:
            return True

        # 1. Check Cookie
        cookie_header = self.headers.get("Cookie", "")
        token = None
        for cookie in cookie_header.split(";"):
            c = cookie.strip()
            if c.startswith("netpulse_session="):
                token = c.split("=", 1)[1]
                break

        # 2. Check Authorization Header (Bearer <token>)
        if not token:
            auth_header = self.headers.get("Authorization", "")
            if auth_header.startswith("Bearer "):
                token = auth_header.split(" ", 1)[1]

        if token and token in ACTIVE_SESSIONS:
            if time.time() < ACTIVE_SESSIONS[token]:
                return True
            else:
                del ACTIVE_SESSIONS[token]

        return False

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Public Auth Status Route
        if path == "/api/auth/status":
            return self.send_json({
                "auth_required": AUTH_ENABLED,
                "authenticated": self.check_authenticated(),
                "db_engine": "PostgreSQL" if database.is_postgres_active() else "SQLite"
            })

        # Protect all other /api/ routes if auth is enabled
        if path.startswith("/api/"):
            if not self.check_authenticated():
                return self.send_json({"error": "Autenticação necessária", "auth_required": True}, 401)

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
                
                ping_res = latency_monitor.measure_ping_socket(target["ip"], count=2)
                return self.send_json({"device_id": device_id, "ip": target["ip"], "ping": ping_res})
            except Exception as e:
                return self.send_json({"error": str(e)}, 500)

        # Serve static frontend files
        if path == "/" or path == "/index.html":
            return self.serve_file(os.path.join(STATIC_DIR, "index.html"), "text/html")
        elif path == "/favicon.ico":
            return self.serve_file(os.path.join(STATIC_DIR, "icon.png"), "image/png")
        elif path in ("/icon.svg", "/static/icon.svg"):
            return self.serve_file(os.path.join(STATIC_DIR, "icon.svg"), "image/svg+xml")
        elif path in ("/icon.png", "/static/icon.png"):
            return self.serve_file(os.path.join(STATIC_DIR, "icon.png"), "image/png")
        else:
            rel_path = path.lstrip("/")
            if rel_path.startswith("static/"):
                rel_path = rel_path[len("static/"):]
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

        # Public Login Route
        if path == "/api/auth/login":
            if not AUTH_ENABLED:
                return self.send_json({"success": True, "auth_required": False})

            # Rate limit protection against brute-force (max 10 attempts per minute per IP)
            client_ip = self.client_address[0]
            now = time.time()
            attempts = [t for t in LOGIN_ATTEMPTS.get(client_ip, []) if now - t < 60]
            if len(attempts) >= 10:
                return self.send_json({"error": "Demasiadas tentativas incorretas. Aguarde 1 minuto."}, 429)

            pwd = body_data.get("password", "")
            if pwd == AUTH_PASSWORD:
                token = secrets.token_hex(24)
                ACTIVE_SESSIONS[token] = now + (86400 * 30)
                LOGIN_ATTEMPTS[client_ip] = []
                cookie_val = f"netpulse_session={token}; Path=/; Max-Age={86400 * 30}; SameSite=Lax"
                return self.send_json(
                    {"success": True, "token": token},
                    extra_headers={"Set-Cookie": cookie_val}
                )
            else:
                attempts.append(now)
                LOGIN_ATTEMPTS[client_ip] = attempts
                return self.send_json({"error": "Palavra-passe incorreta"}, 401)

        elif path == "/api/auth/logout":
            cookie_val = "netpulse_session=; Path=/; Max-Age=0; SameSite=Lax"
            return self.send_json({"success": True}, extra_headers={"Set-Cookie": cookie_val})

        # Protect all other POST routes
        if not self.check_authenticated():
            return self.send_json({"error": "Autenticação necessária", "auth_required": True}, 401)

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
            parts = path.split("/")
            try:
                agent_id = parts[3]
                is_enabled = bool(body_data.get("is_enabled", False))
                database.update_agent_config(agent_id, is_enabled=is_enabled)
                return self.send_json({"success": True, "agent_id": agent_id, "is_enabled": is_enabled})
            except Exception as e:
                return self.send_json({"error": str(e)}, 500)

        elif path.startswith("/api/agents/") and path.endswith("/run"):
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
            
            # Security headers
            self.send_header("X-Frame-Options", "DENY")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("X-XSS-Protection", "1; mode=block")
            self.send_header("Referrer-Policy", "strict-origin-when-cross-origin")
            
            self.end_headers()
            self.wfile.write(content)
            self.close_connection = True
        except Exception as e:
            self.send_error(500, f"Erro ao ler ficheiro: {e}")

def background_monitor():
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
    print("[NetPulse] Inicializando base de dados e inventário de rede...")
    try:
        network_scanner.scan_network_full(quick=True)
    except Exception as e:
        print(f"[NetPulse] Aviso durante varrimento inicial: {e}")

    try:
        agents_engine.get_engine().start()
        print("[NetPulse] 🤖 Agentes Autónomos iniciados com sucesso.")
    except Exception as e:
        print(f"[NetPulse] Erro ao iniciar agentes: {e}")

    bg_thread = threading.Thread(target=background_monitor, daemon=True)
    bg_thread.start()

    server = http.server.ThreadingHTTPServer(("0.0.0.0", PORT), NetPulseHandler)
    engine_name = "🐘 PostgreSQL" if database.is_postgres_active() else "🗄️ SQLite"
    auth_status = "🔒 Ativa (Palavra-passe configurada)" if AUTH_ENABLED else "🔓 Desativada (Acesso Livre na LAN)"
    
    print(f"============================================================")
    print(f"  ⚡ NetPulse - Network Analyzer & Sentinel WebApp")
    print(f"  💾 Motor de Base de Dados: {engine_name}")
    print(f"  🛡️ Autenticação de Segurança: {auth_status}")
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
