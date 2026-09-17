"""
NetPulse - Dual Database Layer (PostgreSQL & SQLite)
Persists device inventory, categorization, custom aliases, security alerts, and network metrics.
Supports both PostgreSQL (via DATABASE_URL or POSTGRES_* env vars) and SQLite (netpulse.db).
Includes automatic migration from SQLite to PostgreSQL on first launch.
"""

import sqlite3
import os
import json
from datetime import datetime, date

DATABASE_URL = os.environ.get("DATABASE_URL")
POSTGRES_HOST = os.environ.get("POSTGRES_HOST")
IS_POSTGRES = bool(DATABASE_URL or POSTGRES_HOST)

DATA_DIR = os.environ.get("NETPULSE_DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("NETPULSE_DB_PATH") or os.path.join(DATA_DIR, "netpulse.db")

def is_postgres_active() -> bool:
    return IS_POSTGRES

def get_postgres_connection():
    import psycopg2
    from psycopg2.extras import RealDictCursor
    url = DATABASE_URL
    if not url and POSTGRES_HOST:
        user = os.environ.get("POSTGRES_USER", "postgres")
        pwd = os.environ.get("POSTGRES_PASSWORD", "")
        db = os.environ.get("POSTGRES_DB", "netpulse")
        port = os.environ.get("POSTGRES_PORT", "5432")
        url = f"postgresql://{user}:{pwd}@{POSTGRES_HOST}:{port}/{db}"
    return psycopg2.connect(url, cursor_factory=RealDictCursor)

class CursorWrapper:
    def __init__(self, raw_cursor, is_pg=False):
        self.raw = raw_cursor
        self.is_pg = is_pg

    def execute(self, query, params=None):
        if self.is_pg:
            q = query.replace("?", "%s")
            q = q.replace("INSERT OR IGNORE INTO", "INSERT INTO")
            if params is not None:
                return self.raw.execute(q, params)
            return self.raw.execute(q)
        else:
            if params is not None:
                return self.raw.execute(query, params)
            return self.raw.execute(query)

    def fetchone(self):
        row = self.raw.fetchone()
        if row is None:
            return None
        return dict(row)

    def fetchall(self):
        rows = self.raw.fetchall()
        return [dict(r) for r in rows]

    @property
    def lastrowid(self):
        return getattr(self.raw, "lastrowid", None)

class DBWrapper:
    def __init__(self, conn, is_pg=False):
        self.conn = conn
        self.is_pg = is_pg

    def cursor(self):
        return CursorWrapper(self.conn.cursor(), self.is_pg)

    def commit(self):
        self.conn.commit()

    def close(self):
        self.conn.close()

def get_db_connection():
    if IS_POSTGRES:
        try:
            conn = get_postgres_connection()
            return DBWrapper(conn, is_pg=True)
        except Exception as e:
            print(f"⚠️ Falha ao ligar ao PostgreSQL ({e}). A usar SQLite de contingência.")

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return DBWrapper(conn, is_pg=False)

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    id_type = "SERIAL PRIMARY KEY" if conn.is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
    on_conflict_ignore = "ON CONFLICT DO NOTHING" if conn.is_pg else ""

    # 1. Devices table
    cursor.execute(f"""
    CREATE TABLE IF NOT EXISTS devices (
        id {id_type},
        ip TEXT NOT NULL,
        mac TEXT UNIQUE NOT NULL,
        hostname TEXT,
        custom_name TEXT,
        vendor TEXT,
        device_type TEXT DEFAULT 'unknown',
        status TEXT DEFAULT 'online',
        is_trusted INTEGER DEFAULT 0,
        is_new INTEGER DEFAULT 1,
        first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        open_ports TEXT DEFAULT '[]',
        notes TEXT DEFAULT ''
    );
    """)

    # 2. Security Alerts
    cursor.execute(f"""
    CREATE TABLE IF NOT EXISTS alerts (
        id {id_type},
        device_mac TEXT,
        device_ip TEXT,
        alert_type TEXT NOT NULL,
        message TEXT NOT NULL,
        severity TEXT DEFAULT 'info',
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 3. Speedtests
    cursor.execute(f"""
    CREATE TABLE IF NOT EXISTS speedtests (
        id {id_type},
        download_mbps REAL NOT NULL,
        upload_mbps REAL NOT NULL,
        ping_ms REAL NOT NULL,
        jitter_ms REAL DEFAULT 0.0,
        server_info TEXT DEFAULT 'CDN Fastest',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 4. Latency History
    cursor.execute(f"""
    CREATE TABLE IF NOT EXISTS latency_history (
        id {id_type},
        gateway_ip TEXT,
        gateway_ms REAL,
        dns_ms REAL,
        jitter_ms REAL,
        packet_loss REAL DEFAULT 0.0,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # 5. Autonomous Agents Configs
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS agent_configs (
        agent_id TEXT PRIMARY KEY,
        name TEXT NOT NULL,
        description TEXT NOT NULL,
        category TEXT NOT NULL,
        is_enabled INTEGER DEFAULT 1,
        interval_seconds INTEGER DEFAULT 60,
        last_run TIMESTAMP,
        stats_json TEXT DEFAULT '{}'
    );
    """)

    # 6. Autonomous Agents Logs
    cursor.execute(f"""
    CREATE TABLE IF NOT EXISTS agent_logs (
        id {id_type},
        agent_id TEXT NOT NULL,
        level TEXT DEFAULT 'INFO',
        message TEXT NOT NULL,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Seed Default Agents
    default_agents = [
        ("sentinel", "Sentinela de Intrusão", "Patrulhamento ativo 24/7 de novos dispositivos e monitorização de servidores críticos.", "security", 1, 30),
        ("forensics", "Forense mDNS & SSDP", "Reconhecimento e identificação profunda de modelos e fabricantes reais via broadcast.", "discovery", 1, 90),
        ("security_auditor", "Auditor de Vulnerabilidades", "Auditoria contínua de portas expostas e cálculo da pontuação de segurança da rede.", "security", 1, 120),
        ("qos_sentinel", "Sentinela de Desempenho & QoS", "Monitorização de jitter, latência do router e estabilidade do operador MEO/Altice.", "network", 1, 45),
        ("brand_stylist", "Agente de Identidade Visual & Marcas", "Audita e cataloga marcas oficiais de hardware, mantendo a renderização de logótipos nas cores autênticas e sem limites.", "visual", 1, 60)
    ]
    for aid, name, desc, cat, enabled, interval in default_agents:
        if conn.is_pg:
            cursor.execute("""
            INSERT INTO agent_configs (agent_id, name, description, category, is_enabled, interval_seconds, stats_json)
            VALUES (?, ?, ?, ?, ?, ?, '{}')
            ON CONFLICT (agent_id) DO NOTHING
            """, (aid, name, desc, cat, enabled, interval))
        else:
            cursor.execute("""
            INSERT OR IGNORE INTO agent_configs (agent_id, name, description, category, is_enabled, interval_seconds, stats_json)
            VALUES (?, ?, ?, ?, ?, ?, '{}')
            """, (aid, name, desc, cat, enabled, interval))

    conn.commit()

    # If connected to PostgreSQL, migrate any existing SQLite data
    if conn.is_pg:
        migrate_sqlite_to_postgres(DB_PATH, conn)

    # Clean up virtual Docker containers and align vendor identifications
    cleanup_and_realign_devices(conn)

    conn.close()

def cleanup_and_realign_devices(conn):
    """
    1. Removes any virtual Docker container entries (172.x, 02:42:x).
    2. Recalculates vendors and categories using the latest OUI dictionary (fixes Formuler / Aloys etc).
    """
    try:
        from oui_database import lookup_vendor, classify_device
        cursor = conn.cursor()

        # 1. Purge non-LAN / Docker containers
        cursor.execute("DELETE FROM devices WHERE ip LIKE '172.%' OR mac LIKE '02:42:%'")
        cursor.execute("DELETE FROM alerts WHERE device_ip LIKE '172.%' OR device_mac LIKE '02:42:%'")

        # 2. Re-align vendor & classification for all devices with self-healing conflict resolution
        cursor.execute("SELECT id, ip, mac, hostname, custom_name, vendor, device_type FROM devices")
        all_devs = cursor.fetchall()
        for d in all_devs:
            mac = d["mac"]
            curr_vendor = d["vendor"] or ""
            curr_type = d["device_type"]
            name = (d["custom_name"] or "").strip()
            name_lower = name.lower()
            vendor_lower = curr_vendor.lower()

            expected_vendor = lookup_vendor(mac)
            should_update = False
            new_vendor = curr_vendor
            new_type = curr_type

            if expected_vendor and expected_vendor not in ("Desconhecido", "Broadcast") and expected_vendor != curr_vendor:
                should_update = True
                new_vendor = expected_vendor
            elif "samsung" in name_lower and "samsung" not in vendor_lower:
                should_update = True
                new_vendor = "Samsung Electronics"
            elif "formuler" in name_lower and "aloys" not in vendor_lower and "formuler" not in vendor_lower:
                should_update = True
                new_vendor = "Aloys, Inc (Box Formuler IPTV)"
            elif "apple" in name_lower and "apple" not in vendor_lower:
                should_update = True
                new_vendor = "Apple, Inc."
            elif "home assistant" in name_lower and "google" in vendor_lower:
                should_update = True
                new_vendor = "Proxmox Server Solutions (Home Assistant)"
            elif "unraid" in name_lower or "castleserver" in name_lower or mac == "34:5a:60:3a:e1:28":
                should_update = True
                if not name:
                    name = "Servidor Unraid (CastleServer)"
                    cursor.execute("UPDATE devices SET custom_name = ? WHERE id = ?", (name, d["id"]))
                if not curr_vendor or curr_vendor == "Desconhecido":
                    new_vendor = "Micro-Star INTL (MSI)"

            # Recalculate target device type
            target_type = classify_device(d["ip"], mac, d["hostname"], new_vendor, custom_name=name)

            if should_update or target_type != curr_type:
                cursor.execute(
                    "UPDATE devices SET vendor = ?, device_type = ? WHERE id = ?",
                    (new_vendor, target_type, d["id"])
                )
        conn.commit()
    except Exception as e:
        print(f"Erro ao realinhar dispositivos: {e}")

def migrate_sqlite_to_postgres(sqlite_path, pg_wrapper):
    """Copies existing data from SQLite netpulse.db to PostgreSQL if Postgres tables are empty."""
    if not os.path.exists(sqlite_path):
        return
    try:
        cur = pg_wrapper.cursor()
        cur.execute("SELECT COUNT(*) as cnt FROM devices")
        cnt = cur.fetchone()["cnt"]
        if cnt > 0:
            return  # Postgres already seeded with data

        print("🔄 A migrar dados existentes do SQLite para o PostgreSQL...")
        sq_conn = sqlite3.connect(sqlite_path)
        sq_conn.row_factory = sqlite3.Row
        sq_cur = sq_conn.cursor()

        # Migrate devices
        sq_cur.execute("SELECT * FROM devices")
        for d in sq_cur.fetchall():
            cur.execute("""
                INSERT INTO devices (id, ip, mac, hostname, custom_name, vendor, device_type, status, is_trusted, is_new, first_seen, last_seen, open_ports, notes)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (mac) DO NOTHING
            """, (
                d["id"], d["ip"], d["mac"], d["hostname"], d["custom_name"], d["vendor"],
                d["device_type"], d["status"], d["is_trusted"], d["is_new"],
                d["first_seen"], d["last_seen"], d["open_ports"], d["notes"]
            ))

        # Reset devices sequence
        cur.execute("SELECT setval(pg_get_serial_sequence('devices', 'id'), COALESCE((SELECT MAX(id) FROM devices), 1))")

        # Migrate alerts
        sq_cur.execute("SELECT * FROM alerts")
        for a in sq_cur.fetchall():
            cur.execute("""
                INSERT INTO alerts (id, device_mac, device_ip, alert_type, message, severity, is_read, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
            """, (a["id"], a["device_mac"], a["device_ip"], a["alert_type"], a["message"], a["severity"], a["is_read"], a["created_at"]))
        cur.execute("SELECT setval(pg_get_serial_sequence('alerts', 'id'), COALESCE((SELECT MAX(id) FROM alerts), 1))")

        # Migrate agent configs
        sq_cur.execute("SELECT * FROM agent_configs")
        for c in sq_cur.fetchall():
            cur.execute("""
                INSERT INTO agent_configs (agent_id, name, description, category, is_enabled, interval_seconds, last_run, stats_json)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (agent_id) DO UPDATE SET 
                    is_enabled = EXCLUDED.is_enabled,
                    stats_json = EXCLUDED.stats_json
            """, (c["agent_id"], c["name"], c["description"], c["category"], c["is_enabled"], c["interval_seconds"], c["last_run"], c["stats_json"]))

        # Migrate latency history
        sq_cur.execute("SELECT * FROM latency_history")
        for l in sq_cur.fetchall():
            cur.execute("""
                INSERT INTO latency_history (id, gateway_ip, gateway_ms, dns_ms, jitter_ms, packet_loss, timestamp)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
            """, (l["id"], l["gateway_ip"], l["gateway_ms"], l["dns_ms"], l["jitter_ms"], l["packet_loss"], l["timestamp"]))
        cur.execute("SELECT setval(pg_get_serial_sequence('latency_history', 'id'), COALESCE((SELECT MAX(id) FROM latency_history), 1))")

        # Migrate speedtests
        sq_cur.execute("SELECT * FROM speedtests")
        for s in sq_cur.fetchall():
            cur.execute("""
                INSERT INTO speedtests (id, download_mbps, upload_mbps, ping_ms, jitter_ms, server_info, created_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT DO NOTHING
            """, (s["id"], s["download_mbps"], s["upload_mbps"], s["ping_ms"], s["jitter_ms"], s["server_info"], s["created_at"]))
        cur.execute("SELECT setval(pg_get_serial_sequence('speedtests', 'id'), COALESCE((SELECT MAX(id) FROM speedtests), 1))")

        pg_wrapper.commit()
        sq_conn.close()
        print("✅ Migração de SQLite para PostgreSQL concluída com sucesso!")
    except Exception as e:
        print(f"⚠️ Aviso na migração para PostgreSQL: {e}")

def upsert_device(ip, mac, hostname, vendor, device_type="unknown"):
    mac = mac.lower().strip()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
    existing = cursor.fetchone()

    is_new = False
    if existing is None:
        is_new = True
        if conn.is_pg:
            cursor.raw.execute("""
                INSERT INTO devices (ip, mac, hostname, vendor, device_type, status, is_trusted, is_new, last_seen)
                VALUES (%s, %s, %s, %s, %s, 'online', 0, 1, CURRENT_TIMESTAMP)
                RETURNING id
            """, (ip, mac, hostname, vendor, device_type))
            r = cursor.raw.fetchone()
            device_id = r["id"] if isinstance(r, dict) else r[0]
        else:
            cursor.execute("""
                INSERT INTO devices (ip, mac, hostname, vendor, device_type, status, is_trusted, is_new, last_seen)
                VALUES (?, ?, ?, ?, ?, 'online', 0, 1, CURRENT_TIMESTAMP)
            """, (ip, mac, hostname, vendor, device_type))
            device_id = cursor.lastrowid

        cursor.execute("""
            INSERT INTO alerts (device_mac, device_ip, alert_type, message, severity)
            VALUES (?, ?, 'new_device', ?, 'warning')
        """, (mac, ip, f"Novo dispositivo detetado na rede: {ip} ({vendor or 'Desconhecido'})"))
    else:
        device_id = existing["id"]
        new_hostname = hostname if (hostname and hostname != "?") else existing["hostname"]
        new_vendor = vendor if (vendor and vendor != "Desconhecido") else existing["vendor"]
        curr_type = existing["device_type"]
        if curr_type == "unknown" and device_type != "unknown":
            curr_type = device_type

        cursor.execute("""
            UPDATE devices 
            SET ip = ?, hostname = ?, vendor = ?, device_type = ?, status = 'online', last_seen = CURRENT_TIMESTAMP
            WHERE id = ?
        """, (ip, new_hostname, new_vendor, curr_type, device_id))

    conn.commit()
    cursor.execute("SELECT * FROM devices WHERE id = ?", (device_id,))
    device_dict = cursor.fetchone()
    conn.close()
    return device_dict, is_new

def mark_offline_stale_devices(active_macs):
    conn = get_db_connection()
    cursor = conn.cursor()
    if active_macs:
        placeholders = ",".join(["?"] * len(active_macs))
        cursor.execute(f"UPDATE devices SET status = 'offline' WHERE mac NOT IN ({placeholders})", list(active_macs))
    conn.commit()
    conn.close()

def get_all_devices():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY CASE WHEN status = 'online' THEN 0 ELSE 1 END, ip ASC")
    rows = cursor.fetchall()
    devices = []
    for r in rows:
        d = dict(r)
        if isinstance(d.get("open_ports"), str):
            try:
                d["open_ports"] = json.loads(d["open_ports"])
            except Exception:
                d["open_ports"] = []
        devices.append(d)
    conn.close()
    return devices

def update_device_details(device_id, custom_name=None, device_type=None, is_trusted=None, notes=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    fields = []
    values = []
    if custom_name is not None:
        fields.append("custom_name = ?")
        values.append(custom_name)
    if device_type is not None:
        fields.append("device_type = ?")
        values.append(device_type)
    if is_trusted is not None:
        fields.append("is_trusted = ?")
        values.append(1 if is_trusted else 0)
        fields.append("is_new = 0")
    if notes is not None:
        fields.append("notes = ?")
        values.append(notes)
    
    if fields:
        values.append(device_id)
        sql = f"UPDATE devices SET {', '.join(fields)} WHERE id = ?"
        cursor.execute(sql, values)
        conn.commit()
    conn.close()

def update_device_ports(device_id, open_ports_list):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET open_ports = ? WHERE id = ?", (json.dumps(open_ports_list), device_id))
    conn.commit()
    conn.close()

def mark_device_acknowledged(device_id):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE devices SET is_new = 0 WHERE id = ?", (device_id,))
    conn.commit()
    conn.close()

def add_speedtest_result(download, upload, ping, jitter=0.0, server="Cloudflare / Akamai"):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO speedtests (download_mbps, upload_mbps, ping_ms, jitter_ms, server_info)
        VALUES (?, ?, ?, ?, ?)
    """, (download, upload, ping, jitter, server))
    conn.commit()
    conn.close()

def get_recent_speedtests(limit=10):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM speedtests ORDER BY id DESC LIMIT ?", (limit,))
    res = cursor.fetchall()
    conn.close()
    return res

def add_latency_sample(gateway_ip, gateway_ms, dns_ms, jitter_ms, packet_loss=0.0):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO latency_history (gateway_ip, gateway_ms, dns_ms, jitter_ms, packet_loss)
        VALUES (?, ?, ?, ?, ?)
    """, (gateway_ip, gateway_ms, dns_ms, jitter_ms, packet_loss))
    
    # Prune old samples to keep table fast (last 200 records)
    cursor.execute("""
        DELETE FROM latency_history WHERE id NOT IN (
            SELECT id FROM latency_history ORDER BY id DESC LIMIT 200
        )
    """)
    conn.commit()
    conn.close()

def get_recent_latency(limit=30):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM latency_history ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    res = list(reversed(rows))
    conn.close()
    return res

def get_alerts(unread_only=False, limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    if unread_only:
        cursor.execute("SELECT * FROM alerts WHERE is_read = 0 ORDER BY id DESC LIMIT ?", (limit,))
    else:
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    res = cursor.fetchall()
    conn.close()
    return res

def mark_alerts_as_read():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET is_read = 1 WHERE is_read = 0")
    conn.commit()
    conn.close()

def get_agent_configs():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM agent_configs ORDER BY agent_id")
    rows = cursor.fetchall()
    res = []
    for r in rows:
        d = dict(r)
        try:
            d["stats"] = json.loads(d.get("stats_json") or "{}")
        except:
            d["stats"] = {}
        res.append(d)
    conn.close()
    return res

def update_agent_config(agent_id, is_enabled=None, last_run=None, stats=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if is_enabled is not None:
        cursor.execute("UPDATE agent_configs SET is_enabled = ? WHERE agent_id = ?", (1 if is_enabled else 0, agent_id))
    if last_run is not None:
        cursor.execute("UPDATE agent_configs SET last_run = ? WHERE agent_id = ?", (last_run, agent_id))
    if stats is not None:
        cursor.execute("UPDATE agent_configs SET stats_json = ? WHERE agent_id = ?", (json.dumps(stats), agent_id))
    conn.commit()
    conn.close()

def log_agent_activity(agent_id, level, message):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO agent_logs (agent_id, level, message)
        VALUES (?, ?, ?)
    """, (agent_id, level.upper(), message))
    cursor.execute("""
        DELETE FROM agent_logs WHERE id NOT IN (
            SELECT id FROM agent_logs ORDER BY id DESC LIMIT 500
        )
    """)
    conn.commit()
    conn.close()

def get_recent_agent_logs(limit=100, agent_id=None):
    conn = get_db_connection()
    cursor = conn.cursor()
    if agent_id:
        cursor.execute("SELECT * FROM agent_logs WHERE agent_id = ? ORDER BY id DESC LIMIT ?", (agent_id, limit))
    else:
        cursor.execute("SELECT * FROM agent_logs ORDER BY id DESC LIMIT ?", (limit,))
    res = cursor.fetchall()
    conn.close()
    return res
