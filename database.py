"""
NetPulse - SQLite Database Layer
Persists device inventory, categorization, custom aliases, security alerts, and network metrics.
"""

import sqlite3
import os
import json
from datetime import datetime

DATA_DIR = os.environ.get("NETPULSE_DATA_DIR") or os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.environ.get("NETPULSE_DB_PATH") or os.path.join(DATA_DIR, "netpulse.db")

def get_db_connection():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = get_db_connection()
    cursor = conn.cursor()

    # Devices table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS devices (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
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

    # Security & Discovery Alerts
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        device_mac TEXT,
        device_ip TEXT,
        alert_type TEXT NOT NULL,
        message TEXT NOT NULL,
        severity TEXT DEFAULT 'info',
        is_read INTEGER DEFAULT 0,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Speedtest History
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS speedtests (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        download_mbps REAL NOT NULL,
        upload_mbps REAL NOT NULL,
        ping_ms REAL NOT NULL,
        jitter_ms REAL DEFAULT 0.0,
        server_info TEXT DEFAULT 'CDN Fastest',
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Latency History
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS latency_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        gateway_ip TEXT,
        gateway_ms REAL,
        dns_ms REAL,
        jitter_ms REAL,
        packet_loss REAL DEFAULT 0.0,
        timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    """)

    # Autonomous Network Agents Configuration
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

    # Autonomous Network Agents Event & Activity Log
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS agent_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
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
        cursor.execute("""
        INSERT OR IGNORE INTO agent_configs (agent_id, name, description, category, is_enabled, interval_seconds, stats_json)
        VALUES (?, ?, ?, ?, ?, ?, '{}')
        """, (aid, name, desc, cat, enabled, interval))

    conn.commit()
    conn.close()

def upsert_device(ip, mac, hostname, vendor, device_type="unknown"):
    """
    Inserts a newly discovered device or updates an existing one.
    Returns (device_dict, is_new_device).
    """
    mac = mac.lower().strip()
    conn = get_db_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM devices WHERE mac = ?", (mac,))
    existing = cursor.fetchone()

    is_new = False
    if existing is None:
        is_new = True
        cursor.execute("""
            INSERT INTO devices (ip, mac, hostname, vendor, device_type, status, is_trusted, is_new, last_seen)
            VALUES (?, ?, ?, ?, ?, 'online', 0, 1, CURRENT_TIMESTAMP)
        """, (ip, mac, hostname, vendor, device_type))
        device_id = cursor.lastrowid

        # Create security alert for new device
        cursor.execute("""
            INSERT INTO alerts (device_mac, device_ip, alert_type, message, severity)
            VALUES (?, ?, 'new_device', ?, 'warning')
        """, (mac, ip, f"Novo dispositivo detetado na rede: {ip} ({vendor or 'Desconhecido'})"))
    else:
        device_id = existing["id"]
        # Update IP, status, and last seen
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
    row = cursor.fetchone()
    device_dict = dict(row)
    conn.close()
    return device_dict, is_new

def mark_offline_stale_devices(active_macs):
    """Marks devices not seen in the latest active MAC set as offline."""
    conn = get_db_connection()
    cursor = conn.cursor()
    placeholders = ",".join(["?"] * len(active_macs)) if active_macs else "''"
    if active_macs:
        cursor.execute(f"UPDATE devices SET status = 'offline' WHERE mac NOT IN ({placeholders})", list(active_macs))
    conn.commit()
    conn.close()

def get_all_devices():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM devices ORDER BY status ASC, ip ASC")
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
    rows = cursor.fetchall()
    res = [dict(r) for r in rows]
    conn.close()
    return res

def add_latency_sample(gateway_ip, gateway_ms, dns_ms, jitter_ms, packet_loss=0.0):
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO latency_history (gateway_ip, gateway_ms, dns_ms, jitter_ms, packet_loss)
        VALUES (?, ?, ?, ?, ?)
    """, (gateway_ip, gateway_ms, dns_ms, jitter_ms, packet_loss))
    # Keep only last 200 records to prevent table bloating
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
    res = [dict(r) for r in reversed(rows)]
    conn.close()
    return res

def get_alerts(unread_only=False, limit=50):
    conn = get_db_connection()
    cursor = conn.cursor()
    if unread_only:
        cursor.execute("SELECT * FROM alerts WHERE is_read = 0 ORDER BY id DESC LIMIT ?", (limit,))
    else:
        cursor.execute("SELECT * FROM alerts ORDER BY id DESC LIMIT ?", (limit,))
    rows = cursor.fetchall()
    res = [dict(r) for r in rows]
    conn.close()
    return res

def mark_alerts_as_read():
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute("UPDATE alerts SET is_read = 1 WHERE is_read = 0")
    conn.commit()
    conn.close()

# Agent Configuration & Logs Helpers
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
    # Keep only last 500 logs to prevent unbounded table growth
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
    rows = cursor.fetchall()
    res = [dict(r) for r in rows]
    conn.close()
    return res

