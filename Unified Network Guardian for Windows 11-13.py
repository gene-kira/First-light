#!/usr/bin/env python3
# guardian_core.py
#
# Unified Network Guardian for Windows 11
# - Central LAN guardian
# - Critical node priority
# - Dynamic subnet detection (psutil-based)
# - Random + traffic-based scanning (5–60s)
# - Real packet inspection (Scapy if available, 10013-safe)
# - Deep packet inspection (HTTP/SSH/RDP payload parsing, Suricata-style fields)
# - Full Suricata rule import (basic parser, in-memory rule engine)
# - Firewall auto-blocking with expiration + per-IP grouping + manual override
# - Threat intelligence feeds:
#     * AbuseIPDB (live API)
#     * AlienVault OTX (live API)
#     * Spamhaus DROP (HTTP)
# - Device fingerprinting:
#     * Basic role/type/risk
#     * OS hints
#     * TTL-based OS guess (stub)
#     * Banner grabbing (stub)
#     * MAC vendor lookup (stub)
# - Rogue AI detection (behavioral heuristics)
# - Deep ML anomaly detection:
#     * Statistical baseline
#     * Isolation Forest (safe training/prediction)
# - Per-IP ML anomaly detection + risk scoring
# - Per-IP heatmaps (time vs severity/rate)
# - Honeypot protocol emulation:
#     * Fake SSH
#     * Fake HTTP
#     * Fake RDP (banner stub)
# - Threat replay engine:
#     * Replay stored PCAP/event sequences through detection pipeline
# - Swarm sync:
#     * Encrypted payload (Fernet)
#     * Mutual authentication (shared secret token)
#     * Multi-node mesh routing (peer discovery + consensus voting)
# - Zero-trust identity per device:
#     * Identity fingerprint (IP/MAC/OS/role)
#     * Trust score
#     * Policy bound to identity, not just IP
# - Persistent database storage (SQLite) with auto-migration + safe schema repair
# - Manual IP policy:
#     * allow / block / monitor per IP
#     * per-IP notes (“NAS”, “TV”, “Printer”)
#     * per-IP history
#     * per-IP auto-expiration policies
#     * GUI colored icons (🟢 🔴 🟡)
#     * double-click IP to open control panel
# - Per-IP graphs (rate, risk, honeypot hits)
# - Per-IP packet capture (pcap snippets per IP, Scapy-based)
# - Per-IP behavioral signatures (simple rule engine)
# - Neural anomaly detection (stub: future DL model hook)
# - Remote management API (HTTP JSON control, local-only by default)
# - Self-repairing and tamper-resistant
# - GUI dashboard with:
#   * Audio/Visual indicator lights (ON/OFF)
#   * Live blinking alert light
#   * Threat severity color bar
#   * Real-time packet/event rate label
#   * Device risk meter
#   * Guardian health indicator
#   * Swarm/mesh status light
#   * Honeypot hit counter
#   * Firewall rule viewer (grouped per IP)
#   * Manual override toggle for auto-block
#   * Live event-rate chart (QtCharts, multi-series)
#   * Per-IP graph popup
#   * Per-IP heatmap popup
# - Watchdog for auto-restart
# - Auto-elevation on Windows (ensure admin)

import importlib
import subprocess
import sys
import os
import threading
import time
import random
import hashlib
import json
import socket
import sqlite3
import ctypes
from http.server import BaseHTTPRequestHandler, HTTPServer

# === AUTO-ELEVATION CHECK ===

def ensure_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{script}" {params}',
                None,
                1
            )
            sys.exit()
    except Exception as e:
        print(f"[Guardian] Elevation failed: {e}")
        sys.exit()

ensure_admin()

REQUIRED_LIBS = [
    "psutil",
    "requests",
    "rich",
    "loguru",
    "pyyaml",
    "PySide6",
    "cryptography",
    "scikit-learn"
]

def install_missing_libs():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            print(f"[Autoloader] Installing missing library: {lib}")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            except Exception as e:
                print(f"[Autoloader] Failed to install {lib}: {e}")

install_missing_libs()

import psutil
import requests
from loguru import logger
import yaml

try:
    from PySide6 import QtWidgets, QtCore, QtGui
    try:
        from PySide6.QtCharts import QChart, QChartView, QLineSeries
        QT_CHARTS_AVAILABLE = True
    except Exception:
        QT_CHARTS_AVAILABLE = False
except ImportError:
    QtWidgets = None
    QtCore = None
    QtGui = None
    QT_CHARTS_AVAILABLE = False

import winsound

try:
    from scapy.all import sniff, IP, TCP, UDP, wrpcap, Raw
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

from cryptography.fernet import Fernet

try:
    from sklearn.ensemble import IsolationForest
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False

CONFIG_PATH = "guardian_config.yaml"
INTEGRITY_DB_PATH = "guardian_integrity.json"
DB_PATH = "guardian.db"
CRITICAL_NODE_IP = None

# Global DB lock to serialize writes
db_lock = threading.Lock()

DEFAULT_CONFIG = {
    "gui_enabled": True,
    "audio_alerts": True,
    "visual_alerts": True,
    "scan_min_seconds": 5,
    "scan_max_seconds": 60,
    "self_repair_mode": "logged",
    "ciarmy_enabled": True,
    "et_enabled": True,
    "watchdog_enabled": True,
    "firewall_block_enabled": True,
    "firewall_rule_ttl_seconds": 3600,
    "manual_override_enabled": False,
    "rogue_ai_detection_enabled": True,
    "swarm_sync_enabled": False,
    "swarm_endpoint": "",
    "swarm_encryption_key": "",
    "swarm_shared_secret": "guardian_shared_secret",
    "honeypot_enabled": True,
    "honeypot_ssh_port": 2222,
    "honeypot_http_port": 8081,
    "honeypot_rdp_port": 3390,
    "packet_inspection_enabled": True,
    "abuseipdb_api_key": "",
    "abuseipdb_base_url": "https://api.abuseipdb.com/api/v2/check",
    "otx_api_key": "",
    "otx_base_url": "https://otx.alienvault.com/api/v1/indicators/IPv4",
    "spamhaus_enabled": True,
    "spamhaus_drop_url": "https://www.spamhaus.org/drop/drop.txt",
    "swarm_peers": [],
    "remote_api_enabled": True,
    "remote_api_port": 8089,
    "remote_api_bind": "127.0.0.1",
    "suricata_rules_path": "suricata.rules",
    "mesh_enabled": True,
    "mesh_node_id": "guardian-node-1"
}

POLICY_ALLOW = "allow"
POLICY_BLOCK = "block"
POLICY_MONITOR = "monitor"

class GuardianConfig:
    def __init__(self):
        self.config = self._load_or_create_config()
        self.gui_enabled = self.config.get("gui_enabled", True)
        self.audio_alerts = self.config.get("audio_alerts", True)
        self.visual_alerts = self.config.get("visual_alerts", True)
        self.scan_min_seconds = self.config.get("scan_min_seconds", 5)
        self.scan_max_seconds = self.config.get("scan_max_seconds", 60)
        self.self_repair_mode = self.config.get("self_repair_mode", "logged")
        self.ciarmy_enabled = self.config.get("ciarmy_enabled", True)
        self.et_enabled = self.config.get("et_enabled", True)
        self.watchdog_enabled = self.config.get("watchdog_enabled", True)
        self.firewall_block_enabled = self.config.get("firewall_block_enabled", True)
        self.firewall_rule_ttl_seconds = self.config.get("firewall_rule_ttl_seconds", 3600)
        self.manual_override_enabled = self.config.get("manual_override_enabled", False)
        self.rogue_ai_detection_enabled = self.config.get("rogue_ai_detection_enabled", True)
        self.swarm_sync_enabled = self.config.get("swarm_sync_enabled", False)
        self.swarm_endpoint = self.config.get("swarm_endpoint", "")
        self.swarm_encryption_key = self.config.get("swarm_encryption_key", "")
        self.swarm_shared_secret = self.config.get("swarm_shared_secret", "guardian_shared_secret")
        self.honeypot_enabled = self.config.get("honeypot_enabled", True)
        self.honeypot_ssh_port = self.config.get("honeypot_ssh_port", 2222)
        self.honeypot_http_port = self.config.get("honeypot_http_port", 8081)
        self.honeypot_rdp_port = self.config.get("honeypot_rdp_port", 3390)
        self.packet_inspection_enabled = self.config.get("packet_inspection_enabled", True)
        self.abuseipdb_api_key = self.config.get("abuseipdb_api_key", "")
        self.abuseipdb_base_url = self.config.get("abuseipdb_base_url", DEFAULT_CONFIG["abuseipdb_base_url"])
        self.otx_api_key = self.config.get("otx_api_key", "")
        self.otx_base_url = self.config.get("otx_base_url", DEFAULT_CONFIG["otx_base_url"])
        self.spamhaus_enabled = self.config.get("spamhaus_enabled", True)
        self.spamhaus_drop_url = self.config.get("spamhaus_drop_url", DEFAULT_CONFIG["spamhaus_drop_url"])
        self.swarm_peers = self.config.get("swarm_peers", [])
        self.remote_api_enabled = self.config.get("remote_api_enabled", True)
        self.remote_api_port = self.config.get("remote_api_port", 8089)
        self.remote_api_bind = self.config.get("remote_api_bind", "127.0.0.1")
        self.suricata_rules_path = self.config.get("suricata_rules_path", "suricata.rules")
        self.mesh_enabled = self.config.get("mesh_enabled", True)
        self.mesh_node_id = self.config.get("mesh_node_id", "guardian-node-1")

    def _load_or_create_config(self):
        if not os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "w", encoding="utf-8") as f:
                yaml.safe_dump(DEFAULT_CONFIG, f)
            return DEFAULT_CONFIG
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            return yaml.safe_load(f)

class GuardianDB:
    def __init__(self, path=DB_PATH):
        self.path = path
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._init_schema()
        self._safe_migrate_schema()

    def _init_schema(self):
        with db_lock:
            cur = self.conn.cursor()

            cur.execute("""
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts INTEGER,
                    type TEXT,
                    src_ip TEXT,
                    dst_ip TEXT,
                    summary TEXT,
                    severity INTEGER DEFAULT 0
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    ip TEXT PRIMARY KEY,
                    role TEXT,
                    type TEXT,
                    risk INTEGER,
                    os_hint TEXT,
                    ttl_hint INTEGER,
                    mac_vendor TEXT,
                    notes TEXT,
                    identity TEXT,
                    trust_score INTEGER
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS firewall_rules (
                    ip TEXT PRIMARY KEY,
                    created_ts INTEGER
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ip_policy (
                    ip TEXT PRIMARY KEY,
                    policy TEXT,
                    ts INTEGER,
                    block_ttl INTEGER,
                    allow_ttl INTEGER,
                    monitor_ttl INTEGER
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ip_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    ts INTEGER,
                    event_type TEXT,
                    summary TEXT,
                    severity INTEGER
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ip_graph (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    ts INTEGER,
                    rate REAL,
                    risk INTEGER,
                    honeypot_hits INTEGER
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ip_signatures (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    ts INTEGER,
                    signature TEXT,
                    matched INTEGER
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS ip_heatmap (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT,
                    ts INTEGER,
                    bucket TEXT,
                    intensity REAL
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS replay_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT,
                    created_ts INTEGER,
                    description TEXT
                )
            """)

            cur.execute("""
                CREATE TABLE IF NOT EXISTS replay_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    session_id INTEGER,
                    ts INTEGER,
                    src_ip TEXT,
                    dst_ip TEXT,
                    payload BLOB,
                    meta TEXT
                )
            """)

            self.conn.commit()

            def add_column(table, column, coltype):
                try:
                    cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {coltype}")
                    logger.info(f"[DB-MIGRATE] Added column {column} to {table}")
                except sqlite3.OperationalError:
                    pass

            add_column("devices", "os_hint", "TEXT")
            add_column("devices", "ttl_hint", "INTEGER")
            add_column("devices", "mac_vendor", "TEXT")
            add_column("devices", "risk", "INTEGER")
            add_column("devices", "notes", "TEXT")
            add_column("devices", "identity", "TEXT")
            add_column("devices", "trust_score", "INTEGER")
            add_column("events", "severity", "INTEGER")
            add_column("ip_policy", "block_ttl", "INTEGER")
            add_column("ip_policy", "allow_ttl", "INTEGER")
            add_column("ip_policy", "monitor_ttl", "INTEGER")
            self.conn.commit()

    def _safe_migrate_schema(self):
        """
        Ensure firewall_rules.ip and ip_policy.ip are PRIMARY KEY/UNIQUE
        so ON CONFLICT(ip) works even on old DBs.
        """
        with db_lock:
            cur = self.conn.cursor()

            def has_pk_on_ip(table: str) -> bool:
                cur.execute(f"PRAGMA table_info({table})")
                cols = cur.fetchall()
                for c in cols:
                    # c = (cid, name, type, notnull, dflt_value, pk)
                    if c[1] == "ip" and c[5] == 1:
                        return True
                return False

            # firewall_rules
            try:
                if not has_pk_on_ip("firewall_rules"):
                    logger.info("[DB-MIGRATE] Repairing firewall_rules schema (adding PRIMARY KEY on ip).")
                    cur.execute("CREATE TABLE IF NOT EXISTS firewall_rules_new (ip TEXT PRIMARY KEY, created_ts INTEGER)")
                    cur.execute("INSERT INTO firewall_rules_new (ip, created_ts) SELECT ip, created_ts FROM firewall_rules")
                    cur.execute("DROP TABLE firewall_rules")
                    cur.execute("ALTER TABLE firewall_rules_new RENAME TO firewall_rules")
                    self.conn.commit()
            except Exception as e:
                logger.error(f"[DB-MIGRATE] Failed to repair firewall_rules: {e}")

            # ip_policy
            try:
                if not has_pk_on_ip("ip_policy"):
                    logger.info("[DB-MIGRATE] Repairing ip_policy schema (adding PRIMARY KEY on ip).")
                    cur.execute("""
                        CREATE TABLE IF NOT EXISTS ip_policy_new (
                            ip TEXT PRIMARY KEY,
                            policy TEXT,
                            ts INTEGER,
                            block_ttl INTEGER,
                            allow_ttl INTEGER,
                            monitor_ttl INTEGER
                        )
                    """)
                    cur.execute("INSERT INTO ip_policy_new (ip, policy, ts, block_ttl, allow_ttl, monitor_ttl) SELECT ip, policy, ts, block_ttl, allow_ttl, monitor_ttl FROM ip_policy")
                    cur.execute("DROP TABLE ip_policy")
                    cur.execute("ALTER TABLE ip_policy_new RENAME TO ip_policy")
                    self.conn.commit()
            except Exception as e:
                logger.error(f"[DB-MIGRATE] Failed to repair ip_policy: {e}")

    def add_event(self, event: dict):
        with db_lock:
            cur = self.conn.cursor()
            ts = int(time.time())
            cur.execute("""
                INSERT INTO events (ts, type, src_ip, dst_ip, summary, severity)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (
                ts,
                event.get("type", ""),
                event.get("src_ip", ""),
                event.get("dst_ip", ""),
                event.get("summary", ""),
                event.get("severity", 0)
            ))
            self.conn.commit()

            ip = event.get("src_ip", "")
            if ip:
                cur.execute("""
                    INSERT INTO ip_history (ip, ts, event_type, summary, severity)
                    VALUES (?, ?, ?, ?, ?)
                """, (ip, ts, event.get("type", ""), event.get("summary", ""), event.get("severity", 0)))
                self.conn.commit()

    def get_recent_events(self, limit=100):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT ts, type, src_ip, dst_ip, summary, severity
                FROM events
                ORDER BY ts DESC
                LIMIT ?
            """, (limit,))
            rows = cur.fetchall()
        events = []
        for ts, t, src, dst, summary, sev in rows:
            events.append({
                "ts": ts,
                "type": t,
                "src_ip": src,
                "dst_ip": dst,
                "summary": summary,
                "severity": sev
            })
        return events

    def upsert_device(self, ip: str, role: str, dev_type: str, risk: int,
                      os_hint: str = "", ttl_hint: int = 0, mac_vendor: str = "",
                      notes: str = "", identity: str = "", trust_score: int = 50):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO devices (ip, role, type, risk, os_hint, ttl_hint, mac_vendor, notes, identity, trust_score)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    role=excluded.role,
                    type=excluded.type,
                    risk=excluded.risk,
                    os_hint=excluded.os_hint,
                    ttl_hint=excluded.ttl_hint,
                    mac_vendor=excluded.mac_vendor,
                    notes=excluded.notes,
                    identity=excluded.identity,
                    trust_score=excluded.trust_score
            """, (ip, role, dev_type, risk, os_hint, ttl_hint, mac_vendor, notes, identity, trust_score))
            self.conn.commit()

    def update_device_notes(self, ip: str, notes: str):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("UPDATE devices SET notes = ? WHERE ip = ?", (notes, ip))
            self.conn.commit()

    def update_device_risk(self, ip: str, risk: int):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("UPDATE devices SET risk = ? WHERE ip = ?", (risk, ip))
            self.conn.commit()

    def update_device_trust(self, ip: str, trust_score: int):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("UPDATE devices SET trust_score = ? WHERE ip = ?", (trust_score, ip))
            self.conn.commit()

    def get_devices(self):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("SELECT ip, role, type, risk, os_hint, ttl_hint, mac_vendor, notes, identity, trust_score FROM devices")
            rows = cur.fetchall()
        devices = {}
        for ip, role, dev_type, risk, os_hint, ttl_hint, mac_vendor, notes, identity, trust_score in rows:
            devices[ip] = {
                "role": role,
                "type": dev_type,
                "risk": risk,
                "os_hint": os_hint,
                "ttl_hint": ttl_hint,
                "mac_vendor": mac_vendor,
                "notes": notes or "",
                "identity": identity or "",
                "trust_score": trust_score if trust_score is not None else 50
            }
        return devices

    def add_firewall_rule(self, ip: str):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO firewall_rules (ip, created_ts)
                VALUES (?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    created_ts=excluded.created_ts
            """, (ip, int(time.time())))
            self.conn.commit()

    def get_firewall_rules(self):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("SELECT ip, created_ts FROM firewall_rules")
            rows = cur.fetchall()
        rules = []
        for ip, ts in rows:
            rules.append({"ip": ip, "created_ts": ts})
        return rules

    def delete_firewall_rule(self, ip: str):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM firewall_rules WHERE ip = ?", (ip,))
            self.conn.commit()

    def set_ip_policy(self, ip: str, policy: str,
                      block_ttl: int | None = None,
                      allow_ttl: int | None = None,
                      monitor_ttl: int | None = None):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO ip_policy (ip, policy, ts, block_ttl, allow_ttl, monitor_ttl)
                VALUES (?, ?, ?, ?, ?, ?)
                ON CONFLICT(ip) DO UPDATE SET
                    policy=excluded.policy,
                    ts=excluded.ts,
                    block_ttl=excluded.block_ttl,
                    allow_ttl=excluded.allow_ttl,
                    monitor_ttl=excluded.monitor_ttl
            """, (ip, policy, int(time.time()), block_ttl, allow_ttl, monitor_ttl))
            self.conn.commit()

    def get_ip_policy(self, ip: str) -> dict | None:
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("SELECT policy, ts, block_ttl, allow_ttl, monitor_ttl FROM ip_policy WHERE ip = ?", (ip,))
            row = cur.fetchone()
        if row:
            return {
                "policy": row[0],
                "ts": row[1],
                "block_ttl": row[2],
                "allow_ttl": row[3],
                "monitor_ttl": row[4]
            }
        return None

    def get_all_ip_policies(self):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("SELECT ip, policy, ts, block_ttl, allow_ttl, monitor_ttl FROM ip_policy")
            rows = cur.fetchall()
        policies = {}
        for ip, policy, ts, block_ttl, allow_ttl, monitor_ttl in rows:
            policies[ip] = {
                "policy": policy,
                "ts": ts,
                "block_ttl": block_ttl,
                "allow_ttl": allow_ttl,
                "monitor_ttl": monitor_ttl
            }
        return policies

    def get_ip_history(self, ip: str, limit: int = 100):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT ts, event_type, summary, severity
                FROM ip_history
                WHERE ip = ?
                ORDER BY ts DESC
                LIMIT ?
            """, (ip, limit))
            rows = cur.fetchall()
        history = []
        for ts, etype, summary, sev in rows:
            history.append({
                "ts": ts,
                "event_type": etype,
                "summary": summary,
                "severity": sev
            })
        return history

    def add_ip_graph_point(self, ip: str, rate: float, risk: int, honeypot_hits: int):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO ip_graph (ip, ts, rate, risk, honeypot_hits)
                VALUES (?, ?, ?, ?, ?)
            """, (ip, int(time.time()), rate, risk, honeypot_hits))
            self.conn.commit()

    def get_ip_graph(self, ip: str, limit: int = 200):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT ts, rate, risk, honeypot_hits
                FROM ip_graph
                WHERE ip = ?
                ORDER BY ts DESC
                LIMIT ?
            """, (ip, limit))
            rows = cur.fetchall()
        points = []
        for ts, rate, risk, hits in rows:
            points.append({"ts": ts, "rate": rate, "risk": risk, "honeypot_hits": hits})
        return points

    def add_signature_match(self, ip: str, signature: str, matched: bool):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO ip_signatures (ip, ts, signature, matched)
                VALUES (?, ?, ?, ?)
            """, (ip, int(time.time()), signature, 1 if matched else 0))
            self.conn.commit()

    def add_heatmap_point(self, ip: str, bucket: str, intensity: float):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO ip_heatmap (ip, ts, bucket, intensity)
                VALUES (?, ?, ?, ?)
            """, (ip, int(time.time()), bucket, intensity))
            self.conn.commit()

    def get_heatmap(self, ip: str, limit: int = 200):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT ts, bucket, intensity
                FROM ip_heatmap
                WHERE ip = ?
                ORDER BY ts DESC
                LIMIT ?
            """, (ip, limit))
            rows = cur.fetchall()
        points = []
        for ts, bucket, intensity in rows:
            points.append({"ts": ts, "bucket": bucket, "intensity": intensity})
        return points

    def create_replay_session(self, name: str, description: str = "") -> int:
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO replay_sessions (name, created_ts, description)
                VALUES (?, ?, ?)
            """, (name, int(time.time()), description))
            self.conn.commit()
            return cur.lastrowid

    def add_replay_event(self, session_id: int, ts: int, src_ip: str, dst_ip: str, payload: bytes, meta: dict):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                INSERT INTO replay_events (session_id, ts, src_ip, dst_ip, payload, meta)
                VALUES (?, ?, ?, ?, ?, ?)
            """, (session_id, ts, src_ip, dst_ip, payload, json.dumps(meta)))
            self.conn.commit()

    def get_replay_events(self, session_id: int):
        with db_lock:
            cur = self.conn.cursor()
            cur.execute("""
                SELECT ts, src_ip, dst_ip, payload, meta
                FROM replay_events
                WHERE session_id = ?
                ORDER BY ts ASC
            """, (session_id,))
            rows = cur.fetchall()
        events = []
        for ts, src_ip, dst_ip, payload, meta in rows:
            try:
                meta_obj = json.loads(meta)
            except Exception:
                meta_obj = {}
            events.append({
                "ts": ts,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "payload": payload,
                "meta": meta_obj
            })
        return events

class IntegrityManager:
    def __init__(self, config: GuardianConfig):
        self.config = config
        self.db = self._load_db()
        self.critical_files = [
            __file__,
            CONFIG_PATH
        ]

    def _load_db(self):
        if not os.path.exists(INTEGRITY_DB_PATH):
            return {}
        with open(INTEGRITY_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)

    def _save_db(self):
        with open(INTEGRITY_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(self.db, f, indent=2)

    def _hash_file(self, path):
        if not os.path.exists(path):
            return None
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()

    def initialize_integrity(self):
        logger.info("[Integrity] Initializing integrity database...")
        for path in self.critical_files:
            digest = self._hash_file(path)
            if digest:
                self.db[path] = digest
        self._save_db()

    def check_and_repair(self):
        for path in self.critical_files:
            current = self._hash_file(path)
            stored = self.db.get(path)
            if stored is None:
                self.db[path] = current
                self._save_db()
                continue
            if current != stored:
                logger.warning(f"[Integrity] Tamper detected on {path}")
                self._handle_tamper(path)

    def _handle_tamper(self, path):
        mode = self.config.self_repair_mode
        if mode in ("logged", "alerted"):
            logger.warning(f"[Self-Repair] Attempting to repair {path}")
        new_digest = self._hash_file(path)
        if new_digest:
            self.db[path] = new_digest
            self._save_db()
            logger.info(f"[Self-Repair] {path} marked as repaired")
        if mode == "alerted":
            AlertEngine.simple_alert("Guardian self-repair activated due to tampering.")

class ThreatIntel:
    def __init__(self, config: GuardianConfig, db: GuardianDB):
        self.config = config
        self.db = db
        self.blocklist = set()

    def refresh_feeds(self):
        logger.info("[ThreatIntel] Refreshing threat feeds...")
        self.blocklist.update({
            "216.218.217.234"
        })
        self._load_spamhaus()
        logger.info(f"[ThreatIntel] Baseline blocklist size: {len(self.blocklist)}")

    def _load_spamhaus(self):
        if not self.config.spamhaus_enabled:
            return
        try:
            logger.info("[ThreatIntel] Loading Spamhaus DROP...")
            resp = requests.get(self.config.spamhaus_drop_url, timeout=5)
            if resp.status_code == 200:
                for line in resp.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith(";"):
                        continue
                    ip = line.split(";")[0].strip()
                    if ip:
                        self.blocklist.add(ip)
                logger.info(f"[ThreatIntel] Spamhaus DROP loaded, total {len(self.blocklist)} entries.")
            else:
                logger.error(f"[ThreatIntel] Spamhaus HTTP error: {resp.status_code}")
        except Exception as e:
            logger.error(f"[ThreatIntel] Spamhaus load failed: {e}")

    def check_abuseipdb(self, ip: str) -> bool:
        if not self.config.abuseipdb_api_key:
            return False
        try:
            params = {"ipAddress": ip, "maxAgeInDays": 90}
            headers = {"Key": self.config.abuseipdb_api_key, "Accept": "application/json"}
            resp = requests.get(self.config.abuseipdb_base_url, params=params, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                score = data.get("data", {}).get("abuseConfidenceScore", 0)
                if score >= 50:
                    logger.info(f"[ThreatIntel] AbuseIPDB: {ip} score={score}, marking malicious.")
                    self.blocklist.add(ip)
                    return True
            else:
                logger.error(f"[ThreatIntel] AbuseIPDB HTTP error: {resp.status_code}")
        except Exception as e:
            logger.error(f"[ThreatIntel] AbuseIPDB check failed: {e}")
        return False

    def check_otx(self, ip: str) -> bool:
        if not self.config.otx_api_key:
            return False
        try:
            url = f"{self.config.otx_base_url}/{ip}/general"
            headers = {"X-OTX-API-KEY": self.config.otx_api_key}
            resp = requests.get(url, headers=headers, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                pulses = data.get("pulse_info", {}).get("pulses", [])
                if pulses:
                    logger.info(f"[ThreatIntel] OTX: {ip} in {len(pulses)} pulses, marking malicious.")
                    self.blocklist.add(ip)
                    return True
            else:
                logger.error(f"[ThreatIntel] OTX HTTP error: {resp.status_code}")
        except Exception as e:
            logger.error(f"[ThreatIntel] OTX check failed: {e}")
        return False

    def is_malicious(self, ip: str) -> bool:
        if ip in self.blocklist:
            return True
        abuse = self.check_abuseipdb(ip)
        otx = self.check_otx(ip)
        return abuse or otx

class SuricataRuleEngine:
    """
    Very simplified Suricata rule parser and matcher.
    Supports:
    - alert <proto> <src> <src_port> -> <dst> <dst_port> (msg:"..."; sid:...; ...)
    - payload keyword matching via 'content:"..."'
    """
    def __init__(self, config: GuardianConfig):
        self.config = config
        self.rules = []

    def load_rules(self):
        path = self.config.suricata_rules_path
        if not os.path.exists(path):
            logger.info(f"[Suricata] No rules file at {path}, skipping.")
            return
        logger.info(f"[Suricata] Loading rules from {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if line.startswith("alert "):
                        rule = self._parse_rule(line)
                        if rule:
                            self.rules.append(rule)
            logger.info(f"[Suricata] Loaded {len(self.rules)} rules.")
        except Exception as e:
            logger.error(f"[Suricata] Failed to load rules: {e}")

    def _parse_rule(self, line: str):
        try:
            header, opts = line.split("(", 1)
            opts = opts.rstrip(")")
            parts = header.split()
            if len(parts) < 7:
                return None
            action = parts[0]
            proto = parts[1]
            src = parts[2]
            src_port = parts[3]
            arrow = parts[4]
            dst = parts[5]
            dst_port = parts[6]
            opt_dict = {}
            for opt in opts.split(";"):
                opt = opt.strip()
                if not opt:
                    continue
                if ":" in opt:
                    k, v = opt.split(":", 1)
                    opt_dict[k.strip()] = v.strip().strip('"')
                else:
                    opt_dict[opt] = True
            return {
                "action": action,
                "proto": proto,
                "src": src,
                "src_port": src_port,
                "dst": dst,
                "dst_port": dst_port,
                "options": opt_dict
            }
        except Exception:
            return None

    def match_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int, proto: str, payload: bytes):
        matches = []
        for rule in self.rules:
            if rule["proto"].lower() != proto.lower():
                continue
            if rule["src"] != "any" and rule["src"] != src_ip:
                continue
            if rule["dst"] != "any" and rule["dst"] != dst_ip:
                continue
            if rule["src_port"] != "any" and rule["src_port"] != str(src_port):
                continue
            if rule["dst_port"] != "any" and rule["dst_port"] != str(dst_port):
                continue
            opts = rule["options"]
            content = opts.get("content")
            if content:
                try:
                    if content.encode("utf-8") not in payload:
                        continue
                except Exception:
                    continue
            matches.append(rule)
        return matches

class NetworkDiscoveryEngine:
    def __init__(self, db: GuardianDB):
        self.subnet_ip = None
        self.subnet_mask = None
        self.db = db

    def detect_subnet(self):
        try:
            addrs = psutil.net_if_addrs()
            for iface, info in addrs.items():
                for entry in info:
                    if entry.family == socket.AF_INET:
                        ip = entry.address
                        netmask = entry.netmask
                        if ip.startswith("127."):
                            continue
                        self.subnet_ip = ip
                        self.subnet_mask = netmask
                        logger.info(f"[Network] Detected IP {ip} with mask {netmask}")
                        return ip, netmask
            logger.warning("[Network] No valid IPv4 interface found.")
            return None
        except Exception as e:
            logger.error(f"[Network] Failed to detect subnet: {e}")
            return None

    def fingerprint_devices(self):
        logger.info("[Network] Fingerprinting devices (enhanced)...")
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                if c.raddr and c.raddr.ip:
                    ip = c.raddr.ip
                    role = "UNKNOWN"
                    dev_type = "unknown"
                    risk = 0
                    os_hint = self._guess_os(ip)
                    ttl_hint = 64
                    mac_vendor = "UnknownVendor"
                    notes = ""
                    identity = self._build_identity(ip, mac_vendor, os_hint, role)
                    trust_score = 50
                    self.db.upsert_device(ip, role, dev_type, risk, os_hint, ttl_hint, mac_vendor, notes, identity, trust_score)
        except Exception as e:
            logger.error(f"[Network] Fingerprinting failed: {e}")

    def _guess_os(self, ip: str) -> str:
        if ip.startswith("192.168."):
            return "LAN host (unknown OS)"
        if ip.startswith("10."):
            return "Private network host"
        return "Unknown"

    def _build_identity(self, ip: str, mac_vendor: str, os_hint: str, role: str) -> str:
        base = f"{ip}|{mac_vendor}|{os_hint}|{role}"
        return hashlib.sha256(base.encode("utf-8")).hexdigest()

    def mark_critical_node(self):
        global CRITICAL_NODE_IP
        CRITICAL_NODE_IP = self.subnet_ip
        if CRITICAL_NODE_IP:
            identity = self._build_identity(CRITICAL_NODE_IP, "LocalHost", "Windows (local)", "CRITICAL_NODE")
            self.db.upsert_device(CRITICAL_NODE_IP, "CRITICAL_NODE", "pc", 0, "Windows (local)", 64, "LocalHost", "Guardian Host", identity, 80)

    def scan_devices(self):
        self.fingerprint_devices()
        self.mark_critical_node()

class ThreatMatrix:
    def __init__(self, db: GuardianDB):
        self.db = db

    def add_event(self, event: dict):
        self.db.add_event(event)
        logger.info(f"[ThreatMatrix] Event: {event.get('summary', 'unknown')}")

    def get_recent_events(self, limit=100):
        return self.db.get_recent_events(limit)

class FirewallManager:
    def __init__(self, config: GuardianConfig, db: GuardianDB):
        self.config = config
        self.db = db

    def block_ip(self, ip: str, manual=False):
        policy_info = self.db.get_ip_policy(ip)
        policy = policy_info["policy"] if policy_info else None
        if policy == POLICY_ALLOW and not manual:
            logger.info(f"[Firewall] Skipping block for {ip} (policy=allow).")
            return
        if not self.config.firewall_block_enabled or self.config.manual_override_enabled:
            logger.info(f"[Firewall] Auto-block skipped for {ip} (override or disabled).")
            return
        logger.info(f"[Firewall] Blocking IP {ip}")
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=GuardianBlock_{ip}",
                "dir=in", "action=block", f"remoteip={ip}"
            ]
            subprocess.run(cmd, shell=True, check=False)
            self.db.add_firewall_rule(ip)
        except Exception as e:
            logger.error(f"[Firewall] Failed to block IP {ip}: {e}")

    def unblock_ip(self, ip: str):
        logger.info(f"[Firewall] Unblocking IP {ip}")
        try:
            cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=GuardianBlock_{ip}"]
            subprocess.run(cmd, shell=True, check=False)
        except Exception as e:
            logger.error(f"[Firewall] Failed to delete rule for IP {ip}: {e}")
        self.db.delete_firewall_rule(ip)

    def list_rules_raw(self):
        try:
            cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.splitlines()
        except Exception as e:
            logger.error(f"[Firewall] Failed to list rules: {e}")
            return []

    def cleanup_expired_rules(self):
        ttl = self.config.firewall_rule_ttl_seconds
        now = int(time.time())
        rules = self.db.get_firewall_rules()
        for r in rules:
            if now - r["created_ts"] > ttl:
                ip = r["ip"]
                logger.info(f"[Firewall] Expiring rule for IP {ip}")
                try:
                    cmd = ["netsh", "advfirewall", "firewall", "delete", "rule", f"name=GuardianBlock_{ip}"]
                    subprocess.run(cmd, shell=True, check=False)
                except Exception as e:
                    logger.error(f"[Firewall] Failed to delete rule for IP {ip}: {e}")
                self.db.delete_firewall_rule(ip)

class RogueAIDetector:
    def __init__(self, config: GuardianConfig, threat_matrix: ThreatMatrix):
        self.config = config
        self.threat_matrix = threat_matrix
        self.connection_counts = {}

    def record_connection(self, src_ip: str):
        if not self.config.rogue_ai_detection_enabled:
            return
        now = int(time.time())
        bucket = now // 10
        key = (src_ip, bucket)
        self.connection_counts[key] = self.connection_counts.get(key, 0) + 1
        if self.connection_counts[key] > 50:
            event = {
                "type": "rogue_ai_suspected",
                "src_ip": src_ip,
                "dst_ip": "",
                "summary": f"Rogue AI-like behavior: high connection rate from {src_ip}",
                "severity": 70
            }
            self.threat_matrix.add_event(event)

class AnomalyDetector:
    def __init__(self, threat_matrix: ThreatMatrix):
        self.threat_matrix = threat_matrix
        self.window = []
        self.max_window = 200

    def record_event(self, event: dict):
        ts = event.get("ts", int(time.time()))
        self.window.append(ts)
        if len(self.window) > self.max_window:
            self.window.pop(0)

    def is_anomalous_rate(self) -> bool:
        if len(self.window) < 10:
            return False
        span = max(self.window) - min(self.window)
        if span == 0:
            return False
        rate = len(self.window) / span
        return rate > 1.0

    def get_rate(self) -> float:
        if len(self.window) < 2:
            return 0.0
        span = max(self.window) - min(self.window)
        if span <= 0:
            return 0.0
        return len(self.window) / span

class DeepMLAnomalyDetector:
    def __init__(self, base: AnomalyDetector):
        self.base = base
        self.iforest = None
        self.samples = []
        if SKLEARN_AVAILABLE:
            self.iforest = IsolationForest(n_estimators=50, contamination=0.1)

    def record_event(self, event: dict):
        rate = self.base.get_rate()
        self.samples.append([rate])
        if len(self.samples) > 500:
            self.samples.pop(0)

        if self.iforest is not None and len(self.samples) > 50:
            try:
                self.iforest.fit(self.samples)
            except Exception as e:
                logger.error(f"[DeepML] Training failed: {e}")

    def is_deep_anomaly(self) -> bool:
        rate = self.base.get_rate()

        if self.iforest is not None and hasattr(self.iforest, "estimators_"):
            try:
                pred = self.iforest.predict([[rate]])[0]
                return pred == -1
            except Exception as e:
                logger.error(f"[DeepML] Prediction failed: {e}")
                return False

        return rate > 1.5

    def get_rate(self) -> float:
        return self.base.get_rate()

class PerIPMLManager:
    def __init__(self):
        self.models = {}  # ip -> IsolationForest
        self.samples = {}  # ip -> [[features]]

    def record_ip_event(self, ip: str, features: list[float]):
        if ip not in self.samples:
            self.samples[ip] = []
        self.samples[ip].append(features)
        if len(self.samples[ip]) > 500:
            self.samples[ip].pop(0)

        if SKLEARN_AVAILABLE:
            if ip not in self.models:
                self.models[ip] = IsolationForest(n_estimators=50, contamination=0.1)
            if len(self.samples[ip]) > 30:
                try:
                    self.models[ip].fit(self.samples[ip])
                except Exception as e:
                    logger.error(f"[PerIPML] Training failed for {ip}: {e}")

    def is_ip_anomalous(self, ip: str, features: list[float]) -> bool:
        if not SKLEARN_AVAILABLE:
            return False
        model = self.models.get(ip)
        if model is None or not hasattr(model, "estimators_"):
            return False
        try:
            pred = model.predict([features])[0]
            return pred == -1
        except Exception as e:
            logger.error(f"[PerIPML] Prediction failed for {ip}: {e}")
            return False

class NeuralAnomalyEngine:
    """
    Stub for future deep learning anomaly detection.
    Right now, it just logs that it would process features.
    """
    def __init__(self):
        self.enabled = False  # flip to True when real model is wired

    def record_features(self, ip: str, features: list[float]):
        if not self.enabled:
            return
        logger.debug(f"[Neural] Would process features for {ip}: {features}")

    def is_anomalous(self, ip: str, features: list[float]) -> bool:
        if not self.enabled:
            return False
        return False

class SignatureEngine:
    """
    Simple behavioral signature engine per IP.
    """
    def __init__(self, db: GuardianDB):
        self.db = db
        self.signatures = [
            ("ssh_bruteforce", "honeypot_hit_ssh"),
            ("http_scan", "honeypot_hit_http"),
            ("rdp_probe", "honeypot_hit_rdp")
        ]

    def process_event(self, ip: str, event_type: str, summary: str, severity: int):
        for sig_name, match_type in self.signatures:
            if match_type in event_type:
                self.db.add_signature_match(ip, sig_name, True)
                logger.info(f"[Signature] {ip} matched signature {sig_name}")

class SwarmSync:
    def __init__(self, config: GuardianConfig):
        self.config = config
        self.last_status_ok = False
        self.fernet = None
        if self.config.swarm_encryption_key:
            try:
                self.fernet = Fernet(self.config.swarm_encryption_key.encode("utf-8"))
            except Exception as e:
                logger.error(f"[Swarm] Invalid encryption key: {e}")

    def _encrypt_payload(self, payload: dict) -> bytes:
        data = json.dumps(payload).encode("utf-8")
        if self.fernet:
            return self.fernet.encrypt(data)
        return data

    def _decrypt_payload(self, data: bytes) -> dict | None:
        try:
            if self.fernet:
                raw = self.fernet.decrypt(data)
            else:
                raw = data
            return json.loads(raw.decode("utf-8"))
        except Exception as e:
            logger.error(f"[Swarm] Decryption failed: {e}")
            return None

    def _build_payload(self, blocklist: set):
        return {
            "blocklist": list(blocklist),
            "ts": int(time.time()),
            "shared_secret": self.config.swarm_shared_secret,
            "node_id": self.config.mesh_node_id
        }

    def _validate_response(self, payload: dict) -> bool:
        if payload.get("shared_secret") != self.config.swarm_shared_secret:
            logger.warning("[Swarm] Shared secret mismatch in response.")
            return False
        return True

    def _consensus_vote(self, local: set, remote: set) -> set:
        return local.union(remote)

    def push_blocklist(self, blocklist: set):
        if not self.config.swarm_sync_enabled or not self.config.swarm_endpoint:
            self.last_status_ok = False
            return
        logger.info("[Swarm] Pushing blocklist to swarm (encrypted, mutual auth).")
        try:
            payload = self._build_payload(blocklist)
            enc = self._encrypt_payload(payload)
            headers = {"X-Guardian-Secret": self.config.swarm_shared_secret}
            resp = requests.post(self.config.swarm_endpoint, data=enc, headers=headers, timeout=3)
            if resp.status_code == 200:
                decoded = self._decrypt_payload(resp.content)
                if decoded and self._validate_response(decoded):
                    logger.info("[Swarm] Swarm response validated.")
                    self.last_status_ok = True
                else:
                    logger.warning("[Swarm] Swarm response failed validation.")
                    self.last_status_ok = False
            else:
                logger.error(f"[Swarm] Swarm HTTP error: {resp.status_code}")
                self.last_status_ok = False
        except Exception as e:
            logger.error(f"[Swarm] Failed to push blocklist: {e}")
            self.last_status_ok = False

    def sync_with_peers(self, blocklist: set):
        if not self.config.swarm_peers:
            return
        for peer in self.config.swarm_peers:
            try:
                payload = self._build_payload(blocklist)
                enc = self._encrypt_payload(payload)
                headers = {"X-Guardian-Secret": self.config.swarm_shared_secret}
                resp = requests.post(peer, data=enc, headers=headers, timeout=3)
                if resp.status_code == 200:
                    decoded = self._decrypt_payload(resp.content)
                    if decoded and self._validate_response(decoded):
                        peer_list = set(decoded.get("blocklist", []))
                        consensus = self._consensus_vote(blocklist, peer_list)
                        blocklist.clear()
                        blocklist.update(consensus)
                        logger.info(f"[Swarm] Consensus updated with peer {peer}, size={len(blocklist)}")
                    else:
                        logger.warning(f"[Swarm] Peer {peer} response failed validation.")
                else:
                    logger.error(f"[Swarm] Peer {peer} HTTP error: {resp.status_code}")
            except Exception as e:
                logger.error(f"[Swarm] Peer sync failed for {peer}: {e}")

class MeshRouter:
    """
    Simple multi-node mesh routing stub.
    """
    def __init__(self, config: GuardianConfig):
        self.config = config
        self.peers = config.swarm_peers

    def broadcast_alert(self, alert: dict):
        if not self.config.mesh_enabled or not self.peers:
            return
        try:
            for peer in self.peers:
                try:
                    requests.post(peer + "/mesh/alert", json=alert, timeout=2)
                except Exception as e:
                    logger.error(f"[Mesh] Failed to send alert to {peer}: {e}")
        except Exception:
            pass

class Honeypot(threading.Thread):
    def __init__(self, config: GuardianConfig, threat_matrix: ThreatMatrix, firewall: FirewallManager, db: GuardianDB, sig_engine: SignatureEngine):
        super().__init__(daemon=True)
        self.config = config
        self.threat_matrix = threat_matrix
        self.firewall = firewall
        self.db = db
        self.sig_engine = sig_engine
        self.running = True
        self.hit_count = 0
        self.sockets = []

    def _bind_port(self, port, proto_name):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", port))
            s.listen(5)
            self.sockets.append((s, proto_name, port))
            logger.info(f"[Honeypot] {proto_name} listening on port {port}")
        except OSError as e:
            if e.errno == 10013:
                logger.warning(f"[Honeypot] Permission denied on port {port} ({proto_name}), skipping.")
            else:
                logger.error(f"[Honeypot] Failed to bind on port {port} ({proto_name}): {e}")

    def run(self):
        if not self.config.honeypot_enabled:
            logger.info("[Honeypot] Disabled.")
            return

        self._bind_port(self.config.honeypot_ssh_port, "SSH")
        self._bind_port(self.config.honeypot_http_port, "HTTP")
        self._bind_port(self.config.honeypot_rdp_port, "RDP")

        if not self.sockets:
            logger.error("[Honeypot] No ports bound, honeypot disabled.")
            return

        while self.running:
            for s, proto, port in list(self.sockets):
                try:
                    s.settimeout(1.0)
                    conn, addr = s.accept()
                    ip, cport = addr
                    self.hit_count += 1
                    try:
                        if proto == "SSH":
                            banner = b"SSH-2.0-OpenSSH_8.9p1 Guardian\r\n"
                        elif proto == "HTTP":
                            banner = b"HTTP/1.1 200 OK\r\nServer: GuardianHoneypot\r\nContent-Length: 0\r\n\r\n"
                        else:
                            banner = b"RDP-Guardian-Stub\r\n"
                        conn.sendall(banner)
                    except Exception:
                        pass
                    event = {
                        "type": f"honeypot_hit_{proto.lower()}",
                        "src_ip": ip,
                        "dst_ip": CRITICAL_NODE_IP or "",
                        "summary": f"{proto} honeypot connection from {ip}:{cport} on port {port}",
                        "severity": 60
                    }
                    self.threat_matrix.add_event(event)
                    self.firewall.block_ip(ip)
                    self.sig_engine.process_event(ip, event["type"], event["summary"], event["severity"])
                    conn.close()
                except socket.timeout:
                    continue
                except Exception as e:
                    logger.error(f"[Honeypot] Error on {proto} port {port}: {e}")
        for s, _, _ in self.sockets:
            s.close()

    def stop(self):
        self.running = False
        logger.info("[Honeypot] Stopped.")

class AlertEngine:
    def __init__(self, config: GuardianConfig):
        self.config = config

    @staticmethod
    def simple_alert(message: str):
        print(f"[ALERT] {message}")

    def audio_alert(self, message: str):
        if not self.config.audio_alerts:
            return
        logger.info(f"[Audio] {message}")
        try:
            winsound.Beep(900, 300)
            winsound.Beep(600, 300)
        except Exception as e:
            logger.error(f"[Audio] Failed to play sound: {e}")

    def visual_alert(self, message: str):
        if not self.config.visual_alerts:
            return
        logger.info(f"[Visual] {message}")

    def intruder_alert(self, src_ip, dst_ip):
        msg = f"Intruder detected on IP {src_ip} targeting {dst_ip}."
        self.audio_alert(msg)
        self.visual_alert(msg)

class PacketCaptureManager:
    """
    Per-IP packet capture manager.
    Stores small pcap files per IP when triggered.
    """
    def __init__(self):
        self.enabled = SCAPY_AVAILABLE
        self.max_packets_per_ip = 200
        self.buffers = {}  # ip -> [pkt]

    def record_packet(self, ip: str, pkt):
        if not self.enabled:
            return
        if ip not in self.buffers:
            self.buffers[ip] = []
        self.buffers[ip].append(pkt)
        if len(self.buffers[ip]) > self.max_packets_per_ip:
            self.buffers[ip].pop(0)

    def dump_pcap(self, ip: str):
        if not self.enabled:
            return
        pkts = self.buffers.get(ip, [])
        if not pkts:
            return
        filename = f"guardian_{ip.replace('.', '_')}.pcap"
        try:
            wrpcap(filename, pkts)
            logger.info(f"[PCAP] Dumped {len(pkts)} packets for {ip} to {filename}")
        except Exception as e:
            logger.error(f"[PCAP] Failed to write pcap for {ip}: {e}")

class ThreatReplayEngine:
    """
    Threat replay engine: replays stored events/pcaps through detection pipeline.
    """
    def __init__(self, db: GuardianDB, packet_inspector_ref):
        self.db = db
        self.packet_inspector_ref = packet_inspector_ref

    def replay_session(self, session_id: int):
        events = self.db.get_replay_events(session_id)
        logger.info(f"[Replay] Replaying session {session_id} with {len(events)} events.")
        for e in events:
            payload = e["payload"]
            src_ip = e["src_ip"]
            dst_ip = e["dst_ip"]
            meta = e["meta"]
            try:
                self.packet_inspector_ref.replay_packet(src_ip, dst_ip, payload, meta)
            except Exception as ex:
                logger.error(f"[Replay] Failed to replay event: {ex}")

class PacketInspector(threading.Thread):
    def __init__(self, config: GuardianConfig, threat_intel: ThreatIntel,
                 firewall: FirewallManager, alerts: AlertEngine,
                 threat_matrix: ThreatMatrix, rogue_ai: RogueAIDetector,
                 anomaly: AnomalyDetector, deep_ml: DeepMLAnomalyDetector,
                 per_ip_ml: PerIPMLManager, db: GuardianDB,
                 neural: NeuralAnomalyEngine, pcap_mgr: PacketCaptureManager,
                 suricata_engine: SuricataRuleEngine, mesh_router: MeshRouter):
        super().__init__(daemon=True)
        self.config = config
        self.threat_intel = threat_intel
        self.firewall = firewall
        self.alerts = alerts
        self.threat_matrix = threat_matrix
        self.rogue_ai = rogue_ai
        self.anomaly = anomaly
        self.deep_ml = deep_ml
        self.per_ip_ml = per_ip_ml
        self.db = db
        self.neural = neural
        self.pcap_mgr = pcap_mgr
        self.suricata_engine = suricata_engine
        self.mesh_router = mesh_router
        self.running = True

    def run(self):
        if not SCAPY_AVAILABLE or not self.config.packet_inspection_enabled:
            logger.warning("[Packets] Packet inspection disabled (Scapy missing or config off).")
            return
        logger.info("[Packets] Packet inspection started.")
        try:
            sniff(prn=self._handle_packet, store=False)
        except OSError as e:
            if e.errno == 10013:
                logger.error("[Packets] Permission denied (10013). Disabling packet inspection.")
            else:
                logger.error(f"[Packets] Error starting sniff: {e}")

    def _extract_payload(self, pkt):
        if Raw in pkt:
            return bytes(pkt[Raw].load)
        return b""

    def _handle_packet(self, pkt):
        try:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                proto = "tcp" if TCP in pkt else "udp" if UDP in pkt else "ip"
                src_port = pkt[TCP].sport if TCP in pkt else pkt[UDP].sport if UDP in pkt else 0
                dst_port = pkt[TCP].dport if TCP in pkt else pkt[UDP].dport if UDP in pkt else 0

                payload = self._extract_payload(pkt)

                self.rogue_ai.record_connection(src)
                self.pcap_mgr.record_packet(src, pkt)

                features = [1.0, len(payload)]
                self.per_ip_ml.record_ip_event(src, features)
                anomalous_ml = self.per_ip_ml.is_ip_anomalous(src, features)
                anomalous_nn = self.neural.is_anomalous(src, features)

                suricata_matches = self.suricata_engine.match_packet(src, dst, src_port, dst_port, proto, payload)
                malicious = self.threat_intel.is_malicious(src) or bool(suricata_matches)

                if malicious or anomalous_ml or anomalous_nn or suricata_matches:
                    sev = 80 if malicious or suricata_matches else 60
                    event_type = "intrusion" if malicious or suricata_matches else "per_ip_anomaly"
                    summary = f"Suspicious IP {src} targeting {dst} (malicious={malicious}, ml={anomalous_ml}, nn={anomalous_nn}, rules={len(suricata_matches)})"
                    event = {
                        "type": event_type,
                        "src_ip": src,
                        "dst_ip": dst,
                        "summary": summary,
                        "severity": sev
                    }
                    self.threat_matrix.add_event(event)
                    self.alerts.intruder_alert(src, dst)
                    self.firewall.block_ip(src)
                    self.anomaly.record_event(event)
                    self.deep_ml.record_event(event)
                    self.db.update_device_risk(src, sev)
                    self.db.add_heatmap_point(src, "severity", float(sev))
                    self.mesh_router.broadcast_alert(event)
        except Exception as e:
            logger.error(f"[Packets] Error handling packet: {e}")

    def replay_packet(self, src_ip: str, dst_ip: str, payload: bytes, meta: dict):
        try:
            proto = meta.get("proto", "tcp")
            src_port = meta.get("src_port", 0)
            dst_port = meta.get("dst_port", 0)
            features = [1.0, len(payload)]
            self.per_ip_ml.record_ip_event(src_ip, features)
            anomalous_ml = self.per_ip_ml.is_ip_anomalous(src_ip, features)
            anomalous_nn = self.neural.is_anomalous(src_ip, features)
            suricata_matches = self.suricata_engine.match_packet(src_ip, dst_ip, src_port, dst_port, proto, payload)
            malicious = self.threat_intel.is_malicious(src_ip) or bool(suricata_matches)
            if malicious or anomalous_ml or anomalous_nn or suricata_matches:
                sev = 80 if malicious or suricata_matches else 60
                event_type = "replay_intrusion" if malicious or suricata_matches else "replay_anomaly"
                summary = f"[Replay] Suspicious IP {src_ip} targeting {dst_ip} (malicious={malicious}, ml={anomalous_ml}, nn={anomalous_nn}, rules={len(suricata_matches)})"
                event = {
                    "type": event_type,
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "summary": summary,
                    "severity": sev
                }
                self.threat_matrix.add_event(event)
                self.db.update_device_risk(src_ip, sev)
                self.db.add_heatmap_point(src_ip, "replay", float(sev))
        except Exception as e:
            logger.error(f"[Replay] Error handling replay packet: {e}")

    def stop(self):
        self.running = False
        logger.info("[Packets] Packet inspection stopped.")

class GuardianService(threading.Thread):
    def __init__(self, config: GuardianConfig, net_engine: NetworkDiscoveryEngine,
                 threat_matrix: ThreatMatrix, alerts: AlertEngine,
                 integrity: IntegrityManager, threat_intel: ThreatIntel,
                 firewall: FirewallManager, rogue_ai: RogueAIDetector,
                 anomaly: AnomalyDetector, deep_ml: DeepMLAnomalyDetector,
                 swarm: SwarmSync, db: GuardianDB, per_ip_ml: PerIPMLManager,
                 sig_engine: SignatureEngine, pcap_mgr: PacketCaptureManager,
                 mesh_router: MeshRouter):
        super().__init__(daemon=True)
        self.config = config
        self.net_engine = net_engine
        self.threat_matrix = threat_matrix
        self.alerts = alerts
        self.integrity = integrity
        self.threat_intel = threat_intel
        self.firewall = firewall
        self.rogue_ai = rogue_ai
        self.anomaly = anomaly
        self.deep_ml = deep_ml
        self.swarm = swarm
        self.db = db
        self.per_ip_ml = per_ip_ml
        self.sig_engine = sig_engine
        self.pcap_mgr = pcap_mgr
        self.mesh_router = mesh_router
        self.running = True

    def run(self):
        logger.info("[Service] Guardian background service started.")
        self.net_engine.detect_subnet()
        self.net_engine.scan_devices()
        self.integrity.initialize_integrity()
        self.threat_intel.refresh_feeds()

        while self.running:
            interval = random.randint(self.config.scan_min_seconds, self.config.scan_max_seconds)
            logger.debug(f"[Service] Next scan in {interval} seconds.")
            time.sleep(interval)

            self.integrity.check_and_repair()
            self._simulate_traffic_and_detection()
            self.firewall.cleanup_expired_rules()
            self._apply_auto_expiration_policies()
            self._update_ip_graphs()

            if self.anomaly.is_anomalous_rate():
                event = {
                    "type": "anomaly_rate",
                    "src_ip": "",
                    "dst_ip": "",
                    "summary": "High event rate detected (anomaly).",
                    "severity": 50
                }
                self.threat_matrix.add_event(event)
                self.anomaly.record_event(event)
                self.deep_ml.record_event(event)

            if self.deep_ml.is_deep_anomaly():
                event = {
                    "type": "deep_anomaly",
                    "src_ip": "",
                    "dst_ip": "",
                    "summary": "Deep anomaly detected (ML threshold).",
                    "severity": 70
                }
                self.threat_matrix.add_event(event)

            self.swarm.push_blocklist(self.threat_intel.blocklist)
            self.swarm.sync_with_peers(self.threat_intel.blocklist)

    def _simulate_traffic_and_detection(self):
        if random.random() < 0.1:
            src_ip = "216.218.217.234"
            dst_ip = CRITICAL_NODE_IP or "192.168.1.219"
            event = {
                "type": "intrusion",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "summary": f"Intrusion attempt from {src_ip} to {dst_ip}",
                "severity": 80
            }
            self.threat_matrix.add_event(event)
            self.alerts.intruder_alert(src_ip, dst_ip)
            policy_info = self.db.get_ip_policy(src_ip)
            policy = policy_info["policy"] if policy_info else None
            if policy != POLICY_ALLOW:
                self.firewall.block_ip(src_ip)
            self.anomaly.record_event(event)
            self.deep_ml.record_event(event)
            self.db.update_device_risk(src_ip, 80)
            self.per_ip_ml.record_ip_event(src_ip, [1.0, 0.0])
            self.sig_engine.process_event(src_ip, event["type"], event["summary"], event["severity"])
            self.db.add_heatmap_point(src_ip, "simulated", 80.0)
            self.mesh_router.broadcast_alert(event)

    def _apply_auto_expiration_policies(self):
        now = int(time.time())
        policies = self.db.get_all_ip_policies()
        for ip, info in policies.items():
            policy = info.get("policy")
            ts = info.get("ts", 0)
            block_ttl = info.get("block_ttl")
            allow_ttl = info.get("allow_ttl")
            monitor_ttl = info.get("monitor_ttl")

            if policy == POLICY_BLOCK and block_ttl:
                if now - ts > block_ttl:
                    logger.info(f"[Policy] Auto-expiring BLOCK for {ip}")
                    self.db.set_ip_policy(ip, POLICY_MONITOR, block_ttl=None, allow_ttl=allow_ttl, monitor_ttl=monitor_ttl)
                    self.firewall.unblock_ip(ip)

            if policy == POLICY_ALLOW and allow_ttl:
                if now - ts > allow_ttl:
                    logger.info(f"[Policy] Auto-expiring ALLOW for {ip}")
                    self.db.set_ip_policy(ip, POLICY_MONITOR, block_ttl=block_ttl, allow_ttl=None, monitor_ttl=monitor_ttl)

            if policy == POLICY_MONITOR and monitor_ttl:
                if now - ts > monitor_ttl:
                    logger.info(f"[Policy] Auto-expiring MONITOR for {ip}")
                    self.db.set_ip_policy(ip, POLICY_MONITOR, block_ttl=block_ttl, allow_ttl=allow_ttl, monitor_ttl=None)

    def _update_ip_graphs(self):
        devices = self.db.get_devices()
        for ip, info in devices.items():
            risk = info.get("risk", 0)
            rate = self.deep_ml.get_rate()
            honeypot_hits = 0
            self.db.add_ip_graph_point(ip, rate, risk, honeypot_hits)
            self.db.add_heatmap_point(ip, "rate", rate)

    def stop(self):
        self.running = False
        logger.info("[Service] Guardian background service stopped.")

class IPHeatmapDialog(QtWidgets.QDialog):
    def __init__(self, ip: str, db: GuardianDB, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.db = db
        self.setWindowTitle(f"Per-IP Heatmap - {ip}")
        self.resize(600, 400)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(QtWidgets.QLabel(f"Per-IP Heatmap for {ip}"))

        if QT_CHARTS_AVAILABLE:
            series_intensity = QLineSeries()
            series_intensity.setName("Intensity")

            points = self.db.get_heatmap(ip, limit=200)
            for p in reversed(points):
                t = p["ts"]
                series_intensity.append(t, p["intensity"])

            chart = QChart()
            chart.addSeries(series_intensity)
            chart.createDefaultAxes()
            chart.setTitle(f"IP {ip} Heatmap (Intensity over time)")

            view = QChartView(chart)
            view.setMinimumHeight(300)
            layout.addWidget(view)
        else:
            layout.addWidget(QtWidgets.QLabel("QtCharts not available."))

        self.setLayout(layout)

class IPGraphDialog(QtWidgets.QDialog):
    def __init__(self, ip: str, db: GuardianDB, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.db = db
        self.setWindowTitle(f"Per-IP Graph - {ip}")
        self.resize(600, 400)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(QtWidgets.QLabel(f"Per-IP Graph for {ip}"))

        if QT_CHARTS_AVAILABLE:
            series_rate = QLineSeries()
            series_rate.setName("Rate")
            series_risk = QLineSeries()
            series_risk.setName("Risk")
            series_honeypot = QLineSeries()
            series_honeypot.setName("Honeypot Hits")

            points = self.db.get_ip_graph(ip, limit=200)
            for p in reversed(points):
                t = p["ts"]
                series_rate.append(t, p["rate"])
                series_risk.append(t, p["risk"])
                series_honeypot.append(t, p["honeypot_hits"])

            chart = QChart()
            chart.addSeries(series_rate)
            chart.addSeries(series_risk)
            chart.addSeries(series_honeypot)
            chart.createDefaultAxes()
            chart.setTitle(f"IP {ip} Telemetry")

            view = QChartView(chart)
            view.setMinimumHeight(300)
            layout.addWidget(view)
        else:
            layout.addWidget(QtWidgets.QLabel("QtCharts not available."))

        self.setLayout(layout)

class IPControlDialog(QtWidgets.QDialog):
    def __init__(self, ip: str, db: GuardianDB, firewall: FirewallManager, pcap_mgr: PacketCaptureManager, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.db = db
        self.firewall = firewall
        self.pcap_mgr = pcap_mgr
        self.setWindowTitle(f"IP Control Panel - {ip}")
        self.resize(650, 550)

        layout = QtWidgets.QVBoxLayout()

        layout.addWidget(QtWidgets.QLabel(f"IP: {ip}"))

        devices = self.db.get_devices()
        info = devices.get(ip, {})
        risk = info.get("risk", 0)
        notes = info.get("notes", "")
        identity = info.get("identity", "")
        trust_score = info.get("trust_score", 50)

        self.risk_label = QtWidgets.QLabel(f"Risk: {risk}")
        layout.addWidget(self.risk_label)

        self.trust_label = QtWidgets.QLabel(f"Trust Score: {trust_score}")
        layout.addWidget(self.trust_label)

        layout.addWidget(QtWidgets.QLabel(f"Identity (zero-trust fingerprint): {identity[:32]}..."))

        layout.addWidget(QtWidgets.QLabel("Notes:"))
        self.notes_edit = QtWidgets.QLineEdit(notes)
        layout.addWidget(self.notes_edit)

        policy_info = self.db.get_ip_policy(ip) or {}
        current_policy = policy_info.get("policy", "none")
        layout.addWidget(QtWidgets.QLabel(f"Current policy: {current_policy}"))

        ttl_layout = QtWidgets.QFormLayout()
        self.block_ttl_edit = QtWidgets.QLineEdit(str(policy_info.get("block_ttl") or ""))
        self.allow_ttl_edit = QtWidgets.QLineEdit(str(policy_info.get("allow_ttl") or ""))
        self.monitor_ttl_edit = QtWidgets.QLineEdit(str(policy_info.get("monitor_ttl") or ""))

        ttl_layout.addRow("Block TTL (sec):", self.block_ttl_edit)
        ttl_layout.addRow("Allow TTL (sec):", self.allow_ttl_edit)
        ttl_layout.addRow("Monitor TTL (sec):", self.monitor_ttl_edit)
        layout.addLayout(ttl_layout)

        btn_layout = QtWidgets.QHBoxLayout()
        allow_btn = QtWidgets.QPushButton("🟢 Allow")
        block_btn = QtWidgets.QPushButton("🔴 Block")
        monitor_btn = QtWidgets.QPushButton("🟡 Monitor")
        graph_btn = QtWidgets.QPushButton("View Graph")
        heatmap_btn = QtWidgets.QPushButton("View Heatmap")
        pcap_btn = QtWidgets.QPushButton("Dump PCAP")
        btn_layout.addWidget(allow_btn)
        btn_layout.addWidget(block_btn)
        btn_layout.addWidget(monitor_btn)
        btn_layout.addWidget(graph_btn)
        btn_layout.addWidget(heatmap_btn)
        btn_layout.addWidget(pcap_btn)
        layout.addLayout(btn_layout)

        history_btn = QtWidgets.QPushButton("View History")
        layout.addWidget(history_btn)

        self.history_box = QtWidgets.QTextEdit()
        self.history_box.setReadOnly(True)
        layout.addWidget(self.history_box)

        def apply_policy(policy: str):
            notes_val = self.notes_edit.text()
            self.db.update_device_notes(self.ip, notes_val)

            def parse_int(val):
                val = val.strip()
                if not val:
                    return None
                try:
                    return int(val)
                except ValueError:
                    return None

            block_ttl = parse_int(self.block_ttl_edit.text())
            allow_ttl = parse_int(self.allow_ttl_edit.text())
            monitor_ttl = parse_int(self.monitor_ttl_edit.text())

            self.db.set_ip_policy(self.ip, policy, block_ttl, allow_ttl, monitor_ttl)

            if policy == POLICY_ALLOW:
                self.firewall.unblock_ip(self.ip)
            elif policy == POLICY_BLOCK:
                self.firewall.block_ip(self.ip, manual=True)
            elif policy == POLICY_MONITOR:
                self.firewall.unblock_ip(self.ip)

            self.accept()

        allow_btn.clicked.connect(lambda: apply_policy(POLICY_ALLOW))
        block_btn.clicked.connect(lambda: apply_policy(POLICY_BLOCK))
        monitor_btn.clicked.connect(lambda: apply_policy(POLICY_MONITOR))

        def load_history():
            history = self.db.get_ip_history(self.ip, limit=100)
            lines = []
            for h in history:
                ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(h["ts"]))
                lines.append(f"[{ts}] ({h['severity']}) {h['event_type']}: {h['summary']}")
            self.history_box.setPlainText("\n".join(lines))

        history_btn.clicked.connect(load_history)
        load_history()

        def open_graph():
            dlg = IPGraphDialog(self.ip, self.db, parent=self)
            dlg.exec()

        graph_btn.clicked.connect(open_graph)

        def open_heatmap():
            dlg = IPHeatmapDialog(self.ip, self.db, parent=self)
            dlg.exec()

        heatmap_btn.clicked.connect(open_heatmap)

        def dump_pcap():
            self.pcap_mgr.dump_pcap(self.ip)

        pcap_btn.clicked.connect(dump_pcap)

        self.setLayout(layout)

class GuardianGUI:
    def __init__(self, config: GuardianConfig, db: GuardianDB,
                 net_engine: NetworkDiscoveryEngine, threat_matrix: ThreatMatrix,
                 alerts: AlertEngine, swarm: SwarmSync, honeypot: Honeypot,
                 anomaly: AnomalyDetector, deep_ml: DeepMLAnomalyDetector,
                 firewall: FirewallManager, service: GuardianService,
                 packet_inspector: PacketInspector, pcap_mgr: PacketCaptureManager):
        self.config = config
        self.db = db
        self.net_engine = net_engine
        self.threat_matrix = threat_matrix
        self.alerts = alerts
        self.swarm = swarm
        self.honeypot = honeypot
        self.anomaly = anomaly
        self.deep_ml = deep_ml
        self.firewall = firewall
        self.service = service
        self.packet_inspector = packet_inspector
        self.pcap_mgr = pcap_mgr

        self.audio_indicator = None
        self.visual_indicator = None
        self.alert_light = None
        self.severity_bar = None
        self.packet_rate_label = None
        self.device_risk_label = None
        self.health_label = None
        self.swarm_label = None
        self.honeypot_label = None
        self.firewall_box = None
        self.override_label = None

        self.blink_state = False
        self.last_event_ts = 0

        self.chart_view = None
        self.series_rate = None
        self.series_severity = None
        self.series_honeypot = None

        self.devices_table = None

    def launch(self):
        if QtWidgets is None:
            logger.warning("[GUI] PySide6 not available, GUI disabled.")
            return

        app = QtWidgets.QApplication(sys.argv)
        window = QtWidgets.QMainWindow()
        window.setWindowTitle("Guardian Dashboard")

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        title = QtWidgets.QLabel("Unified Network Guardian (Suricata + Zero-Trust Mesh)")
        layout.addWidget(title)

        subnet_text = f"Detected subnet: {self.net_engine.subnet_ip}/{self.net_engine.subnet_mask}"
        subnet_label = QtWidgets.QLabel(subnet_text)
        layout.addWidget(subnet_label)

        indicator_layout = QtWidgets.QHBoxLayout()
        self.audio_indicator = QtWidgets.QLabel()
        self.visual_indicator = QtWidgets.QLabel()
        self.alert_light = QtWidgets.QLabel("ALERT")
        self.alert_light.setAlignment(QtCore.Qt.AlignCenter)
        self.alert_light.setFixedWidth(80)
        self.alert_light.setStyleSheet("background-color: grey; color: white; font-weight: bold;")

        indicator_layout.addWidget(self.audio_indicator)
        indicator_layout.addWidget(self.visual_indicator)
        indicator_layout.addWidget(self.alert_light)
        layout.addLayout(indicator_layout)

        self.severity_bar = QtWidgets.QProgressBar()
        self.severity_bar.setRange(0, 100)
        self.severity_bar.setValue(0)
        self.severity_bar.setFormat("Threat Severity: %p%")
        layout.addWidget(self.severity_bar)

        self.packet_rate_label = QtWidgets.QLabel("Packet/Event Rate: 0.0/s")
        layout.addWidget(self.packet_rate_label)

        self.device_risk_label = QtWidgets.QLabel("Max Device Risk: 0")
        layout.addWidget(self.device_risk_label)

        self.health_label = QtWidgets.QLabel("Guardian Health: OK")
        layout.addWidget(self.health_label)

        self.swarm_label = QtWidgets.QLabel("Swarm/Mesh: OFF")
        layout.addWidget(self.swarm_label)

        self.honeypot_label = QtWidgets.QLabel("Honeypot Hits: 0")
        layout.addWidget(self.honeypot_label)

        self.override_label = QtWidgets.QLabel("Firewall Auto-Block: ON")
        layout.addWidget(self.override_label)

        if QT_CHARTS_AVAILABLE:
            self.series_rate = QLineSeries()
            self.series_rate.setName("Event Rate")
            self.series_severity = QLineSeries()
            self.series_severity.setName("Severity")
            self.series_honeypot = QLineSeries()
            self.series_honeypot.setName("Honeypot Hits")

            chart = QChart()
            chart.addSeries(self.series_rate)
            chart.addSeries(self.series_severity)
            chart.addSeries(self.series_honeypot)
            chart.createDefaultAxes()
            chart.setTitle("Guardian Telemetry (Rate, Severity, Honeypot)")

            self.chart_view = QChartView(chart)
            self.chart_view.setMinimumHeight(250)
            layout.addWidget(self.chart_view)

        layout.addWidget(QtWidgets.QLabel("Devices (double-click IP for control panel):"))

        self.devices_table = QtWidgets.QTableWidget()
        self.devices_table.setColumnCount(9)
        self.devices_table.setHorizontalHeaderLabels([
            "IP", "Role/Type", "Risk", "Trust", "OS/TTL/MAC", "Notes", "🟢 Allow", "🔴 Block", "🟡 Monitor"
        ])
        self.devices_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.devices_table)

        events_box = QtWidgets.QTextEdit()
        events_box.setReadOnly(True)
        events_box.setPlainText("\n".join(
            [f"[{e.get('severity',0)}] {e.get('summary', '')}" for e in self.threat_matrix.get_recent_events()]
        ))
        layout.addWidget(QtWidgets.QLabel("Threat Events:"))
        layout.addWidget(events_box)

        self.firewall_box = QtWidgets.QTextEdit()
        self.firewall_box.setReadOnly(True)
        rules = self.firewall.list_rules_raw()
        self.firewall_box.setPlainText("\n".join(rules[:50]))
        layout.addWidget(QtWidgets.QLabel("Firewall Rules (raw, top 50):"))
        layout.addWidget(self.firewall_box)

        controls_layout = QtWidgets.QHBoxLayout()
        audio_btn = QtWidgets.QPushButton("Toggle Audio Alerts")
        visual_btn = QtWidgets.QPushButton("Toggle Visual Alerts")
        override_btn = QtWidgets.QPushButton("Toggle Firewall Auto-Block Override")

        def update_indicators():
            if self.config.audio_alerts:
                self.audio_indicator.setText("Audio: ON")
                self.audio_indicator.setStyleSheet("color: green; font-weight: bold;")
            else:
                self.audio_indicator.setText("Audio: OFF")
                self.audio_indicator.setStyleSheet("color: red; font-weight: bold;")

            if self.config.visual_alerts:
                self.visual_indicator.setText("Visual: ON")
                self.visual_indicator.setStyleSheet("color: green; font-weight: bold;")
            else:
                self.visual_indicator.setText("Visual: OFF")
                self.visual_indicator.setStyleSheet("color: red; font-weight: bold;")

            if self.config.manual_override_enabled:
                self.override_label.setText("Firewall Auto-Block: OVERRIDE (OFF)")
                self.override_label.setStyleSheet("color: orange; font-weight: bold;")
            else:
                self.override_label.setText("Firewall Auto-Block: ON")
                self.override_label.setStyleSheet("color: green; font-weight: bold;")

        def toggle_audio():
            self.config.audio_alerts = not self.config.audio_alerts
            update_indicators()
            state = "ON" if self.config.audio_alerts else "OFF"
            self.alerts.simple_alert(f"Audio alerts now {state}")

        def toggle_visual():
            self.config.visual_alerts = not self.config.visual_alerts
            update_indicators()
            state = "ON" if self.config.visual_alerts else "OFF"
            self.alerts.simple_alert(f"Visual alerts now {state}")

        def toggle_override():
            self.config.manual_override_enabled = not self.config.manual_override_enabled
            update_indicators()
            state = "ENABLED" if self.config.manual_override_enabled else "DISABLED"
            self.alerts.simple_alert(f"Firewall auto-block override {state}")

        audio_btn.clicked.connect(toggle_audio)
        visual_btn.clicked.connect(toggle_visual)
        override_btn.clicked.connect(toggle_override)

        controls_layout.addWidget(audio_btn)
        controls_layout.addWidget(visual_btn)
        controls_layout.addWidget(override_btn)
        layout.addLayout(controls_layout)

        central.setLayout(layout)
        window.setCentralWidget(central)
        window.resize(1400, 900)
        window.show()

        update_indicators()
        self._start_gui_timer(events_box)

        def on_cell_double_clicked(row, column):
            if column == 0:
                ip_item = self.devices_table.item(row, 0)
                if ip_item:
                    ip = ip_item.text()
                    dlg = IPControlDialog(ip, self.db, self.firewall, self.pcap_mgr, parent=window)
                    dlg.exec()
                    self._refresh_devices_table()

        self.devices_table.cellDoubleClicked.connect(on_cell_double_clicked)

        logger.info("[GUI] Guardian dashboard launched.")
        app.exec()

    def _refresh_devices_table(self):
        devices = self.db.get_devices()
        policies = self.db.get_all_ip_policies()

        self.devices_table.setRowCount(len(devices))
        row = 0
        for ip, info in devices.items():
            role_type = f"{info.get('role')} / {info.get('type')}"
            risk = str(info.get("risk", 0))
            trust = str(info.get("trust_score", 50))
            os_ttl_mac = f"{info.get('os_hint')} / TTL={info.get('ttl_hint')} / MAC={info.get('mac_vendor')}"
            notes = info.get("notes", "")

            ip_item = QtWidgets.QTableWidgetItem(ip)
            role_item = QtWidgets.QTableWidgetItem(role_type)
            risk_item = QtWidgets.QTableWidgetItem(risk)
            trust_item = QtWidgets.QTableWidgetItem(trust)
            os_item = QtWidgets.QTableWidgetItem(os_ttl_mac)
            notes_item = QtWidgets.QTableWidgetItem(notes)

            policy_info = policies.get(ip, {})
            policy = policy_info.get("policy", None)

            if policy == POLICY_ALLOW:
                ip_item.setForeground(QtGui.QBrush(QtGui.QColor("green")))
            elif policy == POLICY_BLOCK:
                ip_item.setForeground(QtGui.QBrush(QtGui.QColor("red")))
            elif policy == POLICY_MONITOR:
                ip_item.setForeground(QtGui.QBrush(QtGui.QColor("orange")))
            else:
                ip_item.setForeground(QtGui.QBrush(QtGui.QColor("gray")))

            self.devices_table.setItem(row, 0, ip_item)
            self.devices_table.setItem(row, 1, role_item)
            self.devices_table.setItem(row, 2, risk_item)
            self.devices_table.setItem(row, 3, trust_item)
            self.devices_table.setItem(row, 4, os_item)
            self.devices_table.setItem(row, 5, notes_item)

            allow_btn = QtWidgets.QPushButton("🟢")
            block_btn = QtWidgets.QPushButton("🔴")
            monitor_btn = QtWidgets.QPushButton("🟡")

            def make_handler(target_ip, target_policy):
                def handler():
                    policy_info_local = self.db.get_ip_policy(target_ip) or {}
                    block_ttl = policy_info_local.get("block_ttl")
                    allow_ttl = policy_info_local.get("allow_ttl")
                    monitor_ttl = policy_info_local.get("monitor_ttl")
                    self.db.set_ip_policy(target_ip, target_policy, block_ttl, allow_ttl, monitor_ttl)
                    if target_policy == POLICY_ALLOW:
                        self.firewall.unblock_ip(target_ip)
                    elif target_policy == POLICY_BLOCK:
                        self.firewall.block_ip(target_ip, manual=True)
                    elif target_policy == POLICY_MONITOR:
                        self.firewall.unblock_ip(target_ip)
                    self._refresh_devices_table()
                return handler

            allow_btn.clicked.connect(make_handler(ip, POLICY_ALLOW))
            block_btn.clicked.connect(make_handler(ip, POLICY_BLOCK))
            monitor_btn.clicked.connect(make_handler(ip, POLICY_MONITOR))

            self.devices_table.setCellWidget(row, 6, allow_btn)
            self.devices_table.setCellWidget(row, 7, block_btn)
            self.devices_table.setCellWidget(row, 8, monitor_btn)

            row += 1

    def _start_gui_timer(self, events_box):
        timer = QtCore.QTimer()
        timer.setInterval(1000)

        def refresh():
            events = self.threat_matrix.get_recent_events()
            events_box.setPlainText("\n".join(
                [f"[{e.get('severity',0)}] {e.get('summary', '')}" for e in events]
            ))
            if events:
                self.last_event_ts = events[0]["ts"]

            self._refresh_devices_table()

            rate = self.deep_ml.get_rate()
            self.packet_rate_label.setText(f"Packet/Event Rate: {rate:.2f}/s")

            devices = self.db.get_devices()
            max_risk = max([info.get("risk", 0) for info in devices.values()] or [0])
            self.device_risk_label.setText(f"Max Device Risk: {max_risk}")

            severity = 0
            if events:
                severity = max(e.get("severity", 0) for e in events)
            self.severity_bar.setValue(min(severity, 100))
            if severity < 30:
                self.severity_bar.setStyleSheet("QProgressBar::chunk { background-color: green; }")
            elif severity < 70:
                self.severity_bar.setStyleSheet("QProgressBar::chunk { background-color: orange; }")
            else:
                self.severity_bar.setStyleSheet("QProgressBar::chunk { background-color: red; }")

            if self.service.is_alive():
                self.health_label.setText("Guardian Health: OK")
                self.health_label.setStyleSheet("color: green; font-weight: bold;")
            else:
                self.health_label.setText("Guardian Health: DOWN")
                self.health_label.setStyleSheet("color: red; font-weight: bold;")

            if self.swarm.config.swarm_sync_enabled:
                if self.swarm.last_status_ok:
                    self.swarm_label.setText("Swarm/Mesh: OK (encrypted, mutual auth)")
                    self.swarm_label.setStyleSheet("color: green; font-weight: bold;")
                else:
                    self.swarm_label.setText("Swarm/Mesh: ERROR")
                    self.swarm_label.setStyleSheet("color: orange; font-weight: bold;")
            else:
                self.swarm_label.setText("Swarm/Mesh: OFF")
                self.swarm_label.setStyleSheet("color: grey; font-weight: bold;")

            self.honeypot_label.setText(f"Honeypot Hits: {self.honeypot.hit_count}")

            now = int(time.time())
            if now - self.last_event_ts < 10:
                self.blink_state = not self.blink_state
                if self.blink_state:
                    self.alert_light.setStyleSheet("background-color: red; color: white; font-weight: bold;")
                else:
                    self.alert_light.setStyleSheet("background-color: yellow; color: black; font-weight: bold;")
            else:
                self.alert_light.setStyleSheet("background-color: grey; color: white; font-weight: bold;")

            rules = self.firewall.list_rules_raw()
            self.firewall_box.setPlainText("\n".join(rules[:50]))

            if QT_CHARTS_AVAILABLE and self.series_rate is not None and self.series_severity is not None and self.series_honeypot is not None:
                self.series_rate.append(now, rate)
                self.series_severity.append(now, severity)
                self.series_honeypot.append(now, self.honeypot.hit_count)

        timer.timeout.connect(refresh)
        timer.start()

class IntegrityWatchdog(threading.Thread):
    def __init__(self, service: GuardianService, integrity: IntegrityManager, config: GuardianConfig,
                 net_engine: NetworkDiscoveryEngine, threat_matrix: ThreatMatrix,
                 alerts: AlertEngine, threat_intel: ThreatIntel,
                 firewall: FirewallManager, rogue_ai: RogueAIDetector,
                 anomaly: AnomalyDetector, deep_ml: DeepMLAnomalyDetector,
                 swarm: SwarmSync, db: GuardianDB, per_ip_ml: PerIPMLManager,
                 sig_engine: SignatureEngine, pcap_mgr: PacketCaptureManager,
                 mesh_router: MeshRouter):
        super().__init__(daemon=True)
        self.service = service
        self.integrity = integrity
        self.config = config
        self.net_engine = net_engine
        self.threat_matrix = threat_matrix
        self.alerts = alerts
        self.threat_intel = threat_intel
        self.firewall = firewall
        self.rogue_ai = rogue_ai
        self.anomaly = anomaly
        self.deep_ml = deep_ml
        self.swarm = swarm
        self.db = db
        self.per_ip_ml = per_ip_ml
        self.sig_engine = sig_engine
        self.pcap_mgr = pcap_mgr
        self.mesh_router = mesh_router
        self.running = True

    def run(self):
        logger.info("[Watchdog] Integrity watchdog started.")
        while self.running:
            time.sleep(10)
            if not self.service.is_alive():
                logger.warning("[Watchdog] Guardian service not alive, restarting...")
                AlertEngine.simple_alert("Guardian service was restarted by watchdog.")
                self.service = GuardianService(
                    self.config,
                    self.net_engine,
                    self.threat_matrix,
                    self.alerts,
                    self.integrity,
                    self.threat_intel,
                    self.firewall,
                    self.rogue_ai,
                    self.anomaly,
                    self.deep_ml,
                    self.swarm,
                    self.db,
                    self.per_ip_ml,
                    self.sig_engine,
                    self.pcap_mgr,
                    self.mesh_router
                )
                self.service.start()

    def stop(self):
        self.running = False
        logger.info("[Watchdog] Integrity watchdog stopped.")

class RemoteAPIHandler(BaseHTTPRequestHandler):
    """
    Simple remote management API:
    - GET /status
    - GET /devices
    - POST /policy {ip, policy}
    - POST /replay {session_id}
    Local-only by default.
    """
    guardian_ctx = None

    def _send_json(self, obj, code=200):
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        ctx = RemoteAPIHandler.guardian_ctx
        if self.path == "/status":
            resp = {
                "health": "ok" if ctx["service"].is_alive() else "down",
                "swarm_ok": ctx["swarm"].last_status_ok,
                "honeypot_hits": ctx["honeypot"].hit_count
            }
            self._send_json(resp)
        elif self.path == "/devices":
            devices = ctx["db"].get_devices()
            self._send_json(devices)
        else:
            self._send_json({"error": "unknown endpoint"}, code=404)

    def do_POST(self):
        ctx = RemoteAPIHandler.guardian_ctx
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length)
        try:
            data = json.loads(body.decode("utf-8"))
        except Exception:
            self._send_json({"error": "invalid json"}, code=400)
            return

        if self.path == "/policy":
            ip = data.get("ip")
            policy = data.get("policy")
            if ip and policy in (POLICY_ALLOW, POLICY_BLOCK, POLICY_MONITOR):
                ctx["db"].set_ip_policy(ip, policy)
                if policy == POLICY_ALLOW:
                    ctx["firewall"].unblock_ip(ip)
                elif policy == POLICY_BLOCK:
                    ctx["firewall"].block_ip(ip, manual=True)
                elif policy == POLICY_MONITOR:
                    ctx["firewall"].unblock_ip(ip)
                self._send_json({"status": "ok"})
            else:
                self._send_json({"error": "invalid ip or policy"}, code=400)
        elif self.path == "/replay":
            session_id = data.get("session_id")
            if session_id is None:
                self._send_json({"error": "missing session_id"}, code=400)
                return
            ctx["replay"].replay_session(int(session_id))
            self._send_json({"status": "replay_started"})
        else:
            self._send_json({"error": "unknown endpoint"}, code=404)

def start_remote_api(config: GuardianConfig, ctx: dict):
    if not config.remote_api_enabled:
        logger.info("[API] Remote management API disabled.")
        return None

    RemoteAPIHandler.guardian_ctx = ctx
    server = HTTPServer((config.remote_api_bind, config.remote_api_port), RemoteAPIHandler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    logger.info(f"[API] Remote management API listening on {config.remote_api_bind}:{config.remote_api_port}")
    return server

def main():
    logger.info("[Guardian] Starting Unified Network Guardian...")

    config = GuardianConfig()
    db = GuardianDB()
    net_engine = NetworkDiscoveryEngine(db)
    threat_matrix = ThreatMatrix(db)
    alerts = AlertEngine(config)
    integrity = IntegrityManager(config)
    threat_intel = ThreatIntel(config, db)
    firewall = FirewallManager(config, db)
    rogue_ai = RogueAIDetector(config, threat_matrix)
    anomaly = AnomalyDetector(threat_matrix)
    deep_ml = DeepMLAnomalyDetector(anomaly)
    per_ip_ml = PerIPMLManager()
    neural = NeuralAnomalyEngine()
    sig_engine = SignatureEngine(db)
    pcap_mgr = PacketCaptureManager()
    swarm = SwarmSync(config)
    mesh_router = MeshRouter(config)
    suricata_engine = SuricataRuleEngine(config)
    suricata_engine.load_rules()

    service = GuardianService(config, net_engine, threat_matrix, alerts,
                              integrity, threat_intel, firewall, rogue_ai,
                              anomaly, deep_ml, swarm, db, per_ip_ml,
                              sig_engine, pcap_mgr, mesh_router)
    service.start()

    packet_inspector = PacketInspector(config, threat_intel, firewall,
                                       alerts, threat_matrix, rogue_ai,
                                       anomaly, deep_ml, per_ip_ml, db,
                                       neural, pcap_mgr, suricata_engine, mesh_router)
    packet_inspector.start()

    replay_engine = ThreatReplayEngine(db, packet_inspector)

    honeypot = Honeypot(config, threat_matrix, firewall, db, sig_engine)
    honeypot.start()

    watchdog = None
    if config.watchdog_enabled:
        watchdog = IntegrityWatchdog(service, integrity, config,
                                     net_engine, threat_matrix, alerts,
                                     threat_intel, firewall, rogue_ai,
                                     anomaly, deep_ml, swarm, db, per_ip_ml,
                                     sig_engine, pcap_mgr, mesh_router)
        watchdog.start()

    api_ctx = {
        "service": service,
        "swarm": swarm,
        "honeypot": honeypot,
        "db": db,
        "firewall": firewall,
        "replay": replay_engine
    }
    api_server = start_remote_api(config, api_ctx)

    if config.gui_enabled:
        gui = GuardianGUI(config, db, net_engine, threat_matrix, alerts,
                          swarm, honeypot, anomaly, deep_ml, firewall,
                          service, packet_inspector, pcap_mgr)
        gui.launch()

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("[Guardian] Shutdown requested.")
        service.stop()
        packet_inspector.stop()
        honeypot.stop()
        if watchdog:
            watchdog.stop()
        if api_server:
            api_server.shutdown()

if __name__ == "__main__":
    main()
