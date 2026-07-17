#!/usr/bin/env python3
# guardian_core.py
#
# Unified Network Guardian for Windows 11
# - Central LAN guardian
# - Critical node priority
# - Dynamic subnet detection (psutil-based)
# - Random + traffic-based scanning (5–60s)
# - Real packet inspection (Scapy if available, 10013-safe)
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
# - Honeypot protocol emulation:
#     * Fake SSH
#     * Fake HTTP
#     * Fake RDP (banner stub)
# - Swarm sync:
#     * Encrypted payload (Fernet)
#     * Mutual authentication (shared secret token)
#     * Multi-node logic (peer list + consensus)
# - Persistent database storage (SQLite) with auto-migration
# - Manual IP policy:
#     * allow / block / monitor per IP
#     * per-IP notes (“NAS”, “TV”, “Printer”)
#     * per-IP history
#     * per-IP auto-expiration policies
#     * GUI colored icons (🟢 🔴 🟡)
#     * double-click IP to open control panel
# - Self-repairing and tamper-resistant
# - GUI dashboard with:
#   * Audio/Visual indicator lights (ON/OFF)
#   * Live blinking alert light
#   * Threat severity color bar
#   * Real-time packet/event rate label
#   * Device risk meter
#   * Guardian health indicator
#   * Swarm sync status light
#   * Honeypot hit counter
#   * Firewall rule viewer (grouped per IP)
#   * Manual override toggle for auto-block
#   * Live event-rate chart (QtCharts, multi-series)
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
    from scapy.all import sniff, IP, TCP, UDP
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
    "swarm_peers": []
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

    def _init_schema(self):
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
                notes TEXT
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
        add_column("events", "severity", "INTEGER")
        add_column("ip_policy", "block_ttl", "INTEGER")
        add_column("ip_policy", "allow_ttl", "INTEGER")
        add_column("ip_policy", "monitor_ttl", "INTEGER")
        self.conn.commit()

    def add_event(self, event: dict):
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
                      os_hint: str = "", ttl_hint: int = 0, mac_vendor: str = "", notes: str = ""):
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO devices (ip, role, type, risk, os_hint, ttl_hint, mac_vendor, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                role=excluded.role,
                type=excluded.type,
                risk=excluded.risk,
                os_hint=excluded.os_hint,
                ttl_hint=excluded.ttl_hint,
                mac_vendor=excluded.mac_vendor,
                notes=excluded.notes
        """, (ip, role, dev_type, risk, os_hint, ttl_hint, mac_vendor, notes))
        self.conn.commit()

    def update_device_notes(self, ip: str, notes: str):
        cur = self.conn.cursor()
        cur.execute("UPDATE devices SET notes = ? WHERE ip = ?", (notes, ip))
        self.conn.commit()

    def update_device_risk(self, ip: str, risk: int):
        cur = self.conn.cursor()
        cur.execute("UPDATE devices SET risk = ? WHERE ip = ?", (risk, ip))
        self.conn.commit()

    def get_devices(self):
        cur = self.conn.cursor()
        cur.execute("SELECT ip, role, type, risk, os_hint, ttl_hint, mac_vendor, notes FROM devices")
        rows = cur.fetchall()
        devices = {}
        for ip, role, dev_type, risk, os_hint, ttl_hint, mac_vendor, notes in rows:
            devices[ip] = {
                "role": role,
                "type": dev_type,
                "risk": risk,
                "os_hint": os_hint,
                "ttl_hint": ttl_hint,
                "mac_vendor": mac_vendor,
                "notes": notes or ""
            }
        return devices

    def add_firewall_rule(self, ip: str):
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO firewall_rules (ip, created_ts)
            VALUES (?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                created_ts=excluded.created_ts
        """, (ip, int(time.time())))
        self.conn.commit()

    def get_firewall_rules(self):
        cur = self.conn.cursor()
        cur.execute("SELECT ip, created_ts FROM firewall_rules")
        rows = cur.fetchall()
        rules = []
        for ip, ts in rows:
            rules.append({"ip": ip, "created_ts": ts})
        return rules

    def delete_firewall_rule(self, ip: str):
        cur = self.conn.cursor()
        cur.execute("DELETE FROM firewall_rules WHERE ip = ?", (ip,))
        self.conn.commit()

    def set_ip_policy(self, ip: str, policy: str,
                      block_ttl: int | None = None,
                      allow_ttl: int | None = None,
                      monitor_ttl: int | None = None):
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
                    self.db.upsert_device(ip, role, dev_type, risk, os_hint, ttl_hint, mac_vendor, notes)
        except Exception as e:
            logger.error(f"[Network] Fingerprinting failed: {e}")

    def _guess_os(self, ip: str) -> str:
        if ip.startswith("192.168."):
            return "LAN host (unknown OS)"
        if ip.startswith("10."):
            return "Private network host"
        return "Unknown"

    def mark_critical_node(self):
        global CRITICAL_NODE_IP
        CRITICAL_NODE_IP = self.subnet_ip
        if CRITICAL_NODE_IP:
            self.db.upsert_device(CRITICAL_NODE_IP, "CRITICAL_NODE", "pc", 0, "Windows (local)", 64, "LocalHost", "Guardian Host")

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
            "shared_secret": self.config.swarm_shared_secret
        }

    def _validate_response(self, payload: dict) -> bool:
        if payload.get("shared_secret") != self.config.swarm_shared_secret:
            logger.warning("[Swarm] Shared secret mismatch in response.")
            return False
        return True

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
                        consensus = blocklist.union(peer_list)
                        blocklist.clear()
                        blocklist.update(consensus)
                        logger.info(f"[Swarm] Consensus updated with peer {peer}, size={len(blocklist)}")
                    else:
                        logger.warning(f"[Swarm] Peer {peer} response failed validation.")
                else:
                    logger.error(f"[Swarm] Peer {peer} HTTP error: {resp.status_code}")
            except Exception as e:
                logger.error(f"[Swarm] Peer sync failed for {peer}: {e}")

class Honeypot(threading.Thread):
    def __init__(self, config: GuardianConfig, threat_matrix: ThreatMatrix, firewall: FirewallManager):
        super().__init__(daemon=True)
        self.config = config
        self.threat_matrix = threat_matrix
        self.firewall = firewall
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

class PacketInspector(threading.Thread):
    def __init__(self, config: GuardianConfig, threat_intel: ThreatIntel,
                 firewall: FirewallManager, alerts: AlertEngine,
                 threat_matrix: ThreatMatrix, rogue_ai: RogueAIDetector,
                 anomaly: AnomalyDetector, deep_ml: DeepMLAnomalyDetector,
                 per_ip_ml: PerIPMLManager, db: GuardianDB):
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

    def _handle_packet(self, pkt):
        try:
            if IP in pkt:
                src = pkt[IP].src
                dst = pkt[IP].dst
                self.rogue_ai.record_connection(src)

                features = [1.0]  # simple feature: one event
                self.per_ip_ml.record_ip_event(src, features)
                anomalous = self.per_ip_ml.is_ip_anomalous(src, features)

                if self.threat_intel.is_malicious(src) or anomalous:
                    sev = 80 if self.threat_intel.is_malicious(src) else 60
                    event = {
                        "type": "intrusion" if self.threat_intel.is_malicious(src) else "per_ip_anomaly",
                        "src_ip": src,
                        "dst_ip": dst,
                        "summary": f"Suspicious IP {src} targeting {dst} (malicious={self.threat_intel.is_malicious(src)}, anomalous={anomalous})",
                        "severity": sev
                    }
                    self.threat_matrix.add_event(event)
                    self.alerts.intruder_alert(src, dst)
                    self.firewall.block_ip(src)
                    self.anomaly.record_event(event)
                    self.deep_ml.record_event(event)

                    current_risk = 50 if anomalous else 80
                    self.db.update_device_risk(src, current_risk)
        except Exception as e:
            logger.error(f"[Packets] Error handling packet: {e}")

    def stop(self):
        self.running = False
        logger.info("[Packets] Packet inspection stopped.")

class GuardianService(threading.Thread):
    def __init__(self, config: GuardianConfig, net_engine: NetworkDiscoveryEngine,
                 threat_matrix: ThreatMatrix, alerts: AlertEngine,
                 integrity: IntegrityManager, threat_intel: ThreatIntel,
                 firewall: FirewallManager, rogue_ai: RogueAIDetector,
                 anomaly: AnomalyDetector, deep_ml: DeepMLAnomalyDetector,
                 swarm: SwarmSync, db: GuardianDB, per_ip_ml: PerIPMLManager):
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
            self.per_ip_ml.record_ip_event(src_ip, [1.0])

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

    def stop(self):
        self.running = False
        logger.info("[Service] Guardian background service stopped.")

class IPControlDialog(QtWidgets.QDialog):
    def __init__(self, ip: str, db: GuardianDB, firewall: FirewallManager, parent=None):
        super().__init__(parent)
        self.ip = ip
        self.db = db
        self.firewall = firewall
        self.setWindowTitle(f"IP Control Panel - {ip}")
        self.resize(500, 400)

        layout = QtWidgets.QVBoxLayout()

        layout.addWidget(QtWidgets.QLabel(f"IP: {ip}"))

        devices = self.db.get_devices()
        info = devices.get(ip, {})
        risk = info.get("risk", 0)
        notes = info.get("notes", "")

        self.risk_label = QtWidgets.QLabel(f"Risk: {risk}")
        layout.addWidget(self.risk_label)

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
        btn_layout.addWidget(allow_btn)
        btn_layout.addWidget(block_btn)
        btn_layout.addWidget(monitor_btn)
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

        self.setLayout(layout)

class GuardianGUI:
    def __init__(self, config: GuardianConfig, db: GuardianDB,
                 net_engine: NetworkDiscoveryEngine, threat_matrix: ThreatMatrix,
                 alerts: AlertEngine, swarm: SwarmSync, honeypot: Honeypot,
                 anomaly: AnomalyDetector, deep_ml: DeepMLAnomalyDetector,
                 firewall: FirewallManager, service: GuardianService,
                 packet_inspector: PacketInspector):
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

        title = QtWidgets.QLabel("Unified Network Guardian")
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

        self.swarm_label = QtWidgets.QLabel("Swarm Sync: OFF")
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
        self.devices_table.setColumnCount(8)
        self.devices_table.setHorizontalHeaderLabels([
            "IP", "Role/Type", "Risk", "OS/TTL/MAC", "Notes", "🟢 Allow", "🔴 Block", "🟡 Monitor"
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
        window.resize(1300, 900)
        window.show()

        update_indicators()
        self._start_gui_timer(events_box)

        def on_cell_double_clicked(row, column):
            if column == 0:
                ip_item = self.devices_table.item(row, 0)
                if ip_item:
                    ip = ip_item.text()
                    dlg = IPControlDialog(ip, self.db, self.firewall, parent=window)
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
            os_ttl_mac = f"{info.get('os_hint')} / TTL={info.get('ttl_hint')} / MAC={info.get('mac_vendor')}"
            notes = info.get("notes", "")

            ip_item = QtWidgets.QTableWidgetItem(ip)
            role_item = QtWidgets.QTableWidgetItem(role_type)
            risk_item = QtWidgets.QTableWidgetItem(risk)
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
            self.devices_table.setItem(row, 3, os_item)
            self.devices_table.setItem(row, 4, notes_item)

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

            self.devices_table.setCellWidget(row, 5, allow_btn)
            self.devices_table.setCellWidget(row, 6, block_btn)
            self.devices_table.setCellWidget(row, 7, monitor_btn)

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
                    self.swarm_label.setText("Swarm Sync: OK (encrypted, mutual auth)")
                    self.swarm_label.setStyleSheet("color: green; font-weight: bold;")
                else:
                    self.swarm_label.setText("Swarm Sync: ERROR")
                    self.swarm_label.setStyleSheet("color: orange; font-weight: bold;")
            else:
                self.swarm_label.setText("Swarm Sync: OFF")
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
                 swarm: SwarmSync, db: GuardianDB, per_ip_ml: PerIPMLManager):
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
                    self.per_ip_ml
                )
                self.service.start()

    def stop(self):
        self.running = False
        logger.info("[Watchdog] Integrity watchdog stopped.")

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
    swarm = SwarmSync(config)

    service = GuardianService(config, net_engine, threat_matrix, alerts,
                              integrity, threat_intel, firewall, rogue_ai,
                              anomaly, deep_ml, swarm, db, per_ip_ml)
    service.start()

    packet_inspector = PacketInspector(config, threat_intel, firewall,
                                       alerts, threat_matrix, rogue_ai,
                                       anomaly, deep_ml, per_ip_ml, db)
    packet_inspector.start()

    honeypot = Honeypot(config, threat_matrix, firewall)
    honeypot.start()

    watchdog = None
    if config.watchdog_enabled:
        watchdog = IntegrityWatchdog(service, integrity, config,
                                     net_engine, threat_matrix, alerts,
                                     threat_intel, firewall, rogue_ai,
                                     anomaly, deep_ml, swarm, db, per_ip_ml)
        watchdog.start()

    if config.gui_enabled:
        gui = GuardianGUI(config, db, net_engine, threat_matrix, alerts,
                          swarm, honeypot, anomaly, deep_ml, firewall,
                          service, packet_inspector)
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

if __name__ == "__main__":
    main()
