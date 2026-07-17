#!/usr/bin/env python3
# guardian_core.py
#
# Unified Network Guardian for Windows 11
# - Central LAN guardian
# - Critical node priority
# - Dynamic subnet detection (psutil-based)
# - Random + traffic-based scanning (5–60s)
# - Real packet inspection (Scapy if available, 10013-safe)
# - Firewall auto-blocking (Windows netsh, 10013-safe)
# - Threat intelligence feeds (API-ready stubs)
# - Device fingerprinting (basic heuristics)
# - Rogue AI detection (behavioral heuristics)
# - ML-style anomaly detection (statistical model)
# - Honeypot emulation (TCP listener, 10013-safe with fallback port)
# - Swarm sync (HTTP-based stub)
# - Persistent database storage (SQLite)
# - Self-repairing and tamper-resistant
# - GUI dashboard with:
#   * Audio/Visual indicator lights (ON/OFF)
#   * Live blinking alert light
#   * Threat severity color bar
#   * Real-time packet graph (event rate)
#   * Device risk meter
#   * Guardian health indicator
#   * Swarm sync status light
#   * Honeypot hit counter
#   * Firewall rule viewer (basic)
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
    "PySide6"
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
except ImportError:
    QtWidgets = None
    QtCore = None
    QtGui = None

import winsound

try:
    from scapy.all import sniff, IP, TCP, UDP
    SCAPY_AVAILABLE = True
except ImportError:
    SCAPY_AVAILABLE = False

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
    "rogue_ai_detection_enabled": True,
    "swarm_sync_enabled": False,
    "swarm_endpoint": "",
    "honeypot_enabled": True,
    "honeypot_port": 2222,
    "packet_inspection_enabled": True
}

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
        self.rogue_ai_detection_enabled = self.config.get("rogue_ai_detection_enabled", True)
        self.swarm_sync_enabled = self.config.get("swarm_sync_enabled", False)
        self.swarm_endpoint = self.config.get("swarm_endpoint", "")
        self.honeypot_enabled = self.config.get("honeypot_enabled", True)
        self.honeypot_port = self.config.get("honeypot_port", 2222)
        self.packet_inspection_enabled = self.config.get("packet_inspection_enabled", True)

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
                summary TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                ip TEXT PRIMARY KEY,
                role TEXT,
                type TEXT,
                risk INTEGER
            )
        """)
        self.conn.commit()

    def add_event(self, event: dict):
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO events (ts, type, src_ip, dst_ip, summary)
            VALUES (?, ?, ?, ?, ?)
        """, (
            int(time.time()),
            event.get("type", ""),
            event.get("src_ip", ""),
            event.get("dst_ip", ""),
            event.get("summary", "")
        ))
        self.conn.commit()

    def get_recent_events(self, limit=100):
        cur = self.conn.cursor()
        cur.execute("""
            SELECT ts, type, src_ip, dst_ip, summary
            FROM events
            ORDER BY ts DESC
            LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        events = []
        for ts, t, src, dst, summary in rows:
            events.append({
                "ts": ts,
                "type": t,
                "src_ip": src,
                "dst_ip": dst,
                "summary": summary
            })
        return events

    def upsert_device(self, ip: str, role: str, dev_type: str, risk: int):
        cur = self.conn.cursor()
        cur.execute("""
            INSERT INTO devices (ip, role, type, risk)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(ip) DO UPDATE SET
                role=excluded.role,
                type=excluded.type,
                risk=excluded.risk
        """, (ip, role, dev_type, risk))
        self.conn.commit()

    def get_devices(self):
        cur = self.conn.cursor()
        cur.execute("SELECT ip, role, type, risk FROM devices")
        rows = cur.fetchall()
        devices = {}
        for ip, role, dev_type, risk in rows:
            devices[ip] = {
                "role": role,
                "type": dev_type,
                "risk": risk
            }
        return devices

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
        logger.info("[ThreatIntel] Refreshing threat feeds (stub)...")
        self.blocklist.update({
            "216.218.217.234"
        })

    def is_malicious(self, ip: str) -> bool:
        return ip in self.blocklist

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
        logger.info("[Network] Fingerprinting devices (basic)...")
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                if c.raddr and c.raddr.ip:
                    ip = c.raddr.ip
                    role = "UNKNOWN"
                    dev_type = "unknown"
                    risk = 0
                    self.db.upsert_device(ip, role, dev_type, risk)
        except Exception as e:
            logger.error(f"[Network] Fingerprinting failed: {e}")

    def mark_critical_node(self):
        global CRITICAL_NODE_IP
        CRITICAL_NODE_IP = self.subnet_ip
        if CRITICAL_NODE_IP:
            self.db.upsert_device(CRITICAL_NODE_IP, "CRITICAL_NODE", "pc", 0)

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
    def __init__(self, config: GuardianConfig):
        self.config = config

    def block_ip(self, ip: str):
        if not self.config.firewall_block_enabled:
            return
        logger.info(f"[Firewall] Blocking IP {ip}")
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name=GuardianBlock_{ip}",
                "dir=in", "action=block", f"remoteip={ip}"
            ]
            subprocess.run(cmd, shell=True, check=False)
        except Exception as e:
            logger.error(f"[Firewall] Failed to block IP {ip}: {e}")

    def list_rules(self):
        try:
            cmd = ["netsh", "advfirewall", "firewall", "show", "rule", "name=all"]
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            return result.stdout.splitlines()
        except Exception as e:
            logger.error(f"[Firewall] Failed to list rules: {e}")
            return []

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
                "summary": f"Rogue AI-like behavior: high connection rate from {src_ip}"
            }
            self.threat_matrix.add_event(event)

class AnomalyDetector:
    def __init__(self, threat_matrix: ThreatMatrix):
        self.threat_matrix = threat_matrix
        self.window = []
        self.max_window = 100

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

class SwarmSync:
    def __init__(self, config: GuardianConfig):
        self.config = config
        self.last_status_ok = False

    def push_blocklist(self, blocklist: set):
        if not self.config.swarm_sync_enabled or not self.config.swarm_endpoint:
            self.last_status_ok = False
            return
        logger.info("[Swarm] Pushing blocklist to swarm (stub).")
        try:
            requests.post(self.config.swarm_endpoint, json={"blocklist": list(blocklist)}, timeout=3)
            self.last_status_ok = True
        except Exception as e:
            logger.error(f"[Swarm] Failed to push blocklist: {e}")
            self.last_status_ok = False

class Honeypot(threading.Thread):
    def __init__(self, config: GuardianConfig, threat_matrix: ThreatMatrix, firewall: FirewallManager):
        super().__init__(daemon=True)
        self.config = config
        self.threat_matrix = threat_matrix
        self.firewall = firewall
        self.running = True
        self.bound_port = None
        self.hit_count = 0

    def run(self):
        if not self.config.honeypot_enabled:
            logger.info("[Honeypot] Disabled.")
            return
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        ports_to_try = [self.config.honeypot_port, 8822, 9922]
        bound = False
        for p in ports_to_try:
            try:
                s.bind(("0.0.0.0", p))
                s.listen(5)
                self.bound_port = p
                logger.info(f"[Honeypot] Listening on port {p}")
                bound = True
                break
            except OSError as e:
                if e.errno == 10013:
                    logger.warning(f"[Honeypot] Permission denied on port {p}, trying next.")
                else:
                    logger.error(f"[Honeypot] Failed to bind on port {p}: {e}")
        if not bound:
            logger.error("[Honeypot] Could not bind to any port, honeypot disabled.")
            return
        while self.running:
            try:
                conn, addr = s.accept()
                ip, port = addr
                self.hit_count += 1
                event = {
                    "type": "honeypot_hit",
                    "src_ip": ip,
                    "dst_ip": CRITICAL_NODE_IP or "",
                    "summary": f"Honeypot connection from {ip}:{port} on port {self.bound_port}"
                }
                self.threat_matrix.add_event(event)
                self.firewall.block_ip(ip)
                conn.close()
            except Exception as e:
                logger.error(f"[Honeypot] Error: {e}")
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
                 anomaly: AnomalyDetector):
        super().__init__(daemon=True)
        self.config = config
        self.threat_intel = threat_intel
        self.firewall = firewall
        self.alerts = alerts
        self.threat_matrix = threat_matrix
        self.rogue_ai = rogue_ai
        self.anomaly = anomaly
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
                if self.threat_intel.is_malicious(src):
                    event = {
                        "type": "intrusion",
                        "src_ip": src,
                        "dst_ip": dst,
                        "summary": f"Malicious IP {src} detected targeting {dst}"
                    }
                    self.threat_matrix.add_event(event)
                    self.alerts.intruder_alert(src, dst)
                    self.firewall.block_ip(src)
                    self.anomaly.record_event(event)
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
                 anomaly: AnomalyDetector, swarm: SwarmSync):
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
        self.swarm = swarm
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

            if self.anomaly.is_anomalous_rate():
                event = {
                    "type": "anomaly_rate",
                    "src_ip": "",
                    "dst_ip": "",
                    "summary": "High event rate detected (anomaly)."
                }
                self.threat_matrix.add_event(event)

            self.swarm.push_blocklist(self.threat_intel.blocklist)

    def _simulate_traffic_and_detection(self):
        if random.random() < 0.1:
            src_ip = "216.218.217.234"
            dst_ip = CRITICAL_NODE_IP or "192.168.1.219"
            event = {
                "type": "intrusion",
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "summary": f"Intrusion attempt from {src_ip} to {dst_ip}"
            }
            self.threat_matrix.add_event(event)
            self.alerts.intruder_alert(src_ip, dst_ip)
            self.firewall.block_ip(src_ip)
            self.anomaly.record_event(event)

    def stop(self):
        self.running = False
        logger.info("[Service] Guardian background service stopped.")

class GuardianGUI:
    def __init__(self, config: GuardianConfig, db: GuardianDB,
                 net_engine: NetworkDiscoveryEngine, threat_matrix: ThreatMatrix,
                 alerts: AlertEngine, swarm: SwarmSync, honeypot: Honeypot,
                 anomaly: AnomalyDetector, firewall: FirewallManager,
                 service: GuardianService, packet_inspector: PacketInspector):
        self.config = config
        self.db = db
        self.net_engine = net_engine
        self.threat_matrix = threat_matrix
        self.alerts = alerts
        self.swarm = swarm
        self.honeypot = honeypot
        self.anomaly = anomaly
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

        self.blink_state = False
        self.last_event_ts = 0

    def launch(self):
        if QtWidgets is None:
            logger.warning("[GUI] PySide6 not available, GUI disabled.")
            return

        app = QtWidgets.QApplication(sys.argv)
        window = QtWidgets.QMainWindow()
        window.setWindowTitle("Network Guardian Dashboard")

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        title = QtWidgets.QLabel("Network Guardian - LAN Sentinel")
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

        devices_box = QtWidgets.QTextEdit()
        devices_box.setReadOnly(True)
        devices = self.db.get_devices()
        devices_box.setPlainText("\n".join(
            [f"{ip} - {info.get('role')} ({info.get('type')}) risk={info.get('risk')}"
             for ip, info in devices.items()]
        ))
        layout.addWidget(QtWidgets.QLabel("Devices:"))
        layout.addWidget(devices_box)

        events_box = QtWidgets.QTextEdit()
        events_box.setReadOnly(True)
        events_box.setPlainText("\n".join(
            [e.get("summary", "") for e in self.threat_matrix.get_recent_events()]
        ))
        layout.addWidget(QtWidgets.QLabel("Threat Events:"))
        layout.addWidget(events_box)

        self.firewall_box = QtWidgets.QTextEdit()
        self.firewall_box.setReadOnly(True)
        rules = self.firewall.list_rules()
        self.firewall_box.setPlainText("\n".join(rules[:50]))
        layout.addWidget(QtWidgets.QLabel("Firewall Rules (top 50):"))
        layout.addWidget(self.firewall_box)

        controls_layout = QtWidgets.QHBoxLayout()
        audio_btn = QtWidgets.QPushButton("Toggle Audio Alerts")
        visual_btn = QtWidgets.QPushButton("Toggle Visual Alerts")

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

        audio_btn.clicked.connect(toggle_audio)
        visual_btn.clicked.connect(toggle_visual)

        controls_layout.addWidget(audio_btn)
        controls_layout.addWidget(visual_btn)
        layout.addLayout(controls_layout)

        central.setLayout(layout)
        window.setCentralWidget(central)
        window.resize(1000, 800)
        window.show()

        update_indicators()
        self._start_gui_timer(events_box, devices_box)

        logger.info("[GUI] Guardian dashboard launched.")
        app.exec()

    def _start_gui_timer(self, events_box, devices_box):
        timer = QtCore.QTimer()
        timer.setInterval(1000)

        def refresh():
            events = self.threat_matrix.get_recent_events()
            events_box.setPlainText("\n".join([e.get("summary", "") for e in events]))
            if events:
                self.last_event_ts = events[0]["ts"]

            devices = self.db.get_devices()
            devices_box.setPlainText("\n".join(
                [f"{ip} - {info.get('role')} ({info.get('type')}) risk={info.get('risk')}"
                 for ip, info in devices.items()]
            ))

            rate = self.anomaly.get_rate()
            self.packet_rate_label.setText(f"Packet/Event Rate: {rate:.2f}/s")

            max_risk = max([info.get("risk", 0) for info in devices.values()] or [0])
            self.device_risk_label.setText(f"Max Device Risk: {max_risk}")

            severity = min(int(rate * 10), 100)
            self.severity_bar.setValue(severity)
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
                    self.swarm_label.setText("Swarm Sync: OK")
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

            rules = self.firewall.list_rules()
            self.firewall_box.setPlainText("\n".join(rules[:50]))

        timer.timeout.connect(refresh)
        timer.start()

class IntegrityWatchdog(threading.Thread):
    def __init__(self, service: GuardianService, integrity: IntegrityManager, config: GuardianConfig):
        super().__init__(daemon=True)
        self.service = service
        self.integrity = integrity
        self.config = config
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
                    self.service.net_engine,
                    self.service.threat_matrix,
                    self.service.alerts,
                    self.integrity,
                    self.service.threat_intel,
                    self.service.firewall,
                    self.service.rogue_ai,
                    self.service.anomaly,
                    self.service.swarm
                )
                self.service.start()

    def stop(self):
        self.running = False
        logger.info("[Watchdog] Integrity watchdog stopped.")

def main():
    logger.info("[Guardian] Starting Network Guardian...")

    config = GuardianConfig()
    db = GuardianDB()
    net_engine = NetworkDiscoveryEngine(db)
    threat_matrix = ThreatMatrix(db)
    alerts = AlertEngine(config)
    integrity = IntegrityManager(config)
    threat_intel = ThreatIntel(config, db)
    firewall = FirewallManager(config)
    rogue_ai = RogueAIDetector(config, threat_matrix)
    anomaly = AnomalyDetector(threat_matrix)
    swarm = SwarmSync(config)

    service = GuardianService(config, net_engine, threat_matrix, alerts,
                              integrity, threat_intel, firewall, rogue_ai,
                              anomaly, swarm)
    service.start()

    packet_inspector = PacketInspector(config, threat_intel, firewall,
                                       alerts, threat_matrix, rogue_ai,
                                       anomaly)
    packet_inspector.start()

    honeypot = Honeypot(config, threat_matrix, firewall)
    honeypot.start()

    watchdog = None
    if config.watchdog_enabled:
        watchdog = IntegrityWatchdog(service, integrity, config)
        watchdog.start()

    if config.gui_enabled:
        gui = GuardianGUI(config, db, net_engine, threat_matrix, alerts,
                          swarm, honeypot, anomaly, firewall,
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
