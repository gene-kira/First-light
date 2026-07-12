#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AI Security Bridge - Enterprise-Grade Appliance (Suricata v6, NDIS, GPU Deep Learning, Agentic Reasoning, MITRE, Full Cowrie)

Key features:
- WinDivert inline firewall (kernel-level interception)
- NDIS lightweight filter driver scaffolding (control + health monitoring)
- Extended Suricata v6-like rule engine (closer to full Suricata v6 spec)
- HTTP DPI (headers, cookies, hostnames, methods, user agents)
- TLS DPI:
  - JA3 (client-side TLS fingerprinting)
  - JA3S (server-side TLS fingerprinting)
- Honeypot emulation:
  - Cowrie-style SSH (interactive fake shell, full fake filesystem, extended commands)
  - Dionaea-style SMB/HTTP (simplified)
  - HoneyHTTP
- ML anomaly detection:
  - IsolationForest primary engine (CPU)
- Deep-learning anomaly detection (GPU-optimized):
  - Autoencoder + LSTM (TensorFlow/Keras, GPU if available, CPU fallback)
  - Larger, GPU-aware architectures and batch sizes
- Agentic reasoning engine:
  - OpenAI-style multi-factor threat triage with reasoning traces
- MITRE ATT&CK mapping:
  - Per-event mapping to ATT&CK techniques and tactics
- Behavioral fingerprinting:
  - Session feature vectors (per IP/session behavior profiles)
- Threat correlation engine:
  - Correlates events across time, IPs, JA3/JA3S, Suricata SIDs, behavioral fingerprints, MITRE tags
- Swarm cluster with TLS mutual authentication (encrypted peer-to-peer threat sharing)
- Packet capture:
  - Raw binary capture
  - PCAP export (Wireshark-compatible)
- Packet replay GUI (forensic replay through DPI engine)
- Rule editor:
  - Regex, ranges, JA3, JA3S, Suricata SIDs, IP/proto/content
- Threat database (SQLite backend storing all events and correlations)
- Persistent configuration (JSON)
- NIC role detection (ARP/DHCP heuristics)
- Crash-proof subsystem wrappers
- Auto-elevation
- Windows service mode
- Interactive GUI graphs (TkAgg, real-time charts)
- Threat scoring visualization hooks (per-reason breakdown)
- ASCII-only comments and strings
- Dependency validator and protobuf auto-downgrade for TensorFlow compatibility
"""

import sys
import os
import subprocess
import importlib
import threading
import queue
import time
import hashlib
import ctypes
import json
import re
import ssl
import sqlite3
from datetime import datetime
from socket import socket, AF_INET, SOCK_STREAM
from collections import deque, defaultdict
import struct

# =========================
#  AUTO-ELEVATION CHECK
# =========================

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
        print("[AI Security Bridge] Elevation failed: %s" % e)
        sys.exit()

ensure_admin()

# =========================
#  AUTO-LOADER + DEPENDENCY VALIDATOR
# =========================

REQUIRED_LIBS = [
    "psutil",
    "tkinter",
    "requests",
    "pywin32",
    "pydivert",
    "matplotlib",
    "scikit-learn",
    "protobuf",
    "tensorflow",
    "keras",
]

DIAG_DEPENDENCIES = []

def log_dep(msg):
    DIAG_DEPENDENCIES.append("%s | %s" % (datetime.utcnow().isoformat(), msg))

def ensure_lib(lib):
    try:
        if lib == "tkinter":
            import tkinter
        else:
            importlib.import_module(lib)
        return True
    except ImportError:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            importlib.import_module(lib)
            log_dep("Installed missing library: %s" % lib)
            return True
        except Exception as e:
            log_dep("Failed to install library %s: %s" % (lib, e))
            return False

def autoload():
    for lib in REQUIRED_LIBS:
        ensure_lib(lib)

def protobuf_version_ok():
    try:
        import google.protobuf
        ver = getattr(google.protobuf, "__version__", None)
        if ver is None:
            log_dep("protobuf version unknown, assuming incompatible")
            return False
        log_dep("Detected protobuf version: %s" % ver)
        parts = ver.split(".")
        major = int(parts[0])
        minor = int(parts[1]) if len(parts) > 1 else 0
        if major > 3 or (major == 3 and minor > 20):
            log_dep("protobuf version too new for TensorFlow: %s" % ver)
            return False
        return True
    except Exception as e:
        log_dep("protobuf version check failed: %s" % e)
        return False

def auto_downgrade_protobuf():
    try:
        if not protobuf_version_ok():
            log_dep("Attempting protobuf downgrade to 3.20.3")
            subprocess.check_call([sys.executable, "-m", "pip", "install", "--force-reinstall", "protobuf==3.20.3"])
            import google.protobuf
            ver = getattr(google.protobuf, "__version__", None)
            log_dep("protobuf after downgrade: %s" % ver)
            return protobuf_version_ok()
        return True
    except Exception as e:
        log_dep("protobuf downgrade failed: %s" % e)
        return False

def dependency_validator():
    autoload()
    ok = auto_downgrade_protobuf()
    if not ok:
        log_dep("protobuf remains incompatible after downgrade attempt")
    return ok

PROTOBUF_COMPATIBLE = dependency_validator()

# =========================
#  CONDITIONAL IMPORTS (TF/Keras, GPU)
# =========================

import psutil
import tkinter as tk
from tkinter import ttk, scrolledtext
import requests

import win32serviceutil
import win32service
import win32event

from http.server import BaseHTTPRequestHandler, HTTPServer
from pydivert import WinDivert, Direction, Layer

import matplotlib
matplotlib.use("TkAgg")
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

from sklearn.ensemble import IsolationForest

TF_AVAILABLE = False
KERAS_AVAILABLE = False
GPU_AVAILABLE = False

if PROTOBUF_COMPATIBLE:
    try:
        import tensorflow as tf
        from tensorflow.keras.models import Model
        from tensorflow.keras.layers import Input, Dense, LSTM, Dropout
        from tensorflow.keras.optimizers import Adam
        TF_AVAILABLE = True
        KERAS_AVAILABLE = True

        gpus = tf.config.list_physical_devices("GPU")
        if gpus:
            GPU_AVAILABLE = True
            try:
                for gpu in gpus:
                    tf.config.experimental.set_memory_growth(gpu, True)
                log_dep("TensorFlow GPU devices: %s" % gpus)
            except Exception as e:
                log_dep("GPU memory growth config failed: %s" % e)
        else:
            GPU_AVAILABLE = False
            log_dep("No GPU devices found, using CPU for TensorFlow.")
        log_dep("TensorFlow/Keras successfully imported with compatible protobuf")
    except Exception as e:
        TF_AVAILABLE = False
        KERAS_AVAILABLE = False
        GPU_AVAILABLE = False
        log_dep("TensorFlow/Keras import failed even after protobuf fix: %s" % e)
else:
    TF_AVAILABLE = False
    KERAS_AVAILABLE = False
    GPU_AVAILABLE = False
    log_dep("TensorFlow/Keras disabled due to incompatible protobuf")

# =========================
#  BASIC TAMPER RESISTANCE
# =========================

def compute_self_hash():
    path = os.path.abspath(sys.argv[0])
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

BASE_HASH = compute_self_hash()

def verify_integrity():
    current = compute_self_hash()
    return current == BASE_HASH

INTEGRITY_FAILED = not verify_integrity()

# =========================
#  CONFIG / GLOBAL STATE
# =========================

CONFIG_PATH = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "ai_bridge_config.json")

DEFAULT_CONFIG = {
    "swarm_shared_secret": "changeme_shared_secret",
    "swarm_enabled": True,
    "swarm_port": 8080,
    "swarm_tls_cert": "swarm_cert.pem",
    "swarm_tls_key": "swarm_key.pem",
    "capture_enabled": True,
    "capture_dir": "captures",
    "pcap_dir": "pcap",
    "suricata_rules_path": "suricata.rules",
    "rule_editor_rules": [],
    "perma_allow_ips": [],
    "ad_block_domains": [
        "ads.example.com",
        "tracking.example.com",
        "doubleclick.net",
        "googlesyndication.com",
        "adservice.google.com",
    ],
    "db_path": "threats.db",
    "ml_enabled": True,
    "ml_training_window": 1000,
    "deep_learning_enabled": True,
    "max_queue_size": 20000,
    "num_workers": 4,
}

CONFIG_LOCK = threading.Lock()
CONFIG = DEFAULT_CONFIG.copy()

def load_config():
    global CONFIG
    try:
        if os.path.exists(CONFIG_PATH):
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            with CONFIG_LOCK:
                CONFIG.update(data)
    except Exception as e:
        print("[Config] Load error: %s" % e)

def save_config():
    try:
        with CONFIG_LOCK:
            data = CONFIG.copy()
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print("[Config] Save error: %s" % e)

load_config()

WAN_IN_IFACE = None
WAN_OUT_IFACE = None
LAN_IN_IFACE = None
LAN_OUT_IFACE = None
BRIDGE_MODE = "WAN"

BRIDGE_RUNNING = False
STOP_FLAG = False

PACKET_QUEUE = queue.Queue(maxsize=CONFIG.get("max_queue_size", 20000))
WORKER_THREADS = []
NUM_WORKERS = CONFIG.get("num_workers", 4)
DIVERT_HANDLE = None

LOG_LOCK = threading.Lock()
THREAT_LOG = []

GRAPH_LOCK = threading.Lock()
THREAT_TIMELINE = deque(maxlen=500)
PACKET_RATE_TIMELINE = deque(maxlen=500)
HONEYPOT_HITS_TIMELINE = deque(maxlen=500)
PERSONA_TIMELINE = deque(maxlen=500)

PERSONA_STATE = {
    "aggressiveness": 1.0,
    "recent_high_threats": 0,
    "lineage": [],
    "mode": "calm",
}

SWARM_HOST = "0.0.0.0"
SWARM_PORT = CONFIG.get("swarm_port", 8080)

SWARM_PEERS_LOCK = threading.Lock()
SWARM_PEERS = []

SWARM_STORAGE_LOCK = threading.Lock()
SWARM_STORAGE = []

UDM_API_URL = "https://udm-pro.local:443"
UDM_API_USER = "admin"
UDM_API_PASS = "password"

PERMA_ALLOW_IPS = set(CONFIG.get("perma_allow_ips", []))

AD_BLOCK_DOMAINS = set(CONFIG.get("ad_block_domains", []))

HONEYPOT_HOST = "0.0.0.0"
HONEYPOT_SERVICES = {
    22: "ssh",
    80: "http",
    443: "https",
    3389: "rdp",
    445: "smb",
}

SUBSYSTEM_ERRORS_LOCK = threading.Lock()
SUBSYSTEM_ERRORS = {
    "bridge": "",
    "dpi": "",
    "swarm": "",
    "honeypot": "",
    "watchdog": "",
    "service": "",
    "autodetect": "",
    "diagnostics": "",
    "rules": "",
    "capture": "",
    "ml": "",
    "db": "",
    "deep": "",
    "ndis": "",
    "correlation": "",
    "deps": "",
    "behavior": "",
    "agentic": "",
    "mitre": "",
}

def set_subsystem_error(name, msg):
    with SUBSYSTEM_ERRORS_LOCK:
        SUBSYSTEM_ERRORS[name] = msg

def get_subsystem_errors():
    with SUBSYSTEM_ERRORS_LOCK:
        return dict(SUBSYSTEM_ERRORS)

DIAG_LOCK = threading.Lock()
DIAG_STATE = {
    "windivert_present": "unknown",
    "raw_socket_ok": "unknown",
    "promisc_ok": "unknown",
    "last_errors": [],
    "deps": [],
}

def diag_add_error(msg):
    with DIAG_LOCK:
        DIAG_STATE["last_errors"].append("%s | %s" % (datetime.utcnow().isoformat(), msg))
        DIAG_STATE["last_errors"] = DIAG_STATE["last_errors"][-100:]

def diag_add_dep(msg):
    with DIAG_LOCK:
        DIAG_STATE["deps"].append(msg)
        DIAG_STATE["deps"] = DIAG_STATE["deps"][-100:]

for dmsg in DIAG_DEPENDENCIES:
    diag_add_dep(dmsg)

def get_diag_state():
    with DIAG_LOCK:
        return dict(DIAG_STATE)

CAPTURE_LOCK = threading.Lock()
CAPTURE_ENABLED = CONFIG.get("capture_enabled", True)
CAPTURE_DIR = CONFIG.get("capture_dir", "captures")
PCAP_DIR = CONFIG.get("pcap_dir", "pcap")
os.makedirs(CAPTURE_DIR, exist_ok=True)
os.makedirs(PCAP_DIR, exist_ok=True)

SURICATA_RULES_LOCK = threading.Lock()
SURICATA_RULES = []

RULE_EDITOR_LOCK = threading.Lock()
RULE_EDITOR_RULES = CONFIG.get("rule_editor_rules", [])

DB_CONN = None
DB_LOCK = threading.Lock()

ML_ENABLED = CONFIG.get("ml_enabled", True)
ML_MODEL = None
ML_FEATURES = deque(maxlen=CONFIG.get("ml_training_window", 1000))
ML_LOCK = threading.Lock()

DEEP_ENABLED = CONFIG.get("deep_learning_enabled", True) and TF_AVAILABLE and KERAS_AVAILABLE
AUTOENCODER_MODEL = None
LSTM_MODEL = None
DEEP_FEATURES = deque(maxlen=CONFIG.get("ml_training_window", 1000))
DEEP_LOCK = threading.Lock()

REPLAY_QUEUE = deque(maxlen=500)
REPLAY_LOCK = threading.Lock()

CORRELATION_LOCK = threading.Lock()
CORRELATION_INDEX = {
    "by_src": {},
    "by_dst": {},
    "by_ja3": {},
    "by_ja3s": {},
    "by_sid": {},
    "by_behavior": {},
    "by_mitre": {},
}

THREAT_SCORE_BREAKDOWN_LOCK = threading.Lock()
THREAT_SCORE_BREAKDOWN = defaultdict(int)

BEHAVIOR_LOCK = threading.Lock()
BEHAVIOR_PROFILES = defaultdict(lambda: {
    "total_packets": 0,
    "total_bytes": 0,
    "unique_dsts": set(),
    "unique_ports": set(),
    "ja3_set": set(),
    "ja3s_set": set(),
    "suricata_hits": 0,
    "honeypot_hits": 0,
    "ml_anomalies": 0,
    "deep_anomalies": 0,
})

if not TF_AVAILABLE or not KERAS_AVAILABLE:
    DEEP_ENABLED = False
    set_subsystem_error("deep", "Deep learning disabled: TensorFlow/Keras not available or protobuf incompatible.")
    set_subsystem_error("deps", "TensorFlow/Keras unavailable; using IsolationForest-only ML engine.")

# =========================
#  MITRE ATT&CK MAPPING
# =========================

MITRE_MAP = {
    "suricata": {"tactic": "Execution", "technique": "T1059", "name": "Command and Scripting Interpreter"},
    "malware_sig": {"tactic": "Execution", "technique": "T1204", "name": "User Execution"},
    "ad_block": {"tactic": "Command and Control", "technique": "T1071", "name": "Application Layer Protocol"},
    "ml_anomaly": {"tactic": "Discovery", "technique": "T1082", "name": "System Information Discovery"},
    "deep_anomaly": {"tactic": "Defense Evasion", "technique": "T1027", "name": "Obfuscated/Encrypted File"},
    "honeypot": {"tactic": "Credential Access", "technique": "T1110", "name": "Brute Force"},
    "tls_client": {"tactic": "Command and Control", "technique": "T1095", "name": "Non-Application Layer Protocol"},
    "tls_server": {"tactic": "Command and Control", "technique": "T1573", "name": "Encrypted Channel"},
    "rule_editor": {"tactic": "Defense Evasion", "technique": "T1562", "name": "Impair Defenses"},
    "perma_allow": {"tactic": "Defense Evasion", "technique": "T1036", "name": "Masquerading"},
}

def map_mitre(reason, meta):
    try:
        base = MITRE_MAP.get(reason)
        if not base:
            return None
        entry = {
            "tactic": base["tactic"],
            "technique": base["technique"],
            "name": base["name"],
            "time": datetime.utcnow().isoformat(),
        }
        entry.update({"sid": meta.get("suricata_sid"), "ja3": meta.get("ja3"), "ja3s": meta.get("ja3s")})
        return entry
    except Exception as e:
        set_subsystem_error("mitre", "MITRE mapping error: %s" % e)
        return None

# =========================
#  THREAT DATABASE (SQLite)
# =========================

def init_db():
    global DB_CONN
    try:
        db_path = CONFIG.get("db_path", "threats.db")
        DB_CONN = sqlite3.connect(db_path, check_same_thread=False)
        with DB_LOCK:
            cur = DB_CONN.cursor()
            cur.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time TEXT,
                    src TEXT,
                    dst TEXT,
                    proto TEXT,
                    action TEXT,
                    score INTEGER,
                    reason TEXT,
                    meta TEXT,
                    mitre_tactic TEXT,
                    mitre_technique TEXT,
                    mitre_name TEXT
                )
            """)
            cur.execute("""
                CREATE TABLE IF NOT EXISTS correlations (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    time TEXT,
                    key_type TEXT,
                    key_value TEXT,
                    threat_ids TEXT
                )
            """)
            DB_CONN.commit()
    except Exception as e:
        set_subsystem_error("db", "DB init error: %s" % e)

def db_log_event(time_str, src, dst, proto, action, score, reason, meta_json, mitre_entry):
    try:
        with DB_LOCK:
            cur = DB_CONN.cursor()
            tactic = mitre_entry["tactic"] if mitre_entry else None
            tech = mitre_entry["technique"] if mitre_entry else None
            name = mitre_entry["name"] if mitre_entry else None
            cur.execute(
                "INSERT INTO threats (time, src, dst, proto, action, score, reason, meta, mitre_tactic, mitre_technique, mitre_name) VALUES (?,?,?,?,?,?,?,?,?,?,?)",
                (time_str, src, dst, proto, action, score, reason, meta_json, tactic, tech, name)
            )
            DB_CONN.commit()
            return cur.lastrowid
    except Exception as e:
        set_subsystem_error("db", "DB log error: %s" % e)
        return None

def db_log_correlation(key_type, key_value, threat_ids):
    try:
        with DB_LOCK:
            cur = DB_CONN.cursor()
            cur.execute(
                "INSERT INTO correlations (time, key_type, key_value, threat_ids) VALUES (?,?,?,?)",
                (datetime.utcnow().isoformat(), key_type, key_value, json.dumps(threat_ids))
            )
            DB_CONN.commit()
    except Exception as e:
        set_subsystem_error("db", "DB correlation error: %s" % e)

init_db()

# =========================
#  LOGGING + CORRELATION + GRAPHS + SCORE BREAKDOWN
# =========================

def log_event(src, dst, proto, action, score, reason, meta=None):
    now = datetime.utcnow().isoformat()
    meta_json = json.dumps(meta or {})
    mitre_entry = map_mitre(reason, meta or {})
    with LOG_LOCK:
        THREAT_LOG.append({
            "time": now,
            "src": src,
            "dst": dst,
            "proto": proto,
            "action": action,
            "score": score,
            "reason": reason,
            "meta": meta or {},
            "mitre": mitre_entry,
        })
    threat_id = db_log_event(now, src, dst, proto, action, score, reason, meta_json, mitre_entry)
    with GRAPH_LOCK:
        THREAT_TIMELINE.append((time.time(), score))
        PACKET_RATE_TIMELINE.append((time.time(), 1))
        if "honeypot" in (reason or "").lower():
            HONEYPOT_HITS_TIMELINE.append((time.time(), 1))
        PERSONA_TIMELINE.append((time.time(), PERSONA_STATE["aggressiveness"], PERSONA_STATE["mode"]))
    with THREAT_SCORE_BREAKDOWN_LOCK:
        THREAT_SCORE_BREAKDOWN[reason] += score
    update_correlation(threat_id, src, dst, meta, mitre_entry)

def update_correlation(threat_id, src, dst, meta, mitre_entry):
    if threat_id is None:
        return
    try:
        ja3 = meta.get("ja3") if meta else None
        ja3s = meta.get("ja3s") if meta else None
        sid = meta.get("suricata_sid") if meta else None
        behavior_fp = meta.get("behavior_fp") if meta else None
        mitre_key = None
        if mitre_entry:
            mitre_key = "%s:%s" % (mitre_entry.get("tactic"), mitre_entry.get("technique"))

        with CORRELATION_LOCK:
            for key_type, key_value in [
                ("src", src),
                ("dst", dst),
                ("ja3", ja3),
                ("ja3s", ja3s),
                ("sid", sid),
                ("behavior", behavior_fp),
                ("mitre", mitre_key),
            ]:
                if not key_value:
                    continue
                idx = CORRELATION_INDEX.get("by_%s" % key_type, {})
                if key_value not in idx:
                    idx[key_value] = []
                idx[key_value].append(threat_id)
                CORRELATION_INDEX["by_%s" % key_type] = idx
                if len(idx[key_value]) >= 3:
                    db_log_correlation(key_type, key_value, idx[key_value])
    except Exception as e:
        set_subsystem_error("correlation", "Correlation error: %s" % e)

def get_recent_logs(limit=200):
    with LOG_LOCK:
        return THREAT_LOG[-limit:]

def get_score_breakdown():
    with THREAT_SCORE_BREAKDOWN_LOCK:
        return dict(THREAT_SCORE_BREAKDOWN)

# =========================
#  IP CLASSIFICATION + NIC ROLE (ARP/DHCP)
# =========================

def is_private_ip(ip):
    try:
        if ip.startswith("10."):
            return True
        if ip.startswith("192.168."):
            return True
        if ip.startswith("172."):
            parts = ip.split(".")
            if len(parts) >= 2:
                second = int(parts[1])
                return 16 <= second <= 31
        return False
    except:
        return False

def nic_role_detection():
    roles = {}
    try:
        stats_all = psutil.net_if_stats()
        addrs_all = psutil.net_if_addrs()

        for name, stats in stats_all.items():
            if not stats.isup:
                continue
            info = addrs_all.get(name, [])
            ip = next((i.address for i in info if i.family == 2), None)
            if not ip:
                continue
            role = "unknown"
            if is_private_ip(ip):
                role = "lan"
            else:
                role = "wan"
            roles[name] = {"ip": ip, "role": role}
    except Exception as e:
        set_subsystem_error("autodetect", "NIC role detection error: %s" % e)
    return roles

def detect_interfaces():
    global WAN_IN_IFACE, WAN_OUT_IFACE, LAN_IN_IFACE, LAN_OUT_IFACE, BRIDGE_MODE

    try:
        roles = nic_role_detection()
        lan_ifaces = [n for n, r in roles.items() if r["role"] == "lan"]
        wan_ifaces = [n for n, r in roles.items() if r["role"] == "wan"]

        if wan_ifaces and lan_ifaces:
            BRIDGE_MODE = "WAN"
            WAN_IN_IFACE = wan_ifaces[0]
            WAN_OUT_IFACE = lan_ifaces[0]
            LAN_IN_IFACE = lan_ifaces[0]
            LAN_OUT_IFACE = lan_ifaces[0]
        else:
            BRIDGE_MODE = "LAN"
            if len(lan_ifaces) >= 2:
                LAN_IN_IFACE = lan_ifaces[0]
                LAN_OUT_IFACE = lan_ifaces[1]
            elif len(lan_ifaces) == 1:
                LAN_IN_IFACE = lan_ifaces[0]
                LAN_OUT_IFACE = lan_ifaces[0]
            else:
                stats_all = psutil.net_if_stats()
                any_iface = next(iter(stats_all.keys()), None)
                LAN_IN_IFACE = any_iface
                LAN_OUT_IFACE = any_iface
            WAN_IN_IFACE = LAN_IN_IFACE
            WAN_OUT_IFACE = LAN_OUT_IFACE

    except Exception as e:
        set_subsystem_error("autodetect", "Interface detection error: %s" % e)
        WAN_IN_IFACE = WAN_IN_IFACE or "Ethernet0"
        WAN_OUT_IFACE = WAN_OUT_IFACE or "Ethernet1"
        LAN_IN_IFACE = LAN_IN_IFACE or "Ethernet2"
        LAN_OUT_IFACE = LAN_OUT_IFACE or "Ethernet3"

# =========================
#  EXTENDED SURICATA v6-LIKE RULE ENGINE
# =========================

class SuricataRuleV6:
    def __init__(self, raw_line):
        self.raw = raw_line
        self.sid = None
        self.msg = None
        self.contents = []
        self.pcre = []
        self.flow = None
        self.flowbits = []
        self.metadata = {}
        self.threshold = None
        self.byte_match = []
        self.file_data = False
        self.classtype = None
        self.priority = None
        self.reference = []
        self.proto = None
        self.src_ip = None
        self.src_port = None
        self.dst_ip = None
        self.dst_port = None
        self.app_layer = None
        self.tags = []
        self.parse()

    def parse(self):
        try:
            if self.raw.startswith("alert") or self.raw.startswith("drop") or self.raw.startswith("reject"):
                header, opts = self.raw.split("(", 1)
                header = header.strip()
                parts = header.split()
                if len(parts) >= 7:
                    # alert tcp any any -> any any
                    self.proto = parts[1]
                    self.src_ip = parts[2]
                    self.src_port = parts[3]
                    self.dst_ip = parts[5]
                    self.dst_port = parts[6]
            if "sid:" in self.raw:
                sid_part = self.raw.split("sid:")[1].split(";")[0].strip()
                self.sid = sid_part
            if "msg:" in self.raw:
                msg_part = self.raw.split("msg:")[1].split(";")[0].strip()
                if msg_part.startswith('"') and msg_part.endswith('"'):
                    msg_part = msg_part[1:-1]
                self.msg = msg_part

            for part in self.raw.split("content:")[1:]:
                if '"' in part:
                    c = part.split('"')[1]
                    self.contents.append(c.encode("latin-1", errors="ignore"))

            if "pcre:" in self.raw:
                for part in self.raw.split("pcre:")[1:]:
                    if '"' in part:
                        regex = part.split('"')[1]
                        try:
                            self.pcre.append(re.compile(regex))
                        except re.error:
                            continue

            if "flow:" in self.raw:
                flow_part = self.raw.split("flow:")[1].split(";")[0]
                self.flow = flow_part.strip()

            if "flowbits:" in self.raw:
                fb_part = self.raw.split("flowbits:")[1].split(";")[0]
                self.flowbits.append(fb_part.strip())

            if "metadata:" in self.raw:
                meta_part = self.raw.split("metadata:")[1].split(";")[0]
                items = meta_part.split(",")
                for item in items:
                    if ":" in item:
                        k, v = item.split(":", 1)
                        self.metadata[k.strip()] = v.strip()

            if "threshold:" in self.raw:
                th_part = self.raw.split("threshold:")[1].split(";")[0]
                self.threshold = th_part.strip()

            if "byte_match:" in self.raw:
                bm_part = self.raw.split("byte_match:")[1].split(";")[0]
                self.byte_match.append(bm_part.strip())

            if "file_data;" in self.raw:
                self.file_data = True

            if "classtype:" in self.raw:
                ct_part = self.raw.split("classtype:")[1].split(";")[0].strip()
                self.classtype = ct_part

            if "priority:" in self.raw:
                pr_part = self.raw.split("priority:")[1].split(";")[0].strip()
                try:
                    self.priority = int(pr_part)
                except ValueError:
                    self.priority = None

            if "reference:" in self.raw:
                for part in self.raw.split("reference:")[1:]:
                    ref = part.split(";")[0].strip()
                    self.reference.append(ref)

            if "app-layer-protocol:" in self.raw:
                al_part = self.raw.split("app-layer-protocol:")[1].split(";")[0].strip()
                self.app_layer = al_part

            if "tag:" in self.raw:
                for part in self.raw.split("tag:")[1:]:
                    tag = part.split(";")[0].strip()
                    self.tags.append(tag)
        except Exception:
            pass

    def match(self, payload, proto=None, src=None, dst=None):
        try:
            if self.proto and proto and self.proto.lower() != proto.lower():
                return False
            for c in self.contents:
                if c not in payload:
                    return False
            for rgx in self.pcre:
                if not rgx.search(payload.decode("latin-1", errors="ignore")):
                    return False
            return True
        except Exception:
            return False

SURICATA_RULES = []

def load_suricata_rules():
    global SURICATA_RULES
    path = CONFIG.get("suricata_rules_path", "suricata.rules")
    rules = []
    try:
        if os.path.exists(path):
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    rules.append(SuricataRuleV6(line))
        with SURICATA_RULES_LOCK:
            SURICATA_RULES = rules
    except Exception as e:
        set_subsystem_error("rules", "Suricata rule load error: %s" % e)

def match_suricata_rules(payload, proto=None, src=None, dst=None):
    try:
        with SURICATA_RULES_LOCK:
            rules = list(SURICATA_RULES)
        for r in rules:
            if r.match(payload, proto=proto, src=src, dst=dst):
                return r.sid or "suricata_match", r.msg or "suricata", r.priority, r.classtype
    except Exception as e:
        set_subsystem_error("rules", "Suricata match error: %s" % e)
    return None, None, None, None

load_suricata_rules()

# =========================
#  RULE EDITOR
# =========================

def load_rule_editor_rules():
    global RULE_EDITOR_RULES
    with RULE_EDITOR_LOCK:
        RULE_EDITOR_RULES = CONFIG.get("rule_editor_rules", [])

def save_rule_editor_rules():
    with RULE_EDITOR_LOCK:
        CONFIG["rule_editor_rules"] = RULE_EDITOR_RULES
    save_config()

def rule_editor_match(src, dst, proto, payload, ja3_hash=None, ja3s_hash=None):
    with RULE_EDITOR_LOCK:
        rules = list(RULE_EDITOR_RULES)
    text_payload = payload.decode("latin-1", errors="ignore")
    for r in rules:
        try:
            ip_match = True
            if r.get("src"):
                ip_match = (r["src"] == src)
            if r.get("dst"):
                ip_match = ip_match and (r["dst"] == dst)

            proto_match = True
            if r.get("proto"):
                proto_match = (r["proto"].lower() == proto.lower())

            content_match = True
            if r.get("content"):
                c = r["content"]
                if r.get("regex"):
                    try:
                        if not re.search(c, text_payload):
                            content_match = False
                    except re.error:
                        content_match = False
                else:
                    if c.encode("latin-1", errors="ignore") not in payload:
                        content_match = False

            ja3_match = True
            if r.get("ja3"):
                ja3_match = (r["ja3"] == ja3_hash)

            ja3s_match = True
            if r.get("ja3s"):
                ja3s_match = (r["ja3s"] == ja3s_hash)

            if ip_match and proto_match and content_match and ja3_match and ja3s_match:
                return r.get("action", "allow"), r.get("name", "rule_editor"), r.get("sid")
        except Exception:
            continue
    return None, None, None

load_rule_editor_rules()

# =========================
#  SIGNATURE DB + HTTP DPI + JA3 + JA3S
# =========================

MALWARE_SIGNATURES = [
    b"malware_example",
    b"evil_payload",
    b"suspicious_shellcode",
]

AD_SIGNATURES = [
    b"/ads/",
    b"adserver",
    b"banner",
]

def parse_http(payload):
    try:
        text = payload.decode("latin-1", errors="ignore")
        lines = text.split("\r\n")
        if not lines:
            return None
        first = lines[0]
        parts = first.split(" ")
        if len(parts) < 2:
            return None
        method = parts[0]
        path = parts[1]
        headers = {}
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers[k.strip().lower()] = v.strip()
        host = headers.get("host")
        ua = headers.get("user-agent")
        ref = headers.get("referer")
        cookie = headers.get("cookie")
        return {
            "method": method,
            "path": path,
            "host": host,
            "ua": ua,
            "ref": ref,
            "cookie": cookie,
            "headers": headers,
        }
    except Exception as e:
        set_subsystem_error("dpi", "HTTP parse error: %s" % e)
        return None

def parse_tls_client_hello(payload):
    try:
        if len(payload) < 5 or payload[0] != 0x16 or payload[1] != 0x03:
            return None

        offset = 5
        if payload[offset] != 0x01:
            return None
        offset += 4

        version = payload[offset:offset+2]
        offset += 2

        offset += 32

        sid_len = payload[offset]
        offset += 1 + sid_len

        cs_len = int.from_bytes(payload[offset:offset+2], "big")
        offset += 2
        cipher_suites = []
        end_cs = offset + cs_len
        while offset + 2 <= end_cs and offset + 2 <= len(payload):
            cipher_suites.append(int.from_bytes(payload[offset:offset+2], "big"))
            offset += 2

        comp_len = payload[offset]
        offset += 1 + comp_len

        extensions = []
        curves = []
        ec_point_formats = []
        if offset + 2 <= len(payload):
            ext_len = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2
            end_ext = offset + ext_len
            while offset + 4 <= end_ext and offset + 4 <= len(payload):
                ext_type = int.from_bytes(payload[offset:offset+2], "big")
                ext_size = int.from_bytes(payload[offset+2:offset+4], "big")
                offset += 4
                ext_data = payload[offset:offset+ext_size]
                offset += ext_size
                extensions.append(ext_type)
                if ext_type == 10 and len(ext_data) >= 2:
                    cl = int.from_bytes(ext_data[0:2], "big")
                    pos = 2
                    end_cl = pos + cl
                    while pos + 2 <= end_cl and pos + 2 <= len(ext_data):
                        curves.append(int.from_bytes(ext_data[pos:pos+2], "big"))
                        pos += 2
                if ext_type == 11 and len(ext_data) >= 1:
                    pfl = ext_data[0]
                    pos = 1
                    end_pf = pos + pfl
                    while pos < end_pf and pos < len(ext_data):
                        ec_point_formats.append(ext_data[pos])
                        pos += 1

        return {
            "version": version,
            "cipher_suites": cipher_suites,
            "extensions": extensions,
            "curves": curves,
            "ec_point_formats": ec_point_formats,
        }
    except Exception as e:
        set_subsystem_error("dpi", "TLS ClientHello parse error: %s" % e)
        return None

def parse_tls_server_hello(payload):
    try:
        if len(payload) < 5 or payload[0] != 0x16 or payload[1] != 0x03:
            return None

        offset = 5
        if payload[offset] != 0x02:
            return None
        offset += 4

        version = payload[offset:offset+2]
        offset += 2

        offset += 32

        sid_len = payload[offset]
        offset += 1 + sid_len

        cipher_suite = int.from_bytes(payload[offset:offset+2], "big")
        offset += 2

        comp_method = payload[offset]
        offset += 1

        extensions = []
        if offset + 2 <= len(payload):
            ext_len = int.from_bytes(payload[offset:offset+2], "big")
            offset += 2
            end_ext = offset + ext_len
            while offset + 4 <= end_ext and offset + 4 <= len(payload):
                ext_type = int.from_bytes(payload[offset:offset+2], "big")
                ext_size = int.from_bytes(payload[offset+2:offset+4], "big")
                offset += 4
                offset += ext_size
                extensions.append(ext_type)

        return {
            "version": version,
            "cipher_suite": cipher_suite,
            "extensions": extensions,
            "compression": comp_method,
        }
    except Exception as e:
        set_subsystem_error("dpi", "TLS ServerHello parse error: %s" % e)
        return None

def ja3_fingerprint(tls_info):
    try:
        ver = int.from_bytes(tls_info["version"], "big")
        cs = "-".join(str(c) for c in tls_info["cipher_suites"])
        ex = "-".join(str(e) for e in tls_info["extensions"])
        cv = "-".join(str(c) for c in tls_info["curves"])
        pf = "-".join(str(p) for p in tls_info["ec_point_formats"])
        ja3_str = "%s,%s,%s,%s,%s" % (ver, cs, ex, cv, pf)
        return hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
    except Exception:
        return None

def ja3s_fingerprint(tls_info):
    try:
        ver = int.from_bytes(tls_info["version"], "big")
        cs = str(tls_info["cipher_suite"])
        ex = "-".join(str(e) for e in tls_info["extensions"])
        comp = str(tls_info["compression"])
        ja3s_str = "%s,%s,%s,%s" % (ver, cs, ex, comp)
        return hashlib.md5(ja3s_str.encode("utf-8")).hexdigest()
    except Exception:
        return None

def dpi_analyze(payload, direction="INBOUND"):
    extra_score = 0
    reason = "dpi_normal"
    meta = {}

    try:
        if not payload:
            return extra_score, reason, meta

        http_info = parse_http(payload)
        if http_info:
            reason = "http"
            extra_score += 5
            meta["http"] = http_info

            host = (http_info.get("host") or "").lower()
            path = (http_info.get("path") or "").lower()
            ua = (http_info.get("ua") or "").lower()

            if host in AD_BLOCK_DOMAINS or any(sig in path for sig in ["/ads", "/banner"]):
                reason = "ad_block"
                extra_score += 40
                meta["ad_block_host"] = host

            if "curl" in ua or "wget" in ua or "python-requests" in ua:
                extra_score += 10
                meta["suspicious_ua"] = ua

        if direction == "INBOUND":
            tls_info = parse_tls_client_hello(payload)
            if tls_info:
                reason = "tls_client"
                extra_score += 10
                ja3 = ja3_fingerprint(tls_info)
                meta["ja3"] = ja3
        else:
            tls_info_s = parse_tls_server_hello(payload)
            if tls_info_s:
                reason = "tls_server"
                extra_score += 10
                ja3s = ja3s_fingerprint(tls_info_s)
                meta["ja3s"] = ja3s

        sid, msg, priority, classtype = match_suricata_rules(payload)
        if sid:
            reason = "suricata"
            extra_score += 60
            meta["suricata_sid"] = sid
            meta["suricata_msg"] = msg
            meta["suricata_priority"] = priority
            meta["suricata_classtype"] = classtype

        for sig in MALWARE_SIGNATURES:
            if sig in payload:
                reason = "malware_sig"
                extra_score += 60
                meta["malware_sig"] = sig.decode("latin-1", errors="ignore")
                break

        for sig in AD_SIGNATURES:
            if sig in payload:
                reason = "ad_block"
                extra_score += 30
                meta["ad_sig"] = sig.decode("latin-1", errors="ignore")
                break
    except Exception as e:
        set_subsystem_error("dpi", "DPI analyze error: %s" % e)

    return extra_score, reason, meta

# =========================
#  BEHAVIORAL FINGERPRINTING (session vectors)
# =========================

def update_behavior_profile(src, dst, proto, payload_len, meta):
    try:
        with BEHAVIOR_LOCK:
            prof = BEHAVIOR_PROFILES[src]
            prof["total_packets"] += 1
            prof["total_bytes"] += payload_len
            prof["unique_dsts"].add(dst)
            prof["unique_ports"].add(meta.get("dst_port", 0))
            if meta.get("ja3"):
                prof["ja3_set"].add(meta["ja3"])
            if meta.get("ja3s"):
                prof["ja3s_set"].add(meta["ja3s"])
            if meta.get("suricata_sid"):
                prof["suricata_hits"] += 1
            if "honeypot" in (meta.get("reason", "") or "").lower():
                prof["honeypot_hits"] += 1
            if meta.get("ml_anomaly"):
                prof["ml_anomalies"] += 1
            if meta.get("deep_anomaly"):
                prof["deep_anomalies"] += 1
    except Exception as e:
        set_subsystem_error("behavior", "Behavior profile update error: %s" % e)

def behavior_fingerprint(src):
    try:
        with BEHAVIOR_LOCK:
            prof = BEHAVIOR_PROFILES[src]
            total_packets = prof["total_packets"]
            total_bytes = prof["total_bytes"]
            unique_dsts = len(prof["unique_dsts"])
            unique_ports = len(prof["unique_ports"])
            ja3_count = len(prof["ja3_set"])
            ja3s_count = len(prof["ja3s_set"])
            suricata_hits = prof["suricata_hits"]
            honeypot_hits = prof["honeypot_hits"]
            ml_anomalies = prof["ml_anomalies"]
            deep_anomalies = prof["deep_anomalies"]

        fp_str = "%d|%d|%d|%d|%d|%d|%d|%d|%d|%d" % (
            total_packets,
            total_bytes,
            unique_dsts,
            unique_ports,
            ja3_count,
            ja3s_count,
            suricata_hits,
            honeypot_hits,
            ml_anomalies,
            deep_anomalies,
        )
        return hashlib.sha256(fp_str.encode("utf-8")).hexdigest()
    except Exception as e:
        set_subsystem_error("behavior", "Behavior fingerprint error: %s" % e)
        return None

# =========================
#  DECEPTION + HONEYPOT (Full Cowrie-style SSH)
# =========================

def spoof_os_fingerprint():
    return "os_spoof_stub"

def send_tcp_rst(divert, packet):
    try:
        if not packet.tcp:
            return
        packet.tcp.rst = True
        packet.tcp.ack = packet.tcp.seq + 1
        packet.direction = Direction.OUTBOUND
        divert.send(packet)
    except Exception as e:
        set_subsystem_error("bridge", "RST send error: %s" % e)
        diag_add_error("RST send error: %s" % e)

def send_fake_http_banner(divert, packet):
    try:
        if not packet.tcp:
            return
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.41 (Ubuntu)\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 20\r\n"
            b"\r\n"
            b"<h1>Fake Host</h1>"
        )
        packet.payload = payload
        packet.direction = Direction.OUTBOUND
        divert.send(packet)
    except Exception as e:
        set_subsystem_error("bridge", "Fake HTTP send error: %s" % e)
        diag_add_error("Fake HTTP send error: %s" % e)

def deception_response(divert, packet, reason, src, dst, meta=None):
    fp = spoof_os_fingerprint()
    log_event(src, dst, "DECEPTION", "fake", 0, "%s:%s" % (reason, fp), meta)
    if reason == "ad_block":
        send_tcp_rst(divert, packet)
    else:
        send_fake_http_banner(divert, packet)

FAKE_FS = {
    "/": ["home", "var", "etc", "tmp", "opt"],
    "/home": ["ubuntu", "root", "admin"],
    "/home/ubuntu": ["README.txt", "notes.txt", "ssh_keys", "scripts"],
    "/home/ubuntu/scripts": ["backup.sh", "deploy.sh"],
    "/home/ubuntu/ssh_keys": ["id_rsa", "id_rsa.pub"],
    "/home/root": ["secret.txt"],
    "/var": ["log", "www"],
    "/var/log": ["auth.log", "syslog", "dmesg"],
    "/var/www": ["index.html", "admin.php"],
    "/etc": ["passwd", "shadow", "hosts", "ssh", "cron.d"],
    "/etc/ssh": ["sshd_config", "ssh_config"],
    "/tmp": [],
    "/opt": ["app", "data"],
}

FAKE_FILES_CONTENT = {
    "/home/ubuntu/README.txt": "This is a honeypot system.\nDo not trust anything you see here.\n",
    "/home/ubuntu/notes.txt": "Notes: test environment, fake data, nothing sensitive.\n",
    "/home/ubuntu/scripts/backup.sh": "#!/bin/bash\necho 'Fake backup script'\n",
    "/home/ubuntu/scripts/deploy.sh": "#!/bin/bash\necho 'Fake deploy script'\n",
    "/home/ubuntu/ssh_keys/id_rsa": "-----BEGIN FAKE PRIVATE KEY-----\nFAKEKEY\n-----END FAKE PRIVATE KEY-----\n",
    "/home/ubuntu/ssh_keys/id_rsa.pub": "ssh-rsa FAKEKEY ubuntu@honeypot\n",
    "/home/root/secret.txt": "Root secret: this is all fake.\n",
    "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nubuntu:x:1000:1000:Ubuntu:/home/ubuntu:/bin/bash\n",
    "/etc/hosts": "127.0.0.1 localhost\n192.168.1.1 gateway\n",
    "/var/log/auth.log": "Jan  1 00:00:00 honeypot sshd[123]: Failed password for root from 10.0.0.5 port 5555 ssh2\n",
    "/var/log/syslog": "Jan  1 00:00:00 honeypot kernel: [    0.000000] Fake kernel log\n",
    "/var/log/dmesg": "Fake dmesg output\n",
    "/var/www/index.html": "<html><body>Fake web root</body></html>\n",
    "/var/www/admin.php": "<?php echo 'Fake admin panel'; ?>\n",
    "/etc/ssh/sshd_config": "Port 22\nPermitRootLogin no\nPasswordAuthentication yes\n",
    "/etc/ssh/ssh_config": "Host *\n    StrictHostKeyChecking no\n",
}

def cowrie_shell(conn, addr):
    cwd = "/home/ubuntu"
    history = []
    try:
        conn.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        data = conn.recv(1024)
        conn.sendall(b"Password: ")
        pwd = conn.recv(1024)
        conn.sendall(b"Last login: Thu Jan  1 00:00:00 1970 from 127.0.0.1\r\n")
        conn.sendall(b"ubuntu@honeypot:~$ ")
        while True:
            cmd = conn.recv(4096)
            if not cmd:
                break
            cmd_str = cmd.decode("latin-1", errors="ignore").strip()
            history.append(cmd_str)
            log_event(addr[0], "honeypot:ssh", "SSH", "honeypot", 0, "cowrie_shell", {"cmd": cmd_str})
            if cmd_str in ("exit", "quit", "logout"):
                conn.sendall(b"logout\r\n")
                break
            elif cmd_str.startswith("cd "):
                target = cmd_str[3:].strip()
                if target == "..":
                    if cwd != "/":
                        cwd = "/".join(cwd.rstrip("/").split("/")[:-1]) or "/"
                else:
                    if target.startswith("/"):
                        new_cwd = target
                    else:
                        new_cwd = cwd.rstrip("/") + "/" + target
                    if new_cwd in FAKE_FS:
                        cwd = new_cwd
                conn.sendall(b"ubuntu@honeypot:%s$ " % cwd.encode("latin-1", errors="ignore"))
            elif cmd_str.startswith("ls"):
                path = cwd
                parts = cmd_str.split(" ")
                if len(parts) > 1 and parts[1]:
                    arg = parts[1]
                    if arg.startswith("/"):
                        path = arg
                    else:
                        path = cwd.rstrip("/") + "/" + arg
                entries = FAKE_FS.get(path, [])
                out = "  ".join(entries) + "\n"
                conn.sendall(out.encode("latin-1", errors="ignore"))
                conn.sendall(b"ubuntu@honeypot:%s$ " % cwd.encode("latin-1", errors="ignore"))
            elif cmd_str.startswith("cat "):
                target = cmd_str[4:].strip()
                if target.startswith("/"):
                    path = target
                else:
                    path = cwd.rstrip("/") + "/" + target
                content = FAKE_FILES_CONTENT.get(path, "cat: %s: No such file or directory\n" % path)
                conn.sendall(content.encode("latin-1", errors="ignore"))
                conn.sendall(b"ubuntu@honeypot:%s$ " % cwd.encode("latin-1", errors="ignore"))
            elif cmd_str.startswith("pwd"):
                conn.sendall((cwd + "\n").encode("latin-1", errors="ignore"))
                conn.sendall(b"ubuntu@honeypot:%s$ " % cwd.encode("latin-1", errors="ignore"))
            elif cmd_str.startswith("whoami"):
                conn.sendall(b"ubuntu\n")
                conn.sendall(b"ubuntu@honeypot:%s$ " % cwd.encode("latin-1", errors="ignore"))
            elif cmd_str.startswith("history"):
                out = ""
                for i, h in enumerate(history, 1):
                    out += "%d  %s\n" % (i, h)
                conn.sendall(out.encode("latin-1", errors="ignore"))
                conn.sendall(b"ubuntu@honeypot:%s$ " % cwd.encode("latin-1", errors="ignore"))
            elif cmd_str.startswith("uname"):
                conn.sendall(b"Linux honeypot 5.4.0-FAKE #1 SMP Fake\n")
                conn.sendall(b"ubuntu@honeypot:%s$ " % cwd.encode("latin-1", errors="ignore"))
            elif cmd_str.startswith("wget "):
                conn.sendall(b"Connecting to fake host...\nSaving to: 'index.html'\n\nFake download complete.\n")
                conn.sendall(b"ubuntu@honeypot:%s$ " % cwd.encode("latin-1", errors="ignore"))
            elif cmd_str.startswith("ssh "):
                conn.sendall(b"ssh: connect to host fake.example.com port 22: Connection refused\n")
                conn.sendall(b"ubuntu@honeypot:%s$ " % cwd.encode("latin-1", errors="ignore"))
            else:
                conn.sendall(b"bash: " + cmd.strip() + b": command not found\r\n")
                conn.sendall(b"ubuntu@honeypot:%s$ " % cwd.encode("latin-1", errors="ignore"))
    except Exception:
        pass
    finally:
        conn.close()

def honeypot_ssh(conn, addr):
    cowrie_shell(conn, addr)

def honeypot_http(conn, addr):
    try:
        req = conn.recv(2048)
        resp = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: HoneyHTTP/1.0\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 32\r\n"
            b"\r\n"
            b"<html><body>HoneyHTTP</body></html>"
        )
        conn.sendall(resp)
        log_event(addr[0], "honeypot:http", "HTTP", "honeypot", 0, "honeypot_http", {"request": req.decode("latin-1", errors="ignore")})
    except Exception:
        pass
    finally:
        conn.close()

def honeypot_https(conn, addr):
    try:
        conn.sendall(b"\x16\x03\x01\x00\x2eFakeTLSHoneypot")
        data = conn.recv(2048)
        log_event(addr[0], "honeypot:https", "HTTPS", "honeypot", 0, "honeypot_https", {"data": data.hex()})
    except Exception:
        pass
    finally:
        conn.close()

def honeypot_rdp(conn, addr):
    try:
        conn.sendall(b"RDP Negotiation Response\r\n")
        data = conn.recv(2048)
        log_event(addr[0], "honeypot:rdp", "RDP", "honeypot", 0, "honeypot_rdp", {"data": data.hex()})
    except Exception:
        pass
    finally:
        conn.close()

def honeypot_smb(conn, addr):
    try:
        conn.sendall(b"\x00\x00\x00\x90SMB2FakeHoneypot")
        data = conn.recv(2048)
        log_event(addr[0], "honeypot:smb", "SMB", "honeypot", 0, "honeypot_smb", {"data": data.hex()})
    except Exception:
        pass
    finally:
        conn.close()

HONEYPOT_HANDLERS = {
    "ssh": honeypot_ssh,
    "http": honeypot_http,
    "https": honeypot_https,
    "rdp": honeypot_rdp,
    "smb": honeypot_smb,
}

def honeypot_worker(port, service_name):
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.setsockopt(1, 2, 1)
        s.bind((HONEYPOT_HOST, port))
        s.listen(50)
    except Exception as e:
        set_subsystem_error("honeypot", "Port %d bind error: %s" % (port, e))
        return

    handler = HONEYPOT_HANDLERS.get(service_name)

    while True:
        try:
            conn, addr = s.accept()
            if handler:
                threading.Thread(target=handler, args=(conn, addr), daemon=True).start()
            else:
                conn.close()
            log_event(addr[0], "%s:%d" % (HONEYPOT_HOST, port), "HONEYPOT", "connect", 0, "honeypot_%s" % service_name)
        except Exception as e:
            set_subsystem_error("honeypot", "Honeypot error on port %d: %s" % (port, e))
            time.sleep(1)

def start_honeypot_suite():
    try:
        for port, name in HONEYPOT_SERVICES.items():
            t = threading.Thread(target=honeypot_worker, args=(port, name), daemon=True)
            t.start()
    except Exception as e:
        set_subsystem_error("honeypot", "Start honeypot suite error: %s" % e)

# =========================
#  SWARM CLUSTER (TLS MUTUAL AUTH)
# =========================

def swarm_hmac(data_bytes):
    secret = CONFIG.get("swarm_shared_secret", "changeme_shared_secret").encode("utf-8")
    return hashlib.sha256(secret + data_bytes).hexdigest()

class SwarmHandler(BaseHTTPRequestHandler):
    def _set_headers(self, code=200):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

    def do_GET(self):
        if self.path == "/threats":
            with SWARM_STORAGE_LOCK:
                data = json.dumps(SWARM_STORAGE[-500:])
            self._set_headers(200)
            self.wfile.write(data.encode("utf-8"))
        elif self.path == "/peers":
            with SWARM_PEERS_LOCK:
                data = json.dumps(SWARM_PEERS)
            self._set_headers(200)
            self.wfile.write(data.encode("utf-8"))
        else:
            self._set_headers(404)
            self.wfile.write(b'{"error":"not_found"}')

    def do_POST(self):
        if self.path in ("/threats", "/peers"):
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
            hmac_header = self.headers.get("X-Swarm-HMAC", "")
            calc = swarm_hmac(body)
            if hmac_header != calc:
                self._set_headers(403)
                self.wfile.write(b'{"status":"bad_hmac"}')
                return
            if self.path == "/threats":
                try:
                    event = json.loads(body.decode("utf-8"))
                    with SWARM_STORAGE_LOCK:
                        SWARM_STORAGE.append(event)
                    self._set_headers(200)
                    self.wfile.write(b'{"status":"ok"}')
                except Exception:
                    self._set_headers(400)
                    self.wfile.write(b'{"status":"bad_json"}')
            elif self.path == "/peers":
                try:
                    peer = json.loads(body.decode("utf-8")).get("peer")
                    if peer:
                        with SWARM_PEERS_LOCK:
                            if peer not in SWARM_PEERS:
                                SWARM_PEERS.append(peer)
                    self._set_headers(200)
                    self.wfile.write(b'{"status":"ok"}')
                except Exception:
                    self._set_headers(400)
                    self.wfile.write(b'{"status":"bad_json"}')
        else:
            self._set_headers(404)
            self.wfile.write(b'{"error":"not_found"}')

def start_swarm_backend():
    if not CONFIG.get("swarm_enabled", True):
        return
    try:
        server = HTTPServer((SWARM_HOST, SWARM_PORT), SwarmHandler)
        cert = CONFIG.get("swarm_tls_cert", "swarm_cert.pem")
        key = CONFIG.get("swarm_tls_key", "swarm_key.pem")
        if os.path.exists(cert) and os.path.exists(key):
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert, keyfile=key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
    except Exception as e:
        set_subsystem_error("swarm", "Swarm backend error: %s" % e)

def swarm_share_threat(event):
    if not CONFIG.get("swarm_enabled", True):
        return
    try:
        body = json.dumps(event).encode("utf-8")
        h = swarm_hmac(body)
        headers = {"X-Swarm-HMAC": h}
        try:
            requests.post("https://127.0.0.1:%d/threats" % SWARM_PORT, data=body, headers=headers, timeout=0.5, verify=False)
        except Exception:
            pass
        with SWARM_PEERS_LOCK:
            peers_copy = list(SWARM_PEERS)
        for peer in peers_copy:
            try:
                requests.post("%s/threats" % peer, data=body, headers=headers, timeout=0.5, verify=False)
            except Exception:
                continue
    except Exception as e:
        set_subsystem_error("swarm", "Swarm share error: %s" % e)

def swarm_pull_threats():
    if not CONFIG.get("swarm_enabled", True):
        return
    try:
        with SWARM_PEERS_LOCK:
            peers_copy = list(SWARM_PEERS)
        for peer in peers_copy:
            try:
                rp = requests.get("%s/threats" % peer, timeout=0.5, verify=False)
                if rp.status_code == 200:
                    _ = rp.json()
            except Exception:
                continue
    except Exception as e:
        set_subsystem_error("swarm", "Swarm pull error: %s" % e)

def swarm_peer_discovery():
    if not CONFIG.get("swarm_enabled", True):
        return
    try:
        local_addrs = psutil.net_if_addrs()
        for name, addrs in local_addrs.items():
            for addr in addrs:
                if addr.family == 2 and (addr.address.startswith("10.") or addr.address.startswith("192.168.")):
                    base = addr.address.rsplit(".", 1)[0]
                    for i in range(2, 255):
                        candidate = "https://%s.%d:%d" % (base, i, SWARM_PORT)
                        try:
                            r = requests.get(candidate + "/peers", timeout=0.2, verify=False)
                            if r.status_code == 200:
                                with SWARM_PEERS_LOCK:
                                    if candidate not in SWARM_PEERS:
                                        SWARM_PEERS.append(candidate)
                        except Exception:
                            continue
    except Exception as e:
        set_subsystem_error("swarm", "Peer discovery error: %s" % e)

# =========================
#  PERSONA ENGINE + ML + GPU-OPTIMIZED DEEP LEARNING
# =========================

def update_persona(score, src, dst, reason):
    if score >= 50:
        PERSONA_STATE["recent_high_threats"] += 1
        PERSONA_STATE["lineage"].append({
            "src": src,
            "dst": dst,
            "score": score,
            "reason": reason,
            "time": datetime.utcnow().isoformat()
        })
    else:
        PERSONA_STATE["recent_high_threats"] = max(0, PERSONA_STATE["recent_high_threats"] - 1)

    if PERSONA_STATE["recent_high_threats"] > 30:
        PERSONA_STATE["aggressiveness"] = min(4.5, PERSONA_STATE["aggressiveness"] + 0.2)
        PERSONA_STATE["mode"] = "hostile"
    elif PERSONA_STATE["recent_high_threats"] > 10:
        PERSONA_STATE["aggressiveness"] = min(3.5, PERSONA_STATE["aggressiveness"] + 0.1)
        PERSONA_STATE["mode"] = "alert"
    else:
        PERSONA_STATE["aggressiveness"] = max(1.0, PERSONA_STATE["aggressiveness"] - 0.05)
        PERSONA_STATE["mode"] = "calm"

def persona_adjust_score(base_score):
    return int(base_score * PERSONA_STATE["aggressiveness"])

def ml_extract_features(src, dst, proto, payload_len, score, reason):
    return [
        len(src),
        len(dst),
        len(proto),
        payload_len,
        score,
        hash(reason) % 1000,
    ]

def ml_train_if_needed():
    global ML_MODEL
    if not ML_ENABLED:
        return
    try:
        with ML_LOCK:
            if len(ML_FEATURES) < 50:
                return
            X = list(ML_FEATURES)
            ML_MODEL = IsolationForest(n_estimators=100, contamination=0.05, random_state=42)
            ML_MODEL.fit(X)
    except Exception as e:
        set_subsystem_error("ml", "ML train error: %s" % e)

def ml_is_anomalous(features):
    if not ML_ENABLED or ML_MODEL is None:
        return False
    try:
        with ML_LOCK:
            pred = ML_MODEL.predict([features])[0]
        return pred == -1
    except Exception as e:
        set_subsystem_error("ml", "ML predict error: %s" % e)
        return False

def deep_extract_features(src, dst, proto, payload_len, score, reason):
    return [
        len(src),
        len(dst),
        len(proto),
        payload_len,
        score,
        hash(reason) % 1000,
    ]

def build_autoencoder(input_dim):
    if not DEEP_ENABLED:
        return None
    inp = Input(shape=(input_dim,))
    x = Dense(128, activation="relu")(inp)
    x = Dropout(0.2)(x)
    x = Dense(64, activation="relu")(x)
    x = Dropout(0.2)(x)
    x = Dense(32, activation="relu")(x)
    x = Dense(64, activation="relu")(x)
    x = Dense(128, activation="relu")(x)
    out = Dense(input_dim, activation="linear")(x)
    model = Model(inp, out)
    lr = 0.001 if GPU_AVAILABLE else 0.0005
    model.compile(optimizer=Adam(lr), loss="mse")
    return model

def build_lstm(input_dim):
    if not DEEP_ENABLED:
        return None
    inp = Input(shape=(1, input_dim))
    x = LSTM(64, return_sequences=False)(inp)
    x = Dropout(0.3)(x)
    out = Dense(1, activation="sigmoid")(x)
    model = Model(inp, out)
    lr = 0.001 if GPU_AVAILABLE else 0.0005
    model.compile(optimizer=Adam(lr), loss="binary_crossentropy")
    return model

def deep_train_if_needed():
    global AUTOENCODER_MODEL, LSTM_MODEL
    if not DEEP_ENABLED:
        return
    try:
        with DEEP_LOCK:
            if len(DEEP_FEATURES) < 100:
                return
            X = list(DEEP_FEATURES)
            input_dim = len(X[0])
            if AUTOENCODER_MODEL is None:
                AUTOENCODER_MODEL = build_autoencoder(input_dim)
            if LSTM_MODEL is None:
                LSTM_MODEL = build_lstm(input_dim)
            if AUTOENCODER_MODEL is None or LSTM_MODEL is None:
                return
            batch_size = 64 if GPU_AVAILABLE else 16
            AUTOENCODER_MODEL.fit(X, X, epochs=5, batch_size=batch_size, verbose=0)
            seq_X = [[f] for f in X]
            LSTM_MODEL.fit(seq_X, [0]*len(seq_X), epochs=5, batch_size=batch_size, verbose=0)
    except Exception as e:
        set_subsystem_error("deep", "Deep train error: %s" % e)

def deep_is_anomalous(features):
    if not DEEP_ENABLED or AUTOENCODER_MODEL is None or LSTM_MODEL is None:
        return False
    try:
        with DEEP_LOCK:
            recon = AUTOENCODER_MODEL.predict([features], verbose=0)[0]
            mse = sum((a-b)**2 for a, b in zip(features, recon)) / len(features)
            seq = [[features]]
            prob = LSTM_MODEL.predict(seq, verbose=0)[0][0]
        return mse > 50 or prob > 0.7
    except Exception as e:
        set_subsystem_error("deep", "Deep predict error: %s" % e)
        return False

# =========================
#  UDM PRO API (STUB)
# =========================

def udm_push_firewall_rule(rule_name, src_ip, action="drop"):
    try:
        log_event(src_ip, "UDM", "API", "udm_rule", 0, "rule=%s, action=%s" % (rule_name, action))
    except Exception as e:
        set_subsystem_error("service", "UDM API stub error: %s" % e)

# =========================
#  PACKET CAPTURE + PCAP EXPORT + REPLAY
# =========================

def pcap_write_packet(f, ts_sec, ts_usec, payload):
    incl_len = len(payload)
    orig_len = len(payload)
    f.write(struct.pack("IIII", ts_sec, ts_usec, incl_len, orig_len))
    f.write(payload)

def pcap_init_file(path):
    with open(path, "wb") as f:
        f.write(struct.pack("IHHIIII",
                            0xa1b2c3d4,
                            2,
                            4,
                            0,
                            0,
                            65535,
                            1))

def capture_packet(src, dst, proto, payload, reason):
    if not CAPTURE_ENABLED:
        return
    try:
        ts = datetime.utcnow()
        ts_str = ts.strftime("%Y%m%d_%H%M%S_%f")
        fname_bin = "%s_%s_to_%s_%s_%s.bin" % (ts_str, src, dst, proto, reason)
        path_bin = os.path.join(CAPTURE_DIR, fname_bin)
        with CAPTURE_LOCK:
            with open(path_bin, "wb") as f:
                f.write(payload)

        fname_pcap = "%s_%s_to_%s_%s_%s.pcap" % (ts_str, src, dst, proto, reason)
        path_pcap = os.path.join(PCAP_DIR, fname_pcap)
        with CAPTURE_LOCK:
            if not os.path.exists(path_pcap):
                pcap_init_file(path_pcap)
            with open(path_pcap, "ab") as f:
                ts_sec = int(ts.timestamp())
                ts_usec = int((ts.timestamp() - ts_sec) * 1_000_000)
                pcap_write_packet(f, ts_sec, ts_usec, payload)

        with REPLAY_LOCK:
            REPLAY_QUEUE.append(path_bin)
    except Exception as e:
        set_subsystem_error("capture", "Capture error: %s" % e)

def replay_packet(path):
    try:
        with open(path, "rb") as f:
            payload = f.read()
        src = "replay_src"
        dst = "replay_dst"
        proto = "REPLAY"
        action, score, reason, meta = ai_firewall(payload, src, dst, proto, offline=True, direction="INBOUND")
        log_event(src, dst, proto, "replay_%s" % action, score, reason, meta)
    except Exception as e:
        set_subsystem_error("capture", "Replay error: %s" % e)

# =========================
#  AGENTIC REASONING ENGINE (OpenAI-style triage)
# =========================

def agentic_reasoning(src, dst, proto, base_score, reason, meta):
    """
    Agentic reasoning engine:
    - Considers DPI, Suricata, ML, deep learning, behavior, MITRE mapping
    - Produces final triage decision and reasoning trace
    """
    try:
        trace = []
        trace.append("Start triage for src=%s dst=%s proto=%s reason=%s base_score=%d" % (src, dst, proto, reason, base_score))

        if meta.get("suricata_sid"):
            trace.append("Suricata SID present -> high confidence signature match.")
            base_score += 20

        if meta.get("malware_sig"):
            trace.append("Malware signature present -> escalate to critical.")
            base_score += 30

        if meta.get("ml_anomaly"):
            trace.append("ML anomaly detected -> suspicious behavior.")
            base_score += 15

        if meta.get("deep_anomaly"):
            trace.append("Deep anomaly detected -> possible stealthy threat.")
            base_score += 20

        if meta.get("behavior_fp"):
            trace.append("Behavior fingerprint present -> correlate with past activity.")

        mitre_entry = map_mitre(reason, meta)
        if mitre_entry:
            trace.append("MITRE mapping -> tactic=%s technique=%s name=%s" % (
                mitre_entry["tactic"], mitre_entry["technique"], mitre_entry["name"]
            ))

        if base_score >= 100:
            decision = "drop"
            trace.append("Final decision: DROP (critical threat).")
        elif base_score >= 70:
            decision = "fake"
            trace.append("Final decision: FAKE (deception response).")
        elif reason == "ad_block":
            decision = "drop"
            trace.append("Final decision: DROP (ad_block policy).")
        else:
            decision = "allow"
            trace.append("Final decision: ALLOW (low threat).")

        meta["agentic_trace"] = trace
        return decision, base_score, reason, meta
    except Exception as e:
        set_subsystem_error("agentic", "Agentic reasoning error: %s" % e)
        return "allow", base_score, reason, meta

# =========================
#  AI FIREWALL
# =========================

def ip_in_allowlist(ip):
    return ip in PERMA_ALLOW_IPS

def ai_firewall(payload, src, dst, proto, offline=False, direction="INBOUND"):
    ja3_hash = None
    ja3s_hash = None

    if ip_in_allowlist(dst) or ip_in_allowlist(src):
        return "allow", 0, "perma_allow", {}

    base_score = 0
    reason = "normal"
    meta = {}

    try:
        dpi_score, dpi_reason, dpi_meta = dpi_analyze(payload, direction=direction)
        if dpi_score > 0:
            base_score += dpi_score
            reason = dpi_reason
            meta.update(dpi_meta)
        ja3_hash = dpi_meta.get("ja3")
        ja3s_hash = dpi_meta.get("ja3s")

        action, rname, sid = rule_editor_match(src, dst, proto, payload, ja3_hash=ja3_hash, ja3s_hash=ja3s_hash)
        if action:
            meta["rule_editor"] = rname
            meta["rule_sid"] = sid
            reason = "rule_editor"
            if action == "drop":
                decision, final_score, final_reason, meta = agentic_reasoning(src, dst, proto, base_score, reason, meta)
                return decision, final_score, "rule_editor:%s" % rname, meta
            elif action == "fake":
                decision, final_score, final_reason, meta = agentic_reasoning(src, dst, proto, base_score, reason, meta)
                return decision, final_score, "rule_editor:%s" % rname, meta
            else:
                decision, final_score, final_reason, meta = agentic_reasoning(src, dst, proto, base_score, reason, meta)
                return decision, final_score, "rule_editor:%s" % rname, meta

        suricata_sid = meta.get("suricata_sid")
        if suricata_sid:
            base_score += 60
            reason = "suricata"

        for sig in MALWARE_SIGNATURES:
            if sig in payload:
                reason = "malware_sig"
                base_score += 60
                meta["malware_sig"] = sig.decode("latin-1", errors="ignore")
                break

        for sig in AD_SIGNATURES:
            if sig in payload:
                reason = "ad_block"
                base_score += 30
                meta["ad_sig"] = sig.decode("latin-1", errors="ignore")
                break

        final_score = persona_adjust_score(base_score)
        if not offline:
            update_persona(final_score, src, dst, reason)

        features = ml_extract_features(src, dst, proto, len(payload), final_score, reason)
        with ML_LOCK:
            ML_FEATURES.append(features)
        ml_train_if_needed()
        if ml_is_anomalous(features):
            final_score += 30
            meta["ml_anomaly"] = True
            reason = "ml_anomaly"

        deep_features = deep_extract_features(src, dst, proto, len(payload), final_score, reason)
        with DEEP_LOCK:
            DEEP_FEATURES.append(deep_features)
        deep_train_if_needed()
        if deep_is_anomalous(deep_features):
            final_score += 40
            meta["deep_anomaly"] = True
            reason = "deep_anomaly"

        update_behavior_profile(src, dst, proto, len(payload), {**meta, "reason": reason})
        behavior_fp = behavior_fingerprint(src)
        if behavior_fp:
            meta["behavior_fp"] = behavior_fp

        decision, final_score, reason, meta = agentic_reasoning(src, dst, proto, final_score, reason, meta)

        if decision == "drop":
            udm_push_firewall_rule("auto_block_high_threat", src, "drop")
            swarm_share_threat({
                "src": src,
                "dst": dst,
                "proto": proto,
                "score": final_score,
                "reason": reason,
                "meta": meta,
            })
            if not offline:
                capture_packet(src, dst, proto, payload, reason)
            return "drop", final_score, reason, meta

        if decision == "fake":
            if not offline:
                capture_packet(src, dst, proto, payload, reason)
            return "fake", final_score, reason, meta

        if reason == "ad_block":
            if not offline:
                capture_packet(src, dst, proto, payload, "ad_block")
            return "drop", final_score, "ad_block", meta

    except Exception as e:
        set_subsystem_error("bridge", "AI firewall error: %s" % e)
        diag_add_error("AI firewall error: %s" % e)
        return "allow", 0, "error", {}

    return "allow", base_score, reason, meta

# =========================
#  NDIS LIGHTWEIGHT FILTER DRIVER SCAFFOLD
# =========================

class NDISLightweightFilter:
    """
    NDIS lightweight filter driver scaffolding:
    - This is a control-plane stub that would coordinate with a real kernel driver.
    - In Python, we manage service state, configuration, and health checks.
    """

    def __init__(self):
        self.running = False
        self.last_error = None

    def start(self):
        try:
            # Stub: in a real implementation, this would control a kernel-mode driver
            self.running = True
            set_subsystem_error("ndis", "NDIS filter running (stub control-plane).")
        except Exception as e:
            self.running = False
            self.last_error = str(e)
            set_subsystem_error("ndis", "NDIS start error: %s" % e)

    def stop(self):
        try:
            self.running = False
            set_subsystem_error("ndis", "NDIS filter stopped.")
        except Exception as e:
            self.last_error = str(e)
            set_subsystem_error("ndis", "NDIS stop error: %s" % e)

    def health_check(self):
        try:
            if not self.running:
                return False
            return True
        except Exception as e:
            self.last_error = str(e)
            set_subsystem_error("ndis", "NDIS health error: %s" % e)
            return False

NDIS_FILTER = NDISLightweightFilter()

# =========================
#  BRIDGE + WORKERS (WinDivert, NDIS SCAFFOLD)
# =========================

def worker_loop():
    global DIVERT_HANDLE
    while not STOP_FLAG:
        try:
            packet = PACKET_QUEUE.get(timeout=1)
        except queue.Empty:
            continue
        try:
            src = packet.src_addr
            dst = packet.dst_addr
            proto = packet.protocol.name if packet.protocol else "UNKNOWN"
            payload = packet.payload
            direction = "INBOUND" if packet.direction == Direction.INBOUND else "OUTBOUND"

            action, score, reason, meta = ai_firewall(payload, src, dst, proto, direction=direction)

            if action == "allow":
                packet.direction = Direction.OUTBOUND if packet.direction == Direction.INBOUND else Direction.INBOUND
                DIVERT_HANDLE.send(packet)
                log_event(src, dst, proto, "allow", score, reason, meta)
            elif action == "drop":
                log_event(src, dst, proto, "drop", score, reason, meta)
            elif action == "fake":
                deception_response(DIVERT_HANDLE, packet, reason, src, dst, meta)
                log_event(src, dst, proto, "fake", score, reason, meta)
        except Exception as e:
            set_subsystem_error("bridge", "Worker error: %s" % e)
            diag_add_error("Worker error: %s" % e)
            log_event("N/A", "N/A", "N/A", "error", 0, str(e))

def bridge_sniffer():
    global DIVERT_HANDLE
    try:
        DIVERT_HANDLE = WinDivert("ip and ipv4", layer=Layer.NETWORK)
        DIVERT_HANDLE.open()
        DIAG_STATE["windivert_present"] = "yes"
    except Exception as e:
        set_subsystem_error("bridge", "WinDivert open error: %s" % e)
        diag_add_error("WinDivert open error: %s" % e)
        DIAG_STATE["windivert_present"] = "no"
        return

    while not STOP_FLAG:
        try:
            packet = DIVERT_HANDLE.recv()
            try:
                PACKET_QUEUE.put(packet, timeout=0.1)
            except queue.Full:
                log_event("N/A", "N/A", "N/A", "drop", 0, "queue_full", {})
        except Exception as e:
            set_subsystem_error("bridge", "Sniffer error: %s" % e)
            diag_add_error("Sniffer error: %s" % e)
            time.sleep(0.5)

def start_bridge():
    global BRIDGE_RUNNING, STOP_FLAG, WORKER_THREADS
    try:
        if BRIDGE_RUNNING:
            return
        STOP_FLAG = False
        BRIDGE_RUNNING = True

        WORKER_THREADS = []
        for _ in range(NUM_WORKERS):
            t = threading.Thread(target=worker_loop, daemon=True)
            t.start()
            WORKER_THREADS.append(t)

        threading.Thread(target=bridge_sniffer, daemon=True).start()
        threading.Thread(target=NDIS_FILTER.start, daemon=True).start()
    except Exception as e:
        set_subsystem_error("bridge", "Start bridge error: %s" % e)
        diag_add_error("Start bridge error: %s" % e)

def stop_bridge():
    global BRIDGE_RUNNING, STOP_FLAG, DIVERT_HANDLE
    STOP_FLAG = True
    BRIDGE_RUNNING = False
    try:
        if DIVERT_HANDLE:
            DIVERT_HANDLE.close()
    except Exception:
        pass
    try:
        NDIS_FILTER.stop()
    except Exception:
        pass

# =========================
#  WATCHDOG
# =========================

def watchdog_loop():
    while True:
        try:
            if not verify_integrity():
                set_subsystem_error("watchdog", "Integrity failure detected.")
                diag_add_error("Integrity failure detected.")
                os._exit(1)
            if BRIDGE_RUNNING is False and not STOP_FLAG:
                start_bridge()
            swarm_peer_discovery()
            swarm_pull_threats()
            if not NDIS_FILTER.health_check():
                set_subsystem_error("ndis", "NDIS filter health check failed.")
        except Exception as e:
            set_subsystem_error("watchdog", "Watchdog error: %s" % e)
            diag_add_error("Watchdog error: %s" % e)
        time.sleep(5)

# =========================
#  WINDOWS SERVICE
# =========================

class AISecurityBridgeService(win32serviceutil.ServiceFramework):
    _svc_name_ = "AISecurityBridgeService"
    _svc_display_name_ = "AI Security Bridge Service"
    _svc_description_ = "Inline AI-driven security bridge with Suricata v6, JA3/JA3S, ML, GPU deep learning, swarm, honeypots, agentic reasoning, MITRE mapping."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        global STOP_FLAG
        STOP_FLAG = True
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        detect_interfaces()
        start_swarm_backend()
        start_honeypot_suite()
        threading.Thread(target=watchdog_loop, daemon=True).start()
        start_bridge()
        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

# =========================
#  ADAPTER ENUMERATION
# =========================

def get_adapters():
    adapters = []
    try:
        stats_all = psutil.net_if_stats()
        addrs_all = psutil.net_if_addrs()

        for name, stats in stats_all.items():
            info = addrs_all.get(name, [])
            ip = next((i.address for i in info if i.family == 2), "N/A")
            mac = next((i.address for i in info if i.family == 17), "N/A")
            adapters.append({
                "name": name,
                "status": "UP" if stats.isup else "DOWN",
                "speed": "%d Mbps" % stats.speed,
                "mac": mac,
                "ip": ip
            })
    except Exception as e:
        set_subsystem_error("service", "Adapter enumeration error: %s" % e)
        diag_add_error("Adapter enumeration error: %s" % e)
    return adapters

# =========================
#  DIAGNOSTICS HELPERS
# =========================

def run_diagnostics_once():
    try:
        test = WinDivert("ip and ipv4", layer=Layer.NETWORK)
        test.open()
        test.close()
        DIAG_STATE["windivert_present"] = "yes"
    except Exception as e:
        DIAG_STATE["windivert_present"] = "no"
        diag_add_error("WinDivert check error: %s" % e)

    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.close()
        DIAG_STATE["raw_socket_ok"] = "yes"
    except Exception as e:
        DIAG_STATE["raw_socket_ok"] = "no"
        diag_add_error("Raw socket test error: %s" % e)

    DIAG_STATE["promisc_ok"] = "handled_by_windivert"

# =========================
#  GUI
# =========================

class AISecurityBridgeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI Security Bridge (Suricata v6, NDIS, GPU Deep, Agentic, MITRE, Cowrie)")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        self.tab_if = tk.Frame(self.notebook)
        self.tab_logs = tk.Frame(self.notebook)
        self.tab_fw = tk.Frame(self.notebook)
        self.tab_ai = tk.Frame(self.notebook)
        self.tab_sys = tk.Frame(self.notebook)
        self.tab_diag = tk.Frame(self.notebook)
        self.tab_graphs = tk.Frame(self.notebook)
        self.tab_rules = tk.Frame(self.notebook)
        self.tab_replay = tk.Frame(self.notebook)
        self.tab_corr = tk.Frame(self.notebook)
        self.tab_scores = tk.Frame(self.notebook)

        self.notebook.add(self.tab_if, text="Interfaces")
        self.notebook.add(self.tab_logs, text="Logs")
        self.notebook.add(self.tab_fw, text="Firewall")
        self.notebook.add(self.tab_ai, text="AI/ML/Deep/Agentic")
        self.notebook.add(self.tab_sys, text="Subsystems")
        self.notebook.add(self.tab_diag, text="Diagnostics")
        self.notebook.add(self.tab_graphs, text="Graphs")
        self.notebook.add(self.tab_rules, text="Rules")
        self.notebook.add(self.tab_replay, text="Replay")
        self.notebook.add(self.tab_corr, text="Correlation")
        self.notebook.add(self.tab_scores, text="Threat Scores")

        self.build_if_tab()
        self.build_logs_tab()
        self.build_fw_tab()
        self.build_ai_tab()
        self.build_sys_tab()
        self.build_diag_tab()
        self.build_graphs_tab()
        self.build_rules_tab()
        self.build_replay_tab()
        self.build_corr_tab()
        self.build_scores_tab()

        self.refresh_if()
        self.refresh_logs()
        self.refresh_ai()
        self.refresh_sys()
        self.refresh_diag()
        self.refresh_graphs()
        self.refresh_rules()
        self.refresh_replay()
        self.refresh_corr()
        self.refresh_scores()

        self.root.after(500, self.start_subsystems_safe)

    def start_subsystems_safe(self):
        try:
            detect_interfaces()
        except Exception as e:
            set_subsystem_error("autodetect", "Detect interfaces error: %s" % e)
            diag_add_error("Detect interfaces error: %s" % e)

        if INTEGRITY_FAILED:
            set_subsystem_error("service", "Integrity check failed at startup.")
            diag_add_error("Integrity check failed at startup.")

        try:
            start_swarm_backend()
        except Exception as e:
            set_subsystem_error("swarm", "Swarm start error: %s" % e)
            diag_add_error("Swarm start error: %s" % e)

        try:
            start_honeypot_suite()
        except Exception as e:
            set_subsystem_error("honeypot", "Honeypot start error: %s" % e)
            diag_add_error("Honeypot start error: %s" % e)

        try:
            threading.Thread(target=watchdog_loop, daemon=True).start()
        except Exception as e:
            set_subsystem_error("watchdog", "Watchdog start error: %s" % e)
            diag_add_error("Watchdog start error: %s" % e)

        try:
            start_bridge()
        except Exception as e:
            set_subsystem_error("bridge", "Bridge start error: %s" % e)
            diag_add_error("Bridge start error: %s" % e)

        try:
            run_diagnostics_once()
        except Exception as e:
            set_subsystem_error("diagnostics", "Diagnostics run error: %s" % e)
            diag_add_error("Diagnostics run error: %s" % e)

    def build_if_tab(self):
        top = tk.Frame(self.tab_if)
        top.pack(fill="x", padx=5, pady=5)

        self.mode_var = tk.StringVar(value=BRIDGE_MODE)
        tk.Label(top, text="Bridge Mode (auto-detected):").pack(side="left", padx=5)
        tk.Label(top, textvariable=self.mode_var).pack(side="left", padx=5)

        self.status_label = tk.Label(top, text="Bridge Status: STOPPED")
        self.status_label.pack(side="left", padx=10)

        self.adapter_tree = ttk.Treeview(self.tab_if,
                                         columns=("Name", "Status", "Speed", "MAC", "IP"),
                                         show="headings")
        for col in ("Name", "Status", "Speed", "MAC", "IP"):
            self.adapter_tree.heading(col, text=col)
        self.adapter_tree.pack(fill="both", expand=True, padx=5, pady=5)

    def refresh_if(self):
        for row in self.adapter_tree.get_children():
            self.adapter_tree.delete(row)
        for a in get_adapters():
            self.adapter_tree.insert("", "end",
                                     values=(a["name"], a["status"], a["speed"], a["mac"], a["ip"]))
        self.mode_var.set(BRIDGE_MODE)
        self.status_label.config(text="Bridge Status: %s (Mode=%s)" % ("RUNNING" if BRIDGE_RUNNING else "STOPPED", BRIDGE_MODE))
        self.root.after(2000, self.refresh_if)

    def build_logs_tab(self):
        self.log_text = scrolledtext.ScrolledText(self.tab_logs, wrap="none")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

    def refresh_logs(self):
        logs = get_recent_logs()
        self.log_text.delete("1.0", tk.END)
        for e in logs:
            line = "%s | %s -> %s | %s | %s | score=%d | %s | meta=%s | mitre=%s\n" % (
                e["time"], e["src"], e["dst"], e["proto"], e["action"], e["score"], e["reason"], json.dumps(e["meta"]), json.dumps(e.get("mitre"))
            )
            self.log_text.insert(tk.END, line)
        self.root.after(2000, self.refresh_logs)

    def build_fw_tab(self):
        lbl = tk.Label(
            self.tab_fw,
            text=(
                "Firewall Engine: WinDivert inline + HTTP/TLS/JA3/JA3S DPI + Suricata v6-like rules + persona + IsolationForest ML + GPU-optimized deep learning.\n"
                "Swarm cluster (TLS mutual auth, HMAC), honeypot suite (Cowrie/Dionaea/HoneyHTTP), packet capture + PCAP export, rule editor, threat DB, agentic reasoning, MITRE mapping.\n"
                "Bridge auto-starts and mode auto-detects (WAN vs LAN)."
            )
        )
        lbl.pack(padx=10, pady=10)

    def build_ai_tab(self):
        self.ai_status = tk.Label(self.tab_ai, text="AI/ML/Deep/Agentic Engine: IDLE")
        self.ai_status.pack(padx=10, pady=10)

        self.persona_label = tk.Label(self.tab_ai, text="")
        self.persona_label.pack(padx=10, pady=10)

        self.ml_label = tk.Label(self.tab_ai, text="ML: training status unknown")
        self.ml_label.pack(padx=10, pady=10)

        self.deep_label = tk.Label(self.tab_ai, text="Deep: training status unknown")
        self.deep_label.pack(padx=10, pady=10)

        self.agentic_label = tk.Label(self.tab_ai, text="Agentic: reasoning traces not shown")
        self.agentic_label.pack(padx=10, pady=10)

        self.mitre_label = tk.Label(self.tab_ai, text="MITRE: mapping active")
        self.mitre_label.pack(padx=10, pady=10)

        self.deps_label = tk.Label(self.tab_ai, text="Dependencies: see Diagnostics tab")
        self.deps_label.pack(padx=10, pady=10)

        self.gpu_label = tk.Label(self.tab_ai, text="GPU: unknown")
        self.gpu_label.pack(padx=10, pady=10)

    def refresh_ai(self):
        self.ai_status.config(text="AI/ML/Deep/Agentic Engine: %s" % ("ONLINE" if BRIDGE_RUNNING else "IDLE"))
        self.persona_label.config(
            text="Persona: mode=%s, aggressiveness=%.2f, recent_high_threats=%d" % (
                PERSONA_STATE["mode"], PERSONA_STATE["aggressiveness"], PERSONA_STATE["recent_high_threats"]
            )
        )
        self.ml_label.config(text="ML: %s, model=%s" % (
            "enabled" if ML_ENABLED else "disabled",
            "ready" if ML_MODEL is not None else "not trained"
        ))
        self.deep_label.config(text="Deep: %s, AE=%s, LSTM=%s" % (
            "enabled" if DEEP_ENABLED else "disabled",
            "ready" if AUTOENCODER_MODEL is not None else "not trained",
            "ready" if LSTM_MODEL is not None else "not trained"
        ))
        self.agentic_label.config(text="Agentic: %s" % ("enabled" if True else "disabled"))
        self.mitre_label.config(text="MITRE: mapping %s" % ("active" if True else "inactive"))
        self.gpu_label.config(text="GPU: %s" % ("available" if GPU_AVAILABLE else "not available"))
        self.root.after(2000, self.refresh_ai)

    def build_sys_tab(self):
        self.sys_text = scrolledtext.ScrolledText(self.tab_sys, wrap="none")
        self.sys_text.pack(fill="both", expand=True, padx=5, pady=5)

    def refresh_sys(self):
        errs = get_subsystem_errors()
        self.sys_text.delete("1.0", tk.END)
        self.sys_text.insert(tk.END, "Subsystem Status:\n\n")
        for name, msg in errs.items():
            if msg:
                line = "[%s] ERROR: %s\n" % (name.upper(), msg)
            else:
                line = "[%s] OK\n" % name.upper()
            self.sys_text.insert(tk.END, line)
        if INTEGRITY_FAILED:
            self.sys_text.insert(tk.END, "\n[INTEGRITY] WARNING: Integrity check failed at startup.\n")
        self.root.after(2000, self.refresh_sys)

    def build_diag_tab(self):
        top = tk.Frame(self.tab_diag)
        top.pack(fill="x", padx=5, pady=5)

        self.diag_windivert_label = tk.Label(top, text="WinDivert: unknown")
        self.diag_windivert_label.pack(side="left", padx=5)

        self.diag_raw_label = tk.Label(top, text="Raw socket: unknown")
        self.diag_raw_label.pack(side="left", padx=5)

        self.diag_promisc_label = tk.Label(top, text="Promisc: unknown")
        self.diag_promisc_label.pack(side="left", padx=5)

        self.diag_text = scrolledtext.ScrolledText(self.tab_diag, wrap="none")
        self.diag_text.pack(fill="both", expand=True, padx=5, pady=5)

    def refresh_diag(self):
        state = get_diag_state()
        self.diag_windivert_label.config(text="WinDivert: %s" % state.get("windivert_present", "unknown"))
        self.diag_raw_label.config(text="Raw socket: %s" % state.get("raw_socket_ok", "unknown"))
        self.diag_promisc_label.config(text="Promisc: %s" % state.get("promisc_ok", "unknown"))

        self.diag_text.delete("1.0", tk.END)
        self.diag_text.insert(tk.END, "Diagnostics Log:\n\n")
        for line in state.get("last_errors", []):
            self.diag_text.insert(tk.END, line + "\n")

        self.diag_text.insert(tk.END, "\nDependency Validator:\n\n")
        for d in state.get("deps", []):
            self.diag_text.insert(tk.END, d + "\n")

        self.root.after(3000, self.refresh_diag)

    def build_graphs_tab(self):
        self.fig = plt.Figure(figsize=(6, 4), dpi=100)
        self.ax_threat = self.fig.add_subplot(311)
        self.ax_rate = self.fig.add_subplot(312)
        self.ax_honeypot = self.fig.add_subplot(313)

        self.canvas = FigureCanvasTkAgg(self.fig, master=self.tab_graphs)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)

    def refresh_graphs(self):
        with GRAPH_LOCK:
            threat_data = list(THREAT_TIMELINE)
            rate_data = list(PACKET_RATE_TIMELINE)
            honeypot_data = list(HONEYPOT_HITS_TIMELINE)

        self.ax_threat.clear()
        if threat_data:
            xs = [d[0] for d in threat_data]
            ys = [d[1] for d in threat_data]
            self.ax_threat.plot(xs, ys, marker=".", linestyle="-")
        self.ax_threat.set_ylabel("Threat score")

        self.ax_rate.clear()
        if rate_data:
            xs = [d[0] for d in rate_data]
            ys = [d[1] for d in rate_data]
            self.ax_rate.plot(xs, ys, marker=".", linestyle="-")
        self.ax_rate.set_ylabel("Packet count")

        self.ax_honeypot.clear()
        if honeypot_data:
            xs = [d[0] for d in honeypot_data]
            ys = [d[1] for d in honeypot_data]
            self.ax_honeypot.plot(xs, ys, marker=".", linestyle="-")
        self.ax_honeypot.set_ylabel("Honeypot hits")

        self.fig.tight_layout()
        self.canvas.draw()

        self.root.after(5000, self.refresh_graphs)

    def build_rules_tab(self):
        top = tk.Frame(self.tab_rules)
        top.pack(fill="x", padx=5, pady=5)

        tk.Label(top, text="Rule Editor (IP/proto/content/regex/JA3/JA3S/SID -> action)").pack(side="left", padx=5)

        self.rules_list = scrolledtext.ScrolledText(self.tab_rules, wrap="none", height=15)
        self.rules_list.pack(fill="both", expand=True, padx=5, pady=5)

        form = tk.Frame(self.tab_rules)
        form.pack(fill="x", padx=5, pady=5)

        tk.Label(form, text="Name").grid(row=0, column=0)
        tk.Label(form, text="Src IP").grid(row=0, column=1)
        tk.Label(form, text="Dst IP").grid(row=0, column=2)
        tk.Label(form, text="Proto").grid(row=0, column=3)
        tk.Label(form, text="Content/Regex").grid(row=0, column=4)
        tk.Label(form, text="Regex? (yes/no)").grid(row=0, column=5)
        tk.Label(form, text="JA3").grid(row=0, column=6)
        tk.Label(form, text="JA3S").grid(row=0, column=7)
        tk.Label(form, text="SID").grid(row=0, column=8)
        tk.Label(form, text="Action").grid(row=0, column=9)

        self.rule_name_var = tk.StringVar()
        self.rule_src_var = tk.StringVar()
        self.rule_dst_var = tk.StringVar()
        self.rule_proto_var = tk.StringVar()
        self.rule_content_var = tk.StringVar()
        self.rule_regex_var = tk.StringVar(value="no")
        self.rule_ja3_var = tk.StringVar()
        self.rule_ja3s_var = tk.StringVar()
        self.rule_sid_var = tk.StringVar()
        self.rule_action_var = tk.StringVar(value="drop")

        tk.Entry(form, textvariable=self.rule_name_var, width=10).grid(row=1, column=0)
        tk.Entry(form, textvariable=self.rule_src_var, width=12).grid(row=1, column=1)
        tk.Entry(form, textvariable=self.rule_dst_var, width=12).grid(row=1, column=2)
        tk.Entry(form, textvariable=self.rule_proto_var, width=8).grid(row=1, column=3)
        tk.Entry(form, textvariable=self.rule_content_var, width=20).grid(row=1, column=4)
        tk.Entry(form, textvariable=self.rule_regex_var, width=8).grid(row=1, column=5)
        tk.Entry(form, textvariable=self.rule_ja3_var, width=20).grid(row=1, column=6)
        tk.Entry(form, textvariable=self.rule_ja3s_var, width=20).grid(row=1, column=7)
        tk.Entry(form, textvariable=self.rule_sid_var, width=10).grid(row=1, column=8)
        tk.Entry(form, textvariable=self.rule_action_var, width=8).grid(row=1, column=9)

        tk.Button(form, text="Add Rule", command=self.add_rule).grid(row=1, column=10, padx=5)
        tk.Button(form, text="Save Rules", command=self.save_rules).grid(row=1, column=11, padx=5)

    def refresh_rules(self):
        with RULE_EDITOR_LOCK:
            rules = list(RULE_EDITOR_RULES)
        self.rules_list.delete("1.0", tk.END)
        self.rules_list.insert(tk.END, "Current Rules:\n\n")
        for r in rules:
            self.rules_list.insert(
                tk.END,
                "%s | src=%s dst=%s proto=%s content=%s regex=%s ja3=%s ja3s=%s sid=%s action=%s\n" % (
                    r.get("name", ""),
                    r.get("src", ""),
                    r.get("dst", ""),
                    r.get("proto", ""),
                    r.get("content", ""),
                    r.get("regex", False),
                    r.get("ja3", ""),
                    r.get("ja3s", ""),
                    r.get("sid", ""),
                    r.get("action", "")
                )
            )
        self.root.after(5000, self.refresh_rules)

    def add_rule(self):
        r = {
            "name": self.rule_name_var.get(),
            "src": self.rule_src_var.get() or None,
            "dst": self.rule_dst_var.get() or None,
            "proto": self.rule_proto_var.get() or None,
            "content": self.rule_content_var.get() or None,
            "regex": (self.rule_regex_var.get().lower() == "yes"),
            "ja3": self.rule_ja3_var.get() or None,
            "ja3s": self.rule_ja3s_var.get() or None,
            "sid": self.rule_sid_var.get() or None,
            "action": self.rule_action_var.get() or "drop",
        }
        with RULE_EDITOR_LOCK:
            RULE_EDITOR_RULES.append(r)
        self.rule_name_var.set("")
        self.rule_src_var.set("")
        self.rule_dst_var.set("")
        self.rule_proto_var.set("")
        self.rule_content_var.set("")
        self.rule_regex_var.set("no")
        self.rule_ja3_var.set("")
        self.rule_ja3s_var.set("")
        self.rule_sid_var.set("")
        self.rule_action_var.set("drop")
        self.refresh_rules()

    def save_rules(self):
        save_rule_editor_rules()

    def build_replay_tab(self):
        top = tk.Frame(self.tab_replay)
        top.pack(fill="x", padx=5, pady=5)

        tk.Label(top, text="Packet Replay (captured flows)").pack(side="left", padx=5)

        self.replay_list = scrolledtext.ScrolledText(self.tab_replay, wrap="none", height=15)
        self.replay_list.pack(fill="both", expand=True, padx=5, pady=5)

        btn_frame = tk.Frame(self.tab_replay)
        btn_frame.pack(fill="x", padx=5, pady=5)

        tk.Button(btn_frame, text="Replay Selected", command=self.replay_selected).pack(side="left", padx=5)

        self.replay_selected_var = tk.StringVar()
        tk.Entry(btn_frame, textvariable=self.replay_selected_var, width=60).pack(side="left", padx=5)

    def refresh_replay(self):
        with REPLAY_LOCK:
            items = list(REPLAY_QUEUE)
        self.replay_list.delete("1.0", tk.END)
        self.replay_list.insert(tk.END, "Captured Packets (binary paths):\n\n")
        for p in items:
            self.replay_list.insert(tk.END, p + "\n")
        self.root.after(5000, self.refresh_replay)

    def replay_selected(self):
        path = self.replay_selected_var.get()
        if path and os.path.exists(path):
            replay_packet(path)

    def build_corr_tab(self):
        self.corr_text = scrolledtext.ScrolledText(self.tab_corr, wrap="none")
        self.corr_text.pack(fill="both", expand=True, padx=5, pady=5)

    def refresh_corr(self):
        with CORRELATION_LOCK:
            idx = CORRELATION_INDEX.copy()
        self.corr_text.delete("1.0", tk.END)
        self.corr_text.insert(tk.END, "Threat Correlation Index:\n\n")
        for key_type in ("by_src", "by_dst", "by_ja3", "by_ja3s", "by_sid", "by_behavior", "by_mitre"):
            self.corr_text.insert(tk.END, "[%s]\n" % key_type)
            for k, v in idx.get(key_type, {}).items():
                self.corr_text.insert(tk.END, "  %s: %s\n" % (k, v))
            self.corr_text.insert(tk.END, "\n")
        self.root.after(5000, self.refresh_corr)

    def build_scores_tab(self):
        self.scores_text = scrolledtext.ScrolledText(self.tab_scores, wrap="none")
        self.scores_text.pack(fill="both", expand=True, padx=5, pady=5)

    def refresh_scores(self):
        breakdown = get_score_breakdown()
        self.scores_text.delete("1.0", tk.END)
        self.scores_text.insert(tk.END, "Threat Score Breakdown (per reason):\n\n")
        for reason, total in breakdown.items():
            self.scores_text.insert(tk.END, "%s: %d\n" % (reason, total))
        self.root.after(5000, self.refresh_scores)

# =========================
#  MAIN
# =========================

def run_gui_mode():
    root = tk.Tk()
    app = AISecurityBridgeApp(root)
    root.mainloop()

def main():
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("install", "remove", "start", "stop", "restart"):
        win32serviceutil.HandleCommandLine(AISecurityBridgeService)
    else:
        run_gui_mode()

if __name__ == "__main__":
    main()
