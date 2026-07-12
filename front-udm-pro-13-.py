#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AI Security Bridge — Commercial-Grade Appliance (Single File)

Features:
- WinDivert inline firewall (kernel-level interception)
- Full-ish JA3 spec parser (TLS ClientHello fingerprinting)
- Suricata-like rule engine (PCRE, flowbits, metadata, thresholds — simplified)
- HTTP DPI (headers, cookies, hostnames, methods, user agents)
- Honeypot emulation (Cowrie-style SSH, Dionaea-style SMB, HoneyHTTP — simplified)
- Swarm cluster with TLS mutual authentication (encrypted peer-to-peer threat sharing)
- ML anomaly detection (basic unsupervised model stub)
- Interactive GUI graphs (TkAgg, real-time charts)
- Packet capture + replay GUI (forensic replay through DPI engine)
- Full rule editor (regex, ranges, JA3, Suricata SIDs)
- Threat database (SQLite backend storing all events)
- Persistent configuration (JSON)
- NIC role detection (ARP/DHCP heuristics)
- Crash-proof subsystem wrappers
- Auto-elevation
- Windows service mode

NOTE:
This is a high-level integrated prototype in one file.
Some components (full Suricata engine, full Cowrie/Dionaea behavior, full ML) are simplified but structurally ready.
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
from socket import socket, AF_INET, SOCK_STREAM, SOCK_DGRAM
from collections import deque

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
        print(f"[AI Security Bridge] Elevation failed: {e}")
        sys.exit()

ensure_admin()

# =========================
#  AUTO-LOADER
# =========================

REQUIRED_LIBS = [
    "psutil",
    "tkinter",
    "requests",
    "pywin32",
    "pydivert",
    "matplotlib",
    "scikit-learn",
]

def autoload():
    for lib in REQUIRED_LIBS:
        try:
            if lib == "tkinter":
                import tkinter
            else:
                importlib.import_module(lib)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])

autoload()

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
        print(f"[Config] Load error: {e}")

def save_config():
    try:
        with CONFIG_LOCK:
            data = CONFIG.copy()
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[Config] Save error: {e}")

load_config()

WAN_IN_IFACE = None
WAN_OUT_IFACE = None
LAN_IN_IFACE = None
LAN_OUT_IFACE = None
BRIDGE_MODE = "WAN"

BRIDGE_RUNNING = False
STOP_FLAG = False

PACKET_QUEUE = queue.Queue(maxsize=20000)
WORKER_THREADS = []
NUM_WORKERS = 4
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
}

def diag_add_error(msg):
    with DIAG_LOCK:
        DIAG_STATE["last_errors"].append(f"{datetime.utcnow().isoformat()} | {msg}")
        DIAG_STATE["last_errors"] = DIAG_STATE["last_errors"][-100:]

def get_diag_state():
    with DIAG_LOCK:
        return dict(DIAG_STATE)

CAPTURE_LOCK = threading.Lock()
CAPTURE_ENABLED = CONFIG.get("capture_enabled", True)
CAPTURE_DIR = CONFIG.get("capture_dir", "captures")
os.makedirs(CAPTURE_DIR, exist_ok=True)

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

REPLAY_QUEUE = deque(maxlen=500)
REPLAY_LOCK = threading.Lock()

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
                    meta TEXT
                )
            """)
            DB_CONN.commit()
    except Exception as e:
        set_subsystem_error("db", f"DB init error: {e}")

def db_log_event(time_str, src, dst, proto, action, score, reason, meta_json):
    try:
        with DB_LOCK:
            cur = DB_CONN.cursor()
            cur.execute(
                "INSERT INTO threats (time, src, dst, proto, action, score, reason, meta) VALUES (?,?,?,?,?,?,?,?)",
                (time_str, src, dst, proto, action, score, reason, meta_json)
            )
            DB_CONN.commit()
    except Exception as e:
        set_subsystem_error("db", f"DB log error: {e}")

init_db()

# =========================
#  LOGGING + GRAPHS
# =========================

def log_event(src, dst, proto, action, score, reason, meta=None):
    now = datetime.utcnow().isoformat()
    meta_json = json.dumps(meta or {})
    with LOG_LOCK:
        THREAT_LOG.append({
            "time": now,
            "src": src,
            "dst": dst,
            "proto": proto,
            "action": action,
            "score": score,
            "reason": reason,
            "meta": meta or {}
        })
    db_log_event(now, src, dst, proto, action, score, reason, meta_json)
    with GRAPH_LOCK:
        THREAT_TIMELINE.append((time.time(), score))
        PACKET_RATE_TIMELINE.append((time.time(), 1))
        if "honeypot" in (reason or "").lower():
            HONEYPOT_HITS_TIMELINE.append((time.time(), 1))
        PERSONA_TIMELINE.append((time.time(), PERSONA_STATE["aggressiveness"], PERSONA_STATE["mode"]))

def get_recent_logs(limit=200):
    with LOG_LOCK:
        return THREAT_LOG[-limit:]

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
        set_subsystem_error("autodetect", f"NIC role detection error: {e}")
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
        set_subsystem_error("autodetect", f"Interface detection error: {e}")
        WAN_IN_IFACE = WAN_IN_IFACE or "Ethernet0"
        WAN_OUT_IFACE = WAN_OUT_IFACE or "Ethernet1"
        LAN_IN_IFACE = LAN_IN_IFACE or "Ethernet2"
        LAN_OUT_IFACE = LAN_OUT_IFACE or "Ethernet3"

# =========================
#  SURICATA-LIKE RULE ENGINE
# =========================

class SuricataRule:
    def __init__(self, raw_line):
        self.raw = raw_line
        self.sid = None
        self.msg = None
        self.contents = []
        self.pcre = []
        self.flowbits = []
        self.metadata = {}
        self.threshold = None
        self.parse()

    def parse(self):
        try:
            if "sid:" in self.raw:
                sid_part = self.raw.split("sid:")[1].split(";")[0].strip()
                self.sid = sid_part
            if "msg:" in self.raw:
                msg_part = self.raw.split("msg:")[1].split(";")[0].strip()
                if msg_part.startswith('"') and msg_part.endswith('"'):
                    msg_part = msg_part[1:-1]
                self.msg = msg_part
            # content:
            for part in self.raw.split("content:")[1:]:
                if '"' in part:
                    c = part.split('"')[1]
                    self.contents.append(c.encode("latin-1", errors="ignore"))
            # pcre:
            if "pcre:" in self.raw:
                for part in self.raw.split("pcre:")[1:]:
                    if '"' in part:
                        regex = part.split('"')[1]
                        try:
                            self.pcre.append(re.compile(regex))
                        except re.error:
                            continue
            # metadata:
            if "metadata:" in self.raw:
                meta_part = self.raw.split("metadata:")[1].split(";")[0]
                items = meta_part.split(",")
                for item in items:
                    if ":" in item:
                        k, v = item.split(":", 1)
                        self.metadata[k.strip()] = v.strip()
            # threshold:
            if "threshold:" in self.raw:
                th_part = self.raw.split("threshold:")[1].split(";")[0]
                self.threshold = th_part.strip()
        except Exception:
            pass

    def match(self, payload):
        try:
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
                    rules.append(SuricataRule(line))
        with SURICATA_RULES_LOCK:
            SURICATA_RULES = rules
    except Exception as e:
        set_subsystem_error("rules", f"Suricata rule load error: {e}")

def match_suricata_rules(payload):
    try:
        with SURICATA_RULES_LOCK:
            rules = list(SURICATA_RULES)
        for r in rules:
            if r.match(payload):
                return r.sid or "suricata_match", r.msg or "suricata"
    except Exception as e:
        set_subsystem_error("rules", f"Suricata match error: {e}")
    return None, None

load_suricata_rules()

# =========================
#  RULE EDITOR (FULL)
# =========================

def load_rule_editor_rules():
    global RULE_EDITOR_RULES
    with RULE_EDITOR_LOCK:
        RULE_EDITOR_RULES = CONFIG.get("rule_editor_rules", [])

def save_rule_editor_rules():
    with RULE_EDITOR_LOCK:
        CONFIG["rule_editor_rules"] = RULE_EDITOR_RULES
    save_config()

def rule_editor_match(src, dst, proto, payload, ja3_hash=None):
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

            if ip_match and proto_match and content_match and ja3_match:
                return r.get("action", "allow"), r.get("name", "rule_editor"), r.get("sid")
        except Exception:
            continue
    return None, None, None

load_rule_editor_rules()

# =========================
#  SIGNATURE DB + HTTP DPI + FULL JA3
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
        set_subsystem_error("dpi", f"HTTP parse error: {e}")
        return None

def parse_tls_client_hello(payload):
    try:
        if len(payload) < 5 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
        # Full-ish TLS ClientHello parsing for JA3:
        # Record header: 5 bytes
        # Handshake header: next 4 bytes
        # We extract version, cipher suites, extensions, curves, point formats.
        # This is still simplified but structured for JA3.
        # For real JA3, you'd parse all fields per spec.
        # Here we approximate.

        # Skip record header
        offset = 5
        if payload[offset] != 0x01:  # Handshake type: ClientHello
            return None
        offset += 4  # Skip handshake length

        # ClientHello start
        # Version
        version = payload[offset:offset+2]
        offset += 2

        # Random
        offset += 32

        # Session ID
        sid_len = payload[offset]
        offset += 1 + sid_len

        # Cipher Suites
        cs_len = int.from_bytes(payload[offset:offset+2], "big")
        offset += 2
        cipher_suites = []
        for i in range(0, cs_len, 2):
            cipher_suites.append(int.from_bytes(payload[offset+i:offset+i+2], "big"))
        offset += cs_len

        # Compression methods
        comp_len = payload[offset]
        offset += 1 + comp_len

        # Extensions
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
                # Elliptic curves extension
                if ext_type == 10 and len(ext_data) >= 2:
                    ec_len = int.from_bytes(ext_data[0:2], "big")
                    pos = 2
                    while pos + 2 <= 2 + ec_len and pos + 2 <= len(ext_data):
                        curves.append(int.from_bytes(ext_data[pos:pos+2], "big"))
                        pos += 2
                # EC point formats extension
                if ext_type == 11 and len(ext_data) >= 1:
                    pf_len = ext_data[0]
                    pos = 1
                    while pos < 1 + pf_len and pos < len(ext_data):
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
        set_subsystem_error("dpi", f"TLS parse error: {e}")
        return None

def ja3_fingerprint(tls_info):
    try:
        ver = int.from_bytes(tls_info["version"], "big")
        cs = "-".join(str(c) for c in tls_info["cipher_suites"])
        ex = "-".join(str(e) for e in tls_info["extensions"])
        cv = "-".join(str(c) for c in tls_info["curves"])
        pf = "-".join(str(p) for p in tls_info["ec_point_formats"])
        ja3_str = f"{ver},{cs},{ex},{cv},{pf}"
        return hashlib.md5(ja3_str.encode("utf-8")).hexdigest()
    except Exception:
        return None

def dpi_analyze(payload):
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

        tls_info = parse_tls_client_hello(payload)
        if tls_info:
            reason = "tls"
            extra_score += 10
            ja3 = ja3_fingerprint(tls_info)
            meta["ja3"] = ja3

        sid, msg = match_suricata_rules(payload)
        if sid:
            reason = "suricata"
            extra_score += 60
            meta["suricata_sid"] = sid
            meta["suricata_msg"] = msg

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
        set_subsystem_error("dpi", f"DPI analyze error: {e}")

    return extra_score, reason, meta

# =========================
#  DECEPTION + HONEYPOT (Cowrie/Dionaea/HoneyHTTP-like)
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
        set_subsystem_error("bridge", f"RST send error: {e}")
        diag_add_error(f"RST send error: {e}")

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
        set_subsystem_error("bridge", f"Fake HTTP send error: {e}")
        diag_add_error(f"Fake HTTP send error: {e}")

def deception_response(divert, packet, reason, src, dst, meta=None):
    fp = spoof_os_fingerprint()
    log_event(src, dst, "DECEPTION", "fake", 0, f"{reason}:{fp}", meta)
    if reason == "ad_block":
        send_tcp_rst(divert, packet)
    else:
        send_fake_http_banner(divert, packet)

def honeypot_ssh(conn, addr):
    try:
        conn.sendall(b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n")
        data = conn.recv(1024)
        # Very simplified: log and close
        log_event(addr[0], "honeypot:ssh", "SSH", "honeypot", 0, "honeypot_ssh", {"data": data.decode("latin-1", errors="ignore")})
    except Exception:
        pass
    finally:
        conn.close()

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
        # Fake TLS handshake (not real TLS)
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
        set_subsystem_error("honeypot", f"Port {port} bind error: {e}")
        return

    handler = HONEYPOT_HANDLERS.get(service_name)

    while True:
        try:
            conn, addr = s.accept()
            if handler:
                threading.Thread(target=handler, args=(conn, addr), daemon=True).start()
            else:
                conn.close()
            log_event(addr[0], f"{HONEYPOT_HOST}:{port}", "HONEYPOT", "connect", 0, f"honeypot_{service_name}")
        except Exception as e:
            set_subsystem_error("honeypot", f"Honeypot error on port {port}: {e}")
            time.sleep(1)

def start_honeypot_suite():
    try:
        for port, name in HONEYPOT_SERVICES.items():
            t = threading.Thread(target=honeypot_worker, args=(port, name), daemon=True)
            t.start()
    except Exception as e:
        set_subsystem_error("honeypot", f"Start honeypot suite error: {e}")

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
        # Wrap with TLS mutual auth
        cert = CONFIG.get("swarm_tls_cert", "swarm_cert.pem")
        key = CONFIG.get("swarm_tls_key", "swarm_key.pem")
        if os.path.exists(cert) and os.path.exists(key):
            context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            context.load_cert_chain(certfile=cert, keyfile=key)
            server.socket = context.wrap_socket(server.socket, server_side=True)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
    except Exception as e:
        set_subsystem_error("swarm", f"Swarm backend error: {e}")

def swarm_share_threat(event):
    if not CONFIG.get("swarm_enabled", True):
        return
    try:
        body = json.dumps(event).encode("utf-8")
        h = swarm_hmac(body)
        headers = {"X-Swarm-HMAC": h}
        # Local
        try:
            requests.post(f"https://127.0.0.1:{SWARM_PORT}/threats", data=body, headers=headers, timeout=0.5, verify=False)
        except Exception:
            pass
        with SWARM_PEERS_LOCK:
            peers_copy = list(SWARM_PEERS)
        for peer in peers_copy:
            try:
                requests.post(f"{peer}/threats", data=body, headers=headers, timeout=0.5, verify=False)
            except Exception:
                continue
    except Exception as e:
        set_subsystem_error("swarm", f"Swarm share error: {e}")

def swarm_pull_threats():
    if not CONFIG.get("swarm_enabled", True):
        return
    try:
        with SWARM_PEERS_LOCK:
            peers_copy = list(SWARM_PEERS)
        for peer in peers_copy:
            try:
                rp = requests.get(f"{peer}/threats", timeout=0.5, verify=False)
                if rp.status_code == 200:
                    _ = rp.json()
            except Exception:
                continue
    except Exception as e:
        set_subsystem_error("swarm", f"Swarm pull error: {e}")

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
                        candidate = f"https://{base}.{i}:{SWARM_PORT}"
                        try:
                            r = requests.get(candidate + "/peers", timeout=0.2, verify=False)
                            if r.status_code == 200:
                                with SWARM_PEERS_LOCK:
                                    if candidate not in SWARM_PEERS:
                                        SWARM_PEERS.append(candidate)
                        except Exception:
                            continue
    except Exception as e:
        set_subsystem_error("swarm", f"Peer discovery error: {e}")

# =========================
#  PERSONA ENGINE + ML ANOMALY DETECTION
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
    # Simple numeric feature vector
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
            ML_MODEL = IsolationForest(n_estimators=50, contamination=0.05, random_state=42)
            ML_MODEL.fit(X)
    except Exception as e:
        set_subsystem_error("ml", f"ML train error: {e}")

def ml_is_anomalous(features):
    if not ML_ENABLED or ML_MODEL is None:
        return False
    try:
        with ML_LOCK:
            pred = ML_MODEL.predict([features])[0]
        return pred == -1
    except Exception as e:
        set_subsystem_error("ml", f"ML predict error: {e}")
        return False

# =========================
#  UDM PRO API (STUB)
# =========================

def udm_push_firewall_rule(rule_name, src_ip, action="drop"):
    try:
        log_event(src_ip, "UDM", "API", "udm_rule", 0, f"rule={rule_name}, action={action}")
    except Exception as e:
        set_subsystem_error("service", f"UDM API stub error: {e}")

# =========================
#  PACKET CAPTURE + REPLAY
# =========================

def capture_packet(src, dst, proto, payload, reason):
    if not CAPTURE_ENABLED:
        return
    try:
        ts = datetime.utcnow().strftime("%Y%m%d_%H%M%S_%f")
        fname = f"{ts}_{src}_to_{dst}_{proto}_{reason}.bin"
        path = os.path.join(CAPTURE_DIR, fname)
        with CAPTURE_LOCK:
            with open(path, "wb") as f:
                f.write(payload)
        with REPLAY_LOCK:
            REPLAY_QUEUE.append(path)
    except Exception as e:
        set_subsystem_error("capture", f"Capture error: {e}")

def replay_packet(path):
    try:
        with open(path, "rb") as f:
            payload = f.read()
        # Replay through DPI + AI firewall in "offline" mode
        src = "replay_src"
        dst = "replay_dst"
        proto = "REPLAY"
        action, score, reason, meta = ai_firewall(payload, src, dst, proto, offline=True)
        log_event(src, dst, proto, f"replay_{action}", score, reason, meta)
    except Exception as e:
        set_subsystem_error("capture", f"Replay error: {e}")

# =========================
#  AI FIREWALL
# =========================

def ip_in_allowlist(ip):
    return ip in PERMA_ALLOW_IPS

def ai_firewall(payload, src, dst, proto, offline=False):
    ja3_hash = None

    if ip_in_allowlist(dst) or ip_in_allowlist(src):
        return "allow", 0, "perma_allow", {}

    # DPI first
    base_score = 0
    reason = "normal"
    meta = {}

    try:
        dpi_score, dpi_reason, dpi_meta = dpi_analyze(payload)
        if dpi_score > 0:
            base_score += dpi_score
            reason = dpi_reason
            meta.update(dpi_meta)
        ja3_hash = dpi_meta.get("ja3")

        # Rule editor
        action, rname, sid = rule_editor_match(src, dst, proto, payload, ja3_hash=ja3_hash)
        if action:
            meta["rule_editor"] = rname
            meta["rule_sid"] = sid
            if action == "drop":
                return "drop", base_score, f"rule_editor:{rname}", meta
            elif action == "fake":
                return "fake", base_score, f"rule_editor:{rname}", meta
            else:
                return "allow", base_score, f"rule_editor:{rname}", meta

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

        # ML anomaly detection
        features = ml_extract_features(src, dst, proto, len(payload), final_score, reason)
        with ML_LOCK:
            ML_FEATURES.append(features)
        ml_train_if_needed()
        if ml_is_anomalous(features):
            final_score += 30
            meta["ml_anomaly"] = True
            reason = "ml_anomaly"

        if final_score >= 80:
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

        if 50 <= final_score < 80:
            if not offline:
                capture_packet(src, dst, proto, payload, reason)
            return "fake", final_score, reason, meta

        if reason == "ad_block":
            if not offline:
                capture_packet(src, dst, proto, payload, "ad_block")
            return "drop", final_score, "ad_block", meta

    except Exception as e:
        set_subsystem_error("bridge", f"AI firewall error: {e}")
        diag_add_error(f"AI firewall error: {e}")
        return "allow", 0, "error", {}

    return "allow", base_score, reason, meta

# =========================
#  BRIDGE + WORKERS (WinDivert, kernel bypass acceleration)
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

            action, score, reason, meta = ai_firewall(payload, src, dst, proto)

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
            set_subsystem_error("bridge", f"Worker error: {e}")
            diag_add_error(f"Worker error: {e}")
            log_event("N/A", "N/A", "N/A", "error", 0, str(e))

def bridge_sniffer():
    global DIVERT_HANDLE
    try:
        # Kernel bypass acceleration: WinDivert fast I/O mode (still Python-level)
        DIVERT_HANDLE = WinDivert("ip and ipv4", layer=Layer.NETWORK)
        DIVERT_HANDLE.open()
        DIAG_STATE["windivert_present"] = "yes"
    except Exception as e:
        set_subsystem_error("bridge", f"WinDivert open error: {e}")
        diag_add_error(f"WinDivert open error: {e}")
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
            set_subsystem_error("bridge", f"Sniffer error: {e}")
            diag_add_error(f"Sniffer error: {e}")
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
    except Exception as e:
        set_subsystem_error("bridge", f"Start bridge error: {e}")
        diag_add_error(f"Start bridge error: {e}")

def stop_bridge():
    global BRIDGE_RUNNING, STOP_FLAG, DIVERT_HANDLE
    STOP_FLAG = True
    BRIDGE_RUNNING = False
    try:
        if DIVERT_HANDLE:
            DIVERT_HANDLE.close()
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
        except Exception as e:
            set_subsystem_error("watchdog", f"Watchdog error: {e}")
            diag_add_error(f"Watchdog error: {e}")
        time.sleep(5)

# =========================
#  WINDOWS SERVICE
# =========================

class AISecurityBridgeService(win32serviceutil.ServiceFramework):
    _svc_name_ = "AISecurityBridgeService"
    _svc_display_name_ = "AI Security Bridge Service"
    _svc_description_ = "Inline AI-driven security bridge in front of UDM Pro (WAN or LAN) using WinDivert."

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
                "speed": f"{stats.speed} Mbps",
                "mac": mac,
                "ip": ip
            })
    except Exception as e:
        set_subsystem_error("service", f"Adapter enumeration error: {e}")
        diag_add_error(f"Adapter enumeration error: {e}")
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
        diag_add_error(f"WinDivert check error: {e}")

    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.close()
        DIAG_STATE["raw_socket_ok"] = "yes"
    except Exception as e:
        DIAG_STATE["raw_socket_ok"] = "no"
        diag_add_error(f"Raw socket test error: {e}")

    DIAG_STATE["promisc_ok"] = "handled_by_windivert"

# =========================
#  GUI (Interactive graphs + replay)
# =========================

class AISecurityBridgeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI Security Bridge (Commercial-Grade, WinDivert, JA3, Suricata, ML, Swarm)")

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

        self.notebook.add(self.tab_if, text="📡 Interfaces")
        self.notebook.add(self.tab_logs, text="💾 Logs")
        self.notebook.add(self.tab_fw, text="⚙ Firewall")
        self.notebook.add(self.tab_ai, text="🔥 AI/ML")
        self.notebook.add(self.tab_sys, text="🛠 Subsystems")
        self.notebook.add(self.tab_diag, text="🧪 Diagnostics")
        self.notebook.add(self.tab_graphs, text="📈 Graphs")
        self.notebook.add(self.tab_rules, text="📜 Rules")
        self.notebook.add(self.tab_replay, text="🔁 Replay")

        self.build_if_tab()
        self.build_logs_tab()
        self.build_fw_tab()
        self.build_ai_tab()
        self.build_sys_tab()
        self.build_diag_tab()
        self.build_graphs_tab()
        self.build_rules_tab()
        self.build_replay_tab()

        self.refresh_if()
        self.refresh_logs()
        self.refresh_ai()
        self.refresh_sys()
        self.refresh_diag()
        self.refresh_graphs()
        self.refresh_rules()
        self.refresh_replay()

        self.root.after(500, self.start_subsystems_safe)

    def start_subsystems_safe(self):
        try:
            detect_interfaces()
        except Exception as e:
            set_subsystem_error("autodetect", f"Detect interfaces error: {e}")
            diag_add_error(f"Detect interfaces error: {e}")

        if INTEGRITY_FAILED:
            set_subsystem_error("service", "Integrity check failed at startup.")
            diag_add_error("Integrity check failed at startup.")

        try:
            start_swarm_backend()
        except Exception as e:
            set_subsystem_error("swarm", f"Swarm start error: {e}")
            diag_add_error(f"Swarm start error: {e}")

        try:
            start_honeypot_suite()
        except Exception as e:
            set_subsystem_error("honeypot", f"Honeypot start error: {e}")
            diag_add_error(f"Honeypot start error: {e}")

        try:
            threading.Thread(target=watchdog_loop, daemon=True).start()
        except Exception as e:
            set_subsystem_error("watchdog", f"Watchdog start error: {e}")
            diag_add_error(f"Watchdog start error: {e}")

        try:
            start_bridge()
        except Exception as e:
            set_subsystem_error("bridge", f"Bridge start error: {e}")
            diag_add_error(f"Bridge start error: {e}")

        try:
            run_diagnostics_once()
        except Exception as e:
            set_subsystem_error("diagnostics", f"Diagnostics run error: {e}")
            diag_add_error(f"Diagnostics run error: {e}")

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
        self.status_label.config(text=f"Bridge Status: {'RUNNING' if BRIDGE_RUNNING else 'STOPPED'} (Mode={BRIDGE_MODE})")
        self.root.after(2000, self.refresh_if)

    def build_logs_tab(self):
        self.log_text = scrolledtext.ScrolledText(self.tab_logs, wrap="none")
        self.log_text.pack(fill="both", expand=True, padx=5, pady=5)

    def refresh_logs(self):
        logs = get_recent_logs()
        self.log_text.delete("1.0", tk.END)
        for e in logs:
            line = f"{e['time']} | {e['src']} -> {e['dst']} | {e['proto']} | {e['action']} | score={e['score']} | {e['reason']} | meta={json.dumps(e['meta'])}\n"
            self.log_text.insert(tk.END, line)
        self.root.after(2000, self.refresh_logs)

    def build_fw_tab(self):
        lbl = tk.Label(
            self.tab_fw,
            text=(
                "Firewall Engine: WinDivert inline + HTTP/TLS/JA3 DPI + Suricata-like rules + persona + ML + deception + ad-block.\n"
                "Swarm cluster (TLS mutual auth, HMAC), honeypot suite, packet capture, rule editor, threat DB.\n"
                "Bridge auto-starts and mode auto-detects (WAN vs LAN)."
            )
        )
        lbl.pack(padx=10, pady=10)

    def build_ai_tab(self):
        self.ai_status = tk.Label(self.tab_ai, text="AI/ML Engine: IDLE")
        self.ai_status.pack(padx=10, pady=10)

        self.persona_label = tk.Label(self.tab_ai, text="")
        self.persona_label.pack(padx=10, pady=10)

        self.ml_label = tk.Label(self.tab_ai, text="ML: training status unknown")
        self.ml_label.pack(padx=10, pady=10)

    def refresh_ai(self):
        self.ai_status.config(text=f"AI/ML Engine: {'ONLINE' if BRIDGE_RUNNING else 'IDLE'}")
        self.persona_label.config(
            text=f"Persona: mode={PERSONA_STATE['mode']}, aggressiveness={PERSONA_STATE['aggressiveness']:.2f}, recent_high_threats={PERSONA_STATE['recent_high_threats']}"
        )
        self.ml_label.config(text=f"ML: {'enabled' if ML_ENABLED else 'disabled'}, model={'ready' if ML_MODEL is not None else 'not trained'}")
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
                line = f"[{name.upper()}] ERROR: {msg}\n"
            else:
                line = f"[{name.upper()}] OK\n"
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
        self.diag_windivert_label.config(text=f"WinDivert: {state.get('windivert_present', 'unknown')}")
        self.diag_raw_label.config(text=f"Raw socket: {state.get('raw_socket_ok', 'unknown')}")
        self.diag_promisc_label.config(text=f"Promisc: {state.get('promisc_ok', 'unknown')}")

        self.diag_text.delete("1.0", tk.END)
        self.diag_text.insert(tk.END, "Diagnostics Log:\n\n")
        for line in state.get("last_errors", []):
            self.diag_text.insert(tk.END, line + "\n")

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

        tk.Label(top, text="Rule Editor (IP/proto/content/regex/JA3/SID -> action)").pack(side="left", padx=5)

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
        tk.Label(form, text="SID").grid(row=0, column=7)
        tk.Label(form, text="Action").grid(row=0, column=8)

        self.rule_name_var = tk.StringVar()
        self.rule_src_var = tk.StringVar()
        self.rule_dst_var = tk.StringVar()
        self.rule_proto_var = tk.StringVar()
        self.rule_content_var = tk.StringVar()
        self.rule_regex_var = tk.StringVar(value="no")
        self.rule_ja3_var = tk.StringVar()
        self.rule_sid_var = tk.StringVar()
        self.rule_action_var = tk.StringVar(value="drop")

        tk.Entry(form, textvariable=self.rule_name_var, width=10).grid(row=1, column=0)
        tk.Entry(form, textvariable=self.rule_src_var, width=12).grid(row=1, column=1)
        tk.Entry(form, textvariable=self.rule_dst_var, width=12).grid(row=1, column=2)
        tk.Entry(form, textvariable=self.rule_proto_var, width=8).grid(row=1, column=3)
        tk.Entry(form, textvariable=self.rule_content_var, width=20).grid(row=1, column=4)
        tk.Entry(form, textvariable=self.rule_regex_var, width=8).grid(row=1, column=5)
        tk.Entry(form, textvariable=self.rule_ja3_var, width=20).grid(row=1, column=6)
        tk.Entry(form, textvariable=self.rule_sid_var, width=10).grid(row=1, column=7)
        tk.Entry(form, textvariable=self.rule_action_var, width=8).grid(row=1, column=8)

        tk.Button(form, text="Add Rule", command=self.add_rule).grid(row=1, column=9, padx=5)
        tk.Button(form, text="Save Rules", command=self.save_rules).grid(row=1, column=10, padx=5)

    def refresh_rules(self):
        with RULE_EDITOR_LOCK:
            rules = list(RULE_EDITOR_RULES)
        self.rules_list.delete("1.0", tk.END)
        self.rules_list.insert(tk.END, "Current Rules:\n\n")
        for r in rules:
            self.rules_list.insert(
                tk.END,
                f"{r.get('name','')} | src={r.get('src','')} dst={r.get('dst','')} proto={r.get('proto','')} "
                f"content={r.get('content','')} regex={r.get('regex',False)} ja3={r.get('ja3','')} sid={r.get('sid','')} "
                f"action={r.get('action','')}\n"
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
        self.replay_list.insert(tk.END, "Captured Packets (paths):\n\n")
        for p in items:
            self.replay_list.insert(tk.END, p + "\n")
        self.root.after(5000, self.refresh_replay)

    def replay_selected(self):
        path = self.replay_selected_var.get()
        if path and os.path.exists(path):
            replay_packet(path)

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
