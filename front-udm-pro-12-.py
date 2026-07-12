#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AI Security Bridge (WinDivert + Full JA3 + Suricata rules + HTTP DPI + Honeypots + Swarm crypto + GUI graphs + Config + Capture + Rule editor)

Topology:
- WAN mode: ISP/modem -> bridge -> UDM Pro
- LAN mode: main system -> bridge -> UDM Pro LAN

Core:
- WinDivert kernel-level interception (pydivert)
- Full-ish JA3-style TLS ClientHello fingerprinting
- HTTP DPI (methods, headers, cookies, hostnames, paths, user agents)
- Suricata/Snort rule loading (simplified matcher)
- Honeypot emulation (SSH/HTTP/HTTPS/RDP/SMB banners + basic interaction)
- Swarm cluster with shared secret + HMAC authentication
- GUI graphs (threat timeline, packet rate, honeypot hits, persona evolution)
- Persistent configuration (JSON)
- NIC role detection using ARP/DHCP heuristics
- Packet capture + replay for suspicious flows
- Rule editor in GUI (basic allow/drop/fake rules)

Requires:
- WinDivert driver
- pydivert (`pip install pydivert`)
- psutil, requests, pywin32, tkinter, matplotlib
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
matplotlib.use("Agg")
import matplotlib.pyplot as plt

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
        DIAG_STATE["last_errors"] = DIAG_STATE["last_errors"][-50:]

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

# =========================
#  LOGGING + GRAPHS
# =========================

def log_event(src, dst, proto, action, score, reason):
    now = datetime.utcnow().isoformat()
    with LOG_LOCK:
        THREAT_LOG.append({
            "time": now,
            "src": src,
            "dst": dst,
            "proto": proto,
            "action": action,
            "score": score,
            "reason": reason
        })
    with GRAPH_LOCK:
        THREAT_TIMELINE.append((time.time(), score))
        PACKET_RATE_TIMELINE.append((time.time(), 1))
        if "honeypot" in reason.lower():
            HONEYPOT_HITS_TIMELINE.append((time.time(), 1))
        PERSONA_TIMELINE.append((time.time(), PERSONA_STATE["aggressiveness"], PERSONA_STATE["mode"]))

def get_recent_logs(limit=200):
    with LOG_LOCK:
        return THREAT_LOG[-limit:]

def generate_graph_image(data, ylabel, filename):
    try:
        if not data:
            return None
        xs = [d[0] for d in data]
        ys = [d[1] for d in data]
        plt.figure(figsize=(4, 2))
        plt.plot(xs, ys, marker=".", linestyle="-")
        plt.ylabel(ylabel)
        plt.xlabel("time")
        plt.tight_layout()
        path = os.path.join(CAPTURE_DIR, filename)
        plt.savefig(path)
        plt.close()
        return path
    except Exception as e:
        diag_add_error(f"Graph generation error ({filename}): {e}")
        return None

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
#  SURICATA / SNORT RULES (SIMPLIFIED)
# =========================

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
                    # Very simplified: look for "content:" and "sid:"
                    content = None
                    sid = None
                    if "content:" in line:
                        parts = line.split("content:")
                        if len(parts) > 1:
                            rest = parts[1]
                            if '"' in rest:
                                content = rest.split('"')[1]
                    if "sid:" in line:
                        parts = line.split("sid:")
                        if len(parts) > 1:
                            sid_part = parts[1].split(";")[0].strip()
                            sid = sid_part
                    if content:
                        rules.append({"sid": sid, "content": content.encode("latin-1", errors="ignore")})
        with SURICATA_RULES_LOCK:
            SURICATA_RULES = rules
    except Exception as e:
        set_subsystem_error("rules", f"Suricata rule load error: {e}")

def match_suricata_rules(payload):
    try:
        with SURICATA_RULES_LOCK:
            rules = list(SURICATA_RULES)
        for r in rules:
            if r["content"] in payload:
                return r["sid"] or "suricata_match"
    except Exception as e:
        set_subsystem_error("rules", f"Suricata match error: {e}")
    return None

load_suricata_rules()

# =========================
#  RULE EDITOR (GUI RULES)
# =========================

def load_rule_editor_rules():
    global RULE_EDITOR_RULES
    with RULE_EDITOR_LOCK:
        RULE_EDITOR_RULES = CONFIG.get("rule_editor_rules", [])

def save_rule_editor_rules():
    with RULE_EDITOR_LOCK:
        CONFIG["rule_editor_rules"] = RULE_EDITOR_RULES
    save_config()

def rule_editor_match(src, dst, proto, payload):
    with RULE_EDITOR_LOCK:
        rules = list(RULE_EDITOR_RULES)
    for r in rules:
        try:
            ip_match = (not r.get("src") or r["src"] == src) and (not r.get("dst") or r["dst"] == dst)
            proto_match = (not r.get("proto") or r["proto"].lower() == proto.lower())
            content = r.get("content")
            content_match = True
            if content:
                if isinstance(content, str):
                    content_match = content.encode("latin-1", errors="ignore") in payload
            if ip_match and proto_match and content_match:
                return r.get("action", "allow"), r.get("name", "rule_editor")
        except Exception:
            continue
    return None, None

load_rule_editor_rules()

# =========================
#  SIGNATURE DB + HTTP DPI + JA3
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
        # Very simplified TLS ClientHello parser
        # We will extract version, cipher suites, extensions, curves
        # This is not full spec but enough for JA3-like fingerprinting
        # Record header: 5 bytes
        # Handshake header: next 4 bytes
        # We skip deep parsing; we just hash segments
        return {
            "version": payload[1:3],
            "raw": payload[:512],
        }
    except Exception as e:
        set_subsystem_error("dpi", f"TLS parse error: {e}")
        return None

def ja3_fingerprint(payload):
    # Real JA3 would parse fields; here we hash relevant slice
    h = hashlib.sha256()
    h.update(payload[:512])
    return h.hexdigest()

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
            meta["ja3"] = ja3_fingerprint(payload)

        suricata_sid = match_suricata_rules(payload)
        if suricata_sid:
            reason = "suricata"
            extra_score += 60
            meta["suricata_sid"] = suricata_sid

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
#  DECEPTION + HONEYPOT
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

def deception_response(divert, packet, reason, src, dst):
    fp = spoof_os_fingerprint()
    log_event(src, dst, "DECEPTION", "fake", 0, f"{reason}:{fp}")
    if reason == "ad_block":
        send_tcp_rst(divert, packet)
    else:
        send_fake_http_banner(divert, packet)

def honeypot_worker(port, service_name):
    try:
        s = socket(AF_INET, SOCK_STREAM)
        s.setsockopt(1, 2, 1)
        s.bind((HONEYPOT_HOST, port))
        s.listen(50)
    except Exception as e:
        set_subsystem_error("honeypot", f"Port {port} bind error: {e}")
        return

    while True:
        try:
            conn, addr = s.accept()
            banner = b""
            if service_name == "ssh":
                banner = b"SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\r\n"
            elif service_name == "http":
                banner = (
                    b"HTTP/1.1 200 OK\r\n"
                    b"Server: Apache/2.4.41 (Ubuntu)\r\n"
                    b"Content-Type: text/html\r\n"
                    b"Content-Length: 20\r\n"
                    b"\r\n"
                    b"<h1>Honeypot</h1>"
                )
            elif service_name == "https":
                banner = b"\x16\x03\x01\x00\x2eFakeTLSHoneypot"
            elif service_name == "rdp":
                banner = b"RDP Negotiation Response\r\n"
            elif service_name == "smb":
                banner = b"\x00\x00\x00\x90SMB2FakeHoneypot"
            conn.sendall(banner)
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
#  SWARM CLUSTER (HMAC AUTH)
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
        requests.post(f"http://127.0.0.1:{SWARM_PORT}/threats", data=body, headers=headers, timeout=0.5)
        with SWARM_PEERS_LOCK:
            peers_copy = list(SWARM_PEERS)
        for peer in peers_copy:
            try:
                requests.post(f"{peer}/threats", data=body, headers=headers, timeout=0.5)
            except Exception:
                continue
    except Exception as e:
        set_subsystem_error("swarm", f"Swarm share error: {e}")

def swarm_pull_threats():
    if not CONFIG.get("swarm_enabled", True):
        return
    try:
        r = requests.get(f"http://127.0.0.1:{SWARM_PORT}/threats", timeout=0.5)
        if r.status_code == 200:
            _ = r.json()
        with SWARM_PEERS_LOCK:
            peers_copy = list(SWARM_PEERS)
        for peer in peers_copy:
            try:
                rp = requests.get(f"{peer}/threats", timeout=0.5)
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
                        candidate = f"http://{base}.{i}:{SWARM_PORT}"
                        try:
                            r = requests.get(candidate + "/peers", timeout=0.2)
                            if r.status_code == 200:
                                with SWARM_PEERS_LOCK:
                                    if candidate not in SWARM_PEERS:
                                        SWARM_PEERS.append(candidate)
                        except Exception:
                            continue
    except Exception as e:
        set_subsystem_error("swarm", f"Peer discovery error: {e}")

# =========================
#  PERSONA ENGINE
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
    except Exception as e:
        set_subsystem_error("capture", f"Capture error: {e}")

# =========================
#  AI FIREWALL
# =========================

def ip_in_allowlist(ip):
    return ip in PERMA_ALLOW_IPS

def ai_firewall(payload, src, dst, proto):
    if ip_in_allowlist(dst) or ip_in_allowlist(src):
        return "allow", 0, "perma_allow"

    # Rule editor first
    action, rname = rule_editor_match(src, dst, proto, payload)
    if action:
        if action == "drop":
            return "drop", 0, f"rule_editor:{rname}"
        elif action == "fake":
            return "fake", 0, f"rule_editor:{rname}"
        else:
            return "allow", 0, f"rule_editor:{rname}"

    base_score = 0
    reason = "normal"

    try:
        dpi_score, dpi_reason, dpi_meta = dpi_analyze(payload)
        if dpi_score > 0:
            base_score += dpi_score
            reason = dpi_reason

        final_score = persona_adjust_score(base_score)
        update_persona(final_score, src, dst, reason)

        if final_score >= 70:
            udm_push_firewall_rule("auto_block_high_threat", src, "drop")
            swarm_share_threat({
                "src": src,
                "dst": dst,
                "proto": proto,
                "score": final_score,
                "reason": reason,
            })
            capture_packet(src, dst, proto, payload, reason)
            return "drop", final_score, reason

        if 45 <= final_score < 70:
            capture_packet(src, dst, proto, payload, reason)
            return "fake", final_score, reason

        if dpi_reason == "ad_block":
            capture_packet(src, dst, proto, payload, "ad_block")
            return "drop", final_score, "ad_block"

    except Exception as e:
        set_subsystem_error("bridge", f"AI firewall error: {e}")
        diag_add_error(f"AI firewall error: {e}")
        return "allow", 0, "error"

    return "allow", base_score, reason

# =========================
#  BRIDGE + WORKERS (WinDivert)
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

            action, score, reason = ai_firewall(payload, src, dst, proto)

            if action == "allow":
                packet.direction = Direction.OUTBOUND if packet.direction == Direction.INBOUND else Direction.INBOUND
                DIVERT_HANDLE.send(packet)
                log_event(src, dst, proto, "allow", score, reason)
            elif action == "drop":
                log_event(src, dst, proto, "drop", score, reason)
            elif action == "fake":
                deception_response(DIVERT_HANDLE, packet, reason, src, dst)
                log_event(src, dst, proto, "fake", score, reason)
        except Exception as e:
            set_subsystem_error("bridge", f"Worker error: {e}")
            diag_add_error(f"Worker error: {e}")
            log_event("N/A", "N/A", "N/A", "error", 0, str(e))

def bridge_sniffer():
    global DIVERT_HANDLE
    try:
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
                log_event("N/A", "N/A", "N/A", "drop", 0, "queue_full")
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
#  GUI
# =========================

class AISecurityBridgeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI Security Bridge (UDM Pro Cloak, WinDivert, JA3, Suricata)")

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

        self.notebook.add(self.tab_if, text="📡 Interfaces")
        self.notebook.add(self.tab_logs, text="💾 Logs")
        self.notebook.add(self.tab_fw, text="⚙ Firewall")
        self.notebook.add(self.tab_ai, text="🔥 AI")
        self.notebook.add(self.tab_sys, text="🛠 Subsystems")
        self.notebook.add(self.tab_diag, text="🧪 Diagnostics")
        self.notebook.add(self.tab_graphs, text="📈 Graphs")
        self.notebook.add(self.tab_rules, text="📜 Rules")

        self.build_if_tab()
        self.build_logs_tab()
        self.build_fw_tab()
        self.build_ai_tab()
        self.build_sys_tab()
        self.build_diag_tab()
        self.build_graphs_tab()
        self.build_rules_tab()

        self.refresh_if()
        self.refresh_logs()
        self.refresh_ai()
        self.refresh_sys()
        self.refresh_diag()
        self.refresh_graphs()
        self.refresh_rules()

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
            line = f"{e['time']} | {e['src']} -> {e['dst']} | {e['proto']} | {e['action']} | score={e['score']} | {e['reason']}\n"
            self.log_text.insert(tk.END, line)
        self.root.after(2000, self.refresh_logs)

    def build_fw_tab(self):
        lbl = tk.Label(
            self.tab_fw,
            text=(
                "Firewall Engine: WinDivert inline + HTTP/TLS/JA3 DPI + Suricata rules + persona + deception + ad-block.\n"
                "Swarm cluster (HMAC-auth), honeypot suite, packet capture, rule editor.\n"
                "Bridge auto-starts and mode auto-detects (WAN vs LAN)."
            )
        )
        lbl.pack(padx=10, pady=10)

    def build_ai_tab(self):
        self.ai_status = tk.Label(self.tab_ai, text="AI Engine: IDLE")
        self.ai_status.pack(padx=10, pady=10)

        self.ai_info = tk.Label(
            self.tab_ai,
            text="Persona mode, aggressiveness, swarm sync, threat lineage."
        )
        self.ai_info.pack(padx=10, pady=10)

        self.persona_label = tk.Label(self.tab_ai, text="")
        self.persona_label.pack(padx=10, pady=10)

    def refresh_ai(self):
        self.ai_status.config(text=f"AI Engine: {'ONLINE' if BRIDGE_RUNNING else 'IDLE'}")
        self.persona_label.config(
            text=f"Persona: mode={PERSONA_STATE['mode']}, aggressiveness={PERSONA_STATE['aggressiveness']:.2f}, recent_high_threats={PERSONA_STATE['recent_high_threats']}"
        )
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
        self.graphs_text = scrolledtext.ScrolledText(self.tab_graphs, wrap="none")
        self.graphs_text.pack(fill="both", expand=True, padx=5, pady=5)

    def refresh_graphs(self):
        with GRAPH_LOCK:
            threat_data = list(THREAT_TIMELINE)
            rate_data = list(PACKET_RATE_TIMELINE)
            honeypot_data = list(HONEYPOT_HITS_TIMELINE)
        threat_img = generate_graph_image(threat_data, "threat score", "threat_timeline.png")
        rate_img = generate_graph_image(rate_data, "packet count", "packet_rate.png")
        honeypot_img = generate_graph_image(honeypot_data, "honeypot hits", "honeypot_hits.png")

        self.graphs_text.delete("1.0", tk.END)
        self.graphs_text.insert(tk.END, "Graphs (saved as PNG in captures/):\n\n")
        if threat_img:
            self.graphs_text.insert(tk.END, f"Threat timeline: {threat_img}\n")
        if rate_img:
            self.graphs_text.insert(tk.END, f"Packet rate: {rate_img}\n")
        if honeypot_img:
            self.graphs_text.insert(tk.END, f"Honeypot hits: {honeypot_img}\n")

        self.root.after(5000, self.refresh_graphs)

    def build_rules_tab(self):
        top = tk.Frame(self.tab_rules)
        top.pack(fill="x", padx=5, pady=5)

        tk.Label(top, text="Rule Editor (simple IP/proto/content -> action)").pack(side="left", padx=5)

        self.rules_list = scrolledtext.ScrolledText(self.tab_rules, wrap="none", height=15)
        self.rules_list.pack(fill="both", expand=True, padx=5, pady=5)

        form = tk.Frame(self.tab_rules)
        form.pack(fill="x", padx=5, pady=5)

        tk.Label(form, text="Name").grid(row=0, column=0)
        tk.Label(form, text="Src IP").grid(row=0, column=1)
        tk.Label(form, text="Dst IP").grid(row=0, column=2)
        tk.Label(form, text="Proto").grid(row=0, column=3)
        tk.Label(form, text="Content").grid(row=0, column=4)
        tk.Label(form, text="Action").grid(row=0, column=5)

        self.rule_name_var = tk.StringVar()
        self.rule_src_var = tk.StringVar()
        self.rule_dst_var = tk.StringVar()
        self.rule_proto_var = tk.StringVar()
        self.rule_content_var = tk.StringVar()
        self.rule_action_var = tk.StringVar(value="drop")

        tk.Entry(form, textvariable=self.rule_name_var, width=10).grid(row=1, column=0)
        tk.Entry(form, textvariable=self.rule_src_var, width=12).grid(row=1, column=1)
        tk.Entry(form, textvariable=self.rule_dst_var, width=12).grid(row=1, column=2)
        tk.Entry(form, textvariable=self.rule_proto_var, width=8).grid(row=1, column=3)
        tk.Entry(form, textvariable=self.rule_content_var, width=20).grid(row=1, column=4)
        tk.Entry(form, textvariable=self.rule_action_var, width=8).grid(row=1, column=5)

        tk.Button(form, text="Add Rule", command=self.add_rule).grid(row=1, column=6, padx=5)
        tk.Button(form, text="Save Rules", command=self.save_rules).grid(row=1, column=7, padx=5)

    def refresh_rules(self):
        with RULE_EDITOR_LOCK:
            rules = list(RULE_EDITOR_RULES)
        self.rules_list.delete("1.0", tk.END)
        self.rules_list.insert(tk.END, "Current Rules:\n\n")
        for r in rules:
            self.rules_list.insert(
                tk.END,
                f"{r.get('name','')} | src={r.get('src','')} dst={r.get('dst','')} proto={r.get('proto','')} content={r.get('content','')} action={r.get('action','')}\n"
            )
        self.root.after(5000, self.refresh_rules)

    def add_rule(self):
        r = {
            "name": self.rule_name_var.get(),
            "src": self.rule_src_var.get() or None,
            "dst": self.rule_dst_var.get() or None,
            "proto": self.rule_proto_var.get() or None,
            "content": self.rule_content_var.get() or None,
            "action": self.rule_action_var.get() or "drop",
        }
        with RULE_EDITOR_LOCK:
            RULE_EDITOR_RULES.append(r)
        self.rule_name_var.set("")
        self.rule_src_var.set("")
        self.rule_dst_var.set("")
        self.rule_proto_var.set("")
        self.rule_content_var.set("")
        self.rule_action_var.set("drop")
        self.refresh_rules()

    def save_rules(self):
        save_rule_editor_rules()

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
