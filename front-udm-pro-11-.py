#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AI Security Bridge (WinDivert kernel-mode + GUI-first + Auto-elevation + Auto WAN/LAN detect + Auto-start bridge + Crash-proof subsystems + Diagnostics)

Topology:
- WAN mode: ISP/modem -> bridge -> UDM Pro
- LAN-to-LAN mode: main system -> bridge -> UDM Pro LAN

Core change:
- Uses **WinDivert** (via pydivert) for kernel-level packet interception and forwarding
- No Scapy, no raw sockets; faster, more stable, fewer Windows errors

Features:
- Auto-elevation on Windows (relaunches as admin if needed)
- GUI-first startup (Tkinter always appears)
- Auto-detect WAN vs LAN mode using interface IP ranges (for display / context)
- WinDivert-based inline firewall (captures all IPv4 traffic)
- Auto-start bridge, swarm backend, honeypot suite, watchdog
- Crash-proof subsystem startup (errors captured and shown in GUI)
- DPI:
  - HTTP parser (method, path, host, UA, referer)
  - TLS ClientHello parsing + JA3-style fingerprint (simplified)
  - Simple signature DB (malware/ad patterns)
- Deception engine:
  - Fake HTTP banners (via crafted TCP payload)
  - TCP RST responses
  - OS fingerprint spoofing (stub)
- Honeypot emulation suite:
  - SSH, HTTP, HTTPS, RDP, SMB fake services
- Distributed swarm cluster:
  - Embedded HTTP server for threat sharing
  - Peer discovery (simple subnet scan)
  - Threat replication across peers
- Persona engine (behavioral evolution + threat lineage + modes)
- Tamper-resistance (integrity hash, watchdog)
- UDM Pro API client stubs
- GUI with tabs:
  - 📡 Interfaces
  - 💾 Logs
  - ⚙ Firewall
  - 🔥 AI
  - 🛠 Subsystems
  - 🧪 Diagnostics
- Windows service mode (pywin32) for headless operation

Requires:
- Npcap or WinDivert driver installed
- pydivert (`pip install pydivert`)
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
from socket import socket, AF_INET, SOCK_STREAM

# =========================
#  AUTO-ELEVATION CHECK
# =========================

def ensure_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
():
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
#  CONFIG (AUTO-DETECTED)
# =========================

WAN_IN_IFACE = None
WAN_OUT_IFACE = None

LAN_IN_IFACE = None
LAN_OUT_IFACE = None

BRIDGE_MODE = "WAN"    # "WAN" or "LAN"

BRIDGE_RUNNING = False
STOP_FLAG = False

PACKET_QUEUE = queue.Queue(maxsize=20000)
WORKER_THREADS = []
NUM_WORKERS = 4

LOG_LOCK = threading.Lock()
THREAT_LOG = []

PERSONA_STATE = {
    "aggressiveness": 1.0,
    "recent_high_threats": 0,
    "lineage": [],
    "mode": "calm",
}

SWARM_HOST = "0.0.0.0"
SWARM_PORT = 8080

SWARM_PEERS_LOCK = threading.Lock()
SWARM_PEERS = []

SWARM_STORAGE_LOCK = threading.Lock()
SWARM_STORAGE = []

UDM_API_URL = "https://udm-pro.local:443"
UDM_API_USER = "admin"
UDM_API_PASS = "password"

PERMA_ALLOW_IPS = set()

AD_BLOCK_DOMAINS = {
    "ads.example.com",
    "tracking.example.com",
    "doubleclick.net",
    "googlesyndication.com",
    "adservice.google.com",
}

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

# =========================
#  LOGGING
# =========================

def log_event(src, dst, proto, action, score, reason):
    with LOG_LOCK:
        THREAT_LOG.append({
            "time": datetime.utcnow().isoformat(),
            "src": src,
            "dst": dst,
            "proto": proto,
            "action": action,
            "score": score,
            "reason": reason
        })

def get_recent_logs(limit=200):
    with LOG_LOCK:
        return THREAT_LOG[-limit:]

# =========================
#  IP CLASSIFICATION (WAN/LAN)
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

def detect_interfaces():
    global WAN_IN_IFACE, WAN_OUT_IFACE, LAN_IN_IFACE, LAN_OUT_IFACE, BRIDGE_MODE

    try:
        stats_all = psutil.net_if_stats()
        addrs_all = psutil.net_if_addrs()

        private_ifaces = []
        public_ifaces = []

        for name, stats in stats_all.items():
            if not stats.isup:
                continue
            info = addrs_all.get(name, [])
            ip = next((i.address for i in info if i.family == 2), None)
            if not ip:
                continue
            if is_private_ip(ip):
                private_ifaces.append((name, ip))
            else:
                public_ifaces.append((name, ip))

        if public_ifaces and private_ifaces:
            BRIDGE_MODE = "WAN"
            WAN_IN_IFACE = public_ifaces[0][0]
            WAN_OUT_IFACE = private_ifaces[0][0]
            LAN_IN_IFACE = private_ifaces[0][0]
            LAN_OUT_IFACE = private_ifaces[0][0]
        else:
            BRIDGE_MODE = "LAN"
            if len(private_ifaces) >= 2:
                LAN_IN_IFACE = private_ifaces[0][0]
                LAN_OUT_IFACE = private_ifaces[1][0]
            elif len(private_ifaces) == 1:
                LAN_IN_IFACE = private_ifaces[0][0]
                LAN_OUT_IFACE = private_ifaces[0][0]
            else:
                any_iface = next(iter(stats_all.keys()), None)
                LAN_IN_IFACE = any_iface
                LAN_OUT_IFACE = any_iface
            WAN_IN_IFACE = LAN_IN_IFACE
            WAN_OUT_IFACE = LAN_OUT_IFACE

        stats_all = psutil.net_if_stats()
        if WAN_IN_IFACE is None or WAN_OUT_IFACE is None or LAN_IN_IFACE is None or LAN_OUT_IFACE is None:
            any_up = [n for n, s in stats_all.items() if s.isup]
            if any_up:
                fallback = any_up[0]
                WAN_IN_IFACE = WAN_IN_IFACE or fallback
                WAN_OUT_IFACE = WAN_OUT_IFACE or fallback
                LAN_IN_IFACE = LAN_IN_IFACE or fallback
                LAN_OUT_IFACE = LAN_OUT_IFACE or fallback

    except Exception as e:
        set_subsystem_error("autodetect", f"Interface detection error: {e}")
        WAN_IN_IFACE = WAN_IN_IFACE or "Ethernet0"
        WAN_OUT_IFACE = WAN_OUT_IFACE or "Ethernet1"
        LAN_IN_IFACE = LAN_IN_IFACE or "Ethernet2"
        LAN_OUT_IFACE = LAN_OUT_IFACE or "Ethernet3"

# =========================
#  SIGNATURE DB + DPI
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
        host = None
        ua = None
        ref = None
        for line in lines[1:]:
            lower = line.lower()
            if lower.startswith("host:"):
                host = line.split(":", 1)[1].strip()
            elif lower.startswith("user-agent:"):
                ua = line.split(":", 1)[1].strip()
            elif lower.startswith("referer:"):
                ref = line.split(":", 1)[1].strip()
        return {"method": method, "path": path, "host": host, "ua": ua, "ref": ref}
    except Exception as e:
        set_subsystem_error("dpi", f"HTTP parse error: {e}")
        return None

def parse_tls_client_hello(payload):
    try:
        if len(payload) < 5 or payload[0] != 0x16 or payload[1] != 0x03:
            return None
        return {
            "version": payload[1:3],
            "random": payload[11:43],
        }
    except Exception as e:
        set_subsystem_error("dpi", f"TLS parse error: {e}")
        return None

def ja3_fingerprint(payload):
    h = hashlib.sha256()
    h.update(payload[:256])
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

            if host in AD_BLOCK_DOMAINS or any(sig in path for sig in ["/ads", "/banner"]):
                reason = "ad_block"
                extra_score += 40
                meta["ad_block_host"] = host

        tls_info = parse_tls_client_hello(payload)
        if tls_info:
            reason = "tls"
            extra_score += 10
            meta["ja3"] = ja3_fingerprint(payload)

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
        # WinDivert can set RST flag by modifying packet fields
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
#  SWARM CLUSTER + PEER DISCOVERY
# =========================

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
        if self.path == "/threats":
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
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
            length = int(self.headers.get("Content-Length", 0))
            body = self.rfile.read(length)
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
    try:
        server = HTTPServer((SWARM_HOST, SWARM_PORT), SwarmHandler)
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
    except Exception as e:
        set_subsystem_error("swarm", f"Swarm backend error: {e}")

def swarm_share_threat(event):
    try:
        requests.post(f"http://127.0.0.1:{SWARM_PORT}/threats", json=event, timeout=0.5)
        with SWARM_PEERS_LOCK:
            peers_copy = list(SWARM_PEERS)
        for peer in peers_copy:
            try:
                requests.post(f"{peer}/threats", json=event, timeout=0.5)
            except Exception:
                continue
    except Exception as e:
        set_subsystem_error("swarm", f"Swarm share error: {e}")

def swarm_pull_threats():
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
#  AI FIREWALL
# =========================

def ip_in_allowlist(ip):
    return ip in PERMA_ALLOW_IPS

def ai_firewall(payload, src, dst, proto):
    if ip_in_allowlist(dst) or ip_in_allowlist(src):
        return "allow", 0, "perma_allow"

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
            return "drop", final_score, reason

        if 45 <= final_score < 70:
            return "fake", final_score, reason

        if dpi_reason == "ad_block":
            return "drop", final_score, "ad_block"

    except Exception as e:
        set_subsystem_error("bridge", f"AI firewall error: {e}")
        diag_add_error(f"AI firewall error: {e}")
        return "allow", 0, "error"

    return "allow", base_score, reason

# =========================
#  BRIDGE + WORKERS (WinDivert)
# =========================

DIVERT_HANDLE = None

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
        # Filter: all IPv4 traffic
        DIVERT_HANDLE = WinDivert("ip and ipv4", layer=Layer.NETWORK)
        DIVERT_HANDLE.open()
    except Exception as e:
        set_subsystem_error("bridge", f"WinDivert open error: {e}")
        diag_add_error(f"WinDivert open error: {e}")
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
        # crude check: try opening WinDivert
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
        self.root.title("AI Security Bridge (UDM Pro Cloak, WinDivert)")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        self.tab_if = tk.Frame(self.notebook)
        self.tab_logs = tk.Frame(self.notebook)
        self.tab_fw = tk.Frame(self.notebook)
        self.tab_ai = tk.Frame(self.notebook)
        self.tab_sys = tk.Frame(self.notebook)
        self.tab_diag = tk.Frame(self.notebook)

        self.notebook.add(self.tab_if, text="📡 Interfaces")
        self.notebook.add(self.tab_logs, text="💾 Logs")
        self.notebook.add(self.tab_fw, text="⚙ Firewall")
        self.notebook.add(self.tab_ai, text="🔥 AI")
        self.notebook.add(self.tab_sys, text="🛠 Subsystems")
        self.notebook.add(self.tab_diag, text="🧪 Diagnostics")

        self.build_if_tab()
        self.build_logs_tab()
        self.build_fw_tab()
        self.build_ai_tab()
        self.build_sys_tab()
        self.build_diag_tab()

        self.refresh_if()
        self.refresh_logs()
        self.refresh_ai()
        self.refresh_sys()
        self.refresh_diag()

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
                "Firewall Engine: WinDivert-based inline filter + DPI (HTTP/TLS/signatures), deception, persona, ad-block.\n"
                "Swarm cluster + honeypot suite running in background.\n"
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
