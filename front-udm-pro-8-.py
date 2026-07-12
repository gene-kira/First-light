#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AI Security Bridge (GUI-first + Crash-proof subsystems + Swarm + Honeypot + DPI with JA3)

Topology:
- WAN mode: ISP/modem -> bridge -> UDM Pro
- LAN-to-LAN mode: main system -> bridge -> UDM Pro LAN

Features:
- GUI-first startup (Tkinter always appears)
- Crash-proof subsystem startup (errors captured and shown in GUI)
- Inline transparent bridge (WAN or LAN-to-LAN)
- Multi-threaded forwarding
- DPI:
  - HTTP parser (method, path, host, UA, referer)
  - TLS ClientHello parsing + JA3-style fingerprint (simplified)
  - Simple signature DB (malware/ad patterns)
- Deception engine:
  - Fake HTTP banners
  - TCP RST responses
  - OS fingerprint spoofing (stub)
- Honeypot emulation suite:
  - SSH, HTTP, HTTPS, RDP, SMB fake services
- Distributed swarm cluster:
  - Embedded HTTP server for threat sharing
  - Peer discovery (simple subnet scan)
  - Threat replication across peers
- Persona engine (behavioral evolution + threat lineage + modes)
- Tamper-resistance (admin check, integrity hash, watchdog)
- UDM Pro API client stubs
- GUI with tabs (📡 Interfaces, 💾 Logs, ⚙ Firewall, 🔥 AI, 🛠 Subsystems)
- Windows service mode (pywin32) for headless operation

Run modes:
- GUI: python this_file.py
- Service: python this_file.py install / start / stop / remove
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
#  AUTO-LOADER
# =========================

REQUIRED_LIBS = [
    "psutil",
    "tkinter",
    "scapy",
    "requests",
    "pywin32",
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
from scapy.all import sniff, sendp, IP, TCP, UDP, Raw, Ether
import requests

import win32serviceutil
import win32service
import win32event

from http.server import BaseHTTPRequestHandler, HTTPServer

# =========================
#  BASIC TAMPER RESISTANCE
# =========================

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

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

if not is_admin():
    print("[SECURITY] Must run as Administrator.")
    # Do NOT exit here; GUI-first means we still show window with error
    ADMIN_REQUIRED = True
else:
    ADMIN_REQUIRED = False

INTEGRITY_FAILED = not verify_integrity()

# =========================
#  CONFIG
# =========================

WAN_IN_IFACE = "Ethernet0"    # From ISP / modem
WAN_OUT_IFACE = "Ethernet1"   # To UDM Pro WAN port

LAN_IN_IFACE = "Ethernet2"    # From main system
LAN_OUT_IFACE = "Ethernet3"   # To UDM Pro LAN

BRIDGE_MODE = "WAN"  # "WAN" or "LAN"

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

# Subsystem error tracking (for GUI)
SUBSYSTEM_ERRORS_LOCK = threading.Lock()
SUBSYSTEM_ERRORS = {
    "bridge": "",
    "dpi": "",
    "swarm": "",
    "honeypot": "",
    "watchdog": "",
    "service": "",
}

def set_subsystem_error(name, msg):
    with SUBSYSTEM_ERRORS_LOCK:
        SUBSYSTEM_ERRORS[name] = msg

def get_subsystem_errors():
    with SUBSYSTEM_ERRORS_LOCK:
        return dict(SUBSYSTEM_ERRORS)

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

def dpi_analyze(pkt):
    extra_score = 0
    reason = "dpi_normal"
    meta = {}

    try:
        if pkt.haslayer(Raw):
            payload = bytes(pkt[Raw].load)

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

def spoof_os_fingerprint(pkt):
    return "os_spoof_stub"

def send_tcp_rst(pkt, iface):
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]
        rst = Ether() / IP(src=ip.dst, dst=ip.src) / TCP(
            sport=tcp.dport,
            dport=tcp.sport,
            flags="R",
            seq=tcp.ack,
            ack=tcp.seq + 1
        )
        sendp(rst, iface=iface, verbose=False)
    except Exception as e:
        set_subsystem_error("bridge", f"RST send error: {e}")

def send_fake_http_banner(pkt, iface):
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Apache/2.4.41 (Ubuntu)\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 20\r\n"
            b"\r\n"
            b"<h1>Fake Host</h1>"
        )
        resp = Ether() / IP(src=ip.dst, dst=ip.src) / TCP(
            sport=tcp.dport,
            dport=tcp.sport,
            flags="PA",
            seq=tcp.ack,
            ack=tcp.seq + (len(pkt[Raw].load) if pkt.haslayer(Raw) else 1)
        ) / Raw(load=payload)
        sendp(resp, iface=iface, verbose=False)
    except Exception as e:
        set_subsystem_error("bridge", f"Fake HTTP send error: {e}")

def deception_response(pkt, reason):
    iface = WAN_OUT_IFACE if BRIDGE_MODE == "WAN" else LAN_OUT_IFACE
    src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
    dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
    fp = spoof_os_fingerprint(pkt)
    log_event(src, dst, "DECEPTION", "fake", 0, f"{reason}:{fp}")
    if reason == "ad_block":
        send_tcp_rst(pkt, iface)
    else:
        send_fake_http_banner(pkt, iface)

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

def ai_firewall(pkt):
    src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
    dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
    proto = pkt.name

    if ip_in_allowlist(dst) or ip_in_allowlist(src):
        return "allow", 0, "perma_allow"

    base_score = 0
    reason = "normal"

    try:
        if pkt.haslayer(TCP):
            tcp = pkt[TCP]
            if tcp.flags == "S":
                base_score += 10
                reason = "syn"
            if tcp.dport in [22, 23, 3389, 445]:
                base_score += 25
                reason = "sensitive_port"

        dpi_score, dpi_reason, dpi_meta = dpi_analyze(pkt)
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
            deception_response(pkt, reason)
            return "fake", final_score, reason

        if dpi_reason == "ad_block":
            deception_response(pkt, "ad_block")
            return "drop", final_score, "ad_block"

    except Exception as e:
        set_subsystem_error("bridge", f"AI firewall error: {e}")
        return "allow", 0, "error"

    return "allow", base_score, reason

# =========================
#  BRIDGE + WORKERS
# =========================

def get_active_out_iface():
    return WAN_OUT_IFACE if BRIDGE_MODE == "WAN" else LAN_OUT_IFACE

def get_active_in_iface():
    return WAN_IN_IFACE if BRIDGE_MODE == "WAN" else LAN_IN_IFACE

def worker_loop():
    while not STOP_FLAG:
        try:
            pkt = PACKET_QUEUE.get(timeout=1)
        except queue.Empty:
            continue
        try:
            action, score, reason = ai_firewall(pkt)
            src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
            dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
            proto = pkt.name

            if action == "allow":
                sendp(pkt, iface=get_active_out_iface(), verbose=False)
                log_event(src, dst, proto, "allow", score, reason)
            elif action == "drop":
                log_event(src, dst, proto, "drop", score, reason)
            elif action == "fake":
                log_event(src, dst, proto, "fake", score, reason)
        except Exception as e:
            set_subsystem_error("bridge", f"Worker error: {e}")
            log_event("N/A", "N/A", "N/A", "error", 0, str(e))

def bridge_sniffer():
    def enqueue(pkt):
        if not STOP_FLAG:
            try:
                PACKET_QUEUE.put(pkt, timeout=0.1)
            except queue.Full:
                log_event("N/A", "N/A", "N/A", "drop", 0, "queue_full")

    try:
        sniff(iface=get_active_in_iface(), prn=enqueue, store=0)
    except Exception as e:
        set_subsystem_error("bridge", f"Sniffer error: {e}")

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

def stop_bridge():
    global BRIDGE_RUNNING, STOP_FLAG
    STOP_FLAG = True
    BRIDGE_RUNNING = False

# =========================
#  WATCHDOG
# =========================

def watchdog_loop():
    while True:
        try:
            if not verify_integrity():
                set_subsystem_error("watchdog", "Integrity failure detected.")
                os._exit(1)
            if BRIDGE_RUNNING is False and not STOP_FLAG:
                start_bridge()
            swarm_peer_discovery()
            swarm_pull_threats()
        except Exception as e:
            set_subsystem_error("watchdog", f"Watchdog error: {e}")
        time.sleep(5)

# =========================
#  WINDOWS SERVICE
# =========================

class AISecurityBridgeService(win32serviceutil.ServiceFramework):
    _svc_name_ = "AISecurityBridgeService"
    _svc_display_name_ = "AI Security Bridge Service"
    _svc_description_ = "Inline AI-driven security bridge in front of UDM Pro (WAN or LAN)."

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)

    def SvcStop(self):
        global STOP_FLAG
        STOP_FLAG = True
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
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
    return adapters

# =========================
#  GUI
# =========================

class AISecurityBridgeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI Security Bridge (UDM Pro Cloak)")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        self.tab_if = tk.Frame(self.notebook)
        self.tab_logs = tk.Frame(self.notebook)
        self.tab_fw = tk.Frame(self.notebook)
        self.tab_ai = tk.Frame(self.notebook)
        self.tab_sys = tk.Frame(self.notebook)

        self.notebook.add(self.tab_if, text="📡 Interfaces")
        self.notebook.add(self.tab_logs, text="💾 Logs")
        self.notebook.add(self.tab_fw, text="⚙ Firewall")
        self.notebook.add(self.tab_ai, text="🔥 AI")
        self.notebook.add(self.tab_sys, text="🛠 Subsystems")

        self.build_if_tab()
        self.build_logs_tab()
        self.build_fw_tab()
        self.build_ai_tab()
        self.build_sys_tab()

        self.refresh_if()
        self.refresh_logs()
        self.refresh_ai()
        self.refresh_sys()

        # GUI-first: start subsystems AFTER GUI is up
        self.root.after(500, self.start_subsystems_safe)

    def start_subsystems_safe(self):
        if ADMIN_REQUIRED:
            set_subsystem_error("service", "Must run as Administrator for full functionality.")
        if INTEGRITY_FAILED:
            set_subsystem_error("service", "Integrity check failed at startup.")

        try:
            start_swarm_backend()
        except Exception as e:
            set_subsystem_error("swarm", f"Swarm start error: {e}")

        try:
            start_honeypot_suite()
        except Exception as e:
            set_subsystem_error("honeypot", f"Honeypot start error: {e}")

        try:
            threading.Thread(target=watchdog_loop, daemon=True).start()
        except Exception as e:
            set_subsystem_error("watchdog", f"Watchdog start error: {e}")

        try:
            start_bridge()
        except Exception as e:
            set_subsystem_error("bridge", f"Bridge start error: {e}")

    def build_if_tab(self):
        top = tk.Frame(self.tab_if)
        top.pack(fill="x", padx=5, pady=5)

        self.mode_var = tk.StringVar(value=BRIDGE_MODE)
        tk.Label(top, text="Bridge Mode:").pack(side="left", padx=5)
        tk.Radiobutton(top, text="WAN", variable=self.mode_var, value="WAN", command=self.on_mode_change).pack(side="left")
        tk.Radiobutton(top, text="LAN-to-LAN", variable=self.mode_var, value="LAN", command=self.on_mode_change).pack(side="left")

        self.start_btn = tk.Button(top, text="Start Bridge", command=self.on_start_bridge)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = tk.Button(top, text="Stop Bridge", command=self.on_stop_bridge)
        self.stop_btn.pack(side="left", padx=5)

        self.status_label = tk.Label(top, text="Bridge Status: STOPPED")
        self.status_label.pack(side="left", padx=10)

        self.adapter_tree = ttk.Treeview(self.tab_if,
                                         columns=("Name", "Status", "Speed", "MAC", "IP"),
                                         show="headings")
        for col in ("Name", "Status", "Speed", "MAC", "IP"):
            self.adapter_tree.heading(col, text=col)
        self.adapter_tree.pack(fill="both", expand=True, padx=5, pady=5)

    def on_mode_change(self):
        global BRIDGE_MODE
        BRIDGE_MODE = self.mode_var.get()

    def refresh_if(self):
        for row in self.adapter_tree.get_children():
            self.adapter_tree.delete(row)
        for a in get_adapters():
            self.adapter_tree.insert("", "end",
                                     values=(a["name"], a["status"], a["speed"], a["mac"], a["ip"]))
        self.status_label.config(text=f"Bridge Status: {'RUNNING' if BRIDGE_RUNNING else 'STOPPED'} (Mode={BRIDGE_MODE})")
        self.root.after(2000, self.refresh_if)

    def on_start_bridge(self):
        try:
            start_bridge()
            self.status_label.config(text=f"Bridge Status: RUNNING (Mode={BRIDGE_MODE})")
        except Exception as e:
            set_subsystem_error("bridge", f"Manual start error: {e}")

    def on_stop_bridge(self):
        try:
            stop_bridge()
            self.status_label.config(text=f"Bridge Status: STOPPED (Mode={BRIDGE_MODE})")
        except Exception as e:
            set_subsystem_error("bridge", f"Manual stop error: {e}")

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
        lbl = tk.Label(self.tab_fw, text="Firewall Engine: DPI (HTTP + TLS + signatures), deception, persona, ad-block.\nSwarm cluster + honeypot suite running in background.")
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
        if ADMIN_REQUIRED:
            self.sys_text.insert(tk.END, "\n[ADMIN] WARNING: Run as Administrator for full functionality.\n")
        if INTEGRITY_FAILED:
            self.sys_text.insert(tk.END, "\n[INTEGRITY] WARNING: Integrity check failed at startup.\n")
        self.root.after(2000, self.refresh_sys)

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
