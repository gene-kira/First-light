#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AI Security Bridge (Full Enhanced Version, Windows-focused, Monolithic)

- Inline transparent bridge in front of UDM Pro
- Multi-threaded forwarding
- Enhanced DPI (HTTP parsing, TLS fingerprint stub, malware + ad-block hooks)
- Deception engine (fake OS fingerprints, fake banners, RST stubs)
- Swarm sync client hooks (ready for real backend)
- Persona engine with threat lineage tracking
- Tamper-resistance (admin check, integrity hash, watchdog)
- UDM Pro API client stubs (clear integration points)
- GUI with tabs (📡 WAN, 💾 Logs, ⚙ Firewall, 🔥 AI)
- Auto-loader for dependencies
- Basic ad-blocking (drops HTTP requests to known ad domains)

NOTE:
- Real Windows service installation, real swarm backend, and full UniFi API integration
  should be implemented as separate components, not inside this single file.
- Linux hardware-accelerated bridge (br0) should be a separate port of the core logic.
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
from datetime import datetime

# =========================
#  AUTO-LOADER
# =========================

REQUIRED_LIBS = [
    "psutil",
    "tkinter",
    "scapy",
    "requests",
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
from scapy.all import sniff, sendp, IP, TCP, UDP, Raw
import requests

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
    sys.exit(1)

if not verify_integrity():
    print("[SECURITY] Integrity check FAILED. Possible tampering.")
    sys.exit(1)

# =========================
#  CONFIG
# =========================

WAN_IN_IFACE = "Ethernet0"   # From ISP / modem
WAN_OUT_IFACE = "Ethernet1"  # To UDM Pro WAN port

BRIDGE_RUNNING = False
STOP_FLAG = False

PACKET_QUEUE = queue.Queue(maxsize=20000)
WORKER_THREADS = []
NUM_WORKERS = 4

LOG_LOCK = threading.Lock()
THREAT_LOG = []

# Persona state (adaptive behavior + lineage)
PERSONA_STATE = {
    "aggressiveness": 1.0,
    "recent_high_threats": 0,
    "lineage": [],  # list of {src, dst, score, reason, time}
}

# Swarm sync config (placeholder)
SWARM_ENDPOINT = "http://127.0.0.1:8080/threat_sync"  # change to real endpoint

# UDM Pro API config (placeholder)
UDM_API_URL = "https://udm-pro.local:443"
UDM_API_USER = "admin"
UDM_API_PASS = "password"

# Allowlist placeholder
PERMA_ALLOW_IPS = set()

# Basic ad-block domain list (expand as needed)
AD_BLOCK_DOMAINS = {
    "ads.example.com",
    "tracking.example.com",
    "doubleclick.net",
    "googlesyndication.com",
    "adservice.google.com",
}

# =========================
#  LOGGING + THREAT MATRIX
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
#  DPI ENGINE (ENHANCED)
# =========================

MALWARE_SIGNATURES = [
    b"malware_example",  # placeholder
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
        for line in lines[1:]:
            if line.lower().startswith("host:"):
                host = line.split(":", 1)[1].strip()
                break
        return {"method": method, "path": path, "host": host}
    except Exception:
        return None

def tls_fingerprint_stub(payload):
    # Very rough JA3-style stub: hash of first N bytes
    h = hashlib.sha256()
    h.update(payload[:64])
    return h.hexdigest()

def dpi_analyze(pkt):
    """
    Enhanced DPI:
    - Detect HTTP and extract method/host/path
    - Detect TLS ClientHello and compute a fingerprint stub
    - Check simple payload signatures
    - Ad-block: detect HTTP host in AD_BLOCK_DOMAINS
    Returns (extra_score, dpi_reason, dpi_meta)
    """
    extra_score = 0
    reason = "dpi_normal"
    meta = {}

    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)

        # HTTP
        http_info = parse_http(payload)
        if http_info:
            reason = "http"
            extra_score += 5
            meta["http"] = http_info

            host = (http_info.get("host") or "").lower()
            if host in AD_BLOCK_DOMAINS:
                reason = "ad_block"
                extra_score += 40
                meta["ad_block_host"] = host

        # TLS ClientHello
        if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
            reason = "tls"
            extra_score += 10
            meta["tls_fp"] = tls_fingerprint_stub(payload)

        # Malware signatures
        for sig in MALWARE_SIGNATURES:
            if sig in payload:
                reason = "malware_sig"
                extra_score += 50
                meta["malware_sig"] = sig.decode("latin-1", errors="ignore")
                break

    return extra_score, reason, meta

# =========================
#  DECEPTION ENGINE (ENHANCED STUB)
# =========================

def spoof_os_fingerprint(pkt):
    """
    Basic OS fingerprint spoofing stub:
    - Conceptual: mimic TTL/window/options of a chosen OS.
    """
    return "os_spoof_stub"

def deception_response(pkt):
    """
    Stub for fake OS banners / fake services.
    Logs deception intent; real implementation would craft and send responses.
    """
    src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
    dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
    fp = spoof_os_fingerprint(pkt)
    log_event(src, dst, "DECEPTION", "fake", 0, f"deception_stub:{fp}")
    # Real implementation would craft TCP responses here.

# =========================
#  SWARM SYNC (CLIENT STUB)
# =========================

def swarm_share_threat(event):
    """
    Send threat event to swarm endpoint (stub).
    """
    try:
        requests.post(SWARM_ENDPOINT, json=event, timeout=0.5)
    except Exception:
        pass

def swarm_pull_threats():
    """
    Pull threat intel from swarm endpoint (stub).
    """
    try:
        r = requests.get(SWARM_ENDPOINT, timeout=0.5)
        if r.status_code == 200:
            data = r.json()
            # integrate data (placeholder)
    except Exception:
        pass

# =========================
#  PERSONA ENGINE (ADAPTIVE + LINEAGE)
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

    if PERSONA_STATE["recent_high_threats"] > 10:
        PERSONA_STATE["aggressiveness"] = min(3.0, PERSONA_STATE["aggressiveness"] + 0.1)
    else:
        PERSONA_STATE["aggressiveness"] = max(1.0, PERSONA_STATE["aggressiveness"] - 0.05)

def persona_adjust_score(base_score):
    return int(base_score * PERSONA_STATE["aggressiveness"])

# =========================
#  UDM PRO API CLIENT (STUB)
# =========================

def udm_push_firewall_rule(rule_name, src_ip, action="drop"):
    """
    Stub for pushing firewall rules to UDM Pro via API.
    Real implementation should:
    - Authenticate to UniFi controller
    - Use official endpoints to create/update firewall rules
    """
    try:
        log_event(src_ip, "UDM", "API", "udm_rule", 0, f"rule={rule_name}, action={action}")
    except Exception:
        pass

# =========================
#  AI FIREWALL ENGINE
# =========================

def ip_in_allowlist(ip):
    return ip in PERMA_ALLOW_IPS

def ai_firewall(pkt):
    """
    Returns:
        (action, score, reason)
        action: "allow" | "drop" | "fake"
    """
    src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
    dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
    proto = pkt.name

    if ip_in_allowlist(dst) or ip_in_allowlist(src):
        return "allow", 0, "perma_allow"

    base_score = 0
    reason = "normal"

    if pkt.haslayer(TCP):
        tcp = pkt[TCP]
        if tcp.flags == "S":
            base_score += 10
            reason = "syn"
        if tcp.dport in [22, 23, 3389]:
            base_score += 20
            reason = "sensitive_port"

    dpi_score, dpi_reason, dpi_meta = dpi_analyze(pkt)
    if dpi_score > 0:
        base_score += dpi_score
        reason = dpi_reason

    final_score = persona_adjust_score(base_score)
    update_persona(final_score, src, dst, reason)

    # High threat: drop + push rule + share
    if final_score >= 60:
        udm_push_firewall_rule("auto_block_high_threat", src, "drop")
        swarm_share_threat({
            "src": src,
            "dst": dst,
            "proto": proto,
            "score": final_score,
            "reason": reason,
        })
        return "drop", final_score, reason

    # Medium threat: deception
    if 40 <= final_score < 60:
        deception_response(pkt)
        return "fake", final_score, reason

    # Ad-block: if DPI reason is ad_block, treat as drop
    if dpi_reason == "ad_block":
        return "drop", final_score, "ad_block"

    return "allow", final_score, reason

# =========================
#  BRIDGE + WORKERS
# =========================

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
                sendp(pkt, iface=WAN_OUT_IFACE, verbose=False)
                log_event(src, dst, proto, "allow", score, reason)
            elif action == "drop":
                log_event(src, dst, proto, "drop", score, reason)
            elif action == "fake":
                log_event(src, dst, proto, "fake", score, reason)
        except Exception as e:
            log_event("N/A", "N/A", "N/A", "error", 0, str(e))

def bridge_sniffer():
    def enqueue(pkt):
        if not STOP_FLAG:
            try:
                PACKET_QUEUE.put(pkt, timeout=0.1)
            except queue.Full:
                log_event("N/A", "N/A", "N/A", "drop", 0, "queue_full")

    sniff(iface=WAN_IN_IFACE, prn=enqueue, store=0)

def start_bridge():
    global BRIDGE_RUNNING, STOP_FLAG, WORKER_THREADS
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

def stop_bridge():
    global BRIDGE_RUNNING, STOP_FLAG
    STOP_FLAG = True
    BRIDGE_RUNNING = False

# =========================
#  WATCHDOG (SERVICE-LIKE)
# =========================

def watchdog_loop():
    while True:
        if not verify_integrity():
            print("[WATCHDOG] Integrity failure. Exiting.")
            os._exit(1)
        swarm_pull_threats()
        time.sleep(5)

# =========================
#  ADAPTER ENUMERATION
# =========================

def get_adapters():
    adapters = []
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
    return adapters

# =========================
#  GUI WRAPPER
# =========================

class AISecurityBridgeApp:
    def __init__(self, root):
        self.root = root
        self.root.title("AI Security Bridge (UDM Pro Cloak)")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill="both", expand=True)

        self.tab_wan = tk.Frame(self.notebook)
        self.tab_logs = tk.Frame(self.notebook)
        self.tab_fw = tk.Frame(self.notebook)
        self.tab_ai = tk.Frame(self.notebook)

        self.notebook.add(self.tab_wan, text="📡 WAN")
        self.notebook.add(self.tab_logs, text="💾 Logs")
        self.notebook.add(self.tab_fw, text="⚙ Firewall")
        self.notebook.add(self.tab_ai, text="🔥 AI")

        self.build_wan_tab()
        self.build_logs_tab()
        self.build_fw_tab()
        self.build_ai_tab()

        self.refresh_wan()
        self.refresh_logs()
        self.refresh_ai()

    def build_wan_tab(self):
        top = tk.Frame(self.tab_wan)
        top.pack(fill="x", padx=5, pady=5)

        self.start_btn = tk.Button(top, text="Start Bridge", command=self.on_start_bridge)
        self.start_btn.pack(side="left", padx=5)

        self.stop_btn = tk.Button(top, text="Stop Bridge", command=self.on_stop_bridge)
        self.stop_btn.pack(side="left", padx=5)

        self.status_label = tk.Label(top, text="Bridge Status: STOPPED")
        self.status_label.pack(side="left", padx=10)

        self.adapter_tree = ttk.Treeview(self.tab_wan,
                                         columns=("Name", "Status", "Speed", "MAC", "IP"),
                                         show="headings")
        for col in ("Name", "Status", "Speed", "MAC", "IP"):
            self.adapter_tree.heading(col, text=col)
        self.adapter_tree.pack(fill="both", expand=True, padx=5, pady=5)

    def refresh_wan(self):
        for row in self.adapter_tree.get_children():
            self.adapter_tree.delete(row)
        for a in get_adapters():
            self.adapter_tree.insert("", "end",
                                     values=(a["name"], a["status"], a["speed"], a["mac"], a["ip"]))
        self.status_label.config(text=f"Bridge Status: {'RUNNING' if BRIDGE_RUNNING else 'STOPPED'}")
        self.root.after(2000, self.refresh_wan)

    def on_start_bridge(self):
        start_bridge()
        self.status_label.config(text="Bridge Status: RUNNING")

    def on_stop_bridge(self):
        stop_bridge()
        self.status_label.config(text="Bridge Status: STOPPED")

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
        lbl = tk.Label(self.tab_fw, text="Firewall Engine: DPI, deception, persona, ad-block.\nFuture: rule editor UI.")
        lbl.pack(padx=10, pady=10)

    def build_ai_tab(self):
        self.ai_status = tk.Label(self.tab_ai, text="AI Engine: IDLE")
        self.ai_status.pack(padx=10, pady=10)

        self.ai_info = tk.Label(
            self.tab_ai,
            text="Persona aggressiveness, swarm sync, threat lineage.\nReady for deeper AI integration."
        )
        self.ai_info.pack(padx=10, pady=10)

        self.persona_label = tk.Label(self.tab_ai, text="")
        self.persona_label.pack(padx=10, pady=10)

    def refresh_ai(self):
        self.ai_status.config(text=f"AI Engine: {'ONLINE' if BRIDGE_RUNNING else 'IDLE'}")
        self.persona_label.config(
            text=f"Persona: aggressiveness={PERSONA_STATE['aggressiveness']:.2f}, recent_high_threats={PERSONA_STATE['recent_high_threats']}"
        )
        self.root.after(2000, self.refresh_ai)

# =========================
#  MAIN WRAPPER
# =========================

def main():
    threading.Thread(target=watchdog_loop, daemon=True).start()
    root = tk.Tk()
    app = AISecurityBridgeApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
