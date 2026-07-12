#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AI Security Bridge (Deception + Advanced Persona + Service-Aware, Windows-focused, Monolithic)

- Inline transparent bridge in front of UDM Pro
- Multi-threaded forwarding
- DPI (HTTP parsing, TLS fingerprint stub, malware + ad-block hooks)
- REAL-ish deception engine (fake HTTP banners + TCP RST responses)
- Advanced persona engine (behavioral evolution + threat lineage + modes)
- Tamper-resistance (admin check, integrity hash, watchdog)
- UDM Pro API client stubs (clear integration points)
- GUI with tabs (📡 WAN, 💾 Logs, ⚙ Firewall, 🔥 AI)
- Auto-loader for dependencies
- Basic ad-blocking (drops HTTP requests to known ad domains)
- Service-aware: helper to register as Windows service + auto-recovery of bridge

NOTE:
- Real Windows service hosting should be done via NSSM / sc.exe or a dedicated service wrapper.
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
from scapy.all import sniff, sendp, IP, TCP, UDP, Raw, Ether
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

# Persona state (adaptive behavior + lineage + mode)
PERSONA_STATE = {
    "aggressiveness": 1.0,
    "recent_high_threats": 0,
    "lineage": [],  # list of {src, dst, score, reason, time}
    "mode": "calm",  # calm, alert, hostile
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
#  DPI ENGINE
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
    h = hashlib.sha256()
    h.update(payload[:64])
    return h.hexdigest()

def dpi_analyze(pkt):
    extra_score = 0
    reason = "dpi_normal"
    meta = {}

    if pkt.haslayer(Raw):
        payload = bytes(pkt[Raw].load)

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

        if len(payload) > 5 and payload[0] == 0x16 and payload[1] == 0x03:
            reason = "tls"
            extra_score += 10
            meta["tls_fp"] = tls_fingerprint_stub(payload)

        for sig in MALWARE_SIGNATURES:
            if sig in payload:
                reason = "malware_sig"
                extra_score += 50
                meta["malware_sig"] = sig.decode("latin-1", errors="ignore")
                break

    return extra_score, reason, meta

# =========================
#  DECEPTION ENGINE (REAL-ISH)
# =========================

def spoof_os_fingerprint(pkt):
    return "os_spoof_stub"

def send_tcp_rst(pkt):
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
        sendp(rst, iface=WAN_OUT_IFACE, verbose=False)
    except Exception:
        pass

def send_fake_http_banner(pkt):
    try:
        if not pkt.haslayer(IP) or not pkt.haslayer(TCP):
            return
        ip = pkt[IP]
        tcp = pkt[TCP]
        payload = (
            b"HTTP/1.1 200 OK\r\n"
            b"Server: Microsoft-IIS/10.0\r\n"
            b"Content-Type: text/html\r\n"
            b"Content-Length: 20\r\n"
            b"\r\n"
            b"<h1>Hello World</h1>"
        )
        resp = Ether() / IP(src=ip.dst, dst=ip.src) / TCP(
            sport=tcp.dport,
            dport=tcp.sport,
            flags="PA",
            seq=tcp.ack,
            ack=tcp.seq + len(pkt[Raw].load) if pkt.haslayer(Raw) else tcp.seq + 1
        ) / Raw(load=payload)
        sendp(resp, iface=WAN_OUT_IFACE, verbose=False)
    except Exception:
        pass

def deception_response(pkt, reason):
    src = pkt[IP].src if pkt.haslayer(IP) else "N/A"
    dst = pkt[IP].dst if pkt.haslayer(IP) else "N/A"
    fp = spoof_os_fingerprint(pkt)
    log_event(src, dst, "DECEPTION", "fake", 0, f"{reason}:{fp}")
    if reason == "ad_block":
        send_tcp_rst(pkt)
    else:
        send_fake_http_banner(pkt)

# =========================
#  SWARM SYNC (CLIENT STUB)
# =========================

def swarm_share_threat(event):
    try:
        requests.post(SWARM_ENDPOINT, json=event, timeout=0.5)
    except Exception:
        pass

def swarm_pull_threats():
    try:
        r = requests.get(SWARM_ENDPOINT, timeout=0.5)
        if r.status_code == 200:
            data = r.json()
            # integrate data (placeholder)
    except Exception:
        pass

# =========================
#  PERSONA ENGINE (ADVANCED)
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

    if PERSONA_STATE["recent_high_threats"] > 20:
        PERSONA_STATE["aggressiveness"] = min(4.0, PERSONA_STATE["aggressiveness"] + 0.2)
        PERSONA_STATE["mode"] = "hostile"
    elif PERSONA_STATE["recent_high_threats"] > 5:
        PERSONA_STATE["aggressiveness"] = min(3.0, PERSONA_STATE["aggressiveness"] + 0.1)
        PERSONA_STATE["mode"] = "alert"
    else:
        PERSONA_STATE["aggressiveness"] = max(1.0, PERSONA_STATE["aggressiveness"] - 0.05)
        PERSONA_STATE["mode"] = "calm"

def persona_adjust_score(base_score):
    return int(base_score * PERSONA_STATE["aggressiveness"])

# =========================
#  UDM PRO API CLIENT (STUB)
# =========================

def udm_push_firewall_rule(rule_name, src_ip, action="drop"):
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

    if 40 <= final_score < 60:
        deception_response(pkt, reason)
        return "fake", final_score, reason

    if dpi_reason == "ad_block":
        deception_response(pkt, "ad_block")
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
#  WATCHDOG (AUTO-RECOVERY)
# =========================

def watchdog_loop():
    while True:
        if not verify_integrity():
            print("[WATCHDOG] Integrity failure. Exiting.")
            os._exit(1)
        if BRIDGE_RUNNING is False and not STOP_FLAG:
            start_bridge()
        swarm_pull_threats()
        time.sleep(5)

# =========================
#  WINDOWS SERVICE HELPER (STUB)
# =========================

def install_windows_service(service_name="AISecurityBridge"):
    exe_path = os.path.abspath(sys.argv[0])
    cmd = [
        "sc",
        "create",
        service_name,
        "binPath=",
        f'"{sys.executable} {exe_path}"',
        "start=",
        "auto"
    ]
    try:
        subprocess.run(" ".join(cmd), shell=True)
        print(f"[SERVICE] Attempted to create service '{service_name}'.")
    except Exception as e:
        print(f"[SERVICE] Failed to create service: {e}")

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
        lbl = tk.Label(self.tab_fw, text="Firewall Engine: DPI, deception, persona, ad-block.\nService helper available via install_windows_service().")
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
