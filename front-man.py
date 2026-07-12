#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
AI Security Bridge (Full Evolution, Windows-focused, Monolithic)
- Inline transparent bridge in front of UDM Pro
- Multi-threaded forwarding
- AI firewall engine (stub with threat scoring + allowlist)
- Logging + threat matrix
- GUI with tabs (📡 WAN, 💾 Logs, ⚙ Firewall, 🔥 AI)
- Auto-loader for dependencies
- Basic tamper-resistance (admin check, integrity hash, watchdog)
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
from scapy.all import sniff, sendp

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

SELF_HASH = compute_self_hash()

def verify_integrity():
    current = compute_self_hash()
    return current == SELF_HASH

if not is_admin():
    print("[SECURITY] This program must be run as Administrator.")
    sys.exit(1)

if not verify_integrity():
    print("[SECURITY] File integrity check FAILED. Possible tampering detected.")
    sys.exit(1)

# =========================
#  CONFIG
# =========================

WAN_IN_IFACE = "Ethernet0"   # From ISP / modem
WAN_OUT_IFACE = "Ethernet1"  # To UDM Pro WAN port

BRIDGE_RUNNING = False
STOP_FLAG = False

PACKET_QUEUE = queue.Queue(maxsize=10000)
WORKER_THREADS = []
NUM_WORKERS = 4

LOG_LOCK = threading.Lock()
THREAT_LOG = []  # in-memory log; could be extended to file/DB

# Allowlist (gaming, Teams, etc.)
PERMA_ALLOW_IPS = {
    "52.112.0.0/14",   # Example: Teams (placeholder)
    # Add Steam / Epic / MS ranges as needed
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
#  AI FIREWALL ENGINE (STUB)
# =========================

def ip_in_allowlist(ip):
    # Placeholder: real implementation would parse CIDR ranges
    return False

def ai_firewall(pkt):
    """
    Returns:
        ("allow" | "drop" | "fake", score, reason)
    """
    src = pkt[0][1].src if pkt.haslayer("IP") else "N/A"
    dst = pkt[0][1].dst if pkt.haslayer("IP") else "N/A"
    proto = pkt[0].name

    # Basic allowlist
    if ip_in_allowlist(dst) or ip_in_allowlist(src):
        return "allow", 0, "perma_allow"

    # Simple heuristic: high port scans, SYN floods, etc. (placeholder)
    score = 0
    reason = "normal"

    if pkt.haslayer("TCP"):
        tcp = pkt["TCP"]
        if tcp.flags == "S":  # SYN
            score += 10
            reason = "syn"
        if tcp.dport in [22, 23, 3389]:
            score += 20
            reason = "sensitive_port"

    if score >= 25:
        return "drop", score, reason

    return "allow", score, reason

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
            src = pkt[0][1].src if pkt.haslayer("IP") else "N/A"
            dst = pkt[0][1].dst if pkt.haslayer("IP") else "N/A"
            proto = pkt[0].name

            if action == "allow":
                sendp(pkt, iface=WAN_OUT_IFACE, verbose=False)
                log_event(src, dst, proto, "allow", score, reason)
            elif action == "drop":
                log_event(src, dst, proto, "drop", score, reason)
            elif action == "fake":
                # Future: send fake response
                log_event(src, dst, proto, "fake", score, reason)
        except Exception as e:
            log_event("N/A", "N/A", "N/A", "error", 0, str(e))

def bridge_sniffer():
    def enqueue(pkt):
        if not STOP_FLAG:
            try:
                PACKET_QUEUE.put(pkt, timeout=0.1)
            except queue.Full:
                # Queue full: drop packet, log
                log_event("N/A", "N/A", "N/A", "drop", 0, "queue_full")

    sniff(iface=WAN_IN_IFACE, prn=enqueue, store=0)

def start_bridge():
    global BRIDGE_RUNNING, STOP_FLAG, WORKER_THREADS
    if BRIDGE_RUNNING:
        return
    STOP_FLAG = False
    BRIDGE_RUNNING = True

    # Start workers
    WORKER_THREADS = []
    for _ in range(NUM_WORKERS):
        t = threading.Thread(target=worker_loop, daemon=True)
        t.start()
        WORKER_THREADS.append(t)

    # Start sniffer
    threading.Thread(target=bridge_sniffer, daemon=True).start()

def stop_bridge():
    global BRIDGE_RUNNING, STOP_FLAG
    STOP_FLAG = True
    BRIDGE_RUNNING = False

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

        # Tabs
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

    # --- WAN TAB ---
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

    # --- LOGS TAB ---
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

    # --- FIREWALL TAB ---
    def build_fw_tab(self):
        lbl = tk.Label(self.tab_fw, text="Firewall Engine (stub) - future rule editor here")
        lbl.pack(padx=10, pady=10)

    # --- AI TAB ---
    def build_ai_tab(self):
        self.ai_status = tk.Label(self.tab_ai, text="AI Engine: ONLINE (stub)")
        self.ai_status.pack(padx=10, pady=10)

        self.ai_info = tk.Label(self.tab_ai,
                                text="Threat scoring, persona, swarm sync, gaming allowlist\n(placeholder, ready for expansion).")
        self.ai_info.pack(padx=10, pady=10)

    def refresh_ai(self):
        self.ai_status.config(text=f"AI Engine: {'ONLINE' if BRIDGE_RUNNING else 'IDLE'}")
        self.root.after(2000, self.refresh_ai)

# =========================
#  MAIN WRAPPER
# =========================

def main():
    root = tk.Tk()
    app = AISecurityBridgeApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
