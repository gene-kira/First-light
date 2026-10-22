#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hybrid Ad Blocker – FULL UPGRADED VERSION [TEST MODE ON]
- Auto-elevation
- PID + window title website detection
- TEST MODE: all domains treated as ads (so counters ALWAYS move)
- Hosts-based blocking + blocked/missed counters
- Import/Export hosts from GUI
- GUI showing current page + blocked/missed + prediction score
"""

# ============================================================
# AUTO-ELEVATION
# ============================================================
import ctypes, os, sys

def ensure_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                f'"{script}" {params}', None, 1
            )
            sys.exit()
    except Exception as e:
        print(f"[Hybrid AdBlock] Elevation failed: {e}")
        sys.exit()

ensure_admin()

# ============================================================
# IMPORTS
# ============================================================
import time, json, threading, socket
from pathlib import Path
from collections import defaultdict

import psutil
import requests

import tkinter as tk
from tkinter import ttk, filedialog

# ============================================================
# CONFIG
# ============================================================
CUSTOM_HOSTS_PATH = Path(r"C:\AdBlock\ad_hosts.txt")
BLOCK_IP = "0.0.0.0"
BACKUP_DIR = CUSTOM_HOSTS_PATH.parent / "backups"
LOG_PATH = CUSTOM_HOSTS_PATH.parent / "adblock_log.json"

PRIMARY_TEST_SITE = "adblock.turtlecute.org"

AD_RULE_URLS = [
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
]

WEB_AD_DETECTION_INTERVAL = 1.0
AD_RULES_SYNC_INTERVAL = 300.0

BROWSER_NAMES = ["chrome", "msedge", "edge", "firefox", "brave", "opera"]

# ============================================================
# GLOBAL STATE
# ============================================================
ad_rules = set()
ad_host_hints = set()

web_ad_state = {
    "active": False,
    "last_scan_ts": 0.0,
    "connections": [],
    "ad_connections": [],
    "domain_stats": {},
    "prediction_score": 0.0,
    "last_event_ts": 0.0,
}

active_domain_state = {
    "domain": None,
    "title": "",
    "pid": None,
}

# ============================================================
# LOGGING
# ============================================================
def log(msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")

# ============================================================
# HOSTS MANAGER
# ============================================================
class HostsManager:
    def __init__(self, path: Path, block_ip: str):
        self.path = path
        self.block_ip = block_ip
        self.entries = set()
        self._load()

    def _load(self):
        self.entries.clear()
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch()
            return
        with self.path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip, domain = parts[0], parts[1]
                    if ip == self.block_ip:
                        self.entries.add(domain.lower())

    def is_blocked(self, domain: str) -> bool:
        return domain.lower() in self.entries

    def add(self, domain: str) -> bool:
        d = domain.lower().strip()
        if not d or d.startswith("#"):
            return False
        if d in self.entries:
            return False
        self.entries.add(d)
        return True

    def save(self):
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        backup_path = BACKUP_DIR / f"hosts_backup_{ts}.txt"
        if self.path.exists():
            backup_path.write_text(
                self.path.read_text(encoding="utf-8", errors="ignore"),
                encoding="utf-8"
            )
        lines = [
            "# Hybrid AdBlock Hosts File\n",
            f"# Block IP: {self.block_ip}\n",
            f"# Last update: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        ]
        for domain in sorted(self.entries):
            lines.append(f"{self.block_ip} {domain}\n")
        self.path.write_text("".join(lines), encoding="utf-8")

# ============================================================
# COUNTERS + ANALYTICS
# ============================================================
class AdCounter:
    def __init__(self):
        self.reset()

    def reset(self):
        self.page = None
        self.blocked = 0
        self.missed = 0
        self.missed_list = []

    def set_page(self, page_id: str):
        if self.page != page_id:
            self.reset()
            self.page = page_id

    def log_blocked(self):
        self.blocked += 1

    def log_missed(self, domain: str):
        self.missed += 1
        self.missed_list.append(domain)

class Analytics:
    def __init__(self):
        self.per_site = defaultdict(lambda: {"blocked": 0, "missed": 0})

    def log(self, domain: str, blocked: bool):
        site = domain.lower()
        if blocked:
            self.per_site[site]["blocked"] += 1
        else:
            self.per_site[site]["missed"] += 1

    def snapshot(self):
        return dict(self.per_site)

def write_log(counter: AdCounter, analytics: Analytics):
    LOG_PATH.write_text(json.dumps({
        "page": counter.page,
        "blocked": counter.blocked,
        "missed": counter.missed,
        "missed_list": counter.missed_list,
        "per_site": analytics.snapshot(),
        "timestamp": time.time()
    }, indent=2))

# ============================================================
# AD RULES (kept for future, not critical for TEST MODE)
# ============================================================
def _extract_host_hint_from_rule(line: str):
    line = line.strip()
    if not line or line.startswith("!"):
        return None
    host = None
    if line.startswith("||"):
        body = line[2:]
        for sep in ("^", "/", "$"):
            if sep in body:
                body = body.split(sep, 1)[0]
        if body and "." in body:
            host = body.lower()
    else:
        if "." in line and not line.startswith("@@"):
            host = line.lower()
    return host

def fetch_ad_rules_from_internet():
    global ad_rules, ad_host_hints
    new_rules = set()
    new_hosts = set()
    for url in AD_RULE_URLS:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("!"):
                        continue
                    new_rules.add(line)
                    host_hint = _extract_host_hint_from_rule(line)
                    if host_hint:
                        new_hosts.add(host_hint)
                log(f"[AD] Fetched rules from {url}")
        except Exception as e:
            log(f"[AD] Failed to fetch {url}: {e}")
    ad_rules |= new_rules
    ad_host_hints |= new_hosts

def ad_rules_sync_loop():
    while True:
        fetch_ad_rules_from_internet()
        time.sleep(AD_RULES_SYNC_INTERVAL)

# ============================================================
# PID + WINDOW TITLE DETECTION
# ============================================================
def get_active_window_info():
    if os.name != "nt":
        return "", None
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return "", None
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(max(1, length + 1))
        user32.GetWindowTextW(hwnd, buf, len(buf))
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return buf.value.strip(), int(pid.value) or None
    except Exception:
        return "", None

# ============================================================
# WHOLE-WEB CONNECTION SCAN (TEST MODE)
# ============================================================
def _reverse_dns(ip: str):
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except Exception:
        return None

def _classify_connection(conn):
    if not conn.raddr:
        return None
    r_ip = conn.raddr.ip
    r_port = conn.raddr.port
    host = _reverse_dns(r_ip)
    descriptor = f"{r_ip}:{r_port}"
    return {
        "pid": conn.pid,
        "host": host,
        "raddr": descriptor,
    }

def scan_web_ports_all():
    connections = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return connections
    for conn in conns:
        info = _classify_connection(conn)
        if not info:
            continue
        connections.append(info)
    return connections

def _update_domain_stats(ad_connections):
    for info in ad_connections:
        host = info.get("host") or info.get("raddr")
        if not host:
            continue
        key = host.lower()
        stats = web_ad_state["domain_stats"].get(key, {"hits": 0, "ad_hits": 0, "score": 0.0})
        stats["hits"] += 1
        stats["ad_hits"] += 1  # TEST MODE: everything is ad-like
        stats["score"] = stats["ad_hits"] / max(1, stats["hits"])
        web_ad_state["domain_stats"][key] = stats
    if web_ad_state["domain_stats"]:
        scores = sorted((v["score"] for v in web_ad_state["domain_stats"].values()), reverse=True)
        web_ad_state["prediction_score"] = sum(scores[:10]) / max(1, len(scores[:10]))
    else:
        web_ad_state["prediction_score"] = 0.0

# ============================================================
# ACTIVE DOMAIN DETECTION
# ============================================================
def extract_domain_from_title(title: str):
    if not title:
        return None
    for part in title.split():
        part = part.strip()
        if "." in part and "/" not in part:
            return part.lower()
    return None

def active_domain_detection_loop():
    while True:
        try:
            title, pid = get_active_window_info()
            active_domain_state["title"] = title
            active_domain_state["pid"] = pid

            domain = extract_domain_from_title(title)

            if not domain and pid:
                try:
                    conns = psutil.net_connections(kind="inet")
                except Exception:
                    conns = []
                for conn in conns:
                    if conn.pid != pid or not conn.raddr:
                        continue
                    host = _reverse_dns(conn.raddr.ip)
                    if host and "." in host:
                        domain = host.lower()
                        break

            if not domain and PRIMARY_TEST_SITE in (title or "").lower():
                domain = PRIMARY_TEST_SITE

            active_domain_state["domain"] = domain
        except Exception as e:
            log(f"[ACTIVE] Detection error: {e}")
        time.sleep(0.5)

# ============================================================
# AD DETECTION LOOP (TEST MODE: ALL DOMAINS AS ADS)
# ============================================================
def web_ad_detection_loop(manager: HostsManager, counter: AdCounter, analytics: Analytics):
    while True:
        try:
            connections = scan_web_ports_all()

            # TEST MODE: treat ALL connections as ad-like
            ad_connections = connections

            web_ad_state["connections"] = connections
            web_ad_state["ad_connections"] = ad_connections
            web_ad_state["active"] = bool(ad_connections)
            _update_domain_stats(ad_connections)

            current_page = active_domain_state["domain"] or "unknown"
            counter.set_page(current_page)

            for info in ad_connections:
                host = info.get("host") or info.get("raddr")
                if not host:
                    continue
                domain = host.lower()

                if manager.is_blocked(domain):
                    counter.log_blocked()
                    analytics.log(domain, True)
                else:
                    counter.log_missed(domain)
                    analytics.log(domain, False)
                    if manager.add(domain):
                        manager.save()

            write_log(counter, analytics)
        except Exception as e:
            log(f"[WEB-AD] Detection loop error: {e}")
        time.sleep(WEB_AD_DETECTION_INTERVAL)

# ============================================================
# GUI (WITH IMPORT/EXPORT HOSTS)
# ============================================================
class AdBlockGUI:
    def __init__(self, manager: HostsManager, counter: AdCounter, analytics: Analytics):
        self.manager = manager
        self.counter = counter
        self.analytics = analytics
        self.root = tk.Tk()
        self._build()

    def _build(self):
        self.root.title("Hybrid Ad Blocker (FULL UPGRADED – TEST MODE)")
        self.root.geometry("460x360")
        self.root.resizable(False, False)

        self.page_label = ttk.Label(self.root, text="Page: -")
        self.page_label.pack(anchor="w", padx=8, pady=(8, 2))

        self.title_label = ttk.Label(self.root, text="Window: -")
        self.title_label.pack(anchor="w", padx=8, pady=(0, 4))

        self.blocked_label = ttk.Label(self.root, text="Blocked: 0")
        self.blocked_label.pack(anchor="w", padx=8)

        self.missed_label = ttk.Label(self.root, text="Missed: 0")
        self.missed_label.pack(anchor="w", padx=8, pady=(0, 4))

        self.pred_label = ttk.Label(self.root, text="Ad prediction score: 0.00")
        self.pred_label.pack(anchor="w", padx=8, pady=(0, 8))

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill="x", padx=8, pady=(0, 8))

        import_btn = ttk.Button(btn_frame, text="Import Hosts", command=self._import_hosts)
        import_btn.pack(side="left", padx=(0, 4))

        export_btn = ttk.Button(btn_frame, text="Export Hosts", command=self._export_hosts)
        export_btn.pack(side="left", padx=(4, 0))

        ttk.Label(self.root, text="Per-site analytics:").pack(anchor="w", padx=8)
        self.site_list = tk.Listbox(self.root, height=10)
        self.site_list.pack(fill="both", expand=True, padx=8, pady=(2, 8))

        self._schedule_update()

    def _schedule_update(self):
        self._update()
        self.root.after(1000, self._schedule_update)

    def _update(self):
        page = active_domain_state["domain"] or "-"
        title = active_domain_state["title"] or "-"
        self.page_label.config(text=f"Page: {page}")
        self.title_label.config(text=f"Window: {title}")
        self.blocked_label.config(text=f"Blocked: {self.counter.blocked}")
        self.missed_label.config(text=f"Missed: {self.counter.missed}")
        self.pred_label.config(
            text=f"Ad prediction score: {web_ad_state['prediction_score']:.2f}"
        )

        self.site_list.delete(0, tk.END)
        for site, stats in sorted(self.analytics.snapshot().items()):
            line = f"{site}  B:{stats['blocked']}  M:{stats['missed']}"
            self.site_list.insert(tk.END, line)

    def _import_hosts(self):
        filepath = filedialog.askopenfilename(
            title="Select Hosts File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not filepath:
            return
        try:
            imported = set()
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip, domain = parts[0], parts[1]
                        if ip == self.manager.block_ip:
                            imported.add(domain.lower())
                    else:
                        imported.add(line.lower())
            before = len(self.manager.entries)
            self.manager.entries.update(imported)
            self.manager.save()
            log(f"[GUI] Imported {len(self.manager.entries) - before} host entries from {filepath}")
        except Exception as e:
            log(f"[GUI] Import failed: {e}")

    def _export_hosts(self):
        filepath = filedialog.asksaveasfilename(
            title="Save Hosts File",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not filepath:
            return
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("# Exported Hosts\n")
                for domain in sorted(self.manager.entries):
                    f.write(f"{self.manager.block_ip} {domain}\n")
            log(f"[GUI] Exported hosts to {filepath}")
        except Exception as e:
            log(f"[GUI] Export failed: {e}")

    def run(self):
        self.root.mainloop()

# ============================================================
# MAIN
# ============================================================
def main():
    manager = HostsManager(CUSTOM_HOSTS_PATH, BLOCK_IP)
    counter = AdCounter()
    analytics = Analytics()

    threading.Thread(target=ad_rules_sync_loop, daemon=True).start()
    threading.Thread(target=active_domain_detection_loop, daemon=True).start()
    threading.Thread(target=web_ad_detection_loop, args=(manager, counter, analytics), daemon=True).start()

    gui = AdBlockGUI(manager, counter, analytics)
    gui.run()

if __name__ == "__main__":
    main()
