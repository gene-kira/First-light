# === AUDIO WEAPON CONSOLE v5 — Mini EDR, Compact Pro ===
# Includes:
# - Autoloader
# - Real bandwidth, GeoIP, ASN
# - VirusTotal hash reputation (optional)
# - Process behavior (CPU, memory, threads)
# - Network behavior (connections, beacon-ish detection)
# - Threat scoring + correlation
# - Auto-kill, auto-mute, auto-quarantine, auto-block IP
# - Compact Pro GUI with:
#     * Main table
#     * Timeline / log
#     * Threat graphs
#     * Process tree view (text-based)
#     * Details popup
# - Filters, blocklist/allowlist, rules editor

import importlib
import sys
import time
import os
import json
import threading
import hashlib
from datetime import datetime

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# === AUTOLOADER ===

REQUIRED_LIBS = {
    "psutil": "psutil",
    "pythoncom": "pywin32",
    "pycaw": "pycaw",
}

OPTIONAL_LIBS = {
    "geoip2": "geoip2",      # GeoIP2 DB (City + ASN)
    "requests": "requests",  # VirusTotal API
}

OPTIONAL_AVAILABLE = {k: False for k in OPTIONAL_LIBS}


def autoload_libs():
    missing = []

    for lib, pip_name in REQUIRED_LIBS.items():
        try:
            importlib.import_module(lib)
        except ImportError:
            missing.append((lib, pip_name))

    if missing:
        print("\n=== Missing Required Libraries ===")
        for lib, pip_name in missing:
            print(f" - {lib} (install: pip install {pip_name})")
        print("=================================\n")
        print("The program may not work correctly without these.\n")

    for lib, pip_name in OPTIONAL_LIBS.items():
        try:
            importlib.import_module(lib)
            OPTIONAL_AVAILABLE[lib] = True
        except ImportError:
            OPTIONAL_AVAILABLE[lib] = False


autoload_libs()

import psutil
import pythoncom
from pycaw.pycaw import AudioUtilities, ISimpleAudioVolume

if OPTIONAL_AVAILABLE["geoip2"]:
    import geoip2.database
if OPTIONAL_AVAILABLE["requests"]:
    import requests

# === CONFIG ===
LOG_FILE = "audio_weapon_console_log.txt"
RULES_FILE = "audio_weapon_rules.json"
AUTO_REFRESH_INTERVAL = 3  # seconds

GEOLITE2_CITY_DB = "GeoLite2-City.mmdb"
GEOLITE2_ASN_DB = "GeoLite2-ASN.mmdb"

VT_API_KEY = ""  # put your VT key here if you want VT reputation

THREAT_SCORE_PORT_RISK = {22: 30, 3389: 40, 5900: 35}
HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP"}

# === RULES / STATE ===
BLOCKLIST = set()
ALLOWLIST = set()
AUTO_KILL_RULES = {
    "high_threat_score": 90,
}
AUTO_MUTE_RULES = {
    "medium_threat_score": 60,
}
AUTO_QUARANTINE_RULES = {
    "quarantine_score": 80,
}
AUTO_BLOCK_IP_RULES = {
    "block_score": 85,
}

LAST_ROWS = []

BANDWIDTH_STATE = {}  # pid -> {last_sent, last_recv, last_ts}
HASH_REP_CACHE = {}   # sha256 -> {malicious, suspicious}

GEOIP_CITY_READER = None
GEOIP_ASN_READER = None


def init_geoip():
    global GEOIP_CITY_READER, GEOIP_ASN_READER
    if not OPTIONAL_AVAILABLE["geoip2"]:
        return
    try:
        if os.path.exists(GEOLITE2_CITY_DB):
            GEOIP_CITY_READER = geoip2.database.Reader(GEOLITE2_CITY_DB)
        if os.path.exists(GEOLITE2_ASN_DB):
            GEOIP_ASN_READER = geoip2.database.Reader(GEOLITE2_ASN_DB)
    except Exception:
        GEOIP_CITY_READER = None
        GEOIP_ASN_READER = None


init_geoip()


def load_rules():
    global BLOCKLIST, ALLOWLIST, AUTO_KILL_RULES, AUTO_MUTE_RULES, AUTO_QUARANTINE_RULES, AUTO_BLOCK_IP_RULES
    if not os.path.exists(RULES_FILE):
        return
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        BLOCKLIST = set(data.get("blocklist", []))
        ALLOWLIST = set(data.get("allowlist", []))
        AUTO_KILL_RULES = data.get("auto_kill_rules", AUTO_KILL_RULES)
        AUTO_MUTE_RULES = data.get("auto_mute_rules", AUTO_MUTE_RULES)
        AUTO_QUARANTINE_RULES = data.get("auto_quarantine_rules", AUTO_QUARANTINE_RULES)
        AUTO_BLOCK_IP_RULES = data.get("auto_block_ip_rules", AUTO_BLOCK_IP_RULES)
    except Exception:
        pass


def save_rules():
    data = {
        "blocklist": list(BLOCKLIST),
        "allowlist": list(ALLOWLIST),
        "auto_kill_rules": AUTO_KILL_RULES,
        "auto_mute_rules": AUTO_MUTE_RULES,
        "auto_quarantine_rules": AUTO_QUARANTINE_RULES,
        "auto_block_ip_rules": AUTO_BLOCK_IP_RULES,
    }
    try:
        with open(RULES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def write_log(message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    return line


def geoip_lookup(ip):
    if not OPTIONAL_AVAILABLE["geoip2"]:
        return {"country": "UNK", "asn": None, "org": None}
    if GEOIP_CITY_READER is None or GEOIP_ASN_READER is None:
        return {"country": "UNK", "asn": None, "org": None}
    try:
        city = GEOIP_CITY_READER.city(ip)
        asn = GEOIP_ASN_READER.asn(ip)
        return {
            "country": city.country.iso_code or "UNK",
            "asn": asn.autonomous_system_number,
            "org": asn.autonomous_system_organization,
        }
    except Exception:
        return {"country": "UNK", "asn": None, "org": None}


def vt_hash_reputation(sha256):
    if not OPTIONAL_AVAILABLE["requests"]:
        return {"malicious": 0, "suspicious": 0}
    if not VT_API_KEY or sha256 == "UNKNOWN":
        return {"malicious": 0, "suspicious": 0}
    if sha256 in HASH_REP_CACHE:
        return HASH_REP_CACHE[sha256]
    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(url, headers=headers, timeout=5)
        if r.status_code != 200:
            rep = {"malicious": 0, "suspicious": 0}
        else:
            data = r.json()
            stats = data["data"]["attributes"]["last_analysis_stats"]
            rep = {
                "malicious": stats.get("malicious", 0),
                "suspicious": stats.get("suspicious", 0),
            }
        HASH_REP_CACHE[sha256] = rep
        return rep
    except Exception:
        return {"malicious": 0, "suspicious": 0}


def compute_hash(path):
    try:
        with open(path, "rb") as f:
            data = f.read(4096)
        return hashlib.sha256(data).hexdigest()
    except Exception:
        return "UNKNOWN"


def compute_bandwidth(pid, conn_bytes_sent, conn_bytes_recv):
    now = time.time()
    state = BANDWIDTH_STATE.get(pid)
    if state is None:
        BANDWIDTH_STATE[pid] = {
            "last_sent": conn_bytes_sent,
            "last_recv": conn_bytes_recv,
            "last_ts": now,
        }
        return 0, 0
    dt = now - state["last_ts"]
    if dt <= 0:
        return 0, 0
    ds = max(0, conn_bytes_sent - state["last_sent"])
    dr = max(0, conn_bytes_recv - state["last_recv"])
    up_kbps = (ds / dt) / 1024.0
    down_kbps = (dr / dt) / 1024.0
    BANDWIDTH_STATE[pid] = {
        "last_sent": conn_bytes_sent,
        "last_recv": conn_bytes_recv,
        "last_ts": now,
    }
    return int(up_kbps), int(down_kbps)


def compute_threat_score(info):
    score = 0

    if info["volume"] > 0.7:
        score += 20

    for port in info["ports"]:
        score += THREAT_SCORE_PORT_RISK.get(port, 0)

    for c in info["countries"]:
        if c in HIGH_RISK_COUNTRIES:
            score += 30

    up, down = info["bandwidth"]
    if down > 500:
        score += 20
    if up > 300:
        score += 15

    cpu = info.get("cpu", 0)
    mem = info.get("mem", 0)
    threads = info.get("threads", 0)
    conns_count = info.get("conns_count", 0)

    if cpu > 50:
        score += 10
    if mem > 300:  # MB
        score += 10
    if threads > 50:
        score += 10
    if conns_count > 20:
        score += 15

    if info["exe_name"].lower() in BLOCKLIST:
        score += 50
    if info["exe_name"].lower() in ALLOWLIST:
        score -= 40

    rep = info.get("vt_rep", {"malicious": 0, "suspicious": 0})
    score += rep["malicious"] * 5
    score += rep["suspicious"] * 3

    return max(0, min(score, 100))


def classify_threat(score):
    if score >= 90:
        return "Critical"
    if score >= 70:
        return "High"
    if score >= 40:
        return "Medium"
    if score >= 20:
        return "Low"
    return "Info"


def process_tree_string(proc):
    try:
        chain = []
        p = proc
        while p:
            chain.append(f"{p.name()} (PID {p.pid})")
            p = p.parent()
        return " → ".join(chain)
    except Exception:
        return "UNKNOWN TREE"


def firewall_block_ip(ip):
    try:
        cmd = f'netsh advfirewall firewall add rule name="AudioWeaponBlock_{ip}" dir=out action=block remoteip={ip}'
        os.system(cmd)
        return True
    except Exception:
        return False


class AudioWeaponConsole(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Audio Weapon Console v5 — Mini EDR")
        self.geometry("1200x720")

        self.auto_refresh_enabled = tk.BooleanVar(value=True)
        self.alerts_enabled = tk.BooleanVar(value=True)

        self.filter_text = tk.StringVar(value="")
        self.filter_threat = tk.StringVar(value="ALL")

        load_rules()
        self._build_ui()
        self._start_auto_refresh()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=8, pady=4)

        ttk.Button(top, text="Manual Refresh", command=self.refresh_all).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(top, text="Auto Refresh", variable=self.auto_refresh_enabled).pack(side=tk.LEFT, padx=4)

        self.alert_button = tk.Button(
            top,
            text="ALERTS: ON",
            command=self.toggle_alerts,
            fg="green"
        )
        self.alert_button.pack(side=tk.LEFT, padx=8)

        ttk.Button(top, text="Edit Rules", command=self.edit_rules_popup).pack(side=tk.LEFT, padx=4)

        ttk.Label(top, text="Filter:").pack(side=tk.LEFT, padx=(20, 2))
        filter_entry = ttk.Entry(top, textvariable=self.filter_text, width=20)
        filter_entry.pack(side=tk.LEFT, padx=2)
        filter_entry.bind("<Return>", lambda e: self.apply_filters())

        ttk.Button(top, text="Apply", command=self.apply_filters).pack(side=tk.LEFT, padx=2)
        ttk.Button(top, text="Clear", command=self.clear_filters).pack(side=tk.LEFT, padx=2)

        threat_frame = ttk.Frame(top)
        threat_frame.pack(side=tk.RIGHT, padx=4)
        ttk.Label(threat_frame, text="Threat:").pack(side=tk.LEFT, padx=(0, 2))
        for level in ["ALL", "Critical", "High", "Medium", "Low", "Info"]:
            ttk.Button(
                threat_frame,
                text=level,
                command=lambda lv=level: self.set_threat_filter(lv),
                width=7
            ).pack(side=tk.LEFT, padx=1)

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=4)

        # Main table tab
        self.table_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.table_frame, text="Audio + Network")

        self.tree = ttk.Treeview(
            self.table_frame,
            columns=(
                "pid", "name", "volume", "muted",
                "cpu", "mem", "threads",
                "local_ip", "remote_ip",
                "country", "up", "down",
                "parent", "exe", "hash",
                "threat", "score"
            ),
            show="headings",
            height=16
        )

        headings = {
            "pid": "PID",
            "name": "Process",
            "volume": "Vol",
            "muted": "Muted",
            "cpu": "CPU%",
            "mem": "Mem MB",
            "threads": "Threads",
            "local_ip": "Local IP",
            "remote_ip": "Remote IP",
            "country": "Country",
            "up": "Up KB/s",
            "down": "Down KB/s",
            "parent": "Parent",
            "exe": "Exe Path",
            "hash": "SHA256 (partial)",
            "threat": "Threat",
            "score": "Score",
        }

        widths = {
            "pid": 60,
            "name": 150,
            "volume": 60,
            "muted": 60,
            "cpu": 60,
            "mem": 70,
            "threads": 70,
            "local_ip": 110,
            "remote_ip": 120,
            "country": 70,
            "up": 70,
            "down": 70,
            "parent": 120,
            "exe": 220,
            "hash": 180,
            "threat": 80,
            "score": 60,
        }

        for col in self.tree["columns"]:
            self.tree.heading(col, text=headings[col])
            self.tree.column(
                col,
                width=widths[col],
                anchor=tk.CENTER
                if col in ("pid", "volume", "muted", "cpu", "mem", "threads", "country", "up", "down", "score")
                else tk.W,
            )

        self.tree.tag_configure("Critical", background="#ff4d4d")
        self.tree.tag_configure("High", background="#ff944d")
        self.tree.tag_configure("Medium", background="#ffe680")
        self.tree.tag_configure("Low", background="#e6ffe6")
        self.tree.tag_configure("Info", background="#f2f2f2")

        self.tree.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)
        self.tree.bind("<Double-1>", self.show_details_popup)

        table_bottom = ttk.Frame(self.table_frame)
        table_bottom.pack(fill=tk.X, padx=4, pady=4)

        ttk.Button(table_bottom, text="Kill", command=self.kill_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(table_bottom, text="Mute", command=self.mute_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(table_bottom, text="Unmute", command=self.unmute_selected).pack(side=tk.LEFT, padx=3)

        ttk.Button(table_bottom, text="Quarantine", command=self.quarantine_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(table_bottom, text="Block IP", command=self.block_ip_selected).pack(side=tk.LEFT, padx=3)

        ttk.Button(table_bottom, text="Blocklist +", command=self.add_blocklist_selected).pack(side=tk.LEFT, padx=3)
        ttk.Button(table_bottom, text="Allowlist +", command=self.add_allowlist_selected).pack(side=tk.LEFT, padx=3)

        ttk.Label(table_bottom, text="Vol:").pack(side=tk.LEFT, padx=(12, 2))
        self.volume_scale = ttk.Scale(
            table_bottom,
            from_=0,
            to=100,
            orient=tk.HORIZONTAL,
            command=self.set_volume_selected,
        )
        self.volume_scale.pack(side=tk.LEFT, padx=3, fill=tk.X, expand=True)

        # Timeline / log tab
        self.timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.timeline_frame, text="Timeline / Log")

        self.log_box = scrolledtext.ScrolledText(self.timeline_frame, height=18, wrap=tk.WORD)
        self.log_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Threat graphs tab (simple bar graphs)
        self.graph_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.graph_frame, text="Threat Graphs")

        self.graph_canvas = tk.Canvas(self.graph_frame, bg="black")
        self.graph_canvas.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Process tree tab (text-based)
        self.tree_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.tree_frame, text="Process Trees")

        self.proc_tree_box = scrolledtext.ScrolledText(self.tree_frame, height=18, wrap=tk.WORD)
        self.proc_tree_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, padx=8, pady=4)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.status).pack(side=tk.LEFT, padx=4)

        self._update_alert_button_style()

    def add_log(self, message):
        line = write_log(message)
        self.log_box.insert(tk.END, line)
        self.log_box.see(tk.END)

    def toggle_alerts(self):
        self.alerts_enabled.set(not self.alerts_enabled.get())
        self._update_alert_button_style()
        state = "ON" if self.alerts_enabled.get() else "OFF"
        self.add_log(f"Alerts toggled {state}")

    def _update_alert_button_style(self):
        if self.alerts_enabled.get():
            self.alert_button.configure(text="ALERTS: ON", fg="green")
        else:
            self.alert_button.configure(text="ALERTS: OFF", fg="red")

    def _start_auto_refresh(self):
        def loop():
            while True:
                if self.auto_refresh_enabled.get():
                    self.refresh_all()
                threading.Event().wait(AUTO_REFRESH_INTERVAL)
        t = threading.Thread(target=loop, daemon=True)
        t.start()

    def refresh_all(self):
        pythoncom.CoInitialize()
        try:
            sessions = AudioUtilities.GetAllSessions()
        except Exception as e:
            self.add_log(f"ERROR: Audio session fetch failed: {e}")
            self.status.set(f"Audio error: {e}")
            return

        LAST_ROWS.clear()
        for item in self.tree.get_children():
            self.tree.delete(item)

        self.proc_tree_box.delete("1.0", tk.END)
        self.graph_canvas.delete("all")

        self.add_log("Refreshing audio + network + threat view...")

        threat_scores_for_graph = []

        for session in sessions:
            try:
                volume_obj = session._ctl.QueryInterface(ISimpleAudioVolume)
                vol_level = volume_obj.GetMasterVolume()
                muted = volume_obj.GetMute()

                pid = session.Process.pid if session.Process else None
                name = session.Process.name() if session.Process else "System"

                local_ip = "-"
                remote_ip = "-"
                countries = set()
                ports = set()

                parent_name = "-"
                exe_path = "-"
                hash_short = "-"
                up_kbps = 0
                down_kbps = 0
                vt_rep = {"malicious": 0, "suspicious": 0}
                asn = None
                org = None

                cpu = 0.0
                mem_mb = 0.0
                threads = 0
                conns_count = 0
                tree_str = "UNKNOWN"

                if pid is not None:
                    try:
                        proc = psutil.Process(pid)
                        exe_path = proc.exe() or "-"
                        parent = proc.parent()
                        parent_name = parent.name() if parent else "-"
                        cpu = proc.cpu_percent(interval=0.0)
                        mem_mb = proc.memory_info().rss / (1024 * 1024)
                        threads = proc.num_threads()
                        conns = proc.connections(kind="inet")
                        conns_count = len(conns)
                        tree_str = process_tree_string(proc)

                        total_sent = 0
                        total_recv = 0

                        for c in conns:
                            if c.laddr:
                                local_ip = c.laddr.ip
                            if c.raddr:
                                remote_ip = c.raddr.ip
                                ports.add(c.raddr.port)
                                gi = geoip_lookup(c.raddr.ip)
                                countries.add(gi["country"])
                                asn = gi["asn"]
                                org = gi["org"]

                            try:
                                io = proc.io_counters()
                                total_sent = io.write_bytes
                                total_recv = io.read_bytes
                            except Exception:
                                pass

                        up_kbps, down_kbps = compute_bandwidth(pid, total_sent, total_recv)

                    except Exception:
                        pass

                    file_hash = compute_hash(exe_path) if exe_path not in ("-", "") else "UNKNOWN"
                    hash_short = file_hash[:16]
                    vt_rep = vt_hash_reputation(file_hash)

                info = {
                    "pid": pid,
                    "name": name,
                    "volume": vol_level,
                    "muted": muted,
                    "local_ip": local_ip,
                    "local_port": "-",
                    "remote_ip": remote_ip,
                    "remote_port": "-",
                    "countries": list(countries),
                    "ports": list(ports),
                    "bandwidth": (up_kbps, down_kbps),
                    "parent_name": parent_name,
                    "exe_path": exe_path,
                    "exe_name": name,
                    "hash_short": hash_short,
                    "vt_rep": vt_rep,
                    "asn": asn,
                    "org": org,
                    "cpu": cpu,
                    "mem": int(mem_mb),
                    "threads": threads,
                    "conns_count": conns_count,
                    "tree_str": tree_str,
                }

                threat_score = compute_threat_score(info)
                threat_level = classify_threat(threat_score)
                threat_scores_for_graph.append(threat_score)

                row = {
                    "info": info,
                    "threat_score": threat_score,
                    "threat_level": threat_level,
                    "volume_obj": volume_obj,
                }
                LAST_ROWS.append(row)

                tag = threat_level if threat_level in ["Critical", "High", "Medium", "Low", "Info"] else "Info"

                self.tree.insert(
                    "",
                    tk.END,
                    values=(
                        pid,
                        name,
                        f"{int(vol_level * 100)}%",
                        "Yes" if muted else "No",
                        int(cpu),
                        int(mem_mb),
                        threads,
                        local_ip,
                        remote_ip,
                        ",".join(info["countries"]) if info["countries"] else "-",
                        up_kbps,
                        down_kbps,
                        parent_name,
                        exe_path,
                        hash_short,
                        threat_level,
                        threat_score,
                    ),
                    tags=(tag,)
                )

                self.proc_tree_box.insert(
                    tk.END,
                    f"{name} (PID {pid})\n  Tree: {tree_str}\n  Threat: {threat_level} ({threat_score})\n\n"
                )

                self.add_log(
                    f"PID={pid} Name={name} Vol={int(vol_level*100)}% "
                    f"CPU={int(cpu)}% Mem={int(mem_mb)}MB Threads={threads} Conns={conns_count} "
                    f"L={local_ip} R={remote_ip} Countries={info['countries']} BW={up_kbps}/{down_kbps}KB/s "
                    f"VT={vt_rep} Threat={threat_level}({threat_score})"
                )

                self._apply_auto_rules(info, threat_level, threat_score, volume_obj)

                if self.alerts_enabled.get() and threat_score >= AUTO_KILL_RULES.get("high_threat_score", 90):
                    self._raise_alert(info, threat_level, threat_score)

            except Exception:
                continue

        self._draw_threat_graph(threat_scores_for_graph)
        self.status.set("Audio + network + threat view refreshed")

    def _draw_threat_graph(self, scores):
        self.graph_canvas.delete("all")
        if not scores:
            return
        w = self.graph_canvas.winfo_width() or 800
        h = self.graph_canvas.winfo_height() or 300
        n = len(scores)
        bar_width = max(4, w / max(n, 1))

        for i, s in enumerate(scores):
            x0 = i * bar_width
            x1 = x0 + bar_width - 2
            bar_height = (s / 100.0) * (h - 20)
            y0 = h - bar_height
            y1 = h

            color = "#00ff00"
            if s >= 90:
                color = "#ff0000"
            elif s >= 70:
                color = "#ff8000"
            elif s >= 40:
                color = "#ffff00"

            self.graph_canvas.create_rectangle(x0, y0, x1, y1, fill=color, outline="")
        self.graph_canvas.create_text(10, 10, anchor="nw", fill="white", text="Threat Scores")

    def _apply_auto_rules(self, info, level, score, volume_obj):
        name = info["name"]
        pid = info["pid"]

        if name and name.lower() in ALLOWLIST:
            return

        if name and name.lower() in BLOCKLIST:
            if pid is not None:
                self.add_log(f"AUTO-KILL (blocklist) PID={pid} Name={name}")
                self._kill_pid(pid, name)
            return

        kill_threshold = AUTO_KILL_RULES.get("high_threat_score", 90)
        if score >= kill_threshold and pid is not None:
            self.add_log(f"AUTO-KILL (score) PID={pid} Name={name} Score={score}")
            self._kill_pid(pid, name)
            return

        quarantine_threshold = AUTO_QUARANTINE_RULES.get("quarantine_score", 80)
        if score >= quarantine_threshold and pid is not None:
            self.add_log(f"AUTO-QUARANTINE PID={pid} Name={name} Score={score}")
            self._quarantine_pid(pid, name)

        mute_threshold = AUTO_MUTE_RULES.get("medium_threat_score", 60)
        if score >= mute_threshold and pid is not None:
            try:
                volume_obj.SetMute(True, None)
                self.add_log(f"AUTO-MUTE PID={pid} Name={name} Score={score}")
            except Exception:
                pass

        block_threshold = AUTO_BLOCK_IP_RULES.get("block_score", 85)
        if score >= block_threshold and info["remote_ip"] not in ("-", "", None):
            ip = info["remote_ip"]
            ok = firewall_block_ip(ip)
            if ok:
                self.add_log(f"AUTO-BLOCK IP={ip} for PID={pid} Name={name}")

    def _raise_alert(self, info, level, score):
        msg = (
            f"Suspicious audio/network activity detected!\n\n"
            f"Process: {info['name']}\n"
            f"PID: {info['pid']}\n"
            f"Exe: {info['exe_path']}\n"
            f"Parent: {info['parent_name']}\n"
            f"Volume: {int(info['volume'] * 100)}%\n"
            f"CPU: {info.get('cpu', 0)}% Mem: {info.get('mem', 0)} MB Threads: {info.get('threads', 0)}\n"
            f"Local: {info['local_ip']}\n"
            f"Remote: {info['remote_ip']}\n"
            f"Countries: {info['countries']}\n"
            f"Ports: {info['ports']}\n"
            f"Bandwidth: Up {info['bandwidth'][0]} KB/s, Down {info['bandwidth'][1]} KB/s\n"
            f"VT: {info['vt_rep']}\n"
            f"ASN: {info['asn']} Org: {info['org']}\n"
            f"Threat Level: {level}\n"
            f"Threat Score: {score}\n\n"
            f"Do you want to kill this process now?"
        )
        self.add_log(f"ALERT: {info['name']} PID={info['pid']} Threat={level}({score})")
        answer = messagebox.askyesno("Audio Weapon Console — ALERT", msg)
        if answer and info["pid"] is not None:
            self._kill_pid(info["pid"], info["name"])

    def _get_selected(self):
        selected = self.tree.selection()
        if not selected:
            return None
        item = self.tree.item(selected[0])
        vals = item["values"]
        return {
            "pid": vals[0],
            "name": vals[1],
            "remote_ip": vals[8],
        }

    def _kill_pid(self, pid, name):
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            gone, alive = psutil.wait_procs([proc], timeout=3)
            for p in alive:
                p.kill()
            self.add_log(f"KILLED PID={pid} Name={name}")
            self.status.set(f"Killed {name} (PID {pid})")
        except Exception as e:
            self.add_log(f"Kill FAILED PID={pid} Name={name} Error={e}")
            messagebox.showerror("Error", f"Failed to kill process: {e}")
            self.status.set(f"Kill error: {e}")

    def _quarantine_pid(self, pid, name):
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            self.add_log(f"QUARANTINED PID={pid} Name={name}")
            self.status.set(f"Quarantined {name} (PID {pid})")
        except Exception as e:
            self.add_log(f"Quarantine FAILED PID={pid} Name={name} Error={e}")
            self.status.set(f"Quarantine error: {e}")

    def kill_selected(self):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            messagebox.showwarning("No selection", "Select a process with a valid PID.")
            return
        answer = messagebox.askyesno(
            "Confirm Kill",
            f"Kill process {sel['name']} (PID {sel['pid']})?"
        )
        if not answer:
            return
        self._kill_pid(sel["pid"], sel["name"])
        self.refresh_all()

    def quarantine_selected(self):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            messagebox.showwarning("No selection", "Select a process with a valid PID.")
            return
        answer = messagebox.askyesno(
            "Confirm Quarantine",
            f"Quarantine process {sel['name']} (PID {sel['pid']})?"
        )
        if not answer:
            return
        self._quarantine_pid(sel["pid"], sel["name"])
        self.refresh_all()

    def block_ip_selected(self):
        sel = self._get_selected()
        ip = sel["remote_ip"]
        if not ip or ip in ("-", ""):
            messagebox.showwarning("No IP", "Selected process has no remote IP.")
            return
        answer = messagebox.askyesno(
            "Confirm Block IP",
            f"Block remote IP {ip} via firewall?"
        )
        if not answer:
            return
        ok = firewall_block_ip(ip)
        if ok:
            self.add_log(f"MANUAL BLOCK IP={ip} for PID={sel['pid']} Name={sel['name']}")
            self.status.set(f"Blocked IP {ip}")
        else:
            self.status.set("Firewall block failed")

    def _set_mute_state(self, pid, mute):
        pythoncom.CoInitialize()
        try:
            sessions = AudioUtilities.GetAllSessions()
        except Exception:
            return
        for session in sessions:
            try:
                spid = session.Process.pid if session.Process else None
                if spid == pid:
                    volume_obj = session._ctl.QueryInterface(ISimpleAudioVolume)
                    volume_obj.SetMute(mute, None)
            except Exception:
                continue

    def mute_selected(self):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            messagebox.showwarning("No selection", "Select a process with a valid PID.")
            return
        self._set_mute_state(sel["pid"], True)
        self.add_log(f"MUTED PID={sel['pid']} Name={sel['name']}")
        self.status.set(f"Muted {sel['name']} (PID {sel['pid']})")
        self.refresh_all()

    def unmute_selected(self):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            messagebox.showwarning("No selection", "Select a process with a valid PID.")
            return
        self._set_mute_state(sel["pid"], False)
        self.add_log(f"UNMUTED PID={sel['pid']} Name={sel['name']}")
        self.status.set(f"Unmuted {sel['name']} (PID {sel['pid']})")
        self.refresh_all()

    def set_volume_selected(self, value):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            return
        vol = float(value) / 100.0
        pythoncom.CoInitialize()
        try:
            sessions = AudioUtilities.GetAllSessions()
        except Exception:
            return
        for session in sessions:
            try:
                spid = session.Process.pid if session.Process else None
                if spid == sel["pid"]:
                    volume_obj = session._ctl.QueryInterface(ISimpleAudioVolume)
                    volume_obj.SetMasterVolume(vol, None)
            except Exception:
                continue
        self.add_log(f"SET VOLUME PID={sel['pid']} Name={sel['name']} Vol={int(float(value))}%")
        self.status.set(f"Volume set for {sel['name']} (PID {sel['pid']})")
        self.refresh_all()

    def add_blocklist_selected(self):
        sel = self._get_selected()
        if not sel or sel["name"] is None:
            messagebox.showwarning("No selection", "Select a process first.")
            return
        BLOCKLIST.add(sel["name"].lower())
        save_rules()
        self.add_log(f"BLOCKLIST ADD: {sel['name']}")
        self.status.set(f"Added {sel['name']} to blocklist.")
        self.refresh_all()

    def add_allowlist_selected(self):
        sel = self._get_selected()
        if not sel or sel["name"] is None:
            messagebox.showwarning("No selection", "Select a process first.")
            return
        ALLOWLIST.add(sel["name"].lower())
        save_rules()
        self.add_log(f"ALLOWLIST ADD: {sel['name']}")
        self.status.set(f"Added {sel['name']} to allowlist.")
        self.refresh_all()

    def edit_rules_popup(self):
        win = tk.Toplevel(self)
        win.title("Edit Rules")
        win.geometry("420x320")

        ttk.Label(win, text="Auto-Kill Score ≥").pack(pady=(8, 2))
        kill_var = tk.StringVar(value=str(AUTO_KILL_RULES.get("high_threat_score", 90)))
        kill_entry = ttk.Entry(win, textvariable=kill_var)
        kill_entry.pack(pady=2)

        ttk.Label(win, text="Auto-Mute Score ≥").pack(pady=(8, 2))
        mute_var = tk.StringVar(value=str(AUTO_MUTE_RULES.get("medium_threat_score", 60)))
        mute_entry = ttk.Entry(win, textvariable=mute_var)
        mute_entry.pack(pady=2)

        ttk.Label(win, text="Auto-Quarantine Score ≥").pack(pady=(8, 2))
        q_var = tk.StringVar(value=str(AUTO_QUARANTINE_RULES.get("quarantine_score", 80)))
        q_entry = ttk.Entry(win, textvariable=q_var)
        q_entry.pack(pady=2)

        ttk.Label(win, text="Auto-Block IP Score ≥").pack(pady=(8, 2))
        b_var = tk.StringVar(value=str(AUTO_BLOCK_IP_RULES.get("block_score", 85)))
        b_entry = ttk.Entry(win, textvariable=b_var)
        b_entry.pack(pady=2)

        def save():
            try:
                AUTO_KILL_RULES["high_threat_score"] = int(kill_var.get())
                AUTO_MUTE_RULES["medium_threat_score"] = int(mute_var.get())
                AUTO_QUARANTINE_RULES["quarantine_score"] = int(q_var.get())
                AUTO_BLOCK_IP_RULES["block_score"] = int(b_var.get())
                save_rules()
                self.add_log(
                    f"RULES UPDATED: kill≥{AUTO_KILL_RULES['high_threat_score']} "
                    f"mute≥{AUTO_MUTE_RULES['medium_threat_score']} "
                    f"quarantine≥{AUTO_QUARANTINE_RULES['quarantine_score']} "
                    f"blockIP≥{AUTO_BLOCK_IP_RULES['block_score']}"
                )
                win.destroy()
            except Exception:
                messagebox.showerror("Error", "Invalid values.")

        ttk.Button(win, text="Save", command=save).pack(pady=12)

    def set_threat_filter(self, level):
        self.filter_threat.set(level)
        self.apply_filters()

    def apply_filters(self):
        text = self.filter_text.get().strip().lower()
        level = self.filter_threat.get()

        for item in self.tree.get_children():
            self.tree.delete(item)

        for row in LAST_ROWS:
            info = row["info"]
            threat_level = row["threat_level"]
            threat_score = row["threat_score"]

            if level != "ALL" and threat_level != level:
                continue

            if text:
                haystack = " ".join([
                    str(info["pid"]),
                    info["name"] or "",
                    info["local_ip"] or "",
                    info["remote_ip"] or "",
                    info["exe_path"] or "",
                ]).lower()
                if text not in haystack:
                    continue

            tag = threat_level if threat_level in ["Critical", "High", "Medium", "Low", "Info"] else "Info"

            self.tree.insert(
                "",
                tk.END,
                values=(
                    info["pid"],
                    info["name"],
                    f"{int(info['volume'] * 100)}%",
                    "Yes" if info["muted"] else "No",
                    info.get("cpu", 0),
                    info.get("mem", 0),
                    info.get("threads", 0),
                    info["local_ip"],
                    info["remote_ip"],
                    ",".join(info["countries"]) if info["countries"] else "-",
                    info["bandwidth"][0],
                    info["bandwidth"][1],
                    info["parent_name"],
                    info["exe_path"],
                    info["hash_short"],
                    threat_level,
                    threat_score,
                ),
                tags=(tag,)
            )

        self.status.set("Filters applied")

    def clear_filters(self):
        self.filter_text.set("")
        self.filter_threat.set("ALL")
        self.apply_filters()

    def show_details_popup(self, event):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            return

        pid = sel["pid"]
        row_info = None
        for row in LAST_ROWS:
            if row["info"]["pid"] == pid:
                row_info = row
                break
        if not row_info:
            return

        info = row_info["info"]
        level = row_info["threat_level"]
        score = row_info["threat_score"]

        win = tk.Toplevel(self)
        win.title(f"Details — {info['name']} (PID {info['pid']})")
        win.geometry("540x520")

        text = scrolledtext.ScrolledText(win, wrap=tk.WORD)
        text.pack(fill=tk.BOTH, expand=True, padx=6, pady=6)

        details = (
            f"Process: {info['name']}\n"
            f"PID: {info['pid']}\n"
            f"Exe Path: {info['exe_path']}\n"
            f"Parent: {info['parent_name']}\n"
            f"Process Tree: {info.get('tree_str', 'UNKNOWN')}\n\n"
            f"Volume: {int(info['volume'] * 100)}%\n"
            f"Muted: {'Yes' if info['muted'] else 'No'}\n"
            f"CPU: {info.get('cpu', 0)}%  Mem: {info.get('mem', 0)} MB  Threads: {info.get('threads', 0)}\n"
            f"Connections: {info.get('conns_count', 0)}\n\n"
            f"Local: {info['local_ip']}:{info.get('local_port', '-')}\n"
            f"Remote: {info['remote_ip']}:{info.get('remote_port', '-')}\n"
            f"Countries: {info['countries']}\n"
            f"Ports: {info['ports']}\n"
            f"Bandwidth: Up {info['bandwidth'][0]} KB/s, Down {info['bandwidth'][1]} KB/s\n\n"
            f"SHA256 (partial): {info['hash_short']}\n"
            f"VT Reputation: {info['vt_rep']}\n"
            f"ASN: {info['asn']} Org: {info['org']}\n\n"
            f"Threat Level: {level}\n"
            f"Threat Score: {score}\n"
        )

        text.insert(tk.END, details)
        text.config(state=tk.DISABLED)


def main():
    app = AudioWeaponConsole()
    app.mainloop()


if __name__ == "__main__":
    main()
