# === AUDIO WEAPON CONSOLE v6.1 — Engine + Event Bus + Baselines + Timeline + Defense + ML Stub ===
# Fixes:
# - Proper engine thread COM initialization
# - Correct shared snapshot update (no rebinding)
# - GUI shows “no sessions” status when empty
# - Safer snapshot copy for GUI

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
    "geoip2": "geoip2",
    "requests": "requests",
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

# === CONFIG / FILES ===
LOG_FILE = "audio_weapon_console_log.txt"
RULES_FILE = "audio_weapon_rules.json"
BASELINES_FILE = "audio_weapon_baselines.json"
TIMELINE_FILE = "audio_weapon_timeline.json"

AUTO_REFRESH_INTERVAL = 3  # GUI polling
ENGINE_SCAN_INTERVAL = 3   # engine scan

GEOLITE2_CITY_DB = "GeoLite2-City.mmdb"
GEOLITE2_ASN_DB = "GeoLite2-ASN.mmdb"

VT_API_KEY = ""  # optional

THREAT_SCORE_PORT_RISK = {22: 30, 3389: 40, 5900: 35}
HIGH_RISK_COUNTRIES = {"RU", "CN", "IR", "KP"}

# === RULES / STATE ===
BLOCKLIST = set()
ALLOWLIST = set()
AUTO_KILL_RULES = {"high_threat_score": 90}
AUTO_MUTE_RULES = {"medium_threat_score": 60}
AUTO_QUARANTINE_RULES = {"quarantine_score": 80}
AUTO_BLOCK_IP_RULES = {"block_score": 85}

BANDWIDTH_STATE = {}
HASH_REP_CACHE = {}

GEOIP_CITY_READER = None
GEOIP_ASN_READER = None

BASELINES = {}          # exe_name -> stats
TIMELINE = []           # list of events
EVENT_SUBSCRIBERS = {}  # event_type -> [callbacks]
ENGINE_LOCK = threading.Lock()
ENGINE_LAST_SNAPSHOT = []  # list of info dicts


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


def load_baselines():
    global BASELINES
    if not os.path.exists(BASELINES_FILE):
        BASELINES = {}
        return
    try:
        with open(BASELINES_FILE, "r", encoding="utf-8") as f:
            BASELINES = json.load(f)
    except Exception:
        BASELINES = {}


def save_baselines():
    try:
        with open(BASELINES_FILE, "w", encoding="utf-8") as f:
            json.dump(BASELINES, f, indent=2)
    except Exception:
        pass


def load_timeline():
    global TIMELINE
    if not os.path.exists(TIMELINE_FILE):
        TIMELINE = []
        return
    try:
        with open(TIMELINE_FILE, "r", encoding="utf-8") as f:
            TIMELINE = json.load(f)
    except Exception:
        TIMELINE = []


def save_timeline():
    try:
        with open(TIMELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(TIMELINE, f, indent=2)
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


def publish_event(event_type, payload):
    ts = datetime.now().isoformat()
    event = {
        "timestamp": ts,
        "type": event_type,
        "payload": payload,
    }
    TIMELINE.append(event)
    if event_type in EVENT_SUBSCRIBERS:
        for cb in EVENT_SUBSCRIBERS[event_type]:
            try:
                cb(event)
            except Exception:
                continue


def subscribe_event(event_type, callback):
    EVENT_SUBSCRIBERS.setdefault(event_type, []).append(callback)


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


def process_tree_string(proc):
    try:
        chain = []
        p = proc
        while p:
            chain.append(f"{p.name()}({p.pid})")
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


def update_baseline(info):
    name = info["exe_name"].lower()
    cpu = info.get("cpu", 0)
    mem = info.get("mem", 0)
    bw_down = info["bandwidth"][1]
    entry = BASELINES.get(name, {"cpu_avg": 0, "mem_avg": 0, "bw_avg": 0, "count": 0})
    c = entry["count"] + 1
    entry["cpu_avg"] = (entry["cpu_avg"] * entry["count"] + cpu) / c
    entry["mem_avg"] = (entry["mem_avg"] * entry["count"] + mem) / c
    entry["bw_avg"] = (entry["bw_avg"] * entry["count"] + bw_down) / c
    entry["count"] = c
    BASELINES[name] = entry


def baseline_deviation(info):
    name = info["exe_name"].lower()
    base = BASELINES.get(name)
    if not base or base["count"] < 5:
        return 0
    cpu = info.get("cpu", 0)
    mem = info.get("mem", 0)
    bw = info["bandwidth"][1]
    dev = 0
    if base["cpu_avg"] > 0 and cpu > base["cpu_avg"] * 3:
        dev += 10
    if base["mem_avg"] > 0 and mem > base["mem_avg"] * 3:
        dev += 10
    if base["bw_avg"] > 0 and bw > base["bw_avg"] * 3:
        dev += 10
    return dev


def ml_threat_classify(info, score):
    rep = info.get("vt_rep", {"malicious": 0, "suspicious": 0})
    mal = rep["malicious"]
    sus = rep["suspicious"]
    cpu = info.get("cpu", 0)
    bw = info["bandwidth"][1]
    if mal >= 5 or score >= 90:
        return "malicious"
    if sus >= 3 or score >= 70:
        return "suspicious"
    if cpu < 5 and bw < 50 and score < 20:
        return "benign"
    if bw > 300 and score >= 40:
        return "remote_control"
    return "unknown"


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
    if mem > 300:
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
    score += baseline_deviation(info)
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


# === ENGINE (BACKGROUND SERVICE) ===

def engine_scan_once():
    pythoncom.CoInitialize()
    try:
        sessions = AudioUtilities.GetAllSessions()
    except Exception as e:
        publish_event("ENGINE_ERROR", {"error": str(e)})
        return []

    if not sessions:
        publish_event("ENGINE_NO_AUDIO_SESSIONS", {})
        return []

    snapshot = []
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
                "remote_ip": remote_ip,
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
                "cpu": int(cpu),
                "mem": int(mem_mb),
                "threads": threads,
                "conns_count": conns_count,
                "tree_str": tree_str,
                "volume_obj": volume_obj,
            }

            update_baseline(info)
            score = compute_threat_score(info)
            level = classify_threat(score)
            ml_class = ml_threat_classify(info, score)

            info["threat_score"] = score
            info["threat_level"] = level
            info["ml_class"] = ml_class

            snapshot.append(info)

            publish_event("SCAN_RESULT", {"info": info})

            if score >= AUTO_KILL_RULES.get("high_threat_score", 90):
                publish_event("THREAT_CRITICAL", {"info": info})
            elif score >= AUTO_QUARANTINE_RULES.get("quarantine_score", 80):
                publish_event("THREAT_HIGH", {"info": info})
            elif score >= AUTO_MUTE_RULES.get("medium_threat_score", 60):
                publish_event("THREAT_MEDIUM", {"info": info})

        except Exception:
            continue

    return snapshot


def engine_defense_handler(event):
    info = event["payload"]["info"]
    name = info["name"]
    pid = info["pid"]
    score = info["threat_score"]
    remote_ip = info["remote_ip"]

    if name and name.lower() in ALLOWLIST:
        return

    if name and name.lower() in BLOCKLIST and pid is not None:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            publish_event("AUTO_KILL", {"pid": pid, "name": name, "reason": "blocklist"})
        except Exception:
            pass
        return

    if score >= AUTO_KILL_RULES.get("high_threat_score", 90) and pid is not None:
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            publish_event("AUTO_KILL", {"pid": pid, "name": name, "reason": "score"})
        except Exception:
            pass
        return

    if score >= AUTO_QUARANTINE_RULES.get("quarantine_score", 80) and pid is not None:
        try:
            proc = psutil.Process(pid)
            proc.suspend()
            publish_event("AUTO_QUARANTINE", {"pid": pid, "name": name})
        except Exception:
            pass

    if score >= AUTO_MUTE_RULES.get("medium_threat_score", 60) and pid is not None:
        try:
            info["volume_obj"].SetMute(True, None)
            publish_event("AUTO_MUTE", {"pid": pid, "name": name})
        except Exception:
            pass

    if score >= AUTO_BLOCK_IP_RULES.get("block_score", 85) and remote_ip not in ("-", "", None):
        if firewall_block_ip(remote_ip):
            publish_event("AUTO_BLOCK_IP", {"ip": remote_ip, "pid": pid, "name": name})


subscribe_event("THREAT_CRITICAL", engine_defense_handler)
subscribe_event("THREAT_HIGH", engine_defense_handler)
subscribe_event("THREAT_MEDIUM", engine_defense_handler)


def engine_loop():
    pythoncom.CoInitialize()  # COM init for engine thread
    load_rules()
    load_baselines()
    load_timeline()

    while True:
        snapshot = engine_scan_once()

        with ENGINE_LOCK:
            ENGINE_LAST_SNAPSHOT.clear()
            ENGINE_LAST_SNAPSHOT.extend(snapshot)

        save_baselines()
        save_timeline()

        print("ENGINE SCAN:", len(snapshot), "items")
        time.sleep(ENGINE_SCAN_INTERVAL)


# === GUI (CLIENT) ===

class AudioWeaponConsole(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Audio Weapon Console v6.1 — Engine/EDR")
        self.geometry("1200x720")

        self.auto_refresh_enabled = tk.BooleanVar(value=True)
        self.alerts_enabled = tk.BooleanVar(value=True)

        self.filter_text = tk.StringVar(value="")
        self.filter_threat = tk.StringVar(value="ALL")

        self._build_ui()
        self._start_gui_refresh()

    def _build_ui(self):
        top = ttk.Frame(self)
        top.pack(fill=tk.X, padx=8, pady=4)

        ttk.Button(top, text="Manual Refresh", command=self.refresh_from_engine).pack(side=tk.LEFT, padx=4)
        ttk.Checkbutton(top, text="Auto Refresh", variable=self.auto_refresh_enabled).pack(side=tk.LEFT, padx=4)

        self.alert_button = tk.Button(top, text="ALERTS: ON", command=self.toggle_alerts, fg="green")
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

        # Main table
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
                "threat", "score", "ml",
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
            "ml": "ML Class",
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
            "ml": 90,
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

        # Timeline / replay
        self.timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.timeline_frame, text="Timeline / Replay")

        self.timeline_box = scrolledtext.ScrolledText(self.timeline_frame, height=18, wrap=tk.WORD)
        self.timeline_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        ttk.Button(self.timeline_frame, text="Reload Timeline", command=self.reload_timeline).pack(pady=4)

        # Bottom status
        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, padx=8, pady=4)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.status).pack(side=tk.LEFT, padx=4)

        self._update_alert_button_style()

    def _start_gui_refresh(self):
        def loop():
            while True:
                if self.auto_refresh_enabled.get():
                    self.refresh_from_engine()
                time.sleep(AUTO_REFRESH_INTERVAL)
        t = threading.Thread(target=loop, daemon=True)
        t.start()

    def toggle_alerts(self):
        self.alerts_enabled.set(not self.alerts_enabled.get())
        self._update_alert_button_style()

    def _update_alert_button_style(self):
        if self.alerts_enabled.get():
            self.alert_button.configure(text="ALERTS: ON", fg="green")
        else:
            self.alert_button.configure(text="ALERTS: OFF", fg="red")

    def refresh_from_engine(self):
        with ENGINE_LOCK:
            snapshot = ENGINE_LAST_SNAPSHOT.copy()

        self.tree.delete(*self.tree.get_children())

        if not snapshot:
            self.status.set("Engine running — no audio sessions detected")
            return

        for info in snapshot:
            level = info["threat_level"]
            score = info["threat_score"]
            ml_class = info["ml_class"]
            tag = level if level in ["Critical", "High", "Medium", "Low", "Info"] else "Info"
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
                    level,
                    score,
                    ml_class,
                ),
                tags=(tag,)
            )
        self.status.set("Refreshed from engine")

    def set_threat_filter(self, level):
        self.filter_threat.set(level)
        self.apply_filters()

    def apply_filters(self):
        text = self.filter_text.get().strip().lower()
        level = self.filter_threat.get()
        self.tree.delete(*self.tree.get_children())
        with ENGINE_LOCK:
            snapshot = ENGINE_LAST_SNAPSHOT.copy()
        if not snapshot:
            self.status.set("Engine running — no audio sessions detected")
            return
        for info in snapshot:
            threat_level = info["threat_level"]
            threat_score = info["threat_score"]
            ml_class = info["ml_class"]
            if level != "ALL" and threat_level != level:
                continue
            if text:
                haystack = " ".join([
                    str(info["pid"]),
                    info["name"] or "",
                    info["local_ip"] or "",
                    info["remote_ip"] or "",
                    info["exe_path"] or "",
                    ml_class or "",
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
                    ml_class,
                ),
                tags=(tag,)
            )
        self.status.set("Filters applied")

    def clear_filters(self):
        self.filter_text.set("")
        self.filter_threat.set("ALL")
        self.apply_filters()

    def _get_selected(self):
        sel = self.tree.selection()
        if not sel:
            return None
        vals = self.tree.item(sel[0])["values"]
        return {
            "pid": vals[0],
            "name": vals[1],
            "remote_ip": vals[8],
        }

    def kill_selected(self):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            messagebox.showwarning("No selection", "Select a process with a valid PID.")
            return
        if not messagebox.askyesno("Confirm Kill", f"Kill {sel['name']} (PID {sel['pid']})?"):
            return
        try:
            proc = psutil.Process(sel["pid"])
            proc.terminate()
            self.status.set(f"Killed {sel['name']} ({sel['pid']})")
        except Exception as e:
            messagebox.showerror("Error", f"Kill failed: {e}")
        self.refresh_from_engine()

    def quarantine_selected(self):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            messagebox.showwarning("No selection", "Select a process with a valid PID.")
            return
        if not messagebox.askyesno("Confirm Quarantine", f"Quarantine {sel['name']} (PID {sel['pid']})?"):
            return
        try:
            proc = psutil.Process(sel["pid"])
            proc.suspend()
            self.status.set(f"Quarantined {sel['name']} ({sel['pid']})")
        except Exception as e:
            messagebox.showerror("Error", f"Quarantine failed: {e}")
        self.refresh_from_engine()

    def block_ip_selected(self):
        sel = self._get_selected()
        ip = sel["remote_ip"]
        if not ip or ip in ("-", ""):
            messagebox.showwarning("No IP", "Selected process has no remote IP.")
            return
        if not messagebox.askyesno("Confirm Block IP", f"Block {ip} via firewall?"):
            return
        ok = firewall_block_ip(ip)
        if ok:
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
        self.status.set(f"Muted {sel['name']} ({sel['pid']})")
        self.refresh_from_engine()

    def unmute_selected(self):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            messagebox.showwarning("No selection", "Select a process with a valid PID.")
            return
        self._set_mute_state(sel["pid"], False)
        self.status.set(f"Unmuted {sel['name']} ({sel['pid']})")
        self.refresh_from_engine()

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
        self.status.set(f"Volume set for {sel['name']} ({sel['pid']})")
        self.refresh_from_engine()

    def add_blocklist_selected(self):
        sel = self._get_selected()
        if not sel or sel["name"] is None:
            messagebox.showwarning("No selection", "Select a process first.")
            return
        BLOCKLIST.add(sel["name"].lower())
        save_rules()
        self.status.set(f"Blocklisted {sel['name']}")
        self.refresh_from_engine()

    def add_allowlist_selected(self):
        sel = self._get_selected()
        if not sel or sel["name"] is None:
            messagebox.showwarning("No selection", "Select a process first.")
            return
        ALLOWLIST.add(sel["name"].lower())
        save_rules()
        self.status.set(f"Allowlisted {sel['name']}")
        self.refresh_from_engine()

    def edit_rules_popup(self):
        win = tk.Toplevel(self)
        win.title("Edit Rules")
        win.geometry("420x320")

        ttk.Label(win, text="Auto-Kill Score ≥").pack(pady=(8, 2))
        kill_var = tk.StringVar(value=str(AUTO_KILL_RULES.get("high_threat_score", 90)))
        ttk.Entry(win, textvariable=kill_var).pack(pady=2)

        ttk.Label(win, text="Auto-Mute Score ≥").pack(pady=(8, 2))
        mute_var = tk.StringVar(value=str(AUTO_MUTE_RULES.get("medium_threat_score", 60)))
        ttk.Entry(win, textvariable=mute_var).pack(pady=2)

        ttk.Label(win, text="Auto-Quarantine Score ≥").pack(pady=(8, 2))
        q_var = tk.StringVar(value=str(AUTO_QUARANTINE_RULES.get("quarantine_score", 80)))
        ttk.Entry(win, textvariable=q_var).pack(pady=2)

        ttk.Label(win, text="Auto-Block IP Score ≥").pack(pady=(8, 2))
        b_var = tk.StringVar(value=str(AUTO_BLOCK_IP_RULES.get("block_score", 85)))
        ttk.Entry(win, textvariable=b_var).pack(pady=2)

        def save():
            try:
                AUTO_KILL_RULES["high_threat_score"] = int(kill_var.get())
                AUTO_MUTE_RULES["medium_threat_score"] = int(mute_var.get())
                AUTO_QUARANTINE_RULES["quarantine_score"] = int(q_var.get())
                AUTO_BLOCK_IP_RULES["block_score"] = int(b_var.get())
                save_rules()
                win.destroy()
            except Exception:
                messagebox.showerror("Error", "Invalid values.")

        ttk.Button(win, text="Save", command=save).pack(pady=12)

    def reload_timeline(self):
        load_timeline()
        self.timeline_box.delete("1.0", tk.END)
        for ev in TIMELINE:
            self.timeline_box.insert(
                tk.END,
                f"{ev['timestamp']} [{ev['type']}] {ev['payload']}\n"
            )
        self.timeline_box.see(tk.END)
        self.status.set("Timeline reloaded")

    def show_details_popup(self, event):
        sel = self._get_selected()
        if not sel or sel["pid"] is None:
            return
        pid = sel["pid"]
        with ENGINE_LOCK:
            snapshot = ENGINE_LAST_SNAPSHOT.copy()
        info = None
        for i in snapshot:
            if i["pid"] == pid:
                info = i
                break
        if not info:
            return
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
            f"Local: {info['local_ip']}\n"
            f"Remote: {info['remote_ip']}\n"
            f"Countries: {info['countries']}\n"
            f"Ports: {info['ports']}\n"
            f"Bandwidth: Up {info['bandwidth'][0]} KB/s, Down {info['bandwidth'][1]} KB/s\n\n"
            f"SHA256 (partial): {info['hash_short']}\n"
            f"VT Reputation: {info['vt_rep']}\n"
            f"ASN: {info['asn']} Org: {info['org']}\n\n"
            f"Threat Level: {info['threat_level']}\n"
            f"Threat Score: {info['threat_score']}\n"
            f"ML Class: {info['ml_class']}\n"
        )
        text.insert(tk.END, details)
        text.config(state=tk.DISABLED)


def main():
    engine_thread = threading.Thread(target=engine_loop, daemon=True)
    engine_thread.start()
    app = AudioWeaponConsole()
    app.mainloop()


if __name__ == "__main__":
    main()
