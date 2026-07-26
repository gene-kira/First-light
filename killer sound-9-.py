# === AUDIO WEAPON CONSOLE v8 — Intelligence EDR with ETW + Packet Skeleton ===
# Features:
# - Background engine service + watchdog
# - Event bus with unified Event model
# - Threat chains + correlation
# - Behavior baselines + deviation scoring
# - Signature engine
# - Timeline + replay
# - Plugin system
# - ML-like classifier
# - IP reputation + GeoIP + VT (optional)
# - ETW Process / Network / File skeleton (pywintrace-ready)
# - Packet capture skeleton (pcap/WinDivert/Npcap)
# - Attacker profile builder
# - Compact Pro GUI with:
#   - Audio+Network table
#   - Threat chain viewer
#   - Timeline viewer
#   - Attacker profile viewer
#   - Plugin list
#   - Engine health panel

import importlib
import sys
import time
import os
import json
import threading
import hashlib
import uuid
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
    "pywintrace": "pywintrace",  # ETW
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
if OPTIONAL_AVAILABLE["pywintrace"]:
    import pywintrace

# === CONFIG / FILES ===
LOG_FILE = "awc_v8_log.txt"
RULES_FILE = "awc_v8_rules.json"
BASELINES_FILE = "awc_v8_baselines.json"
TIMELINE_FILE = "awc_v8_timeline.json"
CHAIN_FILE = "awc_v8_chains.json"
PROFILES_FILE = "awc_v8_profiles.json"
PLUGINS_DIR = "plugins"

AUTO_REFRESH_INTERVAL = 3
ENGINE_SCAN_INTERVAL = 3
WATCHDOG_INTERVAL = 5

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

BASELINES = {}
TIMELINE = []          # list of bus events (including unified Event payloads)
EVENT_SUBSCRIBERS = {}
ENGINE_LOCK = threading.Lock()
ENGINE_LAST_SNAPSHOT = []   # last audio+proc snapshot
ENGINE_LAST_HEARTBEAT = 0

THREAT_CHAINS = {}     # chain_id -> chain dict
CHAIN_LOCK = threading.Lock()

ATTACKER_PROFILES = {} # profile_id -> profile dict
PROFILE_LOCK = threading.Lock()

PLUGINS = []
PLUGIN_ERRORS = []

# === GEOIP / VT ===

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


# === PERSISTENCE ===

def load_json(path, default):
    if not os.path.exists(path):
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default


def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass


def load_rules():
    global BLOCKLIST, ALLOWLIST, AUTO_KILL_RULES, AUTO_MUTE_RULES, AUTO_QUARANTINE_RULES, AUTO_BLOCK_IP_RULES
    data = load_json(RULES_FILE, {})
    BLOCKLIST = set(data.get("blocklist", []))
    ALLOWLIST = set(data.get("allowlist", []))
    AUTO_KILL_RULES = data.get("auto_kill_rules", AUTO_KILL_RULES)
    AUTO_MUTE_RULES = data.get("auto_mute_rules", AUTO_MUTE_RULES)
    AUTO_QUARANTINE_RULES = data.get("auto_quarantine_rules", AUTO_QUARANTINE_RULES)
    AUTO_BLOCK_IP_RULES = data.get("auto_block_ip_rules", AUTO_BLOCK_IP_RULES)


def save_rules():
    data = {
        "blocklist": list(BLOCKLIST),
        "allowlist": list(ALLOWLIST),
        "auto_kill_rules": AUTO_KILL_RULES,
        "auto_mute_rules": AUTO_MUTE_RULES,
        "auto_quarantine_rules": AUTO_QUARANTINE_RULES,
        "auto_block_ip_rules": AUTO_BLOCK_IP_RULES,
    }
    save_json(RULES_FILE, data)


def load_baselines():
    global BASELINES
    BASELINES = load_json(BASELINES_FILE, {})


def save_baselines():
    save_json(BASELINES_FILE, BASELINES)


def load_timeline():
    global TIMELINE
    TIMELINE = load_json(TIMELINE_FILE, [])


def save_timeline():
    save_json(TIMELINE_FILE, TIMELINE)


def load_chains():
    global THREAT_CHAINS
    THREAT_CHAINS = load_json(CHAIN_FILE, {})


def save_chains():
    save_json(CHAIN_FILE, THREAT_CHAINS)


def load_profiles():
    global ATTACKER_PROFILES
    ATTACKER_PROFILES = load_json(PROFILES_FILE, {})


def save_profiles():
    save_json(PROFILES_FILE, ATTACKER_PROFILES)


def write_log(message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {message}\n"
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line)
    except Exception:
        pass
    return line


# === UNIFIED EVENT MODEL / EVENT BUS ===

def new_event_id():
    return str(uuid.uuid4())


def make_event(
    source,
    kind,
    pid=None,
    ppid=None,
    exe=None,
    cmdline=None,
    user=None,
    net=None,
    geo=None,
    proc=None,
    audio=None,
    vt=None,
    score=None,
    meta=None,
):
    ev = {
        "id": new_event_id(),
        "ts": datetime.now().isoformat(),
        "source": source,
        "kind": kind,
        "pid": pid,
        "ppid": ppid,
        "exe": exe,
        "cmdline": cmdline,
        "user": user,
        "net": net or {
            "local_ip": None,
            "local_port": None,
            "remote_ip": None,
            "remote_port": None,
            "proto": None,
            "dns_name": None,
            "tls_sni": None,
            "ja3": None,
            "bytes_sent": None,
            "bytes_recv": None,
        },
        "geo": geo or {
            "country": None,
            "asn": None,
            "org": None,
        },
        "proc": proc or {
            "cpu": None,
            "mem_mb": None,
            "threads": None,
            "tree": None,
            "is_lolbin": None,
        },
        "audio": audio or {
            "volume": None,
            "muted": None,
        },
        "vt": vt or {
            "hash": None,
            "malicious": None,
            "suspicious": None,
        },
        "score": score or {
            "threat_score": None,
            "threat_level": None,
            "ml_class": None,
            "signatures": [],
        },
        "meta": meta or {
            "chain_id": None,
            "root_cause_pid": None,
            "tags": [],
        },
    }
    return ev


def publish_event(event_type, payload):
    ts = datetime.now().isoformat()
    ev = {
        "timestamp": ts,
        "type": event_type,
        "payload": payload,
    }
    TIMELINE.append(ev)
    if event_type in EVENT_SUBSCRIBERS:
        for cb in EVENT_SUBSCRIBERS[event_type]:
            try:
                cb(ev)
            except Exception as e:
                write_log(f"EVENT HANDLER ERROR {event_type}: {e}")


def subscribe_event(event_type, callback):
    EVENT_SUBSCRIBERS.setdefault(event_type, []).append(callback)


# === PLUGIN SYSTEM ===

class PluginContext:
    def __init__(self):
        self.publish_event = publish_event
        self.write_log = write_log

    def get_baselines(self):
        return BASELINES

    def get_chains(self):
        return THREAT_CHAINS

    def get_timeline(self):
        return TIMELINE

    def get_profiles(self):
        return ATTACKER_PROFILES


def load_plugins():
    global PLUGINS, PLUGIN_ERRORS
    PLUGINS = []
    PLUGIN_ERRORS = []
    if not os.path.isdir(PLUGINS_DIR):
        return
    ctx = PluginContext()
    for fname in os.listdir(PLUGINS_DIR):
        if not fname.endswith(".py"):
            continue
        path = os.path.join(PLUGINS_DIR, fname)
        mod_name = f"plugin_{fname[:-3]}"
        try:
            spec = importlib.util.spec_from_file_location(mod_name, path)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, "init_plugin"):
                plugin_obj = mod.init_plugin(ctx)
                PLUGINS.append(plugin_obj)
                write_log(f"PLUGIN LOADED: {fname}")
            else:
                write_log(f"PLUGIN SKIPPED (no init_plugin): {fname}")
        except Exception as e:
            PLUGIN_ERRORS.append((fname, str(e)))
            write_log(f"PLUGIN ERROR {fname}: {e}")


def plugin_on_scan(info):
    for p in PLUGINS:
        try:
            if hasattr(p, "on_scan"):
                p.on_scan(info)
        except Exception as e:
            write_log(f"PLUGIN on_scan error: {e}")


def plugin_on_chain(chain):
    for p in PLUGINS:
        try:
            if hasattr(p, "on_chain"):
                p.on_chain(chain)
        except Exception as e:
            write_log(f"PLUGIN on_chain error: {e}")


def plugin_on_profile(profile):
    for p in PLUGINS:
        try:
            if hasattr(p, "on_profile"):
                p.on_profile(profile)
        except Exception as e:
            write_log(f"PLUGIN on_profile error: {e}")


# === SIGNATURE ENGINE ===

SIGNATURES = [
    {
        "id": "audio_remote_high_bw",
        "desc": "Remote IP + high down bandwidth + non-system process",
        "conditions": {
            "remote_ip": True,
            "bandwidth_down_min": 300,
            "system_process": False,
        },
        "score": 25,
    },
    {
        "id": "high_risk_country_audio",
        "desc": "Audio session with high-risk country",
        "conditions": {
            "country_in_high_risk": True,
        },
        "score": 30,
    },
    {
        "id": "vt_malicious",
        "desc": "VT malicious >= 3",
        "conditions": {
            "vt_malicious_min": 3,
        },
        "score": 40,
    },
]


def apply_signatures(info):
    extra_score = 0
    matched = []
    for sig in SIGNATURES:
        cond = sig["conditions"]
        ok = True
        if cond.get("remote_ip"):
            if not info["remote_ip"] or info["remote_ip"] in ("-", ""):
                ok = False
        if "bandwidth_down_min" in cond:
            if info["bandwidth"][1] < cond["bandwidth_down_min"]:
                ok = False
        if "system_process" in cond:
            is_system = info["exe_path"].lower().startswith("c:\\windows")
            if cond["system_process"] and not is_system:
                ok = False
            if not cond["system_process"] and is_system:
                ok = False
        if cond.get("country_in_high_risk"):
            if not any(c in HIGH_RISK_COUNTRIES for c in info["countries"]):
                ok = False
        if "vt_malicious_min" in cond:
            if info["vt_rep"]["malicious"] < cond["vt_malicious_min"]:
                ok = False
        if ok:
            extra_score += sig["score"]
            matched.append(sig["id"])
    return extra_score, matched


# === BASELINES / ML ===

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
    ports = info["ports"]
    if mal >= 5 or score >= 95:
        return "malicious"
    if sus >= 3 or score >= 75:
        return "suspicious"
    if cpu < 5 and bw < 50 and score < 20:
        return "benign"
    if bw > 300 and score >= 40 and any(p in (22, 3389, 5900) for p in ports):
        return "remote_control"
    if score >= 50 and bw > 200:
        return "high_activity"
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
    sig_score, matched = apply_signatures(info)
    info["matched_signatures"] = matched
    score += sig_score
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


# === THREAT CHAINS ===

def get_chain_id(info):
    return f"{info['exe_name'].lower()}::{info['remote_ip'] or '-'}"


def add_to_chain(info):
    chain_id = get_chain_id(info)
    with CHAIN_LOCK:
        chain = THREAT_CHAINS.get(chain_id)
        event = {
            "ts": datetime.now().isoformat(),
            "pid": info["pid"],
            "name": info["exe_name"],
            "remote_ip": info["remote_ip"],
            "countries": info["countries"],
            "ports": info["ports"],
            "score": info["threat_score"],
            "level": info["threat_level"],
            "ml": info["ml_class"],
            "signatures": info.get("matched_signatures", []),
        }
        if chain is None:
            chain = {
                "id": chain_id,
                "first_seen": event["ts"],
                "last_seen": event["ts"],
                "events": [event],
            }
        else:
            chain["last_seen"] = event["ts"]
            chain["events"].append(event)
        THREAT_CHAINS[chain_id] = chain
        plugin_on_chain(chain)


# === ATTACKER PROFILES ===

def update_attacker_profiles_from_chain(chain):
    countries = set()
    ports = set()
    ips = set()
    for ev in chain["events"]:
        for c in ev["countries"]:
            countries.add(c)
        for p in ev["ports"]:
            ports.add(p)
        if ev["remote_ip"]:
            ips.add(ev["remote_ip"])

    key = (tuple(sorted(countries)), tuple(sorted(ports)))
    profile_id = None

    with PROFILE_LOCK:
        for pid, prof in ATTACKER_PROFILES.items():
            pc = tuple(sorted(prof["infra"]["countries"]))
            pp = tuple(sorted(prof["tools"]["ports"]))
            if pc == key[0] and pp == key[1]:
                profile_id = pid
                break

        if profile_id is None:
            profile_id = f"actor_{len(ATTACKER_PROFILES) + 1:03d}"
            ATTACKER_PROFILES[profile_id] = {
                "id": profile_id,
                "first_seen": chain["first_seen"],
                "last_seen": chain["last_seen"],
                "infra": {
                    "countries": list(countries),
                    "asns": [],
                    "orgs": [],
                    "ips": list(ips),
                },
                "tools": {
                    "ja3": [],
                    "user_agents": [],
                    "lolbins": [],
                    "ports": list(ports),
                },
                "behaviors": {
                    "beacon_intervals": [],
                    "dns_tunnel_like": False,
                    "short_lived_procs": False,
                    "file_drop_exec": False,
                },
                "chains": [chain["id"]],
                "score": {
                    "confidence": 0.5,
                    "severity": "High" if countries & HIGH_RISK_COUNTRIES else "Medium",
                },
            }
        else:
            prof = ATTACKER_PROFILES[profile_id]
            prof["last_seen"] = chain["last_seen"]
            prof["infra"]["countries"] = sorted(set(prof["infra"]["countries"]) | countries)
            prof["infra"]["ips"] = sorted(set(prof["infra"]["ips"]) | ips)
            prof["tools"]["ports"] = sorted(set(prof["tools"]["ports"]) | ports)
            if chain["id"] not in prof["chains"]:
                prof["chains"].append(chain["id"])

    save_profiles()
    plugin_on_profile(ATTACKER_PROFILES[profile_id])


# === DEFENSE ENGINE ===

def firewall_block_ip(ip):
    try:
        cmd = f'netsh advfirewall firewall add rule name="AWC_v8_Block_{ip}" dir=out action=block remoteip={ip}'
        os.system(cmd)
        return True
    except Exception:
        return False


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


# === ENGINE CORE (Audio + Proc) ===

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

            plugin_on_scan(info)
            add_to_chain(info)

            net = {
                "local_ip": local_ip,
                "local_port": None,
                "remote_ip": remote_ip,
                "remote_port": ports[0] if ports else None,
                "proto": "TCP",
                "dns_name": None,
                "tls_sni": None,
                "ja3": None,
                "bytes_sent": None,
                "bytes_recv": None,
            }
            geo = {
                "country": list(countries)[0] if countries else None,
                "asn": asn,
                "org": org,
            }
            proc_info = {
                "cpu": int(cpu),
                "mem_mb": int(mem_mb),
                "threads": threads,
                "tree": tree_str,
                "is_lolbin": name.lower() in ("powershell.exe", "cmd.exe", "rundll32.exe"),
            }
            audio_info = {
                "volume": vol_level,
                "muted": muted,
            }
            vt_info = {
                "hash": hash_short,
                "malicious": vt_rep["malicious"],
                "suspicious": vt_rep["suspicious"],
            }
            score_info = {
                "threat_score": score,
                "threat_level": level,
                "ml_class": ml_class,
                "signatures": info.get("matched_signatures", []),
            }
            meta_info = {
                "chain_id": get_chain_id(info),
                "root_cause_pid": None,
                "tags": [],
            }

            ev = make_event(
                source="AUDIO",
                kind="AUDIO_SESSION",
                pid=pid,
                ppid=None,
                exe=exe_path,
                cmdline=None,
                user=None,
                net=net,
                geo=geo,
                proc=proc_info,
                audio=audio_info,
                vt=vt_info,
                score=score_info,
                meta=meta_info,
            )
            publish_event("SCAN_RESULT", {"info": info, "event": ev})

            if score >= AUTO_KILL_RULES.get("high_threat_score", 90):
                publish_event("THREAT_CRITICAL", {"info": info, "event": ev})
            elif score >= AUTO_QUARANTINE_RULES.get("quarantine_score", 80):
                publish_event("THREAT_HIGH", {"info": info, "event": ev})
            elif score >= AUTO_MUTE_RULES.get("medium_threat_score", 60):
                publish_event("THREAT_MEDIUM", {"info": info, "event": ev})

        except Exception:
            continue

    return snapshot


def engine_loop():
    global ENGINE_LAST_HEARTBEAT
    pythoncom.CoInitialize()
    load_rules()
    load_baselines()
    load_timeline()
    load_chains()
    load_profiles()
    load_plugins()

    while True:
        snapshot = engine_scan_once()

        with ENGINE_LOCK:
            ENGINE_LAST_SNAPSHOT.clear()
            ENGINE_LAST_SNAPSHOT.extend(snapshot)
            ENGINE_LAST_HEARTBEAT = time.time()

        save_baselines()
        save_timeline()
        save_chains()
        save_profiles()

        print("ENGINE SCAN:", len(snapshot), "items")
        time.sleep(ENGINE_SCAN_INTERVAL)


def watchdog_loop():
    global ENGINE_LAST_HEARTBEAT
    while True:
        now = time.time()
        if ENGINE_LAST_HEARTBEAT == 0:
            time.sleep(WATCHDOG_INTERVAL)
            continue
        if now - ENGINE_LAST_HEARTBEAT > ENGINE_SCAN_INTERVAL * 3:
            write_log("WATCHDOG: Engine heartbeat stalled")
            publish_event("ENGINE_STALLED", {"last_heartbeat": ENGINE_LAST_HEARTBEAT})
        time.sleep(WATCHDOG_INTERVAL)


# === ETW LOOPS (pywintrace skeleton) ===

def etw_process_loop():
    if not OPTIONAL_AVAILABLE.get("pywintrace"):
        return

    try:
        session = pywintrace.RealTimeSession("AWC_v8_Process")
        provider = pywintrace.Provider("Microsoft-Windows-Kernel-Process")
        session.add_provider(provider)

        def on_event(evt):
            try:
                fields = evt.fields
                pid = fields.get("ProcessId")
                ppid = fields.get("ParentProcessId")
                image = fields.get("ImageFileName") or fields.get("ProcessName")
                cmdline = fields.get("CommandLine")

                proc_info = {
                    "cpu": None,
                    "mem_mb": None,
                    "threads": None,
                    "tree": None,
                    "is_lolbin": str(image).lower() in ("powershell.exe", "cmd.exe", "rundll32.exe"),
                }

                meta = {
                    "chain_id": f"{str(image).lower()}::-",
                    "root_cause_pid": ppid,
                    "tags": ["etw_process"],
                }

                kind = "PROCESS_CREATE"  # you can refine based on evt.id
                ev = make_event(
                    source="ETW_PROCESS",
                    kind=kind,
                    pid=pid,
                    ppid=ppid,
                    exe=image,
                    cmdline=cmdline,
                    proc=proc_info,
                    meta=meta,
                )

                publish_event("ETW_PROCESS", {"event": ev})

            except Exception as e:
                write_log(f"ETW_PROCESS error: {e}")

        session.on_event(on_event)
        session.start()
    except Exception as e:
        write_log(f"ETW_PROCESS loop failed: {e}")


def etw_network_loop():
    if not OPTIONAL_AVAILABLE.get("pywintrace"):
        return

    try:
        session = pywintrace.RealTimeSession("AWC_v8_Network")
        provider = pywintrace.Provider("Microsoft-Windows-Kernel-Network")
        session.add_provider(provider)

        def on_event(evt):
            try:
                fields = evt.fields
                pid = fields.get("ProcessId")
                local_ip = fields.get("LocalAddress")
                local_port = fields.get("LocalPort")
                remote_ip = fields.get("RemoteAddress")
                remote_port = fields.get("RemotePort")
                proto = fields.get("Protocol")

                geo = geoip_lookup(remote_ip) if remote_ip else {"country": None, "asn": None, "org": None}

                net = {
                    "local_ip": local_ip,
                    "local_port": local_port,
                    "remote_ip": remote_ip,
                    "remote_port": remote_port,
                    "proto": proto,
                    "dns_name": None,
                    "tls_sni": None,
                    "ja3": None,
                    "bytes_sent": None,
                    "bytes_recv": None,
                }

                meta = {
                    "chain_id": None,
                    "root_cause_pid": None,
                    "tags": ["etw_network"],
                }

                ev = make_event(
                    source="ETW_NETWORK",
                    kind="NET_CONNECT",
                    pid=pid,
                    net=net,
                    geo={
                        "country": geo["country"],
                        "asn": geo["asn"],
                        "org": geo["org"],
                    },
                    meta=meta,
                )

                publish_event("ETW_NETWORK", {"event": ev})

            except Exception as e:
                write_log(f"ETW_NETWORK error: {e}")

        session.on_event(on_event)
        session.start()
    except Exception as e:
        write_log(f"ETW_NETWORK loop failed: {e}")


def etw_file_loop():
    if not OPTIONAL_AVAILABLE.get("pywintrace"):
        return

    try:
        session = pywintrace.RealTimeSession("AWC_v8_File")
        provider = pywintrace.Provider("Microsoft-Windows-Kernel-File")
        session.add_provider(provider)

        def on_event(evt):
            try:
                fields = evt.fields
                pid = fields.get("ProcessId")
                file_path = fields.get("FileName")
                op = fields.get("Operation")  # e.g., Create, Write, Delete

                tags = ["etw_file"]
                if file_path and str(file_path).lower().endswith((".exe", ".dll")):
                    tags.append("file_exec_like")

                meta = {
                    "chain_id": None,
                    "root_cause_pid": None,
                    "tags": tags,
                }

                kind = "FILE_WRITE" if op in ("Create", "Write") else "FILE_DELETE"
                ev = make_event(
                    source="ETW_FILE",
                    kind=kind,
                    pid=pid,
                    exe=None,
                    cmdline=None,
                    meta=meta,
                )

                publish_event("ETW_FILE", {"event": ev})

            except Exception as e:
                write_log(f"ETW_FILE error: {e}")

        session.on_event(on_event)
        session.start()
    except Exception as e:
        write_log(f"ETW_FILE loop failed: {e}")


def packet_capture_loop():
    """
    Skeleton:
    - Use Npcap/WinDivert/pcapy to capture packets
    - Extract IP/port/proto, TLS SNI, JA3, DNS names
    - Build Event with source='PACKET', kind='PACKET'
    """
    while True:
        time.sleep(1)


# === GUI ===

class AudioWeaponConsole(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Audio Weapon Console v8 — Intelligence EDR")
        self.geometry("1400x820")

        self.auto_refresh_enabled = tk.BooleanVar(value=True)
        self.alerts_enabled = tk.BooleanVar(value=True)

        self.filter_text = tk.StringVar(value="")
        self.filter_threat = tk.StringVar(value="ALL")

        self.selected_chain_id = None
        self.selected_profile_id = None

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

        # Tab 1: Audio + Network
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
                "threat", "score", "ml", "sigs",
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
            "sigs": "Signatures",
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
            "sigs": 140,
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

        # Tab 2: Threat Chains
        self.chain_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.chain_frame, text="Threat Chains")

        left_chain = ttk.Frame(self.chain_frame)
        left_chain.pack(side=tk.LEFT, fill=tk.Y, padx=4, pady=4)

        ttk.Label(left_chain, text="Chains").pack(anchor=tk.W)
        self.chain_list = tk.Listbox(left_chain, height=20)
        self.chain_list.pack(fill=tk.Y, expand=True)
        self.chain_list.bind("<<ListboxSelect>>", self.on_chain_select)

        ttk.Button(left_chain, text="Refresh Chains", command=self.refresh_chains).pack(pady=4)

        right_chain = ttk.Frame(self.chain_frame)
        right_chain.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4, pady=4)

        ttk.Label(right_chain, text="Chain Events").pack(anchor=tk.W)
        self.chain_events_box = scrolledtext.ScrolledText(right_chain, height=18, wrap=tk.WORD)
        self.chain_events_box.pack(fill=tk.BOTH, expand=True)

        # Tab 3: Timeline / Replay
        self.timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.timeline_frame, text="Timeline / Replay")

        self.timeline_box = scrolledtext.ScrolledText(self.timeline_frame, height=18, wrap=tk.WORD)
        self.timeline_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        ttk.Button(self.timeline_frame, text="Reload Timeline", command=self.reload_timeline).pack(pady=4)

        # Tab 4: Attacker Profiles
        self.profile_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.profile_frame, text="Attacker Profiles")

        ttk.Label(self.profile_frame, text="Profiles").pack(anchor=tk.W, padx=4, pady=(4, 2))
        self.profile_list = tk.Listbox(self.profile_frame, height=10)
        self.profile_list.pack(fill=tk.X, padx=4)
        self.profile_list.bind("<<ListboxSelect>>", self.on_profile_select)

        ttk.Button(self.profile_frame, text="Refresh Profiles", command=self.refresh_profiles).pack(pady=4)

        ttk.Label(self.profile_frame, text="Profile Details").pack(anchor=tk.W, padx=4, pady=(8, 2))
        self.profile_details_box = scrolledtext.ScrolledText(self.profile_frame, height=10, wrap=tk.WORD)
        self.profile_details_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        # Tab 5: Plugins / Health
        self.plugin_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.plugin_frame, text="Plugins / Health")

        ttk.Label(self.plugin_frame, text="Loaded Plugins").pack(anchor=tk.W, padx=4, pady=(4, 2))
        self.plugin_list_box = tk.Listbox(self.plugin_frame, height=8)
        self.plugin_list_box.pack(fill=tk.X, padx=4)

        ttk.Label(self.plugin_frame, text="Plugin Errors").pack(anchor=tk.W, padx=4, pady=(8, 2))
        self.plugin_error_box = scrolledtext.ScrolledText(self.plugin_frame, height=6, wrap=tk.WORD)
        self.plugin_error_box.pack(fill=tk.BOTH, expand=True, padx=4, pady=4)

        ttk.Label(self.plugin_frame, text="Engine Health").pack(anchor=tk.W, padx=4, pady=(8, 2))
        self.health_label = ttk.Label(self.plugin_frame, text="Engine heartbeat: unknown")
        self.health_label.pack(anchor=tk.W, padx=4)

        bottom = ttk.Frame(self)
        bottom.pack(fill=tk.X, padx=8, pady=4)

        self.status = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.status).pack(side=tk.LEFT, padx=4)

        self._update_alert_button_style()
        self.refresh_plugins_view()
        self.refresh_profiles()

    def _start_gui_refresh(self):
        def loop():
            while True:
                if self.auto_refresh_enabled.get():
                    self.refresh_from_engine()
                    self.refresh_health()
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
            sigs = ",".join(info.get("matched_signatures", []))
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
                    sigs,
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
            sigs = ",".join(info.get("matched_signatures", []))
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
                    sigs or "",
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
                    sigs,
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

    def refresh_chains(self):
        load_chains()
        self.chain_list.delete(0, tk.END)
        for cid, chain in THREAT_CHAINS.items():
            label = f"{cid} ({len(chain['events'])} events)"
            self.chain_list.insert(tk.END, label)
        self.chain_events_box.delete("1.0", tk.END)
        self.status.set("Chains refreshed")

    def on_chain_select(self, event):
        idxs = self.chain_list.curselection()
        if not idxs:
            return
        idx = idxs[0]
        label = self.chain_list.get(idx)
        cid = label.split(" (")[0]
        self.selected_chain_id = cid
        chain = THREAT_CHAINS.get(cid)
        self.chain_events_box.delete("1.0", tk.END)
        if not chain:
            return
        for ev in chain["events"]:
            self.chain_events_box.insert(
                tk.END,
                f"{ev['ts']} [{ev['level']}/{ev['score']}] {ev['name']} PID={ev['pid']} IP={ev['remote_ip']} Ports={ev['ports']} Sigs={ev['signatures']}\n"
            )
        self.chain_events_box.see(tk.END)
        update_attacker_profiles_from_chain(chain)
        self.refresh_profiles()

    def refresh_plugins_view(self):
        self.plugin_list_box.delete(0, tk.END)
        for p in PLUGINS:
            self.plugin_list_box.insert(tk.END, getattr(p, "name", str(p)))
        self.plugin_error_box.delete("1.0", tk.END)
        for fname, err in PLUGIN_ERRORS:
            self.plugin_error_box.insert(tk.END, f"{fname}: {err}\n")

    def refresh_health(self):
        hb = ENGINE_LAST_HEARTBEAT
        if hb == 0:
            self.health_label.configure(text="Engine heartbeat: not yet started")
            return
        age = time.time() - hb
        self.health_label.configure(text=f"Engine heartbeat age: {age:.1f}s")

    def refresh_profiles(self):
        load_profiles()
        self.profile_list.delete(0, tk.END)
        for pid, prof in ATTACKER_PROFILES.items():
            label = f"{pid} ({prof['score']['severity']} / {prof['score']['confidence']:.2f})"
            self.profile_list.insert(tk.END, label)
        self.profile_details_box.delete("1.0", tk.END)
        self.status.set("Profiles refreshed")

    def on_profile_select(self, event):
        idxs = self.profile_list.curselection()
        if not idxs:
            return
        idx = idxs[0]
        label = self.profile_list.get(idx)
        pid = label.split(" ")[0]
        self.selected_profile_id = pid
        prof = ATTACKER_PROFILES.get(pid)
        self.profile_details_box.delete("1.0", tk.END)
        if not prof:
            return
        details = (
            f"Profile ID: {prof['id']}\n"
            f"First Seen: {prof['first_seen']}\n"
            f"Last Seen: {prof['last_seen']}\n\n"
            f"Infra:\n"
            f"  Countries: {prof['infra']['countries']}\n"
            f"  ASNs: {prof['infra']['asns']}\n"
            f"  Orgs: {prof['infra']['orgs']}\n"
            f"  IPs: {prof['infra']['ips']}\n\n"
            f"Tools:\n"
            f"  JA3: {prof['tools']['ja3']}\n"
            f"  User-Agents: {prof['tools']['user_agents']}\n"
            f"  LOLBins: {prof['tools']['lolbins']}\n"
            f"  Ports: {prof['tools']['ports']}\n\n"
            f"Behaviors:\n"
            f"  Beacon intervals: {prof['behaviors']['beacon_intervals']}\n"
            f"  DNS tunnel-like: {prof['behaviors']['dns_tunnel_like']}\n"
            f"  Short-lived procs: {prof['behaviors']['short_lived_procs']}\n"
            f"  File drop+exec: {prof['behaviors']['file_drop_exec']}\n\n"
            f"Chains: {prof['chains']}\n\n"
            f"Score:\n"
            f"  Confidence: {prof['score']['confidence']}\n"
            f"  Severity: {prof['score']['severity']}\n"
        )
        self.profile_details_box.insert(tk.END, details)
        self.profile_details_box.see(tk.END)

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
        win.geometry("560x540")
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
            f"Signatures: {info.get('matched_signatures', [])}\n"
        )
        text.insert(tk.END, details)
        text.config(state=tk.DISABLED)


def main():
    engine_thread = threading.Thread(target=engine_loop, daemon=True)
    engine_thread.start()

    watchdog_thread = threading.Thread(target=watchdog_loop, daemon=True)
    watchdog_thread.start()

    etw_proc_thread = threading.Thread(target=etw_process_loop, daemon=True)
    etw_proc_thread.start()

    etw_net_thread = threading.Thread(target=etw_network_loop, daemon=True)
    etw_net_thread.start()

    etw_file_thread = threading.Thread(target=etw_file_loop, daemon=True)
    etw_file_thread.start()

    packet_thread = threading.Thread(target=packet_capture_loop, daemon=True)
    packet_thread.start()

    app = AudioWeaponConsole()
    app.mainloop()


if __name__ == "__main__":
    main()
