import sys
import subprocess
import importlib
import os
import time
import threading
import json
import socket
import hashlib
import zipfile
from datetime import datetime, timedelta

# -----------------------------
# Auto-loader for dependencies
# -----------------------------
REQUIRED_LIBS = [
    "psutil",
    "comtypes",
    "pycaw",
    "requests",
    "pefile",
    "pywin32",
    "numpy",
]

def ensure_libs():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            print(f"[+] Installing missing library: {lib}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
    globals()["psutil"] = importlib.import_module("psutil")
    globals()["comtypes"] = importlib.import_module("comtypes")
    globals()["pycaw"] = importlib.import_module("pycaw")
    globals()["requests"] = importlib.import_module("requests")
    globals()["pefile"] = importlib.import_module("pefile")
    globals()["pythoncom"] = importlib.import_module("pythoncom")
    globals()["np"] = importlib.import_module("numpy")

ensure_libs()

import psutil
from pycaw.pycaw import AudioUtilities, ISimpleAudioVolume
import requests
import pefile
import pythoncom
import numpy as np

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

# -----------------------------
# Config / constants
# -----------------------------
LOG_FILE = "security_bridge.log"
STATE_FILE = "security_state.json"
RULES_FILE = "rules.json"
REPORT_FILE_JSON = "security_report.json"
REPORT_FILE_TXT = "security_report.txt"
INCIDENT_ZIP = "security_incident_pack.zip"
INCIDENT_SESSION_FILE = "incident_session.json"

REMOTE_TOOL_KEYWORDS = [
    "anydesk", "teamviewer", "rustdesk", "parsec",
    "chrome remote desktop", "chromeremotedesktop",
    "splashtop", "ultravnc", "tightvnc", "realvnc",
    "mstsc", "rdp", "screenconnect", "logmein",
    "gotomypc"
]

SUSPICIOUS_PORTS = [
    3389,
    5938,
    7070,
    47984,
]

MITRE_MAP = {
    "REMOTE_TOOL": ["T1105", "T1071"],
    "AUDIO_ACTIVE": ["T1129"],
    "SUSP_PORT": ["T1071"],
    "EXTERNAL_IP": ["T1041"],
    "REPEATED_HIT": ["T1027"],
    "FILE_SUSP": ["T1059", "T1055"],
    "MEM_SUSP": ["T1055"],
    "EXFIL": ["T1041"],
}

DEFAULT_AUTO_BLOCK_THRESHOLD = 70
HONEYPOT_PORTS = [55222, 3390]

DEFAULT_ALLOW_NAMES = [
    "steam.exe",
    "steamwebhelper.exe",
    "Spotify.exe",
    "SpotifyWidgetProvider.exe",
    "chrome.exe",
    "msedge.exe",
    "discord.exe",
]

DEFAULT_AUDIO_WHITELIST = [
    "Spotify.exe",
    "SpotifyWidgetProvider.exe",
    "chrome.exe",
    "msedge.exe",
    "discord.exe",
]

DEFAULT_TRUSTED_GAMING = [
    "steam.exe",
    "steamwebhelper.exe",
]

MEDIUM_LOG_COOLDOWN = 60
LOW_LOG_COOLDOWN = 120

DEFAULT_MODE = "AGGRESSIVE"  # or "SILENT"

BAD_IP_REPUTATION = {
    "1.2.3.4": "Known C2",
    "5.6.7.8": "Malicious host",
}

# -----------------------------
# Logging / state
# -----------------------------
def log_event(level, message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {message}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass

def load_rules():
    if not os.path.exists(RULES_FILE):
        rules = {
            "block_names": REMOTE_TOOL_KEYWORDS,
            "block_ports": SUSPICIOUS_PORTS,
            "auto_block_threshold": DEFAULT_AUTO_BLOCK_THRESHOLD,
            "allow_names": DEFAULT_ALLOW_NAMES,
            "audio_whitelist": DEFAULT_AUDIO_WHITELIST,
            "trusted_gaming": DEFAULT_TRUSTED_GAMING,
            "mode": DEFAULT_MODE,
        }
        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2)
        except Exception:
            pass
        return rules
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "block_names": REMOTE_TOOL_KEYWORDS,
            "block_ports": SUSPICIOUS_PORTS,
            "auto_block_threshold": DEFAULT_AUTO_BLOCK_THRESHOLD,
            "allow_names": DEFAULT_ALLOW_NAMES,
            "audio_whitelist": DEFAULT_AUDIO_WHITELIST,
            "trusted_gaming": DEFAULT_TRUSTED_GAMING,
            "mode": DEFAULT_MODE,
        }

STATE = load_state()
RULES = load_rules()

def increment_detection_count(proc_key):
    global STATE
    if "detections" not in STATE:
        STATE["detections"] = {}
    if proc_key not in STATE["detections"]:
        STATE["detections"][proc_key] = 0
    STATE["detections"][proc_key] += 1
    save_state(STATE)
    return STATE["detections"][proc_key]

def get_dynamic_threshold():
    global STATE, RULES
    base = RULES.get("auto_block_threshold", DEFAULT_AUTO_BLOCK_THRESHOLD)
    detections = STATE.get("detections", {})
    high_hits = sum(1 for _, v in detections.items() if v > 5)
    adjust = min(high_hits * 2, 10)
    return max(50, base - adjust)

def should_log(proc_key, risk_level):
    global STATE
    now = time.time()
    if "log_cooldown" not in STATE:
        STATE["log_cooldown"] = {}
    cooldowns = STATE["log_cooldown"]
    last = cooldowns.get(proc_key, 0)

    mode = RULES.get("mode", DEFAULT_MODE).upper()
    if mode == "SILENT":
        if risk_level == "High":
            cooldowns[proc_key] = now
            save_state(STATE)
            return True
        return False

    if risk_level == "High":
        cooldowns[proc_key] = now
        save_state(STATE)
        return True
    elif risk_level == "Medium":
        if now - last >= MEDIUM_LOG_COOLDOWN:
            cooldowns[proc_key] = now
            save_state(STATE)
            return True
        return False
    else:
        if now - last >= LOW_LOG_COOLDOWN:
            cooldowns[proc_key] = now
            save_state(STATE)
            return True
        return False

# -----------------------------
# Data structures
# -----------------------------
class ProcessSecurityInfo:
    def __init__(self, pid, name, volume, muted, connections,
                 risk_level, risk_reason, score, mitre_tags,
                 parent_pid, exe_path, cmdline, create_time,
                 file_hash, file_suspicious,
                 mem_suspicious, threat_class,
                 audio_profile,
                 remote_index,
                 persona):
        self.pid = pid
        self.name = name
        self.volume = volume
        self.muted = muted
        self.connections = connections
        self.risk_level = risk_level
        self.risk_reason = risk_reason
        self.score = score
        self.mitre_tags = mitre_tags
        self.parent_pid = parent_pid
        self.exe_path = exe_path
        self.cmdline = cmdline
        self.create_time = create_time
        self.file_hash = file_hash
        self.file_suspicious = file_suspicious
        self.mem_suspicious = mem_suspicious
        self.threat_class = threat_class
        self.audio_profile = audio_profile
        self.remote_index = remote_index
        self.persona = persona

# -----------------------------
# Core analysis functions
# -----------------------------
def get_audio_sessions():
    pythoncom.CoInitialize()
    sessions = AudioUtilities.GetAllSessions()
    result = []
    for session in sessions:
        try:
            volume = session._ctl.QueryInterface(ISimpleAudioVolume)
            vol_level = volume.GetMasterVolume()
            muted = volume.GetMute()
            pid = session.Process.pid if session.Process else None
            process_name = "System (no process)" if not session.Process else session.Process.name()
            result.append((pid, process_name, vol_level, muted))
        except Exception:
            continue
    return result

def is_external_ip(ip):
    if not ip:
        return False
    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.")
    return not ip.startswith(private_prefixes)

def get_process_connections(pid):
    connections_info = []
    try:
        proc = psutil.Process(pid)
        conns = proc.net_connections(kind="inet")
        for c in conns:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            external = False
            if c.raddr and is_external_ip(c.raddr.ip):
                external = True
            rep = BAD_IP_REPUTATION.get(c.raddr.ip, "") if c.raddr else ""
            connections_info.append((laddr, raddr, c.status, external, rep))
    except Exception:
        pass
    return connections_info

def get_process_metadata(pid):
    parent_pid = None
    exe_path = ""
    cmdline = ""
    create_time = None
    try:
        proc = psutil.Process(pid)
        parent = proc.parent()
        parent_pid = parent.pid if parent else None
        exe_path = proc.exe()
        cmdline = " ".join(proc.cmdline())
        create_time = datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return parent_pid, exe_path, cmdline, create_time

def hash_file(path):
    if not path or not os.path.exists(path):
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def analyze_pe_file(path):
    if not path or not os.path.exists(path):
        return False
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
        suspicious = False
        imports = [entry.dll.decode(errors="ignore").lower()
                   for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        bad_imports = ["ws2_32.dll", "wininet.dll", "advapi32.dll"]
        if any(b in imports for b in bad_imports):
            suspicious = True
        for section in pe.sections:
            if section.get_entropy() > 7.5:
                suspicious = True
                break
        return suspicious
    except Exception:
        return False

def analyze_memory(pid):
    mem_suspicious = False
    try:
        proc = psutil.Process(pid)
        handle_count = proc.num_handles() if hasattr(proc, "num_handles") else 0
        dll_count = len(proc.memory_maps())
        mem_info = proc.memory_info()
        private_bytes = getattr(mem_info, "private", mem_info.rss)
        if handle_count > 500 or dll_count > 200 or private_bytes > 500 * 1024 * 1024:
            mem_suspicious = True
    except Exception:
        pass
    return mem_suspicious

def audio_fingerprint(volume):
    if volume is None or volume < 0.01:
        return {"level": "silent", "voice_like": False, "music_like": False, "game_like": False}
    if volume < 0.2:
        return {"level": "low", "voice_like": True, "music_like": False, "game_like": False}
    if volume < 0.6:
        return {"level": "medium", "voice_like": True, "music_like": True, "game_like": False}
    return {"level": "high", "voice_like": True, "music_like": True, "game_like": True}

def map_mitre_tags(remote_keyword_hit, has_audio, suspicious_port_hit,
                   external_ip_hit, repeated_hit, file_suspicious,
                   mem_suspicious, exfil_suspect):
    tags = set()
    if remote_keyword_hit:
        tags.update(MITRE_MAP["REMOTE_TOOL"])
    if has_audio:
        tags.update(MITRE_MAP["AUDIO_ACTIVE"])
    if suspicious_port_hit:
        tags.update(MITRE_MAP["SUSP_PORT"])
    if external_ip_hit:
        tags.update(MITRE_MAP["EXTERNAL_IP"])
    if repeated_hit:
        tags.update(MITRE_MAP["REPEATED_HIT"])
    if file_suspicious:
        tags.update(MITRE_MAP["FILE_SUSP"])
    if mem_suspicious:
        tags.update(MITRE_MAP["MEM_SUSP"])
    if exfil_suspect:
        tags.update(MITRE_MAP["EXFIL"])
    return sorted(tags)

def compute_threat_score(remote_keyword_hit, has_audio, suspicious_port_hit,
                         external_ip_hit, repeated_hit, has_network,
                         file_suspicious, mem_suspicious, exfil_suspect,
                         name_lower):
    score = 0
    if has_audio:
        score += 20
    if remote_keyword_hit:
        score += 40
    if suspicious_port_hit:
        score += 30
    if external_ip_hit:
        score += 20
    if has_network:
        score += 10
    if repeated_hit:
        score += 10
    if file_suspicious:
        score += 20
    if mem_suspicious:
        score += 25
    if exfil_suspect:
        score += 20

    trusted_gaming = [n.lower() for n in RULES.get("trusted_gaming", DEFAULT_TRUSTED_GAMING)]
    if any(tg in name_lower for tg in trusted_gaming):
        score = max(0, score - 25)

    audio_whitelist = [n.lower() for n in RULES.get("audio_whitelist", DEFAULT_AUDIO_WHITELIST)]
    if any(aw in name_lower for aw in audio_whitelist):
        score = max(0, score - 25)

    return min(score, 100)

def compute_remote_index(name_lower, connections, has_audio):
    idx = 0
    if any(k in name_lower for k in REMOTE_TOOL_KEYWORDS):
        idx += 40
    for _, raddr, status, external, rep in connections:
        if not raddr:
            continue
        try:
            port = int(raddr.split(":")[-1])
        except Exception:
            port = None
        if port in SUSPICIOUS_PORTS:
            idx += 25
        if external:
            idx += 15
        if rep:
            idx += 20
        if status in ("ESTABLISHED", "CLOSE_WAIT"):
            idx += 10
    if has_audio:
        idx += 10
    return min(idx, 100)

def is_allowlisted(name_lower):
    allow = [n.lower() for n in RULES.get("allow_names", DEFAULT_ALLOW_NAMES)]
    return any(a == name_lower for a in allow)

def classify_threat(score, remote_keyword_hit, mem_suspicious, exfil_suspect, file_suspicious):
    if score < 20 and not (remote_keyword_hit or mem_suspicious or exfil_suspect or file_suspicious):
        return "benign"
    if remote_keyword_hit and score >= 40:
        return "remote-control"
    if exfil_suspect and score >= 50:
        return "exfiltration"
    if mem_suspicious and score >= 50:
        return "injected"
    if file_suspicious and score >= 40:
        return "malware-like"
    if score >= 70:
        return "high-risk"
    if score >= 40:
        return "suspicious"
    return "unknown"

def persona_for_process(name_lower, has_audio, has_network, remote_index, file_suspicious, mem_suspicious):
    if is_allowlisted(name_lower) and has_audio and not has_network:
        return "Streamer / media app"
    if any(tg in name_lower for tg in [n.lower() for n in DEFAULT_TRUSTED_GAMING]):
        return "Game client"
    if remote_index >= 60:
        return "Remote admin tool / RAT-like"
    if has_network and not has_audio and not file_suspicious and not mem_suspicious:
        return "Background updater / service"
    if file_suspicious or mem_suspicious:
        return "Suspicious / malware-like"
    if has_audio and has_network:
        return "Interactive app (chat / browser / media)"
    return "Generic process"

def assess_risk(name, pid, volume, muted, connections, file_suspicious, mem_suspicious):
    name_lower = (name or "").lower()
    has_audio = (volume is not None and volume > 0.01 and not muted)
    has_network = any(raddr for (_, raddr, _, _, _) in connections)
    remote_keyword_hit = any(k in name_lower for k in RULES.get("block_names", REMOTE_TOOL_KEYWORDS))
    suspicious_port_hit = any(
        (raddr and any(str(p) == raddr.split(":")[-1] for p in RULES.get("block_ports", SUSPICIOUS_PORTS)))
        for (_, raddr, _, _, _) in connections
    )
    external_ip_hit = any(ext for (_, _, _, ext, _) in connections)
    exfil_suspect = any(rep for (_, _, _, _, rep) in connections)

    proc_key = f"{name_lower}:{pid}"
    detection_count = increment_detection_count(proc_key)
    repeated_hit = detection_count > 3

    mitre_tags = map_mitre_tags(remote_keyword_hit, has_audio,
                                suspicious_port_hit, external_ip_hit,
                                repeated_hit, file_suspicious,
                                mem_suspicious, exfil_suspect)
    score = compute_threat_score(remote_keyword_hit, has_audio,
                                 suspicious_port_hit, external_ip_hit,
                                 repeated_hit, has_network, file_suspicious,
                                 mem_suspicious, exfil_suspect,
                                 name_lower)

    remote_index = compute_remote_index(name_lower, connections, has_audio)
    threat_class = classify_threat(score, remote_keyword_hit, mem_suspicious, exfil_suspect, file_suspicious)
    persona = persona_for_process(name_lower, has_audio, has_network, remote_index, file_suspicious, mem_suspicious)

    risk_level = "Low"
    reasons = []

    if remote_keyword_hit:
        reasons.append("Process name matches known remote-control tool.")
    if suspicious_port_hit:
        reasons.append("Process uses suspicious remote-control port.")
    if has_audio:
        reasons.append("Process is actively playing audio.")
    if has_network:
        reasons.append("Process has active network connections.")
    if external_ip_hit:
        reasons.append("Process connects to external IPs.")
    if exfil_suspect:
        reasons.append("Network reputation indicates possible exfil/C2.")
    if repeated_hit:
        reasons.append("Process repeatedly flagged in prior sessions.")
    if file_suspicious:
        reasons.append("Executable shows suspicious PE characteristics.")
    if mem_suspicious:
        reasons.append("Process memory characteristics are suspicious.")

    safe_set = STATE.get("safe_to_ignore", [])
    if proc_key in safe_set:
        score = max(0, score - 30)
        remote_index = max(0, remote_index - 30)
        reasons.append("Previously marked as safe-to-ignore; downgraded risk.")

    if is_allowlisted(name_lower):
        risk_level = "Low"
        score = 0
        remote_index = 0
        threat_class = "benign"
        persona = "Allowlisted app"
        reasons.append("Process is allowlisted.")
    else:
        if score >= 80:
            risk_level = "High"
        elif score >= 50:
            risk_level = "Medium"
        else:
            risk_level = "Low"

    if should_log(proc_key, risk_level) and risk_level != "Low":
        log_event(
            risk_level,
            f"PID {pid} ({name}) score={score}, remote_index={remote_index}, persona={persona}, "
            f"class={threat_class}, MITRE={mitre_tags}, reasons={'; '.join(reasons)}"
        )

    if "proc_history" not in STATE:
        STATE["proc_history"] = {}
    hist = STATE["proc_history"].setdefault(proc_key, [])
    hist.append({
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "score": score,
        "risk": risk_level,
        "class": threat_class,
        "audio": has_audio,
        "network": has_network,
        "remote_index": remote_index,
        "persona": persona,
    })
    save_state(STATE)

    return risk_level, "; ".join(reasons) if reasons else "No obvious risk indicators.", score, mitre_tags, threat_class, remote_index, persona

def sandbox_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.suspend()
        log_event("SANDBOX", f"Suspended PID {pid} for sandbox inspection.")
        parent_pid, exe_path, cmdline, create_time = get_process_metadata(pid)
        file_hash = hash_file(exe_path)
        file_suspicious = analyze_pe_file(exe_path)
        mem_suspicious = analyze_memory(pid)
        return {
            "pid": pid,
            "parent_pid": parent_pid,
            "exe_path": exe_path,
            "cmdline": cmdline,
            "create_time": create_time,
            "file_hash": file_hash,
            "file_suspicious": file_suspicious,
            "mem_suspicious": mem_suspicious,
        }
    except Exception as e:
        log_event("ERROR", f"Sandbox failed for PID {pid}: {e}")
        return None

def resume_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.resume()
        log_event("SANDBOX", f"Resumed PID {pid} from sandbox.")
    except Exception as e:
        log_event("ERROR", f"Resume failed for PID {pid}: {e}")

def kill_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        gone, alive = psutil.wait_procs([proc], timeout=3)
        for p in alive:
            p.kill()
        log_event("SANDBOX", f"Killed PID {pid} from sandbox.")
    except Exception as e:
        log_event("ERROR", f"Kill failed for PID {pid}: {e}")

def auto_block_if_needed(info: ProcessSecurityInfo, gui_confirm_callback=None):
    if info.pid is None:
        return
    mode = RULES.get("mode", DEFAULT_MODE).upper()
    if mode == "SILENT":
        return
    name_lower = (info.name or "").lower()
    if is_allowlisted(name_lower):
        return
    threshold = get_dynamic_threshold()
    if info.score < threshold:
        return

    sb = sandbox_process(info.pid)
    if gui_confirm_callback:
        decision = gui_confirm_callback(info, sb)
        if decision == "kill":
            kill_process(info.pid)
        elif decision == "resume":
            resume_process(info.pid)
        else:
            resume_process(info.pid)
    else:
        kill_process(info.pid)

def build_security_snapshot(gui_confirm_callback=None):
    snapshot = []
    audio_sessions = get_audio_sessions()

    for pid, name, volume, muted in audio_sessions:
        audio_profile = audio_fingerprint(volume)

        if pid is None:
            connections = []
            parent_pid = None
            exe_path = ""
            cmdline = ""
            create_time = None
            file_hash = None
            file_suspicious = False
            mem_suspicious = False
            risk_level, risk_reason, score, mitre_tags, threat_class, remote_index, persona = assess_risk(
                name, pid, volume, muted, connections, file_suspicious, mem_suspicious
            )
            info = ProcessSecurityInfo(
                pid, name, volume, muted, connections,
                risk_level, risk_reason, score, mitre_tags,
                parent_pid, exe_path, cmdline, create_time,
                file_hash, file_suspicious,
                mem_suspicious, threat_class,
                audio_profile,
                remote_index,
                persona
            )
            snapshot.append(info)
            continue

        connections = get_process_connections(pid)
        parent_pid, exe_path, cmdline, create_time = get_process_metadata(pid)
        file_hash = hash_file(exe_path)
        file_suspicious = analyze_pe_file(exe_path)
        mem_suspicious = analyze_memory(pid)
        risk_level, risk_reason, score, mitre_tags, threat_class, remote_index, persona = assess_risk(
            name, pid, volume, muted, connections, file_suspicious, mem_suspicious
        )
        info = ProcessSecurityInfo(
            pid, name, volume, muted, connections,
            risk_level, risk_reason, score, mitre_tags,
            parent_pid, exe_path, cmdline, create_time,
            file_hash, file_suspicious,
            mem_suspicious, threat_class,
            audio_profile,
            remote_index,
            persona
        )
        auto_block_if_needed(info, gui_confirm_callback)
        snapshot.append(info)

    if "timeline" not in STATE:
        STATE["timeline"] = []
    for info in snapshot:
        STATE["timeline"].append({
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "pid": info.pid,
            "name": info.name,
            "score": info.score,
            "risk": info.risk_level,
            "class": info.threat_class,
            "remote_index": info.remote_index,
            "persona": info.persona,
        })
    save_state(STATE)

    clusters = build_clusters(snapshot)
    STATE["clusters"] = clusters
    save_state(STATE)

    return snapshot

def build_clusters(snapshot):
    clusters = []
    for info in snapshot:
        if info.pid is None:
            continue
        cluster = {
            "pid": info.pid,
            "name": info.name,
            "parent_pid": info.parent_pid,
            "external_ips": list({c[1].split(":")[0] for c in info.connections if c[3]}),
            "remote_index": info.remote_index,
            "persona": info.persona,
        }
        clusters.append(cluster)
    return clusters

# -----------------------------
# Honeypot listener
# -----------------------------
def honeypot_worker(port):
    pythoncom.CoInitialize()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
        sock.listen(5)
        log_event("HONEYPOT", f"Listening on fake service port {port}")
        while True:
            conn, addr = sock.accept()
            log_event("HONEYPOT", f"Connection from {addr[0]}:{addr[1]} to port {port}")
            try:
                conn.sendall(b"Fake service.\r\n")
            except Exception:
                pass
            conn.close()
    except Exception as e:
        log_event("ERROR", f"Honeypot failed on port {port}: {e}")

def start_honeypot():
    for p in HONEYPOT_PORTS:
        t = threading.Thread(target=honeypot_worker, args=(p,), daemon=True)
        t.start()

# -----------------------------
# Threat report & incident pack
# -----------------------------
def generate_report(snapshot):
    report = {
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "entries": [],
    }
    for info in snapshot:
        report["entries"].append({
            "pid": info.pid,
            "name": info.name,
            "score": info.score,
            "risk": info.risk_level,
            "class": info.threat_class,
            "persona": info.persona,
            "remote_index": info.remote_index,
            "mitre": info.mitre_tags,
            "exe_path": info.exe_path,
            "file_hash": info.file_hash,
            "file_suspicious": info.file_suspicious,
            "mem_suspicious": info.mem_suspicious,
            "audio_profile": info.audio_profile,
            "connections": info.connections,
        })
    try:
        with open(REPORT_FILE_JSON, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        with open(REPORT_FILE_TXT, "w", encoding="utf-8") as f:
            for e in report["entries"]:
                f.write(
                    f"PID {e['pid']} {e['name']} score={e['score']} risk={e['risk']} class={e['class']} "
                    f"persona={e['persona']} remote_index={e['remote_index']} "
                    f"file_susp={e['file_suspicious']} mem_susp={e['mem_suspicious']} mitre={e['mitre']}\n"
                )
        log_event("REPORT", f"Threat report written to {REPORT_FILE_JSON} and {REPORT_FILE_TXT}")
    except Exception as e:
        log_event("ERROR", f"Failed to write report: {e}")

def create_incident_pack(snapshot):
    generate_report(snapshot)
    try:
        with open("snapshot.json", "w", encoding="utf-8") as f:
            json.dump(
                [
                    {
                        "pid": s.pid,
                        "name": s.name,
                        "score": s.score,
                        "risk": s.risk_level,
                        "class": s.threat_class,
                        "persona": s.persona,
                        "remote_index": s.remote_index,
                    }
                    for s in snapshot
                ],
                f,
                indent=2,
            )
        with zipfile.ZipFile(INCIDENT_ZIP, "w", zipfile.ZIP_DEFLATED) as z:
            for fn in [LOG_FILE, STATE_FILE, RULES_FILE, REPORT_FILE_JSON, REPORT_FILE_TXT, "snapshot.json", INCIDENT_SESSION_FILE]:
                if os.path.exists(fn):
                    z.write(fn)
        log_event("INCIDENT", f"Incident pack written to {INCIDENT_ZIP}")
    except Exception as e:
        log_event("ERROR", f"Failed to create incident pack: {e}")

def freeze_incident_session(snapshot):
    session = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "snapshot": [
            {
                "pid": s.pid,
                "name": s.name,
                "score": s.score,
                "risk": s.risk_level,
                "class": s.threat_class,
                "persona": s.persona,
                "remote_index": s.remote_index,
                "audio_profile": s.audio_profile,
                "connections": s.connections,
            }
            for s in snapshot
        ],
        "timeline_last_60_entries": STATE.get("timeline", [])[-60:],
    }
    try:
        with open(INCIDENT_SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump(session, f, indent=2)
        log_event("INCIDENT", f"Incident session frozen to {INCIDENT_SESSION_FILE}")
    except Exception as e:
        log_event("ERROR", f"Failed to freeze incident session: {e}")

# -----------------------------
# GUI
# -----------------------------
class SecurityBridgeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Bridge - v6.1 (Personas + Remote Index + Incident Session + Clusters + Noise Filter)")
        self.root.geometry("1600x850")

        self.auto_refresh = tk.BooleanVar(value=True)
        self.refresh_interval = 5

        self._build_ui()
        self._start_auto_refresh()

    def _build_ui(self):
        top_frame = ttk.Frame(self.root)
        top_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(
            top_frame,
            text="Security Bridge v6.1 - Investigation-centric",
            font=("Segoe UI", 11, "bold")
        ).pack(side=tk.LEFT)

        self.mode_var = tk.StringVar(value=RULES.get("mode", DEFAULT_MODE).upper())
        ttk.Label(top_frame, text="Mode:").pack(side=tk.LEFT, padx=(20, 2))
        mode_combo = ttk.Combobox(top_frame, textvariable=self.mode_var, values=["AGGRESSIVE", "SILENT"], width=12)
        mode_combo.pack(side=tk.LEFT)
        mode_combo.bind("<<ComboboxSelected>>", self.on_mode_change)

        ttk.Checkbutton(
            top_frame,
            text="Auto refresh",
            variable=self.auto_refresh
        ).pack(side=tk.LEFT, padx=10)

        ttk.Button(
            top_frame,
            text="Refresh now",
            command=self.refresh_snapshot
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            top_frame,
            text="Generate report",
            command=self.generate_report_gui
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            top_frame,
            text="Incident pack",
            command=self.incident_pack_gui
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            top_frame,
            text="Culprit check",
            command=self.culprit_check_gui
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            top_frame,
            text="Freeze incident session",
            command=self.freeze_session_gui
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            top_frame,
            text="Sandbox selected",
            command=self.sandbox_selected
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            top_frame,
            text="Resume sandboxed",
            command=self.resume_selected
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            top_frame,
            text="Kill selected",
            command=self.kill_selected_process
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            top_frame,
            text="Mark selected as safe-to-ignore",
            command=self.mark_safe_selected
        ).pack(side=tk.LEFT, padx=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Processes tab
        self.proc_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.proc_frame, text="Processes")

        columns = ("pid", "process", "volume", "muted",
                   "risk", "score", "class", "persona", "remote_index", "mitre", "reason")
        self.tree = ttk.Treeview(self.proc_frame, columns=columns, show="headings")
        for col, text, width in [
            ("pid", "PID", 70),
            ("process", "Process", 220),
            ("volume", "Volume", 70),
            ("muted", "Muted", 70),
            ("risk", "Risk", 80),
            ("score", "Score", 70),
            ("class", "Class", 120),
            ("persona", "Persona", 160),
            ("remote_index", "RemoteIdx", 90),
            ("mitre", "MITRE", 200),
            ("reason", "Reason", 500),
        ]:
            self.tree.heading(col, text=text)
            self.tree.column(col, width=width, anchor=tk.CENTER if col in ("pid", "volume", "muted", "risk", "score", "remote_index") else tk.W)
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_process_select)

        # Timeline tab
        self.timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.timeline_frame, text="Threat Timeline")
        self.timeline_text = scrolledtext.ScrolledText(self.timeline_frame, wrap=tk.WORD, height=20)
        self.timeline_text.pack(fill=tk.BOTH, expand=True)

        # Remote-control tab
        self.remote_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.remote_frame, text="Remote-Control Tools / Remote Index")
        self.remote_text = scrolledtext.ScrolledText(self.remote_frame, wrap=tk.WORD, height=20)
        self.remote_text.pack(fill=tk.BOTH, expand=True)

        # Audio focus tab
        self.audio_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.audio_frame, text="Suspicious Audio Focus")
        self.audio_text = scrolledtext.ScrolledText(self.audio_frame, wrap=tk.WORD, height=20)
        self.audio_text.pack(fill=tk.BOTH, expand=True)

        # Rule editor tab
        self.rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.rules_frame, text="Rule Editor")
        self._build_rule_editor(self.rules_frame)

        # Per-process history tab
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="Process History")
        self.history_text = scrolledtext.ScrolledText(self.history_frame, wrap=tk.WORD, height=20)
        self.history_text.pack(fill=tk.BOTH, expand=True)

        # Clusters tab
        self.cluster_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.cluster_frame, text="Correlation Clusters")
        self.cluster_text = scrolledtext.ScrolledText(self.cluster_frame, wrap=tk.WORD, height=20)
        self.cluster_text.pack(fill=tk.BOTH, expand=True)

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=10, pady=3)

    def _build_rule_editor(self, frame):
        pad = 5
        ttk.Label(frame, text="Allowlist (one name per line):").pack(anchor=tk.W, padx=pad, pady=(pad, 0))
        self.allow_text = scrolledtext.ScrolledText(frame, height=6)
        self.allow_text.pack(fill=tk.X, padx=pad, pady=(0, pad))

        ttk.Label(frame, text="Block (remote tool) keywords (one per line):").pack(anchor=tk.W, padx=pad, pady=(pad, 0))
        self.block_text = scrolledtext.ScrolledText(frame, height=6)
        self.block_text.pack(fill=tk.X, padx=pad, pady=(0, pad))

        ttk.Label(frame, text="Suspicious ports (comma-separated):").pack(anchor=tk.W, padx=pad, pady=(pad, 0))
        self.ports_entry = ttk.Entry(frame)
        self.ports_entry.pack(fill=tk.X, padx=pad, pady=(0, pad))

        ttk.Label(frame, text="Auto-block threshold:").pack(anchor=tk.W, padx=pad, pady=(pad, 0))
        self.threshold_entry = ttk.Entry(frame)
        self.threshold_entry.pack(fill=tk.X, padx=pad, pady=(0, pad))

        ttk.Button(frame, text="Load rules", command=self.load_rules_into_editor).pack(side=tk.LEFT, padx=pad, pady=pad)
        ttk.Button(frame, text="Save rules", command=self.save_rules_from_editor).pack(side=tk.LEFT, padx=pad, pady=pad)

        self.load_rules_into_editor()

    def load_rules_into_editor(self):
        self.allow_text.delete("1.0", tk.END)
        self.block_text.delete("1.0", tk.END)
        self.ports_entry.delete(0, tk.END)
        self.threshold_entry.delete(0, tk.END)

        for n in RULES.get("allow_names", DEFAULT_ALLOW_NAMES):
            self.allow_text.insert(tk.END, n + "\n")
        for k in RULES.get("block_names", REMOTE_TOOL_KEYWORDS):
            self.block_text.insert(tk.END, k + "\n")
        self.ports_entry.insert(0, ",".join(str(p) for p in RULES.get("block_ports", SUSPICIOUS_PORTS)))
        self.threshold_entry.insert(0, str(RULES.get("auto_block_threshold", DEFAULT_AUTO_BLOCK_THRESHOLD)))

    def save_rules_from_editor(self):
        allow_lines = [l.strip() for l in self.allow_text.get("1.0", tk.END).splitlines() if l.strip()]
        block_lines = [l.strip() for l in self.block_text.get("1.0", tk.END).splitlines() if l.strip()]
        ports_str = self.ports_entry.get().strip()
        threshold_str = self.threshold_entry.get().strip()

        try:
            ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
            threshold = int(threshold_str)
        except ValueError:
            messagebox.showerror("Error", "Ports must be integers, threshold must be integer.")
            return

        RULES["allow_names"] = allow_lines
        RULES["block_names"] = block_lines
        RULES["block_ports"] = ports
        RULES["auto_block_threshold"] = threshold

        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(RULES, f, indent=2)
        except Exception:
            pass

        self.status_var.set("Rules saved.")
        messagebox.showinfo("Rules", "Rules updated and saved.")

    def on_mode_change(self, event=None):
        mode = self.mode_var.get().upper()
        RULES["mode"] = mode
        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(RULES, f, indent=2)
        except Exception:
            pass
        self.status_var.set(f"Mode changed to {mode}")

    def _start_auto_refresh(self):
        def loop():
            pythoncom.CoInitialize()
            while True:
                if self.auto_refresh.get():
                    self.refresh_snapshot()
                time.sleep(self.refresh_interval)
        t = threading.Thread(target=loop, daemon=True)
        t.start()

    def gui_confirm_autoblock(self, info, sandbox_info):
        if sandbox_info is None:
            return "kill"
        msg = (
            f"Auto-block candidate:\n\n"
            f"PID: {info.pid}\n"
            f"Name: {info.name}\n"
            f"Score: {info.score}\n"
            f"Risk: {info.risk_level}\n"
            f"Class: {info.threat_class}\n"
            f"Persona: {info.persona}\n"
            f"Remote index: {info.remote_index}\n"
            f"Executable: {sandbox_info['exe_path']}\n"
            f"SHA256: {sandbox_info['file_hash']}\n"
            f"File suspicious: {sandbox_info['file_suspicious']}\n"
            f"Memory suspicious: {sandbox_info['mem_suspicious']}\n\n"
            f"Kill this process?"
        )
        answer = messagebox.askyesnocancel("Auto-block decision", msg)
        if answer is None:
            return "resume"
        return "kill" if answer else "resume"

    def refresh_snapshot(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
        except Exception as e:
            self.status_var.set(f"Error building snapshot: {e}")
            log_event("ERROR", f"Snapshot error: {e}")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        for info in snapshot:
            vol_str = f"{int(info.volume * 100)}%" if info.volume is not None else "N/A"
            muted_str = "Yes" if info.muted else "No"
            pid_str = info.pid if info.pid is not None else "-"
            mitre_str = ",".join(info.mitre_tags) if info.mitre_tags else ""
            self.tree.insert(
                "",
                tk.END,
                values=(
                    pid_str,
                    info.name,
                    vol_str,
                    muted_str,
                    info.risk_level,
                    info.score,
                    info.threat_class,
                    info.persona,
                    info.remote_index,
                    mitre_str,
                    info.risk_reason
                )
            )

        self.update_timeline()
        self.update_remote_panel(snapshot)
        self.update_audio_focus(snapshot)
        self.update_clusters()

        self.status_var.set(f"Snapshot updated: {len(snapshot)} audio sessions")

    def update_timeline(self):
        self.timeline_text.delete("1.0", tk.END)
        timeline = STATE.get("timeline", [])
        for entry in timeline[-200:]:
            persona = entry.get("persona", "unknown")
            remote_index = entry.get("remote_index", 0)
            score = entry.get("score", 0)
            risk = entry.get("risk", "Low")
            cls = entry.get("class", "unknown")
            self.timeline_text.insert(
                tk.END,
                f"{entry.get('ts', '?')} PID {entry.get('pid', '?')} {entry.get('name', '?')} "
                f"score={score} risk={risk} class={cls} persona={persona} "
                f"remote_index={remote_index}\n"
            )

    def update_remote_panel(self, snapshot):
        self.remote_text.delete("1.0", tk.END)
        for info in snapshot:
            if info.remote_index >= 40 or any(k in (info.name or "").lower() for k in REMOTE_TOOL_KEYWORDS):
                self.remote_text.insert(
                    tk.END,
                    f"REMOTE SUSPECT: PID {info.pid} {info.name} score={info.score} "
                    f"risk={info.risk_level} class={info.threat_class} persona={info.persona} "
                    f"remote_index={info.remote_index}\n"
                )
                for laddr, raddr, status, external, rep in info.connections:
                    self.remote_text.insert(
                        tk.END,
                        f"  {laddr} -> {raddr} [{status}] external={external} rep={rep}\n"
                    )

    def update_audio_focus(self, snapshot):
        self.audio_text.delete("1.0", tk.END)
        for info in snapshot:
            if info.audio_profile["level"] in ("medium", "high") and not is_allowlisted((info.name or "").lower()):
                self.audio_text.insert(
                    tk.END,
                    f"AUDIO: PID {info.pid} {info.name} level={info.audio_profile['level']} "
                    f"voice={info.audio_profile['voice_like']} music={info.audio_profile['music_like']} "
                    f"game={info.audio_profile['game_like']} score={info.score} risk={info.risk_level} "
                    f"class={info.threat_class} persona={info.persona} remote_index={info.remote_index}\n"
                )

    def update_clusters(self):
        self.cluster_text.delete("1.0", tk.END)
        clusters = STATE.get("clusters", [])
        if not clusters:
            self.cluster_text.insert(tk.END, "No clusters recorded.\n")
            return
        self.cluster_text.insert(tk.END, "Correlation clusters (lightweight):\n\n")
        for c in clusters:
            self.cluster_text.insert(
                tk.END,
                f"PID {c.get('pid')} {c.get('name')} parent={c.get('parent_pid')} "
                f"remote_index={c.get('remote_index')} persona={c.get('persona')} "
                f"external_ips={c.get('external_ips')}\n"
            )

    def on_process_select(self, event=None):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            return
        name_lower = (process_name or "").lower()
        proc_key = f"{name_lower}:{pid}"
        hist = STATE.get("proc_history", {}).get(proc_key, [])
        self.history_text.delete("1.0", tk.END)
        self.history_text.insert(tk.END, f"History for {process_name} (PID {pid}):\n\n")
        for h in hist[-100:]:
            self.history_text.insert(
                tk.END,
                f"{h.get('ts', '?')} score={h.get('score', 0)} risk={h.get('risk', 'Low')} "
                f"class={h.get('class', 'unknown')} persona={h.get('persona', 'unknown')} "
                f"remote_index={h.get('remote_index', 0)} "
                f"audio={h.get('audio', False)} net={h.get('network', False)}\n"
            )

    def _get_selected_pid_and_name(self):
        selected = self.tree.selection()
        if not selected:
            return None, None
        item = self.tree.item(selected[0])
        pid_str = item["values"][0]
        process_name = item["values"][1]
        if pid_str == "-" or pid_str is None:
            return None, process_name
        try:
            pid = int(pid_str)
        except ValueError:
            return None, process_name
        return pid, process_name

    def kill_selected_process(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot kill", "Selected session is not tied to a user process.")
            return
        answer = messagebox.askyesno(
            "Confirm kill",
            f"Kill process {process_name} (PID {pid})?\n\nThis will forcibly stop its audio and any running activity."
        )
        if not answer:
            return
        kill_process(pid)
        self.status_var.set(f"Killed process {process_name} (PID {pid})")
        self.refresh_snapshot()

    def sandbox_selected(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot sandbox", "Selected session is not tied to a user process.")
            return
        info = sandbox_process(pid)
        if not info:
            messagebox.showerror("Sandbox failed", "Could not sandbox process.")
            return
        msg = (
            f"Sandboxed PID {pid} ({process_name})\n"
            f"Parent PID: {info['parent_pid']}\n"
            f"Executable: {info['exe_path']}\n"
            f"Cmdline: {info['cmdline']}\n"
            f"Created: {info['create_time']}\n"
            f"SHA256: {info['file_hash']}\n"
            f"File suspicious: {info['file_suspicious']}\n"
            f"Memory suspicious: {info['mem_suspicious']}\n"
        )
        messagebox.showinfo("Sandbox inspection", msg)
        self.status_var.set(f"Sandboxed PID {pid} ({process_name})")

    def resume_selected(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot resume", "Selected session is not tied to a user process.")
            return
        resume_process(pid)
        self.status_var.set(f"Resumed PID {pid} ({process_name})")
        self.refresh_snapshot()

    def generate_report_gui(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
            generate_report(snapshot)
            messagebox.showinfo("Report", f"Threat report written to {REPORT_FILE_JSON} and {REPORT_FILE_TXT}")
            self.status_var.set("Report generated.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {e}")
            self.status_var.set(f"Report error: {e}")

    def incident_pack_gui(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
            create_incident_pack(snapshot)
            messagebox.showinfo("Incident pack", f"Incident pack written to {INCIDENT_ZIP}")
            self.status_var.set("Incident pack created.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create incident pack: {e}")
            self.status_var.set(f"Incident pack error: {e}")

    def culprit_check_gui(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
        except Exception as e:
            messagebox.showerror("Error", f"Snapshot error: {e}")
            return

        candidates = [
            s for s in snapshot
            if s.audio_profile["level"] in ("medium", "high")
            and not is_allowlisted((s.name or "").lower())
        ]
        if not candidates:
            messagebox.showinfo("Culprit check", "No obvious non-allowlisted loud audio processes.")
            return

        best = max(candidates, key=lambda s: s.score)
        verdict = "LIKELY" if best.score >= 50 else "POSSIBLE"

        msg = (
            f"Culprit check verdict: {verdict} source of weird audio.\n\n"
            f"PID: {best.pid}\n"
            f"Name: {best.name}\n"
            f"Score: {best.score}\n"
            f"Risk: {best.risk_level}\n"
            f"Class: {best.threat_class}\n"
            f"Persona: {best.persona}\n"
            f"Remote index: {best.remote_index}\n"
            f"Audio level: {best.audio_profile['level']}\n"
        )
        messagebox.showinfo("Culprit check", msg)
        self.status_var.set(f"Culprit check: {verdict} - {best.name} (PID {best.pid})")

    def freeze_session_gui(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
            freeze_incident_session(snapshot)
            messagebox.showinfo("Incident session", f"Incident session frozen to {INCIDENT_SESSION_FILE}")
            self.status_var.set("Incident session frozen.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to freeze incident session: {e}")
            self.status_var.set(f"Incident session error: {e}")

    def mark_safe_selected(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot mark", "Selected session is not tied to a user process.")
            return
        name_lower = (process_name or "").lower()
        proc_key = f"{name_lower}:{pid}"
        safe_set = STATE.get("safe_to_ignore", [])
        if proc_key not in safe_set:
            safe_set.append(proc_key)
            STATE["safe_to_ignore"] = safe_set
            save_state(STATE)
        messagebox.showinfo("Noise filter", f"Marked {process_name} (PID {pid}) as safe-to-ignore.")
        self.status_var.set(f"Marked {process_name} as safe-to-ignore.")
        self.refresh_snapshot()


def main():
    log_event("INFO", "Security Bridge (Full Upgrade v6.1) started.")
    start_honeypot()
    root = tk.Tk()
    app = SecurityBridgeGUI(root)
    root.mainloop()
    log_event("INFO", "Security Bridge closed.")


if __name__ == "__main__":
    main()
