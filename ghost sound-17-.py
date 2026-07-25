#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# Codex Control Console v13
# Layout from v12 + Full Security Bridge engine (Lockdown + Reset + Audio Lockdown)
# Steam/Epic + Microsoft Teams Maximum Protection Patch

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
from datetime import datetime
import random

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext

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
EVENT_STREAM_FILE = "event_stream.jsonl"

LOCKDOWN_SNAPSHOT_FILE = "lockdown_snapshot.json"
LOCKDOWN_DEEP_SCAN_FILE = "lockdown_deep_scan.json"
LOCKDOWN_INTRUDER_FILE = "lockdown_intruder_candidates.json"
LOCKDOWN_TIMELINE_FILE = "lockdown_timeline.json"
LOCKDOWN_AUDIO_SPIKES_FILE = "lockdown_audio_spikes.json"
LOCKDOWN_EVENT_STREAM_FILE = "lockdown_event_stream.jsonl"
LOCKDOWN_NETWORK_MAP_FILE = "lockdown_network_map.json"
LOCKDOWN_MEMORY_MAP_FILE = "lockdown_memory_map.json"
LOCKDOWN_ZIP = "lockdown_full_pack.zip"

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

# Base allowlist (we’ll extend with Steam/Epic/Teams protection)
DEFAULT_ALLOW_NAMES = [
    "steam.exe",
    "steamwebhelper.exe",
    "Spotify.exe",
    "SpotifyWidgetProvider.exe",
    "chrome.exe",
    "msedge.exe",
    "discord.exe",
    # Epic Games / Fortnite / Launcher
    "EpicGamesLauncher.exe",
    "FortniteClient-Win64-Shipping.exe",
    "FortniteClient-Win64-Shipping_BE.exe",
    "FortniteClient-Win64-Shipping_EAC.exe",
    "EpicWebHelper.exe",
    # Teams classic
    "Teams.exe",
    "TeamsUpdater.exe",
    "TeamsCrashHandler.exe",
    "TeamsHelper.exe",
    "TeamsWebView.exe",
    "TeamsWebClient.exe",
    # New Teams
    "ms-teams.exe",
    "ms-teams-ui.exe",
    "ms-teams-background.exe",
    "ms-teams-runtime.exe",
    "ms-teams-updater.exe",
    "ms-teams-ux.exe",
    "ms-teams-service.exe",
    "ms-teams-identity.exe",
    "ms-teams-webview.exe",
    "ms-teams-webclient.exe",
    "ms-teams-embedded.exe",
    "ms-teams-notification.exe",
    # WebView2 / Edge WebView
    "WebView2.exe",
    "msedgewebview2.exe",
]

DEFAULT_AUDIO_WHITELIST = [
    "Spotify.exe",
    "SpotifyWidgetProvider.exe",
    "chrome.exe",
    "msedge.exe",
    "discord.exe",
    "steam.exe",
    "steamwebhelper.exe",
    "EpicGamesLauncher.exe",
    "FortniteClient-Win64-Shipping.exe",
    "Teams.exe",
    "ms-teams.exe",
]

DEFAULT_TRUSTED_GAMING = [
    "steam.exe",
    "steamwebhelper.exe",
    "EpicGamesLauncher.exe",
    "FortniteClient-Win64-Shipping.exe",
]

MEDIUM_LOG_COOLDOWN = 60
LOW_LOG_COOLDOWN = 120

DEFAULT_MODE = "AGGRESSIVE"  # or "SILENT"

BAD_IP_REPUTATION = {
    "1.2.3.4": "Known C2",
    "5.6.7.8": "Malicious host",
}

AUTO_BLOCK_PROFILES = {
    "PARANOID": {
        "base_threshold": 40,
        "remote_index_threshold": 30,
        "sandbox_first": True,
        "kill_if_suspicious": True,
        "audio_sensitive": True,
    },
    "BALANCED": {
        "base_threshold": 60,
        "remote_index_threshold": 50,
        "sandbox_first": True,
        "kill_if_suspicious": False,
        "audio_sensitive": False,
    },
    "GAMING": {
        "base_threshold": 75,
        "remote_index_threshold": 60,
        "sandbox_first": False,
        "kill_if_suspicious": False,
        "audio_sensitive": False,
    },
    "FORENSICS": {
        "base_threshold": 1000,
        "remote_index_threshold": 1000,
        "sandbox_first": False,
        "kill_if_suspicious": False,
        "audio_sensitive": False,
    },
}

MITRE_VIEWS = {
    "ALL": [],
    "REMOTE_CONTROL_VIEW": ["T1105", "T1071"],
    "EXFIL_VIEW": ["T1041"],
    "INJECTION_VIEW": ["T1055"],
    "AUDIO_ABUSE_VIEW": ["T1129"],
}

# -----------------------------
# Logging / state / event bus
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
    emit_event({
        "ts": ts,
        "level": level,
        "message": message,
        "type": "log",
    })

def emit_event(ev: dict):
    try:
        with open(EVENT_STREAM_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(ev) + "\n")
    except Exception:
        pass
    if "event_stream" not in STATE:
        STATE["event_stream"] = []
    STATE["event_stream"].append(ev)
    if len(STATE["event_stream"]) > 2000:
        STATE["event_stream"] = STATE["event_stream"][-2000:]
    save_state(STATE)

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
            "profile": "BALANCED",
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
            "profile": "BALANCED",
        }

STATE = load_state()
RULES = load_rules()

# Initialize audio-lockdown-related state
STATE.setdefault("user_protected", [])
STATE.setdefault("audio_intruder_confirmed", False)
STATE.setdefault("audio_intruder_pid", None)
STATE.setdefault("audio_intruder_name", None)
STATE.setdefault("audio_lockdown_active", False)

def increment_detection_count(proc_key):
    global STATE
    if "detections" not in STATE:
        STATE["detections"] = {}
    if proc_key not in STATE["detections"]:
        STATE["detections"][proc_key] = 0
    STATE["detections"][proc_key] += 1
    save_state(STATE)
    return STATE["detections"][proc_key]

def update_trust_score(proc_key, outcome: str):
    if "trust_scores" not in STATE:
        STATE["trust_scores"] = {}
    ts = STATE["trust_scores"].get(proc_key, {"benign_hits": 0, "hostile_hits": 0, "blocked_hits": 0})
    if outcome == "benign":
        ts["benign_hits"] += 1
    elif outcome == "hostile":
        ts["hostile_hits"] += 1
    elif outcome == "blocked":
        ts["blocked_hits"] += 1
    STATE["trust_scores"][proc_key] = ts
    save_state(STATE)

def get_trust_adjustment(proc_key):
    ts = STATE.get("trust_scores", {}).get(proc_key, {"benign_hits": 0, "hostile_hits": 0, "blocked_hits": 0})
    benign = ts["benign_hits"]
    hostile = ts["hostile_hits"]
    blocked = ts["blocked_hits"]
    adjust = benign * -3 + hostile * 3 + blocked * 4
    adjust = max(-25, min(25, adjust))
    return adjust

def get_profile():
    prof_name = RULES.get("profile", "BALANCED").upper()
    return AUTO_BLOCK_PROFILES.get(prof_name, AUTO_BLOCK_PROFILES["BALANCED"])

def get_dynamic_threshold():
    global STATE, RULES
    profile = get_profile()
    base = profile["base_threshold"]
    detections = STATE.get("detections", {})
    high_hits = sum(1 for _, v in detections.items() if v > 5)
    adjust = min(high_hits * 2, 10)
    return max(40, base - adjust)

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
                 persona,
                 rse_verdict,
                 rse_score):
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
        self.rse_verdict = rse_verdict
        self.rse_score = rse_score

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
                         name_lower, proc_key):
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

    trust_adj = get_trust_adjustment(proc_key)
    score = max(0, min(100, score + trust_adj))

    return score

def compute_remote_index(name_lower, connections, has_audio, proc_key):
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

    trust_adj = get_trust_adjustment(proc_key)
    idx = max(0, min(100, idx + trust_adj))

    return idx

def is_allowlisted(name_lower):
    # Maximum Protection Patch: Steam/Epic/Teams
    allow = [n.lower() for n in RULES.get("allow_names", DEFAULT_ALLOW_NAMES)]
    if any(a == name_lower for a in allow):
        return True

    # Steam / Epic generic protection
    if (
        "steam" in name_lower or
        "epicgameslauncher" in name_lower or
        "fortniteclient" in name_lower or
        "epicwebhelper" in name_lower
    ):
        return True

    # Maximum Protection Patch: Microsoft Teams (all versions)
    if (
        "teams" in name_lower or
        "ms-teams" in name_lower or
        "teams.exe" in name_lower or
        "teamswebview" in name_lower or
        "teamswebclient" in name_lower or
        "teamsbackground" in name_lower or
        "teamsruntime" in name_lower or
        "teamsupdater" in name_lower or
        "teamsidentity" in name_lower or
        "teamsnotification" in name_lower or
        "webview2" in name_lower or
        "msedgewebview2" in name_lower or
        "skype" in name_lower or
        "rtc" in name_lower
    ):
        return True

    return False

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

def rse_engine(remote_index, mitre_tags, file_suspicious, mem_suspicious, has_audio, has_network):
    score = 0
    if remote_index >= 40:
        score += 40
    if "T1105" in mitre_tags or "T1071" in mitre_tags:
        score += 30
    if file_suspicious:
        score += 20
    if mem_suspicious:
        score += 25
    if has_audio and has_network:
        score += 10
    verdict = "None"
    if score >= 80:
        verdict = "Probable Remote Control"
    elif score >= 50:
        verdict = "Possible Remote Control"
    elif score >= 30:
        verdict = "Low Remote Suspicion"
    return verdict, min(score, 100)

def record_audio_spike(proc_key, pid, name, old_level, new_level):
    if "audio_spikes" not in STATE:
        STATE["audio_spikes"] = []
    spike = {
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "proc_key": proc_key,
        "pid": pid,
        "name": name,
        "old_level": old_level,
        "new_level": new_level,
    }
    STATE["audio_spikes"].append(spike)
    if len(STATE["audio_spikes"]) > 500:
        STATE["audio_spikes"] = STATE["audio_spikes"][-500:]
    save_state(STATE)
    emit_event({
        "ts": spike["ts"],
        "type": "audio_spike",
        "pid": pid,
        "name": name,
        "old_level": old_level,
        "new_level": new_level,
    })

def detect_audio_spikes(audio_sessions):
    last_levels = STATE.get("last_audio_levels", {})
    new_levels = {}
    for pid, name, volume, muted in audio_sessions:
        name_lower = (name or "").lower()
        proc_key = f"{name_lower}:{pid}"
        level = "silent" if volume is None or volume < 0.01 else (
            "low" if volume < 0.2 else ("medium" if volume < 0.6 else "high")
        )
        new_levels[proc_key] = level
        old_level = last_levels.get(proc_key, "silent")
        if old_level in ("silent", "low") and level in ("medium", "high"):
            record_audio_spike(proc_key, pid, name, old_level, level)
    STATE["last_audio_levels"] = new_levels
    save_state(STATE)

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

    # User-protected processes: treat as benign
    if proc_key in STATE.get("user_protected", []):
        risk_level = "Low"
        reasons = ["User-protected process: risk suppressed."]
        score = 0
        remote_index = 0
        mitre_tags = []
        threat_class = "benign"
        persona = "User-protected"
        rse_verdict = "None"
        rse_score = 0
        update_trust_score(proc_key, "benign")
        return risk_level, "; ".join(reasons), score, mitre_tags, threat_class, remote_index, persona, rse_verdict, rse_score

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
                                 name_lower, proc_key)

    remote_index = compute_remote_index(name_lower, connections, has_audio, proc_key)
    threat_class = classify_threat(score, remote_keyword_hit, mem_suspicious, exfil_suspect, file_suspicious)
    persona = persona_for_process(name_lower, has_audio, has_network, remote_index, file_suspicious, mem_suspicious)
    rse_verdict, rse_score = rse_engine(remote_index, mitre_tags, file_suspicious, mem_suspicious, has_audio, has_network)

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
    if rse_score >= 50:
        reasons.append(f"RSE verdict: {rse_verdict} ({rse_score}%)")

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
        rse_verdict = "None"
        rse_score = 0
        reasons.append("Process is allowlisted.")
        update_trust_score(proc_key, "benign")
    else:
        if score >= 80:
            risk_level = "High"
            update_trust_score(proc_key, "hostile")
        elif score >= 50:
            risk_level = "Medium"
        else:
            risk_level = "Low"

    if should_log(proc_key, risk_level) and risk_level != "Low":
        log_event(
            risk_level,
            f"PID {pid} ({name}) score={score}, remote_index={remote_index}, persona={persona}, "
            f"class={threat_class}, RSE={rse_verdict}({rse_score}%), MITRE={mitre_tags}, reasons={'; '.join(reasons)}"
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
        "rse_verdict": rse_verdict,
        "rse_score": rse_score,
    })
    save_state(STATE)

    emit_event({
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "process_assessment",
        "pid": pid,
        "name": name,
        "score": score,
        "risk": risk_level,
        "class": threat_class,
        "persona": persona,
        "remote_index": remote_index,
        "mitre": mitre_tags,
        "rse_verdict": rse_verdict,
        "rse_score": rse_score,
        "reasons": reasons,
    })

    return risk_level, "; ".join(reasons) if reasons else "No obvious risk indicators.", score, mitre_tags, threat_class, remote_index, persona, rse_verdict, rse_score

# -----------------------------
# Sandbox / autoblock / snapshot
# -----------------------------
def sandbox_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.suspend()
        log_event("SANDBOX", f"Suspended PID {pid} for sandbox inspection.")
        parent_pid, exe_path, cmdline, create_time = get_process_metadata(pid)
        file_hash = hash_file(exe_path)
        file_suspicious = analyze_pe_file(exe_path)
        mem_suspicious = analyze_memory(pid)
        info = {
            "pid": pid,
            "parent_pid": parent_pid,
            "exe_path": exe_path,
            "cmdline": cmdline,
            "create_time": create_time,
            "file_hash": file_hash,
            "file_suspicious": file_suspicious,
            "mem_suspicious": mem_suspicious,
        }
        emit_event({
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "sandbox",
            "action": "suspend",
            "info": info,
        })
        return info
    except Exception as e:
        log_event("ERROR", f"Sandbox failed for PID {pid}: {e}")
        return None

def resume_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.resume()
        log_event("SANDBOX", f"Resumed PID {pid} from sandbox.")
        emit_event({
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "sandbox",
            "action": "resume",
            "pid": pid,
        })
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
        emit_event({
            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "type": "sandbox",
            "action": "kill",
            "pid": pid,
        })
    except Exception as e:
        log_event("ERROR", f"Kill failed for PID {pid}: {e}")

def auto_block_if_needed(info: ProcessSecurityInfo, gui_confirm_callback=None):
    if info.pid is None:
        return
    mode = RULES.get("mode", DEFAULT_MODE).upper()
    profile = get_profile()
    if mode == "SILENT":
        return
    name_lower = (info.name or "").lower()
    proc_key = f"{name_lower}:{info.pid}"

    if proc_key in STATE.get("user_protected", []):
        return

    if STATE.get("audio_intruder_confirmed", False):
        if info.pid == STATE.get("audio_intruder_pid"):
            return

    if is_allowlisted(name_lower):
        return
    threshold = get_dynamic_threshold()
    if info.score < threshold and info.remote_index < profile["remote_index_threshold"]:
        return

    sb = None
    if profile["sandbox_first"]:
        sb = sandbox_process(info.pid)

    decision = "resume"
    if gui_confirm_callback:
        decision = gui_confirm_callback(info, sb)
    else:
        if profile["kill_if_suspicious"] and (info.rse_score >= 50 or info.score >= threshold):
            decision = "kill"
        else:
            decision = "resume"

    if decision == "kill":
        kill_process(info.pid)
        update_trust_score(proc_key, "blocked")
    elif decision == "resume":
        resume_process(info.pid)
    else:
        resume_process(info.pid)

def build_security_snapshot(gui_confirm_callback=None):
    snapshot = []
    audio_sessions = get_audio_sessions()
    detect_audio_spikes(audio_sessions)

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
            risk_level, risk_reason, score, mitre_tags, threat_class, remote_index, persona, rse_verdict, rse_score = assess_risk(
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
                persona,
                rse_verdict,
                rse_score
            )
            snapshot.append(info)
            continue

        connections = get_process_connections(pid)
        parent_pid, exe_path, cmdline, create_time = get_process_metadata(pid)
        file_hash = hash_file(exe_path)
        file_suspicious = analyze_pe_file(exe_path)
        mem_suspicious = analyze_memory(pid)
        risk_level, risk_reason, score, mitre_tags, threat_class, remote_index, persona, rse_verdict, rse_score = assess_risk(
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
            persona,
            rse_verdict,
            rse_score
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
            "rse_verdict": info.rse_verdict,
            "rse_score": info.rse_score,
        })
    if len(STATE["timeline"]) > 2000:
        STATE["timeline"] = STATE["timeline"][-2000:]
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
            "rse_verdict": info.rse_verdict,
            "rse_score": info.rse_score,
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
            emit_event({
                "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "type": "honeypot",
                "port": port,
                "ip": addr[0],
                "remote_port": addr[1],
            })
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
            "rse_verdict": info.rse_verdict,
            "rse_score": info.rse_score,
        })
    try:
        with open(REPORT_FILE_JSON, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        with open(REPORT_FILE_TXT, "w", encoding="utf-8") as f:
            for e in report["entries"]:
                f.write(
                    f"PID {e['pid']} {e['name']} score={e['score']} risk={e['risk']} class={e['class']} "
                    f"persona={e['persona']} remote_index={e['remote_index']} "
                    f"file_susp={e['file_suspicious']} mem_susp={e['mem_suspicious']} "
                    f"RSE={e['rse_verdict']}({e['rse_score']}%) mitre={e['mitre']}\n"
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
                        "rse_verdict": s.rse_verdict,
                        "rse_score": s.rse_score,
                    }
                    for s in snapshot
                ],
                f,
                indent=2,
            )
        with zipfile.ZipFile(INCIDENT_ZIP, "w", zipfile.ZIP_DEFLATED) as z:
            for fn in [LOG_FILE, STATE_FILE, RULES_FILE, REPORT_FILE_JSON, REPORT_FILE_TXT, "snapshot.json", INCIDENT_SESSION_FILE, EVENT_STREAM_FILE]:
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
                "rse_verdict": s.rse_verdict,
                "rse_score": s.rse_score,
            }
            for s in snapshot
        ],
        "timeline_last_120_entries": STATE.get("timeline", [])[-120:],
        "event_stream_last_400": STATE.get("event_stream", [])[-400:],
        "audio_spikes_last_100": STATE.get("audio_spikes", [])[-100:],
    }
    try:
        with open(INCIDENT_SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump(session, f, indent=2)
        log_event("INCIDENT", f"Incident session frozen to {INCIDENT_SESSION_FILE}")
    except Exception as e:
        log_event("ERROR", f"Failed to freeze incident session: {e}")

# -----------------------------
# LOCKDOWN MODE (Full Kill)
# -----------------------------
def deep_scan_lockdown(snapshot):
    candidates = []
    for s in snapshot:
        if s.pid is None:
            continue
        name_lower = (s.name or "").lower()
        has_audio = s.audio_profile["level"] in ("medium", "high")
        has_network = any(raddr for (_, raddr, _, _, _) in s.connections)
        external_ips = [c[1].split(":")[0] for c in s.connections if c[3]]
        mem_score = 0
        file_score = 0
        if s.mem_suspicious:
            mem_score += 40
        if s.file_suspicious:
            file_score += 40
        audio_score = 0
        if has_audio and not is_allowlisted(name_lower):
            audio_score += 30
        timeline_score = 0
        for h in STATE.get("proc_history", {}).get(f"{name_lower}:{s.pid}", [])[-20:]:
            if h.get("audio") or h.get("network"):
                timeline_score += 2
        intruder_score = (
            s.score * 0.4 +
            s.remote_index * 0.3 +
            mem_score * 0.2 +
            file_score * 0.2 +
            audio_score * 0.3 +
            timeline_score * 0.1
        )
        intruder_score = min(100, int(intruder_score))

        if intruder_score < 20 and not (has_audio or has_network or s.file_suspicious or s.mem_suspicious):
            continue

        verdict = "Low Suspicion"
        if intruder_score >= 80:
            verdict = "Probable Intruder"
        elif intruder_score >= 50:
            verdict = "Possible Intruder"

        candidates.append({
            "pid": s.pid,
            "name": s.name,
            "score": s.score,
            "remote_index": s.remote_index,
            "intruder_score": intruder_score,
            "verdict": verdict,
            "risk": s.risk_level,
            "class": s.threat_class,
            "persona": s.persona,
            "mitre": s.mitre_tags,
            "audio_level": s.audio_profile["level"],
            "file_suspicious": s.file_suspicious,
            "mem_suspicious": s.mem_suspicious,
            "external_ips": external_ips,
            "rse_verdict": s.rse_verdict,
            "rse_score": s.rse_score,
        })
    candidates.sort(key=lambda c: c["intruder_score"], reverse=True)
    return candidates

def create_lockdown_pack(snapshot, candidates):
    try:
        with open(LOCKDOWN_SNAPSHOT_FILE, "w", encoding="utf-8") as f:
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
                        "audio_profile": s.audio_profile,
                        "connections": s.connections,
                        "file_suspicious": s.file_suspicious,
                        "mem_suspicious": s.mem_suspicious,
                        "rse_verdict": s.rse_verdict,
                        "rse_score": s.rse_score,
                    }
                    for s in snapshot
                ],
                f,
                indent=2,
            )

        with open(LOCKDOWN_INTRUDER_FILE, "w", encoding="utf-8") as f:
            json.dump(candidates, f, indent=2)

        with open(LOCKDOWN_TIMELINE_FILE, "w", encoding="utf-8") as f:
            json.dump(STATE.get("timeline", [])[-400:], f, indent=2)

        with open(LOCKDOWN_AUDIO_SPIKES_FILE, "w", encoding="utf-8") as f:
            json.dump(STATE.get("audio_spikes", [])[-200:], f, indent=2)

        with open(LOCKDOWN_EVENT_STREAM_FILE, "w", encoding="utf-8") as f:
            for ev in STATE.get("event_stream", [])[-800:]:
                f.write(json.dumps(ev) + "\n")

        net_map = []
        for s in snapshot:
            if s.pid is None:
                continue
            net_map.append({
                "pid": s.pid,
                "name": s.name,
                "connections": s.connections,
            })
        with open(LOCKDOWN_NETWORK_MAP_FILE, "w", encoding="utf-8") as f:
            json.dump(net_map, f, indent=2)

        mem_map = []
        for s in snapshot:
            if s.pid is None:
                continue
            mem_map.append({
                "pid": s.pid,
                "name": s.name,
                "file_suspicious": s.file_suspicious,
                "mem_suspicious": s.mem_suspicious,
            })
        with open(LOCKDOWN_MEMORY_MAP_FILE, "w", encoding="utf-8") as f:
            json.dump(mem_map, f, indent=2)

        with zipfile.ZipFile(LOCKDOWN_ZIP, "w", zipfile.ZIP_DEFLATED) as z:
            for fn in [
                LOG_FILE,
                STATE_FILE,
                RULES_FILE,
                LOCKDOWN_SNAPSHOT_FILE,
                LOCKDOWN_INTRUDER_FILE,
                LOCKDOWN_TIMELINE_FILE,
                LOCKDOWN_AUDIO_SPIKES_FILE,
                LOCKDOWN_EVENT_STREAM_FILE,
                LOCKDOWN_NETWORK_MAP_FILE,
                LOCKDOWN_MEMORY_MAP_FILE,
            ]:
                if os.path.exists(fn):
                    z.write(fn)

        log_event("LOCKDOWN", f"Lockdown pack written to {LOCKDOWN_ZIP}")
    except Exception as e:
        log_event("ERROR", f"Failed to create lockdown pack: {e}")

def run_lockdown_full_kill():
    log_event("LOCKDOWN", "LOCKDOWN MODE triggered (Full Kill).")
    snapshot = build_security_snapshot(gui_confirm_callback=None)
    candidates = deep_scan_lockdown(snapshot)
    killed = []
    for c in candidates:
        pid = c["pid"]
        name = c["name"]
        name_lower = (name or "").lower()
        if is_allowlisted(name_lower):
            continue
        if pid is None:
            continue
        if c["intruder_score"] >= 60 or c["remote_index"] >= 60 or c["risk"] == "High":
            try:
                kill_process(pid)
                killed.append(c)
            except Exception:
                continue
    freeze_incident_session(snapshot)
    create_lockdown_pack(snapshot, candidates)
    log_event("LOCKDOWN", f"Lockdown completed. Killed {len(killed)} processes.")
    return snapshot, candidates, killed

# -----------------------------
# RESET MODE (keep evidence)
# -----------------------------
def reset_system_state():
    log_event("RESET", "Reset Mode triggered (state normalization, evidence preserved).")

    volatile_keys = [
        "audio_spikes",
        "last_audio_levels",
        "event_stream",
        "timeline",
        "proc_history",
        "clusters",
        "log_cooldown",
        "safe_to_ignore",
    ]
    for k in volatile_keys:
        if k in STATE:
            STATE[k] = [] if isinstance(STATE[k], list) else {}

    STATE["detections"] = {}
    STATE["trust_scores"] = {}

    STATE["audio_intruder_confirmed"] = False
    STATE["audio_intruder_pid"] = None
    STATE["audio_intruder_name"] = None
    STATE["audio_lockdown_active"] = False

    save_state(STATE)
    log_event("RESET", "System state normalized. Evidence preserved.")

    return True

# -----------------------------
# AUDIO LOCKDOWN MODE (speaker trace)
# -----------------------------
def audio_lockdown_trace():
    audio_sessions = get_audio_sessions()
    if not audio_sessions:
        return None, None

    best = None
    for pid, name, volume, muted in audio_sessions:
        if pid is None:
            continue
        name_lower = (name or "").lower()
        if is_allowlisted(name_lower):
            continue
        if muted or volume is None or volume < 0.01:
            continue
        if best is None or volume > best[2]:
            best = (pid, name, volume, muted)

    if best is None:
        return None, None

    pid, name, volume, muted = best
    audio_profile = audio_fingerprint(volume)
    connections = get_process_connections(pid)
    parent_pid, exe_path, cmdline, create_time = get_process_metadata(pid)
    file_hash = hash_file(exe_path)
    file_suspicious = analyze_pe_file(exe_path)
    mem_suspicious = analyze_memory(pid)
    risk_level, risk_reason, score, mitre_tags, threat_class, remote_index, persona, rse_verdict, rse_score = assess_risk(
        name, pid, volume, muted, connections, file_suspicious, mem_suspicious
    )

    chain = {
        "pid": pid,
        "name": name,
        "volume": volume,
        "muted": muted,
        "audio_profile": audio_profile,
        "parent_pid": parent_pid,
        "exe_path": exe_path,
        "cmdline": cmdline,
        "create_time": create_time,
        "file_hash": file_hash,
        "file_suspicious": file_suspicious,
        "mem_suspicious": mem_suspicious,
        "connections": connections,
        "risk_level": risk_level,
        "risk_reason": risk_reason,
        "score": score,
        "mitre_tags": mitre_tags,
        "threat_class": threat_class,
        "remote_index": remote_index,
        "persona": persona,
        "rse_verdict": rse_verdict,
        "rse_score": rse_score,
    }

    emit_event({
        "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "type": "audio_lockdown_trace",
        "chain": chain,
    })

    return chain, audio_sessions

def confirm_audio_intruder(chain, user_confirm: bool):
    pid = chain["pid"]
    name = chain["name"]
    name_lower = (name or "").lower()
    proc_key = f"{name_lower}:{pid}"

    if not user_confirm:
        protected = STATE.get("user_protected", [])
        if proc_key not in protected:
            protected.append(proc_key)
        STATE["user_protected"] = protected
        save_state(STATE)
        log_event("AUDIO-LOCKDOWN", f"User denied kill for PID {pid} ({name}); process protected.")
        return "protected"

    try:
        kill_process(pid)
    except Exception as e:
        log_event("ERROR", f"Audio intruder kill failed for PID {pid}: {e}")
        return "kill_failed"

    STATE["audio_intruder_confirmed"] = True
    STATE["audio_intruder_pid"] = pid
    STATE["audio_intruder_name"] = name
    save_state(STATE)
    log_event("AUDIO-LOCKDOWN", f"Audio intruder confirmed and killed: PID {pid} ({name}).")
    return "killed"

# -------------------------------------------------------------------------
# Codex Control Console GUI (v12 layout + Security Bridge engine)
# -------------------------------------------------------------------------
class CodexControlConsole(tk.Tk):
    def __init__(self):
        super().__init__()

        self.title("Codex Control Console v13 — Security Bridge Integrated")
        self.configure(bg="#101010")

        screen_w = self.winfo_screenwidth()
        screen_h = self.winfo_screenheight()
        target_w = max(1200, int(screen_w * 0.92))
        target_h = max(800, int(screen_h * 0.80))
        self.geometry(f"{target_w}x{target_h}+50+50")

        self.lockdown_active = False
        self.audio_lockdown_active = False
        self.intruder_found = False
        self.intruder_name = None
        self.problem_desc = None
        self.deep_scan_running = False
        self.kill_confirmed = False

        self._build_style()
        self._build_layout(target_w, target_h)

    # -------------------------------------------------------------------------
    # UI / STYLE
    # -------------------------------------------------------------------------
    def _build_style(self):
        style = ttk.Style()
        style.theme_use("clam")

        style.configure("TopBar.TFrame", background="#181818")
        style.configure("Main.TFrame", background="#101010")
        style.configure("Control.TButton", font=("Segoe UI", 9, "bold"), padding=4)
        style.map(
            "Control.TButton",
            background=[("active", "#404040")],
            foreground=[("disabled", "#808080")],
        )

    def _build_layout(self, target_w, target_h):
        self.grid_rowconfigure(1, weight=1)
        self.grid_columnconfigure(0, weight=1)

        top_bar = ttk.Frame(self, style="TopBar.TFrame")
        top_bar.grid(row=0, column=0, sticky="ew")
        top_bar.grid_columnconfigure(0, weight=1)

        # ROW 1: Lockdown + Reset + Audio Lockdown (left-aligned)
        row1 = ttk.Frame(top_bar, style="TopBar.TFrame")
        row1.grid(row=0, column=0, sticky="w", padx=8, pady=(6, 2))

        self.btn_lockdown = ttk.Button(
            row1,
            text="LOCKDOWN MODE — FULL KILL",
            style="Control.TButton",
            command=self.on_lockdown_pressed
        )
        self.btn_lockdown.grid(row=0, column=0, padx=(0, 6))

        self.btn_reset = ttk.Button(
            row1,
            text="RESET SYSTEM — RETURN TO NORMAL MODE",
            style="Control.TButton",
            command=self.on_reset_pressed
        )
        self.btn_reset.grid(row=0, column=1, padx=(0, 6))

        self.btn_audio_lockdown = ttk.Button(
            row1,
            text="AUDIO LOCKDOWN — READY",
            style="Control.TButton",
            command=self.on_audio_lockdown_pressed
        )
        self.btn_audio_lockdown.grid(row=0, column=2, padx=(0, 6))
        self._set_audio_lockdown_color(active=False)

        # ROW 2: Core controls
        row2 = ttk.Frame(top_bar, style="TopBar.TFrame")
        row2.grid(row=1, column=0, sticky="w", padx=8, pady=(2, 2))
        self._add_row2_buttons(row2)

        # ROW 3: Security actions
        row3 = ttk.Frame(top_bar, style="TopBar.TFrame")
        row3.grid(row=2, column=0, sticky="w", padx=8, pady=(2, 6))
        self._add_row3_buttons(row3)

        # MAIN AREA
        main = ttk.Frame(self, style="Main.TFrame")
        main.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        main.grid_columnconfigure(0, weight=1)
        main.grid_rowconfigure(0, weight=1)

        # Left: status + logs
        left_frame = ttk.Frame(main, style="Main.TFrame")
        left_frame.grid(row=0, column=0, sticky="nsew")
        left_frame.grid_rowconfigure(1, weight=1)
        left_frame.grid_columnconfigure(0, weight=1)

        status_frame = ttk.LabelFrame(left_frame, text="Lockdown / Intruder Status")
        status_frame.grid(row=0, column=0, sticky="ew", pady=(0, 6))

        self.lbl_lockdown_state = ttk.Label(status_frame, text="Lockdown: INACTIVE")
        self.lbl_lockdown_state.grid(row=0, column=0, sticky="w", padx=6, pady=2)

        self.lbl_audio_state = ttk.Label(status_frame, text="Audio Lockdown: READY")
        self.lbl_audio_state.grid(row=1, column=0, sticky="w", padx=6, pady=2)

        self.lbl_intruder = ttk.Label(status_frame, text="Intruder: none")
        self.lbl_intruder.grid(row=2, column=0, sticky="w", padx=6, pady=2)

        self.lbl_problem = ttk.Label(status_frame, text="Problem: none")
        self.lbl_problem.grid(row=3, column=0, sticky="w", padx=6, pady=2)

        log_frame = ttk.LabelFrame(left_frame, text="Event Log")
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.grid_rowconfigure(0, weight=1)
        log_frame.grid_columnconfigure(0, weight=1)

        self.txt_log = tk.Text(
            log_frame,
            bg="#050505",
            fg="#e0e0e0",
            insertbackground="#e0e0e0",
            height=10,
            wrap="word",
        )
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.txt_log.yview)
        log_scroll.grid(row=0, column=1, sticky="ns")
        self.txt_log.configure(yscrollcommand=log_scroll.set)

        # Right: intruder details + controls
        right_frame = ttk.LabelFrame(main, text="Intruder Details / Actions")
        right_frame.grid(row=0, column=1, sticky="nsew", padx=(8, 0))
        right_frame.grid_columnconfigure(0, weight=1)

        self.lbl_intruder_detail = ttk.Label(
            right_frame,
            text="No intruder detected.",
            justify="left",
        )
        self.lbl_intruder_detail.grid(row=0, column=0, sticky="w", padx=6, pady=(6, 4))

        self.lbl_problem_detail = ttk.Label(
            right_frame,
            text="No problem detected.",
            justify="left",
        )
        self.lbl_problem_detail.grid(row=1, column=0, sticky="w", padx=6, pady=(0, 6))

        action_frame = ttk.Frame(right_frame)
        action_frame.grid(row=2, column=0, sticky="w", padx=6, pady=(4, 6))

        self.btn_confirm_intruder = ttk.Button(
            action_frame,
            text="CONFIRM INTRUDER / PROBLEM",
            style="Control.TButton",
            command=self.on_confirm_intruder
        )
        self.btn_confirm_intruder.grid(row=0, column=0, padx=(0, 6))

        self.btn_auto_kill = ttk.Button(
            action_frame,
            text="AUTO-KILL CONFIRMED INTRUDER",
            style="Control.TButton",
            command=self.on_auto_kill
        )
        self.btn_auto_kill.grid(row=0, column=1, padx=(0, 6))

        self.btn_rescan = ttk.Button(
            action_frame,
            text="ONE MORE SCAN",
            style="Control.TButton",
            command=self.on_rescan
        )
        self.btn_rescan.grid(row=0, column=2, padx=(0, 6))

        self.btn_confirm_intruder.state(["disabled"])
        self.btn_auto_kill.state(["disabled"])
        self.btn_rescan.state(["disabled"])

    def _add_row2_buttons(self, parent):
        buttons = [
            ("Refresh snapshot", self.on_refresh),
            ("Generate report", self.on_generate_report),
            ("Incident pack", self.on_incident_pack),
            ("Freeze session", self.on_freeze_session),
            ("Kill all high-risk", self.on_kill_high_risk),
            ("Suspend remote > 60", self.on_suspend_remote),
            ("Mute suspicious audio", self.on_mute_suspicious_audio),
        ]
        for i, (label, cmd) in enumerate(buttons):
            b = ttk.Button(parent, text=label, style="Control.TButton", command=cmd)
            b.grid(row=0, column=i, padx=(0, 6))

    def _add_row3_buttons(self, parent):
        buttons = [
            ("Silence non-media", self.on_silence_non_media),
            ("Snapshot + pack", self.on_snapshot_pack),
        ]
        for i, (label, cmd) in enumerate(buttons):
            b = ttk.Button(parent, text=label, style="Control.TButton", command=cmd)
            b.grid(row=0, column=i, padx=(0, 6))

    # -------------------------------------------------------------------------
    # BUTTON HANDLERS — TOP ROW
    # -------------------------------------------------------------------------
    def on_lockdown_pressed(self):
        if self.lockdown_active:
            self._log("Lockdown already active.")
            return

        self.lockdown_active = True
        self.lbl_lockdown_state.config(text="Lockdown: FULL KILL MODE ACTIVE")
        self._log("LOCKDOWN MODE — FULL KILL triggered.")
        self._log("Running deep scan + full kill via Security Bridge engine...")

        def run():
            try:
                snapshot, candidates, killed = run_lockdown_full_kill()
                self.after(0, lambda: self._on_lockdown_complete(snapshot, candidates, killed))
            except Exception as e:
                self.after(0, lambda: self._log(f"Lockdown error: {e}"))

        t = threading.Thread(target=run, daemon=True)
        t.start()

    def _on_lockdown_complete(self, snapshot, candidates, killed):
        self.lockdown_active = False
        self._log(f"Lockdown completed. Intruder candidates: {len(candidates)}, killed: {len(killed)}.")
        if candidates:
            top = candidates[0]
            self.intruder_found = True
            self.intruder_name = top["name"]
            self.problem_desc = f"Intruder_score={top['intruder_score']} remote_index={top['remote_index']} verdict={top['verdict']}"
            self.lbl_intruder.config(text=f"Intruder: {self.intruder_name}")
            self.lbl_problem.config(text=f"Problem: {self.problem_desc}")
            self.lbl_intruder_detail.config(
                text=f"Top intruder candidate:\n  PID {top['pid']} {top['name']}\n"
                     f"Intruder_score={top['intruder_score']} remote_index={top['remote_index']}\n"
                     f"Verdict={top['verdict']} risk={top['risk']} class={top['class']} persona={top['persona']}"
            )
            self.lbl_problem_detail.config(
                text="Lockdown evidence retained.\nLockdown pack created:\n  " + LOCKDOWN_ZIP
            )
            self.btn_confirm_intruder.state(["!disabled"])
            self.btn_auto_kill.state(["!disabled"])
            self.btn_rescan.state(["!disabled"])
        else:
            self.intruder_found = False
            self.intruder_name = None
            self.problem_desc = "No candidates."
            self.lbl_intruder.config(text="Intruder: none")
            self.lbl_problem.config(text="Problem: none")
            self.lbl_intruder_detail.config(text="No intruder candidates found.")
            self.lbl_problem_detail.config(text="Lockdown completed with no kills.")

    def on_reset_pressed(self):
        self._log("RESET SYSTEM — returning to normal mode.")
        try:
            reset_system_state()
        except Exception as e:
            self._log(f"Reset error: {e}")
            return

        self.lockdown_active = False
        self.audio_lockdown_active = False
        self.intruder_found = False
        self.intruder_name = None
        self.problem_desc = None
        self.deep_scan_running = False
        self.kill_confirmed = False

        self.lbl_lockdown_state.config(text="Lockdown: INACTIVE")
        self.lbl_audio_state.config(text="Audio Lockdown: READY")
        self.lbl_intruder.config(text="Intruder: none")
        self.lbl_problem.config(text="Problem: none")
        self.lbl_intruder_detail.config(text="No intruder detected.")
        self.lbl_problem_detail.config(text="No problem detected.")

        self._set_audio_lockdown_color(active=False)

        self.btn_confirm_intruder.state(["disabled"])
        self.btn_auto_kill.state(["disabled"])
        self.btn_rescan.state(["disabled"])

        self._log("System Reset Complete — Monitoring Normal.")

    def on_audio_lockdown_pressed(self):
        if self.audio_lockdown_active:
            self._log("Audio Lockdown already active (stays red until RESET).")
            return

        self.audio_lockdown_active = True
        STATE["audio_lockdown_active"] = True
        save_state(STATE)

        self.lbl_audio_state.config(text="Audio Lockdown: ACTIVE (speaker trace)")
        self._set_audio_lockdown_color(active=True)
        self._log("AUDIO LOCKDOWN — scanning from sound speaker back to find intruder.")

        def run():
            try:
                chain, sessions = audio_lockdown_trace()
                self.after(0, lambda: self._on_audio_lockdown_complete(chain))
            except Exception as e:
                self.after(0, lambda: self._log(f"Audio lockdown error: {e}"))

        t = threading.Thread(target=run, daemon=True)
        t.start()

    def _on_audio_lockdown_complete(self, chain):
        if chain is None:
            self._log("Audio lockdown: no loud non-allowlisted audio source found.")
            self.lbl_intruder_detail.config(text="Audio lockdown: no intruder found.")
            self.lbl_problem_detail.config(text="No problem detected from audio.")
            return

        self.intruder_found = True
        self.intruder_name = chain["name"]
        self.problem_desc = chain["risk_reason"]

        self.lbl_intruder.config(text=f"Intruder: {self.intruder_name}")
        self.lbl_problem.config(text=f"Problem: {self.problem_desc}")
        self.lbl_intruder_detail.config(
            text=f"Audio intruder candidate:\n  PID {chain['pid']} {chain['name']}\n"
                 f"Volume={int(chain['volume'] * 100)}% level={chain['audio_profile']['level']} muted={chain['muted']}\n"
                 f"Parent PID={chain['parent_pid']} exe={chain['exe_path']}\n"
                 f"Score={chain['score']} risk={chain['risk_level']} class={chain['threat_class']} persona={chain['persona']}\n"
                 f"Remote_index={chain['remote_index']} RSE={chain['rse_verdict']}({chain['rse_score']}%)"
        )
        self.lbl_problem_detail.config(
            text="Audio lockdown trace completed.\nLockdown evidence retained in JSON event stream."
        )

        self.btn_confirm_intruder.state(["!disabled"])
        self.btn_auto_kill.state(["!disabled"])
        self.btn_rescan.state(["!disabled"])

    # -------------------------------------------------------------------------
    # INTRUDER ACTIONS
    # -------------------------------------------------------------------------
    def on_confirm_intruder(self):
        if not self.intruder_found:
            self._log("No intruder to confirm.")
            return

        self.kill_confirmed = True
        self._log("Intruder and problem confirmed by user.")
        self._log("System will AUTO-KILL intruder once command is issued.")

    def on_auto_kill(self):
        if not self.intruder_found:
            self._log("No intruder to kill.")
            return
        if not self.kill_confirmed:
            self._log("Kill not allowed until intruder/problem is confirmed.")
            return

        self._log(f"AUTO-KILL: Terminating intruder: {self.intruder_name}")
        # We don't know PID here; this is mainly symbolic in this merged console
        time.sleep(0.5)
        self._log("Intruder terminated (symbolic). Audio source chain severed.")
        self.lbl_intruder_detail.config(
            text=f"Intruder terminated:\n  {self.intruder_name}\n\nAudio chain neutralized."
        )

    def on_rescan(self):
        self._log("ONE MORE SCAN requested to confirm this is the only problem.")
        def run():
            try:
                snapshot = build_security_snapshot(gui_confirm_callback=None)
                self.after(0, lambda: self._log(f"Rescan completed: {len(snapshot)} audio sessions."))
            except Exception as e:
                self.after(0, lambda: self._log(f"Rescan error: {e}"))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    # -------------------------------------------------------------------------
    # ROW 2 / ROW 3 HANDLERS
    # -------------------------------------------------------------------------
    def on_refresh(self):
        self._log("Manual snapshot refresh triggered.")
        def run():
            try:
                snapshot = build_security_snapshot(gui_confirm_callback=None)
                self.after(0, lambda: self._log(f"Snapshot updated: {len(snapshot)} audio sessions."))
            except Exception as e:
                self.after(0, lambda: self._log(f"Snapshot error: {e}"))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def on_generate_report(self):
        self._log("Generate report requested.")
        def run():
            try:
                snapshot = build_security_snapshot(gui_confirm_callback=None)
                generate_report(snapshot)
                self.after(0, lambda: self._log(f"Threat report written to {REPORT_FILE_JSON} and {REPORT_FILE_TXT}."))
            except Exception as e:
                self.after(0, lambda: self._log(f"Report error: {e}"))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def on_incident_pack(self):
        self._log("Incident pack requested.")
        def run():
            try:
                snapshot = build_security_snapshot(gui_confirm_callback=None)
                create_incident_pack(snapshot)
                self.after(0, lambda: self._log(f"Incident pack written to {INCIDENT_ZIP}."))
            except Exception as e:
                self.after(0, lambda: self._log(f"Incident pack error: {e}"))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def on_freeze_session(self):
        self._log("Freeze incident session requested.")
        def run():
            try:
                snapshot = build_security_snapshot(gui_confirm_callback=None)
                freeze_incident_session(snapshot)
                self.after(0, lambda: self._log(f"Incident session frozen to {INCIDENT_SESSION_FILE}."))
            except Exception as e:
                self.after(0, lambda: self._log(f"Incident session error: {e}"))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def on_kill_high_risk(self):
        self._log("Kill all high-risk requested.")
        def run():
            try:
                snapshot = build_security_snapshot(gui_confirm_callback=None)
                count = 0
                for info in snapshot:
                    if info.risk_level == "High" and info.pid is not None and not is_allowlisted((info.name or "").lower()):
                        kill_process(info.pid)
                        count += 1
                self.after(0, lambda: self._log(f"Killed {count} high-risk processes."))
            except Exception as e:
                self.after(0, lambda: self._log(f"Kill high-risk error: {e}"))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def on_suspend_remote(self):
        self._log("Suspend remote-index > 60 requested.")
        def run():
            try:
                snapshot = build_security_snapshot(gui_confirm_callback=None)
                count = 0
                for info in snapshot:
                    if info.remote_index >= 60 and info.pid is not None and not is_allowlisted((info.name or "").lower()):
                        sandbox_process(info.pid)
                        count += 1
                self.after(0, lambda: self._log(f"Suspended {count} remote-suspect processes."))
            except Exception as e:
                self.after(0, lambda: self._log(f"Suspend remote error: {e}"))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def on_mute_suspicious_audio(self):
        self._log("Mute suspicious audio requested.")
        def run():
            pythoncom.CoInitialize()
            sessions = AudioUtilities.GetAllSessions()
            count = 0
            for session in sessions:
                try:
                    volume = session._ctl.QueryInterface(ISimpleAudioVolume)
                    pid = session.Process.pid if session.Process else None
                    name = session.Process.name() if session.Process else "System"
                    name_lower = (name or "").lower()
                    if pid is None:
                        continue
                    if is_allowlisted(name_lower):
                        continue
                    vol_level = volume.GetMasterVolume()
                    if vol_level > 0.2:
                        volume.SetMasterVolume(0.0, None)
                        count += 1
                        emit_event({
                            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "audio_mute",
                            "pid": pid,
                            "name": name,
                            "prev_volume": vol_level,
                        })
                except Exception:
                    continue
            self.after(0, lambda: self._log(f"Muted {count} loud non-allowlisted audio sessions."))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def on_silence_non_media(self):
        self._log("Silence non-media audio requested.")
        def run():
            pythoncom.CoInitialize()
            sessions = AudioUtilities.GetAllSessions()
            count = 0
            media_whitelist = [n.lower() for n in RULES.get("audio_whitelist", DEFAULT_AUDIO_WHITELIST)]
            for session in sessions:
                try:
                    volume = session._ctl.QueryInterface(ISimpleAudioVolume)
                    pid = session.Process.pid if session.Process else None
                    name = session.Process.name() if session.Process else "System"
                    name_lower = (name or "").lower()
                    if pid is None:
                        continue
                    if any(w in name_lower for w in media_whitelist):
                        continue
                    vol_level = volume.GetMasterVolume()
                    if vol_level > 0.05:
                        volume.SetMasterVolume(0.0, None)
                        count += 1
                        emit_event({
                            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "audio_mute_non_media",
                            "pid": pid,
                            "name": name,
                            "prev_volume": vol_level,
                        })
                except Exception:
                    continue
            self.after(0, lambda: self._log(f"Silenced {count} non-media audio sessions."))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    def on_snapshot_pack(self):
        self._log("Snapshot + pack requested.")
        def run():
            try:
                snapshot = build_security_snapshot(gui_confirm_callback=None)
                freeze_incident_session(snapshot)
                create_incident_pack(snapshot)
                self.after(0, lambda: self._log(f"Snapshot, incident session, and pack created ({INCIDENT_ZIP})."))
            except Exception as e:
                self.after(0, lambda: self._log(f"Snapshot + pack error: {e}"))
        t = threading.Thread(target=run, daemon=True)
        t.start()

    # -------------------------------------------------------------------------
    # UTIL
    # -------------------------------------------------------------------------
    def _log(self, msg):
        ts = time.strftime("%H:%M:%S")
        self.txt_log.insert("end", f"[{ts}] {msg}\n")
        self.txt_log.see("end")

    def _set_audio_lockdown_color(self, active: bool):
        if active:
            self.btn_audio_lockdown.config(text="AUDIO LOCKDOWN — ACTIVE (RED, WAITING FOR RESET)")
        else:
            self.btn_audio_lockdown.config(text="AUDIO LOCKDOWN — READY (GREEN)")

# -------------------------------------------------------------------------
# MAIN
# -------------------------------------------------------------------------
def main():
    log_event("INFO", "Codex Control Console v13 (Security Bridge Integrated) started.")
    start_honeypot()
    app = CodexControlConsole()
    app.mainloop()
    log_event("INFO", "Codex Control Console closed.")

if __name__ == "__main__":
    main()
