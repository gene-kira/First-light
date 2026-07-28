#!/usr/bin/env python3
# Rogue Process Monitor v17.0
# MANUAL_ALERT default mode + Borg + ML + GPU (optional) + Suricata v6-style rules + Kernel/ETW stubs
# + PyTorch Autoencoder + Distributed Borg nodes + Threat Intel (MITRE ATT&CK mapping)
# + Network reputation scoring + SQLite telemetry DB + Flask/WebSocket web dashboard mirror

import sys
import subprocess
import time
import datetime
import threading
import json
import os
import math
import socket
import queue
import sqlite3

# ============================================================
# Aggressive Autoloader
# ============================================================

REQUIRED_PACKAGES = [
    "psutil",
    "matplotlib",
    "scikit-learn",
    "tk",
    "torch",
    "flask",
    "websocket-client",
]

def ensure_package(pkg_name, import_name=None):
    if import_name is None:
        import_name = pkg_name
    try:
        __import__(import_name)
        return True
    except ImportError:
        print(f"[AUTOLOADER] Missing '{pkg_name}', installing via pip...")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name])
            __import__(import_name)
            print(f"[AUTOLOADER] Installed '{pkg_name}'.")
            return True
        except Exception as e:
            print(f"[AUTOLOADER] Failed to install '{pkg_name}': {e}")
            return False

def aggressive_autoload():
    ensure_package("psutil")
    ensure_package("matplotlib")
    ensure_package("scikit-learn", "sklearn")
    try:
        import tkinter  # noqa
    except ImportError:
        ensure_package("tk")
    ensure_package("torch")
    ensure_package("flask")
    ensure_package("websocket-client")

aggressive_autoload()

import psutil
import tkinter as tk
from tkinter import ttk, messagebox

from flask import Flask, jsonify
from websocket import create_connection

ML_AVAILABLE = False
GPU_AVAILABLE = False
PLOTTING_AVAILABLE = False
AUTOENCODER_AVAILABLE = False

try:
    from sklearn.ensemble import IsolationForest
    ML_AVAILABLE = True
except Exception:
    ML_AVAILABLE = False

try:
    import matplotlib.pyplot as plt
    PLOTTING_AVAILABLE = True
except Exception:
    PLOTTING_AVAILABLE = False

try:
    import torch
    import torch.nn as nn
    GPU_AVAILABLE = torch.cuda.is_available()
except Exception:
    GPU_AVAILABLE = False

# ============================================================
# Logging / Config / SQLite Telemetry
# ============================================================

LOG_FILE = "rogue_monitor_v17_log.txt"
CONFIG_FILE = "rogue_monitor_v17_config.json"
DB_FILE = "rogue_monitor_v17_telemetry.db"

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def init_db():
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("""
            CREATE TABLE IF NOT EXISTS telemetry (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT,
                name TEXT,
                pid INTEGER,
                path TEXT,
                score INTEGER,
                anomaly REAL,
                ml_anomaly REAL,
                gpu_anomaly REAL,
                autoenc_anomaly REAL,
                suricata_matches TEXT,
                resurrected INTEGER,
                mode TEXT
            )
        """)
        conn.commit()
        conn.close()
        log("SQLite telemetry DB initialized.")
    except Exception as e:
        log(f"Failed to init DB: {e}")

def db_insert_event(ev, mode):
    try:
        conn = sqlite3.connect(DB_FILE)
        c = conn.cursor()
        c.execute("""
            INSERT INTO telemetry (ts, name, pid, path, score, anomaly, ml_anomaly, gpu_anomaly, autoenc_anomaly, suricata_matches, resurrected, mode)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (
            ev.get("ts", ""),
            ev.get("name", ""),
            ev.get("pid", 0),
            ev.get("path", ""),
            ev.get("score", 0),
            ev.get("anomaly", 0.0),
            ev.get("ml_anomaly", 0.0),
            ev.get("gpu_anomaly", 0.0),
            ev.get("autoenc_anomaly", 0.0),
            ",".join(ev.get("suricata_matches", [])),
            1 if ev.get("resurrected", False) else 0,
            mode,
        ))
        conn.commit()
        conn.close()
    except Exception as e:
        log(f"DB insert error: {e}")

DEFAULT_CONFIG = {
    # Default mode: MANUAL_ALERT (no destructive actions, but alerts)
    "mode": "MANUAL_ALERT",  # MANUAL_ALERT, AUTO_KILL_ROGUE, AUTO_KILL_CHROME_PDPRO, AUTO_QUARANTINE
    "heuristic_threshold": 50,
    "anomaly_threshold": 60.0,
    "ml_anomaly_threshold": 60.0,
    "autoenc_anomaly_threshold": 60.0,
    "chrome_pdpro_targets": [
        "chrome.exe",
        "google chrome for testing.exe",
        "pdpro7 hook.exe",
    ],
    "suricata_rules_file": "suricata_v6_rules.json",
    "distributed_borg_nodes": [],
    "web_dashboard_port": 5005,
    "websocket_feed_url": "",
}

config_lock = threading.Lock()
config = DEFAULT_CONFIG.copy()

def load_config():
    global config
    if not os.path.exists(CONFIG_FILE):
        save_config()
        return
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        with config_lock:
            config.update(data)
        log("Config loaded.")
    except Exception as e:
        log(f"Failed to load config: {e}")

def save_config():
    try:
        with config_lock:
            data = dict(config)
        with open(CONFIG_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        log("Config saved.")
    except Exception as e:
        log(f"Failed to save config: {e}")

def get_config():
    with config_lock:
        return dict(config)

def set_config_key(key, value):
    with config_lock:
        config[key] = value
    save_config()

# ============================================================
# Blacklist / Suricata-style rules / Network reputation
# ============================================================

DEFAULT_BLACKLIST = [
    "google chrome for testing.exe",
    "chrome.exe",
    "chrome_sandbox.exe",
    "chrome_child.exe",
    "chrome_renderer.exe",
    "chrome_gpu.exe",
    "pdpro7 hook.exe",
    "audiohook.dll",
    "overlayinjector.exe",
    "virtualaudio.exe",
    "debug_audio_hook.exe",
]

SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
    "/tmp/",
    "/var/tmp/",
    "/home/",
]

SUSPICIOUS_PARENT_KEYWORDS = [
    "steamwebhelper.exe",
    "chrome.exe",
    "google chrome for testing.exe",
    "pdpro7 hook.exe",
]

blacklist_lock = threading.Lock()
blacklist = DEFAULT_BLACKLIST.copy()

def get_blacklist():
    with blacklist_lock:
        return list(blacklist)

def add_to_blacklist(name):
    name = name.strip()
    if not name:
        return
    with blacklist_lock:
        if name not in blacklist:
            blacklist.append(name)
    log(f"Added to blacklist: {name}")

def remove_from_blacklist(name):
    name = name.strip()
    if not name:
        return
    with blacklist_lock:
        if name in blacklist:
            blacklist.remove(name)
    log(f"Removed from blacklist: {name}")

def is_rogue_name(name: str) -> bool:
    if not name:
        return False
    lname = name.lower()
    with blacklist_lock:
        for entry in blacklist:
            if entry.lower() in lname:
                return True
    return False

# Suricata v6-style rule engine (simplified parser)
suricata_lock = threading.Lock()
suricata_rules = []

def load_suricata_rules():
    global suricata_rules
    cfg = get_config()
    path = cfg.get("suricata_rules_file", "suricata_v6_rules.json")
    if not os.path.exists(path):
        default_rules = [
            {
                "id": "R1",
                "name": "High CPU rogue",
                "conditions": {
                    "cpu_gt": 50.0,
                    "score_gt": 60
                },
                "action": "flag",
                "mitre": ["T1059", "T1082"]
            },
            {
                "id": "R2",
                "name": "Temp path executable",
                "conditions": {
                    "path_contains": ["\\temp\\", "/tmp/"],
                    "score_gt": 40
                },
                "action": "flag",
                "mitre": ["T1036"]
            },
            {
                "id": "R3",
                "name": "Chrome child suspicious",
                "conditions": {
                    "parent_name_contains": ["chrome.exe", "google chrome for testing.exe"],
                    "score_gt": 50
                },
                "action": "flag",
                "mitre": ["T1204"]
            },
        ]
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(default_rules, f, indent=2)
            log(f"Created default Suricata rules at {path}")
        except Exception as e:
            log(f"Failed to create default Suricata rules: {e}")
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        with suricata_lock:
            suricata_rules = data
        log(f"Loaded Suricata-style rules from {path}")
    except Exception as e:
        log(f"Failed to load Suricata rules: {e}")

def apply_suricata_rules(proc_info):
    matches = []
    mitre_tags = []
    with suricata_lock:
        rules = list(suricata_rules)
    for r in rules:
        cond = r.get("conditions", {})
        ok = True
        if "cpu_gt" in cond:
            if proc_info.get("cpu", 0.0) <= cond["cpu_gt"]:
                ok = False
        if "score_gt" in cond:
            if proc_info.get("score", 0) <= cond["score_gt"]:
                ok = False
        if "path_contains" in cond:
            path = proc_info.get("path", "").lower()
            if not any(k.lower() in path for k in cond["path_contains"]):
                ok = False
        if "parent_name_contains" in cond:
            pname = proc_info.get("parent_name", "").lower()
            if not any(k.lower() in pname for k in cond["parent_name_contains"]):
                ok = False
        if ok:
            matches.append(r.get("name", r.get("id", "rule")))
            mitre_tags.extend(r.get("mitre", []))
    return matches, list(set(mitre_tags))

# Simple network reputation scoring (stub)
def network_reputation_score(domain_or_ip: str) -> float:
    if not domain_or_ip:
        return 0.0
    s = domain_or_ip.lower()
    score = 0.0
    if any(bad in s for bad in ["tor", "dark", "malware", "hack"]):
        score += 60.0
    if s.endswith(".ru") or s.endswith(".cn"):
        score += 30.0
    if s.startswith("192.168.") or s.startswith("10.") or s.startswith("172.16."):
        score += 5.0
    if score > 100.0:
        score = 100.0
    return score

# ============================================================
# Kernel driver / ETW stubs (conceptual)
# ============================================================

class KernelDriverStub:
    """
    Conceptual kernel/ETW stub:
    - In real implementation, this would be a Windows driver / ETW consumer.
    - Here we simulate extra signals: handle count, thread count, registry hints, file activity hints.
    """

    def __init__(self):
        self.loaded = False

    def load(self):
        self.loaded = True
        log("KernelDriverStub: loaded (conceptual ETW hooks).")

    def unload(self):
        self.loaded = False
        log("KernelDriverStub: unloaded (conceptual).")

    def get_extra_signals(self, pid):
        try:
            proc = psutil.Process(pid)
        except Exception:
            return {
                "handle_count": 0,
                "thread_count": 0,
                "registry_persistence_hint": False,
                "file_activity_hint": False,
            }
        try:
            handles = getattr(proc, "num_handles", lambda: 0)()
        except Exception:
            handles = 0
        try:
            threads = proc.num_threads()
        except Exception:
            threads = 0
        name = (proc.name() or "").lower()
        reg_hint = ("update" in name or "service" in name)
        file_hint = ("sync" in name or "backup" in name)
        return {
            "handle_count": handles,
            "thread_count": threads,
            "registry_persistence_hint": reg_hint,
            "file_activity_hint": file_hint,
        }

kernel_stub = KernelDriverStub()
kernel_stub.load()

# ============================================================
# Sandbox shared state
# ============================================================

sandbox_lock = threading.Lock()

sandbox_live_processes = []   # {pid, name, path, score, rogue, anomaly, ml_anomaly, gpu_anomaly, autoenc_anomaly, suricata_matches, mitre_tags, quarantine, resurrected}
sandbox_history_events = []   # {ts, name, pid, path, reason, score, anomaly, ml_anomaly, gpu_anomaly, autoenc_anomaly, suricata_matches, mitre_tags}
sandbox_tree_lines = []       # text tree
sandbox_alerts = []           # {name, pid, path, reason, score}
sandbox_threat_level_raw = 0
sandbox_threat_level_smoothed = 0

sandbox_swarm_status = {
    "worker_count": 0,
    "avg_latency": 0.0,
    "total_processed": 0,
    "total_errors": 0,
    "slow_workers": 0,
    "restarted_workers": 0,
}

sandbox_ai_insights = {
    "last_update_ts": "",
    "summary": "",
    "recommendations": [],
    "focus_targets": [],
}

sandbox_threat_matrix = {
    "high_score": [],
    "medium_score": [],
    "low_score": [],
    "by_parent": {},
    "by_path_keyword": {},
    "by_mitre": {},
}

sandbox_timeline_buckets = []  # {bucket_ts, count, avg_score, avg_threat}
sandbox_threat_bucket_history = []  # for plotting threat over time

# Quarantine / resurrection tracking
quarantine_lock = threading.Lock()
quarantined_pids = {}   # pid -> info
killed_history = []     # {name, pid, ts}

def sandbox_set_live_processes(items):
    global sandbox_live_processes
    with sandbox_lock:
        sandbox_live_processes = items

def sandbox_get_live_processes():
    with sandbox_lock:
        return list(sandbox_live_processes)

def sandbox_append_history(event):
    global sandbox_history_events
    with sandbox_lock:
        sandbox_history_events.append(event)
        if len(sandbox_history_events) > 6000:
            sandbox_history_events.pop(0)

def sandbox_get_history():
    with sandbox_lock:
        return list(sandbox_history_events)

def sandbox_set_tree_lines(lines):
    global sandbox_tree_lines
    with sandbox_lock:
        sandbox_tree_lines = lines

def sandbox_get_tree_lines():
    with sandbox_lock:
        return list(sandbox_tree_lines)

def sandbox_add_alert(alert):
    global sandbox_alerts
    with sandbox_lock:
        sandbox_alerts.append(alert)
        if len(sandbox_alerts) > 1000:
            sandbox_alerts.pop(0)

def sandbox_pop_alerts(max_count=10):
    global sandbox_alerts
    with sandbox_lock:
        alerts = sandbox_alerts[:max_count]
        sandbox_alerts = sandbox_alerts[max_count:]
        return alerts

def sandbox_set_threat_level(level):
    global sandbox_threat_level_raw, sandbox_threat_level_smoothed, sandbox_threat_bucket_history
    with sandbox_lock:
        sandbox_threat_level_raw = int(max(0, min(100, level)))
        sandbox_threat_level_smoothed = int(
            0.7 * sandbox_threat_level_smoothed + 0.3 * sandbox_threat_level_raw
        )
        sandbox_threat_bucket_history.append(
            (time.time(), sandbox_threat_level_smoothed)
        )
        if len(sandbox_threat_bucket_history) > 800:
            sandbox_threat_bucket_history.pop(0)

def sandbox_get_threat_level():
    with sandbox_lock:
        return sandbox_threat_level_smoothed

def sandbox_get_threat_bucket_history():
    with sandbox_lock:
        return list(sandbox_threat_bucket_history)

def sandbox_set_swarm_status(worker_count, avg_latency, total_processed, total_errors, slow_workers, restarted_workers):
    global sandbox_swarm_status
    with sandbox_lock:
        sandbox_swarm_status = {
            "worker_count": worker_count,
            "avg_latency": avg_latency,
            "total_processed": total_processed,
            "total_errors": total_errors,
            "slow_workers": slow_workers,
            "restarted_workers": restarted_workers,
        }

def sandbox_get_swarm_status():
    with sandbox_lock:
        return dict(sandbox_swarm_status)

def sandbox_set_ai_insights(summary, recommendations, focus_targets):
    global sandbox_ai_insights
    with sandbox_lock:
        sandbox_ai_insights = {
            "last_update_ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "summary": summary,
            "recommendations": recommendations,
            "focus_targets": focus_targets,
        }

def sandbox_get_ai_insights():
    with sandbox_lock:
        return dict(sandbox_ai_insights)

def sandbox_set_threat_matrix(matrix):
    global sandbox_threat_matrix
    with sandbox_lock:
        sandbox_threat_matrix = matrix

def sandbox_get_threat_matrix():
    with sandbox_lock:
        return dict(sandbox_threat_matrix)

def sandbox_set_timeline_buckets(buckets):
    global sandbox_timeline_buckets
    with sandbox_lock:
        sandbox_timeline_buckets = buckets

def sandbox_get_timeline_buckets():
    with sandbox_lock:
        return list(sandbox_timeline_buckets)

def quarantine_pid(pid, info):
    with quarantine_lock:
        quarantined_pids[pid] = {
            "info": info,
            "ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }
    log(f"Quarantined PID {pid} ({info.get('name', '')})")

def is_quarantined(pid):
    with quarantine_lock:
        return pid in quarantined_pids

def record_kill(name, pid):
    killed_history.append({
        "name": name,
        "pid": pid,
        "ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
    })
    if len(killed_history) > 800:
        killed_history.pop(0)

def check_resurrection(name, pid):
    for e in killed_history[-300:]:
        if e["name"] == name and e["pid"] != pid:
            return True
    return False

# ============================================================
# Behavior engine / scoring
# ============================================================

def estimate_signature_status(proc: psutil.Process):
    try:
        exe = proc.exe()
    except Exception:
        exe = ""
    exe_lower = exe.lower()

    if "\\windows\\" in exe_lower or "/windows/" in exe_lower:
        return "trusted"
    if "\\program files" in exe_lower or "/usr/bin" in exe_lower or "/usr/sbin" in exe_lower:
        return "likely trusted"
    if any(k in exe_lower for k in SUSPICIOUS_PATH_KEYWORDS):
        return "unknown"
    return "unknown"

def compute_reputation_score(proc: psutil.Process):
    score = 0
    reasons = []

    try:
        name = proc.name() or ""
        exe = proc.exe() or ""
        exe_lower = exe.lower()
    except Exception:
        name = ""
        exe = ""
        exe_lower = ""

    if is_rogue_name(name):
        score += 40
        reasons.append("Name matched blacklist")

    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in exe_lower:
            score += 20
            reasons.append(f"Suspicious path keyword: {kw}")
            break

    try:
        parent = proc.parent()
        if parent:
            pname = parent.name() or ""
            plower = pname.lower()
            for kw in SUSPICIOUS_PARENT_KEYWORDS:
                if kw in plower:
                    score += 15
                    reasons.append(f"Suspicious parent: {pname}")
                    break
    except Exception:
        pass

    try:
        cpu = proc.cpu_percent(interval=0.0)
        mem = proc.memory_info().rss
        if cpu > 20.0:
            score += 10
            reasons.append(f"High CPU usage: {cpu:.1f}%")
        if mem > 200 * 1024 * 1024:
            score += 5
            reasons.append(f"High memory usage: {mem // (1024 * 1024)}MB")
    except Exception:
        pass

    sig = estimate_signature_status(proc)
    if sig == "unknown":
        score += 10
        reasons.append("Unknown signature / non-system path")
    elif sig == "trusted":
        score -= 10
        reasons.append("Trusted system binary")

    extra = kernel_stub.get_extra_signals(proc.pid)
    if extra.get("registry_persistence_hint", False):
        score += 10
        reasons.append("Registry persistence hint (kernel stub)")
    if extra.get("file_activity_hint", False):
        score += 5
        reasons.append("File activity hint (kernel stub)")
    if extra.get("handle_count", 0) > 1000:
        score += 10
        reasons.append(f"High handle count: {extra['handle_count']}")
    if extra.get("thread_count", 0) > 80:
        score += 10
        reasons.append(f"High thread count: {extra['thread_count']}")

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    return score, reasons

# ============================================================
# Incremental scanning cache + anomaly scoring + ML features
# ============================================================

scan_cache_lock = threading.Lock()
scan_cache = {}  # pid -> {pid, name, path, score, rogue, last_seen, history_scores, cpu, rss}

def update_scan_cache(pid, name, path, score, rogue, cpu=0.0, rss=0):
    now = time.time()
    with scan_cache_lock:
        entry = scan_cache.get(pid, {
            "pid": pid,
            "name": name,
            "path": path,
            "score": score,
            "rogue": rogue,
            "last_seen": now,
            "history_scores": [],
            "cpu": cpu,
            "rss": rss,
        })
        entry["name"] = name
        entry["path"] = path
        entry["score"] = score
        entry["rogue"] = rogue
        entry["last_seen"] = now
        entry["cpu"] = cpu
        entry["rss"] = rss
        hs = entry.get("history_scores", [])
        hs.append(score)
        if len(hs) > 80:
            hs.pop(0)
        entry["history_scores"] = hs
        scan_cache[pid] = entry

def get_scan_cache_snapshot():
    with scan_cache_lock:
        return dict(scan_cache)

def prune_scan_cache(max_age=300.0):
    now = time.time()
    with scan_cache_lock:
        to_delete = [pid for pid, info in scan_cache.items()
                     if now - info.get("last_seen", 0) > max_age]
        for pid in to_delete:
            del scan_cache[pid]

def compute_anomaly_score(entry):
    hs = entry.get("history_scores", [])
    if not hs:
        return 0.0
    avg = sum(hs) / len(hs)
    last = hs[-1]
    deviation = abs(last - avg)
    anomaly = deviation + (last / 2.0)
    if anomaly > 100:
        anomaly = 100.0
    return anomaly

def build_ml_features(cache_snapshot):
    X = []
    pids = []
    for pid, e in cache_snapshot.items():
        hs = e.get("history_scores", [])
        if not hs:
            avg = e["score"]
            std = 0.0
        else:
            avg = sum(hs) / len(hs)
            if len(hs) > 1:
                m = avg
                var = sum((v - m) ** 2 for v in hs) / (len(hs) - 1)
                std = var ** 0.5
            else:
                std = 0.0
        cpu = float(e.get("cpu", 0.0))
        rss_mb = float(e.get("rss", 0) / (1024 * 1024))
        X.append([e["score"], avg, std, cpu, rss_mb])
        pids.append(pid)
    return pids, X

def compute_ml_anomaly_scores(cache_snapshot):
    if not ML_AVAILABLE:
        return {}
    pids, X = build_ml_features(cache_snapshot)
    if len(X) < 10:
        return {}
    try:
        model = IsolationForest(
            n_estimators=100,
            contamination=0.05,
            random_state=42,
        )
        model.fit(X)
        scores = model.decision_function(X)
        min_s = min(scores)
        max_s = max(scores)
        if max_s == min_s:
            return {}
        ml_scores = {}
        for pid, s in zip(pids, scores):
            norm = (s - min_s) / (max_s - min_s)
            anomaly = (1.0 - norm) * 100.0
            ml_scores[pid] = anomaly
        return ml_scores
    except Exception as e:
        log(f"ML anomaly error: {e}")
        return {}

def compute_gpu_anomaly_scores(cache_snapshot):
    if not GPU_AVAILABLE:
        return {}
    try:
        pids, X = build_ml_features(cache_snapshot)
        if len(X) < 20:
            return {}
        tensor = torch.tensor(X, dtype=torch.float32).cuda()
        mean = tensor.mean(dim=0)
        diff = tensor - mean
        dist = torch.sqrt((diff ** 2).sum(dim=1))
        dmin = float(dist.min().cpu())
        dmax = float(dist.max().cpu())
        if dmax == dmin:
            return {}
        anomalies = {}
        for pid, d in zip(pids, dist.cpu().tolist()):
            norm = (d - dmin) / (dmax - dmin)
            anomalies[pid] = norm * 100.0
        return anomalies
    except Exception as e:
        log(f"GPU anomaly error: {e}")
        return {}

# ============================================================
# PyTorch Autoencoder (Neural anomaly model)
# ============================================================

class SimpleAutoencoder(nn.Module):
    def __init__(self, input_dim=5, latent_dim=3):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, 8),
            nn.ReLU(),
            nn.Linear(8, latent_dim),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(latent_dim, 8),
            nn.ReLU(),
            nn.Linear(8, input_dim),
        )

    def forward(self, x):
        z = self.encoder(x)
        out = self.decoder(z)
        return out

autoenc_model = None

def init_autoencoder():
    global autoenc_model, AUTOENCODER_AVAILABLE
    try:
        autoenc_model = SimpleAutoencoder()
        if GPU_AVAILABLE:
            autoenc_model.cuda()
        AUTOENCODER_AVAILABLE = True
        log("Autoencoder initialized (simple neural anomaly model).")
    except Exception as e:
        AUTOENCODER_AVAILABLE = False
        log(f"Autoencoder init failed: {e}")

def compute_autoenc_anomaly_scores(cache_snapshot):
    if not AUTOENCODER_AVAILABLE or autoenc_model is None:
        return {}
    try:
        pids, X = build_ml_features(cache_snapshot)
        if len(X) < 20:
            return {}
        tensor = torch.tensor(X, dtype=torch.float32)
        if GPU_AVAILABLE:
            tensor = tensor.cuda()
        with torch.no_grad():
            recon = autoenc_model(tensor)
            loss = ((tensor - recon) ** 2).mean(dim=1)
        losses = loss.cpu().tolist()
        lmin = min(losses)
        lmax = max(losses)
        if lmax == lmin:
            return {}
        anomalies = {}
        for pid, l in zip(pids, losses):
            norm = (l - lmin) / (lmax - lmin)
            anomalies[pid] = norm * 100.0
        return anomalies
    except Exception as e:
        log(f"Autoencoder anomaly error: {e}")
        return {}

# ============================================================
# Borg Tech: Queen + Workers + Distributed nodes
# ============================================================

class BorgWorker(threading.Thread):
    def __init__(self, queen, chunk, worker_id):
        super().__init__(daemon=True)
        self.queen = queen
        self.chunk = chunk
        self.worker_id = worker_id
        self.latency = 0.0
        self.processed = 0
        self.errors = 0

    def run(self):
        start = time.time()
        local_results = []
        for proc in self.chunk:
            r = self.score_proc(proc)
            if r is not None:
                local_results.append(r)
                self.processed += 1
        self.latency = time.time() - start
        self.queen.worker_report(self.worker_id, local_results, self.latency, self.processed, self.errors)

    def score_proc(self, proc):
        try:
            name = proc.info["name"]
            pid = proc.info["pid"]
            path = proc.info.get("exe", "") or ""
            if not name:
                return None

            try:
                p_obj = psutil.Process(pid)
                cpu = p_obj.cpu_percent(interval=0.0)
                rss = p_obj.memory_info().rss
                parent = p_obj.parent()
                parent_name = parent.name() if parent else ""
            except Exception:
                cpu = 0.0
                rss = 0
                parent_name = ""

            score, reasons = compute_reputation_score(psutil.Process(pid))
            cfg = get_config()
            heuristic_threshold = cfg.get("heuristic_threshold", 50)
            rogue = (score >= heuristic_threshold or is_rogue_name(name))

            update_scan_cache(pid, name, path, score, rogue, cpu=cpu, rss=rss)
            cache_snapshot = get_scan_cache_snapshot()
            entry = cache_snapshot.get(pid, {})
            anomaly = compute_anomaly_score(entry)
            ml_anomaly = 0.0
            gpu_anomaly = 0.0
            autoenc_anomaly = 0.0

            suricata_matches, mitre_tags = apply_suricata_rules({
                "name": name,
                "path": path,
                "score": score,
                "cpu": cpu,
                "rss_mb": float(rss / (1024 * 1024)),
                "parent_name": parent_name,
            })

            reason_text = "; ".join(reasons) if reasons else "Suspicious behavior"
            if anomaly >= cfg.get("anomaly_threshold", 60.0):
                reason_text += f"; anomaly_score={anomaly:.1f}"
            if suricata_matches:
                reason_text += f"; Suricata={','.join(suricata_matches)}"
            if mitre_tags:
                reason_text += f"; MITRE={','.join(mitre_tags)}"

            ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            event = {
                "ts": ts,
                "name": name,
                "pid": pid,
                "path": path,
                "reason": reason_text,
                "score": score,
                "anomaly": anomaly,
                "ml_anomaly": ml_anomaly,
                "gpu_anomaly": gpu_anomaly,
                "autoenc_anomaly": autoenc_anomaly,
                "suricata_matches": suricata_matches,
                "mitre_tags": mitre_tags,
            }

            return {
                "live": {
                    "pid": pid,
                    "name": name,
                    "path": path,
                    "score": score,
                    "rogue": rogue,
                    "anomaly": anomaly,
                    "ml_anomaly": ml_anomaly,
                    "gpu_anomaly": gpu_anomaly,
                    "autoenc_anomaly": autoenc_anomaly,
                    "suricata_matches": suricata_matches,
                    "mitre_tags": mitre_tags,
                    "quarantine": False,
                    "resurrected": False,
                },
                "history": event,
                "alert": {
                    "name": name,
                    "pid": pid,
                    "path": path,
                    "reason": reason_text,
                    "score": score,
                } if (rogue or anomaly >= cfg.get("anomaly_threshold", 60.0) or suricata_matches) else None,
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            self.errors += 1
            return None
        except Exception:
            self.errors += 1
            return None

class BorgQueen:
    def __init__(self):
        self.results_lock = threading.Lock()
        self.live_items = []
        self.history_batch = []
        self.alerts_batch = []

        self.worker_metrics_lock = threading.Lock()
        self.worker_metrics = {}

        self.total_processed = 0
        self.total_errors = 0
        self.slow_workers = 0
        self.restarted_workers = 0

        self.base_worker_count = 6
        self.max_worker_count = 16
        self.min_worker_count = 2

    def reset_cycle(self):
        with self.results_lock:
            self.live_items = []
            self.history_batch = []
            self.alerts_batch = []
        with self.worker_metrics_lock:
            self.worker_metrics = {}
            self.slow_workers = 0

    def worker_report(self, worker_id, worker_results, latency, processed, errors):
        with self.results_lock:
            for r in worker_results:
                self.live_items.append(r["live"])
                if r["history"] is not None:
                    self.history_batch.append(r["history"])
                if r["alert"] is not None:
                    self.alerts_batch.append(r["alert"])

        with self.worker_metrics_lock:
            self.worker_metrics[worker_id] = {
                "latency": latency,
                "processed": processed,
                "errors": errors,
            }
            self.total_processed += processed
            self.total_errors += errors

    def self_heal_and_distribute(self, procs):
        worker_count = min(self.max_worker_count, max(self.min_worker_count, self.base_worker_count))
        chunk_size = max(1, len(procs) // worker_count)
        workers = []
        for i in range(worker_count):
            chunk = procs[i * chunk_size:(i + 1) * chunk_size]
            if not chunk:
                continue
            w = BorgWorker(self, chunk, worker_id=i)
            w.start()
            workers.append(w)

        for w in workers:
            w.join()

        with self.worker_metrics_lock:
            slow_workers = sum(1 for m in self.worker_metrics.values() if m["latency"] > 1.5)
        if slow_workers > 0:
            self.restarted_workers += slow_workers
            log(f"BorgQueen: detected {slow_workers} slow workers, conceptually restarting them next cycle.")

        avg_latency = 0.0
        if self.worker_metrics:
            avg_latency = sum(m["latency"] for m in self.worker_metrics.values()) / len(self.worker_metrics)
        sandbox_set_swarm_status(
            worker_count=len(self.worker_metrics),
            avg_latency=avg_latency,
            total_processed=self.total_processed,
            total_errors=self.total_errors,
            slow_workers=slow_workers,
            restarted_workers=self.restarted_workers,
        )

        return workers

    def finalize_cycle(self):
        prune_scan_cache()

        cache_snapshot = get_scan_cache_snapshot()
        ml_scores = compute_ml_anomaly_scores(cache_snapshot)
        gpu_scores = compute_gpu_anomaly_scores(cache_snapshot)
        autoenc_scores = compute_autoenc_anomaly_scores(cache_snapshot)

        cfg = get_config()
        ml_thr = cfg.get("ml_anomaly_threshold", 60.0)
        auto_thr = cfg.get("autoenc_anomaly_threshold", 60.0)

        for item in self.live_items:
            pid = item["pid"]
            if pid in ml_scores:
                item["ml_anomaly"] = ml_scores[pid]
            if pid in gpu_scores:
                item["gpu_anomaly"] = gpu_scores[pid]
            if pid in autoenc_scores:
                item["autoenc_anomaly"] = autoenc_scores[pid]

            if check_resurrection(item["name"], pid):
                item["resurrected"] = True

        sandbox_set_live_processes(self.live_items)
        for ev in self.history_batch:
            sandbox_append_history(ev)

        cfg_mode = cfg.get("mode", "MANUAL_ALERT")
        for ev in self.history_batch:
            db_insert_event(ev, cfg_mode)

        for al in self.alerts_batch:
            sandbox_add_alert(al)

        history = sandbox_get_history()
        recent = history[-300:]
        if recent:
            avg_score = sum(e["score"] for e in recent) / len(recent)
            threat_level = min(100, max(0, avg_score))
            sandbox_set_threat_level(threat_level)
            self.agentic_tune_threshold(avg_score)

        ThreatMatrixEngine.build_matrix(history)
        TimelineEngine.build_timeline(history, sandbox_get_threat_level())
        AIInsightEngine.generate_insights(history, sandbox_get_threat_level())

    def agentic_tune_threshold(self, avg_score):
        cfg = get_config()
        current = cfg.get("heuristic_threshold", 50)
        target = current
        if avg_score < 20:
            target = min(70, current + 2)
        elif avg_score > 60:
            target = max(30, current - 2)
        if target != current:
            set_config_key("heuristic_threshold", target)
            log(f"Agentic tuning: heuristic_threshold adjusted from {current} to {target} (avg_score={avg_score:.1f})")

# ============================================================
# Threat Matrix / Timeline / AI Insights
# ============================================================

class ThreatMatrixEngine:
    @staticmethod
    def build_matrix(history):
        matrix = {
            "high_score": [],
            "medium_score": [],
            "low_score": [],
            "by_parent": {},
            "by_path_keyword": {},
            "by_mitre": {},
        }

        for e in history[-400:]:
            s = e["score"]
            path = e["path"]
            reason = e["reason"]
            mitre_tags = e.get("mitre_tags", [])

            if s >= 70:
                matrix["high_score"].append(e)
            elif s >= 40:
                matrix["medium_score"].append(e)
            else:
                matrix["low_score"].append(e)

            parent_hint = None
            if "Suspicious parent:" in reason:
                parent_hint = reason.split("Suspicious parent:")[-1].strip()
            if parent_hint:
                matrix["by_parent"].setdefault(parent_hint, []).append(e)

            for kw in SUSPICIOUS_PATH_KEYWORDS:
                if kw in path.lower():
                    matrix["by_path_keyword"].setdefault(kw, []).append(e)

            for mt in mitre_tags:
                matrix["by_mitre"].setdefault(mt, []).append(e)

        sandbox_set_threat_matrix(matrix)

class TimelineEngine:
    @staticmethod
    def build_timeline(history, threat_level, bucket_seconds=300):
        if not history:
            sandbox_set_timeline_buckets([])
            return

        buckets = {}
        for e in history:
            try:
                ts = datetime.datetime.strptime(e["ts"], "%Y-%m-%d %H:%M:%S")
            except Exception:
                continue
            bucket_key = int(ts.timestamp() // bucket_seconds) * bucket_seconds
            b = buckets.get(bucket_key, {"bucket_ts": bucket_key, "count": 0, "sum_score": 0})
            b["count"] += 1
            b["sum_score"] += e["score"]
            buckets[bucket_key] = b

        result = []
        for bk in sorted(buckets.keys()):
            b = buckets[bk]
            avg_score = b["sum_score"] / b["count"] if b["count"] else 0
            result.append({
                "bucket_ts": bk,
                "count": b["count"],
                "avg_score": avg_score,
                "avg_threat": threat_level,
            })

        sandbox_set_timeline_buckets(result)

class AIInsightEngine:
    @staticmethod
    def generate_insights(history, threat_level):
        if not history:
            summary = "No rogue events recorded yet. System appears calm."
            recommendations = [
                "Keep the monitor running to build a baseline.",
                "Add known bad tools or test binaries to the blacklist for faster detection.",
            ]
            focus_targets = []
            sandbox_set_ai_insights(summary, recommendations, focus_targets)
            return

        total = len(history)
        recent = history[-200:]
        recent_scores = [e["score"] for e in recent]
        avg_recent_score = sum(recent_scores) / len(recent_scores) if recent_scores else 0

        freq = {}
        for e in history:
            freq[e["name"]] = freq.get(e["name"], 0) + 1

        top_offenders = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:5]

        rare_high = []
        for e in recent:
            if freq.get(e["name"], 0) <= 2 and e["score"] >= 70:
                rare_high.append(e)

        now = datetime.datetime.now()
        burst_count = 0
        for e in recent:
            try:
                ts = datetime.datetime.strptime(e["ts"], "%Y-%m-%d %H:%M:%S")
                if (now - ts).total_seconds() <= 300:
                    burst_count += 1
            except Exception:
                continue

        summary_lines = [
            f"Total rogue events: {total}",
            f"Recent average score: {avg_recent_score:.1f}",
            f"Current threat level (smoothed): {threat_level}",
        ]
        if burst_count > 20:
            summary_lines.append(f"Detection burst: {burst_count} events in the last 5 minutes.")
        elif burst_count > 5:
            summary_lines.append(f"Moderate activity: {burst_count} events in the last 5 minutes.")
        else:
            summary_lines.append(f"Low recent activity: {burst_count} events in the last 5 minutes.")

        summary_lines.append("")
        summary_lines.append("Top offenders:")
        for name, count in top_offenders:
            summary_lines.append(f"  {name}: {count} detections")

        summary = "\n".join(summary_lines)

        recommendations = []
        if threat_level >= 70:
            recommendations.append(
                "Threat level is high. Use the Threat Matrix tab to inspect high-score, MITRE tags, and parent-based clusters."
            )
            recommendations.append(
                "Capture deep snapshots for top offenders and review their network activity."
            )
        elif threat_level >= 40:
            recommendations.append(
                "Threat level is moderate. Monitor repeated offenders and verify they are expected tools."
            )
        else:
            recommendations.append(
                "Threat level is low. Use this time to refine your blacklist and baseline."
            )

        if rare_high:
            recommendations.append(
                "Rare processes with high scores detected. These may represent out-of-pattern tools or test binaries."
            )

        if burst_count > 20:
            recommendations.append(
                "Detection burst suggests scripted or automated activity. Check for scheduled tasks or batch tools."
            )

        focus_targets = []
        for name, count in top_offenders:
            focus_targets.append({
                "name": name,
                "count": count,
                "type": "repeated_offender",
            })
        for e in rare_high[:10]:
            focus_targets.append({
                "name": e["name"],
                "pid": e["pid"],
                "score": e["score"],
                "reason": e["reason"],
                "type": "rare_high_score",
            })

        sandbox_set_ai_insights(summary, recommendations, focus_targets)

# ============================================================
# Distributed Borg nodes (telemetry sync stub)
# ============================================================

distributed_queue = queue.Queue()

def distributed_borg_sender():
    cfg = get_config()
    nodes = cfg.get("distributed_borg_nodes", [])
    while True:
        try:
            item = distributed_queue.get()
            if item is None:
                break
            data = json.dumps(item)
            for node in nodes:
                try:
                    host, port = node.split(":")
                    port = int(port)
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.settimeout(1.0)
                    s.connect((host, port))
                    s.sendall(data.encode("utf-8"))
                    s.close()
                except Exception:
                    continue
        except Exception:
            time.sleep(1.0)

def distributed_borg_push(event):
    try:
        distributed_queue.put(event)
    except Exception:
        pass

# ============================================================
# Sandbox Scanner
# ============================================================

class SandboxScanner:
    def __init__(self):
        self.running = True
        self.queen = BorgQueen()
        self.scan_thread = threading.Thread(target=self.scan_loop, daemon=True)
        self.tree_thread = threading.Thread(target=self.tree_loop, daemon=True)
        self.scan_thread.start()
        self.tree_thread.start()

    def scan_loop(self):
        log("SandboxScanner v17 Borg swarm scan loop started")
        while self.running:
            try:
                self.borg_scan_cycle()
            except Exception as e:
                log(f"Sandbox scan error: {e}")
            time.sleep(5.0)

    def tree_loop(self):
        log("SandboxScanner v17 tree loop started")
        while self.running:
            try:
                self.build_tree()
            except Exception as e:
                log(f"Sandbox tree error: {e}")
            time.sleep(30.0)

    def borg_scan_cycle(self):
        procs = []
        for proc in psutil.process_iter(["name", "pid", "exe", "ppid"]):
            try:
                procs.append(proc)
            except Exception:
                continue

        self.queen.reset_cycle()
        self.queen.self_heal_and_distribute(procs)
        self.queen.finalize_cycle()

        self.apply_actions()

    def build_tree(self):
        procs = {}
        children_map = {}

        for proc in psutil.process_iter(["pid", "name", "ppid"]):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"] or ""
                ppid = proc.info["ppid"]
                procs[pid] = (name, ppid)
                children_map.setdefault(ppid, []).append(pid)
            except Exception:
                continue

        visited = set()
        lines = []

        def render_node(pid, indent=""):
            if pid in visited:
                lines.append(f"{indent}{pid} (cycle detected)")
                return
            visited.add(pid)

            if pid not in procs:
                return

            name, ppid = procs[pid]
            try:
                score, _ = compute_reputation_score(psutil.Process(pid))
            except Exception:
                score = 0

            rogue_flag = " [ROGUE]" if (score >= get_config().get("heuristic_threshold", 50) or is_rogue_name(name)) else ""
            lines.append(f"{indent}{name} (PID={pid}, score={score}){rogue_flag}")

            for child_pid in children_map.get(pid, []):
                render_node(child_pid, indent + "    ")

        roots = [pid for pid, (name, ppid) in procs.items() if ppid == 0]

        for root_pid in roots:
            render_node(root_pid)

        sandbox_set_tree_lines(lines)

    def apply_actions(self):
        cfg = get_config()
        mode = cfg.get("mode", "MANUAL_ALERT")
        items = sandbox_get_live_processes()
        chrome_targets = cfg.get("chrome_pdpro_targets", [])
        anomaly_thr = cfg.get("anomaly_threshold", 60.0)
        ml_thr = cfg.get("ml_anomaly_threshold", 60.0)
        auto_thr = cfg.get("autoenc_anomaly_threshold", 60.0)

        for item in items:
            pid = item["pid"]
            name = item["name"]
            path = item["path"]
            score = item["score"]
            rogue = item["rogue"]
            anomaly = item.get("anomaly", 0.0)
            ml_anomaly = item.get("ml_anomaly", 0.0)
            gpu_anomaly = item.get("gpu_anomaly", 0.0)
            autoenc_anomaly = item.get("autoenc_anomaly", 0.0)
            suricata_matches = item.get("suricata_matches", [])
            resurrected = item.get("resurrected", False)

            if is_quarantined(pid):
                item["quarantine"] = True
                continue

            should_act = False
            reason = []

            if mode == "AUTO_KILL_ROGUE":
                if (rogue or anomaly >= anomaly_thr or ml_anomaly >= ml_thr or autoenc_anomaly >= auto_thr or suricata_matches or resurrected):
                    should_act = True
                    reason.append("AUTO_KILL_ROGUE criteria met")
            elif mode == "AUTO_KILL_CHROME_PDPRO":
                lname = name.lower()
                for t in chrome_targets:
                    if t.lower() in lname:
                        should_act = True
                        reason.append("AUTO_KILL_CHROME_PDPRO target match")
                        break
            elif mode == "AUTO_QUARANTINE":
                if (rogue or anomaly >= anomaly_thr or ml_anomaly >= ml_thr or autoenc_anomaly >= auto_thr or suricata_matches or resurrected):
                    should_act = True
                    reason.append("AUTO_QUARANTINE criteria met")
            elif mode == "MANUAL_ALERT":
                # Manual mode: no destructive actions, but alerts are already generated.
                continue

            if not should_act or mode == "MANUAL_ALERT":
                continue

            try:
                proc = psutil.Process(pid)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

            if mode in ("AUTO_KILL_ROGUE", "AUTO_KILL_CHROME_PDPRO"):
                try:
                    proc.terminate()
                    record_kill(name, pid)
                    log(f"ActionEngine: KILLED {name} (PID={pid}) mode={mode} reason={'; '.join(reason)}")
                    sandbox_add_alert({
                        "name": name,
                        "pid": pid,
                        "path": path,
                        "reason": f"ActionEngine kill: {', '.join(reason)}",
                        "score": score,
                    })
                except Exception as e:
                    log(f"ActionEngine: failed to kill {name} (PID={pid}): {e}")
            elif mode == "AUTO_QUARANTINE":
                try:
                    proc.suspend()
                    quarantine_pid(pid, {
                        "name": name,
                        "path": path,
                        "score": score,
                        "anomaly": anomaly,
                        "ml_anomaly": ml_anomaly,
                        "gpu_anomaly": gpu_anomaly,
                        "autoenc_anomaly": autoenc_anomaly,
                        "suricata_matches": suricata_matches,
                        "resurrected": resurrected,
                    })
                    item["quarantine"] = True
                    log(f"ActionEngine: QUARANTINED {name} (PID={pid}) reason={'; '.join(reason)}")
                    sandbox_add_alert({
                        "name": name,
                        "pid": pid,
                        "path": path,
                        "reason": f"ActionEngine quarantine: {', '.join(reason)}",
                        "score": score,
                    })
                except Exception as e:
                    log(f"ActionEngine: failed to quarantine {name} (PID={pid}): {e}")

# ============================================================
# Web dashboard (Flask + WebSocket feed)
# ============================================================

flask_app = Flask(__name__)

@flask_app.route("/api/live")
def api_live():
    return jsonify(sandbox_get_live_processes())

@flask_app.route("/api/history")
def api_history():
    return jsonify(sandbox_get_history()[-200:])

@flask_app.route("/api/threat")
def api_threat():
    return jsonify({
        "threat_level": sandbox_get_threat_level(),
        "swarm": sandbox_get_swarm_status(),
    })

def run_flask_server():
    cfg = get_config()
    port = cfg.get("web_dashboard_port", 5005)
    try:
        flask_app.run(host="0.0.0.0", port=port, debug=False, use_reloader=False)
    except Exception as e:
        log(f"Flask server error: {e}")

def websocket_feed_sender():
    cfg = get_config()
    url = cfg.get("websocket_feed_url", "")
    if not url:
        return
    ws = None
    while True:
        try:
            if ws is None:
                ws = create_connection(url)
            payload = {
                "ts": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "threat_level": sandbox_get_threat_level(),
                "live": sandbox_get_live_processes()[:50],
            }
            ws.send(json.dumps(payload))
        except Exception:
            try:
                if ws is not None:
                    ws.close()
            except Exception:
                pass
            ws = None
            time.sleep(5.0)
        time.sleep(10.0)

# ============================================================
# GUI
# ============================================================

class RogueMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Rogue Process Monitor v17.0 (MANUAL_ALERT, Borg + ML + GPU + Autoencoder + Suricata + Kernel Stub + Agentic)")
        self.root.geometry("1550x1000")

        init_db()
        load_config()
        load_suricata_rules()
        init_autoencoder()

        self._build_ui()

        self.sandbox = SandboxScanner()

        self.last_history_text = ""
        self.last_tree_text = ""
        self.last_live_snapshot = []
        self.last_swarm_text = ""
        self.last_ai_text = ""
        self.last_matrix_text = ""
        self.last_timeline_text = ""

        self.last_alert_popup_time = 0.0

        self.live_page = 0
        self.live_page_size = 50

        self._start_refresh_loops()

    def _build_ui(self):
        main = ttk.Notebook(self.root)
        main.pack(fill=tk.BOTH, expand=True)

        self.tab_overview = ttk.Frame(main, padding=10)
        self.tab_blacklist = ttk.Frame(main, padding=10)
        self.tab_history = ttk.Frame(main, padding=10)
        self.tab_live = ttk.Frame(main, padding=10)
        self.tab_tree = ttk.Frame(main, padding=10)
        self.tab_snapshot = ttk.Frame(main, padding=10)
        self.tab_report = ttk.Frame(main, padding=10)
        self.tab_swarm = ttk.Frame(main, padding=10)
        self.tab_ai = ttk.Frame(main, padding=10)
        self.tab_matrix = ttk.Frame(main, padding=10)
        self.tab_timeline = ttk.Frame(main, padding=10)
        self.tab_plots = ttk.Frame(main, padding=10)
        self.tab_actions = ttk.Frame(main, padding=10)
        self.tab_quarantine = ttk.Frame(main, padding=10)

        main.add(self.tab_overview, text="Overview")
        main.add(self.tab_blacklist, text="Blacklist")
        main.add(self.tab_history, text="History / Timeline Text")
        main.add(self.tab_live, text="Live Processes")
        main.add(self.tab_tree, text="Process Tree")
        main.add(self.tab_snapshot, text="Snapshot")
        main.add(self.tab_report, text="Rogue Report")
        main.add(self.tab_swarm, text="Borg Swarm Status")
        main.add(self.tab_ai, text="AI Insights")
        main.add(self.tab_matrix, text="Threat Matrix")
        main.add(self.tab_timeline, text="Timeline View")
        main.add(self.tab_plots, text="Plots (Matplotlib)")
        main.add(self.tab_actions, text="Action Engine / Mode")
        main.add(self.tab_quarantine, text="Quarantine View")

        self._build_overview_tab()
        self._build_blacklist_tab()
        self._build_history_tab()
        self._build_live_tab()
        self._build_tree_tab()
        self._build_snapshot_tab()
        self._build_report_tab()
        self._build_swarm_tab()
        self._build_ai_tab()
        self._build_matrix_tab()
        self._build_timeline_tab()
        self._build_plots_tab()
        self._build_actions_tab()
        self._build_quarantine_tab()

    def _build_overview_tab(self):
        frame = self.tab_overview

        title = ttk.Label(frame, text="Rogue Process Monitor v17.0 (MANUAL_ALERT, Borg + ML + GPU + Autoencoder + Suricata + Kernel Stub + Agentic)", font=("Segoe UI", 14, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Aggressive autoloader installs missing dependencies automatically.\n"
                "Borg swarm tracks per-PID behavior over time.\n"
                "IsolationForest ML + GPU + Autoencoder neural anomaly scoring.\n"
                "Suricata-style rules add signature-based detection with MITRE ATT&CK tags.\n"
                "Kernel driver stub simulates deeper ETW-like signals.\n"
                "Agentic tuning adjusts thresholds based on observed behavior.\n"
                "Modes: MANUAL_ALERT (default), AUTO_KILL_ROGUE, AUTO_KILL_CHROME_PDPRO, AUTO_QUARANTINE.\n"
                "SQLite telemetry DB + Flask/WebSocket web dashboard mirror."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        ml_status = "enabled" if ML_AVAILABLE else "disabled (sklearn not found)"
        gpu_status = "enabled" if GPU_AVAILABLE else "disabled"
        auto_status = "enabled" if AUTOENCODER_AVAILABLE else "disabled"
        plot_status = "enabled" if PLOTTING_AVAILABLE else "disabled (matplotlib not found)"

        cfg = get_config()
        mode = cfg.get("mode", "MANUAL_ALERT")

        self.status_label = ttk.Label(
            frame,
            text=f"Status: starting... | Mode={mode} | ML={ml_status} | GPU={gpu_status} | Autoenc={auto_status} | Plots={plot_status}",
            foreground="#00aa00"
        )
        self.status_label.grid(row=2, column=0, columnspan=3, sticky="w", pady=(5, 10))

        meter_label = ttk.Label(frame, text="Threat Meter (0-100):")
        meter_label.grid(row=3, column=0, sticky="w", pady=(5, 0))

        self.meter_canvas = tk.Canvas(frame, width=700, height=30, bg="#000000",
                                      highlightthickness=1, highlightbackground="#333333")
        self.meter_canvas.grid(row=4, column=0, columnspan=3, sticky="w", pady=(5, 10))

        alert_label = ttk.Label(frame, text="Recent Alerts:")
        alert_label.grid(row=5, column=0, sticky="w", pady=(5, 0))

        self.alert_box = tk.Text(frame, height=10, width=140, state="disabled", bg="#101010", fg="#ffcc00")
        self.alert_box.grid(row=6, column=0, columnspan=3, sticky="we", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=1)

    def _build_blacklist_tab(self):
        frame = self.tab_blacklist

        title = ttk.Label(frame, text="Rogue Process Blacklist", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Names containing any of these entries will be treated as rogue by the Borg sandbox.\n"
                "The monitor will log and alert when they are detected. Actions depend on mode."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.blacklist_listbox = tk.Listbox(frame, height=18, width=60, bg="#101010", fg="#00ffcc")
        self.blacklist_listbox.grid(row=2, column=0, columnspan=2, sticky="nswe", pady=(5, 10))

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.blacklist_listbox.yview)
        scrollbar.grid(row=2, column=2, sticky="ns")
        self.blacklist_listbox.config(yscrollcommand=scrollbar.set)

        self._refresh_blacklist_listbox()

        add_label = ttk.Label(frame, text="Add entry:")
        add_label.grid(row=3, column=0, sticky="w", pady=(5, 0))

        self.add_entry = ttk.Entry(frame, width=40)
        self.add_entry.grid(row=3, column=1, sticky="w", pady=(5, 0))

        add_btn = ttk.Button(frame, text="Add to blacklist", command=self._add_blacklist_entry)
        add_btn.grid(row=3, column=2, sticky="w", padx=(5, 0))

        remove_btn = ttk.Button(frame, text="Remove selected", command=self._remove_selected_blacklist_entry)
        remove_btn.grid(row=4, column=0, sticky="w", pady=(10, 0))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=0)

    def _build_history_tab(self):
        frame = self.tab_history

        title = ttk.Label(frame, text="Detection History / Timeline Text", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Raw rogue detection history.\n"
                "Timeline tab shows bucketed counts and average scores."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.history_box = tk.Text(frame, height=25, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.history_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_live_tab(self):
        frame = self.tab_live

        title = ttk.Label(frame, text="Live Process View (Borg + ML + GPU + Autoenc + Suricata)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows processes as summarized by the Borg Queen.\n"
                "Includes heuristic anomaly, ML anomaly, GPU anomaly, Autoencoder anomaly, Suricata matches, MITRE tags, and resurrection flags."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        columns = ("pid", "name", "path", "score", "anomaly", "ml_anomaly", "gpu_anomaly", "autoenc_anomaly", "rogue", "suricata", "mitre", "quarantine", "resurrected")
        self.live_tree = ttk.Treeview(frame, columns=columns, show="headings", height=25)
        for col in columns:
            self.live_tree.heading(col, text=col.capitalize())

        self.live_tree.column("pid", width=80, anchor="w")
        self.live_tree.column("name", width=200, anchor="w")
        self.live_tree.column("path", width=600, anchor="w")
        self.live_tree.column("score", width=80, anchor="center")
        self.live_tree.column("anomaly", width=120, anchor="center")
        self.live_tree.column("ml_anomaly", width=120, anchor="center")
        self.live_tree.column("gpu_anomaly", width=120, anchor="center")
        self.live_tree.column("autoenc_anomaly", width=120, anchor="center")
        self.live_tree.column("rogue", width=80, anchor="center")
        self.live_tree.column("suricata", width=200, anchor="w")
        self.live_tree.column("mitre", width=200, anchor="w")
        self.live_tree.column("quarantine", width=100, anchor="center")
        self.live_tree.column("resurrected", width=100, anchor="center")

        self.live_tree.grid(row=2, column=0, columnspan=3, sticky="nswe", pady=(5, 10))

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.live_tree.yview)
        scrollbar.grid(row=2, column=3, sticky="ns")
        self.live_tree.config(yscrollcommand=scrollbar.set)

        self.page_label = ttk.Label(frame, text="Page 1", anchor="w")
        self.page_label.grid(row=3, column=0, sticky="w", pady=(0, 5))

        prev_btn = ttk.Button(frame, text="Prev Page", command=self._prev_live_page)
        prev_btn.grid(row=3, column=1, sticky="e", pady=(0, 5))

        next_btn = ttk.Button(frame, text="Next Page", command=self._next_live_page)
        next_btn.grid(row=3, column=2, sticky="e", pady=(0, 5))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=0)
        frame.grid_columnconfigure(2, weight=0)
        frame.grid_columnconfigure(3, weight=0)
        frame.grid_rowconfigure(2, weight=1)

    def _build_tree_tab(self):
        frame = self.tab_tree

        title = ttk.Label(frame, text="Parent/Child Process Tree (Borg Sandbox)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Tree is built inside the Borg sandbox and streamed here.\n"
                "Diff-based updates avoid heavy redraws."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.tree_box = tk.Text(frame, height=25, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.tree_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_snapshot_tab(self):
        frame = self.tab_snapshot

        title = ttk.Label(frame, text="Process Snapshot (Deep Borg + Kernel Stub View)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Deep snapshot uses direct psutil calls for a single PID.\n"
                "Shows CPU, memory, threads, handles, DLLs, network connections, and kernel stub signals."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        pid_label = ttk.Label(frame, text="PID:")
        pid_label.grid(row=2, column=0, sticky="w", pady=(5, 0))

        self.snapshot_pid_entry = ttk.Entry(frame, width=15)
        self.snapshot_pid_entry.grid(row=2, column=1, sticky="w", pady=(5, 0))

        snap_btn = ttk.Button(frame, text="Capture Deep Snapshot", command=self._capture_snapshot)
        snap_btn.grid(row=2, column=2, sticky="w", padx=(5, 0))

        self.snapshot_box = tk.Text(frame, height=25, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.snapshot_box.grid(row=3, column=0, columnspan=3, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=0)
        frame.grid_columnconfigure(2, weight=0)
        frame.grid_rowconfigure(3, weight=1)

    def _build_report_tab(self):
        frame = self.tab_report

        title = ttk.Label(frame, text="Rogue Process Report (Borg Sandbox)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Generates a summary of rogue detections based on Borg sandbox history.\n"
                "Helps understand long-term patterns."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        report_btn = ttk.Button(frame, text="Generate Report", command=self._generate_report)
        report_btn.grid(row=2, column=0, sticky="w", pady=(5, 10))

        self.report_box = tk.Text(frame, height=25, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.report_box.grid(row=3, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

    def _build_swarm_tab(self):
        frame = self.tab_swarm

        title = ttk.Label(frame, text="Borg Swarm Status (Self-Healing + Agentic)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows health and activity of the Borg worker swarm.\n"
                "Includes slow worker count and conceptual restarts.\n"
                "Agentic tuning adjusts heuristic thresholds based on observed scores."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.swarm_box = tk.Text(frame, height=20, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.swarm_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_ai_tab(self):
        frame = self.tab_ai

        title = ttk.Label(frame, text="AI Insights (Heuristic + ML + Autoenc + Suricata Context)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "AI Insight Engine analyzes rogue history and threat level.\n"
                "It suggests recommendations and highlights focus targets.\n"
                "All actions are advisory only; destructive behavior depends on mode."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.ai_box = tk.Text(frame, height=22, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.ai_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_matrix_tab(self):
        frame = self.tab_matrix

        title = ttk.Label(frame, text="Threat Matrix (Score / Parent / Path / MITRE)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Matrix groups events by score band, parent hints, path keywords, and MITRE ATT&CK tags.\n"
                "Helps see clusters instead of isolated events."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.matrix_box = tk.Text(frame, height=24, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.matrix_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_timeline_tab(self):
        frame = self.tab_timeline

        title = ttk.Label(frame, text="Timeline View (Bucketed Activity)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows bucketed counts and average scores over time.\n"
                "Each bucket represents a time window (e.g., 5 minutes)."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.timeline_box = tk.Text(frame, height=24, width=140, state="disabled", bg="#101010", fg="#00ffcc")
        self.timeline_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_plots_tab(self):
        frame = self.tab_plots

        title = ttk.Label(frame, text="Threat / Activity Plots (Matplotlib)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        status = "Matplotlib available" if PLOTTING_AVAILABLE else "Matplotlib NOT available"
        desc = ttk.Label(
            frame,
            text=(
                f"{status}.\n"
                "If available, you can open plots for:\n"
                "  - Threat level over time\n"
                "  - Bucketed activity (count vs avg score)\n"
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.plot_threat_btn = ttk.Button(frame, text="Plot Threat Level Over Time", command=self._plot_threat)
        self.plot_threat_btn.grid(row=2, column=0, sticky="w", pady=(5, 5))

        self.plot_activity_btn = ttk.Button(frame, text="Plot Bucketed Activity", command=self._plot_activity)
        self.plot_activity_btn.grid(row=3, column=0, sticky="w", pady=(5, 5))

        if not PLOTTING_AVAILABLE:
            self.plot_threat_btn.config(state="disabled")
            self.plot_activity_btn.config(state="disabled")

        frame.grid_columnconfigure(0, weight=1)

    def _build_actions_tab(self):
        frame = self.tab_actions

        title = ttk.Label(frame, text="Action Engine / Mode Control", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Select operating mode:\n"
                "  MANUAL_ALERT: no destructive actions, alerts only.\n"
                "  AUTO_KILL_ROGUE: kill processes matching rogue criteria.\n"
                "  AUTO_KILL_CHROME_PDPRO: kill only chrome/pdpro targets.\n"
                "  AUTO_QUARANTINE: suspend rogue processes instead of killing.\n"
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        cfg = get_config()
        mode = cfg.get("mode", "MANUAL_ALERT")

        self.mode_var = tk.StringVar(value=mode)

        modes = [
            ("MANUAL_ALERT", "MANUAL_ALERT"),
            ("AUTO_KILL_ROGUE", "AUTO_KILL_ROGUE"),
            ("AUTO_KILL_CHROME_PDPRO", "AUTO_KILL_CHROME_PDPRO"),
            ("AUTO_QUARANTINE", "AUTO_QUARANTINE"),
        ]

        row = 2
        for label, value in modes:
            rb = ttk.Radiobutton(frame, text=label, value=value, variable=self.mode_var, command=self._change_mode)
            rb.grid(row=row, column=0, sticky="w", pady=(2, 2))
            row += 1

        thr_label = ttk.Label(frame, text="Heuristic threshold:")
        thr_label.grid(row=row, column=0, sticky="w", pady=(10, 0))
        self.thr_entry = ttk.Entry(frame, width=10)
        self.thr_entry.insert(0, str(cfg.get("heuristic_threshold", 50)))
        self.thr_entry.grid(row=row, column=1, sticky="w", pady=(10, 0))
        thr_btn = ttk.Button(frame, text="Update", command=self._update_threshold)
        thr_btn.grid(row=row, column=2, sticky="w", padx=(5, 0))
        row += 1

        an_label = ttk.Label(frame, text="Anomaly threshold:")
        an_label.grid(row=row, column=0, sticky="w", pady=(5, 0))
        self.an_entry = ttk.Entry(frame, width=10)
        self.an_entry.insert(0, str(cfg.get("anomaly_threshold", 60.0)))
        self.an_entry.grid(row=row, column=1, sticky="w", pady=(5, 0))
        an_btn = ttk.Button(frame, text="Update", command=self._update_anomaly_threshold)
        an_btn.grid(row=row, column=2, sticky="w", padx=(5, 0))
        row += 1

        ml_label = ttk.Label(frame, text="ML anomaly threshold:")
        ml_label.grid(row=row, column=0, sticky="w", pady=(5, 0))
        self.ml_entry = ttk.Entry(frame, width=10)
        self.ml_entry.insert(0, str(cfg.get("ml_anomaly_threshold", 60.0)))
        self.ml_entry.grid(row=row, column=1, sticky="w", pady=(5, 0))
        ml_btn = ttk.Button(frame, text="Update", command=self._update_ml_threshold)
        ml_btn.grid(row=row, column=2, sticky="w", padx=(5, 0))
        row += 1

        auto_label = ttk.Label(frame, text="Autoenc anomaly threshold:")
        auto_label.grid(row=row, column=0, sticky="w", pady=(5, 0))
        self.auto_entry = ttk.Entry(frame, width=10)
        self.auto_entry.insert(0, str(cfg.get("autoenc_anomaly_threshold", 60.0)))
        self.auto_entry.grid(row=row, column=1, sticky="w", pady=(5, 0))
        auto_btn = ttk.Button(frame, text="Update", command=self._update_auto_threshold)
        auto_btn.grid(row=row, column=2, sticky="w", padx=(5, 0))
        row += 1

        frame.grid_columnconfigure(0, weight=1)

    def _build_quarantine_tab(self):
        frame = self.tab_quarantine

        title = ttk.Label(frame, text="Quarantine View", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows processes currently quarantined (suspended).\n"
                "You can resume or kill them manually."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        columns = ("pid", "name", "path", "score", "anomaly", "ml_anomaly", "gpu_anomaly", "autoenc_anomaly", "suricata", "ts")
        self.quarantine_tree = ttk.Treeview(frame, columns=columns, show="headings", height=20)
        for col in columns:
            self.quarantine_tree.heading(col, text=col.capitalize())

        self.quarantine_tree.column("pid", width=80, anchor="w")
        self.quarantine_tree.column("name", width=200, anchor="w")
        self.quarantine_tree.column("path", width=600, anchor="w")
        self.quarantine_tree.column("score", width=80, anchor="center")
        self.quarantine_tree.column("anomaly", width=120, anchor="center")
        self.quarantine_tree.column("ml_anomaly", width=120, anchor="center")
        self.quarantine_tree.column("gpu_anomaly", width=120, anchor="center")
        self.quarantine_tree.column("autoenc_anomaly", width=120, anchor="center")
        self.quarantine_tree.column("suricata", width=200, anchor="w")
        self.quarantine_tree.column("ts", width=160, anchor="center")

        self.quarantine_tree.grid(row=2, column=0, columnspan=3, sticky="nswe", pady=(5, 10))

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.quarantine_tree.yview)
        scrollbar.grid(row=2, column=3, sticky="ns")
        self.quarantine_tree.config(yscrollcommand=scrollbar.set)

        resume_btn = ttk.Button(frame, text="Resume selected", command=self._resume_quarantined)
        resume_btn.grid(row=3, column=0, sticky="w", pady=(5, 5))

        kill_btn = ttk.Button(frame, text="Kill selected", command=self._kill_quarantined)
        kill_btn.grid(row=3, column=1, sticky="w", pady=(5, 5))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    # ---- Blacklist actions ----

    def _refresh_blacklist_listbox(self):
        self.blacklist_listbox.delete(0, tk.END)
        for entry in get_blacklist():
            self.blacklist_listbox.insert(tk.END, entry)

    def _add_blacklist_entry(self):
        text = self.add_entry.get().strip()
        if not text:
            return
        add_to_blacklist(text)
        self.add_entry.delete(0, tk.END)
        self._refresh_blacklist_listbox()
        self._update_status(f"Added '{text}' to blacklist")

    def _remove_selected_blacklist_entry(self):
        selection = self.blacklist_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        entry = self.blacklist_listbox.get(index)
        remove_from_blacklist(entry)
        self._refresh_blacklist_listbox()
        self._update_status(f"Removed '{entry}' from blacklist")

    # ---- Snapshot ----

    def _capture_snapshot(self):
        text_pid = self.snapshot_pid_entry.get().strip()
        if not text_pid.isdigit():
            messagebox.showerror("Invalid PID", "Please enter a numeric PID.")
            return
        pid = int(text_pid)
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            messagebox.showerror("Process not found", f"No process with PID {pid}.")
            return
        except psutil.AccessDenied:
            messagebox.showerror("Access denied", f"Access denied to PID {pid}.")
            return

        try:
            name = proc.name() or ""
            exe = proc.exe() or ""
            cpu = proc.cpu_percent(interval=0.1)
            mem = proc.memory_info().rss
            threads = proc.num_threads()
            handles = getattr(proc, "num_handles", lambda: 0)()
            score, reasons = compute_reputation_score(proc)

            dlls = []
            try:
                for m in proc.memory_maps():
                    path = getattr(m, "path", "")
                    if path:
                        dlls.append(path)
            except Exception:
                dlls = []

            conns = []
            try:
                for c in proc.connections(kind="inet"):
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                    raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                    rep_score = network_reputation_score(c.raddr.ip if c.raddr else "")
                    conns.append(f"{c.status} {laddr} -> {raddr} (net_rep={rep_score:.1f})")
            except Exception:
                conns = []

            extra = kernel_stub.get_extra_signals(pid)

        except Exception as e:
            messagebox.showerror("Error", f"Failed to capture snapshot: {e}")
            return

        lines = [
            f"Deep Snapshot for PID {pid}",
            f"Name: {name}",
            f"Path: {exe}",
            f"CPU: {cpu:.1f}%",
            f"Memory: {mem // (1024 * 1024)} MB",
            f"Threads: {threads}",
            f"Handles: {handles}",
            f"Kernel stub signals: handles={extra.get('handle_count', 0)}, threads={extra.get('thread_count', 0)}, registry_persistence_hint={extra.get('registry_persistence_hint', False)}, file_activity_hint={extra.get('file_activity_hint', False)}",
            f"Reputation score: {score}",
            f"Reasons: {', '.join(reasons) if reasons else 'None'}",
            "",
            "Loaded modules / DLLs (top 30):",
        ]
        for dll in dlls[:30]:
            lines.append(f"  {dll}")

        lines.append("")
        lines.append("Network connections (top 20):")
        for c in conns[:20]:
            lines.append(f"  {c}")

        self.snapshot_box.config(state="normal")
        self.snapshot_box.delete("1.0", tk.END)
        self.snapshot_box.insert(tk.END, "\n".join(lines))
        self.snapshot_box.config(state="disabled")

    # ---- Report ----

    def _generate_report(self):
        events = sandbox_get_history()

        if not events:
            text = "No rogue events recorded yet."
        else:
            total = len(events)
            avg_score = sum(e["score"] for e in events) / total
            freq = {}
            for e in events:
                freq[e["name"]] = freq.get(e["name"], 0) + 1
            top = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:10]

            lines = [
                f"Rogue Process Report (Borg Sandbox)",
                f"Total events: {total}",
                f"Average score: {avg_score:.1f}",
                "",
                "Top offenders:",
            ]
            for name, count in top:
                lines.append(f"  {name}: {count} detections")

            lines.append("")
            lines.append("Recent events:")
            for e in events[-80:]:
                lines.append(
                    f"[{e['ts']}] {e['name']} (PID={e['pid']}) score={e['score']} anomaly={e.get('anomaly',0):.1f} ml={e.get('ml_anomaly',0):.1f} autoenc={e.get('autoenc_anomaly',0):.1f} reason={e['reason']}"
                )

            text = "\n".join(lines)

        self.report_box.config(state="normal")
        self.report_box.delete("1.0", tk.END)
        self.report_box.insert(tk.END, text)
        self.report_box.config(state="disabled")

    # ---- Swarm status ----

    def _refresh_swarm_status(self):
        status = sandbox_get_swarm_status()
        worker_count = status.get("worker_count", 0)
        avg_latency = status.get("avg_latency", 0.0)
        total_processed = status.get("total_processed", 0)
        total_errors = status.get("total_errors", 0)
        slow_workers = status.get("slow_workers", 0)
        restarted_workers = status.get("restarted_workers", 0)

        lines = [
            "Borg Swarm Status:",
            f"  Active workers: {worker_count}",
            f"  Average worker latency: {avg_latency:.3f} s",
            f"  Total processes scanned: {total_processed}",
            f"  Total worker errors: {total_errors}",
            f"  Slow workers (last cycle): {slow_workers}",
            f"  Conceptual worker restarts (total): {restarted_workers}",
        ]

        text = "\n".join(lines)
        if text != self.last_swarm_text:
            self.last_swarm_text = text
            self.swarm_box.config(state="normal")
            self.swarm_box.delete("1.0", tk.END)
            self.swarm_box.insert(tk.END, text)
            self.swarm_box.config(state="disabled")

    # ---- AI Insights ----

    def _refresh_ai_insights(self):
        insights = sandbox_get_ai_insights()
        summary = insights.get("summary", "")
        recs = insights.get("recommendations", [])
        targets = insights.get("focus_targets", [])
        ts = insights.get("last_update_ts", "")

        lines = []
        lines.append(f"AI Insight Engine (last update: {ts})")
        lines.append("")
        if summary:
            lines.append("Summary:")
            lines.append(summary)
            lines.append("")
        if recs:
            lines.append("Recommendations:")
            for r in recs:
                lines.append(f"  - {r}")
            lines.append("")
        if targets:
            lines.append("Focus targets:")
            for t in targets:
                if t.get("type") == "repeated_offender":
                    lines.append(f"  [Repeated] {t['name']} ({t['count']} detections)")
                elif t.get("type") == "rare_high_score":
                    lines.append(
                        f"  [Rare High] {t['name']} (PID={t.get('pid','?')}) score={t['score']} reason={t['reason']}"
                    )

        text = "\n".join(lines)
        if text != self.last_ai_text:
            self.last_ai_text = text
            self.ai_box.config(state="normal")
            self.ai_box.delete("1.0", tk.END)
            self.ai_box.insert(tk.END, text)
            self.ai_box.config(state="disabled")

    # ---- Matrix ----

    def _refresh_matrix_view(self):
        matrix = sandbox_get_threat_matrix()
        high = matrix.get("high_score", [])
        medium = matrix.get("medium_score", [])
        low = matrix.get("low_score", [])
        by_parent = matrix.get("by_parent", {})
        by_path = matrix.get("by_path_keyword", {})
        by_mitre = matrix.get("by_mitre", {})

        lines = []
        lines.append("Threat Matrix:")
        lines.append("")
        lines.append(f"High-score events (>=70): {len(high)}")
        for e in high[:20]:
            lines.append(f"  [HIGH] {e['name']} (PID={e['pid']}) score={e['score']} reason={e['reason']}")
        lines.append("")
        lines.append(f"Medium-score events (40-69): {len(medium)}")
        for e in medium[:20]:
            lines.append(f"  [MED] {e['name']} (PID={e['pid']}) score={e['score']} reason={e['reason']}")
        lines.append("")
        lines.append(f"Low-score events (<40): {len(low)}")
        lines.append("")

        lines.append("By parent hint:")
        for parent, events in by_parent.items():
            lines.append(f"  Parent={parent} -> {len(events)} events")
        lines.append("")

        lines.append("By path keyword:")
        for kw, events in by_path.items():
            lines.append(f"  Path contains '{kw}' -> {len(events)} events")
        lines.append("")

        lines.append("By MITRE ATT&CK tag:")
        for mt, events in by_mitre.items():
            lines.append(f"  MITRE {mt} -> {len(events)} events")

        text = "\n".join(lines)
        if text != self.last_matrix_text:
            self.last_matrix_text = text
            self.matrix_box.config(state="normal")
            self.matrix_box.delete("1.0", tk.END)
            self.matrix_box.insert(tk.END, text)
            self.matrix_box.config(state="disabled")

    # ---- Timeline ----

    def _refresh_timeline_view(self):
        buckets = sandbox_get_timeline_buckets()
        lines = []
        lines.append("Timeline (bucketed activity):")
        lines.append("")
        for b in buckets[-40:]:
            ts = datetime.datetime.fromtimestamp(b["bucket_ts"]).strftime("%Y-%m-%d %H:%M:%S")
            lines.append(f"  [{ts}] count={b['count']} avg_score={b['avg_score']:.1f} avg_threat={b['avg_threat']:.1f}")

        text = "\n".join(lines)
        if text != self.last_timeline_text:
            self.last_timeline_text = text
            self.timeline_box.config(state="normal")
            self.timeline_box.delete("1.0", tk.END)
            self.timeline_box.insert(tk.END, text)
            self.timeline_box.config(state="disabled")

    # ---- Threat meter ----

    def _refresh_threat_meter(self):
        level = sandbox_get_threat_level()
        self.meter_canvas.delete("all")
        w = self.meter_canvas.winfo_width()
        h = self.meter_canvas.winfo_height()
        bar_width = int((level / 100) * w)

        if level < 30:
            color = "#00ff00"
        elif level < 60:
            color = "#ffff00"
        else:
            color = "#ff0000"

        self.meter_canvas.create_rectangle(0, 0, bar_width, h, fill=color, outline="")
        self.meter_canvas.create_text(
            w // 2,
            h // 2,
            text=f"Threat Level: {level}",
            fill="#ffffff",
            font=("Consolas", 11),
        )

    # ---- Status ----

    def _update_status(self, text):
        ml_status = "enabled" if ML_AVAILABLE else "disabled"
        gpu_status = "enabled" if GPU_AVAILABLE else "disabled"
        auto_status = "enabled" if AUTOENCODER_AVAILABLE else "disabled"
        plot_status = "enabled" if PLOTTING_AVAILABLE else "disabled"
        cfg = get_config()
        mode = cfg.get("mode", "MANUAL_ALERT")
        self.status_label.config(
            text=f"Status: {text} | Mode={mode} | ML={ml_status} | GPU={gpu_status} | Autoenc={auto_status} | Plots={plot_status}",
            foreground="#00aa00"
        )

    # ---- Live paging ----

    def _prev_live_page(self):
        if self.live_page > 0:
            self.live_page -= 1
            self._refresh_live_view(force=True)

    def _next_live_page(self):
        items = sandbox_get_live_processes()
        max_page = max(0, (len(items) - 1) // self.live_page_size)
        if self.live_page < max_page:
            self.live_page += 1
            self._refresh_live_view(force=True)

    def _refresh_live_view(self, force=False):
        items = sandbox_get_live_processes()
        items = sorted(
            items,
            key=lambda x: (
                max(
                    x.get("autoenc_anomaly", 0),
                    x.get("ml_anomaly", 0),
                    x.get("anomaly", 0),
                    x.get("gpu_anomaly", 0),
                ),
                x["score"]
            ),
            reverse=True
        )

        start = self.live_page * self.live_page_size
        end = start + self.live_page_size
        page_items = items[start:end]

        snapshot = [
            (
                i["pid"],
                i["name"],
                i["path"],
                i["score"],
                i.get("anomaly", 0),
                i.get("ml_anomaly", 0),
                i.get("gpu_anomaly", 0),
                i.get("autoenc_anomaly", 0),
                i["rogue"],
                ",".join(i.get("suricata_matches", [])),
                ",".join(i.get("mitre_tags", [])),
                i.get("quarantine", False),
                i.get("resurrected", False),
            )
            for i in page_items
        ]
        if snapshot != self.last_live_snapshot or force:
            self.last_live_snapshot = snapshot
            self.live_tree.delete(*self.live_tree.get_children())
            for pid, name, path, score, anomaly, ml_anomaly, gpu_anomaly, autoenc_anomaly, rogue, suricata, mitre, quarantine, resurrected in snapshot:
                rogue_str = "YES" if rogue else "NO"
                q_str = "YES" if quarantine else "NO"
                r_str = "YES" if resurrected else "NO"
                values = (
                    pid,
                    name,
                    path,
                    score,
                    f"{anomaly:.1f}",
                    f"{ml_anomaly:.1f}",
                    f"{gpu_anomaly:.1f}",
                    f"{autoenc_anomaly:.1f}",
                    rogue_str,
                    suricata,
                    mitre,
                    q_str,
                    r_str,
                )
                iid = self.live_tree.insert("", tk.END, values=values)
                cfg = get_config()
                if (
                    rogue_str == "YES"
                    or anomaly >= cfg.get("anomaly_threshold", 60.0)
                    or ml_anomaly >= cfg.get("ml_anomaly_threshold", 60.0)
                    or autoenc_anomaly >= cfg.get("autoenc_anomaly_threshold", 60.0)
                    or resurrected
                ):
                    self.live_tree.item(iid, tags=("rogue",))
                if q_str == "YES":
                    self.live_tree.item(iid, tags=("quarantine",))
            self.live_tree.tag_configure("rogue", background="#330000", foreground="#ff6666")
            self.live_tree.tag_configure("quarantine", background="#003333", foreground="#66ffff")

        max_page = max(0, (len(items) - 1) // self.live_page_size)
        self.page_label.config(text=f"Page {self.live_page + 1} / {max_page + 1}")

    # ---- GUI refresh loops (slowed down ~30s where possible) ----

    def _start_refresh_loops(self):
        self._schedule_status_refresh()
        self._schedule_history_refresh()
        self._schedule_live_refresh()
        self._schedule_alert_refresh()
        self._schedule_tree_refresh()
        self._schedule_meter_refresh()
        self._schedule_swarm_refresh()
        self._schedule_ai_refresh()
        self._schedule_matrix_refresh()
        self._schedule_timeline_refresh()
        self._schedule_quarantine_refresh()

    def _schedule_status_refresh(self):
        self._update_status(f"monitoring | blacklist entries={len(get_blacklist())}")
        self.root.after(30000, self._schedule_status_refresh)

    def _schedule_history_refresh(self):
        events = sandbox_get_history()
        lines = [
            f"[{e['ts']}] {e['name']} (PID={e['pid']}) path={e['path']} reason={e['reason']} score={e['score']} anomaly={e.get('anomaly',0):.1f}"
            for e in events
        ]
        text = "\n".join(lines)
        if text != self.last_history_text:
            self.last_history_text = text
            self.history_box.config(state="normal")
            self.history_box.delete("1.0", tk.END)
            self.history_box.insert(tk.END, text)
            self.history_box.config(state="disabled")
        self.root.after(30000, self._schedule_history_refresh)

    def _schedule_live_refresh(self):
        self._refresh_live_view()
        self.root.after(30000, self._schedule_live_refresh)

    def _schedule_alert_refresh(self):
        alerts = sandbox_pop_alerts(max_count=5)
        if alerts:
            self.alert_box.config(state="normal")
            for al in alerts:
                line = f"[ALERT] {al['name']} (PID={al['pid']}) path={al['path']} reason={al['reason']} score={al['score']}\n"
                self.alert_box.insert(tk.END, line)
                self.alert_box.see(tk.END)
            self.alert_box.config(state="disabled")

            now = time.time()
            for al in alerts:
                if now - self.last_alert_popup_time > 2.0:
                    self.last_alert_popup_time = now
                    self._show_alert_popup(al)
                    break
        self.root.after(5000, self._schedule_alert_refresh)

    def _show_alert_popup(self, al):
        def _popup():
            messagebox.showwarning(
                "Rogue Process Detected (Borg Sandbox)",
                f"Process: {al['name']}\nPID: {al['pid']}\nPath: {al['path']}\nReason: {al['reason']}\nScore: {al['score']}\n\n"
                "This process matches your rogue criteria.\n"
                "Actions depend on current mode."
            )
        self.root.after(0, _popup)

    def _schedule_tree_refresh(self):
        lines = sandbox_get_tree_lines()
        text = "\n".join(lines)
        if text != self.last_tree_text:
            self.last_tree_text = text
            self.tree_box.config(state="normal")
            self.tree_box.delete("1.0", tk.END)
            self.tree_box.insert(tk.END, text)
            self.tree_box.config(state="disabled")
        self.root.after(30000, self._schedule_tree_refresh)

    def _schedule_meter_refresh(self):
        self._refresh_threat_meter()
        self.root.after(30000, self._schedule_meter_refresh)

    def _schedule_swarm_refresh(self):
        self._refresh_swarm_status()
        self.root.after(30000, self._schedule_swarm_refresh)

    def _schedule_ai_refresh(self):
        self._refresh_ai_insights()
        self.root.after(30000, self._schedule_ai_refresh)

    def _schedule_matrix_refresh(self):
        self._refresh_matrix_view()
        self.root.after(30000, self._schedule_matrix_refresh)

    def _schedule_timeline_refresh(self):
        self._refresh_timeline_view()
        self.root.after(30000, self._schedule_timeline_refresh)

    def _schedule_quarantine_refresh(self):
        self._refresh_quarantine_view()
        self.root.after(30000, self._schedule_quarantine_refresh)

    # ---- Quarantine view ----

    def _refresh_quarantine_view(self):
        with quarantine_lock:
            q = dict(quarantined_pids)
        self.quarantine_tree.delete(*self.quarantine_tree.get_children())
        for pid, info in q.items():
            data = info["info"]
            ts = info["ts"]
            values = (
                pid,
                data.get("name", ""),
                data.get("path", ""),
                data.get("score", 0),
                f"{data.get('anomaly', 0.0):.1f}",
                f"{data.get('ml_anomaly', 0.0):.1f}",
                f"{data.get('gpu_anomaly', 0.0):.1f}",
                f"{data.get('autoenc_anomaly', 0.0):.1f}",
                ",".join(data.get("suricata_matches", [])),
                ts,
            )
            self.quarantine_tree.insert("", tk.END, values=values)

    def _resume_quarantined(self):
        selection = self.quarantine_tree.selection()
        if not selection:
            return
        for iid in selection:
            values = self.quarantine_tree.item(iid, "values")
            pid = int(values[0])
            with quarantine_lock:
                info = quarantined_pids.pop(pid, None)
            if info is None:
                continue
            try:
                proc = psutil.Process(pid)
                proc.resume()
                log(f"Quarantine: resumed PID {pid} ({values[1]})")
            except Exception as e:
                log(f"Quarantine: failed to resume PID {pid}: {e}")
        self._refresh_quarantine_view()

    def _kill_quarantined(self):
        selection = self.quarantine_tree.selection()
        if not selection:
            return
        for iid in selection:
            values = self.quarantine_tree.item(iid, "values")
            pid = int(values[0])
            with quarantine_lock:
                info = quarantined_pids.pop(pid, None)
            if info is None:
                continue
            try:
                proc = psutil.Process(pid)
                proc.terminate()
                record_kill(values[1], pid)
                log(f"Quarantine: killed PID {pid} ({values[1]})")
            except Exception as e:
                log(f"Quarantine: failed to kill PID {pid}: {e}")
        self._refresh_quarantine_view()

    # ---- Mode / thresholds ----

    def _change_mode(self):
        mode = self.mode_var.get()
        set_config_key("mode", mode)
        self._update_status(f"mode changed to {mode}")

    def _update_threshold(self):
        text = self.thr_entry.get().strip()
        try:
            val = int(text)
        except ValueError:
            messagebox.showerror("Invalid threshold", "Please enter an integer.")
            return
        set_config_key("heuristic_threshold", val)
        self._update_status(f"heuristic_threshold updated to {val}")

    def _update_anomaly_threshold(self):
        text = self.an_entry.get().strip()
        try:
            val = float(text)
        except ValueError:
            messagebox.showerror("Invalid threshold", "Please enter a number.")
            return
        set_config_key("anomaly_threshold", val)
        self._update_status(f"anomaly_threshold updated to {val}")

    def _update_ml_threshold(self):
        text = self.ml_entry.get().strip()
        try:
            val = float(text)
        except ValueError:
            messagebox.showerror("Invalid threshold", "Please enter a number.")
            return
        set_config_key("ml_anomaly_threshold", val)
        self._update_status(f"ml_anomaly_threshold updated to {val}")

    def _update_auto_threshold(self):
        text = self.auto_entry.get().strip()
        try:
            val = float(text)
        except ValueError:
            messagebox.showerror("Invalid threshold", "Please enter a number.")
            return
        set_config_key("autoenc_anomaly_threshold", val)
        self._update_status(f"autoenc_anomaly_threshold updated to {val}")

    # ---- Matplotlib plots ----

    def _plot_threat(self):
        if not PLOTTING_AVAILABLE:
            messagebox.showerror("Plots disabled", "Matplotlib is not available.")
            return
        data = sandbox_get_threat_bucket_history()
        if not data:
            messagebox.showinfo("No data", "No threat history yet.")
            return
        times = [datetime.datetime.fromtimestamp(t) for t, v in data]
        values = [v for t, v in data]
        plt.figure(figsize=(10, 4))
        plt.plot(times, values, marker="o", linestyle="-", color="red")
        plt.title("Threat Level Over Time (Smoothed)")
        plt.xlabel("Time")
        plt.ylabel("Threat Level (0-100)")
        plt.grid(True)
        plt.tight_layout()
        plt.show()

    def _plot_activity(self):
        if not PLOTTING_AVAILABLE:
            messagebox.showerror("Plots disabled", "Matplotlib is not available.")
            return
        buckets = sandbox_get_timeline_buckets()
        if not buckets:
            messagebox.showinfo("No data", "No timeline buckets yet.")
            return
        times = [datetime.datetime.fromtimestamp(b["bucket_ts"]) for b in buckets]
        counts = [b["count"] for b in buckets]
        avg_scores = [b["avg_score"] for b in buckets]

        fig, ax1 = plt.subplots(figsize=(10, 4))
        ax2 = ax1.twinx()

        ax1.bar(times, counts, width=0.02, color="blue", alpha=0.6, label="Event Count")
        ax2.plot(times, avg_scores, color="orange", marker="o", label="Avg Score")

        ax1.set_xlabel("Time")
        ax1.set_ylabel("Event Count", color="blue")
        ax2.set_ylabel("Avg Score", color="orange")
        plt.title("Bucketed Activity: Count vs Avg Score")
        fig.autofmt_xdate()
        fig.tight_layout()
        plt.show()

# ============================================================
# Main
# ============================================================

def main():
    log("Rogue Process Monitor v17.0 (MANUAL_ALERT, Borg + ML + GPU + Autoencoder + Suricata + Kernel Stub + Agentic) starting")

    cfg = get_config()
    flask_thread = threading.Thread(target=run_flask_server, daemon=True)
    flask_thread.start()

    ws_thread = threading.Thread(target=websocket_feed_sender, daemon=True)
    ws_thread.start()

    dist_thread = threading.Thread(target=distributed_borg_sender, daemon=True)
    dist_thread.start()

    root = tk.Tk()
    gui = RogueMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
