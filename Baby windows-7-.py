#!/usr/bin/env python3
"""
System Governor v2.0
Resilient, self-learning, physics-inspired system governor with AI-style prediction

New in v2.0:
- Auto-elevation to admin
- Robust autoloader for all required libraries
- 2-week observation-only phase (no actions)
- Baseline learning (daily rhythm, normal behavior)
- Auto-whitelist of essential/core processes
- Anomaly detection (CPU/RAM/I/O deviations)
- True AI-style prediction (ML model using historical features)
- Anomaly severity levels (Low/Medium/High/Critical)
- Threat scoring (per process)
- Infection pattern detection (suspicious behavior combos)
- Drive/USB behavioral baselines
- Process lineage tracking (parent/child relationships)
- Fluid-style resource modeling (flow/pressure/turbulence/viscosity)
- Altered-state classification (Stable/Chaotic/Dormant/Aggressive/Parasitic/Transient)
- Neural-style scoring (stability/activity/bloat/risk/resource)
- System mood visualization (overall health state)
- Threat matrix view (process vs threat dimensions)
- Self-healing (priority/affinity/suspend/kill with safeguards)
- Integrity checks on config
- Settings manager (known/unknown/new) with backup/restore
- Hybrid Settings Panel (Simple + Advanced collapsible)
- Apply Standby to selected PID
- Cleanup suggestions view
- GUI dashboard + system tray agent
"""

# ==========================
# AUTO-ELEVATION CHECK
# ==========================
import ctypes
import os
import sys

def ensure_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[Governor] Admin rights required. Relaunching with elevation...")
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{script}" {params}',
                None,
                1
            )
            sys.exit()
    except Exception as e:
        print(f"[Governor] Elevation failed: {e}")
        sys.exit()

if "--watchdog" not in sys.argv:
    ensure_admin()

# ==========================
# AUTOLOADER
# ==========================
import importlib
import subprocess

REQUIRED_MODULES = {
    "os": "os",
    "time": "time",
    "threading": "threading",
    "json": "json",
    "hashlib": "hashlib",
    "logging": "logging",
    "psutil": "psutil",
    "schedule": "schedule",
    "PySide6": "PySide6",
    "win32api": "pywin32",
    "win32con": "pywin32",
    "win32process": "pywin32",
    "pystray": "pystray",
    "PIL": "Pillow",
    "sklearn": "scikit-learn",
}

BUILTIN_OR_OS = {
    "os",
    "time",
    "threading",
    "json",
    "hashlib",
    "logging",
}

def _safe_import(module_name):
    try:
        importlib.import_module(module_name)
        print(f"[AUTOLOADER] Loaded: {module_name}")
        return True
    except ImportError:
        print(f"[AUTOLOADER] Missing: {module_name}")
        return False
    except Exception as e:
        print(f"[AUTOLOADER] Error importing {module_name}: {e}")
        return False

def _install_packages(pkgs):
    if not pkgs:
        return True
    try:
        print(f"[AUTOLOADER] Installing: {pkgs}")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + pkgs)
        return True
    except Exception as e:
        print(f"[AUTOLOADER] Install failed for {pkgs}: {e}")
        return False

def autoload_modules():
    missing = []
    for module_name, pip_name in REQUIRED_MODULES.items():
        if module_name in BUILTIN_OR_OS:
            print(f"[AUTOLOADER] {module_name} is builtin/OS-provided.")
            continue
        if not _safe_import(module_name):
            missing.append(pip_name)

    if missing:
        if not _install_packages(missing):
            print("[AUTOLOADER] FATAL: required modules failed to install.")
            sys.exit(1)

    for module_name in REQUIRED_MODULES.keys():
        if module_name in BUILTIN_OR_OS:
            continue
        _safe_import(module_name)

    print("[AUTOLOADER] Complete.")

autoload_modules()

# ==========================
# IMPORTS AFTER LOADER
# ==========================
import time
import threading
import json
import hashlib
import logging
import psutil
import schedule
from PySide6 import QtWidgets, QtCore
import win32api
import win32con
import win32process
import pystray
from PIL import Image, ImageDraw
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import StandardScaler
from sklearn.pipeline import Pipeline

# ==========================
# LOGGING + CONFIG + INTEGRITY
# ==========================
BASE_DIR = os.getcwd()
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "system_governor_v2_0.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

def log_info(msg):
    print(msg)
    logging.info(msg)

CONFIG_PATH = os.path.join(BASE_DIR, "system_governor_config.json")
CONFIG_HASH_PATH = os.path.join(BASE_DIR, "system_governor_config.hash")
CONFIG_BACKUP_PATH = os.path.join(BASE_DIR, "system_governor_config_backup.json")

DEFAULT_CONFIG = {
    "scan_interval_sec": 10,
    "usage_window_minutes": 60,
    "observation_days": 14,
    "standby_threshold_cpu": 5,
    "standby_idle_minutes": 15,
    "auto_standby_enabled": True,
    "whitelist": [
        "System",
        "Registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "explorer.exe",
        "python.exe",
    ],
    "bloat_min_days": 7,
    "bloat_max_active_sec": 300,
    "self_healing_enabled": True,
    "settings_version": 2,
    "user_settings": {},
    "unknown_settings": {},
    "new_settings": {},
    "ai_prediction_enabled": True,
    "ai_min_samples": 200,
}

def _hash_file(path):
    if not os.path.isfile(path):
        return None
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            chunk = f.read(8192)
            if not chunk:
                break
            h.update(chunk)
    return h.hexdigest()

def _backup_config(cfg):
    try:
        with open(CONFIG_BACKUP_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        log_info("[CONFIG] Backup saved.")
    except Exception as e:
        log_info(f"[CONFIG BACKUP ERROR] {e}")

def _restore_config_from_backup():
    if not os.path.isfile(CONFIG_BACKUP_PATH):
        return None
    try:
        with open(CONFIG_BACKUP_PATH, "r", encoding="utf-8") as f:
            cfg = json.load(f)
        log_info("[CONFIG] Restored from backup.")
        return cfg
    except Exception as e:
        log_info(f"[CONFIG RESTORE ERROR] {e}")
        return None

def load_config():
    if not os.path.isfile(CONFIG_PATH):
        cfg = DEFAULT_CONFIG.copy()
        save_config(cfg)
        return cfg
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            if k not in data:
                data[k] = v
        return data
    except Exception as e:
        log_info(f"[CONFIG] Failed to load config, trying backup: {e}")
        backup = _restore_config_from_backup()
        if backup:
            return backup
        log_info("[CONFIG] Using defaults.")
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        h = _hash_file(CONFIG_PATH)
        if h:
            with open(CONFIG_HASH_PATH, "w", encoding="utf-8") as hf:
                hf.write(h)
        _backup_config(cfg)
        log_info("[CONFIG] system_governor_config.json updated.")
    except Exception as e:
        log_info(f"[CONFIG ERROR] {e}")

def verify_config_integrity():
    if not os.path.isfile(CONFIG_PATH) or not os.path.isfile(CONFIG_HASH_PATH):
        return True
    try:
        with open(CONFIG_HASH_PATH, "r", encoding="utf-8") as hf:
            stored = hf.read().strip()
        current = _hash_file(CONFIG_PATH)
        if stored != current:
            log_info("[INTEGRITY] Config hash mismatch detected.")
            return False
        return True
    except Exception as e:
        log_info(f"[INTEGRITY] Config integrity check failed: {e}")
        return True

CONFIG = load_config()

# ==========================
# SETTINGS MANAGER
# ==========================
SETTINGS_DB_PATH = os.path.join(BASE_DIR, "system_governor_settings_db.json")

def load_settings_db():
    if not os.path.isfile(SETTINGS_DB_PATH):
        return {"known": {}, "unknown": {}, "new": {}}
    try:
        with open(SETTINGS_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"known": {}, "unknown": {}, "new": {}}

def save_settings_db(db):
    try:
        with open(SETTINGS_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        log_info("[SETTINGS DB] Updated.")
    except Exception as e:
        log_info(f"[SETTINGS DB ERROR] {e}")

SETTINGS_DB = load_settings_db()

def register_setting(key, value, category="unknown"):
    if category == "known":
        SETTINGS_DB["known"][key] = value
        CONFIG["user_settings"][key] = value
    elif category == "new":
        SETTINGS_DB["new"][key] = value
        CONFIG["new_settings"][key] = value
    else:
        SETTINGS_DB["unknown"][key] = value
        CONFIG["unknown_settings"][key] = value
    save_settings_db(SETTINGS_DB)
    save_config(CONFIG)

def protect_user_settings():
    for key, value in CONFIG.get("user_settings", {}).items():
        SETTINGS_DB["known"][key] = value
    save_settings_db(SETTINGS_DB)
    save_config(CONFIG)

# ==========================
# WATCHDOG (CONCEPTUAL)
# ==========================
def start_watchdog():
    log_info("[WATCHDOG] Watchdog active (conceptual).")

# ==========================
# STANDBY ENGINE + WHITELIST
# ==========================
def is_whitelisted(name: str) -> bool:
    wl = CONFIG.get("whitelist", [])
    name_lower = (name or "").lower()
    for w in wl:
        if w.lower() == name_lower:
            return True
    return False

def suspend_process(pid, name):
    if is_whitelisted(name):
        log_info(f"[STANDBY] Skipping suspend for whitelisted {name} (PID {pid})")
        return False
    try:
        proc = psutil.Process(pid)
        proc.suspend()
        log_info(f"[STANDBY] Suspended {name} (PID {pid})")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Suspend failed for {name} (PID {pid}): {e}")
        return False

def resume_process(pid, name):
    try:
        proc = psutil.Process(pid)
        proc.resume()
        log_info(f"[STANDBY] Resumed {name} (PID {pid})")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Resume failed for {name} (PID {pid}): {e}")
        return False

def lower_priority(pid, name):
    if is_whitelisted(name):
        log_info(f"[STANDBY] Skipping priority change for whitelisted {name} (PID {pid})")
        return False
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
        win32process.SetPriorityClass(handle, win32process.IDLE_PRIORITY_CLASS)
        win32api.CloseHandle(handle)
        log_info(f"[STANDBY] Lowered priority for {name} (PID {pid})")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Priority change failed for {name} (PID {pid}): {e}")
        return False

def reduce_affinity(pid, name):
    if is_whitelisted(name):
        log_info(f"[STANDBY] Skipping affinity change for whitelisted {name} (PID {pid})")
        return False
    try:
        proc = psutil.Process(pid)
        proc.cpu_affinity([0])
        log_info(f"[STANDBY] Reduced affinity for {name} (PID {pid}) to core 0")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Affinity change failed for {name} (PID {pid}): {e}")
        return False

def kill_process(pid, name):
    if is_whitelisted(name):
        log_info(f"[HEALING] Skipping kill for whitelisted {name} (PID {pid})")
        return False
    try:
        proc = psutil.Process(pid)
        proc.terminate()
        log_info(f"[HEALING] Terminated {name} (PID {pid})")
        return True
    except Exception as e:
        log_info(f"[HEALING] Kill failed for {name} (PID {pid}): {e}")
        return False

# ==========================
# PROGRAM DB + BASELINES
# ==========================
PROGRAM_DB_PATH = os.path.join(BASE_DIR, "governor_program_db.json")

def load_program_db():
    if not os.path.isfile(PROGRAM_DB_PATH):
        return {}
    try:
        with open(PROGRAM_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_program_db(db):
    try:
        with open(PROGRAM_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        log_info("[PROGRAM DB] Updated.")
    except Exception as e:
        log_info(f"[PROGRAM DB ERROR] {e}")

# ==========================
# AI PREDICTION ENGINE
# ==========================
AI_MODEL_PATH = os.path.join(BASE_DIR, "governor_ai_model.json")

class AIPredictor:
    def __init__(self):
        self.pipeline = Pipeline([
            ("scaler", StandardScaler()),
            ("rf", RandomForestClassifier(n_estimators=50, random_state=42))
        ])
        self.trained = False
        self.training_data = []
        self.training_labels = []

    def add_sample(self, features, label):
        self.training_data.append(features)
        self.training_labels.append(label)

    def can_train(self):
        return len(self.training_data) >= CONFIG.get("ai_min_samples", 200)

    def train(self):
        if not self.can_train():
            return
        try:
            self.pipeline.fit(self.training_data, self.training_labels)
            self.trained = True
            log_info("[AI] Model trained.")
        except Exception as e:
            log_info(f"[AI] Training failed: {e}")

    def predict_risk(self, features):
        if not self.trained:
            return 0.0
        try:
            proba = self.pipeline.predict_proba([features])
            # Assume label 1 = risky, 0 = normal
            if proba.shape[1] == 1:
                return 0.0
            return float(proba[0][1] * 100.0)
        except Exception as e:
            log_info(f"[AI] Prediction failed: {e}")
            return 0.0

ai_predictor = AIPredictor()

# ==========================
# USAGE TRACKER + PHYSICS MODEL + LINEAGE + DRIVES
# ==========================
class UsageTracker:
    def __init__(self, window_minutes=60):
        self.window_seconds = window_minutes * 60
        self.process_usage = {}
        self.program_db = load_program_db()
        self.lock = threading.Lock()
        self.start_time = time.time()
        self.drive_baselines = {}
        self.usb_baselines = {}
        self.system_mood = "Unknown"

    def observation_phase_active(self):
        days = (time.time() - self.start_time) / 86400.0
        return days < CONFIG.get("observation_days", 14)

    def update_drives(self):
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                baseline = self.drive_baselines.get(part.device, {"samples": [], "avg": 0.0})
                baseline["samples"].append(usage.percent)
                baseline["avg"] = sum(baseline["samples"]) / len(baseline["samples"])
                self.drive_baselines[part.device] = baseline
            except Exception:
                continue

    def update_usb(self):
        # Simple heuristic: treat removable drives as USB baseline
        for part in psutil.disk_partitions():
            if "removable" in part.opts.lower():
                try:
                    usage = psutil.disk_usage(part.mountpoint)
                    baseline = self.usb_baselines.get(part.device, {"samples": [], "avg": 0.0})
                    baseline["samples"].append(usage.percent)
                    baseline["avg"] = sum(baseline["samples"]) / len(baseline["samples"])
                    self.usb_baselines[part.device] = baseline
                except Exception:
                    continue

    def update(self):
        now = time.time()
        with self.lock:
            self.update_drives()
            self.update_usb()

            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "io_counters", "ppid"]):
                pid = proc.info["pid"]
                name = proc.info["name"] or "unknown"
                cpu = proc.info["cpu_percent"] or 0.0
                mem = proc.info["memory_info"].rss if proc.info["memory_info"] else 0
                io = proc.info["io_counters"].read_bytes + proc.info["io_counters"].write_bytes if proc.info["io_counters"] else 0
                ppid = proc.info.get("ppid", 0)

                if pid not in self.process_usage:
                    self.process_usage[pid] = {
                        "name": name,
                        "first_seen": now,
                        "last_seen": now,
                        "total_active_sec": 0.0,
                        "last_cpu": cpu,
                        "last_mem": mem,
                        "last_io": io,
                        "cpu_history": [cpu],
                        "mem_history": [mem],
                        "io_history": [io],
                        "ppid": ppid,
                        "lineage": [],
                    }
                else:
                    info = self.process_usage[pid]
                    delta = now - info["last_seen"]
                    info["total_active_sec"] += delta
                    info["last_seen"] = now
                    info["last_cpu"] = cpu
                    info["last_mem"] = mem
                    info["last_io"] = io
                    info["cpu_history"].append(cpu)
                    info["mem_history"].append(mem)
                    info["io_history"].append(io)
                    info["ppid"] = ppid

                # lineage tracking
                if ppid:
                    self.process_usage[pid]["lineage"].append(ppid)

                entry = self.program_db.get(name, {
                    "first_seen": now,
                    "last_seen": now,
                    "total_active_sec": 0.0,
                    "cpu_samples": [],
                    "mem_samples": [],
                    "io_samples": [],
                })
                entry["last_seen"] = now
                entry["total_active_sec"] += CONFIG["scan_interval_sec"]
                entry["cpu_samples"].append(cpu)
                entry["mem_samples"].append(mem)
                entry["io_samples"].append(io)
                self.program_db[name] = entry

            to_delete = []
            for pid, info in self.process_usage.items():
                if now - info["last_seen"] > self.window_seconds:
                    to_delete.append(pid)
            for pid in to_delete:
                del self.process_usage[pid]

            save_program_db(self.program_db)

    def compute_flow_metrics(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        return {
            "cpu_flow": cpu,
            "ram_pressure": mem.percent,
            "disk_turbulence": disk.percent,
        }

    def classify_process_state(self, info):
        cpu = info["last_cpu"]
        mem = info["last_mem"]
        io = info["last_io"]
        active = info["total_active_sec"]
        if cpu < 2 and active > 3600:
            return "Dormant"
        if cpu > 50 or mem > 500 * 1024 * 1024:
            return "Aggressive"
        if io > 50 * 1024 * 1024:
            return "Chaotic"
        if active < 60 and cpu < 1 and mem < 50 * 1024 * 1024:
            return "Transient"
        if cpu < 5 and mem < 200 * 1024 * 1024 and io < 10 * 1024 * 1024:
            return "Stable"
        return "Parasitic"

    def score_process(self, name, info):
        cpu_hist = info.get("cpu_history", [])
        if cpu_hist:
            avg_cpu = sum(cpu_hist) / len(cpu_hist)
            var_cpu = sum((c - avg_cpu) ** 2 for c in cpu_hist) / len(cpu_hist)
        else:
            avg_cpu = 0.0
            var_cpu = 0.0

        total_active = info.get("total_active_sec", 0.0)

        stability = max(0.0, 100.0 - var_cpu)
        activity = min(100.0, total_active / 60.0)
        resource = min(100.0, avg_cpu + (info["last_mem"] / (1024 * 1024 * 50)) + (info["last_io"] / (1024 * 1024 * 50)))

        if total_active < 300 and (time.time() - info["first_seen"]) > CONFIG["bloat_min_days"] * 86400:
            bloat = 80.0
        else:
            bloat = 0.0

        risk = min(100.0, resource + var_cpu / 2.0)

        return {
            "stability": stability,
            "activity": activity,
            "bloat": bloat,
            "risk": risk,
            "resource": resource,
        }

    def detect_anomalies(self):
        anomalies = []
        for pid, info in self.process_usage.items():
            name = info["name"]
            entry = self.program_db.get(name)
            if not entry:
                continue
            cpu_samples = entry.get("cpu_samples", [])
            mem_samples = entry.get("mem_samples", [])
            io_samples = entry.get("io_samples", [])
            if len(cpu_samples) < 10:
                continue
            avg_cpu = sum(cpu_samples) / len(cpu_samples)
            avg_mem = sum(mem_samples) / len(mem_samples) if mem_samples else 0
            avg_io = sum(io_samples) / len(io_samples) if io_samples else 0

            reason = None
            if info["last_cpu"] > avg_cpu * 3 + 20:
                reason = "CPU spike"
            if info["last_mem"] > avg_mem * 3 + 200 * 1024 * 1024:
                reason = "RAM growth"
            if info["last_io"] > avg_io * 3 + 50 * 1024 * 1024:
                reason = "I/O burst"

            if reason:
                anomalies.append((pid, name, reason))
        return anomalies

    def auto_whitelist_update(self):
        if self.observation_phase_active():
            return
        for name, entry in self.program_db.items():
            total_active = entry.get("total_active_sec", 0.0)
            days = (time.time() - entry.get("first_seen", self.start_time)) / 86400.0
            if days > 7 and total_active > 3600:
                if name not in CONFIG["whitelist"]:
                    CONFIG["whitelist"].append(name)
                    log_info(f"[WHITELIST] Auto-added {name} based on baseline usage.")
        save_config(CONFIG)

    def compute_system_mood(self):
        flow = self.compute_flow_metrics()
        cpu = flow["cpu_flow"]
        ram = flow["ram_pressure"]
        disk = flow["disk_turbulence"]

        if cpu < 30 and ram < 50 and disk < 50:
            self.system_mood = "Calm"
        elif cpu < 60 and ram < 70 and disk < 70:
            self.system_mood = "Focused"
        elif cpu < 80 and ram < 85 and disk < 85:
            self.system_mood = "Stressed"
        else:
            self.system_mood = "Overloaded"

usage_tracker = UsageTracker(window_minutes=CONFIG["usage_window_minutes"])

# ==========================
# CLEANUP SUGGESTIONS
# ==========================
def get_cleanup_suggestions():
    suggestions = []
    now = time.time()
    for name, entry in usage_tracker.program_db.items():
        first_seen = entry.get("first_seen", now)
        total_active = entry.get("total_active_sec", 0.0)
        days_installed = (now - first_seen) / 86400.0
        if days_installed >= CONFIG["bloat_min_days"] and total_active <= CONFIG["bloat_max_active_sec"]:
            suggestions.append({
                "name": name,
                "days_installed": days_installed,
                "total_active_sec": total_active,
            })
    return sorted(suggestions, key=lambda x: (-x["days_installed"], x["total_active_sec"]))

# ==========================
# THREAT SCORING + INFECTION PATTERNS
# ==========================
def compute_anomaly_severity(reason, scores, ai_risk):
    base = scores["risk"]
    if reason == "CPU spike":
        base += 10
    elif reason == "RAM growth":
        base += 15
    elif reason == "I/O burst":
        base += 20
    base = min(100.0, base + ai_risk / 2.0)

    if base < 30:
        return "Low", base
    elif base < 60:
        return "Medium", base
    elif base < 80:
        return "High", base
    else:
        return "Critical", base

def detect_infection_pattern(info, scores, ai_risk):
    # Simple heuristic: high IO + high RAM + high risk + short lifetime
    if info["last_io"] > 100 * 1024 * 1024 and info["last_mem"] > 500 * 1024 * 1024:
        if scores["risk"] > 70 or ai_risk > 70:
            if (time.time() - info["first_seen"]) < 3600:
                return True
    return False

def build_threat_matrix_entry(pid, info, scores, ai_risk, severity, infection_flag):
    return {
        "pid": pid,
        "name": info["name"],
        "state": usage_tracker.classify_process_state(info),
        "stability": scores["stability"],
        "activity": scores["activity"],
        "bloat": scores["bloat"],
        "risk": scores["risk"],
        "resource": scores["resource"],
        "ai_risk": ai_risk,
        "severity": severity,
        "infection_pattern": infection_flag,
        "ppid": info.get("ppid", 0),
        "lineage": info.get("lineage", []),
    }

# ==========================
# AUTO-STANDBY + SELF-HEALING
# ==========================
def auto_standby_tick():
    if usage_tracker.observation_phase_active():
        return
    candidates = []
    with usage_tracker.lock:
        threshold = CONFIG["standby_threshold_cpu"]
        idle_minutes = CONFIG["standby_idle_minutes"]
        idle_sec = idle_minutes * 60
        now = time.time()
        for pid, info in usage_tracker.process_usage.items():
            idle_time = now - info["last_seen"]
            if info["last_cpu"] < threshold and idle_time > idle_sec:
                candidates.append((pid, info["name"], info["last_cpu"], idle_time))

    for pid, name, cpu, idle in candidates:
        lower_priority(pid, name)
        reduce_affinity(pid, name)
        if idle > idle_sec * 2 and CONFIG.get("self_healing_enabled", True):
            suspend_process(pid, name)

def self_healing_tick():
    if usage_tracker.observation_phase_active():
        return
    anomalies = usage_tracker.detect_anomalies()
    threat_matrix = []
    for pid, name, reason in anomalies:
        with usage_tracker.lock:
            info = usage_tracker.process_usage.get(pid)
        if not info:
            continue
        scores = usage_tracker.score_process(name, info)

        # AI features: cpu, mem, io, activity, risk
        features = [
            info["last_cpu"],
            info["last_mem"] / (1024 * 1024),
            info["last_io"] / (1024 * 1024),
            scores["activity"],
            scores["risk"],
        ]
        ai_risk = ai_predictor.predict_risk(features) if CONFIG.get("ai_prediction_enabled", True) else 0.0

        severity_label, severity_score = compute_anomaly_severity(reason, scores, ai_risk)
        infection_flag = detect_infection_pattern(info, scores, ai_risk)

        threat_entry = build_threat_matrix_entry(
            pid, info, scores, ai_risk, severity_label, infection_flag
        )
        threat_matrix.append(threat_entry)

        log_info(f"[ANOMALY] {name} (PID {pid}) — {reason}, Severity: {severity_label}, AI risk: {ai_risk:.1f}")

        if not CONFIG.get("self_healing_enabled", True):
            continue

        if severity_label in ("High", "Critical") or infection_flag:
            lower_priority(pid, name)
            reduce_affinity(pid, name)
            if severity_label == "Critical" or infection_flag:
                if not is_whitelisted(name):
                    kill_process(pid, name)

    # Feed AI training data (normal vs anomaly)
    with usage_tracker.lock:
        for pid, info in usage_tracker.process_usage.items():
            scores = usage_tracker.score_process(info["name"], info)
            features = [
                info["last_cpu"],
                info["last_mem"] / (1024 * 1024),
                info["last_io"] / (1024 * 1024),
                scores["activity"],
                scores["risk"],
            ]
            label = 0  # normal
            for t in threat_matrix:
                if t["pid"] == pid:
                    label = 1  # risky
                    break
            ai_predictor.add_sample(features, label)

    if ai_predictor.can_train() and not ai_predictor.trained:
        ai_predictor.train()

# ==========================
# BACKGROUND LOOPS
# ==========================
def usage_loop():
    while True:
        try:
            if not verify_config_integrity():
                log_info("[INTEGRITY] Config mismatch, protecting user settings.")
                protect_user_settings()
            usage_tracker.update()
            usage_tracker.auto_whitelist_update()
            usage_tracker.compute_system_mood()
            if CONFIG.get("auto_standby_enabled", True):
                auto_standby_tick()
            self_healing_tick()
        except Exception as e:
            log_info(f"[USAGE LOOP ERROR] {e}")
        time.sleep(CONFIG["scan_interval_sec"])

def schedule_loop():
    schedule.every().week.do(lambda: log_info("[SCHEDULE] Weekly baseline check complete."))
    while True:
        try:
            schedule.run_pending()
        except Exception as e:
            log_info(f"[SCHEDULE ERROR] {e}")
        time.sleep(1)

# ==========================
# SYSTEM TRAY
# ==========================
def create_tray_icon(on_show_callback, on_exit_callback):
    img = Image.new("RGB", (64, 64), color=(10, 10, 30))
    d = ImageDraw.Draw(img)
    d.ellipse([8, 8, 56, 56], outline=(0, 200, 255), width=3)
    d.line([16, 48, 32, 24, 48, 40], fill=(0, 200, 255), width=3)
    menu = pystray.Menu(
        pystray.MenuItem("Show", lambda icon, item: on_show_callback()),
        pystray.MenuItem("Exit", lambda icon, item: on_exit_callback())
    )
    icon = pystray.Icon("SystemGovernor", img, "System Governor", menu)
    return icon

# ==========================
# GUI
# ==========================
class GovernorWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("System Governor v2.0")
        self.resize(1200, 800)

        self.tabs = QtWidgets.QTabWidget()
        self.setCentralWidget(self.tabs)

        self.dashboard_tab = QtWidgets.QWidget()
        self.settings_tab = QtWidgets.QWidget()
        self.cleanup_tab = QtWidgets.QWidget()
        self.threat_tab = QtWidgets.QWidget()

        self.tabs.addTab(self.dashboard_tab, "Dashboard")
        self.tabs.addTab(self.settings_tab, "Settings")
        self.tabs.addTab(self.cleanup_tab, "Cleanup")
        self.tabs.addTab(self.threat_tab, "Threat Matrix")

        self._init_dashboard_tab()
        self._init_settings_tab()
        self._init_cleanup_tab()
        self._init_threat_tab()

        self.tray_icon = None

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.refresh_view)
        self.timer.start(3000)

        self.refresh_view()

    # ----- Dashboard -----
    def _init_dashboard_tab(self):
        layout = QtWidgets.QVBoxLayout(self.dashboard_tab)

        self.summary_label = QtWidgets.QLabel("System summary")
        layout.addWidget(self.summary_label)

        self.mood_label = QtWidgets.QLabel("System mood: Unknown")
        layout.addWidget(self.mood_label)

        self.top_programs_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Processes (states + scores):"))
        layout.addWidget(self.top_programs_list)

        self.anomaly_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Recent anomalies:"))
        layout.addWidget(self.anomaly_list)

        btn_layout = QtWidgets.QHBoxLayout()
        self.to_tray_btn = QtWidgets.QPushButton("Minimize to Tray")
        self.to_tray_btn.clicked.connect(self.minimize_to_tray)
        btn_layout.addWidget(self.to_tray_btn)

        self.apply_standby_btn = QtWidgets.QPushButton("Apply Standby to Selected PID")
        self.apply_standby_btn.clicked.connect(self.apply_standby_to_selected)
        btn_layout.addWidget(self.apply_standby_btn)

        layout.addLayout(btn_layout)

    # ----- Settings (Hybrid: Simple + Advanced) -----
    def _init_settings_tab(self):
        layout = QtWidgets.QVBoxLayout(self.settings_tab)

        # Simple section
        simple_group = QtWidgets.QGroupBox("Simple Settings")
        simple_layout = QtWidgets.QFormLayout(simple_group)

        self.scan_interval_spin = QtWidgets.QSpinBox()
        self.scan_interval_spin.setRange(1, 300)
        self.scan_interval_spin.setValue(CONFIG["scan_interval_sec"])
        simple_layout.addRow("Scan interval (sec):", self.scan_interval_spin)

        self.usage_window_spin = QtWidgets.QSpinBox()
        self.usage_window_spin.setRange(5, 1440)
        self.usage_window_spin.setValue(CONFIG["usage_window_minutes"])
        simple_layout.addRow("Usage window (minutes):", self.usage_window_spin)

        self.standby_threshold_spin = QtWidgets.QSpinBox()
        self.standby_threshold_spin.setRange(0, 100)
        self.standby_threshold_spin.setValue(CONFIG["standby_threshold_cpu"])
        simple_layout.addRow("Standby CPU threshold (%):", self.standby_threshold_spin)

        self.standby_idle_spin = QtWidgets.QSpinBox()
        self.standby_idle_spin.setRange(1, 240)
        self.standby_idle_spin.setValue(CONFIG["standby_idle_minutes"])
        simple_layout.addRow("Standby idle (minutes):", self.standby_idle_spin)

        self.auto_standby_check = QtWidgets.QCheckBox("Enable auto-standby")
        self.auto_standby_check.setChecked(CONFIG["auto_standby_enabled"])
        simple_layout.addRow(self.auto_standby_check)

        self.self_healing_check = QtWidgets.QCheckBox("Enable self-healing")
        self.self_healing_check.setChecked(CONFIG["self_healing_enabled"])
        simple_layout.addRow(self.self_healing_check)

        self.ai_prediction_check = QtWidgets.QCheckBox("Enable AI prediction")
        self.ai_prediction_check.setChecked(CONFIG["ai_prediction_enabled"])
        simple_layout.addRow(self.ai_prediction_check)

        layout.addWidget(simple_group)

        # Advanced section (collapsible)
        advanced_group = QtWidgets.QGroupBox("Advanced Settings")
        advanced_group.setCheckable(True)
        advanced_group.setChecked(False)
        advanced_layout = QtWidgets.QVBoxLayout(advanced_group)

        # Known settings
        known_group = QtWidgets.QGroupBox("Known (User) Settings")
        known_layout = QtWidgets.QFormLayout(known_group)
        self.known_settings_edits = {}
        for key, value in CONFIG.get("user_settings", {}).items():
            edit = QtWidgets.QLineEdit(str(value))
            known_layout.addRow(key + ":", edit)
            self.known_settings_edits[key] = edit
        advanced_layout.addWidget(known_group)

        # Unknown settings
        unknown_group = QtWidgets.QGroupBox("Unknown Settings")
        unknown_layout = QtWidgets.QFormLayout(unknown_group)
        self.unknown_settings_labels = {}
        for key, value in CONFIG.get("unknown_settings", {}).items():
            label = QtWidgets.QLabel(str(value))
            unknown_layout.addRow(key + ":", label)
            self.unknown_settings_labels[key] = label
        advanced_layout.addWidget(unknown_group)

        # New settings
        new_group = QtWidgets.QGroupBox("New Settings")
        new_layout = QtWidgets.QFormLayout(new_group)
        self.new_settings_edits = {}
        for key, value in CONFIG.get("new_settings", {}).items():
            edit = QtWidgets.QLineEdit(str(value))
            new_layout.addRow(key + ":", edit)
            self.new_settings_edits[key] = edit
        advanced_layout.addWidget(new_group)

        # Backup/restore
        backup_layout = QtWidgets.QHBoxLayout()
        self.backup_btn = QtWidgets.QPushButton("Export Settings Backup")
        self.backup_btn.clicked.connect(self.export_settings_backup)
        backup_layout.addWidget(self.backup_btn)

        self.restore_btn = QtWidgets.QPushButton("Restore Settings from Backup")
        self.restore_btn.clicked.connect(self.restore_settings_backup)
        backup_layout.addWidget(self.restore_btn)

        advanced_layout.addLayout(backup_layout)

        layout.addWidget(advanced_group)

        # Apply button
        apply_layout = QtWidgets.QHBoxLayout()
        self.apply_settings_btn = QtWidgets.QPushButton("Apply Settings")
        self.apply_settings_btn.clicked.connect(self.apply_settings_changes)
        apply_layout.addWidget(self.apply_settings_btn)
        layout.addLayout(apply_layout)

    # ----- Cleanup Tab -----
    def _init_cleanup_tab(self):
        layout = QtWidgets.QVBoxLayout(self.cleanup_tab)

        self.cleanup_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Cleanup Suggestions (bloat candidates):"))
        layout.addWidget(self.cleanup_list)

        btn_layout = QtWidgets.QHBoxLayout()
        self.refresh_cleanup_btn = QtWidgets.QPushButton("Refresh Cleanup Suggestions")
        self.refresh_cleanup_btn.clicked.connect(self.refresh_cleanup_suggestions)
        btn_layout.addWidget(self.refresh_cleanup_btn)

        self.mark_ignore_btn = QtWidgets.QPushButton("Mark Selected as Ignore")
        self.mark_ignore_btn.clicked.connect(self.mark_selected_cleanup_ignore)
        btn_layout.addWidget(self.mark_ignore_btn)

        self.mark_parasitic_btn = QtWidgets.QPushButton("Mark Selected as Parasitic")
        self.mark_parasitic_btn.clicked.connect(self.mark_selected_cleanup_parasitic)
        btn_layout.addWidget(self.mark_parasitic_btn)

        layout.addLayout(btn_layout)

    # ----- Threat Matrix Tab -----
    def _init_threat_tab(self):
        layout = QtWidgets.QVBoxLayout(self.threat_tab)

        self.threat_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Threat Matrix (process vs threat dimensions):"))
        layout.addWidget(self.threat_list)

        self.refresh_threat_btn = QtWidgets.QPushButton("Refresh Threat Matrix")
        self.refresh_threat_btn.clicked.connect(self.refresh_threat_matrix)
        layout.addWidget(self.refresh_threat_btn)

    # ----- Dashboard actions -----
    def minimize_to_tray(self):
        self.hide()
        if self.tray_icon is None:
            def on_show():
                self.show()
            def on_exit():
                QtWidgets.QApplication.quit()
            self.tray_icon = create_tray_icon(on_show, on_exit)
            threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def apply_standby_to_selected(self):
        item = self.top_programs_list.currentItem()
        if not item:
            QtWidgets.QMessageBox.warning(self, "Standby", "No process selected.")
            return
        text = item.text()
        try:
            pid_str = text.split()[0]
            pid = int(pid_str)
        except Exception:
            QtWidgets.QMessageBox.warning(self, "Standby", "Could not parse PID from selection.")
            return
        with usage_tracker.lock:
            info = usage_tracker.process_usage.get(pid)
        if not info:
            QtWidgets.QMessageBox.warning(self, "Standby", "Process no longer tracked.")
            return
        name = info["name"]
        lower_priority(pid, name)
        reduce_affinity(pid, name)
        suspend_process(pid, name)
        QtWidgets.QMessageBox.information(self, "Standby", f"Standby applied to {name} (PID {pid}).")

    # ----- Settings actions -----
    def apply_settings_changes(self):
        CONFIG["scan_interval_sec"] = self.scan_interval_spin.value()
        CONFIG["usage_window_minutes"] = self.usage_window_spin.value()
        CONFIG["standby_threshold_cpu"] = self.standby_threshold_spin.value()
        CONFIG["standby_idle_minutes"] = self.standby_idle_spin.value()
        CONFIG["auto_standby_enabled"] = self.auto_standby_check.isChecked()
        CONFIG["self_healing_enabled"] = self.self_healing_check.isChecked()
        CONFIG["ai_prediction_enabled"] = self.ai_prediction_check.isChecked()

        for key, edit in self.known_settings_edits.items():
            CONFIG["user_settings"][key] = edit.text()
            SETTINGS_DB["known"][key] = edit.text()

        for key, edit in self.new_settings_edits.items():
            CONFIG["new_settings"][key] = edit.text()
            SETTINGS_DB["new"][key] = edit.text()

        save_settings_db(SETTINGS_DB)
        save_config(CONFIG)
        QtWidgets.QMessageBox.information(self, "Settings", "Settings applied and saved.")

    def export_settings_backup(self):
        _backup_config(CONFIG)
        QtWidgets.QMessageBox.information(self, "Backup", "Settings backup exported.")

    def restore_settings_backup(self):
        cfg = _restore_config_from_backup()
        if not cfg:
            QtWidgets.QMessageBox.warning(self, "Restore", "No backup available.")
            return
        global CONFIG
        CONFIG = cfg
        self.scan_interval_spin.setValue(CONFIG["scan_interval_sec"])
        self.usage_window_spin.setValue(CONFIG["usage_window_minutes"])
        self.standby_threshold_spin.setValue(CONFIG["standby_threshold_cpu"])
        self.standby_idle_spin.setValue(CONFIG["standby_idle_minutes"])
        self.auto_standby_check.setChecked(CONFIG["auto_standby_enabled"])
        self.self_healing_check.setChecked(CONFIG["self_healing_enabled"])
        self.ai_prediction_check.setChecked(CONFIG["ai_prediction_enabled"])
        QtWidgets.QMessageBox.information(self, "Restore", "Settings restored from backup.")

    # ----- Cleanup actions -----
    def refresh_cleanup_suggestions(self):
        self.cleanup_list.clear()
        suggestions = get_cleanup_suggestions()
        for s in suggestions:
            self.cleanup_list.addItem(
                f"{s['name']} — Days: {s['days_installed']:.1f}, Active: {s['total_active_sec']:.0f}s"
            )

    def mark_selected_cleanup_ignore(self):
        item = self.cleanup_list.currentItem()
        if not item:
            QtWidgets.QMessageBox.warning(self, "Cleanup", "No suggestion selected.")
            return
        name = item.text().split(" — ")[0]
        CONFIG["user_settings"][f"cleanup_ignore_{name}"] = True
        register_setting(f"cleanup_ignore_{name}", True, category="known")
        QtWidgets.QMessageBox.information(self, "Cleanup", f"{name} marked as ignore.")

    def mark_selected_cleanup_parasitic(self):
        item = self.cleanup_list.currentItem()
        if not item:
            QtWidgets.QMessageBox.warning(self, "Cleanup", "No suggestion selected.")
            return
        name = item.text().split(" — ")[0]
        CONFIG["user_settings"][f"cleanup_parasitic_{name}"] = True
        register_setting(f"cleanup_parasitic_{name}", True, category="known")
        QtWidgets.QMessageBox.information(self, "Cleanup", f"{name} marked as parasitic.")

    # ----- Threat Matrix actions -----
    def refresh_threat_matrix(self):
        self.threat_list.clear()
        with usage_tracker.lock:
            for pid, info in usage_tracker.process_usage.items():
                scores = usage_tracker.score_process(info["name"], info)
                features = [
                    info["last_cpu"],
                    info["last_mem"] / (1024 * 1024),
                    info["last_io"] / (1024 * 1024),
                    scores["activity"],
                    scores["risk"],
                ]
                ai_risk = ai_predictor.predict_risk(features) if CONFIG.get("ai_prediction_enabled", True) else 0.0
                severity_label, severity_score = compute_anomaly_severity("none", scores, ai_risk)
                infection_flag = detect_infection_pattern(info, scores, ai_risk)
                state = usage_tracker.classify_process_state(info)
                self.threat_list.addItem(
                    f"{pid} {info['name']} — State:{state} Sev:{severity_label} "
                    f"Risk:{scores['risk']:.1f} AI:{ai_risk:.1f} Infect:{infection_flag}"
                )

    # ----- Refresh view -----
    def refresh_view(self):
        flow = usage_tracker.compute_flow_metrics()
        obs_active = usage_tracker.observation_phase_active()
        days_elapsed = (time.time() - usage_tracker.start_time) / 86400.0
        obs_days = CONFIG.get("observation_days", 14)
        summary_lines = [
            f"Observation phase active: {obs_active} (day {days_elapsed:.1f}/{obs_days})",
            f"CPU flow: {flow['cpu_flow']:.1f}%",
            f"RAM pressure: {flow['ram_pressure']:.1f}%",
            f"Disk turbulence: {flow['disk_turbulence']:.1f}%",
        ]
        self.summary_label.setText("System summary:\n" + "\n".join(summary_lines))

        self.mood_label.setText(f"System mood: {usage_tracker.system_mood}")

        self.top_programs_list.clear()
        anomalies = usage_tracker.detect_anomalies()
        self.anomaly_list.clear()
        for pid, name, reason in anomalies:
            self.anomaly_list.addItem(f"{pid} {name} — {reason}")

        with usage_tracker.lock:
            for pid, info in usage_tracker.process_usage.items():
                state = usage_tracker.classify_process_state(info)
                scores = usage_tracker.score_process(info["name"], info)
                self.top_programs_list.addItem(
                    f"{pid} {info['name']} — State: {state}, "
                    f"S:{scores['stability']:.1f} A:{scores['activity']:.1f} "
                    f"B:{scores['bloat']:.1f} R:{scores['risk']:.1f} "
                    f"Res:{scores['resource']:.1f}"
                )

# ==========================
# MAIN
# ==========================
def main():
    start_watchdog()

    t_usage = threading.Thread(target=usage_loop, daemon=True)
    t_usage.start()

    t_sched = threading.Thread(target=schedule_loop, daemon=True)
    t_sched.start()

    app = QtWidgets.QApplication(sys.argv)
    win = GovernorWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
