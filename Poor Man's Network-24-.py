#!/usr/bin/env python3
# Poor Man's Network + DominionDeck Command Center v6.0
# Strong YouTube + Whole-Web Ad Detection + Predictive Mouse + Cluster Monitor + Ad-Skip Pattern + Oscilloscope
# - Strong YouTube detection: network + PID + window title
# - Whole-web ad heuristics: all ports, all connections, EasyList-derived host hints
# - Desktop cursor telemetry + circular gesture "ad signal"
# - YouTube PID/port detection (HTTPS streams from browser)
# - Webcam yellow-bar + mouse-vision (optional)
# - Oscilloscope-style activity waveform:
#     Video = BLUE, Ad (YT or web) = RED, smooth scrolling
# - GUI banner: "Trying to pinpoint ad location" above oscilloscope
#   (always when any ad signal is active; color changes on gesture/ad)
# - Predictive reasoning:
#   * Tracks domains and ad hits over time
#   * Builds heuristic confidence per domain and per user behavior pattern
#   * Uses mouse patterns + network + rules to estimate ad likelihood

import importlib
import importlib.util
import subprocess
import sys
import os
import socket
import threading
import json
import time
import queue
import base64
import hashlib
import random
import math
from collections import deque

# -----------------------------
# AUTOLOADER
# -----------------------------
REQUIRED_LIBS = [
    ("tkinter", "tkinter", False), ("psutil", "psutil", True),
    ("GPUtil", "GPUtil", True), ("cryptography", "cryptography", True),
    ("requests", "requests", True), ("pynput", "pynput", True),
    ("cv2", "opencv-python", True), ("numpy", "numpy", True),
    ("PIL", "Pillow", True),
]

def autoload():
    for module_name, package_name, installable in REQUIRED_LIBS:
        try:
            importlib.import_module(module_name)
        except ImportError:
            if not installable:
                print(f"[AUTOLOADER] {module_name} unavailable; continuing without auto-install.")
                continue
            print(f"[AUTOLOADER] Missing {module_name}; installing {package_name}...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", package_name])
                importlib.invalidate_caches()
                importlib.import_module(module_name)
            except Exception as e:
                print(f"[AUTOLOADER] Failed to install {package_name}: {e}")

autoload()

import tkinter as tk
from tkinter import ttk
import psutil
import GPUtil
import requests
from cryptography.fernet import Fernet
from pynput import mouse
import cv2
import numpy as np
from PIL import Image, ImageTk

# -----------------------------
# CONFIG + PROFILES
# -----------------------------
DEFAULT_CONFIG = {
    "cluster_id": "PMN-CLUSTER-001",
    "node_port": 50900,
    "broadcast_port": 50901,
    "broadcast_interval": 3,
    "plugin_dir": "plugins",
    "node_roles": ["GAMING", "STORAGE", "UTILITY", "MONITOR"],
    "shared_passphrase": "poor-man-network-secret",
    "ad_rule_urls": [
        "https://easylist.to/easylist/easylist.txt",
        "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
    ],
    "cpu_cap_soft": 70.0,
    "cpu_cap_strict": 85.0,
    "telemetry_interval": 5,
    "ad_rules_sync_interval": 300,
    "yt_detection_interval": 1.0,
    "yt_behavior_interval": 0.25,  # faster for smoother oscilloscope
    "web_ad_detection_interval": 1.0,  # whole-web ad scan interval
    "storage_index_max_files": 3000,
    "storage_index_on_start": True,
    "log_buffer_max": 2000,
    "yt_events_max": 500,
    "ad_intel_max": 500,
    "task_result_preview_len": 512,
    # Webcam vision config
    "webcam_enabled_default": False,
    "webcam_index": 0,
    "webcam_frame_interval": 0.5,
    "webcam_downscale": 0.5,
    # Visual mouse tracking config
    "mouse_tracking_enabled_default": True,
    "mouse_cursor_color_hint": [255, 255, 255],
    "mouse_cursor_search_band_height_ratio": 1.0,
    "mouse_cursor_min_area": 5,
    "mouse_prediction_horizon_ms": 120,
    "mouse_smoothing": 0.35,
    "mouse_history_size": 60,
    # Ad-skip pattern config
    "ad_skip_pattern_min_clicks": 5,
    "ad_skip_pattern_time_window": 2.0,
    "ad_skip_pattern_max_radius_px": 40.0,
}

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "pmn_config.json")

def load_config():
    cfg = DEFAULT_CONFIG.copy()
    if os.path.isfile(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            cfg.update(user_cfg or {})
            print(f"[CONFIG] Loaded pmn_config.json with overrides")
        except Exception as e:
            print(f"[CONFIG] Failed to load pmn_config.json: {e}")
    for arg in sys.argv[1:]:
        if "=" in arg and arg.startswith("--"):
            key, val = arg[2:].split("=", 1)
            if key in cfg:
                try:
                    if isinstance(cfg[key], (int, float)):
                        cfg[key] = float(val)
                    elif isinstance(cfg[key], list):
                        cfg[key] = json.loads(val)
                    else:
                        cfg[key] = val
                    print(f"[CONFIG] Override {key}={cfg[key]}")
                except Exception:
                    print(f"[CONFIG] Failed to parse override {arg}")
    return cfg

CFG = load_config()

CLUSTER_ID = CFG["cluster_id"]
NODE_PORT = CFG["node_port"]
BROADCAST_PORT = CFG["broadcast_port"]
BROADCAST_INTERVAL = CFG["broadcast_interval"]

PLUGIN_DIR = os.path.join(os.path.dirname(__file__), CFG["plugin_dir"])
NODE_ROLES = CFG["node_roles"]

SHARED_PASSPHRASE = CFG["shared_passphrase"]
AD_RULE_URLS = CFG["ad_rule_urls"]

CPU_CAP_SOFT = CFG["cpu_cap_soft"]
CPU_CAP_STRICT = CFG["cpu_cap_strict"]

TELEMETRY_INTERVAL = CFG["telemetry_interval"]
AD_RULES_SYNC_INTERVAL = CFG["ad_rules_sync_interval"]
YT_DETECTION_INTERVAL = CFG["yt_detection_interval"]
YT_BEHAVIOR_INTERVAL = CFG["yt_behavior_interval"]
WEB_AD_DETECTION_INTERVAL = CFG["web_ad_detection_interval"]
STORAGE_INDEX_MAX_FILES = CFG["storage_index_max_files"]
STORAGE_INDEX_ON_START = CFG["storage_index_on_start"]
LOG_BUFFER_MAX = CFG["log_buffer_max"]
YT_EVENTS_MAX = CFG["yt_events_max"]
AD_INTEL_MAX = CFG["ad_intel_max"]
TASK_RESULT_PREVIEW_LEN = CFG["task_result_preview_len"]

WEBCAM_ENABLED_DEFAULT = CFG["webcam_enabled_default"]
WEBCAM_INDEX = int(CFG["webcam_index"])
WEBCAM_FRAME_INTERVAL = CFG["webcam_frame_interval"]
WEBCAM_DOWNSCALE = CFG["webcam_downscale"]

MOUSE_TRACKING_ENABLED_DEFAULT = CFG["mouse_tracking_enabled_default"]
MOUSE_CURSOR_COLOR_HINT = CFG["mouse_cursor_color_hint"]
MOUSE_CURSOR_SEARCH_BAND_HEIGHT_RATIO = CFG["mouse_cursor_search_band_height_ratio"]
MOUSE_CURSOR_MIN_AREA = int(CFG["mouse_cursor_min_area"])

AD_SKIP_PATTERN_MIN_CLICKS = int(CFG.get("ad_skip_pattern_min_clicks", 5))
AD_SKIP_PATTERN_TIME_WINDOW = float(CFG.get("ad_skip_pattern_time_window", 2.0))
AD_SKIP_PATTERN_MAX_RADIUS_PX = float(CFG.get("ad_skip_pattern_max_radius_px", 40.0))

def make_fernet_key(passphrase: str) -> bytes:
    h = hashlib.sha256(passphrase.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(h)

FERNET = Fernet(make_fernet_key(SHARED_PASSPHRASE))

# -----------------------------
# GLOBAL STATE
# -----------------------------
node_name = socket.gethostname()
node_role = "UTILITY"
node_id = f"{node_name}-{int(time.time())}"

known_nodes = {}
telemetry_data = {}
ad_intel = []
ad_rules = set()
ad_rules_sources = {}
ad_host_hints = set()  # derived host/domain hints from EasyList-style rules
storage_index_local = {}
plugins = {}
logs = queue.Queue()

task_queue_local = queue.Queue()
tasks_cluster = {}
task_counter = 0
task_lock = threading.Lock()

# YouTube-specific state
yt_state = {
    "active": False,
    "last_scan_ts": 0.0,
    "current_proc": None,
    "current_title": "",
    "active_window_title": "",
    "active_window_pid": None,
    "detection_reason": "Starting",
    "last_event_ts": 0.0,
    "ad_skip_clicks": 0,
    "ad_suspected_events": 0,
    "cluster_yt_events": [],
    "port_streams": [],
    "ad_skip_confidence": 0.0,
    "ad_skip_patterns": deque(maxlen=50),
    "circle_last_ts": 0.0,
    "gesture_active": False,
}

# Whole-web ad state (non-YouTube specific)
web_ad_state = {
    "active": False,
    "last_scan_ts": 0.0,
    "connections": [],
    "ad_connections": [],
    "domain_stats": {},  # domain -> {"hits": int, "ad_hits": int, "score": float}
    "prediction_score": 0.0,
    "last_event_ts": 0.0,
}

webcam_state = {
    "enabled": WEBCAM_ENABLED_DEFAULT,
    "available": False,
    "last_frame_ts": 0.0,
    "last_ad_active": False,
    "last_confidence": 0.0,
    "last_note": "",
    "last_frame": None,
}

mouse_vision_state = {
    "enabled": MOUSE_TRACKING_ENABLED_DEFAULT,
    "last_cursor_pos": None,
    "last_cursor_confidence": 0.0,
    "last_cursor_note": "",
}

mouse_tracking_state = {
    "enabled": True, "x": None, "y": None, "predicted_x": None, "predicted_y": None,
    "vx": 0.0, "vy": 0.0, "speed": 0.0, "last_move_ts": 0.0,
    "last_click_ts": 0.0, "last_button": "", "click_count": 0,
    "dwell_seconds": 0.0, "direction": "stationary", "confidence": 0.0,
    "events": deque(maxlen=200),
}
mouse_history = deque(maxlen=max(5, int(CFG.get("mouse_history_size", 60))))
mouse_tracking_lock = threading.Lock()

ad_skip_click_buffer = deque(maxlen=200)
ad_skip_lock = threading.Lock()

# Oscilloscope buffer: activity waveform
# 0 = no activity, 1 = video-like, 2 = ad/gesture/web-ad
osc_state = {
    "buffer": deque(maxlen=400),
}

# -----------------------------
# LOGGING
# -----------------------------
LOG_LEVELS = ("INFO", "WARN", "ERROR", "DEBUG")
current_log_level = "INFO"

def log(msg, level="INFO"):
    global current_log_level
    if level not in LOG_LEVELS:
        level = "INFO"
    if level == "DEBUG" and current_log_level != "DEBUG":
        return
    ts = time.strftime("%H:%M:%S")
    line = f"[{ts}] [{level}] {msg}"
    print(line)
    logs.put(line)
    try:
        while logs.qsize() > LOG_BUFFER_MAX:
            logs.get_nowait()
    except Exception:
        pass

def set_log_level(level: str):
    global current_log_level
    if level in LOG_LEVELS:
        current_log_level = level
        log(f"Log level set to {level}", "INFO")

# -----------------------------
# NETWORK HELPERS
# -----------------------------
def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        return socket.gethostbyname(socket.gethostname())

LOCAL_IP = get_local_ip()

# -----------------------------
# ROLE AUTO-DETECTION
# -----------------------------
def auto_detect_role():
    try:
        gpus = GPUtil.getGPUs()
        if gpus:
            return "GAMING"
    except Exception:
        pass
    try:
        disk = psutil.disk_usage(os.path.expanduser("~"))
        if disk.total > 200 * 1024**3:
            return "STORAGE"
    except Exception:
        pass
    return random.choice(["UTILITY", "MONITOR"])

node_role = auto_detect_role()

# -----------------------------
# PLUGIN SYSTEM
# -----------------------------
def load_plugins():
    global plugins
    plugins.clear()
    if not os.path.isdir(PLUGIN_DIR):
        os.makedirs(PLUGIN_DIR, exist_ok=True)
        return
    for fname in os.listdir(PLUGIN_DIR):
        if not fname.endswith(".py"):
            continue
        path = os.path.join(PLUGIN_DIR, fname)
        mod_name = f"plugin_{fname[:-3]}"
        spec = importlib.util.spec_from_file_location(mod_name, path)
        if spec and spec.loader:
            try:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                plugins[fname[:-3]] = mod
                log(f"[PLUGIN] Loaded {fname}")
            except Exception as e:
                log(f"[PLUGIN] Failed to load {fname}: {e}", "WARN")

def execute_plugin(plugin_name, payload):
    mod = plugins.get(plugin_name)
    if not mod:
        log(f"[PLUGIN] Not found: {plugin_name}", "WARN")
        return {"status": "error", "reason": "plugin_not_found"}
    try:
        if hasattr(mod, "run"):
            return mod.run({
                "node_name": node_name,
                "node_id": node_id,
                "role": node_role,
                "payload": payload
            })
        else:
            log(f"[PLUGIN] {plugin_name} has no run()", "WARN")
            return {"status": "error", "reason": "no_run"}
    except Exception as e:
        log(f"[PLUGIN] Error in {plugin_name}: {e}", "ERROR")
        return {"status": "error", "reason": str(e)}

# -----------------------------
# TELEMETRY
# -----------------------------
def collect_gpu_telemetry():
    try:
        gpus = GPUtil.getGPUs()
        if not gpus:
            return None
        gpu = gpus[0]
        return {
            "name": gpu.name,
            "load": gpu.load * 100.0,
            "mem_used": gpu.memoryUsed,
            "mem_total": gpu.memoryTotal,
            "temp": gpu.temperature
        }
    except Exception:
        return None

def collect_disk_summary():
    try:
        home = os.path.expanduser("~")
        usage = psutil.disk_usage(home)
        return {
            "path": home,
            "total": usage.total,
            "used": usage.used,
            "percent": usage.percent,
        }
    except Exception:
        return None

def collect_net_summary():
    try:
        io = psutil.net_io_counters()
        return {
            "bytes_sent": io.bytes_sent,
            "bytes_recv": io.bytes_recv,
            "packets_sent": io.packets_sent,
            "packets_recv": io.packets_recv,
        }
    except Exception:
        return None

def collect_telemetry():
    cpu = psutil.cpu_percent(interval=0.2)
    ram = psutil.virtual_memory().percent
    temp = None
    try:
        sensors = psutil.sensors_temperatures()
        if sensors:
            for name, entries in sensors.items():
                if entries:
                    temp = entries[0].current
                    break
    except Exception:
        temp = None
    vram = None
    gpu = collect_gpu_telemetry()
    disk = collect_disk_summary()
    net = collect_net_summary()
    t = {
        "cpu": cpu,
        "ram": ram,
        "vram": vram,
        "temp": temp,
        "gpu": gpu,
        "disk": disk,
        "net": net,
        "ts": time.time()
    }
    telemetry_data[node_name] = t
    return t

def get_node_cpu(host):
    data = telemetry_data.get(host)
    if not data:
        return None
    return data.get("cpu")

def node_health_score(host, info):
    cpu = get_node_cpu(host)
    ram = telemetry_data.get(host, {}).get("ram")
    now = time.time()
    age = now - info.get("last_seen", now)
    if cpu is None:
        cpu = 100.0
    if ram is None:
        ram = 100.0
    score = cpu * 0.6 + ram * 0.3 + age * 0.1
    return score

# -----------------------------
# STORAGE INDEXING
# -----------------------------
def build_storage_index(max_files=STORAGE_INDEX_MAX_FILES):
    home = os.path.expanduser("~")
    index = []
    for root, dirs, files in os.walk(home):
        for f in files:
            full = os.path.join(root, f)
            try:
                size = os.path.getsize(full)
            except Exception:
                size = None
            index.append({"path": full, "size": size})
        if len(index) > max_files:
            break
    return index

def refresh_storage_index():
    global storage_index_local
    storage_index_local = {
        "node": node_name,
        "ts": time.time(),
        "files": build_storage_index()
    }
    log(f"[STORAGE] Indexed {len(storage_index_local['files'])} files locally")

# -----------------------------
# AD RULES + HOST HINTS
# -----------------------------
def _extract_host_hint_from_rule(line: str):
    """
    Very lightweight reverse-engineering of EasyList-style rules:
    - Lines like '||example.com^' -> 'example.com'
    - Lines containing known ad keywords are kept as-is for substring matching.
    """
    line = line.strip()
    if not line or line.startswith("!"):
        return None
    host = None
    if line.startswith("||"):
        # Typical EasyList host rule: ||domain.tld^
        body = line[2:]
        # Cut at ^ or /
        for sep in ("^", "/", "$"):
            if sep in body:
                body = body.split(sep, 1)[0]
        if body and "." in body:
            host = body.lower()
    else:
        # Fallback: keep rules that look like host fragments
        if "." in line and not line.startswith("@@"):
            host = line.lower()
    return host

def fetch_ad_rules_from_internet():
    global ad_rules, ad_rules_sources, ad_host_hints
    new_rules = set()
    new_hosts = set()
    for url in AD_RULE_URLS:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                count_before = len(new_rules)
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("!"):
                        continue
                    new_rules.add(line)
                    host_hint = _extract_host_hint_from_rule(line)
                    if host_hint:
                        new_hosts.add(host_hint)
                added = len(new_rules) - count_before
                ad_rules_sources[url] = ad_rules_sources.get(url, 0) + added
                log(f"[AD] Fetched {added} rules from {url} ({len(new_rules)} total)")
        except Exception as e:
            log(f"[AD] Failed to fetch {url}: {e}", "WARN")
    if new_rules:
        before = len(ad_rules)
        ad_rules |= new_rules
        after = len(ad_rules)
        log(f"[AD] Total rules in memory: {after} (+{after - before})")
    if new_hosts:
        before_h = len(ad_host_hints)
        ad_host_hints |= new_hosts
        after_h = len(ad_host_hints)
        log(f"[AD] Host hints derived: {after_h} (+{after_h - before_h})")

def ad_rules_sync_loop():
    while True:
        if node_role in ("UTILITY", "STORAGE", "MONITOR"):
            fetch_ad_rules_from_internet()
        share_ad_rules_with_cluster()
        time.sleep(AD_RULES_SYNC_INTERVAL)

def share_ad_rules_with_cluster():
    sample = list(ad_rules)[:500]
    payload = {
        "type": "ad_rules_sync",
        "rules": sample,
        "node": node_name,
        "ts": time.time()
    }
    for host, info in list(known_nodes.items()):
        ip = info["ip"]
        send_request(ip, payload)

def merge_ad_rules_from_node(rules):
    global ad_rules, ad_host_hints
    before = len(ad_rules)
    new_hosts = set()
    for r in rules:
        ad_rules.add(r)
        host_hint = _extract_host_hint_from_rule(r)
        if host_hint:
            new_hosts.add(host_hint)
    after = len(ad_rules)
    if after > before:
        log(f"[AD] Merged {after - before} new rules from cluster")
    if new_hosts:
        before_h = len(ad_host_hints)
        ad_host_hints |= new_hosts
        after_h = len(ad_host_hints)
        log(f"[AD] Merged {after_h - before_h} new host hints from cluster")

# -----------------------------
# TASK SCHEDULER
# -----------------------------
def create_task(payload, preferred_role=None, plugin=None, auto=True, description=None):
    global task_counter
    with task_lock:
        task_counter += 1
        task_id = f"task-{node_name}-{task_counter}"
    task_info = {
        "id": task_id,
        "creator": node_name,
        "preferred_role": preferred_role,
        "plugin": plugin,
        "payload": payload,
        "status": "pending",
        "result": None,
        "ts": time.time(),
        "auto": auto,
        "description": description or "",
    }
    tasks_cluster[task_id] = task_info
    log(f"[TASK] Created {task_id} (role={preferred_role}, plugin={plugin})")
    dispatch_task(task_info)
    return task_id

def choose_best_node(preferred_role=None):
    candidates = []
    local_info = {
        "ip": LOCAL_IP,
        "last_seen": time.time(),
        "role": node_role,
        "node_id": node_id
    }
    known_all = {node_name: local_info}
    known_all.update(known_nodes)
    for host, info in known_all.items():
        if preferred_role and info.get("role") != preferred_role:
            continue
        cpu = get_node_cpu(host)
        if cpu is None:
            cpu = 100.0
        if cpu > CPU_CAP_SOFT:
            continue
        score = node_health_score(host, info)
        candidates.append((score, host, info))
    if not candidates:
        return None, None
    candidates.sort(key=lambda x: x[0])
    _, host, info = candidates[0]
    return host, info

def dispatch_task(task_info):
    preferred_role = task_info.get("preferred_role")
    host, info = choose_best_node(preferred_role=preferred_role)
    if host is None:
        log(f"[TASK] No node under soft CPU cap {CPU_CAP_SOFT}% for {task_info['id']}, keeping pending", "WARN")
        return
    ip = info["ip"]
    if host == node_name:
        log(f"[TASK] Dispatching {task_info['id']} locally (CPU-aware)")
        task_queue_local.put(task_info)
        tasks_cluster[task_info["id"]]["status"] = "running"
    else:
        log(f"[TASK] Dispatching {task_info['id']} to {host} ({ip})")
        payload = {"type": "task_exec_request", "task": task_info}
        resp = send_request(ip, payload)
        if resp and resp.get("type") == "task_exec_response":
            if resp.get("accepted"):
                log(f"[TASK] Node {host} accepted {task_info['id']}")
                tasks_cluster[task_info["id"]]["status"] = "running"
            else:
                log(f"[TASK] Node {host} rejected {task_info['id']}", "WARN")
        else:
            log(f"[TASK] No valid response from {host} for {task_info['id']}", "WARN")

def execute_task_local(task_info):
    plugin = task_info.get("plugin")
    payload = task_info.get("payload")
    if plugin:
        result = execute_plugin(plugin, payload)
    else:
        result = {
            "status": "ok",
            "node": node_name,
            "payload": payload,
            "telemetry": collect_telemetry()
        }
    task_info["status"] = "done"
    task_info["result"] = result
    tasks_cluster[task_info["id"]] = task_info
    log(f"[TASK] Executed locally {task_info['id']}")

def task_execution_loop():
    while True:
        task_info = task_queue_local.get()
        if not task_info:
            continue
        t = collect_telemetry()
        if t["cpu"] > CPU_CAP_STRICT:
            log(f"[TASK] Local CPU {t['cpu']:.1f}% > strict cap {CPU_CAP_STRICT}%, delaying {task_info['id']}", "WARN")
            time.sleep(1.0)
            task_queue_local.put(task_info)
            continue
        execute_task_local(task_info)

# -----------------------------
# UDP BROADCAST
# -----------------------------
def broadcast_presence():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        msg = {
            "type": "presence",
            "cluster_id": CLUSTER_ID,
            "hostname": node_name,
            "node_id": node_id,
            "ip": LOCAL_IP,
            "role": node_role,
            "ts": time.time()
        }
        data = json.dumps(msg).encode("utf-8")
        try:
            sock.sendto(data, ("<broadcast>", BROADCAST_PORT))
        except Exception as e:
            log(f"[NET] Broadcast error: {e}", "WARN")
        time.sleep(BROADCAST_INTERVAL)

def broadcast_ad_intel(ad_text):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    msg = {
        "type": "ad_intel",
        "cluster_id": CLUSTER_ID,
        "hostname": node_name,
        "node_id": node_id,
        "ip": LOCAL_IP,
        "ad": ad_text,
        "ts": time.time()
    }
    data = json.dumps(msg).encode("utf-8")
    try:
        sock.sendto(data, ("<broadcast>", BROADCAST_PORT))
    except Exception as e:
        log(f"[NET] Ad broadcast error: {e}", "WARN")

def broadcast_yt_event(event_type, meta=None):
    msg = {
        "type": "yt_ad_event",
        "cluster_id": CLUSTER_ID,
        "hostname": node_name,
        "node_id": node_id,
        "ip": LOCAL_IP,
        "event_type": event_type,
        "meta": meta or {},
        "ts": time.time()
    }
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            sock.sendto(json.dumps(msg).encode("utf-8"), ("<broadcast>", BROADCAST_PORT))
    except Exception as e:
        log(f"[NET] YT event broadcast error: {e}", "WARN")

def record_yt_event(event_type, meta=None, broadcast=True):
    event = {
        "type": "yt_ad_event",
        "cluster_id": CLUSTER_ID,
        "hostname": node_name,
        "node_id": node_id,
        "ip": LOCAL_IP,
        "event_type": event_type,
        "meta": meta or {},
        "ts": time.time(),
        "local": True
    }
    yt_state["cluster_yt_events"].append(event)
    if len(yt_state["cluster_yt_events"]) > YT_EVENTS_MAX:
        yt_state["cluster_yt_events"] = yt_state["cluster_yt_events"][-YT_EVENTS_MAX:]
    yt_state["last_event_ts"] = event["ts"]
    log(f"[YT-EVENT] {event_type}: {meta or {}}", "DEBUG")
    if broadcast:
        broadcast_yt_event(event_type, meta)

def listen_for_broadcasts():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("", BROADCAST_PORT))
    while True:
        data, addr = sock.recvfrom(8192)
        try:
            msg = json.loads(data.decode("utf-8"))
        except Exception:
            continue
        if msg.get("cluster_id") != CLUSTER_ID:
            continue
        mtype = msg.get("type")
        if mtype == "presence":
            host = msg["hostname"]
            known_nodes[host] = {
                "ip": msg["ip"],
                "last_seen": msg["ts"],
                "role": msg.get("role"),
                "node_id": msg.get("node_id")
            }
        elif mtype == "ad_intel":
            ad_intel.append(msg)
            if len(ad_intel) > AD_INTEL_MAX:
                ad_intel.pop(0)
        elif mtype == "yt_ad_event":
            if msg.get("hostname") != node_name:
                yt_state["cluster_yt_events"].append(msg)
                if len(yt_state["cluster_yt_events"]) > YT_EVENTS_MAX:
                    yt_state["cluster_yt_events"] = yt_state["cluster_yt_events"][-YT_EVENTS_MAX:]

# -----------------------------
# TCP SERVER / CLIENT
# -----------------------------
def recv_json_encrypted(conn):
    buf = b""
    while True:
        chunk = conn.recv(4096)
        if not chunk:
            break
        buf += chunk
        try:
            decrypted = FERNET.decrypt(buf)
            return json.loads(decrypted.decode("utf-8"))
        except Exception:
            continue
    return None

def send_json_encrypted(conn, obj):
    data = json.dumps(obj).encode("utf-8")
    encrypted = FERNET.encrypt(data)
    conn.sendall(encrypted)

def handle_client(conn, addr):
    msg = recv_json_encrypted(conn)
    if not msg:
        conn.close()
        return
    msg_type = msg.get("type")

    if msg_type == "telemetry_request":
        t = collect_telemetry()
        send_json_encrypted(conn, {"type": "telemetry_response", "node": node_name, "data": t})

    elif msg_type == "storage_index_request":
        send_json_encrypted(conn, {"type": "storage_index_response", "node": node_name, "index": storage_index_local})

    elif msg_type == "storage_get_request":
        path = msg.get("path")
        try:
            with open(path, "rb") as f:
                content = f.read()
            send_json_encrypted(conn, {
                "type": "storage_get_response",
                "status": "ok",
                "path": path,
                "data": content.decode("latin1")
            })
        except Exception as e:
            send_json_encrypted(conn, {
                "type": "storage_get_response",
                "status": "error",
                "reason": str(e)
            })

    elif msg_type == "plugin_list_request":
        send_json_encrypted(conn, {"type": "plugin_list_response", "plugins": list(plugins.keys())})

    elif msg_type == "plugin_exec_request":
        pname = msg.get("plugin")
        payload = msg.get("payload")
        result = execute_plugin(pname, payload)
        send_json_encrypted(conn, {"type": "plugin_exec_response", "plugin": pname, "result": result})

    elif msg_type == "task_exec_request":
        task_info = msg.get("task")
        t = collect_telemetry()
        if t["cpu"] > CPU_CAP_STRICT:
            log(f"[TASK] Rejecting remote task {task_info.get('id')} due to CPU {t['cpu']:.1f}% > {CPU_CAP_STRICT}%", "WARN")
            send_json_encrypted(conn, {"type": "task_exec_response", "accepted": False})
        else:
            preferred_role = task_info.get("preferred_role")
            if preferred_role and preferred_role != node_role:
                send_json_encrypted(conn, {"type": "task_exec_response", "accepted": False})
            else:
                task_queue_local.put(task_info)
                send_json_encrypted(conn, {"type": "task_exec_response", "accepted": True})

    elif msg_type == "ad_rules_sync":
        rules = msg.get("rules", [])
        merge_ad_rules_from_node(rules)
        send_json_encrypted(conn, {"type": "ad_rules_sync_ack", "node": node_name})

    conn.close()

def tcp_server():
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("", NODE_PORT))
    srv.listen(5)
    log(f"[TCP] Listening (encrypted) on {LOCAL_IP}:{NODE_PORT}")
    while True:
        conn, addr = srv.accept()
        threading.Thread(target=handle_client, args=(conn, addr), daemon=True).start()

def send_request(ip, payload, timeout=4):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, NODE_PORT))
        send_json_encrypted(s, payload)
        resp = recv_json_encrypted(s)
        s.close()
        return resp
    except Exception as e:
        log(f"[TCP] Request error to {ip}: {e}", "WARN")
        return None

# -----------------------------
# CLUSTER TELEMETRY SYNC
# -----------------------------
def telemetry_sync_loop():
    while True:
        collect_telemetry()
        for host, info in list(known_nodes.items()):
            ip = info["ip"]
            resp = send_request(ip, {"type": "telemetry_request"})
            if resp and resp.get("type") == "telemetry_response":
                telemetry_data[host] = resp["data"]
        time.sleep(TELEMETRY_INTERVAL)

# -----------------------------
# YOUTUBE AD AI (STRONG DETECTION)
# -----------------------------
BROWSER_NAMES = ["chrome", "msedge", "edge", "firefox", "brave", "opera"]

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

def is_browser_name(name):
    return any(b in (name or "").lower() for b in BROWSER_NAMES)

def scan_youtube_ports():
    """
    Heuristic: treat any HTTPS stream from a browser PID as a candidate video stream.
    This is not proof of YouTube; it is a signal that a browser is actively streaming.
    """
    streams, browser_pids = [], set()
    for proc in psutil.process_iter(["pid", "name"]):
        try:
            if is_browser_name(proc.info.get("name")):
                browser_pids.add(proc.info["pid"])
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError, psutil.Error):
        return streams
    for conn in conns:
        if conn.pid not in browser_pids or not conn.raddr:
            continue
        try:
            streams.append({
                "pid": conn.pid,
                "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
                "raddr": f"{conn.raddr.ip}:{conn.raddr.port}",
                "port": conn.raddr.port,
                "status": getattr(conn, "status", ""),
                "kind": "HTTPS candidate" if conn.raddr.port == 443 else "browser connection"
            })
        except Exception:
            continue
    return streams

def strong_youtube_detection():
    """
    Strong detection:
    - If any browser PID has active HTTPS streams (port 443), treat as YouTube-like playing.
    - If window title or cmdline contains 'youtube', mark reason accordingly.
    - This is a candidate signal, not a guarantee of YouTube or an ad.
    """
    active_title, active_pid = get_active_window_info()
    streams = scan_youtube_ports()
    yt_state["port_streams"] = streams
    browser_pids = {s["pid"] for s in streams}
    candidate_proc = None
    candidate_title = ""
    reason = "network-streams"

    # Prefer processes whose cmdline mentions youtube.com
    yt_cmd_proc = None
    yt_cmd_title = ""
    for proc in psutil.process_iter(["pid", "name", "cmdline"]):
        try:
            pid = proc.info["pid"]
            name = (proc.info.get("name") or "").lower()
            cmd = " ".join(proc.info.get("cmdline") or []).lower()
            if not is_browser_name(name):
                continue
            if "youtube.com" in cmd:
                yt_cmd_proc = proc
                yt_cmd_title = cmd
                break
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            continue

    if yt_cmd_proc is not None:
        candidate_proc = yt_cmd_proc
        candidate_title = yt_cmd_title or active_title or "(YouTube browser process)"
        reason = "process-command-line"
    elif browser_pids:
        pid = next(iter(browser_pids))
        try:
            proc = psutil.Process(pid)
            candidate_proc = proc
            candidate_title = active_title or proc.name() or "(Browser with video streams)"
            reason = "network-streams"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            candidate_proc = None

    # Window title hint
    if "youtube" in (active_title or "").lower() and active_pid:
        try:
            proc = psutil.Process(active_pid)
            if is_browser_name(proc.name()):
                candidate_proc = proc
                candidate_title = active_title
                reason = "active-window-title"
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            pass

    return candidate_proc, candidate_title, active_title, active_pid, reason, streams

def yt_detection_loop():
    last_signature = None
    while True:
        try:
            proc, title, active_title, active_pid, reason, streams = strong_youtube_detection()
            yt_state["last_scan_ts"] = time.time()
            yt_state["active_window_title"] = active_title
            yt_state["active_window_pid"] = active_pid
            yt_state["detection_reason"] = reason

            detected = proc is not None or bool(streams)
            if detected:
                pid = proc.pid if proc is not None else (streams[0]["pid"] if streams else None)
                title = title or active_title or "(YouTube-related browser process)"
                signature = (pid, title)
                if not yt_state["active"] or signature != last_signature:
                    record_yt_event("yt_detected_strong", {
                        "pid": pid,
                        "title": title,
                        "active_window": active_title,
                        "reason": reason,
                        "streams_count": len(streams),
                    })
                yt_state["active"] = True
                yt_state["current_proc"], yt_state["current_title"] = pid, title
                last_signature = signature
            else:
                if yt_state["active"]:
                    record_yt_event("yt_closed", {"active_window": active_title})
                yt_state["active"] = False
                yt_state["current_proc"], yt_state["current_title"] = None, ""
                last_signature = None
                yt_state["ad_skip_confidence"] = 0.0
                yt_state["gesture_active"] = False
        except Exception as e:
            log(f"[YT] Detection loop error: {e}", "WARN")
        time.sleep(YT_DETECTION_INTERVAL)

# -----------------------------
# WHOLE-WEB AD AI (ALL PORTS, ALL CONNECTIONS)
# -----------------------------
def _reverse_dns(ip: str):
    """
    Best-effort reverse DNS:
    - Tries to map IP -> hostname.
    - Failure is expected; we keep it lightweight and non-blocking by catching errors.
    """
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        return host.lower()
    except Exception:
        return None

def _classify_connection_for_ad(conn):
    """
    Chain-of-thought style reasoning in code:
    - We look at remote IP/port.
    - We attempt reverse DNS to get a hostname.
    - We compare hostname/IP string against ad_host_hints.
    - We treat matches as ad-like connections.
    - This is heuristic, not proof; it is meant to surface likely ad traffic.
    """
    if not conn.raddr:
        return None

    r_ip = conn.raddr.ip
    r_port = conn.raddr.port
    host = _reverse_dns(r_ip)
    descriptor = f"{r_ip}:{r_port}"
    host_str = host or descriptor

    # Simple heuristic: if any host hint is a substring of the hostname, mark as ad-like.
    ad_hit = False
    matched_hint = None
    for hint in list(ad_host_hints)[:500]:  # limit to keep it cheap
        if hint in host_str:
            ad_hit = True
            matched_hint = hint
            break

    return {
        "pid": conn.pid,
        "laddr": f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "",
        "raddr": descriptor,
        "host": host,
        "port": r_port,
        "status": getattr(conn, "status", ""),
        "ad_like": ad_hit,
        "matched_hint": matched_hint,
    }

def scan_web_ports_all():
    """
    Whole-web scan:
    - Iterate all inet connections.
    - For each connection, run ad heuristic classification.
    - Build a list of connections and a subset that look ad-like.
    """
    connections = []
    ad_connections = []
    try:
        conns = psutil.net_connections(kind="inet")
    except (psutil.AccessDenied, OSError, psutil.Error):
        return connections, ad_connections

    for conn in conns:
        try:
            info = _classify_connection_for_ad(conn)
            if not info:
                continue
            connections.append(info)
            if info["ad_like"]:
                ad_connections.append(info)
        except Exception:
            continue
    return connections, ad_connections

def _update_domain_stats(ad_connections):
    """
    Predictive reasoning:
    - For each ad-like connection, we update domain stats.
    - Domain stats track how often a domain appears and how often it is ad-like.
    - Score = ad_hits / hits, used as a heuristic prediction for future traffic.
    """
    now = time.time()
    for info in ad_connections:
        host = info.get("host") or info.get("raddr")
        if not host:
            continue
        key = host.lower()
        stats = web_ad_state["domain_stats"].get(key, {"hits": 0, "ad_hits": 0, "score": 0.0, "last_ts": 0.0})
        stats["hits"] += 1
        stats["ad_hits"] += 1
        stats["score"] = stats["ad_hits"] / max(1, stats["hits"])
        stats["last_ts"] = now
        web_ad_state["domain_stats"][key] = stats

    # Global prediction score: average of top N domains
    if web_ad_state["domain_stats"]:
        scores = sorted((v["score"] for v in web_ad_state["domain_stats"].values()), reverse=True)
        top = scores[:10]
        web_ad_state["prediction_score"] = sum(top) / max(1, len(top))
    else:
        web_ad_state["prediction_score"] = 0.0

def web_ad_detection_loop():
    """
    Whole-web ad detection loop:
    - Scans all inet connections.
    - Uses EasyList-derived host hints + reverse DNS to flag ad-like traffic.
    - Updates predictive domain stats.
    - Feeds into global ad state used by the oscilloscope and GUI.
    """
    while True:
        try:
            connections, ad_connections = scan_web_ports_all()
            web_ad_state["last_scan_ts"] = time.time()
            web_ad_state["connections"] = connections
            web_ad_state["ad_connections"] = ad_connections
            web_ad_state["active"] = bool(ad_connections)
            _update_domain_stats(ad_connections)
            web_ad_state["last_event_ts"] = time.time() if ad_connections else web_ad_state["last_event_ts"]
        except Exception as e:
            log(f"[WEB-AD] Detection loop error: {e}", "WARN")
        time.sleep(WEB_AD_DETECTION_INTERVAL)

# -----------------------------
# WEBCAM VISION (YELLOW SKIP BAR + MOUSE TRACKING)
# -----------------------------
def analyze_frame_for_ad(frame):
    if frame is None:
        return {"ad_active": False, "confidence": 0.0, "note": "no-frame"}
    try:
        h, w = frame.shape[:2]
        if WEBCAM_DOWNSCALE > 0 and WEBCAM_DOWNSCALE < 1.0:
            frame = cv2.resize(frame, (int(w * WEBCAM_DOWNSCALE), int(h * WEBCAM_DOWNSCALE)))
            h, w = frame.shape[:2]
        hsv = cv2.cvtColor(frame, cv2.COLOR_BGR2HSV)
        lower_yellow = np.array([20, 80, 120])
        upper_yellow = np.array([40, 255, 255])
        band = hsv[int(h * 2 / 3):, :]
        mask_yellow = cv2.inRange(band, lower_yellow, upper_yellow)
        yellow_ratio = np.mean(mask_yellow > 0)
        gray_band = cv2.cvtColor(frame[int(h * 2 / 3):, :], cv2.COLOR_BGR2GRAY)
        edges = cv2.Canny(gray_band, 80, 160)
        edge_density = np.mean(edges > 0)
        confidence = float(0.7 * yellow_ratio + 0.3 * edge_density)
        ad_active = confidence > 0.05
        note = f"yellow_ratio={yellow_ratio:.3f}, edge_density={edge_density:.3f}"
        return {"ad_active": ad_active, "confidence": confidence, "note": note}
    except Exception as e:
        return {"ad_active": False, "confidence": 0.0, "note": f"error:{e}"}

def analyze_frame_for_mouse_cursor(frame):
    if frame is None or not mouse_vision_state["enabled"]:
        return {"cursor_pos": None, "confidence": 0.0, "note": "mouse-vision-disabled-or-no-frame"}
    try:
        h, w = frame.shape[:2]
        if WEBCAM_DOWNSCALE > 0 and WEBCAM_DOWNSCALE < 1.0:
            frame = cv2.resize(frame, (int(w * WEBCAM_DOWNSCALE), int(h * WEBCAM_DOWNSCALE)))
            h, w = frame.shape[:2]
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        band_height = int(h * MOUSE_CURSOR_SEARCH_BAND_HEIGHT_RATIO)
        band = gray[h - band_height:h, :]
        _, thresh = cv2.threshold(band, 220, 255, cv2.THRESH_BINARY)
        contours, _ = cv2.findContours(thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        if not contours:
            return {"cursor_pos": None, "confidence": 0.0, "note": "no-bright-contours"}
        best_contour = None
        best_score = 0.0
        for c in contours:
            area = cv2.contourArea(c)
            if area < MOUSE_CURSOR_MIN_AREA:
                continue
            x, y, w_c, h_c = cv2.boundingRect(c)
            score = 1.0 / (1.0 + area)
            if score > best_score:
                best_score = score
                best_contour = (x, y, w_c, h_c)
        if best_contour is None:
            return {"cursor_pos": None, "confidence": 0.0, "note": "no-valid-contour"}
        x, y, w_c, h_c = best_contour
        cursor_x = x + w_c / 2.0
        cursor_y = (h - band_height) + y + h_c / 2.0
        confidence = float(best_score)
        note = f"cursor_area={w_c*h_c:.1f}, score={confidence:.3f}"
        return {"cursor_pos": (cursor_x, cursor_y), "confidence": confidence, "note": note}
    except Exception as e:
        return {"cursor_pos": None, "confidence": 0.0, "note": f"error:{e}"}

def webcam_vision_loop():
    cap = None
    if webcam_state["enabled"]:
        try:
            cap = cv2.VideoCapture(WEBCAM_INDEX)
            if not cap or not cap.isOpened():
                log(f"[WEBCAM] Failed to open camera index {WEBCAM_INDEX}", "WARN")
                webcam_state["available"] = False
                cap = None
            else:
                webcam_state["available"] = True
                log(f"[WEBCAM] Camera index {WEBCAM_INDEX} opened", "INFO")
        except Exception as e:
            log(f"[WEBCAM] Error opening camera: {e}", "WARN")
            webcam_state["available"] = False
            cap = None
    else:
        webcam_state["available"] = False

    while True:
        try:
            if not webcam_state["enabled"]:
                time.sleep(WEBCAM_FRAME_INTERVAL)
                continue
            if cap is None or not cap.isOpened():
                try:
                    cap = cv2.VideoCapture(WEBCAM_INDEX)
                    if not cap or not cap.isOpened():
                        webcam_state["available"] = False
                        time.sleep(WEBCAM_FRAME_INTERVAL)
                        continue
                    webcam_state["available"] = True
                    log(f"[WEBCAM] Camera index {WEBCAM_INDEX} reopened", "INFO")
                except Exception as e:
                    log(f"[WEBCAM] Reopen error: {e}", "WARN")
                    webcam_state["available"] = False
                    time.sleep(WEBCAM_FRAME_INTERVAL)
                    continue
            ret, frame = cap.read()
            if not ret:
                webcam_state["available"] = False
                time.sleep(WEBCAM_FRAME_INTERVAL)
                continue
            webcam_state["last_frame_ts"] = time.time()
            webcam_state["last_frame"] = frame.copy()

            ad_result = analyze_frame_for_ad(frame)
            ad_active = ad_result["ad_active"]
            confidence = ad_result["confidence"]
            note = ad_result["note"]

            cursor_result = analyze_frame_for_mouse_cursor(frame)
            cursor_pos = cursor_result["cursor_pos"]
            cursor_conf = cursor_result["confidence"]
            cursor_note = cursor_result["note"]

            mouse_vision_state["last_cursor_pos"] = cursor_pos
            mouse_vision_state["last_cursor_confidence"] = cursor_conf
            mouse_vision_state["last_cursor_note"] = cursor_note

            if ad_active and not webcam_state["last_ad_active"]:
                record_yt_event("yt_webcam_ad_start", {
                    "confidence": confidence,
                    "note": note,
                    "cursor_pos": cursor_pos,
                    "cursor_conf": cursor_conf,
                })
            elif not ad_active and webcam_state["last_ad_active"]:
                record_yt_event("yt_webcam_ad_end", {
                    "confidence": confidence,
                    "note": note,
                    "cursor_pos": cursor_pos,
                    "cursor_conf": cursor_conf,
                })
            webcam_state["last_ad_active"] = ad_active
            webcam_state["last_confidence"] = confidence
            webcam_state["last_note"] = note
        except Exception as e:
            log(f"[WEBCAM] Vision loop error: {e}", "WARN")
            time.sleep(WEBCAM_FRAME_INTERVAL)

# -----------------------------
# MOUSE TELEMETRY + PATTERNS + CIRCLE GESTURE
# -----------------------------
def detect_circle_gesture_from_history():
    """
    Predictive gesture reasoning:
    - We look at recent mouse positions.
    - If they form a roughly circular path with enough angular span,
      we treat it as an intentional 'ad signal' gesture.
    """
    if len(mouse_history) < 20:
        return False
    pts = list(mouse_history)[-40:]
    xs = [p[1] for p in pts]
    ys = [p[2] for p in pts]
    cx = sum(xs) / len(xs)
    cy = sum(ys) / len(ys)
    radii = [math.hypot(x - cx, y - cy) for x, y in zip(xs, ys)]
    mean_r = sum(radii) / len(radii)
    if mean_r < 25:
        return False
    std_r = (sum((r - mean_r) ** 2 for r in radii) / len(radii)) ** 0.5
    if std_r > mean_r * 0.35:
        return False
    angles = [math.atan2(y - cy, x - cx) for x, y in zip(xs, ys)]
    angles_sorted = sorted(angles)
    span = angles_sorted[-1] - angles_sorted[0]
    if span < 0:
        span += 2 * math.pi
    if span < 4.0:
        return False
    now = time.time()
    if now - yt_state.get("circle_last_ts", 0.0) < 3.0:
        return False
    yt_state["circle_last_ts"] = now
    return True

def update_actual_mouse(x, y, event="move", button=""):
    now = time.monotonic()
    horizon = max(0.0, min(0.5, float(CFG.get("mouse_prediction_horizon_ms", 120)) / 1000.0))
    smoothing = max(0.05, min(1.0, float(CFG.get("mouse_smoothing", 0.35))))
    with mouse_tracking_lock:
        st = mouse_tracking_state
        old_x, old_y, old_ts = st["x"], st["y"], st["last_move_ts"]
        if old_x is not None and old_y is not None and old_ts and event == "move":
            dt = max(0.001, now - old_ts)
            raw_vx = max(-10000.0, min(10000.0, (float(x) - old_x) / dt))
            raw_vy = max(-10000.0, min(10000.0, (float(y) - old_y) / dt))
            st["vx"] = (1.0 - smoothing) * st["vx"] + smoothing * raw_vx
            st["vy"] = (1.0 - smoothing) * st["vy"] + smoothing * raw_vy
            st["speed"] = math.hypot(st["vx"], st["vy"])
            if st["speed"] < 18:
                st["direction"] = "stationary"
            else:
                angle = math.degrees(math.atan2(-st["vy"], st["vx"]))
                st["direction"] = ("right" if -22.5 <= angle < 22.5 else
                    "up-right" if 22.5 <= angle < 67.5 else
                    "up" if 67.5 <= angle < 112.5 else
                    "up-left" if 112.5 <= angle < 157.5 else
                    "left" if angle >= 157.5 or angle < -157.5 else
                    "down-left" if -157.5 <= angle < -112.5 else
                    "down" if -112.5 <= angle < -67.5 else "down-right")
        st["x"], st["y"] = int(x), int(y)
        if event == "move":
            st["last_move_ts"] = now
            mouse_history.append((now, int(x), int(y)))
        elif event == "click":
            st["last_click_ts"] = now
            st["click_count"] += 1
            st["last_button"] = str(button)
        st["predicted_x"] = int(x + st["vx"] * horizon)
        st["predicted_y"] = int(y + st["vy"] * horizon)
        st["confidence"] = min(0.99, len(mouse_history) / 10.0) if len(mouse_history) >= 2 else 0.1
        st["dwell_seconds"] = max(0.0, now - st["last_move_ts"]) if st["last_move_ts"] else 0.0
        st["events"].append({
            "ts": time.time(),
            "event": event,
            "x": int(x),
            "y": int(y),
            "button": str(button) if button else "",
            "speed_px_s": round(st["speed"], 1),
            "predicted": [st["predicted_x"], st["predicted_y"]],
        })

        # Gesture-based ad signal: circle gesture while any video/ad signal is active
        if event == "move" and (yt_state.get("active") or web_ad_state.get("active")):
            if detect_circle_gesture_from_history():
                yt_state["gesture_active"] = True
                conf_boost = 0.8
                yt_state["ad_skip_confidence"] = max(yt_state["ad_skip_confidence"], conf_boost)
                meta = {
                    "center_estimate": [
                        sum(p[1] for p in mouse_history) / len(mouse_history),
                        sum(p[2] for p in mouse_history) / len(mouse_history),
                    ],
                    "radius_estimate": "circle-gesture",
                    "note": "User drew a circle with mouse to signal ad playing.",
                }
                record_yt_event("yt_circle_ad_signal", meta)

def register_ad_skip_click(x, y):
    now = time.time()
    with ad_skip_lock:
        ad_skip_click_buffer.append({"ts": now, "x": x, "y": y})
        cutoff = now - AD_SKIP_PATTERN_TIME_WINDOW
        while ad_skip_click_buffer and ad_skip_click_buffer[0]["ts"] < cutoff:
            ad_skip_click_buffer.popleft()

        if len(ad_skip_click_buffer) < AD_SKIP_PATTERN_MIN_CLICKS:
            return False

        xs = [c["x"] for c in ad_skip_click_buffer]
        ys = [c["y"] for c in ad_skip_click_buffer]
        cx = sum(xs) / len(xs)
        cy = sum(ys) / len(ys)
        max_r = max(math.hypot(c["x"] - cx, c["y"] - cy) for c in ad_skip_click_buffer)
        if max_r <= AD_SKIP_PATTERN_MAX_RADIUS_PX:
            confidence = min(1.0, 0.4 + 0.1 * (len(ad_skip_click_buffer) - AD_SKIP_PATTERN_MIN_CLICKS))
            yt_state["ad_skip_confidence"] = max(yt_state["ad_skip_confidence"], confidence)
            pattern = {
                "ts": now,
                "center": [cx, cy],
                "clicks": len(ad_skip_click_buffer),
                "radius_px": max_r,
                "confidence": confidence,
            }
            yt_state["ad_skip_patterns"].append(pattern)
            record_yt_event("yt_ad_skip_pattern", pattern)
            return True
        return False

def mouse_click_listener():
    def on_move(x, y):
        if mouse_tracking_state["enabled"]:
            update_actual_mouse(x, y, "move")

    def on_click(x, y, button, pressed):
        if not pressed:
            return
        if mouse_tracking_state["enabled"]:
            update_actual_mouse(x, y, "click", button)

        # We treat clicks during any active video/ad signal as telemetry.
        if not (yt_state.get("active") or web_ad_state.get("active")):
            return

        pattern_triggered = register_ad_skip_click(x, y)

        meta = {
            "pid": yt_state.get("current_proc"),
            "button": str(button),
            "x": x,
            "y": y,
            "title": yt_state.get("current_title", ""),
            "click_count": mouse_tracking_state.get("click_count", 0),
            "note": "Observed click during browser/video activity; ad-skip outcome is not verified.",
            "predicted_cursor": [mouse_tracking_state.get("predicted_x"), mouse_tracking_state.get("predicted_y")],
            "speed_px_s": mouse_tracking_state.get("speed", 0.0),
            "pattern_triggered": pattern_triggered,
            "ad_skip_confidence": yt_state.get("ad_skip_confidence", 0.0),
            "web_ad_prediction": web_ad_state.get("prediction_score", 0.0),
        }
        yt_state["ad_skip_clicks"] += 1
        yt_state["ad_suspected_events"] += 1
        record_yt_event("yt_mouse_click_observed", meta)
        try:
            create_task(
                payload={"reason": "yt_mouse_click_observed", "meta": meta},
                preferred_role="UTILITY",
                plugin=None,
                auto=True,
                description="Browser/video-related mouse click telemetry",
            )
        except Exception as e:
            log(f"[YT] Optional task creation failed: {e}", "WARN")

    try:
        listener = mouse.Listener(on_move=on_move, on_click=on_click)
        listener.start()
        log("[MOUSE] Actual desktop cursor tracking listener started")
    except Exception as e:
        log(f"[MOUSE] Mouse listener unavailable: {e}", "WARN")

def yt_behavior_loop():
    """
    Behavior loop:
    - Integrates YouTube-specific signals, webcam vision, mouse gestures, and whole-web ad state.
    - Feeds a single activity value into the oscilloscope:
      0 = idle, 1 = video-like, 2 = ad-like (YT or web).
    """
    while True:
        if yt_state["active"]:
            if yt_state["ad_skip_clicks"] >= 3:
                log(f"[YT] Heavy ad pattern detected (skip_clicks={yt_state['ad_skip_clicks']})")
            if webcam_state["enabled"] and webcam_state["available"]:
                if webcam_state["last_ad_active"]:
                    log(
                        f"[YT] Webcam suggests ad active (conf={webcam_state['last_confidence']:.3f}, "
                        f"note={webcam_state['last_note']}, cursor={mouse_vision_state['last_cursor_pos']}, "
                        f"cursor_conf={mouse_vision_state['last_cursor_confidence']:.3f}, "
                        f"ad_skip_conf={yt_state['ad_skip_confidence']:.3f})",
                        "DEBUG",
                    )

        if yt_state["gesture_active"]:
            if time.time() - yt_state.get("circle_last_ts", 0.0) > 4.0:
                yt_state["gesture_active"] = False

        # Combine YouTube + whole-web ad signals into a single activity value.
        any_video_signal = yt_state.get("active", False) or bool(yt_state.get("port_streams"))
        any_ad_signal = (
            webcam_state.get("last_ad_active", False)
            or yt_state.get("gesture_active", False)
            or yt_state.get("ad_skip_confidence", 0.0) > 0.3
            or web_ad_state.get("active", False)
            or web_ad_state.get("prediction_score", 0.0) > 0.4
        )

        if any_ad_signal:
            val = 2
        elif any_video_signal:
            val = 1
        else:
            val = 0
        osc_state["buffer"].append(val)

        time.sleep(YT_BEHAVIOR_INTERVAL)

# DominionDeck UI state mirror; values are populated from live telemetry.
DETECTION_STATE = {
    "yt_detect": {"progress": 0.0, "status": "Idle"},
    "ad_suspect": {"progress": 0.0, "status": "Idle"},
    "cursor_gesture": {"progress": 0.0, "status": "Idle"},
    "skip_pattern": {"progress": 0.0, "status": "Idle"},
    "ad_lock": {"progress": 0.0, "status": "Idle"},
    "banner_mode": "idle",
    "banner_text": "Idle — no YouTube or web ad activity",
}

# -----------------------------
# GUI
# -----------------------------
def gui_main():
    global node_role

    root = tk.Tk()
    root.title(f"Poor Man's Network + DominionDeck v6.0 - {node_name} ({node_role})")
    root.geometry("1180x780")
    root.minsize(900, 600)
    root.protocol("WM_DELETE_WINDOW", root.destroy)

    # DominionDeck global status panel, driven by the real detection engine.
    status_panel = ttk.LabelFrame(root, text="Browser / Ad Tracking Status")
    status_panel.pack(side="top", fill="x", padx=7, pady=(7, 3))
    status_panel.columnconfigure(1, weight=1)
    status_bars = {}

    def make_status_row(row_idx, key, label_text):
        ttk.Label(status_panel, text=label_text).grid(
            row=row_idx, column=0, sticky="w", padx=(6, 4), pady=2
        )
        bar = ttk.Progressbar(status_panel, orient="horizontal", mode="determinate", maximum=100)
        bar.grid(row=row_idx, column=1, sticky="ew", padx=5, pady=2)
        status = ttk.Label(status_panel, text="Waiting for detector")
        status.grid(row=row_idx, column=2, sticky="w", padx=5, pady=2)
        status_bars[key] = {"bar": bar, "status": status}

    make_status_row(1, "yt_detect", "YouTube / Video Detection")
    make_status_row(2, "ad_suspect", "Ad / Skip Signal (YT + Web)")
    make_status_row(3, "cursor_gesture", "Predictive Mouse")
    make_status_row(4, "skip_pattern", "Repeated Click Pattern")
    make_status_row(5, "ad_lock", "Signal Confidence")
    banner_summary = tk.Label(
        status_panel, text="Idle — waiting for browser activity", anchor="w",
        justify="left", padx=8, pady=5, bg="#444444", fg="white",
        font=("Segoe UI", 10, "bold"),
    )
    banner_summary.grid(row=1, column=3, rowspan=5, sticky="nsew", padx=7, pady=3)

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True, padx=5, pady=4)

    # DominionDeck dashboard tab
    frame_dashboard = ttk.Frame(notebook)
    notebook.add(frame_dashboard, text="Dashboard")
    dashboard_summary = tk.Text(frame_dashboard, height=9, wrap="word")
    dashboard_summary.pack(fill="both", expand=True, padx=8, pady=8)
    dashboard_summary.insert(
        "1.0",
        "Live command-center summary will appear here.\n"
        "Status is based on real process/window/network and mouse telemetry.\n"
        "A browser HTTPS connection or ad-like host match is only a candidate signal, "
        "not proof that a specific ad is playing.",
    )
    dashboard_summary.configure(state="disabled")

    # Telemetry-only GPU page; no hardware controls are falsely implied.
    frame_gpu = ttk.Frame(notebook)
    notebook.add(frame_gpu, text="GPU Governor")
    gpu_summary = tk.Text(frame_gpu, height=10, wrap="word")
    gpu_summary.pack(fill="both", expand=True, padx=8, pady=8)
    gpu_summary.insert(
        "1.0",
        "GPU telemetry / governor status\n"
        "This integration reports available GPU load, temperature, and memory telemetry. "
        "Clock, voltage, and fan controls are not implemented in the source engine.",
    )
    gpu_summary.configure(state="disabled")

    # Nodes tab
    frame_nodes = ttk.Frame(notebook)
    notebook.add(frame_nodes, text="Nodes")
    node_list = tk.Listbox(frame_nodes)
    node_list.pack(fill="both", expand=True)

    # Telemetry tab
    frame_tel = ttk.Frame(notebook)
    notebook.add(frame_tel, text="Telemetry")
    tel_tree = ttk.Treeview(
        frame_tel,
        columns=("host", "cpu", "ram", "gpu", "temp", "disk", "net"),
        show="headings",
    )
    for col in ("host", "cpu", "ram", "gpu", "temp", "disk", "net"):
        tel_tree.heading(col, text=col.upper())
    tel_tree.pack(fill="both", expand=True)

    # Storage tab
    frame_storage = ttk.Frame(notebook)
    notebook.add(frame_storage, text="Storage")
    storage_tree = ttk.Treeview(
        frame_storage,
        columns=("node", "path", "size"),
        show="headings",
    )
    for col in ("node", "path", "size"):
        storage_tree.heading(col, text=col.upper())
    storage_tree.pack(fill="both", expand=True)

    storage_filter_entry = tk.Entry(frame_storage)
    storage_filter_entry.pack(fill="x", padx=5, pady=2)
    storage_filter_entry.insert(0, "filter substring...")

    btn_refresh_storage = tk.Button(
        frame_storage,
        text="Refresh Local Storage Index",
    )
    btn_refresh_storage.pack(pady=5)

    # Ad Intel tab
    frame_ad = ttk.Frame(notebook)
    notebook.add(frame_ad, text="Ad Intel")
    ad_listbox = tk.Listbox(frame_ad)
    ad_listbox.pack(fill="both", expand=True)
    ad_entry = tk.Entry(frame_ad)
    ad_entry.pack(fill="x", padx=5, pady=5)

    def send_ad_gui():
        text = ad_entry.get().strip()
        if text:
            broadcast_ad_intel(text)
            ad_entry.delete(0, tk.END)

    ad_btn = tk.Button(frame_ad, text="Share Ad Intel", command=send_ad_gui)
    ad_btn.pack(pady=5)

    # Ad Rules tab
    frame_rules = ttk.Frame(notebook)
    notebook.add(frame_rules, text="Ad Rules")
    rules_listbox = tk.Listbox(frame_rules)
    rules_listbox.pack(fill="both", expand=True)

    rules_search_entry = tk.Entry(frame_rules)
    rules_search_entry.pack(fill="x", padx=5, pady=2)
    rules_search_entry.insert(0, "search rule substring...")

    rules_stats_label = tk.Label(frame_rules, text="Rules: 0")
    rules_stats_label.pack(pady=2)

    def update_rules_view(filter_text=""):
        rules_listbox.delete(0, tk.END)
        rules = sorted(ad_rules)
        if filter_text:
            rules = [r for r in rules if filter_text.lower() in r.lower()]
        for r in rules[:2000]:
            rules_listbox.insert(tk.END, r)
        rules_stats_label.config(
            text=f"Rules: {len(ad_rules)} (showing {min(len(rules), 2000)})"
        )

    def on_rules_search(_event=None):
        txt = rules_search_entry.get().strip()
        update_rules_view(txt)

    rules_search_entry.bind("<Return>", on_rules_search)

    # Plugins tab
    frame_plugins = ttk.Frame(notebook)
    notebook.add(frame_plugins, text="Plugins")
    plugin_listbox = tk.Listbox(frame_plugins)
    plugin_listbox.pack(fill="both", expand=True)

    plugin_payload_label = tk.Label(frame_plugins, text="Plugin payload (JSON):")
    plugin_payload_label.pack(pady=2)
    plugin_payload_text = tk.Text(frame_plugins, height=6)
    plugin_payload_text.pack(fill="x", padx=5, pady=2)

    plugin_result_label = tk.Label(frame_plugins, text="Result preview:")
    plugin_result_label.pack(pady=2)
    plugin_result_text = tk.Text(frame_plugins, height=8)
    plugin_result_text.pack(fill="both", padx=5, pady=2)

    def update_plugins():
        plugin_listbox.delete(0, tk.END)
        for name in sorted(plugins.keys()):
            plugin_listbox.insert(tk.END, name)

    def run_selected_plugin():
        sel = plugin_listbox.curselection()
        if not sel:
            return
        name = plugin_listbox.get(sel[0])
        raw = plugin_payload_text.get("1.0", tk.END).strip()
        if not raw:
            payload = {}
        else:
            try:
                payload = json.loads(raw)
            except Exception as e:
                plugin_result_text.delete("1.0", tk.END)
                plugin_result_text.insert("1.0", f"Invalid JSON payload: {e}")
                return
        result = execute_plugin(name, payload)
        preview = json.dumps(result, indent=2)[:TASK_RESULT_PREVIEW_LEN]
        plugin_result_text.delete("1.0", tk.END)
        plugin_result_text.insert("1.0", preview)

    btn_reload_plugins = tk.Button(
        frame_plugins,
        text="Reload Plugins",
        command=lambda: [load_plugins(), update_plugins()],
    )
    btn_reload_plugins.pack(pady=5)

    btn_run_plugin = tk.Button(
        frame_plugins,
        text="Run Selected Plugin",
        command=run_selected_plugin,
    )
    btn_run_plugin.pack(pady=5)

    # Tasks tab
    frame_tasks = ttk.Frame(notebook)
    notebook.add(frame_tasks, text="Tasks")
    task_tree = ttk.Treeview(
        frame_tasks,
        columns=("id", "creator", "role", "plugin", "status", "ts"),
        show="headings",
    )
    for col in ("id", "creator", "role", "plugin", "status", "ts"):
        task_tree.heading(col, text=col.upper())
    task_tree.pack(fill="both", expand=True)

    task_result_text = tk.Text(frame_tasks, height=10)
    task_result_text.pack(fill="both", padx=5, pady=5)

    def update_tasks_view():
        task_tree.delete(*task_tree.get_children())
        for tid, info in sorted(tasks_cluster.items(), key=lambda x: x[1]["ts"], reverse=True):
            task_tree.insert(
                "",
                tk.END,
                values=(
                    tid,
                    info.get("creator"),
                    info.get("preferred_role"),
                    info.get("plugin"),
                    info.get("status"),
                    time.strftime("%H:%M:%S", time.localtime(info.get("ts", time.time()))),
                ),
            )

    def on_task_select(_event=None):
        sel = task_tree.selection()
        if not sel:
            return
        item = task_tree.item(sel[0])
        tid = item["values"][0]
        info = tasks_cluster.get(tid)
        if not info:
            return
        result = info.get("result")
        preview = json.dumps(result, indent=2)[:TASK_RESULT_PREVIEW_LEN] if result is not None else "No result yet."
        task_result_text.delete("1.0", tk.END)
        task_result_text.insert("1.0", preview)

    task_tree.bind("<<TreeviewSelect>>", on_task_select)

    # YouTube AI tab
    frame_yt = ttk.Frame(notebook)
    notebook.add(frame_yt, text="YouTube AI")
    yt_info_label = tk.Label(frame_yt, text="YouTube detection state:")
    yt_info_label.pack(pady=2)

    yt_state_text = tk.Text(frame_yt, height=8)
    yt_state_text.pack(fill="both", padx=5, pady=2)

    yt_events_label = tk.Label(frame_yt, text="Recent YT events:")
    yt_events_label.pack(pady=2)
    yt_events_list = tk.Listbox(frame_yt)
    yt_events_list.pack(fill="both", expand=True)

    webcam_status_label = tk.Label(frame_yt, text="Webcam Vision: disabled")
    webcam_status_label.pack(pady=2)

    webcam_preview_label = tk.Label(frame_yt, text="Webcam preview (mouse + yellow tracking bar):")
    webcam_preview_label.pack(pady=2)
    webcam_preview_canvas = tk.Label(frame_yt)
    webcam_preview_canvas.pack(fill="both", expand=True)

    mouse_vision_status_label = tk.Label(
        frame_yt,
        text="Webcam Mouse Vision: enabled" if mouse_vision_state["enabled"] else "Webcam Mouse Vision: disabled",
    )
    mouse_vision_status_label.pack(pady=2)

    actual_mouse_status_label = tk.Label(
        frame_yt,
        text="Desktop Mouse: waiting for input",
        justify="left",
        anchor="w",
    )
    actual_mouse_status_label.pack(fill="x", padx=6, pady=4)

    tk.Label(frame_yt, text="Recent desktop mouse events").pack(pady=2)
    mouse_events_list = tk.Listbox(frame_yt, height=5)
    mouse_events_list.pack(fill="x", padx=6, pady=2)

    ad_skip_conf_label = tk.Label(frame_yt, text="Ad-skip confidence:")
    ad_skip_conf_label.pack(pady=2)
    ad_skip_conf_bar = tk.Label(frame_yt, text="[----------] 0.00", anchor="w", justify="left")
    ad_skip_conf_bar.pack(fill="x", padx=6, pady=2)

    # Banner: "Trying to pinpoint ad location" above oscilloscope
    ad_banner_label = tk.Label(
        frame_yt,
        text="YouTube / Web inactive",
        anchor="w",
        justify="left",
        fg="gray",
    )
    ad_banner_label.pack(fill="x", padx=6, pady=4)

    # Oscilloscope-style activity graph
    osc_label = tk.Label(frame_yt, text="Activity waveform (video=blue, ad=red):")
    osc_label.pack(pady=2)
    osc_canvas = tk.Canvas(frame_yt, height=120, bg="black", highlightthickness=1, highlightbackground="#444")
    osc_canvas.pack(fill="x", padx=6, pady=4)

    # Web Ads AI tab
    frame_webad = ttk.Frame(notebook)
    notebook.add(frame_webad, text="Web Ads AI")
    webad_state_label = tk.Label(frame_webad, text="Whole-web ad detection state:")
    webad_state_label.pack(pady=2)
    webad_state_text = tk.Text(frame_webad, height=8)
    webad_state_text.pack(fill="both", padx=5, pady=2)

    webad_conn_label = tk.Label(frame_webad, text="Recent ad-like connections:")
    webad_conn_label.pack(pady=2)
    webad_conn_list = tk.Listbox(frame_webad)
    webad_conn_list.pack(fill="both", expand=True)

    webad_domain_label = tk.Label(frame_webad, text="Domain prediction scores:")
    webad_domain_label.pack(pady=2)
    webad_domain_list = tk.Listbox(frame_webad)
    webad_domain_list.pack(fill="both", expand=True)

    # Logs tab
    frame_logs = ttk.Frame(notebook)
    notebook.add(frame_logs, text="Logs")
    logs_listbox = tk.Listbox(frame_logs)
    logs_listbox.pack(fill="both", expand=True)

    cpu_info_label = tk.Label(
        frame_tel,
        text=f"CPU caps: soft={CPU_CAP_SOFT:.1f}%, strict={CPU_CAP_STRICT:.1f}%",
        anchor="w",
        justify="left",
    )
    cpu_info_label.pack(fill="x", padx=4, pady=2)

    def update_nodes_view():
        node_list.delete(0, tk.END)
        node_list.insert(tk.END, f"{node_name} (local, role={node_role}, ip={LOCAL_IP})")
        for host, info in sorted(known_nodes.items()):
            node_list.insert(
                tk.END,
                f"{host} (role={info.get('role')}, ip={info.get('ip')}, last_seen={time.strftime('%H:%M:%S', time.localtime(info.get('last_seen', time.time())))})",
            )

    def update_telemetry_view():
        tel_tree.delete(*tel_tree.get_children())
        for host, data in telemetry_data.items():
            gpu = data.get("gpu")
            gpu_str = f"{gpu['name']} {gpu['load']:.1f}% {gpu['temp']}C" if gpu else "N/A"
            disk = data.get("disk")
            disk_str = f"{disk['percent']:.1f}% {disk['used']/(1024**3):.1f}GiB" if disk else "N/A"
            net = data.get("net")
            net_str = f"↑{net['bytes_sent']//1024}KiB ↓{net['bytes_recv']//1024}KiB" if net else "N/A"
            tel_tree.insert(
                "",
                tk.END,
                values=(
                    host,
                    f"{data.get('cpu', 0.0):.1f}%",
                    f"{data.get('ram', 0.0):.1f}%",
                    gpu_str,
                    f"{data.get('temp', 0.0) or 0.0:.1f}C",
                    disk_str,
                    net_str,
                ),
            )

    def update_storage_view(filter_text=""):
        storage_tree.delete(*storage_tree.get_children())
        files = storage_index_local.get("files", [])
        for entry in files:
            path = entry.get("path")
            if filter_text and filter_text.lower() not in (path or "").lower():
                continue
            size = entry.get("size")
            storage_tree.insert(
                "",
                tk.END,
                values=(
                    storage_index_local.get("node", node_name),
                    path,
                    size if size is not None else "N/A",
                ),
            )

    def on_storage_filter(_event=None):
        txt = storage_filter_entry.get().strip()
        update_storage_view(txt)

    storage_filter_entry.bind("<Return>", on_storage_filter)

    def refresh_storage_button():
        try:
            refresh_storage_index()
            update_storage_view(storage_filter_entry.get().strip())
        except Exception as e:
            log(f"[GUI] Storage refresh failed: {e}", "WARN")

    btn_refresh_storage.config(command=refresh_storage_button)

    def update_ad_intel_view():
        ad_listbox.delete(0, tk.END)
        for item in ad_intel[-100:]:
            ts = time.strftime("%H:%M:%S", time.localtime(item.get("ts", time.time())))
            ad_listbox.insert(
                tk.END,
                f"[{ts}] {item.get('hostname')} -> {item.get('ad')}",
            )

    def draw_oscilloscope():
        osc_canvas.delete("all")
        buf = list(osc_state["buffer"])
        if not buf:
            return
        w = osc_canvas.winfo_width() or 400
        h = osc_canvas.winfo_height() or 120
        mid = h / 2
        max_amp = h / 2 - 5
        n = len(buf)
        if n < 2:
            return
        step_x = w / (n - 1)
        points = []
        for i, v in enumerate(buf):
            if v == 0:
                amp = 0.0
            elif v == 1:
                amp = 0.4
            else:
                amp = 0.9
            y = mid - amp * max_amp
            x = i * step_x
            points.append((x, y, v))
        for i in range(len(points) - 1):
            x1, y1, v1 = points[i]
            x2, y2, v2 = points[i + 1]
            if v1 >= 2 or v2 >= 2:
                color = "#ff0000"  # red for ad/gesture/web-ad
            elif v1 == 1 or v2 == 1:
                color = "#0080ff"  # blue for video-like
            else:
                color = "#404040"  # dim gray for no activity
            osc_canvas.create_line(x1, y1, x2, y2, fill=color, width=2)

    def update_dominion_status():
        active_video = bool(yt_state.get("active") or yt_state.get("port_streams"))
        gesture = bool(yt_state.get("gesture_active"))
        webcam_ad = bool(webcam_state.get("last_ad_active"))
        web_ad_active = bool(web_ad_state.get("active"))
        web_pred = float(web_ad_state.get("prediction_score", 0.0) or 0.0)
        confidence = float(yt_state.get("ad_skip_confidence", 0.0) or 0.0)
        patterns = list(yt_state.get("ad_skip_patterns", []))
        clicks = int(yt_state.get("ad_skip_clicks", 0) or 0)
        mouse_st = mouse_tracking_state
        speed = float(mouse_st.get("speed", 0.0) or 0.0)

        states = {
            "yt_detect": (
                100.0 if active_video else 0.0,
                "Browser/video candidate detected" if active_video else "No current video-related signal",
            ),
            "ad_suspect": (
                min(
                    100.0,
                    max(
                        confidence * 100.0,
                        85.0 if (webcam_ad or web_ad_active or web_pred > 0.4) else 0.0,
                    ),
                ),
                "Heuristic ad signal present"
                if (webcam_ad or gesture or confidence > 0.3 or web_ad_active or web_pred > 0.4)
                else "No ad signal confirmed",
            ),
            "cursor_gesture": (
                min(100.0, max(0.0, min(1.0, speed / 1600.0) * 100.0)),
                f"{mouse_st.get('direction', 'stationary')} · {speed:.0f}px/s",
            ),
            "skip_pattern": (
                min(100.0, len(patterns) * 20.0),
                f"{len(patterns)} pattern(s), {clicks} observed click(s)",
            ),
            "ad_lock": (
                min(100.0, max(confidence * 100.0, web_pred * 100.0)),
                f"Heuristic confidence {confidence:.2f}, web prediction {web_pred:.2f}",
            ),
        }
        for key, (progress, status_text) in states.items():
            status_bars[key]["bar"]["value"] = max(0.0, min(100.0, progress))
            status_bars[key]["status"].configure(text=status_text)

        if active_video or web_ad_active:
            if webcam_ad or gesture or confidence > 0.3 or web_ad_active or web_pred > 0.4:
                mode, bg = "tracking", "#aa0000"
                banner_text = "Trying to pinpoint ad location — heuristic signal, not confirmed"
            else:
                mode, bg = "video", "#004488"
                banner_text = "Browser/video-related activity detected — monitoring"
        else:
            mode, bg = "idle", "#444444"
            banner_text = "Idle — no current browser/video-related signal"
        banner_summary.configure(text=banner_text, bg=bg, fg="white")
        DETECTION_STATE.update({
            "yt_detect": {"progress": states["yt_detect"][0], "status": states["yt_detect"][1]},
            "ad_suspect": {"progress": states["ad_suspect"][0], "status": states["ad_suspect"][1]},
            "cursor_gesture": {"progress": states["cursor_gesture"][0], "status": states["cursor_gesture"][1]},
            "skip_pattern": {"progress": states["skip_pattern"][0], "status": states["skip_pattern"][1]},
            "ad_lock": {"progress": states["ad_lock"][0], "status": states["ad_lock"][1]},
            "banner_mode": mode,
            "banner_text": banner_text,
        })

        gpu = collect_gpu_telemetry()
        summary = (
            f"Node: {node_name}  |  Role: {node_role}  |  IP: {LOCAL_IP}\n"
            f"Cluster peers: {len(known_nodes)}  |  Queued tasks: {task_queue_local.qsize()}  |  Plugins: {len(plugins)}\n"
            f"CPU: {psutil.cpu_percent(interval=None):.1f}%  |  RAM: {psutil.virtual_memory().percent:.1f}%\n"
            f"Video signal: {'active' if active_video else 'idle'}  |  Reason: {yt_state.get('detection_reason', 'n/a')}\n"
            f"Active window: {yt_state.get('active_window_title') or '(not available)'}\n"
            f"Web ad state: {'active' if web_ad_active else 'idle'}  |  prediction={web_pred:.2f}\n"
            f"Mouse: ({mouse_st.get('x')}, {mouse_st.get('y')})  |  Predicted: "
            f"({mouse_st.get('predicted_x')}, {mouse_st.get('predicted_y')})  |  Speed: {speed:.1f}px/s\n"
            f"Ad/skip heuristic: {confidence:.2f}  |  Webcam vision: "
            f"{'enabled' if webcam_state.get('enabled') else 'disabled'}\n"
            f"GPU: {gpu.get('name', 'not available') if gpu else 'telemetry unavailable'}"
        )
        dashboard_summary.configure(state="normal")
        dashboard_summary.delete("1.0", tk.END)
        dashboard_summary.insert("1.0", summary)
        dashboard_summary.configure(state="disabled")

        gpu_text = (
            "GPU telemetry / governor status\n"
            "This version reports telemetry only; hardware tuning controls are not implemented.\n\n"
            + (json.dumps(gpu, indent=2) if gpu else "No GPU telemetry available.")
        )
        gpu_summary.configure(state="normal")
        gpu_summary.delete("1.0", tk.END)
        gpu_summary.insert("1.0", gpu_text)
        gpu_summary.configure(state="disabled")

    def update_yt_view():
        state = {
            "active": yt_state.get("active"),
            "current_proc": yt_state.get("current_proc"),
            "current_title": yt_state.get("current_title"),
            "active_window_title": yt_state.get("active_window_title"),
            "active_window_pid": yt_state.get("active_window_pid"),
            "detection_reason": yt_state.get("detection_reason"),
            "last_scan_ts": yt_state.get("last_scan_ts"),
            "ad_skip_clicks": yt_state.get("ad_skip_clicks"),
            "ad_suspected_events": yt_state.get("ad_suspected_events"),
            "ad_skip_confidence": yt_state.get("ad_skip_confidence"),
            "webcam_ad_active": webcam_state.get("last_ad_active"),
            "gesture_active": yt_state.get("gesture_active"),
            "streams_count": len(yt_state.get("port_streams", [])),
        }
        yt_state_text.delete("1.0", tk.END)
        yt_state_text.insert("1.0", json.dumps(state, indent=2))

        yt_events_list.delete(0, tk.END)
        for ev in yt_state["cluster_yt_events"][-50:]:
            ts = time.strftime("%H:%M:%S", time.localtime(ev.get("ts", time.time())))
            etype = ev.get("event_type")
            meta = ev.get("meta", {})
            yt_events_list.insert(tk.END, f"[{ts}] {etype}: {meta}")

        if webcam_state["enabled"]:
            webcam_status_label.config(
                text=f"Webcam Vision: enabled (available={webcam_state['available']}, conf={webcam_state['last_confidence']:.3f}, ad_active={webcam_state['last_ad_active']})"
            )
        else:
            webcam_status_label.config(text="Webcam Vision: disabled")

        if mouse_vision_state["enabled"]:
            mouse_vision_status_label.config(
                text=f"Webcam Mouse Vision: enabled (cursor={mouse_vision_state['last_cursor_pos']}, conf={mouse_vision_state['last_cursor_confidence']:.3f})"
            )
        else:
            mouse_vision_status_label.config(text="Webcam Mouse Vision: disabled")

        st = mouse_tracking_state
        actual_mouse_status_label.config(
            text=(
                f"Desktop Mouse: x={st.get('x')}, y={st.get('y')}, "
                f"speed={st.get('speed', 0.0):.1f}px/s, dir={st.get('direction')}, "
                f"dwell={st.get('dwell_seconds', 0.0):.2f}s, clicks={st.get('click_count', 0)}"
            )
        )

        mouse_events_list.delete(0, tk.END)
        for ev in list(st["events"])[-20:]:
            ts = time.strftime("%H:%M:%S", time.localtime(ev["ts"]))
            mouse_events_list.insert(
                tk.END,
                f"[{ts}] {ev['event']} ({ev['x']},{ev['y']}) btn={ev['button']} speed={ev['speed_px_s']} pred={ev['predicted']}",
            )

        conf = yt_state.get("ad_skip_confidence", 0.0)
        bar_len = 10
        filled = int(conf * bar_len)
        bar = "[" + "#" * filled + "-" * (bar_len - filled) + f"] {conf:.2f}"
        ad_skip_conf_bar.config(text=bar)

        if yt_state.get("active") or web_ad_state.get("active"):
            ad_banner_label.config(text="Trying to pinpoint ad location")
            ad_like = (
                yt_state.get("gesture_active", False)
                or webcam_state.get("last_ad_active", False)
                or yt_state.get("ad_skip_confidence", 0.0) > 0.3
                or web_ad_state.get("active", False)
                or web_ad_state.get("prediction_score", 0.0) > 0.4
            )
            if ad_like:
                ad_banner_label.config(fg="red")
            else:
                ad_banner_label.config(fg="blue")
        else:
            ad_banner_label.config(text="YouTube / Web inactive", fg="gray")

        frame = webcam_state.get("last_frame")
        if frame is not None:
            try:
                disp = frame.copy()
                h, w = disp.shape[:2]
                bar_y0 = int(h * 2 / 3)
                cv2.rectangle(disp, (0, bar_y0), (w - 1, h - 1), (0, 255, 255), 2)
                cpos = mouse_vision_state.get("last_cursor_pos")
                if cpos:
                    cx, cy = int(cpos[0]), int(cpos[1])
                    cv2.circle(disp, (cx, cy), 6, (0, 0, 255), -1)
                rgb = cv2.cvtColor(disp, cv2.COLOR_BGR2RGB)
                img = Image.fromarray(rgb)
                img = img.resize((min(640, w), min(360, h)))
                imgtk = ImageTk.PhotoImage(image=img)
                webcam_preview_canvas.imgtk = imgtk
                webcam_preview_canvas.config(image=imgtk)
            except Exception as e:
                log(f"[GUI] Webcam preview error: {e}", "WARN")

        draw_oscilloscope()

    def update_webad_view():
        state = {
            "active": web_ad_state.get("active"),
            "last_scan_ts": web_ad_state.get("last_scan_ts"),
            "prediction_score": web_ad_state.get("prediction_score"),
            "ad_connections_count": len(web_ad_state.get("ad_connections", [])),
            "total_connections_count": len(web_ad_state.get("connections", [])),
        }
        webad_state_text.delete("1.0", tk.END)
        webad_state_text.insert("1.0", json.dumps(state, indent=2))

        webad_conn_list.delete(0, tk.END)
        for info in web_ad_state.get("ad_connections", [])[-50:]:
            host = info.get("host") or info.get("raddr")
            hint = info.get("matched_hint")
            webad_conn_list.insert(
                tk.END,
                f"PID={info.get('pid')} host={host} port={info.get('port')} hint={hint}",
            )

        webad_domain_list.delete(0, tk.END)
        for host, stats in sorted(web_ad_state.get("domain_stats", {}).items(), key=lambda x: x[1]["score"], reverse=True)[:50]:
            webad_domain_list.insert(
                tk.END,
                f"{host} -> hits={stats['hits']} ad_hits={stats['ad_hits']} score={stats['score']:.2f}",
            )

    def update_logs_view():
        logs_listbox.delete(0, tk.END)
        items = []
        try:
            while True:
                items.append(logs.get_nowait())
        except Exception:
            pass
        for line in items[-200:]:
            logs_listbox.insert(tk.END, line)

    def periodic_update():
        try:
            update_dominion_status()
            update_nodes_view()
            update_telemetry_view()
            update_tasks_view()
            update_ad_intel_view()
            update_rules_view(rules_search_entry.get().strip())
            update_yt_view()
            update_webad_view()
            update_logs_view()
        except Exception as e:
            log(f"[GUI] periodic_update error: {e}", "WARN")
        root.after(200, periodic_update)

    update_plugins()
    periodic_update()
    root.mainloop()

# -----------------------------
# MAIN
# -----------------------------
def main():
    set_log_level("INFO")
    load_plugins()
    if STORAGE_INDEX_ON_START:
        try:
            refresh_storage_index()
        except Exception as e:
            log(f"[MAIN] Initial storage index failed: {e}", "WARN")

    threading.Thread(target=broadcast_presence, daemon=True).start()
    threading.Thread(target=listen_for_broadcasts, daemon=True).start()
    threading.Thread(target=tcp_server, daemon=True).start()
    threading.Thread(target=telemetry_sync_loop, daemon=True).start()
    threading.Thread(target=ad_rules_sync_loop, daemon=True).start()
    threading.Thread(target=yt_detection_loop, daemon=True).start()
    threading.Thread(target=web_ad_detection_loop, daemon=True).start()
    threading.Thread(target=yt_behavior_loop, daemon=True).start()
    threading.Thread(target=webcam_vision_loop, daemon=True).start()
    threading.Thread(target=task_execution_loop, daemon=True).start()
    threading.Thread(target=mouse_click_listener, daemon=True).start()

    gui_main()

if __name__ == "__main__":
    main()
