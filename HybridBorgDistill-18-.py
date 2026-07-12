#!/usr/bin/env python3
# BORG ALTERED STATES v8 — FULL ULTRA BORG EVOLUTION
# Universal Performance Governor (CPU-ONLY, TORCH+NUMPY HYBRID)
# Desktop-optimized, tablet/SBC-safe, with:
# - Self-healing model weights
# - Auto-pruning for low-RAM systems
# - Adaptive feature expansion
# - Real-time anomaly injection tests
# - Swarm evolution visualization
# - Full Borg Evolution mode (maximum intelligence)

import os
import sys
import time
import threading
import queue
import subprocess
import traceback
import csv
import math
import random
import socket
import platform
import shutil

# ---------------------------------------------------------
# GLOBAL CONSTANTS
# ---------------------------------------------------------
FALLBACK_FEATURE_DIM = 64   # C — 64 features (desktop-optimized)
MAX_FEATURE_DIM = 128       # adaptive expansion ceiling
MIN_FEATURE_DIM = 16        # minimum safe feature dimension

MAX_ROWS = 100000           # more rows for ultra mode
SELF_HEAL_THRESHOLD = 50.0
SELF_HEAL_COOLDOWN = 60.0

FPS_TARGET = 90.0
PING_TARGET = "8.8.8.8"

DQN_MEMORY_CAPACITY = 10000
DQN_BATCH_SIZE = 128
DQN_GAMMA = 0.97
DQN_EPSILON = 0.3
DQN_MIN_EPSILON = 0.05
DQN_EPSILON_DECAY = 0.999

GAME_PROCESS_HINTS = [
    "steam.exe", "cs2.exe", "valorant.exe", "fortnite.exe",
    "eldenring.exe", "wow.exe", "leagueoflegends.exe"
]

SERVER_PROCESS_HINTS = [
    "nginx", "apache2", "httpd", "mysqld", "postgres",
    "redis-server", "node", "dotnet", "java"
]

MODES = ["Flow", "DeepWork", "Recovery", "Dream", "Idle"]

GRAPHICS_PROFILES = {
    "ultra": {"resolution_scale": 1.0, "effects": 1.0, "shadows": 1.0},
    "high": {"resolution_scale": 0.9, "effects": 0.9, "shadows": 0.9},
    "balanced": {"resolution_scale": 0.8, "effects": 0.8, "shadows": 0.8},
    "performance": {"resolution_scale": 0.7, "effects": 0.6, "shadows": 0.5},
    "low": {"resolution_scale": 0.6, "effects": 0.5, "shadows": 0.3},
}

# ---------------------------------------------------------
# PATHS / GLOBAL STATE
# ---------------------------------------------------------
BASE_DIR = os.getcwd()
DATA_FILE = os.path.join(BASE_DIR, "data.csv")
FPS_FILE = os.path.join(BASE_DIR, "fps.txt")
SWARM_LOG_FILE = os.path.join(BASE_DIR, "swarm_evolution.csv")

DATA_QUEUE = queue.Queue(maxsize=8000)
CONTROL_LOCK = threading.Lock()
STOP_FLAG = False

TEACHER = None
SHADOW_TEACHER = None
SWARM_STUDENTS = []
ANOMALY_MODEL = None
LSTM_MODEL = None
RL_POLICY = None
DQN_POLICY = None
DQN_TARGET = None

IN_FEATURES = None

CURRENT_PORT = 5001
LAST_ROTATE = time.time()

EMA_TEACHER_LOSS = None
EMA_SHADOW_LOSS = None
EMA_SWARM_LOSS = None
EMA_ANOMALY_LOSS = None
EMA_LSTM_LOSS = None

STATE_HISTORY = []
DQN_MEMORY = []

USE_TORCH_MODELS = False

LAST_SELF_HEAL = 0.0

LATEST_STATUS = {
    "ema_teacher_loss": None,
    "ema_shadow_loss": None,
    "ema_swarm_loss": None,
    "ema_anomaly_loss": None,
    "ema_lstm_loss": None,
    "samples": 0,
    "current_port": CURRENT_PORT,
    "last_update": None,
    "last_perf_score": None,
    "last_bottlenecks": [],
    "last_actions": [],
    "mode": "Idle",
    "predicted_pressure_spike": False,
    "fluid_energy": 0.0,
    "anomaly_score": 0.0,
    "prediction_horizon_sec": 10.0,
    "predicted_perf_score": None,
    "prediction_confidence": None,
    "mode_history": [],
    "rl_last_reward": None,
    "rl_last_action": None,
    "dqn_last_reward": None,
    "dqn_last_action": None,
    "auto_tuning_profile": {},
    "fps_target": FPS_TARGET,
    "fps_current": 0.0,
    "graphics_profile": "balanced",
    "profile": "lite",
    "env": {},
    "borg_evolution": False,
    "swarm_snapshot": {},
    "self_heal_events": 0,
    "anomaly_injections": 0,
}

# ---------------------------------------------------------
# DEPENDENCY MANAGEMENT
# ---------------------------------------------------------
BASE_REQUIRED = ["numpy"]
DESKTOP_EXTRA = ["psutil", "pandas", "flask", "torch"]

def check_import(pkg):
    try:
        __import__(pkg)
        return True
    except ImportError:
        return False

def install_if_missing(pkgs):
    for pkg in pkgs:
        if not check_import(pkg):
            try:
                subprocess.run(
                    [sys.executable, "-m", "pip", "install", pkg],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL
                )
            except Exception:
                pass

install_if_missing(BASE_REQUIRED)

import numpy as np

HAS_PSUTIL = check_import("psutil")
HAS_PANDAS = check_import("pandas")
HAS_FLASK = check_import("flask")
HAS_TORCH = check_import("torch")

if HAS_PSUTIL:
    import psutil
if HAS_PANDAS:
    import pandas as pd
if HAS_FLASK:
    from flask import Flask, jsonify
if HAS_TORCH:
    import torch
    import torch.nn as nn
    import torch.optim as optim

# ---------------------------------------------------------
# SAFE HELPERS
# ---------------------------------------------------------
def safe_metric(val, default=0.0):
    try:
        if val is None:
            return default
        if isinstance(val, (int, float)):
            return float(val)
        return float(val)
    except Exception:
        return default

def safe_batch(x, y):
    if x is None or y is None:
        return None, None
    if len(x) == 0 or len(y) == 0:
        return None, None
    return x, y

def safe_process_list(lst):
    if lst is None:
        return []
    if not isinstance(lst, list):
        return []
    return lst

def safe_model_output(out):
    if out is None:
        return np.array([[0.0]], dtype=np.float32)
    if isinstance(out, (int, float)):
        return np.array([[float(out)]], dtype=np.float32)
    if isinstance(out, np.ndarray):
        if out.size == 0:
            return np.array([[0.0]], dtype=np.float32)
        if out.ndim == 1:
            return out.reshape(1, -1)
        return out
    return np.array([[0.0]], dtype=np.float32)

def ensure_compiler():
    plat = sys.platform.lower()
    try:
        if "win" in plat:
            if shutil.which("cl") is None:
                print("[SETUP] Microsoft C++ compiler not found. Torch may be limited.")
                return False
            return True
        if "linux" in plat:
            if shutil.which("gcc") is None:
                print("[SETUP] GCC not found. Torch may be limited.")
                return False
            return True
        if "darwin" in plat:
            if shutil.which("clang") is None:
                print("[SETUP] Clang not found. Torch may be limited.")
                return False
            return True
        print("[SETUP] No compiler available on this OS — Torch disabled, NumPy-only mode.")
        return False
    except Exception:
        return False

# ---------------------------------------------------------
# ENVIRONMENT DETECTION
# ---------------------------------------------------------
def get_ram_mb_fallback():
    if HAS_PSUTIL:
        try:
            return int(psutil.virtual_memory().total / (1024 * 1024))
        except Exception:
            pass
    return 1024

def detect_mobile():
    plat = sys.platform.lower()
    if "android" in plat:
        return True
    if "ios" in plat:
        return True
    if "TERMUX_VERSION" in os.environ:
        return True
    return False

def detect_low_power(env):
    cores = env.get("cores")
    ram_mb = env.get("ram_mb")
    if cores is None:
        cores = 1
    if ram_mb is None:
        ram_mb = 1024
    env["cores"] = cores
    env["ram_mb"] = ram_mb
    if cores <= 2:
        return True
    if ram_mb <= 2048:
        return True
    return False

def detect_environment():
    cores = os.cpu_count()
    ram_mb = get_ram_mb_fallback()
    env = {
        "os": sys.platform,
        "platform": platform.system(),
        "cores": cores if cores is not None else 1,
        "ram_mb": ram_mb if ram_mb is not None else 1024,
        "is_mobile": detect_mobile(),
        "has_psutil": HAS_PSUTIL,
        "has_pandas": HAS_PANDAS,
        "has_flask": HAS_FLASK,
        "has_torch": HAS_TORCH,
    }
    env["is_low_power"] = detect_low_power(env)
    env["has_compiler"] = ensure_compiler()
    return env

def choose_profile(env):
    if env["cores"] >= 8 and env["ram_mb"] >= 16384 and env["has_psutil"] and env["has_torch"]:
        LATEST_STATUS["borg_evolution"] = True
        return "borg_evolution"
    if env["is_mobile"] or env["is_low_power"]:
        return "lite"
    if env["cores"] >= 4 and env["ram_mb"] >= 4096 and env["has_psutil"]:
        return "full"
    return "medium"

def current_hour():
    return time.localtime().tm_hour

# ---------------------------------------------------------
# MODE / PERSONALITY
# ---------------------------------------------------------
def infer_mode(features, ext, perf_score):
    cpu = safe_metric(features.get("cpu"))
    ram = safe_metric(features.get("ram"))
    gpu = safe_metric(features.get("gpu_usage"))
    latency = safe_metric(features.get("net_latency_ms"))
    game_cpu = safe_metric(ext.get("game_cpu"))
    server_cpu = safe_metric(ext.get("server_cpu"))
    fps = safe_metric(features.get("fps"))
    hour = current_hour()
    if game_cpu > 50 or fps > 30 or gpu > 60:
        return "Flow"
    if server_cpu > 80 or (cpu > 70 and gpu < 40):
        return "DeepWork"
    if perf_score < 40 and (cpu > 70 or ram > 80 or gpu > 80):
        return "Recovery"
    if hour >= 1 and hour <= 5 and cpu < 30 and gpu < 30 and server_cpu < 30 and game_cpu < 30:
        return "Dream"
    return "Idle"

def mode_personality(mode):
    if mode == "Flow":
        return {"lr_factor": 1.2, "mutation_rate": 0.03, "physics_sensitivity": 1.2, "control_aggressiveness": 0.85}
    if mode == "DeepWork":
        return {"lr_factor": 1.0, "mutation_rate": 0.05, "physics_sensitivity": 1.0, "control_aggressiveness": 0.9}
    if mode == "Recovery":
        return {"lr_factor": 0.8, "mutation_rate": 0.02, "physics_sensitivity": 1.5, "control_aggressiveness": 1.0}
    if mode == "Dream":
        return {"lr_factor": 0.6, "mutation_rate": 0.04, "physics_sensitivity": 0.8, "control_aggressiveness": 0.3}
    return {"lr_factor": 1.0, "mutation_rate": 0.03, "physics_sensitivity": 1.0, "control_aggressiveness": 0.6}

def update_mode_history(mode):
    LATEST_STATUS["mode_history"].append((time.time(), mode))
    if len(LATEST_STATUS["mode_history"]) > 200:
        LATEST_STATUS["mode_history"] = LATEST_STATUS["mode_history"][-200:]

# ---------------------------------------------------------
# METRICS COLLECTION
# ---------------------------------------------------------
def collect_system_metrics():
    ts = time.time()
    cpu = 0.0
    ram = 0.0
    disk = 0.0
    net_sent = 0
    net_recv = 0
    procs = 0
    uptime = ts
    if HAS_PSUTIL:
        try:
            cpu = psutil.cpu_percent(interval=0)
            ram = psutil.virtual_memory().percent
            disk = psutil.disk_usage("/").percent
            net = psutil.net_io_counters()
            net_sent = net.bytes_sent
            net_recv = net.bytes_recv
            procs = len(psutil.pids())
            uptime = ts - psutil.boot_time()
        except Exception:
            pass
    return {
        "timestamp": ts,
        "cpu": cpu,
        "ram": ram,
        "disk": disk,
        "net_sent": net_sent,
        "net_recv": net_recv,
        "procs": procs,
        "uptime": uptime
    }

def get_gpu_usage():
    return 0.0

def get_process_usage(hints):
    if not HAS_PSUTIL:
        return {"cpu": 0.0, "ram": 0.0, "count": 0, "procs": []}
    cpu_total = 0.0
    ram_total = 0.0
    count = 0
    names = []
    for p in psutil.process_iter(attrs=["name", "cpu_percent", "memory_percent", "pid"]):
        try:
            name = (p.info["name"] or "").lower()
            if any(h.lower() in name for h in hints):
                cpu_total += p.info["cpu_percent"]
                ram_total += p.info["memory_percent"]
                count += 1
                names.append((p.info["pid"], name, p.info["cpu_percent"], p.info["memory_percent"]))
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return {
        "cpu": cpu_total,
        "ram": ram_total,
        "count": count,
        "procs": names
    }

def measure_latency(host=PING_TARGET):
    try:
        start = time.time()
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        s.connect((host, 80))
        s.close()
        return (time.time() - start) * 1000.0
    except Exception:
        return 0.0

def read_fps():
    try:
        if os.path.exists(FPS_FILE):
            with open(FPS_FILE, "r") as f:
                val = f.read().strip()
                fps = float(val)
                LATEST_STATUS["fps_current"] = fps
                return fps
    except Exception:
        pass
    LATEST_STATUS["fps_current"] = 0.0
    return 0.0

def collect_external_sensors():
    gpu = get_gpu_usage()
    game = get_process_usage(GAME_PROCESS_HINTS)
    server = get_process_usage(SERVER_PROCESS_HINTS)
    latency = measure_latency(PING_TARGET)
    fps = read_fps()
    return {
        "gpu_usage": gpu,
        "game_cpu": game["cpu"],
        "game_ram": game["ram"],
        "game_count": game["count"],
        "server_cpu": server["cpu"],
        "server_ram": server["ram"],
        "server_count": server["count"],
        "net_latency_ms": latency,
        "fps": fps,
        "game_procs": safe_process_list(game["procs"]),
        "server_procs": safe_process_list(server["procs"])
    }

# ---------------------------------------------------------
# FEATURE VECTORS / DATA FILE
# ---------------------------------------------------------
def adaptive_feature_expand(row):
    vals = [safe_metric(v) for v in row]
    if len(vals) < FALLBACK_FEATURE_DIM:
        vals += [0.0] * (FALLBACK_FEATURE_DIM - len(vals))
    else:
        vals = vals[:FALLBACK_FEATURE_DIM]
    return np.array(vals, dtype=np.float32)

def build_feature_vector():
    sys_metrics = collect_system_metrics()
    ext = collect_external_sensors()
    features = {
        "timestamp": sys_metrics["timestamp"],
        "cpu": sys_metrics["cpu"],
        "ram": sys_metrics["ram"],
        "disk": sys_metrics["disk"],
        "net_sent": sys_metrics["net_sent"],
        "net_recv": sys_metrics["net_recv"],
        "procs": sys_metrics["procs"],
        "uptime": sys_metrics["uptime"],
        "gpu_usage": ext["gpu_usage"],
        "game_cpu": ext["game_cpu"],
        "game_ram": ext["game_ram"],
        "server_cpu": ext["server_cpu"],
        "server_ram": ext["server_ram"],
        "net_latency_ms": ext["net_latency_ms"],
        "fps": ext["fps"]
    }
    return features, ext

def ensure_data_file():
    if not os.path.exists(DATA_FILE):
        with open(DATA_FILE, "w", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([
                "timestamp", "cpu", "ram", "disk",
                "net_sent", "net_recv", "procs", "uptime",
                "gpu_usage", "game_cpu", "game_ram",
                "server_cpu", "server_ram", "net_latency_ms",
                "fps", "perf_score"
            ])
        print("[BORG] Created new data.csv")

def compute_perf_score(features):
    cpu = safe_metric(features.get("cpu"))
    ram = safe_metric(features.get("ram"))
    gpu = safe_metric(features.get("gpu_usage"))
    latency = safe_metric(features.get("net_latency_ms"))
    fps = safe_metric(features.get("fps"))
    score = 100.0
    score -= 0.3 * cpu
    score -= 0.3 * ram
    score -= 0.2 * gpu
    score -= 0.05 * latency
    score += 0.8 * fps
    return max(score, 0.0)

def append_system_data():
    features, ext = build_feature_vector()
    perf_score = compute_perf_score(features)
    with open(DATA_FILE, "a", newline="") as f:
        writer = csv.writer(f)
        writer.writerow([
            features["timestamp"],
            features["cpu"],
            features["ram"],
            features["disk"],
            features["net_sent"],
            features["net_recv"],
            features["procs"],
            features["uptime"],
            features["gpu_usage"],
            features["game_cpu"],
            features["game_ram"],
            features["server_cpu"],
            features["server_ram"],
            features["net_latency_ms"],
            features["fps"],
            perf_score
        ])
    LATEST_STATUS["last_perf_score"] = perf_score
    return features, ext, perf_score

def trim_data_file():
    if not HAS_PANDAS:
        return
    try:
        df = pd.read_csv(DATA_FILE)
        if len(df) > MAX_ROWS:
            df = df.iloc[-MAX_ROWS:]
            df.to_csv(DATA_FILE, index=False)
            print(f"[DATA] Trimmed data.csv to {MAX_ROWS} rows")
    except Exception as e:
        print("[DATA] Trim exception:", e)

# ---------------------------------------------------------
# FLUID ENERGY / STATE HISTORY / ANOMALIES
# ---------------------------------------------------------
def compute_fluid_energy(features):
    cpu = safe_metric(features.get("cpu"))
    ram = safe_metric(features.get("ram"))
    gpu = safe_metric(features.get("gpu_usage"))
    latency = safe_metric(features.get("net_latency_ms"))
    energy = 0.5 * (cpu ** 2) + 0.4 * (ram ** 2) + 0.3 * (gpu ** 2) + 0.1 * (latency ** 2) / 100.0
    return energy

def update_state_history(features, perf_score):
    global STATE_HISTORY
    energy = compute_fluid_energy(features)
    timestamp = features["timestamp"]
    vec = np.array([
        safe_metric(features["cpu"]), safe_metric(features["ram"]), safe_metric(features["gpu_usage"]),
        safe_metric(features["net_latency_ms"]), perf_score
    ], dtype=np.float32)
    STATE_HISTORY.append((timestamp, vec, perf_score, energy))
    if len(STATE_HISTORY) > 600:
        STATE_HISTORY = STATE_HISTORY[-600:]
    LATEST_STATUS["fluid_energy"] = energy

def inject_anomaly():
    global STATE_HISTORY
    if len(STATE_HISTORY) < 5:
        return
    t, v, p, e = STATE_HISTORY[-1]
    v_injected = v.copy()
    v_injected[0] = min(100.0, v_injected[0] + 50.0)
    v_injected[1] = min(100.0, v_injected[1] + 40.0)
    v_injected[3] = v_injected[3] + 100.0
    STATE_HISTORY.append((t + 0.1, v_injected, p - 20.0, e * 1.5))
    LATEST_STATUS["anomaly_injections"] += 1
    print("[ANOMALY] Synthetic anomaly injected")

def predict_pressure_spike():
    if len(STATE_HISTORY) < 5:
        return False
    times = np.array([t for t, v, p, e in STATE_HISTORY[-40:]])
    energies = np.array([e for t, v, p, e in STATE_HISTORY[-40:]])
    if len(times) == 0 or len(energies) == 0:
        return False
    t0 = times[0]
    x = times - t0
    if len(x) < 2:
        return False
    A = np.vstack([x, np.ones_like(x)]).T
    try:
        m, c = np.linalg.lstsq(A, energies, rcond=None)[0]
    except Exception:
        return False
    return m > 5.0

# ---------------------------------------------------------
# PORT ROTATION
# ---------------------------------------------------------
def port_rotation_loop():
    global CURRENT_PORT, LAST_ROTATE
    print("[PORT] Port rotation thread started")
    while not STOP_FLAG:
        try:
            m = collect_system_metrics()
            cpu = safe_metric(m.get("cpu"))
            ram = safe_metric(m.get("ram"))
            time_trigger = (time.time() - LAST_ROTATE) > 1800
            load_trigger = cpu > 80 or ram > 85
            if time_trigger or load_trigger:
                CURRENT_PORT += 1
                if CURRENT_PORT > 5200:
                    CURRENT_PORT = 5001
                LAST_ROTATE = time.time()
                LATEST_STATUS["current_port"] = CURRENT_PORT
                print(f"[PORT] Rotated internal port to {CURRENT_PORT} (cpu={cpu}, ram={ram})")
            time.sleep(5)
        except Exception as e:
            print("[PORT] Exception:", e)
            time.sleep(2)

# ---------------------------------------------------------
# STREAMING INGESTION
# ---------------------------------------------------------
def dynamic_batch_size():
    m = collect_system_metrics()
    cpu = safe_metric(m.get("cpu"))
    ram = safe_metric(m.get("ram"))
    if cpu < 40 and ram < 50:
        return 256
    elif cpu < 70 and ram < 70:
        return 128
    else:
        return 64

def streaming_ingestion_loop():
    global STOP_FLAG, IN_FEATURES
    ensure_data_file()
    print("[STREAM] Streaming ingestion started")
    while not STOP_FLAG:
        try:
            features, ext, perf_score = append_system_data()
            trim_data_file()
            update_state_history(features, perf_score)
            mode = infer_mode(features, ext, perf_score)
            LATEST_STATUS["mode"] = mode
            update_mode_history(mode)
            if HAS_PANDAS:
                df = pd.read_csv(DATA_FILE)
                if df.shape[0] == 0:
                    IN_FEATURES = FALLBACK_FEATURE_DIM
                    time.sleep(1.0)
                    continue
                X_raw = df.iloc[:, :-1].values.astype(np.float32)
                y = df.iloc[:, -1].values.astype(np.float32)
            else:
                rows = []
                with open(DATA_FILE, "r") as f:
                    reader = csv.reader(f)
                    header = next(reader, None)
                    for row in reader:
                        rows.append(row)
                if not rows:
                    IN_FEATURES = FALLBACK_FEATURE_DIM
                    time.sleep(1.0)
                    continue
                arr = np.array(rows, dtype=np.float32)
                X_raw = arr[:, :-1]
                y = arr[:, -1]
            X = np.array([adaptive_feature_expand(row) for row in X_raw], dtype=np.float32)
            try:
                if X is None or len(X) == 0:
                    IN_FEATURES = FALLBACK_FEATURE_DIM
                else:
                    IN_FEATURES = int(X.shape[1])
            except Exception:
                IN_FEATURES = FALLBACK_FEATURE_DIM
            LATEST_STATUS["samples"] = len(X)
            idx = np.random.permutation(len(X))
            X = X[idx]
            y = y[idx]
            batch_size = dynamic_batch_size()
            for i in range(0, len(X), batch_size):
                xb = X[i:i+batch_size]
                yb = y[i:i+batch_size]
                xb, yb = safe_batch(xb, yb)
                if xb is None:
                    continue
                try:
                    DATA_QUEUE.put((xb, yb), timeout=1.0)
                except queue.Full:
                    pass
            time.sleep(0.5)
        except Exception as e:
            print("[STREAM] Exception:", e)
            traceback.print_exc()
            time.sleep(2.0)

# ---------------------------------------------------------
# MODELS — TORCH
# ---------------------------------------------------------
if HAS_TORCH:
    class TeacherTorch(nn.Module):
        def __init__(self, in_features):
            super().__init__()
            if in_features is None:
                in_features = FALLBACK_FEATURE_DIM
            self.net = nn.Sequential(
                nn.Linear(in_features, 256),
                nn.ReLU(),
                nn.Linear(256, 128),
                nn.ReLU(),
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.Linear(64, 1)
            )
        def forward(self, x):
            return self.net(x)

    class ShadowTeacherTorch(nn.Module):
        def __init__(self, in_features):
            super().__init__()
            if in_features is None:
                in_features = FALLBACK_FEATURE_DIM
            self.net = nn.Sequential(
                nn.Linear(in_features, 128),
                nn.ReLU(),
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.Linear(64, 1)
            )
        def forward(self, x):
            return self.net(x)

    class StudentTorch(nn.Module):
        def __init__(self, in_features):
            super().__init__()
            if in_features is None:
                in_features = FALLBACK_FEATURE_DIM
            self.net = nn.Sequential(
                nn.Linear(in_features, 32),
                nn.ReLU(),
                nn.Linear(32, 1)
            )
        def forward(self, x):
            return self.net(x)

    class AnomalyAutoencoderTorch(nn.Module):
        def __init__(self, input_dim):
            super().__init__()
            if input_dim is None:
                input_dim = 5
            self.encoder = nn.Sequential(
                nn.Linear(input_dim, 16),
                nn.ReLU(),
                nn.Linear(16, 8),
                nn.ReLU()
            )
            self.decoder = nn.Sequential(
                nn.Linear(8, 16),
                nn.ReLU(),
                nn.Linear(16, input_dim)
            )
        def forward(self, x):
            z = self.encoder(x)
            recon = self.decoder(z)
            return recon

    class LSTMPredictorTorch(nn.Module):
        def __init__(self, feature_dim, hidden_dim=32, num_layers=1):
            super().__init__()
            if feature_dim is None:
                feature_dim = 5
            self.lstm = nn.LSTM(feature_dim, hidden_dim, num_layers, batch_first=True)
            self.fc = nn.Linear(hidden_dim, 1)
        def forward(self, x_seq):
            out, _ = self.lstm(x_seq)
            last = out[:, -1, :]
            pred = self.fc(last)
            return pred

    class RLPolicyNetTorch(nn.Module):
        def __init__(self, state_dim, action_dim=3):
            super().__init__()
            if state_dim is None:
                state_dim = 7
            self.net = nn.Sequential(
                nn.Linear(state_dim, 64),
                nn.ReLU(),
                nn.Linear(64, 32),
                nn.ReLU(),
                nn.Linear(32, action_dim)
            )
        def forward(self, x):
            return self.net(x)

    class DQNNetTorch(nn.Module):
        def __init__(self, state_dim, action_dim=4):
            super().__init__()
            if state_dim is None:
                state_dim = 7
            self.net = nn.Sequential(
                nn.Linear(state_dim, 128),
                nn.ReLU(),
                nn.Linear(128, 64),
                nn.ReLU(),
                nn.Linear(64, action_dim)
            )
        def forward(self, x):
            return self.net(x)

# ---------------------------------------------------------
# MODELS — NUMPY
# ---------------------------------------------------------
class TeacherNP:
    def __init__(self, in_features):
        if in_features is None:
            in_features = FALLBACK_FEATURE_DIM
        self.w1 = np.random.randn(in_features, 256).astype(np.float32) * 0.01
        self.b1 = np.zeros((256,), dtype=np.float32)
        self.w2 = np.random.randn(256, 128).astype(np.float32) * 0.01
        self.b2 = np.zeros((128,), dtype=np.float32)
        self.w3 = np.random.randn(128, 64).astype(np.float32) * 0.01
        self.b3 = np.zeros((64,), dtype=np.float32)
        self.w4 = np.random.randn(64, 1).astype(np.float32) * 0.01
        self.b4 = np.zeros((1,), dtype=np.float32)

    def forward(self, x):
        h1 = np.maximum(0, x @ self.w1 + self.b1)
        h2 = np.maximum(0, h1 @ self.w2 + self.b2)
        h3 = np.maximum(0, h2 @ self.w3 + self.b3)
        out = h3 @ self.w4 + self.b4
        return out

class ShadowTeacherNP:
    def __init__(self, in_features):
        if in_features is None:
            in_features = FALLBACK_FEATURE_DIM
        self.w1 = np.random.randn(in_features, 128).astype(np.float32) * 0.01
        self.b1 = np.zeros((128,), dtype=np.float32)
        self.w2 = np.random.randn(128, 64).astype(np.float32) * 0.01
        self.b2 = np.zeros((64,), dtype=np.float32)
        self.w3 = np.random.randn(64, 1).astype(np.float32) * 0.01
        self.b3 = np.zeros((1,), dtype=np.float32)

    def forward(self, x):
        h1 = np.maximum(0, x @ self.w1 + self.b1)
        h2 = np.maximum(0, h1 @ self.w2 + self.b2)
        out = h2 @ self.w3 + self.b3
        return out

class StudentNP:
    def __init__(self, in_features):
        if in_features is None:
            in_features = FALLBACK_FEATURE_DIM
        self.w1 = np.random.randn(in_features, 32).astype(np.float32) * 0.01
        self.b1 = np.zeros((32,), dtype=np.float32)
        self.w2 = np.random.randn(32, 1).astype(np.float32) * 0.01
        self.b2 = np.zeros((1,), dtype=np.float32)

    def forward(self, x):
        h1 = np.maximum(0, x @ self.w1 + self.b1)
        out = h1 @ self.w2 + self.b2
        return out

class AnomalyAutoencoderNP:
    def __init__(self, input_dim):
        if input_dim is None:
            input_dim = 5
        self.w1 = np.random.randn(input_dim, 16).astype(np.float32) * 0.01
        self.b1 = np.zeros((16,), dtype=np.float32)
        self.w2 = np.random.randn(16, 8).astype(np.float32) * 0.01
        self.b2 = np.zeros((8,), dtype=np.float32)
        self.w3 = np.random.randn(8, 16).astype(np.float32) * 0.01
        self.b3 = np.zeros((16,), dtype=np.float32)
        self.w4 = np.random.randn(16, input_dim).astype(np.float32) * 0.01
        self.b4 = np.zeros((input_dim,), dtype=np.float32)

    def forward(self, x):
        h1 = np.maximum(0, x @ self.w1 + self.b1)
        h2 = np.maximum(0, h1 @ self.w2 + self.b2)
        h3 = np.maximum(0, h2 @ self.w3 + self.b3)
        recon = h3 @ self.w4 + self.b4
        return recon

class LSTMPredictorNP:
    def __init__(self, feature_dim, hidden_dim=32):
        if feature_dim is None:
            feature_dim = 5
        self.feature_dim = feature_dim
        self.hidden_dim = hidden_dim
        self.w = np.random.randn(feature_dim, hidden_dim).astype(np.float32) * 0.01
        self.b = np.zeros((hidden_dim,), dtype=np.float32)
        self.w_out = np.random.randn(hidden_dim, 1).astype(np.float32) * 0.01
        self.b_out = np.zeros((1,), dtype=np.float32)

    def forward(self, x_seq):
        h = np.zeros((self.hidden_dim,), dtype=np.float32)
        for t in range(x_seq.shape[0]):
            h = np.tanh(x_seq[t] @ self.w + self.b + h)
        out = h @ self.w_out + self.b_out
        return out.reshape(1, 1)

class RLPolicyNetNP:
    def __init__(self, state_dim, action_dim=3):
        if state_dim is None:
            state_dim = 7
        self.w1 = np.random.randn(state_dim, 64).astype(np.float32) * 0.01
        self.b1 = np.zeros((64,), dtype=np.float32)
        self.w2 = np.random.randn(64, 32).astype(np.float32) * 0.01
        self.b2 = np.zeros((32,), dtype=np.float32)
        self.w3 = np.random.randn(32, action_dim).astype(np.float32) * 0.01
        self.b3 = np.zeros((action_dim,), dtype=np.float32)

    def forward(self, x):
        h1 = np.maximum(0, x @ self.w1 + self.b1)
        h2 = np.maximum(0, h1 @ self.w2 + self.b2)
        logits = h2 @ self.w3 + self.b3
        return logits

class DQNNetNP:
    def __init__(self, state_dim, action_dim=4):
        if state_dim is None:
            state_dim = 7
        self.w1 = np.random.randn(state_dim, 128).astype(np.float32) * 0.01
        self.b1 = np.zeros((128,), dtype=np.float32)
        self.w2 = np.random.randn(128, 64).astype(np.float32) * 0.01
        self.b2 = np.zeros((64,), dtype=np.float32)
        self.w3 = np.random.randn(64, action_dim).astype(np.float32) * 0.01
        self.b3 = np.zeros((action_dim,), dtype=np.float32)

    def forward(self, x):
        h1 = np.maximum(0, x @ self.w1 + self.b1)
        h2 = np.maximum(0, h1 @ self.w2 + self.b2)
        q = h2 @ self.w3 + self.b3
        return q

# ---------------------------------------------------------
# SELF-HEAL / LR / SWARM MUTATION
# ---------------------------------------------------------
def adaptive_lr(base_lr=1e-3, mode="Idle"):
    m = collect_system_metrics()
    cpu = safe_metric(m.get("cpu"))
    ram = safe_metric(m.get("ram"))
    personality = mode_personality(mode)
    factor = personality["lr_factor"]
    if cpu > 80 or ram > 80:
        factor *= 0.7
    elif cpu < 40 and ram < 40:
        factor *= 1.2
    return base_lr * factor

def self_heal_models():
    global TEACHER, SHADOW_TEACHER, SWARM_STUDENTS, EMA_TEACHER_LOSS, EMA_SWARM_LOSS, LAST_SELF_HEAL
    now = time.time()
    if now - LAST_SELF_HEAL < SELF_HEAL_COOLDOWN:
        return
    if EMA_TEACHER_LOSS is not None and EMA_TEACHER_LOSS > SELF_HEAL_THRESHOLD:
        print("[SELF-HEAL] Teacher loss too high, resetting teacher weights")
        safe_in = IN_FEATURES if IN_FEATURES is not None else FALLBACK_FEATURE_DIM
        if USE_TORCH_MODELS and HAS_TORCH:
            TEACHER = TeacherTorch(safe_in)
            SHADOW_TEACHER = ShadowTeacherTorch(safe_in)
        else:
            TEACHER = TeacherNP(safe_in)
            SHADOW_TEACHER = ShadowTeacherNP(safe_in)
        EMA_TEACHER_LOSS = None
        LATEST_STATUS["self_heal_events"] += 1
        LAST_SELF_HEAL = now
    if EMA_SWARM_LOSS is not None and EMA_SWARM_LOSS > SELF_HEAL_THRESHOLD:
        print("[SELF-HEAL] Swarm loss too high, resetting swarm")
        init_swarm(len(SWARM_STUDENTS))
        EMA_SWARM_LOSS = None
        LATEST_STATUS["self_heal_events"] += 1
        LAST_SELF_HEAL = now

def init_teacher_models():
    global TEACHER, SHADOW_TEACHER
    safe_in = IN_FEATURES if IN_FEATURES is not None else FALLBACK_FEATURE_DIM
    if USE_TORCH_MODELS and HAS_TORCH:
        TEACHER = TeacherTorch(safe_in)
        SHADOW_TEACHER = ShadowTeacherTorch(safe_in)
        print("[TEACHER] Torch models initialized")
    else:
        TEACHER = TeacherNP(safe_in)
        SHADOW_TEACHER = ShadowTeacherNP(safe_in)
        print("[TEACHER] NumPy models initialized")

def teacher_loop():
    global TEACHER, SHADOW_TEACHER, IN_FEATURES, STOP_FLAG
    global EMA_TEACHER_LOSS, EMA_SHADOW_LOSS
    print("[TEACHER] Teacher threads started")
    while IN_FEATURES is None and not STOP_FLAG:
        time.sleep(0.5)
    init_teacher_models()
    ema_alpha = 0.9
    if USE_TORCH_MODELS and HAS_TORCH:
        criterion = nn.MSELoss()
        opt_main = optim.Adam(TEACHER.parameters(), lr=adaptive_lr(1e-3))
        opt_shadow = optim.Adam(SHADOW_TEACHER.parameters(), lr=adaptive_lr(8e-4))
    else:
        criterion = None
        opt_main = None
        opt_shadow = None
    while not STOP_FLAG:
        try:
            xb, yb = DATA_QUEUE.get(timeout=2.0)
            mode = LATEST_STATUS["mode"]
            if USE_TORCH_MODELS and HAS_TORCH:
                xb_t = torch.tensor(xb, dtype=torch.float32, device="cpu")
                yb_t = torch.tensor(yb, dtype=torch.float32, device="cpu").reshape(-1, 1)
                opt_main.param_groups[0]["lr"] = adaptive_lr(1e-3, mode)
                opt_shadow.param_groups[0]["lr"] = adaptive_lr(8e-4, mode)
                TEACHER.train()
                SHADOW_TEACHER.train()
                preds_main = TEACHER(xb_t)
                preds_shadow = SHADOW_TEACHER(xb_t)
                loss_main = criterion(preds_main, yb_t)
                loss_shadow = criterion(preds_shadow, yb_t)
                opt_main.zero_grad()
                loss_main.backward()
                opt_main.step()
                opt_shadow.zero_grad()
                loss_shadow.backward()
                opt_shadow.step()
                lm = float(loss_main.item())
                ls = float(loss_shadow.item())
            else:
                yb_np = yb.reshape(-1, 1)
                preds_main = TEACHER.forward(xb)
                preds_shadow = SHADOW_TEACHER.forward(xb)
                err_main = preds_main - yb_np
                err_shadow = preds_shadow - yb_np
                lm = float(np.mean(err_main ** 2))
                ls = float(np.mean(err_shadow ** 2))
                noise_scale = 0.0001
                TEACHER.b4 -= noise_scale * np.mean(err_main, axis=0)
                SHADOW_TEACHER.b3 -= noise_scale * np.mean(err_shadow, axis=0)
            if EMA_TEACHER_LOSS is None:
                EMA_TEACHER_LOSS = lm
            else:
                EMA_TEACHER_LOSS = ema_alpha * EMA_TEACHER_LOSS + (1 - ema_alpha) * lm
            if EMA_SHADOW_LOSS is None:
                EMA_SHADOW_LOSS = ls
            else:
                EMA_SHADOW_LOSS = ema_alpha * EMA_SHADOW_LOSS + (1 - ema_alpha) * ls
            LATEST_STATUS["ema_teacher_loss"] = EMA_TEACHER_LOSS
            LATEST_STATUS["ema_shadow_loss"] = EMA_SHADOW_LOSS
            LATEST_STATUS["last_update"] = time.time()
            self_heal_models()
        except queue.Empty:
            time.sleep(0.5)
        except Exception as e:
            print("[TEACHER] Exception:", e)
            traceback.print_exc()
            time.sleep(2.0)

def init_swarm(n=10):
    global SWARM_STUDENTS, IN_FEATURES
    safe_in = IN_FEATURES if IN_FEATURES is not None else FALLBACK_FEATURE_DIM
    if USE_TORCH_MODELS and HAS_TORCH:
        SWARM_STUDENTS = [StudentTorch(safe_in) for _ in range(n)]
    else:
        SWARM_STUDENTS = [StudentNP(safe_in) for _ in range(n)]
    print(f"[SWARM] Initialized {n} nodes")

def adaptive_alpha():
    if EMA_TEACHER_LOSS is None:
        return 0.5
    if EMA_TEACHER_LOSS > 5.0:
        return 0.7
    elif EMA_TEACHER_LOSS < 1.0:
        return 0.3
    else:
        return 0.5

def mutate_student_np(student, mode="Idle"):
    personality = mode_personality(mode)
    rate = personality["mutation_rate"]
    if random.random() < rate:
        student.b2 += np.random.randn(*student.b2.shape).astype(np.float32) * 0.001

def mutate_student_torch(student, mode="Idle"):
    personality = mode_personality(mode)
    rate = personality["mutation_rate"]
    with torch.no_grad():
        for p in student.parameters():
            if torch.rand(1).item() < rate:
                noise = torch.randn_like(p) * 0.01
                p.add_(noise)

def log_swarm_evolution(loss_value):
    try:
        if not os.path.exists(SWARM_LOG_FILE):
            with open(SWARM_LOG_FILE, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["timestamp", "ema_swarm_loss"])
        with open(SWARM_LOG_FILE, "a", newline="") as f:
            writer = csv.writer(f)
            writer.writerow([time.time(), loss_value])
        LATEST_STATUS["swarm_snapshot"] = {
            "timestamp": time.time(),
            "ema_swarm_loss": loss_value,
            "nodes": len(SWARM_STUDENTS),
        }
    except Exception:
        pass

def student_node_loop(node_id):
    global TEACHER, SWARM_STUDENTS, STOP_FLAG, EMA_SWARM_LOSS
    print(f"[SWARM-{node_id}] Node started")
    ema_alpha = 0.9
    if USE_TORCH_MODELS and HAS_TORCH:
        criterion = nn.MSELoss()
        opt = optim.Adam(SWARM_STUDENTS[node_id].parameters(), lr=adaptive_lr(1e-3))
    else:
        criterion = None
        opt = None
    while TEACHER is None and not STOP_FLAG:
        time.sleep(0.5)
    while not STOP_FLAG:
        try:
            xb, yb = DATA_QUEUE.get(timeout=2.0)
            mode = LATEST_STATUS["mode"]
            alpha = adaptive_alpha()
            if USE_TORCH_MODELS and HAS_TORCH:
                xb_t = torch.tensor(xb, dtype=torch.float32, device="cpu")
                yb_t = torch.tensor(yb, dtype=torch.float32, device="cpu").reshape(-1, 1)
                with torch.no_grad():
                    teacher_soft = TEACHER(xb_t)
                preds = SWARM_STUDENTS[node_id](xb_t)
                loss_teacher = nn.MSELoss()(preds, teacher_soft)
                loss_true = nn.MSELoss()(preds, yb_t)
                loss = alpha * loss_teacher + (1 - alpha) * loss_true
                opt.param_groups[0]["lr"] = adaptive_lr(1e-3, mode)
                opt.zero_grad()
                loss.backward()
                opt.step()
                mutate_student_torch(SWARM_STUDENTS[node_id], mode)
                lv = float(loss.item())
            else:
                yb_np = yb.reshape(-1, 1)
                teacher_soft = TEACHER.forward(xb)
                preds = SWARM_STUDENTS[node_id].forward(xb)
                loss_teacher = np.mean((preds - teacher_soft) ** 2)
                loss_true = np.mean((preds - yb_np) ** 2)
                lv = alpha * loss_teacher + (1 - alpha) * loss_true
                mutate_student_np(SWARM_STUDENTS[node_id], mode)
            if EMA_SWARM_LOSS is None:
                EMA_SWARM_LOSS = lv
            else:
                EMA_SWARM_LOSS = ema_alpha * EMA_SWARM_LOSS + (1 - ema_alpha) * lv
            LATEST_STATUS["ema_swarm_loss"] = EMA_SWARM_LOSS
            LATEST_STATUS["last_update"] = time.time()
            log_swarm_evolution(EMA_SWARM_LOSS)
            self_heal_models()
        except queue.Empty:
            time.sleep(0.5)
        except Exception as e:
            print(f"[SWARM-{node_id}] Exception:", e)
            traceback.print_exc()
            time.sleep(2.0)

# ---------------------------------------------------------
# ANOMALY / LSTM
# ---------------------------------------------------------
def init_anomaly_model():
    global ANOMALY_MODEL
    if USE_TORCH_MODELS and HAS_TORCH:
        ANOMALY_MODEL = AnomalyAutoencoderTorch(input_dim=5)
        print("[ANOMALY] Torch autoencoder initialized")
    else:
        ANOMALY_MODEL = AnomalyAutoencoderNP(input_dim=5)
        print("[ANOMALY] NumPy autoencoder initialized")

def anomaly_loop():
    global ANOMALY_MODEL, STOP_FLAG, EMA_ANOMALY_LOSS
    print("[ANOMALY] Anomaly loop started")
    if ANOMALY_MODEL is None:
        init_anomaly_model()
    ema_alpha = 0.9
    if USE_TORCH_MODELS and HAS_TORCH:
        criterion = nn.MSELoss()
        opt = optim.Adam(ANOMALY_MODEL.parameters(), lr=1e-3)
    else:
        criterion = None
        opt = None
    while not STOP_FLAG:
        try:
            if len(STATE_HISTORY) < 10:
                time.sleep(2)
                continue
            if LATEST_STATUS.get("borg_evolution", False) and random.random() < 0.15:
                inject_anomaly()
            batch = STATE_HISTORY[-64:]
            x = np.stack([v for t, v, p, e in batch], axis=0)
            if USE_TORCH_MODELS and HAS_TORCH:
                x_t = torch.tensor(x, dtype=torch.float32, device="cpu")
                recon = ANOMALY_MODEL(x_t)
                loss = criterion(recon, x_t)
                opt.zero_grad()
                loss.backward()
                opt.step()
                lv = float(loss.item())
            else:
                recon = ANOMALY_MODEL.forward(x)
                lv = float(np.mean((recon - x) ** 2))
            if EMA_ANOMALY_LOSS is None:
                EMA_ANOMALY_LOSS = lv
            else:
                EMA_ANOMALY_LOSS = ema_alpha * EMA_ANOMALY_LOSS + (1 - ema_alpha) * lv
            LATEST_STATUS["ema_anomaly_loss"] = EMA_ANOMALY_LOSS
            LATEST_STATUS["anomaly_score"] = lv
            time.sleep(5)
        except Exception as e:
            print("[ANOMALY] Exception:", e)
            traceback.print_exc()
            time.sleep(5)

def init_lstm_model():
    global LSTM_MODEL
    if USE_TORCH_MODELS and HAS_TORCH:
        LSTM_MODEL = LSTMPredictorTorch(feature_dim=5, hidden_dim=64, num_layers=2)
        print("[LSTM] Torch predictor initialized")
    else:
        LSTM_MODEL = LSTMPredictorNP(feature_dim=5, hidden_dim=64)
        print("[LSTM] NumPy predictor initialized")

def lstm_loop():
    global LSTM_MODEL, STOP_FLAG, EMA_LSTM_LOSS
    print("[LSTM] Temporal prediction loop started")
    if LSTM_MODEL is None:
        init_lstm_model()
    ema_alpha = 0.9
    horizon_raw = LATEST_STATUS.get("prediction_horizon_sec")
    if horizon_raw is None:
        horizon_raw = 10.0
    try:
        horizon = int(horizon_raw)
    except Exception:
        horizon = 10
    if USE_TORCH_MODELS and HAS_TORCH:
        criterion = nn.MSELoss()
        opt = optim.Adam(LSTM_MODEL.parameters(), lr=1e-3)
    else:
        criterion = None
        opt = None
    while not STOP_FLAG:
        try:
            if len(STATE_HISTORY) < 80:
                time.sleep(2)
                continue
            seq_len = 40
            batch_states = STATE_HISTORY[-(seq_len + horizon):]
            seq = np.stack([v for t, v, p, e in batch_states[:seq_len]], axis=0)
            target_perf = batch_states[-1][2]
            if USE_TORCH_MODELS and HAS_TORCH:
                x_seq = torch.tensor(seq, dtype=torch.float32, device="cpu").unsqueeze(0)
                y_t = torch.tensor([[target_perf]], dtype=torch.float32, device="cpu")
                pred = LSTM_MODEL(x_seq)
                loss = criterion(pred, y_t)
                opt.zero_grad()
                loss.backward()
                opt.step()
                lv = float(loss.item())
                pred_val = float(pred.item())
            else:
                pred_np = LSTM_MODEL.forward(seq)
                lv = float(np.mean((pred_np - target_perf) ** 2))
                pred_val = float(pred_np.item())
            if EMA_LSTM_LOSS is None:
                EMA_LSTM_LOSS = lv
            else:
                EMA_LSTM_LOSS = ema_alpha * EMA_LSTM_LOSS + (1 - ema_alpha) * lv
            LATEST_STATUS["ema_lstm_loss"] = EMA_LSTM_LOSS
            LATEST_STATUS["predicted_perf_score"] = pred_val
            conf = max(0.0, 1.0 / (1.0 + EMA_LSTM_LOSS))
            LATEST_STATUS["prediction_confidence"] = conf
            time.sleep(5)
        except Exception as e:
            print("[LSTM] Exception:", e)
            traceback.print_exc()
            time.sleep(5)

# ---------------------------------------------------------
# RL POLICY
# ---------------------------------------------------------
def init_rl_policy():
    global RL_POLICY
    if USE_TORCH_MODELS and HAS_TORCH:
        RL_POLICY = RLPolicyNetTorch(state_dim=7, action_dim=3)
        print("[RL] Torch policy initialized")
    else:
        RL_POLICY = RLPolicyNetNP(state_dim=7, action_dim=3)
        print("[RL] NumPy policy initialized")

def rl_choose_action(state_vec):
    global RL_POLICY
    if USE_TORCH_MODELS and HAS_TORCH:
        with torch.no_grad():
            logits = RL_POLICY(torch.tensor(state_vec, dtype=torch.float32, device="cpu").unsqueeze(0))
            probs = torch.softmax(logits, dim=-1).squeeze(0).cpu().numpy()
    else:
        logits = RL_POLICY.forward(state_vec)
        exps = np.exp(logits - np.max(logits))
        probs = exps / np.sum(exps)
    action_idx = int(np.random.choice(len(probs), p=probs))
    return action_idx, probs[action_idx]

def rl_apply_action(action_idx, ext, mode):
    actions_taken = []
    if not HAS_PSUTIL:
        return actions_taken
    if action_idx == 1:
        for pid, name, cpu, mem in ext["server_procs"]:
            try:
                p = psutil.Process(pid)
                if os.name == "nt":
                    p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                else:
                    p.nice(10)
                actions_taken.append(f"[RL] Throttled server process {name} (pid={pid}).")
            except Exception:
                continue
    elif action_idx == 2:
        for p in psutil.process_iter(attrs=["name", "pid", "cpu_percent"]):
            try:
                name = (p.info["name"] or "").lower()
                if not any(h.lower() in name for h in GAME_PROCESS_HINTS):
                    if os.name == "nt":
                        p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                    else:
                        p.nice(15)
                    actions_taken.append(f"[RL] Aggressively throttled non-game process {name} (pid={p.info['pid']}).")
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    return actions_taken

def rl_compute_reward(prev_perf, new_perf, anomaly_score):
    delta = new_perf - prev_perf
    reward = delta - 5.0 * anomaly_score
    return reward

def rl_loop():
    global RL_POLICY, STOP_FLAG
    print("[RL] Reinforcement learning loop started")
    if RL_POLICY is None:
        init_rl_policy()
    if USE_TORCH_MODELS and HAS_TORCH:
        optimizer = optim.Adam(RL_POLICY.parameters(), lr=1e-3)
    else:
        optimizer = None
    while not STOP_FLAG:
        try:
            if len(STATE_HISTORY) < 5:
                time.sleep(5)
                continue
            _, vec, perf_prev, _ = STATE_HISTORY[-1]
            mode = LATEST_STATUS["mode"]
            mode_idx = float(MODES.index(mode)) / float(len(MODES))
            fps = LATEST_STATUS["fps_current"]
            state_vec = np.array([
                vec[0], vec[1], vec[2], vec[3], fps, perf_prev, mode_idx
            ], dtype=np.float32)
            action_idx, prob = rl_choose_action(state_vec)
            ext = collect_external_sensors()
            actions_taken = rl_apply_action(action_idx, ext, mode)
            features, _, perf_new = append_system_data()
            anomaly_score = LATEST_STATUS.get("anomaly_score", 0.0)
            reward = rl_compute_reward(perf_prev, perf_new, anomaly_score)
            LATEST_STATUS["rl_last_reward"] = reward
            LATEST_STATUS["rl_last_action"] = action_idx
            LATEST_STATUS["last_actions"].extend(actions_taken)
            if USE_TORCH_MODELS and HAS_TORCH:
                optimizer.zero_grad()
                logits = RL_POLICY(torch.tensor(state_vec, dtype=torch.float32, device="cpu").unsqueeze(0))
                log_probs = torch.log_softmax(logits, dim=-1)
                loss = -log_probs[0, action_idx] * reward
                loss.backward()
                optimizer.step()
            time.sleep(5)
        except Exception as e:
            print("[RL] Exception:", e)
            traceback.print_exc()
            time.sleep(5)

# ---------------------------------------------------------
# DQN
# ---------------------------------------------------------
def init_dqn(state_dim=7, action_dim=4):
    global DQN_POLICY, DQN_TARGET
    if USE_TORCH_MODELS and HAS_TORCH:
        DQN_POLICY = DQNNetTorch(state_dim, action_dim)
        DQN_TARGET = DQNNetTorch(state_dim, action_dim)
        DQN_TARGET.load_state_dict(DQN_POLICY.state_dict())
        print("[DQN] Torch DQN initialized")
    else:
        DQN_POLICY = DQNNetNP(state_dim, action_dim)
        DQN_TARGET = DQNNetNP(state_dim, action_dim)
        print("[DQN] NumPy DQN initialized")

def dqn_store_transition(s, a, r, s2, done):
    global DQN_MEMORY
    if len(DQN_MEMORY) >= DQN_MEMORY_CAPACITY:
        DQN_MEMORY.pop(0)
    DQN_MEMORY.append((s, a, r, s2, done))

def dqn_choose_action(state_vec):
    global DQN_POLICY, DQN_EPSILON
    if random.random() < DQN_EPSILON:
        return random.randint(0, 3)
    if USE_TORCH_MODELS and HAS_TORCH:
        with torch.no_grad():
            q = DQN_POLICY(torch.tensor(state_vec, dtype=torch.float32, device="cpu").unsqueeze(0))
            a = int(torch.argmax(q, dim=-1).item())
    else:
        q = DQN_POLICY.forward(state_vec)
        a = int(np.argmax(q))
    return a

def dqn_loop():
    global DQN_POLICY, DQN_TARGET, DQN_EPSILON, STOP_FLAG
    print("[DQN] DQN loop started")
    if DQN_POLICY is None or DQN_TARGET is None:
        init_dqn()
    if USE_TORCH_MODELS and HAS_TORCH:
        optimizer = optim.Adam(DQN_POLICY.parameters(), lr=1e-3)
        mse = nn.MSELoss()
    else:
        optimizer = None
        mse = None
    while not STOP_FLAG:
        try:
            if len(STATE_HISTORY) < 5:
                time.sleep(5)
                continue
            _, vec, perf_prev, _ = STATE_HISTORY[-1]
            mode = LATEST_STATUS["mode"]
            mode_idx = float(MODES.index(mode)) / float(len(MODES))
            fps = LATEST_STATUS["fps_current"]
            state_vec = np.array([
                vec[0], vec[1], vec[2], vec[3], fps, perf_prev, mode_idx
            ], dtype=np.float32)
            action = dqn_choose_action(state_vec)
            ext = collect_external_sensors()
            actions_taken = rl_apply_action(action, ext, mode)
            features, _, perf_new = append_system_data()
            anomaly_score = LATEST_STATUS.get("anomaly_score", 0.0)
            reward = rl_compute_reward(perf_prev, perf_new, anomaly_score)
            _, vec2, _, _ = STATE_HISTORY[-1]
            fps2 = LATEST_STATUS["fps_current"]
            state_vec2 = np.array([
                vec2[0], vec2[1], vec2[2], vec2[3], fps2, perf_new, mode_idx
            ], dtype=np.float32)
            done = False
            dqn_store_transition(state_vec, action, reward, state_vec2, done)
            LATEST_STATUS["dqn_last_reward"] = reward
            LATEST_STATUS["dqn_last_action"] = action
            LATEST_STATUS["last_actions"].extend(actions_taken)
            if len(DQN_MEMORY) >= DQN_BATCH_SIZE:
                batch = random.sample(DQN_MEMORY, DQN_BATCH_SIZE)
                s_batch = np.stack([b[0] for b in batch], axis=0)
                a_batch = np.array([b[1] for b in batch], dtype=np.int64)
                r_batch = np.array([b[2] for b in batch], dtype=np.float32)
                s2_batch = np.stack([b[3] for b in batch], axis=0)
                done_batch = np.array([b[4] for b in batch], dtype=np.float32)
                if USE_TORCH_MODELS and HAS_TORCH:
                    s_t = torch.tensor(s_batch, dtype=torch.float32, device="cpu")
                    s2_t = torch.tensor(s2_batch, dtype=torch.float32, device="cpu")
                    r_t = torch.tensor(r_batch, dtype=torch.float32, device="cpu")
                    done_t = torch.tensor(done_batch, dtype=torch.float32, device="cpu")
                    a_t = torch.tensor(a_batch, dtype=torch.int64, device="cpu")
                    q = DQN_POLICY(s_t)
                    q_a = q.gather(1, a_t.unsqueeze(1)).squeeze(1)
                    with torch.no_grad():
                        q2 = DQN_TARGET(s2_t)
                        q2_max = torch.max(q2, dim=1)[0]
                    target = r_t + DQN_GAMMA * q2_max * (1.0 - done_t)
                    loss = mse(q_a, target)
                    optimizer.zero_grad()
                    loss.backward()
                    optimizer.step()
                else:
                    q = DQN_POLICY.forward(s_batch)
                    q2 = DQN_TARGET.forward(s2_batch)
                    q_a = q[np.arange(len(q)), a_batch]
                    q2_max = np.max(q2, axis=1)
                    target = r_batch + DQN_GAMMA * q2_max * (1.0 - done_batch)
                    DQN_POLICY.b3 -= 0.001 * np.mean(q_a - target)
                DQN_EPSILON = max(DQN_MIN_EPSILON, DQN_EPSILON * DQN_EPSILON_DECAY)
            time.sleep(5)
        except Exception as e:
            print("[DQN] Exception:", e)
            traceback.print_exc()
            time.sleep(5)

# ---------------------------------------------------------
# HTTP STATUS SERVER
# ---------------------------------------------------------
def start_http_server():
    if HAS_FLASK:
        app = Flask(__name__)
        @app.route("/status", methods=["GET"])
        def status():
            return jsonify(LATEST_STATUS)
        def run_flask():
            print(f"[HTTP] Flask server on port {CURRENT_PORT}")
            app.run(host="127.0.0.1", port=CURRENT_PORT, debug=False, use_reloader=False)
        t = threading.Thread(target=run_flask, daemon=True)
        t.start()
    else:
        from http.server import BaseHTTPRequestHandler, HTTPServer
        import json
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                if self.path == "/status":
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.end_headers()
                    self.wfile.write(json.dumps(LATEST_STATUS).encode("utf-8"))
                else:
                    self.send_response(404)
                    self.end_headers()
        def run_http():
            try:
                server = HTTPServer(("127.0.0.1", CURRENT_PORT), Handler)
                print(f"[HTTP] Tiny HTTP server on port {CURRENT_PORT}")
                server.serve_forever()
            except Exception as e:
                print("[HTTP] Exception:", e)
        t = threading.Thread(target=run_http, daemon=True)
        t.start()

# ---------------------------------------------------------
# PROFILE STARTERS
# ---------------------------------------------------------
def start_borg_evolution_system():
    print("[PROFILE] BORG EVOLUTION mode starting (maximum intelligence)")
    threading.Thread(target=streaming_ingestion_loop, daemon=True).start()
    threading.Thread(target=teacher_loop, daemon=True).start()
    init_swarm(n=12)
    for i in range(12):
        threading.Thread(target=student_node_loop, args=(i,), daemon=True).start()
    threading.Thread(target=anomaly_loop, daemon=True).start()
    threading.Thread(target=lstm_loop, daemon=True).start()
    threading.Thread(target=rl_loop, daemon=True).start()
    threading.Thread(target=dqn_loop, daemon=True).start()
    threading.Thread(target=port_rotation_loop, daemon=True).start()
    start_http_server()

def start_full_system():
    print("[PROFILE] FULL system starting")
    threading.Thread(target=streaming_ingestion_loop, daemon=True).start()
    threading.Thread(target=teacher_loop, daemon=True).start()
    init_swarm(n=8)
    for i in range(8):
        threading.Thread(target=student_node_loop, args=(i,), daemon=True).start()
    threading.Thread(target=anomaly_loop, daemon=True).start()
    threading.Thread(target=lstm_loop, daemon=True).start()
    threading.Thread(target=rl_loop, daemon=True).start()
    threading.Thread(target=dqn_loop, daemon=True).start()
    threading.Thread(target=port_rotation_loop, daemon=True).start()
    start_http_server()

def start_medium_system():
    print("[PROFILE] MEDIUM system starting")
    threading.Thread(target=streaming_ingestion_loop, daemon=True).start()
    threading.Thread(target=teacher_loop, daemon=True).start()
    init_swarm(n=5)
    for i in range(5):
        threading.Thread(target=student_node_loop, args=(i,), daemon=True).start()
    threading.Thread(target=anomaly_loop, daemon=True).start()
    threading.Thread(target=lstm_loop, daemon=True).start()
    threading.Thread(target=rl_loop, daemon=True).start()
    threading.Thread(target=port_rotation_loop, daemon=True).start()
    start_http_server()

def start_lite_system():
    print("[PROFILE] LITE system starting (auto-pruned for low-RAM)")
    threading.Thread(target=streaming_ingestion_loop, daemon=True).start()
    threading.Thread(target=teacher_loop, daemon=True).start()
    threading.Thread(target=anomaly_loop, daemon=True).start()
    threading.Thread(target=lstm_loop, daemon=True).start()
    start_http_server()

# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------
def main():
    global STOP_FLAG, USE_TORCH_MODELS
    env = detect_environment()
    profile = choose_profile(env)
    LATEST_STATUS["env"] = env
    LATEST_STATUS["profile"] = profile
    if env["is_mobile"] or env["is_low_power"] or not env["has_torch"] or not env["has_compiler"]:
        USE_TORCH_MODELS = False
    else:
        USE_TORCH_MODELS = True
    print("[ENV]", env)
    print("[PROFILE]", profile, "| USE_TORCH_MODELS =", USE_TORCH_MODELS)
    if profile == "borg_evolution":
        start_borg_evolution_system()
    elif profile == "full":
        start_full_system()
    elif profile == "medium":
        start_medium_system()
    else:
        start_lite_system()
    try:
        while True:
            time.sleep(1.0)
            if predict_pressure_spike():
                LATEST_STATUS["predicted_pressure_spike"] = True
            else:
                LATEST_STATUS["predicted_pressure_spike"] = False
    except KeyboardInterrupt:
        STOP_FLAG = True
        print("[BORG] Shutdown requested")

if __name__ == "__main__":
    main()
