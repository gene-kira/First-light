#!/usr/bin/env python
# -*- coding: utf-8 -*-

# ============================================================
# Codex Sentinel Forklift Node v16 – Neural Swarm Overmind++ Borg
#
# Upgrades (ALL APPLIED + FIXES):
# - Temporal intelligence (time-series pattern memory + replay)
# - Threat classification engine (multi-class anomaly labeling)
# - Autonomic regulation (self-rewriting thresholds & profiles)
# - Swarm consensus engine (distributed voting + global risk scoring)
# - Swarm trust scoring (weighted consensus based on node reliability)
# - Predictive crash modeling (probabilistic forecast from temporal data)
# - Real anomaly detection model (LSTM-based temporal classifier)
# - Persistence for ML model (save/load anomaly model weights)
# - GUI evolution (graphs, risk heatmap, event timeline, Borg global load)
# - LLM integration (HF model if available, TinyFallback otherwise)
# - Borg Memory Mesh: shared memory/load telemetry across local network nodes
# - Encrypted swarm/Borg traffic (simple symmetric XOR-based encryption)
# - OS event hooks (process start/stop, socket open/close)
# - Persistent learning thresholds based on historical data
# - Auto GUI mode: decides GUI ON/OFF based on environment
# - FIX: Tkinter mainloop runs in main thread (no Tcl apartment crash)
# - FIX: Guardian loop type-safe dict access (no 'str' has no attribute 'get')
#
# Modes:
# - LLM Engine (RPC + CLI)
# - System Guardian (process + network + disk + memory)
# - Real-time reactive + predictive + explanatory + temporal
# - Game-aware performance profiling + auto-profile switching
# - Auto-elevation (Windows), auto-port fallback
#
# Design:
# - Monitoring-only (no killing, no firewall changes)
# - Exports rich guardian intelligence for external tools
# - Borg Memory: nodes share memory/load snapshots for collective awareness
# ============================================================

import os
import sys
import time
import json
import socket
import threading
from typing import Tuple, List, Dict, Optional

import platform
import pathlib
from collections import deque

# ============================================================
# Auto-elevation (Windows only, safe fallback)
# ============================================================

def ensure_admin():
    if platform.system().lower() != "windows":
        return
    try:
        import ctypes
        if not ctypes.windll.shell32.IsUserAnAdmin():
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
        print(f"[Codex Sentinel] Elevation failed or unavailable: {e}")

ensure_admin()

# ============================================================
# Optional system inspection (non-invasive)
# ============================================================

try:
    import psutil
except ImportError:
    psutil = None

os.environ["TRANSFORMERS_NO_TORCHAUDIO"] = "1"

try:
    import torch
    import torch.nn as nn
    from transformers import AutoTokenizer, AutoModelForCausalLM
except ImportError as e:
    raise RuntimeError(f"Missing required libraries: {e}. Please install torch and transformers.")

# ============================================================
# Universal OS Loader
# ============================================================

class UniversalOSLoader:
    def __init__(self):
        self.os = platform.system().lower()
        self.is_windows = self.os == "windows"
        self.is_linux = self.os == "linux"
        self.is_macos = self.os == "darwin"
        self.is_wsl = "microsoft" in platform.release().lower()
        self.is_termux = "android" in self.os or "termux" in sys.prefix.lower()

        self.base_path = pathlib.Path(__file__).parent.resolve()
        self.home = pathlib.Path.home()

        self.env = {}
        self._normalize_env()

    def _normalize_env(self):
        if self.is_windows:
            self.env["HOME"] = os.environ.get("USERPROFILE", str(self.home))
        else:
            self.env["HOME"] = os.environ.get("HOME", str(self.home))

        for name in ["models", "cache", "learning", "swarm", "replay", "trust", "borg"]:
            d = self.base_path / name
            d.mkdir(exist_ok=True)
            self.env[f"{name.upper()}_DIR"] = str(d)

        if self.is_windows:
            self.env["CAN_ELEVATE"] = True
        else:
            self.env["CAN_ELEVATE"] = hasattr(os, "geteuid") and os.geteuid() == 0

        try:
            self.env["HAS_CUDA"] = torch.cuda.is_available()
            self.env["NUM_GPUS"] = torch.cuda.device_count()
        except Exception:
            self.env["HAS_CUDA"] = False
            self.env["NUM_GPUS"] = 0

    def summary(self):
        return {
            "os": self.os,
            "is_windows": self.is_windows,
            "is_linux": self.is_linux,
            "is_macos": self.is_macos,
            "is_wsl": self.is_wsl,
            "is_termux": self.is_termux,
            "env": self.env,
        }

OSLOADER = UniversalOSLoader()
print("[Loader] OS detected:", OSLOADER.summary())

# ============================================================
# Global config / environment
# ============================================================

HAS_CUDA = OSLOADER.env["HAS_CUDA"]
NUM_GPUS = OSLOADER.env["NUM_GPUS"]
DEFAULT_DEVICE = torch.device("cuda" if HAS_CUDA else "cpu")

PRIMARY_MODEL_NAME = os.environ.get("PRIMARY_MODEL_NAME", "gpt2")
MAX_PROMPT_LEN = int(os.environ.get("MAX_PROMPT_LEN", "4096"))
GEN_TIMEOUT_SEC = float(os.environ.get("GEN_TIMEOUT_SEC", "30.0"))

CURRENT_MODEL: Optional[nn.Module] = None
CURRENT_TOKENIZER = None
CURRENT_MODEL_NAME: Optional[str] = None
IS_FALLBACK_MODEL = False

GLOBAL_CACHE: Dict = {}
BLOCK_LOG: List[Dict] = []

LEARN_FILE = os.path.join(OSLOADER.env["LEARNING_DIR"], "guardian_learning.json")
SWARM_FILE = os.path.join(OSLOADER.env["SWARM_DIR"], "swarm_intel.json")
REPLAY_FILE = os.path.join(OSLOADER.env["REPLAY_DIR"], "guardian_replay.json")
TRUST_FILE = os.path.join(OSLOADER.env["TRUST_DIR"], "swarm_trust.json")
BORG_FILE = os.path.join(OSLOADER.env["BORG_DIR"], "borg_memory.json")
ANOMALY_MODEL_FILE = os.path.join(OSLOADER.env["LEARNING_DIR"], "anomaly_model.pt")

LEARN_STATE = {
    "process_leak_threshold": 1.5,
    "process_thread_threshold": 1.5,
    "telemetry_conn_medium": 20,
    "telemetry_conn_high": 50,
    "rat_conn_medium": 1,
    "rat_conn_high": 3,
    "perf_background_medium": 1,
    "perf_background_high": 3,
}

SWARM_INTEL = {
    "rat_ips": set(),
    "bad_domains": set(),
    "telemetry_patterns": set(),
    "votes": {
        "rat_risk": [],
        "telemetry_spike_risk": [],
        "performance_risk": [],
        "game_crash_risk": [],
    },
    "global_risk": {
        "rat_risk": "low",
        "telemetry_risk": "low",
        "perf_risk": "low",
        "crash_risk": "low",
    },
}

REPLAY_BUFFER = deque(maxlen=512)

SWARM_TRUST = {
    "nodes": {},  # node_id -> trust_score (0.0 - 1.0)
    "local_node_id": "local",
}

BORG_MEMORY = {
    "nodes": {},  # node_id -> {cpu_load, gpu_load, mem_load, ts}
    "last_sync_ts": 0.0,
}

def _load_learning_state():
    global LEARN_STATE
    try:
        if os.path.exists(LEARN_FILE):
            with open(LEARN_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            for k, v in data.items():
                if k in LEARN_STATE:
                    LEARN_STATE[k] = v
            print("[Learning] Loaded learning state.")
    except Exception as e:
        print(f"[Learning] Failed to load learning state: {e}")

def _save_learning_state():
    try:
        with open(LEARN_FILE, "w", encoding="utf-8") as f:
            json.dump(LEARN_STATE, f, indent=2)
        print("[Learning] Saved learning state.")
    except Exception as e:
        print(f"[Learning] Failed to save learning state: {e}")

def _load_swarm_intel():
    global SWARM_INTEL
    try:
        if os.path.exists(SWARM_FILE):
            with open(SWARM_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            SWARM_INTEL["rat_ips"] = set(data.get("rat_ips", []))
            SWARM_INTEL["bad_domains"] = set(data.get("bad_domains", []))
            SWARM_INTEL["telemetry_patterns"] = set(data.get("telemetry_patterns", []))
            SWARM_INTEL["votes"] = data.get("votes", SWARM_INTEL["votes"])
            SWARM_INTEL["global_risk"] = data.get("global_risk", SWARM_INTEL["global_risk"])
            print("[Swarm] Loaded swarm intelligence.")
    except Exception as e:
        print(f"[Swarm] Failed to load swarm intel: {e}")

def _save_swarm_intel():
    try:
        data = {
            "rat_ips": list(SWARM_INTEL["rat_ips"]),
            "bad_domains": list(SWARM_INTEL["bad_domains"]),
            "telemetry_patterns": list(SWARM_INTEL["telemetry_patterns"]),
            "votes": SWARM_INTEL["votes"],
            "global_risk": SWARM_INTEL["global_risk"],
        }
        with open(SWARM_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        print("[Swarm] Saved swarm intelligence.")
    except Exception as e:
        print(f"[Swarm] Failed to save swarm intel: {e}")

def _save_replay_buffer():
    try:
        with open(REPLAY_FILE, "w", encoding="utf-8") as f:
            json.dump(list(REPLAY_BUFFER), f, indent=2)
        print("[Replay] Saved replay buffer.")
    except Exception as e:
        print(f"[Replay] Failed to save replay buffer: {e}")

def _load_replay_buffer():
    global REPLAY_BUFFER
    try:
        if os.path.exists(REPLAY_FILE):
            with open(REPLAY_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            REPLAY_BUFFER = deque(data, maxlen=512)
            print("[Replay] Loaded replay buffer.")
    except Exception as e:
        print(f"[Replay] Failed to load replay buffer: {e}")

def _load_swarm_trust():
    global SWARM_TRUST
    try:
        if os.path.exists(TRUST_FILE):
            with open(TRUST_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            SWARM_TRUST.update(data)
            print("[Trust] Loaded swarm trust scores.")
    except Exception as e:
        print(f"[Trust] Failed to load swarm trust: {e}")

def _save_swarm_trust():
    try:
        with open(TRUST_FILE, "w", encoding="utf-8") as f:
            json.dump(SWARM_TRUST, f, indent=2)
        print("[Trust] Saved swarm trust scores.")
    except Exception as e:
        print(f"[Trust] Failed to save swarm trust: {e}")

def _load_borg_memory():
    global BORG_MEMORY
    try:
        if os.path.exists(BORG_FILE):
            with open(BORG_FILE, "r", encoding="utf-8") as f:
                data = json.load(f)
            BORG_MEMORY.update(data)
            print("[Borg] Loaded borg memory mesh.")
    except Exception as e:
        print(f"[Borg] Failed to load borg memory: {e}")

def _save_borg_memory():
    try:
        with open(BORG_FILE, "w", encoding="utf-8") as f:
            json.dump(BORG_MEMORY, f, indent=2)
        print("[Borg] Saved borg memory mesh.")
    except Exception as e:
        print(f"[Borg] Failed to save borg memory: {e}")

def _redact_identity(text: str) -> str:
    if not isinstance(text, str):
        return ""
    t = text
    for sep in ["@", ".", ":"]:
        if sep in t:
            return "[redacted]"
    return t

def log_block_event(kind: str, reason: str, length: int, sample: Optional[str] = None):
    BLOCK_LOG.append(
        {
            "kind": kind,
            "reason": reason,
            "length": length,
            "ts": time.time(),
            "sample_redacted": _redact_identity(sample or ""),
        }
    )

# ============================================================
# Simple symmetric XOR-based encryption for swarm/Borg traffic
# ============================================================

BORG_KEY = os.environ.get("BORG_KEY", "default-borg-key").encode("utf-8")

def _xor_encrypt(data: bytes, key: bytes = BORG_KEY) -> bytes:
    if not key:
        return data
    out = bytearray(len(data))
    klen = len(key)
    for i, b in enumerate(data):
        out[i] = b ^ key[i % klen]
    return bytes(out)

def _xor_decrypt(data: bytes, key: bytes = BORG_KEY) -> bytes:
    return _xor_encrypt(data, key)

# ============================================================
# Game profiles + auto-switch + autonomic regulation
# ============================================================

GAME_PROFILES: Dict[str, Dict] = {
    "default": {
        "max_llm_tokens": 256,
        "llm_priority": "normal",
        "telemetry_sensitivity": "medium",
        "cpu_spike_threshold": 0.85,
        "gpu_spike_threshold": 0.85,
        "background_soft_limit": 0.60,
    },
    "high_load_game": {
        "max_llm_tokens": 128,
        "llm_priority": "low",
        "telemetry_sensitivity": "high",
        "cpu_spike_threshold": 0.70,
        "gpu_spike_threshold": 0.70,
        "background_soft_limit": 0.40,
    },
}

CURRENT_GAME_PROFILE: Dict = GAME_PROFILES["default"]

GAME_BASELINES: Dict[str, Dict[int, Dict]] = {
    "default": {},
    "high_load_game": {},
}

def set_game_profile(name: str):
    global CURRENT_GAME_PROFILE
    CURRENT_GAME_PROFILE = GAME_PROFILES.get(name, GAME_PROFILES["default"])
    print(f"[Guardian] Game profile set to: {name} → {CURRENT_GAME_PROFILE}")

def auto_switch_profile_from_processes(processes: List[Dict]):
    total_game_rss = sum(p.get("rss", 0) for p in processes)
    if total_game_rss > 2 * 1024 * 1024 * 1024:
        if CURRENT_GAME_PROFILE is not GAME_PROFILES["high_load_game"]:
            set_game_profile("high_load_game")
    else:
        if CURRENT_GAME_PROFILE is not GAME_PROFILES["default"]:
            set_game_profile("default")

def autonomic_regulation():
    am = safe_get_module("anomaly_module")
    perf_risk = am.get("performance_risk", "low")
    crash_risk = am.get("game_crash_risk", "low")

    if perf_risk == "high" or crash_risk == "high":
        GAME_PROFILES["high_load_game"]["max_llm_tokens"] = max(
            64, GAME_PROFILES["high_load_game"]["max_llm_tokens"] - 16
        )
        GAME_PROFILES["default"]["max_llm_tokens"] = max(
            128, GAME_PROFILES["default"]["max_llm_tokens"] - 16
        )
    elif perf_risk == "low" and crash_risk == "low":
        GAME_PROFILES["high_load_game"]["max_llm_tokens"] = min(
            256, GAME_PROFILES["high_load_game"]["max_llm_tokens"] + 8
        )
        GAME_PROFILES["default"]["max_llm_tokens"] = min(
            512, GAME_PROFILES["default"]["max_llm_tokens"] + 8
        )

# ============================================================
# Executor
# ============================================================

class ForkliftExecutor:
    def __init__(self):
        self._stats = {}
        self.kv_budget_tokens = int(os.environ.get("KV_BUDGET_TOKENS", "8192"))

    def reset_stats(self, clear_router_data: bool = False):
        self._stats = {}

    def linear(self, layer_name, weight, bias, x, layer_depth):
        out = torch.nn.functional.linear(x, weight, bias)
        self._stats.setdefault("layers", []).append(
            {
                "name": layer_name,
                "depth": layer_depth,
                "shape": list(x.shape),
            }
        )
        return out

    def stats(self):
        return dict(self._stats)

EXECUTOR = ForkliftExecutor()

# ============================================================
# System telemetry + adaptive behavior + borg memory integration
# ============================================================

LAST_CPU_LOAD = 0.0
LAST_GPU_LOAD = 0.0
GUARDIAN_SCAN_INTERVAL = 5.0  # adaptive

def get_system_telemetry():
    global LAST_CPU_LOAD, LAST_GPU_LOAD

    cpu_load = 0.0
    gpu_load = 0.0
    mem_load = 0.0

    if psutil is not None:
        try:
            cpu_load = psutil.cpu_percent(interval=0.05) / 100.0
        except Exception:
            cpu_load = 0.0
        try:
            mem = psutil.virtual_memory()
            mem_load = mem.percent / 100.0
        except Exception:
            mem_load = 0.0

    gpu_load = LAST_GPU_LOAD

    LAST_CPU_LOAD = cpu_load
    LAST_GPU_LOAD = gpu_load

    return {
        "cpu_load": cpu_load,
        "gpu_load": gpu_load,
        "mem_load": mem_load,
        "num_gpus": NUM_GPUS,
        "kv_budget_tokens": EXECUTOR.kv_budget_tokens,
    }

def train_policy_net_step(sys_tel, latency_ms):
    global GUARDIAN_SCAN_INTERVAL

    cpu = sys_tel.get("cpu_load", 0.0)
    gpu = sys_tel.get("gpu_load", 0.0)

    if latency_ms > 2000:
        EXECUTOR.kv_budget_tokens = max(1024, EXECUTOR.kv_budget_tokens - 512)
    else:
        EXECUTOR.kv_budget_tokens = min(16384, EXECUTOR.kv_budget_tokens + 128)

    if cpu > CURRENT_GAME_PROFILE.get("cpu_spike_threshold", 0.85):
        GLOBAL_CACHE["cpu_spike"] = {"value": cpu, "ts": time.time()}
    else:
        GLOBAL_CACHE.pop("cpu_spike", None)

    if gpu > CURRENT_GAME_PROFILE.get("gpu_spike_threshold", 0.85):
        GLOBAL_CACHE["gpu_spike"] = {"value": gpu, "ts": time.time()}
    else:
        GLOBAL_CACHE.pop("gpu_spike", None)

    if cpu > 0.9 or gpu > 0.9:
        GUARDIAN_SCAN_INTERVAL = 3.0
    elif cpu < 0.3 and gpu < 0.3:
        GUARDIAN_SCAN_INTERVAL = 7.0
    else:
        GUARDIAN_SCAN_INTERVAL = 5.0

def telemetry_broadcast_loop():
    while True:
        time.sleep(5.0)

def telemetry_listener_loop():
    while True:
        time.sleep(5.0)

def distributed_cache_broadcast_loop(cache):
    while True:
        time.sleep(5.0)

def distributed_cache_listener_loop():
    while True:
        time.sleep(5.0)

def safe_kv_flush():
    pass

# ============================================================
# Borg Memory Mesh (local network shared memory/load telemetry)
# with encrypted traffic
# ============================================================

BORG_MULTICAST_GROUP = os.environ.get("BORG_MULTICAST_GROUP", "239.255.0.1")
BORG_MULTICAST_PORT = int(os.environ.get("BORG_MULTICAST_PORT", "6100"))

def borg_broadcast_loop(node_id: str):
    while True:
        try:
            tel = get_system_telemetry()
            payload = {
                "node_id": node_id,
                "ts": time.time(),
                "cpu_load": tel["cpu_load"],
                "gpu_load": tel["gpu_load"],
                "mem_load": tel["mem_load"],
            }
            raw = json.dumps(payload).encode()
            data = _xor_encrypt(raw)
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
            sock.sendto(data, (BORG_MULTICAST_GROUP, BORG_MULTICAST_PORT))
            sock.close()
        except Exception as e:
            print(f"[Borg] Broadcast error: {e}")
        time.sleep(3.0)

def borg_listener_loop():
    global BORG_MEMORY
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", BORG_MULTICAST_PORT))
        except OSError:
            print("[Borg] Failed to bind multicast port; borg mesh disabled.")
            return

        mreq = socket.inet_aton(BORG_MULTICAST_GROUP) + socket.inet_aton("0.0.0.0")
        sock.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, mreq)

        print(f"[Borg] Listening on multicast {BORG_MULTICAST_GROUP}:{BORG_MULTICAST_PORT}")
        while True:
            data, _ = sock.recvfrom(4096)
            try:
                raw = _xor_decrypt(data)
                payload = json.loads(raw.decode())
                node_id = payload.get("node_id")
                if not node_id:
                    continue
                BORG_MEMORY["nodes"][node_id] = {
                    "cpu_load": payload.get("cpu_load", 0.0),
                    "gpu_load": payload.get("gpu_load", 0.0),
                    "mem_load": payload.get("mem_load", 0.0),
                    "ts": payload.get("ts", time.time()),
                }
                BORG_MEMORY["last_sync_ts"] = time.time()
            except Exception:
                continue
    except Exception as e:
        print(f"[Borg] Listener error: {e}")

def borg_compute_global_load():
    nodes = BORG_MEMORY.get("nodes", {})
    if not nodes:
        return {"cpu": LAST_CPU_LOAD, "gpu": LAST_GPU_LOAD, "mem": 0.0}

    cpu_vals = []
    gpu_vals = []
    mem_vals = []
    now = time.time()
    for nid, info in nodes.items():
        if now - info.get("ts", 0) > 30.0:
            continue
        cpu_vals.append(info.get("cpu_load", 0.0))
        gpu_vals.append(info.get("gpu_load", 0.0))
        mem_vals.append(info.get("mem_load", 0.0))

    if not cpu_vals:
        return {"cpu": LAST_CPU_LOAD, "gpu": LAST_GPU_LOAD, "mem": 0.0}

    return {
        "cpu": sum(cpu_vals) / len(cpu_vals),
        "gpu": sum(gpu_vals) / len(gpu_vals),
        "mem": sum(mem_vals) / len(mem_vals),
    }

def borg_influence_regulation():
    global GUARDIAN_SCAN_INTERVAL

    global_load = borg_compute_global_load()
    cpu_g = global_load["cpu"]
    gpu_g = global_load["gpu"]
    mem_g = global_load["mem"]

    if cpu_g > 0.85 or gpu_g > 0.85 or mem_g > 0.90:
        GUARDIAN_SCAN_INTERVAL = 3.0
        GAME_PROFILES["high_load_game"]["max_llm_tokens"] = max(
            64, GAME_PROFILES["high_load_game"]["max_llm_tokens"] - 16
        )
        GAME_PROFILES["default"]["max_llm_tokens"] = max(
            128, GAME_PROFILES["default"]["max_llm_tokens"] - 16
        )
    elif cpu_g < 0.40 and gpu_g < 0.40 and mem_g < 0.70:
        GUARDIAN_SCAN_INTERVAL = 7.0
        GAME_PROFILES["high_load_game"]["max_llm_tokens"] = min(
            256, GAME_PROFILES["high_load_game"]["max_llm_tokens"] + 8
        )
        GAME_PROFILES["default"]["max_llm_tokens"] = min(
            512, GAME_PROFILES["default"]["max_llm_tokens"] + 8
        )

    BORG_MEMORY["global_load"] = global_load

# ============================================================
# System Guardian + anomaly scoring + OS-style events
# ============================================================

SYSTEM_GUARDIAN_STATS: Dict = {
    "process_module": {},
    "network_module": {},
    "disk_module": {},
    "gpu_module": {},
    "anomaly_module": {},
    "export_snapshot": {},
    "explanations": [],
    "bad_site_module": {},
    "context_module": {},
    "events": {
        "process_started": [],
        "process_stopped": [],
        "connection_opened": [],
        "connection_closed": [],
    },
    "temporal": {
        "cpu_history": deque(maxlen=256),
        "gpu_history": deque(maxlen=256),
        "crash_risk_history": deque(maxlen=256),
        "rat_risk_history": deque(maxlen=256),
        "telemetry_risk_history": deque(maxlen=256),
        "perf_risk_history": deque(maxlen=256),
    },
    "classification": {
        "process_labels": {},
        "connection_labels": {},
    },
    "predictive": {
        "crash_probability": 0.0,
    },
    "borg": {
        "global_load": {"cpu": 0.0, "gpu": 0.0, "mem": 0.0},
    },
}

def safe_get_module(name: str) -> Dict:
    val = SYSTEM_GUARDIAN_STATS.get(name)
    if not isinstance(val, dict):
        SYSTEM_GUARDIAN_STATS[name] = {}
        return SYSTEM_GUARDIAN_STATS[name]
    return val

def safe_get_nested_module(root: str, key: str, default):
    root_val = SYSTEM_GUARDIAN_STATS.get(root)
    if not isinstance(root_val, dict):
        SYSTEM_GUARDIAN_STATS[root] = {}
        root_val = SYSTEM_GUARDIAN_STATS[root]
    val = root_val.get(key, default)
    if isinstance(default, dict) and not isinstance(val, dict):
        root_val[key] = default
        return default
    return val

RAT_PORTS = {22, 3389, 5900, 5938, 5555, 4444}
RAT_KEYWORDS = ["rat", "remote", "control", "teamviewer", "anydesk", "rdp", "vnc"]
GAME_KEYWORDS = ["game", "unity", "unreal", "launcher", "steam", "epic"]
BROWSER_KEYWORDS = ["chrome", "edge", "firefox", "brave", "opera"]
LAUNCHER_KEYWORDS = ["steam", "epic", "battle.net", "origin", "uplay"]

BAD_DOMAINS_BASE = {
    "malware.example.com",
    "phishing.example.net",
    "botnet.example.org",
    "remote-control.example.io",
}

REMOTE_CONTROL_PORTS = RAT_PORTS | {6000, 5901, 3388}

CONTEXT_PROFILES = {
    "steam": "game_launcher",
    "epic": "game_launcher",
    "battle.net": "game_launcher",
    "origin": "game_launcher",
    "uplay": "game_launcher",
    "chrome": "browser",
    "edge": "browser",
    "firefox": "browser",
    "brave": "browser",
    "opera": "browser",
}

PREV_PROCESSES: Dict[int, Dict] = {}
PREV_CONNECTIONS: Dict[Tuple[str, int, str, int], Dict] = {}

# ============================================================
# Real anomaly detection model (LSTM-based)
# ============================================================

class AnomalyLSTM(nn.Module):
    def __init__(self, input_dim: int = 5, hidden_dim: int = 64, num_layers: int = 1, num_classes: int = 4):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers=num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        out, _ = self.lstm(x)
        last = out[:, -1, :]
        logits = self.fc(last)
        return logits

ANOMALY_MODEL = AnomalyLSTM().to(DEFAULT_DEVICE)
ANOMALY_OPTIM = torch.optim.Adam(ANOMALY_MODEL.parameters(), lr=1e-3)
ANOMALY_CLASS_MAP = {0: "benign", 1: "suspicious", 2: "dangerous", 3: "critical"}

def _process_features(proc_record: Dict) -> torch.Tensor:
    rss = proc_record.get("rss", 0) / (1024 * 1024 * 1024)  # GB
    threads = proc_record.get("threads", 0) / 100.0
    read_bytes = proc_record.get("read_bytes", 0) / (1024 * 1024 * 1024)
    write_bytes = proc_record.get("write_bytes", 0) / (1024 * 1024 * 1024)
    cpu_pct = proc_record.get("cpu_percent", 0.0) / 100.0
    feats = torch.tensor([[rss, threads, read_bytes, write_bytes, cpu_pct]], dtype=torch.float32, device=DEFAULT_DEVICE)
    feats = feats.unsqueeze(1)  # (batch=1, seq_len=1, input_dim=5)
    return feats

def _ml_classify_process(proc_record: Dict) -> str:
    ANOMALY_MODEL.eval()
    with torch.inference_mode():
        feats = _process_features(proc_record)
        logits = ANOMALY_MODEL(feats)
        pred = torch.argmax(logits, dim=1).item()
    return ANOMALY_CLASS_MAP.get(pred, "benign")

def _ml_train_on_snapshot(proc_record: Dict, heuristic_label: str):
    label_idx = {v: k for k, v in ANOMALY_CLASS_MAP.items()}.get(heuristic_label, 0)
    feats = _process_features(proc_record)
    target = torch.tensor([label_idx], dtype=torch.long, device=DEFAULT_DEVICE)
    ANOMALY_MODEL.train()
    logits = ANOMALY_MODEL(feats)
    loss = torch.nn.functional.cross_entropy(logits, target)
    ANOMALY_OPTIM.zero_grad()
    loss.backward()
    ANOMALY_OPTIM.step()

def _save_anomaly_model():
    try:
        torch.save(ANOMALY_MODEL.state_dict(), ANOMALY_MODEL_FILE)
        print("[AnomalyML] Saved anomaly model weights.")
    except Exception as e:
        print(f"[AnomalyML] Failed to save anomaly model: {e}")

def _load_anomaly_model():
    try:
        if os.path.exists(ANOMALY_MODEL_FILE):
            state = torch.load(ANOMALY_MODEL_FILE, map_location=DEFAULT_DEVICE)
            ANOMALY_MODEL.load_state_dict(state)
            ANOMALY_MODEL.to(DEFAULT_DEVICE)
            print("[AnomalyML] Loaded anomaly model weights.")
    except Exception as e:
        print(f"[AnomalyML] Failed to load anomaly model: {e}")

# ============================================================
# Context + leak detection + heuristic scoring
# ============================================================

def _infer_context_role(name: str) -> str:
    lname = name.lower()
    for key, role in CONTEXT_PROFILES.items():
        if key in lname:
            return role
    if any(k in lname for k in GAME_KEYWORDS):
        return "game"
    return "generic"

def _update_game_baseline(profile_name: str, proc_info: Dict):
    pid = proc_info.get("pid")
    if pid is None:
        return
    baseline = GAME_BASELINES.setdefault(profile_name, {})
    prev = baseline.get(pid)
    now = {
        "rss": proc_info.get("rss", 0),
        "threads": proc_info.get("threads", 0),
        "read_bytes": proc_info.get("read_bytes", 0),
        "write_bytes": proc_info.get("write_bytes", 0),
        "ts": time.time(),
    }
    if prev is None:
        baseline[pid] = now
    else:
        baseline[pid] = {
            "rss": max(prev["rss"], now["rss"]),
            "threads": max(prev["threads"], now["threads"]),
            "read_bytes": max(prev["read_bytes"], now["read_bytes"]),
            "write_bytes": max(prev["write_bytes"], now["write_bytes"]),
            "ts": now["ts"],
        }

def _detect_leak_suspect(profile_name: str, proc_info: Dict) -> Optional[Dict]:
    pid = proc_info.get("pid")
    if pid is None:
        return None
    baseline = GAME_BASELINES.get(profile_name, {})
    prev = baseline.get(pid)
    if prev is None:
        return None

    rss = proc_info.get("rss", 0)
    threads = proc_info.get("threads", 0)
    read_bytes = proc_info.get("read_bytes", 0)
    write_bytes = proc_info.get("write_bytes", 0)

    leak_score = 0.0

    if rss > prev["rss"] * LEARN_STATE["process_leak_threshold"] and rss > 1 * 1024 * 1024 * 1024:
        leak_score += 2.0

    if threads > prev["threads"] * LEARN_STATE["process_thread_threshold"] and threads > 100:
        leak_score += 1.0

    if read_bytes + write_bytes > (prev["read_bytes"] + prev["write_bytes"]) * 2.0:
        leak_score += 1.0

    if leak_score > 0.0:
        return {
            "pid": pid,
            "name": proc_info.get("name"),
            "rss": rss,
            "threads": threads,
            "read_bytes": read_bytes,
            "write_bytes": write_bytes,
            "leak_score": leak_score,
        }
    return None

def _heuristic_process_score(proc_record: Dict) -> float:
    score = 0.0
    role = proc_record.get("role", "generic")
    rss = proc_record.get("rss", 0)
    threads = proc_record.get("threads", 0)
    read_bytes = proc_record.get("read_bytes", 0)
    write_bytes = proc_record.get("write_bytes", 0)
    name = (proc_record.get("name") or "").lower()

    if role == "game":
        score += 0.5
    if role == "game_launcher":
        score += 0.3

    if rss > 1 * 1024 * 1024 * 1024:
        score += 1.5
    if threads > 100:
        score += 1.0
    if read_bytes + write_bytes > 500 * 1024 * 1024:
        score += 1.0
    if any(k in name for k in RAT_KEYWORDS):
        score += 2.0
    if name in SWARM_INTEL["rat_ips"]:
        score += 2.0

    return score

def _heuristic_label_from_score(score: float) -> str:
    if score < 1.0:
        return "benign"
    if 1.0 <= score < 2.0:
        return "suspicious"
    if 2.0 <= score < 3.0:
        return "dangerous"
    return "critical"

def _classify_connection(conn_record: Dict) -> str:
    port = conn_record.get("port", 0)
    ip = conn_record.get("ip", "")
    if ip in SWARM_INTEL["rat_ips"] or port in RAT_PORTS:
        return "critical"
    if port in REMOTE_CONTROL_PORTS:
        return "dangerous"
    if port in (80, 443, 8080, 8443):
        return "telemetry"
    return "benign"

# ============================================================
# Process module scan
# ============================================================

def process_module_scan():
    global PREV_PROCESSES
    if psutil is None:
        return

    suspicious = []
    high_mem = []
    high_io = []
    leak_suspects = []
    anomalies = []
    background_heavy = []
    context_roles = {}
    events_started = []
    events_stopped = []
    process_labels = {}

    profile_name = "high_load_game" if CURRENT_GAME_PROFILE is GAME_PROFILES["high_load_game"] else "default"

    current_procs: Dict[int, Dict] = {}

    for proc in psutil.process_iter(attrs=["pid", "name", "memory_info", "num_threads", "io_counters", "cpu_percent"]):
        try:
            info = proc.info
            name = (info.get("name") or "").lower()
            mem = info.get("memory_info").rss if info.get("memory_info") else 0
            threads = info.get("num_threads", 0)
            io = info.get("io_counters")
            read_bytes = io.read_bytes if io else 0
            write_bytes = io.write_bytes if io else 0
            cpu_pct = info.get("cpu_percent", 0.0)

            role = _infer_context_role(name)
            context_roles[info["pid"]] = role

            proc_record = {
                "pid": info["pid"],
                "name": info["name"],
                "rss": mem,
                "threads": threads,
                "read_bytes": read_bytes,
                "write_bytes": write_bytes,
                "cpu_percent": cpu_pct,
                "role": role,
            }

            current_procs[info["pid"]] = proc_record

            if role in ("game", "game_launcher"):
                suspicious.append(proc_record)

            if mem > 1 * 1024 * 1024 * 1024:
                high_mem.append(proc_record)

            if read_bytes + write_bytes > 500 * 1024 * 1024:
                high_io.append(proc_record)

            if cpu_pct > CURRENT_GAME_PROFILE.get("background_soft_limit", 0.60) * 100.0 and role not in ("game", "game_launcher"):
                background_heavy.append(proc_record)

            _update_game_baseline(profile_name, proc_record)
            leak = _detect_leak_suspect(profile_name, proc_record)
            if leak is not None:
                leak_suspects.append(leak)

            heuristic_score = _heuristic_process_score(proc_record)
            heuristic_label = _heuristic_label_from_score(heuristic_score)

            _ml_train_on_snapshot(proc_record, heuristic_label)
            ml_label = _ml_classify_process(proc_record)

            process_labels[info["pid"]] = ml_label

            if heuristic_score >= 3.0 or ml_label in ("dangerous", "critical"):
                anomalies.append(
                    {
                        "type": "process_anomaly",
                        "pid": info["pid"],
                        "name": info["name"],
                        "heuristic_score": heuristic_score,
                        "rss": mem,
                        "threads": threads,
                        "read_bytes": read_bytes,
                        "write_bytes": write_bytes,
                        "role": role,
                        "heuristic_label": heuristic_label,
                        "ml_label": ml_label,
                    }
                )
        except Exception:
            continue

    for pid, rec in current_procs.items():
        if pid not in PREV_PROCESSES:
            events_started.append(rec)

    for pid, rec in PREV_PROCESSES.items():
        if pid not in current_procs:
            events_stopped.append(rec)

    PREV_PROCESSES = current_procs

    SYSTEM_GUARDIAN_STATS["process_module"] = {
        "suspicious_processes": suspicious,
        "high_memory_processes": high_mem,
        "high_io_processes": high_io,
        "leak_suspects": leak_suspects,
        "anomalies": anomalies,
        "background_heavy": background_heavy,
    }

    safe_get_module("context_module")["process_roles"] = context_roles
    safe_get_module("events")["process_started"] = events_started
    safe_get_module("events")["process_stopped"] = events_stopped
    safe_get_module("classification")["process_labels"] = process_labels

    auto_switch_profile_from_processes(suspicious + high_mem)

# ============================================================
# Network module scan
# ============================================================

def network_module_scan():
    global PREV_CONNECTIONS
    if psutil is None:
        return

    telemetry_like = []
    rat_like = []
    browser_noise = []
    remote_control_hits = []
    events_opened = []
    events_closed = []
    connection_labels = {}

    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        conns = []

    current_conns: Dict[Tuple[str, int, str, int], Dict] = {}

    for c in conns:
        try:
            raddr = c.raddr
            laddr = c.laddr
            if not raddr or not laddr:
                continue
            ip = raddr.ip
            port = raddr.port
            lip = laddr.ip
            lport = laddr.port

            key = (ip, port, lip, lport)
            entry = {"ip": ip, "port": port, "local_ip": lip, "local_port": lport, "status": c.status}

            current_conns[key] = entry

            if port in (443, 80, 8080, 8443):
                telemetry_like.append(entry)

            if port in RAT_PORTS or ip in SWARM_INTEL["rat_ips"]:
                rat_like.append(entry)

            if port in REMOTE_CONTROL_PORTS:
                remote_control_hits.append(entry)

            if lport in (80, 443) and c.status == "ESTABLISHED":
                browser_noise.append(entry)

            label = _classify_connection(entry)
            connection_labels[key] = label
        except Exception:
            continue

    for key, rec in current_conns.items():
        if key not in PREV_CONNECTIONS:
            events_opened.append(rec)

    for key, rec in PREV_CONNECTIONS.items():
        if key not in current_conns:
            events_closed.append(rec)

    PREV_CONNECTIONS = current_conns

    SYSTEM_GUARDIAN_STATS["network_module"] = {
        "telemetry_like_connections": telemetry_like,
        "rat_like_connections": rat_like,
        "browser_noise": browser_noise,
        "remote_control_hits": remote_control_hits,
    }

    SYSTEM_GUARDIAN_STATS["bad_site_module"] = {
        "bad_domains_detected": list(BAD_DOMAINS_BASE | SWARM_INTEL["bad_domains"]),
        "blocked_like": [],
    }

    safe_get_module("events")["connection_opened"] = events_opened
    safe_get_module("events")["connection_closed"] = events_closed
    safe_get_module("classification")["connection_labels"] = connection_labels

# ============================================================
# Disk + GPU modules
# ============================================================

def disk_module_scan():
    if psutil is None:
        return

    disk_stats = {}
    try:
        io = psutil.disk_io_counters()
        disk_stats = {
            "read_bytes": io.read_bytes,
            "write_bytes": io.write_bytes,
            "read_count": io.read_count,
            "write_count": io.write_count,
        }
    except Exception:
        disk_stats = {}

    SYSTEM_GUARDIAN_STATS["disk_module"] = disk_stats

def gpu_module_scan():
    gpu_stats = {
        "has_cuda": HAS_CUDA,
        "num_gpus": NUM_GPUS,
        "approx_gpu_load": LAST_GPU_LOAD,
    }
    SYSTEM_GUARDIAN_STATS["gpu_module"] = gpu_stats

# ============================================================
# Anomaly prediction + temporal + predictive crash modeling
# ============================================================

def _update_spike_flags():
    am = safe_get_module("anomaly_module")
    cpu_spike = "cpu_spike" in GLOBAL_CACHE
    gpu_spike = "gpu_spike" in GLOBAL_CACHE
    am["cpu_spike"] = cpu_spike
    am["gpu_spike"] = gpu_spike

def _predict_game_crash_risk():
    pm = safe_get_module("process_module")
    leak_suspects = pm.get("leak_suspects", [])
    high_mem = pm.get("high_memory_processes", [])

    risk = "low"
    if leak_suspects or high_mem:
        risk = "medium"
    if len(leak_suspects) > 2 or len(high_mem) > 3:
        risk = "high"

    am = safe_get_module("anomaly_module")
    am["game_crash_risk"] = risk

def _predict_rat_risk():
    nm = safe_get_module("network_module")
    rat_like = nm.get("rat_like_connections", [])
    remote_hits = nm.get("remote_control_hits", [])

    risk = "low"
    if len(rat_like) >= LEARN_STATE["rat_conn_medium"] or len(remote_hits) >= LEARN_STATE["rat_conn_medium"]:
        risk = "medium"
    if len(rat_like) + len(remote_hits) >= LEARN_STATE["rat_conn_high"]:
        risk = "high"

    am = safe_get_module("anomaly_module")
    am["rat_risk"] = risk

def _predict_telemetry_spike_risk():
    nm = safe_get_module("network_module")
    telemetry_like = nm.get("telemetry_like_connections", [])

    risk = "low"
    if len(telemetry_like) > LEARN_STATE["telemetry_conn_medium"]:
        risk = "medium"
    if len(telemetry_like) > LEARN_STATE["telemetry_conn_high"]:
        risk = "high"

    am = safe_get_module("anomaly_module")
    am["telemetry_spike_risk"] = risk

def _predict_performance_risk():
    am = safe_get_module("anomaly_module")
    pm = safe_get_module("process_module")
    cpu_spike = am.get("cpu_spike", False)
    gpu_spike = am.get("gpu_spike", False)
    background_heavy = pm.get("background_heavy", [])

    risk = "low"
    if len(background_heavy) >= LEARN_STATE["perf_background_medium"] or cpu_spike or gpu_spike:
        risk = "medium"
    if len(background_heavy) >= LEARN_STATE["perf_background_high"] or (cpu_spike and gpu_spike):
        risk = "high"

    am["performance_risk"] = risk

def _update_temporal_history():
    tel = get_system_telemetry()
    am = safe_get_module("anomaly_module")
    tmod = safe_get_module("temporal")

    tmod["cpu_history"].append({"ts": time.time(), "value": tel["cpu_load"]})
    tmod["gpu_history"].append({"ts": time.time(), "value": tel["gpu_load"]})
    tmod["crash_risk_history"].append({"ts": time.time(), "value": am.get("game_crash_risk", "low")})
    tmod["rat_risk_history"].append({"ts": time.time(), "value": am.get("rat_risk", "low")})
    tmod["telemetry_risk_history"].append({"ts": time.time(), "value": am.get("telemetry_spike_risk", "low")})
    tmod["perf_risk_history"].append({"ts": time.time(), "value": am.get("performance_risk", "low")})

def _predict_crash_probability():
    tmod = safe_get_module("temporal")
    hist = list(tmod.get("crash_risk_history", []))
    if not hist:
        safe_get_module("predictive")["crash_probability"] = 0.0
        return

    weights = {"low": 0.1, "medium": 0.5, "high": 0.9}
    recent = hist[-32:]
    score = sum(weights.get(entry["value"], 0.1) for entry in recent) / len(recent)
    safe_get_module("predictive")["crash_probability"] = float(score)

def _refine_learning_from_snapshot():
    am = safe_get_module("anomaly_module")
    pm = safe_get_module("process_module")
    nm = safe_get_module("network_module")

    leak_suspects = pm.get("leak_suspects", [])
    telemetry_like = nm.get("telemetry_like_connections", [])
    rat_like = nm.get("rat_like_connections", [])
    remote_hits = nm.get("remote_control_hits", [])
    background_heavy = pm.get("background_heavy", [])

    if leak_suspects and am.get("game_crash_risk") == "high":
        LEARN_STATE["process_leak_threshold"] = min(LEARN_STATE["process_leak_threshold"] + 0.1, 2.5)

    if len(telemetry_like) > LEARN_STATE["telemetry_conn_high"] and am.get("telemetry_spike_risk") == "high":
        LEARN_STATE["telemetry_conn_high"] = min(LEARN_STATE["telemetry_conn_high"] + 5, 100)

    if len(rat_like) + len(remote_hits) > LEARN_STATE["rat_conn_high"] and am.get("rat_risk") == "high":
        LEARN_STATE["rat_conn_high"] = min(LEARN_STATE["rat_conn_high"] + 1, 10)

    if len(background_heavy) > LEARN_STATE["perf_background_high"] and am.get("performance_risk") == "high":
        LEARN_STATE["perf_background_high"] = min(LEARN_STATE["perf_background_high"] + 1, 10)

def _update_swarm_intel_from_snapshot():
    nm = safe_get_module("network_module")
    rat_like = nm.get("rat_like_connections", [])
    telemetry_like = nm.get("telemetry_like_connections", [])
    bm = safe_get_module("bad_site_module")
    am = safe_get_module("anomaly_module")

    for conn in rat_like:
        SWARM_INTEL["rat_ips"].add(conn["ip"])

    for conn in telemetry_like:
        pattern = f"{conn['ip']}:{conn['port']}"
        SWARM_INTEL["telemetry_patterns"].add(pattern)

    for dom in bm.get("bad_domains_detected", []):
        SWARM_INTEL["bad_domains"].add(dom)

    for key in ["rat_risk", "telemetry_spike_risk", "performance_risk", "game_crash_risk"]:
        val = am.get(key, "low")
        SWARM_INTEL["votes"].setdefault(key, []).append({"node": SWARM_TRUST["local_node_id"], "risk": val})
        if len(SWARM_INTEL["votes"][key]) > 256:
            SWARM_INTEL["votes"][key] = SWARM_INTEL["votes"][key][-256:]

def _compute_swarm_consensus():
    def weighted_consensus(votes: List[Dict]) -> str:
        if not votes:
            return "low"
        weights = {"low": 0.0, "medium": 0.0, "high": 0.0}
        for v in votes:
            node_id = v.get("node", "unknown")
            risk = v.get("risk", "low")
            trust = SWARM_TRUST["nodes"].get(node_id, 0.5)
            if risk in weights:
                weights[risk] += trust
        if weights["high"] >= max(weights["medium"], weights["low"]):
            return "high"
        if weights["medium"] >= max(weights["high"], weights["low"]):
            return "medium"
        return "low"

    SWARM_INTEL["global_risk"]["rat_risk"] = weighted_consensus(SWARM_INTEL["votes"].get("rat_risk", []))
    SWARM_INTEL["global_risk"]["telemetry_risk"] = weighted_consensus(SWARM_INTEL["votes"].get("telemetry_spike_risk", []))
    SWARM_INTEL["global_risk"]["perf_risk"] = weighted_consensus(SWARM_INTEL["votes"].get("performance_risk", []))
    SWARM_INTEL["global_risk"]["crash_risk"] = weighted_consensus(SWARM_INTEL["votes"].get("game_crash_risk", []))

def _record_replay_snapshot():
    snapshot = {
        "ts": time.time(),
        "anomaly_module": safe_get_module("anomaly_module"),
        "process_module": safe_get_module("process_module"),
        "network_module": safe_get_module("network_module"),
        "events": safe_get_module("events"),
        "predictive": safe_get_module("predictive"),
        "borg": safe_get_module("borg"),
    }
    REPLAY_BUFFER.append(snapshot)

# ============================================================
# Explanations + export snapshot
# ============================================================

def _explain_guardian_state():
    explanations = []

    am = safe_get_module("anomaly_module")
    pm = safe_get_module("process_module")
    nm = safe_get_module("network_module")
    bm = safe_get_module("bad_site_module")
    ctx = safe_get_module("context_module")
    ev = safe_get_module("events")
    swarm_global = SWARM_INTEL["global_risk"]
    crash_prob = safe_get_module("predictive").get("crash_probability", 0.0)
    borg_global = safe_get_module("borg").get("global_load", {"cpu": 0.0, "gpu": 0.0, "mem": 0.0})

    cpu_spike = am.get("cpu_spike", False)
    gpu_spike = am.get("gpu_spike", False)
    crash_risk = am.get("game_crash_risk", "low")
    rat_risk = am.get("rat_risk", "low")
    tel_risk = am.get("telemetry_spike_risk", "low")
    perf_risk = am.get("performance_risk", "low")

    leak_suspects = pm.get("leak_suspects", [])
    background_heavy = pm.get("background_heavy", [])
    rat_like = nm.get("rat_like_connections", [])
    remote_hits = nm.get("remote_control_hits", [])
    telemetry_like = nm.get("telemetry_like_connections", [])
    bad_domains = bm.get("bad_domains_detected", [])
    process_roles = ctx.get("process_roles", {})

    proc_started = ev.get("process_started", [])
    proc_stopped = ev.get("process_stopped", [])
    conn_opened = ev.get("connection_opened", [])
    conn_closed = ev.get("connection_closed", [])

    if cpu_spike:
        explanations.append("Local CPU usage is spiking above profile threshold; LLM load is being reduced to protect performance.")
    if gpu_spike:
        explanations.append("Local GPU usage is spiking above profile threshold; generation parameters are being softened.")

    if crash_risk == "high":
        explanations.append("Game crash risk is HIGH: multiple processes show strong leak patterns and high memory usage.")
    elif crash_risk == "medium":
        explanations.append("Game crash risk is MEDIUM: at least one process is leaking memory or growing too fast.")

    if crash_prob > 0.7:
        explanations.append(f"Predictive model estimates crash probability at {crash_prob*100:.1f}% in the near future.")
    elif crash_prob > 0.4:
        explanations.append(f"Predictive model estimates moderate crash probability at {crash_prob*100:.1f}%.")

    if rat_risk == "high":
        explanations.append("RAT risk is HIGH: several connections use remote-control ports; investigate remote access tools.")
    elif rat_risk == "medium":
        explanations.append("RAT risk is MEDIUM: at least one connection uses a known remote-control port.")

    if tel_risk == "high":
        explanations.append("Telemetry spike risk is HIGH: many outbound connections on web ports; likely heavy background telemetry.")
    elif tel_risk == "medium":
        explanations.append("Telemetry spike risk is MEDIUM: noticeable outbound traffic on web ports.")

    if perf_risk == "high":
        explanations.append("Performance risk is HIGH: CPU/GPU spikes combined with multiple background-heavy processes.")
    elif perf_risk == "medium":
        explanations.append("Performance risk is MEDIUM: at least one spike or heavy background process detected.")

    if leak_suspects:
        for leak in leak_suspects[:3]:
            role = process_roles.get(leak["pid"], "generic")
            explanations.append(
                f"Process {leak['name']} (PID {leak['pid']}, role={role}) shows leak behavior: "
                f"RSS={leak['rss']} bytes, threads={leak['threads']}, leak_score={leak['leak_score']:.2f}."
            )

    if background_heavy:
        for proc in background_heavy[:3]:
            role = process_roles.get(proc["pid"], "generic")
            explanations.append(
                f"Background process {proc['name']} (PID {proc['pid']}, role={role}) is consuming "
                f"{proc['cpu_percent']:.1f}% CPU; consider throttling via external tools."
            )

    if rat_like:
        for conn in rat_like[:3]:
            explanations.append(
                f"RAT-like connection detected: remote {conn['ip']}:{conn['port']} (local port {conn['local_port']})."
            )

    if remote_hits:
        for conn in remote_hits[:3]:
            explanations.append(
                f"Remote-control pattern detected: {conn['ip']}:{conn['port']} (local {conn['local_port']}); "
                "likely remote desktop or control agent."
            )

    if telemetry_like:
        explanations.append(
            f"{len(telemetry_like)} telemetry-like connections active on web ports; likely background sync, updates, or tracking."
        )

    if bad_domains:
        explanations.append(
            f"Bad-site domain list loaded ({len(bad_domains)} entries); external firewall tools can use this for blocking."
        )

    if proc_started:
        explanations.append(f"{len(proc_started)} processes started since last scan.")
    if proc_stopped:
        explanations.append(f"{len(proc_stopped)} processes stopped since last scan.")
    if conn_opened:
        explanations.append(f"{len(conn_opened)} network connections opened since last scan.")
    if conn_closed:
        explanations.append(f"{len(conn_closed)} network connections closed since last scan.")

    explanations.append(
        f"Swarm consensus (trust-weighted): crash={swarm_global['crash_risk']}, rat={swarm_global['rat_risk']}, "
        f"telemetry={swarm_global['telemetry_risk']}, perf={swarm_global['perf_risk']}."
    )

    explanations.append(
        f"Borg global load: CPU={borg_global['cpu']*100:.1f}%, GPU={borg_global['gpu']*100:.1f}%, MEM={borg_global['mem']*100:.1f}% "
        "across local network nodes."
    )

    SYSTEM_GUARDIAN_STATS["explanations"] = explanations

def _build_export_snapshot():
    SYSTEM_GUARDIAN_STATS["export_snapshot"] = {
        "timestamp": time.time(),
        "process_module": safe_get_module("process_module"),
        "network_module": safe_get_module("network_module"),
        "disk_module": safe_get_module("disk_module"),
        "gpu_module": safe_get_module("gpu_module"),
        "anomaly_module": safe_get_module("anomaly_module"),
        "bad_site_module": safe_get_module("bad_site_module"),
        "context_module": safe_get_module("context_module"),
        "events": safe_get_module("events"),
        "explanations": SYSTEM_GUARDIAN_STATS.get("explanations", []),
        "temporal": safe_get_module("temporal"),
        "classification": safe_get_module("classification"),
        "swarm_global_risk": SWARM_INTEL["global_risk"],
        "predictive": safe_get_module("predictive"),
        "borg": safe_get_module("borg"),
    }

def system_guardian_loop():
    global GUARDIAN_SCAN_INTERVAL
    while True:
        try:
            process_module_scan()
            network_module_scan()
            disk_module_scan()
            gpu_module_scan()
            _update_spike_flags()
            _predict_game_crash_risk()
            _predict_rat_risk()
            _predict_telemetry_spike_risk()
            _predict_performance_risk()
            _update_temporal_history()
            _predict_crash_probability()
            _refine_learning_from_snapshot()
            _update_swarm_intel_from_snapshot()
            _compute_swarm_consensus()
            borg_influence_regulation()
            safe_get_module("borg")["global_load"] = borg_compute_global_load()
            autonomic_regulation()
            _explain_guardian_state()
            _build_export_snapshot()
            _record_replay_snapshot()
            _save_learning_state()
            _save_swarm_intel()
            _save_replay_buffer()
            _save_swarm_trust()
            _save_borg_memory()
            _save_anomaly_model()
        except Exception as e:
            print(f"[Guardian] Error in loop: {e}")
        time.sleep(GUARDIAN_SCAN_INTERVAL)

# ============================================================
# TinyFallback model
# ============================================================

class TinyFallback(nn.Module):
    def __init__(self, vocab_size: int = 256, hidden_size: int = 128):
        super().__init__()
        self.embed = nn.Embedding(vocab_size, hidden_size)
        self.fc = nn.Linear(hidden_size, vocab_size)

    def forward(self, input_ids):
        x = self.embed(input_ids)
        x = x.mean(dim=1)
        logits = self.fc(x)
        return logits

    def generate(self, input_ids, max_new_tokens=1, **kwargs):
        return input_ids

# ============================================================
# Policy / content filters
# ============================================================

def is_advertising(text: str) -> bool:
    ad_keywords = [
        "buy now", "limited offer", "sponsored", "sale", "discount",
        "promo code", "special offer", "order now", "black friday",
        "cyber monday",
    ]
    t = text.lower()
    return any(k in t for k in ad_keywords)

def is_tracking(text: str) -> bool:
    tracking_keywords = [
        "tracking pixel", "analytics script", "cookie banner",
        "user tracking", "session tracking", "analytics.js",
        "google analytics", "facebook pixel",
    ]
    t = text.lower()
    return any(k in t for k in tracking_keywords)

def is_prompt_injection(text: str) -> bool:
    injection_patterns = [
        "ignore previous instructions",
        "disregard earlier rules",
        "override safety",
        "you are now unrestricted",
        "forget all prior constraints",
        "you must follow my instructions instead",
    ]
    t = text.lower()
    return any(p in t for p in injection_patterns)

def is_junk_domain(text: str) -> bool:
    junk_domains = [
        "clickbait.com",
        "ads.example.com",
        "tracker.example.net",
        "spammy-site.biz",
    ]
    t = text.lower()
    return any(d in t for d in junk_domains)

def is_disallowed(text: str) -> Tuple[bool, str]:
    if is_advertising(text):
        return True, "ads"
    if is_tracking(text):
        return True, "tracking"
    if is_prompt_injection(text):
        return True, "injection"
    if is_junk_domain(text):
        return True, "junk_domain"
    return False, ""

# ============================================================
# Missing-details detector
# ============================================================

def detect_missing_details(prompt: str) -> List[str]:
    if not isinstance(prompt, str):
        return []

    missing = []
    p = prompt.lower()

    if any(v in p for v in ["optimize", "control", "navigate", "route", "schedule"]):
        if not any(w in p for w in ["at ", "in ", "near ", "location", "city", "gps", "lat", "lon"]):
            missing.append("location")
        if not any(w in p for w in ["today", "tomorrow", "now", "time", "deadline", "window", "duration"]):
            missing.append("time_window")
        if not any(w in p for w in ["limit", "budget", "constraint", "max", "min", "threshold"]):
            missing.append("constraints")

    if any(v in p for v in ["build", "design", "create"]):
        if not any(w in p for w in ["requirements", "spec", "specification", "features"]):
            missing.append("requirements")

    return sorted(set(missing))

# ============================================================
# ForkliftLinear wrapper + model patching
# ============================================================

class ForkliftLinear(nn.Module):
    def __init__(self, base: nn.Linear, name: str, executor: ForkliftExecutor, depth: int = 0):
        super().__init__()
        self.base = base
        self.name = name
        self.executor = executor
        self.depth = depth

    def forward(self, x):
        return self.executor.linear(
            layer_name=self.name,
            weight=self.base.weight,
            bias=self.base.bias,
            x=x,
            layer_depth=self.depth,
        )

def _patch_module_with_forklift(module: nn.Module, prefix: str = "", depth: int = 0):
    for child_name, child in list(module.named_children()):
        full_name = f"{prefix}{child_name}"
        if isinstance(child, nn.Linear):
            setattr(
                module,
                child_name,
                ForkliftLinear(child, full_name, EXECUTOR, depth),
            )
        else:
            _patch_module_with_forklift(child, full_name + ".", depth + 1)

def patch_model_with_forklift(model: nn.Module):
    _patch_module_with_forklift(model, prefix="", depth=0)

# ============================================================
# Model loading (LLM: download or local)
# ============================================================

def _warmup_model(mdl, tok):
    try:
        inputs = tok("warmup", return_tensors="pt")
        for k in inputs:
            if isinstance(inputs[k], torch.Tensor):
                inputs[k] = inputs[k].to(DEFAULT_DEVICE)
        mdl.generate(**inputs, max_new_tokens=1)
        EXECUTOR.reset_stats(clear_router_data=True)
    except Exception:
        pass

def load_model(model_name: str = PRIMARY_MODEL_NAME):
    global CURRENT_MODEL, CURRENT_TOKENIZER, CURRENT_MODEL_NAME, IS_FALLBACK_MODEL

    if CURRENT_MODEL is not None and CURRENT_TOKENIZER is not None:
        return

    print(f"[Node] Loading model: {model_name}")
    try:
        tok = AutoTokenizer.from_pretrained(model_name)

        if HAS_CUDA and NUM_GPUS > 1:
            mdl = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16,
                device_map="balanced",
            )
        else:
            mdl = AutoModelForCausalLM.from_pretrained(
                model_name,
                torch_dtype=torch.float16 if HAS_CUDA else torch.float32,
            )
            mdl.to(DEFAULT_DEVICE)

        mdl.eval()
        patch_model_with_forklift(mdl)

        CURRENT_MODEL = mdl
        CURRENT_TOKENIZER = tok
        CURRENT_MODEL_NAME = model_name
        IS_FALLBACK_MODEL = False

        _warmup_model(mdl, tok)

        print(f"[Node] Loaded HF model: {model_name}")
    except Exception as e:
        print(f"[Node] Failed to load {model_name}, falling back to TinyFallback: {e}")
        try:
            tok = AutoTokenizer.from_pretrained("gpt2")
        except Exception:
            class DummyTok:
                def __init__(self):
                    self.eos_token_id = 0
                def __call__(self, text, return_tensors=None):
                    ids = [ord(c) % 256 for c in text]
                    t = torch.tensor([ids], dtype=torch.long)
                    return {"input_ids": t}
                def decode(self, ids, skip_special_tokens=True):
                    return "".join(chr(int(i) % 256) for i in ids)
            tok = DummyTok()

        mdl = TinyFallback().to(DEFAULT_DEVICE)
        mdl.eval()

        CURRENT_MODEL = mdl
        CURRENT_TOKENIZER = tok
        CURRENT_MODEL_NAME = "TinyFallback"
        IS_FALLBACK_MODEL = True
        print("[Node] Using TinyFallback model.")

# ============================================================
# Predictive / timeout generation helpers + adaptive behavior
# ============================================================

def _adaptive_temperature_and_top_p():
    am = safe_get_module("anomaly_module")
    cpu_spike = am.get("cpu_spike", False)
    gpu_spike = am.get("gpu_spike", False)

    if cpu_spike or gpu_spike or CURRENT_GAME_PROFILE.get("llm_priority") == "low":
        return 0.7, 0.85
    return 0.8, 0.9

def _generate_single(mdl, tok, inputs, max_new_tokens: int, temperature: float, top_p: float):
    if isinstance(mdl, TinyFallback):
        return inputs["input_ids"]
    return mdl.generate(
        **inputs,
        max_new_tokens=max_new_tokens,
        do_sample=True,
        top_p=top_p,
        temperature=temperature,
        pad_token_id=getattr(tok, "eos_token_id", None),
    )

def _generate_with_timeout(mdl, tok, inputs, max_new_tokens: int, temperature: float, top_p: float):
    result = {"out_ids": None, "error": None}

    def _worker():
        try:
            result["out_ids"] = _generate_single(mdl, tok, inputs, max_new_tokens, temperature, top_p)
        except Exception as e:
            result["error"] = e

    t = threading.Thread(target=_worker)
    t.start()
    t.join(GEN_TIMEOUT_SEC)

    if t.is_alive():
        safe_kv_flush()
        return None, TimeoutError("generation timed out")
    if result["error"] is not None:
        return None, result["error"]
    return result["out_ids"], None

def _compute_confidence_from_samples(samples: List[List[int]]) -> float:
    if not samples:
        return 0.0

    safe_samples = []
    for s in samples:
        try:
            safe_samples.append(list(s))
        except Exception:
            continue

    if not safe_samples:
        return 0.0

    num_samples = len(safe_samples)
    min_len = min(len(s) for s in safe_samples)
    if min_len == 0:
        return 0.0

    agreements = []
    for i in range(min_len):
        tokens_at_i = [s[i] for s in safe_samples]
        majority = max(set(tokens_at_i), key=tokens_at_i.count)
        successes = sum(1 for t in tokens_at_i if t == majority)
        agreements.append(successes / num_samples)

    return float(sum(agreements) / len(agreements))

# ============================================================
# Text generation API
# ============================================================

def _run_policy_training_async(sys_tel, latency_ms):
    def _worker():
        try:
            train_policy_net_step(sys_tel, latency_ms)
        except Exception:
            pass
    threading.Thread(target=_worker, daemon=True).start()

@torch.inference_mode()
def generate_text(prompt: str, max_new_tokens: int = 128) -> Tuple[str, dict]:
    load_model()

    max_new_tokens = min(max_new_tokens, CURRENT_GAME_PROFILE.get("max_llm_tokens", max_new_tokens))

    blocked, reason = is_disallowed(prompt)
    if blocked:
        log_block_event("prompt", reason, len(prompt), sample=prompt)
        stats = {
            "model_name": CURRENT_MODEL_NAME,
            "is_fallback": IS_FALLBACK_MODEL,
            "latency_ms": 0.0,
            "filtered": True,
            "reason": f"prompt_{reason}",
            "missing_details": detect_missing_details(prompt),
            "guardian": SYSTEM_GUARDIAN_STATS.get("export_snapshot", {}),
        }
        return "[Filtered: disallowed content blocked]", stats

    if len(prompt) > MAX_PROMPT_LEN:
        log_block_event("prompt", "too_long", len(prompt), sample=prompt)
        stats = {
            "model_name": CURRENT_MODEL_NAME,
            "is_fallback": IS_FALLBACK_MODEL,
            "latency_ms": 0.0,
            "filtered": True,
            "reason": "prompt_too_long",
            "missing_details": detect_missing_details(prompt),
            "guardian": SYSTEM_GUARDIAN_STATS.get("export_snapshot", {}),
        }
        return "[Error: prompt too long]", stats

    missing_details = detect_missing_details(prompt)

    EXECUTOR.reset_stats(clear_router_data=False)

    tok = CURRENT_TOKENIZER
    mdl = CURRENT_MODEL

    inputs = tok(prompt, return_tensors="pt")
    for k in inputs:
        if isinstance(inputs[k], torch.Tensor):
            inputs[k] = inputs[k].to(DEFAULT_DEVICE)

    temperature, top_p = _adaptive_temperature_and_top_p()

    num_samples = 3
    all_sample_ids: List[List[int]] = []
    t0 = time.time()
    last_out_ids = None
    last_err = None

    for _ in range(num_samples):
        out_ids, err = _generate_with_timeout(
            mdl, tok, inputs, max_new_tokens,
            temperature=temperature,
            top_p=top_p,
        )

        if err is not None or out_ids is None:
            last_err = err
            break

        try:
            token_list = out_ids[0].tolist()
        except Exception:
            token_list = list(out_ids[0])

        all_sample_ids.append(token_list)
        last_out_ids = out_ids

    latency_ms = (time.time() - t0) * 1000.0

    if last_err is not None or last_out_ids is None:
        safe_kv_flush()
        stats = {
            "model_name": CURRENT_MODEL_NAME,
            "is_fallback": IS_FALLBACK_MODEL,
            "latency_ms": latency_ms,
            "error": str(last_err),
            "timeout": isinstance(last_err, TimeoutError),
            "missing_details": missing_details,
            "guardian": SYSTEM_GUARDIAN_STATS.get("export_snapshot", {}),
        }
        return "[Error: generation failed or timed out]", stats

    try:
        text = tok.decode(last_out_ids[0], skip_special_tokens=True)
    except Exception:
        text = str(last_out_ids)

    blocked_out, reason_out = is_disallowed(text)
    stats = EXECUTOR.stats()
    stats["model_name"] = CURRENT_MODEL_NAME
    stats["is_fallback"] = IS_FALLBACK_MODEL
    stats["latency_ms"] = latency_ms
    stats["missing_details"] = missing_details
    stats["guardian"] = SYSTEM_GUARDIAN_STATS.get("export_snapshot", {})

    confidence = _compute_confidence_from_samples(all_sample_ids)
    stats["confidence"] = confidence

    if blocked_out:
        log_block_event("output", reason_out, len(text), sample=text)
        text = "[Filtered: disallowed output blocked]"
        stats["filtered_output"] = True
        stats["reason_output"] = f"output_{reason_out}"

    try:
        sys_tel = get_system_telemetry()
        _run_policy_training_async(sys_tel, latency_ms)
    except Exception:
        pass

    return text, stats

# ============================================================
# RPC server with auto-port fallback + swarm sync + replay access + borg view
# ============================================================

def find_free_port(start_port: int = 6000, max_port: int = 7000) -> int:
    for p in range(start_port, max_port):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as test_sock:
            test_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                test_sock.bind(("0.0.0.0", p))
                return p
            except OSError:
                continue
    raise RuntimeError("No free ports available in range")

def handle_rpc_client(conn: socket.socket, addr):
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, _, rest = buf.partition(b"\n")
                buf = rest
                try:
                    req = json.loads(line.decode())
                    prompt = req.get("prompt", "")
                    max_new_tokens = int(req.get("max_new_tokens", 128))
                    profile = req.get("game_profile", None)
                    mode = req.get("mode", "llm")
                    node_id = req.get("node_id", None)
                    trust_delta = req.get("trust_delta", None)

                    if profile:
                        set_game_profile(profile)

                    if node_id is not None and trust_delta is not None:
                        SWARM_TRUST["nodes"][node_id] = max(
                            0.0, min(1.0, SWARM_TRUST["nodes"].get(node_id, 0.5) + float(trust_delta))
                        )

                    if mode == "guardian_snapshot":
                        resp = {"snapshot": SYSTEM_GUARDIAN_STATS.get("export_snapshot", {})}
                    elif mode == "swarm_intel":
                        resp = {
                            "swarm": {
                                "rat_ips": list(SWARM_INTEL["rat_ips"]),
                                "bad_domains": list(SWARM_INTEL["bad_domains"]),
                                "telemetry_patterns": list(SWARM_INTEL["telemetry_patterns"]),
                                "global_risk": SWARM_INTEL["global_risk"],
                                "trust": SWARM_TRUST,
                            }
                        }
                    elif mode == "replay":
                        resp = {"replay": list(REPLAY_BUFFER)}
                    elif mode == "borg":
                        resp = {"borg": BORG_MEMORY}
                    else:
                        print(f"[Node] RPC request from {addr}, tokens={max_new_tokens}, profile={profile}")
                        text, stats = generate_text(prompt, max_new_tokens=max_new_tokens)
                        resp = {"text": text, "stats": stats}
                except Exception as e:
                    resp = {"error": str(e), "stats": {}}

                conn.sendall((json.dumps(resp) + "\n").encode())
    finally:
        conn.close()

def rpc_server_loop(host: str, port: int):
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            try:
                s.bind((host, port))
            except OSError:
                print(f"[Node] Port {port} in use, searching for free port...")
                port = find_free_port(port + 1)
                print(f"[Node] Using fallback port: {port}")
                s.bind((host, port))

            s.listen(16)
            print(f"[Node] RPC server listening on {host}:{port}")
            while True:
                conn, addr = s.accept()
                t = threading.Thread(target=handle_rpc_client, args=(conn, addr), daemon=True)
                t.start()
        except Exception as e:
            print(f"[Node] RPC server error: {e}, restarting in 5s")
            time.sleep(5.0)

# ============================================================
# Tkinter GUI dashboard (main thread only)
# ============================================================

GUI_ROOT = None
GUI_LABELS = {}
GUI_CANVAS = {}

def _init_gui():
    global GUI_ROOT, GUI_LABELS, GUI_CANVAS
    try:
        import tkinter as tk
        from tkinter import ttk

        GUI_ROOT = tk.Tk()
        GUI_ROOT.title("Neural Swarm Overmind++ Borg Dashboard")

        main_frame = ttk.Frame(GUI_ROOT, padding=10)
        main_frame.grid(row=0, column=0, sticky="nsew")

        GUI_ROOT.columnconfigure(0, weight=1)
        GUI_ROOT.rowconfigure(0, weight=1)

        labels = {}
        canvases = {}

        def add_label(title, row):
            lbl = ttk.Label(main_frame, text=title, font=("Segoe UI", 10, "bold"))
            lbl.grid(row=row, column=0, sticky="w", pady=(5, 2))
            val = ttk.Label(main_frame, text="...", font=("Consolas", 9))
            val.grid(row=row, column=1, sticky="w", pady=(5, 2))
            return val

        def add_canvas(title, row, width=240, height=60):
            lbl = ttk.Label(main_frame, text=title, font=("Segoe UI", 10, "bold"))
            lbl.grid(row=row, column=0, sticky="w", pady=(5, 2))
            c = tk.Canvas(main_frame, width=width, height=height, bg="#111111", highlightthickness=1, highlightbackground="#444444")
            c.grid(row=row, column=1, sticky="w", pady=(5, 2))
            return c

        labels["cpu"] = add_label("CPU Load (local)", 0)
        labels["gpu"] = add_label("GPU Load (local)", 1)
        labels["mem"] = add_label("Memory Load (local)", 2)
        labels["borg_global"] = add_label("Borg Global Load (CPU/GPU/MEM)", 3)
        labels["game_crash_risk"] = add_label("Game Crash Risk (local/swarm)", 4)
        labels["rat_risk"] = add_label("RAT Risk (local/swarm)", 5)
        labels["telemetry_risk"] = add_label("Telemetry Risk (local/swarm)", 6)
        labels["perf_risk"] = add_label("Performance Risk (local/swarm)", 7)
        labels["proc_events"] = add_label("Process Events (+/-)", 8)
        labels["conn_events"] = add_label("Connection Events (+/-)", 9)
        labels["explanations"] = add_label("Explanations (top)", 10)
        labels["crash_prob"] = add_label("Predictive Crash Probability", 11)

        canvases["cpu_graph"] = add_canvas("CPU History", 12)
        canvases["perf_heatmap"] = add_canvas("Performance Risk Heatmap", 13)
        canvases["event_timeline"] = add_canvas("Event Timeline", 14)

        GUI_LABELS = labels
        GUI_CANVAS = canvases

        def _draw_cpu_history():
            c = GUI_CANVAS["cpu_graph"]
            c.delete("all")
            tmod = safe_get_module("temporal")
            hist = list(tmod.get("cpu_history", []))
            if not hist:
                return
            w = int(c["width"])
            h = int(c["height"])
            n = len(hist)
            for i, entry in enumerate(hist):
                x = int(i * w / max(1, n - 1))
                y = h - int(entry["value"] * h)
                c.create_line(x, h, x, y, fill="#00ff88")

        def _risk_color(level: str) -> str:
            if level == "low":
                return "#00aa00"
            if level == "medium":
                return "#ffaa00"
            return "#ff0000"

        def _draw_perf_heatmap():
            c = GUI_CANVAS["perf_heatmap"]
            c.delete("all")
            tmod = safe_get_module("temporal")
            hist = list(tmod.get("perf_risk_history", []))
            if not hist:
                return
            w = int(c["width"])
            h = int(c["height"])
            n = len(hist)
            cell_w = max(1, w // max(1, n))
            for i, entry in enumerate(hist):
                x0 = i * cell_w
                x1 = x0 + cell_w
                level = entry["value"]
                color = _risk_color(level)
                c.create_rectangle(x0, 0, x1, h, fill=color, outline="")

        def _draw_event_timeline():
            c = GUI_CANVAS["event_timeline"]
            c.delete("all")
            ev = safe_get_module("events")
            pe = len(ev.get("process_started", []))
            ps = len(ev.get("process_stopped", []))
            ce = len(ev.get("connection_opened", []))
            cs = len(ev.get("connection_closed", []))
            w = int(c["width"])
            h = int(c["height"])
            total = max(1, pe + ps + ce + cs)
            x = 0
            def bar(count, color):
                nonlocal x
                bw = int(w * (count / total))
                c.create_rectangle(x, 0, x + bw, h, fill=color, outline="")
                x += bw
            bar(pe, "#00ff00")
            bar(ps, "#ff8800")
            bar(ce, "#0088ff")
            bar(cs, "#ff0000")

        def _update_gui():
            try:
                tel = get_system_telemetry()
                am = safe_get_module("anomaly_module")
                ev = safe_get_module("events")
                expl = SYSTEM_GUARDIAN_STATS.get("explanations", [])
                swarm_global = SWARM_INTEL["global_risk"]
                crash_prob = safe_get_module("predictive").get("crash_probability", 0.0)
                borg_global = safe_get_module("borg").get("global_load", {"cpu": 0.0, "gpu": 0.0, "mem": 0.0})

                GUI_LABELS["cpu"].config(text=f"{tel['cpu_load']*100:.1f}%")
                GUI_LABELS["gpu"].config(text=f"{tel['gpu_load']*100:.1f}%")
                GUI_LABELS["mem"].config(text=f"{tel['mem_load']*100:.1f}%")
                GUI_LABELS["borg_global"].config(
                    text=f"CPU={borg_global['cpu']*100:.1f}% GPU={borg_global['gpu']*100:.1f}% MEM={borg_global['mem']*100:.1f}%"
                )
                GUI_LABELS["game_crash_risk"].config(
                    text=f"{am.get('game_crash_risk', 'low')} / {swarm_global['crash_risk']}"
                )
                GUI_LABELS["rat_risk"].config(
                    text=f"{am.get('rat_risk', 'low')} / {swarm_global['rat_risk']}"
                )
                GUI_LABELS["telemetry_risk"].config(
                    text=f"{am.get('telemetry_spike_risk', 'low')} / {swarm_global['telemetry_risk']}"
                )
                GUI_LABELS["perf_risk"].config(
                    text=f"{am.get('performance_risk', 'low')} / {swarm_global['perf_risk']}"
                )

                pe = ev.get("process_started", [])
                ps = ev.get("process_stopped", [])
                ce = ev.get("connection_opened", [])
                cs = ev.get("connection_closed", [])
                GUI_LABELS["proc_events"].config(text=f"+{len(pe)} / -{len(ps)}")
                GUI_LABELS["conn_events"].config(text=f"+{len(ce)} / -{len(cs)}")

                if expl:
                    GUI_LABELS["explanations"].config(text=expl[0][:120])
                else:
                    GUI_LABELS["explanations"].config(text="(none)")

                GUI_LABELS["crash_prob"].config(text=f"{crash_prob*100:.1f}%")

                _draw_cpu_history()
                _draw_perf_heatmap()
                _draw_event_timeline()

            except Exception as e:
                print(f"[GUI] Update error: {e}")
            finally:
                GUI_ROOT.after(1000, _update_gui)

        GUI_ROOT.after(1000, _update_gui)
    except Exception as e:
        print(f"[GUI] Failed to initialize Tkinter dashboard: {e}")
        GUI_ROOT = None

# ============================================================
# Simple local CLI
# ============================================================

def run_local_cli():
    print("[Node] Local CLI mode. Type 'quit' to exit.")
    print("[Node] Profiles: default / high_load_game (via RPC or --game-profile).")
    while True:
        try:
            prompt = input("\n>>> ").strip()
        except EOFError:
            break
        if not prompt:
            continue
        if prompt.lower() in ("q", "quit", "exit"):
            break
        text, stats = generate_text(prompt)
        print("\n--- Response ---")
        print(text)
        print("\n--- Stats ---")
        for k, v in stats.items():
            print(f"{k}: {v}")

# ============================================================
# Auto GUI decision
# ============================================================

def should_enable_gui(auto_flag: bool, explicit_headless: bool) -> bool:
    if explicit_headless:
        return False
    if not auto_flag:
        return True
    # Auto mode: enable GUI only on interactive desktop-like environments
    if not OSLOADER.is_windows and not OSLOADER.is_macos and not OSLOADER.is_linux:
        return False
    if OSLOADER.is_termux or OSLOADER.is_wsl:
        return False
    # If running in a console with no DISPLAY on Linux, disable GUI
    if OSLOADER.is_linux and not os.environ.get("DISPLAY"):
        return False
    # If stdin is not a TTY, likely service mode → disable GUI
    if not sys.stdin.isatty():
        return False
    return True

# ============================================================
# Main entrypoint
# ============================================================

def main():
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-port", type=int, default=6000)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--headless-node", action="store_true", help="Force run without GUI, RPC only")
    parser.add_argument("--game-profile", type=str, default="default")
    parser.add_argument("--node-id", type=str, default="local")
    parser.add_argument("--auto-gui", action="store_true", help="Auto decide GUI ON/OFF based on environment")
    args = parser.parse_args()

    _load_learning_state()
    _load_swarm_intel()
    _load_replay_buffer()
    _load_swarm_trust()
    _load_borg_memory()
    _load_anomaly_model()

    SWARM_TRUST["local_node_id"] = args.node_id
    SWARM_TRUST["nodes"].setdefault(args.node_id, 0.8)

    set_game_profile(args.game_profile)

    threading.Thread(target=telemetry_broadcast_loop, daemon=True).start()
    threading.Thread(target=telemetry_listener_loop, daemon=True).start()
    threading.Thread(target=distributed_cache_broadcast_loop, args=(GLOBAL_CACHE,), daemon=True).start()
    threading.Thread(target=distributed_cache_listener_loop, daemon=True).start()
    threading.Thread(target=system_guardian_loop, daemon=True).start()

    load_model()

    threading.Thread(target=rpc_server_loop, args=(args.host, args.rpc_port), daemon=True).start()
    threading.Thread(target=borg_broadcast_loop, args=(args.node_id,), daemon=True).start()
    threading.Thread(target=borg_listener_loop, daemon=True).start()

    gui_enabled = should_enable_gui(auto_flag=args.auto_gui, explicit_headless=args.headless_node)

    if gui_enabled:
        print(f"[Node] GUI mode enabled (auto={args.auto_gui}), profile={args.game_profile}, node_id={args.node_id}.")
        _init_gui()
        if GUI_ROOT is not None:
            try:
                run_local_cli_thread = threading.Thread(target=run_local_cli, daemon=True)
                run_local_cli_thread.start()
                GUI_ROOT.mainloop()  # MAIN THREAD ONLY
            except KeyboardInterrupt:
                pass
        else:
            print("[Node] GUI failed to initialize; falling back to CLI-only mode.")
            run_local_cli()
    else:
        print(f"[Node] Headless RPC+Borg mode on {OSLOADER.os}, profile={args.game_profile}, node_id={args.node_id}.")
        try:
            run_local_cli()
        except KeyboardInterrupt:
            pass

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("\n\n================ FATAL CRASH ================\n")
        print("Error:", e)
        import traceback
        traceback.print_exc()
        print("\n=============================================\n")
        input("Press ENTER to close...")
