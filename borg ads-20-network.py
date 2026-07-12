#!/usr/bin/env python3
"""
ULTRABORG V7.3 — GAMING-FIRST FULL SYSTEM GOVERNOR
(RL + DEEP RL + WATCHDOG + ANOMALY + ADBLOCK + GUI + EVOLUTION + SUPERVISOR +
 NEURAL MEMORY + SWARM + RESURRECTION GLYPHS + GPU CURVE TUNING + GAME PROFILES +
 AUTO GAME MODE + ADVANCED NETWORK SCANNER (AUTO CIDR, ARP, ICMP, TCP) +
 PATCH MANAGER + NETWORK GUI PANEL + KERNEL-LEVEL DRIVER STUB +
 NVAPI-READY GPU CURVE HOOKS + GAME LATENCY/JITTER MONITOR +
 MOBILE REMOTE-CONTROL STUB + FULL TELEMETRY DASHBOARD +
 AI-GOVERNED FIREWALL POLICY ENGINE)

"""

import os
import sys
import json
import time
import random
import threading
import socket
import subprocess
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple
from queue import Queue

# ============================================================
# HARD CRASH LOGGER
# ============================================================

def hard_log(e, tag="HARD"):
    import traceback
    print(f"[{tag}] CRASH: {e}")
    traceback.print_exc()

# ============================================================
# AUTOLOADER
# ============================================================

import importlib

AUTOLOADER_LOG = "borg_autoloader_log.txt"

REQUIRED_LIBS = {
    "psutil": "psutil",
    "numpy": "numpy",
    "torch": "torch",
    "pynvml": "pynvml",
    "tkinter": None,
    "http.server": None,
}

def autoloader_log(msg: str):
    try:
        with open(AUTOLOADER_LOG, "a", encoding="utf-8") as f:
            f.write(f"{time.ctime()} :: {msg}\n")
    except:
        pass

def try_import(libname):
    try:
        return importlib.import_module(libname)
    except Exception as e:
        autoloader_log(f"IMPORT FAIL: {libname} :: {e}")
        return None

def try_install(libname, pipname):
    if pipname is None:
        return None
    autoloader_log(f"INSTALL ATTEMPT: {pipname}")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", pipname],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL
        )
        autoloader_log(f"INSTALL SUCCESS: {pipname}")
        return importlib.import_module(libname)
    except Exception as e:
        autoloader_log(f"INSTALL FAIL: {pipname} :: {e}")
        return None

def load_all_libs():
    loaded = {}
    for libname, pipname in REQUIRED_LIBS.items():
        mod = try_import(libname)
        if mod is None and pipname is not None:
            mod = try_install(libname, pipname)
        if mod is None:
            autoloader_log(f"FALLBACK: {libname} unavailable")
            print(f"[AUTOLOADER] WARNING: {libname} missing (fallback mode)")
        else:
            print(f"[AUTOLOADER] Loaded: {libname}")
            loaded[libname] = mod
    return loaded

AUTOLOADED = load_all_libs()

psutil = AUTOLOADED.get("psutil")
np = AUTOLOADED.get("numpy")
torch = AUTOLOADED.get("torch")
pynvml = AUTOLOADED.get("pynvml")

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except Exception:
    tk = None
    ttk = None
    messagebox = None
    print("[AUTOLOADER] Tkinter unavailable — GUI disabled")

def safe_import(name, pip_name=None):
    if name in AUTOLOADED and AUTOLOADED[name] is not None:
        return AUTOLOADED[name]
    try:
        return __import__(name)
    except ImportError:
        print(f"[WARN] Missing library: {name}")
        if pip_name:
            print(f"       Install via: pip install {pip_name}")
        return None

psutil = psutil or safe_import("psutil", "psutil")
np = np or safe_import("numpy", "numpy")
torch = torch or safe_import("torch", "torch")
pynvml = pynvml or safe_import("pynvml", "pynvml")

if torch is None or np is None or psutil is None:
    print("[FATAL] Core libraries missing. Install psutil, numpy, torch.")
    input("Press Enter to exit...")
    sys.exit(1)

try:
    import winreg
except ImportError:
    winreg = None
    print("[WARN] winreg not available (non-Windows or limited environment)")

try:
    from http.server import BaseHTTPRequestHandler, HTTPServer
except Exception:
    BaseHTTPRequestHandler = object
    HTTPServer = None
    print("[WARN] http.server not available — mobile remote-control stub disabled")

# ============================================================
# PERSISTENT LISTS
# ============================================================

WHITELIST_PATH = "borg_whitelist.json"
BLOCKLIST_PATH = "borg_blocklist.json"
KILLLIST_PATH = "borg_killlist.json"

def load_json_list(path):
    if os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except:
            return []
    return []

def save_json_list(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except:
        pass

WHITELIST = load_json_list(WHITELIST_PATH)
BLOCKLIST = load_json_list(BLOCKLIST_PATH)
KILLLIST = load_json_list(KILLLIST_PATH)

if "aeroadmin.exe" not in WHITELIST:
    WHITELIST.append("aeroadmin.exe")
    save_json_list(WHITELIST_PATH, WHITELIST)

# ============================================================
# CONFIG
# ============================================================

GAME_PROFILES = {
    "cs2": {
        "target_fps": 240,
        "max_gpu": 0.95,
        "max_cpu": 0.90,
        "hosts": ["cs2.example.com", "valve.example.com"]
    },
    "apex": {
        "target_fps": 165,
        "max_gpu": 0.95,
        "max_cpu": 0.90,
        "hosts": ["apex.example.com"]
    },
    "fortnite": {
        "target_fps": 144,
        "max_gpu": 0.95,
        "max_cpu": 0.90,
        "hosts": ["fortnite.example.com"]
    },
}

DEFAULT_CONFIG = {
    "version": "7.3.0",
    "update": {
        "auto_check_interval_sec": 3600,
        "local_update_manifest": "borg_v3_update.json",
        "remote_url_stub": "https://example.com/borg_v3_update.json"
    },
    "modes": {
        "flow": {
            "target_fps": 120,
            "max_cpu": 0.90,
            "max_gpu": 0.95,
            "reward_weights": {
                "fps_stability": 1.4,
                "cpu_headroom": 0.6,
                "gpu_headroom": 0.6,
                "thermal_safety": 1.0,
                "frametime_stability": 1.3,
                "network_health": 0.8
            }
        },
        "deep_work": {
            "target_fps": 60,
            "max_cpu": 0.70,
            "max_gpu": 0.60,
            "reward_weights": {
                "fps_stability": 0.5,
                "cpu_headroom": 1.2,
                "gpu_headroom": 0.8,
                "thermal_safety": 1.0,
                "frametime_stability": 1.0,
                "network_health": 1.0
            }
        },
        "recovery": {
            "target_fps": 30,
            "max_cpu": 0.50,
            "max_gpu": 0.40,
            "reward_weights": {
                "fps_stability": 0.3,
                "cpu_headroom": 1.4,
                "gpu_headroom": 1.4,
                "thermal_safety": 1.6,
                "frametime_stability": 0.6,
                "network_health": 1.2
            }
        }
    },
    "rl": {
        "gamma": 0.99,
        "dqn_lr": 1e-4,
        "ppo_lr": 3e-4,
        "ppo_clip": 0.25,
        "entropy_coef": 0.02,
        "value_coef": 0.5,
        "batch_size": 64,
        "trajectory_len": 256,
        "epsilon_start": 0.25,
        "epsilon_end": 0.02,
        "epsilon_decay_steps": 60000
    },
    "watchdog": {
        "max_temp_c": 83.0,
        "emergency_temp_c": 90.0,
        "max_crash_count": 3,
        "check_interval_sec": 2.0,
        "backoff_max_sec": 12.0
    },
    "graphics": {
        "registry_paths": {
            "nvidia_quality": r"Software\\NVIDIA Corporation\\Global\\Quality",
            "amd_quality": r"Software\\AMD\\Global\\Quality",
            "nvidia_perf": r"Software\\NVIDIA Corporation\\Global\\Perf",
            "amd_perf": r"Software\\AMD\\Global\\Perf"
        },
        "game_config_root": os.path.expanduser("~\\Documents\\MyGames"),
        "default_game_profile": {
            "resolution_scale_step": 0.05,
            "shadow_quality_step": 1,
            "postfx_step": 1,
            "lod_bias_step": 0.25
        }
    },
    "dream": {
        "enabled": True,
        "interval_steps": 4000,
        "episodes": 12,
        "length": 160
    },
    "anomaly": {
        "latent_dim": 4,
        "train_buffer_size": 6000,
        "train_interval_steps": 1500,
        "threshold": 0.02
    },
    "logging": {
        "json_log_path": "borg_v3_log.jsonl",
        "max_lines": 200000
    },
    "daemon": {
        "enabled": True,
        "quiet": True,
        "borg_evolution": True,
        "supervisor_interval_sec": 5.0
    },
    "state_physics": {
        "inertia": 0.85,
        "damping": 0.15,
        "strain_threshold": 0.4,
        "recovery_threshold": 0.2,
        "flow_threshold": 0.6,
        "max_phase_change_rate": 0.2
    },
    "predictive": {
        "enabled": True,
        "horizon_steps": 3,
        "risk_temp_margin": 5.0,
        "risk_ft_margin": 0.2,
        "confidence_decay": 0.98,
        "phase_weights": {
            "flow":     {"reward": 1.2, "risk": 1.4, "conf": 0.8},
            "strain":   {"reward": 0.7, "risk": 2.5, "conf": 0.8},
            "recovery": {"reward": 0.4, "risk": 3.5, "conf": 1.0},
            "neutral":  {"reward": 0.8, "risk": 2.0, "conf": 0.8}
        }
    },
    "adblock": {
        "dns_blacklist_path": "ad_blacklist.txt",
        "proxy_port": 8888
    },
    "memory": {
        "enabled": True,
        "path": "borg_memory.jsonl",
        "max_episodes": 50000
    },
    "swarm": {
        "enabled": True,
        "sync_path": "borg_swarm_sync.jsonl",
        "sync_interval_sec": 30.0
    },
    "gpu_curve": {
        "enabled": True,
        "min_power_w": 150.0,
        "max_power_w": 280.0,
        "safe_temp_c": 80.0,
        "hard_temp_c": 90.0
    },
    "network": {
        "scan_interval_sec": 20.0,
        "threat_threshold": 0.7,
        "lan_cidr": "auto",
        "tcp_ports": [22, 53, 80, 443, 8080, 8443, 1900, 5000]
    },
    "patch": {
        "check_interval_sec": 1800,
        "manifest_path": "borg_patch_manifest.json",
        "rollback_root": "borg_rollback",
        "max_concurrent_patches": 2
    },
    "kernel": {
        "driver_name": "UltraBorgDriverStub",
        "enabled": True
    },
    "firewall": {
        "enabled": True,
        "policy_path": "borg_firewall_policy.json"
    },
    "mobile": {
        "enabled": True,
        "port": 9090
    }
}

CONFIG_PATH = "borg_v3_config.json"

def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            print(f"[CONFIG] Loaded external config from {CONFIG_PATH}")
            return cfg
        except Exception as e:
            print(f"[WARN] Failed to load {CONFIG_PATH}: {e}")
    print("[CONFIG] Using embedded default config (gaming-first, V7.3)")
    return DEFAULT_CONFIG

CONFIG = load_config()

# ============================================================
# LOGGER
# ============================================================

class JsonLogger:
    def __init__(self, path: str, max_lines: int):
        self.path = path
        self.max_lines = max_lines
        self.lines = 0

    def log(self, kind: str, payload: Dict[str, Any]):
        entry = {"kind": kind, "time": time.time(), **payload}
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
            self.lines += 1
            if self.lines > self.max_lines:
                with open(self.path, "w", encoding="utf-8") as f:
                    f.write("")
                self.lines = 0
        except Exception as e:
            print(f"[LOG] Failed to write log: {e}")

LOGGER = JsonLogger(CONFIG["logging"]["json_log_path"], CONFIG["logging"]["max_lines"])

# ============================================================
# BORG MEMORY
# ============================================================

class BorgMemory:
    def __init__(self, cfg: Dict[str, Any]):
        self.enabled = cfg.get("enabled", True)
        self.path = cfg.get("path", "borg_memory.jsonl")
        self.max_episodes = cfg.get("max_episodes", 50000)
        self.count = 0

    def store_episode(self, snap: "SensorSnapshot", action: str, reward: float, net_health: float = 1.0):
        if not self.enabled:
            return
        episode = {
            "time": time.time(),
            "cpu": snap.cpu_usage,
            "gpu": snap.gpu_usage,
            "temp": snap.gpu_temp,
            "fps": snap.fps,
            "ft_var": snap.frametime_var,
            "vram": snap.vram_usage,
            "power": snap.gpu_power,
            "action": action,
            "reward": reward,
            "net_health": net_health
        }
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(episode) + "\n")
            self.count += 1
            if self.count > self.max_episodes:
                with open(self.path, "w", encoding="utf-8") as f:
                    f.write("")
                self.count = 0
        except Exception as e:
            print(f"[MEMORY] Failed to store episode: {e}")

    def load_episodes(self, max_items: int = 2000) -> List[Dict[str, Any]]:
        if not os.path.exists(self.path):
            return []
        episodes = []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                for line in f:
                    if not line.strip():
                        continue
                    try:
                        episodes.append(json.loads(line))
                        if len(episodes) >= max_items:
                            break
                    except:
                        continue
        except Exception as e:
            print(f"[MEMORY] Failed to load episodes: {e}")
        return episodes

    def snapshot_summary(self) -> Dict[str, Any]:
        return {
            "episodes": self.count,
            "path": self.path,
            "enabled": self.enabled
        }

MEMORY = BorgMemory(CONFIG["memory"])

# ============================================================
# SWARM SYNC
# ============================================================

class SwarmSync:
    def __init__(self, cfg: Dict[str, Any]):
        self.enabled = cfg.get("enabled", False)
        self.path = cfg.get("sync_path", "borg_swarm_sync.jsonl")
        self.interval = cfg.get("sync_interval_sec", 30.0)
        self.running = False
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def start(self):
        if not self.enabled:
            return
        self.running = True
        print("[SWARM] Swarm sync starting")
        self.thread.start()

    def publish(self, payload: Dict[str, Any]):
        if not self.enabled:
            return
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps({"time": time.time(), **payload}) + "\n")
        except Exception as e:
            print(f"[SWARM] Failed to publish: {e}")

    def loop(self):
        while self.running:
            try:
                summary = MEMORY.snapshot_summary()
                self.publish({"kind": "memory_summary", **summary})
            except Exception as e:
                print(f"[SWARM] Loop error: {e}")
            time.sleep(self.interval)

SWARM = SwarmSync(CONFIG["swarm"])

# ============================================================
# AUTO-UPDATER
# ============================================================

class AutoUpdater:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.running = True
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def start(self):
        print("[UPDATE] Auto-updater starting")
        self.thread.start()

    def _read_local_manifest(self) -> Dict[str, Any]:
        path = self.cfg["local_update_manifest"]
        if not os.path.exists(path):
            return {}
        try:
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[UPDATE] Failed to read local manifest: {e}")
            return {}

    def check_for_update(self):
        current_version = CONFIG.get("version", "0.0.0")
        manifest = self._read_local_manifest()
        target_version = manifest.get("version")
        if not target_version:
            LOGGER.log("update_check", {"status": "no_manifest"})
            return
        LOGGER.log("update_check", {"current": current_version, "target": target_version})
        if target_version != current_version:
            print(f"[UPDATE] New version available: {target_version} (current {current_version})")
            LOGGER.log("update_available", {"current": current_version, "target": target_version})

    def loop(self):
        interval = self.cfg["auto_check_interval_sec"]
        while self.running:
            try:
                self.check_for_update()
            except Exception as e:
                print(f"[UPDATE] Loop error: {e}")
            time.sleep(interval)

UPDATER = AutoUpdater(CONFIG["update"])

# ============================================================
# SENSORS
# ============================================================

@dataclass
class SensorSnapshot:
    cpu_usage: float
    ram_usage: float
    gpu_usage: float
    gpu_temp: float
    fps: float
    frametime_var: float
    vram_usage: float
    gpu_power: float

class SensorHub:
    def __init__(self):
        self.has_nvml = pynvml is not None
        if self.has_nvml:
            try:
                pynvml.nvmlInit()
                self.gpu_handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                print("[SENSORS] NVML initialized")
            except Exception as e:
                print(f"[WARN] NVML init failed: {e}")
                self.has_nvml = False
                self.gpu_handle = None
        self._fps_history: List[float] = []

    def read_cpu_ram(self) -> Tuple[float, float]:
        cpu = psutil.cpu_percent(interval=None) / 100.0
        ram = psutil.virtual_memory().percent / 100.0
        return cpu, ram

    def read_gpu(self) -> Tuple[float, float, float, float]:
        if not self.has_nvml:
            return 0.0, 40.0, 0.0, 0.0
        try:
            util = pynvml.nvmlDeviceGetUtilizationRates(self.gpu_handle)
            temp = pynvml.nvmlDeviceGetTemperature(
                self.gpu_handle, pynvml.NVML_TEMPERATURE_GPU
            )
            mem = pynvml.nvmlDeviceGetMemoryInfo(self.gpu_handle)
            power = pynvml.nvmlDeviceGetPowerUsage(self.gpu_handle) / 1000.0
            vram_usage = mem.used / max(mem.total, 1)
            return util.gpu / 100.0, float(temp), float(vram_usage), float(power)
        except Exception:
            return 0.0, 40.0, 0.0, 0.0

    def read_fps(self) -> float:
        fps = 120.0 + random.uniform(-30.0, 30.0)
        self._fps_history.append(fps)
        if len(self._fps_history) > 240:
            self._fps_history.pop(0)
        return fps

    def frametime_variance(self) -> float:
        if len(self._fps_history) < 2:
            return 0.0
        ft = [1.0 / max(f, 1e-3) for f in self._fps_history]
        return float(np.var(ft))

    def snapshot(self) -> SensorSnapshot:
        cpu, ram = self.read_cpu_ram()
        gpu, temp, vram, power = self.read_gpu()
        fps = self.read_fps()
        ft_var = self.frametime_variance()
        snap = SensorSnapshot(
            cpu_usage=cpu,
            ram_usage=ram,
            gpu_usage=gpu,
            gpu_temp=temp,
            fps=fps,
            frametime_var=ft_var,
            vram_usage=vram,
            gpu_power=power,
        )
        LOGGER.log("sensors", {
            "cpu": cpu,
            "ram": ram,
            "gpu": gpu,
            "temp": temp,
            "fps": fps,
            "ft_var": ft_var,
            "vram": vram,
            "power": power,
        })
        return snap

SENSORS = SensorHub()

# ============================================================
# KERNEL DRIVER STUB
# ============================================================

class KernelDriverStub:
    def __init__(self, cfg: Dict[str, Any]):
        self.enabled = cfg.get("enabled", True)
        self.name = cfg.get("driver_name", "UltraBorgDriverStub")

    def init(self):
        if not self.enabled:
            return
        print(f"[KERNEL] Initializing kernel driver stub: {self.name}")
        LOGGER.log("kernel_driver_init", {"name": self.name})

    def send_telemetry(self, snap: SensorSnapshot):
        if not self.enabled:
            return
        LOGGER.log("kernel_telemetry", {
            "cpu": snap.cpu_usage,
            "gpu": snap.gpu_usage,
            "temp": snap.gpu_temp,
            "fps": snap.fps
        })

KERNEL_DRIVER = KernelDriverStub(CONFIG["kernel"])

# ============================================================
# NVAPI TUNER
# ============================================================

class NVAPITuner:
    def __init__(self):
        self.available = True

    def set_power_limit(self, watts: float):
        print(f"[NVAPI] (stub) Set GPU power limit to {watts:.1f} W")
        LOGGER.log("nvapi_power_limit", {"watts": watts})

    def set_temp_target(self, temp_c: float):
        print(f"[NVAPI] (stub) Set GPU temp target to {temp_c:.1f} C")
        LOGGER.log("nvapi_temp_target", {"temp_c": temp_c})

    def set_perf_mode(self, mode: str):
        print(f"[NVAPI] (stub) Set GPU perf mode to {mode}")
        LOGGER.log("nvapi_perf_mode", {"mode": mode})

NVAPI = NVAPITuner()

class GPUCurveTuner:
    def __init__(self, cfg: Dict[str, Any]):
        self.enabled = cfg.get("enabled", True)
        self.min_power = cfg.get("min_power_w", 150.0)
        self.max_power = cfg.get("max_power_w", 280.0)
        self.safe_temp = cfg.get("safe_temp_c", 80.0)
        self.hard_temp = cfg.get("hard_temp_c", 90.0)

    def tune(self, snap: SensorSnapshot):
        if not self.enabled:
            return
        temp = snap.gpu_temp
        util = snap.gpu_usage
        if temp > self.hard_temp:
            target_power = self.min_power
        elif temp > self.safe_temp:
            factor = (self.hard_temp - temp) / max(self.hard_temp - self.safe_temp, 1.0)
            target_power = self.min_power + factor * (self.max_power - self.min_power)
        else:
            if util > 0.85:
                target_power = self.max_power
            else:
                target_power = self.min_power + util * (self.max_power - self.min_power)
        target_power = max(self.min_power, min(self.max_power, target_power))
        NVAPI.set_power_limit(target_power)
        LOGGER.log("gpu_curve_tune", {
            "temp": temp,
            "util": util,
            "target_power": target_power
        })

GPU_CURVE = GPUCurveTuner(CONFIG["gpu_curve"])

# ============================================================
# ADBLOCK CORE (unchanged from V7.2, trimmed)
# ============================================================

AD_KEYWORDS = [
    "ad", "ads", "advert", "doubleclick", "googlesyndication",
    "taboola", "outbrain", "tracking", "promo", "sponsor",
    "widget", "iframe", "renderer", "subframe", "cef"
]

AD_KILL_EVENTS = Queue()
AD_DOMAIN_EVENTS = Queue()
AD_PROXY_EVENTS = Queue()

SAFE_NAMES = [
    "steam", "steam.exe",
    "epic games", "epicgameslauncher", "epicgameslauncher.exe",
    "copilot", "copilot.exe",
    "python", "python.exe",
    "py", ".py",
    "aeroadmin", "aeroadmin.exe",
    "chrome.exe", "chrome", "chromium",
    "chrome_child", "chrome_renderer", "chrome_gpu", "chrome_utility",
    "chrome_crashpad", "chrome_sandbox",
    "msedge.exe", "edge.exe", "edge",
    "msedge_child", "msedge_renderer", "msedge_gpu", "msedge_utility",
    "msedge_crashpad", "msedge_sandbox",
    "opera.exe", "opera", "opera_child", "opera_renderer",
    "opera_gpu", "opera_utility", "opera_crashpad", "opera_sandbox",
    "vivaldi.exe", "vivaldi", "vivaldi_child", "vivaldi_renderer",
    "vivaldi_gpu", "vivaldi_utility", "vivaldi_crashpad", "vivaldi_sandbox",
    "firefox.exe", "firefox", "firefox_child", "firefox_renderer",
    "firefox_gpu", "firefox_utility", "firefox_crashpad", "firefox_sandbox",
    "teams", "teams.exe",
    "teamshelper", "teamshelper.exe",
    "teamswebview", "teamswebview.exe",
    "teamsrenderer", "teamsrenderer.exe",
    "teamsutility", "teamsutility.exe",
    "teamswebclient", "teamswebclient.exe",
    "teamsupdate", "teamsupdate.exe",
    "teamsbootstrapper", "teamsbootstrapper.exe",
    "teamscrashpad", "teamscrashpad.exe",
    "teamsbackground", "teamsbackground.exe",
    "teamsusersession", "teamsusersession.exe",
    "onedrive", "onedrive.exe",
    "outlook", "outlook.exe",
    "officeclicktorun", "officeclicktorun.exe",
    "searchapp", "searchapp.exe",
    "shellexperiencehost", "shellexperiencehost.exe",
    "widgets", "widgets.exe",
    "startmenuexperiencehost", "startmenuexperiencehost.exe",
    "windowsterminal", "windowsterminal.exe",
    "explorer", "explorer.exe",
    "runtimebroker", "runtimebroker.exe",
    "winstore.app.exe", "winstore", "microsoftstore",
    "xboxapp", "xboxapp.exe",
    "gamebar", "gamebar.exe",
    "gamebarpresencewriter", "gamebarpresencewriter.exe",
    "textinputhost", "textinputhost.exe",
    "ctfmon", "ctfmon.exe",
    "dwm", "dwm.exe",
    "taskmgr", "taskmgr.exe",
    "smartscreen", "smartscreen.exe",
    "notepad", "notepad.exe",
    "notepad_child", "notepad_child.exe",
    "notepad_renderer", "notepad_renderer.exe",
    "notepad_utility", "notepad_utility.exe",
]

SAFE_NAMES += [
    "msedgewebview2.exe",
    "msedgewebview2",
    "webview2.exe",
    "webview2",
]

class AdBlockDNS:
    def __init__(self, blacklist_path: str):
        self.domains = set()
        if os.path.exists(blacklist_path):
            try:
                with open(blacklist_path, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            self.domains.add(line.lower())
                print(f"[ADBLOCK] Loaded {len(self.domains)} ad domains from {blacklist_path}")
            except Exception as e:
                print(f"[ADBLOCK] Failed to read blacklist: {e}")
        else:
            print(f"[ADBLOCK] No blacklist file at {blacklist_path}")

    def is_ad_domain(self, host: str) -> bool:
        host = (host or "").lower()
        if any(host.endswith(d) for d in self.domains):
            AD_DOMAIN_EVENTS.put(f"Blocked domain: {host}")
            LOGGER.log("ad_block_dns", {"host": host})
            return True
        return False

AD_DNS = AdBlockDNS(CONFIG["adblock"]["dns_blacklist_path"])

GUI_INSTANCE = None

SYSTEM32_PATH = os.path.join(os.environ.get("SystemRoot", r"C:\Windows"), "System32").lower()
WINDOWS_APPS_PATH = os.path.join(
    os.environ.get("ProgramFiles", r"C:\Program Files"),
    "WindowsApps"
).lower()

def get_proc_path(proc):
    try:
        return (proc.exe() or "").lower()
    except Exception:
        return ""

def is_microsoft_product(proc):
    try:
        info = proc.as_dict(attrs=["name"])
        name = (info.get("name") or "").lower()
        return "microsoft" in name
    except Exception:
        return False

def is_auto_protected(proc, name: str) -> bool:
    name = (name or "").lower()
    path = get_proc_path(proc)
    if not path:
        return False
    if SYSTEM32_PATH in path:
        return True
    if WINDOWS_APPS_PATH in path:
        return True
    if is_microsoft_product(proc):
        return True
    return False

PROCESS_CACHE: Dict[int, Dict[str, Any]] = {}
RESURRECTION_LOG_PATH = "borg_resurrection_glyphs.jsonl"

def log_resurrection_glyph(name: str, pid: int):
    glyph = {
        "time": time.time(),
        "name": name,
        "pid": pid,
        "glyph": "RESURRECTION"
    }
    try:
        with open(RESURRECTION_LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(glyph) + "\n")
        LOGGER.log("resurrection_glyph", glyph)
    except Exception as e:
        print(f"[GLYPH] Failed to log resurrection glyph: {e}")

def get_proc_info(proc):
    pid = proc.pid
    name_raw = proc.info.get("name") or ""
    name = name_raw.lower()

    if pid in PROCESS_CACHE:
        info = PROCESS_CACHE[pid]
        info["last_seen"] = time.time()
        return info

    try:
        cmd = " ".join(proc.cmdline()).lower()
    except Exception:
        cmd = ""
    try:
        path = (proc.exe() or "").lower()
    except Exception:
        path = ""

    resurrected = False
    for old_pid, old_info in list(PROCESS_CACHE.items()):
        if old_info.get("name") == name and old_info.get("dead", False):
            resurrected = True
            log_resurrection_glyph(name_raw, pid)
            PROCESS_CACHE.pop(old_pid, None)
            break

    info = {
        "pid": pid,
        "name": name,
        "cmd": cmd,
        "path": path,
        "last_seen": time.time(),
        "resurrected": resurrected,
        "dead": False
    }
    PROCESS_CACHE[pid] = info
    return info

def cleanup_cache(current_pids: List[int]):
    current_set = set(current_pids)
    for pid, info in list(PROCESS_CACHE.items()):
        if pid not in current_set:
            info["dead"] = True

ADBLOCK_RUNNING = True

def kill_ads_only_once():
    try:
        current_pid = os.getpid()
        current_pids: List[int] = []

        for proc in psutil.process_iter(attrs=["pid", "name"]):
            try:
                info_cached = get_proc_info(proc)
                pid = info_cached["pid"]
                name = info_cached["name"]
                name_raw = proc.info.get("name") or ""
                cmd = info_cached["cmd"]

                current_pids.append(pid)

                if GUI_INSTANCE is not None:
                    GUI_INSTANCE.add_process_row(name_raw, pid)

                if pid == current_pid:
                    continue

                if name in WHITELIST:
                    continue

                if "teams" in name:
                    if name not in WHITELIST:
                        WHITELIST.append(name)
                        save_json_list(WHITELIST_PATH, WHITELIST)
                    continue

                if is_auto_protected(proc, name_raw):
                    continue

                if any(s == name or s in name for s in SAFE_NAMES):
                    continue

                if name in BLOCKLIST:
                    AD_KILL_EVENTS.put(f"BLOCKLIST: {name_raw} ({pid})")
                    LOGGER.log("blocklist_hit", {"pid": pid, "name": name_raw})
                    continue

                if name in KILLLIST:
                    AD_KILL_EVENTS.put(f"KILLLIST: {name_raw} ({pid})")
                    LOGGER.log("killlist_hit", {"pid": pid, "name": name_raw})
                    try:
                        proc.terminate()
                    except:
                        pass
                    continue

                try:
                    parent = proc.parent()
                    parent_name = (parent.name() or "").lower() if parent else ""
                except Exception:
                    parent_name = ""

                is_teams_webview = (
                    ("webview2" in cmd or "msedgewebview2" in cmd or "webview" in cmd)
                ) and (
                    "teams" in cmd or "msteams" in cmd or "teams" in parent_name
                )

                if is_teams_webview:
                    safe_name = name
                    if safe_name and safe_name not in WHITELIST:
                        WHITELIST.append(safe_name)
                        save_json_list(WHITELIST_PATH, WHITELIST)
                    continue

                if "python" in cmd or cmd.endswith(".py"):
                    continue

                gpu_usage, temp, vram, power = SENSORS.read_gpu()
                gpu_heavy = gpu_usage > 0.85
                looks_like_game = any(k in name for k in ["game", "unity", "unreal", "ue4", "ue5", "dx11", "dx12"])
                if gpu_heavy and looks_like_game:
                    continue

                is_ad = (
                    any(k in name for k in AD_KEYWORDS) or
                    any(k in cmd for k in AD_KEYWORDS) or
                    ("renderer" in cmd and ("ad" in cmd or "promo" in cmd)) or
                    ("subframe" in cmd and ("ad" in cmd or "promo" in cmd)) or
                    ("cef" in name and ("ad" in cmd or "promo" in cmd))
                )

                if not is_ad:
                    continue

                msg = f"Killed: {name_raw} ({pid})"
                AD_KILL_EVENTS.put(msg)
                LOGGER.log("ad_kill", {
                    "pid": pid,
                    "name": name_raw,
                    "cmd": cmd
                })

                try:
                    proc.terminate()
                except:
                    pass

                print(f"[ADBLOCK] Terminated ad process: {name_raw} ({pid})")

            except Exception as e:
                print(f"[ADBLOCK] per-proc error: {e}")
                continue

        cleanup_cache(current_pids)

    except Exception as e:
        print(f"[ADBLOCK] kill_ads_only_once() top-level error: {e}")
        LOGGER.log("ad_kill_error", {"error": str(e)})

def adblock_loop():
    print("[ADBLOCK] Adblock loop starting")
    while ADBLOCK_RUNNING:
        kill_ads_only_once()
        time.sleep(2.0)

def start_ad_proxy_stub(port: int):
    def loop():
        try:
            print(f"[ADBLOCK] Proxy stub running on 127.0.0.1:{port}")
            while True:
                time.sleep(5.0)
        except Exception as e:
            hard_log(e, "PROXY_TOP")

    threading.Thread(target=loop, daemon=True).start()

# ============================================================
# GRAPHICS TUNER
# ============================================================

class GraphicsTuner:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.registry_paths = cfg["registry_paths"]
        self.game_root = cfg["game_config_root"]
        self.profile = cfg["default_game_profile"]

    def _set_registry_value(self, root, path: str, name: str, value: Any):
        if winreg is None:
            print(f"[GFX] (stub) Registry set {path}\\{name} = {value}")
            LOGGER.log("gfx_registry_stub", {"path": path, "name": name, "value": value})
            return
        try:
            key = winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE)
        except FileNotFoundError:
            try:
                key = winreg.CreateKey(root, path)
            except Exception as e:
                print(f"[GFX] Failed to create key {path}: {e}")
                return
        try:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
            winreg.CloseKey(key)
            print(f"[GFX] Registry set {path}\\{name} = {value}")
            LOGGER.log("gfx_registry", {"path": path, "name": name, "value": value})
        except Exception as e:
            print(f"[GFX] Failed to set registry {path}\\{name}: {e}")

    def lower_global_quality(self):
        print("[GFX] Lowering global graphics quality")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["nvidia_quality"], "QualityLevel", "Low")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["amd_quality"], "QualityLevel", "Low")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["nvidia_perf"], "PerfMode", "MaxPerf")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["amd_perf"], "PerfMode", "MaxPerf")
        NVAPI.set_perf_mode("MaxPerf")

    def raise_global_quality(self):
        print("[GFX] Raising global graphics quality")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["nvidia_quality"], "QualityLevel", "High")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["amd_quality"], "QualityLevel", "High")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["nvidia_perf"], "PerfMode", "Balanced")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["amd_perf"], "PerfMode", "Balanced")
        NVAPI.set_perf_mode("Balanced")

    def _find_game_configs(self) -> List[str]:
        paths = []
        if os.path.isdir(self.game_root):
            for root, dirs, files in os.walk(self.game_root):
                for f in files:
                    if f.lower().endswith((".ini", ".cfg", ".json")):
                        paths.append(os.path.join(root, f))
        return paths

    def _patch_game_config(self, path: str, lower: bool = True):
        print(f"[GFX] Patching game config: {path} (lower={lower})")
        LOGGER.log("gfx_game_patch", {"path": path, "lower": lower})

    def lower_game_quality(self):
        print("[GFX] Lowering per-game graphics quality")
        for cfg_path in self._find_game_configs():
            self._patch_game_config(cfg_path, lower=True)

    def raise_game_quality(self):
        print("[GFX] Raising per-game graphics quality")
        for cfg_path in self._find_game_configs():
            self._patch_game_config(cfg_path, lower=False)

    def kill_heavy_background(self, cpu_threshold: float = 0.25):
        print("[GFX] Killing heavy background processes")
        for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent"]):
            try:
                name = (proc.info["name"] or "").lower()
                cpu = proc.info.get("cpu_percent", 0.0)
                if cpu is None:
                    cpu = 0.0
                if cpu > cpu_threshold * 100.0:
                    if any(s == name or s in name for s in SAFE_NAMES):
                        continue
                    if is_auto_protected(proc, name):
                        continue
                    LOGGER.log("gfx_kill_heavy", {"pid": proc.info["pid"], "name": name, "cpu": cpu})
                    print(f"[GFX] Terminating heavy background {name} ({proc.info['pid']}) cpu={cpu:.1f}%")
                    try:
                        psutil.Process(proc.info["pid"]).terminate()
                    except Exception:
                        pass
            except Exception as e:
                print(f"[GFX] kill_heavy_background error: {e}")
                continue

GFX = GraphicsTuner(CONFIG["graphics"])

# ============================================================
# GAME PROFILE DETECTION
# ============================================================

CURRENT_GAME_PROFILE = None

def detect_game_profile() -> Dict[str, Any]:
    global CURRENT_GAME_PROFILE
    active_names = []
    try:
        for proc in psutil.process_iter(attrs=["name"]):
            name = (proc.info.get("name") or "").lower()
            active_names.append(name)
    except Exception:
        pass

    chosen = None
    joined = " ".join(active_names)
    for key, profile in GAME_PROFILES.items():
        if key in joined:
            chosen = profile
            break

    if chosen is None:
        chosen = CONFIG["modes"]["flow"]

    CURRENT_GAME_PROFILE = chosen
    LOGGER.log("game_profile", {"profile": chosen})
    return chosen

# ============================================================
# NETWORK: AUTO CIDR + ARP + ICMP + TCP
# ============================================================

class NetHistory:
    def __init__(self, max_len: int = 32):
        self.max_len = max_len
        self.snapshots: List[List[str]] = []

    def update(self, devices: List[Dict[str, Any]]):
        ips = sorted(d.get("ip", "") for d in devices)
        self.snapshots.append(ips)
        if len(self.snapshots) > self.max_len:
            self.snapshots.pop(0)

    def stability_score(self) -> float:
        if len(self.snapshots) < 2:
            return 1.0
        last = set(self.snapshots[-1])
        prev = set(self.snapshots[-2])
        added = len(last - prev)
        removed = len(prev - last)
        change = added + removed
        return max(0.0, 1.0 - change / 10.0)

NET_HISTORY = NetHistory()

class NetworkScanner:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.interval = cfg.get("scan_interval_sec", 20.0)
        self.threat_threshold = cfg.get("threat_threshold", 0.7)
        self.tcp_ports = cfg.get("tcp_ports", [22, 53, 80, 443, 8080, 8443])
        self.running = True
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.devices: Dict[str, Dict[str, Any]] = {}
        self.lock = threading.Lock()
        self.base_ip, self.cidr = self._auto_lan()

    def _auto_lan(self) -> Tuple[str, str]:
        try:
            gws = psutil.net_if_addrs()
            for name, addrs in gws.items():
                for a in addrs:
                    if a.family == socket.AF_INET:
                        ip = a.address
                        if ip.startswith("192.168.") or ip.startswith("10.") or ip.startswith("172."):
                            base = ip.rsplit(".", 1)[0] + "."
                            cidr = base + "0/24"
                            print(f"[NET] Auto-detected LAN: {cidr}")
                            return base, cidr
        except Exception as e:
            print(f"[NET] Auto LAN detect failed: {e}")
        return "192.168.0.", "192.168.0.0/24"

    def start(self):
        print("[NET] NetworkScanner starting")
        self.thread.start()

    def _cidr_hosts(self) -> List[str]:
        base = self.base_ip
        return [f"{base}{i}" for i in range(1, 255)]

    def _ping(self, ip: str, timeout_ms: int = 500) -> bool:
        try:
            if os.name == "nt":
                cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout_ms // 1000), ip]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    def _probe_tcp(self, ip: str, port: int, timeout: float = 0.3) -> bool:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            s.connect((ip, port))
            s.close()
            return True
        except Exception:
            return False

    def _arp_table(self) -> Dict[str, str]:
        table = {}
        try:
            if os.name == "nt":
                cmd = ["arp", "-a"]
            else:
                cmd = ["arp", "-n"]
            out = subprocess.check_output(cmd, encoding="utf-8", errors="ignore")
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and "." in parts[0]:
                    ip = parts[0]
                    mac = parts[1]
                    table[ip] = mac
        except Exception as e:
            print(f"[NET] ARP parse failed: {e}")
        return table

    def _scan_ip(self, ip: str, arp_mac: str = "") -> Dict[str, Any]:
        alive = self._ping(ip)
        open_ports = []
        if alive:
            for p in self.tcp_ports:
                if self._probe_tcp(ip, p):
                    open_ports.append(p)
        if not alive and not open_ports and not arp_mac:
            return {}
        label = "Unknown"
        if ip.endswith(".1"):
            label = "Router"
        dev = {"ip": ip, "label": label, "ports": open_ports, "mac": arp_mac}
        return dev

    def _score_device(self, dev: Dict[str, Any]) -> float:
        ports = dev.get("ports", [])
        score = 0.0
        if 445 in ports or 23 in ports:
            score += 0.6
        if len(ports) > 3:
            score += 0.3
        return min(1.0, score)

    def loop(self):
        while self.running:
            try:
                arp = self._arp_table()
                hosts = self._cidr_hosts()
                devices = []
                for ip in hosts:
                    dev = self._scan_ip(ip, arp_mac=arp.get(ip, ""))
                    if dev:
                        score = self._score_device(dev)
                        dev["score"] = score
                        devices.append(dev)
                        LOGGER.log("net_device", dev)
                        if score >= self.threat_threshold:
                            LOGGER.log("net_threat", dev)
                with self.lock:
                    self.devices = {d["ip"]: d for d in devices}
                NET_HISTORY.update(devices)
                for d in devices:
                    FIREWALL.decide(d)
                SWARM.publish({"kind": "net_scan_summary", "count": len(devices)})
            except Exception as e:
                print(f"[NET] Scanner loop error: {e}")
            time.sleep(self.interval)

    def get_snapshot(self) -> List[Dict[str, Any]]:
        with self.lock:
            return list(self.devices.values())

NETWORK_SCANNER = NetworkScanner(CONFIG["network"])

# ============================================================
# PATCH MANAGER
# ============================================================

class PatchManager:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.interval = cfg.get("check_interval_sec", 1800)
        self.manifest_path = cfg.get("manifest_path", "borg_patch_manifest.json")
        self.rollback_root = cfg.get("rollback_root", "borg_rollback")
        self.max_concurrent = cfg.get("max_concurrent_patches", 2)
        self.running = True
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.status = {"pending": 0, "applied": 0, "failed": 0}
        self.lock = threading.Lock()

    def start(self):
        print("[PATCH] PatchManager starting")
        self.thread.start()

    def _read_manifest(self) -> List[Dict[str, Any]]:
        if not os.path.exists(self.manifest_path):
            return []
        try:
            with open(self.manifest_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            return data.get("patches", [])
        except Exception as e:
            print(f"[PATCH] Failed to read manifest: {e}")
            return []

    def _apply_patch(self, patch: Dict[str, Any]) -> bool:
        LOGGER.log("patch_apply_stub", patch)
        return True

    def loop(self):
        while self.running:
            try:
                patches = self._read_manifest()
                if not patches:
                    time.sleep(self.interval)
                    continue

                with self.lock:
                    self.status["pending"] = len(patches)

                snap = SENSORS.snapshot()
                if snap.cpu_usage > 0.7 or snap.gpu_usage > 0.7:
                    LOGGER.log("patch_deferral", {
                        "cpu": snap.cpu_usage,
                        "gpu": snap.gpu_usage,
                        "reason": "high_load"
                    })
                    time.sleep(self.interval)
                    continue

                applied = 0
                for p in patches:
                    if applied >= self.max_concurrent:
                        break
                    ok = self._apply_patch(p)
                    with self.lock:
                        if ok:
                            self.status["applied"] += 1
                        else:
                            self.status["failed"] += 1
                    applied += 1

                SWARM.publish({"kind": "patch_summary", **self.get_status()})
            except Exception as e:
                print(f"[PATCH] Loop error: {e}")
            time.sleep(self.interval)

    def get_status(self) -> Dict[str, Any]:
        with self.lock:
            return dict(self.status)

PATCH_MANAGER = PatchManager(CONFIG["patch"])

# ============================================================
# FIREWALL
# ============================================================

class AIFirewall:
    def __init__(self, cfg: Dict[str, Any]):
        self.enabled = cfg.get("enabled", True)
        self.policy_path = cfg.get("policy_path", "borg_firewall_policy.json")
        self.policy = self._load_policy()
        self.last_cycle_decisions: List[str] = []

    def _load_policy(self) -> Dict[str, Any]:
        if not os.path.exists(self.policy_path):
            return {"rules": []}
        try:
            with open(self.policy_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception as e:
            print(f"[FIREWALL] Failed to load policy: {e}")
            return {"rules": []}

    def decide(self, device: Dict[str, Any]) -> str:
        score = device.get("score", 0.0)
        if score >= CONFIG["network"]["threat_threshold"]:
            decision = "monitor"
        else:
            decision = "allow"
        LOGGER.log("firewall_decision", {"device": device, "decision": decision})
        self.last_cycle_decisions.append(decision)
        return decision

    def consume_cycle_penalty(self) -> float:
        penalty = 0.0
        for d in self.last_cycle_decisions:
            if d == "monitor":
                penalty += 0.2
        self.last_cycle_decisions = []
        return penalty

FIREWALL = AIFirewall(CONFIG["firewall"])

# ============================================================
# GAME LATENCY/JITTER MONITOR
# ============================================================

class GameLatencyMonitor:
    def __init__(self):
        self.samples: List[float] = []
        self.max_samples = 32
        self.lock = threading.Lock()

    def _ping_host(self, host: str, timeout_ms: int = 500) -> float:
        try:
            if os.name == "nt":
                cmd = ["ping", "-n", "1", "-w", str(timeout_ms), host]
            else:
                cmd = ["ping", "-c", "1", "-W", str(timeout_ms // 1000), host]
            start = time.time()
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            end = time.time()
            rtt_ms = (end - start) * 1000.0
            return rtt_ms
        except Exception:
            return float(timeout_ms)

    def measure_for_profile(self, profile: Dict[str, Any]):
        hosts = profile.get("hosts", [])
        if not hosts:
            return
        latencies = []
        for h in hosts:
            rtt = self._ping_host(h)
            latencies.append(rtt)
        if not latencies:
            return
        avg = sum(latencies) / len(latencies)
        with self.lock:
            self.samples.append(avg)
            if len(self.samples) > self.max_samples:
                self.samples.pop(0)
        LOGGER.log("game_latency", {"hosts": hosts, "avg_ms": avg})

    def latency_score(self) -> Tuple[float, float]:
        with self.lock:
            if not self.samples:
                return 1.0, 0.0
            arr = np.array(self.samples, dtype=np.float32)
        avg = float(arr.mean())
        jitter = float(arr.std())
        score = max(0.0, min(1.0, 1.0 - (avg / 100.0) - (jitter / 50.0)))
        return score, jitter

GAME_LATENCY = GameLatencyMonitor()

# ============================================================
# DEEP RL TRAINER
# ============================================================

class DeepRLTrainer:
    def __init__(self, cfg: Dict[str, Any]):
        self.gamma = cfg.get("gamma", 0.99)
        self.lr = cfg.get("dqn_lr", 1e-4)
        self.model = self._build_model()
        self.optimizer = torch.optim.Adam(self.model.parameters(), lr=self.lr)
        self.running = True
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def _build_model(self):
        return torch.nn.Sequential(
            torch.nn.Linear(9, 64),
            torch.nn.ReLU(),
            torch.nn.Linear(64, 64),
            torch.nn.ReLU(),
            torch.nn.Linear(64, 3)
        )

    def start(self):
        print("[DEEP_RL] Trainer starting")
        self.thread.start()

    def _encode_episode(self, ep: Dict[str, Any]) -> Tuple[torch.Tensor, int, float]:
        state = torch.tensor([
            ep.get("cpu", 0.0),
            ep.get("gpu", 0.0),
            ep.get("temp", 0.0) / 100.0,
            ep.get("fps", 0.0) / 240.0,
            ep.get("ft_var", 0.0),
            ep.get("vram", 0.0),
            ep.get("power", 0.0) / 300.0,
            ep.get("net_health", 1.0),
            1.0
        ], dtype=torch.float32)
        action_str = ep.get("action", "noop")
        if action_str == "lower":
            action_idx = 0
        elif action_str == "raise":
            action_idx = 1
        else:
            action_idx = 2
        reward = float(ep.get("reward", 0.0))
        return state, action_idx, reward

    def train_batch(self, episodes: List[Dict[str, Any]]):
        if not episodes:
            return
        states = []
        actions = []
        rewards = []
        for ep in episodes:
            s, a, r = self._encode_episode(ep)
            states.append(s)
            actions.append(a)
            rewards.append(r)
        states = torch.stack(states)
        actions = torch.tensor(actions, dtype=torch.long)
        rewards = torch.tensor(rewards, dtype=torch.float32)

        q_values = self.model(states)
        chosen_q = q_values.gather(1, actions.unsqueeze(1)).squeeze(1)
        loss = torch.nn.functional.mse_loss(chosen_q, rewards)

        self.optimizer.zero_grad()
        loss.backward()
        self.optimizer.step()
        LOGGER.log("deep_rl_train", {"episodes": len(episodes), "loss": float(loss.item())})

    def loop(self):
        while self.running:
            try:
                episodes = MEMORY.load_episodes(max_items=512)
                self.train_batch(episodes)
            except Exception as e:
                print(f"[DEEP_RL] Loop error: {e}")
            time.sleep(20.0)

DEEP_RL = DeepRLTrainer(CONFIG["rl"])

# ============================================================
# RL CORE
# ============================================================

class BorgRLCore:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.epsilon = cfg["epsilon_start"]
        self.epsilon_end = cfg["epsilon_end"]
        self.epsilon_decay_steps = cfg["epsilon_decay_steps"]
        self.step_count = 0
        self.evolution_enabled = CONFIG["daemon"].get("borg_evolution", False)
        self.evolution_factor = 1.0

    def _update_epsilon(self):
        self.step_count += 1
        base_eps = self.cfg["epsilon_start"] - (self.step_count / self.epsilon_decay_steps) * (self.cfg["epsilon_start"] - self.epsilon_end)
        self.epsilon = max(self.epsilon_end, base_eps)
        if self.evolution_enabled:
            self.evolution_factor = min(3.0, 1.0 + self.step_count / (self.epsilon_decay_steps * 2.0))

    def _compute_network_health(self) -> Dict[str, float]:
        devices = NETWORK_SCANNER.get_snapshot()
        if not devices:
            net_health_raw = 1.0
        else:
            worst = max(d.get("score", 0.0) for d in devices)
            net_health_raw = max(0.0, 1.0 - worst)

        stability = NET_HISTORY.stability_score()
        fw_penalty = FIREWALL.consume_cycle_penalty()

        profile = CURRENT_GAME_PROFILE or CONFIG["modes"]["flow"]
        GAME_LATENCY.measure_for_profile(profile)
        latency_score, jitter = GAME_LATENCY.latency_score()

        net_health = max(0.0, min(1.0, 0.4 * net_health_raw + 0.3 * stability + 0.3 * latency_score))

        return {
            "net_health_raw": net_health_raw,
            "lan_stability": stability,
            "fw_penalty": fw_penalty,
            "latency_score": latency_score,
            "latency_jitter": jitter,
            "net_health": net_health
        }

    def _compute_reward(self, snap: SensorSnapshot) -> Tuple[float, Dict[str, float]]:
        profile = detect_game_profile()
        fps_target = profile.get("target_fps", CONFIG["modes"]["flow"]["target_fps"])
        max_gpu = profile.get("max_gpu", CONFIG["modes"]["flow"]["max_gpu"])
        max_cpu = profile.get("max_cpu", CONFIG["modes"]["flow"]["max_cpu"])
        w = CONFIG["modes"]["flow"]["reward_weights"]

        fps_stability = max(0.0, 1.0 - abs(snap.fps - fps_target) / fps_target)
        cpu_headroom = max(0.0, 1.0 - snap.cpu_usage / max_cpu)
        gpu_headroom = max(0.0, 1.0 - snap.gpu_usage / max_gpu)
        thermal_safety = max(0.0, 1.0 - max(0.0, (snap.gpu_temp - CONFIG["watchdog"]["max_temp_c"]) / 20.0))
        ft_stability = max(0.0, 1.0 - min(1.0, snap.frametime_var * 120.0))

        net_info = self._compute_network_health()
        net_health = net_info["net_health"]
        lan_stability = net_info["lan_stability"]
        fw_penalty = net_info["fw_penalty"]
        latency_score = net_info["latency_score"]

        reward = (
            w["fps_stability"] * fps_stability +
            w["cpu_headroom"] * cpu_headroom +
            w["gpu_headroom"] * gpu_headroom +
            w["thermal_safety"] * thermal_safety +
            w["frametime_stability"] * ft_stability +
            w["network_health"] * net_health
            + 0.8 * lan_stability
            + 1.0 * latency_score
            - 1.0 * fw_penalty
        )

        return reward, net_info

    def select_action(self, state: SensorSnapshot) -> Tuple[str, Dict[str, float]]:
        self._update_epsilon()
        reward, net_info = self._compute_reward(state)
        LOGGER.log("rl_state", {
            "eps": self.epsilon,
            "evolution_factor": self.evolution_factor,
            "reward": reward,
            "fps": state.fps,
            "temp": state.gpu_temp,
            "gpu": state.gpu_usage,
            "cpu": state.cpu_usage,
            **net_info
        })

        if random.random() < self.epsilon / self.evolution_factor:
            action = random.choice(["lower", "raise", "noop"])
        else:
            profile = CURRENT_GAME_PROFILE or CONFIG["modes"]["flow"]
            max_gpu = profile.get("max_gpu", CONFIG["modes"]["flow"]["max_gpu"])
            max_cpu = profile.get("max_cpu", CONFIG["modes"]["flow"]["max_cpu"])
            if state.gpu_temp > CONFIG["watchdog"]["max_temp_c"] or state.gpu_usage > max_gpu or state.cpu_usage > max_cpu:
                action = "lower"
            elif reward > 4.5 and net_info["net_health"] > 0.8 and net_info["lan_stability"] > 0.7 and net_info["latency_score"] > 0.7:
                action = "raise"
            else:
                action = "noop"

        MEMORY.store_episode(state, action, reward, net_info["net_health"])
        SWARM.publish({"kind": "rl_episode", "action": action, "reward": reward, **net_info})
        return action, net_info

    def apply_action(self, action: str, snap: SensorSnapshot):
        GPU_CURVE.tune(snap)
        if action == "lower":
            GFX.lower_global_quality()
            GFX.lower_game_quality()
        elif action == "raise":
            GFX.raise_global_quality()
            GFX.raise_game_quality()

RL_CORE = BorgRLCore(CONFIG["rl"])

# ============================================================
# WATCHDOG
# ============================================================

class BorgWatchdog:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.crash_count = 0
        self.running = True
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.backoff = cfg.get("check_interval_sec", 2.0)

    def start(self):
        print("[WATCHDOG] Starting")
        self.thread.start()

    def loop(self):
        max_temp = self.cfg["max_temp_c"]
        emergency_temp = self.cfg["emergency_temp_c"]
        backoff_max = self.cfg.get("backoff_max_sec", 12.0)
        while self.running:
            try:
                snap = SENSORS.snapshot()
                if snap.gpu_temp > emergency_temp:
                    print("[WATCHDOG] EMERGENCY TEMP — lowering quality + killing heavy background")
                    GFX.lower_global_quality()
                    GFX.lower_game_quality()
                    GFX.kill_heavy_background(cpu_threshold=0.15)
                    NVAPI.set_temp_target(max_temp)
                    self.backoff = min(backoff_max, self.backoff + 2.0)
                elif snap.gpu_temp > max_temp:
                    print("[WATCHDOG] High temp — lowering quality")
                    GFX.lower_global_quality()
                    GFX.lower_game_quality()
                    NVAPI.set_temp_target(max_temp)
                    self.backoff = min(backoff_max, self.backoff + 1.0)
                else:
                    self.backoff = max(self.cfg["check_interval_sec"], self.backoff - 0.5)

                devices = NETWORK_SCANNER.get_snapshot()
                if any(d.get("score", 0.0) >= CONFIG["network"]["threat_threshold"] for d in devices):
                    LOGGER.log("watchdog_net_anomaly", {"count": len(devices)})
            except Exception as e:
                hard_log(e, "WATCHDOG_LOOP")
                self.crash_count += 1
                if self.crash_count >= self.cfg["max_crash_count"]:
                    print("[WATCHDOG] Max crash count reached, stopping watchdog")
                    self.running = False
            time.sleep(self.backoff)

WATCHDOG = BorgWatchdog(CONFIG["watchdog"])

# ============================================================
# ANOMALY DETECTOR
# ============================================================

class AnomalyDetector:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.buffer: List[Dict[str, float]] = []

    def add(self, snap: SensorSnapshot):
        self.buffer.append({
            "cpu": snap.cpu_usage,
            "gpu": snap.gpu_usage,
            "temp": snap.gpu_temp,
            "fps": snap.fps,
            "ft_var": snap.frametime_var,
        })
        if len(self.buffer) > self.cfg["train_buffer_size"]:
            self.buffer.pop(0)

    def is_anomalous(self, snap: SensorSnapshot) -> bool:
        if snap.gpu_temp > CONFIG["watchdog"]["emergency_temp_c"] and snap.fps < 40.0:
            LOGGER.log("anomaly", {
                "temp": snap.gpu_temp,
                "fps": snap.fps,
                "ft_var": snap.frametime_var
            })
            return True
        return False

ANOMALY = AnomalyDetector(CONFIG["anomaly"])

# ============================================================
# SUPERVISOR
# ============================================================

class DaemonSupervisor:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.running = cfg.get("enabled", True)
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.targets: Dict[str, threading.Thread] = {}

    def register(self, name: str, thread: threading.Thread):
        self.targets[name] = thread

    def start(self):
        if not self.running:
            return
        print("[SUPERVISOR] Starting")
        self.thread.start()

    def loop(self):
        interval = self.cfg.get("supervisor_interval_sec", 5.0)
        while self.running:
            for name, t in list(self.targets.items()):
                if not t.is_alive():
                    LOGGER.log("supervisor_restart", {"thread": name})
                    print(f"[SUPERVISOR] Thread {name} died — cannot auto-restart (manual restart required)")
            time.sleep(interval)

SUPERVISOR = DaemonSupervisor(CONFIG["daemon"])

# ============================================================
# MOBILE REMOTE STUB
# ============================================================

class MobileRemoteHandler(BaseHTTPRequestHandler):
    def _send_json(self, payload: Dict[str, Any]):
        data = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/telemetry":
            snap = SENSORS.snapshot()
            self._send_json({
                "cpu": snap.cpu_usage,
                "gpu": snap.gpu_usage,
                "temp": snap.gpu_temp,
                "fps": snap.fps
            })
        else:
            self._send_json({"status": "ok"})

def start_mobile_remote(port: int):
    if HTTPServer is None:
        print("[MOBILE] http.server unavailable — remote-control disabled")
        return

    def loop():
        try:
            server = HTTPServer(("0.0.0.0", port), MobileRemoteHandler)
            print(f"[MOBILE] Remote-control stub listening on port {port}")
            server.serve_forever()
        except Exception as e:
            hard_log(e, "MOBILE_LOOP")

    threading.Thread(target=loop, daemon=True).start()

# ============================================================
# GUI
# ============================================================

class BorgGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title("ULTRABORG V7.3 — Gaming-First System Governor")
        self.rows: Dict[str, Dict[str, Any]] = {}
        self.tree = None
        self.net_tree = None
        self.telemetry_labels = {}
        self._build_ui()
        self._refresh_thread = threading.Thread(target=self._refresh_loop, daemon=True)
        self._net_refresh_thread = threading.Thread(target=self._net_refresh_loop, daemon=True)
        self._telemetry_thread = threading.Thread(target=self._telemetry_loop, daemon=True)
        self._refresh_thread.start()
        self._net_refresh_thread.start()
        self._telemetry_thread.start()

    def _build_ui(self):
        notebook = ttk.Notebook(self.root)

        proc_frame = ttk.Frame(notebook)
        columns = ("name", "white", "block", "kill")
        self.tree = ttk.Treeview(proc_frame, columns=columns, show="headings", height=20)
        self.tree.heading("name", text="Name")
        self.tree.heading("white", text="White")
        self.tree.heading("block", text="Block")
        self.tree.heading("kill", text="Kill")

        self.tree.column("name", width=260, anchor="w")
        self.tree.column("white", width=60, anchor="center")
        self.tree.column("block", width=60, anchor="center")
        self.tree.column("kill", width=60, anchor="center")

        self.tree.pack(fill="both", expand=True)
        self.tree.bind("<Button-1>", self._on_click)

        net_frame = ttk.Frame(notebook)
        net_columns = ("ip", "label", "ports", "score", "mac")
        self.net_tree = ttk.Treeview(net_frame, columns=net_columns, show="headings", height=20)
        self.net_tree.heading("ip", text="IP")
        self.net_tree.heading("label", text="Label")
        self.net_tree.heading("ports", text="Ports")
        self.net_tree.heading("score", text="Threat")
        self.net_tree.heading("mac", text="MAC")

        self.net_tree.column("ip", width=120, anchor="w")
        self.net_tree.column("label", width=160, anchor="w")
        self.net_tree.column("ports", width=160, anchor="w")
        self.net_tree.column("score", width=80, anchor="center")
        self.net_tree.column("mac", width=160, anchor="w")

        self.net_tree.pack(fill="both", expand=True)

        tel_frame = ttk.Frame(notebook)
        labels = {
            "cpu": ttk.Label(tel_frame, text="CPU: "),
            "gpu": ttk.Label(tel_frame, text="GPU: "),
            "temp": ttk.Label(tel_frame, text="Temp: "),
            "fps": ttk.Label(tel_frame, text="FPS: "),
            "net": ttk.Label(tel_frame, text="Net Health: "),
            "lat": ttk.Label(tel_frame, text="Latency: "),
            "jit": ttk.Label(tel_frame, text="Jitter: "),
        }
        row = 0
        for key, lbl in labels.items():
            lbl.grid(row=row, column=0, sticky="w", padx=8, pady=4)
            self.telemetry_labels[key] = lbl
            row += 1

        notebook.add(proc_frame, text="Processes")
        notebook.add(net_frame, text="Network")
        notebook.add(tel_frame, text="Telemetry")
        notebook.pack(fill="both", expand=True)

    def add_process_row(self, name: str, pid: int):
        key = name.lower()
        if key in self.rows:
            return
        white = "[X]" if key in WHITELIST else "[ ]"
        block = "[X]" if key in BLOCKLIST else "[ ]"
        kill = "[X]" if key in KILLLIST else "[ ]"
        iid = self.tree.insert("", "end", values=(name, white, block, kill))
        self.rows[key] = {
            "iid": iid,
            "name": name,
            "pid": pid,
        }

    def _toggle_list(self, key: str, list_ref: List[str], path: str):
        if key in list_ref:
            list_ref.remove(key)
        else:
            list_ref.append(key)
        save_json_list(path, list_ref)

    def _on_click(self, event):
        region = self.tree.identify("region", event.x, event.y)
        if region != "cell":
            return
        row_id = self.tree.identify_row(event.y)
        col_id = self.tree.identify_column(event.x)
        if not row_id or col_id not in ("#2", "#3", "#4"):
            return

        vals = self.tree.item(row_id, "values")
        if not vals:
            return
        name = vals[0]
        key = name.lower()

        if col_id == "#2":
            self._toggle_list(key, WHITELIST, WHITELIST_PATH)
        elif col_id == "#3":
            self._toggle_list(key, BLOCKLIST, BLOCKLIST_PATH)
        elif col_id == "#4":
            self._toggle_list(key, KILLLIST, KILLLIST_PATH)

        white = "[X]" if key in WHITELIST else "[ ]"
        block = "[X]" if key in BLOCKLIST else "[ ]"
        kill = "[X]" if key in KILLLIST else "[ ]"
        self.tree.item(row_id, values=(name, white, block, kill))

    def _refresh_loop(self):
        while True:
            try:
                for proc in psutil.process_iter(attrs=["pid", "name"]):
                    name_raw = proc.info.get("name") or ""
                    pid = proc.info.get("pid")
                    self.add_process_row(name_raw, pid)
            except Exception:
                pass
            time.sleep(10.0)

    def _net_refresh_loop(self):
        while True:
            try:
                for item in self.net_tree.get_children():
                    self.net_tree.delete(item)
                devices = NETWORK_SCANNER.get_snapshot()
                for d in devices:
                    ip = d.get("ip", "")
                    label = d.get("label", "")
                    ports = ",".join(str(p) for p in d.get("ports", []))
                    score = f"{d.get('score', 0.0):.2f}"
                    mac = d.get("mac", "")
                    self.net_tree.insert("", "end", values=(ip, label, ports, score, mac))
            except Exception:
                pass
            time.sleep(10.0)

    def _telemetry_loop(self):
        core = BorgRLCore(CONFIG["rl"])
        while True:
            try:
                snap = SENSORS.snapshot()
                net_info = core._compute_network_health()
                self.telemetry_labels["cpu"].configure(text=f"CPU: {snap.cpu_usage*100:.1f}%")
                self.telemetry_labels["gpu"].configure(text=f"GPU: {snap.gpu_usage*100:.1f}%")
                self.telemetry_labels["temp"].configure(text=f"Temp: {snap.gpu_temp:.1f} C")
                self.telemetry_labels["fps"].configure(text=f"FPS: {snap.fps:.1f}")
                self.telemetry_labels["net"].configure(text=f"Net Health: {net_info['net_health']:.2f}")
                self.telemetry_labels["lat"].configure(text=f"Latency Score: {net_info['latency_score']:.2f}")
                self.telemetry_labels["jit"].configure(text=f"Jitter: {net_info['latency_jitter']:.1f} ms")
            except Exception:
                pass
            time.sleep(3.0)

# ============================================================
# MAIN LOOP
# ============================================================

def borg_main_loop():
    print("[BORG] Main loop starting (gaming-first, V7.3)")
    KERNEL_DRIVER.init()
    UPDATER.start()
    WATCHDOG.start()
    start_ad_proxy_stub(CONFIG["adblock"]["proxy_port"])
    SWARM.start()
    DEEP_RL.start()
    NETWORK_SCANNER.start()
    PATCH_MANAGER.start()

    if CONFIG["mobile"].get("enabled", True):
        start_mobile_remote(CONFIG["mobile"]["port"])

    ad_thread = threading.Thread(target=adblock_loop, daemon=True)
    ad_thread.start()
    SUPERVISOR.register("adblock_loop", ad_thread)
    SUPERVISOR.register("watchdog", WATCHDOG.thread)
    SUPERVISOR.register("updater", UPDATER.thread)
    SUPERVISOR.register("swarm", SWARM.thread)
    SUPERVISOR.register("deep_rl", DEEP_RL.thread)
    SUPERVISOR.register("network_scanner", NETWORK_SCANNER.thread)
    SUPERVISOR.register("patch_manager", PATCH_MANAGER.thread)
    SUPERVISOR.start()

    while True:
        try:
            snap = SENSORS.snapshot()
            KERNEL_DRIVER.send_telemetry(snap)
            ANOMALY.add(snap)
            if ANOMALY.is_anomalous(snap):
                print("[BORG] Anomaly detected — lowering quality + killing heavy background")
                GFX.lower_global_quality()
                GFX.lower_game_quality()
                GFX.kill_heavy_background(cpu_threshold=0.15)

            action, net_info = RL_CORE.select_action(snap)
            RL_CORE.apply_action(action, snap)

            time.sleep(1.0)
        except KeyboardInterrupt:
            print("[BORG] KeyboardInterrupt — exiting main loop")
            break
        except Exception as e:
            hard_log(e, "BORG_MAIN")
            time.sleep(1.0)

def main():
    global GUI_INSTANCE
    if tk is not None:
        root = tk.Tk()
        GUI_INSTANCE = BorgGUI(root)
        threading.Thread(target=borg_main_loop, daemon=True).start()
        root.mainloop()
    else:
        borg_main_loop()

if __name__ == "__main__":
    main()
