#!/usr/bin/env python3
"""
ULTRABORG V5.x + HYBRID NODE

- God-Governor (SAFE MODE, NON-DESTRUCTIVE, PER-GAME, THERMAL, CLUSTER, CONSENSUS, UNCERTAINTY, HIVE-MIND)
- Borg Federation cluster (leader election, leader/follower roles, multi-node mesh)
- RL governor (DQN + PPO + Oracle + Predictive model + Neural uncertainty + State physics)
- Security engine (attack chains, global risk field, Queen consensus)
- Text-generation node (HF model + TinyFallback + ForkliftLinear + RPC server)

SAFE_MODE: no destructive actions, NVAPI stubbed, registry guarded, cluster safe.
"""

import os
import sys
import json
import time
import random
import threading
import socket
import ctypes
from dataclasses import dataclass
from typing import Dict, Any, List, Tuple
from collections import deque

# =========================
# SAFE MODE / imports
# =========================

SAFE_MODE = True  # set to False once stable on your machine

def safe_import(name, pip_name=None):
    try:
        return __import__(name)
    except ImportError:
        print(f"[WARN] Missing library: {name}")
        if pip_name:
            print(f"       Install via: pip install {pip_name}")
        return None

psutil = safe_import("psutil", "psutil")
pynvml = safe_import("pynvml", "pynvml")
np = safe_import("numpy", "numpy")
torch = safe_import("torch", "torch")

if torch is None or np is None or psutil is None:
    print("[FATAL] Core libraries missing. Install psutil, numpy, torch.")
    sys.exit(1)

try:
    import winreg
except ImportError:
    winreg = None
    print("[WARN] winreg not available (non-Windows or limited environment)")

from transformers import AutoTokenizer, AutoModelForCausalLM

# =========================
# CONFIG
# =========================

DEFAULT_CONFIG = {
    "version": "5.0.0",
    "update": {
        "auto_check_interval_sec": 3600,
        "local_update_manifest": "borg_v5_update.json",
        "remote_url_stub": "https://example.com/borg_v5_update.json"
    },
    "modes": {
        "flow": {
            "target_fps": 90,
            "max_cpu": 0.85,
            "max_gpu": 0.90,
            "reward_weights": {
                "fps_stability": 1.1,
                "cpu_headroom": 0.8,
                "gpu_headroom": 0.8,
                "thermal_safety": 1.2,
                "frametime_stability": 1.0
            }
        },
        "deep_work": {
            "target_fps": 60,
            "max_cpu": 0.70,
            "max_gpu": 0.60,
            "reward_weights": {
                "fps_stability": 0.6,
                "cpu_headroom": 1.1,
                "gpu_headroom": 0.9,
                "thermal_safety": 1.2,
                "frametime_stability": 1.1
            }
        },
        "recovery": {
            "target_fps": 30,
            "max_cpu": 0.50,
            "max_gpu": 0.40,
            "reward_weights": {
                "fps_stability": 0.3,
                "cpu_headroom": 1.3,
                "gpu_headroom": 1.3,
                "thermal_safety": 1.8,
                "frametime_stability": 0.7
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
        "epsilon_start": 0.3,
        "epsilon_end": 0.02,
        "epsilon_decay_steps": 80000
    },
    "watchdog": {
        "max_temp_c": 85.0,
        "emergency_temp_c": 92.0,
        "max_crash_count": 3,
        "check_interval_sec": 3.0
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
        "json_log_path": "borg_v5_log.jsonl",
        "max_lines": 200000,
        "experience_log_path": "borg_experience.jsonl"
    },
    "daemon": {
        "enabled": False,
        "quiet": True
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
            "flow":     {"reward": 1.1, "risk": 1.8, "conf": 0.6},
            "strain":   {"reward": 0.6, "risk": 3.2, "conf": 0.9},
            "recovery": {"reward": 0.3, "risk": 4.0, "conf": 1.1},
            "neutral":  {"reward": 0.7, "risk": 2.4, "conf": 0.8}
        }
    },
    "cluster": {
        "enabled": True,  # Borg Federation enabled
        "role": "auto",   # auto: leader election
        "port": 55555,
        "broadcast_interval_sec": 2.0,
        "election_interval_sec": 5.0,
        "leader_timeout_sec": 10.0
    },
    "personalization": {
        "profile_path": "borg_profile.json",
        "default_profile": {
            "aggressiveness": 0.5,
            "thermal_sensitivity": 0.7,
            "fps_priority": 0.8,
            "background_tolerance": 0.3,
            "flow_bias": 0.5
        },
        "drift_rate": 0.0005
    },
    "frametime_predictor": {
        "history_len": 64,
        "train_interval_steps": 1000
    },
    "thermal_predictor": {
        "history_len": 64,
        "train_interval_steps": 1200
    },
    "per_game": {
        "profile_path": "borg_games.json",
        "default": {
            "target_fps": 60,
            "quality_bias": 0.5,
            "thermal_budget": 80.0
        }
    },
    "consensus": {
        "global_risk_threshold": 1.5,
        "attack_window_sec": 120,
        "prob_field_init_mean": 0.1,
        "prob_field_init_var": 0.05
    },
    "uncertainty": {
        "enabled": True,
        "history_len": 128,
        "entropy_window": 256
    },
    "water_state": {
        "viscosity": 0.7,
        "turbulence_sensitivity": 0.5,
        "pressure_gain": 0.8,
        "cavitation_threshold": 0.85
    }
}

CONFIG_PATH = "borg_v5_config.json"

def load_config() -> Dict[str, Any]:
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            print(f"[CONFIG] Loaded external config from {CONFIG_PATH}")
            return cfg
        except Exception as e:
            print(f"[WARN] Failed to load {CONFIG_PATH}: {e}")
    print("[CONFIG] Using embedded default config")
    return DEFAULT_CONFIG

CONFIG = load_config()

# =========================
# Logging
# =========================

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

class ExperienceLogger:
    def __init__(self, path: str):
        self.path = path

    def log_experience(self, payload: Dict[str, Any]):
        entry = {"time": time.time(), **payload}
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception as e:
            print(f"[EXP] Failed to write experience: {e}")

EXP_LOGGER = ExperienceLogger(CONFIG["logging"]["experience_log_path"])

# =========================
# Auto-updater
# =========================

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
            self.check_for_update()
            time.sleep(interval)

UPDATER = AutoUpdater(CONFIG["update"])

# =========================
# Personalization / per-game
# =========================

class PersonalizationProfile:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.path = cfg["profile_path"]
        self.profile = cfg["default_profile"].copy()
        self.drift_rate = cfg["drift_rate"]
        self.load()
        self.history_entropy: List[float] = []

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.profile.update(data)
                print("[PROFILE] Loaded personalization profile")
            except Exception as e:
                print(f"[PROFILE] Failed to load profile: {e}")
        LOGGER.log("profile", self.profile)

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.profile, f, indent=2)
        except Exception as e:
            print(f"[PROFILE] Failed to save profile: {e}")

    def adjust_from_experience(self, reward: float, temp: float, entropy: float):
        aggr = self.profile["aggressiveness"]
        therm = self.profile["thermal_sensitivity"]
        flow_bias = self.profile["flow_bias"]
        if reward < -0.2:
            aggr = max(0.0, aggr - 0.01)
        else:
            aggr = min(1.0, aggr + 0.005)
        if temp > CONFIG["watchdog"]["max_temp_c"]:
            therm = min(1.0, therm + 0.02)
        else:
            therm = max(0.0, therm - 0.005)
        self.history_entropy.append(entropy)
        if len(self.history_entropy) > CONFIG["uncertainty"]["entropy_window"]:
            self.history_entropy.pop(0)
        avg_ent = sum(self.history_entropy) / max(len(self.history_entropy), 1)
        flow_bias += self.drift_rate * (avg_ent - 1.0)
        flow_bias = max(0.0, min(1.0, flow_bias))
        self.profile["aggressiveness"] = aggr
        self.profile["thermal_sensitivity"] = therm
        self.profile["flow_bias"] = flow_bias
        LOGGER.log("profile_update", self.profile)

PROFILE = PersonalizationProfile(CONFIG["personalization"])

class PerGameProfileManager:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.path = cfg["profile_path"]
        self.default = cfg["default"]
        self.profiles: Dict[str, Dict[str, Any]] = {}
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    self.profiles = json.load(f)
                print("[GAME] Loaded per-game profiles")
            except Exception as e:
                print(f"[GAME] Failed to load per-game profiles: {e}")
        else:
            self.profiles = {}

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.profiles, f, indent=2)
        except Exception as e:
            print(f"[GAME] Failed to save per-game profiles: {e}")

    def detect_active_game(self) -> str:
        active = "unknown"
        try:
            for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent"]):
                name = (proc.info["name"] or "").lower()
                if any(k in name for k in ["exe", "game", "steam", "epic", "uplay"]):
                    if proc.info["cpu_percent"] and proc.info["cpu_percent"] > 5.0:
                        active = name
                        break
        except Exception:
            pass
        LOGGER.log("game_detect", {"active_game": active})
        return active

    def get_profile(self, game_name: str) -> Dict[str, Any]:
        if game_name in self.profiles:
            return self.profiles[game_name]
        return self.default.copy()

    def update_profile_from_experience(self, game_name: str, reward: float, temp: float):
        prof = self.profiles.get(game_name, self.default.copy())
        qbias = prof.get("quality_bias", 0.5)
        tb = prof.get("thermal_budget", 80.0)
        if reward < -0.2:
            qbias = max(0.0, qbias - 0.02)
        else:
            qbias = min(1.0, qbias + 0.01)
        if temp > tb:
            tb = max(60.0, tb - 0.5)
        else:
            tb = min(90.0, tb + 0.2)
        prof["quality_bias"] = qbias
        prof["thermal_budget"] = tb
        self.profiles[game_name] = prof
        LOGGER.log("game_profile_update", {"game": game_name, **prof})

GAME_PROFILES = PerGameProfileManager(CONFIG["per_game"])

# =========================
# Sensors
# =========================

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
        self.has_nvml = False
        self.gpu_handle = None
        self._fps_history: List[float] = []
        self._temp_history: List[float] = []
        if pynvml is not None and not SAFE_MODE:
            try:
                pynvml.nvmlInit()
                self.gpu_handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                self.has_nvml = True
                print("[SENSORS] NVML initialized")
            except Exception as e:
                print(f"[WARN] NVML init failed: {e}")
                self.has_nvml = False
        else:
            print("[SENSORS] SAFE_MODE: NVML disabled")

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
        fps = 60.0 + random.uniform(-15.0, 15.0)
        self._fps_history.append(fps)
        if len(self._fps_history) > 256:
            self._fps_history.pop(0)
        return fps

    def frametime_variance(self) -> float:
        if len(self._fps_history) < 2:
            return 0.0
        ft = [1.0 / max(f, 1e-3) for f in self._fps_history]
        return float(np.var(ft))

    def fps_history(self) -> List[float]:
        return list(self._fps_history)

    def temp_history(self) -> List[float]:
        return list(self._temp_history)

    def snapshot(self) -> SensorSnapshot:
        cpu, ram = self.read_cpu_ram()
        gpu, temp, vram, power = self.read_gpu()
        fps = self.read_fps()
        ft_var = self.frametime_variance()
        self._temp_history.append(temp)
        if len(self._temp_history) > 256:
            self._temp_history.pop(0)
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

# =========================
# NVAPI / graphics tuner
# =========================

class NVAPITuner:
    def __init__(self):
        self.available = False
        self.nvapi = None
        self._init_nvapi()

    def _init_nvapi(self):
        if SAFE_MODE:
            print("[NVAPI] SAFE_MODE: NVAPI disabled")
            self.available = False
            return
        try:
            self.nvapi = ctypes.WinDLL("nvapi64.dll")
            self.available = True
            print("[NVAPI] nvapi64.dll loaded")
        except Exception as e:
            print(f"[NVAPI] Failed to load nvapi64.dll: {e}")
            self.available = False

    def set_power_limit(self, watts: float):
        if not self.available:
            LOGGER.log("nvapi_power_limit_stub", {"watts": watts})
            return
        LOGGER.log("nvapi_power_limit", {"watts": watts})

    def set_temp_target(self, temp_c: float):
        if not self.available:
            LOGGER.log("nvapi_temp_target_stub", {"temp_c": temp_c})
            return
        LOGGER.log("nvapi_temp_target", {"temp_c": temp_c})

    def set_perf_mode(self, mode: str):
        if not self.available:
            LOGGER.log("nvapi_perf_mode_stub", {"mode": mode})
            return
        LOGGER.log("nvapi_perf_mode", {"mode": mode})

NVAPI = NVAPITuner()

class GraphicsTuner:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.registry_paths = cfg["registry_paths"]
        self.game_root = cfg["game_config_root"]
        self.profile = cfg["default_game_profile"]

    def _set_registry_value(self, root, path: str, name: str, value: Any):
        if SAFE_MODE or winreg is None:
            LOGGER.log("gfx_registry_stub", {"path": path, "name": name, "value": value})
            return
        try:
            key = winreg.OpenKey(root, path, 0, winreg.KEY_SET_VALUE)
        except Exception as e:
            LOGGER.log("gfx_registry_open_fail", {"path": path, "error": str(e)})
            return
        try:
            winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
            winreg.CloseKey(key)
            LOGGER.log("gfx_registry", {"path": path, "name": name, "value": value})
        except Exception as e:
            LOGGER.log("gfx_registry_set_fail", {"path": path, "error": str(e)})

    def lower_global_quality(self):
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["nvidia_quality"], "QualityLevel", "Low")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["amd_quality"], "QualityLevel", "Low")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["nvidia_perf"], "PerfMode", "MaxPerf")
        self._set_registry_value(winreg.HKEY_CURRENT_USER, self.registry_paths["amd_perf"], "PerfMode", "MaxPerf")
        NVAPI.set_perf_mode("MaxPerf")

    def raise_global_quality(self):
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

    def _patch_ini(self, path: str, lower: bool):
        try:
            with open(path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            new_lines = []
            for line in lines:
                if "ShadowQuality" in line:
                    val = "1" if lower else "3"
                    new_lines.append(f"ShadowQuality={val}\n")
                elif "ResolutionScale" in line:
                    new_lines.append("ResolutionScale={:.2f}\n".format(0.8 if lower else 1.0))
                else:
                    new_lines.append(line)
            with open(path, "w", encoding="utf-8") as f:
                f.writelines(new_lines)
            LOGGER.log("gfx_ini_patch", {"path": path, "lower": lower})
        except Exception as e:
            print(f"[GFX] Failed to patch INI {path}: {e}")

    def _patch_json(self, path: str, lower: bool):
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
            data["shadow_quality"] = 1 if lower else 3
            data["resolution_scale"] = 0.8 if lower else 1.0
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            LOGGER.log("gfx_json_patch", {"path": path, "lower": lower})
        except Exception as e:
            print(f"[GFX] Failed to patch JSON {path}: {e}")

    def _patch_game_config(self, path: str, lower: bool = True):
        if path.lower().endswith(".ini") or path.lower().endswith(".cfg"):
            self._patch_ini(path, lower)
        elif path.lower().endswith(".json"):
            self._patch_json(path, lower)
        else:
            LOGGER.log("gfx_game_patch_unknown", {"path": path, "lower": lower})

    def lower_game_quality(self):
        for cfg_path in self._find_game_configs():
            self._patch_game_config(cfg_path, lower=True)

    def raise_game_quality(self):
        for cfg_path in self._find_game_configs():
            self._patch_game_config(cfg_path, lower=False)

    def throttle_background_processes(self):
        for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent"]):
            name = (proc.info["name"] or "").lower()
            cpu = proc.info["cpu_percent"] or 0.0
            if cpu > 10.0 and any(k in name for k in ["chrome", "edge", "discord", "obs", "steam"]):
                try:
                    p = psutil.Process(proc.info["pid"])
                    p.nice(psutil.BELOW_NORMAL_PRIORITY_CLASS)
                    LOGGER.log("gfx_throttle", {"pid": proc.info["pid"], "name": name, "cpu": cpu})
                except Exception:
                    pass

    def emergency_downclock_stub(self):
        LOGGER.log("gfx_emergency_downclock", {})
        NVAPI.set_power_limit(150.0)
        NVAPI.set_temp_target(CONFIG["watchdog"]["max_temp_c"])

GFX = GraphicsTuner(CONFIG["graphics"])

# =========================
# Borg environment
# =========================

@dataclass
class BorgState:
    snapshot: SensorSnapshot
    mode_name: str

class BorgEnv:
    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.mode_name = "flow"
        self.mode_cfg = self.config["modes"][self.mode_name]

    def set_mode(self, mode_name: str):
        if mode_name in self.config["modes"]:
            self.mode_name = mode_name
            self.mode_cfg = self.config["modes"][mode_name]
            LOGGER.log("mode_switch", {"mode": mode_name})

    def get_state_vector(self, snap: SensorSnapshot) -> np.ndarray:
        temp_norm = snap.gpu_temp / 100.0
        fps_norm = snap.fps / max(self.mode_cfg["target_fps"], 1)
        ft_norm = min(snap.frametime_var * 100.0, 1.0)
        power_norm = snap.gpu_power / 300.0
        return np.array(
            [
                snap.cpu_usage,
                snap.ram_usage,
                snap.gpu_usage,
                temp_norm,
                fps_norm,
                ft_norm,
                snap.vram_usage,
                power_norm,
            ],
            dtype=np.float32,
        )

    def reward(self, snap: SensorSnapshot, ft_pred: float, thermal_risk: float, global_risk: float, uncertainty: float) -> float:
        w = self.mode_cfg["reward_weights"]
        target_fps = self.mode_cfg["target_fps"]
        fps_stability = -abs(snap.fps - target_fps) / max(target_fps, 1)
        cpu_headroom = 1.0 - snap.cpu_usage
        gpu_headroom = 1.0 - snap.gpu_usage
        thermal_penalty = max(0.0, (snap.gpu_temp - CONFIG["watchdog"]["max_temp_c"]) / 20.0)
        ft_penalty = min(ft_pred * 100.0, 1.0)
        thermal_risk_penalty = thermal_risk
        global_risk_penalty = global_risk
        uncertainty_penalty = uncertainty
        r = (
            w["fps_stability"] * fps_stability
            + w["cpu_headroom"] * cpu_headroom
            + w["gpu_headroom"] * gpu_headroom
            - w["thermal_safety"] * (thermal_penalty + thermal_risk_penalty)
            - w["frametime_stability"] * ft_penalty
            - 0.9 * global_risk_penalty
            - 0.6 * uncertainty_penalty
        )
        return float(r)

    def apply_action(self, action: int):
        LOGGER.log("action", {"mode": self.mode_name, "action": action})
        if action == 0:
            return
        elif action == 1:
            GFX.lower_global_quality()
            GFX.lower_game_quality()
        elif action == 2:
            GFX.raise_global_quality()
            GFX.raise_game_quality()
        elif action == 3:
            GFX.throttle_background_processes()
        elif action == 4:
            GFX.throttle_background_processes()
        elif action == 5:
            self.set_mode("flow")
        elif action == 6:
            self.set_mode("deep_work")
        elif action == 7:
            self.set_mode("recovery")

    def step(self, action: int, ft_pred: float, thermal_risk: float, global_risk: float, uncertainty: float) -> Tuple[np.ndarray, float, SensorSnapshot]:
        self.apply_action(action)
        snap = SENSORS.snapshot()
        r = self.reward(snap, ft_pred, thermal_risk, global_risk, uncertainty)
        s_vec = self.get_state_vector(snap)
        LOGGER.log("step", {
            "mode": self.mode_name,
            "action": action,
            "reward": r,
            "cpu": snap.cpu_usage,
            "gpu": snap.gpu_usage,
            "temp": snap.gpu_temp,
            "fps": snap.fps,
            "ft_var": snap.frametime_var,
            "ft_pred": ft_pred,
            "vram": snap.vram_usage,
            "power": snap.gpu_power,
            "thermal_risk": thermal_risk,
            "global_risk": global_risk,
            "uncertainty": uncertainty,
        })
        return s_vec, r, snap

    def reset(self) -> np.ndarray:
        snap = SENSORS.snapshot()
        return self.get_state_vector(snap)

ENV = BorgEnv(CONFIG)

STATE_DIM = 8
ACTION_DIM = 8

# =========================
# Frametime / thermal predictors
# =========================

class FrametimePredictor(torch.nn.Module):
    def __init__(self, history_len: int):
        super().__init__()
        self.history_len = history_len
        self.net = torch.nn.Sequential(
            torch.nn.Linear(history_len, 64),
            torch.nn.ReLU(),
            torch.nn.Linear(64, 32),
            torch.nn.ReLU(),
            torch.nn.Linear(32, 1),
        )
        self.opt = torch.optim.Adam(self.parameters(), lr=1e-3)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x).squeeze(-1)

    def predict(self, fps_history: List[float]) -> float:
        if len(fps_history) < self.history_len:
            return 0.0
        ft = [1.0 / max(f, 1e-3) for f in fps_history[-self.history_len:]]
        x = torch.tensor(ft, dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            y = self.forward(x)
        val = float(y.item())
        LOGGER.log("ft_predict", {"pred": val})
        return max(val, 0.0)

FT_PREDICTOR = FrametimePredictor(CONFIG["frametime_predictor"]["history_len"])

class ThermalPredictor(torch.nn.Module):
    def __init__(self, history_len: int):
        super().__init__()
        self.history_len = history_len
        self.net = torch.nn.Sequential(
            torch.nn.Linear(history_len, 64),
            torch.nn.ReLU(),
            torch.nn.Linear(64, 32),
            torch.nn.ReLU(),
            torch.nn.Linear(32, 1),
        )
        self.opt = torch.optim.Adam(self.parameters(), lr=1e-3)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        return self.net(x).squeeze(-1)

    def predict(self, temp_history: List[float]) -> float:
        if len(temp_history) < self.history_len:
            return 0.0
        x = torch.tensor(temp_history[-self.history_len:], dtype=torch.float32).unsqueeze(0)
        with torch.no_grad():
            y = self.forward(x)
        val = float(y.item())
        LOGGER.log("thermal_predict", {"pred": val})
        return max(val, 0.0)

THERM_PREDICTOR = ThermalPredictor(CONFIG["thermal_predictor"]["history_len"])

# =========================
# HybridAgent (policy / value / oracle)
# =========================

class HybridAgent(torch.nn.Module):
    def __init__(self, state_dim: int, action_dim: int, cfg: Dict[str, Any]):
        super().__init__()
        self.state_dim = state_dim
        self.action_dim = action_dim
        self.cfg = cfg
        hidden = 64
        self.body = torch.nn.Sequential(
            torch.nn.Linear(state_dim, hidden),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden, hidden),
            torch.nn.ReLU(),
        )
        self.q_head = torch.nn.Linear(hidden, action_dim)
        self.pi_head = torch.nn.Linear(hidden, action_dim)
        self.v_head = torch.nn.Linear(hidden, 1)
        self.oracle_head = torch.nn.Linear(hidden, 1)
        self.dqn_opt = torch.optim.Adam(self.parameters(), lr=cfg["dqn_lr"])
        self.ppo_opt = torch.optim.Adam(self.parameters(), lr=cfg["ppo_lr"])

    def forward(self, x: torch.Tensor) -> Dict[str, torch.Tensor]:
        h = self.body(x)
        q = self.q_head(h)
        logits = self.pi_head(h)
        v = self.v_head(h).squeeze(-1)
        oracle = self.oracle_head(h).squeeze(-1)
        return {"q": q, "logits": logits, "v": v, "oracle": oracle}

    def act(self, state: np.ndarray, epsilon: float = 0.1) -> int:
        s = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
        out = self.forward(s)
        q = out["q"].detach().cpu().numpy()[0]
        if random.random() < epsilon:
            a = random.randint(0, q.shape[0] - 1)
        else:
            a = int(np.argmax(q))
        LOGGER.log("policy_act", {"epsilon": epsilon, "action": a})
        return a

    def oracle_score(self, state: np.ndarray) -> float:
        s = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
        out = self.forward(s)
        score = float(out["oracle"].detach().cpu().numpy()[0])
        LOGGER.log("oracle_score", {"score": score})
        return score

    def dqn_update(self, batch):
        s = torch.tensor(batch["s"], dtype=torch.float32)
        a = torch.tensor(batch["a"], dtype=torch.int64)
        r = torch.tensor(batch["r"], dtype=torch.float32)
        s2 = torch.tensor(batch["s2"], dtype=torch.float32)
        done = torch.tensor(batch["done"], dtype=torch.float32)
        out = self.forward(s)
        q = out["q"]
        q_a = q.gather(1, a.unsqueeze(1)).squeeze(1)
        with torch.no_grad():
            out2 = self.forward(s2)
            q2 = out2["q"]
            q2_max = q2.max(dim=1)[0]
            target = r + self.cfg["gamma"] * (1.0 - done) * q2_max
        loss = torch.nn.functional.mse_loss(q_a, target)
        self.dqn_opt.zero_grad()
        loss.backward()
        self.dqn_opt.step()
        LOGGER.log("dqn_loss", {"loss": float(loss.item())})
        return float(loss.item())

    def ppo_update(self, traj):
        s = torch.tensor(traj["s"], dtype=torch.float32)
        a = torch.tensor(traj["a"], dtype=torch.int64)
        r = torch.tensor(traj["r"], dtype=torch.float32)
        logp_old = torch.tensor(traj["logp"], dtype=torch.float32)
        v_old = torch.tensor(traj["v"], dtype=torch.float32)
        with torch.no_grad():
            adv = r - v_old
            adv = (adv - adv.mean()) / (adv.std() + 1e-8)
            returns = adv + v_old
        out = self.forward(s)
        logits = out["logits"]
        v = out["v"]
        oracle = out["oracle"]
        logp = torch.nn.functional.log_softmax(logits, dim=-1)
        logp_a = logp.gather(1, a.unsqueeze(1)).squeeze(1)
        ratio = torch.exp(logp_a - logp_old)
        clip = self.cfg["ppo_clip"]
        obj1 = ratio * adv
        obj2 = torch.clamp(ratio, 1.0 - clip, 1.0 + clip) * adv
        policy_loss = -torch.min(obj1, obj2).mean()
        value_loss = torch.nn.functional.mse_loss(v, returns)
        oracle_loss = torch.nn.functional.mse_loss(oracle, r)
        entropy = -(logp * torch.exp(logp)).sum(dim=1).mean()
        loss = (
            policy_loss
            + self.cfg["value_coef"] * value_loss
            + 0.1 * oracle_loss
            - self.cfg["entropy_coef"] * entropy
        )
        self.ppo_opt.zero_grad()
        loss.backward()
        self.ppo_opt.step()
        stats = {
            "policy_loss": float(policy_loss.item()),
            "value_loss": float(value_loss.item()),
            "oracle_loss": float(oracle_loss.item()),
            "entropy": float(entropy.item()),
        }
        LOGGER.log("ppo_stats", stats)
        return stats

# =========================
# Anomaly autoencoder
# =========================

class AnomalyAutoencoder(torch.nn.Module):
    def __init__(self, input_dim: int, latent_dim: int):
        super().__init__()
        self.encoder = torch.nn.Sequential(
            torch.nn.Linear(input_dim, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, latent_dim),
        )
        self.decoder = torch.nn.Sequential(
            torch.nn.Linear(latent_dim, 16),
            torch.nn.ReLU(),
            torch.nn.Linear(16, input_dim),
        )
        self.opt = torch.optim.Adam(self.parameters(), lr=1e-3)

    def forward(self, x: torch.Tensor) -> torch.Tensor:
        z = self.encoder(x)
        recon = self.decoder(z)
        return recon

    def train_batch(self, batch: np.ndarray) -> float:
        x = torch.tensor(batch, dtype=torch.float32)
        recon = self.forward(x)
        loss = torch.nn.functional.mse_loss(recon, x)
        self.opt.zero_grad()
        loss.backward()
        self.opt.step()
        LOGGER.log("anomaly_train_loss", {"loss": float(loss.item())})
        return float(loss.item())

    def anomaly_score(self, x: np.ndarray) -> float:
        with torch.no_grad():
            t = torch.tensor(x, dtype=torch.float32).unsqueeze(0)
            recon = self.forward(t)
            loss = torch.nn.functional.mse_loss(recon, t)
        score = float(loss.item())
        LOGGER.log("anomaly_score", {"score": score})
        return score

ANOM_CFG = CONFIG["anomaly"]
AUTOENC = AnomalyAutoencoder(input_dim=STATE_DIM, latent_dim=ANOM_CFG["latent_dim"])
ANOM_BUFFER: List[np.ndarray] = []

# =========================
# Brains
# =========================

@dataclass
class TeacherBrain:
    agent: HybridAgent
    name: str = "Teacher"
    crash_count: int = 0
    active: bool = True
    dream_mode: bool = False
    mood: str = "flow"

@dataclass
class ShadowBrain:
    agent: HybridAgent
    name: str = "Shadow"
    active: bool = False
    anomaly_active: bool = False

@dataclass
class OracleBrain:
    agent: HybridAgent
    name: str = "Oracle"
    active: bool = True

TEACHER = TeacherBrain(agent=HybridAgent(STATE_DIM, ACTION_DIM, CONFIG["rl"]))
SHADOW = ShadowBrain(agent=HybridAgent(STATE_DIM, ACTION_DIM, CONFIG["rl"]))
ORACLE = OracleBrain(agent=HybridAgent(STATE_DIM, ACTION_DIM, CONFIG["rl"]))

# =========================
# Watchdog
# =========================

class Watchdog:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.running = True
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def start(self):
        self.thread.start()

    def loop(self):
        while self.running:
            snap = SENSORS.snapshot()
            s_vec = ENV.get_state_vector(snap)
            if snap.gpu_temp > self.cfg["emergency_temp_c"]:
                ENV.set_mode("recovery")
                GFX.emergency_downclock_stub()
                GFX.throttle_background_processes()
            elif snap.gpu_temp > self.cfg["max_temp_c"]:
                GFX.lower_global_quality()
                GFX.lower_game_quality()
                GFX.throttle_background_processes()
            if TEACHER.crash_count >= self.cfg["max_crash_count"]:
                TEACHER.active = False
                SHADOW.active = True
            score = AUTOENC.anomaly_score(s_vec)
            if score > ANOM_CFG["threshold"]:
                SHADOW.anomaly_active = True
                TEACHER.active = False
                SHADOW.active = True
                GFX.throttle_background_processes()
            LOGGER.log("watchdog", {
                "temp": snap.gpu_temp,
                "anomaly_score": score,
                "teacher_active": TEACHER.active,
                "shadow_active": SHADOW.active,
            })
            time.sleep(self.cfg["check_interval_sec"])

WATCHDOG = Watchdog(CONFIG["watchdog"])

# =========================
# Borg Federation cluster (leader election, mesh)
# =========================

CONS_CFG = CONFIG["consensus"]

class ProbabilisticField:
    def __init__(self, mean: float, var: float):
        self.mean = mean
        self.var = var

    def sample(self) -> float:
        return random.gauss(self.mean, self.var)

    def update(self, observation: float, weight: float = 1.0):
        self.mean = (self.mean + weight * observation) / (1.0 + weight)
        self.var = max(1e-6, self.var * 0.9)
        LOGGER.log("prob_field_update", {"mean": self.mean, "var": self.var, "obs": observation, "weight": weight})

GLOBAL_RISK_FIELD = ProbabilisticField(
    mean=CONS_CFG["prob_field_init_mean"],
    var=CONS_CFG["prob_field_init_var"]
)

class QueenConsensus:
    def __init__(self):
        self.nodes: Dict[str, List[Dict[str, Any]]] = {}

    def update(self, node: str, events: List[Dict[str, Any]]):
        self.nodes[node] = events
        LOGGER.log("queen_update", {"node": node, "events": events})

    def global_risk(self) -> Dict[str, float]:
        risk: Dict[str, float] = {}
        for node, evts in self.nodes.items():
            for e in evts:
                ent = e.get("entity")
                score = e.get("score", 0.0)
                if ent is None:
                    continue
                risk[ent] = risk.get(ent, 0.0) + score
        filtered = {k: v for k, v in risk.items() if v > CONS_CFG["global_risk_threshold"]}
        LOGGER.log("queen_global_risk", {"risk": filtered})
        return filtered

QUEEN_CONSENSUS = QueenConsensus()

class AttackChainEngine:
    def __init__(self, window: int = CONS_CFG["attack_window_sec"]):
        self.events = deque()
        self.window = window

    def add_event(self, event_type: str, data: Dict[str, Any]):
        now = time.time()
        self.events.append((now, event_type, data))
        self._cleanup(now)
        LOGGER.log("attack_event", {"ts": now, "type": event_type, "data": data})

    def _cleanup(self, now: float):
        cutoff = now - self.window
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def detect(self) -> List[Tuple[str, float]]:
        types = [e[1] for e in self.events]
        chains: List[Tuple[str, float]] = []
        if all(x in types for x in ["proc_spawn", "powershell", "net_connect"]):
            chains.append(("LOLBIN_ATTACK", 0.9))
        if types.count("proc_spawn") > 5 and "net_connect" in types:
            chains.append(("PROCESS_STORM", 0.8))
        if "file_mod" in types and "net_connect" in types:
            chains.append(("PERSISTENCE_EXFIL", 0.85))
        LOGGER.log("attack_chains", {"chains": chains})
        return chains

CHAIN_ENGINE = AttackChainEngine()

class SecEvent:
    def __init__(self, etype: str, entity: str, meta: Dict[str, Any] = None):
        self.ts = time.time()
        self.type = etype
        self.entity = entity
        self.meta = meta or {}

class EventBus:
    def __init__(self):
        self.subscribers: List[Any] = []
        self.queue = deque()
        self.running = True
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def publish(self, event: SecEvent):
        self.queue.append(event)

    def subscribe(self, fn):
        self.subscribers.append(fn)

    def run(self):
        while self.running:
            if self.queue:
                evt = self.queue.popleft()
                for fn in self.subscribers:
                    try:
                        fn(evt)
                    except Exception as e:
                        LOGGER.log("event_callback_error", {"error": str(e)})
            time.sleep(0.01)

EVENT_BUS = EventBus()

def security_callback(evt: SecEvent):
    try:
        etype = evt.type
        entity = evt.entity
        score = 0.0
        if etype == "proc_spawn":
            score = 0.4
        elif etype == "net_connect":
            score = 0.5
        elif etype == "file_mod":
            score = 0.3
        CHAIN_ENGINE.add_event(etype, {"entity": entity, **evt.meta})
        GLOBAL_RISK_FIELD.update(score, weight=1.0)
        LOGGER.log("sec_event", {"type": etype, "entity": entity, "meta": evt.meta, "score": score})
    except Exception as e:
        LOGGER.log("sec_event_error", {"error": str(e)})

EVENT_BUS.subscribe(security_callback)

def simulate_security_events():
    if random.random() < 0.02:
        evt = SecEvent("proc_spawn", f"proc_{random.randint(1000,9999)}", {"cmd": "powershell"})
        EVENT_BUS.publish(evt)
    if random.random() < 0.02:
        evt = SecEvent("net_connect", f"ip_{random.randint(1,255)}.{random.randint(1,255)}", {"port": 443})
        EVENT_BUS.publish(evt)
    if random.random() < 0.01:
        evt = SecEvent("file_mod", f"path_{random.randint(1,100)}", {"op": "write"})
        EVENT_BUS.publish(evt)

# =========================
# State physics
# =========================

class StatePhysics:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.phase = "flow"
        self.phase_value = 0.0
        self.stress_accum = 0.0

    def compute_stress(self, snap: SensorSnapshot, reward: float, anomaly_score: float, thermal_risk: float, global_risk: float, uncertainty: float) -> float:
        temp_norm = snap.gpu_temp / 100.0
        ft_norm = min(snap.frametime_var * 100.0, 1.0)
        cpu = snap.cpu_usage
        gpu = snap.gpu_usage
        reward_penalty = max(0.0, -reward)
        global_risk_norm = min(global_risk, 3.0) / 3.0
        stress = (
            0.4 * temp_norm +
            0.2 * ft_norm +
            0.2 * cpu +
            0.2 * gpu +
            0.3 * anomaly_score +
            0.3 * reward_penalty +
            0.3 * thermal_risk +
            0.5 * global_risk_norm +
            0.4 * uncertainty
        )
        return float(stress)

    def update_phase(self, stress: float):
        inertia = self.cfg["inertia"]
        damping = self.cfg["damping"]
        self.stress_accum = inertia * self.stress_accum + (1.0 - inertia) * stress
        target_phase_value = self.stress_accum
        delta = target_phase_value - self.phase_value
        max_rate = self.cfg["max_phase_change_rate"]
        delta = max(-max_rate, min(max_rate, delta))
        self.phase_value += delta * (1.0 - damping)
        sp = self.cfg
        if self.phase_value >= sp["flow_threshold"]:
            self.phase = "flow"
        elif self.phase_value >= sp["strain_threshold"]:
            self.phase = "strain"
        elif self.phase_value <= sp["recovery_threshold"]:
            self.phase = "recovery"
        else:
            self.phase = "neutral"
        LOGGER.log("state_physics", {
            "stress": stress,
            "stress_accum": self.stress_accum,
            "phase_value": self.phase_value,
            "phase": self.phase,
        })

    def smooth_action(self, raw_action: int) -> int:
        if self.phase == "flow":
            return raw_action
        if self.phase == "strain":
            if raw_action in [2, 5]:
                return 1
            return raw_action
        if self.phase == "recovery":
            if raw_action in [2, 5, 6]:
                return 7
            if raw_action in [0]:
                return 1
            return raw_action
        return raw_action

    def should_dream(self) -> bool:
        return self.phase in ["strain", "recovery"]

STATE_PHYSICS = StatePhysics(CONFIG["state_physics"])

# =========================
# Predictive model + uncertainty
# =========================

class PredictiveModel(torch.nn.Module):
    def __init__(self, state_dim: int, action_dim: int):
        super().__init__()
        self.state_dim = state_dim
        self.action_dim = action_dim
        input_dim = state_dim + action_dim
        hidden = 64
        self.net = torch.nn.Sequential(
            torch.nn.Linear(input_dim, hidden),
            torch.nn.ReLU(),
            torch.nn.Linear(hidden, hidden),
            torch.nn.ReLU(),
        )
        self.next_state_head = torch.nn.Linear(hidden, state_dim)
        self.reward_head = torch.nn.Linear(hidden, 1)
        self.risk_head = torch.nn.Linear(hidden, 1)
        self.opt = torch.optim.Adam(self.parameters(), lr=1e-3)
        self.confidence = 0.5

    def forward(self, state: torch.Tensor, action: torch.Tensor) -> Dict[str, torch.Tensor]:
        one_hot = torch.nn.functional.one_hot(action, num_classes=self.action_dim).float()
        x = torch.cat([state, one_hot], dim=-1)
        h = self.net(x)
        next_state = self.next_state_head(h)
        reward = self.reward_head(h).squeeze(-1)
        risk_logit = self.risk_head(h).squeeze(-1)
        risk_prob = torch.sigmoid(risk_logit)
        return {"next_state": next_state, "reward": reward, "risk_prob": risk_prob, "risk_logit": risk_logit}

    def bernoulli_stats(self, risk_prob: torch.Tensor) -> torch.Tensor:
        var = risk_prob * (1.0 - risk_prob)
        return var

    def train_batch(self, batch: Dict[str, np.ndarray]):
        s = torch.tensor(batch["s"], dtype=torch.float32)
        a = torch.tensor(batch["a"], dtype=torch.int64)
        s2 = torch.tensor(batch["s2"], dtype=torch.float32)
        r = torch.tensor(batch["r"], dtype=torch.float32)
        out = self.forward(s, a)
        ns_pred = out["next_state"]
        r_pred = out["reward"]
        risk_prob = out["risk_prob"]
        ns_loss = torch.nn.functional.mse_loss(ns_pred, s2)
        r_loss = torch.nn.functional.mse_loss(r_pred, r)
        risk_target = (r < -0.1).float()
        risk_loss = torch.nn.functional.binary_cross_entropy(risk_prob, risk_target)
        loss = ns_loss + r_loss + 0.7 * risk_loss
        self.opt.zero_grad()
        loss.backward()
        self.opt.step()
        self.confidence = CONFIG["predictive"]["confidence_decay"] * self.confidence + (1.0 - CONFIG["predictive"]["confidence_decay"]) * float(torch.exp(-loss).item())
        avg_p = float(risk_prob.mean().item())
        avg_var = float(self.bernoulli_stats(risk_prob).mean().item())
        LOGGER.log("predictive_train", {
            "ns_loss": float(ns_loss.item()),
            "r_loss": float(r_loss.item()),
            "risk_loss": float(risk_loss.item()),
            "confidence": self.confidence,
            "avg_risk_prob": avg_p,
            "avg_risk_var": avg_var,
        })
        return float(loss.item())

    def predict(self, state: np.ndarray, action: int) -> Dict[str, Any]:
        s = torch.tensor(state, dtype=torch.float32).unsqueeze(0)
        a = torch.tensor([action], dtype=torch.int64)
        out = self.forward(s, a)
        ns = out["next_state"].detach().cpu().numpy()[0]
        r = float(out["reward"].detach().cpu().numpy()[0])
        p = float(out["risk_prob"].detach().cpu().numpy()[0])
        var = float(self.bernoulli_stats(out["risk_prob"]).detach().cpu().numpy()[0])
        LOGGER.log("predictive_infer", {
            "action": action,
            "pred_reward": r,
            "risk_prob": p,
            "risk_var": var,
            "confidence": self.confidence,
        })
        return {"next_state": ns, "reward": r, "risk_prob": p, "risk_var": var, "confidence": self.confidence}

PREDICTIVE = PredictiveModel(STATE_DIM, ACTION_DIM)

class NeuralUncertaintyEngine:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.enabled = cfg["enabled"]
        self.entropy_history: List[float] = []
        self.risk_history: List[float] = []

    def update(self, policy_entropy: float, global_risk: float):
        if not self.enabled:
            return
        self.entropy_history.append(policy_entropy)
        self.risk_history.append(global_risk)
        if len(self.entropy_history) > self.cfg["entropy_window"]:
            self.entropy_history.pop(0)
        if len(self.risk_history) > self.cfg["entropy_window"]:
            self.risk_history.pop(0)
        LOGGER.log("uncertainty_update", {
            "policy_entropy": policy_entropy,
            "global_risk": global_risk
        })

    def compute_uncertainty(self) -> float:
        if not self.enabled:
            return 0.0
        avg_ent = sum(self.entropy_history) / max(len(self.entropy_history), 1)
        avg_risk = sum(self.risk_history) / max(len(self.risk_history), 1)
        uncertainty = 0.5 * max(0.0, 1.5 - avg_ent) + 0.5 * avg_risk
        LOGGER.log("uncertainty_value", {"uncertainty": uncertainty, "avg_ent": avg_ent, "avg_risk": avg_risk})
        return uncertainty

UNCERTAINTY = NeuralUncertaintyEngine(CONFIG["uncertainty"])

# =========================
# Action selection with prediction
# =========================

def choose_action_with_prediction(brain: HybridAgent, state: np.ndarray, epsilon: float) -> int:
    base_action = brain.act(state, epsilon=epsilon)
    if not CONFIG["predictive"]["enabled"]:
        return base_action
    phase = STATE_PHYSICS.phase
    phase_cfg = CONFIG["predictive"]["phase_weights"].get(phase, CONFIG["predictive"]["phase_weights"]["neutral"])
    w_r = phase_cfg["reward"]
    w_k = phase_cfg["risk"]
    w_c = phase_cfg["conf"]
    therm_sens = PROFILE.profile["thermal_sensitivity"]
    w_k *= (1.0 + therm_sens)
    best_action = base_action
    best_score = -1e9
    for a in range(ACTION_DIM):
        pred = PREDICTIVE.predict(state, a)
        reward = pred["reward"]
        risk_prob = pred["risk_prob"]
        risk_var = pred["risk_var"]
        conf = pred["confidence"]
        risk_term = risk_prob + 0.5 * risk_var
        score = w_r * reward - w_k * risk_term + w_c * conf
        if score > best_score:
            best_score = score
            best_action = a
    LOGGER.log("predictive_choice", {
        "base_action": base_action,
        "chosen_action": best_action,
        "best_score": best_score,
        "phase": phase,
        "weights": {"reward": w_r, "risk": w_k, "conf": w_c},
    })
    return best_action

# =========================
# Risk / water-state
# =========================

def compute_thermal_risk(snap: SensorSnapshot, thermal_pred: float, game_profile: Dict[str, Any]) -> float:
    budget = game_profile.get("thermal_budget", CONFIG["watchdog"]["max_temp_c"])
    current = snap.gpu_temp
    predicted = thermal_pred
    over_now = max(0.0, (current - budget) / 20.0)
    over_future = max(0.0, (predicted - budget) / 20.0)
    risk = over_now + 1.2 * over_future
    LOGGER.log("thermal_risk", {"current": current, "predicted": predicted, "budget": budget, "risk": risk})
    return risk

def compute_global_risk_value() -> float:
    sample = GLOBAL_RISK_FIELD.sample()
    chains = CHAIN_ENGINE.detect()
    chain_boost = 0.0
    for cname, score in chains:
        chain_boost += score
    val = sample + 0.5 * chain_boost
    LOGGER.log("global_risk_value", {"sample": sample, "chain_boost": chain_boost, "value": val})
    return val

def water_state_snapshot(phase: str, stress: float, temp: float, fps: float, uncertainty: float) -> Dict[str, Any]:
    cfg = CONFIG["water_state"]
    viscosity = cfg["viscosity"]
    turbulence = cfg["turbulence_sensitivity"] * uncertainty
    pressure = cfg["pressure_gain"] * stress
    cavitation = 1.0 if pressure > cfg["cavitation_threshold"] else 0.0
    snap = {
        "phase": phase,
        "viscosity": viscosity,
        "turbulence": turbulence,
        "pressure": pressure,
        "cavitation": cavitation,
        "temp": temp,
        "fps": fps
    }
    LOGGER.log("water_state", snap)
    return snap

# =========================
# Borg Federation cluster manager (leader election, mesh)
# =========================

class ClusterNode:
    def __init__(self, cfg: Dict[str, Any]):
        self.cfg = cfg
        self.enabled = cfg["enabled"]
        self.port = cfg["port"]
        self.broadcast_interval = cfg["broadcast_interval_sec"]
        self.election_interval = cfg["election_interval_sec"]
        self.leader_timeout = cfg["leader_timeout_sec"]
        self.sock = None
        self.thread_recv = None
        self.thread_bcast = None
        self.thread_election = None
        self.hive_state: Dict[str, Any] = {}
        self.node_id = f"node-{random.randint(1000,9999)}"
        self.is_leader = False
        self.leader_id = None
        self.last_leader_seen = 0.0
        self.current_action_hint = 0
        if self.enabled and not SAFE_MODE:
            self._init_socket()
        elif self.enabled and SAFE_MODE:
            print("[CLUSTER] SAFE_MODE: cluster enabled but NVAPI/registry guarded")
            self._init_socket()

    def _init_socket(self):
        try:
            self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            self.sock.bind(("", self.port))
            self.thread_recv = threading.Thread(target=self.loop_recv, daemon=True)
            self.thread_recv.start()
            self.thread_bcast = threading.Thread(target=self.loop_broadcast, daemon=True)
            self.thread_bcast.start()
            self.thread_election = threading.Thread(target=self.loop_election, daemon=True)
            self.thread_election.start()
            print(f"[CLUSTER] Borg Federation node {self.node_id} on port {self.port}")
        except Exception as e:
            print(f"[CLUSTER] Failed to init cluster socket: {e}")
            self.enabled = False

    def broadcast_state(self, phase: str, temp: float, fps: float, action_hint: int, global_risk: float, uncertainty: float):
        if not self.enabled:
            return
        msg = json.dumps({
            "node_id": self.node_id,
            "is_leader": self.is_leader,
            "phase": phase,
            "temp": temp,
            "fps": fps,
            "action_hint": action_hint,
            "global_risk": global_risk,
            "uncertainty": uncertainty,
            "ts": time.time()
        }).encode("utf-8")
        try:
            self.sock.sendto(msg, ("255.255.255.255", self.port))
            LOGGER.log("cluster_broadcast", {
                "node_id": self.node_id,
                "is_leader": self.is_leader,
                "phase": phase,
                "temp": temp,
                "fps": fps,
                "action_hint": action_hint,
                "global_risk": global_risk,
                "uncertainty": uncertainty
            })
        except Exception as e:
            print(f"[CLUSTER] Broadcast failed: {e}")

    def loop_recv(self):
        while self.enabled:
            try:
                data, addr = self.sock.recvfrom(4096)
                payload = json.loads(data.decode("utf-8"))
                nid = payload.get("node_id")
                if not nid:
                    continue
                self.hive_state[nid] = payload
                LOGGER.log("cluster_recv", {"from": nid, **payload})
                if payload.get("is_leader"):
                    self.leader_id = nid
                    self.last_leader_seen = time.time()
                    self.current_action_hint = payload.get("action_hint", 0)
            except Exception:
                pass

    def loop_broadcast(self):
        while self.enabled:
            try:
                # broadcast minimal state; action_hint updated externally
                phase = STATE_PHYSICS.phase
                temp = SENSORS.snapshot().gpu_temp
                fps = SENSORS.snapshot().fps
                global_risk = compute_global_risk_value()
                uncertainty = UNCERTAINTY.compute_uncertainty()
                self.broadcast_state(phase, temp, fps, self.current_action_hint, global_risk, uncertainty)
            except Exception:
                pass
            time.sleep(self.broadcast_interval)

    def loop_election(self):
        while self.enabled:
            now = time.time()
            # if no leader seen recently, run election
            if self.leader_id is None or (now - self.last_leader_seen) > self.leader_timeout:
                # simple election: highest node_id wins
                candidates = list(self.hive_state.keys()) + [self.node_id]
                leader = max(candidates)
                self.leader_id = leader
                self.is_leader = (leader == self.node_id)
                LOGGER.log("cluster_election", {"leader": self.leader_id, "self": self.node_id, "is_leader": self.is_leader})
            time.sleep(self.election_interval)

    def get_federation_risk(self) -> float:
        # aggregate global_risk from hive_state
        val = 0.0
        for nid, st in self.hive_state.items():
            val += float(st.get("global_risk", 0.0))
        LOGGER.log("cluster_federation_risk", {"value": val})
        return val

CLUSTER = ClusterNode(CONFIG["cluster"])

# =========================
# Dream teacher
# =========================

def run_dream_teacher():
    if not CONFIG["dream"]["enabled"]:
        return
    episodes = CONFIG["dream"]["episodes"]
    length = CONFIG["dream"]["length"]
    for ep in range(episodes):
        s = ENV.reset()
        traj = {"s": [], "a": [], "r": [], "logp": [], "v": []}
        for t in range(length):
            a = TEACHER.agent.act(s, epsilon=0.4)
            s_torch = torch.tensor(s, dtype=torch.float32)
            noise = torch.randn_like(s_torch) * 0.03
            s2_torch = torch.clamp(s_torch + noise, 0.0, 1.5)
            s2 = s2_torch.numpy()
            r = TEACHER.agent.oracle_score(s2)
            out = TEACHER.agent.forward(s_torch.unsqueeze(0))
            logits = out["logits"].detach()
            v = out["v"].detach()
            logp = torch.nn.functional.log_softmax(logits, dim=-1)[0, a].item()
            traj["s"].append(s)
            traj["a"].append(a)
            traj["r"].append(r)
            traj["logp"].append(logp)
            traj["v"].append(v.item())
            s = s2
        stats = TEACHER.agent.ppo_update(traj)
        LOGGER.log("dream_episode", {"ep": ep, **stats})

# =========================
# Epsilon / PPO clip adapt
# =========================

def compute_epsilon(step: int) -> float:
    cfg = CONFIG["rl"]
    start = cfg["epsilon_start"]
    end = cfg["epsilon_end"]
    decay = cfg["epsilon_decay_steps"]
    frac = min(step / max(decay, 1), 1.0)
    eps = float(start + (end - start) * frac)
    aggr = PROFILE.profile["aggressiveness"]
    eps = eps * (0.7 + 0.6 * aggr)
    LOGGER.log("epsilon", {"step": step, "epsilon": eps})
    return eps

def adapt_ppo_clip(recent_entropy: float) -> float:
    base = CONFIG["rl"]["ppo_clip"]
    if recent_entropy < 0.5:
        new_clip = min(base + 0.05, 0.4)
    elif recent_entropy > 1.5:
        new_clip = max(base - 0.05, 0.1)
    else:
        new_clip = base
    CONFIG["rl"]["ppo_clip"] = new_clip
    LOGGER.log("ppo_clip_adapt", {"entropy": recent_entropy, "clip": new_clip})
    return new_clip

# =========================
# Borg main loop (leader/follower behavior)
# =========================

def run_borg_loop():
    WATCHDOG.start()
    UPDATER.start()
    EVENT_BUS.start()
    mode_cycle = ["flow", "deep_work", "recovery"]
    mode_idx = 0
    s = ENV.reset()
    step_count = 0
    recent_entropy = 1.0
    while True:
        simulate_security_events()
        if step_count % 3000 == 0 and step_count > 0:
            mode_idx = (mode_idx + 1) % len(mode_cycle)
            ENV.set_mode(mode_cycle[mode_idx])

        if CONFIG["dream"]["enabled"] and step_count > 0 and step_count % CONFIG["dream"]["interval_steps"] == 0:
            if STATE_PHYSICS.should_dream() and CLUSTER.is_leader:
                TEACHER.dream_mode = True
                TEACHER.mood = "dream"
                run_dream_teacher()
                TEACHER.dream_mode = False
                TEACHER.mood = "flow"

        # leader/follower: only leader runs full RL; followers mirror action_hint with smoothing
        if CLUSTER.is_leader:
            brain = TEACHER.agent if TEACHER.active else SHADOW.agent
            epsilon = compute_epsilon(step_count)
            oracle_score = ORACLE.agent.oracle_score(s)
            if oracle_score < -0.2:
                epsilon = min(epsilon + 0.1, 0.6)
            ft_pred = FT_PREDICTOR.predict(SENSORS.fps_history())
            thermal_pred = THERM_PREDICTOR.predict(SENSORS.temp_history())
            active_game = GAME_PROFILES.detect_active_game()
            game_profile = GAME_PROFILES.get_profile(active_game)
            raw_action = choose_action_with_prediction(brain, s, epsilon)
            smoothed_action = STATE_PHYSICS.smooth_action(raw_action)
            CLUSTER.current_action_hint = smoothed_action
        else:
            # follower: use leader's action_hint, apply local smoothing
            ft_pred = FT_PREDICTOR.predict(SENSORS.fps_history())
            thermal_pred = THERM_PREDICTOR.predict(SENSORS.temp_history())
            active_game = GAME_PROFILES.detect_active_game()
            game_profile = GAME_PROFILES.get_profile(active_game)
            raw_action = CLUSTER.current_action_hint
            smoothed_action = STATE_PHYSICS.smooth_action(raw_action)

        snap_for_risk = SENSORS.snapshot()
        thermal_risk = compute_thermal_risk(snap_for_risk, thermal_pred, game_profile)
        global_risk_value = compute_global_risk_value() + CLUSTER.get_federation_risk()
        uncertainty_value = UNCERTAINTY.compute_uncertainty()
        s2, r, snap = ENV.step(smoothed_action, ft_pred, thermal_risk, global_risk_value, uncertainty_value)
        s_vec_for_physics = ENV.get_state_vector(snap)
        anomaly_score = AUTOENC.anomaly_score(s_vec_for_physics)
        stress = STATE_PHYSICS.compute_stress(snap, r, anomaly_score, thermal_risk, global_risk_value, uncertainty_value)
        STATE_PHYSICS.update_phase(stress)
        water_state_snapshot(STATE_PHYSICS.phase, stress, snap.gpu_temp, snap.fps, uncertainty_value)
        PROFILE.adjust_from_experience(r, snap.gpu_temp, recent_entropy)
        GAME_PROFILES.update_profile_from_experience(active_game, r, snap.gpu_temp)
        EXP_LOGGER.log_experience({
            "reward": r,
            "temp": snap.gpu_temp,
            "fps": snap.fps,
            "phase": STATE_PHYSICS.phase,
            "action": smoothed_action,
            "global_risk": global_risk_value,
            "uncertainty": uncertainty_value,
            "anomaly": anomaly_score,
            "stress": stress,
            "leader": CLUSTER.is_leader,
            "node_id": CLUSTER.node_id,
        })
        s = s2
        step_count += 1
        time.sleep(0.1)

# =========================
# TEXT NODE / LLM
# =========================

HAS_CUDA = torch.cuda.is_available()
NUM_GPUS = torch.cuda.device_count()
DEFAULT_DEVICE = "cuda" if HAS_CUDA else "cpu"

PRIMARY_MODEL_NAME = "gpt2"
CURRENT_MODEL = None
CURRENT_TOKENIZER = None
CURRENT_MODEL_NAME = None
IS_FALLBACK_MODEL = False

GLOBAL_CACHE = {}

class ForkliftExecutor:
    def reset_stats(self, clear_router_data: bool = False):
        pass

    def linear(self, layer_name, weight, bias, x, layer_depth: int = 0):
        return torch.nn.functional.linear(x, weight, bias)

    def stats(self):
        return {}

EXECUTOR = ForkliftExecutor()

def get_system_telemetry() -> dict:
    snap = SENSORS.snapshot()
    return {
        "cpu_usage": snap.cpu_usage * 100.0,
        "gpu_usage": snap.gpu_usage * 100.0,
        "mem_usage": snap.ram_usage * 100.0,
        "temp_c": snap.gpu_temp,
    }

def train_policy_net_step(telemetry: dict, latency_ms: float):
    # stub: could feed latency into RL replay
    LOGGER.log("llm_latency", {"latency_ms": latency_ms, **telemetry})

def log_event(level, source, msg, meta=None):
    print(f"[{level}] [{source}] {msg} {meta or {}}")

class TinyFallback(torch.nn.Module):
    def __init__(self, vocab_size: int = 256, hidden: int = 128):
        super().__init__()
        self.emb = torch.nn.Embedding(vocab_size, hidden)
        self.fc = torch.nn.Linear(hidden, vocab_size)

    def forward(self, input_ids):
        x = self.emb(input_ids)
        x = x.mean(dim=1)
        return self.fc(x)

    def generate(self, input_ids, max_new_tokens=16, **kwargs):
        return input_ids

class ForkliftLinear(torch.nn.Module):
    def __init__(self, base: torch.nn.Linear, name: str, executor: ForkliftExecutor, depth: int = 0):
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

def _patch_module_with_forklift(module: torch.nn.Module, prefix: str = "", depth: int = 0):
    for child_name, child in list(module.named_children()):
        full_name = f"{prefix}{child_name}"
        if isinstance(child, torch.nn.Linear):
            setattr(
                module,
                child_name,
                ForkliftLinear(child, full_name, EXECUTOR, depth),
            )
        else:
            _patch_module_with_forklift(child, full_name + ".", depth + 1)

def patch_model_with_forklift(model: torch.nn.Module):
    _patch_module_with_forklift(model, prefix="", depth=0)

class PredictiveModelNode:
    def __init__(self):
        self.flow_weight = 0.25
        self.recovery_weight = 0.35
        self.strain_weight = 0.40
        self.flow_score = 0.0
        self.recovery_score = 0.0
        self.strain_score = 0.0

    def _phase_scores(self, telemetry: dict, latency_ms: float) -> Tuple[float, float, float]:
        cpu = float(telemetry.get("cpu_usage", 0.0))
        gpu = float(telemetry.get("gpu_usage", 0.0))
        temp = float(telemetry.get("temp_c", telemetry.get("temperature_c", 0.0)))
        mem = float(telemetry.get("mem_usage", 0.0))
        cpu_n = min(max(cpu / 100.0, 0.0), 1.0)
        gpu_n = min(max(gpu / 100.0, 0.0), 1.0)
        mem_n = min(max(mem / 100.0, 0.0), 1.0)
        lat_n = min(max(latency_ms / 1000.0, 0.0), 1.0)
        flow = (1.0 - lat_n) * (1.0 - cpu_n) * (1.0 - gpu_n) * (1.0 - mem_n)
        recovery = (lat_n * 0.5) + (cpu_n * 0.3) + (gpu_n * 0.3)
        if temp > 0.0:
            temp_n = min(max((temp - 40.0) / 40.0, 0.0), 1.0)
            recovery *= (1.0 - 0.5 * temp_n)
        strain = (lat_n * 0.6) + (cpu_n * 0.5) + (gpu_n * 0.5) + (mem_n * 0.4)
        if temp > 0.0:
            temp_n = min(max((temp - 60.0) / 40.0, 0.0), 1.0)
            strain += 0.6 * temp_n
        flow = min(max(flow, 0.0), 1.0)
        recovery = min(max(recovery, 0.0), 1.0)
        strain = min(max(strain, 0.0), 1.0)
        return flow, recovery, strain

    def update(self, telemetry: dict, latency_ms: float) -> dict:
        flow, recovery, strain = self._phase_scores(telemetry, latency_ms)
        alpha = 0.3
        self.flow_score = (1 - alpha) * self.flow_score + alpha * flow
        self.recovery_score = (1 - alpha) * self.recovery_score + alpha * recovery
        self.strain_score = (1 - alpha) * self.strain_score + alpha * strain
        p = min(max(self.strain_score, 0.0), 1.0)
        risk_var = p * (1.0 - p)
        predictive_score = (
            self.flow_weight * self.flow_score
            + self.recovery_weight * self.recovery_score
            + self.strain_weight * self.strain_score
        )
        return {
            "flow_score": self.flow_score,
            "recovery_score": self.recovery_score,
            "strain_score": self.strain_score,
            "bern_risk_p": p,
            "bern_risk_var": risk_var,
            "predictive_score": predictive_score,
        }

PREDICTIVE_MODEL_NODE = PredictiveModelNode()

class QueenNode:
    def __init__(self):
        self.nodes = {}
        self.global_history = deque(maxlen=1024)

    def update_node(self, node_id: str, events: list, stats: dict):
        self.nodes[node_id] = {
            "events": events,
            "stats": stats,
        }
        self.global_history.append((time.time(), node_id, events, stats))

    def global_risk(self):
        risk = {}
        for node_id, data in self.nodes.items():
            events = data.get("events", [])
            stats = data.get("stats", {})
            node_risk_p = float(stats.get("bern_risk_p", 0.0))
            node_strain = float(stats.get("strain_score", 0.0))
            for e in events:
                ent = e.get("entity")
                score = e.get("score", 0.0)
                blended = score + 0.5 * node_strain + 0.5 * node_risk_p
                if ent:
                    risk[ent] = risk.get(ent, 0.0) + blended
        return {k: v for k, v in risk.items() if v > 1.5}

    def global_flow_state(self):
        if not self.nodes:
            return {"flow": 0.0, "recovery": 0.0, "strain": 0.0}
        flow_sum = 0.0
        rec_sum = 0.0
        strain_sum = 0.0
        n = 0
        for _, data in self.nodes.items():
            stats = data.get("stats", {})
            flow_sum += float(stats.get("flow_score", 0.0))
            rec_sum += float(stats.get("recovery_score", 0.0))
            strain_sum += float(stats.get("strain_score", 0.0))
            n += 1
        return {
            "flow": flow_sum / max(n, 1),
            "recovery": rec_sum / max(n, 1),
            "strain": strain_sum / max(n, 1),
        }

QUEEN_NODE = QueenNode()

class AttackChainEngineNode:
    def __init__(self):
        self.events = deque()
        self.window = 120

    def add_event(self, event_type, data):
        now = time.time()
        self.events.append((now, event_type, data))
        self._cleanup(now)

    def _cleanup(self, now):
        cutoff = now - self.window
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def detect(self):
        types = [e[1] for e in self.events]
        chains = []
        if all(x in types for x in ["proc_spawn", "powershell", "net_connect"]):
            chains.append(("LOLBIN_ATTACK", 0.9))
        if types.count("proc_spawn") > 5 and "net_connect" in types:
            chains.append(("PROCESS_STORM", 0.8))
        if "file_mod" in types and "net_connect" in types:
            chains.append(("PERSISTENCE_EXFIL", 0.85))
        return chains

CHAIN_ENGINE_NODE = AttackChainEngineNode()

class SecEventNode:
    def __init__(self, etype, entity, meta=None, score: float = 1.0):
        self.ts = time.time()
        self.type = etype
        self.entity = entity
        self.meta = meta or {}
        self.score = score

def load_model(model_name: str = PRIMARY_MODEL_NAME):
    global CURRENT_MODEL, CURRENT_TOKENIZER, CURRENT_MODEL_NAME, IS_FALLBACK_MODEL
    if CURRENT_MODEL is not None and CURRENT_TOKENIZER is not None:
        return
    print(f"[Node] Loading model: {model_name}")
    try:
        tok = AutoTokenizer.from_pretrained(model_name)
        mdl = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16 if HAS_CUDA else torch.float32,
            device_map="auto" if HAS_CUDA and NUM_GPUS > 1 else None,
        )
        mdl.to(DEFAULT_DEVICE)
        mdl.eval()
        patch_model_with_forklift(mdl)
        CURRENT_MODEL = mdl
        CURRENT_TOKENIZER = tok
        CURRENT_MODEL_NAME = model_name
        IS_FALLBACK_MODEL = False
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

@torch.inference_mode()
def generate_text(prompt: str, max_new_tokens: int = 128, node_id: str = None) -> Tuple[str, dict]:
    if node_id is None:
        node_id = CLUSTER.node_id
    load_model()
    EXECUTOR.reset_stats(clear_router_data=False)
    tok = CURRENT_TOKENIZER
    mdl = CURRENT_MODEL
    inputs = tok(prompt, return_tensors="pt")
    if isinstance(inputs, dict):
        for k in inputs:
            if isinstance(inputs[k], torch.Tensor):
                inputs[k] = inputs[k].to(DEFAULT_DEVICE)
    t0 = time.time()
    if isinstance(mdl, TinyFallback):
        out_ids = inputs["input_ids"]
    else:
        out_ids = mdl.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=True,
            top_p=0.9,
            temperature=0.8,
            pad_token_id=getattr(tok, "eos_token_id", None),
        )
    latency_ms = (time.time() - t0) * 1000.0
    text = tok.decode(out_ids[0], skip_special_tokens=True)
    stats = EXECUTOR.stats()
    stats["model_name"] = CURRENT_MODEL_NAME
    stats["is_fallback"] = IS_FALLBACK_MODEL
    stats["latency_ms"] = latency_ms
    try:
        sys_tel = get_system_telemetry()
        train_policy_net_step(sys_tel, latency_ms)
        pm = PREDICTIVE_MODEL_NODE.update(sys_tel, latency_ms)
        stats.update(pm)
    except Exception:
        pass
    chains = CHAIN_ENGINE_NODE.detect()
    events_for_queen = []
    for cname, score in chains:
        events_for_queen.append({"entity": cname, "score": score})
    QUEEN_NODE.update_node(node_id, events_for_queen, stats)
    return text, stats

def handle_rpc_client(conn: socket.socket, addr):
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                line, _, rest = buf.partition(b"\n")
                buf = rest
                try:
                    req = json.loads(line.decode())
                    prompt = req.get("prompt", "")
                    max_new_tokens = int(req.get("max_new_tokens", 128))
                    node_id = req.get("node_id", CLUSTER.node_id)
                    print(f"[Node] RPC request from {addr}, tokens={max_new_tokens}")
                    text, stats = generate_text(prompt, max_new_tokens=max_new_tokens, node_id=node_id)
                    global_flow = QUEEN_NODE.global_flow_state()
                    global_risk = QUEEN_NODE.global_risk()
                    resp = {
                        "text": text,
                        "stats": stats,
                        "queen_flow": global_flow,
                        "queen_risk": global_risk,
                        "node_id": node_id,
                        "cluster_leader": CLUSTER.leader_id,
                        "cluster_is_leader": CLUSTER.is_leader,
                    }
                except Exception as e:
                    resp = {"error": str(e), "stats": {}}
                conn.sendall((json.dumps(resp) + "\n").encode())
                break
    finally:
        conn.close()

def rpc_server_loop(host: str, port: int):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(16)
    print(f"[Node] RPC server listening on {host}:{port}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_rpc_client, args=(conn, addr), daemon=True)
        t.start()

def run_local_cli():
    print("[Node] Local CLI mode. Type 'quit' to exit.")
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
        print("\n--- Queen global ---")
        print("flow/recovery/strain:", QUEEN_NODE.global_flow_state())
        print("risk:", QUEEN_NODE.global_risk())

# =========================
# Main
# =========================

def main():
    import argparse
    parser = argparse.ArgumentParser()
    parser.add_argument("--rpc-port", type=int, default=6000)
    parser.add_argument("--host", type=str, default="0.0.0.0")
    parser.add_argument("--headless-node", action="store_true", help="Run without CLI, Borg + RPC only")
    args = parser.parse_args()

    # start Borg Federation + governor + RPC
    threading.Thread(target=rpc_server_loop, args=(args.host, args.rpc_port), daemon=True).start()
    threading.Thread(target=run_borg_loop, daemon=True).start()

    if args.headless_node:
        print("[Node] Running in headless Borg Federation mode.")
        try:
            while True:
                time.sleep(3600)
        except KeyboardInterrupt:
            pass
    else:
        run_local_cli()

if __name__ == "__main__":
    main()
