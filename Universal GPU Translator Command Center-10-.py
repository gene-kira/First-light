#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Universal GPU Translator Command Center (Next-Level, Game-Aware, ORIGINAL LOADER RESTORED)
With Game Detection Tab (Compact Card Layout + Additive Override + Stricter Game Detection, Stabilized Refresh)
"""

import os
import sys
import subprocess
import importlib
import json
import time
import traceback

APP_VERSION = "1.3.6-UGTC-GAME-NEXT-COMPARE-CARDS-STRICT-DETECT-STABLE"
AUTOLOADER_VERSION = "1.0-ORIGINAL"
LOGFILE = os.path.join(os.getcwd(), "gpu_translator.log")
PROFILE_PATH = os.path.join(os.getcwd(), "gpu_translation_profiles.json")
SETTINGS_PATH = os.path.join(os.getcwd(), "gpu_translator_settings.json")
PLUGIN_DIR = os.path.join(os.getcwd(), "plugins")
AI_DATASET_PATH = os.path.join(os.getcwd(), "gpu_ai_dataset.json")

# ======================================================================
# Logging
# ======================================================================

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOGFILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# ======================================================================
# ORIGINAL-STYLE AUTOLOADER (RESTORED)
# ======================================================================

REQUIRED_LIBRARIES = {
    "PySide6": "PySide6",
    "GPUtil": "gputil",
    "psutil": "psutil",
    "numpy": "numpy",
    "torch": "torch",
    "pynvml": "pynvml",
    "jsonschema": "jsonschema",
    "requests": "requests",
}

def install_package(pkg_name):
    log(f"[AUTOLOADER] Installing missing package: {pkg_name}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name])
        log(f"[AUTOLOADER] Successfully installed: {pkg_name}")
    except Exception as e:
        log(f"[AUTOLOADER] FAILED to install {pkg_name}: {e}")

def check_and_import(lib, pkg):
    try:
        return importlib.import_module(lib)
    except ImportError:
        install_package(pkg)
        try:
            return importlib.import_module(lib)
        except ImportError as e:
            log(f"[AUTOLOADER] FINAL FAILURE: Could not import {lib}: {e}")
            return None

def autoload():
    log(f"[AUTOLOADER] Autoloader v{AUTOLOADER_VERSION} starting...")
    loaded_modules = {}
    for lib, pkg in REQUIRED_LIBRARIES.items():
        log(f"[AUTOLOADER] Checking library: {lib}")
        module = check_and_import(lib, pkg)
        loaded_modules[lib] = module
    log("[AUTOLOADER] Autoloader finished.")
    return loaded_modules

MODULES = autoload()

PySide6 = MODULES.get("PySide6")
GPUtil = MODULES.get("GPUtil")
psutil = MODULES.get("psutil")
np = MODULES.get("numpy")
torch = MODULES.get("torch")
pynvml = MODULES.get("pynvml")
jsonschema = MODULES.get("jsonschema")
requests = MODULES.get("requests")

if PySide6 is None:
    log("[FATAL] PySide6 could not be loaded. Install with: pip install PySide6")
    sys.exit(1)

from PySide6 import QtWidgets, QtCore, QtGui

# ======================================================================
# Plugin System
# ======================================================================

class PluginManager:
    def __init__(self, plugin_dir=PLUGIN_DIR):
        self.plugin_dir = plugin_dir
        self.plugins = []
        self._load_plugins()

    def _load_plugins(self):
        if not os.path.isdir(self.plugin_dir):
            os.makedirs(self.plugin_dir, exist_ok=True)
            log(f"[PluginManager] Created plugin directory at {self.plugin_dir}")
            return
        for fname in os.listdir(self.plugin_dir):
            if not fname.endswith(".py"):
                continue
            path = os.path.join(self.plugin_dir, fname)
            mod_name = f"plugin_{os.path.splitext(fname)[0]}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                module = importlib.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.plugins.append(module)
                log(f"[PluginManager] Loaded plugin: {fname}")
            except Exception as e:
                log(f"[PluginManager] Failed to load plugin {fname}: {e}")
                log(traceback.format_exc())

    def _call_hook(self, hook_name, *args, **kwargs):
        for plugin in self.plugins:
            func = getattr(plugin, hook_name, None)
            if callable(func):
                try:
                    func(*args, **kwargs)
                except Exception as e:
                    log(f"[PluginManager] Plugin hook {hook_name} failed: {e}")
                    log(traceback.format_exc())

    def on_gpu_detected(self, gpus):
        self._call_hook("on_gpu_detected", gpus)

    def on_profile_built(self, profile_dict):
        self._call_hook("on_profile_built", profile_dict)

    def on_benchmark_completed(self, profile_dict):
        self._call_hook("on_benchmark_completed", profile_dict)

    def on_game_detected(self, game_info, profile_dict):
        self._call_hook("on_game_detected", game_info, profile_dict)

    def on_policy_applied(self, policy_dict):
        self._call_hook("on_policy_applied", policy_dict)

# ======================================================================
# GPU + Driver Detection
# ======================================================================

class GPUInfo:
    def __init__(self, name="", id_str="", memory_total_mb=0, load=0.0,
                 driver_version="", vendor="unknown", temperature=None,
                 cuda_capability=None):
        self.name = name
        self.id_str = id_str
        self.memory_total_mb = memory_total_mb
        self.load = load
        self.driver_version = driver_version
        self.vendor = vendor
        self.temperature = temperature
        self.cuda_capability = cuda_capability

    def to_dict(self):
        return {
            "name": self.name,
            "id": self.id_str,
            "memory_total_mb": self.memory_total_mb,
            "load": self.load,
            "driver_version": self.driver_version,
            "vendor": self.vendor,
            "temperature": self.temperature,
            "cuda_capability": self.cuda_capability,
        }

class GPUDetector:
    def __init__(self):
        self.gpus = []
        self.initialized_nvml = False
        self._init_nvml()

    def _init_nvml(self):
        if pynvml is None:
            log("[GPUDetector] pynvml not available, NV-specific info disabled.")
            return
        try:
            pynvml.nvmlInit()
            self.initialized_nvml = True
            log("[GPUDetector] NVML initialized.")
        except Exception as e:
            log(f"[GPUDetector] NVML init failed: {e}")
            self.initialized_nvml = False

    def _get_nvml_info(self, index):
        if not self.initialized_nvml:
            return None, None, None
        try:
            handle = pynvml.nvmlDeviceGetHandleByIndex(index)
            mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
            driver = pynvml.nvmlSystemGetDriverVersion()
            temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
            return mem, driver, temp
        except Exception as e:
            log(f"[GPUDetector] NVML info failed for index {index}: {e}")
            return None, None, None

    def detect(self):
        self.gpus = []
        try:
            if GPUtil is None:
                log("[GPUDetector] GPUtil not available, no GPU list.")
                return self.gpus

            devices = GPUtil.getGPUs()
            for idx, d in enumerate(devices):
                mem_info, driver_version, temp = self._get_nvml_info(idx)
                if mem_info:
                    mem_total_mb = int(mem_info.total / (1024 * 1024))
                else:
                    mem_total_mb = int(getattr(d, "memoryTotal", 0))

                vendor = "nvidia" if "NVIDIA" in d.name.upper() else "unknown"

                cuda_cap = None
                if torch is not None and torch.cuda.is_available():
                    try:
                        cap = torch.cuda.get_device_capability(idx)
                        cuda_cap = f"{cap[0]}.{cap[1]}"
                    except Exception:
                        cuda_cap = None

                gpu = GPUInfo(
                    name=d.name,
                    id_str=str(d.id),
                    memory_total_mb=mem_total_mb,
                    load=float(d.load) * 100.0,
                    driver_version=driver_version if driver_version else "unknown",
                    vendor=vendor,
                    temperature=temp,
                    cuda_capability=cuda_cap,
                )
                self.gpus.append(gpu)

            log(f"[GPUDetector] Detected {len(self.gpus)} GPU(s).")
        except Exception as e:
            log(f"[GPUDetector] Detection error: {e}")
            log(traceback.format_exc())
        return self.gpus

class DriverInfo:
    def __init__(self, name="", version="", api_support=None):
        self.name = name
        self.version = version
        self.api_support = api_support or {
            "DirectX": False,
            "Vulkan": False,
            "OpenGL": False,
            "CUDA": False,
        }

    def to_dict(self):
        return {
            "name": self.name,
            "version": self.version,
            "api_support": self.api_support,
        }

class DriverDetector:
    def __init__(self, gpu_detector: GPUDetector):
        self.gpu_detector = gpu_detector
        self.drivers = []

    def detect(self):
        self.drivers = []
        try:
            gpus = self.gpu_detector.detect()
            for gpu in gpus:
                api_support = {
                    "DirectX": True,
                    "Vulkan": True,
                    "OpenGL": True,
                    "CUDA": gpu.cuda_capability is not None,
                }
                driver = DriverInfo(
                    name=f"{gpu.vendor}_driver",
                    version=gpu.driver_version,
                    api_support=api_support,
                )
                self.drivers.append(driver)
            log(f"[DriverDetector] Detected {len(self.drivers)} driver(s) (inferred).")
        except Exception as e:
            log(f"[DriverDetector] Detection error: {e}")
            log(traceback.format_exc())
        return self.drivers

# ======================================================================
# AI Translation Engine
# ======================================================================

class TranslationProfile:
    def __init__(self, gpu: GPUInfo, driver: DriverInfo, mode="balanced",
                 ai_score=0.0, heuristic_score=0.0, benchmark_score=0.0,
                 capabilities=None, game_exe=None, policy=None,
                 aggressiveness=1):
        self.gpu = gpu
        self.driver = driver
        self.mode = mode
        self.created_at = time.time()
        self.ai_score = ai_score
        self.heuristic_score = heuristic_score
        self.benchmark_score = benchmark_score
        self.capabilities = capabilities or {}
        self.game_exe = game_exe
        self.policy = policy or {
            "type": "auto",
            "aggressiveness": aggressiveness,
        }

    def to_dict(self):
        return {
            "gpu": self.gpu.to_dict() if self.gpu else None,
            "driver": self.driver.to_dict() if self.driver else None,
            "mode": self.mode,
            "created_at": self.created_at,
            "ai_score": self.ai_score,
            "heuristic_score": self.heuristic_score,
            "benchmark_score": self.benchmark_score,
            "capabilities": self.capabilities,
            "game_exe": self.game_exe,
            "policy": self.policy,
        }

class TinyTranslatorNet(torch.nn.Module if torch is not None else object):
    def __init__(self):
        if torch is None:
            return
        super().__init__()
        self.fc1 = torch.nn.Linear(10, 32)
        self.fc2 = torch.nn.Linear(32, 16)
        self.fc3 = torch.nn.Linear(16, 1)
        self.act = torch.nn.ReLU()

    def forward(self, x):
        x = self.act(self.fc1(x))
        x = self.act(self.fc2(x))
        x = self.fc3(x)
        return x

class AITranslatorEngine:
    def __init__(self):
        self.current_profile = None
        self.model = None
        self.device = None
        self._init_model()
        self._maybe_train_from_dataset()

    def _init_model(self):
        if torch is None:
            log("[AITranslatorEngine] Torch not available, using heuristic only.")
            return
        try:
            self.device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            self.model = TinyTranslatorNet().to(self.device)
            self.model.eval()
            log(f"[AITranslatorEngine] TinyTranslatorNet initialized on {self.device}.")
        except Exception as e:
            log(f"[AITranslatorEngine] Failed to init TinyTranslatorNet: {e}")
            log(traceback.format_exc())
            self.model = None
            self.device = None

    def _encode_features(self, gpu: GPUInfo, driver: DriverInfo, mode: str, policy, benchmark_score: float):
        mem_gb = gpu.memory_total_mb / 1024.0
        load_pct = gpu.load

        vendor_vec = [0.0, 0.0]
        if gpu.vendor.lower() == "nvidia":
            vendor_vec[0] = 1.0
        else:
            vendor_vec[1] = 1.0

        mode_vec = [0.0, 0.0, 0.0, 0.0]
        mode = mode.lower()
        if mode == "balanced":
            mode_vec[0] = 1.0
        elif mode == "performance":
            mode_vec[1] = 1.0
        elif mode == "eco":
            mode_vec[2] = 1.0
        else:
            mode_vec[3] = 1.0

        cuda_flag = 1.0 if driver.api_support.get("CUDA", False) else 0.0
        bench_norm = benchmark_score / 100.0 if benchmark_score > 0 else 0.0
        aggr = float(policy.get("aggressiveness", 1))

        features = [mem_gb, load_pct] + vendor_vec + mode_vec + [cuda_flag, bench_norm, aggr]
        return features

    def _heuristic_score(self, gpu: GPUInfo, mode: str, benchmark_score: float, policy):
        base = gpu.memory_total_mb / 1024.0
        load_factor = max(0.1, 1.0 - gpu.load / 100.0)

        mode = mode.lower()
        if mode == "performance":
            mode_factor = 1.4
        elif mode == "eco":
            mode_factor = 0.8
        elif mode == "compatibility":
            mode_factor = 0.9
        else:
            mode_factor = 1.0

        bench_factor = 1.0 + (benchmark_score / 150.0)
        aggr = float(policy.get("aggressiveness", 1))
        aggr_factor = 1.0 + (aggr * 0.1)

        score = base * load_factor * mode_factor * bench_factor * aggr_factor * 10.0
        return score

    def _maybe_train_from_dataset(self):
        if self.model is None or self.device is None or torch is None:
            return
        if not os.path.exists(AI_DATASET_PATH):
            log("[AITranslatorEngine] No AI dataset found, skipping training.")
            return
        try:
            with open(AI_DATASET_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if not isinstance(data, list) or not data:
                log("[AITranslatorEngine] AI dataset empty, skipping training.")
                return

            xs = []
            ys = []
            for entry in data:
                feats = entry.get("features")
                target = entry.get("target")
                if feats is None or target is None:
                    continue
                xs.append(feats)
                ys.append([float(target)])

            x_tensor = torch.tensor(xs, dtype=torch.float32, device=self.device)
            y_tensor = torch.tensor(ys, dtype=torch.float32, device=self.device)

            self.model.train()
            opt = torch.optim.Adam(self.model.parameters(), lr=1e-3)
            loss_fn = torch.nn.MSELoss()

            for epoch in range(10):
                opt.zero_grad()
                pred = self.model(x_tensor)
                loss = loss_fn(pred, y_tensor)
                loss.backward()
                opt.step()
            self.model.eval()
            log("[AITranslatorEngine] Trained TinyTranslatorNet from local dataset.")
        except Exception as e:
            log(f"[AITranslatorEngine] Training failed, continuing with default weights: {e}")
            log(traceback.format_exc())

    def build_profile(self, gpu: GPUInfo, driver: DriverInfo, mode="balanced",
                      benchmark_score: float = 0.0, capabilities=None,
                      game_exe=None, policy=None):
        if policy is None:
            policy = {"type": "auto", "aggressiveness": 1}

        ai_score = 0.0
        heuristic_score = self._heuristic_score(gpu, mode, benchmark_score, policy)

        if self.model is not None and self.device is not None and torch is not None:
            try:
                feats = self._encode_features(gpu, driver, mode, policy, benchmark_score)
                x = torch.tensor(feats, dtype=torch.float32, device=self.device).unsqueeze(0)
                with torch.no_grad():
                    out = self.model(x)
                ai_score = float(out.item())
                log(f"[AITranslatorEngine] AI score={ai_score:.3f}, heuristic={heuristic_score:.3f}")
            except Exception as e:
                log(f"[AITranslatorEngine] AI inference failed, using heuristic only: {e}")
                log(traceback.format_exc())
                ai_score = heuristic_score
        else:
            ai_score = heuristic_score
            log(f"[AITranslatorEngine] Using heuristic only, score={heuristic_score:.3f}")

        self.current_profile = TranslationProfile(
            gpu, driver, mode, ai_score, heuristic_score, benchmark_score,
            capabilities, game_exe, policy,
            aggressiveness=policy.get("aggressiveness", 1)
        )
        return self.current_profile

    def simulate_translation_score(self):
        if not self.current_profile:
            return 0.0
        return self.current_profile.ai_score

    def export_profile(self):
        if not self.current_profile:
            return None
        return self.current_profile.to_dict()

# ======================================================================
# Benchmarking Engine
# ======================================================================

class BenchmarkEngine:
    def __init__(self):
        self.last_score = 0.0

    def run_microbench(self):
        if torch is None:
            log("[BenchmarkEngine] Torch not available, benchmark skipped.")
            self.last_score = 0.0
            return self.last_score
        try:
            device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
            size = 1024
            a = torch.randn((size, size), device=device)
            b = torch.randn((size, size), device=device)
            if device.type == "cuda":
                torch.cuda.synchronize()
            t0 = time.time()
            c = torch.matmul(a, b)
            if device.type == "cuda":
                torch.cuda.synchronize()
            t1 = time.time()
            elapsed = t1 - t0
            ops = size * size * size
            gflops = (ops / elapsed) / 1e9
            self.last_score = gflops
            log(f"[BenchmarkEngine] Matmul benchmark: {gflops:.2f} GFLOPS (elapsed {elapsed:.3f}s)")
            return self.last_score
        except Exception as e:
            log(f"[BenchmarkEngine] Benchmark failed: {e}")
            log(traceback.format_exc())
            self.last_score = 0.0
            return self.last_score

# ======================================================================
# Profile & Settings Manager
# ======================================================================

class ProfileManager:
    def __init__(self, path=PROFILE_PATH):
        self.path = path
        self.profiles = self._load_all()

    def _load_all(self):
        if not os.path.exists(self.path):
            return []
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                log(f"[ProfileManager] Loaded {len(data)} profile(s).")
                return data
            return []
        except Exception as e:
            log(f"[ProfileManager] Failed to load profiles: {e}")
            log(traceback.format_exc())
            return []

    def save_profile(self, profile_dict):
        self.profiles.append(profile_dict)
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.profiles, f, indent=2)
            log("[ProfileManager] Profile saved.")
        except Exception as e:
            log(f"[ProfileManager] Failed to save profile: {e}")
            log(traceback.format_exc())

    def list_profiles(self):
        return self.profiles

    def find_profile_for_game(self, game_exe):
        if not game_exe:
            return None
        for p in self.profiles:
            if p.get("game_exe") == game_exe:
                return p
        return None

    def find_profile_by_index(self, index):
        if 0 <= index < len(self.profiles):
            return self.profiles[index]
        return None

class SettingsManager:
    def __init__(self, path=SETTINGS_PATH):
        self.path = path
        self.settings = self._load()

    def _load(self):
        if not os.path.exists(self.path):
            log("[SettingsManager] No settings file, using defaults.")
            return {
                "auto_mode": True,
                "last_gpu_id": None,
                "last_driver_version": None,
                "last_mode": "balanced",
                "global_aggressiveness": 1,
                "default_game_policy": "auto",
                "manual_override": 0,
            }
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            log("[SettingsManager] Settings loaded.")
            return {
                "auto_mode": bool(data.get("auto_mode", True)),
                "last_gpu_id": data.get("last_gpu_id"),
                "last_driver_version": data.get("last_driver_version"),
                "last_mode": data.get("last_mode", "balanced"),
                "global_aggressiveness": int(data.get("global_aggressiveness", 1)),
                "default_game_policy": data.get("default_game_policy", "auto"),
                "manual_override": int(data.get("manual_override", 0)),
            }
        except Exception as e:
            log(f"[SettingsManager] Failed to load settings, using defaults: {e}")
            log(traceback.format_exc())
            return {
                "auto_mode": True,
                "last_gpu_id": None,
                "last_driver_version": None,
                "last_mode": "balanced",
                "global_aggressiveness": 1,
                "default_game_policy": "auto",
                "manual_override": 0,
            }

    def save(self):
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.settings, f, indent=2)
            log("[SettingsManager] Settings saved.")
        except Exception as e:
            log(f"[SettingsManager] Failed to save settings: {e}")
            log(traceback.format_exc())

    def set_auto_mode(self, auto: bool):
        self.settings["auto_mode"] = bool(auto)
        self.save()

    def update_profile_info(self, gpu: GPUInfo, driver: DriverInfo, mode: str):
        self.settings["last_gpu_id"] = gpu.id_str
        self.settings["last_driver_version"] = driver.version
        self.settings["last_mode"] = mode
        self.save()

    def get_auto_mode(self):
        return bool(self.settings.get("auto_mode", True))

    def get_last_gpu_id(self):
        return self.settings.get("last_gpu_id")

    def get_last_driver_version(self):
        return self.settings.get("last_driver_version")

    def get_last_mode(self):
        return self.settings.get("last_mode", "balanced")

    def get_global_aggressiveness(self):
        return int(self.settings.get("global_aggressiveness", 1))

    def set_global_aggressiveness(self, value: int):
        self.settings["global_aggressiveness"] = max(0, min(3, int(value)))
        self.save()

    def get_default_game_policy(self):
        return self.settings.get("default_game_policy", "auto")

    def set_default_game_policy(self, policy: str):
        self.settings["default_game_policy"] = policy
        self.save()

    def get_manual_override(self):
        return int(self.settings.get("manual_override", 0))

    def set_manual_override(self, value: int):
        self.settings["manual_override"] = max(-3, min(3, int(value)))
        self.save()

# ======================================================================
# Translation Policy & Task Engine
# ======================================================================

class TranslationPolicyEngine:
    def build_policy_for_game(self, settings: SettingsManager, game_exe: str):
        base_type = settings.get_default_game_policy()
        base_aggr = settings.get_global_aggressiveness()
        manual_override = settings.get_manual_override()
        effective_aggr = base_aggr + manual_override
        effective_aggr = max(0, min(3, effective_aggr))
        return {
            "type": base_type,
            "aggressiveness": effective_aggr,
            "game_exe": game_exe,
            "base_aggressiveness": base_aggr,
            "manual_override": manual_override,
        }

    def describe_policy(self, policy):
        t = policy.get("type", "auto")
        aggr = policy.get("aggressiveness", 1)
        base = policy.get("base_aggressiveness", aggr)
        override = policy.get("manual_override", 0)
        return f"type={t}, effective={aggr} (base={base}, override={override:+d})"

class TranslationTaskEngine:
    def shader_translation(self, policy, profile: TranslationProfile):
        log(f"[TranslationTaskEngine] Shader translation policy={policy.get('type')} aggr={policy.get('aggressiveness')} "
            f"GPU={profile.gpu.name}, game={profile.game_exe}")
        return {
            "status": "ok",
            "details": "Shader translation pipeline configured (policy-driven stub).",
        }

    def driver_compat_translation(self, policy, profile: TranslationProfile):
        log(f"[TranslationTaskEngine] Driver compatibility policy={policy.get('type')} "
            f"driver={profile.driver.version}, game={profile.game_exe}")
        return {
            "status": "ok",
            "details": "Driver compatibility mapping applied (policy-driven stub).",
        }

    def performance_tuning(self, policy, profile: TranslationProfile):
        log(f"[TranslationTaskEngine] Performance tuning policy={policy.get('type')} aggr={policy.get('aggressiveness')} "
            f"AI score={profile.ai_score:.2f}, game={profile.game_exe}")
        return {
            "status": "ok",
            "details": "Performance tuning hints generated (policy-driven stub).",
        }

# ======================================================================
# Game Integration Layer (non-invasive, stricter detection)
# ======================================================================

class GameSessionManager:
    def __init__(self, gpu_detector: GPUDetector, profile_manager: ProfileManager,
                 translator: AITranslatorEngine, driver_detector: DriverDetector,
                 benchmark_engine: BenchmarkEngine, settings_manager: SettingsManager,
                 plugin_manager: PluginManager, policy_engine: TranslationPolicyEngine):
        self.gpu_detector = gpu_detector
        self.profile_manager = profile_manager
        self.translator = translator
        self.driver_detector = driver_detector
        self.benchmark_engine = benchmark_engine
        self.settings_manager = settings_manager
        self.plugin_manager = plugin_manager
        self.policy_engine = policy_engine
        self.current_game_exe = None
        self.last_check_time = 0.0
        self.check_interval = 8.0  # slightly slower to avoid UI flicker

        # Known game-ish keywords (you can expand this list)
        self.known_game_keywords = [
            "eldenring", "fortnite", "doom", "cod", "battlefield",
            "cyberpunk", "witcher", "overwatch", "valorant", "leagueoflegends",
            "csgo", "cs2", "starfield", "minecraft", "roblox",
        ]

        # Launchers / non-game processes to ignore
        self.ignore_keywords = [
            "steam", "epic", "uplay", "origin", "gog", "battle.net",
            "discord", "chrome", "edge", "firefox", "opera",
            "explorer", "shellexperiencehost", "dwm",
        ]

    def _pick_best_gpu(self):
        gpus = self.gpu_detector.gpus
        if not gpus:
            return None
        gpus_sorted = sorted(
            gpus,
            key=lambda g: (-g.memory_total_mb, g.load)
        )
        best = gpus_sorted[0]
        log(f"[GameSessionManager] Best GPU selected: {best.name} ({best.memory_total_mb} MB, load={best.load:.1f}%)")
        return best

    def _is_game_candidate(self, proc):
        try:
            name = (proc.name() or "").lower()
        except Exception:
            name = ""
        try:
            exe = (proc.exe() or "").lower()
        except Exception:
            exe = ""

        if not exe:
            return False

        for kw in self.ignore_keywords:
            if kw in name or kw in exe:
                return False

        for kw in self.known_game_keywords:
            if kw in name or kw in exe:
                return True

        if exe.endswith(".exe") and ("game" in exe or "games" in exe):
            return True

        return False

    def _collect_game_processes(self):
        if psutil is None:
            log("[GameSessionManager] psutil not available, game detection disabled.")
            return []

        candidates = []
        for proc in psutil.process_iter(attrs=["pid", "name", "exe", "cpu_percent"]):
            try:
                if not self._is_game_candidate(proc):
                    continue
                info = proc.info
                cpu = info.get("cpu_percent", 0.0)
                exe = info.get("exe") or ""
                name = info.get("name") or ""
                if not exe:
                    continue
                candidates.append({
                    "pid": info.get("pid"),
                    "name": name,
                    "exe": exe,
                    "cpu_percent": cpu,
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
            except Exception as e:
                log(f"[GameSessionManager] Process scan error: {e}")
        return candidates

    def _pick_active_game(self, candidates):
        if not candidates:
            return None
        active = sorted(
            candidates,
            key=lambda c: (-c["cpu_percent"], c["name"].lower())
        )[0]
        return active

    def strict_detect_game(self):
        now = time.time()
        if now - self.last_check_time < self.check_interval:
            return None
        self.last_check_time = now

        candidates = self._collect_game_processes()
        active = self._pick_active_game(candidates)
        if not active:
            return None

        exe = active["exe"]
        name = active["name"]
        cpu = active["cpu_percent"]
        log(f"[GameSessionManager] Strict game candidate: {name} ({exe}), cpu={cpu:.1f}%")

        self.current_game_exe = exe
        return {
            "name": name,
            "exe": exe,
            "cpu_percent": cpu,
        }

    def build_or_reuse_profile_for_game(self, game_info):
        game_exe = game_info["exe"]
        existing = self.profile_manager.find_profile_for_game(game_exe)
        if existing:
            log(f"[GameSessionManager] Reusing existing profile for {game_exe}")
            return existing

        gpus = self.gpu_detector.detect()
        drivers = self.driver_detector.detect()
        if not gpus or not drivers:
            log("[GameSessionManager] No GPU/driver for profile build.")
            return None

        best_gpu = self._pick_best_gpu()
        driver = drivers[0]

        bench_score = self.benchmark_engine.run_microbench()
        policy = self.policy_engine.build_policy_for_game(self.settings_manager, game_exe)
        profile = self.translator.build_profile(
            best_gpu,
            driver,
            mode=self.settings_manager.get_last_mode(),
            benchmark_score=bench_score,
            capabilities={"game_mode": True},
            game_exe=game_exe,
            policy=policy,
        )
        profile_dict = profile.to_dict()
        self.profile_manager.save_profile(profile_dict)
        self.plugin_manager.on_profile_built(profile_dict)
        self.plugin_manager.on_benchmark_completed(profile_dict)
        self.plugin_manager.on_game_detected(game_info, profile_dict)
        log(f"[GameSessionManager] New profile built for game {game_exe}")
        return profile_dict

    def apply_policy_for_game(self, game_info, profile_dict):
        game_exe = game_info["exe"]
        policy = self.policy_engine.build_policy_for_game(self.settings_manager, game_exe)
        self.plugin_manager.on_policy_applied(policy)

        gpu_dict = profile_dict.get("gpu") or {}
        driver_dict = profile_dict.get("driver") or {}
        gpu = GPUInfo(
            name=gpu_dict.get("name", ""),
            id_str=gpu_dict.get("id", ""),
            memory_total_mb=gpu_dict.get("memory_total_mb", 0),
            load=gpu_dict.get("load", 0.0),
            driver_version=gpu_dict.get("driver_version", ""),
            vendor=gpu_dict.get("vendor", "unknown"),
            temperature=gpu_dict.get("temperature"),
            cuda_capability=gpu_dict.get("cuda_capability"),
        )
        driver = DriverInfo(
            name=driver_dict.get("name", ""),
            version=driver_dict.get("version", ""),
            api_support=driver_dict.get("api_support", {}),
        )

        profile = TranslationProfile(
            gpu=gpu,
            driver=driver,
            mode=profile_dict.get("mode", "balanced"),
            ai_score=profile_dict.get("ai_score", 0.0),
            heuristic_score=profile_dict.get("heuristic_score", 0.0),
            benchmark_score=profile_dict.get("benchmark_score", 0.0),
            capabilities=profile_dict.get("capabilities", {}),
            game_exe=profile_dict.get("game_exe"),
            policy=policy,
            aggressiveness=policy.get("aggressiveness", 1),
        )

        task_engine = TranslationTaskEngine()
        shader_res = task_engine.shader_translation(policy, profile)
        compat_res = task_engine.driver_compat_translation(policy, profile)
        perf_res = task_engine.performance_tuning(policy, profile)

        log(f"[GameSessionManager] Policy applied for {game_exe}: "
            f"shader={shader_res['status']}, compat={compat_res['status']}, perf={perf_res['status']}")
        return {
            "policy": policy,
            "shader": shader_res,
            "compat": compat_res,
            "perf": perf_res,
        }

# ======================================================================
# Qt GUI – Command Center + Game Detection Tab (Compact Cards, Stable)
# ======================================================================

class GameCardWidget(QtWidgets.QFrame):
    applyRequested = QtCore.Signal(dict)

    def __init__(self, game_info, profile_dict, policy_engine: TranslationPolicyEngine, settings: SettingsManager, parent=None):
        super().__init__(parent)
        self.game_info = game_info
        self.profile_dict = profile_dict
        self.policy_engine = policy_engine
        self.settings = settings

        self.setFrameShape(QtWidgets.QFrame.StyledPanel)
        self.setFrameShadow(QtWidgets.QFrame.Raised)
        self.setObjectName("GameCardWidget")

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(8, 8, 8, 8)
        layout.setSpacing(4)

        title = QtWidgets.QLabel(f"{game_info['name']}  ({os.path.basename(game_info['exe'])})")
        title.setStyleSheet("font-weight: bold;")
        layout.addWidget(title)

        exe_label = QtWidgets.QLabel(game_info["exe"])
        exe_label.setStyleSheet("color: #888; font-size: 10px;")
        layout.addWidget(exe_label)

        ai_score = profile_dict.get("ai_score", 0.0)
        heuristic_score = profile_dict.get("heuristic_score", 0.0)
        bench_score = profile_dict.get("benchmark_score", 0.0)

        info_line = QtWidgets.QLabel(
            f"AI={ai_score:.2f}  Heuristic={heuristic_score:.2f}  Bench={bench_score:.2f} GFLOPS"
        )
        layout.addWidget(info_line)

        policy = self.policy_engine.build_policy_for_game(self.settings, game_info["exe"])
        policy_desc = QtWidgets.QLabel(self.policy_engine.describe_policy(policy))
        layout.addWidget(policy_desc)

        slider_layout = QtWidgets.QHBoxLayout()
        slider_label = QtWidgets.QLabel("Additive override:")
        slider_layout.addWidget(slider_label)

        self.override_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.override_slider.setMinimum(-3)
        self.override_slider.setMaximum(3)
        self.override_slider.setValue(self.settings.get_manual_override())
        self.override_slider.setTickPosition(QtWidgets.QSlider.TicksBelow)
        self.override_slider.setTickInterval(1)
        slider_layout.addWidget(self.override_slider)

        self.override_value_label = QtWidgets.QLabel(f"{self.override_slider.value():+d}")
        slider_layout.addWidget(self.override_value_label)

        layout.addLayout(slider_layout)

        btn_layout = QtWidgets.QHBoxLayout()
        self.apply_btn = QtWidgets.QPushButton("Apply Policy")
        self.apply_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_MediaPlay))
        btn_layout.addWidget(self.apply_btn)

        self.compare_btn = QtWidgets.QPushButton("Compare Scores")
        self.compare_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_FileDialogDetailedView))
        btn_layout.addWidget(self.compare_btn)

        layout.addLayout(btn_layout)

        self.apply_btn.clicked.connect(self._on_apply_clicked)
        self.override_slider.valueChanged.connect(self._on_override_changed)
        self.compare_btn.clicked.connect(self._on_compare_clicked)

    def _on_override_changed(self, value):
        self.override_value_label.setText(f"{value:+d}")
        self.settings.set_manual_override(value)

    def _on_apply_clicked(self):
        payload = {
            "game_info": self.game_info,
            "profile_dict": self.profile_dict,
        }
        self.applyRequested.emit(payload)

    def _on_compare_clicked(self):
        ai_score = self.profile_dict.get("ai_score", 0.0)
        heuristic_score = self.profile_dict.get("heuristic_score", 0.0)
        QtWidgets.QMessageBox.information(
            self,
            "Score Comparison",
            f"AI score: {ai_score:.3f}\nHeuristic score: {heuristic_score:.3f}",
        )

class GameDetectionTab(QtWidgets.QWidget):
    def __init__(self, game_session: GameSessionManager, settings: SettingsManager,
                 policy_engine: TranslationPolicyEngine, parent=None):
        super().__init__(parent)
        self.game_session = game_session
        self.settings = settings
        self.policy_engine = policy_engine

        self.cards = []
        self.last_game_exe = None  # to avoid flicker when nothing changes

        main_layout = QtWidgets.QVBoxLayout(self)
        main_layout.setContentsMargins(6, 6, 6, 6)
        main_layout.setSpacing(6)

        header_layout = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("Game Detection (Strict, Non-Invasive)")
        title.setStyleSheet("font-weight: bold; font-size: 12px;")
        header_layout.addWidget(title)

        self.refresh_btn = QtWidgets.QPushButton("Scan Now")
        self.refresh_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_BrowserReload))
        header_layout.addWidget(self.refresh_btn)

        header_layout.addStretch()
        main_layout.addLayout(header_layout)

        self.scroll = QtWidgets.QScrollArea()
        self.scroll.setWidgetResizable(True)
        self.scroll_content = QtWidgets.QWidget()
        self.scroll_layout = QtWidgets.QVBoxLayout(self.scroll_content)
        self.scroll_layout.setContentsMargins(4, 4, 4, 4)
        self.scroll_layout.setSpacing(4)
        self.scroll.setWidget(self.scroll_content)
        main_layout.addWidget(self.scroll)

        self.status_label = QtWidgets.QLabel("No game detected yet.")
        self.status_label.setStyleSheet("color: #888; font-size: 10px;")
        main_layout.addWidget(self.status_label)

        self.refresh_btn.clicked.connect(self.scan_games)

        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(int(self.game_session.check_interval * 1000))
        self.timer.timeout.connect(self.scan_games)
        self.timer.start()

    def clear_cards(self):
        for card in self.cards:
            card.setParent(None)
        self.cards = []
        while self.scroll_layout.count():
            item = self.scroll_layout.takeAt(0)
            w = item.widget()
            if w is not None:
                w.deleteLater()

    def scan_games(self):
        game_info = self.game_session.strict_detect_game()

        # If nothing new, keep current card to avoid flicker
        if not game_info:
            if not self.cards:
                self.status_label.setText("No active game detected (strict filter).")
            return

        if self.last_game_exe == game_info["exe"] and self.cards:
            # Same game, no need to rebuild UI
            self.status_label.setText(
                f"Detected game: {game_info['name']} ({os.path.basename(game_info['exe'])})"
            )
            return

        self.last_game_exe = game_info["exe"]
        self.clear_cards()

        profile_dict = self.game_session.build_or_reuse_profile_for_game(game_info)
        if not profile_dict:
            self.status_label.setText("Game detected, but profile could not be built.")
            return

        card = GameCardWidget(game_info, profile_dict, self.policy_engine, self.settings)
        card.applyRequested.connect(self._on_apply_requested)
        self.scroll_layout.addWidget(card)
        self.cards.append(card)

        self.status_label.setText(
            f"Detected game: {game_info['name']} ({os.path.basename(game_info['exe'])})"
        )

    def _on_apply_requested(self, payload):
        game_info = payload["game_info"]
        profile_dict = payload["profile_dict"]
        res = self.game_session.apply_policy_for_game(game_info, profile_dict)
        QtWidgets.QMessageBox.information(
            self,
            "Policy Applied",
            f"Policy: {self.policy_engine.describe_policy(res['policy'])}\n"
            f"Shader: {res['shader']['status']}\n"
            f"Compat: {res['compat']['status']}\n"
            f"Perf: {res['perf']['status']}",
        )

class GPUOverviewTab(QtWidgets.QWidget):
    def __init__(self, gpu_detector: GPUDetector, driver_detector: DriverDetector,
                 translator: AITranslatorEngine, benchmark_engine: BenchmarkEngine,
                 profile_manager: ProfileManager, settings: SettingsManager,
                 plugin_manager: PluginManager, parent=None):
        super().__init__(parent)
        self.gpu_detector = gpu_detector
        self.driver_detector = driver_detector
        self.translator = translator
        self.benchmark_engine = benchmark_engine
        self.profile_manager = profile_manager
        self.settings = settings
        self.plugin_manager = plugin_manager

        layout = QtWidgets.QVBoxLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        header_layout = QtWidgets.QHBoxLayout()
        title = QtWidgets.QLabel("GPU Overview & Translation Profile")
        title.setStyleSheet("font-weight: bold; font-size: 12px;")
        header_layout.addWidget(title)

        self.refresh_btn = QtWidgets.QPushButton("Refresh")
        self.refresh_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_BrowserReload))
        header_layout.addWidget(self.refresh_btn)

        header_layout.addStretch()
        layout.addLayout(header_layout)

        self.info_text = QtWidgets.QTextEdit()
        self.info_text.setReadOnly(True)
        layout.addWidget(self.info_text)

        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(["balanced", "performance", "eco", "compatibility"])
        self.mode_combo.setCurrentText(self.settings.get_last_mode())

        mode_layout = QtWidgets.QHBoxLayout()
        mode_layout.addWidget(QtWidgets.QLabel("Mode:"))
        mode_layout.addWidget(self.mode_combo)
        mode_layout.addStretch()
        layout.addLayout(mode_layout)

        self.build_btn = QtWidgets.QPushButton("Build Profile")
        self.build_btn.setIcon(self.style().standardIcon(QtWidgets.QStyle.SP_DialogApplyButton))
        layout.addWidget(self.build_btn)

        self.refresh_btn.clicked.connect(self.refresh_info)
        self.build_btn.clicked.connect(self.build_profile)

        self.refresh_info()

    def refresh_info(self):
        gpus = self.gpu_detector.detect()
        drivers = self.driver_detector.detect()
        lines = []
        lines.append(f"App version: {APP_VERSION}")
        lines.append("")
        if not gpus:
            lines.append("No GPUs detected.")
        else:
            lines.append(f"Detected {len(gpus)} GPU(s):")
            for g in gpus:
                lines.append(
                    f" - {g.name} (id={g.id_str}, {g.memory_total_mb} MB, load={g.load:.1f}%, "
                    f"driver={g.driver_version}, vendor={g.vendor}, cuda={g.cuda_capability})"
                )
        lines.append("")
        if not drivers:
            lines.append("No drivers detected.")
        else:
            lines.append(f"Detected {len(drivers)} driver(s):")
            for d in drivers:
                lines.append(
                    f" - {d.name} v{d.version} | DX={d.api_support.get('DirectX')} "
                    f"VK={d.api_support.get('Vulkan')} GL={d.api_support.get('OpenGL')} "
                    f"CUDA={d.api_support.get('CUDA')}"
                )
        self.info_text.setPlainText("\n".join(lines))

    def build_profile(self):
        gpus = self.gpu_detector.detect()
        drivers = self.driver_detector.detect()
        if not gpus or not drivers:
            QtWidgets.QMessageBox.warning(self, "Profile", "No GPU/driver available.")
            return

        best_gpu = sorted(gpus, key=lambda g: (-g.memory_total_mb, g.load))[0]
        driver = drivers[0]
        mode = self.mode_combo.currentText()
        bench_score = self.benchmark_engine.run_microbench()

        policy = {
            "type": "auto",
            "aggressiveness": self.settings.get_global_aggressiveness(),
        }

        profile = self.translator.build_profile(
            best_gpu,
            driver,
            mode=mode,
            benchmark_score=bench_score,
            capabilities={"game_mode": False},
            game_exe=None,
            policy=policy,
        )
        profile_dict = profile.to_dict()
        self.profile_manager.save_profile(profile_dict)
        self.settings.update_profile_info(best_gpu, driver, mode)
        self.plugin_manager.on_profile_built(profile_dict)
        self.plugin_manager.on_benchmark_completed(profile_dict)

        QtWidgets.QMessageBox.information(
            self,
            "Profile Built",
            f"Profile built for {best_gpu.name} in {mode} mode.\n"
            f"AI score={profile.ai_score:.2f}, heuristic={profile.heuristic_score:.2f}",
        )

class SettingsTab(QtWidgets.QWidget):
    def __init__(self, settings: SettingsManager, parent=None):
        super().__init__(parent)
        self.settings = settings

        layout = QtWidgets.QFormLayout(self)
        layout.setContentsMargins(6, 6, 6, 6)
        layout.setSpacing(6)

        self.auto_mode_checkbox = QtWidgets.QCheckBox("Enable auto mode")
        self.auto_mode_checkbox.setChecked(self.settings.get_auto_mode())
        layout.addRow("Auto mode:", self.auto_mode_checkbox)

        self.global_aggr_spin = QtWidgets.QSpinBox()
        self.global_aggr_spin.setRange(0, 3)
        self.global_aggr_spin.setValue(self.settings.get_global_aggressiveness())
        layout.addRow("Global aggressiveness:", self.global_aggr_spin)

        self.default_policy_combo = QtWidgets.QComboBox()
        self.default_policy_combo.addItems(["auto", "performance", "eco", "compatibility"])
        self.default_policy_combo.setCurrentText(self.settings.get_default_game_policy())
        layout.addRow("Default game policy:", self.default_policy_combo)

        self.manual_override_spin = QtWidgets.QSpinBox()
        self.manual_override_spin.setRange(-3, 3)
        self.manual_override_spin.setValue(self.settings.get_manual_override())
        layout.addRow("Manual override:", self.manual_override_spin)

        self.save_btn = QtWidgets.QPushButton("Save Settings")
        layout.addRow(self.save_btn)

        self.save_btn.clicked.connect(self.save_settings)

    def save_settings(self):
        self.settings.set_auto_mode(self.auto_mode_checkbox.isChecked())
        self.settings.set_global_aggressiveness(self.global_aggr_spin.value())
        self.settings.set_default_game_policy(self.default_policy_combo.currentText())
        self.settings.set_manual_override(self.manual_override_spin.value())
        QtWidgets.QMessageBox.information(self, "Settings", "Settings saved.")

class MainWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Universal GPU Translator Command Center")
        self.resize(900, 600)

        self.plugin_manager = PluginManager()
        self.gpu_detector = GPUDetector()
        self.driver_detector = DriverDetector(self.gpu_detector)
        self.translator = AITranslatorEngine()
        self.benchmark_engine = BenchmarkEngine()
        self.profile_manager = ProfileManager()
        self.settings_manager = SettingsManager()
        self.policy_engine = TranslationPolicyEngine()
        self.game_session = GameSessionManager(
            self.gpu_detector,
            self.profile_manager,
            self.translator,
            self.driver_detector,
            self.benchmark_engine,
            self.settings_manager,
            self.plugin_manager,
            self.policy_engine,
        )

        self.tab_widget = QtWidgets.QTabWidget()
        self.setCentralWidget(self.tab_widget)

        self.gpu_tab = GPUOverviewTab(
            self.gpu_detector,
            self.driver_detector,
            self.translator,
            self.benchmark_engine,
            self.profile_manager,
            self.settings_manager,
            self.plugin_manager,
        )
        self.game_tab = GameDetectionTab(
            self.game_session,
            self.settings_manager,
            self.policy_engine,
        )
        self.settings_tab = SettingsTab(self.settings_manager)

        self.tab_widget.addTab(self.gpu_tab, "GPU & Profiles")
        self.tab_widget.addTab(self.game_tab, "Game Detection")
        self.tab_widget.addTab(self.settings_tab, "Settings")

        self._setup_style()

    def _setup_style(self):
        self.setWindowIcon(self.style().standardIcon(QtWidgets.QStyle.SP_ComputerIcon))
        self.tab_widget.setDocumentMode(True)

# ======================================================================
# Entry Point
# ======================================================================

def main():
    app = QtWidgets.QApplication(sys.argv)
    win = MainWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
