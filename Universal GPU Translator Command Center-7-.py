#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Universal GPU Translator Command Center (Next-Level, Game-Aware, ORIGINAL LOADER RESTORED)
"""

import os
import sys
import subprocess
import importlib
import json
import time
import traceback

APP_VERSION = "1.3.3-UGTC-GAME-NEXT-COMPARE"
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

# ======================================================================
# Translation Policy & Task Engine
# ======================================================================

class TranslationPolicyEngine:
    def build_policy_for_game(self, settings: SettingsManager, game_exe: str):
        base_type = settings.get_default_game_policy()
        aggr = settings.get_global_aggressiveness()
        return {
            "type": base_type,
            "aggressiveness": aggr,
            "game_exe": game_exe,
        }

    def describe_policy(self, policy):
        t = policy.get("type", "auto")
        aggr = policy.get("aggressiveness", 1)
        return f"type={t}, aggressiveness={aggr}"

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
# Game Integration Layer (non-invasive)
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
        self.check_interval = 5.0

    def _pick_best_gpu(self):
        gpus = self.gpu_detector.gpus
        if not gpus:
            return None
        gpus_sorted = sorted(
            gpus,
            key=lambda g: (-g.memory_total_mb, g.load)
        )
        return gpus_sorted[0]

    def _pick_driver_for_gpu(self, gpu: GPUInfo):
        drivers = self.driver_detector.drivers
        if not drivers:
            return None
        for d in drivers:
            if gpu.vendor.lower() in d.name.lower():
                return d
        return drivers[0]

    def _detect_candidate_game_process(self):
        if psutil is None:
            return None
        try:
            candidates = []
            for p in psutil.process_iter(["name", "exe"]):
                name = p.info.get("name") or ""
                exe = p.info.get("exe") or ""
                low_name = name.lower()
                if any(tag in low_name for tag in ["game", "steam", "epic", "uplay", "origin", "gog"]):
                    candidates.append(exe or name)
            if candidates:
                return candidates[0]
        except Exception as e:
            log(f"[GameSessionManager] Process scan failed: {e}")
            log(traceback.format_exc())
        return None

    def _build_or_select_profile_for_game(self, game_exe):
        existing = self.profile_manager.find_profile_for_game(game_exe)
        if existing:
            log(f"[GameSessionManager] Found existing profile for game {game_exe}")
            gpu_data = existing.get("gpu", {})
            driver_data = existing.get("driver", {})
            policy_data = existing.get("policy", {"type": "auto", "aggressiveness": 1})
            gpu = GPUInfo(
                name=gpu_data.get("name", ""),
                id_str=gpu_data.get("id", ""),
                memory_total_mb=gpu_data.get("memory_total_mb", 0),
                load=gpu_data.get("load", 0.0),
                driver_version=gpu_data.get("driver_version", ""),
                vendor=gpu_data.get("vendor", "unknown"),
                temperature=gpu_data.get("temperature"),
                cuda_capability=gpu_data.get("cuda_capability"),
            )
            driver = DriverInfo(
                name=driver_data.get("name", ""),
                version=driver_data.get("version", ""),
                api_support=driver_data.get("api_support", {}),
            )
            profile = TranslationProfile(
                gpu, driver, existing.get("mode", "balanced"),
                ai_score=existing.get("ai_score", 0.0),
                heuristic_score=existing.get("heuristic_score", 0.0),
                benchmark_score=existing.get("benchmark_score", 0.0),
                capabilities=existing.get("capabilities", {}),
                game_exe=existing.get("game_exe"),
                policy=policy_data,
                aggressiveness=policy_data.get("aggressiveness", 1),
            )
            self.translator.current_profile = profile
            return profile

        gpu = self._pick_best_gpu()
        if not gpu:
            log("[GameSessionManager] No GPU available for game profile.")
            return None
        driver = self._pick_driver_for_gpu(gpu)
        if not driver:
            log("[GameSessionManager] No driver available for game profile.")
            return None

        mode = self.settings_manager.get_last_mode()
        bench_score = self.benchmark_engine.run_microbench()
        capabilities = {
            "directx": driver.api_support.get("DirectX"),
            "vulkan": driver.api_support.get("Vulkan"),
            "opengl": driver.api_support.get("OpenGL"),
            "cuda": driver.api_support.get("CUDA"),
            "cuda_capability": gpu.cuda_capability,
        }

        policy = self.policy_engine.build_policy_for_game(self.settings_manager, game_exe)
        profile = self.translator.build_profile(
            gpu, driver, mode, bench_score, capabilities, game_exe=game_exe, policy=policy
        )
        profile_dict = profile.to_dict()
        self.profile_manager.save_profile(profile_dict)
        self.plugin_manager.on_profile_built(profile_dict)
        self.plugin_manager.on_benchmark_completed(profile_dict)
        self.plugin_manager.on_game_detected({"exe": game_exe}, profile_dict)
        self.plugin_manager.on_policy_applied(policy)
        log(f"[GameSessionManager] Built new profile for game {game_exe} with policy {self.policy_engine.describe_policy(policy)}")
        return profile

    def tick(self):
        now = time.time()
        if now - self.last_check_time < self.check_interval:
            return
        self.last_check_time = now

        game_exe = self._detect_candidate_game_process()
        if not game_exe:
            return

        if game_exe == self.current_game_exe:
            return

        self.current_game_exe = game_exe
        log(f"[GameSessionManager] Detected game process: {game_exe}")
        profile = self._build_or_select_profile_for_game(game_exe)
        if profile:
            log(f"[GameSessionManager] Active game profile AI={profile.ai_score:.2f}, mode={profile.mode}, "
                f"policy={profile.policy.get('type')} aggr={profile.policy.get('aggressiveness')}")

# ======================================================================
# GUI
# ======================================================================

class GPUTranslatorGUI(QtWidgets.QMainWindow):
    def __init__(self, gpu_detector: GPUDetector, driver_detector: DriverDetector,
                 translator: AITranslatorEngine, profile_manager: ProfileManager,
                 settings_manager: SettingsManager, benchmark_engine: BenchmarkEngine,
                 plugin_manager: PluginManager, translation_engine: TranslationTaskEngine,
                 game_session_manager: GameSessionManager, policy_engine: TranslationPolicyEngine):
        super().__init__()
        self.gpu_detector = gpu_detector
        self.driver_detector = driver_detector
        self.translator = translator
        self.profile_manager = profile_manager
        self.settings_manager = settings_manager
        self.benchmark_engine = benchmark_engine
        self.plugin_manager = plugin_manager
        self.translation_engine = translation_engine
        self.game_session_manager = game_session_manager
        self.policy_engine = policy_engine

        self.setWindowTitle(f"Universal GPU Translator Command Center v{APP_VERSION}")
        self.resize(1200, 850)

        self.monitor_timer = QtCore.QTimer(self)
        self.monitor_timer.setInterval(3000)
        self.monitor_timer.timeout.connect(self.on_monitor_tick)

        self._build_ui()
        self._wire_events()
        self.refresh_all()
        self.auto_bootstrap()
        self.monitor_timer.start()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QVBoxLayout(central)

        self.tabs = QtWidgets.QTabWidget()
        main_layout.addWidget(self.tabs)

        self.overview_tab = QtWidgets.QWidget()
        ov_layout = QtWidgets.QVBoxLayout(self.overview_tab)

        top_split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        gpu_widget = QtWidgets.QWidget()
        gpu_layout = QtWidgets.QVBoxLayout(gpu_widget)
        self.gpu_list = QtWidgets.QTableWidget()
        self.gpu_list.setColumnCount(7)
        self.gpu_list.setHorizontalHeaderLabels(
            ["Name", "ID", "Memory (MB)", "Load (%)", "Driver", "Temp (°C)", "CUDA Cap"]
        )
        self.gpu_list.horizontalHeader().setStretchLastSection(True)
        gpu_layout.addWidget(QtWidgets.QLabel("Detected GPUs"))
        gpu_layout.addWidget(self.gpu_list)

        driver_widget = QtWidgets.QWidget()
        driver_layout = QtWidgets.QVBoxLayout(driver_widget)
        self.driver_list = QtWidgets.QTableWidget()
        self.driver_list.setColumnCount(5)
        self.driver_list.setHorizontalHeaderLabels(
            ["Name", "Version", "DirectX", "Vulkan/OpenGL", "CUDA"]
        )
        self.driver_list.horizontalHeader().setStretchLastSection(True)
        driver_layout.addWidget(QtWidgets.QLabel("Detected Drivers"))
        driver_layout.addWidget(self.driver_list)

        top_split.addWidget(gpu_widget)
        top_split.addWidget(driver_widget)
        ov_layout.addWidget(top_split)

        mid_widget = QtWidgets.QWidget()
        mid_layout = QtWidgets.QGridLayout(mid_widget)

        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(["balanced", "performance", "eco", "compatibility", "custom"])

        self.auto_mode_checkbox = QtWidgets.QCheckBox("Automatic mode")
        self.auto_mode_checkbox.setChecked(self.settings_manager.get_auto_mode())

        self.aggr_slider = QtWidgets.QSlider(QtCore.Qt.Horizontal)
        self.aggr_slider.setMinimum(0)
        self.aggr_slider.setMaximum(3)
        self.aggr_slider.setValue(self.settings_manager.get_global_aggressiveness())
        self.aggr_label = QtWidgets.QLabel(f"Aggressiveness: {self.aggr_slider.value()}")

        self.default_policy_combo = QtWidgets.QComboBox()
        self.default_policy_combo.addItems(["auto", "performance", "eco", "compatibility", "strict"])
        idx_policy = self.default_policy_combo.findText(self.settings_manager.get_default_game_policy())
        if idx_policy >= 0:
            self.default_policy_combo.setCurrentIndex(idx_policy)

        self.build_profile_btn = QtWidgets.QPushButton("Build Profile (Manual)")
        self.save_profile_btn = QtWidgets.QPushButton("Save Profile (Manual)")
        self.run_bench_btn = QtWidgets.QPushButton("Run Benchmark")

        self.score_label = QtWidgets.QLabel("AI: N/A | Heuristic: N/A | Bench: N/A")
        self.cap_label = QtWidgets.QLabel("Capabilities: N/A")
        self.game_label = QtWidgets.QLabel("Current game: None")
        self.policy_label = QtWidgets.QLabel("Current policy: N/A")

        mid_layout.addWidget(QtWidgets.QLabel("Translation Mode:"), 0, 0)
        mid_layout.addWidget(self.mode_combo, 0, 1)
        mid_layout.addWidget(self.auto_mode_checkbox, 1, 0, 1, 2)
        mid_layout.addWidget(QtWidgets.QLabel("Global aggressiveness (0–3):"), 2, 0)
        mid_layout.addWidget(self.aggr_slider, 2, 1)
        mid_layout.addWidget(self.aggr_label, 3, 0, 1, 2)
        mid_layout.addWidget(QtWidgets.QLabel("Default game policy:"), 4, 0)
        mid_layout.addWidget(self.default_policy_combo, 4, 1)
        mid_layout.addWidget(self.build_profile_btn, 5, 0, 1, 2)
        mid_layout.addWidget(self.save_profile_btn, 6, 0, 1, 2)
        mid_layout.addWidget(self.run_bench_btn, 7, 0, 1, 2)
        mid_layout.addWidget(self.score_label, 8, 0, 1, 2)
        mid_layout.addWidget(self.cap_label, 9, 0, 1, 2)
        mid_layout.addWidget(self.game_label, 10, 0, 1, 2)
        mid_layout.addWidget(self.policy_label, 11, 0, 1, 2)

        ov_layout.addWidget(mid_widget)

        compare_widget = QtWidgets.QGroupBox("Game Settings vs Global Aggressiveness")
        compare_layout = QtWidgets.QGridLayout(compare_widget)

        self.game_detected_label = QtWidgets.QLabel("Game recognized: No")
        self.game_policy_value = QtWidgets.QLabel("Game policy: N/A")
        self.game_aggr_value = QtWidgets.QLabel("Game aggressiveness: N/A")
        self.global_aggr_value = QtWidgets.QLabel(
            f"Global aggressiveness: {self.settings_manager.get_global_aggressiveness()}"
        )
        self.game_vs_global_diff_label = QtWidgets.QLabel("Difference: N/A")

        compare_layout.addWidget(self.game_detected_label, 0, 0, 1, 2)
        compare_layout.addWidget(QtWidgets.QLabel("Game policy:"), 1, 0)
        compare_layout.addWidget(self.game_policy_value, 1, 1)
        compare_layout.addWidget(QtWidgets.QLabel("Game aggressiveness:"), 2, 0)
        compare_layout.addWidget(self.game_aggr_value, 2, 1)
        compare_layout.addWidget(QtWidgets.QLabel("Global aggressiveness:"), 3, 0)
        compare_layout.addWidget(self.global_aggr_value, 3, 1)
        compare_layout.addWidget(QtWidgets.QLabel("Aggressiveness difference (game - global):"), 4, 0)
        compare_layout.addWidget(self.game_vs_global_diff_label, 4, 1)

        ov_layout.addWidget(compare_widget)

        bottom_widget = QtWidgets.QWidget()
        bottom_layout = QtWidgets.QVBoxLayout(bottom_widget)
        bottom_layout.addWidget(QtWidgets.QLabel("Saved Profiles (generic + per-game)"))
        self.profile_list = QtWidgets.QListWidget()
        bottom_layout.addWidget(self.profile_list)

        self.inspect_profile_btn = QtWidgets.QPushButton("Inspect Selected Profile")
        self.activate_profile_btn = QtWidgets.QPushButton("Activate Selected Profile")
        self.translation_btn = QtWidgets.QPushButton("Run Translation Tasks (Shader/Driver/Perf)")
        bottom_layout.addWidget(self.inspect_profile_btn)
        bottom_layout.addWidget(self.activate_profile_btn)
        bottom_layout.addWidget(self.translation_btn)

        ov_layout.addWidget(bottom_widget)

        btn_row = QtWidgets.QHBoxLayout()
        self.refresh_btn = QtWidgets.QPushButton("Refresh GPUs/Drivers")
        self.exit_btn = QtWidgets.QPushButton("Exit")
        btn_row.addWidget(self.refresh_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.exit_btn)
        ov_layout.addLayout(btn_row)

        self.tabs.addTab(self.overview_tab, "Overview")

        self.plugins_tab = QtWidgets.QWidget()
        pl_layout = QtWidgets.QVBoxLayout(self.plugins_tab)
        self.plugin_status_label = QtWidgets.QLabel("Plugins loaded: 0")
        pl_layout.addWidget(self.plugin_status_label)
        self.tabs.addTab(self.plugins_tab, "Plugins")

        self.logs_tab = QtWidgets.QWidget()
        lg_layout = QtWidgets.QVBoxLayout(self.logs_tab)
        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        lg_layout.addWidget(QtWidgets.QLabel("Log snapshot (tail)"))
        lg_layout.addWidget(self.log_view)
        self.tabs.addTab(self.logs_tab, "Logs")

        last_mode = self.settings_manager.get_last_mode()
        idx = self.mode_combo.findText(last_mode)
        if idx >= 0:
            self.mode_combo.setCurrentIndex(idx)

        self._update_manual_controls_enabled()
        self._update_plugin_status()
        self._refresh_log_view()
        self._update_game_vs_global_view()

    def _wire_events(self):
        self.refresh_btn.clicked.connect(self.on_refresh_clicked)
        self.exit_btn.clicked.connect(self.close)
        self.build_profile_btn.clicked.connect(self.on_build_profile_manual)
        self.save_profile_btn.clicked.connect(self.on_save_profile_manual)
        self.auto_mode_checkbox.stateChanged.connect(self.on_auto_mode_changed)
        self.mode_combo.currentTextChanged.connect(self.on_mode_changed)
        self.run_bench_btn.clicked.connect(self.on_run_benchmark)
        self.translation_btn.clicked.connect(self.on_run_translation_tasks)
        self.aggr_slider.valueChanged.connect(self.on_aggr_changed)
        self.default_policy_combo.currentTextChanged.connect(self.on_default_policy_changed)
        self.inspect_profile_btn.clicked.connect(self.on_inspect_profile)
        self.activate_profile_btn.clicked.connect(self.on_activate_profile)

    def _update_manual_controls_enabled(self):
        auto = self.auto_mode_checkbox.isChecked()
        self.build_profile_btn.setEnabled(not auto)
        self.save_profile_btn.setEnabled(not auto)

    def _update_plugin_status(self):
        count = len(self.plugin_manager.plugins)
        self.plugin_status_label.setText(f"Plugins loaded: {count}")

    def _refresh_log_view(self):
        try:
            if not os.path.exists(LOGFILE):
                self.log_view.setPlainText("No log file yet.")
                return
            with open(LOGFILE, "r", encoding="utf-8") as f:
                lines = f.readlines()
            tail = "".join(lines[-200:])
            self.log_view.setPlainText(tail)
        except Exception as e:
            self.log_view.setPlainText(f"Failed to read log: {e}")

    def refresh_all(self):
        self._refresh_gpus()
        self._refresh_drivers()
        self._refresh_profiles()
        self._refresh_log_view()
        self._update_game_vs_global_view()

    def _refresh_gpus(self):
        gpus = self.gpu_detector.detect()
        self.plugin_manager.on_gpu_detected([g.to_dict() for g in gpus])
        self.gpu_list.setRowCount(len(gpus))
        for row, gpu in enumerate(gpus):
            self.gpu_list.setItem(row, 0, QtWidgets.QTableWidgetItem(gpu.name))
            self.gpu_list.setItem(row, 1, QtWidgets.QTableWidgetItem(gpu.id_str))
            self.gpu_list.setItem(row, 2, QtWidgets.QTableWidgetItem(str(gpu.memory_total_mb)))
            self.gpu_list.setItem(row, 3, QtWidgets.QTableWidgetItem(f"{gpu.load:.1f}"))
            self.gpu_list.setItem(row, 4, QtWidgets.QTableWidgetItem(gpu.driver_version))
            self.gpu_list.setItem(row, 5, QtWidgets.QTableWidgetItem(
                "" if gpu.temperature is None else str(gpu.temperature)))
            self.gpu_list.setItem(row, 6, QtWidgets.QTableWidgetItem(
                "" if gpu.cuda_capability is None else gpu.cuda_capability))

    def _refresh_drivers(self):
        drivers = self.driver_detector.detect()
        self.driver_list.setRowCount(len(drivers))
        for row, drv in enumerate(drivers):
            self.driver_list.setItem(row, 0, QtWidgets.QTableWidgetItem(drv.name))
            self.driver_list.setItem(row, 1, QtWidgets.QTableWidgetItem(drv.version))
            dx = "Yes" if drv.api_support.get("DirectX") else "No"
            vk_gl = "Yes" if (drv.api_support.get("Vulkan") or drv.api_support.get("OpenGL")) else "No"
            cuda = "Yes" if drv.api_support.get("CUDA") else "No"
            self.driver_list.setItem(row, 2, QtWidgets.QTableWidgetItem(dx))
            self.driver_list.setItem(row, 3, QtWidgets.QTableWidgetItem(vk_gl))
            self.driver_list.setItem(row, 4, QtWidgets.QTableWidgetItem(cuda))

    def _refresh_profiles(self):
        self.profile_list.clear()
        profiles = self.profile_manager.list_profiles()
        for p in profiles:
            gpu_name = p.get("gpu", {}).get("name", "Unknown GPU")
            mode = p.get("mode", "balanced")
            ai_score = p.get("ai_score", 0.0)
            heur = p.get("heuristic_score", 0.0)
            bench = p.get("benchmark_score", 0.0)
            game_exe = p.get("game_exe") or "generic"
            policy = p.get("policy", {})
            policy_str = f"{policy.get('type', 'auto')}/{policy.get('aggressiveness', 1)}"
            created = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(p.get("created_at", time.time())),
            )
            self.profile_list.addItem(
                f"{gpu_name} | mode={mode} | AI={ai_score:.2f} | H={heur:.2f} | B={bench:.2f} "
                f"| game={game_exe} | policy={policy_str} | {created}"
            )

    def _get_gpu_by_id(self, gpu_id: str):
        gpus = self.gpu_detector.gpus
        for g in gpus:
            if g.id_str == gpu_id:
                return g
        return None

    def _pick_best_gpu(self):
        gpus = self.gpu_detector.gpus
        if not gpus:
            return None
        gpus_sorted = sorted(
            gpus,
            key=lambda g: (-g.memory_total_mb, g.load)
        )
        best = gpus_sorted[0]
        log(f"[GUI] Best GPU selected: {best.name} (VRAM={best.memory_total_mb}MB, load={best.load:.1f}%)")
        return best

    def _pick_default_gpu_and_driver(self):
        gpus = self.gpu_detector.gpus
        drivers = self.driver_detector.drivers

        if not gpus or not drivers:
            log("[GUI] No GPUs or drivers detected for auto selection.")
            return None, None

        last_gpu_id = self.settings_manager.get_last_gpu_id()
        gpu = None
        if last_gpu_id is not None:
            gpu = self._get_gpu_by_id(last_gpu_id)

        if gpu is None:
            gpu = self._pick_best_gpu()
        else:
            log(f"[GUI] Using last GPU from settings: {gpu.name} (ID={gpu.id_str})")

        last_drv_ver = self.settings_manager.get_last_driver_version()
        driver = None
        if last_drv_ver is not None:
            for d in drivers:
                if d.version == last_drv_ver:
                    driver = d
                    break

        if driver is None:
            for d in drivers:
                if gpu.vendor.lower() in d.name.lower():
                    driver = d
                    break

        if driver is None:
            driver = drivers[0]
            log(f"[GUI] Using first driver as default: {driver.name} ({driver.version})")
        else:
            log(f"[GUI] Using driver: {driver.name} ({driver.version})")

        return gpu, driver

    def _get_selected_gpu(self):
        row = self.gpu_list.currentRow()
        if row < 0:
            return None
        try:
            name = self.gpu_list.item(row, 0).text()
            id_str = self.gpu_list.item(row, 1).text()
            mem = int(self.gpu_list.item(row, 2).text())
            load = float(self.gpu_list.item(row, 3).text())
            driver_version = self.gpu_list.item(row, 4).text()
            temp_text = self.gpu_list.item(row, 5).text()
            cuda_cap = self.gpu_list.item(row, 6).text()
            temp = None
            if temp_text:
                try:
                    temp = float(temp_text)
                except ValueError:
                    temp = None
            vendor = "nvidia" if "NVIDIA" in name.upper() else "unknown"
            return GPUInfo(name, id_str, mem, load, driver_version, vendor, temp, cuda_cap or None)
        except Exception as e:
            log(f"[GUI] Failed to reconstruct GPU from row {row}: {e}")
            log(traceback.format_exc())
            return None

    def _get_selected_driver(self):
        row = self.driver_list.currentRow()
        if row < 0:
            return None
        try:
            name = self.driver_list.item(row, 0).text()
            version = self.driver_list.item(row, 1).text()
            dx = self.driver_list.item(row, 2).text() == "Yes"
            vk_gl = self.driver_list.item(row, 3).text() == "Yes"
            cuda = self.driver_list.item(row, 4).text() == "Yes"
            api_support = {
                "DirectX": dx,
                "Vulkan": vk_gl,
                "OpenGL": vk_gl,
                "CUDA": cuda,
            }
            return DriverInfo(name, version, api_support)
        except Exception as e:
            log(f"[GUI] Failed to reconstruct Driver from row {row}: {e}")
            log(traceback.format_exc())
            return None

    def auto_bootstrap(self):
        auto = self.settings_manager.get_auto_mode()
        if not auto:
            log("[GUI] Auto mode disabled, skipping auto bootstrap.")
            return

        gpu, driver = self._pick_default_gpu_and_driver()
        if not gpu or not driver:
            return

        current_mode = self.mode_combo.currentText()
        last_drv_ver = self.settings_manager.get_last_driver_version()

        if last_drv_ver is None:
            log("[GUI] No previous driver version, building initial profile.")
        elif last_drv_ver != driver.version:
            log(f"[GUI] Driver change detected: {last_drv_ver} -> {driver.version}, rebuilding profile.")
        else:
            log("[GUI] Driver version unchanged, auto profile refresh.")

        bench_score = self.benchmark_engine.run_microbench()
        capabilities = {
            "directx": driver.api_support.get("DirectX"),
            "vulkan": driver.api_support.get("Vulkan"),
            "opengl": driver.api_support.get("OpenGL"),
            "cuda": driver.api_support.get("CUDA"),
            "cuda_capability": gpu.cuda_capability,
        }

        policy = {
            "type": "auto",
            "aggressiveness": self.settings_manager.get_global_aggressiveness(),
        }

        profile = self.translator.build_profile(gpu, driver, current_mode, bench_score, capabilities, game_exe=None, policy=policy)
        ai_score = profile.ai_score
        heur = profile.heuristic_score
        bench = profile.benchmark_score
        self.score_label.setText(f"AI: {ai_score:.2f} | Heuristic: {heur:.2f} | Bench: {bench:.2f}")
        self.cap_label.setText(
            f"Capabilities: DX={capabilities['directx']} VK={capabilities['vulkan']} "
            f"GL={capabilities['opengl']} CUDA={capabilities['cuda']} CC={capabilities['cuda_capability']}"
        )
        self.policy_label.setText(f"Current policy: {self.policy_engine.describe_policy(policy)}")

        profile_dict = profile.to_dict()
        self.profile_manager.save_profile(profile_dict)
        self.plugin_manager.on_profile_built(profile_dict)
        self.plugin_manager.on_benchmark_completed(profile_dict)
        self.plugin_manager.on_policy_applied(policy)
        self._refresh_profiles()

        self.settings_manager.update_profile_info(gpu, driver, current_mode)
        log("[GUI] Auto bootstrap complete. Generic translation profile is active.")
        self._update_game_vs_global_view()

    def on_refresh_clicked(self):
        self.refresh_all()
        if self.auto_mode_checkbox.isChecked():
            self.auto_bootstrap()

    def on_build_profile_manual(self):
        auto = self.auto_mode_checkbox.isChecked()
        if auto:
            QtWidgets.QMessageBox.information(
                self,
                "Automatic mode",
                "Automatic mode is enabled. Disable it to use manual profile building.",
            )
            return

        gpu = self._get_selected_gpu()
        driver = self._get_selected_driver()
        if not gpu or not driver:
            QtWidgets.QMessageBox.warning(
                self,
                "Missing selection",
                "Please select both a GPU and a Driver row.",
            )
            return
        mode = self.mode_combo.currentText()
        bench_score = self.benchmark_engine.run_microbench()
        capabilities = {
            "directx": driver.api_support.get("DirectX"),
            "vulkan": driver.api_support.get("Vulkan"),
            "opengl": driver.api_support.get("OpenGL"),
            "cuda": driver.api_support.get("CUDA"),
            "cuda_capability": gpu.cuda_capability,
        }
        policy = {
            "type": "auto",
            "aggressiveness": self.settings_manager.get_global_aggressiveness(),
        }
        profile = self.translator.build_profile(gpu, driver, mode, bench_score, capabilities, game_exe=None, policy=policy)
        ai_score = profile.ai_score
        heur = profile.heuristic_score
        bench = profile.benchmark_score
        self.score_label.setText(f"AI: {ai_score:.2f} | Heuristic: {heur:.2f} | Bench: {bench:.2f}")
        self.cap_label.setText(
            f"Capabilities: DX={capabilities['directx']} VK={capabilities['vulkan']} "
            f"GL={capabilities['opengl']} CUDA={capabilities['cuda']} CC={capabilities['cuda_capability']}"
        )
        self.policy_label.setText(f"Current policy: {self.policy_engine.describe_policy(policy)}")
        QtWidgets.QMessageBox.information(
            self,
            "Profile built (Manual)",
            f"Profile built for {gpu.name} in mode '{mode}'.\n"
            f"AI score: {ai_score:.2f}\nHeuristic score: {heur:.2f}\nBenchmark: {bench:.2f}",
        )
        profile_dict = profile.to_dict()
        self.plugin_manager.on_profile_built(profile_dict)
        self.plugin_manager.on_benchmark_completed(profile_dict)
        self.plugin_manager.on_policy_applied(policy)
        self.settings_manager.update_profile_info(gpu, driver, mode)
        self._update_game_vs_global_view()

    def on_save_profile_manual(self):
        auto = self.auto_mode_checkbox.isChecked()
        if auto:
            QtWidgets.QMessageBox.information(
                self,
                "Automatic mode",
                "Automatic mode is enabled. Profiles are already saved automatically.",
            )
            return

        profile_dict = self.translator.export_profile()
        if not profile_dict:
            QtWidgets.QMessageBox.warning(
                self,
                "No profile",
                "No active profile to save. Build one first.",
            )
            return
        self.profile_manager.save_profile(profile_dict)
        self._refresh_profiles()
        QtWidgets.QMessageBox.information(
            self,
            "Profile saved (Manual)",
            "Current profile saved to disk.",
        )

    def on_auto_mode_changed(self, state):
        auto = state == QtCore.Qt.Checked
        self.settings_manager.set_auto_mode(auto)
        self._update_manual_controls_enabled()
        if auto:
            log("[GUI] Auto mode enabled, running auto bootstrap.")
            self.auto_bootstrap()
        else:
            log("[GUI] Auto mode disabled, manual controls enabled.")

    def on_mode_changed(self, new_mode: str):
        if self.auto_mode_checkbox.isChecked():
            log(f"[GUI] Mode changed to '{new_mode}' in auto mode, rebuilding profile.")
            self.auto_bootstrap()
        else:
            self.settings_manager.settings["last_mode"] = new_mode
            self.settings_manager.save()

    def on_aggr_changed(self, value: int):
        self.settings_manager.set_global_aggressiveness(value)
        self.aggr_label.setText(f"Aggressiveness: {value}")
        self.global_aggr_value.setText(f"Global aggressiveness: {value}")
        if self.auto_mode_checkbox.isChecked():
            log("[GUI] Aggressiveness changed in auto mode, rebuilding profile.")
            self.auto_bootstrap()
        self._update_game_vs_global_view()

    def on_default_policy_changed(self, policy: str):
        self.settings_manager.set_default_game_policy(policy)

    def on_run_benchmark(self):
        bench_score = self.benchmark_engine.run_microbench()
        profile_dict = self.translator.export_profile()
        if profile_dict:
            profile_dict["benchmark_score"] = bench_score
            self.plugin_manager.on_benchmark_completed(profile_dict)
        QtWidgets.QMessageBox.information(
            self,
            "Benchmark completed",
            f"Matmul benchmark score: {bench_score:.2f} GFLOPS",
        )
        self._refresh_log_view()

    def _profile_from_dict(self, profile_dict):
        gpu_data = profile_dict.get("gpu")
        driver_data = profile_dict.get("driver")
        mode = profile_dict.get("mode", "balanced")
        game_exe = profile_dict.get("game_exe")
        policy_data = profile_dict.get("policy", {"type": "auto", "aggressiveness": 1})
        gpu = GPUInfo(
            name=gpu_data.get("name", ""),
            id_str=gpu_data.get("id", ""),
            memory_total_mb=gpu_data.get("memory_total_mb", 0),
            load=gpu_data.get("load", 0.0),
            driver_version=gpu_data.get("driver_version", ""),
            vendor=gpu_data.get("vendor", "unknown"),
            temperature=gpu_data.get("temperature"),
            cuda_capability=gpu_data.get("cuda_capability"),
        )
        driver = DriverInfo(
            name=driver_data.get("name", ""),
            version=driver_data.get("version", ""),
            api_support=driver_data.get("api_support", {}),
        )
        profile = TranslationProfile(
            gpu, driver, mode,
            ai_score=profile_dict.get("ai_score", 0.0),
            heuristic_score=profile_dict.get("heuristic_score", 0.0),
            benchmark_score=profile_dict.get("benchmark_score", 0.0),
            capabilities=profile_dict.get("capabilities", {}),
            game_exe=game_exe,
            policy=policy_data,
            aggressiveness=policy_data.get("aggressiveness", 1),
        )
        return profile

    def on_run_translation_tasks(self):
        profile_dict = self.translator.export_profile()
        if not profile_dict:
            QtWidgets.QMessageBox.warning(
                self,
                "No profile",
                "No active profile. Build one first.",
            )
            return

        profile = self._profile_from_dict(profile_dict)
        policy = profile.policy

        shader_res = self.translation_engine.shader_translation(policy, profile)
        compat_res = self.translation_engine.driver_compat_translation(policy, profile)
        perf_res = self.translation_engine.performance_tuning(policy, profile)

        msg = (
            f"Game: {profile.game_exe or 'generic'}\n\n"
            f"Policy: {self.policy_engine.describe_policy(policy)}\n\n"
            f"Shader: {shader_res['status']} - {shader_res['details']}\n"
            f"Driver: {compat_res['status']} - {compat_res['details']}\n"
            f"Perf: {perf_res['status']} - {perf_res['details']}"
        )
        QtWidgets.QMessageBox.information(
            self,
            "Translation tasks",
            msg,
        )

    def on_inspect_profile(self):
        row = self.profile_list.currentRow()
        if row < 0:
            QtWidgets.QMessageBox.information(
                self,
                "No selection",
                "Select a profile from the list first.",
            )
            return
        profile_dict = self.profile_manager.find_profile_by_index(row)
        if not profile_dict:
            return
        profile = self._profile_from_dict(profile_dict)
        policy = profile.policy
        msg = (
            f"GPU: {profile.gpu.name}\n"
            f"Driver: {profile.driver.version}\n"
            f"Mode: {profile.mode}\n"
            f"Game: {profile.game_exe or 'generic'}\n"
            f"AI score: {profile.ai_score:.2f}\n"
            f"Heuristic score: {profile.heuristic_score:.2f}\n"
            f"Benchmark: {profile.benchmark_score:.2f}\n"
            f"Policy: {self.policy_engine.describe_policy(policy)}\n"
        )
        QtWidgets.QMessageBox.information(
            self,
            "Profile inspector",
            msg,
        )

    def on_activate_profile(self):
        row = self.profile_list.currentRow()
        if row < 0:
            QtWidgets.QMessageBox.information(
                self,
                "No selection",
                "Select a profile from the list first.",
            )
            return
        profile_dict = self.profile_manager.find_profile_by_index(row)
        if not profile_dict:
            return
        profile = self._profile_from_dict(profile_dict)
        self.translator.current_profile = profile
        self.score_label.setText(
            f"AI: {profile.ai_score:.2f} | Heuristic: {profile.heuristic_score:.2f} | Bench: {profile.benchmark_score:.2f}"
        )
        self.policy_label.setText(f"Current policy: {self.policy_engine.describe_policy(profile.policy)}")
        self.game_label.setText(f"Current game: {profile.game_exe or 'generic'}")
        self._update_game_vs_global_view()
        QtWidgets.QMessageBox.information(
            self,
            "Profile activated",
            "Selected profile is now active.",
        )

    def _update_game_vs_global_view(self):
        profile_dict = self.translator.export_profile()
        global_aggr = self.settings_manager.get_global_aggressiveness()
        self.global_aggr_value.setText(f"Global aggressiveness: {global_aggr}")

        if not profile_dict:
            self.game_detected_label.setText("Game recognized: No")
            self.game_policy_value.setText("Game policy: N/A")
            self.game_aggr_value.setText("Game aggressiveness: N/A")
            self.game_vs_global_diff_label.setText("Difference: N/A")
            return

        game_exe = profile_dict.get("game_exe")
        policy = profile_dict.get("policy", {})
        game_policy_type = policy.get("type", "auto")
        game_aggr = policy.get("aggressiveness", global_aggr)

        if game_exe:
            self.game_detected_label.setText(f"Game recognized: Yes ({game_exe})")
        else:
            self.game_detected_label.setText("Game recognized: No (generic profile)")

        self.game_policy_value.setText(f"Game policy: {game_policy_type}")
        self.game_aggr_value.setText(f"Game aggressiveness: {game_aggr}")
        diff = game_aggr - global_aggr
        self.game_vs_global_diff_label.setText(f"{diff:+d}")

    def on_monitor_tick(self):
        try:
            gpus = self.gpu_detector.detect()
            self.gpu_list.setRowCount(len(gpus))
            for row, gpu in enumerate(gpus):
                self.gpu_list.setItem(row, 0, QtWidgets.QTableWidgetItem(gpu.name))
                self.gpu_list.setItem(row, 1, QtWidgets.QTableWidgetItem(gpu.id_str))
                self.gpu_list.setItem(row, 2, QtWidgets.QTableWidgetItem(str(gpu.memory_total_mb)))
                self.gpu_list.setItem(row, 3, QtWidgets.QTableWidgetItem(f"{gpu.load:.1f}"))
                self.gpu_list.setItem(row, 4, QtWidgets.QTableWidgetItem(gpu.driver_version))
                self.gpu_list.setItem(row, 5, QtWidgets.QTableWidgetItem(
                    "" if gpu.temperature is None else str(gpu.temperature)))
                self.gpu_list.setItem(row, 6, QtWidgets.QTableWidgetItem(
                    "" if gpu.cuda_capability is None else gpu.cuda_capability))
        except Exception as e:
            log(f"[GUI] Monitor tick failed: {e}")
            log(traceback.format_exc())

        self.game_session_manager.tick()
        current_game = self.game_session_manager.current_game_exe or "None"
        self.game_label.setText(f"Current game: {current_game}")
        self._update_game_vs_global_view()
        self._refresh_log_view()

# ======================================================================
# Entry point
# ======================================================================

def main():
    log(f"Starting Universal GPU Translator Command Center v{APP_VERSION}")
    try:
        gpu_detector = GPUDetector()
        driver_detector = DriverDetector(gpu_detector)
        translator = AITranslatorEngine()
        profile_manager = ProfileManager()
        settings_manager = SettingsManager()
        benchmark_engine = BenchmarkEngine()
        plugin_manager = PluginManager()
        policy_engine = TranslationPolicyEngine()
        translation_engine = TranslationTaskEngine()
        game_session_manager = GameSessionManager(
            gpu_detector, profile_manager, translator,
            driver_detector, benchmark_engine, settings_manager,
            plugin_manager, policy_engine
        )

        app = QtWidgets.QApplication(sys.argv)
        gui = GPUTranslatorGUI(
            gpu_detector, driver_detector, translator,
            profile_manager, settings_manager,
            benchmark_engine, plugin_manager,
            translation_engine, game_session_manager, policy_engine
        )
        gui.show()
        sys.exit(app.exec())
    except Exception as e:
        log(f"[FATAL] {e}")
        log(traceback.format_exc())
        try:
            QtWidgets.QMessageBox.critical(
                None,
                "Fatal error",
                f"An unrecoverable error occurred.\n\nDetails:\n{e}",
            )
        except Exception:
            pass
        sys.exit(1)

if __name__ == "__main__":
    main()
