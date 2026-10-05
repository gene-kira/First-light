#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Universal GPU Translator Command Center
- Single-file, monolithic
- Autoloader for all libraries
- GPU + driver detection
- Driver capability inference
- AI translation engine (tiny Torch model + heuristic fallback)
- Profile save/load
- Persistent settings (auto/manual mode, last GPU/driver/mode)
- Auto boot:
    * Detect GPU + driver
    * Build translation profile automatically (auto mode)
    * Detect driver changes and rebuild profile
- Manual mode:
    * User can build/save profiles explicitly
- PySide6 GUI
"""

import os
import sys
import subprocess
import importlib
import json
import time
import traceback

APP_VERSION = "0.7.0-UGTC"
AUTOLOADER_VERSION = "1.5"
LOGFILE = os.path.join(os.getcwd(), "gpu_translator.log")


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
# Autoloader
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


# ======================================================================
# Load modules
# ======================================================================

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
# GPU + Driver Detection
# ======================================================================

class GPUInfo:
    def __init__(self, name="", id_str="", memory_total_mb=0, load=0.0,
                 driver_version="", vendor="unknown"):
        self.name = name
        self.id_str = id_str
        self.memory_total_mb = memory_total_mb
        self.load = load
        self.driver_version = driver_version
        self.vendor = vendor

    def to_dict(self):
        return {
            "name": self.name,
            "id": self.id_str,
            "memory_total_mb": self.memory_total_mb,
            "load": self.load,
            "driver_version": self.driver_version,
            "vendor": self.vendor,
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
            return None, None
        try:
            handle = pynvml.nvmlDeviceGetHandleByIndex(index)
            mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
            driver = pynvml.nvmlSystemGetDriverVersion()
            return mem, driver
        except Exception as e:
            log(f"[GPUDetector] NVML info failed for index {index}: {e}")
            return None, None

    def detect(self):
        self.gpus = []
        try:
            if GPUtil is None:
                log("[GPUDetector] GPUtil not available, no GPU list.")
                return self.gpus

            devices = GPUtil.getGPUs()
            for idx, d in enumerate(devices):
                mem_info, driver_version = self._get_nvml_info(idx)
                if mem_info:
                    mem_total_mb = int(mem_info.total / (1024 * 1024))
                else:
                    mem_total_mb = int(getattr(d, "memoryTotal", 0))

                vendor = "nvidia" if "NVIDIA" in d.name.upper() else "unknown"

                gpu = GPUInfo(
                    name=d.name,
                    id_str=str(d.id),
                    memory_total_mb=mem_total_mb,
                    load=float(d.load) * 100.0,
                    driver_version=driver_version if driver_version else "unknown",
                    vendor=vendor,
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
# AI Translation Engine (tiny Torch model + heuristic)
# ======================================================================

class TranslationProfile:
    def __init__(self, gpu: GPUInfo, driver: DriverInfo, mode="balanced",
                 ai_score=0.0, heuristic_score=0.0):
        self.gpu = gpu
        self.driver = driver
        self.mode = mode
        self.created_at = time.time()
        self.ai_score = ai_score
        self.heuristic_score = heuristic_score

    def to_dict(self):
        return {
            "gpu": self.gpu.to_dict() if self.gpu else None,
            "driver": self.driver.to_dict() if self.driver else None,
            "mode": self.mode,
            "created_at": self.created_at,
            "ai_score": self.ai_score,
            "heuristic_score": self.heuristic_score,
        }


class TinyTranslatorNet(torch.nn.Module if torch is not None else object):
    """
    Very small feed-forward network:
    Input features:
      [mem_gb, load_pct, vendor_onehot(2), mode_onehot(3)]
      total = 1 + 1 + 2 + 3 = 7
    Output:
      single scalar "translation quality" score
    """

    def __init__(self):
        if torch is None:
            return
        super().__init__()
        self.fc1 = torch.nn.Linear(7, 16)
        self.fc2 = torch.nn.Linear(16, 8)
        self.fc3 = torch.nn.Linear(8, 1)
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

    def _encode_features(self, gpu: GPUInfo, driver: DriverInfo, mode: str):
        mem_gb = gpu.memory_total_mb / 1024.0
        load_pct = gpu.load

        vendor_vec = [0.0, 0.0]  # [nvidia, other]
        if gpu.vendor.lower() == "nvidia":
            vendor_vec[0] = 1.0
        else:
            vendor_vec[1] = 1.0

        mode_vec = [0.0, 0.0, 0.0]  # [balanced, performance, compatibility]
        mode = mode.lower()
        if mode == "balanced":
            mode_vec[0] = 1.0
        elif mode == "performance":
            mode_vec[1] = 1.0
        else:
            mode_vec[2] = 1.0

        features = [mem_gb, load_pct] + vendor_vec + mode_vec
        return features

    def _heuristic_score(self, gpu: GPUInfo, mode: str):
        base = gpu.memory_total_mb / 1024.0
        load_factor = max(0.1, 1.0 - gpu.load / 100.0)

        mode = mode.lower()
        if mode == "performance":
            mode_factor = 1.2
        elif mode == "compatibility":
            mode_factor = 0.9
        else:
            mode_factor = 1.0

        score = base * load_factor * mode_factor * 10.0
        return score

    def build_profile(self, gpu: GPUInfo, driver: DriverInfo, mode="balanced"):
        ai_score = 0.0
        heuristic_score = self._heuristic_score(gpu, mode)

        if self.model is not None and self.device is not None:
            try:
                feats = self._encode_features(gpu, driver, mode)
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

        self.current_profile = TranslationProfile(gpu, driver, mode, ai_score, heuristic_score)
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
# Profile & Settings Manager
# ======================================================================

PROFILE_PATH = os.path.join(os.getcwd(), "gpu_translation_profiles.json")
SETTINGS_PATH = os.path.join(os.getcwd(), "gpu_translator_settings.json")


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


class SettingsManager:
    """
    Persistent settings:
      - auto_mode: bool
      - last_gpu_id: str or None
      - last_driver_version: str or None
      - last_mode: str or None
    """

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
            }
        except Exception as e:
            log(f"[SettingsManager] Failed to load settings, using defaults: {e}")
            log(traceback.format_exc())
            return {
                "auto_mode": True,
                "last_gpu_id": None,
                "last_driver_version": None,
                "last_mode": "balanced",
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


# ======================================================================
# GUI
# ======================================================================

class GPUTranslatorGUI(QtWidgets.QMainWindow):
    def __init__(self, gpu_detector: GPUDetector, driver_detector: DriverDetector,
                 translator: AITranslatorEngine, profile_manager: ProfileManager,
                 settings_manager: SettingsManager):
        super().__init__()
        self.gpu_detector = gpu_detector
        self.driver_detector = driver_detector
        self.translator = translator
        self.profile_manager = profile_manager
        self.settings_manager = settings_manager

        self.setWindowTitle(f"Universal GPU Translator Command Center v{APP_VERSION}")
        self.resize(900, 600)

        self._build_ui()
        self._wire_events()
        self.refresh_all()
        self.auto_bootstrap()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)

        layout = QtWidgets.QVBoxLayout(central)

        top_split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        # GPU panel
        gpu_widget = QtWidgets.QWidget()
        gpu_layout = QtWidgets.QVBoxLayout(gpu_widget)
        self.gpu_list = QtWidgets.QTableWidget()
        self.gpu_list.setColumnCount(5)
        self.gpu_list.setHorizontalHeaderLabels(
            ["Name", "ID", "Memory (MB)", "Load (%)", "Driver"]
        )
        self.gpu_list.horizontalHeader().setStretchLastSection(True)
        gpu_layout.addWidget(QtWidgets.QLabel("Detected GPUs"))
        gpu_layout.addWidget(self.gpu_list)

        # Driver panel
        driver_widget = QtWidgets.QWidget()
        driver_layout = QtWidgets.QVBoxLayout(driver_widget)
        self.driver_list = QtWidgets.QTableWidget()
        self.driver_list.setColumnCount(4)
        self.driver_list.setHorizontalHeaderLabels(
            ["Name", "Version", "DirectX", "Vulkan/OpenGL"]
        )
        self.driver_list.horizontalHeader().setStretchLastSection(True)
        driver_layout.addWidget(QtWidgets.QLabel("Detected Drivers"))
        driver_layout.addWidget(self.driver_list)

        top_split.addWidget(gpu_widget)
        top_split.addWidget(driver_widget)

        # Middle: translator controls + mode
        mid_widget = QtWidgets.QWidget()
        mid_layout = QtWidgets.QGridLayout(mid_widget)

        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(["balanced", "performance", "compatibility"])

        self.auto_mode_checkbox = QtWidgets.QCheckBox("Automatic mode")
        self.auto_mode_checkbox.setChecked(self.settings_manager.get_auto_mode())

        self.build_profile_btn = QtWidgets.QPushButton("Build Translation Profile (Manual)")
        self.score_label = QtWidgets.QLabel("AI Score: N/A | Heuristic: N/A")
        self.save_profile_btn = QtWidgets.QPushButton("Save Profile (Manual)")

        mid_layout.addWidget(QtWidgets.QLabel("Translation Mode:"), 0, 0)
        mid_layout.addWidget(self.mode_combo, 0, 1)
        mid_layout.addWidget(self.auto_mode_checkbox, 1, 0, 1, 2)
        mid_layout.addWidget(self.build_profile_btn, 2, 0, 1, 2)
        mid_layout.addWidget(self.score_label, 3, 0, 1, 2)
        mid_layout.addWidget(self.save_profile_btn, 4, 0, 1, 2)

        # Bottom: profiles list
        bottom_widget = QtWidgets.QWidget()
        bottom_layout = QtWidgets.QVBoxLayout(bottom_widget)
        bottom_layout.addWidget(QtWidgets.QLabel("Saved Profiles"))
        self.profile_list = QtWidgets.QListWidget()
        bottom_layout.addWidget(self.profile_list)

        # Buttons row
        btn_row = QtWidgets.QHBoxLayout()
        self.refresh_btn = QtWidgets.QPushButton("Refresh GPUs/Drivers")
        self.exit_btn = QtWidgets.QPushButton("Exit")
        btn_row.addWidget(self.refresh_btn)
        btn_row.addStretch()
        btn_row.addWidget(self.exit_btn)

        layout.addWidget(top_split)
        layout.addWidget(mid_widget)
        layout.addWidget(bottom_widget)
        layout.addLayout(btn_row)

        # Initialize mode combo from settings
        last_mode = self.settings_manager.get_last_mode()
        idx = self.mode_combo.findText(last_mode)
        if idx >= 0:
            self.mode_combo.setCurrentIndex(idx)

        self._update_manual_controls_enabled()

    def _wire_events(self):
        self.refresh_btn.clicked.connect(self.on_refresh_clicked)
        self.exit_btn.clicked.connect(self.close)
        self.build_profile_btn.clicked.connect(self.on_build_profile_manual)
        self.save_profile_btn.clicked.connect(self.on_save_profile_manual)
        self.auto_mode_checkbox.stateChanged.connect(self.on_auto_mode_changed)
        self.mode_combo.currentTextChanged.connect(self.on_mode_changed)

    def _update_manual_controls_enabled(self):
        auto = self.auto_mode_checkbox.isChecked()
        self.build_profile_btn.setEnabled(not auto)
        self.save_profile_btn.setEnabled(not auto)

    def refresh_all(self):
        self._refresh_gpus()
        self._refresh_drivers()
        self._refresh_profiles()

    def _refresh_gpus(self):
        gpus = self.gpu_detector.detect()
        self.gpu_list.setRowCount(len(gpus))
        for row, gpu in enumerate(gpus):
            self.gpu_list.setItem(row, 0, QtWidgets.QTableWidgetItem(gpu.name))
            self.gpu_list.setItem(row, 1, QtWidgets.QTableWidgetItem(gpu.id_str))
            self.gpu_list.setItem(row, 2, QtWidgets.QTableWidgetItem(str(gpu.memory_total_mb)))
            self.gpu_list.setItem(row, 3, QtWidgets.QTableWidgetItem(f"{gpu.load:.1f}"))
            self.gpu_list.setItem(row, 4, QtWidgets.QTableWidgetItem(gpu.driver_version))

    def _refresh_drivers(self):
        drivers = self.driver_detector.detect()
        self.driver_list.setRowCount(len(drivers))
        for row, drv in enumerate(drivers):
            self.driver_list.setItem(row, 0, QtWidgets.QTableWidgetItem(drv.name))
            self.driver_list.setItem(row, 1, QtWidgets.QTableWidgetItem(drv.version))
            dx = "Yes" if drv.api_support.get("DirectX") else "No"
            vk_gl = "Yes" if (drv.api_support.get("Vulkan") or drv.api_support.get("OpenGL")) else "No"
            self.driver_list.setItem(row, 2, QtWidgets.QTableWidgetItem(dx))
            self.driver_list.setItem(row, 3, QtWidgets.QTableWidgetItem(vk_gl))

    def _refresh_profiles(self):
        self.profile_list.clear()
        profiles = self.profile_manager.list_profiles()
        for p in profiles:
            gpu_name = p.get("gpu", {}).get("name", "Unknown GPU")
            mode = p.get("mode", "balanced")
            ai_score = p.get("ai_score", 0.0)
            heur = p.get("heuristic_score", 0.0)
            created = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(p.get("created_at", time.time())),
            )
            self.profile_list.addItem(
                f"{gpu_name} | mode={mode} | AI={ai_score:.2f} | H={heur:.2f} | {created}"
            )

    def _get_gpu_by_id(self, gpu_id: str):
        gpus = self.gpu_detector.gpus
        for g in gpus:
            if g.id_str == gpu_id:
                return g
        return None

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
            vendor = "nvidia" if "NVIDIA" in name.upper() else "unknown"
            return GPUInfo(name, id_str, mem, load, driver_version, vendor)
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
            api_support = {
                "DirectX": dx,
                "Vulkan": vk_gl,
                "OpenGL": vk_gl,
            }
            return DriverInfo(name, version, api_support)
        except Exception as e:
            log(f"[GUI] Failed to reconstruct Driver from row {row}: {e}")
            log(traceback.format_exc())
            return None

    def _pick_default_gpu_and_driver(self):
        """
        Auto-selection logic:
          - Try last_gpu_id from settings
          - If not found, pick first GPU
          - Driver: match by vendor/driver_version if possible, else first
        """
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
            gpu = gpus[0]
            log(f"[GUI] Using first GPU as default: {gpu.name} (ID={gpu.id_str})")
        else:
            log(f"[GUI] Using last GPU from settings: {gpu.name} (ID={gpu.id_str})")

        # Pick driver: match version if possible
        last_drv_ver = self.settings_manager.get_last_driver_version()
        driver = None
        if last_drv_ver is not None:
            for d in drivers:
                if d.version == last_drv_ver:
                    driver = d
                    break

        if driver is None:
            # Try vendor match
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

    def auto_bootstrap(self):
        """
        Automatic boot:
          - If auto mode is enabled:
              * pick GPU + driver
              * detect driver change vs settings
              * build profile
              * save profile + settings
        """
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
            log("[GUI] Driver version unchanged, but auto mode will still ensure profile is active.")

        profile = self.translator.build_profile(gpu, driver, current_mode)
        ai_score = profile.ai_score
        heur = profile.heuristic_score
        self.score_label.setText(f"AI Score: {ai_score:.2f} | Heuristic: {heur:.2f}")

        # Save profile automatically
        self.profile_manager.save_profile(profile.to_dict())
        self._refresh_profiles()

        # Update settings
        self.settings_manager.update_profile_info(gpu, driver, current_mode)

        log("[GUI] Auto bootstrap complete. Translation profile is active.")

    # ------------------------------------------------------------------
    # Event handlers
    # ------------------------------------------------------------------

    def on_refresh_clicked(self):
        self.refresh_all()
        # In auto mode, re-bootstrap after refresh (e.g., after driver update)
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
        profile = self.translator.build_profile(gpu, driver, mode)
        ai_score = profile.ai_score
        heur = profile.heuristic_score
        self.score_label.setText(f"AI Score: {ai_score:.2f} | Heuristic: {heur:.2f}")
        QtWidgets.QMessageBox.information(
            self,
            "Profile built (Manual)",
            f"Profile built for {gpu.name} in mode '{mode}'.\n"
            f"AI score: {ai_score:.2f}\nHeuristic score: {heur:.2f}",
        )
        # Update settings with manual choice
        self.settings_manager.update_profile_info(gpu, driver, mode)

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
        # When mode changes in auto mode, rebuild automatically
        if self.auto_mode_checkbox.isChecked():
            log(f"[GUI] Mode changed to '{new_mode}' in auto mode, rebuilding profile.")
            self.auto_bootstrap()
        else:
            # In manual mode, just update settings; user can rebuild when ready
            self.settings_manager.settings["last_mode"] = new_mode
            self.settings_manager.save()


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

        app = QtWidgets.QApplication(sys.argv)
        gui = GPUTranslatorGUI(gpu_detector, driver_detector, translator, profile_manager, settings_manager)
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
