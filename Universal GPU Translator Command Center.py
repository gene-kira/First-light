#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Universal GPU Translator Command Center
- Single-file, monolithic
- Autoloader for all libraries
- GPU + driver detection
- AI translation engine (stubbed)
- Profile save/load
- PySide6 GUI

Switched from PyQt5 to PySide6.
"""

import os
import sys
import subprocess
import importlib
import json
import time
import traceback

APP_VERSION = "0.5.0-UGTC"
AUTOLOADER_VERSION = "1.3"
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
# AI Translation Engine (stub)
# ======================================================================

class TranslationProfile:
    def __init__(self, gpu: GPUInfo, driver: DriverInfo, mode="balanced"):
        self.gpu = gpu
        self.driver = driver
        self.mode = mode
        self.created_at = time.time()

    def to_dict(self):
        return {
            "gpu": self.gpu.to_dict() if self.gpu else None,
            "driver": self.driver.to_dict() if self.driver else None,
            "mode": self.mode,
            "created_at": self.created_at,
        }


class AITranslatorEngine:
    def __init__(self):
        self.current_profile = None

    def build_profile(self, gpu: GPUInfo, driver: DriverInfo, mode="balanced"):
        log(f"[AITranslatorEngine] Building profile for GPU={gpu.name}, driver={driver.version}, mode={mode}")
        self.current_profile = TranslationProfile(gpu, driver, mode)
        return self.current_profile

    def simulate_translation_score(self):
        if not self.current_profile or not self.current_profile.gpu:
            return 0.0
        gpu = self.current_profile.gpu
        base = gpu.memory_total_mb / 1024.0
        load_factor = max(0.1, 1.0 - gpu.load / 100.0)
        score = base * load_factor * 10.0
        log(f"[AITranslatorEngine] Simulated translation score: {score:.2f}")
        return score

    def export_profile(self):
        if not self.current_profile:
            return None
        return self.current_profile.to_dict()


# ======================================================================
# Profile Manager
# ======================================================================

PROFILE_PATH = os.path.join(os.getcwd(), "gpu_translation_profiles.json")

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


# ======================================================================
# GUI
# ======================================================================

class GPUTranslatorGUI(QtWidgets.QMainWindow):
    def __init__(self, gpu_detector: GPUDetector, driver_detector: DriverDetector,
                 translator: AITranslatorEngine, profile_manager: ProfileManager):
        super().__init__()
        self.gpu_detector = gpu_detector
        self.driver_detector = driver_detector
        self.translator = translator
        self.profile_manager = profile_manager

        self.setWindowTitle(f"Universal GPU Translator Command Center v{APP_VERSION}")
        self.resize(900, 600)

        self._build_ui()
        self._wire_events()
        self.refresh_all()

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

        # Middle: translator controls
        mid_widget = QtWidgets.QWidget()
        mid_layout = QtWidgets.QGridLayout(mid_widget)

        self.mode_combo = QtWidgets.QComboBox()
        self.mode_combo.addItems(["balanced", "performance", "compatibility"])

        self.build_profile_btn = QtWidgets.QPushButton("Build Translation Profile")
        self.score_label = QtWidgets.QLabel("Score: N/A")
        self.save_profile_btn = QtWidgets.QPushButton("Save Profile")

        mid_layout.addWidget(QtWidgets.QLabel("Translation Mode:"), 0, 0)
        mid_layout.addWidget(self.mode_combo, 0, 1)
        mid_layout.addWidget(self.build_profile_btn, 1, 0, 1, 2)
        mid_layout.addWidget(self.score_label, 2, 0, 1, 2)
        mid_layout.addWidget(self.save_profile_btn, 3, 0, 1, 2)

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

    def _wire_events(self):
        self.refresh_btn.clicked.connect(self.refresh_all)
        self.exit_btn.clicked.connect(self.close)
        self.build_profile_btn.clicked.connect(self.on_build_profile)
        self.save_profile_btn.clicked.connect(self.on_save_profile)

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
            created = time.strftime(
                "%Y-%m-%d %H:%M:%S",
                time.localtime(p.get("created_at", time.time())),
            )
            self.profile_list.addItem(f"{gpu_name} | mode={mode} | {created}")

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

    def on_build_profile(self):
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
        self.translator.build_profile(gpu, driver, mode)
        score = self.translator.simulate_translation_score()
        self.score_label.setText(f"Score: {score:.2f}")
        QtWidgets.QMessageBox.information(
            self,
            "Profile built",
            f"Profile built for {gpu.name} in mode '{mode}'.\nSimulated score: {score:.2f}",
        )

    def on_save_profile(self):
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
            "Profile saved",
            "Current profile saved to disk.",
        )


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

        app = QtWidgets.QApplication(sys.argv)
        gui = GPUTranslatorGUI(gpu_detector, driver_detector, translator, profile_manager)
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
