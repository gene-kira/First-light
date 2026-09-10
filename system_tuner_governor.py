#!/usr/bin/env python3
# system_tuner_governor.py
#
# Concept implementation of a Windows system tuner with:
# - Autoloader for required libraries
# - GUI with Base / Turbo / Auto (AI-ish) modes
# - CPU power/performance profiles
# - "Beast mode" core/thread utilization helper
# - GPU telemetry (safe, read-only)
# - Manual + Auto "timing profile" controls (conceptual)
#
# IMPORTANT:
# This file DOES NOT actually change GPU timings or clocks.
# The functions that would do that are explicit placeholders.
# If you hook them to vendor tools (e.g., NVAPI, NVML with
# privileged extensions, AMD ADL, etc.), you do so at your
# own risk.

import importlib
import subprocess
import sys

# ---------------------------------------------------------------------------
# Autoloader for required libraries
# ---------------------------------------------------------------------------

REQUIRED_LIBS = [
    "psutil",
    "tkinter",   # usually built-in
    "pynvml",    # for NVIDIA GPU telemetry (optional, handled gracefully)
]

def ensure_library(lib_name: str):
    try:
        importlib.import_module(lib_name)
    except ImportError:
        print(f"[AUTOLOADER] Installing missing library: {lib_name}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib_name])
        except Exception as e:
            print(f"[AUTOLOADER] Failed to install {lib_name}: {e}")

def autoload_libraries():
    for lib in REQUIRED_LIBS:
        if lib == "tkinter":
            try:
                import tkinter  # noqa
            except ImportError:
                print("[AUTOLOADER] tkinter not found. Install via OS package manager.")
        else:
            ensure_library(lib)

autoload_libraries()

# Now safe to import what we can
import psutil
import threading
import time
import json
import os
import platform
import tkinter as tk
from tkinter import ttk

# Try GPU telemetry libs
GPU_BACKEND = None
try:
    import pynvml
    pynvml.nvmlInit()
    GPU_BACKEND = "nvidia_nvml"
except Exception:
    GPU_BACKEND = None

# ---------------------------------------------------------------------------
# Configuration & Profiles
# ---------------------------------------------------------------------------

CONFIG_PATH = os.path.join(os.path.dirname(__file__), "system_tuner_config.json")

DEFAULT_CONFIG = {
    "mode": "base",  # base | turbo | auto
    "beast_mode_enabled": False,
    "base_profile": {
        "cpu_affinity": "low",   # low | medium | high | all
        "priority": "normal",    # idle | below_normal | normal | above_normal | high
        "poll_interval": 3.0,
        "gpu_timing_profile": "eco"  # eco | balanced | performance
    },
    "turbo_profile": {
        "cpu_affinity": "all",
        "priority": "high",
        "poll_interval": 1.0,
        "gpu_timing_profile": "performance"
    },
    "auto_profile": {
        "poll_interval": 2.0,
        "cpu_affinity_idle": "low",
        "cpu_affinity_active": "all",
        "priority_idle": "below_normal",
        "priority_active": "high",
        "cpu_idle_threshold": 20.0,
        "cpu_active_threshold": 50.0,
        "gpu_idle_threshold": 20.0,
        "gpu_active_threshold": 60.0,
        "gpu_timing_idle": "eco",
        "gpu_timing_active": "performance"
    },
    "beast_mode": {
        "worker_threads": 4,
        "workload_intensity": 0.2
    },
    "manual_gpu_timing": {
        "core_offset_mhz": 0,
        "mem_offset_mhz": 0,
        "power_target_percent": 100
    }
}

def load_config():
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            return cfg
        except Exception:
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[CONFIG] Failed to save config: {e}")

CONFIG = load_config()

# ---------------------------------------------------------------------------
# System tuning helpers (CPU affinity, priority)
# ---------------------------------------------------------------------------

def get_current_process():
    return psutil.Process(os.getpid())

def map_affinity(profile_value: str):
    cpu_count = psutil.cpu_count(logical=True) or 1
    if profile_value == "low":
        return list(range(max(1, cpu_count // 4)))
    elif profile_value == "medium":
        return list(range(max(1, cpu_count // 2)))
    elif profile_value == "high":
        return list(range(max(1, int(cpu_count * 0.75))))
    elif profile_value == "all":
        return list(range(cpu_count))
    else:
        return list(range(cpu_count))

def map_priority(profile_value: str):
    if platform.system().lower() == "windows":
        mapping = {
            "idle": psutil.IDLE_PRIORITY_CLASS,
            "below_normal": psutil.BELOW_NORMAL_PRIORITY_CLASS,
            "normal": psutil.NORMAL_PRIORITY_CLASS,
            "above_normal": psutil.ABOVE_NORMAL_PRIORITY_CLASS,
            "high": psutil.HIGH_PRIORITY_CLASS,
        }
        return mapping.get(profile_value, psutil.NORMAL_PRIORITY_CLASS)
    else:
        mapping = {
            "idle": 19,
            "below_normal": 10,
            "normal": 0,
            "above_normal": -5,
            "high": -10,
        }
        return mapping.get(profile_value, 0)

def apply_cpu_profile(profile: dict):
    proc = get_current_process()
    affinity = map_affinity(profile.get("cpu_affinity", "all"))
    priority = map_priority(profile.get("priority", "normal"))

    try:
        proc.cpu_affinity(affinity)
    except Exception as e:
        print(f"[PROFILE] Failed to set CPU affinity: {e}")

    try:
        proc.nice(priority)
    except Exception as e:
        print(f"[PROFILE] Failed to set priority: {e}")

# ---------------------------------------------------------------------------
# GPU telemetry (safe, read-only)
# ---------------------------------------------------------------------------

def get_gpu_telemetry():
    if GPU_BACKEND == "nvidia_nvml":
        try:
            device_count = pynvml.nvmlDeviceGetCount()
            if device_count == 0:
                return {"backend": "nvidia_nvml", "devices": []}
            devices = []
            for i in range(device_count):
                h = pynvml.nvmlDeviceGetHandleByIndex(i)
                name = pynvml.nvmlDeviceGetName(h).decode("utf-8", errors="ignore")
                util = pynvml.nvmlDeviceGetUtilizationRates(h)
                mem = pynvml.nvmlDeviceGetMemoryInfo(h)
                clocks = {
                    "graphics_clock_mhz": pynvml.nvmlDeviceGetClockInfo(
                        h, pynvml.NVML_CLOCK_GRAPHICS
                    ),
                    "sm_clock_mhz": pynvml.nvmlDeviceGetClockInfo(
                        h, pynvml.NVML_CLOCK_SM
                    ),
                    "mem_clock_mhz": pynvml.nvmlDeviceGetClockInfo(
                        h, pynvml.NVML_CLOCK_MEM
                    ),
                }
                devices.append({
                    "index": i,
                    "name": name,
                    "gpu_util_percent": util.gpu,
                    "mem_util_percent": util.memory,
                    "mem_used_gb": round(mem.used / (1024 ** 3), 2),
                    "mem_total_gb": round(mem.total / (1024 ** 3), 2),
                    "clocks": clocks
                })
            return {"backend": "nvidia_nvml", "devices": devices}
        except Exception as e:
            print(f"[GPU] NVML telemetry error: {e}")
            return {"backend": "nvidia_nvml", "devices": []}
    else:
        return {"backend": "none", "devices": []}

# ---------------------------------------------------------------------------
# GPU "timing" profile (conceptual, non-destructive)
# ---------------------------------------------------------------------------

def apply_gpu_timing_profile(profile_name: str):
    """
    Conceptual GPU timing profile application.

    This function DOES NOT change real GPU clocks or firmware.
    It only logs what would be applied. If you later hook this
    to vendor APIs, keep safety in mind.
    """
    print(f"[GPU_TIMING] Requested profile: {profile_name}")
    # Example conceptual mapping
    if profile_name == "eco":
        print("[GPU_TIMING] Eco: lower power target, conservative clocks (placeholder).")
    elif profile_name == "balanced":
        print("[GPU_TIMING] Balanced: default-like behavior (placeholder).")
    elif profile_name == "performance":
        print("[GPU_TIMING] Performance: higher power target, aggressive clocks (placeholder).")
    else:
        print("[GPU_TIMING] Unknown profile, no-op.")

def apply_manual_gpu_timing(manual_cfg: dict):
    """
    Conceptual manual timing application.

    manual_cfg:
      - core_offset_mhz
      - mem_offset_mhz
      - power_target_percent

    This function DOES NOT actually apply offsets. It logs them.
    """
    core_off = manual_cfg.get("core_offset_mhz", 0)
    mem_off = manual_cfg.get("mem_offset_mhz", 0)
    pwr = manual_cfg.get("power_target_percent", 100)
    print(f"[GPU_TIMING_MANUAL] core_offset={core_off} MHz, "
          f"mem_offset={mem_off} MHz, power_target={pwr}% (placeholder only)")

# ---------------------------------------------------------------------------
# Beast mode: use idle cores/threads for synthetic helper work
# ---------------------------------------------------------------------------

class BeastModeWorker(threading.Thread):
    def __init__(self, intensity: float, stop_event: threading.Event, idx: int):
        super().__init__(daemon=True)
        self.intensity = max(0.0, min(1.0, intensity))
        self.stop_event = stop_event
        self.idx = idx

    def run(self):
        print(f"[BEAST] Worker {self.idx} started.")
        while not self.stop_event.is_set():
            start = time.time()
            work_duration = self.intensity * 0.5
            while time.time() - start < work_duration and not self.stop_event.is_set():
                x = 0
                for i in range(10000):
                    x += i * i
            time.sleep(0.5 * (1.0 - self.intensity))
        print(f"[BEAST] Worker {self.idx} stopped.")

class BeastModeController:
    def __init__(self, cfg_beast: dict):
        self.cfg = cfg_beast
        self.stop_event = threading.Event()
        self.workers = []

    def start(self):
        if self.workers:
            return
        threads = self.cfg.get("worker_threads", 4)
        intensity = self.cfg.get("workload_intensity", 0.2)
        for i in range(threads):
            w = BeastModeWorker(intensity, self.stop_event, i)
            self.workers.append(w)
            w.start()
        print("[BEAST] Beast mode enabled.")

    def stop(self):
        if not self.workers:
            return
        self.stop_event.set()
        for w in self.workers:
            w.join(timeout=2.0)
        self.workers = []
        self.stop_event = threading.Event()
        print("[BEAST] Beast mode disabled.")

BEAST_CONTROLLER = BeastModeController(CONFIG.get("beast_mode", {}))

# ---------------------------------------------------------------------------
# Auto mode controller (CPU + GPU heuristic)
# ---------------------------------------------------------------------------

class AutoModeController(threading.Thread):
    def __init__(self, cfg_auto: dict, gui_callback=None):
        super().__init__(daemon=True)
        self.cfg = cfg_auto
        self.gui_callback = gui_callback
        self.stop_event = threading.Event()

    def run(self):
        print("[AUTO] Auto mode controller started.")
        while not self.stop_event.is_set():
            poll_interval = self.cfg.get("poll_interval", 2.0)
            cpu_percent = psutil.cpu_percent(interval=None)
            gpu_info = get_gpu_telemetry()
            gpu_util = 0.0
            if gpu_info["devices"]:
                # Take max util across devices
                gpu_util = max(d["gpu_util_percent"] for d in gpu_info["devices"])

            # Decide state
            if (cpu_percent < self.cfg.get("cpu_idle_threshold", 20.0) and
                gpu_util < self.cfg.get("gpu_idle_threshold", 20.0)):
                profile = {
                    "cpu_affinity": self.cfg.get("cpu_affinity_idle", "low"),
                    "priority": self.cfg.get("priority_idle", "below_normal")
                }
                gpu_profile = self.cfg.get("gpu_timing_idle", "eco")
                state = "idle"
            elif (cpu_percent > self.cfg.get("cpu_active_threshold", 50.0) or
                  gpu_util > self.cfg.get("gpu_active_threshold", 60.0)):
                profile = {
                    "cpu_affinity": self.cfg.get("cpu_affinity_active", "all"),
                    "priority": self.cfg.get("priority_active", "high")
                }
                gpu_profile = self.cfg.get("gpu_timing_active", "performance")
                state = "active"
            else:
                profile = None
                gpu_profile = "balanced"
                state = "balanced"

            if profile is not None:
                apply_cpu_profile(profile)
            apply_gpu_timing_profile(gpu_profile)

            if self.gui_callback:
                self.gui_callback(cpu_percent, gpu_util, state)

            time.sleep(poll_interval)
        print("[AUTO] Auto mode controller stopped.")

AUTO_CONTROLLER = None

def start_auto_mode(gui_callback=None):
    global AUTO_CONTROLLER
    if AUTO_CONTROLLER is not None:
        return
    AUTO_CONTROLLER = AutoModeController(CONFIG.get("auto_profile", {}), gui_callback)
    AUTO_CONTROLLER.start()

def stop_auto_mode():
    global AUTO_CONTROLLER
    if AUTO_CONTROLLER is None:
        return
    AUTO_CONTROLLER.stop_event.set()
    AUTO_CONTROLLER = None

# ---------------------------------------------------------------------------
# Telemetry helpers
# ---------------------------------------------------------------------------

def get_telemetry_snapshot():
    cpu_percent = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory()
    gpu_info = get_gpu_telemetry()

    summary = {
        "cpu_percent": cpu_percent,
        "mem_percent": mem.percent,
        "mem_used_gb": round(mem.used / (1024 ** 3), 2),
        "mem_total_gb": round(mem.total / (1024 ** 3), 2),
        "gpu_backend": gpu_info["backend"],
        "gpu_devices": gpu_info["devices"]
    }
    return summary

# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class SystemTunerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("System Tuner Governor (Concept v2)")
        self.root.geometry("900x520")

        self.mode_var = tk.StringVar(value=CONFIG.get("mode", "base"))
        self.beast_var = tk.BooleanVar(value=CONFIG.get("beast_mode_enabled", False))

        self.telemetry_cpu = tk.StringVar(value="CPU: -- %")
        self.telemetry_mem = tk.StringVar(value="MEM: -- % (-- / -- GB)")
        self.telemetry_state = tk.StringVar(value="State: --")
        self.telemetry_mode = tk.StringVar(value=f"Mode: {self.mode_var.get()}")
        self.telemetry_gpu = tk.StringVar(value="GPU: backend=--, util=-- %")

        # Manual GPU timing controls
        self.manual_core_offset = tk.IntVar(value=CONFIG["manual_gpu_timing"].get("core_offset_mhz", 0))
        self.manual_mem_offset = tk.IntVar(value=CONFIG["manual_gpu_timing"].get("mem_offset_mhz", 0))
        self.manual_power_target = tk.IntVar(value=CONFIG["manual_gpu_timing"].get("power_target_percent", 100))

        self._build_layout()
        self._start_telemetry_loop()

        self.apply_mode(self.mode_var.get())

    def _build_layout(self):
        main_frame = ttk.Frame(self.root, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text="Mode Selection")
        mode_frame.pack(fill=tk.X, pady=5)

        ttk.Radiobutton(
            mode_frame, text="Base", variable=self.mode_var, value="base",
            command=lambda: self.apply_mode("base")
        ).pack(side=tk.LEFT, padx=5)

        ttk.Radiobutton(
            mode_frame, text="Turbo", variable=self.mode_var, value="turbo",
            command=lambda: self.apply_mode("turbo")
        ).pack(side=tk.LEFT, padx=5)

        ttk.Radiobutton(
            mode_frame, text="Auto (AI)", variable=self.mode_var, value="auto",
            command=lambda: self.apply_mode("auto")
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            mode_frame, text="Save Profile",
            command=self.save_current_config
        ).pack(side=tk.RIGHT, padx=5)

        # Beast mode
        beast_frame = ttk.LabelFrame(main_frame, text="Beast Mode (Core/Thread Utilization)")
        beast_frame.pack(fill=tk.X, pady=5)

        ttk.Checkbutton(
            beast_frame, text="Enable Beast Mode",
            variable=self.beast_var,
            command=self.toggle_beast_mode
        ).pack(side=tk.LEFT, padx=5)

        ttk.Label(beast_frame, text="Uses idle cores/threads for synthetic helper work.").pack(side=tk.LEFT, padx=10)

        # Telemetry
        telemetry_frame = ttk.LabelFrame(main_frame, text="Telemetry")
        telemetry_frame.pack(fill=tk.X, pady=5)

        ttk.Label(telemetry_frame, textvariable=self.telemetry_cpu).pack(anchor=tk.W)
        ttk.Label(telemetry_frame, textvariable=self.telemetry_mem).pack(anchor=tk.W)
        ttk.Label(telemetry_frame, textvariable=self.telemetry_gpu).pack(anchor=tk.W)
        ttk.Label(telemetry_frame, textvariable=self.telemetry_state).pack(anchor=tk.W)
        ttk.Label(telemetry_frame, textvariable=self.telemetry_mode).pack(anchor=tk.W)

        # Manual GPU timing
        gpu_manual_frame = ttk.LabelFrame(main_frame, text="Manual GPU Timing (Conceptual)")
        gpu_manual_frame.pack(fill=tk.X, pady=5)

        ttk.Label(gpu_manual_frame, text="Core Offset (MHz):").grid(row=0, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(gpu_manual_frame, textvariable=self.manual_core_offset, width=8).grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(gpu_manual_frame, text="Memory Offset (MHz):").grid(row=1, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(gpu_manual_frame, textvariable=self.manual_mem_offset, width=8).grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(gpu_manual_frame, text="Power Target (%):").grid(row=2, column=0, sticky=tk.W, padx=5, pady=2)
        ttk.Entry(gpu_manual_frame, textvariable=self.manual_power_target, width=8).grid(row=2, column=1, padx=5, pady=2)

        ttk.Button(
            gpu_manual_frame, text="Apply Manual Timing (Placeholder)",
            command=self.apply_manual_timing_clicked
        ).grid(row=3, column=0, columnspan=2, pady=5)

        # Info / description
        info_frame = ttk.LabelFrame(main_frame, text="Description")
        info_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        info_text = (
            "Base mode: conservative CPU + eco GPU profile for chatting, browsing, light work.\n"
            "Turbo mode: aggressive CPU + performance GPU profile for gaming or heavy workloads.\n"
            "Auto (AI) mode: monitors CPU/GPU usage and switches between idle/active profiles.\n\n"
            "Beast mode: uses synthetic workloads on idle cores/threads to keep them engaged.\n"
            "Manual GPU timing: conceptual offsets and power target, logged only (no real clock changes).\n"
            "GPU telemetry: read-only via NVML when available.\n"
        )
        ttk.Label(info_frame, text=info_text, justify=tk.LEFT).pack(anchor=tk.W)

    def apply_mode(self, mode: str):
        CONFIG["mode"] = mode
        self.telemetry_mode.set(f"Mode: {mode}")

        if mode == "base":
            stop_auto_mode()
            apply_cpu_profile(CONFIG.get("base_profile", {}))
            apply_gpu_timing_profile(CONFIG.get("base_profile", {}).get("gpu_timing_profile", "eco"))
        elif mode == "turbo":
            stop_auto_mode()
            apply_cpu_profile(CONFIG.get("turbo_profile", {}))
            apply_gpu_timing_profile(CONFIG.get("turbo_profile", {}).get("gpu_timing_profile", "performance"))
        elif mode == "auto":
            start_auto_mode(gui_callback=self._auto_gui_callback)
        else:
            stop_auto_mode()

        save_config(CONFIG)

    def _auto_gui_callback(self, cpu_percent: float, gpu_util: float, state: str):
        self.telemetry_state.set(f"State: {state} (CPU {cpu_percent:.1f}%, GPU {gpu_util:.1f}%)")

    def toggle_beast_mode(self):
        enabled = self.beast_var.get()
        CONFIG["beast_mode_enabled"] = enabled
        save_config(CONFIG)
        if enabled:
            BEAST_CONTROLLER.start()
        else:
            BEAST_CONTROLLER.stop()

    def save_current_config(self):
        CONFIG["manual_gpu_timing"]["core_offset_mhz"] = self.manual_core_offset.get()
        CONFIG["manual_gpu_timing"]["mem_offset_mhz"] = self.manual_mem_offset.get()
        CONFIG["manual_gpu_timing"]["power_target_percent"] = self.manual_power_target.get()
        save_config(CONFIG)

    def apply_manual_timing_clicked(self):
        manual_cfg = {
            "core_offset_mhz": self.manual_core_offset.get(),
            "mem_offset_mhz": self.manual_mem_offset.get(),
            "power_target_percent": self.manual_power_target.get()
        }
        CONFIG["manual_gpu_timing"] = manual_cfg
        save_config(CONFIG)
        apply_manual_gpu_timing(manual_cfg)

    def _start_telemetry_loop(self):
        def loop():
            while True:
                snap = get_telemetry_snapshot()
                self.telemetry_cpu.set(f"CPU: {snap['cpu_percent']:.1f} %")
                self.telemetry_mem.set(
                    f"MEM: {snap['mem_percent']:.1f} % "
                    f"({snap['mem_used_gb']:.2f} / {snap['mem_total_gb']:.2f} GB)"
                )
                if snap["gpu_backend"] == "nvidia_nvml" and snap["gpu_devices"]:
                    d0 = snap["gpu_devices"][0]
                    self.telemetry_gpu.set(
                        f"GPU[0]: {d0['name']} util={d0['gpu_util_percent']}% "
                        f"mem={d0['mem_util_percent']}% "
                        f"clk G={d0['clocks']['graphics_clock_mhz']} "
                        f"M={d0['clocks']['mem_clock_mhz']} MHz"
                    )
                else:
                    self.telemetry_gpu.set("GPU: backend=none, util=-- %")

                if CONFIG.get("mode") != "auto":
                    self.telemetry_state.set("State: manual")

                time.sleep(1.0)

        t = threading.Thread(target=loop, daemon=True)
        t.start()

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    root = tk.Tk()
    gui = SystemTunerGUI(root)
    root.protocol("WM_DELETE_WINDOW", lambda: on_close(root))
    root.mainloop()

def on_close(root):
    stop_auto_mode()
    BEAST_CONTROLLER.stop()
    root.destroy()

if __name__ == "__main__":
    main()
