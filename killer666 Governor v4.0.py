#!/usr/bin/env python3
# killer666_governor_v4.py
#
# HARD MERGE v4.0:
# - Universal GPU Control Center (UGCC) + System Tuner Governor (STG)
# - Single monolithic governor engine + GUI (delivered in 2 parts; this is PART 1: core engine)
#
# IMPORTANT:
# This program does NOT perform arbitrary GPU register/VBIOS writes or undocumented VRAM timing/strap changes.

from __future__ import annotations

import csv
import json
import os
import platform
import shutil
import subprocess
import threading
import time
import sys
from dataclasses import dataclass, asdict, field
from pathlib import Path

# ---------------------------------------------------------------------------
# Autoloader for required libraries
# ---------------------------------------------------------------------------

import importlib

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

import psutil

# Try GPU telemetry libs (NVML)
GPU_BACKEND_NVML = None
try:
    import pynvml

    pynvml.nvmlInit()
    GPU_BACKEND_NVML = "nvidia_nvml"
except Exception:
    GPU_BACKEND_NVML = None

# ---------------------------------------------------------------------------
# App-level constants / profile directory / config
# ---------------------------------------------------------------------------

APP_NAME = "killer666 Governor v4.0"
PROFILE_DIR = Path.home() / "GPUControlCenter"
PROFILE_DIR.mkdir(parents=True, exist_ok=True)

CONFIG_PATH = PROFILE_DIR / "killer666_governor_config_v4.json"

DEFAULT_CONFIG = {
    "mode": "base",  # base | turbo | auto
    "beast_mode_enabled": False,
    "base_profile": {
        "cpu_affinity": "low",
        "priority": "normal",
        "poll_interval": 3.0,
        "gpu_timing_profile": "eco",
    },
    "turbo_profile": {
        "cpu_affinity": "all",
        "priority": "high",
        "poll_interval": 1.0,
        "gpu_timing_profile": "performance",
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
        "gpu_timing_active": "performance",
    },
    "beast_mode": {
        "worker_threads": 4,
        "workload_intensity": 0.2,
    },
    "manual_gpu_timing": {
        "core_offset_mhz": 0,
        "mem_offset_mhz": 0,
        "power_target_percent": 100,
    },
}


def load_config():
    if CONFIG_PATH.exists():
        try:
            with CONFIG_PATH.open("r", encoding="utf-8") as f:
                cfg = json.load(f)
            return cfg
        except Exception:
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()


def save_config(cfg):
    try:
        with CONFIG_PATH.open("w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        print(f"[CONFIG] Failed to save config: {e}")


CONFIG = load_config()

# ---------------------------------------------------------------------------
# Unified GPU model
# ---------------------------------------------------------------------------


@dataclass
class GPU:
    index: int
    name: str
    vendor: str
    driver: str = "Unknown"
    memory_mb: int = 0
    device_id: str = ""
    pnp_id: str = ""
    temperature_c: float | None = None
    utilization_pct: float | None = None
    memory_used_mb: float | None = None
    memory_total_mb: float | None = None
    core_clock_mhz: float | None = None
    memory_clock_mhz: float | None = None
    power_w: float | None = None
    power_limit_w: float | None = None
    fan_pct: float | None = None
    controls: dict = field(default_factory=dict)


# ---------------------------------------------------------------------------
# Utility commands / PowerShell / detection
# ---------------------------------------------------------------------------


def run_cmd(args, timeout=4):
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return -1, "", ""


def powershell(script, timeout=6):
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return ""
    rc, out, _ = run_cmd(
        [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout,
    )
    return out if rc == 0 else ""


def detect_windows_adapters():
    script = r"""
$ErrorActionPreference='SilentlyContinue'
Get-CimInstance Win32_VideoController |
Select-Object Name,PNPDeviceID,AdapterCompatibility,DriverVersion,
AdapterRAM,VideoProcessor |
ConvertTo-Json -Compress
"""
    raw = powershell(script)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return data


def detect_nvidia_smi():
    exe = shutil.which("nvidia-smi")
    if not exe:
        candidates = [
            r"C:\Windows\System32\nvidia-smi.exe",
            r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
        ]
        exe = next((x for x in candidates if os.path.exists(x)), None)
    if not exe:
        return [], None

    query = (
        "index,name,driver_version,memory.total,memory.used,"
        "temperature.gpu,utilization.gpu,clocks.gr,clocks.mem,"
        "power.draw,power.limit,fan.speed,pci.device"
    )
    rc, out, _ = run_cmd(
        [exe, f"--query-gpu={query}", "--format=csv,noheader,nounits"], timeout=6
    )
    if rc != 0:
        return [], exe

    result = []
    for row in csv.reader(out.splitlines()):
        if len(row) < 13:
            continue
        try:
            def num(i):
                try:
                    return float(row[i].strip())
                except Exception:
                    return None

            result.append(
                GPU(
                    index=int(row[0].strip()),
                    name=row[1].strip(),
                    vendor="NVIDIA",
                    driver=row[2].strip(),
                    memory_mb=int(num(3) or 0),
                    memory_total_mb=num(3),
                    memory_used_mb=num(4),
                    temperature_c=num(5),
                    utilization_pct=num(6),
                    core_clock_mhz=num(7),
                    memory_clock_mhz=num(8),
                    power_w=num(9),
                    power_limit_w=num(10),
                    fan_pct=num(11),
                    device_id=row[12].strip(),
                    controls={
                        "telemetry": True,
                        "power_limit": True,
                        "core_clock_offset": False,
                        "memory_clock_offset": False,
                        "fan_control": False,
                        "voltage": False,
                        "memory_timings": False,
                        "vbios_write": False,
                    },
                )
            )
        except Exception:
            continue
    return result, exe


def classify_vendor(name, compatibility=""):
    text = f"{name} {compatibility}".lower()
    if "nvidia" in text:
        return "NVIDIA"
    if "amd" in text or "advanced micro devices" in text or "radeon" in text:
        return "AMD"
    if "intel" in text:
        return "Intel"
    return "Other"


def detect_gpus():
    gpus_smi, _ = detect_nvidia_smi()
    seen = {g.name.lower() for g in gpus_smi}

    adapters = detect_windows_adapters()
    next_index = max([g.index for g in gpus_smi], default=-1) + 1

    gpus = list(gpus_smi)

    for a in adapters:
        name = str(a.get("Name") or "Unknown GPU")
        vendor = classify_vendor(name, str(a.get("AdapterCompatibility") or ""))

        if name.lower() in seen:
            continue

        ram = a.get("AdapterRAM") or 0
        try:
            ram_mb = int(ram) // (1024 * 1024)
        except Exception:
            ram_mb = 0

        g = GPU(
            index=next_index,
            name=name,
            vendor=vendor,
            driver=str(a.get("DriverVersion") or "Unknown"),
            memory_mb=ram_mb,
            device_id=str(a.get("PNPDeviceID") or ""),
            pnp_id=str(a.get("PNPDeviceID") or ""),
            controls={
                "telemetry": True,
                "power_limit": False,
                "core_clock_offset": False,
                "memory_clock_offset": False,
                "fan_control": False,
                "voltage": False,
                "memory_timings": False,
                "vbios_write": False,
            },
        )
        gpus.append(g)
        next_index += 1

    return gpus


# ---------------------------------------------------------------------------
# Vendor backend abstraction (NVIDIA via nvidia-smi + generic)
# ---------------------------------------------------------------------------


class VendorBackend:
    def __init__(self, gpu: GPU):
        self.gpu = gpu

    def set_power_limit(self, watts: float):
        raise NotImplementedError("No safe generic power-limit interface.")

    def set_clock_offset(self, core: int, memory: int):
        raise NotImplementedError("No safe generic clock-offset interface.")

    def set_fan(self, percent: int):
        raise NotImplementedError("No safe generic fan interface.")

    def refresh(self):
        return self.gpu


class NvidiaBackend(VendorBackend):
    def __init__(self, gpu):
        super().__init__(gpu)
        self.exe = shutil.which("nvidia-smi") or (
            r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
        )

    def set_power_limit(self, watts: float):
        if not os.path.exists(self.exe) and not shutil.which(self.exe):
            raise RuntimeError("nvidia-smi was not found.")
        if watts <= 0:
            raise ValueError("Power limit must be positive.")
        rc, out, err = run_cmd(
            [self.exe, "-i", str(self.gpu.index), "-pl", str(int(watts))], timeout=5
        )
        if rc != 0:
            raise RuntimeError(err or out or "nvidia-smi rejected the power limit.")
        return out or "Power limit applied."

    def refresh(self):
        latest, _ = detect_nvidia_smi()
        for g in latest:
            if g.index == self.gpu.index:
                self.gpu = g
                break
        return self.gpu


class GenericBackend(VendorBackend):
    pass


def backend_for(gpu):
    return NvidiaBackend(gpu) if gpu.vendor == "NVIDIA" else GenericBackend(gpu)


# ---------------------------------------------------------------------------
# NVML GPU telemetry (safe, read-only)
# ---------------------------------------------------------------------------


def _safe_decode_name(name_raw):
    if isinstance(name_raw, bytes):
        return name_raw.decode("utf-8", errors="ignore")
    return str(name_raw)


def get_gpu_telemetry_nvml():
    if GPU_BACKEND_NVML == "nvidia_nvml":
        try:
            device_count = pynvml.nvmlDeviceGetCount()
            if device_count == 0:
                return {"backend": "nvidia_nvml", "devices": []}
            devices = []
            for i in range(device_count):
                h = pynvml.nvmlDeviceGetHandleByIndex(i)
                name_raw = pynvml.nvmlDeviceGetName(h)
                name = _safe_decode_name(name_raw)
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
                devices.append(
                    {
                        "index": i,
                        "name": name,
                        "gpu_util_percent": util.gpu,
                        "mem_util_percent": util.memory,
                        "mem_used_gb": round(mem.used / (1024**3), 2),
                        "mem_total_gb": round(mem.total / (1024**3), 2),
                        "clocks": clocks,
                    }
                )
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
    print(f"[GPU_TIMING] Requested profile: {profile_name}")
    if profile_name == "eco":
        print("[GPU_TIMING] Eco: lower power target, conservative clocks (placeholder).")
    elif profile_name == "balanced":
        print("[GPU_TIMING] Balanced: default-like behavior (placeholder).")
    elif profile_name == "performance":
        print("[GPU_TIMING] Performance: higher power target, aggressive clocks (placeholder).")
    else:
        print("[GPU_TIMING] Unknown profile, no-op.")


def apply_manual_gpu_timing(manual_cfg: dict):
    core_off = manual_cfg.get("core_offset_mhz", 0)
    mem_off = manual_cfg.get("mem_offset_mhz", 0)
    pwr = manual_cfg.get("power_target_percent", 100)
    print(
        f"[GPU_TIMING_MANUAL] core_offset={core_off} MHz, "
        f"mem_offset={mem_off} MHz, power_target={pwr}% (placeholder only)"
    )


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
# Beast mode engine
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
            gpu_info = get_gpu_telemetry_nvml()
            gpu_util = 0.0
            if gpu_info["devices"]:
                gpu_util = max(d["gpu_util_percent"] for d in gpu_info["devices"])

            if (
                cpu_percent < self.cfg.get("cpu_idle_threshold", 20.0)
                and gpu_util < self.cfg.get("gpu_idle_threshold", 20.0)
            ):
                profile = {
                    "cpu_affinity": self.cfg.get("cpu_affinity_idle", "low"),
                    "priority": self.cfg.get("priority_idle", "below_normal"),
                }
                gpu_profile = self.cfg.get("gpu_timing_idle", "eco")
                state = "idle"
            elif (
                cpu_percent > self.cfg.get("cpu_active_threshold", 50.0)
                or gpu_util > self.cfg.get("gpu_active_threshold", 60.0)
            ):
                profile = {
                    "cpu_affinity": self.cfg.get("cpu_affinity_active", "all"),
                    "priority": self.cfg.get("priority_active", "high"),
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


AUTO_CONTROLLER: AutoModeController | None = None


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
# Unified telemetry snapshot (CPU, RAM, NVML GPU)
# ---------------------------------------------------------------------------


def get_telemetry_snapshot():
    cpu_percent = psutil.cpu_percent(interval=0.2)
    mem = psutil.virtual_memory()
    gpu_info = get_gpu_telemetry_nvml()

    summary = {
        "cpu_percent": cpu_percent,
        "mem_percent": mem.percent,
        "mem_used_gb": round(mem.used / (1024**3), 2),
        "mem_total_gb": round(mem.total / (1024**3), 2),
        "gpu_backend": gpu_info["backend"],
        "gpu_devices": gpu_info["devices"],
    }
    return summary

# ---------------------------------------------------------------------------
# END OF PART 1 (core engine)
# PART 2 will contain:
# - Full tkinter GUI (UGCC + System Governor merged)
# - Tabs: GPU Info, Live Monitor, Controls, Timings, Profiles, Diagnostics, System Governor
# - Unified monitoring loops, logging, profile save/load, report export, entry point
# ---------------------------------------------------------------------------
# killer666_governor_v4.py — PART 2 (GUI + entry point)
#
# This file continues directly from PART 1 (core engine).
# Make sure PART 1 and PART 2 are concatenated into a single file.

import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from pathlib import Path

# ---------------------------------------------------------------------------
# GUI: Unified governor (UGCC + System Tuner Governor)
# ---------------------------------------------------------------------------


class GovernorApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1180x780")
        self.minsize(960, 620)

        # GPU state
        self.gpus: list[GPU] = []
        self.selected_gpu: GPU | None = None
        self.backend: VendorBackend | None = None
        self.monitoring = False

        # System governor state
        self.mode_var = tk.StringVar(value=CONFIG.get("mode", "base"))
        self.beast_var = tk.BooleanVar(value=CONFIG.get("beast_mode_enabled", False))

        self.telemetry_cpu = tk.StringVar(value="CPU: -- %")
        self.telemetry_mem = tk.StringVar(value="MEM: -- % (-- / -- GB)")
        self.telemetry_state = tk.StringVar(value="State: --")
        self.telemetry_mode = tk.StringVar(value=f"Mode: {self.mode_var.get()}")
        self.telemetry_gpu = tk.StringVar(value="GPU: backend=--, util=-- %")

        self.manual_core_offset = tk.IntVar(
            value=CONFIG["manual_gpu_timing"].get("core_offset_mhz", 0)
        )
        self.manual_mem_offset = tk.IntVar(
            value=CONFIG["manual_gpu_timing"].get("mem_offset_mhz", 0)
        )
        self.manual_power_target = tk.IntVar(
            value=CONFIG["manual_gpu_timing"].get("power_target_percent", 100)
        )

        self._build_ui()
        self.after(100, self.detect_gpus)
        self._start_governor_telemetry_loop()
        self.apply_mode(self.mode_var.get())

    # -----------------------------------------------------------------------
    # UI construction
    # -----------------------------------------------------------------------

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text=APP_NAME, font=("Segoe UI", 18, "bold")).pack(side="left")

        ttk.Button(top, text="Detect GPUs", command=self.detect_gpus).pack(side="right")
        ttk.Button(top, text="Export Report", command=self.export_report).pack(
            side="right", padx=6
        )

        self.gpu_combo = ttk.Combobox(top, state="readonly", width=42)
        self.gpu_combo.pack(side="right", padx=10)
        self.gpu_combo.bind("<<ComboboxSelected>>", self.select_gpu)

        self.status = tk.StringVar(value="Detecting hardware...")
        ttk.Label(self, textvariable=self.status, padding=(10, 0)).pack(fill="x")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.info_tab = ttk.Frame(self.notebook, padding=15)
        self.monitor_tab = ttk.Frame(self.notebook, padding=15)
        self.control_tab = ttk.Frame(self.notebook, padding=15)
        self.timing_tab = ttk.Frame(self.notebook, padding=15)
        self.profile_tab = ttk.Frame(self.notebook, padding=15)
        self.log_tab = ttk.Frame(self.notebook, padding=15)
        self.governor_tab = ttk.Frame(self.notebook, padding=15)

        for tab, title in [
            (self.info_tab, "GPU Information"),
            (self.monitor_tab, "Live Monitor"),
            (self.control_tab, "Controls"),
            (self.timing_tab, "Memory / Timings"),
            (self.profile_tab, "Profiles"),
            (self.log_tab, "Diagnostics"),
            (self.governor_tab, "System Governor"),
        ]:
            self.notebook.add(tab, text=title)

        self._build_info_tab()
        self._build_monitor_tab()
        self._build_control_tab()
        self._build_timing_tab()
        self._build_profile_tab()
        self._build_log_tab()
        self._build_governor_tab()

    def _build_info_tab(self):
        self.info_tree = ttk.Treeview(
            self.info_tab, columns=("value",), show="tree headings", height=18
        )
        self.info_tree.heading("#0", text="Property")
        self.info_tree.heading("value", text="Value")
        self.info_tree.column("#0", width=270)
        self.info_tree.column("value", width=650)
        self.info_tree.pack(fill="both", expand=True)

    def _build_monitor_tab(self):
        self.monitor_text = tk.Text(
            self.monitor_tab, wrap="word", state="disabled", font=("Consolas", 11)
        )
        self.monitor_text.pack(fill="both", expand=True)

        bar = ttk.Frame(self.monitor_tab)
        bar.pack(fill="x", pady=(10, 0))
        self.monitor_button = ttk.Button(
            bar, text="Start Monitoring", command=self.toggle_monitor
        )
        self.monitor_button.pack(side="left")

    def _build_control_tab(self):
        frame = ttk.Frame(self.control_tab)
        frame.pack(fill="x")

        self.control_status = tk.StringVar(
            value="Select a GPU to see supported controls."
        )
        ttk.Label(frame, textvariable=self.control_status, wraplength=900).pack(
            anchor="w", pady=(0, 15)
        )

        power = ttk.LabelFrame(frame, text="Power Limit", padding=12)
        power.pack(fill="x", pady=6)

        self.power_var = tk.StringVar()
        ttk.Label(power, text="Watts:").pack(side="left")
        ttk.Entry(power, textvariable=self.power_var, width=12).pack(
            side="left", padx=8
        )
        self.power_button = ttk.Button(power, text="Apply", command=self.apply_power)
        self.power_button.pack(side="left")

        clock = ttk.LabelFrame(frame, text="Clock Offsets", padding=12)
        clock.pack(fill="x", pady=6)

        self.core_var = tk.StringVar(value="0")
        self.mem_var = tk.StringVar(value="0")

        ttk.Label(clock, text="Core offset (MHz):").pack(side="left")
        ttk.Entry(clock, textvariable=self.core_var, width=10).pack(
            side="left", padx=6
        )
        ttk.Label(clock, text="Memory offset (MHz):").pack(side="left")
        ttk.Entry(clock, textvariable=self.mem_var, width=10).pack(
            side="left", padx=6
        )

        self.clock_button = ttk.Button(clock, text="Apply", command=self.apply_clocks)
        self.clock_button.pack(side="left", padx=8)

        fan = ttk.LabelFrame(frame, text="Fan", padding=12)
        fan.pack(fill="x", pady=6)

        self.fan_var = tk.StringVar(value="Auto")
        ttk.Label(fan, text="Mode:").pack(side="left")
        self.fan_combo = ttk.Combobox(
            fan,
            textvariable=self.fan_var,
            values=["Auto", "25", "50", "75", "100"],
            state="readonly",
            width=10,
        )
        self.fan_combo.pack(side="left", padx=8)

        self.fan_button = ttk.Button(fan, text="Apply", command=self.apply_fan)
        self.fan_button.pack(side="left")

        ttk.Label(
            frame,
            text=(
                "Unsupported controls are intentionally disabled. "
                "This governor does not perform arbitrary register or VBIOS writes."
            ),
            wraplength=900,
        ).pack(anchor="w", pady=20)

    def _build_timing_tab(self):
        ttk.Label(
            self.timing_tab,
            text="Memory Timing Capability",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w")

        self.timing_tree = ttk.Treeview(
            self.timing_tab, columns=("value", "status"), show="headings"
        )
        self.timing_tree.heading("value", text="Value")
        self.timing_tree.heading("status", text="Status")
        self.timing_tree.pack(fill="both", expand=True, pady=10)

        ttk.Label(
            self.timing_tab,
            text=(
                "VRAM timing/strap editing is not a universal GPU setting. "
                "It depends on the GPU generation, firmware and vendor tools. "
                "The governor reports availability instead of writing "
                "undocumented registers."
            ),
            wraplength=950,
        ).pack(anchor="w")

    def _build_profile_tab(self):
        top = ttk.Frame(self.profile_tab)
        top.pack(fill="x")

        ttk.Button(top, text="Save GPU Profile", command=self.save_profile).pack(
            side="left"
        )
        ttk.Button(top, text="Load GPU Profile", command=self.load_profile).pack(
            side="left", padx=6
        )
        ttk.Button(top, text="Reset Fields", command=self.reset_fields).pack(
            side="left"
        )

        self.profile_text = tk.Text(self.profile_tab, height=18, font=("Consolas", 10))
        self.profile_text.pack(fill="both", expand=True, pady=12)

    def _build_log_tab(self):
        self.log_text = tk.Text(
            self.log_tab, wrap="word", state="disabled", font=("Consolas", 10)
        )
        self.log_text.pack(fill="both", expand=True)

    def _build_governor_tab(self):
        main_frame = ttk.Frame(self.governor_tab)
        main_frame.pack(fill=tk.BOTH, expand=True)

        mode_frame = ttk.LabelFrame(main_frame, text="Mode Selection")
        mode_frame.pack(fill=tk.X, pady=5)

        ttk.Radiobutton(
            mode_frame,
            text="Base",
            variable=self.mode_var,
            value="base",
            command=lambda: self.apply_mode("base"),
        ).pack(side=tk.LEFT, padx=5)

        ttk.Radiobutton(
            mode_frame,
            text="Turbo",
            variable=self.mode_var,
            value="turbo",
            command=lambda: self.apply_mode("turbo"),
        ).pack(side=tk.LEFT, padx=5)

        ttk.Radiobutton(
            mode_frame,
            text="Auto (AI)",
            variable=self.mode_var,
            value="auto",
            command=lambda: self.apply_mode("auto"),
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            mode_frame, text="Save Governor Config", command=self.save_governor_config
        ).pack(side=tk.RIGHT, padx=5)

        beast_frame = ttk.LabelFrame(
            main_frame, text="Beast Mode (Core/Thread Utilization)"
        )
        beast_frame.pack(fill=tk.X, pady=5)

        ttk.Checkbutton(
            beast_frame,
            text="Enable Beast Mode",
            variable=self.beast_var,
            command=self.toggle_beast_mode,
        ).pack(side=tk.LEFT, padx=5)

        ttk.Label(
            beast_frame,
            text="Uses idle cores/threads for synthetic helper work.",
        ).pack(side=tk.LEFT, padx=10)

        telemetry_frame = ttk.LabelFrame(main_frame, text="System Telemetry")
        telemetry_frame.pack(fill=tk.X, pady=5)

        ttk.Label(telemetry_frame, textvariable=self.telemetry_cpu).pack(anchor=tk.W)
        ttk.Label(telemetry_frame, textvariable=self.telemetry_mem).pack(anchor=tk.W)
        ttk.Label(telemetry_frame, textvariable=self.telemetry_gpu).pack(anchor=tk.W)
        ttk.Label(telemetry_frame, textvariable=self.telemetry_state).pack(anchor=tk.W)
        ttk.Label(telemetry_frame, textvariable=self.telemetry_mode).pack(anchor=tk.W)

        gpu_manual_frame = ttk.LabelFrame(
            main_frame, text="Manual GPU Timing (Conceptual)"
        )
        gpu_manual_frame.pack(fill=tk.X, pady=5)

        ttk.Label(gpu_manual_frame, text="Core Offset (MHz):").grid(
            row=0, column=0, sticky=tk.W, padx=5, pady=2
        )
        ttk.Entry(
            gpu_manual_frame, textvariable=self.manual_core_offset, width=8
        ).grid(row=0, column=1, padx=5, pady=2)

        ttk.Label(gpu_manual_frame, text="Memory Offset (MHz):").grid(
            row=1, column=0, sticky=tk.W, padx=5, pady=2
        )
        ttk.Entry(
            gpu_manual_frame, textvariable=self.manual_mem_offset, width=8
        ).grid(row=1, column=1, padx=5, pady=2)

        ttk.Label(gpu_manual_frame, text="Power Target (%):").grid(
            row=2, column=0, sticky=tk.W, padx=5, pady=2
        )
        ttk.Entry(
            gpu_manual_frame, textvariable=self.manual_power_target, width=8
        ).grid(row=2, column=1, padx=5, pady=2)

        ttk.Button(
            gpu_manual_frame,
            text="Apply Manual Timing (Placeholder)",
            command=self.apply_manual_timing_clicked,
        ).grid(row=3, column=0, columnspan=2, pady=5)

        info_frame = ttk.LabelFrame(main_frame, text="Governor Description")
        info_frame.pack(fill=tk.BOTH, expand=True, pady=5)

        info_text = (
            "Base mode: conservative CPU + eco GPU profile for chatting, browsing, light work.\n"
            "Turbo mode: aggressive CPU + performance GPU profile for gaming or heavy workloads.\n"
            "Auto (AI) mode: monitors CPU/GPU usage and switches between idle/active profiles.\n\n"
            "Beast mode: uses synthetic workloads on idle cores/threads to keep them engaged.\n"
            "Manual GPU timing: conceptual offsets and power target, logged only (no real clock changes).\n"
            "GPU telemetry: read-only via NVML when available; GPU control via vendor-safe interfaces.\n"
        )
        ttk.Label(info_frame, text=info_text, justify=tk.LEFT).pack(anchor=tk.W)

    # -----------------------------------------------------------------------
    # Logging
    # -----------------------------------------------------------------------

    def log(self, message: str):
        stamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{stamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    # -----------------------------------------------------------------------
    # GPU detection / selection
    # -----------------------------------------------------------------------

    def detect_gpus(self):
        self.status.set("Detecting GPUs...")
        self.log("Starting hardware detection.")

        def worker():
            gpus = detect_gpus()
            self.after(0, lambda: self._finish_detection(gpus))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_detection(self, gpus: list[GPU]):
        self.gpus = gpus
        self.gpu_combo["values"] = [
            f"GPU {g.index}: {g.vendor} — {g.name}" for g in gpus
        ]

        if gpus:
            self.gpu_combo.current(0)
            self.select_gpu()
            self.status.set(f"Detected {len(gpus)} GPU(s).")
            self.log(f"Detected {len(gpus)} GPU(s).")
        else:
            self.status.set("No GPU could be identified.")
            self.log("No GPU detected through available Windows interfaces.")
            self._clear_gpu_ui()

    def select_gpu(self, event=None):
        if not self.gpus:
            return
        idx = self.gpu_combo.current()
        if idx < 0:
            return

        self.selected_gpu = self.gpus[idx]
        self.backend = backend_for(self.selected_gpu)

        self._update_info_tab()
        self._update_control_tab()
        self._update_timing_tab()
        self.log(
            f"Selected GPU {self.selected_gpu.index}: "
            f"{self.selected_gpu.vendor} {self.selected_gpu.name}"
        )

    def _clear_gpu_ui(self):
        for tree in (self.info_tree, self.timing_tree):
            for item in tree.get_children():
                tree.delete(item)

    # -----------------------------------------------------------------------
    # Info / controls / timings
    # -----------------------------------------------------------------------

    def _update_info_tab(self):
        for item in self.info_tree.get_children():
            self.info_tree.delete(item)

        g = self.selected_gpu
        if not g:
            return

        values = [
            ("Name", g.name),
            ("Vendor", g.vendor),
            ("Driver", g.driver),
            ("VRAM", f"{g.memory_mb:,} MB" if g.memory_mb else "Unknown"),
            ("Device ID", g.device_id or "Unknown"),
            ("Temperature", self._fmt(g.temperature_c, " °C")),
            ("GPU Utilization", self._fmt(g.utilization_pct, " %")),
            ("VRAM Used", self._fmt(g.memory_used_mb, " MB")),
            ("Core Clock", self._fmt(g.core_clock_mhz, " MHz")),
            ("Memory Clock", self._fmt(g.memory_clock_mhz, " MHz")),
            ("Power", self._fmt(g.power_w, " W")),
            ("Power Limit", self._fmt(g.power_limit_w, " W")),
            ("Fan", self._fmt(g.fan_pct, " %")),
        ]

        for k, v in values:
            self.info_tree.insert("", "end", text=k, values=(v,))

    @staticmethod
    def _fmt(value, suffix=""):
        return "Unknown" if value is None else f"{value:g}{suffix}"

    def _update_control_tab(self):
        g = self.selected_gpu
        if not g:
            return

        controls = g.controls
        self.power_button.configure(
            state="normal" if controls.get("power_limit") else "disabled"
        )
        self.clock_button.configure(
            state="normal"
            if controls.get("core_clock_offset") or controls.get("memory_clock_offset")
            else "disabled"
        )
        self.fan_button.configure(
            state="normal" if controls.get("fan_control") else "disabled"
        )

        supported = [
            name.replace("_", " ").title() for name, value in controls.items() if value
        ]
        self.control_status.set(
            f"{g.vendor} / {g.name}\n"
            f"Supported interfaces: {', '.join(supported) or 'telemetry only'}"
        )

    def _update_timing_tab(self):
        for item in self.timing_tree.get_children():
            self.timing_tree.delete(item)

        g = self.selected_gpu
        if not g:
            return

        entries = [
            ("Memory clock", self._fmt(g.memory_clock_mhz, " MHz"), "Read-only telemetry"),
            ("Memory timing control", "", "Not exposed by generic Windows interface"),
            ("Timing/strap registers", "", "Not supported by this safe generic backend"),
            ("VBIOS timing modification", "", "Disabled"),
        ]

        if g.controls.get("memory_timings"):
            entries[1] = (
                "Memory timing control",
                "Vendor interface available",
                "Supported backend",
            )

        for a, b, c in entries:
            self.timing_tree.insert("", "end", values=(f"{a}: {b}", c))

    # -----------------------------------------------------------------------
    # GPU control actions
    # -----------------------------------------------------------------------

    def apply_power(self):
        if not self.backend or not self.selected_gpu:
            return
        try:
            value = float(self.power_var.get())
            result = self.backend.set_power_limit(value)
            self.log(result)
            self.status.set("Power-limit request completed.")
        except Exception as e:
            self.log(f"Power-limit change rejected: {e}")
            messagebox.showwarning("Unsupported / rejected", str(e))

    def apply_clocks(self):
        messagebox.showinfo(
            "Vendor-specific control",
            "Clock-offset control is not exposed by the generic backend. "
            "A vendor-specific backend must be implemented for this GPU.",
        )
        self.log("Clock-offset request not applied.")

    def apply_fan(self):
        messagebox.showinfo(
            "Vendor-specific control",
            "Fan control is not exposed by the generic backend for this GPU.",
        )
        self.log("Fan-control request not applied.")

    # -----------------------------------------------------------------------
    # Live GPU monitor
    # -----------------------------------------------------------------------

    def toggle_monitor(self):
        if self.monitoring:
            self.monitoring = False
            self.monitor_button.configure(text="Start Monitoring")
            self.log("Monitoring stopped.")
        else:
            if not self.selected_gpu:
                return
            self.monitoring = True
            self.monitor_button.configure(text="Stop Monitoring")
            self.log("Monitoring started.")
            self.after(100, self._monitor_tick)

    def _monitor_tick(self):
        if not self.monitoring or not self.backend:
            return

        def worker():
            try:
                g = self.backend.refresh()
                self.after(0, lambda: self._update_live_monitor(g))
            except Exception as e:
                self.after(0, lambda: self.log(f"Monitor error: {e}"))

        threading.Thread(target=worker, daemon=True).start()
        self.after(1000, self._monitor_tick)

    def _update_live_monitor(self, g: GPU):
        self.selected_gpu = g
        self._update_info_tab()

        lines = [
            f"GPU: {g.name}",
            f"Vendor: {g.vendor}",
            "",
            f"Temperature : {self._fmt(g.temperature_c, ' °C')}",
            f"GPU Load    : {self._fmt(g.utilization_pct, ' %')}",
            f"VRAM Used   : {self._fmt(g.memory_used_mb, ' MB')}",
            f"VRAM Total  : {self._fmt(g.memory_total_mb, ' MB')}",
            f"Core Clock  : {self._fmt(g.core_clock_mhz, ' MHz')}",
            f"Memory Clock: {self._fmt(g.memory_clock_mhz, ' MHz')}",
            f"Power       : {self._fmt(g.power_w, ' W')}",
            f"Power Limit : {self._fmt(g.power_limit_w, ' W')}",
            f"Fan         : {self._fmt(g.fan_pct, ' %')}",
            "",
            "Safety state: arbitrary register/VBIOS writes disabled.",
        ]

        self.monitor_text.configure(state="normal")
        self.monitor_text.delete("1.0", "end")
        self.monitor_text.insert("end", "\n".join(lines))
        self.monitor_text.configure(state="disabled")

    # -----------------------------------------------------------------------
    # Governor mode handling (CPU + GPU timing profiles)
    # -----------------------------------------------------------------------

    def apply_mode(self, mode: str):
        CONFIG["mode"] = mode
        self.telemetry_mode.set(f"Mode: {mode}")

        if mode == "base":
            stop_auto_mode()
            apply_cpu_profile(CONFIG.get("base_profile", {}))
            apply_gpu_timing_profile(
                CONFIG.get("base_profile", {}).get("gpu_timing_profile", "eco")
            )
        elif mode == "turbo":
            stop_auto_mode()
            apply_cpu_profile(CONFIG.get("turbo_profile", {}))
            apply_gpu_timing_profile(
                CONFIG.get("turbo_profile", {}).get("gpu_timing_profile", "performance")
            )
        elif mode == "auto":
            start_auto_mode(gui_callback=self._auto_gui_callback)
        else:
            stop_auto_mode()

        save_config(CONFIG)

    def _auto_gui_callback(self, cpu_percent: float, gpu_util: float, state: str):
        self.telemetry_state.set(
            f"State: {state} (CPU {cpu_percent:.1f}%, GPU {gpu_util:.1f}%)"
        )

    def toggle_beast_mode(self):
        enabled = self.beast_var.get()
        CONFIG["beast_mode_enabled"] = enabled
        save_config(CONFIG)
        if enabled:
            BEAST_CONTROLLER.start()
        else:
            BEAST_CONTROLLER.stop()

    def save_governor_config(self):
        CONFIG["manual_gpu_timing"]["core_offset_mhz"] = self.manual_core_offset.get()
        CONFIG["manual_gpu_timing"]["mem_offset_mhz"] = self.manual_mem_offset.get()
        CONFIG["manual_gpu_timing"]["power_target_percent"] = (
            self.manual_power_target.get()
        )
        save_config(CONFIG)
        self.log("Governor configuration saved.")

    def apply_manual_timing_clicked(self):
        manual_cfg = {
            "core_offset_mhz": self.manual_core_offset.get(),
            "mem_offset_mhz": self.manual_mem_offset.get(),
            "power_target_percent": self.manual_power_target.get(),
        }
        CONFIG["manual_gpu_timing"] = manual_cfg
        save_config(CONFIG)
        apply_manual_gpu_timing(manual_cfg)
        self.log("Manual GPU timing (conceptual) applied.")

    def _start_governor_telemetry_loop(self):
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

    # -----------------------------------------------------------------------
    # GPU profile save/load
    # -----------------------------------------------------------------------

    def reset_fields(self):
        self.power_var.set("")
        self.core_var.set("0")
        self.mem_var.set("0")
        self.fan_var.set("Auto")
        self.log("GPU control fields reset.")

    def _gpu_profile_data(self):
        g = self.selected_gpu
        return {
            "application": APP_NAME,
            "version": 4,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "gpu": asdict(g) if g else None,
            "requested_settings": {
                "power_w": self.power_var.get(),
                "core_offset_mhz": self.core_var.get(),
                "memory_offset_mhz": self.mem_var.get(),
                "fan": self.fan_var.get(),
            },
        }

    def save_profile(self):
        if not self.selected_gpu:
            messagebox.showwarning("No GPU", "Detect and select a GPU first.")
            return

        path = filedialog.asksaveasfilename(
            initialdir=str(PROFILE_DIR),
            defaultextension=".json",
            filetypes=[("GPU profile", "*.json")],
        )
        if not path:
            return

        try:
            data = self._gpu_profile_data()
            Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.profile_text.delete("1.0", "end")
            self.profile_text.insert("end", json.dumps(data, indent=2))
            self.log(f"GPU profile saved: {path}")
        except Exception as e:
            messagebox.showerror("Profile error", str(e))

    def load_profile(self):
        path = filedialog.askopenfilename(
            initialdir=str(PROFILE_DIR),
            filetypes=[("GPU profile", "*.json")],
        )
        if not path:
            return

        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            settings = data.get("requested_settings", {})
            self.power_var.set(settings.get("power_w", ""))
            self.core_var.set(settings.get("core_offset_mhz", "0"))
            self.mem_var.set(settings.get("memory_offset_mhz", "0"))
            self.fan_var.set(settings.get("fan", "Auto"))

            self.profile_text.delete("1.0", "end")
            self.profile_text.insert("end", json.dumps(data, indent=2))
            self.log(f"GPU profile loaded: {path}")
        except Exception as e:
            messagebox.showerror("Profile error", str(e))

    # -----------------------------------------------------------------------
    # Report export
    # -----------------------------------------------------------------------

    def export_report(self):
        if not self.selected_gpu:
            messagebox.showwarning("No GPU", "Detect and select a GPU first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text report", "*.txt")],
        )
        if not path:
            return

        g = self.selected_gpu
        snap = get_telemetry_snapshot()

        lines = [
            APP_NAME,
            "=" * 70,
            "GPU Section",
            "-" * 40,
            f"GPU: {g.name}",
            f"Vendor: {g.vendor}",
            f"Driver: {g.driver}",
            f"VRAM: {g.memory_mb} MB",
            f"Device ID: {g.device_id}",
            "",
            "GPU Telemetry (nvidia-smi / NVML):",
            f"Temperature: {self._fmt(g.temperature_c, ' °C')}",
            f"Utilization: {self._fmt(g.utilization_pct, ' %')}",
            f"Core clock: {self._fmt(g.core_clock_mhz, ' MHz')}",
            f"Memory clock: {self._fmt(g.memory_clock_mhz, ' MHz')}",
            f"Power: {self._fmt(g.power_w, ' W')}",
            f"Power limit: {self._fmt(g.power_limit_w, ' W')}",
            f"Fan: {self._fmt(g.fan_pct, ' %')}",
            "",
            "Capabilities:",
        ]
        lines.extend(f"  {k}: {v}" for k, v in g.controls.items())
        lines += [
            "",
            "System Section",
            "-" * 40,
            f"CPU usage: {snap['cpu_percent']:.1f} %",
            f"Memory usage: {snap['mem_percent']:.1f} % "
            f"({snap['mem_used_gb']:.2f} / {snap['mem_total_gb']:.2f} GB)",
            f"Governor mode: {CONFIG.get('mode')}",
            f"Beast mode enabled: {CONFIG.get('beast_mode_enabled')}",
            "",
            "Safety:",
            "Arbitrary GPU register/VBIOS writes are disabled.",
            "Only controls backed by a supported vendor interface should be enabled.",
        ]

        Path(path).write_text("\n".join(lines), encoding="utf-8")
        self.log(f"Report exported: {path}")
        messagebox.showinfo("Export complete", f"Report saved to:\n{path}")

    # -----------------------------------------------------------------------
    # Shutdown
    # -----------------------------------------------------------------------

    def shutdown(self):
        stop_auto_mode()
        BEAST_CONTROLLER.stop()
        try:
            if GPU_BACKEND_NVML == "nvidia_nvml":
                pynvml.nvmlShutdown()
        except Exception:
            pass
        self.destroy()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main():
    if platform.system() != "Windows":
        print("Warning: killer666 Governor v4.0 is designed for Windows.")
    app = GovernorApp()
    app.protocol("WM_DELETE_WINDOW", app.shutdown)
    app.mainloop()


if __name__ == "__main__":
    main()
