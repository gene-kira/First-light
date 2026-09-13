#!/usr/bin/env python3
# ============================================================
# GPU GOVERNOR v7.0
# Multi-GPU, AI/HC/Gaming profiles, FLOP governor, VRAM stress,
# Curve visualizer, Factory reset, Fan curve (NVAPI-ready),
# Clock/voltage control (NVAPI hook), Qt6 GUI with full dashboard,
# Autoloader, Plugin system, Logging/CSV export, AI auto-tuning,
# Memory leak detector, Power curve visualizer, Thermal prediction
# ============================================================

import sys
import time
import json
import signal
import threading
import os
import csv
import logging
import importlib
from pathlib import Path
from dataclasses import dataclass
from typing import Callable, Optional, List, Dict, Any

# ============================================================
# Autoloader / dependency check
# ============================================================

HAS_TORCH = False
HAS_PYNVML = False
HAS_QT = False
HAS_QTCHARTS = False
HAS_NVAPI = False

def ensure_dependencies():
    global HAS_TORCH, HAS_PYNVML, HAS_QT, HAS_QTCHARTS, HAS_NVAPI
    try:
        import torch  # noqa
        HAS_TORCH = True
    except Exception as e:
        print(f"[AUTOLOAD] Missing torch (PyTorch): {e}")
        print("           Install with: pip install torch --extra-index-url https://download.pytorch.org/whl/cu118")
    try:
        import pynvml  # noqa
        HAS_PYNVML = True
    except Exception as e:
        print(f"[AUTOLOAD] Missing pynvml: {e}")
        print("           Install with: pip install nvidia-ml-py")
    try:
        from PyQt6 import QtWidgets, QtCore, QtGui  # noqa
        HAS_QT = True
    except Exception as e:
        print(f"[AUTOLOAD] Missing PyQt6: {e}")
        print("           Install with: pip install PyQt6")
    if HAS_QT:
        try:
            from PyQt6.QtCharts import QChart, QChartView, QLineSeries  # noqa
            HAS_QTCHARTS = True
        except Exception as e:
            print(f"[AUTOLOAD] QtCharts not available: {e}")
            print("           Install with: pip install PyQt6-Charts (if needed)")
    try:
        # Try a Python NVAPI binding first
        import nvapi  # noqa
        HAS_NVAPI = True
        print("[AUTOLOAD] NVAPI Python binding detected")
    except Exception:
        # Fallback: try loading nvapi64.dll via ctypes (Windows only)
        try:
            import ctypes
            nvapi_lib = ctypes.WinDLL("nvapi64.dll")
            HAS_NVAPI = True
            print("[AUTOLOAD] NVAPI DLL loaded via ctypes")
        except Exception as e:
            print(f"[AUTOLOAD] NVAPI not available: {e}")
            HAS_NVAPI = False
    if not (HAS_TORCH and HAS_PYNVML and HAS_QT):
        print("[AUTOLOAD] Critical dependencies missing — governor will not run correctly.")
    else:
        print("[AUTOLOAD] Dependencies OK: torch, pynvml, PyQt6")

ensure_dependencies()

import torch
import pynvml
from PyQt6 import QtWidgets, QtCore, QtGui
if HAS_QTCHARTS:
    from PyQt6.QtCharts import QChart, QChartView, QLineSeries

# ============================================================
# Logging / CSV export
# ============================================================

BASE_DIR = Path(os.path.dirname(__file__)).resolve()
SETTINGS_PATH = BASE_DIR / "governor_settings.json"
LOG_PATH = BASE_DIR / "governor_log.csv"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler(BASE_DIR / "governor_debug.log", encoding="utf-8")
    ]
)

CSV_LOCK = threading.Lock()

def log_telemetry_csv(row: Dict[str, Any]):
    header = [
        "timestamp", "gpu_index", "name", "temp", "power", "core_clock",
        "mem_clock", "gpu_util", "mem_util", "fan_speed",
        "flops_s", "flop_limit", "profile_mode", "vram_used_mb", "vram_total_mb"
    ]
    with CSV_LOCK:
        file_exists = LOG_PATH.exists()
        with LOG_PATH.open("a", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=header)
            if not file_exists:
                writer.writeheader()
            writer.writerow(row)

# ============================================================
# Hardcoded defaults (manual / gaming profiles)
# ============================================================

HC_POWER_LIMIT_W = 280
HC_TEMP_LIMIT_C = 83
HC_FLOP_LIMIT = 5e12

GAMING_POWER_LIMIT_W = 260
GAMING_TEMP_LIMIT_C = 80
GAMING_FLOP_LIMIT = 4e12

# ============================================================
# NVML / GPU introspection (multi-GPU)
# ============================================================

NVML_INIT = False
NVML_DEVICE_HANDLES: Dict[int, object] = {}
NVML_LOCK = threading.Lock()

def nvml_init():
    global NVML_INIT, NVML_DEVICE_HANDLES
    with NVML_LOCK:
        if NVML_INIT:
            return
        try:
            pynvml.nvmlInit()
            count = pynvml.nvmlDeviceGetCount()
            NVML_DEVICE_HANDLES = {}
            for i in range(count):
                NVML_DEVICE_HANDLES[i] = pynvml.nvmlDeviceGetHandleByIndex(i)
            NVML_INIT = True
            print(f"[NVML] Initialized, {count} GPU(s) detected")
        except Exception as e:
            print(f"[NVML] Init failed: {e}")
            NVML_INIT = False
            NVML_DEVICE_HANDLES = {}

def nvml_shutdown():
    global NVML_INIT, NVML_DEVICE_HANDLES
    with NVML_LOCK:
        if not NVML_INIT:
            return
        try:
            pynvml.nvmlShutdown()
        except Exception as e:
            print(f"[NVML] Shutdown failed: {e}")
        NVML_INIT = False
        NVML_DEVICE_HANDLES = {}

def _get_handle(index: int):
    nvml_init()
    if not NVML_INIT:
        return None
    return NVML_DEVICE_HANDLES.get(index, None)

def _safe_nvml_name(h):
    try:
        name = pynvml.nvmlDeviceGetName(h)
        if isinstance(name, bytes):
            return name.decode("utf-8", errors="ignore")
        return str(name)
    except Exception as e:
        print(f"[NVML] Name read failed: {e}")
        return "Unknown"

def get_gpu_telemetry(index: int):
    h = _get_handle(index)
    if h is None:
        return {
            "index": index,
            "name": "Unknown",
            "temp": 0,
            "power": 0.0,
            "core_clock": 0,
            "mem_clock": 0,
            "gpu_util": 0,
            "mem_util": 0,
            "fan_speed": 0,
            "vram_used_mb": 0,
            "vram_total_mb": 0,
        }
    try:
        name = _safe_nvml_name(h)
        temp = pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU)
        power = pynvml.nvmlDeviceGetPowerUsage(h) / 1000.0
        core_clock = pynvml.nvmlDeviceGetClockInfo(h, pynvml.NVML_CLOCK_GRAPHICS)
        mem_clock = pynvml.nvmlDeviceGetClockInfo(h, pynvml.NVML_CLOCK_MEM)
        util = pynvml.nvmlDeviceGetUtilizationRates(h)
        try:
            fan_speed = pynvml.nvmlDeviceGetFanSpeed(h)
        except Exception:
            fan_speed = 0
        try:
            mem_info = pynvml.nvmlDeviceGetMemoryInfo(h)
            vram_used_mb = mem_info.used / (1024 * 1024)
            vram_total_mb = mem_info.total / (1024 * 1024)
        except Exception:
            vram_used_mb = 0
            vram_total_mb = 0
        return {
            "index": index,
            "name": name,
            "temp": temp,
            "power": power,
            "core_clock": core_clock,
            "mem_clock": mem_clock,
            "gpu_util": util.gpu,
            "mem_util": util.memory,
            "fan_speed": fan_speed,
            "vram_used_mb": vram_used_mb,
            "vram_total_mb": vram_total_mb,
        }
    except Exception as e:
        print(f"[NVML] Telemetry failed (GPU {index}): {e}")
        return {
            "index": index,
            "name": "Unknown",
            "temp": 0,
            "power": 0.0,
            "core_clock": 0,
            "mem_clock": 0,
            "gpu_util": 0,
            "mem_util": 0,
            "fan_speed": 0,
            "vram_used_mb": 0,
            "vram_total_mb": 0,
        }

def get_default_power_limit_w(index: int):
    h = _get_handle(index)
    if h is None:
        return HC_POWER_LIMIT_W
    try:
        return pynvml.nvmlDeviceGetPowerManagementDefaultLimit(h) / 1000.0
    except Exception as e:
        print(f"[NVML] Default power limit failed (GPU {index}): {e}")
        return HC_POWER_LIMIT_W

def get_thermal_cap_c(index: int):
    h = _get_handle(index)
    if h is None:
        return HC_TEMP_LIMIT_C + 5
    try:
        temp = pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU)
        return max(HC_TEMP_LIMIT_C, temp + 10)
    except Exception as e:
        print(f"[NVML] Thermal cap failed (GPU {index}): {e}")
        return HC_TEMP_LIMIT_C + 5

def estimate_fp32_flops_per_sec(index: int):
    h = _get_handle(index)
    if h is None:
        return HC_FLOP_LIMIT
    try:
        core_clock_mhz = pynvml.nvmlDeviceGetClockInfo(h, pynvml.NVML_CLOCK_GRAPHICS)
        sm_count = 80
        fp32_cores_per_sm = 64
        freq_hz = core_clock_mhz * 1e6
        cores = sm_count * fp32_cores_per_sm
        flops = cores * freq_hz * 2
        return max(HC_FLOP_LIMIT, min(flops, 5e13))
    except Exception as e:
        print(f"[NVML] FP32 estimate failed (GPU {index}): {e}")
        return HC_FLOP_LIMIT

def set_power_limit_w(index: int, watts: int):
    h = _get_handle(index)
    if h is None:
        print(f"[NVML] Power limit set skipped (GPU {index} not available)")
        return
    try:
        pynvml.nvmlDeviceSetPowerManagementLimit(h, int(watts * 1000))
        print(f"[NVML] GPU {index}: Power limit set to {watts} W")
    except Exception as e:
        print(f"[NVML] Failed to set power limit (GPU {index}): {e}")

# ============================================================
# NVAPI / fan/clock/voltage control
# ============================================================

def nvapi_set_fan_speed_percent(index: int, percent: int):
    if not HAS_NVAPI:
        print(f"[NVAPI] Fan set stub (GPU {index} -> {percent}%) — NVAPI not available")
        return
    print(f"[NVAPI] Fan speed GPU {index} -> {percent}% (placeholder, integrate real NVAPI calls here)")

def nvapi_set_core_clock_offset(index: int, offset_mhz: int):
    if not HAS_NVAPI:
        print(f"[NVAPI] Core clock offset stub GPU {index} -> {offset_mhz} MHz")
        return
    print(f"[NVAPI] Core clock offset GPU {index} -> {offset_mhz} MHz (placeholder)")

def nvapi_set_mem_clock_offset(index: int, offset_mhz: int):
    if not HAS_NVAPI:
        print(f"[NVAPI] Mem clock offset stub GPU {index} -> {offset_mhz} MHz")
        return
    print(f"[NVAPI] Mem clock offset GPU {index} -> {offset_mhz} MHz (placeholder)")

def nvapi_set_voltage_offset(index: int, offset_mv: int):
    if not HAS_NVAPI:
        print(f"[NVAPI] Voltage offset stub GPU {index} -> {offset_mv} mV")
        return
    print(f"[NVAPI] Voltage offset GPU {index} -> {offset_mv} mV (placeholder)")

# ============================================================
# Fan curve (NVAPI-backed)
# ============================================================

def set_fan_speed_percent(index: int, percent: int):
    nvapi_set_fan_speed_percent(index, percent)

def compute_fan_target(temp_c: int) -> int:
    if temp_c < 40:
        return 20
    elif temp_c < 60:
        return 40
    elif temp_c < 75:
        return 60
    elif temp_c < 85:
        return 80
    else:
        return 100

# ============================================================
# FLOP Governor
# ============================================================

class FlopGovernor:
    def __init__(self, target_flops_per_sec: float):
        self.target = float(target_flops_per_sec)
        self.bucket = float(target_flops_per_sec)
        self.last_refill = time.time()
        self.lock = threading.Lock()
        self.total_flops = 0.0
        self.last_second_flops = 0.0
        self.last_second_timestamp = time.time()

    def _refill(self):
        now = time.time()
        elapsed = now - self.last_refill
        if elapsed >= 1.0:
            self.bucket = self.target
            self.last_refill = now
            self.last_second_flops = 0.0
            self.last_second_timestamp = now

    def register(self, flops: float):
        flops = float(flops)
        with self.lock:
            self._refill()
            self.total_flops += flops
            self.last_second_flops += flops
            if self.bucket <= 0.0 and self.target > 0.0:
                deficit = abs(self.bucket)
                sleep_time = deficit / self.target
                if sleep_time > 0.0:
                    time.sleep(sleep_time)
                self._refill()
            self.bucket -= flops

    def run_op(self, op: Callable[[], torch.Tensor], flops_estimate: float):
        self.register(flops_estimate)
        return op()

    def set_target(self, new_target_flops_per_sec: float):
        with self.lock:
            self.target = float(new_target_flops_per_sec)
            self.bucket = self.target
            self.last_refill = time.time()
            self.last_second_flops = 0.0
            self.last_second_timestamp = self.last_refill
        print(f"[FLOP-GOV] New FLOP limit: {self.target:.3e} FLOP/s")

# ============================================================
# VRAM Stress Tester
# ============================================================

@dataclass
class VramStressConfig:
    duration_s: int = 120
    matrix_n: int = 4096
    cap_util: int = 90

class VramStressTester:
    def __init__(self, cfg: VramStressConfig, flop_gov: Optional[FlopGovernor] = None, gpu_index: int = 0):
        self.cfg = cfg
        self.flop_gov = flop_gov
        self.stop_flag = False
        self.gpu_index = gpu_index

    def _estimate_matmul_flops(self, n: int) -> float:
        return 2.0 * (n ** 3)

    def run(self):
        if not torch.cuda.is_available():
            print("[VRAM-STRESS] CUDA not available, skipping")
            return
        device = torch.device(f"cuda:{self.gpu_index}")
        n = self.cfg.matrix_n
        x = torch.randn(n, n, device=device)
        y = torch.randn(n, n, device=device)
        flops_per_matmul = self._estimate_matmul_flops(n)
        start = time.time()
        print(f"[VRAM-STRESS] Starting GPU {self.gpu_index}, N={n}, FLOPs/op={flops_per_matmul:.3e}")
        while not self.stop_flag and (time.time() - start) < self.cfg.duration_s:
            def op():
                return torch.matmul(x, y)
            if self.flop_gov is not None:
                _ = self.flop_gov.run_op(op, flops_per_matmul)
            else:
                _ = op()
            telem = get_gpu_telemetry(self.gpu_index)
            flops_s = self.flop_gov.last_second_flops if self.flop_gov else 0.0
            print(
                f"[VRAM-STRESS] GPU {self.gpu_index} t={int(time.time()-start)}s "
                f"temp={telem['temp']}C power={telem['power']:.1f}W "
                f"util={telem['gpu_util']}% FLOPs/s={flops_s:.3e}"
            )
            time.sleep(0.05)
        print("[VRAM-STRESS] Completed")

    def stop(self):
        self.stop_flag = True

# ============================================================
# Curve Visualizer / Power curve / Thermal prediction
# ============================================================

@dataclass
class CurveSample:
    timestamp: float
    temp: float
    power: float
    core_clock: float
    mem_clock: float
    gpu_util: float
    fan_speed: int
    vram_used_mb: float

class CurveVisualizer:
    def __init__(self):
        self.samples: Dict[int, List[CurveSample]] = {}

    def sample(self, gpu_index: int):
        telem = get_gpu_telemetry(gpu_index)
        s = CurveSample(
            timestamp=time.time(),
            temp=telem["temp"],
            power=telem["power"],
            core_clock=telem["core_clock"],
            mem_clock=telem["mem_clock"],
            gpu_util=telem["gpu_util"],
            fan_speed=telem["fan_speed"],
            vram_used_mb=telem["vram_used_mb"],
        )
        self.samples.setdefault(gpu_index, []).append(s)

    def export_json(self, path: str):
        data = {}
        for idx, samples in self.samples.items():
            data[idx] = [
                {
                    "t": s.timestamp,
                    "temp": s.temp,
                    "power": s.power,
                    "core_clock": s.core_clock,
                    "mem_clock": s.mem_clock,
                    "gpu_util": s.gpu_util,
                    "fan_speed": s.fan_speed,
                    "vram_used_mb": s.vram_used_mb,
                }
                for s in samples
            ]
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[CURVE] Exported samples for {len(self.samples)} GPU(s) to {path}")
        except Exception as e:
            print(f"[CURVE] Export failed: {e}")

    def get_recent_samples(self, gpu_index: int, window_s: float = 60.0) -> List[CurveSample]:
        now = time.time()
        return [s for s in self.samples.get(gpu_index, []) if now - s.timestamp <= window_s]

    def predict_next_temp(self, gpu_index: int, horizon_s: float = 10.0) -> float:
        samples = self.get_recent_samples(gpu_index, window_s=60.0)
        if len(samples) < 3:
            return samples[-1].temp if samples else 0.0
        xs = [s.timestamp for s in samples]
        ys = [s.temp for s in samples]
        t0 = xs[0]
        xs = [x - t0 for x in xs]
        n = len(xs)
        sum_x = sum(xs)
        sum_y = sum(ys)
        sum_xx = sum(x * x for x in xs)
        sum_xy = sum(x * y for x, y in zip(xs, ys))
        denom = (n * sum_xx - sum_x * sum_x)
        if denom == 0:
            return ys[-1]
        a = (n * sum_xy - sum_x * sum_y) / denom
        b = (sum_y - a * sum_x) / n
        future_t = xs[-1] + horizon_s
        return a * future_t + b

# ============================================================
# Factory Reset
# ============================================================

class FactoryReset:
    def __init__(self):
        self._default_power: Dict[int, float] = {}

    def snapshot_defaults(self):
        nvml_init()
        if not NVML_INIT:
            print("[FACTORY-RESET] NVML not initialized, snapshot skipped")
            return
        for idx in NVML_DEVICE_HANDLES.keys():
            self._default_power[idx] = get_default_power_limit_w(idx)
            print(f"[FACTORY-RESET] Snapshot GPU {idx} default power={self._default_power[idx]:.1f} W")

    def restore(self):
        for idx, p in self._default_power.items():
            print(f"[FACTORY-RESET] Restoring GPU {idx} power limit to {p:.1f} W")
            set_power_limit_w(idx, int(p))

# ============================================================
# Plugin system
# ============================================================

class GovernorPlugin:
    def on_telemetry(self, gpu_index: int, telem: Dict[str, Any], governor: "GpuGovernor"):
        pass

    def on_start(self, gpu_index: int, governor: "GpuGovernor"):
        pass

    def on_stop(self, gpu_index: int, governor: "GpuGovernor"):
        pass

PLUGINS: List[GovernorPlugin] = []

def load_plugins():
    plugins_dir = BASE_DIR / "plugins"
    if not plugins_dir.exists():
        print("[PLUGIN] No plugins directory, skipping")
        return
    for py_file in plugins_dir.glob("*.py"):
        mod_name = f"plugins.{py_file.stem}"
        try:
            mod = importlib.import_module(mod_name)
            if hasattr(mod, "create_plugin"):
                plugin = mod.create_plugin()
                if isinstance(plugin, GovernorPlugin):
                    PLUGINS.append(plugin)
                    print(f"[PLUGIN] Loaded plugin: {mod_name}")
        except Exception as e:
            print(f"[PLUGIN] Failed to load {mod_name}: {e}")

# ============================================================
# Governor core
# ============================================================

@dataclass
class GovernorConfig:
    power_limit_w: int
    temp_limit_c: int
    flop_limit: float
    poll_interval_s: float = 1.0

class GpuGovernor:
    def __init__(self, gpu_index: int = 0):
        self.gpu_index = gpu_index
        ai_power = int(get_default_power_limit_w(self.gpu_index))
        ai_temp_cap = int(get_thermal_cap_c(self.gpu_index))
        ai_flops = estimate_fp32_flops_per_sec(self.gpu_index)
        self.hc_cfg = GovernorConfig(
            power_limit_w=HC_POWER_LIMIT_W,
            temp_limit_c=HC_TEMP_LIMIT_C,
            flop_limit=HC_FLOP_LIMIT,
            poll_interval_s=1.0,
        )
        self.ai_cfg = GovernorConfig(
            power_limit_w=ai_power,
            temp_limit_c=ai_temp_cap - 5,
            flop_limit=ai_flops,
            poll_interval_s=1.0,
        )
        self.gaming_cfg = GovernorConfig(
            power_limit_w=GAMING_POWER_LIMIT_W,
            temp_limit_c=GAMING_TEMP_LIMIT_C,
            flop_limit=GAMING_FLOP_LIMIT,
            poll_interval_s=1.0,
        )
        self.cfg = GovernorConfig(
            power_limit_w=self.ai_cfg.power_limit_w,
            temp_limit_c=self.ai_cfg.temp_limit_c,
            flop_limit=self.ai_cfg.flop_limit,
            poll_interval_s=1.0,
        )
        self.profile_mode = "AI"
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.flop_gov = FlopGovernor(self.cfg.flop_limit)
        self.curve_vis = CurveVisualizer()
        self.factory_reset = FactoryReset()
        self.factory_reset.snapshot_defaults()
        self.vram_stress = VramStressTester(
            VramStressConfig(duration_s=120, matrix_n=4096, cap_util=90),
            flop_gov=self.flop_gov,
            gpu_index=self.gpu_index,
        )
        self.gui_lock = threading.Lock()
        self.gui_flop_slider_value = self.cfg.flop_limit
        self.pending_power = self.cfg.power_limit_w
        self.pending_flops = self.cfg.flop_limit
        self.pending_temp = self.cfg.temp_limit_c
        self.pending_fan_curve_enabled = True
        self.pending_core_offset = 0
        self.pending_mem_offset = 0
        self.pending_voltage_offset = 0
        self._load_persistent_settings()
        self.memory_leak_threshold_mb = 512
        self.memory_leak_window_s = 60.0

    def _load_persistent_settings(self):
        if not SETTINGS_PATH.is_file():
            print("[PERSIST] No settings file, using AI defaults")
            return
        try:
            with SETTINGS_PATH.open("r", encoding="utf-8") as f:
                data = json.load(f)
            gpu_data = data.get(str(self.gpu_index), {})
            mode = gpu_data.get("profile_mode", "AI")
            power = int(gpu_data.get("power_limit_w", self.cfg.power_limit_w))
            temp = int(gpu_data.get("temp_limit_c", self.cfg.temp_limit_c))
            flops = float(gpu_data.get("flop_limit", self.cfg.flop_limit))
            fan_enabled = bool(gpu_data.get("fan_curve_enabled", True))
            core_off = int(gpu_data.get("core_offset_mhz", 0))
            mem_off = int(gpu_data.get("mem_offset_mhz", 0))
            volt_off = int(gpu_data.get("volt_offset_mv", 0))
            if mode not in ("AI", "HC", "Gaming"):
                mode = "AI"
            self.profile_mode = mode
            self.cfg.power_limit_w = power
            self.cfg.temp_limit_c = temp
            self.cfg.flop_limit = flops
            self.flop_gov.set_target(self.cfg.flop_limit)
            self.pending_power = power
            self.pending_temp = temp
            self.pending_flops = flops
            self.pending_fan_curve_enabled = fan_enabled
            self.pending_core_offset = core_off
            self.pending_mem_offset = mem_off
            self.pending_voltage_offset = volt_off
            print(f"[PERSIST] Loaded GPU {self.gpu_index} settings: mode={mode} "
                  f"power={power}W temp={temp}C flops={flops:.3e} "
                  f"fan_curve={fan_enabled} core_off={core_off} mem_off={mem_off} volt_off={volt_off}")
        except Exception as e:
            print(f"[PERSIST] Load failed: {e}")

    def _save_persistent_settings(self):
        data = {}
        if SETTINGS_PATH.is_file():
            try:
                with SETTINGS_PATH.open("r", encoding="utf-8") as f:
                    data = json.load(f)
            except Exception:
                data = {}
        gpu_data = {
            "profile_mode": self.profile_mode,
            "power_limit_w": int(self.cfg.power_limit_w),
            "temp_limit_c": int(self.cfg.temp_limit_c),
            "flop_limit": float(self.cfg.flop_limit),
            "fan_curve_enabled": bool(self.pending_fan_curve_enabled),
            "core_offset_mhz": int(self.pending_core_offset),
            "mem_offset_mhz": int(self.pending_mem_offset),
            "volt_offset_mv": int(self.pending_voltage_offset),
        }
        data[str(self.gpu_index)] = gpu_data
        try:
            with SETTINGS_PATH.open("w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            print(f"[PERSIST] Saved GPU {self.gpu_index} settings to {SETTINGS_PATH}")
        except Exception as e:
            print(f"[PERSIST] Save failed: {e}")

    def set_profile_mode(self, mode: str):
        if mode not in ("AI", "HC", "Gaming"):
            return
        self.profile_mode = mode
        if mode == "AI":
            base = self.ai_cfg
        elif mode == "HC":
            base = self.hc_cfg
        else:
            base = self.gaming_cfg
        self.pending_power = base.power_limit_w
        self.pending_temp = base.temp_limit_c
        self.pending_flops = base.flop_limit
        print(f"[PROFILE] GPU {self.gpu_index} {mode} base pending: "
              f"power={self.pending_power}W temp={self.pending_temp}C flops={self.pending_flops:.3e}")

    def apply_ai_safe(self):
        self.cfg.power_limit_w = int(self.pending_power)
        self.cfg.temp_limit_c = int(self.pending_temp)
        self.cfg.flop_limit = float(self.pending_flops)
        self.flop_gov.set_target(self.cfg.flop_limit)
        self.gui_flop_slider_value = self.cfg.flop_limit
        set_power_limit_w(self.gpu_index, self.cfg.power_limit_w)
        nvapi_set_core_clock_offset(self.gpu_index, self.pending_core_offset)
        nvapi_set_mem_clock_offset(self.gpu_index, self.pending_mem_offset)
        nvapi_set_voltage_offset(self.gpu_index, self.pending_voltage_offset)
        self._save_persistent_settings()
        print(f"[AI-APPLY] GPU {self.gpu_index} Applied: power={self.cfg.power_limit_w}W "
              f"temp={self.cfg.temp_limit_c}C flops={self.cfg.flop_limit:.3e} "
              f"core_off={self.pending_core_offset} mem_off={self.pending_mem_offset} volt_off={self.pending_voltage_offset}")

    def gui_set_pending_flops(self, new_flops: float):
        with self.gui_lock:
            self.pending_flops = float(new_flops)

    def gui_get_pending_flops(self) -> float:
        with self.gui_lock:
            return self.pending_flops

    def gui_set_pending_power(self, new_power_w: int):
        self.pending_power = int(new_power_w)

    def gui_set_pending_temp(self, new_temp_c: int):
        self.pending_temp = int(new_temp_c)

    def gui_set_fan_curve_enabled(self, enabled: bool):
        self.pending_fan_curve_enabled = bool(enabled)

    def gui_set_core_offset(self, offset_mhz: int):
        self.pending_core_offset = int(offset_mhz)

    def gui_set_mem_offset(self, offset_mhz: int):
        self.pending_mem_offset = int(offset_mhz)

    def gui_set_voltage_offset(self, offset_mv: int):
        self.pending_voltage_offset = int(offset_mv)

    def _detect_memory_leak(self):
        samples = self.curve_vis.get_recent_samples(self.gpu_index, window_s=self.memory_leak_window_s)
        if len(samples) < 5:
            return
        vram_values = [s.vram_used_mb for s in samples]
        if max(vram_values) - min(vram_values) > self.memory_leak_threshold_mb:
            print(f"[LEAK] Possible VRAM leak on GPU {self.gpu_index}: "
                  f"{min(vram_values):.1f} -> {max(vram_values):.1f} MB in {self.memory_leak_window_s}s")

    def _ai_auto_tune(self, telem: Dict[str, Any]):
        temp = telem["temp"]
        util = telem["gpu_util"]
        power = telem["power"]
        predicted_temp = self.curve_vis.predict_next_temp(self.gpu_index, horizon_s=10.0)
        if predicted_temp > self.cfg.temp_limit_c + 3:
            new_power = max(150, self.pending_power - 10)
            print(f"[AI-TUNE] Predicted temp {predicted_temp:.1f}C > limit, reducing power to {new_power}W")
            self.pending_power = new_power
        elif util < 40 and power < self.pending_power * 0.7:
            new_power = min(self.pending_power + 10, 450)
            print(f"[AI-TUNE] Low util {util}% and low power {power:.1f}W, gently increasing power to {new_power}W")
            self.pending_power = new_power

    def _safe_tune_loop(self):
        telem = get_gpu_telemetry(self.gpu_index)
        print(
            f"[GOVERNOR] Starting GPU {self.gpu_index} ({telem['name']}) "
            f"profile={self.profile_mode} "
            f"power_limit={self.cfg.power_limit_w} W "
            f"temp_limit={self.cfg.temp_limit_c} C "
            f"default FLOPs={self.cfg.flop_limit:.3e}"
        )
        set_power_limit_w(self.gpu_index, self.cfg.power_limit_w)
        start = time.time()
        for plugin in PLUGINS:
            try:
                plugin.on_start(self.gpu_index, self)
            except Exception as e:
                print(f"[PLUGIN] on_start error: {e}")
        while self.running:
            telem = get_gpu_telemetry(self.gpu_index)
            self.curve_vis.sample(self.gpu_index)
            temp = telem["temp"]
            power = telem["power"]
            util = telem["gpu_util"]
            fan_speed = telem["fan_speed"]
            flops_s = self.flop_gov.last_second_flops
            logging.info(
                f"GPU {self.gpu_index} t={int(time.time()-start)}s "
                f"temp={temp}C power={power:.1f}W util={util}% fan={fan_speed}% "
                f"FLOPs/s={flops_s:.3e} target={self.cfg.flop_limit:.3e} profile={self.profile_mode}"
            )
            log_telemetry_csv({
                "timestamp": time.time(),
                "gpu_index": self.gpu_index,
                "name": telem["name"],
                "temp": temp,
                "power": power,
                "core_clock": telem["core_clock"],
                "mem_clock": telem["mem_clock"],
                "gpu_util": util,
                "mem_util": telem["mem_util"],
                "fan_speed": fan_speed,
                "flops_s": flops_s,
                "flop_limit": self.cfg.flop_limit,
                "profile_mode": self.profile_mode,
                "vram_used_mb": telem["vram_used_mb"],
                "vram_total_mb": telem["vram_total_mb"],
            })
            self._detect_memory_leak()
            self._ai_auto_tune(telem)
            if temp > self.cfg.temp_limit_c:
                print(f"[GOVERNOR] GPU {self.gpu_index} Thermal limit exceeded, backing off power")
                new_limit = max(150, self.cfg.power_limit_w - 20)
                self.cfg.power_limit_w = new_limit
                set_power_limit_w(self.gpu_index, new_limit)
                self._save_persistent_settings()
            if self.pending_fan_curve_enabled:
                fan_target = compute_fan_target(temp)
                set_fan_speed_percent(self.gpu_index, fan_target)
            for plugin in PLUGINS:
                try:
                    plugin.on_telemetry(self.gpu_index, telem, self)
                except Exception as e:
                    print(f"[PLUGIN] on_telemetry error: {e}")
            time.sleep(self.cfg.poll_interval_s)
        print(f"[GOVERNOR] GPU {self.gpu_index} Loop exiting")
        for plugin in PLUGINS:
            try:
                plugin.on_stop(self.gpu_index, self)
            except Exception as e:
                print(f"[PLUGIN] on_stop error: {e}")

    def start(self):
        if self.running:
            print(f"[GOVERNOR] GPU {self.gpu_index} Already running")
            return
        self.running = True
        self.thread = threading.Thread(target=self._safe_tune_loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False
        if self.thread is not None:
            self.thread.join(timeout=5.0)
        self.factory_reset.restore()
        print(f"[GOVERNOR] GPU {self.gpu_index} Stopped, factory defaults restored")

    def run_vram_stress(self):
        self.vram_stress.run()

    def export_curve(self, path: str):
        self.curve_vis.export_json(path)

# ============================================================
# GUI — multi-GPU, full dashboard
# ============================================================

class ColorSlider(QtWidgets.QSlider):
    def __init__(self, orientation, parent=None):
        super().__init__(orientation, parent)
        self.overdrive_threshold = 40

    def set_overdrive_threshold(self, v: int):
        self.overdrive_threshold = v

    def update_color(self):
        v = self.value()
        min_v = self.minimum()
        max_v = self.maximum()
        ratio = (v - min_v) / max(1, (max_v - min_v))
        if v >= self.overdrive_threshold:
            color = QtGui.QColor(255, 0, 0)
        else:
            g = int(255 * ratio)
            r = int(255 * (1 - ratio))
            color = QtGui.QColor(r, g, 0)
        style = f"""
        QSlider::groove:horizontal {{
            height: 8px;
            background: #ffffff;
        }}
        QSlider::handle:horizontal {{
            background: {color.name()};
            border: 1px solid #444;
            width: 18px;
            margin: -5px 0;
            border-radius: 4px;
        }}
        """
        self.setStyleSheet(style)

    def setValue(self, v: int):
        super().setValue(v)
        self.update_color()

class GovernorGUI(QtWidgets.QWidget):
    def __init__(self, governors: Dict[int, GpuGovernor]):
        super().__init__()
        self.govs = governors
        self.current_index = list(governors.keys())[0]
        self.current_gov = self.govs[self.current_index]
        self._build_ui()
        self._start_telemetry_timer()
        if HAS_QTCHARTS:
            self._init_charts()
        else:
            self.chart_start_time = None

    def _build_ui(self):
        telem = get_gpu_telemetry(self.current_index)
        self.setWindowTitle("GPU Governor v7.0 — Multi-GPU AI/HC/Gaming")
        main_layout = QtWidgets.QVBoxLayout()
        gpu_select_layout = QtWidgets.QHBoxLayout()
        gpu_select_layout.addWidget(QtWidgets.QLabel("Active GPU:"))
        self.combo_gpu = QtWidgets.QComboBox()
        nvml_init()
        count = len(NVML_DEVICE_HANDLES)
        if count == 0:
            self.combo_gpu.addItem("GPU 0 (Unknown)", 0)
        else:
            for idx in NVML_DEVICE_HANDLES.keys():
                t = get_gpu_telemetry(idx)
                self.combo_gpu.addItem(f"GPU {idx} — {t['name']}", idx)
        self.combo_gpu.currentIndexChanged.connect(self._on_gpu_changed)
        gpu_select_layout.addWidget(self.combo_gpu)
        main_layout.addLayout(gpu_select_layout)
        self.lbl_gpu = QtWidgets.QLabel(f"GPU {self.current_index}: {telem['name']}")
        main_layout.addWidget(self.lbl_gpu)
        gauges_group = QtWidgets.QGroupBox("Live Telemetry Gauges")
        gauges_layout = QtWidgets.QHBoxLayout()
        self.gauge_temp = QtWidgets.QProgressBar()
        self.gauge_temp.setRange(0, 100)
        self.gauge_temp.setFormat("Temp: %v °C")
        self.gauge_temp.setTextVisible(True)
        self.gauge_power = QtWidgets.QProgressBar()
        self.gauge_power.setRange(0, 500)
        self.gauge_power.setFormat("Power: %v W")
        self.gauge_power.setTextVisible(True)
        self.gauge_util = QtWidgets.QProgressBar()
        self.gauge_util.setRange(0, 100)
        self.gauge_util.setFormat("GPU Util: %v %")
        self.gauge_util.setTextVisible(True)
        self.gauge_flops = QtWidgets.QProgressBar()
        self.gauge_flops.setRange(0, 100)
        self.gauge_flops.setFormat("FLOPs: %v %")
        self.gauge_flops.setTextVisible(True)
        self.gauge_fan = QtWidgets.QProgressBar()
        self.gauge_fan.setRange(0, 100)
        self.gauge_fan.setFormat("Fan: %v %")
        self.gauge_fan.setTextVisible(True)
        self.gauge_vram = QtWidgets.QProgressBar()
        self.gauge_vram.setRange(0, 100)
        self.gauge_vram.setFormat("VRAM: %v %")
        self.gauge_vram.setTextVisible(True)
        gauges_layout.addWidget(self.gauge_temp)
        gauges_layout.addWidget(self.gauge_power)
        gauges_layout.addWidget(self.gauge_util)
        gauges_layout.addWidget(self.gauge_flops)
        gauges_layout.addWidget(self.gauge_fan)
        gauges_layout.addWidget(self.gauge_vram)
        gauges_group.setLayout(gauges_layout)
        main_layout.addWidget(gauges_group)
        self.lbl_temp = QtWidgets.QLabel("Temp: - C")
        self.lbl_power = QtWidgets.QLabel("Power: - W")
        self.lbl_util = QtWidgets.QLabel("Util: - %")
        self.lbl_flops = QtWidgets.QLabel("FLOPs/s: -")
        self.lbl_fan = QtWidgets.QLabel("Fan: - %")
        self.lbl_vram = QtWidgets.QLabel("VRAM: - / - MB")
        self.lbl_pred_temp = QtWidgets.QLabel("Predicted Temp (+10s): - C")
        main_layout.addWidget(self.lbl_temp)
        main_layout.addWidget(self.lbl_power)
        main_layout.addWidget(self.lbl_util)
        main_layout.addWidget(self.lbl_flops)
        main_layout.addWidget(self.lbl_fan)
        main_layout.addWidget(self.lbl_vram)
        main_layout.addWidget(self.lbl_pred_temp)
        profile_group = QtWidgets.QGroupBox("Profile (view only until AI Safe Apply)")
        profile_layout = QtWidgets.QHBoxLayout()
        self.radio_ai = QtWidgets.QRadioButton("AI (GPU-derived)")
        self.radio_hc = QtWidgets.QRadioButton("Hardcoded")
        self.radio_gaming = QtWidgets.QRadioButton("Gaming")
        if self.current_gov.profile_mode == "HC":
            self.radio_hc.setChecked(True)
        elif self.current_gov.profile_mode == "Gaming":
            self.radio_gaming.setChecked(True)
        else:
            self.radio_ai.setChecked(True)
        self.radio_ai.toggled.connect(self._on_profile_changed)
        self.radio_hc.toggled.connect(self._on_profile_changed)
        self.radio_gaming.toggled.connect(self._on_profile_changed)
        profile_layout.addWidget(self.radio_ai)
        profile_layout.addWidget(self.radio_hc)
        profile_layout.addWidget(self.radio_gaming)
        profile_group.setLayout(profile_layout)
        main_layout.addWidget(profile_group)
        main_layout.addWidget(QtWidgets.QLabel(
            "Pending settings (will NOT change GPU until 'AI Safe Apply' is pressed):"
        ))
        self.spin_pending_power = QtWidgets.QSpinBox()
        self.spin_pending_power.setRange(150, 450)
        self.spin_pending_power.setValue(self.current_gov.pending_power)
        self.spin_pending_power.valueChanged.connect(self._on_pending_power_changed)
        main_layout.addWidget(QtWidgets.QLabel("Pending Power limit (W)"))
        main_layout.addWidget(self.spin_pending_power)
        self.spin_pending_temp = QtWidgets.QSpinBox()
        self.spin_pending_temp.setRange(60, 95)
        self.spin_pending_temp.setValue(self.current_gov.pending_temp)
        self.spin_pending_temp.valueChanged.connect(self._on_pending_temp_changed)
        main_layout.addWidget(QtWidgets.QLabel("Pending Temp limit (C)"))
        main_layout.addWidget(self.spin_pending_temp)
        self.slider_flops = ColorSlider(QtCore.Qt.Orientation.Horizontal)
        self.slider_flops.setMinimum(5)
        self.slider_flops.setMaximum(50)
        self.slider_flops.set_overdrive_threshold(40)
        step = max(5, int(self.current_gov.pending_flops / 1e11))
        self.slider_flops.setValue(step)
        self.slider_flops.valueChanged.connect(self._on_pending_flops_changed)
        main_layout.addWidget(QtWidgets.QLabel(
            "Pending FLOP limit (x1e11 FLOP/s) — white→green→red (red = overdrive)"
        ))
        main_layout.addWidget(self.slider_flops)
        self.chk_fan_curve = QtWidgets.QCheckBox("Enable automatic fan curve (safe ramp)")
        self.chk_fan_curve.setChecked(self.current_gov.pending_fan_curve_enabled)
        self.chk_fan_curve.toggled.connect(self._on_fan_curve_toggled)
        main_layout.addWidget(self.chk_fan_curve)
        offsets_group = QtWidgets.QGroupBox("Clock / Voltage offsets (NVAPI-backed)")
        offsets_layout = QtWidgets.QFormLayout()
        self.spin_core_offset = QtWidgets.QSpinBox()
        self.spin_core_offset.setRange(-300, 300)
        self.spin_core_offset.setValue(self.current_gov.pending_core_offset)
        self.spin_core_offset.valueChanged.connect(self._on_core_offset_changed)
        self.spin_mem_offset = QtWidgets.QSpinBox()
        self.spin_mem_offset.setRange(-500, 1000)
        self.spin_mem_offset.setValue(self.current_gov.pending_mem_offset)
        self.spin_mem_offset.valueChanged.connect(self._on_mem_offset_changed)
        self.spin_volt_offset = QtWidgets.QSpinBox()
        self.spin_volt_offset.setRange(-100, 100)
        self.spin_volt_offset.setValue(self.current_gov.pending_voltage_offset)
        self.spin_volt_offset.valueChanged.connect(self._on_volt_offset_changed)
        offsets_layout.addRow("Core clock offset (MHz)", self.spin_core_offset)
        offsets_layout.addRow("Memory clock offset (MHz)", self.spin_mem_offset)
        offsets_layout.addRow("Voltage offset (mV)", self.spin_volt_offset)
        offsets_group.setLayout(offsets_layout)
        main_layout.addWidget(offsets_group)
        self.btn_ai_apply = QtWidgets.QPushButton("AI Safe Apply (commit pending settings)")
        self.btn_ai_apply.clicked.connect(self._on_ai_apply)
        main_layout.addWidget(self.btn_ai_apply)
        btn_start = QtWidgets.QPushButton("Start Governor")
        btn_stop = QtWidgets.QPushButton("Stop Governor")
        btn_stress = QtWidgets.QPushButton("Run VRAM Stress (current GPU)")
        btn_export = QtWidgets.QPushButton("Export Curve JSON (all GPUs)")
        btn_reset = QtWidgets.QPushButton("Factory Reset (all GPUs)")
        btn_start.clicked.connect(self._on_start)
        btn_stop.clicked.connect(self._on_stop)
        btn_stress.clicked.connect(self._on_stress)
        btn_export.clicked.connect(self._on_export)
        btn_reset.clicked.connect(self._on_reset)
        main_layout.addWidget(btn_start)
        main_layout.addWidget(btn_stop)
        main_layout.addWidget(btn_stress)
        main_layout.addWidget(btn_export)
        main_layout.addWidget(btn_reset)
        if HAS_QTCHARTS:
            charts_group = QtWidgets.QGroupBox("Dashboard — Temp / Power / Util / VRAM / Power Curve")
            charts_layout = QtWidgets.QHBoxLayout()
            self.chart_view_temp = QChartView()
            self.chart_view_power = QChartView()
            self.chart_view_util = QChartView()
            self.chart_view_vram = QChartView()
            charts_layout.addWidget(self.chart_view_temp)
            charts_layout.addWidget(self.chart_view_power)
            charts_layout.addWidget(self.chart_view_util)
            charts_layout.addWidget(self.chart_view_vram)
            charts_group.setLayout(charts_layout)
            main_layout.addWidget(charts_group)
        else:
            self.chart_view_temp = None
            self.chart_view_power = None
            self.chart_view_util = None
            self.chart_view_vram = None
        self.setLayout(main_layout)
        self.resize(1100, 800)

    def _init_charts(self):
        self.chart_temp = QChart()
        self.series_temp = QLineSeries()
        self.chart_temp.addSeries(self.series_temp)
        self.chart_temp.createDefaultAxes()
        self.chart_temp.setTitle("Temperature (C)")
        self.chart_view_temp.setChart(self.chart_temp)
        self.chart_power = QChart()
        self.series_power = QLineSeries()
        self.chart_power.addSeries(self.series_power)
        self.chart_power.createDefaultAxes()
        self.chart_power.setTitle("Power (W)")
        self.chart_view_power.setChart(self.chart_power)
        self.chart_util = QChart()
        self.series_util = QLineSeries()
        self.chart_util.addSeries(self.series_util)
        self.chart_util.createDefaultAxes()
        self.chart_util.setTitle("GPU Util (%)")
        self.chart_view_util.setChart(self.chart_util)
        self.chart_vram = QChart()
        self.series_vram = QLineSeries()
        self.chart_vram.addSeries(self.series_vram)
        self.chart_vram.createDefaultAxes()
        self.chart_vram.setTitle("VRAM Used (MB)")
        self.chart_view_vram.setChart(self.chart_vram)
        self.chart_start_time = time.time()

    def _start_telemetry_timer(self):
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self._update_telemetry)
        self.timer.start(1000)

    def _on_gpu_changed(self, idx):
        gpu_index = self.combo_gpu.itemData(idx)
        if gpu_index is None:
            gpu_index = 0
        self.current_index = gpu_index
        self.current_gov = self.govs[self.current_index]
        telem = get_gpu_telemetry(self.current_index)
        self.lbl_gpu.setText(f"GPU {self.current_index}: {telem['name']}")
        self.spin_pending_power.setValue(self.current_gov.pending_power)
        self.spin_pending_temp.setValue(self.current_gov.pending_temp)
        step = max(5, int(self.current_gov.pending_flops / 1e11))
        self.slider_flops.setValue(step)
        self.chk_fan_curve.setChecked(self.current_gov.pending_fan_curve_enabled)
        self.spin_core_offset.setValue(self.current_gov.pending_core_offset)
        self.spin_mem_offset.setValue(self.current_gov.pending_mem_offset)
        self.spin_volt_offset.setValue(self.current_gov.pending_voltage_offset)
        if self.current_gov.profile_mode == "HC":
            self.radio_hc.setChecked(True)
        elif self.current_gov.profile_mode == "Gaming":
            self.radio_gaming.setChecked(True)
        else:
            self.radio_ai.setChecked(True)

    def _on_profile_changed(self):
        if self.radio_ai.isChecked():
            self.current_gov.set_profile_mode("AI")
        elif self.radio_hc.isChecked():
            self.current_gov.set_profile_mode("HC")
        elif self.radio_gaming.isChecked():
            self.current_gov.set_profile_mode("Gaming")
        self.spin_pending_power.setValue(self.current_gov.pending_power)
        self.spin_pending_temp.setValue(self.current_gov.pending_temp)
        step = max(5, int(self.current_gov.pending_flops / 1e11))
        self.slider_flops.setValue(step)

    def _on_pending_power_changed(self, value):
        self.current_gov.gui_set_pending_power(value)

    def _on_pending_temp_changed(self, value):
        self.current_gov.gui_set_pending_temp(value)

    def _on_pending_flops_changed(self, value):
        target = value * 1e11
        self.current_gov.gui_set_pending_flops(target)
        self.slider_flops.update_color()

    def _on_fan_curve_toggled(self, checked):
        self.current_gov.gui_set_fan_curve_enabled(checked)

    def _on_core_offset_changed(self, value):
        self.current_gov.gui_set_core_offset(value)

    def _on_mem_offset_changed(self, value):
        self.current_gov.gui_set_mem_offset(value)

    def _on_volt_offset_changed(self, value):
        self.current_gov.gui_set_voltage_offset(value)

    def _on_ai_apply(self):
        self.current_gov.apply_ai_safe()

    def _on_start(self):
        self.current_gov.start()

    def _on_stop(self):
        self.current_gov.stop()

    def _on_stress(self):
        threading.Thread(target=self.current_gov.run_vram_stress, daemon=True).start()

    def _on_export(self):
        any_gov = next(iter(self.govs.values()))
        any_gov.export_curve(str(BASE_DIR / "curve_v7_0.json"))

    def _on_reset(self):
        for g in self.govs.values():
            g.factory_reset.restore()

    def _update_telemetry(self):
        telem = get_gpu_telemetry(self.current_index)
        self.lbl_temp.setText(f"Temp: {telem['temp']} C")
        self.lbl_power.setText(f"Power: {telem['power']:.1f} W")
        self.lbl_util.setText(f"Util: {telem['gpu_util']} %")
        self.lbl_flops.setText(f"FLOPs/s: {self.current_gov.flop_gov.last_second_flops:.3e}")
        self.lbl_fan.setText(f"Fan: {telem['fan_speed']} %")
        self.lbl_vram.setText(f"VRAM: {telem['vram_used_mb']:.1f} / {telem['vram_total_mb']:.1f} MB")
        pred_temp = self.current_gov.curve_vis.predict_next_temp(self.current_index, horizon_s=10.0)
        self.lbl_pred_temp.setText(f"Predicted Temp (+10s): {pred_temp:.1f} C")
        self.gauge_temp.setValue(int(telem['temp']))
        self.gauge_power.setValue(int(telem['power']))
        self.gauge_util.setValue(int(telem['gpu_util']))
        self.gauge_fan.setValue(int(telem['fan_speed']))
        if telem['vram_total_mb'] > 0:
            vram_ratio = min(1.0, telem['vram_used_mb'] / telem['vram_total_mb'])
        else:
            vram_ratio = 0.0
        self.gauge_vram.setValue(int(vram_ratio * 100))
        limit = max(1e9, self.current_gov.cfg.flop_limit)
        ratio = min(1.0, self.current_gov.flop_gov.last_second_flops / limit)
        self.gauge_flops.setValue(int(ratio * 100))
        if HAS_QTCHARTS and self.chart_start_time is not None:
            t = time.time() - self.chart_start_time
            self.series_temp.append(t, telem['temp'])
            self.series_power.append(t, telem['power'])
            self.series_util.append(t, telem['gpu_util'])
            self.series_vram.append(t, telem['vram_used_mb'])
            for series in (self.series_temp, self.series_power, self.series_util, self.series_vram):
                if series.count() > 300:
                    series.removePoints(0, series.count() - 300)

# ============================================================
# Entry point
# ============================================================

def handle_sigint(sig, frame):
    print("\n[MAIN] SIGINT received, shutting down")
    QtWidgets.QApplication.quit()

def main():
    signal.signal(signal.SIGINT, handle_sigint)
    nvml_init()
    load_plugins()
    if len(NVML_DEVICE_HANDLES) == 0:
        print("[MAIN] No GPUs detected by NVML, creating single governor for index 0")
        govs = {0: GpuGovernor(0)}
    else:
        govs = {idx: GpuGovernor(idx) for idx in NVML_DEVICE_HANDLES.keys()}
    app = QtWidgets.QApplication(sys.argv)
    gui = GovernorGUI(govs)
    gui.show()
    ret = app.exec()
    for g in govs.values():
        g.stop()
    nvml_shutdown()
    sys.exit(ret)

if __name__ == "__main__":
    main()
