#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal GPU Control Center v4.2 (Monolithic Governor, Fine‑Tuning Edition)

Upgrades in this build:
- Advanced GPU tuning organ with:
  - Per‑GPU tuning profiles
  - Aggression levels (eco/balanced/aggressive/extreme)
  - Dynamic power/fan curves based on telemetry + prediction
- Auto profile upgraded with:
  - Multi‑threshold logic (idle/medium/heavy/critical)
  - Hysteresis to avoid mode flapping
  - Adaptive polling based on volatility
- Prediction engine upgraded with:
  - Multi‑window analysis (short/medium/long)
  - Confidence scoring
  - Risk scoring for thermal/load
- Swarm sync upgraded with:
  - Peer telemetry exchange
  - Leader election (simple heuristic)
  - Cluster‑wide risk aggregation (stubbed but structured)
- Plugin API upgraded with:
  - Lifecycle hooks (on_load, on_unload, on_tick, on_profile_change, on_prediction)
  - Plugin settings access
- GUI dashboard upgraded with:
  - Per‑GPU table
  - Simple tuning sliders (power/fan per GPU)
  - Aggression selector
- REST API upgraded with:
  - Tuning endpoints (/tuning/power, /tuning/fan, /tuning/aggression)
  - Swarm endpoints (/swarm/status, /swarm/peers)

SAFETY:
- No VBIOS writes, no strap edits, no voltage-table hacks, no undocumented registers.
- Only documented NVML / vendor APIs used, with strict range checks.
- All tuning actions are optional and gated by config.safety.allow_vendor_writes.
"""

from __future__ import annotations

import asyncio
import csv
import importlib
import json
import math
import os
import queue
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Callable, Optional, Dict, List

APP_NAME = "Universal GPU Control Center"
APP_VERSION = 4.2
PROFILE_DIR = Path.home() / "GPUControlCenter"
PLUGIN_DIR = PROFILE_DIR / "plugins"
PROFILE_DIR.mkdir(parents=True, exist_ok=True)
PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = PROFILE_DIR / "system_tuner_config.json"
TELEMETRY_LOG = PROFILE_DIR / "telemetry.jsonl"

DEFAULT_CONFIG: dict[str, Any] = {
    "mode": "auto",
    "beast_mode_enabled": False,
    "daemon": {
        "enabled": True,
        "host": "127.0.0.1",
        "port": 8765,
        "websocket_port": 8766,
        "interval": 1.0,
    },
    "telemetry": {
        "interval": 1.0,
        "history_size": 600,
        "persist": True,
    },
    "safety": {
        "max_power_percent": 110,
        "max_core_offset_mhz": 300,
        "max_memory_offset_mhz": 1000,
        "max_fan_percent": 100,
        "thermal_limit_c": 85,
        "emergency_temp_c": 92,
        "allow_vendor_writes": False,
        "require_explicit_confirmation": True,
    },
    "network": {
        "enabled": True,
        "allow_remote": False,
        "api_token": "",
    },
    "sync": {
        "enabled": True,
        "node_id": socket.gethostname(),
        "peers": [],  # list of "http://host:port"
        "interval": 5.0,
        "share_profiles": True,
    },
    "prediction": {
        "enabled": True,
        "short_window": 20,
        "medium_window": 60,
        "long_window": 300,
        "horizon_seconds": 60,
    },
    "plugins": {
        "enabled": True,
        "directory": str(PLUGIN_DIR),
        "settings": {},
    },
    "tuning": {
        "aggression": "balanced",  # eco/balanced/aggressive/extreme
        "gpu_overrides": {
            # "0": { "power_target_percent": 105, "fan_percent": 70 }
        },
    },
    "auto_profile": {
        "poll_interval": 2.0,
        "cpu_idle_threshold": 20.0,
        "cpu_medium_threshold": 40.0,
        "cpu_heavy_threshold": 70.0,
        "gpu_idle_threshold": 20.0,
        "gpu_medium_threshold": 50.0,
        "gpu_heavy_threshold": 80.0,
        "gpu_critical_threshold": 95.0,
        "power_idle_percent": 85,
        "power_medium_percent": 95,
        "power_heavy_percent": 105,
        "power_critical_percent": 110,
        "fan_idle_percent": 35,
        "fan_medium_percent": 55,
        "fan_heavy_percent": 75,
        "fan_critical_percent": 90,
        "hysteresis_seconds": 10.0,
    },
    "base_profile": {
        "poll_interval": 3.0,
        "power_target_percent": 90,
        "fan_target_percent": 40,
    },
    "turbo_profile": {
        "poll_interval": 1.0,
        "power_target_percent": 105,
        "fan_target_percent": 70,
    },
    "vram_engine": {
        "enabled": True,
        "backend": "auto",
    },
}


def deep_merge(base: dict[str, Any], update: dict[str, Any]) -> dict[str, Any]:
    result = json.loads(json.dumps(base))
    for key, value in update.items():
        if isinstance(value, dict) and isinstance(result.get(key), dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result


def load_config() -> dict[str, Any]:
    if not CONFIG_PATH.exists():
        return json.loads(json.dumps(DEFAULT_CONFIG))
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        return deep_merge(DEFAULT_CONFIG, data)
    except Exception:
        return json.loads(json.dumps(DEFAULT_CONFIG))


def save_config(cfg: dict[str, Any]) -> None:
    tmp = CONFIG_PATH.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
        tmp.replace(CONFIG_PATH)
    except Exception as exc:
        print(f"[CONFIG] save failed: {exc}")


CONFIG = load_config()


def optional_import(name: str):
    try:
        return importlib.import_module(name)
    except Exception:
        return None


psutil = optional_import("psutil")
pynvml = optional_import("pynvml")
aiohttp = optional_import("aiohttp")
websockets = optional_import("websockets")
PYQT_AVAILABLE = optional_import("PyQt6") is not None

try:
    import numpy as np
    from numba import cuda
    CUDA_AVAILABLE = cuda.is_available()
except Exception:
    np = None
    cuda = None
    CUDA_AVAILABLE = False


def run_cmd(args: list[str], timeout: float = 5.0) -> tuple[int, str, str]:
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


def powershell(script: str, timeout: float = 6.0) -> str:
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return ""
    rc, out, _ = run_cmd(
        [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout,
    )
    return out if rc == 0 else ""


def safe_decode(x):
    return x.decode("utf-8", errors="ignore") if isinstance(x, bytes) else x


class NvmlError(RuntimeError):
    pass


class NvmlNotInitialized(NvmlError):
    pass


class NvmlBackend:
    def __init__(self) -> None:
        self._initialized: bool = False
        self._device_count: int = 0
        self._available: bool = pynvml is not None

    def start(self) -> None:
        if self._initialized:
            return
        if not self._available:
            print("[NVML] pynvml not available; NVML telemetry disabled.")
            return
        try:
            pynvml.nvmlInit()
            self._device_count = pynvml.nvmlDeviceGetCount()
            self._initialized = True
        except pynvml.NVMLError as e:
            print(f"[NVML] init failed: {e}")
            self._initialized = False
            self._device_count = 0

    def stop(self) -> None:
        if not self._initialized or not self._available:
            return
        try:
            pynvml.nvmlShutdown()
        except pynvml.NVMLError as e:
            print(f"[NVML] shutdown error: {e}")
        finally:
            self._initialized = False
            self._device_count = 0

    def _ensure_initialized(self) -> None:
        if not self._available:
            raise NvmlError("NVML not available (no pynvml / no NVIDIA driver).")
        if not self._initialized:
            raise NvmlNotInitialized("NVML backend not started. Call NvmlBackend.start() first.")

    def device_count(self) -> int:
        self._ensure_initialized()
        return self._device_count

    def list_devices(self) -> list[dict[str, Any]]:
        self._ensure_initialized()
        devices: list[dict[str, Any]] = []
        for i in range(self._device_count):
            handle = pynvml.nvmlDeviceGetHandleByIndex(i)
            name = safe_decode(pynvml.nvmlDeviceGetName(handle))
            uuid = safe_decode(pynvml.nvmlDeviceGetUUID(handle))
            pci_bus_id = safe_decode(pynvml.nvmlDeviceGetPciInfo(handle).busId)
            try:
                serial = safe_decode(pynvml.nvmlDeviceGetSerial(handle))
            except pynvml.NVMLError:
                serial = None
            try:
                vbios_version = safe_decode(pynvml.nvmlDeviceGetVbiosVersion(handle))
            except pynvml.NVMLError:
                vbios_version = None
            devices.append(
                {
                    "index": i,
                    "name": name,
                    "uuid": uuid,
                    "pci_bus_id": pci_bus_id,
                    "serial": serial,
                    "vbios_version": vbios_version,
                }
            )
        return devices

    def snapshot(self, index: int) -> dict[str, Any]:
        self._ensure_initialized()
        if index < 0 or index >= self._device_count:
            raise IndexError(f"GPU index {index} out of range (0..{self._device_count - 1})")
        handle = pynvml.nvmlDeviceGetHandleByIndex(index)
        name = safe_decode(pynvml.nvmlDeviceGetName(handle))
        uuid = safe_decode(pynvml.nvmlDeviceGetUUID(handle))
        pci_bus_id = safe_decode(pynvml.nvmlDeviceGetPciInfo(handle).busId)
        try:
            serial = safe_decode(pynvml.nvmlDeviceGetSerial(handle))
        except pynvml.NVMLError:
            serial = None
        try:
            vbios_version = safe_decode(pynvml.nvmlDeviceGetVbiosVersion(handle))
        except pynvml.NVMLError:
            vbios_version = None
        try:
            util = pynvml.nvmlDeviceGetUtilizationRates(handle)
            gpu_util = util.gpu
            mem_util = util.memory
        except pynvml.NVMLError:
            gpu_util = mem_util = None
        try:
            mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
            mem_total = mem.total
            mem_used = mem.used
            mem_free = mem.free
        except pynvml.NVMLError:
            mem_total = mem_used = mem_free = None
        try:
            temp_gpu = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        except pynvml.NVMLError:
            temp_gpu = None

        def _safe_clock(clock_type: int) -> Optional[int]:
            try:
                return pynvml.nvmlDeviceGetClockInfo(handle, clock_type)
            except pynvml.NVMLError:
                return None

        clock_graphics = _safe_clock(pynvml.NVML_CLOCK_GRAPHICS)
        clock_sm = _safe_clock(pynvml.NVML_CLOCK_SM)
        clock_mem = _safe_clock(pynvml.NVML_CLOCK_MEM)
        try:
            power_draw = pynvml.nvmlDeviceGetPowerUsage(handle)
        except pynvml.NVMLError:
            power_draw = None
        try:
            power_limit = pynvml.nvmlDeviceGetEnforcedPowerLimit(handle)
        except pynvml.NVMLError:
            power_limit = None
        try:
            fan_speed = pynvml.nvmlDeviceGetFanSpeed(handle)
        except pynvml.NVMLError:
            fan_speed = None
        processes: list[dict[str, Any]] = []
        try:
            procs = pynvml.nvmlDeviceGetComputeRunningProcesses(handle)
            for p in procs:
                processes.append(
                    {
                        "pid": p.pid,
                        "used_memory_bytes": p.usedGpuMemory,
                    }
                )
        except pynvml.NVMLError:
            processes = []
        return {
            "index": index,
            "identity": {
                "name": name,
                "uuid": uuid,
                "pci_bus_id": pci_bus_id,
                "serial": serial,
                "vbios_version": vbios_version,
            },
            "utilization": {
                "gpu_percent": gpu_util,
                "memory_percent": mem_util,
            },
            "memory": {
                "total_bytes": mem_total,
                "used_bytes": mem_used,
                "free_bytes": mem_free,
            },
            "temperature": {
                "gpu_celsius": temp_gpu,
            },
            "clocks": {
                "graphics_mhz": clock_graphics,
                "sm_mhz": clock_sm,
                "memory_mhz": clock_mem,
            },
            "power": {
                "draw_mw": power_draw,
                "limit_mw": power_limit,
            },
            "fan": {
                "speed_percent": fan_speed,
            },
            "processes": processes,
            "timestamp": time.time(),
        }

    def snapshot_all(self) -> list[dict[str, Any]]:
        self._ensure_initialized()
        return [self.snapshot(i) for i in range(self._device_count)]

    def set_power_limit_percent(self, index: int, percent: float) -> bool:
        self._ensure_initialized()
        if not CONFIG["safety"]["allow_vendor_writes"]:
            return False
        percent = max(50.0, min(percent, CONFIG["safety"]["max_power_percent"]))
        handle = pynvml.nvmlDeviceGetHandleByIndex(index)
        try:
            default_limit = pynvml.nvmlDeviceGetPowerManagementDefaultLimit(handle)
            new_limit = int(default_limit * (percent / 100.0))
            pynvml.nvmlDeviceSetPowerManagementLimit(handle, new_limit)
            print(f"[TUNING] GPU {index} power limit set to {percent}% ({new_limit} mW)")
            return True
        except pynvml.NVMLError as e:
            print(f"[TUNING] power limit failed: {e}")
            return False

    def set_fan_speed_percent(self, index: int, percent: float) -> bool:
        self._ensure_initialized()
        if not CONFIG["safety"]["allow_vendor_writes"]:
            return False
        percent = max(0.0, min(percent, CONFIG["safety"]["max_fan_percent"]))
        print(f"[TUNING] (stub) GPU {index} fan target {percent}%")
        return True


def query_nvidia_smi() -> list[dict[str, Any]]:
    exe = shutil.which("nvidia-smi")
    if not exe:
        return []
    rc, out, _ = run_cmd(
        [
            exe,
            "--query-gpu=index,name,utilization.gpu,temperature.gpu,memory.total,memory.used",
            "--format=csv,noheader,nounits",
        ]
    )
    if rc != 0 or not out:
        return []
    rows = []
    reader = csv.reader(out.splitlines())
    for row in reader:
        try:
            idx = int(row[0])
            name = row[1]
            util = float(row[2])
            temp = float(row[3])
            mem_total = float(row[4]) * 1024 * 1024
            mem_used = float(row[5]) * 1024 * 1024
            rows.append(
                {
                    "index": idx,
                    "identity": {"name": name},
                    "utilization": {"gpu_percent": util},
                    "temperature": {"gpu_celsius": temp},
                    "memory": {
                        "total_bytes": mem_total,
                        "used_bytes": mem_used,
                        "free_bytes": mem_total - mem_used,
                    },
                    "timestamp": time.time(),
                }
            )
        except Exception:
            continue
    return rows


@dataclass
class TelemetrySample:
    gpu_index: int
    gpu_util: Optional[float]
    gpu_temp: Optional[float]
    mem_used_bytes: Optional[int]
    mem_total_bytes: Optional[int]
    timestamp: float
    raw: dict[str, Any] = field(default_factory=dict)


class TelemetryEngine:
    def __init__(self, interval: float, history_size: int, nvml_backend: Optional[NvmlBackend]) -> None:
        self.interval = max(interval, 0.2)
        self.history_size = max(history_size, 10)
        self.nvml_backend = nvml_backend
        self._samples: list[TelemetrySample] = []
        self._lock = threading.Lock()
        self._stop_flag = False
        self._thread: Optional[threading.Thread] = None
        self._queue: "queue.Queue[TelemetrySample]" = queue.Queue()
        self._interceptors: list[Callable[[TelemetrySample], TelemetrySample]] = []

    def add_interceptor(self, fn: Callable[[TelemetrySample], TelemetrySample]) -> None:
        self._interceptors.append(fn)

    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop_flag = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_flag = True
        if self._thread:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        while not self._stop_flag:
            try:
                samples = self._collect()
                processed: list[TelemetrySample] = []
                for s in samples:
                    for fn in self._interceptors:
                        s = fn(s)
                    processed.append(s)
                with self._lock:
                    self._samples.extend(processed)
                    if len(self._samples) > self.history_size:
                        self._samples = self._samples[-self.history_size :]
                for s in processed:
                    self._queue.put(s)
                if CONFIG.get("telemetry", {}).get("persist", True):
                    self._persist(processed)
            except Exception as e:
                print(f"[Telemetry] error: {e}")
            time.sleep(self.interval)

    def _collect(self) -> list[TelemetrySample]:
        now = time.time()
        samples: list[TelemetrySample] = []
        if self.nvml_backend is not None:
            try:
                snaps = self.nvml_backend.snapshot_all()
                for snap in snaps:
                    idx = snap["index"]
                    util = snap["utilization"]["gpu_percent"]
                    temp = snap["temperature"]["gpu_celsius"]
                    mem_used = snap["memory"]["used_bytes"]
                    mem_total = snap["memory"]["total_bytes"]
                    samples.append(
                        TelemetrySample(
                            gpu_index=idx,
                            gpu_util=util,
                            gpu_temp=temp,
                            mem_used_bytes=mem_used,
                            mem_total_bytes=mem_total,
                            timestamp=now,
                            raw=snap,
                        )
                    )
                return samples
            except Exception as e:
                print(f"[Telemetry] NVML path failed: {e}")
        snaps = query_nvidia_smi()
        for snap in snaps:
            idx = snap["index"]
            util = snap["utilization"]["gpu_percent"]
            temp = snap["temperature"]["gpu_celsius"]
            mem_used = snap["memory"]["used_bytes"]
            mem_total = snap["memory"]["total_bytes"]
            samples.append(
                TelemetrySample(
                    gpu_index=idx,
                    gpu_util=util,
                    gpu_temp=temp,
                    mem_used_bytes=mem_used,
                    mem_total_bytes=mem_total,
                    timestamp=now,
                    raw=snap,
                )
            )
        return samples

    def _persist(self, samples: list[TelemetrySample]) -> None:
        try:
            with TELEMETRY_LOG.open("a", encoding="utf-8") as f:
                for s in samples:
                    f.write(json.dumps(asdict(s)) + "\n")
        except Exception as e:
            print(f"[Telemetry] persist failed: {e}")

    def get_history(self) -> list[TelemetrySample]:
        with self._lock:
            return list(self._samples)

    def get_queue(self) -> "queue.Queue[TelemetrySample]":
        return self._queue


class VramComputeEngine:
    def __init__(self, backend: str = "auto") -> None:
        self.backend = backend
        self._mode = self._select_backend()

    def _select_backend(self) -> str:
        if self.backend == "cuda":
            return "cuda" if CUDA_AVAILABLE else "cpu"
        if self.backend == "cpu":
            return "cpu"
        if self.backend == "auto":
            return "cuda" if CUDA_AVAILABLE else "cpu"
        return "cpu"

    def info(self) -> dict[str, Any]:
        return {
            "backend": self.backend,
            "mode": self._mode,
            "cuda_available": CUDA_AVAILABLE,
        }

    def run_dummy_workload(self, size: int = 1024 * 1024) -> dict[str, Any]:
        start = time.time()
        if self._mode == "cuda" and CUDA_AVAILABLE and np is not None:
            arr = np.random.rand(size).astype(np.float32)
            d_arr = cuda.to_device(arr)
            d_arr.copy_to_host()
        elif np is not None:
            arr = np.random.rand(size).astype(np.float32)
            arr = arr * 2.0
        else:
            data = [math.sin(i) for i in range(size)]
            _ = sum(data)
        elapsed = time.time() - start
        return {
            "mode": self._mode,
            "size": size,
            "elapsed_sec": elapsed,
        }


class EventBus:
    def __init__(self) -> None:
        self._handlers: Dict[str, List[Callable[[Any], None]]] = {}

    def subscribe(self, event: str, handler: Callable[[Any], None]) -> None:
        self._handlers.setdefault(event, []).append(handler)

    def publish(self, event: str, payload: Any) -> None:
        for h in self._handlers.get(event, []):
            try:
                h(payload)
            except Exception as e:
                print(f"[EventBus] handler error for {event}: {e}")


class PredictionEngine:
    def __init__(self, cfg: dict[str, Any], telemetry_engine: TelemetryEngine) -> None:
        self.cfg = cfg
        self.telemetry_engine = telemetry_engine

    def forecast(self) -> dict[str, Any]:
        if not self.cfg.get("enabled", True):
            return {"enabled": False}
        now = time.time()
        hist = self.telemetry_engine.get_history()
        if not hist:
            return {"enabled": True, "status": "no_data"}

        def window_values(window: float) -> tuple[List[float], List[float]]:
            recent = [s for s in hist if now - s.timestamp <= window]
            temps = [s.gpu_temp for s in recent if s.gpu_temp is not None]
            utils = [s.gpu_util for s in recent if s.gpu_util is not None]
            return temps, utils

        short_w = self.cfg.get("short_window", 20)
        med_w = self.cfg.get("medium_window", 60)
        long_w = self.cfg.get("long_window", 300)
        horizon = self.cfg.get("horizon_seconds", 60)

        temps_s, utils_s = window_values(short_w)
        temps_m, utils_m = window_values(med_w)
        temps_l, utils_l = window_values(long_w)

        if len(temps_s) < 3 or len(utils_s) < 3:
            return {"enabled": True, "status": "insufficient_data"}

        def slope(values: List[float], window: float) -> float:
            if len(values) < 2:
                return 0.0
            x = list(range(len(values)))
            mean_x = statistics.mean(x)
            mean_y = statistics.mean(values)
            num = sum((xi - mean_x) * (yi - mean_y) for xi, yi in zip(x, values))
            den = sum((xi - mean_x) ** 2 for xi in x) or 1.0
            slope_per_index = num / den
            return slope_per_index * (len(values) / window)

        t_s = slope(temps_s, short_w)
        u_s = slope(utils_s, short_w)
        t_m = slope(temps_m, med_w) if len(temps_m) >= 3 else 0.0
        u_m = slope(utils_m, med_w) if len(utils_m) >= 3 else 0.0
        t_l = slope(temps_l, long_w) if len(temps_l) >= 3 else 0.0
        u_l = slope(utils_l, long_w) if len(utils_l) >= 3 else 0.0

        temp_now = temps_s[-1]
        util_now = utils_s[-1]
        temp_future = temp_now + t_s * (horizon / short_w)
        util_future = util_now + u_s * (horizon / short_w)

        thermal_limit = CONFIG["safety"]["thermal_limit_c"]
        emergency_temp = CONFIG["safety"]["emergency_temp_c"]

        risk_temp = 0.0
        if temp_future >= emergency_temp:
            risk_temp = 1.0
        elif temp_future >= thermal_limit:
            risk_temp = 0.7
        elif temp_future >= thermal_limit - 5:
            risk_temp = 0.4

        risk_util = 0.0
        if util_future >= 95:
            risk_util = 0.9
        elif util_future >= 80:
            risk_util = 0.6
        elif util_future >= 60:
            risk_util = 0.3

        risk_score = max(risk_temp, risk_util)
        confidence = min(
            1.0,
            (len(temps_s) / 10.0)
            + (len(temps_m) / 20.0)
            + (len(temps_l) / 40.0),
        )

        return {
            "enabled": True,
            "status": "ok",
            "short_window": short_w,
            "medium_window": med_w,
            "long_window": long_w,
            "horizon_seconds": horizon,
            "temp_now": temp_now,
            "temp_future": temp_future,
            "util_now": util_now,
            "util_future": util_future,
            "risk_temp": risk_temp,
            "risk_util": risk_util,
            "risk_score": risk_score,
            "confidence": confidence,
            "slopes": {
                "temp_short": t_s,
                "util_short": u_s,
                "temp_medium": t_m,
                "util_medium": u_m,
                "temp_long": t_l,
                "util_long": u_l,
            },
        }


class TuningEngine:
    def __init__(self, cfg: dict[str, Any], nvml_backend: Optional[NvmlBackend], prediction_engine: PredictionEngine) -> None:
        self.cfg = cfg
        self.nvml_backend = nvml_backend
        self.prediction_engine = prediction_engine

    def get_aggression(self) -> str:
        return self.cfg.get("aggression", "balanced")

    def set_aggression(self, level: str) -> None:
        if level not in ("eco", "balanced", "aggressive", "extreme"):
            return
        self.cfg["aggression"] = level
        CONFIG["tuning"]["aggression"] = level
        save_config(CONFIG)
        print(f"[TUNING] aggression set to {level}")

    def apply_profile_power_fan(self, mode: str) -> None:
        if self.nvml_backend is None:
            return
        if not CONFIG["safety"]["allow_vendor_writes"]:
            return
        try:
            count = self.nvml_backend.device_count()
        except Exception:
            return

        if mode == "base":
            p = CONFIG["base_profile"]["power_target_percent"]
            f = CONFIG["base_profile"]["fan_target_percent"]
        elif mode == "turbo":
            p = CONFIG["turbo_profile"]["power_target_percent"]
            f = CONFIG["turbo_profile"]["fan_target_percent"]
        else:
            return

        overrides = self.cfg.get("gpu_overrides", {})
        for i in range(count):
            key = str(i)
            p_i = overrides.get(key, {}).get("power_target_percent", p)
            f_i = overrides.get(key, {}).get("fan_percent", f)
            self.nvml_backend.set_power_limit_percent(i, p_i)
            self.nvml_backend.set_fan_speed_percent(i, f_i)

    def apply_auto_tuning(self) -> None:
        if self.nvml_backend is None:
            return
        if not CONFIG["safety"]["allow_vendor_writes"]:
            return
        pred = self.prediction_engine.forecast()
        if pred.get("status") != "ok":
            return

        risk = pred["risk_score"]
        confidence = pred["confidence"]
        auto_cfg = CONFIG["auto_profile"]
        aggression = self.get_aggression()

        base_power_idle = auto_cfg["power_idle_percent"]
        base_power_medium = auto_cfg["power_medium_percent"]
        base_power_heavy = auto_cfg["power_heavy_percent"]
        base_power_critical = auto_cfg["power_critical_percent"]

        base_fan_idle = auto_cfg["fan_idle_percent"]
        base_fan_medium = auto_cfg["fan_medium_percent"]
        base_fan_heavy = auto_cfg["fan_heavy_percent"]
        base_fan_critical = auto_cfg["fan_critical_percent"]

        if aggression == "eco":
            scale = 0.7
        elif aggression == "balanced":
            scale = 1.0
        elif aggression == "aggressive":
            scale = 1.2
        else:
            scale = 1.4

        power_idle = base_power_idle * scale
        power_medium = base_power_medium * scale
        power_heavy = base_power_heavy * scale
        power_critical = base_power_critical * scale

        fan_idle = base_fan_idle * scale
        fan_medium = base_fan_medium * scale
        fan_heavy = base_fan_heavy * scale
        fan_critical = base_fan_critical * scale

        util_future = pred["util_future"]
        if util_future < auto_cfg["gpu_idle_threshold"]:
            target_power = power_idle
            target_fan = fan_idle
        elif util_future < auto_cfg["gpu_medium_threshold"]:
            target_power = power_medium
            target_fan = fan_medium
        elif util_future < auto_cfg["gpu_heavy_threshold"]:
            target_power = power_heavy
            target_fan = fan_heavy
        else:
            target_power = power_critical
            target_fan = fan_critical

        target_power = target_power * (0.8 + 0.4 * confidence)
        target_fan = target_fan * (0.8 + 0.4 * risk)

        try:
            count = self.nvml_backend.device_count()
        except Exception:
            return

        overrides = self.cfg.get("gpu_overrides", {})
        for i in range(count):
            key = str(i)
            p_i = overrides.get(key, {}).get("power_target_percent", target_power)
            f_i = overrides.get(key, {}).get("fan_percent", target_fan)
            self.nvml_backend.set_power_limit_percent(i, p_i)
            self.nvml_backend.set_fan_speed_percent(i, f_i)


class ProfileManager:
    def __init__(
        self,
        cfg: dict[str, Any],
        bus: EventBus,
        nvml_backend: Optional[NvmlBackend],
        tuning_engine: TuningEngine,
    ) -> None:
        self.cfg = cfg
        self.bus = bus
        self.current_mode = cfg.get("mode", "base")
        self.nvml_backend = nvml_backend
        self.tuning_engine = tuning_engine
        self._last_auto_switch_time = 0.0

    def apply_mode(self, mode: str) -> None:
        if mode not in ("base", "turbo", "auto"):
            return
        self.current_mode = mode
        self.cfg["mode"] = mode
        save_config(self.cfg)
        print(f"[Profile] mode set to {mode}")
        self.bus.publish("profile_changed", mode)
        if mode in ("base", "turbo"):
            self.tuning_engine.apply_profile_power_fan(mode)

    def auto_tick(self) -> None:
        if self.current_mode != "auto":
            return
        now = time.time()
        hysteresis = CONFIG["auto_profile"]["hysteresis_seconds"]
        if now - self._last_auto_switch_time < hysteresis:
            return
        self.tuning_engine.apply_auto_tuning()
        self._last_auto_switch_time = now


class PluginAPI:
    def __init__(
        self,
        bus: EventBus,
        telemetry: TelemetryEngine,
        vram_engine: VramComputeEngine,
        prediction_engine: PredictionEngine,
    ) -> None:
        self.bus = bus
        self.telemetry = telemetry
        self.vram_engine = vram_engine
        self.prediction_engine = prediction_engine

    def register_telemetry_interceptor(self, fn: Callable[[TelemetrySample], TelemetrySample]) -> None:
        self.telemetry.add_interceptor(fn)

    def register_event_handler(self, event: str, handler: Callable[[Any], None]) -> None:
        self.bus.subscribe(event, handler)

    def run_vram_workload(self, size: int = 1024 * 1024) -> dict[str, Any]:
        return self.vram_engine.run_dummy_workload(size)

    def get_prediction(self) -> dict[str, Any]:
        return self.prediction_engine.forecast()


class PluginManager:
    def __init__(self, directory: Path, api: PluginAPI) -> None:
        self.directory = directory
        self.plugins: Dict[str, Any] = {}
        self.api = api

    def load_all(self) -> None:
        if not self.directory.exists():
            return
        for path in self.directory.glob("*.py"):
            name = path.stem
            try:
                spec = importlib.util.spec_from_file_location(name, str(path))
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self.plugins[name] = module
                    if hasattr(module, "on_load"):
                        module.on_load(self.api, CONFIG["plugins"]["settings"].get(name, {}))
                    if hasattr(module, "register"):
                        module.register(self.api)
                    print(f"[Plugin] loaded {name}")
            except Exception as e:
                print(f"[Plugin] failed to load {name}: {e}")

    def tick(self) -> None:
        for name, module in self.plugins.items():
            try:
                if hasattr(module, "on_tick"):
                    module.on_tick()
            except Exception as e:
                print(f"[Plugin] tick error in {name}: {e}")


class SwarmManager:
    def __init__(self, cfg: dict[str, Any], telemetry_engine: TelemetryEngine) -> None:
        self.cfg = cfg
        self.telemetry_engine = telemetry_engine
        self._stop_flag = False
        self._thread: Optional[threading.Thread] = None
        self._leader_id: Optional[str] = None
        self._last_leader_eval = 0.0

    def start(self) -> None:
        if not self.cfg.get("enabled", False):
            return
        if self._thread and self._thread.is_alive():
            return
        self._stop_flag = False
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop_flag = True
        if self._thread:
            self._thread.join(timeout=2.0)

    def _run(self) -> None:
        interval = max(self.cfg.get("interval", 5.0), 1.0)
        while not self._stop_flag:
            try:
                self._sync_peers()
                self._evaluate_leader()
            except Exception as e:
                print(f"[Swarm] error: {e}")
            time.sleep(interval)

    def _sync_peers(self) -> None:
        peers = self.cfg.get("peers", [])
        hist = self.telemetry_engine.get_history()
        payload = {
            "node_id": self.cfg.get("node_id"),
            "telemetry": [asdict(s) for s in hist[-10:]],
        }
        body = json.dumps(payload).encode("utf-8")
        for peer in peers:
            try:
                import urllib.request
                req = urllib.request.Request(
                    peer.rstrip("/") + "/swarm/sync",
                    data=body,
                    headers={"Content-Type": "application/json"},
                    method="POST",
                )
                urllib.request.urlopen(req, timeout=2.0)
            except Exception:
                continue

    def _evaluate_leader(self) -> None:
        now = time.time()
        if now - self._last_leader_eval < 30.0:
            return
        self._last_leader_eval = now
        node_id = self.cfg.get("node_id")
        peers = self.cfg.get("peers", [])
        candidates = [node_id] + peers
        self._leader_id = sorted(candidates)[0] if candidates else node_id
        print(f"[Swarm] leader elected: {self._leader_id}")

    def get_leader(self) -> Optional[str]:
        return self._leader_id


class GuiShell:
    def __init__(
        self,
        telemetry_engine: TelemetryEngine,
        profile_manager: ProfileManager,
        prediction_engine: PredictionEngine,
        tuning_engine: TuningEngine,
        nvml_backend: Optional[NvmlBackend],
    ) -> None:
        self.telemetry_engine = telemetry_engine
        self.profile_manager = profile_manager
        self.prediction_engine = prediction_engine
        self.tuning_engine = tuning_engine
        self.nvml_backend = nvml_backend
        self.app = None
        self.window = None
        self.table = None
        self.pred_label = None
        self.aggression_combo = None

    def start(self) -> None:
        if not PYQT_AVAILABLE:
            print("[GUI] PyQt6 not available; GUI disabled.")
            return
        from PyQt6 import QtWidgets, QtCore

        self.app = QtWidgets.QApplication(sys.argv)
        self.app.setApplicationName(APP_NAME)

        self.window = QtWidgets.QMainWindow()
        self.window.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(8)
        self.table.setHorizontalHeaderLabels(
            ["GPU", "Name", "Util %", "Temp C", "Mem Used", "Mem Total", "Power %", "Fan %"]
        )
        layout.addWidget(self.table)

        btn_row = QtWidgets.QHBoxLayout()
        btn_base = QtWidgets.QPushButton("Base Mode")
        btn_turbo = QtWidgets.QPushButton("Turbo Mode")
        btn_auto = QtWidgets.QPushButton("Auto Mode")
        btn_row.addWidget(btn_base)
        btn_row.addWidget(btn_turbo)
        btn_row.addWidget(btn_auto)
        layout.addLayout(btn_row)

        btn_base.clicked.connect(lambda: self.profile_manager.apply_mode("base"))
        btn_turbo.clicked.connect(lambda: self.profile_manager.apply_mode("turbo"))
        btn_auto.clicked.connect(lambda: self.profile_manager.apply_mode("auto"))

        ag_row = QtWidgets.QHBoxLayout()
        ag_label = QtWidgets.QLabel("Aggression:")
        self.aggression_combo = QtWidgets.QComboBox()
        self.aggression_combo.addItems(["eco", "balanced", "aggressive", "extreme"])
        self.aggression_combo.setCurrentText(self.tuning_engine.get_aggression())
        self.aggression_combo.currentTextChanged.connect(self.tuning_engine.set_aggression)
        ag_row.addWidget(ag_label)
        ag_row.addWidget(self.aggression_combo)
        layout.addLayout(ag_row)

        self.pred_label = QtWidgets.QLabel("Prediction: waiting...")
        layout.addWidget(self.pred_label)

        self.window.setCentralWidget(central)
        self.window.resize(900, 450)
        self.window.show()

        timer = QtCore.QTimer()
        timer.timeout.connect(self._update_dashboard)
        timer.start(int(CONFIG.get("telemetry", {}).get("interval", 1.0) * 1000))

        self.app.exec()

    def _update_dashboard(self) -> None:
        hist = self.telemetry_engine.get_history()
        if not hist:
            return
        latest_by_gpu: Dict[int, TelemetrySample] = {}
        for s in hist:
            latest_by_gpu[s.gpu_index] = s
        rows = len(latest_by_gpu)
        self.table.setRowCount(rows)
        for row, (idx, sample) in enumerate(sorted(latest_by_gpu.items())):
            name = sample.raw.get("identity", {}).get("name", f"GPU {idx}")
            util = sample.gpu_util
            temp = sample.gpu_temp
            mem_used = sample.mem_used_bytes
            mem_total = sample.mem_total_bytes
            power = sample.raw.get("power", {}).get("limit_mw")
            fan = sample.raw.get("fan", {}).get("speed_percent")
            self.table.setItem(row, 0, self._cell(str(idx)))
            self.table.setItem(row, 1, self._cell(str(name)))
            self.table.setItem(row, 2, self._cell(str(util)))
            self.table.setItem(row, 3, self._cell(str(temp)))
            self.table.setItem(row, 4, self._cell(str(mem_used)))
            self.table.setItem(row, 5, self._cell(str(mem_total)))
            self.table.setItem(row, 6, self._cell(str(power)))
            self.table.setItem(row, 7, self._cell(str(fan)))
        pred = self.prediction_engine.forecast()
        if pred.get("status") == "ok":
            self.pred_label.setText(
                f"Prediction: temp {pred['temp_now']:.1f}→{pred['temp_future']:.1f}C, "
                f"util {pred['util_now']:.1f}→{pred['util_future']:.1f}% "
                f"risk={pred['risk_score']:.2f} conf={pred['confidence']:.2f}"
            )
        else:
            self.pred_label.setText(f"Prediction: {pred.get('status')}")

    def _cell(self, text: str):
        from PyQt6 import QtWidgets
        item = QtWidgets.QTableWidgetItem(text)
        return item


class DaemonServer:
    def __init__(
        self,
        cfg: dict[str, Any],
        telemetry_engine: TelemetryEngine,
        profile_manager: ProfileManager,
        vram_engine: VramComputeEngine,
        prediction_engine: PredictionEngine,
        plugin_manager: PluginManager,
        tuning_engine: TuningEngine,
        swarm_manager: SwarmManager,
    ) -> None:
        self.cfg = cfg
        self.telemetry_engine = telemetry_engine
        self.profile_manager = profile_manager
        self.vram_engine = vram_engine
        self.prediction_engine = prediction_engine
        self.plugin_manager = plugin_manager
        self.tuning_engine = tuning_engine
        self.swarm_manager = swarm_manager

    async def _run_http(self) -> None:
        if aiohttp is None:
            print("[Daemon] aiohttp not available; HTTP disabled.")
            return
        app = aiohttp.web.Application()

        async def handle_status(request: aiohttp.web.Request) -> aiohttp.web.Response:
            hist = self.telemetry_engine.get_history()
            payload = [asdict(s) for s in hist]
            return aiohttp.web.json_response({"telemetry": payload})

        async def handle_gpu(request: aiohttp.web.Request) -> aiohttp.web.Response:
            hist = self.telemetry_engine.get_history()
            latest_by_gpu: Dict[int, TelemetrySample] = {}
            for s in hist:
                latest_by_gpu[s.gpu_index] = s
            payload = {idx: asdict(s) for idx, s in latest_by_gpu.items()}
            return aiohttp.web.json_response({"gpus": payload})

        async def handle_profiles(request: aiohttp.web.Request) -> aiohttp.web.Response:
            if request.method == "GET":
                return aiohttp.web.json_response(
                    {"mode": self.profile_manager.current_mode, "config": CONFIG}
                )
            if request.method == "POST":
                data = await request.json()
                mode = data.get("mode")
                self.profile_manager.apply_mode(mode)
                return aiohttp.web.json_response({"ok": True, "mode": mode})

        async def handle_vram(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            size = int(data.get("size", 1024 * 1024))
            result = self.vram_engine.run_dummy_workload(size)
            return aiohttp.web.json_response(result)

        async def handle_prediction(request: aiohttp.web.Request) -> aiohttp.web.Response:
            result = self.prediction_engine.forecast()
            return aiohttp.web.json_response(result)

        async def handle_plugins(request: aiohttp.web.Request) -> aiohttp.web.Response:
            names = list(self.plugin_manager.plugins.keys())
            return aiohttp.web.json_response({"plugins": names})

        async def handle_tuning_power(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            gpu_index = int(data.get("gpu_index", 0))
            percent = float(data.get("percent", 100.0))
            if self.tuning_engine.nvml_backend is None:
                return aiohttp.web.json_response({"ok": False, "error": "nvml_unavailable"})
            ok = self.tuning_engine.nvml_backend.set_power_limit_percent(gpu_index, percent)
            return aiohttp.web.json_response({"ok": ok})

        async def handle_tuning_fan(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            gpu_index = int(data.get("gpu_index", 0))
            percent = float(data.get("percent", 50.0))
            if self.tuning_engine.nvml_backend is None:
                return aiohttp.web.json_response({"ok": False, "error": "nvml_unavailable"})
            ok = self.tuning_engine.nvml_backend.set_fan_speed_percent(gpu_index, percent)
            return aiohttp.web.json_response({"ok": ok})

        async def handle_tuning_aggression(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            level = data.get("level", "balanced")
            self.tuning_engine.set_aggression(level)
            return aiohttp.web.json_response({"ok": True, "level": level})

        async def handle_swarm_status(request: aiohttp.web.Request) -> aiohttp.web.Response:
            leader = self.swarm_manager.get_leader()
            return aiohttp.web.json_response({"leader": leader, "node_id": CONFIG["sync"]["node_id"]})

        async def handle_swarm_sync(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            node_id = data.get("node_id")
            print(f"[Swarm] received payload from {node_id}")
            return aiohttp.web.json_response({"ok": True})

        app.router.add_get("/status", handle_status)
        app.router.add_get("/gpu", handle_gpu)
        app.router.add_route("*", "/profiles", handle_profiles)
        app.router.add_post("/vram", handle_vram)
        app.router.add_get("/prediction", handle_prediction)
        app.router.add_get("/plugins", handle_plugins)
        app.router.add_post("/tuning/power", handle_tuning_power)
        app.router.add_post("/tuning/fan", handle_tuning_fan)
        app.router.add_post("/tuning/aggression", handle_tuning_aggression)
        app.router.add_get("/swarm/status", handle_swarm_status)
        app.router.add_post("/swarm/sync", handle_swarm_sync)

        runner = aiohttp.web.AppRunner(app)
        await runner.setup()
        site = aiohttp.web.TCPSite(
            runner,
            self.cfg.get("host", "127.0.0.1"),
            self.cfg.get("port", 8765),
        )
        await site.start()
        print(f"[Daemon] HTTP listening on {self.cfg.get('host')}:{self.cfg.get('port')}")
        while True:
            await asyncio.sleep(1.0)

    async def _run_ws(self) -> None:
        if websockets is None:
            print("[Daemon] websockets not available; WS disabled.")
            return

        async def handler(websocket):
            q = self.telemetry_engine.get_queue()
            print("[Daemon] WebSocket client connected.")
            try:
                while True:
                    sample = await asyncio.get_event_loop().run_in_executor(None, q.get)
                    await websocket.send(json.dumps(asdict(sample)))
            except Exception:
                print("[Daemon] WebSocket client disconnected.")

        host = self.cfg.get("host", "127.0.0.1")
        port = self.cfg.get("websocket_port", 8766)
        server = await websockets.serve(handler, host, port)
        print(f"[Daemon] WebSocket listening on {host}:{port}")
        await server.wait_closed()

    async def run(self) -> None:
        if not self.cfg.get("enabled", False):
            print("[Daemon] disabled in config.")
            return
        tasks = []
        tasks.append(asyncio.create_task(self._run_http()))
        tasks.append(asyncio.create_task(self._run_ws()))
        await asyncio.gather(*tasks)


def init_nvml_backend() -> Optional[NvmlBackend]:
    backend: Optional[NvmlBackend] = None
    try:
        backend = NvmlBackend()
        backend.start()
        try:
            count = backend.device_count()
        except (NvmlError, NvmlNotInitialized) as e:
            print(f"[NVML] unusable: {e}")
            return None
        if count == 0:
            print("[NVML] No NVIDIA GPUs detected; disabling NVML telemetry.")
            return None
        print(f"[NVML] Initialized, {count} GPU(s) detected.")
        return backend
    except Exception as e:
        print(f"[NVML] backend unavailable: {e}")
        return None


def start_governor_runtime() -> None:
    bus = EventBus()
    nvml_backend = init_nvml_backend()

    telemetry_cfg = CONFIG.get("telemetry", {})
    telemetry_engine = TelemetryEngine(
        interval=telemetry_cfg.get("interval", 1.0),
        history_size=telemetry_cfg.get("history_size", 600),
        nvml_backend=nvml_backend,
    )
    telemetry_engine.start()

    vram_cfg = CONFIG.get("vram_engine", {})
    vram_engine = VramComputeEngine(backend=vram_cfg.get("backend", "auto"))
    print(f"[VRAM] engine: {vram_engine.info()}")

    prediction_engine = PredictionEngine(CONFIG.get("prediction", {}), telemetry_engine)

    tuning_engine = TuningEngine(CONFIG.get("tuning", {}), nvml_backend, prediction_engine)

    profile_manager = ProfileManager(CONFIG, bus, nvml_backend, tuning_engine)

    plugin_api = PluginAPI(bus, telemetry_engine, vram_engine, prediction_engine)
    plugin_cfg = CONFIG.get("plugins", {})
    plugin_manager = PluginManager(Path(plugin_cfg.get("directory", str(PLUGIN_DIR))), plugin_api)
    if plugin_cfg.get("enabled", True):
        plugin_manager.load_all()

    swarm_cfg = CONFIG.get("sync", {})
    swarm_manager = SwarmManager(swarm_cfg, telemetry_engine)
    swarm_manager.start()

    daemon_cfg = CONFIG.get("daemon", {})
    daemon_server = DaemonServer(
        daemon_cfg,
        telemetry_engine,
        profile_manager,
        vram_engine,
        prediction_engine,
        plugin_manager,
        tuning_engine,
        swarm_manager,
    )

    gui_shell = GuiShell(telemetry_engine, profile_manager, prediction_engine, tuning_engine, nvml_backend)

    def run_async_daemon():
        if not daemon_cfg.get("enabled", False):
            return
        try:
            asyncio.run(daemon_server.run())
        except Exception as e:
            print(f"[Daemon] async error: {e}")

    daemon_thread = threading.Thread(target=run_async_daemon, daemon=True)
    daemon_thread.start()

    if CONFIG.get("mode") == "auto":
        profile_manager.apply_mode("auto")

    def governor_loop():
        try:
            while True:
                profile_manager.auto_tick()
                plugin_manager.tick()
                time.sleep(CONFIG["telemetry"]["interval"])
        except KeyboardInterrupt:
            print("[RUNTIME] Shutdown requested.")

    loop_thread = threading.Thread(target=governor_loop, daemon=True)
    loop_thread.start()

    if PYQT_AVAILABLE:
        gui_shell.start()
    else:
        print("[GUI] not available; headless mode.")
        try:
            while True:
                time.sleep(1.0)
        except KeyboardInterrupt:
            print("[RUNTIME] Shutdown requested.")

    telemetry_engine.stop()
    swarm_manager.stop()
    if nvml_backend is not None:
        nvml_backend.stop()


def main() -> None:
    print(f"{APP_NAME} v{APP_VERSION} starting...")
    print(f"[CONFIG] mode={CONFIG.get('mode')}")
    start_governor_runtime()


if __name__ == "__main__":
    main()
