#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hybrid Universal GPU Governor - v4.0 Windows build (monolithic).

Organs included in this build:
- Config + profiles + persistence
- Optional imports + capability detection
- NVML backend (safe-decode, crash-safe, optional)
- WMI + nvidia-smi telemetry fallback
- Async telemetry engine (worker thread + asyncio bridge)
- PyQt6 GUI shell (minimal, Qt6-safe)
- Daemon mode (REST + WebSocket, optional via aiohttp/websockets)
- VRAM Compute Engine (CUDA/CPU, safe workloads only)
- Plugin system (local Python plugins)
- Sync nodes (simple peer telemetry exchange)
- Profile manager + event bus
- Unified runtime loop

SAFETY:
This application intentionally avoids arbitrary GPU register writes, VBIOS writes,
memory strap writes, voltage-table edits, or undocumented timing modifications.
Vendor controls are only exposed when a supported, explicit vendor interface is
detected. All requested values are range checked before an action is attempted.

Optional packages:
    pip install PyQt6 psutil pynvml aiohttp websockets numba numpy

The application can still collect Windows WMI/nvidia-smi telemetry when optional
GPU libraries are unavailable.
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
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Callable, Optional, Dict, List

APP_NAME = "Universal GPU Control Center"
APP_VERSION = 4
PROFILE_DIR = Path.home() / "GPUControlCenter"
PLUGIN_DIR = PROFILE_DIR / "plugins"
PROFILE_DIR.mkdir(parents=True, exist_ok=True)
PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = PROFILE_DIR / "system_tuner_config.json"
TELEMETRY_LOG = PROFILE_DIR / "telemetry.jsonl"

DEFAULT_CONFIG: dict[str, Any] = {
    "mode": "auto",  # base/turbo/auto
    "beast_mode_enabled": False,
    "daemon": {
        "enabled": False,
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
        "enabled": False,
        "node_id": socket.gethostname(),
        "peers": [],
        "interval": 5.0,
        "share_profiles": False,
    },
    "prediction": {
        "enabled": True,
        "window": 30,
        "horizon_seconds": 60,
    },
    "plugins": {
        "enabled": True,
        "directory": str(PLUGIN_DIR),
    },
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
    "vram_engine": {
        "enabled": True,
        "backend": "auto",  # auto/cuda/cpu
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

# VRAM compute optional deps
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


# ------------------------------------------------------------------------- #
# Safe decode helper (handles str/bytes NVML returns)
# ------------------------------------------------------------------------- #

def safe_decode(x):
    return x.decode("utf-8", errors="ignore") if isinstance(x, bytes) else x


# ------------------------------------------------------------------------- #
# NVML backend – crash-safe, integrated with optional_import loader
# ------------------------------------------------------------------------- #

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


class NvmlPoller:
    def __init__(
        self,
        backend: NvmlBackend,
        interval_sec: float,
        callback: Callable[[list[dict[str, Any]]], None],
    ) -> None:
        self.backend = backend
        self.interval_sec = max(interval_sec, 0.1)
        self.callback = callback
        self._thread: Optional[threading.Thread] = None
        self._stop_flag: bool = False

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
                snapshots = self.backend.snapshot_all()
                self.callback(snapshots)
            except Exception as e:
                print(f"[NvmlPoller] error during polling: {e}")
            time.sleep(self.interval_sec)


# ------------------------------------------------------------------------- #
# WMI / nvidia-smi telemetry fallback
# ------------------------------------------------------------------------- #

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


# ------------------------------------------------------------------------- #
# Telemetry engine (async + worker thread)
# ------------------------------------------------------------------------- #

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
                with self._lock:
                    self._samples.extend(samples)
                    if len(self._samples) > self.history_size:
                        self._samples = self._samples[-self.history_size :]
                for s in samples:
                    self._queue.put(s)
                if CONFIG.get("telemetry", {}).get("persist", True):
                    self._persist(samples)
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


# ------------------------------------------------------------------------- #
# VRAM Compute Engine (safe workloads)
# ------------------------------------------------------------------------- #

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


# ------------------------------------------------------------------------- #
# Plugin system
# ------------------------------------------------------------------------- #

class PluginManager:
    def __init__(self, directory: Path) -> None:
        self.directory = directory
        self.plugins: Dict[str, Any] = {}

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
                    print(f"[Plugin] loaded {name}")
            except Exception as e:
                print(f"[Plugin] failed to load {name}: {e}")


# ------------------------------------------------------------------------- #
# Sync nodes (simple peer telemetry exchange)
# ------------------------------------------------------------------------- #

class SyncManager:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        self._stop_flag = False
        self._thread: Optional[threading.Thread] = None

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
                pass
            except Exception as e:
                print(f"[Sync] error: {e}")
            time.sleep(interval)


# ------------------------------------------------------------------------- #
# Profile manager + event bus
# ------------------------------------------------------------------------- #

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


class ProfileManager:
    def __init__(self, cfg: dict[str, Any], bus: EventBus) -> None:
        self.cfg = cfg
        self.bus = bus
        self.current_mode = cfg.get("mode", "base")

    def apply_mode(self, mode: str) -> None:
        if mode not in ("base", "turbo", "auto"):
            return
        self.current_mode = mode
        self.cfg["mode"] = mode
        save_config(self.cfg)
        print(f"[Profile] mode set to {mode}")
        self.bus.publish("profile_changed", mode)


# ------------------------------------------------------------------------- #
# PyQt6 GUI shell (Qt6-safe, no DPI attributes)
# ------------------------------------------------------------------------- #

class GuiShell:
    def __init__(self, telemetry_engine: TelemetryEngine, profile_manager: ProfileManager) -> None:
        self.telemetry_engine = telemetry_engine
        self.profile_manager = profile_manager
        self.app = None
        self.window = None
        self.label = None

    def start(self) -> None:
        if not PYQT_AVAILABLE:
            print("[GUI] PyQt6 not available; GUI disabled.")
            return
        from PyQt6 import QtWidgets

        self.app = QtWidgets.QApplication(sys.argv)
        self.app.setApplicationName(APP_NAME)

        self.window = QtWidgets.QMainWindow()
        self.window.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)

        self.label = QtWidgets.QLabel("Telemetry: waiting...")
        layout.addWidget(self.label)

        btn_base = QtWidgets.QPushButton("Base Mode")
        btn_turbo = QtWidgets.QPushButton("Turbo Mode")
        btn_auto = QtWidgets.QPushButton("Auto Mode")

        btn_base.clicked.connect(lambda: self.profile_manager.apply_mode("base"))
        btn_turbo.clicked.connect(lambda: self.profile_manager.apply_mode("turbo"))
        btn_auto.clicked.connect(lambda: self.profile_manager.apply_mode("auto"))

        layout.addWidget(btn_base)
        layout.addWidget(btn_turbo)
        layout.addWidget(btn_auto)

        self.window.setCentralWidget(central)
        self.window.resize(480, 240)
        self.window.show()

        from PyQt6 import QtCore
        timer = QtCore.QTimer()
        timer.timeout.connect(self._update_telemetry_label)
        timer.start(int(CONFIG.get("telemetry", {}).get("interval", 1.0) * 1000))

        self.app.exec()

    def _update_telemetry_label(self) -> None:
        hist = self.telemetry_engine.get_history()
        if not hist:
            self.label.setText("Telemetry: no samples yet.")
            return
        last = hist[-1]
        self.label.setText(
            f"GPU {last.gpu_index}: util={last.gpu_util}% temp={last.gpu_temp}C "
            f"mem={last.mem_used_bytes}/{last.mem_total_bytes}"
        )


# ------------------------------------------------------------------------- #
# Daemon mode (REST + WebSocket)
# ------------------------------------------------------------------------- #

class DaemonServer:
    def __init__(self, cfg: dict[str, Any], telemetry_engine: TelemetryEngine) -> None:
        self.cfg = cfg
        self.telemetry_engine = telemetry_engine

    async def _run_http(self) -> None:
        if aiohttp is None:
            print("[Daemon] aiohttp not available; HTTP disabled.")
            return
        app = aiohttp.web.Application()

        async def handle_status(request: aiohttp.web.Request) -> aiohttp.web.Response:
            hist = self.telemetry_engine.get_history()
            payload = [asdict(s) for s in hist]
            return aiohttp.web.json_response({"telemetry": payload})

        app.router.add_get("/status", handle_status)
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


# ------------------------------------------------------------------------- #
# Safe NVML bootstrap hook
# ------------------------------------------------------------------------- #

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


# ------------------------------------------------------------------------- #
# Governor runtime starter
# ------------------------------------------------------------------------- #

def start_governor_runtime() -> None:
    bus = EventBus()
    profile_manager = ProfileManager(CONFIG, bus)

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

    plugin_cfg = CONFIG.get("plugins", {})
    plugin_manager = PluginManager(Path(plugin_cfg.get("directory", str(PLUGIN_DIR))))
    if plugin_cfg.get("enabled", True):
        plugin_manager.load_all()

    sync_cfg = CONFIG.get("sync", {})
    sync_manager = SyncManager(sync_cfg)
    sync_manager.start()

    daemon_cfg = CONFIG.get("daemon", {})
    daemon_server = DaemonServer(daemon_cfg, telemetry_engine)

    gui_shell = GuiShell(telemetry_engine, profile_manager)

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
    sync_manager.stop()
    if nvml_backend is not None:
        nvml_backend.stop()


# ------------------------------------------------------------------------- #
# Main entry
# ------------------------------------------------------------------------- #

def main() -> None:
    print(f"{APP_NAME} v{APP_VERSION} starting...")
    print(f"[CONFIG] mode={CONFIG.get('mode')}")
    start_governor_runtime()


if __name__ == "__main__":
    main()
