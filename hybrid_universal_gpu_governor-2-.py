#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hybrid Universal GPU Governor - upgraded Windows build.

Major upgrades:
- Async telemetry pipeline with asyncio + worker thread.
- PyQt6 GUI with DPI scaling.
- Persistent background daemon mode.
- Local REST + WebSocket API when optional packages are installed.
- Vendor capability hooks: NVIDIA NVAPI/ADL-style adapters with strict safety gates.
- Predictive thermal/power trend layer using recent telemetry.
- External plugin system.
- Distributed node telemetry/profile synchronization.
- JSON profile persistence, diagnostics, export and graceful shutdown.

SAFETY:
This application intentionally avoids arbitrary GPU register writes, VBIOS writes,
memory strap writes, voltage-table edits, or undocumented timing modifications.
Vendor controls are only exposed when a supported, explicit vendor interface is
detected. All requested values are range checked before an action is attempted.

Optional packages:
    pip install PyQt6 psutil pynvml aiohttp websockets

The application can still collect Windows WMI/nvidia-smi telemetry when optional
GPU libraries are unavailable.
"""

from __future__ import annotations

import asyncio
import ctypes
import csv
import importlib
import json
import math
import os
import platform
import queue
import shutil
import socket
import statistics
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
import urllib.error
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Callable

APP_NAME = "Universal GPU Control Center"
APP_VERSION = 3
PROFILE_DIR = Path.home() / "GPUControlCenter"
PLUGIN_DIR = PROFILE_DIR / "plugins"
PROFILE_DIR.mkdir(parents=True, exist_ok=True)
PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_PATH = PROFILE_DIR / "system_tuner_config.json"
TELEMETRY_LOG = PROFILE_DIR / "telemetry.jsonl"

DEFAULT_CONFIG: dict[str, Any] = {
    "mode": "base",
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


def classify_vendor(name: str, compatibility: str = "") -> str:
    text = f"{name} {compatibility}".lower()
    if "nvidia" in text:
        return "NVIDIA"
    if "amd" in text or "advanced micro devices" in text or "radeon" in text:
        return "AMD"
    if "intel" in text:
        return "Intel"
    return "Other"


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
    controls: dict[str, bool] = field(default_factory=dict)


def detect_windows_adapters() -> list[dict[str, Any]]:
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
        return data if isinstance(data, list) else [data]
    except json.JSONDecodeError:
        return []


def find_nvidia_smi() -> str | None:
    exe = shutil.which("nvidia-smi")
    if exe:
        return exe
    candidates = [
        r"C:\Windows\System32\nvidia-smi.exe",
        r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
    ]
    return next((x for x in candidates if os.path.exists(x)), None)


def detect_nvidia() -> list[GPU]:
    exe = find_nvidia_smi()
    if not exe:
        return []
    query = (
        "index,name,driver_version,memory.total,memory.used,"
        "temperature.gpu,utilization.gpu,clocks.gr,clocks.mem,"
        "power.draw,power.limit,fan.speed,pci.device"
    )
    rc, out, _ = run_cmd(
        [exe, f"--query-gpu={query}", "--format=csv,noheader,nounits"], 6
    )
    if rc != 0:
        return []
    result: list[GPU] = []
    for row in csv.reader(out.splitlines()):
        if len(row) < 13:
            continue

        def num(i: int) -> float | None:
            try:
                value = row[i].strip()
                return None if value in {"", "N/A", "[Not Supported]"} else float(value)
            except Exception:
                return None

        try:
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
    return result


def detect_gpus() -> list[GPU]:
    gpus = detect_nvidia()
    seen = {g.name.lower() for g in gpus}
    next_index = max([g.index for g in gpus], default=-1) + 1

    for a in detect_windows_adapters():
        name = str(a.get("Name") or "Unknown GPU")
        if name.lower() in seen:
            continue
        vendor = classify_vendor(name, str(a.get("AdapterCompatibility") or ""))
        try:
            ram_mb = int(a.get("AdapterRAM") or 0) // (1024 * 1024)
        except Exception:
            ram_mb = 0
        gpus.append(
            GPU(
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
        )
        next_index += 1
    return gpus


def init_nvml() -> bool:
    if pynvml is None:
        return False
    try:
        pynvml.nvmlInit()
        return True
    except Exception:
        return False


NVML_READY = init_nvml()


def safe_decode(value: Any) -> str:
    return value.decode("utf-8", errors="ignore") if isinstance(value, bytes) else str(value)


def get_gpu_telemetry_nvml() -> dict[str, Any]:
    if not NVML_READY:
        return {"backend": "none", "devices": []}
    try:
        devices = []
        count = pynvml.nvmlDeviceGetCount()
        for i in range(count):
            h = pynvml.nvmlDeviceGetHandleByIndex(i)
            util = pynvml.nvmlDeviceGetUtilizationRates(h)
            mem = pynvml.nvmlDeviceGetMemoryInfo(h)

            def metric(fn: Callable[[], Any]) -> Any:
                try:
                    return fn()
                except Exception:
                    return None

            temp = metric(lambda: pynvml.nvmlDeviceGetTemperature(
                h, pynvml.NVML_TEMPERATURE_GPU
            ))
            power = metric(lambda: pynvml.nvmlDeviceGetPowerUsage(h) / 1000.0)
            limit = metric(lambda: pynvml.nvmlDeviceGetPowerManagementLimit(h) / 1000.0)
            fan = metric(lambda: pynvml.nvmlDeviceGetFanSpeed(h))
            graphics = metric(lambda: pynvml.nvmlDeviceGetClockInfo(
                h, pynvml.NVML_CLOCK_GRAPHICS
            ))
            mem_clock = metric(lambda: pynvml.nvmlDeviceGetClockInfo(
                h, pynvml.NVML_CLOCK_MEM
            ))

            devices.append({
                "index": i,
                "name": safe_decode(pynvml.nvmlDeviceGetName(h)),
                "gpu_util_percent": float(util.gpu),
                "mem_util_percent": float(util.memory),
                "mem_used_gb": round(mem.used / 1024**3, 3),
                "mem_total_gb": round(mem.total / 1024**3, 3),
                "temperature_c": temp,
                "power_w": power,
                "power_limit_w": limit,
                "fan_percent": fan,
                "clocks": {
                    "graphics_clock_mhz": graphics,
                    "mem_clock_mhz": mem_clock,
                },
            })
        return {"backend": "nvidia_nvml", "devices": devices}
    except Exception as exc:
        return {"backend": "nvidia_nvml", "devices": [], "error": str(exc)}


class SafetyManager:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg

    def clamp_power_percent(self, value: float) -> float:
        maximum = float(self.cfg.get("max_power_percent", 110))
        if not 50 <= value <= maximum:
            raise ValueError(f"Power target must be between 50 and {maximum:.0f}%.")
        return value

    def validate_offsets(self, core: int, memory: int) -> None:
        max_core = int(self.cfg.get("max_core_offset_mhz", 300))
        max_mem = int(self.cfg.get("max_memory_offset_mhz", 1000))
        if abs(core) > max_core:
            raise ValueError(f"Core offset exceeds ±{max_core} MHz safety limit.")
        if abs(memory) > max_mem:
            raise ValueError(f"Memory offset exceeds ±{max_mem} MHz safety limit.")

    def validate_fan(self, percent: int) -> int:
        if not 0 <= percent <= int(self.cfg.get("max_fan_percent", 100)):
            raise ValueError("Fan percentage is outside the safe range.")
        return percent

    def vendor_write_allowed(self) -> bool:
        return bool(self.cfg.get("allow_vendor_writes", False))


SAFETY = SafetyManager(CONFIG["safety"])


class VendorBackend:
    """Explicit vendor interface boundary. Unsupported operations remain disabled."""

    def __init__(self, gpu: GPU):
        self.gpu = gpu

    def capabilities(self) -> dict[str, bool]:
        return dict(self.gpu.controls)

    def set_power_limit(self, watts: float) -> str:
        raise RuntimeError("No supported generic power-limit interface.")

    def set_clock_offset(self, core: int, memory: int) -> str:
        raise RuntimeError("No supported generic clock-offset interface.")

    def set_fan(self, percent: int) -> str:
        raise RuntimeError("No supported generic fan interface.")

    def refresh(self) -> GPU:
        return self.gpu


class NvidiaBackend(VendorBackend):
    def __init__(self, gpu: GPU):
        super().__init__(gpu)
        self.exe = find_nvidia_smi()
        self.nvapi = NVAPIAdapter()

    def set_power_limit(self, watts: float) -> str:
        if not SAFETY.vendor_write_allowed():
            raise PermissionError(
                "Vendor writes are disabled by the safety policy. "
                "Enable them explicitly in the Safety configuration."
            )
        if not self.exe:
            raise RuntimeError("nvidia-smi was not found.")
        if watts <= 0:
            raise ValueError("Power limit must be positive.")
        current_limit = self.gpu.power_limit_w
        if current_limit is not None:
            # Do not permit a request beyond the configured relative safety envelope.
            maximum = current_limit * float(CONFIG["safety"]["max_power_percent"]) / 100.0
            if watts > maximum:
                raise ValueError(
                    f"Requested power limit {watts:.1f} W exceeds safety envelope "
                    f"of {maximum:.1f} W."
                )
        rc, out, err = run_cmd(
            [self.exe, "-i", str(self.gpu.index), "-pl", str(int(watts))], 5
        )
        if rc != 0:
            raise RuntimeError(err or out or "nvidia-smi rejected the power limit.")
        return out or "Power limit applied."

    def set_clock_offset(self, core: int, memory: int) -> str:
        SAFETY.validate_offsets(core, memory)
        if not SAFETY.vendor_write_allowed():
            raise PermissionError("Vendor writes are disabled by the safety policy.")
        if not self.nvapi.available:
            raise RuntimeError(
                "NVAPI was not detected. Clock-offset control remains disabled."
            )
        # Deliberately capability-gated. No undocumented NVAPI calls are guessed.
        raise RuntimeError(
            "NVAPI was detected, but no unsafe/undocumented clock-write signature "
            "is inferred. Use a vendor-approved NVAPI adapter implementation."
        )

    def set_fan(self, percent: int) -> str:
        SAFETY.validate_fan(percent)
        if not SAFETY.vendor_write_allowed():
            raise PermissionError("Vendor writes are disabled by the safety policy.")
        raise RuntimeError(
            "Generic NVIDIA fan writes are not enabled in this safe adapter."
        )

    def refresh(self) -> GPU:
        latest = detect_nvidia()
        for gpu in latest:
            if gpu.index == self.gpu.index:
                self.gpu = gpu
                break
        return self.gpu


class AMDBackend(VendorBackend):
    def __init__(self, gpu: GPU):
        super().__init__(gpu)
        self.adl = ADLAdapter()
        self.gpu.controls["adl_detected"] = self.adl.available

    def set_power_limit(self, watts: float) -> str:
        if not SAFETY.vendor_write_allowed():
            raise PermissionError("Vendor writes are disabled by the safety policy.")
        if not self.adl.available:
            raise RuntimeError("AMD ADL libraries were not detected.")
        raise RuntimeError(
            "ADL is detected, but no guessed function signature is used for writes. "
            "Install/use a tested vendor SDK adapter before enabling changes."
        )


class GenericBackend(VendorBackend):
    pass


def backend_for(gpu: GPU) -> VendorBackend:
    if gpu.vendor == "NVIDIA":
        return NvidiaBackend(gpu)
    if gpu.vendor == "AMD":
        return AMDBackend(gpu)
    return GenericBackend(gpu)


class NVAPIAdapter:
    """
    Conservative NVAPI presence detector.

    NVAPI is a vendor SDK with versioned C interfaces. The program detects the DLL
    but intentionally does not invent ABI/function signatures. A tested adapter
    can be plugged into this boundary without changing the governor.
    """

    def __init__(self):
        self.dll = None
        self.path = None
        for name in ("nvapi64.dll", "nvapi.dll"):
            try:
                self.dll = ctypes.WinDLL(name)
                self.path = name
                break
            except Exception:
                pass

    @property
    def available(self) -> bool:
        return self.dll is not None


class ADLAdapter:
    """Conservative AMD ADL DLL detector; write calls require a tested SDK layer."""

    def __init__(self):
        self.dll = None
        self.path = None
        for name in ("atiadlxx.dll", "atiadlxy.dll"):
            try:
                self.dll = ctypes.WinDLL(name)
                self.path = name
                break
            except Exception:
                pass

    @property
    def available(self) -> bool:
        return self.dll is not None


def map_affinity(value: str) -> list[int]:
    if psutil is None:
        return []
    count = psutil.cpu_count(logical=True) or 1
    if value == "low":
        return list(range(max(1, count // 4)))
    if value == "medium":
        return list(range(max(1, count // 2)))
    if value == "high":
        return list(range(max(1, int(count * 0.75))))
    return list(range(count))


def map_priority(value: str):
    if psutil is None:
        return None
    if platform.system().lower() == "windows":
        mapping = {
            "idle": psutil.IDLE_PRIORITY_CLASS,
            "below_normal": psutil.BELOW_NORMAL_PRIORITY_CLASS,
            "normal": psutil.NORMAL_PRIORITY_CLASS,
            "above_normal": psutil.ABOVE_NORMAL_PRIORITY_CLASS,
            "high": psutil.HIGH_PRIORITY_CLASS,
        }
        return mapping.get(value, psutil.NORMAL_PRIORITY_CLASS)
    mapping = {"idle": 19, "below_normal": 10, "normal": 0, "above_normal": -5, "high": -10}
    return mapping.get(value, 0)


def apply_cpu_profile(profile: dict[str, Any]) -> None:
    if psutil is None:
        return
    proc = psutil.Process(os.getpid())
    try:
        affinity = map_affinity(profile.get("cpu_affinity", "all"))
        if affinity:
            proc.cpu_affinity(affinity)
    except Exception as exc:
        print(f"[PROFILE] affinity failed: {exc}")
    try:
        priority = map_priority(profile.get("priority", "normal"))
        if priority is not None:
            proc.nice(priority)
    except Exception as exc:
        print(f"[PROFILE] priority failed: {exc}")


class TrendPredictor:
    """Small, dependency-free linear trend predictor for temperature/power."""

    def __init__(self, max_points: int = 30):
        self.max_points = max(5, int(max_points))
        self.samples: list[tuple[float, float, float]] = []
        self.lock = threading.Lock()

    def add(self, temperature: float | None, power: float | None) -> None:
        now = time.time()
        with self.lock:
            self.samples.append(
                (
                    now,
                    float(temperature) if temperature is not None else math.nan,
                    float(power) if power is not None else math.nan,
                )
            )
            self.samples = self.samples[-self.max_points:]

    @staticmethod
    def _forecast(points: list[tuple[float, float]], horizon: float) -> float | None:
        if len(points) < 5:
            return None
        t0 = points[0][0]
        xs = [p[0] - t0 for p in points]
        ys = [p[1] for p in points]
        if any(not math.isfinite(y) for y in ys):
            return None
        xm = statistics.fmean(xs)
        ym = statistics.fmean(ys)
        denom = sum((x - xm) ** 2 for x in xs)
        if denom <= 1e-9:
            return ys[-1]
        slope = sum((x - xm) * (y - ym) for x, y in zip(xs, ys)) / denom
        future_x = xs[-1] + horizon
        return ym + slope * (future_x - xm)

    def predict(self, horizon: float = 60.0) -> dict[str, float | None]:
        with self.lock:
            temps = [(t, temp) for t, temp, _ in self.samples]
            powers = [(t, power) for t, _, power in self.samples]
        return {
            "temperature_c": self._forecast(temps, horizon),
            "power_w": self._forecast(powers, horizon),
        }


class TelemetryStore:
    def __init__(self, maxlen: int = 600):
        from collections import deque
        self.items = deque(maxlen=maxlen)
        self.lock = threading.Lock()

    def add(self, snapshot: dict[str, Any]) -> None:
        with self.lock:
            self.items.append(snapshot)

    def recent(self, count: int = 60) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.items)[-count:]

    def latest(self) -> dict[str, Any] | None:
        with self.lock:
            return self.items[-1] if self.items else None


def get_telemetry_snapshot() -> dict[str, Any]:
    cpu = psutil.cpu_percent(interval=None) if psutil else 0.0
    mem = psutil.virtual_memory() if psutil else None
    gpu_info = get_gpu_telemetry_nvml()

    return {
        "timestamp": time.time(),
        "iso_time": time.strftime("%Y-%m-%dT%H:%M:%S"),
        "host": socket.gethostname(),
        "cpu_percent": round(float(cpu), 2),
        "mem_percent": round(float(mem.percent), 2) if mem else None,
        "mem_used_gb": round(mem.used / 1024**3, 3) if mem else None,
        "mem_total_gb": round(mem.total / 1024**3, 3) if mem else None,
        "gpu_backend": gpu_info.get("backend"),
        "gpu_devices": gpu_info.get("devices", []),
    }


class AsyncTelemetryEngine:
    """
    Runs asyncio in its own thread so GUI/main thread never blocks on telemetry.
    """

    def __init__(self, store: TelemetryStore, interval: float = 1.0):
        self.store = store
        self.interval = max(0.25, float(interval))
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None
        self.callbacks: list[Callable[[dict[str, Any]], None]] = []
        self.predictor = TrendPredictor(CONFIG["prediction"]["window"])

    def add_callback(self, callback: Callable[[dict[str, Any]], None]) -> None:
        self.callbacks.append(callback)

    def start(self) -> None:
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._thread_main, daemon=True, name="AsyncTelemetry"
        )
        self.thread.start()

    def _thread_main(self) -> None:
        try:
            asyncio.run(self._run())
        except Exception:
            traceback.print_exc()

    async def _run(self) -> None:
        while not self.stop_event.is_set():
            started = time.monotonic()
            snapshot = await asyncio.to_thread(get_telemetry_snapshot)

            devices = snapshot.get("gpu_devices", [])
            first = devices[0] if devices else {}
            self.predictor.add(first.get("temperature_c"), first.get("power_w"))
            snapshot["prediction"] = self.predictor.predict(
                CONFIG["prediction"]["horizon_seconds"]
            )
            self.store.add(snapshot)

            if CONFIG["telemetry"].get("persist", True):
                await asyncio.to_thread(self._persist, snapshot)

            for callback in tuple(self.callbacks):
                try:
                    callback(snapshot)
                except Exception:
                    traceback.print_exc()

            elapsed = time.monotonic() - started
            await asyncio.sleep(max(0.05, self.interval - elapsed))

    @staticmethod
    def _persist(snapshot: dict[str, Any]) -> None:
        try:
            with TELEMETRY_LOG.open("a", encoding="utf-8") as fh:
                fh.write(json.dumps(snapshot, separators=(",", ":")) + "\n")
        except Exception:
            pass

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=2.0)


class PluginManager:
    """
    Plugins are normal Python files in %USERPROFILE%\\GPUControlCenter\\plugins.

    Optional plugin contract:
        PLUGIN_NAME = "Example"
        def register(governor): ...
        def on_telemetry(snapshot): ...
        def on_command(command, payload): ...
    """

    def __init__(self, directory: Path):
        self.directory = directory
        self.modules: list[Any] = []

    def load(self, governor: Any) -> list[str]:
        if not CONFIG["plugins"].get("enabled", True):
            return []
        loaded = []
        for path in sorted(self.directory.glob("*.py")):
            if path.name.startswith("_"):
                continue
            try:
                spec = importlib.util.spec_from_file_location(
                    f"gpu_governor_plugin_{path.stem}", path
                )
                if not spec or not spec.loader:
                    continue
                module = importlib.util.module_from_spec(spec)
                sys.modules[spec.name] = module
                spec.loader.exec_module(module)
                register = getattr(module, "register", None)
                if callable(register):
                    register(governor)
                self.modules.append(module)
                loaded.append(path.name)
            except Exception as exc:
                print(f"[PLUGIN] {path.name}: {exc}")
        return loaded

    def telemetry(self, snapshot: dict[str, Any]) -> None:
        for module in tuple(self.modules):
            fn = getattr(module, "on_telemetry", None)
            if callable(fn):
                try:
                    fn(snapshot)
                except Exception:
                    traceback.print_exc()

    def command(self, command: str, payload: dict[str, Any]) -> Any:
        results = []
        for module in tuple(self.modules):
            fn = getattr(module, "on_command", None)
            if callable(fn):
                try:
                    results.append(fn(command, payload))
                except Exception:
                    traceback.print_exc()
        return results


class DistributedSync:
    """Simple opt-in HTTP telemetry/profile synchronization between trusted PCs."""

    def __init__(self, store: TelemetryStore, log: Callable[[str], None]):
        self.store = store
        self.log = log
        self.stop_event = threading.Event()
        self.thread: threading.Thread | None = None

    def start(self) -> None:
        if not CONFIG["sync"].get("enabled", False):
            return
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._loop, daemon=True, name="DistributedSync"
        )
        self.thread.start()

    def _loop(self) -> None:
        while not self.stop_event.is_set():
            for peer in list(CONFIG["sync"].get("peers", [])):
                try:
                    url = peer.rstrip("/") + "/api/telemetry/latest"
                    req = urllib.request.Request(url, headers={"User-Agent": APP_NAME})
                    with urllib.request.urlopen(req, timeout=2) as response:
                        data = json.loads(response.read().decode("utf-8"))
                    self.log(f"SYNC {peer}: received telemetry from {data.get('host')}")
                except Exception as exc:
                    self.log(f"SYNC {peer}: {exc}")
            self.stop_event.wait(max(1.0, float(CONFIG["sync"].get("interval", 5))))

    def stop(self) -> None:
        self.stop_event.set()
        if self.thread:
            self.thread.join(timeout=2.0)


class GovernorService:
    def __init__(self):
        self.store = TelemetryStore(CONFIG["telemetry"]["history_size"])
        self.telemetry = AsyncTelemetryEngine(
            self.store, CONFIG["telemetry"]["interval"]
        )
        self.plugins = PluginManager(Path(CONFIG["plugins"]["directory"]))
        self.sync = DistributedSync(self.store, self.log)
        self.gpus: list[GPU] = []
        self.backends: dict[int, VendorBackend] = {}
        self.mode = CONFIG.get("mode", "base")
        self.running = False
        self.callbacks: list[Callable[[str], None]] = []
        self.lock = threading.RLock()
        self._load_hardware()

    def log(self, message: str) -> None:
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {message}"
        print(line)
        for callback in tuple(self.callbacks):
            try:
                callback(line)
            except Exception:
                pass

    def add_log_callback(self, callback: Callable[[str], None]) -> None:
        self.callbacks.append(callback)

    def _load_hardware(self) -> None:
        self.gpus = detect_gpus()
        self.backends = {gpu.index: backend_for(gpu) for gpu in self.gpus}
        self.log(f"Detected {len(self.gpus)} GPU(s).")

    def start(self) -> None:
        with self.lock:
            if self.running:
                return
            self.running = True
            self._load_hardware()
            loaded = self.plugins.load(self)
            self.log(f"Plugins loaded: {len(loaded)}")
            self.telemetry.add_callback(self._on_telemetry)
            self.telemetry.start()
            self.sync.start()
            self.apply_mode(self.mode)
            self.log("Governor service started.")

    def _on_telemetry(self, snapshot: dict[str, Any]) -> None:
        self.plugins.telemetry(snapshot)
        devices = snapshot.get("gpu_devices", [])
        if devices:
            temp = devices[0].get("temperature_c")
            emergency = float(CONFIG["safety"]["emergency_temp_c"])
            if temp is not None and temp >= emergency:
                self.log(
                    f"EMERGENCY thermal threshold reached: {float(temp):.1f} C"
                )
                if self.mode == "turbo":
                    self.apply_mode("base")

    def stop(self) -> None:
        with self.lock:
            if not self.running:
                return
            self.running = False
            self.telemetry.stop()
            self.sync.stop()
            self.log("Governor service stopped.")

    def apply_mode(self, mode: str) -> None:
        mode = str(mode).lower()
        if mode not in {"base", "turbo", "auto"}:
            raise ValueError("Mode must be base, turbo, or auto.")
        self.mode = mode
        CONFIG["mode"] = mode
        if mode == "base":
            apply_cpu_profile(CONFIG["base_profile"])
            apply_gpu_timing_profile("eco")
        elif mode == "turbo":
            apply_cpu_profile(CONFIG["turbo_profile"])
            apply_gpu_timing_profile("performance")
        else:
            self.log("Auto mode enabled; profiles will follow telemetry.")
        save_config(CONFIG)

    def auto_decide(self, snapshot: dict[str, Any]) -> str:
        if self.mode != "auto":
            return self.mode
        cpu = float(snapshot.get("cpu_percent") or 0)
        devices = snapshot.get("gpu_devices", [])
        gpu = max(
            [float(d.get("gpu_util_percent") or 0) for d in devices] or [0.0]
        )
        auto = CONFIG["auto_profile"]
        if cpu < auto["cpu_idle_threshold"] and gpu < auto["gpu_idle_threshold"]:
            apply_cpu_profile({
                "cpu_affinity": auto["cpu_affinity_idle"],
                "priority": auto["priority_idle"],
            })
            apply_gpu_timing_profile(auto["gpu_timing_idle"])
            return "idle"
        if cpu > auto["cpu_active_threshold"] or gpu > auto["gpu_active_threshold"]:
            apply_cpu_profile({
                "cpu_affinity": auto["cpu_affinity_active"],
                "priority": auto["priority_active"],
            })
            apply_gpu_timing_profile(auto["gpu_timing_active"])
            return "active"
        return "balanced"

    def set_power(self, gpu_index: int, watts: float) -> str:
        backend = self.backends[gpu_index]
        return backend.set_power_limit(watts)

    def set_offsets(self, gpu_index: int, core: int, memory: int) -> str:
        SAFETY.validate_offsets(core, memory)
        return self.backends[gpu_index].set_clock_offset(core, memory)

    def latest(self) -> dict[str, Any]:
        return self.store.latest() or {"status": "no telemetry yet"}

    def status(self) -> dict[str, Any]:
        return {
            "application": APP_NAME,
            "version": APP_VERSION,
            "running": self.running,
            "mode": self.mode,
            "host": socket.gethostname(),
            "gpu_count": len(self.gpus),
            "gpus": [asdict(g) for g in self.gpus],
            "nvapi": any(
                isinstance(b, NvidiaBackend) and b.nvapi.available
                for b in self.backends.values()
            ),
            "adl": any(
                isinstance(b, AMDBackend) and b.adl.available
                for b in self.backends.values()
            ),
            "api": {
                "aiohttp": aiohttp is not None,
                "websockets": websockets is not None,
                "host": CONFIG["daemon"]["host"],
                "port": CONFIG["daemon"]["port"],
            },
        }


def apply_gpu_timing_profile(profile_name: str) -> None:
    # Profiles remain conceptual until a tested vendor backend is selected.
    print(f"[GPU_PROFILE] {profile_name}: safe policy profile selected.")


class BeastModeWorker(threading.Thread):
    def __init__(self, intensity: float, stop_event: threading.Event, idx: int):
        super().__init__(daemon=True, name=f"BeastWorker-{idx}")
        self.intensity = max(0.0, min(1.0, intensity))
        self.stop_event = stop_event
        self.idx = idx

    def run(self) -> None:
        while not self.stop_event.is_set():
            work_duration = self.intensity * 0.25
            end = time.monotonic() + work_duration
            while time.monotonic() < end and not self.stop_event.is_set():
                value = 0
                for i in range(3000):
                    value += i * i
            self.stop_event.wait(max(0.05, 0.25 * (1 - self.intensity)))


class BeastModeController:
    def __init__(self, cfg: dict[str, Any]):
        self.cfg = cfg
        self.stop_event = threading.Event()
        self.workers: list[BeastModeWorker] = []

    def start(self) -> None:
        if self.workers:
            return
        for i in range(int(self.cfg.get("worker_threads", 4))):
            worker = BeastModeWorker(
                float(self.cfg.get("workload_intensity", 0.2)),
                self.stop_event,
                i,
            )
            self.workers.append(worker)
            worker.start()

    def stop(self) -> None:
        if not self.workers:
            return
        self.stop_event.set()
        for worker in self.workers:
            worker.join(timeout=1)
        self.workers.clear()
        self.stop_event = threading.Event()


BEAST_CONTROLLER = BeastModeController(CONFIG["beast_mode"])


class APIServer:
    """Optional local REST/WebSocket control plane."""

    def __init__(self, service: GovernorService):
        self.service = service
        self.loop: asyncio.AbstractEventLoop | None = None
        self.thread: threading.Thread | None = None
        self.stop_event = threading.Event()
        self.ws_clients: set[Any] = set()

    def start(self) -> None:
        if not CONFIG["network"].get("enabled", True):
            return
        if aiohttp is None:
            self.service.log("REST API unavailable: install aiohttp.")
            return
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(
            target=self._thread_main, daemon=True, name="APIServer"
        )
        self.thread.start()

    def _thread_main(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        try:
            self.loop.run_until_complete(self._run())
        except Exception as exc:
            self.service.log(f"API server stopped: {exc}")
        finally:
            self.loop.close()

    def _authorized(self, request) -> bool:
        token = str(CONFIG["network"].get("api_token", ""))
        if not token:
            return True
        return request.headers.get("X-API-Token", "") == token

    async def _run(self) -> None:
        app = aiohttp.web.Application()
        app.add_routes([
            aiohttp.web.get("/api/status", self.http_status),
            aiohttp.web.get("/api/telemetry/latest", self.http_latest),
            aiohttp.web.get("/api/telemetry/history", self.http_history),
            aiohttp.web.get("/api/gpus", self.http_gpus),
            aiohttp.web.post("/api/mode", self.http_mode),
            aiohttp.web.post("/api/power", self.http_power),
            aiohttp.web.post("/api/offsets", self.http_offsets),
            aiohttp.web.post("/api/profile", self.http_profile),
        ])
        runner = aiohttp.web.AppRunner(app)
        await runner.setup()

        host = CONFIG["daemon"]["host"]
        if not CONFIG["network"].get("allow_remote", False):
            host = "127.0.0.1"
        port = int(CONFIG["daemon"]["port"])
        site = aiohttp.web.TCPSite(runner, host, port)
        await site.start()
        self.service.log(f"REST API listening on {host}:{port}")

        if websockets is not None:
            asyncio.create_task(self._websocket_server())

        while not self.stop_event.is_set():
            await asyncio.sleep(0.25)
        await runner.cleanup()

    async def _websocket_server(self) -> None:
        port = int(CONFIG["daemon"]["websocket_port"])
        host = CONFIG["daemon"]["host"]
        if not CONFIG["network"].get("allow_remote", False):
            host = "127.0.0.1"

        async def handler(websocket):
            self.ws_clients.add(websocket)
            try:
                await websocket.send(json.dumps(self.service.latest()))
                while not self.stop_event.is_set():
                    await asyncio.sleep(1)
                    await websocket.send(json.dumps(self.service.latest()))
            except Exception:
                pass
            finally:
                self.ws_clients.discard(websocket)

        try:
            async with websockets.serve(handler, host, port):
                self.service.log(f"WebSocket telemetry on {host}:{port}")
                while not self.stop_event.is_set():
                    await asyncio.sleep(0.5)
        except Exception as exc:
            self.service.log(f"WebSocket disabled: {exc}")

    async def _json(self, request):
        if not self._authorized(request):
            raise aiohttp.web.HTTPUnauthorized(text="Invalid API token")
        try:
            return await request.json()
        except Exception:
            return {}

    async def http_status(self, request):
        return aiohttp.web.json_response(self.service.status())

    async def http_latest(self, request):
        return aiohttp.web.json_response(self.service.latest())

    async def http_history(self, request):
        count = min(600, max(1, int(request.query.get("count", "60"))))
        return aiohttp.web.json_response(self.service.store.recent(count))

    async def http_gpus(self, request):
        return aiohttp.web.json_response([asdict(g) for g in self.service.gpus])

    async def http_mode(self, request):
        data = await self._json(request)
        self.service.apply_mode(data.get("mode", "base"))
        return aiohttp.web.json_response({"ok": True, "mode": self.service.mode})

    async def http_power(self, request):
        data = await self._json(request)
        idx = int(data["gpu_index"])
        watts = float(data["watts"])
        result = await asyncio.to_thread(self.service.set_power, idx, watts)
        return aiohttp.web.json_response({"ok": True, "result": result})

    async def http_offsets(self, request):
        data = await self._json(request)
        idx = int(data["gpu_index"])
        core = int(data.get("core", 0))
        memory = int(data.get("memory", 0))
        result = await asyncio.to_thread(self.service.set_offsets, idx, core, memory)
        return aiohttp.web.json_response({"ok": True, "result": result})

    async def http_profile(self, request):
        data = await self._json(request)
        if not CONFIG["sync"].get("share_profiles", False):
            raise aiohttp.web.HTTPForbidden(text="Profile sharing is disabled.")
        name = str(data.get("name", "remote_profile.json"))
        safe_name = Path(name).name
        path = PROFILE_DIR / safe_name
        path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        return aiohttp.web.json_response({"ok": True, "path": str(path)})

    def stop(self) -> None:
        self.stop_event.set()
        if self.loop and self.loop.is_running():
            self.loop.call_soon_threadsafe(lambda: None)
        if self.thread:
            self.thread.join(timeout=2)


class DaemonRunner:
    def __init__(self, service: GovernorService):
        self.service = service
        self.api = APIServer(service)
        self.stop_event = threading.Event()

    def run(self) -> None:
        self.service.start()
        self.api.start()
        self.service.log("Persistent daemon mode active. Press Ctrl+C to stop.")
        try:
            while not self.stop_event.wait(1):
                if self.service.mode == "auto":
                    snap = self.service.latest()
                    if snap:
                        state = self.service.auto_decide(snap)
                        self.service.log(f"Auto state: {state}")
        except KeyboardInterrupt:
            pass
        finally:
            self.stop()

    def stop(self) -> None:
        self.api.stop()
        self.service.stop()
        BEAST_CONTROLLER.stop()


def export_report(service: GovernorService, path: Path) -> None:
    latest = service.latest()
    lines = [
        APP_NAME,
        f"Version: {APP_VERSION}",
        "=" * 78,
        json.dumps(service.status(), indent=2),
        "",
        "Latest telemetry:",
        json.dumps(latest, indent=2),
    ]
    path.write_text("\n".join(lines), encoding="utf-8")


# ----------------------------- PyQt6 GUI -----------------------------------

if PYQT_AVAILABLE:
    from PyQt6.QtCore import Qt, QTimer
    from PyQt6.QtGui import QFont, QAction
    from PyQt6.QtWidgets import (
        QApplication, QCheckBox, QComboBox, QDoubleSpinBox, QFileDialog,
        QFormLayout, QGridLayout, QGroupBox, QHBoxLayout, QLabel, QLineEdit,
        QMainWindow, QMessageBox, QPushButton, QPlainTextEdit, QSpinBox,
        QTabWidget, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
    )

    class MainWindow(QMainWindow):
        def __init__(self, service: GovernorService, api: APIServer):
            super().__init__()
            self.service = service
            self.api = api
            self.setWindowTitle(f"{APP_NAME} {APP_VERSION}")
            self.resize(1280, 820)
            self.setMinimumSize(1000, 650)
            self.service.add_log_callback(self.append_log)
            self.build_ui()
            self.refresh_gpus()
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.refresh_view)
            self.timer.start(500)

        def build_ui(self):
            central = QWidget()
            self.setCentralWidget(central)
            root = QVBoxLayout(central)

            header = QHBoxLayout()
            title = QLabel(APP_NAME)
            title.setFont(QFont("Segoe UI", 20, QFont.Weight.Bold))
            header.addWidget(title)
            header.addStretch()

            self.status_label = QLabel("Stopped")
            header.addWidget(self.status_label)
            start = QPushButton("Start Governor")
            start.clicked.connect(self.start_service)
            header.addWidget(start)
            stop = QPushButton("Stop")
            stop.clicked.connect(self.stop_service)
            header.addWidget(stop)
            detect = QPushButton("Detect GPUs")
            detect.clicked.connect(self.refresh_gpus)
            header.addWidget(detect)
            root.addLayout(header)

            self.tabs = QTabWidget()
            root.addWidget(self.tabs)

            self.build_monitor_tab()
            self.build_controls_tab()
            self.build_profiles_tab()
            self.build_network_tab()
            self.build_plugins_tab()
            self.build_diagnostics_tab()

        def build_monitor_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)
            grid = QGridLayout()

            self.cpu_label = QLabel("CPU: --")
            self.mem_label = QLabel("Memory: --")
            self.gpu_label = QLabel("GPU: --")
            self.pred_label = QLabel("Prediction: --")
            for row, widget in enumerate(
                [self.cpu_label, self.mem_label, self.gpu_label, self.pred_label]
            ):
                widget.setFont(QFont("Segoe UI", 12))
                grid.addWidget(widget, row, 0)

            layout.addLayout(grid)
            self.telemetry_text = QPlainTextEdit()
            self.telemetry_text.setReadOnly(True)
            layout.addWidget(self.telemetry_text)
            self.tabs.addTab(tab, "Live Telemetry")

        def build_controls_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)

            mode_box = QGroupBox("Governor Mode")
            mode_layout = QHBoxLayout(mode_box)
            self.mode_combo = QComboBox()
            self.mode_combo.addItems(["base", "turbo", "auto"])
            self.mode_combo.setCurrentText(self.service.mode)
            mode_layout.addWidget(self.mode_combo)
            apply_mode_btn = QPushButton("Apply Mode")
            apply_mode_btn.clicked.connect(
                lambda: self.apply_mode(self.mode_combo.currentText())
            )
            mode_layout.addWidget(apply_mode_btn)
            layout.addWidget(mode_box)

            gpu_box = QGroupBox("GPU Control")
            form = QFormLayout(gpu_box)
            self.gpu_combo = QComboBox()
            form.addRow("GPU:", self.gpu_combo)

            self.power_spin = QDoubleSpinBox()
            self.power_spin.setRange(1, 10000)
            self.power_spin.setDecimals(1)
            form.addRow("Power limit (W):", self.power_spin)

            self.core_spin = QSpinBox()
            self.core_spin.setRange(-300, 300)
            form.addRow("Core offset (MHz):", self.core_spin)

            self.mem_spin = QSpinBox()
            self.mem_spin.setRange(-1000, 1000)
            form.addRow("Memory offset (MHz):", self.mem_spin)

            apply_power_btn = QPushButton("Apply Power Limit")
            apply_power_btn.clicked.connect(self.apply_power)
            form.addRow(apply_power_btn)

            apply_offsets_btn = QPushButton("Apply Clock Offsets")
            apply_offsets_btn.clicked.connect(self.apply_offsets)
            form.addRow(apply_offsets_btn)

            self.vendor_status = QLabel("Vendor controls are safety-gated.")
            self.vendor_status.setWordWrap(True)
            form.addRow(self.vendor_status)
            layout.addWidget(gpu_box)

            self.beast_check = QCheckBox("Enable Beast Mode")
            self.beast_check.setChecked(bool(CONFIG["beast_mode_enabled"]))
            self.beast_check.toggled.connect(self.toggle_beast)
            layout.addWidget(self.beast_check)
            layout.addStretch()
            self.tabs.addTab(tab, "Controls")

        def build_profiles_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)
            buttons = QHBoxLayout()

            save = QPushButton("Save Profile")
            save.clicked.connect(self.save_profile)
            buttons.addWidget(save)

            load = QPushButton("Load Profile")
            load.clicked.connect(self.load_profile)
            buttons.addWidget(load)

            export = QPushButton("Export Report")
            export.clicked.connect(self.export_report)
            buttons.addWidget(export)
            buttons.addStretch()

            layout.addLayout(buttons)
            self.profile_text = QPlainTextEdit()
            layout.addWidget(self.profile_text)
            self.tabs.addTab(tab, "Profiles")

        def build_network_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)
            self.api_check = QCheckBox("Enable REST/WebSocket API")
            self.api_check.setChecked(bool(CONFIG["network"]["enabled"]))
            layout.addWidget(self.api_check)

            self.remote_check = QCheckBox("Allow remote LAN clients")
            self.remote_check.setChecked(bool(CONFIG["network"]["allow_remote"]))
            layout.addWidget(self.remote_check)

            form = QFormLayout()
            self.host_edit = QLineEdit(str(CONFIG["daemon"]["host"]))
            self.port_spin = QSpinBox()
            self.port_spin.setRange(1, 65535)
            self.port_spin.setValue(int(CONFIG["daemon"]["port"]))
            self.token_edit = QLineEdit(str(CONFIG["network"]["api_token"]))
            self.token_edit.setEchoMode(QLineEdit.EchoMode.Password)
            form.addRow("Host:", self.host_edit)
            form.addRow("REST port:", self.port_spin)
            form.addRow("API token:", self.token_edit)
            layout.addLayout(form)

            save = QPushButton("Save Network Settings")
            save.clicked.connect(self.save_network)
            layout.addWidget(save)
            layout.addWidget(QLabel(
                "For safety, remote access defaults to disabled. Use an API token "
                "when exposing the API beyond localhost."
            ))
            layout.addStretch()
            self.tabs.addTab(tab, "Remote API")

        def build_plugins_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)
            layout.addWidget(QLabel(f"Plugin directory:\n{PLUGIN_DIR}"))
            self.plugin_text = QPlainTextEdit()
            self.plugin_text.setReadOnly(True)
            layout.addWidget(self.plugin_text)
            reload_btn = QPushButton("Reload Plugins")
            reload_btn.clicked.connect(self.reload_plugins)
            layout.addWidget(reload_btn)
            self.tabs.addTab(tab, "Plugins")

        def build_diagnostics_tab(self):
            tab = QWidget()
            layout = QVBoxLayout(tab)
            self.log_text = QPlainTextEdit()
            self.log_text.setReadOnly(True)
            layout.addWidget(self.log_text)
            self.tabs.addTab(tab, "Diagnostics")

        def refresh_gpus(self):
            self.service._load_hardware()
            self.gpu_combo.clear()
            for g in self.service.gpus:
                self.gpu_combo.addItem(f"GPU {g.index}: {g.vendor} - {g.name}", g.index)
            if self.service.gpus:
                self.update_vendor_status()

        def update_vendor_status(self):
            idx = self.gpu_combo.currentData()
            if idx is None:
                return
            backend = self.service.backends.get(int(idx))
            if not backend:
                return
            caps = backend.capabilities()
            self.vendor_status.setText(
                f"Backend: {type(backend).__name__}\n"
                f"Capabilities: {', '.join(k for k, v in caps.items() if v) or 'telemetry only'}\n"
                f"Vendor writes: {'ENABLED' if SAFETY.vendor_write_allowed() else 'DISABLED'}"
            )

        def start_service(self):
            self.service.start()
            self.api.start()

        def stop_service(self):
            self.api.stop()
            self.service.stop()
            BEAST_CONTROLLER.stop()

        def apply_mode(self, mode: str):
            try:
                self.service.apply_mode(mode)
                self.mode_combo.setCurrentText(mode)
            except Exception as exc:
                QMessageBox.warning(self, "Mode error", str(exc))

        def apply_power(self):
            idx = self.gpu_combo.currentData()
            if idx is None:
                return
            try:
                result = self.service.set_power(int(idx), self.power_spin.value())
                QMessageBox.information(self, "Power", result)
            except Exception as exc:
                QMessageBox.warning(self, "Power request rejected", str(exc))

        def apply_offsets(self):
            idx = self.gpu_combo.currentData()
            if idx is None:
                return
            try:
                result = self.service.set_offsets(
                    int(idx), self.core_spin.value(), self.mem_spin.value()
                )
                QMessageBox.information(self, "Offsets", result)
            except Exception as exc:
                QMessageBox.warning(self, "Offset request rejected", str(exc))

        def toggle_beast(self, enabled: bool):
            CONFIG["beast_mode_enabled"] = enabled
            save_config(CONFIG)
            if enabled:
                BEAST_CONTROLLER.start()
            else:
                BEAST_CONTROLLER.stop()

        def save_profile(self):
            path, _ = QFileDialog.getSaveFileName(
                self, "Save Profile", str(PROFILE_DIR), "JSON (*.json)"
            )
            if not path:
                return
            data = {
                "application": APP_NAME,
                "version": APP_VERSION,
                "created": time.strftime("%Y-%m-%d %H:%M:%S"),
                "mode": self.service.mode,
                "gpu": [asdict(g) for g in self.service.gpus],
                "config": CONFIG,
            }
            Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.profile_text.setPlainText(json.dumps(data, indent=2))

        def load_profile(self):
            path, _ = QFileDialog.getOpenFileName(
                self, "Load Profile", str(PROFILE_DIR), "JSON (*.json)"
            )
            if not path:
                return
            try:
                data = json.loads(Path(path).read_text(encoding="utf-8"))
                merged = deep_merge(DEFAULT_CONFIG, data.get("config", {}))
                CONFIG.clear()
                CONFIG.update(merged)
                save_config(CONFIG)
                self.service.apply_mode(CONFIG.get("mode", "base"))
                self.profile_text.setPlainText(json.dumps(data, indent=2))
            except Exception as exc:
                QMessageBox.warning(self, "Profile error", str(exc))

        def export_report(self):
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Report", str(PROFILE_DIR), "Text (*.txt)"
            )
            if path:
                export_report(self.service, Path(path))

        def save_network(self):
            CONFIG["network"]["enabled"] = self.api_check.isChecked()
            CONFIG["network"]["allow_remote"] = self.remote_check.isChecked()
            CONFIG["daemon"]["host"] = self.host_edit.text().strip() or "127.0.0.1"
            CONFIG["daemon"]["port"] = self.port_spin.value()
            CONFIG["network"]["api_token"] = self.token_edit.text()
            save_config(CONFIG)
            QMessageBox.information(
                self, "Saved",
                "Network settings saved. Restart the API for port/host changes."
            )

        def reload_plugins(self):
            self.service.plugins.modules.clear()
            loaded = self.service.plugins.load(self.service)
            self.plugin_text.setPlainText(
                "\n".join(loaded) if loaded else "No plugins loaded."
            )

        def append_log(self, message: str):
            if hasattr(self, "log_text"):
                self.log_text.appendPlainText(message)

        def refresh_view(self):
            snap = self.service.latest()
            if not snap or "cpu_percent" not in snap:
                return
            self.status_label.setText(
                "Running" if self.service.running else "Stopped"
            )
            self.cpu_label.setText(f"CPU: {snap.get('cpu_percent', '--')} %")
            self.mem_label.setText(f"Memory: {snap.get('mem_percent', '--')} %")
            devices = snap.get("gpu_devices", [])
            if devices:
                d = devices[0]
                self.gpu_label.setText(
                    f"GPU: {d.get('name')} | Util {d.get('gpu_util_percent')} % | "
                    f"Temp {d.get('temperature_c', '--')} C | "
                    f"Power {d.get('power_w', '--')} W"
                )
                pred = snap.get("prediction", {})
                self.pred_label.setText(
                    f"Forecast +{CONFIG['prediction']['horizon_seconds']}s: "
                    f"Temp {pred.get('temperature_c', '--')} C | "
                    f"Power {pred.get('power_w', '--')} W"
                )
            else:
                self.gpu_label.setText("GPU: telemetry unavailable")
            self.telemetry_text.setPlainText(json.dumps(snap, indent=2))
            self.update_vendor_status()

        def closeEvent(self, event):
            self.api.stop()
            self.service.stop()
            BEAST_CONTROLLER.stop()
            event.accept()


def run_gui() -> int:
    if not PYQT_AVAILABLE:
        print(
            "PyQt6 is not installed. Install with:\n"
            "  python -m pip install PyQt6 psutil pynvml aiohttp websockets"
        )
        return 2

    # Enable modern Windows DPI behavior before creating QApplication.
    os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName("GPUControlCenter")

    service = GovernorService()
    api = APIServer(service)
    window = MainWindow(service, api)
    window.show()

    # Start telemetry automatically so the GUI is useful immediately.
    service.start()
    api.start()
    return app.exec()


def main() -> int:
    if platform.system() != "Windows":
        print("Warning: this application is designed for Windows.")

    args = set(sys.argv[1:])
    if "--install-deps" in args:
        packages = ["PyQt6", "psutil", "pynvml", "aiohttp", "websockets"]
        subprocess.check_call([sys.executable, "-m", "pip", "install", *packages])
        return 0

    service = GovernorService()

    if "--daemon" in args or CONFIG["daemon"].get("enabled", False):
        DaemonRunner(service).run()
        return 0

    if "--detect" in args:
        print(json.dumps(service.status(), indent=2))
        return 0

    if "--export" in args:
        path = Path(args.pop()) if len(sys.argv) > 2 else PROFILE_DIR / "gpu_report.txt"
        service.start()
        time.sleep(1)
        export_report(service, path)
        service.stop()
        print(path)
        return 0

    return run_gui()


if __name__ == "__main__":
    raise SystemExit(main())
