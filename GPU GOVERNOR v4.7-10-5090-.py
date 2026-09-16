#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Universal GPU Control Center v4.9
Safe Tuning + VRAM Stress + Curve Visualizer + Factory Reset + FP32 FLOPS Governor

Upgrades over v4.6:
- Safe "auto undervolt" via dynamic power-limit tuning:
  - Uses prediction + thermal PID + workload classification
  - Lowers power limits when temps are high or risk is elevated
  - Never exceeds configured safety caps
- VRAM stress tester:
  - Runs controlled VRAM workloads (read/write patterns)
  - Time-bounded, temperature-guarded, aborts on risk
- Curve visualizer graphs (GUI):
  - Visualizes fan and power curves
  - Uses simple plotting in PyQt6 (no external web stack)
- Factory reset:
  - Restores DEFAULT_CONFIG
  - Clears overrides, curves, profiles back to baseline
  - Provides REST endpoint + GUI button

Still safe:
- No direct voltage writes
- No direct frequency curve hacks
- No boost/overvolt driver tricks
- Only NVML power limit + fan stubs by default
- FP32 FLOPS is estimated from hardware topology and clock; it is not a guaranteed measured workload FLOPS rate
- Optional NVML GPU clock lock is disabled by default and guarded by safety settings
"""

from __future__ import annotations

import asyncio
import contextlib
import traceback
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
APP_VERSION = 4.9
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
        "allow_vendor_writes": True,
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
        "peers": [],
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

    "benchmark": {"enabled": True, "interval_seconds": 30.0, "duration_seconds": 0.75, "matrix_size": 512, "warmup_iterations": 2, "iterations": 5, "max_temp_c": 82.0},
    "fan_learning": {"enabled": True, "min_temp_c": 35.0, "max_temp_c": 88.0, "min_fan_percent": 25.0, "max_fan_percent": 100.0, "learning_rate": 0.08, "apply_learned_curve": False},
    "adaptive_undervolt": {"enabled": True, "learning_rate": 0.05, "target_temp_c": 78.0, "thermal_ceiling_c": 84.0, "max_power_reduction_percent": 20.0, "min_power_percent": 60.0, "stability_window": 20, "apply_automatically": False},
    "cluster": {"enabled": True, "shared_secret": "", "broadcast_timeout_seconds": 3.0, "max_history_samples": 120},
    "plugin_sandbox": {"enabled": True, "timeout_seconds": 2.0, "max_restarts": 3},
    "flops": {
        "enabled": True,
        "mode": "soft_target",
        "precision": "fp32",
        "default_target_tflops": 0.0,
        "min_target_tflops": 0.1,
        "max_target_tflops": 200.0,
        "control_margin_percent": 5.0,
        "update_interval": 1.0,
        "use_clock_lock": False,
        "min_clock_mhz": 300,
        "max_clock_mhz": 0,
        "thermal_override_c": 80.0,
        "emergency_temp_c": 88.0,
        "targets": {},
    },
    "tuning": {
        "aggression": "balanced",
        "gpu_overrides": {},
        "auto_undervolt": {
            "enabled": True,
            "max_reduction_percent": 25.0,
            "risk_threshold": 0.6,
            "temp_threshold_c": 80.0,
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
    "profiles": {
        "gaming": {
            "power_target_percent": 105,
            "fan_target_percent": 70,
            "aggression": "aggressive",
        },
        "compute": {
            "power_target_percent": 110,
            "fan_target_percent": 80,
            "aggression": "extreme",
        },
        "silent": {
            "power_target_percent": 85,
            "fan_target_percent": 35,
            "aggression": "eco",
        },
        "custom": {
            "power_target_percent": 95,
            "fan_target_percent": 55,
            "aggression": "balanced",
        },
    },
    "curves": {
        "fan": {
            "points": [
                [30, 25],
                [40, 35],
                [50, 45],
                [60, 60],
                [70, 75],
                [80, 90],
            ]
        },
        "power": {
            "points": [
                [10, 80],
                [30, 90],
                [50, 100],
                [70, 105],
                [90, 110],
            ]
        },
    },
    "thermal_pid": {
        "enabled": True,
        "target_temp_c": 75.0,
        "kp": 0.8,
        "ki": 0.05,
        "kd": 0.2,
        "integral_limit": 50.0,
    },
    "vram_engine": {
        "enabled": True,
        "backend": "auto",
    },
    "vram_stress": {
        "enabled": True,
        "max_duration_sec": 120,
        "max_temp_c": 88.0,
        "buffer_size_mb": 512,
        "pattern_rounds": 5,
    },
    "elevation": {
        "auto_elevate": True,
        "windows_only": True,
    },
    "ml": {
        "enabled": True,
        "thermal": {
            "learning_rate": 0.01,
            "max_samples": 2000,
        },
        "workload": {
            "idle_threshold": 10.0,
            "light_threshold": 30.0,
            "gaming_threshold": 70.0,
            "compute_threshold": 90.0,
        },
        "anomaly": {
            "z_threshold": 3.0,
            "window": 120,
        },
        "dl": {
            "enabled": True,
            "hidden_size": 8,
            "learning_rate": 0.005,
            "history_len": 10,
        },
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
        print(f"[CONFIG] saved to {CONFIG_PATH}")
    except Exception as exc:
        print(f"[CONFIG] save failed: {exc}")


def factory_reset() -> None:
    """
    Restore configuration to DEFAULT_CONFIG and clear overrides.
    This is the "safe baseline" reset, not a hardware VBIOS reset.
    """
    global CONFIG
    CONFIG = json.loads(json.dumps(DEFAULT_CONFIG))
    save_config(CONFIG)
    print("[FACTORY] configuration reset to DEFAULT_CONFIG")


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
numba = optional_import("numba")
cupy = optional_import("cupy")
PYQT_AVAILABLE = optional_import("PyQt6") is not None

try:
    import numpy as np
    from numba import cuda
    CUDA_AVAILABLE = cuda.is_available()
except Exception:
    np = None
    cuda = None
    CUDA_AVAILABLE = False


def is_windows() -> bool:
    return os.name == "nt"


def is_admin() -> bool:
    if not is_windows():
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_elevated_if_needed() -> None:
    if not CONFIG.get("elevation", {}).get("auto_elevate", True):
        return
    if not is_windows():
        return
    if is_admin():
        return
    try:
        import ctypes
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            sys.executable,
            params,
            None,
            1,
        )
        print("[ELEVATION] Relaunching elevated...")
        sys.exit(0)
    except Exception as e:
        print(f"[ELEVATION] failed: {e}")


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



# ---------------------------------------------------------------------------
# FLOPS / FP32 PERFORMANCE GOVERNOR
# ---------------------------------------------------------------------------
# FLOPS is not a directly programmable hardware register. This layer estimates
# theoretical FP32 throughput from SM count, FP32 lanes/SM, and active clock,
# then treats a requested TFLOPS value as a performance envelope. Actual
# application FLOPS depends on instruction mix, occupancy, memory bandwidth,
# tensor usage, compiler scheduling, and workload.
#
# Control is intentionally conservative:
#   * power-limit control is the universal fallback for NVIDIA GPUs;
#   * optional NVML clock locking is OFF by default and only used when the
#     installed NVML binding/driver explicitly exposes the API;
#   * all targets are clamped by configured safety limits;
#   * thermal/emergency conditions override performance requests.

def _safe_float(value: Any, default: float = 0.0) -> float:
    try:
        value = float(value)
        return value if math.isfinite(value) else default
    except (TypeError, ValueError):
        return default


def _infer_cores_per_sm(name: str, compute_capability: Optional[tuple[int, int]]) -> int:
    n = (name or "").lower()

    # NVIDIA architecture heuristics. These are only used when NVML does not
    # expose a direct FP32-core count.
    if any(k in n for k in ("rtx 50", "blackwell", "b100", "b200", "gb10")):
        return 128
    if any(k in n for k in ("rtx 40", "ada lovelace", "l40", "l4")):
        return 128
    if any(k in n for k in ("rtx 30", "ampere", "a100", "a10", "a30", "a40")):
        return 128
    if any(k in n for k in ("rtx 20", "gtx 16", "t4", "turing")):
        return 64
    if any(k in n for k in ("gtx 10", "pascal", "p100", "p40", "p4")):
        return 128
    if any(k in n for k in ("volta", "v100")):
        return 64
    if any(k in n for k in ("maxwell", "gtx 9", "m40", "m60")):
        return 128

    if compute_capability:
        major, _minor = compute_capability
        if major >= 8:
            return 128
        if major == 7:
            return 64
        if major == 6:
            return 128
        if major == 5:
            return 128

    # Conservative fallback for unknown NVIDIA devices.
    return 64


def estimate_fp32_tflops(
    sm_count: Optional[int],
    cores_per_sm: Optional[int],
    clock_mhz: Optional[float],
) -> float:
    """Theoretical FP32 FMA peak: SMs * lanes/SM * clock * 2."""
    sm = _safe_float(sm_count)
    cores = _safe_float(cores_per_sm)
    clock_hz = _safe_float(clock_mhz) * 1_000_000.0
    if sm <= 0 or cores <= 0 or clock_hz <= 0:
        return 0.0
    return (sm * cores * clock_hz * 2.0) / 1_000_000_000_000.0


class FlopsGovernor:
    """Safe TFLOPS target governor with telemetry, estimation and controls."""

    def __init__(self, cfg: dict[str, Any], nvml_backend: Optional["NvmlBackend"]) -> None:
        self.cfg = cfg
        self.nvml_backend = nvml_backend
        self._calibration: Dict[int, float] = {}
        self._last_apply: Dict[int, float] = {}
        self._last_state: Dict[int, dict[str, Any]] = {}
        self._lock = threading.Lock()

    def set_benchmark_engine(self, engine) -> None:
        self.benchmark_engine = engine

    def enabled(self) -> bool:
        return bool(self.cfg.get("enabled", True))

    def calibrate(self, gpu_index: int) -> dict[str, Any]:
        if getattr(self, "benchmark_engine", None) is None:
            return {"status": "unavailable", "reason": "benchmark_engine_not_configured"}
        result = self.benchmark_engine.run(gpu_index)
        measured = _safe_float(result.get("measured_fp32_tflops"), 0.0)
        theoretical = _safe_float(self._device_info(gpu_index).get("fp32_peak_tflops"), 0.0)
        if measured > 0 and theoretical > 0:
            self._calibration[gpu_index] = max(0.05, min(1.25, measured / theoretical))
            result["calibration_factor"] = self._calibration[gpu_index]
        return result

    def _target_for(self, gpu_index: int) -> float:
        targets = self.cfg.get("targets", {})
        raw = targets.get(str(gpu_index), self.cfg.get("default_target_tflops", 0.0))
        target = _safe_float(raw, 0.0)
        lo = _safe_float(self.cfg.get("min_target_tflops", 0.1), 0.1)
        hi = _safe_float(self.cfg.get("max_target_tflops", 200.0), 200.0)
        if target <= 0:
            return 0.0
        return max(lo, min(target, hi))

    def set_target(self, gpu_index: int, target_tflops: float, enabled: Optional[bool] = None) -> dict[str, Any]:
        target = _safe_float(target_tflops, 0.0)
        lo = _safe_float(self.cfg.get("min_target_tflops", 0.1), 0.1)
        hi = _safe_float(self.cfg.get("max_target_tflops", 200.0), 200.0)
        if target > 0:
            target = max(lo, min(target, hi))
        else:
            target = 0.0
        self.cfg.setdefault("targets", {})[str(gpu_index)] = target
        if enabled is not None:
            self.cfg["enabled"] = bool(enabled)
        CONFIG["flops"] = self.cfg
        save_config(CONFIG)
        return self.status_for_gpu(gpu_index)

    def _device_info(self, gpu_index: int) -> dict[str, Any]:
        if self.nvml_backend is None:
            return {}
        try:
            return self.nvml_backend.fp32_info(gpu_index)
        except Exception as exc:
            return {"error": str(exc)}

    def status_for_gpu(self, gpu_index: int, sample: Optional["TelemetrySample"] = None) -> dict[str, Any]:
        info = self._device_info(gpu_index)
        if sample is not None:
            raw = sample.raw or {}
            flops_raw = raw.get("flops", {})
            if flops_raw:
                info = {**info, **flops_raw}
        target = self._target_for(gpu_index)
        peak = _safe_float(info.get("fp32_peak_tflops"), 0.0)
        current = _safe_float(info.get("fp32_estimated_tflops"), 0.0)
        calibration = self._calibration.get(gpu_index, 1.0)
        peak *= calibration
        current *= calibration
        if current <= 0 and peak > 0 and sample is not None:
            current = peak * max(0.0, min(_safe_float(sample.gpu_util), 100.0)) / 100.0
        achievement = (current / target * 100.0) if target > 0 else 0.0
        benchmark = self.benchmark_engine.latest(gpu_index) if getattr(self, "benchmark_engine", None) is not None else {}
        return {
            "gpu_index": gpu_index,
            "enabled": self.enabled(),
            "mode": self.cfg.get("mode", "soft_target"),
            "precision": self.cfg.get("precision", "fp32"),
            "target_tflops": target,
            "fp32_peak_tflops": peak,
            "fp32_estimated_tflops": current,
            "target_achievement_percent": achievement,
            "benchmark": self.benchmark_engine.latest(gpu_index) if getattr(self, "benchmark_engine", None) is not None else {},
            "calibration_factor": calibration,
            "control_state": self._last_state.get(gpu_index, {}).get("control_state", "MONITOR"),
            "target_clock_mhz": self._last_state.get(gpu_index, {}).get("target_clock_mhz"),
            "reason": self._last_state.get(gpu_index, {}).get("reason", "no control action"),
            "device": info,
        }

    def status_all(self, telemetry_engine: Optional["TelemetryEngine"] = None) -> dict[int, dict[str, Any]]:
        latest: Dict[int, "TelemetrySample"] = {}
        if telemetry_engine is not None:
            for sample in telemetry_engine.get_history():
                latest[sample.gpu_index] = sample
        indices = set(latest.keys())
        if self.nvml_backend is not None:
            try:
                indices.update(range(self.nvml_backend.device_count()))
            except Exception:
                pass
        return {
            idx: self.status_for_gpu(idx, latest.get(idx))
            for idx in sorted(indices)
        }

    def _safe_clock_limits(self, info: dict[str, Any]) -> tuple[float, float]:
        min_clock = _safe_float(self.cfg.get("min_clock_mhz"), 300.0)
        max_clock_cfg = _safe_float(self.cfg.get("max_clock_mhz"), 0.0)
        device_max = _safe_float(info.get("max_graphics_clock_mhz"), 0.0)
        max_clock = max_clock_cfg if max_clock_cfg > 0 else device_max
        if max_clock <= 0:
            max_clock = 4000.0
        return min_clock, max_clock

    def _apply_clock_target(self, gpu_index: int, target_clock_mhz: float) -> tuple[bool, str]:
        if self.nvml_backend is None:
            return False, "nvml_unavailable"
        if not self.cfg.get("use_clock_lock", False):
            return False, "clock_lock_disabled"
        try:
            ok = self.nvml_backend.set_gpu_clock_lock(
                gpu_index,
                int(target_clock_mhz),
                int(target_clock_mhz),
            )
            return bool(ok), "clock_lock_applied" if ok else "clock_lock_failed"
        except Exception as exc:
            return False, f"clock_lock_error:{exc}"

    def reset_clock_target(self, gpu_index: int) -> bool:
        if self.nvml_backend is None:
            return False
        try:
            return bool(self.nvml_backend.reset_gpu_clock_lock(gpu_index))
        except Exception:
            return False

    def apply(self, gpu_index: int, sample: Optional["TelemetrySample"] = None) -> dict[str, Any]:
        now = time.time()
        interval = max(_safe_float(self.cfg.get("update_interval"), 1.0), 0.2)
        if now - self._last_apply.get(gpu_index, 0.0) < interval:
            return self.status_for_gpu(gpu_index, sample)

        self._last_apply[gpu_index] = now
        status = self.status_for_gpu(gpu_index, sample)
        target = _safe_float(status.get("target_tflops"), 0.0)
        peak = _safe_float(status.get("fp32_peak_tflops"), 0.0)
        temp = sample.gpu_temp if sample is not None else None

        if not self.enabled() or target <= 0:
            self._last_state[gpu_index] = {
                "control_state": "MONITOR",
                "reason": "disabled_or_no_target",
            }
            return self.status_for_gpu(gpu_index, sample)

        if peak <= 0:
            self._last_state[gpu_index] = {
                "control_state": "UNSUPPORTED",
                "reason": "FP32_peak_unavailable",
            }
            return self.status_for_gpu(gpu_index, sample)

        thermal_override = _safe_float(self.cfg.get("thermal_override_c"), 80.0)
        emergency_temp = _safe_float(self.cfg.get("emergency_temp_c"), 88.0)

        if temp is not None and temp >= emergency_temp:
            self.reset_clock_target(gpu_index)
            self._last_state[gpu_index] = {
                "control_state": "THERMAL_OVERRIDE",
                "reason": f"emergency_temperature_{temp:.1f}C",
            }
            return self.status_for_gpu(gpu_index, sample)

        # Target clock derived from theoretical FP32 scaling.
        base_clock = _safe_float(
            status.get("device", {}).get("reference_clock_mhz"),
            _safe_float(sample.raw.get("clocks", {}).get("graphics_mhz") if sample else 0, 0.0),
        )
        if base_clock <= 0:
            base_clock = _safe_float(sample.raw.get("clocks", {}).get("sm_mhz") if sample else 0, 0.0)
        if base_clock <= 0:
            self._last_state[gpu_index] = {
                "control_state": "MONITOR",
                "reason": "clock_telemetry_unavailable",
            }
            return self.status_for_gpu(gpu_index, sample)

        target_clock = base_clock * (target / max(peak, 1e-9))
        min_clock, max_clock = self._safe_clock_limits(status.get("device", {}))
        target_clock = max(min_clock, min(max_clock, target_clock))

        # Never intentionally raise a clock target merely because a TFLOPS target
        # was requested. A target above current performance remains a monitor-only
        # request unless explicit clock locking is enabled.
        current = _safe_float(status.get("fp32_estimated_tflops"), 0.0)
        margin = _safe_float(self.cfg.get("control_margin_percent"), 5.0)
        low = target * (1.0 - margin / 100.0)
        high = target * (1.0 + margin / 100.0)

        if temp is not None and temp >= thermal_override:
            self._last_state[gpu_index] = {
                "control_state": "THERMAL_LIMIT",
                "reason": f"temperature_{temp:.1f}C",
                "target_clock_mhz": target_clock,
            }
            return self.status_for_gpu(gpu_index, sample)

        if current > high:
            # Reduce power envelope when we are materially above the target.
            if self.nvml_backend is not None:
                try:
                    current_limit = self.nvml_backend.get_power_limit_percent(gpu_index)
                    reduction = min(10.0, max(2.0, (current - target) / max(target, 1e-9) * 20.0))
                    requested = max(50.0, current_limit - reduction)
                    self.nvml_backend.set_power_limit_percent(gpu_index, requested)
                except Exception:
                    pass
            self._last_state[gpu_index] = {
                "control_state": "REDUCE",
                "reason": "estimated_tflops_above_target",
                "target_clock_mhz": target_clock,
            }
        elif current < low:
            ok, reason = self._apply_clock_target(gpu_index, target_clock)
            self._last_state[gpu_index] = {
                "control_state": "BOOST" if ok else "MONITOR",
                "reason": reason if ok else "target_below_estimated_capacity",
                "target_clock_mhz": target_clock,
            }
        else:
            self._last_state[gpu_index] = {
                "control_state": "HOLD",
                "reason": "within_target_margin",
                "target_clock_mhz": target_clock,
            }

        return self.status_for_gpu(gpu_index, sample)


class CudaBenchmarkEngine:
    """Bounded CUDA FP32 benchmark for empirical FLOPS calibration."""
    def __init__(self, cfg, nvml_backend):
        self.cfg=cfg; self.nvml_backend=nvml_backend; self._last={}; self._lock=threading.Lock()
    def available(self):
        return cupy is not None or (numba is not None and getattr(numba, "cuda", None) is not None)
    def run(self, gpu_index=0):
        if not self.cfg.get("enabled", True): return {"status":"disabled","gpu_index":gpu_index}
        if not self.available(): return {"status":"unavailable","reason":"CuPy or Numba CUDA unavailable","gpu_index":gpu_index}
        try:
            if self.nvml_backend:
                temp=self.nvml_backend.snapshot(gpu_index).get("temperature",{}).get("gpu_celsius")
                if temp is not None and float(temp)>=float(self.cfg.get("max_temp_c",82.0)):
                    return {"status":"thermal_guard","gpu_index":gpu_index,"temperature_c":temp}
            n=max(128,min(int(self.cfg.get("matrix_size",512)),1024)); it=max(1,min(int(self.cfg.get("iterations",5)),20)); warm=max(0,min(int(self.cfg.get("warmup_iterations",2)),10))
            with self._lock:
                if cupy is not None:
                    with cupy.cuda.Device(gpu_index):
                        a=cupy.random.random((n,n),dtype=cupy.float32); b=cupy.random.random((n,n),dtype=cupy.float32)
                        for _ in range(warm): _=a@b; cupy.cuda.Stream.null.synchronize()
                        t0=time.perf_counter()
                        for _ in range(it): _=a@b
                        cupy.cuda.Stream.null.synchronize(); elapsed=time.perf_counter()-t0
                else:
                    from numba import cuda
                    if not cuda.is_available(): return {"status":"unavailable","reason":"CUDA runtime unavailable","gpu_index":gpu_index}
                    import numpy as np
                    with cuda.gpus[gpu_index]:
                        a=np.random.random((n,n)).astype(np.float32); b=np.random.random((n,n)).astype(np.float32)
                        da,db=cuda.to_device(a),cuda.to_device(b); dc=cuda.device_array((n,n),dtype=np.float32)
                        @cuda.jit
                        def mm(x,y,o):
                            r,c=cuda.grid(2)
                            if r<o.shape[0] and c<o.shape[1]:
                                acc=0.0
                                for k in range(x.shape[1]): acc += x[r,k]*y[k,c]
                                o[r,c]=acc
                        blocks=((n+15)//16,(n+15)//16); threads=(16,16)
                        for _ in range(warm): mm[blocks,threads](da,db,dc)
                        cuda.synchronize(); t0=time.perf_counter()
                        for _ in range(it): mm[blocks,threads](da,db,dc)
                        cuda.synchronize(); elapsed=time.perf_counter()-t0
            measured=(2.0*n*n*n*it)/max(elapsed,1e-9)/1e12
            result={"status":"ok","gpu_index":gpu_index,"matrix_size":n,"iterations":it,"elapsed_seconds":elapsed,"measured_fp32_tflops":measured,"timestamp":time.time()}
            self._last[gpu_index]=result; return result
        except Exception as e:
            result={"status":"error","gpu_index":gpu_index,"error":str(e)}; self._last[gpu_index]=result; return result
    def latest(self,gpu_index): return dict(self._last.get(gpu_index,{}))

class FanCurveLearner:
    """Online temperature/utilization regression for a conservative fan target."""
    def __init__(self,cfg,nvml_backend): self.cfg=cfg; self.nvml_backend=nvml_backend; self.models={}; self.counts={}; self._lock=threading.Lock()
    def _desired(self,temp,util):
        lt=float(self.cfg.get("min_temp_c",35)); ht=float(self.cfg.get("max_temp_c",88)); lf=float(self.cfg.get("min_fan_percent",25)); hf=float(self.cfg.get("max_fan_percent",100)); t=max(0,min(1,(temp-lt)/max(1,ht-lt))); u=max(0,min(1,util/100)); return max(lf,min(hf,lf+(hf-lf)*(0.75*t+0.25*u)))
    def update(self,gpu,temp,util):
        if not self.cfg.get("enabled",True) or temp is None or util is None:return None
        temp=float(temp); util=float(util); y=self._desired(temp,util)
        with self._lock:
            a,b=self.models.get(gpu,(20.0,0.9)); lr=max(.001,min(float(self.cfg.get("learning_rate",.08)),1)); pred=a+b*temp; err=y-pred; a+=lr*err; b+=lr*err*(temp-60)/max(1,temp*temp); self.models[gpu]=(a,b); self.counts[gpu]=self.counts.get(gpu,0)+1
            return self.predict(gpu,temp)
    def predict(self,gpu,temp):
        a,b=self.models.get(gpu,(20.0,.9)); v=a+b*float(temp); return max(float(self.cfg.get("min_fan_percent",25)),min(float(self.cfg.get("max_fan_percent",100)),v))
    def status(self,gpu):
        with self._lock: a,b=self.models.get(gpu,(20,.9)); n=self.counts.get(gpu,0)
        return {"gpu_index":gpu,"model":{"intercept":a,"slope":b},"samples":n,"enabled":self.cfg.get("enabled",True),"apply_learned_curve":self.cfg.get("apply_learned_curve",False)}

class AdaptiveUndervoltLearner:
    """Learns a safe power envelope instead of writing raw voltage curves."""
    def __init__(self,cfg,nvml_backend): self.cfg=cfg; self.nvml_backend=nvml_backend; self.state={}; self._lock=threading.Lock()
    def update(self,gpu,temp,util,power):
        if not self.cfg.get("enabled",True): return self.status(gpu)
        temp=float(temp or 0); util=float(util or 0); power=float(power or 100); target=float(self.cfg.get("target_temp_c",78)); ceiling=float(self.cfg.get("thermal_ceiling_c",84)); maxred=float(self.cfg.get("max_power_reduction_percent",20)); lr=float(self.cfg.get("learning_rate",.05)); minp=float(self.cfg.get("min_power_percent",60))
        with self._lock:
            st=self.state.setdefault(gpu,{"learned_reduction_percent":0.0,"stable_cycles":0,"last_reason":"initial"})
            if temp>=ceiling: st["learned_reduction_percent"]=min(maxred,st["learned_reduction_percent"]+2); st["stable_cycles"]=0; st["last_reason"]="thermal_ceiling"
            elif temp>target and util>50: st["learned_reduction_percent"]=min(maxred,st["learned_reduction_percent"]+lr*min(5,temp-target)); st["stable_cycles"]=0; st["last_reason"]="above_target"
            elif temp<target-3 and util>30: st["learned_reduction_percent"]=max(0,st["learned_reduction_percent"]-lr); st["stable_cycles"]+=1; st["last_reason"]="stable_cool"
            st["recommended_power_percent"]=max(minp,100-st["learned_reduction_percent"]); st["observed_power_percent"]=power; st["apply_automatically"]=bool(self.cfg.get("apply_automatically",False)); return dict(st,gpu_index=gpu)
    def status(self,gpu): return dict(self.state.get(gpu,{"gpu_index":gpu,"learned_reduction_percent":0,"recommended_power_percent":100}))

class PluginSandbox:
    """Process isolation for plugins. It is not a hardened OS security sandbox."""
    def __init__(self,cfg): self.cfg=cfg; self.procs={}; self.restarts={}; self._lock=threading.Lock()
    def _code(self):
        return """import importlib.util,json,sys,traceback\np=sys.argv[1]; s=importlib.util.spec_from_file_location("plugin",p); m=importlib.util.module_from_spec(s); s.loader.exec_module(m); print(json.dumps({"event":"loaded"}),flush=True)\nfor line in sys.stdin:\n try:\n  x=json.loads(line); f=getattr(m,x.get("method","on_tick"),None); r=f(x.get("payload",{})) if callable(f) else {"status":"no_handler"}; print(json.dumps({"event":"result","result":r},default=str),flush=True)\n except Exception as e: print(json.dumps({"event":"error","error":str(e)}),flush=True)"""
    def start(self,name,path):
        with self._lock:
            if name in self.procs and self.procs[name].poll() is None:return True
            if self.restarts.get(name,0)>=int(self.cfg.get("max_restarts",3)):return False
            try:
                proc=subprocess.Popen([sys.executable,"-u","-c",self._code(),str(path)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,creationflags=getattr(subprocess,"CREATE_NO_WINDOW",0)); self.procs[name]=proc; self.restarts[name]=self.restarts.get(name,0)+1; return True
            except Exception as e: print(f"[PLUGIN-SANDBOX] {name}: {e}"); return False
    def call(self,name,method,payload):
        proc=self.procs.get(name)
        if not proc or proc.poll() is not None:return {"status":"offline"}
        try:
            proc.stdin.write(json.dumps({"method":method,"payload":payload})+"\n"); proc.stdin.flush(); deadline=time.time()+float(self.cfg.get("timeout_seconds",2))
            while time.time()<deadline:
                line=proc.stdout.readline()
                if line:return json.loads(line)
                time.sleep(.01)
            return {"status":"timeout"}
        except Exception as e:return {"status":"error","error":str(e)}
    def stop_all(self):
        for p in self.procs.values():
            with contextlib.suppress(Exception):p.terminate()
        self.procs.clear()

class ClusterController:
    def __init__(self,cfg,telemetry_engine): self.cfg=cfg; self.telemetry_engine=telemetry_engine
    def sign(self,payload):
        import hashlib,hmac
        body=json.dumps(payload,separators=(",",":"),default=str).encode(); secret=str(self.cfg.get("shared_secret","")); sig=hmac.new(secret.encode(),body,hashlib.sha256).hexdigest() if secret else ""; return body,sig
    def verify(self,body,sig):
        import hashlib,hmac
        secret=str(self.cfg.get("shared_secret","")); expected=hmac.new(secret.encode(),body,hashlib.sha256).hexdigest() if secret else ""; return bool(expected) and hmac.compare_digest(expected,sig or "")
    def local_snapshot(self):
        n=int(self.cfg.get("max_history_samples",120)); return {"node_id":socket.gethostname(),"timestamp":time.time(),"telemetry":[asdict(x) for x in self.telemetry_engine.get_history()[-n:]]}

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
        flops_info = {}
        try:
            flops_info = self.fp32_info(index)
        except Exception:
            flops_info = {}

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
            "flops": flops_info,
            "processes": processes,
            "timestamp": time.time(),
        }

    def snapshot_all(self) -> list[dict[str, Any]]:
        """Return a telemetry snapshot for every detected GPU.

        Kept as a compatibility method for TelemetryEngine and other callers
        that collect all GPUs in one operation.
        """
        self._ensure_initialized()
        return [self.snapshot(i) for i in range(self._device_count)]


    def fp32_info(self, index: int) -> dict[str, Any]:
        self._ensure_initialized()
        handle = pynvml.nvmlDeviceGetHandleByIndex(index)
        name = safe_decode(pynvml.nvmlDeviceGetName(handle))

        cc = None
        try:
            cc = tuple(pynvml.nvmlDeviceGetCudaComputeCapability(handle))
        except Exception:
            cc = None

        sm_count = None
        try:
            sm_count = int(pynvml.nvmlDeviceGetMultiprocessorCount(handle))
        except Exception:
            sm_count = None

        cores_per_sm = _infer_cores_per_sm(name, cc)

        reference_clock = None
        try:
            reference_clock = pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_GRAPHICS)
        except Exception:
            reference_clock = None

        max_graphics = None
        try:
            max_graphics = pynvml.nvmlDeviceGetMaxClockInfo(handle, pynvml.NVML_CLOCK_GRAPHICS)
        except Exception:
            pass

        peak = estimate_fp32_tflops(sm_count, cores_per_sm, max_graphics or reference_clock)
        current = None
        try:
            current_clock = pynvml.nvmlDeviceGetClockInfo(handle, pynvml.NVML_CLOCK_GRAPHICS)
            current = estimate_fp32_tflops(sm_count, cores_per_sm, current_clock)
        except Exception:
            current_clock = reference_clock

        return {
            "name": name,
            "compute_capability": cc,
            "sm_count": sm_count,
            "cores_per_sm_estimate": cores_per_sm,
            "reference_clock_mhz": reference_clock,
            "max_graphics_clock_mhz": max_graphics,
            "current_graphics_clock_mhz": current_clock,
            "fp32_peak_tflops": peak,
            "fp32_estimated_tflops": current or 0.0,
            "estimation": "theoretical_fp32_fma_clock_model",
        }

    def get_power_limit_percent(self, index: int) -> float:
        self._ensure_initialized()
        handle = pynvml.nvmlDeviceGetHandleByIndex(index)
        current = pynvml.nvmlDeviceGetEnforcedPowerLimit(handle)
        default = pynvml.nvmlDeviceGetPowerManagementDefaultLimit(handle)
        if not default:
            return 100.0
        return float(current) / float(default) * 100.0

    def set_gpu_clock_lock(self, index: int, min_clock_mhz: int, max_clock_mhz: int) -> bool:
        self._ensure_initialized()
        if not CONFIG["safety"]["allow_vendor_writes"]:
            return False
        fn = getattr(pynvml, "nvmlDeviceSetGpuLockedClocks", None)
        if fn is None:
            return False
        handle = pynvml.nvmlDeviceGetHandleByIndex(index)
        try:
            fn(handle, int(min_clock_mhz), int(max_clock_mhz))
            print(f"[FLOPS] GPU {index} clock lock {min_clock_mhz}-{max_clock_mhz} MHz")
            return True
        except Exception as exc:
            print(f"[FLOPS] clock lock failed: {exc}")
            return False

    def reset_gpu_clock_lock(self, index: int) -> bool:
        self._ensure_initialized()
        if not CONFIG["safety"]["allow_vendor_writes"]:
            return False
        fn = getattr(pynvml, "nvmlDeviceResetGpuLockedClocks", None)
        if fn is None:
            return False
        handle = pynvml.nvmlDeviceGetHandleByIndex(index)
        try:
            fn(handle)
            print(f"[FLOPS] GPU {index} clock lock reset")
            return True
        except Exception as exc:
            print(f"[FLOPS] clock lock reset failed: {exc}")
            return False

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


class VramStressTester:
    """
    Safe VRAM stress tester:
    - Allocates large buffers
    - Runs read/write patterns
    - Aborts if duration or temperature exceeds thresholds
    """

    def __init__(
        self,
        cfg: dict[str, Any],
        nvml_backend: Optional[NvmlBackend],
        telemetry_engine: TelemetryEngine,
        flops_governor: Optional[FlopsGovernor] = None,
    ) -> None:
        self.cfg = cfg
        self.nvml_backend = nvml_backend
        self.telemetry_engine = telemetry_engine

    def _current_temp(self, gpu_index: int) -> Optional[float]:
        hist = self.telemetry_engine.get_history()
        latest = None
        for s in hist:
            if s.gpu_index == gpu_index:
                latest = s
        return latest.gpu_temp if latest else None

    def run(self, gpu_index: int = 0) -> dict[str, Any]:
        if not self.cfg.get("enabled", True):
            return {"enabled": False, "status": "disabled"}
        if np is None:
            return {"enabled": True, "status": "no_numpy"}
        max_duration = self.cfg.get("max_duration_sec", 120)
        max_temp = self.cfg.get("max_temp_c", 88.0)
        buffer_size_mb = self.cfg.get("buffer_size_mb", 512)
        pattern_rounds = self.cfg.get("pattern_rounds", 5)

        size = buffer_size_mb * 1024 * 1024 // 4  # float32
        start = time.time()
        arr = np.zeros(size, dtype=np.float32)

        def check_abort(round_idx: int) -> Optional[str]:
            now = time.time()
            if now - start > max_duration:
                return "time_limit"
            temp = self._current_temp(gpu_index)
            if temp is not None and temp >= max_temp:
                return "temp_limit"
            return None

        for r in range(pattern_rounds):
            abort_reason = check_abort(r)
            if abort_reason:
                return {
                    "enabled": True,
                    "status": "aborted",
                    "reason": abort_reason,
                    "rounds_completed": r,
                    "duration_sec": time.time() - start,
                }
            arr[:] = np.random.rand(size).astype(np.float32)
            checksum1 = float(arr.mean())
            arr[:] = arr * 1.0001
            checksum2 = float(arr.mean())
            if abs(checksum2 - checksum1) < 1e-6:
                pass

        return {
            "enabled": True,
            "status": "ok",
            "rounds_completed": pattern_rounds,
            "duration_sec": time.time() - start,
            "buffer_size_mb": buffer_size_mb,
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


class MLModelThermal:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        self.weights: Dict[int, Dict[str, float]] = {}
        self.samples: Dict[int, List[Dict[str, float]]] = {}

    def _init_gpu(self, gpu_index: int) -> None:
        if gpu_index not in self.weights:
            self.weights[gpu_index] = {
                "bias": 0.0,
                "util": 0.0,
                "temp": 1.0,
                "mem_ratio": 0.0,
            }
            self.samples[gpu_index] = []

    def update(self, sample: TelemetrySample) -> None:
        if not self.cfg.get("enabled", True):
            return
        gpu_index = sample.gpu_index
        self._init_gpu(gpu_index)
        if sample.gpu_temp is None or sample.gpu_util is None or sample.mem_total_bytes in (None, 0):
            return
        mem_ratio = (sample.mem_used_bytes or 0) / (sample.mem_total_bytes or 1)
        x = {
            "util": sample.gpu_util / 100.0,
            "temp": sample.gpu_temp / 100.0,
            "mem_ratio": mem_ratio,
        }
        y = sample.gpu_temp / 100.0
        self.samples[gpu_index].append({"util": x["util"], "temp": x["temp"], "mem_ratio": x["mem_ratio"], "y": y})
        max_samples = self.cfg.get("max_samples", 2000)
        if len(self.samples[gpu_index]) > max_samples:
            self.samples[gpu_index] = self.samples[gpu_index][-max_samples:]
        lr = self.cfg.get("learning_rate", 0.01)
        w = self.weights[gpu_index]
        y_pred = w["bias"] + w["util"] * x["util"] + w["temp"] * x["temp"] + w["mem_ratio"] * x["mem_ratio"]
        error = y_pred - y
        w["bias"] -= lr * error
        w["util"] -= lr * error * x["util"]
        w["temp"] -= lr * error * x["temp"]
        w["mem_ratio"] -= lr * error * x["mem_ratio"]

    def predict(self, gpu_index: int, util: float, temp: float, mem_ratio: float, horizon_sec: float) -> float:
        self._init_gpu(gpu_index)
        w = self.weights[gpu_index]
        util_n = util / 100.0
        temp_n = temp / 100.0
        y_pred = w["bias"] + w["util"] * util_n + w["temp"] * temp_n + w["mem_ratio"] * mem_ratio
        base_temp = y_pred * 100.0
        drift = 0.02 * (horizon_sec / 60.0) * util_n * 100.0
        return base_temp + drift


class DLModelThermal:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        self.enabled = cfg.get("enabled", True)
        self.hidden_size = cfg.get("hidden_size", 8)
        self.lr = cfg.get("learning_rate", 0.005)
        self.history_len = cfg.get("history_len", 10)
        self.params: Dict[int, Dict[str, Any]] = {}
        self.history: Dict[int, List[Dict[str, float]]] = {}

    def _init_gpu(self, gpu_index: int) -> None:
        if gpu_index in self.params:
            return
        input_dim = 4 + self.history_len
        if np is None:
            self.params[gpu_index] = {
                "w1": None,
                "b1": None,
                "w2": None,
                "b2": None,
            }
            return
        w1 = np.random.randn(input_dim, self.hidden_size).astype(np.float32) * 0.1
        b1 = np.zeros((self.hidden_size,), dtype=np.float32)
        w2 = np.random.randn(self.hidden_size, 1).astype(np.float32) * 0.1
        b2 = np.zeros((1,), dtype=np.float32)
        self.params[gpu_index] = {"w1": w1, "b1": b1, "w2": w2, "b2": b2}
        self.history[gpu_index] = []

    def _build_input(self, gpu_index: int, sample: TelemetrySample) -> Optional[Any]:
        if np is None:
            return None
        util = (sample.gpu_util or 0.0) / 100.0
        temp = (sample.gpu_temp or 0.0) / 100.0
        mem_ratio = 0.0
        if sample.mem_total_bytes not in (None, 0):
            mem_ratio = (sample.mem_used_bytes or 0) / (sample.mem_total_bytes or 1)
        t_norm = (time.time() % 60.0) / 60.0
        hist = self.history.get(gpu_index, [])
        temps_hist = [h["temp"] for h in hist[-self.history_len :]]
        while len(temps_hist) < self.history_len:
            temps_hist.insert(0, temp)
        x = np.array([util, temp, mem_ratio, t_norm] + temps_hist, dtype=np.float32)
        return x

    def update(self, sample: TelemetrySample) -> None:
        if not self.enabled or np is None:
            return
        gpu_index = sample.gpu_index
        self._init_gpu(gpu_index)
        if sample.gpu_temp is None:
            return
        x = self._build_input(gpu_index, sample)
        if x is None:
            return
        self.history.setdefault(gpu_index, []).append(
            {
                "temp": (sample.gpu_temp or 0.0) / 100.0,
                "util": (sample.gpu_util or 0.0) / 100.0,
            }
        )
        if len(self.history[gpu_index]) > 1000:
            self.history[gpu_index] = self.history[gpu_index][-1000:]
        p = self.params[gpu_index]
        w1, b1, w2, b2 = p["w1"], p["b1"], p["w2"], p["b2"]
        h = np.tanh(x @ w1 + b1)
        y_pred = h @ w2 + b2
        y_true = np.array([sample.gpu_temp / 100.0], dtype=np.float32)
        error = y_pred - y_true
        dy = error
        dw2 = h[:, None] @ dy[None, :]
        db2 = dy
        dh = dy @ w2.T
        dh_raw = dh * (1.0 - h**2)
        dw1 = x[:, None] @ dh_raw[None, :]
        db1 = dh_raw
        w2 -= self.lr * dw2
        b2 -= self.lr * db2
        w1 -= self.lr * dw1
        b1 -= self.lr * db1
        p["w1"], p["b1"], p["w2"], p["b2"] = w1, b1, w2, b2

    def predict(self, gpu_index: int, sample: TelemetrySample, horizon_sec: float) -> float:
        if not self.enabled or np is None:
            return sample.gpu_temp or 0.0
        self._init_gpu(gpu_index)
        x = self._build_input(gpu_index, sample)
        if x is None:
            return sample.gpu_temp or 0.0
        p = self.params[gpu_index]
        w1, b1, w2, b2 = p["w1"], p["b1"], p["w2"], p["b2"]
        h = np.tanh(x @ w1 + b1)
        y_pred = h @ w2 + b2
        base_temp = float(y_pred[0] * 100.0)
        util = (sample.gpu_util or 0.0) / 100.0
        drift = 0.03 * (horizon_sec / 60.0) * util * 100.0
        return base_temp + drift

    def residual_error(self, gpu_index: int) -> float:
        if not self.enabled or np is None:
            return 0.0
        hist = self.history.get(gpu_index, [])
        if len(hist) < 5:
            return 0.0
        temps = [h["temp"] for h in hist[-20:]]
        mean_t = statistics.mean(temps)
        stdev_t = statistics.pstdev(temps) or 1e-6
        last = temps[-1]
        return abs((last - mean_t) / stdev_t)


class MLWorkloadClassifier:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        self.history: Dict[int, List[Dict[str, float]]] = {}

    def classify(self, sample: TelemetrySample) -> str:
        if not self.cfg.get("enabled", True):
            return "unknown"
        gpu_index = sample.gpu_index
        util = sample.gpu_util or 0.0
        mem_ratio = 0.0
        if sample.mem_total_bytes not in (None, 0):
            mem_ratio = (sample.mem_used_bytes or 0) / (sample.mem_total_bytes or 1)
        self.history.setdefault(gpu_index, []).append(
            {"util": util, "mem_ratio": mem_ratio, "temp": sample.gpu_temp or 0.0}
        )
        if len(self.history[gpu_index]) > 100:
            self.history[gpu_index] = self.history[gpu_index][-100:]
        idle_th = self.cfg["workload"].get("idle_threshold", 10.0)
        light_th = self.cfg["workload"].get("light_threshold", 30.0)
        gaming_th = self.cfg["workload"].get("gaming_threshold", 70.0)
        compute_th = self.cfg["workload"].get("compute_threshold", 90.0)
        hist = self.history[gpu_index]
        avg_util = statistics.mean([h["util"] for h in hist]) if hist else util
        avg_mem = statistics.mean([h["mem_ratio"] for h in hist]) if hist else mem_ratio
        if avg_util < idle_th and avg_mem < 0.2:
            return "idle"
        if avg_util < light_th:
            return "light"
        if avg_util < gaming_th and avg_mem < 0.7:
            return "gaming"
        if avg_util >= compute_th and avg_mem >= 0.7:
            return "compute"
        return "mixed"


class MLAnomalyDetector:
    def __init__(self, cfg: dict[str, Any], dl_model: DLModelThermal) -> None:
        self.cfg = cfg
        self.temp_history: Dict[int, List[float]] = {}
        self.util_history: Dict[int, List[float]] = {}
        self.dl_model = dl_model

    def update(self, sample: TelemetrySample) -> None:
        if not self.cfg.get("enabled", True):
            return
        gpu_index = sample.gpu_index
        self.temp_history.setdefault(gpu_index, [])
        self.util_history.setdefault(gpu_index, [])
        if sample.gpu_temp is not None:
            self.temp_history[gpu_index].append(sample.gpu_temp)
        if sample.gpu_util is not None:
            self.util_history[gpu_index].append(sample.gpu_util)
        window = self.cfg["anomaly"].get("window", 120)
        if len(self.temp_history[gpu_index]) > window:
            self.temp_history[gpu_index] = self.temp_history[gpu_index][-window:]
        if len(self.util_history[gpu_index]) > window:
            self.util_history[gpu_index] = self.util_history[gpu_index][-window:]

    def check(self, gpu_index: int) -> dict[str, Any]:
        if not self.cfg.get("enabled", True):
            return {"enabled": False}
        temps = self.temp_history.get(gpu_index, [])
        utils = self.util_history.get(gpu_index, [])
        if len(temps) < 10 or len(utils) < 10:
            return {"enabled": True, "status": "insufficient_data"}

        def z_score(values: List[float]) -> float:
            mean = statistics.mean(values)
            stdev = statistics.pstdev(values) or 1e-6
            last = values[-1]
            return abs((last - mean) / stdev)

        z_temp = z_score(temps)
        z_util = z_score(utils)
        anomaly_temp = z_temp >= self.cfg["anomaly"].get("z_threshold", 3.0)
        anomaly_util = z_util >= self.cfg["anomaly"].get("z_threshold", 3.0)
        dl_residual = self.dl_model.residual_error(gpu_index)
        anomaly_dl = dl_residual >= self.cfg["anomaly"].get("z_threshold", 3.0)
        return {
            "enabled": True,
            "status": "ok",
            "z_temp": z_temp,
            "z_util": z_util,
            "dl_residual": dl_residual,
            "anomaly_temp": anomaly_temp,
            "anomaly_util": anomaly_util,
            "anomaly_dl": anomaly_dl,
        }


class PredictionEngine:
    def __init__(
        self,
        cfg: dict[str, Any],
        telemetry_engine: TelemetryEngine,
        ml_thermal: MLModelThermal,
        dl_thermal: DLModelThermal,
    ) -> None:
        self.cfg = cfg
        self.telemetry_engine = telemetry_engine
        self.ml_thermal = ml_thermal
        self.dl_thermal = dl_thermal

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

        mem_ratio = 0.0
        latest_by_gpu: Dict[int, TelemetrySample] = {}
        for s in hist:
            latest_by_gpu[s.gpu_index] = s
        any_sample = list(latest_by_gpu.values())[-1]
        if any_sample.mem_total_bytes not in (None, 0):
            mem_ratio = (any_sample.mem_used_bytes or 0) / (any_sample.mem_total_bytes or 1)

        temp_future_ml = self.ml_thermal.predict(
            gpu_index=any_sample.gpu_index,
            util=util_now,
            temp=temp_now,
            mem_ratio=mem_ratio,
            horizon_sec=horizon,
        )
        temp_future_dl = self.dl_thermal.predict(
            gpu_index=any_sample.gpu_index,
            sample=any_sample,
            horizon_sec=horizon,
        )
        temp_future_slope = temp_now + t_s * (horizon / short_w)
        temp_future = 0.5 * temp_future_dl + 0.3 * temp_future_ml + 0.2 * temp_future_slope

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
            "temp_future_ml": temp_future_ml,
            "temp_future_dl": temp_future_dl,
            "temp_future_slope": temp_future_slope,
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


class ThermalPIDController:
    def __init__(self, cfg: dict[str, Any]) -> None:
        self.cfg = cfg
        self.integral: Dict[int, float] = {}
        self.last_error: Dict[int, float] = {}
        self.last_time: Dict[int, float] = {}

    def compute(self, gpu_index: int, current_temp: Optional[float]) -> float:
        if not self.cfg.get("enabled", True):
            return 0.0
        if current_temp is None:
            return 0.0
        target = self.cfg.get("target_temp_c", 75.0)
        kp = self.cfg.get("kp", 0.8)
        ki = self.cfg.get("ki", 0.05)
        kd = self.cfg.get("kd", 0.2)
        integral_limit = self.cfg.get("integral_limit", 50.0)

        now = time.time()
        error = target - current_temp
        dt = now - self.last_time.get(gpu_index, now)
        self.last_time[gpu_index] = now

        if dt <= 0:
            dt = 1e-3

        self.integral[gpu_index] = self.integral.get(gpu_index, 0.0) + error * dt
        self.integral[gpu_index] = max(-integral_limit, min(self.integral[gpu_index], integral_limit))

        derivative = (error - self.last_error.get(gpu_index, error)) / dt
        self.last_error[gpu_index] = error

        output = kp * error + ki * self.integral[gpu_index] + kd * derivative
        return output


def eval_curve(points: List[List[float]], x: float) -> float:
    if not points:
        return 0.0
    points = sorted(points, key=lambda p: p[0])
    if x <= points[0][0]:
        return points[0][1]
    if x >= points[-1][0]:
        return points[-1][1]
    for i in range(len(points) - 1):
        x0, y0 = points[i]
        x1, y1 = points[i + 1]
        if x0 <= x <= x1:
            t = (x - x0) / (x1 - x0)
            return y0 + t * (y1 - y0)
    return points[-1][1]


class TuningEngine:
    def __init__(
        self,
        cfg: dict[str, Any],
        nvml_backend: Optional[NvmlBackend],
        prediction_engine: PredictionEngine,
        thermal_pid: ThermalPIDController,
        ml_workload: MLWorkloadClassifier,
        ml_anomaly: MLAnomalyDetector,
        telemetry_engine: TelemetryEngine,
        flops_governor: Optional[FlopsGovernor] = None,
    ) -> None:
        self.cfg = cfg
        self.nvml_backend = nvml_backend
        self.prediction_engine = prediction_engine
        self.thermal_pid = thermal_pid
        self.ml_workload = ml_workload
        self.ml_anomaly = ml_anomaly
        self.telemetry_engine = telemetry_engine
        self.flops_governor = flops_governor
        self.benchmark_engine = CudaBenchmarkEngine(CONFIG.get("benchmark", {}), nvml_backend)
        self.fan_learner = FanCurveLearner(CONFIG.get("fan_learning", {}), nvml_backend)
        self.undervolt_learner = AdaptiveUndervoltLearner(CONFIG.get("adaptive_undervolt", {}), nvml_backend)
        if self.flops_governor is not None: self.flops_governor.set_benchmark_engine(self.benchmark_engine)

    def get_flops_status(self) -> dict[int, dict[str, Any]]:
        if self.flops_governor is None:
            return {}
        return self.flops_governor.status_all(self.telemetry_engine)

    def set_flops_target(self, gpu_index: int, target_tflops: float, enabled: Optional[bool] = None) -> dict[str, Any]:
        if self.flops_governor is None:
            return {"gpu_index": gpu_index, "error": "flops_governor_unavailable"}
        return self.flops_governor.set_target(gpu_index, target_tflops, enabled)

    def apply_flops_governor(self) -> None:
        if self.flops_governor is None:
            return
        latest_by_gpu: Dict[int, TelemetrySample] = {}
        for sample in self.telemetry_engine.get_history():
            latest_by_gpu[sample.gpu_index] = sample
        for gpu_index, sample in latest_by_gpu.items():
            try:
                self.flops_governor.apply(gpu_index, sample)
            except Exception as exc:
                print(f"[FLOPS] governor GPU {gpu_index} error: {exc}")

    def calibrate_flops(self, gpu_index: int = 0) -> dict[str, Any]:
        """Run the bounded FP32 benchmark and update calibration."""
        if self.flops_governor is None:
            return {"status": "unavailable", "reason": "flops_governor_unavailable", "gpu_index": gpu_index}
        try:
            return self.flops_governor.calibrate(gpu_index)
        except Exception as exc:
            return {"status": "error", "gpu_index": gpu_index, "error": str(exc)}

    def get_fan_learning_status(self, gpu_index: int = 0) -> dict[str, Any]:
        try:
            return self.fan_learner.status(gpu_index)
        except Exception as exc:
            return {"gpu_index": gpu_index, "error": str(exc)}

    def get_undervolt_learning_status(self, gpu_index: int = 0) -> dict[str, Any]:
        try:
            return self.undervolt_learner.status(gpu_index)
        except Exception as exc:
            return {"gpu_index": gpu_index, "error": str(exc)}

    def learn_from_telemetry(self) -> None:
        """Update optional learning models without allowing one model to kill the governor thread."""
        latest: Dict[int, TelemetrySample] = {}
        for sample in self.telemetry_engine.get_history():
            latest[sample.gpu_index] = sample
        for idx, sample in latest.items():
            try:
                fan = self.fan_learner.update(idx, sample.gpu_temp, sample.gpu_util)
                power = None
                if self.nvml_backend is not None:
                    try:
                        power = self.nvml_backend.get_power_limit_percent(idx)
                    except Exception:
                        pass
                uv = self.undervolt_learner.update(idx, sample.gpu_temp, sample.gpu_util, power)
                if CONFIG.get("fan_learning", {}).get("apply_learned_curve", False) and fan is not None and self.nvml_backend:
                    self.nvml_backend.set_fan_speed_percent(idx, fan)
                if CONFIG.get("adaptive_undervolt", {}).get("apply_automatically", False) and self.nvml_backend:
                    recommended = uv.get("recommended_power_percent")
                    if recommended is not None:
                        self.nvml_backend.set_power_limit_percent(idx, recommended)
            except Exception as exc:
                print(f"[Learning] GPU {idx} error: {exc}")

    def get_aggression(self) -> str:
        return self.cfg.get("aggression", "balanced")

    def set_aggression(self, level: str) -> None:
        if level not in ("eco", "balanced", "aggressive", "extreme"):
            return
        self.cfg["aggression"] = level
        CONFIG["tuning"]["aggression"] = level
        save_config(CONFIG)
        print(f"[TUNING] aggression set to {level}")

    def set_gpu_override(self, gpu_index: int, power_percent: Optional[float], fan_percent: Optional[float]) -> None:
        key = str(gpu_index)
        overrides = self.cfg.setdefault("gpu_overrides", {})
        entry = overrides.setdefault(key, {})
        if power_percent is not None:
            entry["power_target_percent"] = float(power_percent)
        if fan_percent is not None:
            entry["fan_percent"] = float(fan_percent)
        CONFIG["tuning"]["gpu_overrides"] = overrides
        save_config(CONFIG)
        print(f"[TUNING] override GPU {gpu_index}: {entry}")

    def apply_preset(self, preset_name: str) -> None:
        presets = CONFIG.get("profiles", {})
        preset = presets.get(preset_name)
        if not preset:
            print(f"[Profiles] unknown preset {preset_name}")
            return
        CONFIG["base_profile"]["power_target_percent"] = preset["power_target_percent"]
        CONFIG["base_profile"]["fan_target_percent"] = preset["fan_target_percent"]
        CONFIG["tuning"]["aggression"] = preset["aggression"]
        self.cfg["aggression"] = preset["aggression"]
        save_config(CONFIG)
        print(f"[Profiles] applied preset {preset_name}: {preset}")

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

    def _apply_auto_undervolt(self, gpu_index: int, base_power: float, temp: Optional[float], risk: float) -> float:
        au_cfg = self.cfg.get("auto_undervolt", {})
        if not au_cfg.get("enabled", True):
            return base_power
        temp_th = au_cfg.get("temp_threshold_c", 80.0)
        risk_th = au_cfg.get("risk_threshold", 0.6)
        max_red = au_cfg.get("max_reduction_percent", 25.0)
        if temp is None:
            return base_power
        if temp < temp_th and risk < risk_th:
            return base_power
        reduction = max_red * min(1.0, (risk - risk_th + 0.1))
        new_power = base_power - reduction
        print(f"[Undervolt] GPU {gpu_index}: temp={temp:.1f}C risk={risk:.2f} base={base_power:.1f}% -> {new_power:.1f}%")
        return new_power

    def apply_auto_tuning(self) -> None:
        if self.nvml_backend is None:
            return
        if not CONFIG["safety"]["allow_vendor_writes"]:
            return

        pred = self.prediction_engine.forecast()
        if pred.get("status") != "ok":
            return

        auto_cfg = CONFIG["auto_profile"]
        aggression = self.get_aggression()
        fan_curve = CONFIG["curves"]["fan"]["points"]
        power_curve = CONFIG["curves"]["power"]["points"]

        if aggression == "eco":
            scale = 0.7
        elif aggression == "balanced":
            scale = 1.0
        elif aggression == "aggressive":
            scale = 1.2
        else:
            scale = 1.4

        try:
            count = self.nvml_backend.device_count()
        except Exception:
            return

        overrides = self.cfg.get("gpu_overrides", {})
        hist = self.telemetry_engine.get_history()
        latest_by_gpu: Dict[int, TelemetrySample] = {}
        for s in hist:
            latest_by_gpu[s.gpu_index] = s

        risk_score = pred.get("risk_score", 0.0)

        for i in range(count):
            sample = latest_by_gpu.get(i)
            temp = sample.gpu_temp if sample else None
            util = sample.gpu_util if sample else None

            workload_class = self.ml_workload.classify(sample) if sample else "unknown"
            anomaly_info = self.ml_anomaly.check(i)

            base_power = eval_curve(power_curve, util or 0.0)
            base_fan = eval_curve(fan_curve, temp or 0.0)

            pid_output = self.thermal_pid.compute(i, temp)
            power_adjust = -pid_output * 0.5
            fan_adjust = pid_output * 1.0

            if workload_class == "idle":
                base_power *= 0.8
                base_fan *= 0.8
            elif workload_class == "gaming":
                base_power *= 1.05
                base_fan *= 1.1
            elif workload_class == "compute":
                base_power *= 1.1
                base_fan *= 1.15

            if anomaly_info.get("anomaly_temp") or anomaly_info.get("anomaly_dl"):
                base_power *= 0.9
                base_fan *= 1.1

            target_power = base_power * scale + power_adjust
            target_fan = base_fan * scale + fan_adjust

            target_power = self._apply_auto_undervolt(i, target_power, temp, risk_score)

            target_power = max(50.0, min(target_power, CONFIG["safety"]["max_power_percent"]))
            target_fan = max(0.0, min(target_fan, CONFIG["safety"]["max_fan_percent"]))

            key = str(i)
            p_i = overrides.get(key, {}).get("power_target_percent", target_power)
            f_i = overrides.get(key, {}).get("fan_percent", target_fan)

            self.nvml_backend.set_power_limit_percent(i, p_i)
            self.nvml_backend.set_fan_speed_percent(i, f_i)

        self.apply_flops_governor()


class ProfileManager:
    def __init__(
        self,
        cfg: dict[str, Any],
        bus: EventBus,
        nvml_backend: Optional[NvmlBackend],
        tuning_engine: TuningEngine,
        telemetry_engine: TelemetryEngine,
    ) -> None:
        self.cfg = cfg
        self.bus = bus
        self.current_mode = cfg.get("mode", "base")
        self.nvml_backend = nvml_backend
        self.tuning_engine = tuning_engine
        self.telemetry_engine = telemetry_engine
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
        vram_stress: VramStressTester,
        flops_governor: Optional[FlopsGovernor] = None,
    ) -> None:
        self.bus = bus
        self.telemetry = telemetry
        self.vram_engine = vram_engine
        self.prediction_engine = prediction_engine
        self.vram_stress = vram_stress
        self.flops_governor = flops_governor

    def calibrate_flops(self,gpu_index=0): return self.benchmark_engine.run(gpu_index)
    def get_fan_learning_status(self,gpu_index=0): return self.fan_learner.status(gpu_index)
    def get_undervolt_learning_status(self,gpu_index=0): return self.undervolt_learner.status(gpu_index)
    def learn_from_telemetry(self):
        latest={}
        for sample in self.telemetry_engine.get_history(): latest[sample.gpu_index]=sample
        for idx,sample in latest.items():
            fan=self.fan_learner.update(idx,sample.gpu_temp,sample.gpu_util)
            power=None
            try: power=self.nvml_backend.get_power_limit_percent(idx) if self.nvml_backend else None
            except Exception: pass
            uv=self.undervolt_learner.update(idx,sample.gpu_temp,sample.gpu_util,power)
            if CONFIG.get("fan_learning",{}).get("apply_learned_curve",False) and fan is not None and self.nvml_backend: self.nvml_backend.set_fan_speed_percent(idx,fan)
            if CONFIG.get("adaptive_undervolt",{}).get("apply_automatically",False) and self.nvml_backend and uv.get("recommended_power_percent") is not None: self.nvml_backend.set_power_limit_percent(idx,uv["recommended_power_percent"])

    def get_flops_status(self, gpu_index: Optional[int] = None) -> dict[str, Any]:
        if self.flops_governor is None:
            return {}
        if gpu_index is None:
            return self.flops_governor.status_all(self.telemetry)
        return self.flops_governor.status_for_gpu(gpu_index)

    def set_flops_target(self, gpu_index: int, target_tflops: float) -> dict[str, Any]:
        if self.flops_governor is None:
            return {"error": "flops_governor_unavailable"}
        return self.flops_governor.set_target(gpu_index, target_tflops)

    def register_telemetry_interceptor(self, fn: Callable[[TelemetrySample], TelemetrySample]) -> None:
        self.telemetry.add_interceptor(fn)

    def register_event_handler(self, event: str, handler: Callable[[Any], None]) -> None:
        self.bus.subscribe(event, handler)

    def run_vram_workload(self, size: int = 1024 * 1024) -> dict[str, Any]:
        return self.vram_engine.run_dummy_workload(size)

    def get_prediction(self) -> dict[str, Any]:
        return self.prediction_engine.forecast()

    def run_vram_stress(self, gpu_index: int = 0) -> dict[str, Any]:
        return self.vram_stress.run(gpu_index)


class PluginManager:
    def __init__(self, directory: Path, api: PluginAPI) -> None:
        self.directory = directory
        self.plugins: Dict[str, Any] = {}
        self.api = api
        self.sandbox = PluginSandbox(CONFIG.get("plugin_sandbox", {}))

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
        ml_workload: MLWorkloadClassifier,
        ml_anomaly: MLAnomalyDetector,
        dl_thermal: DLModelThermal,
    ) -> None:
        self.telemetry_engine = telemetry_engine
        self.profile_manager = profile_manager
        self.prediction_engine = prediction_engine
        self.tuning_engine = tuning_engine
        self.nvml_backend = nvml_backend
        self.ml_workload = ml_workload
        self.ml_anomaly = ml_anomaly
        self.dl_thermal = dl_thermal
        self.app = None
        self.window = None
        self.table = None
        self.pred_label = None
        self.aggression_combo = None
        self.gpu_controls: Dict[int, Dict[str, Any]] = {}
        self.fan_curve_editor = None
        self.power_curve_editor = None
        self.profile_combo = None
        self.ml_label = None
        self.fan_curve_plot = None
        self.power_curve_plot = None
        self.flops_group = None
        self.flops_controls: Dict[int, Dict[str, Any]] = {}

    def start(self) -> None:
        if not PYQT_AVAILABLE:
            print("[GUI] PyQt6 not available; GUI disabled.")
            return
        from PyQt6 import QtWidgets, QtCore, QtGui

        self.app = QtWidgets.QApplication(sys.argv)
        self.app.setApplicationName(APP_NAME)

        self.window = QtWidgets.QMainWindow()
        self.window.setWindowTitle(f"{APP_NAME} v{APP_VERSION}")
        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)

        self.table = QtWidgets.QTableWidget()
        self.table.setColumnCount(13)
        self.table.setHorizontalHeaderLabels(
            [
                "GPU", "Name", "Util %", "Temp C", "Mem Used", "Mem Total",
                "Power %", "Fan %", "Workload", "DL Residual",
                "FP32 Peak TFLOPS", "Est. TFLOPS", "Target / State"
            ]
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

        prof_row = QtWidgets.QHBoxLayout()
        prof_label = QtWidgets.QLabel("Profile preset:")
        self.profile_combo = QtWidgets.QComboBox()
        self.profile_combo.addItems(["gaming", "compute", "silent", "custom"])
        self.profile_combo.currentTextChanged.connect(self.tuning_engine.apply_preset)
        prof_row.addWidget(prof_label)
        prof_row.addWidget(self.profile_combo)
        layout.addLayout(prof_row)

        self.pred_label = QtWidgets.QLabel("Prediction: waiting...")
        layout.addWidget(self.pred_label)

        self.ml_label = QtWidgets.QLabel("ML/DL: waiting...")
        layout.addWidget(self.ml_label)

        gpu_group = QtWidgets.QGroupBox("Per‑GPU Controls (Power/Fan + Persistence)")
        gpu_layout = QtWidgets.QVBoxLayout(gpu_group)

        latest_by_gpu = self._get_latest_by_gpu()
        for idx, sample in sorted(latest_by_gpu.items()):
            row_widget = QtWidgets.QWidget()
            row_layout = QtWidgets.QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 0, 0, 0)

            label = QtWidgets.QLabel(f"GPU {idx}")
            power_slider = QtWidgets.QSlider(QtCore.Qt.Orientation.Horizontal)
            power_slider.setMinimum(50)
            power_slider.setMaximum(int(CONFIG["safety"]["max_power_percent"]))
            power_slider.setValue(int(CONFIG["tuning"]["gpu_overrides"].get(str(idx), {}).get(
                "power_target_percent",
                CONFIG["base_profile"]["power_target_percent"],
            )))
            power_slider.setTickInterval(5)
            power_slider.setTickPosition(QtWidgets.QSlider.TickPosition.TicksBelow)

            fan_slider = QtWidgets.QSlider(QtCore.Qt.Orientation.Horizontal)
            fan_slider.setMinimum(0)
            fan_slider.setMaximum(int(CONFIG["safety"]["max_fan_percent"]))
            fan_slider.setValue(int(CONFIG["tuning"]["gpu_overrides"].get(str(idx), {}).get(
                "fan_percent",
                CONFIG["base_profile"]["fan_target_percent"],
            )))
            fan_slider.setTickInterval(5)
            fan_slider.setTickPosition(QtWidgets.QSlider.TickPosition.TicksBelow)

            power_label = QtWidgets.QLabel(f"Power: {power_slider.value()}%")
            fan_label = QtWidgets.QLabel(f"Fan: {fan_slider.value()}%")

            def make_power_cb(gpu_i: int, slider: QtWidgets.QSlider, lbl: QtWidgets.QLabel):
                def cb(value: int):
                    lbl.setText(f"Power: {value}%")
                    self.tuning_engine.set_gpu_override(gpu_i, power_percent=value, fan_percent=None)
                    if self.nvml_backend is not None:
                        self.nvml_backend.set_power_limit_percent(gpu_i, value)
                return cb

            def make_fan_cb(gpu_i: int, slider: QtWidgets.QSlider, lbl: QtWidgets.QLabel):
                def cb(value: int):
                    lbl.setText(f"Fan: {value}%")
                    self.tuning_engine.set_gpu_override(gpu_i, power_percent=None, fan_percent=value)
                    if self.nvml_backend is not None:
                        self.nvml_backend.set_fan_speed_percent(gpu_i, value)
                return cb

            power_slider.valueChanged.connect(make_power_cb(idx, power_slider, power_label))
            fan_slider.valueChanged.connect(make_fan_cb(idx, fan_slider, fan_label))

            row_layout.addWidget(label)
            row_layout.addWidget(power_label)
            row_layout.addWidget(power_slider)
            row_layout.addWidget(fan_label)
            row_layout.addWidget(fan_slider)

            gpu_layout.addWidget(row_widget)

            self.gpu_controls[idx] = {
                "power_slider": power_slider,
                "fan_slider": fan_slider,
                "power_label": power_label,
                "fan_label": fan_label,
            }

        layout.addWidget(gpu_group)


        flops_group = QtWidgets.QGroupBox("FP32 FLOPS Governor (estimated theoretical throughput)")
        flops_layout = QtWidgets.QVBoxLayout(flops_group)
        flops_help = QtWidgets.QLabel(
            "Target TFLOPS is a performance envelope, not a guaranteed measured FLOPS rate. "
            "Actual FLOPS depends on workload. Clock locking is optional and disabled by default."
        )
        flops_help.setWordWrap(True)
        flops_layout.addWidget(flops_help)

        self.flops_group = flops_group
        latest_for_flops = self._get_latest_by_gpu()
        gpu_indices = sorted(latest_for_flops.keys())
        if self.nvml_backend is not None:
            try:
                gpu_indices = sorted(set(gpu_indices) | set(range(self.nvml_backend.device_count())))
            except Exception:
                pass

        for idx in gpu_indices:
            row_widget = QtWidgets.QWidget()
            row_layout = QtWidgets.QHBoxLayout(row_widget)
            row_layout.setContentsMargins(0, 0, 0, 0)

            row_layout.addWidget(QtWidgets.QLabel(f"GPU {idx}"))
            target_spin = QtWidgets.QDoubleSpinBox()
            target_spin.setRange(
                float(CONFIG["flops"].get("min_target_tflops", 0.1)),
                float(CONFIG["flops"].get("max_target_tflops", 200.0)),
            )
            target_spin.setDecimals(2)
            target_spin.setSingleStep(0.25)
            configured = CONFIG["flops"].get("targets", {}).get(
                str(idx), CONFIG["flops"].get("default_target_tflops", 0.0)
            )
            status = self.tuning_engine.get_flops_status().get(idx, {})
            if configured and float(configured) > 0:
                target_spin.setValue(float(configured))
            elif status.get("fp32_peak_tflops", 0) > 0:
                target_spin.setValue(float(status["fp32_peak_tflops"]))
            else:
                target_spin.setValue(float(target_spin.minimum()))

            enabled_box = QtWidgets.QCheckBox("Enable")
            enabled_box.setChecked(bool(CONFIG["flops"].get("enabled", True)))

            apply_btn = QtWidgets.QPushButton("Apply")
            status_label = QtWidgets.QLabel("FLOPS: waiting")

            def make_apply(gpu_i: int, spin: QtWidgets.QDoubleSpinBox, box: QtWidgets.QCheckBox, lbl: QtWidgets.QLabel):
                def cb():
                    result = self.tuning_engine.set_flops_target(gpu_i, spin.value(), box.isChecked())
                    lbl.setText(
                        f"Target {result.get('target_tflops', spin.value()):.2f} TFLOPS | "
                        f"Est {result.get('fp32_estimated_tflops', 0.0):.2f} | "
                        f"{result.get('control_state', 'MONITOR')}"
                    )
                return cb

            apply_btn.clicked.connect(make_apply(idx, target_spin, enabled_box, status_label))
            row_layout.addWidget(target_spin)
            row_layout.addWidget(QtWidgets.QLabel("TFLOPS"))
            row_layout.addWidget(enabled_box)
            row_layout.addWidget(apply_btn)
            row_layout.addWidget(status_label)
            flops_layout.addWidget(row_widget)

            self.flops_controls[idx] = {
                "target_spin": target_spin,
                "enabled_box": enabled_box,
                "status_label": status_label,
            }

        layout.addWidget(flops_group)

        curves_group = QtWidgets.QGroupBox("Curves (Fan / Power)")
        curves_layout = QtWidgets.QHBoxLayout(curves_group)

        self.fan_curve_editor = QtWidgets.QPlainTextEdit()
        self.fan_curve_editor.setPlainText(json.dumps(CONFIG["curves"]["fan"]["points"], indent=2))
        self.power_curve_editor = QtWidgets.QPlainTextEdit()
        self.power_curve_editor.setPlainText(json.dumps(CONFIG["curves"]["power"]["points"], indent=2))

        curves_layout.addWidget(QtWidgets.QLabel("Fan curve [temp, fan%]:"))
        curves_layout.addWidget(self.fan_curve_editor)
        curves_layout.addWidget(QtWidgets.QLabel("Power curve [util, power%]:"))
        curves_layout.addWidget(self.power_curve_editor)

        layout.addWidget(curves_group)

        plot_group = QtWidgets.QGroupBox("Curve Visualizer")
        plot_layout = QtWidgets.QHBoxLayout(plot_group)

        self.fan_curve_plot = QtWidgets.QLabel()
        self.power_curve_plot = QtWidgets.QLabel()
        self.fan_curve_plot.setMinimumSize(300, 200)
        self.power_curve_plot.setMinimumSize(300, 200)

        plot_layout.addWidget(QtWidgets.QLabel("Fan curve graph:"))
        plot_layout.addWidget(self.fan_curve_plot)
        plot_layout.addWidget(QtWidgets.QLabel("Power curve graph:"))
        plot_layout.addWidget(self.power_curve_plot)

        layout.addWidget(plot_group)

        save_curves_btn = QtWidgets.QPushButton("Save Curves")
        def save_curves():
            try:
                fan_points = json.loads(self.fan_curve_editor.toPlainText())
                power_points = json.loads(self.power_curve_editor.toPlainText())
                CONFIG["curves"]["fan"]["points"] = fan_points
                CONFIG["curves"]["power"]["points"] = power_points
                save_config(CONFIG)
                print("[Curves] saved fan/power curves")
                self._update_curve_plots()
            except Exception as e:
                print(f"[Curves] save error: {e}")
        save_curves_btn.clicked.connect(save_curves)
        layout.addWidget(save_curves_btn)

        reset_btn = QtWidgets.QPushButton("Factory Reset (Config)")
        def do_reset():
            factory_reset()
            self.fan_curve_editor.setPlainText(json.dumps(CONFIG["curves"]["fan"]["points"], indent=2))
            self.power_curve_editor.setPlainText(json.dumps(CONFIG["curves"]["power"]["points"], indent=2))
            self.aggression_combo.setCurrentText(CONFIG["tuning"]["aggression"])
            self._update_curve_plots()
        reset_btn.clicked.connect(do_reset)
        layout.addWidget(reset_btn)

        save_btn = QtWidgets.QPushButton("Save Configuration")
        save_btn.clicked.connect(lambda: save_config(CONFIG))
        layout.addWidget(save_btn)

        self.window.setCentralWidget(central)
        self.window.resize(1300, 800)
        self.window.show()

        from PyQt6 import QtCore as QtC
        timer = QtC.QTimer()
        timer.timeout.connect(self._update_dashboard)
        timer.start(int(CONFIG.get("telemetry", {}).get("interval", 1.0) * 1000))

        self._update_curve_plots()

        self.app.exec()

    def _get_latest_by_gpu(self) -> Dict[int, TelemetrySample]:
        hist = self.telemetry_engine.get_history()
        latest_by_gpu: Dict[int, TelemetrySample] = {}
        for s in hist:
            latest_by_gpu[s.gpu_index] = s
        return latest_by_gpu

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
            workload = self.ml_workload.classify(sample)
            dl_residual = self.dl_thermal.residual_error(idx)
            self.table.setItem(row, 0, self._cell(str(idx)))
            self.table.setItem(row, 1, self._cell(str(name)))
            self.table.setItem(row, 2, self._cell(str(util)))
            self.table.setItem(row, 3, self._cell(str(temp)))
            self.table.setItem(row, 4, self._cell(str(mem_used)))
            self.table.setItem(row, 5, self._cell(str(mem_total)))
            self.table.setItem(row, 6, self._cell(str(power)))
            self.table.setItem(row, 7, self._cell(str(fan)))
            self.table.setItem(row, 8, self._cell(workload))
            flops_status = self.tuning_engine.get_flops_status().get(idx, {})
            peak_t = _safe_float(flops_status.get("fp32_peak_tflops"), 0.0)
            est_t = _safe_float(flops_status.get("fp32_estimated_tflops"), 0.0)
            target_t = _safe_float(flops_status.get("target_tflops"), 0.0)
            state = flops_status.get("control_state", "MONITOR")
            self.table.setItem(row, 9, self._cell(f"{dl_residual:.2f}"))
            self.table.setItem(row, 10, self._cell(f"{peak_t:.2f}"))
            self.table.setItem(row, 11, self._cell(f"{est_t:.2f}"))
            self.table.setItem(row, 12, self._cell(f"{target_t:.2f} / {state}"))

            if idx in self.flops_controls:
                c = self.flops_controls[idx]
                c["status_label"].setText(
                    f"Est {est_t:.2f} / {target_t:.2f} TFLOPS | {state}"
                )

        pred = self.prediction_engine.forecast()
        if pred.get("status") == "ok":
            self.pred_label.setText(
                f"Prediction: temp {pred['temp_now']:.1f}→{pred['temp_future']:.1f}C "
                f"(DL {pred['temp_future_dl']:.1f}C, ML {pred['temp_future_ml']:.1f}C), "
                f"util {pred['util_now']:.1f}→{pred['util_future']:.1f}% "
                f"risk={pred['risk_score']:.2f} conf={pred['confidence']:.2f}"
            )
        else:
            self.pred_label.setText(f"Prediction: {pred.get('status')}")
        any_idx = list(latest_by_gpu.keys())[0]
        anomaly = self.ml_anomaly.check(any_idx)
        if anomaly.get("status") == "ok":
            self.ml_label.setText(
                f"ML/DL: z_temp={anomaly['z_temp']:.2f} z_util={anomaly['z_util']:.2f} "
                f"dl_residual={anomaly['dl_residual']:.2f} "
                f"anomaly_temp={anomaly['anomaly_temp']} anomaly_util={anomaly['anomaly_util']} "
                f"anomaly_dl={anomaly['anomaly_dl']}"
            )
        else:
            self.ml_label.setText(f"ML/DL: {anomaly.get('status')}")

    def _update_curve_plots(self) -> None:
        if not PYQT_AVAILABLE:
            return
        from PyQt6 import QtGui

        def render_curve(points: List[List[float]], width: int, height: int) -> QtGui.QPixmap:
            pix = QtGui.QPixmap(width, height)
            pix.fill(QtGui.QColor("black"))
            painter = QtGui.QPainter(pix)
            painter.setRenderHint(QtGui.QPainter.RenderHint.Antialiasing)
            painter.setPen(QtGui.QPen(QtGui.QColor("white"), 2))
            if not points:
                painter.end()
                return pix
            pts = sorted(points, key=lambda p: p[0])
            xs = [p[0] for p in pts]
            ys = [p[1] for p in pts]
            min_x, max_x = min(xs), max(xs)
            min_y, max_y = min(ys), max(ys)
            if max_x == min_x:
                max_x += 1
            if max_y == min_y:
                max_y += 1
            margin = 10
            def map_x(x):
                return margin + (x - min_x) / (max_x - min_x) * (width - 2 * margin)
            def map_y(y):
                return height - margin - (y - min_y) / (max_y - min_y) * (height - 2 * margin)
            for i in range(len(pts) - 1):
                x0, y0 = pts[i]
                x1, y1 = pts[i + 1]
                painter.drawLine(int(map_x(x0)), int(map_y(y0)), int(map_x(x1)), int(map_y(y1)))
            painter.end()
            return pix

        fan_points = CONFIG["curves"]["fan"]["points"]
        power_points = CONFIG["curves"]["power"]["points"]
        fan_pix = render_curve(fan_points, self.fan_curve_plot.width(), self.fan_curve_plot.height())
        power_pix = render_curve(power_points, self.power_curve_plot.width(), self.power_curve_plot.height())
        self.fan_curve_plot.setPixmap(fan_pix)
        self.power_curve_plot.setPixmap(power_pix)

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
        ml_workload: MLWorkloadClassifier,
        ml_anomaly: MLAnomalyDetector,
        ml_thermal: MLModelThermal,
        dl_thermal: DLModelThermal,
        vram_stress: VramStressTester,
        flops_governor: Optional[FlopsGovernor] = None,
    ) -> None:
        self.cfg = cfg
        self.telemetry_engine = telemetry_engine
        self.profile_manager = profile_manager
        self.vram_engine = vram_engine
        self.prediction_engine = prediction_engine
        self.plugin_manager = plugin_manager
        self.tuning_engine = tuning_engine
        self.swarm_manager = swarm_manager
        self.ml_workload = ml_workload
        self.ml_anomaly = ml_anomaly
        self.ml_thermal = ml_thermal
        self.dl_thermal = dl_thermal
        self.vram_stress = vram_stress
        self.flops_governor = flops_governor
        self.cluster = ClusterController(CONFIG.get("cluster", {}), telemetry_engine)
        self.cluster_peers = {}

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

        async def handle_profiles_preset(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            preset = data.get("preset", "gaming")
            self.tuning_engine.apply_preset(preset)
            return aiohttp.web.json_response({"ok": True, "preset": preset})

        async def handle_vram(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            size = int(data.get("size", 1024 * 1024))
            result = self.vram_engine.run_dummy_workload(size)
            return aiohttp.web.json_response(result)

        async def handle_vram_stress(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            gpu_index = int(data.get("gpu_index", 0))
            result = self.vram_stress.run(gpu_index)
            return aiohttp.web.json_response(result)

        async def handle_prediction(request: aiohttp.web.Request) -> aiohttp.web.Response:
            result = self.prediction_engine.forecast()
            return aiohttp.web.json_response(result)

        async def handle_plugins(request: aiohttp.web.Request) -> aiohttp.web.Response:
            names = list(self.plugin_manager.plugins.keys())
            return aiohttp.web.json_response({"plugins": names})


        async def handle_benchmark(request):
            data=await request.json() if request.can_read_body else {}; return aiohttp.web.json_response(self.tuning_engine.calibrate_flops(int(data.get("gpu_index",0))))
        async def handle_fan_learning(request): return aiohttp.web.json_response(self.tuning_engine.get_fan_learning_status(int(request.query.get("gpu_index",0))))
        async def handle_undervolt_learning(request): return aiohttp.web.json_response(self.tuning_engine.get_undervolt_learning_status(int(request.query.get("gpu_index",0))))
        async def handle_cluster_status(request): return aiohttp.web.json_response(self.cluster.local_snapshot())
        async def handle_cluster_broadcast(request):
            if not CONFIG.get("cluster",{}).get("enabled",True): return aiohttp.web.json_response({"ok":False,"error":"cluster_disabled"},status=403)
            data=await request.json(); body,sig=self.cluster.sign(data); import urllib.request; results=[]
            for peer in CONFIG.get("sync",{}).get("peers",[]):
                try:
                    req=urllib.request.Request(peer.rstrip("/")+"/cluster/ingest",data=body,headers={"Content-Type":"application/json","X-Cluster-Signature":sig},method="POST")
                    with urllib.request.urlopen(req,timeout=float(CONFIG["cluster"].get("broadcast_timeout_seconds",3))) as r: results.append({"peer":peer,"status":r.status})
                except Exception as e: results.append({"peer":peer,"error":str(e)})
            return aiohttp.web.json_response({"ok":True,"results":results})
        async def handle_cluster_ingest(request):
            body=await request.read()
            if not self.cluster.verify(body,request.headers.get("X-Cluster-Signature","")): return aiohttp.web.json_response({"ok":False,"error":"invalid_signature"},status=401)
            try: data=json.loads(body)
            except Exception: data={}
            self.cluster_peers[data.get("node_id","unknown")]=data; return aiohttp.web.json_response({"ok":True})
        async def handle_cluster_control(request):
            body=await request.read()
            if not self.cluster.verify(body,request.headers.get("X-Cluster-Signature","")):
                return aiohttp.web.json_response({"ok":False,"error":"invalid_signature"},status=401)
            try: data=json.loads(body)
            except Exception: return aiohttp.web.json_response({"ok":False,"error":"invalid_json"},status=400)
            action=data.get("action")
            try:
                if action=="set_flops":
                    result=self.tuning_engine.set_flops_target(int(data.get("gpu_index",0)),float(data.get("target_tflops",0)),data.get("enabled"))
                elif action=="set_power":
                    idx=int(data.get("gpu_index",0)); result={"ok":bool(self.tuning_engine.nvml_backend and self.tuning_engine.nvml_backend.set_power_limit_percent(idx,float(data.get("power_percent",100))))}
                elif action=="set_profile":
                    mode=str(data.get("mode","auto")); self.profile_manager.apply_mode(mode); result={"ok":True,"mode":mode}
                else: return aiohttp.web.json_response({"ok":False,"error":"unsupported_action"},status=400)
                return aiohttp.web.json_response({"ok":True,"result":result})
            except Exception as e: return aiohttp.web.json_response({"ok":False,"error":str(e)},status=400)

        async def handle_dashboard(request):
            html="<!doctype html><html><meta charset='utf-8'><title>GPU Control Center</title><body><h1>GPU Control Center</h1><pre id='o'>Loading...</pre><script>async function r(){try{document.getElementById('o').textContent=JSON.stringify(await (await fetch('/cluster/status')).json(),null,2)}catch(e){document.getElementById('o').textContent=e}}setInterval(r,1000);r()</script></body></html>"
            return aiohttp.web.Response(text=html,content_type="text/html")

        async def handle_tuning_flops(request: aiohttp.web.Request) -> aiohttp.web.Response:
            if request.method == "GET":
                return aiohttp.web.json_response(self.tuning_engine.get_flops_status())
            data = await request.json()
            gpu_index = int(data.get("gpu_index", 0))
            target = float(data.get("target_tflops", data.get("target", 0.0)))
            enabled = data.get("enabled")
            result = self.tuning_engine.set_flops_target(gpu_index, target, enabled)
            return aiohttp.web.json_response(result)

        async def handle_tuning_power(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            gpu_index = int(data.get("gpu_index", 0))
            percent = float(data.get("percent", 100.0))
            if self.tuning_engine.nvml_backend is None:
                return aiohttp.web.json_response({"ok": False, "error": "nvml_unavailable"})
            ok = self.tuning_engine.nvml_backend.set_power_limit_percent(gpu_index, percent)
            self.tuning_engine.set_gpu_override(gpu_index, power_percent=percent, fan_percent=None)
            return aiohttp.web.json_response({"ok": ok})

        async def handle_tuning_fan(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            gpu_index = int(data.get("gpu_index", 0))
            percent = float(data.get("percent", 50.0))
            if self.tuning_engine.nvml_backend is None:
                return aiohttp.web.json_response({"ok": False, "error": "nvml_unavailable"})
            ok = self.tuning_engine.nvml_backend.set_fan_speed_percent(gpu_index, percent)
            self.tuning_engine.set_gpu_override(gpu_index, power_percent=None, fan_percent=percent)
            return aiohttp.web.json_response({"ok": ok})

        async def handle_tuning_aggression(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            level = data.get("level", "balanced")
            self.tuning_engine.set_aggression(level)
            return aiohttp.web.json_response({"ok": True, "level": level})

        async def handle_tuning_gpu_override(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            gpu_index = int(data.get("gpu_index", 0))
            power = data.get("power_percent")
            fan = data.get("fan_percent")
            self.tuning_engine.set_gpu_override(gpu_index, power_percent=power, fan_percent=fan)
            return aiohttp.web.json_response({"ok": True})

        async def handle_curves_fan(request: aiohttp.web.Request) -> aiohttp.web.Response:
            if request.method == "GET":
                return aiohttp.web.json_response(CONFIG["curves"]["fan"])
            data = await request.json()
            points = data.get("points")
            if isinstance(points, list):
                CONFIG["curves"]["fan"]["points"] = points
                save_config(CONFIG)
            return aiohttp.web.json_response({"ok": True})

        async def handle_curves_power(request: aiohttp.web.Request) -> aiohttp.web.Response:
            if request.method == "GET":
                return aiohttp.web.json_response(CONFIG["curves"]["power"])
            data = await request.json()
            points = data.get("points")
            if isinstance(points, list):
                CONFIG["curves"]["power"]["points"] = points
                save_config(CONFIG)
            return aiohttp.web.json_response({"ok": True})

        async def handle_thermal_pid(request: aiohttp.web.Request) -> aiohttp.web.Response:
            if request.method == "GET":
                return aiohttp.web.json_response(CONFIG["thermal_pid"])
            data = await request.json()
            for k in ("enabled", "target_temp_c", "kp", "ki", "kd", "integral_limit"):
                if k in data:
                    CONFIG["thermal_pid"][k] = data[k]
            save_config(CONFIG)
            return aiohttp.web.json_response({"ok": True})

        async def handle_swarm_status(request: aiohttp.web.Request) -> aiohttp.web.Response:
            leader = self.swarm_manager.get_leader()
            return aiohttp.web.json_response({"leader": leader, "node_id": CONFIG["sync"]["node_id"]})

        async def handle_swarm_sync(request: aiohttp.web.Request) -> aiohttp.web.Response:
            data = await request.json()
            node_id = data.get("node_id")
            print(f"[Swarm] received payload from {node_id}")
            return aiohttp.web.json_response({"ok": True})

        async def handle_config_get(request: aiohttp.web.Request) -> aiohttp.web.Response:
            return aiohttp.web.json_response(CONFIG)

        async def handle_config_save(request: aiohttp.web.Request) -> aiohttp.web.Response:
            save_config(CONFIG)
            return aiohttp.web.json_response({"ok": True})

        async def handle_config_reset(request: aiohttp.web.Request) -> aiohttp.web.Response:
            factory_reset()
            return aiohttp.web.json_response({"ok": True, "status": "reset"})

        async def handle_ml_prediction(request: aiohttp.web.Request) -> aiohttp.web.Response:
            result = self.prediction_engine.forecast()
            return aiohttp.web.json_response(result)

        async def handle_ml_workload(request: aiohttp.web.Request) -> aiohttp.web.Response:
            hist = self.telemetry_engine.get_history()
            latest_by_gpu: Dict[int, TelemetrySample] = {}
            for s in hist:
                latest_by_gpu[s.gpu_index] = s
            payload = {}
            for idx, sample in latest_by_gpu.items():
                payload[idx] = {
                    "workload": self.ml_workload.classify(sample),
                    "sample": asdict(sample),
                }
            return aiohttp.web.json_response(payload)

        async def handle_ml_anomaly(request: aiohttp.web.Request) -> aiohttp.web.Response:
            hist = self.telemetry_engine.get_history()
            latest_by_gpu: Dict[int, TelemetrySample] = {}
            for s in hist:
                latest_by_gpu[s.gpu_index] = s
            payload = {}
            for idx in latest_by_gpu.keys():
                payload[idx] = self.ml_anomaly.check(idx)
            return aiohttp.web.json_response(payload)

        async def handle_ml_dl_prediction(request: aiohttp.web.Request) -> aiohttp.web.Response:
            hist = self.telemetry_engine.get_history()
            latest_by_gpu: Dict[int, TelemetrySample] = {}
            for s in hist:
                latest_by_gpu[s.gpu_index] = s
            payload = {}
            for idx, sample in latest_by_gpu.items():
                temp_future = self.dl_thermal.predict(idx, sample, CONFIG["prediction"]["horizon_seconds"])
                payload[idx] = {
                    "temp_now": sample.gpu_temp,
                    "temp_future_dl": temp_future,
                }
            return aiohttp.web.json_response(payload)

        app.router.add_get("/status", handle_status)
        app.router.add_get("/gpu", handle_gpu)
        app.router.add_route("*", "/profiles", handle_profiles)
        app.router.add_post("/profiles/preset", handle_profiles_preset)
        app.router.add_post("/vram", handle_vram)
        app.router.add_post("/vram/stress", handle_vram_stress)
        app.router.add_get("/prediction", handle_prediction)
        app.router.add_get("/plugins", handle_plugins)
        app.router.add_route("*", "/tuning/flops", handle_tuning_flops)
        app.router.add_post("/benchmark/flops", handle_benchmark)
        app.router.add_get("/learning/fan", handle_fan_learning)
        app.router.add_get("/learning/undervolt", handle_undervolt_learning)
        app.router.add_get("/cluster/status", handle_cluster_status)
        app.router.add_post("/cluster/broadcast", handle_cluster_broadcast)
        app.router.add_post("/cluster/ingest", handle_cluster_ingest)
        app.router.add_post("/cluster/control", handle_cluster_control)
        app.router.add_get("/dashboard", handle_dashboard)
        app.router.add_post("/tuning/power", handle_tuning_power)
        app.router.add_post("/tuning/fan", handle_tuning_fan)
        app.router.add_post("/tuning/aggression", handle_tuning_aggression)
        app.router.add_post("/tuning/gpu_override", handle_tuning_gpu_override)
        app.router.add_route("*", "/curves/fan", handle_curves_fan)
        app.router.add_route("*", "/curves/power", handle_curves_power)
        app.router.add_route("*", "/thermal/pid", handle_thermal_pid)
        app.router.add_get("/swarm/status", handle_swarm_status)
        app.router.add_post("/swarm/sync", handle_swarm_sync)
        app.router.add_get("/config/get", handle_config_get)
        app.router.add_post("/config/save", handle_config_save)
        app.router.add_post("/config/reset", handle_config_reset)
        app.router.add_get("/ml/prediction", handle_ml_prediction)
        app.router.add_get("/ml/workload", handle_ml_workload)
        app.router.add_get("/ml/anomaly", handle_ml_anomaly)
        app.router.add_get("/ml/dl_prediction", handle_ml_dl_prediction)

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

    vram_stress_cfg = CONFIG.get("vram_stress", {})
    vram_stress = VramStressTester(vram_stress_cfg, nvml_backend, telemetry_engine)

    ml_cfg = CONFIG.get("ml", {})
    ml_thermal = MLModelThermal(ml_cfg.get("thermal", {}))
    dl_thermal = DLModelThermal(ml_cfg.get("dl", {}))
    ml_workload = MLWorkloadClassifier(ml_cfg)
    ml_anomaly = MLAnomalyDetector(ml_cfg, dl_thermal)

    def ml_interceptor(sample: TelemetrySample) -> TelemetrySample:
        ml_thermal.update(sample)
        dl_thermal.update(sample)
        ml_anomaly.update(sample)
        return sample

    telemetry_engine.add_interceptor(ml_interceptor)

    prediction_engine = PredictionEngine(CONFIG.get("prediction", {}), telemetry_engine, ml_thermal, dl_thermal)
    thermal_pid = ThermalPIDController(CONFIG.get("thermal_pid", {}))
    flops_governor = FlopsGovernor(CONFIG.get("flops", {}), nvml_backend)

    tuning_engine = TuningEngine(
        CONFIG.get("tuning", {}),
        nvml_backend,
        prediction_engine,
        thermal_pid,
        ml_workload,
        ml_anomaly,
        telemetry_engine,
        flops_governor=flops_governor,
    )

    profile_manager = ProfileManager(CONFIG, bus, nvml_backend, tuning_engine, telemetry_engine)

    plugin_api = PluginAPI(
        bus, telemetry_engine, vram_engine, prediction_engine, vram_stress, flops_governor
    )
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
        ml_workload,
        ml_anomaly,
        ml_thermal,
        dl_thermal,
        vram_stress,
        flops_governor,
    )

    gui_shell = GuiShell(
        telemetry_engine,
        profile_manager,
        prediction_engine,
        tuning_engine,
        nvml_backend,
        ml_workload,
        ml_anomaly,
        dl_thermal,
    )

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
        last_benchmark = 0.0
        try:
            while True:
                profile_manager.auto_tick()
                tuning_engine.learn_from_telemetry()
                if CONFIG.get("benchmark", {}).get("enabled", True) and time.time() - last_benchmark >= float(CONFIG.get("benchmark", {}).get("interval_seconds", 30.0)):
                    if nvml_backend is not None:
                        for gpu_idx in range(nvml_backend.device_count()):
                            result = tuning_engine.benchmark_engine.run(gpu_idx)
                            if result.get("status") == "ok": print(f"[BENCHMARK] GPU {gpu_idx}: {result.get('measured_fp32_tflops', 0.0):.2f} TFLOPS")
                    last_benchmark = time.time()
                if CONFIG.get("mode") != "auto": tuning_engine.apply_flops_governor()
                plugin_manager.tick()
                time.sleep(CONFIG["telemetry"]["interval"])
        except KeyboardInterrupt:
            print("[RUNTIME] Shutdown requested.")
        except Exception as exc:
            print(f"[RUNTIME] governor loop recovered from error: {exc}")
            traceback.print_exc()

    loop_thread = threading.Thread(target=governor_loop, daemon=True, name="GPU-Governor")
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

    plugin_manager.sandbox.stop_all()
    telemetry_engine.stop()
    swarm_manager.stop()
    if nvml_backend is not None:
        nvml_backend.stop()


def main() -> None:
    print(f"{APP_NAME} v{APP_VERSION} starting...")
    print(f"[CONFIG] mode={CONFIG.get('mode')}")
    try:
        relaunch_elevated_if_needed()
        start_governor_runtime()
    except KeyboardInterrupt:
        print("[RUNTIME] Shutdown requested.")
    except Exception as exc:
        print(f"[FATAL] Startup failed: {exc}")
        traceback.print_exc()
        raise


if __name__ == "__main__":
    main()
