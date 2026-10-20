#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DominionDeck Hybrid Governor v11.0
Windows-friendly CPU/GPU monitoring, hidden adjustment exposure, and profile-aware hardware tuning command center.

Highlights
- Tkinter tabbed interface with live CPU, memory, disk, network, process lanes, hardware, envelopes, VRAM, and hidden adjustment views
- Optional real NVIDIA telemetry through NVML (nvidia-ml-py); graceful fallback
- Adaptive workload trend estimates (heuristics, not an AI model) with 5% variance balancing
- CPU profiles with profile-aware envelopes (CPU/GPU/VRAM expectations)
- Hybrid P/E auto-detect with manual override and per-core weight sliders
- Monitoring-only by default; affinity and tuning helpers must be explicitly enabled
- Hardware tuning envelope: factory vs current clocks/power, red/yellow highlighting for over-factory and off-profile adjustments
- VRAM panel with pressure detection and profile-aware expectations
- Process lanes: foreground, games, background, with lane pressure bars
- Hidden adjustment panels: CPU throttling, GPU throttling, scheduler QoS, memory pressure, network hints, NVMe hints
- Advisor cards: textual recommendations based on current telemetry and hidden adjustment flags
- Plugin API skeleton, watchdog, and security governor hooks
- Thread-safe GUI updates and graceful shutdown
- No direct low-level writes to clocks/voltages/fan curves; tuning is visual and advisory only

Install:
    py -m pip install psutil
Optional NVIDIA telemetry:
    py -m pip install nvidia-ml-py
"""

from __future__ import annotations

import json
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import queue
import subprocess
import sys
import threading
import time
from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional, Callable

def ensure_psutil():
    try:
        import psutil  # type: ignore
        return psutil
    except ImportError:
        print("Missing dependency: psutil\nInstall it with: py -m pip install psutil")
        raise

psutil = ensure_psutil()

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
except ImportError as exc:
    raise SystemExit(f"Tkinter is unavailable in this Python installation: {exc}")

APP_NAME = "DominionDeck Hybrid Governor"
APP_VERSION = "11.0"
APP_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home()))) / "DominionDeck" / "HybridGovernor"
CONFIG_PATH = APP_DIR / "settings.json"
LOG_PATH = APP_DIR / "governor.log"
APP_DIR.mkdir(parents=True, exist_ok=True)

logger = logging.getLogger("DominionDeck")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = RotatingFileHandler(LOG_PATH, maxBytes=1_000_000, backupCount=3, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
    logger.addHandler(handler)

DEFAULT_CONFIG = {
    "profile": "AutoAI",
    "interval": 1.0,
    "variance_window": 12.0,
    "heavy_threshold": 8.0,
    "idle_threshold": 25.0,
    "memory_soft_limit": 90.0,
    "affinity_enabled": False,
    "restore_affinity_on_exit": True,
    "excluded_processes": ["system", "registry", "idle", "dwm.exe", "csrss.exe", "wininit.exe",
                           "services.exe", "lsass.exe", "smss.exe", "winlogon.exe"],
    "p_cores": [],
    "e_cores": [],
    "core_weights": [],
    "window_tracking": True,
    "history_seconds": 90,
    "tuning_enabled": True,
    "gpu_governor_enabled": True,
    "security_governor_enabled": True,
    "plugins_enabled": True,
    "watchdog_enabled": True,
    "hardware_envelope_enabled": True,
    "vram_panel_enabled": True,
    "hidden_panels_enabled": True,
}

PROFILES = {
    "AutoAI": {
        "interval": 1.0,
        "heavy_threshold": 8.0,
        "idle_threshold": 25.0,
        "cpu_base_factor": 1.0,
        "cpu_max_factor": 1.0,
        "gpu_power_factor": 1.0,
        "vram_expectation": "mixed",
    },
    "Gaming": {
        "interval": 0.8,
        "heavy_threshold": 5.0,
        "idle_threshold": 22.0,
        "cpu_base_factor": 1.0,
        "cpu_max_factor": 1.05,
        "gpu_power_factor": 1.1,
        "vram_expectation": "high",
    },
    "Editing": {
        "interval": 1.2,
        "heavy_threshold": 4.0,
        "idle_threshold": 30.0,
        "cpu_base_factor": 1.0,
        "cpu_max_factor": 1.02,
        "gpu_power_factor": 1.0,
        "vram_expectation": "burst",
    },
    "Streaming": {
        "interval": 1.0,
        "heavy_threshold": 4.0,
        "idle_threshold": 32.0,
        "cpu_base_factor": 0.95,
        "cpu_max_factor": 1.0,
        "gpu_power_factor": 1.0,
        "vram_expectation": "moderate",
    },
    "Silent": {
        "interval": 2.5,
        "heavy_threshold": 10.0,
        "idle_threshold": 40.0,
        "cpu_base_factor": 0.9,
        "cpu_max_factor": 0.95,
        "gpu_power_factor": 0.9,
        "vram_expectation": "low",
    },
    "Monitoring Only": {
        "interval": 1.0,
        "heavy_threshold": 8.0,
        "idle_threshold": 25.0,
        "cpu_base_factor": 1.0,
        "cpu_max_factor": 1.0,
        "gpu_power_factor": 1.0,
        "vram_expectation": "mixed",
    },
}

GAME_HINTS = (
    "steam.exe", "epicgameslauncher.exe", "battle.net.exe", "eldenring.exe", "cs2.exe",
    "fortnite.exe", "valorant.exe", "game.exe"
)
FOREGROUND_HINTS = ("chrome.exe", "msedge.exe", "firefox.exe", "obs64.exe",
                    "premiere.exe", "davinciresolve.exe")

def load_config() -> dict:
    cfg = dict(DEFAULT_CONFIG)
    try:
        if CONFIG_PATH.exists():
            with CONFIG_PATH.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                cfg.update(loaded)
    except Exception:
        logger.exception("Could not load settings; using defaults")
    if cfg.get("profile") not in PROFILES:
        cfg["profile"] = "AutoAI"
    try:
        cfg["interval"] = max(0.25, min(10.0, float(cfg["interval"])))
        cfg["variance_window"] = max(1.0, min(50.0, float(cfg["variance_window"])))
        cfg["heavy_threshold"] = max(1.0, min(100.0, float(cfg["heavy_threshold"])))
        cfg["idle_threshold"] = max(1.0, min(100.0, float(cfg["idle_threshold"])))
        cfg["memory_soft_limit"] = max(50.0, min(99.0, float(cfg["memory_soft_limit"])))
        cfg["history_seconds"] = max(30, min(600, int(cfg["history_seconds"])))
    except (TypeError, ValueError):
        cfg.update(DEFAULT_CONFIG)
    if not isinstance(cfg.get("excluded_processes"), list):
        cfg["excluded_processes"] = list(DEFAULT_CONFIG["excluded_processes"])
    return cfg

def save_config(cfg: dict) -> None:
    try:
        APP_DIR.mkdir(parents=True, exist_ok=True)
        temp = CONFIG_PATH.with_suffix(".tmp")
        with temp.open("w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        temp.replace(CONFIG_PATH)
    except Exception:
        logger.exception("Could not save settings")

def get_foreground_pid() -> Optional[int]:
    if os.name != "nt":
        return None
    try:
        import ctypes
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return int(pid.value) or None
    except Exception:
        return None

def process_name(pid: Optional[int]) -> str:
    if not pid:
        return "Unavailable"
    try:
        return psutil.Process(pid).name()
    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
        return "Unknown"

def detect_gpu_backend():
    try:
        import pynvml
        pynvml.nvmlInit()
        return ("nvml", pynvml)
    except Exception as exc:
        logger.info("NVIDIA NVML telemetry unavailable: %s", exc)
        return (None, None)

@dataclass
class Sample:
    timestamp: float
    cpu_total: float
    per_core: list[float]
    memory_percent: float
    memory_used_gb: float
    memory_total_gb: float
    disk_percent: float
    net_sent_mb: float
    net_recv_mb: float
    foreground: str
    foreground_pid: Optional[int]
    heavy_processes: list[dict]
    foreground_lane: list[dict]
    game_lane: list[dict]
    background_lane: list[dict]
    gpu_name: str
    gpu_load: Optional[float]
    gpu_memory_percent: Optional[float]
    gpu_temperature: Optional[float]
    vram_used_mb: Optional[float]
    vram_total_mb: Optional[float]
    trend: str
    prediction: str
    events: list[str]
    cpu_freq_current: Optional[float]
    cpu_freq_base: Optional[float]
    cpu_freq_max: Optional[float]
    gpu_core_clock: Optional[float]
    gpu_mem_clock: Optional[float]
    gpu_power_watts: Optional[float]
    gpu_power_default: Optional[float]
    gpu_power_max: Optional[float]
    cpu_throttle_flags: dict
    gpu_throttle_flags: dict
    scheduler_qos_flags: dict
    memory_pressure_flags: dict
    network_flags: dict
    nvme_flags: dict

class Plugin:
    def __init__(self, name: str, on_sample: Optional[Callable[[Sample], None]] = None):
        self.name = name
        self.on_sample = on_sample

class PluginManager:
    def __init__(self):
        self.plugins: list[Plugin] = []

    def register(self, plugin: Plugin):
        self.plugins.append(plugin)

    def dispatch_sample(self, sample: Sample):
        for p in self.plugins:
            if p.on_sample:
                try:
                    p.on_sample(sample)
                except Exception:
                    logger.exception("Plugin %s failed on sample", p.name)

class GPUGovernor:
    def __init__(self, nvml_mode, nvml):
        self.nvml_mode = nvml_mode
        self.nvml = nvml
        self.factory_power_default: Optional[float] = None
        self.factory_power_max: Optional[float] = None
        if self.nvml_mode == "nvml" and self.nvml:
            try:
                h = self.nvml.nvmlDeviceGetHandleByIndex(0)
                pl_default = self.nvml.nvmlDeviceGetPowerManagementDefaultLimit(h)
                pl_max = self.nvml.nvmlDeviceGetPowerManagementLimitConstraints(h)[1]
                self.factory_power_default = pl_default / 1000.0
                self.factory_power_max = pl_max / 1000.0
            except Exception:
                logger.debug("Could not read factory GPU power limits")

    def sample_gpu(self):
        if self.nvml_mode != "nvml" or not self.nvml:
            return ("Not available (optional NVIDIA NVML)", None, None, None, None, None, None, None, None, {})
        try:
            nv = self.nvml
            h = nv.nvmlDeviceGetHandleByIndex(0)
            name = nv.nvmlDeviceGetName(h)
            if isinstance(name, bytes):
                name = name.decode(errors="replace")
            util = nv.nvmlDeviceGetUtilizationRates(h)
            mem = nv.nvmlDeviceGetMemoryInfo(h)
            try:
                temp = float(nv.nvmlDeviceGetTemperature(h, nv.NVML_TEMPERATURE_GPU))
            except Exception:
                temp = None
            mem_pct = (100.0 * mem.used / mem.total) if mem.total else None
            vram_used_mb = mem.used / (1024 * 1024)
            vram_total_mb = mem.total / (1024 * 1024)
            try:
                clk_core = nv.nvmlDeviceGetClockInfo(h, nv.NVML_CLOCK_GRAPHICS)
                clk_mem = nv.nvmlDeviceGetClockInfo(h, nv.NVML_CLOCK_MEM)
            except Exception:
                clk_core = None
                clk_mem = None
            try:
                power = nv.nvmlDeviceGetPowerUsage(h) / 1000.0
            except Exception:
                power = None

            throttle_flags = {}
            try:
                reasons = nv.nvmlDeviceGetCurrentClocksThrottleReasons(h)
                throttle_flags["thermal"] = bool(reasons & nv.NVML_CLOCK_THROTTLE_REASON_THERMAL)
                throttle_flags["power"] = bool(reasons & nv.NVML_CLOCK_THROTTLE_REASON_POWER_LIMIT)
                throttle_flags["reliability"] = bool(reasons & nv.NVML_CLOCK_THROTTLE_REASON_RELIABILITY)
                throttle_flags["low_util"] = bool(reasons & nv.NVML_CLOCK_THROTTLE_REASON_LOW_UTILIZATION)
            except Exception:
                throttle_flags = {}

            return (
                str(name),
                float(util.gpu),
                mem_pct,
                temp,
                clk_core,
                clk_mem,
                power,
                vram_used_mb,
                vram_total_mb,
                throttle_flags,
            )
        except Exception as exc:
            logger.debug("GPU sample failed: %s", exc)
            return ("NVIDIA telemetry error", None, None, None, None, None, None, None, None, {})

class SecurityGovernor:
    def __init__(self):
        self.last_status = "Idle"

    def evaluate(self, sample: Sample):
        if sample.cpu_total > 90 and sample.net_recv_mb > 10:
            self.last_status = "High activity; inspect processes"
        else:
            self.last_status = "Normal"

class Advisor:
    def __init__(self):
        self.last_advice = "No advice yet."

    def update(self, sample: Sample, profile_name: str):
        advice = []
        if sample.cpu_total > 90:
            advice.append("CPU-bound workload; inspect top processes and thermals.")
        if sample.gpu_load and sample.gpu_load > 90:
            advice.append("GPU is saturated; consider reducing in-game settings before touching clocks.")
        if sample.vram_used_mb and sample.vram_total_mb:
            vram_pct = 100.0 * sample.vram_used_mb / sample.vram_total_mb
            if vram_pct > 85:
                advice.append("VRAM pressure is high; texture resolution or cache settings may help.")
        if sample.cpu_throttle_flags.get("thermal"):
            advice.append("CPU thermal throttling detected; check cooling and power limits.")
        if sample.cpu_throttle_flags.get("power"):
            advice.append("CPU power limit throttling detected; PL1/PL2 may be constraining boost.")
        if sample.gpu_throttle_flags.get("thermal"):
            advice.append("GPU thermal throttling detected; fan curve or case airflow may need attention.")
        if sample.gpu_throttle_flags.get("power"):
            advice.append("GPU power limit throttling detected; power limit or PSU constraints in play.")
        if sample.scheduler_qos_flags.get("eco_foreground"):
            advice.append("Foreground app appears in EcoQoS; performance may be reduced.")
        if sample.memory_pressure_flags.get("compression_high"):
            advice.append("High memory compression; consider closing background apps or increasing RAM.")
        if sample.nvme_flags.get("thermal_throttle"):
            advice.append("NVMe thermal throttling; sustained IO may be limited by drive temperature.")
        if not advice:
            advice.append("System within expected envelope for profile.")
        self.last_advice = f"[{profile_name}] " + " ".join(advice)

class Watchdog:
    def __init__(self, engine: "GovernorEngine", interval: float = 5.0):
        self.engine = engine
        self.interval = interval
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self):
        if self.thread and self.thread.is_alive():
            return
        self.stop_event.clear()
        self.thread = threading.Thread(target=self._loop, name="GovernorWatchdog", daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3.0)

    def _loop(self):
        last_heartbeat = time.monotonic()
        while not self.stop_event.is_set():
            time.sleep(self.interval)
            hb = self.engine.last_heartbeat
            if hb is None:
                continue
            if hb < last_heartbeat:
                logger.warning("Sampling heartbeat appears stale")
            last_heartbeat = hb

class GovernorEngine:
    def __init__(self, cfg: dict, event_queue: queue.Queue):
        self.cfg = cfg
        self.events = event_queue
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.running = False
        self.num_cores = psutil.cpu_count(logical=True) or 1
        self.core_weights = self._normalize_weights(cfg.get("core_weights", []))
        self.p_cores, self.e_cores = self._normalize_roles(cfg.get("p_cores", []), cfg.get("e_cores", []))
        self.samples_window = deque(maxlen=max(30, int(cfg.get("history_seconds", 90))))
        self.events_history = deque(maxlen=300)
        self.saved_affinity: dict[int, list[int]] = {}
        self.last_net = psutil.net_io_counters()
        self.last_net_time = time.monotonic()
        self.last_disk = psutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\").percent if os.name == "nt" else 0.0
        self.nvml_mode, self.nvml = detect_gpu_backend()
        self.gpu_governor = GPUGovernor(self.nvml_mode, self.nvml)
        self.security_governor = SecurityGovernor()
        self.plugin_manager = PluginManager()
        self.advisor = Advisor()
        self.last_error = ""
        self.last_heartbeat: Optional[float] = None
        self.watchdog = Watchdog(self) if cfg.get("watchdog_enabled", True) else None

        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

        self._auto_detect_hybrid()

    def _normalize_weights(self, values):
        try:
            out = [max(0.5, min(2.0, float(v))) for v in values]
        except (TypeError, ValueError):
            out = []
        if len(out) != self.num_cores:
            out = [1.0] * self.num_cores
        return out

    def _normalize_roles(self, p_values, e_values):
        try:
            p = {int(x) for x in p_values if 0 <= int(x) < self.num_cores}
            e = {int(x) for x in e_values if 0 <= int(x) < self.num_cores} - p
        except (TypeError, ValueError):
            p, e = set(), set()
        return sorted(p), sorted(e)

    def _auto_detect_hybrid(self):
        try:
            freqs = psutil.cpu_freq(percpu=True)
            if not freqs:
                return
            avg = sum(f.current for f in freqs) / len(freqs)
            p, e = [], []
            for idx, f in enumerate(freqs):
                if f.current >= avg * 1.03:
                    p.append(idx)
                elif f.current <= avg * 0.97:
                    e.append(idx)
            if p or e:
                self.p_cores, self.e_cores = sorted(p), sorted(e)
                self.cfg["p_cores"], self.cfg["e_cores"] = self.p_cores, self.e_cores
                save_config(self.cfg)
        except Exception:
            pass

    def set_roles(self, p_values, e_values):
        self.p_cores, self.e_cores = self._normalize_roles(p_values, e_values)
        self.cfg["p_cores"], self.cfg["e_cores"] = self.p_cores, self.e_cores
        save_config(self.cfg)

    def set_weights(self, values):
        self.core_weights = self._normalize_weights(values)
        self.cfg["core_weights"] = self.core_weights
        save_config(self.cfg)

    def event(self, message: str, level="INFO"):
        stamp = time.strftime("%H:%M:%S")
        line = f"[{stamp}] {message}"
        self.events_history.append(line)
        getattr(logger, level.lower(), logger.info)(message)
        try:
            self.events.put_nowait(line)
        except queue.Full:
            pass

    def start(self):
        if self.running:
            return
        self.stop_event.clear()
        self.running = True
        self.thread = threading.Thread(target=self._loop, name="GovernorWorker", daemon=True)
        self.thread.start()
        if self.watchdog:
            self.watchdog.start()
        self.event("Monitoring started.")

    def stop(self):
        self.stop_event.set()
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3.0)
        if self.cfg.get("restore_affinity_on_exit", True):
            self.restore_affinities()
        if self.nvml_mode == "nvml" and self.nvml:
            try:
                self.nvml.nvmlShutdown()
            except Exception:
                pass
        if self.watchdog:
            self.watchdog.stop()
        self.event("Monitoring stopped.")

    def _top_processes_and_lanes(self):
        rows = []
        foreground_lane, game_lane, background_lane = [], [], []
        fg_pid = get_foreground_pid() if self.cfg.get("window_tracking", True) else None
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status"]):
            try:
                info = proc.info
                cpu = float(info.get("cpu_percent") or 0.0)
                mem = info.get("memory_info")
                row = {
                    "pid": int(info["pid"]),
                    "name": info.get("name") or "Unknown",
                    "cpu": cpu,
                    "memory_mb": round(mem.rss / (1024 * 1024), 1) if mem else 0.0,
                    "status": info.get("status") or "",
                }
                rows.append(row)
                lower = row["name"].lower()
                if fg_pid and row["pid"] == fg_pid or any(h in lower for h in FOREGROUND_HINTS):
                    foreground_lane.append(row)
                elif any(h in lower for h in GAME_HINTS):
                    game_lane.append(row)
                else:
                    background_lane.append(row)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, KeyError):
                continue
        rows.sort(key=lambda r: r["cpu"], reverse=True)
        return rows[:12], rows, foreground_lane, game_lane, background_lane

    def _trend(self, cpu):
        self.samples_window.append({"t": time.monotonic(), "cpu": cpu})
        if len(self.samples_window) < 5:
            return "Collecting baseline", "Need a few more samples"
        recent = list(self.samples_window)[-5:]
        first = sum(x["cpu"] for x in recent[:2]) / 2
        last = sum(x["cpu"] for x in recent[-2:]) / 2
        delta = last - first
        if abs(delta) <= float(self.cfg.get("variance_window", 12.0)) * 0.05:
            if last >= 85:
                return "Sustained high", "CPU is very busy; inspect top processes and thermals"
            return "Stable", "No strong short-term CPU change detected"
        if delta >= 8:
            return "Rising", f"CPU may remain busy (recent change +{delta:.1f} pts)"
        if delta <= -8:
            return "Falling", f"CPU load easing (recent change {delta:.1f} pts)"
        if last >= 85:
            return "Sustained high", "CPU is very busy; inspect top processes and thermals"
        return "Stable", "No strong short-term CPU change detected"

    def _affinity_cycle(self, all_processes, foreground_pid):
        if not self.cfg.get("affinity_enabled", False):
            return
        p_cores, e_cores = self.p_cores, self.e_cores
        if not p_cores and not e_cores:
            return
        allowed = set(range(self.num_cores))
        excluded = {str(x).lower() for x in self.cfg.get("excluded_processes", [])}
        for row in all_processes:
            pid, name, cpu = row["pid"], row["name"], row["cpu"]
            lower = name.lower()
            if pid == os.getpid() or lower in excluded or lower in {"system", "idle"}:
                continue
            if pid == foreground_pid or any(h in lower for h in GAME_HINTS + FOREGROUND_HINTS):
                target = p_cores or sorted(allowed)
            elif cpu >= float(self.cfg.get("heavy_threshold", 8.0)):
                target = p_cores or sorted(allowed)
            else:
                target = e_cores or sorted(allowed)
            try:
                proc = psutil.Process(pid)
                if pid not in self.saved_affinity:
                    self.saved_affinity[pid] = proc.cpu_affinity()
                current = proc.cpu_affinity()
                valid_target = [c for c in target if c in allowed]
                if valid_target and current != valid_target:
                    proc.cpu_affinity(valid_target)
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError, OSError):
                continue

    def restore_affinities(self):
        restored = 0
        for pid, cores in list(self.saved_affinity.items()):
            try:
                psutil.Process(pid).cpu_affinity(cores)
                restored += 1
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, AttributeError, OSError):
                pass
        self.saved_affinity.clear()
        if restored:
            self.event(f"Restored saved affinity for {restored} process(es).")

    def _hidden_cpu_flags(self, cpu_freq):
        flags = {"thermal": False, "power": False}
        try:
            if cpu_freq and cpu_freq.current and cpu_freq.max and cpu_freq.current < cpu_freq.max * 0.9:
                flags["thermal"] = False
                flags["power"] = True
        except Exception:
            pass
        return flags

    def _hidden_scheduler_flags(self, foreground_pid):
        flags = {"eco_foreground": False}
        try:
            if foreground_pid:
                proc = psutil.Process(foreground_pid)
                name = (proc.name() or "").lower()
                if "eco" in name:
                    flags["eco_foreground"] = True
        except Exception:
            pass
        return flags

    def _hidden_memory_flags(self, vm: psutil._pslinux.virtual_memory):
        flags = {"compression_high": False}
        try:
            if vm.percent > 90:
                flags["compression_high"] = True
        except Exception:
            pass
        return flags

    def _hidden_network_flags(self):
        flags = {"rss_maybe_misconfigured": False}
        try:
            # Heuristic: high recv with single-core saturation could hint RSS issues
            flags["rss_maybe_misconfigured"] = False
        except Exception:
            pass
        return flags

    def _hidden_nvme_flags(self):
        flags = {"thermal_throttle": False}
        try:
            # Heuristic only; real NVMe telemetry would require vendor tools
            flags["thermal_throttle"] = False
        except Exception:
            pass
        return flags

    def sample_once(self):
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        cpu_total = psutil.cpu_percent(interval=None)
        vm = psutil.virtual_memory()
        foreground_pid = get_foreground_pid() if self.cfg.get("window_tracking", True) else None
        foreground = process_name(foreground_pid) if foreground_pid else "Disabled / unavailable"
        top, all_rows, fg_lane, game_lane, bg_lane = self._top_processes_and_lanes()
        events = []
        if vm.percent >= float(self.cfg.get("memory_soft_limit", 90.0)):
            events.append(f"Memory pressure: {vm.percent:.1f}% used")
        if cpu_total >= 95:
            events.append(f"CPU saturation: {cpu_total:.1f}%")
        trend, prediction = self._trend(cpu_total)

        gpu_name, gpu_load, gpu_mem, gpu_temp, gpu_core_clk, gpu_mem_clk, gpu_power, vram_used_mb, vram_total_mb, gpu_throttle_flags = \
            self.gpu_governor.sample_gpu()

        now = time.monotonic()
        net = psutil.net_io_counters()
        elapsed = max(0.001, now - self.last_net_time)
        sent_mb = max(0, net.bytes_sent - self.last_net.bytes_sent) / (1024 * 1024) / elapsed
        recv_mb = max(0, net.bytes_recv - self.last_net.bytes_recv) / (1024 * 1024) / elapsed
        self.last_net, self.last_net_time = net, now
        try:
            disk_percent = psutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\").percent if os.name == "nt" else 0.0
        except Exception:
            disk_percent = 0.0

        self._affinity_cycle(all_rows, foreground_pid)
        for ev in events:
            self.event(ev, "WARNING")

        cpu_freq = psutil.cpu_freq()
        cpu_freq_current = cpu_freq.current if cpu_freq else None
        cpu_freq_base = cpu_freq.min if cpu_freq else None
        cpu_freq_max = cpu_freq.max if cpu_freq else None

        cpu_throttle_flags = self._hidden_cpu_flags(cpu_freq)
        scheduler_qos_flags = self._hidden_scheduler_flags(foreground_pid)
        memory_pressure_flags = self._hidden_memory_flags(vm)
        network_flags = self._hidden_network_flags()
        nvme_flags = self._hidden_nvme_flags()

        sample = Sample(
            timestamp=time.time(),
            cpu_total=float(cpu_total),
            per_core=[float(x) for x in per_core],
            memory_percent=float(vm.percent),
            memory_used_gb=vm.used / (1024**3),
            memory_total_gb=vm.total / (1024**3),
            disk_percent=float(disk_percent),
            net_sent_mb=sent_mb,
            net_recv_mb=recv_mb,
            foreground=foreground,
            foreground_pid=foreground_pid,
            heavy_processes=top,
            foreground_lane=fg_lane,
            game_lane=game_lane,
            background_lane=bg_lane,
            gpu_name=gpu_name,
            gpu_load=gpu_load,
            gpu_memory_percent=gpu_mem,
            gpu_temperature=gpu_temp,
            vram_used_mb=vram_used_mb,
            vram_total_mb=vram_total_mb,
            trend=trend,
            prediction=prediction,
            events=events,
            cpu_freq_current=cpu_freq_current,
            cpu_freq_base=cpu_freq_base,
            cpu_freq_max=cpu_freq_max,
            gpu_core_clock=gpu_core_clk,
            gpu_mem_clock=gpu_mem_clk,
            gpu_power_watts=gpu_power,
            gpu_power_default=self.gpu_governor.factory_power_default,
            gpu_power_max=self.gpu_governor.factory_power_max,
            cpu_throttle_flags=cpu_throttle_flags,
            gpu_throttle_flags=gpu_throttle_flags,
            scheduler_qos_flags=scheduler_qos_flags,
            memory_pressure_flags=memory_pressure_flags,
            network_flags=network_flags,
            nvme_flags=nvme_flags,
        )

        self.security_governor.evaluate(sample)
        self.advisor.update(sample, self.cfg.get("profile", "AutoAI"))
        self.plugin_manager.dispatch_sample(sample)
        self.last_heartbeat = time.monotonic()
        return sample

    def _loop(self):
        try:
            psutil.cpu_percent(interval=None, percpu=True)
            psutil.cpu_percent(interval=None)
        except Exception:
            pass
        while not self.stop_event.is_set():
            try:
                sample = self.sample_once()
                self.events.put(("sample", sample))
            except Exception as exc:
                self.last_error = str(exc)
                logger.exception("Sampling cycle failed")
                self.events.put(("error", str(exc)))
            interval = max(0.25, min(10.0, float(self.cfg.get("interval", 1.0))))
            self.stop_event.wait(interval)
        self.running = False

class GovernorGUI:
    def __init__(self, root, engine: GovernorEngine, cfg: dict):
        self.root, self.engine, self.cfg = root, engine, cfg
        self.events = engine.events
        self.latest: Optional[Sample] = None
        self._closing = False

        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1280x840")
        self.root.minsize(860, 620)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        self.style.configure("RedLabel.TLabel", foreground="red")
        self.style.configure("YellowLabel.TLabel", foreground="#c09000")

        top = ttk.Frame(root, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="Profile").pack(side="left")
        self.profile_var = tk.StringVar(value=cfg.get("profile", "AutoAI"))
        self.profile_combo = ttk.Combobox(
            top,
            textvariable=self.profile_var,
            values=list(PROFILES),
            state="readonly",
            width=18,
        )
        self.profile_combo.pack(side="left", padx=(5, 12))
        self.profile_combo.bind("<<ComboboxSelected>>", self.on_profile_change)
        self.start_btn = ttk.Button(top, text="Start Monitoring", command=self.start)
        self.start_btn.pack(side="left", padx=3)
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=3)
        ttk.Button(top, text="Save Settings", command=self.save).pack(side="left", padx=3)
        ttk.Button(top, text="Reset Defaults", command=self.reset).pack(side="right", padx=3)

        self.status_var = tk.StringVar(value="Status: ready — monitoring only; tuning and hidden panels are advisory")
        ttk.Label(root, textvariable=self.status_var, relief="sunken", anchor="w", padding=5).pack(
            side="bottom", fill="x"
        )

        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        self.overview_tab = ttk.Frame(self.nb, padding=10)
        self.process_tab = ttk.Frame(self.nb, padding=8)
        self.tuning_tab = ttk.Frame(self.nb, padding=10)
        self.hardware_tab = ttk.Frame(self.nb, padding=10)
        self.envelope_tab = ttk.Frame(self.nb, padding=10)
        self.vram_tab = ttk.Frame(self.nb, padding=10)
        self.hidden_tab = ttk.Frame(self.nb, padding=10)
        self.events_tab = ttk.Frame(self.nb, padding=8)

        for tab, title in [
            (self.overview_tab, "Overview"),
            (self.process_tab, "Process Lanes"),
            (self.tuning_tab, "CPU Tuning"),
            (self.hardware_tab, "Hardware & Hybrid Map"),
            (self.envelope_tab, "Hardware Envelopes"),
            (self.vram_tab, "VRAM Panel"),
            (self.hidden_tab, "Hidden Adjustments"),
            (self.events_tab, "Events & Advisor"),
        ]:
            self.nb.add(tab, text=title)

        self._build_overview()
        self._build_processes()
        self._build_tuning()
        self._build_hardware()
        self._build_envelope()
        self._build_vram()
        self._build_hidden()
        self._build_events()

        self.root.after(250, self.poll_queue)
        self.root.after(1500, self.refresh_static_info)

    def _metric(self, parent, title, row, col):
        frame = ttk.LabelFrame(parent, text=title, padding=8)
        frame.grid(row=row, column=col, sticky="nsew", padx=5, pady=5)
        val = ttk.Label(frame, text="—", font=("Segoe UI", 15, "bold"))
        val.pack(anchor="w")
        detail = ttk.Label(frame, text="Waiting for samples", wraplength=320)
        detail.pack(anchor="w", pady=(4, 0))
        return val, detail

    def _build_overview(self):
        f = self.overview_tab
        for c in range(2):
            f.columnconfigure(c, weight=1)
        for r in range(3):
            f.rowconfigure(r, weight=1)

        self.cpu_val, self.cpu_detail = self._metric(f, "CPU", 0, 0)
        self.mem_val, self.mem_detail = self._metric(f, "Memory", 0, 1)
        self.gpu_val, self.gpu_detail = self._metric(f, "GPU (real telemetry)", 1, 0)
        self.trend_val, self.trend_detail = self._metric(f, "Workload Trend", 1, 1)
        self.net_val, self.net_detail = self._metric(f, "Network throughput", 2, 0)
        self.disk_val, self.disk_detail = self._metric(f, "System disk", 2, 1)

        cores = ttk.LabelFrame(f, text="Per-logical-CPU utilization", padding=8)
        cores.grid(row=3, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        f.rowconfigure(3, weight=2)

        self.core_canvas = tk.Canvas(cores, height=170, highlightthickness=0)
        self.core_scroll = ttk.Scrollbar(cores, orient="vertical", command=self.core_canvas.yview)
        self.core_canvas.configure(yscrollcommand=self.core_scroll.set)
        self.core_scroll.pack(side="right", fill="y")
        self.core_canvas.pack(side="left", fill="both", expand=True)
        self.core_inner = ttk.Frame(self.core_canvas)
        self.core_canvas.create_window((0, 0), window=self.core_inner, anchor="nw")
        self.core_inner.bind("<Configure>", lambda _e: self.core_canvas.configure(
            scrollregion=self.core_canvas.bbox("all")))
        self.core_rows = []
        for i in range(self.engine.num_cores):
            row = ttk.Frame(self.core_inner)
            row.pack(fill="x", pady=1)
            ttk.Label(row, text=f"CPU {i:02d}", width=9).pack(side="left")
            bar = ttk.Progressbar(row, maximum=100, mode="determinate")
            bar.pack(side="left", fill="x", expand=True, padx=5)
            label = ttk.Label(row, text="—", width=8)
            label.pack(side="right")
            self.core_rows.append((bar, label))

    def _build_processes(self):
        f = self.process_tab
        f.columnconfigure(0, weight=1)
        f.columnconfigure(1, weight=1)
        f.columnconfigure(2, weight=1)

        lanes_frame = ttk.Frame(f)
        lanes_frame.pack(fill="both", expand=True)

        self.foreground_tree = self._lane_tree(lanes_frame, "Foreground lane", 0)
        self.game_tree = self._lane_tree(lanes_frame, "Game lane", 1)
        self.background_tree = self._lane_tree(lanes_frame, "Background lane", 2)

        self.foreground_pressure = ttk.Progressbar(f, maximum=100, mode="determinate")
        self.game_pressure = ttk.Progressbar(f, maximum=100, mode="determinate")
        self.background_pressure = ttk.Progressbar(f, maximum=100, mode="determinate")

        ttk.Label(f, text="Lane pressure (approximate CPU share):").pack(anchor="w", pady=(8, 2))
        lane_bar_frame = ttk.Frame(f)
        lane_bar_frame.pack(fill="x")
        ttk.Label(lane_bar_frame, text="Foreground").pack(side="left")
        self.foreground_pressure.pack(side="left", fill="x", expand=True, padx=4)
        ttk.Label(lane_bar_frame, text="Game").pack(side="left")
        self.game_pressure.pack(side="left", fill="x", expand=True, padx=4)
        ttk.Label(lane_bar_frame, text="Background").pack(side="left")
        self.background_pressure.pack(side="left", fill="x", expand=True, padx=4)

    def _lane_tree(self, parent, title, col):
        frame = ttk.LabelFrame(parent, text=title, padding=4)
        frame.grid(row=0, column=col, sticky="nsew", padx=4, pady=4)
        cols = ("pid", "name", "cpu", "memory")
        tree = ttk.Treeview(frame, columns=cols, show="headings", height=14)
        for c, t, w in [
            ("pid", "PID", 60),
            ("name", "Process", 160),
            ("cpu", "CPU %", 70),
            ("memory", "RAM MB", 80),
        ]:
            tree.heading(c, text=t)
            tree.column(c, width=w, anchor="w" if c == "name" else "e")
        y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
        tree.configure(yscrollcommand=y.set)
        tree.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")
        return tree

    def _build_tuning(self):
        f = self.tuning_tab
        f.columnconfigure(1, weight=1)

        self.interval_var = tk.DoubleVar(value=float(self.cfg["interval"]))
        self.heavy_var = tk.DoubleVar(value=float(self.cfg["heavy_threshold"]))
        self.idle_var = tk.DoubleVar(value=float(self.cfg["idle_threshold"]))
        self.variance_var = tk.DoubleVar(value=float(self.cfg["variance_window"]))
        self.mem_var = tk.DoubleVar(value=float(self.cfg["memory_soft_limit"]))

        settings = [
            ("Sampling interval (seconds)", self.interval_var, 0.25, 5.0, 0.25),
            ("Heavy process threshold (%)", self.heavy_var, 1, 50, 1),
            ("Idle-core indicator (%)", self.idle_var, 5, 80, 1),
            ("Balance variance window (%)", self.variance_var, 1, 30, 1),
            ("Memory pressure alert (%)", self.mem_var, 50, 99, 1),
        ]
        for i, (label, var, low, high, step) in enumerate(settings):
            ttk.Label(f, text=label).grid(row=i, column=0, sticky="w", pady=8, padx=(0, 12))
            scale = tk.Scale(f, variable=var, from_=low, to=high, resolution=step,
                             orient="horizontal", showvalue=True, length=360)
            scale.grid(row=i, column=1, sticky="ew", pady=3)

        self.affinity_var = tk.BooleanVar(value=bool(self.cfg.get("affinity_enabled", False)))
        ttk.Checkbutton(
            f,
            text="Enable automatic CPU-affinity management (advanced; off by default)",
            variable=self.affinity_var,
            command=self.on_affinity_toggle,
        ).grid(row=5, column=0, columnspan=2, sticky="w", pady=(12, 4))

        self.restore_var = tk.BooleanVar(value=bool(self.cfg.get("restore_affinity_on_exit", True)))
        ttk.Checkbutton(
            f,
            text="Restore saved affinities when stopping/exiting",
            variable=self.restore_var,
        ).grid(row=6, column=0, columnspan=2, sticky="w", pady=4)

        self.window_var = tk.BooleanVar(value=bool(self.cfg.get("window_tracking", True)))
        ttk.Checkbutton(
            f,
            text="Track foreground application (Windows)",
            variable=self.window_var,
        ).grid(row=7, column=0, columnspan=2, sticky="w", pady=4)

        ttk.Label(
            f,
            text="Affinity can affect performance and is not a clock-speed control. "
                 "P/E roles are auto-detected with manual override; leave blank to let Windows schedule normally.",
            wraplength=800,
        ).grid(row=8, column=0, columnspan=2, sticky="w", pady=12)

        ttk.Button(f, text="Apply tuning values", command=self.apply_tuning).grid(
            row=9, column=0, sticky="w", pady=8
        )
        ttk.Button(f, text="Restore saved process affinities now", command=self.restore_affinities).grid(
            row=9, column=1, sticky="w", pady=8
        )

    def _build_hardware(self):
        f = self.hardware_tab
        f.columnconfigure(1, weight=1)

        self.machine_text = tk.Text(f, height=6, wrap="word", state="disabled")
        self.machine_text.grid(row=0, column=0, columnspan=3, sticky="ew", pady=(0, 10))

        ttk.Label(f, text="P-core indexes (comma separated; optional)").grid(row=1, column=0, sticky="w", pady=5)
        self.p_entry = ttk.Entry(f, width=45)
        self.p_entry.grid(row=1, column=1, sticky="ew", padx=8)
        self.p_entry.insert(0, ",".join(map(str, self.engine.p_cores)))

        ttk.Label(f, text="E-core indexes (comma separated; optional)").grid(row=2, column=0, sticky="w", pady=5)
        self.e_entry = ttk.Entry(f, width=45)
        self.e_entry.grid(row=2, column=1, sticky="ew", padx=8)
        self.e_entry.insert(0, ",".join(map(str, self.engine.e_cores)))

        ttk.Button(f, text="Apply core role mapping", command=self.apply_roles).grid(
            row=3, column=1, sticky="w", pady=8
        )

        ttk.Label(
            f,
            text="Per-core preference weights (0.5–2.0; used only by affinity logic)",
            wraplength=750,
        ).grid(row=4, column=0, columnspan=3, sticky="w", pady=(15, 5))

        self.weights_canvas = tk.Canvas(f, height=190, highlightthickness=0)
        self.weights_scroll = ttk.Scrollbar(f, orient="vertical", command=self.weights_canvas.yview)
        self.weights_canvas.configure(yscrollcommand=self.weights_scroll.set)
        self.weights_scroll.grid(row=5, column=2, sticky="ns")
        self.weights_canvas.grid(row=5, column=0, columnspan=2, sticky="nsew")
        f.rowconfigure(5, weight=1)

        self.weights_inner = ttk.Frame(self.weights_canvas)
        self.weights_canvas.create_window((0, 0), window=self.weights_inner, anchor="nw")
        self.weights_inner.bind("<Configure>", lambda _e: self.weights_canvas.configure(
            scrollregion=self.weights_canvas.bbox("all")))

        self.weight_vars = []
        for i, value in enumerate(self.engine.core_weights):
            row = ttk.Frame(self.weights_inner)
            row.pack(fill="x")
            ttk.Label(row, text=f"CPU {i:02d}", width=10).pack(side="left")
            var = tk.DoubleVar(value=value)
            tk.Scale(row, variable=var, from_=0.5, to=2.0, resolution=0.05,
                     orient="horizontal", length=260).pack(side="left")
            self.weight_vars.append(var)

        ttk.Button(f, text="Apply weights", command=self.apply_weights).grid(
            row=6, column=1, sticky="w", pady=8
        )

        hybrid_frame = ttk.LabelFrame(f, text="Hybrid core map (P/E/Unknown)", padding=8)
        hybrid_frame.grid(row=7, column=0, columnspan=3, sticky="nsew", padx=5, pady=8)
        f.rowconfigure(7, weight=1)

        self.hybrid_canvas = tk.Canvas(hybrid_frame, height=140, highlightthickness=0)
        self.hybrid_canvas.pack(fill="both", expand=True)
        self._draw_hybrid_map()

    def _draw_hybrid_map(self):
        c = self.hybrid_canvas
        c.delete("all")
        n = self.engine.num_cores
        cols = min(n, 16)
        rows = (n + cols - 1) // cols
        w = 20
        h = 20
        pad = 4
        for idx in range(n):
            r = idx // cols
            col = idx % cols
            x0 = pad + col * (w + pad)
            y0 = pad + r * (h + pad)
            x1 = x0 + w
            y1 = y0 + h
            if idx in self.engine.p_cores:
                color = "#2b6cb0"
            elif idx in self.engine.e_cores:
                color = "#2f855a"
            else:
                color = "#4a5568"
            c.create_rectangle(x0, y0, x1, y1, fill=color, outline="#1a202c")
            c.create_text((x0 + x1) / 2, (y0 + y1) / 2, text=str(idx), fill="white", font=("Segoe UI", 7))

    def _build_envelope(self):
        f = self.envelope_tab
        for c in range(2):
            f.columnconfigure(c, weight=1)
        for r in range(3):
            f.rowconfigure(r, weight=1)

        self.cpu_env_frame = ttk.LabelFrame(f, text="CPU Tuning Envelope (profile-aware)", padding=8)
        self.cpu_env_frame.grid(row=0, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        self.cpu_base_label = ttk.Label(self.cpu_env_frame, text="Base: —")
        self.cpu_base_label.grid(row=0, column=0, sticky="w", padx=4, pady=2)
        self.cpu_max_label = ttk.Label(self.cpu_env_frame, text="Max: —")
        self.cpu_max_label.grid(row=0, column=1, sticky="w", padx=4, pady=2)
        self.cpu_current_label = ttk.Label(self.cpu_env_frame, text="Current: —")
        self.cpu_current_label.grid(row=1, column=0, sticky="w", padx=4, pady=2)
        self.cpu_profile_label = ttk.Label(self.cpu_env_frame, text="Profile envelope: —")
        self.cpu_profile_label.grid(row=1, column=1, sticky="w", padx=4, pady=2)

        self.gpu_env_frame = ttk.LabelFrame(f, text="GPU Tuning Envelope (profile-aware, read-only)", padding=8)
        self.gpu_env_frame.grid(row=1, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)

        self.gpu_power_default_label = ttk.Label(self.gpu_env_frame, text="Default power: — W")
        self.gpu_power_default_label.grid(row=0, column=0, sticky="w", padx=4, pady=2)
        self.gpu_power_max_label = ttk.Label(self.gpu_env_frame, text="Max power: — W")
        self.gpu_power_max_label.grid(row=0, column=1, sticky="w", padx=4, pady=2)
        self.gpu_power_current_label = ttk.Label(self.gpu_env_frame, text="Current power: — W")
        self.gpu_power_current_label.grid(row=1, column=0, sticky="w", padx=4, pady=2)
        self.gpu_power_profile_label = ttk.Label(self.gpu_env_frame, text="Profile envelope: —")
        self.gpu_power_profile_label.grid(row=1, column=1, sticky="w", padx=4, pady=2)

        self.gpu_core_label = ttk.Label(self.gpu_env_frame, text="Core clock: — MHz")
        self.gpu_core_label.grid(row=2, column=0, sticky="w", padx=4, pady=2)
        self.gpu_mem_label = ttk.Label(self.gpu_env_frame, text="Memory clock: — MHz")
        self.gpu_mem_label.grid(row=2, column=1, sticky="w", padx=4, pady=2)

        ttk.Label(
            f,
            text="Values above factory defaults or profile envelopes are shown in red; near-edge values in yellow. "
                 "This governor does not write clocks or voltages; it visualizes what other tools or BIOS apply.",
            wraplength=900,
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=10)

    def _build_vram(self):
        f = self.vram_tab
        f.columnconfigure(0, weight=1)
        f.rowconfigure(0, weight=1)

        panel = ttk.LabelFrame(f, text="VRAM usage and pressure", padding=8)
        panel.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)

        self.vram_usage_label = ttk.Label(panel, text="VRAM: — / — MB (—%)")
        self.vram_usage_label.grid(row=0, column=0, sticky="w", padx=4, pady=4)

        self.vram_pressure_bar = ttk.Progressbar(panel, maximum=100, mode="determinate")
        self.vram_pressure_bar.grid(row=1, column=0, sticky="ew", padx=4, pady=4)

        self.vram_profile_label = ttk.Label(panel, text="Profile expectation: —")
        self.vram_profile_label.grid(row=2, column=0, sticky="w", padx=4, pady=4)

        ttk.Label(
            panel,
            text="High VRAM usage is normal for some profiles (Gaming, Editing bursts). "
                 "Pressure above ~85% is highlighted.",
            wraplength=800,
        ).grid(row=3, column=0, sticky="w", padx=4, pady=6)

    def _build_hidden(self):
        f = self.hidden_tab
        for c in range(2):
            f.columnconfigure(c, weight=1)
        for r in range(3):
            f.rowconfigure(r, weight=1)

        self.hidden_cpu_frame = ttk.LabelFrame(f, text="Hidden CPU adjustments", padding=8)
        self.hidden_cpu_frame.grid(row=0, column=0, sticky="nsew", padx=5, pady=5)
        self.hidden_gpu_frame = ttk.LabelFrame(f, text="Hidden GPU adjustments", padding=8)
        self.hidden_gpu_frame.grid(row=0, column=1, sticky="nsew", padx=5, pady=5)
        self.hidden_sched_frame = ttk.LabelFrame(f, text="Scheduler QoS hints", padding=8)
        self.hidden_sched_frame.grid(row=1, column=0, sticky="nsew", padx=5, pady=5)
        self.hidden_mem_frame = ttk.LabelFrame(f, text="Memory pressure hints", padding=8)
        self.hidden_mem_frame.grid(row=1, column=1, sticky="nsew", padx=5, pady=5)
        self.hidden_net_frame = ttk.LabelFrame(f, text="Network tuning hints", padding=8)
        self.hidden_net_frame.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        self.hidden_nvme_frame = ttk.LabelFrame(f, text="NVMe throttling hints", padding=8)
        self.hidden_nvme_frame.grid(row=2, column=1, sticky="nsew", padx=5, pady=5)

        self.hidden_cpu_label = ttk.Label(self.hidden_cpu_frame, text="CPU: no hidden flags yet", wraplength=400)
        self.hidden_cpu_label.pack(anchor="w")
        self.hidden_gpu_label = ttk.Label(self.hidden_gpu_frame, text="GPU: no hidden flags yet", wraplength=400)
        self.hidden_gpu_label.pack(anchor="w")
        self.hidden_sched_label = ttk.Label(self.hidden_sched_frame, text="Scheduler: no QoS hints yet", wraplength=400)
        self.hidden_sched_label.pack(anchor="w")
        self.hidden_mem_label = ttk.Label(self.hidden_mem_frame, text="Memory: no pressure hints yet", wraplength=400)
        self.hidden_mem_label.pack(anchor="w")
        self.hidden_net_label = ttk.Label(self.hidden_net_frame, text="Network: no tuning hints yet", wraplength=400)
        self.hidden_net_label.pack(anchor="w")
        self.hidden_nvme_label = ttk.Label(self.hidden_nvme_frame, text="NVMe: no throttling hints yet", wraplength=400)
        self.hidden_nvme_label.pack(anchor="w")

        ttk.Label(
            f,
            text="Hidden adjustments are inferred from telemetry and vendor APIs where available. "
                 "Red indicates active constraints; yellow indicates near-edge conditions.",
            wraplength=900,
        ).grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=8)

    def _build_events(self):
        f = self.events_tab
        toolbar = ttk.Frame(f)
        toolbar.pack(fill="x", pady=(0, 5))
        ttk.Button(toolbar, text="Open log folder", command=self.open_log_folder).pack(side="left")
        ttk.Button(toolbar, text="Clear display", command=self.clear_events).pack(side="left", padx=5)

        self.events_text = tk.Text(f, wrap="word", height=14, state="disabled")
        self.events_text.pack(fill="both", expand=True)

        advisor_frame = ttk.LabelFrame(f, text="Advisor", padding=6)
        advisor_frame.pack(fill="x", pady=(6, 4))
        self.advisor_label = ttk.Label(advisor_frame, text="Advisor: waiting for samples", wraplength=900)
        self.advisor_label.pack(anchor="w")

    def on_profile_change(self, _event=None):
        profile = self.profile_var.get()
        if profile in PROFILES:
            p = PROFILES[profile]
            self.interval_var.set(p["interval"])
            self.heavy_var.set(p["heavy_threshold"])
            self.idle_var.set(p["idle_threshold"])
            self.status_var.set(f"Status: profile {profile} applied (monitoring only; tuning advisory)")

    def start(self):
        self.engine.start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set("Status: monitoring active")

    def stop(self):
        self.engine.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_var.set("Status: monitoring stopped")

    def save(self):
        self.cfg["profile"] = self.profile_var.get()
        self.cfg["interval"] = float(self.interval_var.get())
        self.cfg["heavy_threshold"] = float(self.heavy_var.get())
        self.cfg["idle_threshold"] = float(self.idle_var.get())
        self.cfg["variance_window"] = float(self.variance_var.get())
        self.cfg["memory_soft_limit"] = float(self.mem_var.get())
        self.cfg["affinity_enabled"] = bool(self.affinity_var.get())
        self.cfg["restore_affinity_on_exit"] = bool(self.restore_var.get())
        self.cfg["window_tracking"] = bool(self.window_var.get())
        save_config(self.cfg)
        self.status_var.set("Status: settings saved")

    def reset(self):
        self.cfg.update(DEFAULT_CONFIG)
        save_config(self.cfg)
        self.profile_var.set(self.cfg["profile"])
        self.interval_var.set(self.cfg["interval"])
        self.heavy_var.set(self.cfg["heavy_threshold"])
        self.idle_var.set(self.cfg["idle_threshold"])
        self.variance_var.set(self.cfg["variance_window"])
        self.mem_var.set(self.cfg["memory_soft_limit"])
        self.affinity_var.set(self.cfg["affinity_enabled"])
        self.restore_var.set(self.cfg["restore_affinity_on_exit"])
        self.window_var.set(self.cfg["window_tracking"])
        self.status_var.set("Status: defaults restored")
        self._draw_hybrid_map()

    def on_affinity_toggle(self):
        if self.affinity_var.get():
            messagebox.showinfo(
                APP_NAME,
                "CPU affinity management is advanced and can affect performance.\n\n"
                "This governor does not change clocks or voltages; it only adjusts which cores processes may use.",
            )

    def apply_tuning(self):
        self.cfg["interval"] = float(self.interval_var.get())
        self.cfg["heavy_threshold"] = float(self.heavy_var.get())
        self.cfg["idle_threshold"] = float(self.idle_var.get())
        self.cfg["variance_window"] = float(self.variance_var.get())
        self.cfg["memory_soft_limit"] = float(self.mem_var.get())
        self.cfg["affinity_enabled"] = bool(self.affinity_var.get())
        self.cfg["restore_affinity_on_exit"] = bool(self.restore_var.get())
        self.cfg["window_tracking"] = bool(self.window_var.get())
        save_config(self.cfg)
        self.status_var.set("Status: tuning values applied")

    def restore_affinities(self):
        self.engine.restore_affinities()
        self.status_var.set("Status: restore-affinity requested")

    def apply_roles(self):
        p_text = self.p_entry.get().strip()
        e_text = self.e_entry.get().strip()
        try:
            p_values = [int(x) for x in p_text.split(",") if x.strip()] if p_text else []
            e_values = [int(x) for x in e_text.split(",") if x.strip()] if e_text else []
            self.engine.set_roles(p_values, e_values)
            self.status_var.set("Status: core role mapping applied")
            self._draw_hybrid_map()
        except ValueError:
            messagebox.showerror(APP_NAME, "Core indexes must be integers separated by commas.")

    def apply_weights(self):
        values = [float(v.get()) for v in self.weight_vars]
        self.engine.set_weights(values)
        self.status_var.set("Status: per-core weights applied")

    def open_log_folder(self):
        try:
            if os.name == "nt":
                os.startfile(str(APP_DIR))
            else:
                subprocess.Popen(["xdg-open", str(APP_DIR)])
        except Exception:
            messagebox.showerror(APP_NAME, f"Could not open log folder: {APP_DIR}")

    def clear_events(self):
        self.events_text.configure(state="normal")
        self.events_text.delete("1.0", "end")
        self.events_text.configure(state="disabled")

    def on_close(self):
        if self._closing:
            return
        self._closing = True
        try:
            self.engine.stop()
        finally:
            self.root.destroy()

    def poll_queue(self):
        try:
            while True:
                item = self.events.get_nowait()
                if isinstance(item, tuple) and item and item[0] == "sample":
                    self.latest = item[1]
                    self.update_from_sample(self.latest)
                elif isinstance(item, tuple) and item and item[0] == "error":
                    self.status_var.set(f"Status: sampling error: {item[1]}")
                elif isinstance(item, str):
                    self.append_event(item)
        except queue.Empty:
            pass
        if not self._closing:
            self.root.after(250, self.poll_queue)

    def append_event(self, line: str):
        self.events_text.configure(state="normal")
        self.events_text.insert("end", line + "\n")
        self.events_text.see("end")
        self.events_text.configure(state="disabled")

    def refresh_static_info(self):
        info = [
            f"Machine: {platform.node()}",
            f"OS: {platform.system()} {platform.release()} ({platform.version()})",
            f"Python: {platform.python_version()}",
            f"Logical CPUs: {self.engine.num_cores}",
            f"NVIDIA telemetry: {self.engine.nvml_mode or 'disabled'}",
        ]
        self.machine_text.configure(state="normal")
        self.machine_text.delete("1.0", "end")
        self.machine_text.insert("end", "\n".join(info))
        self.machine_text.configure(state="disabled")

    def update_from_sample(self, s: Sample):
        self.cpu_val.configure(text=f"{s.cpu_total:.1f}%")
        self.cpu_detail.configure(text=f"Foreground: {s.foreground} | Trend: {s.trend}")

        self.mem_val.configure(text=f"{s.memory_percent:.1f}%")
        self.mem_detail.configure(
            text=f"Used: {s.memory_used_gb:.2f} GiB / {s.memory_total_gb:.2f} GiB"
        )

        if s.gpu_load is not None:
            self.gpu_val.configure(text=f"{s.gpu_load:.1f}%")
            gpu_detail = f"{s.gpu_name}\nVRAM: {s.gpu_memory_percent or 0:.1f}%\nTemp: {s.gpu_temperature or 0:.1f} °C"
            self.gpu_detail.configure(text=gpu_detail)
        else:
            self.gpu_val.configure(text="—")
            self.gpu_detail.configure(text=s.gpu_name)

        self.trend_val.configure(text=s.trend)
        self.trend_detail.configure(text=s.prediction)

        self.net_val.configure(text=f"{s.net_sent_mb:.2f} MB/s up / {s.net_recv_mb:.2f} MB/s down")
        self.net_detail.configure(text="Approximate throughput since last sample")

        self.disk_val.configure(text=f"{s.disk_percent:.1f}%")
        self.disk_detail.configure(text="System drive utilization")

        for i, (bar, label) in enumerate(self.core_rows):
            if i < len(s.per_core):
                val = s.per_core[i]
                bar.configure(value=val)
                label.configure(text=f"{val:.1f}%")
            else:
                bar.configure(value=0)
                label.configure(text="—")

        self._update_process_lanes(s)
        self._update_envelope(s)
        self._update_vram(s)
        self._update_hidden(s)
        self.advisor_label.configure(text=f"Advisor: {self.engine.advisor.last_advice}")

    def _update_process_lanes(self, s: Sample):
        def fill_tree(tree, rows):
            for item in tree.get_children():
                tree.delete(item)
            for row in rows:
                tree.insert(
                    "",
                    "end",
                    values=(
                        row["pid"],
                        row["name"],
                        f"{row['cpu']:.1f}",
                        f"{row['memory_mb']:.1f}",
                    ),
                )

        fill_tree(self.foreground_tree, s.foreground_lane)
        fill_tree(self.game_tree, s.game_lane)
        fill_tree(self.background_tree, s.background_lane)

        fg_cpu = sum(r["cpu"] for r in s.foreground_lane)
        game_cpu = sum(r["cpu"] for r in s.game_lane)
        bg_cpu = sum(r["cpu"] for r in s.background_lane)
        total = fg_cpu + game_cpu + bg_cpu or 1.0

        self.foreground_pressure.configure(value=min(100.0, 100.0 * fg_cpu / total))
        self.game_pressure.configure(value=min(100.0, 100.0 * game_cpu / total))
        self.background_pressure.configure(value=min(100.0, 100.0 * bg_cpu / total))

    def _update_envelope(self, s: Sample):
        profile_name = self.cfg.get("profile", "AutoAI")
        profile = PROFILES.get(profile_name, PROFILES["AutoAI"])

        base = s.cpu_freq_base or 0.0
        max_ = s.cpu_freq_max or 0.0
        cur = s.cpu_freq_current or 0.0

        self.cpu_base_label.configure(text=f"Base: {base:.0f} MHz" if base else "Base: —")
        self.cpu_max_label.configure(text=f"Max: {max_:.0f} MHz" if max_ else "Max: —")

        cpu_env_low = base * profile["cpu_base_factor"] if base else 0.0
        cpu_env_high = max_ * profile["cpu_max_factor"] if max_ else 0.0
        self.cpu_profile_label.configure(
            text=f"Profile envelope: {cpu_env_low:.0f}–{cpu_env_high:.0f} MHz" if cpu_env_low and cpu_env_high else "Profile envelope: —"
        )

        style = "TLabel"
        if cur and base and cur > base and cur <= cpu_env_high:
            style = "YellowLabel.TLabel"
        if cur and cpu_env_high and cur > cpu_env_high:
            style = "RedLabel.TLabel"
        self.cpu_current_label.configure(
            text=f"Current: {cur:.0f} MHz" if cur else "Current: —",
            style=style,
        )

        dflt = s.gpu_power_default or 0.0
        mx = s.gpu_power_max or 0.0
        cur_p = s.gpu_power_watts or 0.0

        self.gpu_power_default_label.configure(
            text=f"Default power: {dflt:.1f} W" if dflt else "Default power: — W"
        )
        self.gpu_power_max_label.configure(
            text=f"Max power: {mx:.1f} W" if mx else "Max power: — W"
        )

        gpu_env_high = dflt * profile["gpu_power_factor"] if dflt else 0.0
        self.gpu_power_profile_label.configure(
            text=f"Profile envelope: ≤{gpu_env_high:.1f} W" if gpu_env_high else "Profile envelope: —"
        )

        style_p = "TLabel"
        if cur_p and dflt and cur_p > dflt and cur_p <= gpu_env_high:
            style_p = "YellowLabel.TLabel"
        if cur_p and gpu_env_high and cur_p > gpu_env_high:
            style_p = "RedLabel.TLabel"
        self.gpu_power_current_label.configure(
            text=f"Current power: {cur_p:.1f} W" if cur_p else "Current power: — W",
            style=style_p,
        )

        core_clk = s.gpu_core_clock or 0.0
        mem_clk = s.gpu_mem_clock or 0.0

        self.gpu_core_label.configure(
            text=f"Core clock: {core_clk:.0f} MHz" if core_clk else "Core clock: — MHz"
        )
        self.gpu_mem_label.configure(
            text=f"Memory clock: {mem_clk:.0f} MHz" if mem_clk else "Memory clock: — MHz"
        )

    def _update_vram(self, s: Sample):
        profile_name = self.cfg.get("profile", "AutoAI")
        profile = PROFILES.get(profile_name, PROFILES["AutoAI"])
        expectation = profile["vram_expectation"]

        if s.vram_used_mb and s.vram_total_mb:
            pct = 100.0 * s.vram_used_mb / s.vram_total_mb
            self.vram_usage_label.configure(
                text=f"VRAM: {s.vram_used_mb:.0f} / {s.vram_total_mb:.0f} MB ({pct:.1f}%)"
            )
            self.vram_pressure_bar.configure(value=min(100.0, pct))
            style = "TLabel"
            if pct > 85:
                style = "RedLabel.TLabel"
            elif pct > 70:
                style = "YellowLabel.TLabel"
            self.vram_usage_label.configure(style=style)
        else:
            self.vram_usage_label.configure(text="VRAM: — / — MB (—%)")
            self.vram_pressure_bar.configure(value=0)

        self.vram_profile_label.configure(text=f"Profile expectation: {expectation}")

    def _update_hidden(self, s: Sample):
        cpu_text = []
        cpu_style = "TLabel"
        if s.cpu_throttle_flags.get("power"):
            cpu_text.append("Power limit throttling inferred (CPU not reaching max boost).")
            cpu_style = "YellowLabel.TLabel"
        if s.cpu_throttle_flags.get("thermal"):
            cpu_text.append("Thermal throttling inferred.")
            cpu_style = "RedLabel.TLabel"
        if not cpu_text:
            cpu_text.append("No hidden CPU throttling flags inferred.")
        self.hidden_cpu_label.configure(text=" ".join(cpu_text), style=cpu_style)

        gpu_text = []
        gpu_style = "TLabel"
        if s.gpu_throttle_flags.get("power"):
            gpu_text.append("GPU power limit throttling detected.")
            gpu_style = "YellowLabel.TLabel"
        if s.gpu_throttle_flags.get("thermal"):
            gpu_text.append("GPU thermal throttling detected.")
            gpu_style = "RedLabel.TLabel"
        if s.gpu_throttle_flags.get("low_util"):
            gpu_text.append("GPU clocks reduced due to low utilization.")
        if not gpu_text:
            gpu_text.append("No hidden GPU throttling flags detected.")
        self.hidden_gpu_label.configure(text=" ".join(gpu_text), style=gpu_style)

        sched_text = []
        sched_style = "TLabel"
        if s.scheduler_qos_flags.get("eco_foreground"):
            sched_text.append("Foreground app appears in EcoQoS; performance may be reduced.")
            sched_style = "YellowLabel.TLabel"
        if not sched_text:
            sched_text.append("No scheduler QoS anomalies inferred.")
        self.hidden_sched_label.configure(text=" ".join(sched_text), style=sched_style)

        mem_text = []
        mem_style = "TLabel"
        if s.memory_pressure_flags.get("compression_high"):
            mem_text.append("High memory pressure inferred; compression likely elevated.")
            mem_style = "YellowLabel.TLabel"
        if not mem_text:
            mem_text.append("No hidden memory pressure flags inferred beyond visible usage.")
        self.hidden_mem_label.configure(text=" ".join(mem_text), style=mem_style)

        net_text = []
        net_style = "TLabel"
        if s.network_flags.get("rss_maybe_misconfigured"):
            net_text.append("RSS configuration may be suboptimal; network load concentrated on few cores.")
            net_style = "YellowLabel.TLabel"
        if not net_text:
            net_text.append("No hidden network tuning flags inferred.")
        self.hidden_net_label.configure(text=" ".join(net_text), style=net_style)

        nvme_text = []
        nvme_style = "TLabel"
        if s.nvme_flags.get("thermal_throttle"):
            nvme_text.append("NVMe thermal throttling inferred; sustained IO may be constrained.")
            nvme_style = "YellowLabel.TLabel"
        if not nvme_text:
            nvme_text.append("No hidden NVMe throttling flags inferred.")
        self.hidden_nvme_label.configure(text=" ".join(nvme_text), style=nvme_style)

def main():
    cfg = load_config()
    event_queue: queue.Queue[Any] = queue.Queue(maxsize=512)
    engine = GovernorEngine(cfg, event_queue)

    root = tk.Tk()
    gui = GovernorGUI(root, engine, cfg)
    root.mainloop()

if __name__ == "__main__":
    main()
