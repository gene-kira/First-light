#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DominionDeck Hybrid Governor v8.0
Windows-friendly CPU/GPU monitoring and optional CPU-affinity manager.

Highlights
- Tkinter tabbed interface with live CPU, memory, disk, network and process views
- Optional real NVIDIA telemetry through NVML (nvidia-ml-py); graceful fallback
- Adaptive workload trend estimates (heuristics, not an AI model)
- CPU profiles, per-core weights, P/E role overrides, affinity exclusions
- Monitoring-only by default; affinity management must be explicitly enabled
- Saved configuration, rotating logs, event history, restore-affinity support
- Thread-safe GUI updates and graceful shutdown
- No automatic administrator elevation and no automatic package installation

Install:
    py -m pip install psutil
Optional NVIDIA telemetry:
    py -m pip install nvidia-ml-py

Note: Windows controls actual CPU scheduling and hardware clocks. This tool does
not directly change CPU frequencies, timings, voltage, GPU clocks, or fan curves.
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
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Optional

# --------------------------- dependency handling -----------------------------

def ensure_psutil():
    """Return psutil or show a clear installation instruction; never auto-install."""
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
APP_VERSION = "8.0"
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
}

PROFILES = {
    "AutoAI": {"interval": 1.0, "heavy_threshold": 8.0, "idle_threshold": 25.0},
    "Gaming": {"interval": 0.8, "heavy_threshold": 5.0, "idle_threshold": 22.0},
    "Editing": {"interval": 1.2, "heavy_threshold": 4.0, "idle_threshold": 30.0},
    "Streaming": {"interval": 1.0, "heavy_threshold": 4.0, "idle_threshold": 32.0},
    "Silent": {"interval": 2.5, "heavy_threshold": 10.0, "idle_threshold": 40.0},
    "Monitoring Only": {"interval": 1.0, "heavy_threshold": 8.0, "idle_threshold": 25.0},
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
    # Normalize untrusted/old config values.
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
    """Try NVML. This reports NVIDIA telemetry only; it does not tune the GPU."""
    try:
        import pynvml  # provided by package nvidia-ml-py
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
    gpu_name: str
    gpu_load: Optional[float]
    gpu_memory_percent: Optional[float]
    gpu_temperature: Optional[float]
    trend: str
    prediction: str
    events: list[str]

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
        self.samples = deque(maxlen=max(30, int(cfg.get("history_seconds", 90))))
        self.events_history = deque(maxlen=300)
        self.saved_affinity: dict[int, list[int]] = {}
        self.last_net = psutil.net_io_counters()
        self.last_net_time = time.monotonic()
        self.last_disk = psutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\").percent if os.name == "nt" else 0.0
        self.nvml_mode, self.nvml = detect_gpu_backend()
        self.last_cpu_total = 0.0
        self.last_error = ""
        # Prime process CPU counters so first sample is meaningful.
        for p in psutil.process_iter():
            try:
                p.cpu_percent(None)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass

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
        # Do not pretend to detect hybrid architecture from core index ordering.
        # Empty role lists mean "unknown/OS-managed", which is the honest default.
        return sorted(p), sorted(e)

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
        self.event("Monitoring stopped.")

    def _gpu_sample(self):
        if self.nvml_mode != "nvml" or not self.nvml:
            return ("Not available (optional NVIDIA NVML)", None, None, None)
        try:
            nv = self.nvml
            count = nv.nvmlDeviceGetCount()
            if count < 1:
                return ("No GPU found", None, None, None)
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
            return (str(name), float(util.gpu), mem_pct, temp)
        except Exception as exc:
            logger.debug("GPU sample failed: %s", exc)
            return ("NVIDIA telemetry error", None, None, None)

    def _top_processes(self):
        rows = []
        for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "status"]):
            try:
                info = proc.info
                cpu = float(info.get("cpu_percent") or 0.0)
                mem = info.get("memory_info")
                rows.append({
                    "pid": int(info["pid"]),
                    "name": info.get("name") or "Unknown",
                    "cpu": cpu,
                    "memory_mb": round(mem.rss / (1024 * 1024), 1) if mem else 0.0,
                    "status": info.get("status") or "",
                })
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess, KeyError):
                continue
        rows.sort(key=lambda r: r["cpu"], reverse=True)
        return rows[:12], rows

    def _trend(self, cpu):
        self.samples.append({"t": time.monotonic(), "cpu": cpu})
        if len(self.samples) < 5:
            return "Collecting baseline", "Need a few more samples"
        recent = list(self.samples)[-5:]
        first = sum(x["cpu"] for x in recent[:2]) / 2
        last = sum(x["cpu"] for x in recent[-2:]) / 2
        delta = last - first
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
        # Affinity is invasive. Limit it to user processes, never system processes,
        # and only act when a role mapping was explicitly configured.
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

    def sample_once(self):
        per_core = psutil.cpu_percent(interval=None, percpu=True)
        cpu_total = psutil.cpu_percent(interval=None)
        vm = psutil.virtual_memory()
        foreground_pid = get_foreground_pid() if self.cfg.get("window_tracking", True) else None
        foreground = process_name(foreground_pid) if foreground_pid else "Disabled / unavailable"
        top, all_rows = self._top_processes()
        events = []
        if vm.percent >= float(self.cfg.get("memory_soft_limit", 90.0)):
            events.append(f"Memory pressure: {vm.percent:.1f}% used")
        if cpu_total >= 95:
            events.append(f"CPU saturation: {cpu_total:.1f}%")
        trend, prediction = self._trend(cpu_total)
        gpu_name, gpu_load, gpu_mem, gpu_temp = self._gpu_sample()
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
        return Sample(
            timestamp=time.time(), cpu_total=float(cpu_total), per_core=[float(x) for x in per_core],
            memory_percent=float(vm.percent), memory_used_gb=vm.used / (1024**3),
            memory_total_gb=vm.total / (1024**3), disk_percent=float(disk_percent),
            net_sent_mb=sent_mb, net_recv_mb=recv_mb, foreground=foreground,
            foreground_pid=foreground_pid, heavy_processes=top, gpu_name=gpu_name,
            gpu_load=gpu_load, gpu_memory_percent=gpu_mem, gpu_temperature=gpu_temp,
            trend=trend, prediction=prediction, events=events
        )

    def _loop(self):
        # Prime CPU counters once; each iteration remains interruptible.
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
        self.root.geometry("1040x720")
        self.root.minsize(800, 560)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except tk.TclError:
            pass

        top = ttk.Frame(root, padding=(10, 8))
        top.pack(fill="x")
        ttk.Label(top, text="Profile").pack(side="left")
        self.profile_var = tk.StringVar(value=cfg.get("profile", "AutoAI"))
        self.profile_combo = ttk.Combobox(top, textvariable=self.profile_var,
                                          values=list(PROFILES), state="readonly", width=16)
        self.profile_combo.pack(side="left", padx=(5, 12))
        self.profile_combo.bind("<<ComboboxSelected>>", self.on_profile_change)
        self.start_btn = ttk.Button(top, text="Start Monitoring", command=self.start)
        self.start_btn.pack(side="left", padx=3)
        self.stop_btn = ttk.Button(top, text="Stop", command=self.stop, state="disabled")
        self.stop_btn.pack(side="left", padx=3)
        ttk.Button(top, text="Save Settings", command=self.save).pack(side="left", padx=3)
        ttk.Button(top, text="Reset Defaults", command=self.reset).pack(side="right", padx=3)

        self.status_var = tk.StringVar(value="Status: ready — monitoring only")
        ttk.Label(root, textvariable=self.status_var, relief="sunken", anchor="w", padding=5).pack(
            side="bottom", fill="x")

        self.nb = ttk.Notebook(root)
        self.nb.pack(fill="both", expand=True, padx=10, pady=(0, 8))
        self.overview_tab = ttk.Frame(self.nb, padding=10)
        self.process_tab = ttk.Frame(self.nb, padding=8)
        self.tuning_tab = ttk.Frame(self.nb, padding=10)
        self.hardware_tab = ttk.Frame(self.nb, padding=10)
        self.events_tab = ttk.Frame(self.nb, padding=8)
        for tab, title in [(self.overview_tab, "Overview"), (self.process_tab, "Processes"),
                           (self.tuning_tab, "Tuning"), (self.hardware_tab, "Hardware"),
                           (self.events_tab, "Events & Logs")]:
            self.nb.add(tab, text=title)
        self._build_overview()
        self._build_processes()
        self._build_tuning()
        self._build_hardware()
        self._build_events()
        self.root.after(250, self.poll_queue)
        self.root.after(1500, self.refresh_static_info)

    def _metric(self, parent, title, row, col):
        frame = ttk.LabelFrame(parent, text=title, padding=8)
        frame.grid(row=row, column=col, sticky="nsew", padx=5, pady=5)
        val = ttk.Label(frame, text="—", font=("Segoe UI", 15, "bold"))
        val.pack(anchor="w")
        detail = ttk.Label(frame, text="Waiting for samples", wraplength=300)
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
        toolbar = ttk.Frame(f)
        toolbar.pack(fill="x", pady=(0, 5))
        ttk.Label(toolbar, text="Top processes by CPU; inaccessible processes may be omitted.").pack(side="left")
        cols = ("pid", "name", "cpu", "memory", "status")
        self.proc_tree = ttk.Treeview(f, columns=cols, show="headings", height=18)
        for col, title, width in [("pid", "PID", 75), ("name", "Process", 260), ("cpu", "CPU %", 90),
                                  ("memory", "RAM MB", 100), ("status", "Status", 130)]:
            self.proc_tree.heading(col, text=title)
            self.proc_tree.column(col, width=width, anchor="w" if col in ("name", "status") else "e")
        y = ttk.Scrollbar(f, orient="vertical", command=self.proc_tree.yview)
        self.proc_tree.configure(yscrollcommand=y.set)
        self.proc_tree.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")

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
        ttk.Checkbutton(f, text="Enable automatic CPU-affinity management (advanced; off by default)",
                        variable=self.affinity_var, command=self.on_affinity_toggle).grid(
            row=5, column=0, columnspan=2, sticky="w", pady=(12, 4))
        self.restore_var = tk.BooleanVar(value=bool(self.cfg.get("restore_affinity_on_exit", True)))
        ttk.Checkbutton(f, text="Restore saved affinities when stopping/exiting",
                        variable=self.restore_var).grid(row=6, column=0, columnspan=2, sticky="w", pady=4)
        self.window_var = tk.BooleanVar(value=bool(self.cfg.get("window_tracking", True)))
        ttk.Checkbutton(f, text="Track foreground application (Windows)",
                        variable=self.window_var).grid(row=7, column=0, columnspan=2, sticky="w", pady=4)
        ttk.Label(f, text="Affinity can affect performance and is not a clock-speed control. "
                          "P/E roles are user-defined; leave blank to let Windows schedule normally.",
                  wraplength=800).grid(row=8, column=0, columnspan=2, sticky="w", pady=12)
        ttk.Button(f, text="Apply tuning values", command=self.apply_tuning).grid(
            row=9, column=0, sticky="w", pady=8)
        ttk.Button(f, text="Restore saved process affinities now", command=self.restore_affinities).grid(
            row=9, column=1, sticky="w", pady=8)

    def _build_hardware(self):
        f = self.hardware_tab
        f.columnconfigure(1, weight=1)
        self.machine_text = tk.Text(f, height=8, wrap="word", state="disabled")
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
            row=3, column=1, sticky="w", pady=8)
        ttk.Label(f, text="Per-core preference weights (0.5–2.0; used only by affinity logic)",
                  wraplength=750).grid(row=4, column=0, columnspan=3, sticky="w", pady=(15, 5))
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
        ttk.Button(f, text="Apply weights", command=self.apply_weights).grid(row=6, column=1, sticky="w", pady=8)

    def _build_events(self):
        f = self.events_tab
        toolbar = ttk.Frame(f)
        toolbar.pack(fill="x", pady=(0, 5))
        ttk.Button(toolbar, text="Open log folder", command=self.open_log_folder).pack(side="left")
        ttk.Button(toolbar, text="Clear display", command=self.clear_events).pack(side="left", padx=5)
        self.event_text = tk.Text(f, wrap="word", height=20, state="disabled")
        y = ttk.Scrollbar(f, orient="vertical", command=self.event_text.yview)
        self.event_text.configure(yscrollcommand=y.set)
        self.event_text.pack(side="left", fill="both", expand=True)
        y.pack(side="right", fill="y")

    def start(self):
        self._sync_config_from_controls()
        self.engine.start()
        self.start_btn.configure(state="disabled")
        self.stop_btn.configure(state="normal")
        self.status_var.set("Status: monitoring")
    def stop(self):
        self.engine.stop()
        self.start_btn.configure(state="normal")
        self.stop_btn.configure(state="disabled")
        self.status_var.set("Status: stopped")
    def on_profile_change(self, _event=None):
        name = self.profile_var.get()
        vals = PROFILES.get(name, PROFILES["AutoAI"])
        self.interval_var.set(vals["interval"])
        self.heavy_var.set(vals["heavy_threshold"])
        self.idle_var.set(vals["idle_threshold"])
        self.apply_tuning()
    def on_affinity_toggle(self):
        if self.affinity_var.get():
            ok = messagebox.askyesno(
                "Enable CPU affinity management?",
                "This can change process scheduling and may reduce performance or affect applications. "
                "It is not required for monitoring. Enable it?")
            if not ok:
                self.affinity_var.set(False)
        self.apply_tuning()
    def _sync_config_from_controls(self):
        self.cfg.update({
            "profile": self.profile_var.get(),
            "interval": float(self.interval_var.get()),
            "heavy_threshold": float(self.heavy_var.get()),
            "idle_threshold": float(self.idle_var.get()),
            "variance_window": float(self.variance_var.get()),
            "memory_soft_limit": float(self.mem_var.get()),
            "affinity_enabled": bool(self.affinity_var.get()),
            "restore_affinity_on_exit": bool(self.restore_var.get()),
            "window_tracking": bool(self.window_var.get()),
        })
        self.engine.cfg = self.cfg
    def apply_tuning(self):
        self._sync_config_from_controls()
        self.save()
        self.status_var.set("Status: tuning values applied")
    def apply_roles(self):
        try:
            p = self._parse_core_list(self.p_entry.get())
            e = self._parse_core_list(self.e_entry.get())
            if set(p) & set(e):
                raise ValueError("A CPU index cannot be both P-core and E-core.")
            self.engine.set_roles(p, e)
            self.event_line(f"Core role mapping updated: P={p or 'unspecified'}, E={e or 'unspecified'}")
            self.save()
        except ValueError as exc:
            messagebox.showerror("Invalid core mapping", str(exc))
    def _parse_core_list(self, value):
        if not value.strip():
            return []
        result = []
        for token in value.split(","):
            token = token.strip()
            if not token:
                continue
            idx = int(token)
            if not 0 <= idx < self.engine.num_cores:
                raise ValueError(f"CPU index {idx} is outside 0–{self.engine.num_cores - 1}.")
            if idx not in result:
                result.append(idx)
        return sorted(result)
    def apply_weights(self):
        self.engine.set_weights([v.get() for v in self.weight_vars])
        self.event_line("Per-core preference weights saved.")
        self.save()
    def restore_affinities(self):
        self.engine.restore_affinities()
        self.event_line("Requested affinity restoration.")
    def save(self):
        self._sync_config_from_controls()
        self.cfg["p_cores"] = self.engine.p_cores
        self.cfg["e_cores"] = self.engine.e_cores
        self.cfg["core_weights"] = self.engine.core_weights
        save_config(self.cfg)
        self.status_var.set(f"Status: settings saved to {CONFIG_PATH}")
    def reset(self):
        if not messagebox.askyesno("Reset settings", "Restore all settings to defaults?"):
            return
        self.cfg.clear()
        self.cfg.update(DEFAULT_CONFIG)
        self.cfg["core_weights"] = [1.0] * self.engine.num_cores
        self.cfg["p_cores"], self.cfg["e_cores"] = [], []
        self.profile_var.set(self.cfg["profile"])
        self.interval_var.set(self.cfg["interval"])
        self.heavy_var.set(self.cfg["heavy_threshold"])
        self.idle_var.set(self.cfg["idle_threshold"])
        self.variance_var.set(self.cfg["variance_window"])
        self.mem_var.set(self.cfg["memory_soft_limit"])
        self.affinity_var.set(False)
        self.restore_var.set(True)
        self.window_var.set(True)
        self.engine.cfg = self.cfg
        self.engine.set_roles([], [])
        self.engine.set_weights([1.0] * self.engine.num_cores)
        self.p_entry.delete(0, "end")
        self.e_entry.delete(0, "end")
        for var in self.weight_vars:
            var.set(1.0)
        self.apply_tuning()
        self.event_line("Settings reset to defaults.")
    def refresh_static_info(self):
        if self._closing:
            return
        freq = psutil.cpu_freq()
        try:
            disk = psutil.disk_usage(os.environ.get("SystemDrive", "C:") + "\\")
            disk_line = f"System drive usage: {disk.percent:.1f}% ({disk.used / (1024**3):.1f} / {disk.total / (1024**3):.1f} GB)"
        except Exception:
            disk_line = "System drive usage: unavailable"
        lines = [
            f"Application: {APP_NAME} v{APP_VERSION}",
            f"Operating system: {platform.platform()}",
            f"Processor: {platform.processor() or 'Unknown'}",
            f"Logical CPUs: {self.engine.num_cores}",
            f"Current reported frequency: {freq.current / 1000:.2f} GHz" if freq else "Current reported frequency: unavailable",
            f"RAM: {psutil.virtual_memory().total / (1024**3):.1f} GB",
            disk_line,
            f"GPU telemetry backend: {'NVIDIA NVML' if self.engine.nvml_mode == 'nvml' else 'not detected'}",
            f"Settings: {CONFIG_PATH}",
            f"Log: {LOG_PATH}",
            "Hybrid core roles are not inferred automatically because logical CPU ordering varies by processor."
        ]
        self.machine_text.configure(state="normal")
        self.machine_text.delete("1.0", "end")
        self.machine_text.insert("1.0", "\n".join(lines))
        self.machine_text.configure(state="disabled")
        self.root.after(10000, self.refresh_static_info)
    def poll_queue(self):
        if self._closing:
            return
        try:
            while True:
                item = self.events.get_nowait()
                if isinstance(item, tuple) and item[0] == "sample":
                    self.latest = item[1]
                    self.update_sample(item[1])
                elif isinstance(item, tuple) and item[0] == "error":
                    self.status_var.set(f"Status: sampling error — {item[1]}")
                    self.event_line(f"ERROR: {item[1]}")
                else:
                    self.event_line(str(item))
        except queue.Empty:
            pass
        self.root.after(250, self.poll_queue)
    def update_sample(self, s: Sample):
        self.cpu_val.configure(text=f"{s.cpu_total:.1f}%")
        self.cpu_detail.configure(text=f"{len(s.per_core)} logical CPUs · foreground: {s.foreground}")
        self.mem_val.configure(text=f"{s.memory_percent:.1f}%")
        self.mem_detail.configure(text=f"{s.memory_used_gb:.1f} / {s.memory_total_gb:.1f} GB")
        if s.gpu_load is None:
            self.gpu_val.configure(text="Unavailable")
            self.gpu_detail.configure(text=s.gpu_name)
        else:
            self.gpu_val.configure(text=f"{s.gpu_load:.1f}%")
            extra = f"VRAM {s.gpu_memory_percent:.1f}%" if s.gpu_memory_percent is not None else "VRAM unavailable"
            if s.gpu_temperature is not None:
                extra += f" · {s.gpu_temperature:.0f}°C"
            self.gpu_detail.configure(text=f"{s.gpu_name} · {extra}")
        self.trend_val.configure(text=s.trend)
        self.trend_detail.configure(text=s.prediction)
        self.net_val.configure(text=f"↓ {s.net_recv_mb:.2f} / ↑ {s.net_sent_mb:.2f} MB/s")
        self.net_detail.configure(text="Current network throughput (sampled)")
        self.disk_val.configure(text=f"{s.disk_percent:.1f}%")
        self.disk_detail.configure(text="System drive space used")
        for i, (bar, label) in enumerate(self.core_rows):
            if i < len(s.per_core):
                bar["value"] = s.per_core[i]
                label.configure(text=f"{s.per_core[i]:.0f}%")
        existing = set(self.proc_tree.get_children())
        new_ids = []
        for p in s.heavy_processes:
            iid = str(p["pid"])
            new_ids.append(iid)
            values = (p["pid"], p["name"], f'{p["cpu"]:.1f}', f'{p["memory_mb"]:.1f}', p["status"])
            if iid in existing:
                self.proc_tree.item(iid, values=values)
            else:
                self.proc_tree.insert("", "end", iid=iid, values=values)
        for iid in existing - set(new_ids):
            try:
                self.proc_tree.delete(iid)
            except tk.TclError:
                pass
        self.status_var.set(f"Status: live · profile {self.cfg.get('profile')} · {time.strftime('%H:%M:%S')}")
    def event_line(self, line):
        self.event_text.configure(state="normal")
        self.event_text.insert("end", str(line) + "\n")
        # Keep the visible widget bounded.
        try:
            lines = int(self.event_text.index("end-1c").split(".")[0])
            if lines > 600:
                self.event_text.delete("1.0", f"{lines - 500}.0")
        except Exception:
            pass
        self.event_text.see("end")
        self.event_text.configure(state="disabled")
    def clear_events(self):
        self.event_text.configure(state="normal")
        self.event_text.delete("1.0", "end")
        self.event_text.configure(state="disabled")
    def open_log_folder(self):
        try:
            if os.name == "nt":
                os.startfile(str(APP_DIR))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(APP_DIR)])
            else:
                subprocess.Popen(["xdg-open", str(APP_DIR)])
        except Exception as exc:
            messagebox.showerror("Could not open folder", str(exc))
    def on_close(self):
        if self._closing:
            return
        self._closing = True
        try:
            self._sync_config_from_controls()
            self.save()
            self.engine.stop()
        except Exception:
            logger.exception("Shutdown error")
        self.root.destroy()

def main():
    cfg = load_config()
    # Ensure list lengths are valid for the detected machine.
    count = psutil.cpu_count(logical=True) or 1
    if len(cfg.get("core_weights", [])) != count:
        cfg["core_weights"] = [1.0] * count
    events = queue.Queue(maxsize=1000)
    engine = GovernorEngine(cfg, events)
    root = tk.Tk()
    gui = GovernorGUI(root, engine, cfg)
    logger.info("%s v%s launched on %s", APP_NAME, APP_VERSION, platform.platform())
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        pass
    except Exception:
        logger.exception("Fatal application error")
        raise
