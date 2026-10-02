#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
VCCA Lab Governor Ω — v2.0
A safer dependency, plugin, process-health, and predictive monitoring dashboard.

Important:
- This is a monitoring/governance utility, NOT a security sandbox.
- It does not isolate plugins or contain other processes.
- Predictions are heuristic forecasts, not trained AI or proof of a security threat.
- Optional package installation is manual and opt-in.
"""

from __future__ import annotations

import importlib
import importlib.util
import json
import logging
import os
import queue
import statistics
import subprocess
import sys
import threading
import time
import traceback
from collections import defaultdict, deque
from datetime import datetime
from pathlib import Path
from types import ModuleType
from typing import Any

APP_NAME = "VCCA Lab Governor Ω"
APP_VERSION = "2.0"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "vcca_data"
PLUGIN_DIR = BASE_DIR / "plugins"
CONFIG_FILE = DATA_DIR / "config.json"
HISTORY_FILE = DATA_DIR / "history.json"
LOG_FILE = DATA_DIR / "vcca.log"

DATA_DIR.mkdir(parents=True, exist_ok=True)
PLUGIN_DIR.mkdir(parents=True, exist_ok=True)

# Tkinter is part of most standard Windows Python installations.
try:
    import tkinter as tk
    from tkinter import messagebox, ttk
except Exception:
    tk = None
    ttk = None
    messagebox = None

# Optional telemetry dependency. The application still works without it.
try:
    import psutil
except Exception:
    psutil = None


DEPENDENCY_GROUPS: dict[str, dict[str, str]] = {
    "core": {
        "requests": "requests",
        "psutil": "psutil",
        "pyyaml": "yaml",
    },
    "gpu": {
        "torch": "torch",
        "numpy": "numpy",
        "cupy": "cupy",
    },
    "vision": {
        "opencv-python": "cv2",
        "Pillow": "PIL",
    },
    "governor": {
        "pywin32": "win32api",
        "wmi": "wmi",
    },
}

CONTAINMENT_STATES: dict[str, dict[str, Any]] = {
    "baseline": {"required_groups": ["core"], "strictness": 1},
    "hyper_gpu": {"required_groups": ["core", "gpu", "governor"], "strictness": 2},
    "vision_drift": {"required_groups": ["core", "vision", "gpu"], "strictness": 2},
    "security_lock": {"required_groups": ["core", "governor"], "strictness": 3},
    "lockdown": {"required_groups": ["core", "governor"], "strictness": 4},
}

DEFAULT_CONFIG: dict[str, Any] = {
    "mode": "auto",
    "monitor_interval_seconds": 2.0,
    "history_limit": 1000,
    "auto_install_dependencies": False,
    "load_plugins": False,
    "disabled_plugins": [],
    "alert_threshold": 70,
    "critical_threshold": 90,
    "auto_state_changes": True,
    "persist_history": True,
}

VCCA_CACHE: dict[str, ModuleType] = {}
VCCA_USAGE: defaultdict[str, dict[str, Any]] = defaultdict(
    lambda: {"count": 0, "last_used": None, "contexts": set()}
)
VCCA_LOG: deque[str] = deque(maxlen=1000)
THREAT_HISTORY: deque[int] = deque(maxlen=1000)
STATE_HISTORY: deque[str] = deque(maxlen=1000)
METRIC_HISTORY: deque[dict[str, Any]] = deque(maxlen=1000)
LOADED_PLUGINS: dict[str, ModuleType] = {}
PLUGIN_ERRORS: dict[str, str] = {}
PLUGIN_METADATA: dict[str, dict[str, Any]] = {}
EVENT_QUEUE: queue.Queue[str] = queue.Queue()

CURRENT_STATE = "baseline"
THREAT_LEVEL = 0
PROGRAM_RUNNING = False
WATCHDOG_ACTIVE = True
MONITOR_THREAD: threading.Thread | None = None
WATCHDOG_THREAD: threading.Thread | None = None
GUI: "VCCAGUI | None" = None
START_MONOTONIC = time.monotonic()
LAST_MONITOR_AT: float | None = None
MONITOR_DURATION_MS = 0.0
ERROR_COUNT = 0
LAST_ERROR: str | None = None
CONFIG = DEFAULT_CONFIG.copy()
HISTORY_LOCK = threading.Lock()


# ------------------------------- Logging ------------------------------------

def log(message: str, level: int = logging.INFO) -> None:
    """Write to console, in-memory log, file log, and the GUI event queue."""
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{stamp}] {message}"
    VCCA_LOG.append(line)
    try:
        print(line, flush=True)
    except Exception:
        pass
    try:
        logging.log(level, message)
    except Exception:
        pass
    try:
        EVENT_QUEUE.put_nowait(line)
    except Exception:
        pass


def record_error(where: str, exc: BaseException) -> None:
    global ERROR_COUNT, LAST_ERROR
    ERROR_COUNT += 1
    LAST_ERROR = f"{where}: {type(exc).__name__}: {exc}"
    log(f"[ERROR] {LAST_ERROR}", logging.ERROR)
    try:
        logging.debug("%s", traceback.format_exc())
    except Exception:
        pass


def setup_logging() -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )


# ----------------------------- Configuration --------------------------------

def load_config() -> dict[str, Any]:
    config = DEFAULT_CONFIG.copy()
    try:
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open("r", encoding="utf-8") as handle:
                saved = json.load(handle)
            if isinstance(saved, dict):
                config.update(saved)
    except Exception as exc:
        log(f"[CONFIG] Could not load config; defaults used: {exc}")
    # Validate values rather than trusting a hand-edited file.
    try:
        config["monitor_interval_seconds"] = max(
            0.5, min(60.0, float(config["monitor_interval_seconds"]))
        )
    except (TypeError, ValueError):
        config["monitor_interval_seconds"] = 2.0
    try:
        config["history_limit"] = max(50, min(10000, int(config["history_limit"])))
    except (TypeError, ValueError):
        config["history_limit"] = 1000
    for key in (
        "auto_install_dependencies", "load_plugins",
        "auto_state_changes", "persist_history"
    ):
        config[key] = bool(config.get(key, False))
    if config.get("mode") not in ("auto", *CONTAINMENT_STATES.keys()):
        config["mode"] = "auto"
    if not isinstance(config.get("disabled_plugins"), list):
        config["disabled_plugins"] = []
    return config


def save_config() -> None:
    try:
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        temp = CONFIG_FILE.with_suffix(".tmp")
        with temp.open("w", encoding="utf-8") as handle:
            json.dump(CONFIG, handle, indent=2)
        temp.replace(CONFIG_FILE)
        log("[CONFIG] Configuration saved.")
    except Exception as exc:
        record_error("save_config", exc)


def load_history() -> None:
    if not CONFIG.get("persist_history", True) or not HISTORY_FILE.exists():
        return
    try:
        with HISTORY_FILE.open("r", encoding="utf-8") as handle:
            data = json.load(handle)
        for value in data.get("threat_history", [])[-CONFIG["history_limit"]:]:
            if isinstance(value, int):
                THREAT_HISTORY.append(max(0, min(100, value)))
        for value in data.get("state_history", [])[-CONFIG["history_limit"]:]:
            if value in CONTAINMENT_STATES:
                STATE_HISTORY.append(value)
        for item in data.get("metrics", [])[-CONFIG["history_limit"]:]:
            if isinstance(item, dict):
                METRIC_HISTORY.append(item)
        log(f"[HISTORY] Restored {len(METRIC_HISTORY)} metric samples.")
    except Exception as exc:
        log(f"[HISTORY] Could not restore history: {exc}")


def save_history() -> None:
    if not CONFIG.get("persist_history", True):
        return
    try:
        with HISTORY_LOCK:
            data = {
                "saved_at": datetime.now().isoformat(timespec="seconds"),
                "threat_history": list(THREAT_HISTORY),
                "state_history": list(STATE_HISTORY),
                "metrics": list(METRIC_HISTORY),
            }
            temp = HISTORY_FILE.with_suffix(".tmp")
            with temp.open("w", encoding="utf-8") as handle:
                json.dump(data, handle, indent=2)
            temp.replace(HISTORY_FILE)
    except Exception as exc:
        record_error("save_history", exc)


# ---------------------------- Dependencies ----------------------------------

def _record_usage(import_name: str, context: str | None = None) -> None:
    item = VCCA_USAGE[import_name]
    item["count"] += 1
    item["last_used"] = time.time()
    if context:
        item["contexts"].add(context)


def package_for_import(import_name: str) -> str:
    for package, mapped_import in (
        (package, module_name)
        for group in DEPENDENCY_GROUPS.values()
        for package, module_name in group.items()
    ):
        if mapped_import == import_name:
            return package
    return import_name


def _install(package: str) -> bool:
    """Install only when explicitly enabled in settings or called by the user."""
    if not CONFIG.get("auto_install_dependencies", False):
        log(
            f"[DEPENDENCY] {package} is missing. Automatic installation is disabled; "
            "enable it in Settings or install it manually."
        )
        return False
    log(f"[DEPENDENCY] Installing {package} into {sys.executable} ...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", package],
            check=True,
            timeout=300,
        )
        log(f"[DEPENDENCY] Installed {package}. Restart may be required.")
        return True
    except Exception as exc:
        record_error(f"install {package}", exc)
        return False


def require(import_name: str, context: str | None = None) -> ModuleType:
    if import_name in VCCA_CACHE:
        _record_usage(import_name, context)
        return VCCA_CACHE[import_name]
    try:
        module = importlib.import_module(import_name)
    except ImportError:
        package = package_for_import(import_name)
        if not _install(package):
            raise
        importlib.invalidate_caches()
        module = importlib.import_module(import_name)
    VCCA_CACHE[import_name] = module
    _record_usage(import_name, context)
    log(f"[DEPENDENCY] Loaded import '{import_name}'")
    return module


def check_dependency(package: str, import_name: str) -> dict[str, Any]:
    try:
        spec = importlib.util.find_spec(import_name)
        available = spec is not None
        return {
            "package": package,
            "import_name": import_name,
            "available": available,
            "loaded": import_name in VCCA_CACHE,
            "error": None,
        }
    except (ImportError, ValueError, ModuleNotFoundError) as exc:
        return {
            "package": package,
            "import_name": import_name,
            "available": False,
            "loaded": import_name in VCCA_CACHE,
            "error": str(exc),
        }


def dependency_report() -> list[dict[str, Any]]:
    rows = []
    for group, packages in DEPENDENCY_GROUPS.items():
        for package, import_name in packages.items():
            row = check_dependency(package, import_name)
            row["group"] = group
            rows.append(row)
    return rows


def require_group(group: str, context: str | None = None) -> dict[str, ModuleType]:
    if group not in DEPENDENCY_GROUPS:
        raise ValueError(f"Unknown dependency group: {group}")
    loaded = {}
    for package, import_name in DEPENDENCY_GROUPS[group].items():
        try:
            loaded[package] = require(import_name, context=context or group)
        except Exception as exc:
            log(f"[DEPENDENCY] Could not load {package} ({import_name}): {exc}")
    return loaded


# -------------------------------- Plugins ------------------------------------

def _plugin_name(path: Path) -> str:
    return path.stem


def scan_plugins() -> list[dict[str, Any]]:
    """Discover plugin files; importing them executes their top-level code."""
    discovered = []
    if not CONFIG.get("load_plugins", False):
        log("[PLUGIN] Loading disabled in Settings; discovery only.")
        for path in sorted(PLUGIN_DIR.glob("*.py")):
            if path.name.startswith("_"):
                continue
            discovered.append({
                "name": path.stem,
                "path": str(path),
                "enabled": path.stem not in CONFIG["disabled_plugins"],
                "loaded": path.stem in LOADED_PLUGINS,
                "status": "not loaded (plugin loading disabled)",
            })
        return discovered

    disabled = set(CONFIG.get("disabled_plugins", []))
    for path in sorted(PLUGIN_DIR.glob("*.py")):
        if path.name.startswith("_") or path.stem in disabled:
            continue
        name = path.stem
        if name in LOADED_PLUGINS:
            continue
        try:
            spec = importlib.util.spec_from_file_location(f"vcca_plugin_{name}", path)
            if spec is None or spec.loader is None:
                raise ImportError("Could not create import specification")
            module = importlib.util.module_from_spec(spec)
            # Plugins are trusted code unless separately isolated. Never load
            # unknown plugins simply because they exist in the folder.
            spec.loader.exec_module(module)
            LOADED_PLUGINS[name] = module
            PLUGIN_METADATA[name] = {
                "path": str(path),
                "requires": list(getattr(module, "REQUIRES", [])),
                "preferred_state": str(getattr(module, "PREFERRED_STATE", "")),
            }
            log(f"[PLUGIN] Loaded trusted plugin: {name}")
        except Exception as exc:
            PLUGIN_ERRORS[name] = str(exc)
            record_error(f"plugin {name}", exc)

    for path in sorted(PLUGIN_DIR.glob("*.py")):
        if path.name.startswith("_"):
            continue
        name = _plugin_name(path)
        discovered.append({
            "name": name,
            "path": str(path),
            "enabled": name not in disabled,
            "loaded": name in LOADED_PLUGINS,
            "status": (
                "loaded" if name in LOADED_PLUGINS else
                PLUGIN_ERRORS.get(name, "disabled or not loaded")
            ),
        })
    return discovered


def plugin_dependencies() -> list[str]:
    deps: set[str] = set()
    for module in LOADED_PLUGINS.values():
        values = getattr(module, "REQUIRES", [])
        if isinstance(values, (list, tuple, set)):
            deps.update(str(value) for value in values)
    return sorted(deps)


def plugin_preferred_states() -> list[str]:
    states = set()
    for module in LOADED_PLUGINS.values():
        state = getattr(module, "PREFERRED_STATE", None)
        if state in CONTAINMENT_STATES:
            states.add(str(state))
    return sorted(states)


def preload_plugin_dependencies() -> None:
    for import_name in plugin_dependencies():
        try:
            require(import_name, context="plugin")
        except Exception as exc:
            log(f"[PLUGIN] Dependency '{import_name}' unavailable: {exc}")


# --------------------------- Environment/prediction --------------------------

def _detect_environment() -> dict[str, Any]:
    gpu_module_available = importlib.util.find_spec("torch") is not None
    gpu_detected = False
    gpu_name = "Not checked"
    # Do not import torch just to detect a GPU: importing it can be slow.
    if "torch" in sys.modules:
        try:
            torch_module = sys.modules["torch"]
            gpu_detected = bool(torch_module.cuda.is_available())
            if gpu_detected:
                gpu_name = torch_module.cuda.get_device_name(0)
        except Exception:
            pass
    cpu_percent = None
    memory_percent = None
    process_memory_mb = None
    process_cpu_percent = None
    if psutil is not None:
        try:
            cpu_percent = psutil.cpu_percent(interval=None)
            memory_percent = psutil.virtual_memory().percent
            process = psutil.Process(os.getpid())
            process_memory_mb = process.memory_info().rss / (1024 * 1024)
            process_cpu_percent = process.cpu_percent(interval=None)
        except Exception:
            pass
    return {
        "is_windows": os.name == "nt",
        "hour": datetime.now().hour,
        "python": sys.version.split()[0],
        "platform": sys.platform,
        "pid": os.getpid(),
        "gpu_library_available": gpu_module_available,
        "gpu_detected": gpu_detected,
        "gpu_name": gpu_name,
        "cpu_percent": cpu_percent,
        "memory_percent": memory_percent,
        "process_memory_mb": process_memory_mb,
        "process_cpu_percent": process_cpu_percent,
        "uptime_seconds": round(time.monotonic() - START_MONOTONIC, 1),
    }


def _strictness_level(state: str) -> int:
    return int(CONTAINMENT_STATES.get(state, CONTAINMENT_STATES["baseline"])["strictness"])


def _group_score(group: str) -> float:
    score = 0.0
    now = time.time()
    for _, import_name in DEPENDENCY_GROUPS.get(group, {}).items():
        info = VCCA_USAGE.get(import_name)
        if not info:
            continue
        age = now - info["last_used"] if info["last_used"] else float("inf")
        recency = 2.0 if age < 300 else 1.0 if age < 3600 else 0.0
        score += min(info["count"], 100) * (1.0 + recency)
    return score


def _best_state(mode: str | None, env: dict[str, Any]) -> str:
    if mode in CONTAINMENT_STATES:
        return str(mode)
    if env.get("hour", 12) >= 22 or env.get("hour", 12) < 6:
        return "security_lock"
    if env.get("gpu_detected") and env.get("is_windows"):
        return "hyper_gpu"
    if env.get("gpu_library_available"):
        return "vision_drift"
    if env.get("is_windows"):
        return "security_lock"
    return "baseline"


def _predict_groups(env: dict[str, Any], mode: str | None = None) -> tuple[list[str], str]:
    state = _best_state(mode, env)
    predicted = set(CONTAINMENT_STATES[state]["required_groups"])
    if env.get("gpu_library_available"):
        predicted.add("gpu")
    if env.get("is_windows"):
        predicted.add("governor")
    scores = sorted(
        DEPENDENCY_GROUPS,
        key=lambda group: _group_score(group),
        reverse=True,
    )
    for group in scores[:2]:
        if _group_score(group) > 0:
            predicted.add(group)
    return sorted(predicted), state


def compute_threat_level(env: dict[str, Any] | None = None) -> int:
    """
    Compute an operational anomaly indicator, not a cybersecurity verdict.
    Uses sustained resource pressure, recent errors, and plugin load errors.
    """
    env = env or _detect_environment()
    cpu = env.get("cpu_percent")
    memory = env.get("memory_percent")
    cpu_factor = max(0, min(25, int((float(cpu) - 65) * 0.7))) if cpu is not None else 0
    memory_factor = max(0, min(25, int((float(memory) - 70) * 0.8))) if memory is not None else 0
    recent_error_factor = min(35, ERROR_COUNT * 4)
    plugin_error_factor = min(15, len(PLUGIN_ERRORS) * 5)
    return max(0, min(100, cpu_factor + memory_factor + recent_error_factor + plugin_error_factor))


def forecast_threat() -> int:
    if not THREAT_HISTORY:
        return THREAT_LEVEL
    values = list(THREAT_HISTORY)[-10:]
    if len(values) < 3:
        return int(round(statistics.mean(values)))
    recent = values[-5:]
    older = values[-10:-5] if len(values) >= 8 else values[:-len(recent)]
    baseline = statistics.mean(older) if older else recent[0]
    recent_mean = statistics.mean(recent)
    slope = (recent_mean - baseline) / max(1, len(recent))
    forecast = recent_mean + slope * 3
    return max(0, min(100, int(round(forecast))))


def prediction_summary() -> dict[str, Any]:
    values = list(THREAT_HISTORY)
    forecast = forecast_threat()
    if len(values) < 5:
        confidence = "low"
        explanation = "Collecting baseline samples; trend is preliminary."
    else:
        recent = values[-5:]
        spread = max(recent) - min(recent)
        confidence = "moderate" if spread <= 20 else "low"
        explanation = (
            f"Forecast uses recent rolling averages. Recent range: {min(recent)}–{max(recent)}."
        )
    return {
        "current": THREAT_LEVEL,
        "forecast": forecast,
        "confidence": confidence,
        "explanation": explanation,
        "samples": len(values),
        "direction": "rising" if forecast > THREAT_LEVEL + 3 else
                     "falling" if forecast < THREAT_LEVEL - 3 else "stable",
    }


def update_threat_and_cage(env: dict[str, Any] | None = None) -> None:
    global THREAT_LEVEL, CURRENT_STATE
    env = env or _detect_environment()
    THREAT_LEVEL = compute_threat_level(env)
    THREAT_HISTORY.append(THREAT_LEVEL)
    forecast = forecast_threat()

    if CONFIG.get("auto_state_changes", True):
        alert = int(CONFIG.get("alert_threshold", 70))
        critical = int(CONFIG.get("critical_threshold", 90))
        if forecast >= critical or THREAT_LEVEL >= critical:
            new_state = "lockdown"
        elif forecast >= alert or THREAT_LEVEL >= alert:
            new_state = "security_lock"
        elif forecast >= 40 or THREAT_LEVEL >= 40:
            new_state = "hyper_gpu"
        elif forecast < 20 and THREAT_LEVEL < 20:
            new_state = "baseline"
        else:
            new_state = CURRENT_STATE

        # Hysteresis: require several low samples before relaxing a strict state.
        if _strictness_level(new_state) < _strictness_level(CURRENT_STATE):
            recent = list(THREAT_HISTORY)[-4:]
            if len(recent) < 4 or any(value >= 25 for value in recent):
                new_state = CURRENT_STATE
        if new_state != CURRENT_STATE:
            log(
                f"[GOVERNOR] State changed {CURRENT_STATE} -> {new_state} "
                f"(score={THREAT_LEVEL}, forecast={forecast})."
            )
            CURRENT_STATE = new_state

    STATE_HISTORY.append(CURRENT_STATE)
    METRIC_HISTORY.append({
        "timestamp": datetime.now().isoformat(timespec="seconds"),
        "threat": THREAT_LEVEL,
        "forecast": forecast,
        "state": CURRENT_STATE,
        "cpu_percent": env.get("cpu_percent"),
        "memory_percent": env.get("memory_percent"),
        "process_memory_mb": env.get("process_memory_mb"),
        "monitor_duration_ms": round(MONITOR_DURATION_MS, 2),
        "error_count": ERROR_COUNT,
    })


def predictive_preload(mode: str | None = None) -> None:
    env = _detect_environment()
    groups, state = _predict_groups(env, mode)
    global CURRENT_STATE
    CURRENT_STATE = state
    log(f"[PREDICTION] Selected state={state}; suggested groups={groups}.")
    # Only preload required groups by default. Extra groups are suggestions,
    # not a reason to import large optional libraries during every startup.
    for group in CONTAINMENT_STATES[state]["required_groups"]:
        require_group(group, context=f"startup:{state}")


def enforce_state(state: str) -> bool:
    if state not in CONTAINMENT_STATES:
        log(f"[GOVERNOR] Unknown state: {state}")
        return False
    missing = []
    for group in CONTAINMENT_STATES[state]["required_groups"]:
        for _, import_name in DEPENDENCY_GROUPS[group].items():
            if import_name not in VCCA_CACHE:
                missing.append(f"{group}:{import_name}")
    if missing:
        log(f"[GOVERNOR] State '{state}' has unloaded dependencies: {', '.join(missing)}")
        return False
    log(f"[GOVERNOR] Dependency check passed for state '{state}'.")
    return True


def corrective_enforce(state: str) -> bool:
    if state not in CONTAINMENT_STATES:
        return False
    for group in CONTAINMENT_STATES[state]["required_groups"]:
        require_group(group, context=f"recovery:{state}")
    return enforce_state(state)


def vcca_status() -> dict[str, Any]:
    env = _detect_environment()
    return {
        "version": APP_VERSION,
        "loaded_modules": sorted(VCCA_CACHE),
        "usage": {
            name: {
                "count": info["count"],
                "last_used": info["last_used"],
                "contexts": sorted(info["contexts"]),
            }
            for name, info in VCCA_USAGE.items()
        },
        "groups": list(DEPENDENCY_GROUPS),
        "states": CONTAINMENT_STATES,
        "current_state": CURRENT_STATE,
        "running": PROGRAM_RUNNING,
        "threat_level": THREAT_LEVEL,
        "threat_forecast": forecast_threat(),
        "prediction": prediction_summary(),
        "environment": env,
        "dependency_report": dependency_report(),
        "log": list(VCCA_LOG),
        "plugins": sorted(LOADED_PLUGINS),
        "plugin_errors": dict(PLUGIN_ERRORS),
        "state_history": list(STATE_HISTORY),
        "threat_history": list(THREAT_HISTORY),
        "metrics": list(METRIC_HISTORY),
        "error_count": ERROR_COUNT,
        "last_error": LAST_ERROR,
        "monitor_duration_ms": MONITOR_DURATION_MS,
    }


# ------------------------------- Monitoring ---------------------------------

def monitor_loop() -> None:
    global LAST_MONITOR_AT, MONITOR_DURATION_MS
    while PROGRAM_RUNNING:
        started = time.monotonic()
        try:
            env = _detect_environment()
            update_threat_and_cage(env)
            LAST_MONITOR_AT = time.time()
            MONITOR_DURATION_MS = (time.monotonic() - started) * 1000.0
        except Exception as exc:
            record_error("monitor_loop", exc)
        time.sleep(float(CONFIG.get("monitor_interval_seconds", 2.0)))
    log("[MONITOR] Monitor loop stopped.")


def watchdog_loop() -> None:
    last_report = 0.0
    while WATCHDOG_ACTIVE:
        now = time.monotonic()
        if PROGRAM_RUNNING and LAST_MONITOR_AT is not None:
            age = time.time() - LAST_MONITOR_AT
            if age > max(15.0, float(CONFIG.get("monitor_interval_seconds", 2.0)) * 5):
                if now - last_report > 15:
                    log(f"[WATCHDOG] Monitoring appears delayed ({age:.1f}s since last sample).")
                    last_report = now
        time.sleep(3.0)


def start_background_workers() -> None:
    global MONITOR_THREAD, WATCHDOG_THREAD
    MONITOR_THREAD = threading.Thread(target=monitor_loop, name="VCCA-Monitor", daemon=True)
    WATCHDOG_THREAD = threading.Thread(target=watchdog_loop, name="VCCA-Watchdog", daemon=True)
    MONITOR_THREAD.start()
    WATCHDOG_THREAD.start()


# ----------------------------------- GUI -------------------------------------

class VCCAGUI:
    def __init__(self) -> None:
        if tk is None or ttk is None:
            raise RuntimeError("Tkinter is not available in this Python installation.")
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("980x680")
        self.root.minsize(780, 520)
        self.root.protocol("WM_DELETE_WINDOW", self.shutdown)
        self._build_interface()
        self.refresh()

    def _build_interface(self) -> None:
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text=APP_NAME, font=("Segoe UI", 15, "bold")).pack(side="left")
        self.status_label = ttk.Label(header, text="Starting...")
        self.status_label.pack(side="right")

        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)

        self.overview_tab = ttk.Frame(self.tabs, padding=10)
        self.dependencies_tab = ttk.Frame(self.tabs, padding=10)
        self.prediction_tab = ttk.Frame(self.tabs, padding=10)
        self.plugins_tab = ttk.Frame(self.tabs, padding=10)
        self.logs_tab = ttk.Frame(self.tabs, padding=10)
        self.settings_tab = ttk.Frame(self.tabs, padding=10)
        for tab, title in [
            (self.overview_tab, "Overview"),
            (self.dependencies_tab, "Dependencies"),
            (self.prediction_tab, "Prediction"),
            (self.plugins_tab, "Plugins"),
            (self.logs_tab, "Logs"),
            (self.settings_tab, "Settings"),
        ]:
            self.tabs.add(tab, text=title)

        self._build_overview()
        self._build_dependencies()
        self._build_prediction()
        self._build_plugins()
        self._build_logs()
        self._build_settings()

    def _build_overview(self) -> None:
        tab = self.overview_tab
        cards = ttk.Frame(tab)
        cards.pack(fill="x")
        self.state_value = ttk.Label(cards, text="—", font=("Segoe UI", 12, "bold"))
        self.score_value = ttk.Label(cards, text="—", font=("Segoe UI", 12, "bold"))
        self.forecast_value = ttk.Label(cards, text="—", font=("Segoe UI", 12, "bold"))
        self.uptime_value = ttk.Label(cards, text="—", font=("Segoe UI", 12, "bold"))
        for col, (label, widget) in enumerate([
            ("Governor state", self.state_value),
            ("Operational score", self.score_value),
            ("Forecast", self.forecast_value),
            ("Uptime", self.uptime_value),
        ]):
            frame = ttk.LabelFrame(cards, text=label, padding=10)
            frame.grid(row=0, column=col, padx=4, sticky="nsew")
            widget.pack(in_=frame)
            cards.columnconfigure(col, weight=1)

        self.threat_bar = ttk.Progressbar(tab, maximum=100, mode="determinate")
        self.threat_bar.pack(fill="x", pady=10)
        self.environment_text = tk.Text(tab, height=9, wrap="word")
        self.environment_text.pack(fill="both", expand=True)
        self.environment_text.configure(state="disabled")
        ttk.Label(
            tab,
            text="The operational score reflects resource pressure and recorded errors; it is not a malware verdict.",
            wraplength=850,
        ).pack(anchor="w", pady=(8, 0))

    def _build_dependencies(self) -> None:
        top = ttk.Frame(self.dependencies_tab)
        top.pack(fill="x", pady=(0, 8))
        ttk.Button(top, text="Refresh", command=self.refresh).pack(side="left")
        ttk.Button(top, text="Check selected group", command=self.check_selected_group).pack(side="left", padx=6)
        self.dep_tree = ttk.Treeview(
            self.dependencies_tab,
            columns=("group", "package", "import", "status", "loaded"),
            show="headings",
            height=16,
        )
        for col, title, width in [
            ("group", "Group", 100), ("package", "Package", 160),
            ("import", "Import name", 160), ("status", "Availability", 130),
            ("loaded", "Loaded this session", 140),
        ]:
            self.dep_tree.heading(col, text=title)
            self.dep_tree.column(col, width=width, anchor="w")
        self.dep_tree.pack(fill="both", expand=True)

    def _build_prediction(self) -> None:
        tab = self.prediction_tab
        self.prediction_summary_label = ttk.Label(tab, text="Collecting samples...", font=("Segoe UI", 11, "bold"))
        self.prediction_summary_label.pack(anchor="w", pady=(0, 8))
        self.prediction_details = tk.Text(tab, height=8, wrap="word")
        self.prediction_details.pack(fill="x")
        self.prediction_details.configure(state="disabled")
        ttk.Label(tab, text="Recent operational-score samples (oldest → newest):").pack(anchor="w", pady=(10, 4))
        self.history_text = tk.Text(tab, height=8, wrap="word")
        self.history_text.pack(fill="both", expand=True)
        self.history_text.configure(state="disabled")

    def _build_plugins(self) -> None:
        row = ttk.Frame(self.plugins_tab)
        row.pack(fill="x", pady=(0, 8))
        ttk.Button(row, text="Refresh plugin list", command=self.refresh_plugins).pack(side="left")
        ttk.Button(row, text="Enable selected", command=lambda: self.set_selected_plugin(True)).pack(side="left", padx=5)
        ttk.Button(row, text="Disable selected", command=lambda: self.set_selected_plugin(False)).pack(side="left")
        self.plugin_tree = ttk.Treeview(
            self.plugins_tab,
            columns=("name", "enabled", "loaded", "status"),
            show="headings",
            height=14,
        )
        for col, title, width in [
            ("name", "Plugin", 180), ("enabled", "Enabled", 80),
            ("loaded", "Loaded", 80), ("status", "Status", 440),
        ]:
            self.plugin_tree.heading(col, text=title)
            self.plugin_tree.column(col, width=width, anchor="w")
        self.plugin_tree.pack(fill="both", expand=True)
        ttk.Label(
            self.plugins_tab,
            text="Warning: enabled Python plugins execute code inside this process. Only enable plugins you trust.",
            wraplength=850,
        ).pack(anchor="w", pady=(8, 0))

    def _build_logs(self) -> None:
        bar = ttk.Frame(self.logs_tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Clear visible log", command=self.clear_log_view).pack(side="left")
        ttk.Button(bar, text="Open log folder", command=self.open_log_folder).pack(side="left", padx=6)
        self.log_box = tk.Text(self.logs_tab, wrap="none", height=20)
        self.log_box.pack(fill="both", expand=True)

    def _build_settings(self) -> None:
        tab = self.settings_tab
        self.mode_var = tk.StringVar(value=str(CONFIG.get("mode", "auto")))
        self.interval_var = tk.StringVar(value=str(CONFIG.get("monitor_interval_seconds", 2.0)))
        self.install_var = tk.BooleanVar(value=CONFIG.get("auto_install_dependencies", False))
        self.plugins_var = tk.BooleanVar(value=CONFIG.get("load_plugins", False))
        self.auto_state_var = tk.BooleanVar(value=CONFIG.get("auto_state_changes", True))
        self.persist_var = tk.BooleanVar(value=CONFIG.get("persist_history", True))

        ttk.Label(tab, text="Startup mode").grid(row=0, column=0, sticky="w", pady=5)
        ttk.Combobox(
            tab, textvariable=self.mode_var, state="readonly",
            values=["auto", *CONTAINMENT_STATES.keys()], width=24
        ).grid(row=0, column=1, sticky="w", padx=8)
        ttk.Label(tab, text="Monitor interval (seconds, 0.5–60)").grid(row=1, column=0, sticky="w", pady=5)
        ttk.Entry(tab, textvariable=self.interval_var, width=27).grid(row=1, column=1, sticky="w", padx=8)
        ttk.Checkbutton(tab, text="Allow automatic pip installs (not recommended for unattended use)",
                        variable=self.install_var).grid(row=2, column=0, columnspan=2, sticky="w", pady=5)
        ttk.Checkbutton(tab, text="Load enabled plugins (trusted code only)",
                        variable=self.plugins_var).grid(row=3, column=0, columnspan=2, sticky="w", pady=5)
        ttk.Checkbutton(tab, text="Allow automatic governor state changes",
                        variable=self.auto_state_var).grid(row=4, column=0, columnspan=2, sticky="w", pady=5)
        ttk.Checkbutton(tab, text="Persist prediction history to disk",
                        variable=self.persist_var).grid(row=5, column=0, columnspan=2, sticky="w", pady=5)
        ttk.Button(tab, text="Save settings", command=self.save_settings).grid(row=6, column=0, sticky="w", pady=12)
        ttk.Button(tab, text="Save history now", command=save_history).grid(row=6, column=1, sticky="w", pady=12)
        ttk.Label(
            tab,
            text="Settings apply immediately where possible. Startup mode takes effect on the next restart. "
                 "Governor states are internal labels and do not enforce Windows security controls.",
            wraplength=850,
        ).grid(row=7, column=0, columnspan=2, sticky="w", pady=8)

    def _set_text(self, widget: Any, text: str) -> None:
        widget.configure(state="normal")
        widget.delete("1.0", tk.END)
        widget.insert(tk.END, text)
        widget.configure(state="disabled")

    def refresh(self) -> None:
        if not self.root.winfo_exists():
            return
        status = vcca_status()
        self.status_label.configure(text="RUNNING" if status["running"] else "STOPPED")
        self.state_value.configure(text=status["current_state"])
        self.score_value.configure(text=f'{status["threat_level"]}/100')
        self.forecast_value.configure(text=f'{status["threat_forecast"]}/100')
        self.uptime_value.configure(text=f'{status["environment"]["uptime_seconds"]:.0f}s')
        self.threat_bar["value"] = status["threat_level"]

        env = status["environment"]
        lines = [
            f"Application version: {APP_VERSION}",
            f"Python: {env['python']} ({env['platform']})",
            f"PID: {env['pid']}",
            f"Operating system: {'Windows' if env['is_windows'] else env['platform']}",
            f"PyTorch import available: {env['gpu_library_available']}",
            f"CUDA GPU detected by an already-loaded PyTorch: {env['gpu_detected']}",
            f"GPU: {env['gpu_name']}",
            f"System CPU usage: {env['cpu_percent'] if env['cpu_percent'] is not None else 'psutil unavailable'}",
            f"System memory usage: {env['memory_percent'] if env['memory_percent'] is not None else 'psutil unavailable'}",
            f"Process memory: {env['process_memory_mb']:.1f} MB" if env["process_memory_mb"] is not None else "Process memory: unavailable",
            f"Recorded errors: {status['error_count']}",
            f"Loaded imports: {len(status['loaded_modules'])}",
            f"Loaded plugins: {len(status['plugins'])}",
            f"Monitor duration: {status['monitor_duration_ms']:.2f} ms",
            "",
            "Scope: dependency and process-health monitoring only; no OS-level containment.",
        ]
        self._set_text(self.environment_text, "\n".join(lines))
        self.refresh_dependencies()
        self.refresh_prediction()
        self.refresh_plugins()
        self.refresh_logs()
        self.root.after(1500, self.refresh)

    def refresh_dependencies(self) -> None:
        if not hasattr(self, "dep_tree"):
            return
        for item in self.dep_tree.get_children():
            self.dep_tree.delete(item)
        for row in dependency_report():
            self.dep_tree.insert("", "end", values=(
                row["group"], row["package"], row["import_name"],
                "Available" if row["available"] else "Missing",
                "Yes" if row["loaded"] else "No",
            ))

    def check_selected_group(self) -> None:
        selection = self.dep_tree.selection()
        if not selection:
            messagebox.showinfo("Dependencies", "Select a dependency row first.")
            return
        group = self.dep_tree.item(selection[0], "values")[0]
        report = [row for row in dependency_report() if row["group"] == group]
        details = "\n".join(
            f"{row['package']} ({row['import_name']}): "
            f"{'available' if row['available'] else 'missing'}"
            for row in report
        )
        messagebox.showinfo(f"Dependency group: {group}", details or "No dependencies found.")

    def refresh_prediction(self) -> None:
        summary = prediction_summary()
        self.prediction_summary_label.configure(
            text=f"Trend: {summary['direction'].upper()} | "
                 f"Forecast: {summary['forecast']}/100 | "
                 f"Confidence: {summary['confidence']} | Samples: {summary['samples']}"
        )
        detail = (
            f"{summary['explanation']}\n\n"
            "Interpretation: this is a short-horizon estimate of the program's operational "
            "score, not a probability of compromise or a machine-learning diagnosis.\n\n"
            f"Last error: {LAST_ERROR or 'None recorded'}\n"
            f"Monitor duration: {MONITOR_DURATION_MS:.2f} ms"
        )
        self._set_text(self.prediction_details, detail)
        values = list(THREAT_HISTORY)[-80:]
        self._set_text(self.history_text, "  →  ".join(str(v) for v in values) or "Waiting for samples...")

    def refresh_plugins(self) -> None:
        if not hasattr(self, "plugin_tree"):
            return
        for item in self.plugin_tree.get_children():
            self.plugin_tree.delete(item)
        for row in scan_plugins():
            self.plugin_tree.insert("", "end", values=(
                row["name"], "Yes" if row["enabled"] else "No",
                "Yes" if row["loaded"] else "No", row["status"],
            ))

    def set_selected_plugin(self, enabled: bool) -> None:
        selection = self.plugin_tree.selection()
        if not selection:
            messagebox.showinfo("Plugins", "Select a plugin first.")
            return
        name = self.plugin_tree.item(selection[0], "values")[0]
        disabled = set(CONFIG.get("disabled_plugins", []))
        if enabled:
            if name in disabled:
                disabled.remove(name)
        else:
            disabled.add(name)
        CONFIG["disabled_plugins"] = sorted(disabled)
        save_config()
        if enabled:
            messagebox.showinfo(
                "Plugin enabled",
                f"{name} is enabled for loading. If plugin loading is enabled, restart the application to load it.",
            )
        else:
            messagebox.showinfo(
                "Plugin disabled",
                f"{name} will not load on the next scan/restart. A plugin already loaded in this process "
                "cannot be safely unloaded.",
            )
        self.refresh_plugins()

    def refresh_logs(self) -> None:
        if not hasattr(self, "log_box"):
            return
        lines = list(VCCA_LOG)[-500:]
        current = self.log_box.get("1.0", tk.END).splitlines()
        if current != lines:
            self.log_box.configure(state="normal")
            self.log_box.delete("1.0", tk.END)
            self.log_box.insert(tk.END, "\n".join(lines))
            self.log_box.see(tk.END)

    def clear_log_view(self) -> None:
        self.log_box.delete("1.0", tk.END)

    def open_log_folder(self) -> None:
        try:
            if os.name == "nt":
                os.startfile(str(DATA_DIR))
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(DATA_DIR)])
            else:
                subprocess.Popen(["xdg-open", str(DATA_DIR)])
        except Exception as exc:
            messagebox.showerror("Open log folder", str(exc))

    def save_settings(self) -> None:
        try:
            interval = float(self.interval_var.get())
            if not 0.5 <= interval <= 60:
                raise ValueError("Interval must be between 0.5 and 60 seconds.")
            mode = self.mode_var.get()
            if mode not in ("auto", *CONTAINMENT_STATES.keys()):
                raise ValueError("Select a valid startup mode.")
            CONFIG.update({
                "mode": mode,
                "monitor_interval_seconds": interval,
                "auto_install_dependencies": bool(self.install_var.get()),
                "load_plugins": bool(self.plugins_var.get()),
                "auto_state_changes": bool(self.auto_state_var.get()),
                "persist_history": bool(self.persist_var.get()),
            })
            save_config()
            messagebox.showinfo("Settings", "Settings saved.")
        except Exception as exc:
            messagebox.showerror("Invalid settings", str(exc))

    def shutdown(self) -> None:
        global PROGRAM_RUNNING, WATCHDOG_ACTIVE
        PROGRAM_RUNNING = False
        WATCHDOG_ACTIVE = False
        save_history()
        save_config()
        log("[SHUTDOWN] Clean shutdown requested.")
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


# -------------------------------- Bootstrap ----------------------------------

def bootstrap_containment(mode: str | None = None) -> None:
    global PROGRAM_RUNNING, CURRENT_STATE
    PROGRAM_RUNNING = True
    env = _detect_environment()
    chosen_mode = mode if mode is not None else CONFIG.get("mode", "auto")
    chosen_mode = None if chosen_mode == "auto" else chosen_mode
    groups, state = _predict_groups(env, chosen_mode)
    CURRENT_STATE = state
    log(f"[BOOT] {APP_NAME} v{APP_VERSION}; selected state={state}; suggested groups={groups}")
    predictive_preload(chosen_mode)
    if CONFIG.get("load_plugins", False):
        scan_plugins()
        preload_plugin_dependencies()
    else:
        scan_plugins()  # discovery only, no imports
    update_threat_and_cage(_detect_environment())
    log("[BOOT] Ready. Note: governor states do not provide OS-level containment.")


def main() -> int:
    global CONFIG, GUI, PROGRAM_RUNNING, WATCHDOG_ACTIVE
    setup_logging()
    CONFIG = load_config()
    load_history()
    log(f"[START] {APP_NAME} v{APP_VERSION}")
    log(f"[START] Python executable: {sys.executable}")
    log(f"[START] Data directory: {DATA_DIR}")

    try:
        bootstrap_containment()
    except Exception as exc:
        record_error("bootstrap", exc)
        log("[START] Bootstrap continued with reduced functionality.")

    start_background_workers()

    if tk is not None:
        try:
            GUI = VCCAGUI()
            GUI.run()  # Tkinter stays on the main thread.
        except Exception as exc:
            record_error("GUI", exc)
            log("[GUI] GUI unavailable; continuing in console mode.")
            try:
                while PROGRAM_RUNNING:
                    time.sleep(1)
            except KeyboardInterrupt:
                pass
    else:
        log("[GUI] Tkinter unavailable; running in console mode.")
        try:
            while PROGRAM_RUNNING:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    PROGRAM_RUNNING = False
    WATCHDOG_ACTIVE = False
    save_history()
    save_config()
    log("[STOP] Shutdown complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
