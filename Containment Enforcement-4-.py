# ============================================================
#  VCCA LAB GOVERNOR X (VCCA_LAB_X.py)
#  Variable Containment Cage + Autoloader + Threat Engine + GUI + Plugins
#  Strict, intelligent, visual, autonomous, predictive, plugin-aware
# ============================================================

import importlib
import subprocess
import sys
import time
import os
from types import ModuleType
from collections import defaultdict, deque
import threading
from datetime import datetime

# GUI (Tkinter)
try:
    import tkinter as tk
    from tkinter import ttk
except ImportError:
    tk = None
    ttk = None

# ------------------------------------------------------------
#  Global state
# ------------------------------------------------------------

VCCA_CACHE: dict[str, ModuleType] = {}
VCCA_USAGE = defaultdict(lambda: {
    "count": 0,
    "last_used": None,
    "contexts": set(),
})
VCCA_ERRORS: list[str] = []
THREAT_HISTORY: deque[int] = deque(maxlen=50)
STATE_HISTORY: deque[str] = deque(maxlen=50)

DEPENDENCY_GROUPS: dict[str, list[str]] = {
    "core": ["requests", "psutil", "pyyaml"],
    "gpu": ["torch", "numpy", "cupy"],
    "vision": ["opencv-python", "Pillow"],
    "governor": ["pywin32", "wmi"],
}

CONTAINMENT_STATES: dict[str, dict[str, list[str] | int]] = {
    "baseline": {
        "required_groups": ["core"],
        "strictness": 1,
    },
    "hyper_gpu": {
        "required_groups": ["core", "gpu", "governor"],
        "strictness": 2,
    },
    "vision_drift": {
        "required_groups": ["core", "vision", "gpu"],
        "strictness": 2,
    },
    "security_lock": {
        "required_groups": ["core", "governor"],
        "strictness": 3,
    },
    "lockdown": {
        "required_groups": ["core", "governor"],
        "strictness": 4,
    },
}

CURRENT_STATE: str = "baseline"
PROGRAM_RUNNING: bool = False
THREAT_LEVEL: int = 0  # 0–100
PLUGIN_DIR: str = os.path.join(os.path.dirname(__file__), "plugins")
LOADED_PLUGINS: dict[str, ModuleType] = {}
WATCHDOG_ACTIVE: bool = True

# ------------------------------------------------------------
#  Logging helper
# ------------------------------------------------------------

def log(msg: str):
    ts = datetime.now().strftime("%H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    if len(VCCA_ERRORS) > 500:
        VCCA_ERRORS.pop(0)
    VCCA_ERRORS.append(line)

# ------------------------------------------------------------
#  Low-level install / import
# ------------------------------------------------------------

def _install(pkg: str):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        log(f"Installed: {pkg}")
    except Exception as e:
        log(f"Failed to install {pkg}: {e}")

def _record_usage(pkg: str, context: str | None = None):
    info = VCCA_USAGE[pkg]
    info["count"] += 1
    info["last_used"] = time.time()
    if context:
        info["contexts"].add(context)

def _import(pkg: str, context: str | None = None) -> ModuleType:
    if pkg in VCCA_CACHE:
        _record_usage(pkg, context)
        return VCCA_CACHE[pkg]

    try:
        module = importlib.import_module(pkg)
    except ImportError:
        log(f"Missing: {pkg} → enforcing install...")
        _install(pkg)
        try:
            module = importlib.import_module(pkg)
        except Exception as e:
            log(f"Import failed after install for {pkg}: {e}")
            raise

    VCCA_CACHE[pkg] = module
    _record_usage(pkg, context)
    return module

# ------------------------------------------------------------
#  Public require API
# ------------------------------------------------------------

def require(pkg: str, context: str | None = None) -> ModuleType:
    return _import(pkg, context)

def require_group(group: str, context: str | None = None) -> dict[str, ModuleType]:
    if group not in DEPENDENCY_GROUPS:
        raise ValueError(f"[VCCA] Unknown dependency group: {group}")

    loaded: dict[str, ModuleType] = {}
    for pkg in DEPENDENCY_GROUPS[group]:
        loaded[pkg] = require(pkg, context=context or group)
    return loaded

# ------------------------------------------------------------
#  Plugin system (plugin-aware)
# ------------------------------------------------------------

def scan_plugins():
    if CURRENT_STATE == "lockdown":
        log("Lockdown active → plugin loading disabled.")
        return
    if not os.path.isdir(PLUGIN_DIR):
        return
    for fname in os.listdir(PLUGIN_DIR):
        if not fname.endswith(".py"):
            continue
        mod_name = f"plugins.{fname[:-3]}"
        try:
            module = importlib.import_module(mod_name)
            LOADED_PLUGINS[mod_name] = module
            log(f"[PLUGIN] Loaded {mod_name}")
        except Exception as e:
            log(f"Failed to load plugin {mod_name}: {e}")

def plugin_dependencies():
    deps = set()
    for mod in LOADED_PLUGINS.values():
        if hasattr(mod, "REQUIRES"):
            for pkg in getattr(mod, "REQUIRES"):
                deps.add(pkg)
    return list(deps)

def plugin_threat_boost():
    boost = 0
    for mod in LOADED_PLUGINS.values():
        if hasattr(mod, "THREAT_BOOST"):
            boost += int(getattr(mod, "THREAT_BOOST"))
    return boost

def plugin_preferred_states():
    states = set()
    for mod in LOADED_PLUGINS.values():
        if hasattr(mod, "PREFERRED_STATE"):
            states.add(str(getattr(mod, "PREFERRED_STATE")))
    return list(states)

def preload_plugin_dependencies():
    deps = plugin_dependencies()
    if not deps:
        return
    log(f"[PLUGIN] Preloading plugin deps: {deps}")
    for pkg in deps:
        try:
            require(pkg, context="plugin")
        except Exception as e:
            log(f"Failed to preload plugin dep {pkg}: {e}")

# ------------------------------------------------------------
#  Environment + scoring + prediction
# ------------------------------------------------------------

def _detect_environment() -> dict:
    env = {
        "has_gpu": False,
        "is_windows": os.name == "nt",
        "hour": datetime.now().hour,
    }
    try:
        torch_spec = importlib.util.find_spec("torch")
        env["has_gpu"] = torch_spec is not None
    except Exception:
        pass
    return env

def _group_score(group: str) -> float:
    score = 0.0
    now = time.time()
    for pkg in DEPENDENCY_GROUPS.get(group, []):
        info = VCCA_USAGE.get(pkg)
        if not info:
            continue
        mass = float(info["count"])
        if mass <= 0:
            continue
        recency_boost = 0.0
        if info["last_used"]:
            age = now - info["last_used"]
            if age < 300:
                recency_boost = 2.0
            elif age < 3600:
                recency_boost = 1.0
        score += mass * (1.0 + recency_boost)
    return score

def _best_state(mode: str | None, env: dict) -> str:
    plugin_states = plugin_preferred_states()
    if mode in CONTAINMENT_STATES:
        return mode
    if plugin_states:
        for s in plugin_states:
            if s in CONTAINMENT_STATES:
                return s
    if env["hour"] >= 22 or env["hour"] < 6:
        return "security_lock"
    if env.get("has_gpu") and env.get("is_windows"):
        return "hyper_gpu"
    if env.get("has_gpu"):
        return "vision_drift"
    if env.get("is_windows"):
        return "security_lock"
    return "baseline"

def _predict_groups(env: dict, mode: str | None = None) -> tuple[list[str], str]:
    state = _best_state(mode, env)
    base_required = set(CONTAINMENT_STATES[state]["required_groups"])

    predicted = set(base_required)

    if env.get("has_gpu"):
        predicted.add("gpu")
        predicted.add("vision")
    if env.get("is_windows"):
        predicted.add("governor")

    scores = {g: _group_score(g) for g in DEPENDENCY_GROUPS.keys()}
    hot_groups = sorted(scores.keys(), key=lambda g: scores[g], reverse=True)

    for g in hot_groups[:3]:
        if scores[g] > 0:
            predicted.add(g)

    return list(predicted), state

# ------------------------------------------------------------
#  Threat engine + cage logic (strict + predictive)
# ------------------------------------------------------------

def _strictness_level(state: str) -> int:
    return int(CONTAINMENT_STATES.get(state, CONTAINMENT_STATES["baseline"])["strictness"])

def compute_threat_level():
    now = time.time()
    recent_new = 0
    recent_calls = 0
    for pkg, info in VCCA_USAGE.items():
        if info["last_used"]:
            age = now - info["last_used"]
            if age < 120:
                recent_calls += info["count"]
                if info["count"] <= 2:
                    recent_new += 1

    error_factor = min(len(VCCA_ERRORS), 20) * 2
    activity_factor = min(recent_calls, 100) * 1
    novelty_factor = min(recent_new, 20) * 3
    plugin_factor = plugin_threat_boost()

    level = activity_factor + novelty_factor + error_factor + plugin_factor
    return max(0, min(100, level))

def forecast_threat():
    if len(THREAT_HISTORY) < 3:
        return THREAT_LEVEL
    diffs = [THREAT_HISTORY[i] - THREAT_HISTORY[i - 1] for i in range(1, len(THREAT_HISTORY))]
    avg_delta = sum(diffs) / len(diffs)
    forecast = THREAT_LEVEL + avg_delta * 2
    return max(0, min(100, int(forecast)))

def update_threat_and_cage():
    global THREAT_LEVEL, CURRENT_STATE
    THREAT_LEVEL = compute_threat_level()
    THREAT_HISTORY.append(THREAT_LEVEL)

    forecast = forecast_threat()
    current_strict = _strictness_level(CURRENT_STATE)

    if forecast >= 85 or THREAT_LEVEL >= 90:
        if CURRENT_STATE != "lockdown":
            CURRENT_STATE = "lockdown"
            log(f"[THREAT] CRITICAL ({THREAT_LEVEL}, forecast={forecast}) → state={CURRENT_STATE}")
    elif forecast >= 70 or THREAT_LEVEL >= 70:
        if current_strict < 3:
            CURRENT_STATE = "security_lock"
            log(f"[THREAT] HIGH ({THREAT_LEVEL}, forecast={forecast}) → state={CURRENT_STATE}")
    elif forecast >= 40 or THREAT_LEVEL >= 40:
        if current_strict < 2:
            CURRENT_STATE = "hyper_gpu"
            log(f"[THREAT] MED ({THREAT_LEVEL}, forecast={forecast}) → state={CURRENT_STATE}")
    elif forecast < 20 and THREAT_LEVEL < 20 and current_strict > 1:
        CURRENT_STATE = "baseline"
        log(f"[THREAT] LOW ({THREAT_LEVEL}, forecast={forecast}) → state={CURRENT_STATE}")

    STATE_HISTORY.append(CURRENT_STATE)

def predictive_preload(mode: str | None = None):
    env = _detect_environment()
    groups, state = _predict_groups(env, mode)
    global CURRENT_STATE
    CURRENT_STATE = state
    log(f"Predictive preload → state={state}, groups={groups}, env={env}")
    for g in groups:
        try:
            require_group(g, context=f"preload:{state}")
        except Exception as e:
            log(f"Failed to preload group {g}: {e}")

def enforce_state(state: str) -> bool:
    if state not in CONTAINMENT_STATES:
        log(f"[ENFORCER] Unknown state={state}")
        return False

    required_groups = CONTAINMENT_STATES[state]["required_groups"]
    missing_groups = []

    for g in required_groups:
        for pkg in DEPENDENCY_GROUPS.get(g, []):
            if pkg not in VCCA_CACHE:
                missing_groups.append(g)
                break

    if missing_groups:
        log(f"[ENFORCER] Non-compliant state={state}, missing={missing_groups}")
        return False

    log(f"[ENFORCER] State={state} compliant.")
    return True

def corrective_enforce(state: str):
    log(f"Corrective enforcement for state={state}...")
    required_groups = CONTAINMENT_STATES[state]["required_groups"]
    for g in required_groups:
        try:
            require_group(g, context=f"corrective:{state}")
        except Exception as e:
            log(f"Corrective preload failed for group {g}: {e}")
    enforce_state(state)

# ------------------------------------------------------------
#  Introspection
# ------------------------------------------------------------

def vcca_status() -> dict:
    return {
        "loaded_modules": list(VCCA_CACHE.keys()),
        "usage": {
            pkg: {
                "count": info["count"],
                "last_used": info["last_used"],
                "contexts": list(info["contexts"]),
            }
            for pkg, info in VCCA_USAGE.items()
        },
        "groups": list(DEPENDENCY_GROUPS.keys()),
        "states": CONTAINMENT_STATES,
        "current_state": CURRENT_STATE,
        "running": PROGRAM_RUNNING,
        "threat_level": THREAT_LEVEL,
        "threat_forecast": forecast_threat(),
        "errors": list(VCCA_ERRORS[-20:]),
        "plugins": list(LOADED_PLUGINS.keys()),
        "state_history": list(STATE_HISTORY),
        "threat_history": list(THREAT_HISTORY),
    }

# ------------------------------------------------------------
#  GUI (more visual)
# ------------------------------------------------------------

class VCCAGUI:
    def __init__(self):
        if tk is None:
            log("[GUI] Tkinter not available, GUI disabled.")
            self.root = None
            return

        self.root = tk.Tk()
        self.root.title("Containment Cage Lab X")

        self.label_running = ttk.Label(self.root, text="Program: UNKNOWN")
        self.label_running.grid(row=0, column=0, padx=10, pady=5, sticky="w")

        self.label_state = ttk.Label(self.root, text="State: UNKNOWN")
        self.label_state.grid(row=1, column=0, padx=10, pady=5, sticky="w")

        self.label_strict = ttk.Label(self.root, text="Strictness: UNKNOWN")
        self.label_strict.grid(row=2, column=0, padx=10, pady=5, sticky="w")

        self.label_threat = ttk.Label(self.root, text="Threat: 0")
        self.label_threat.grid(row=3, column=0, padx=10, pady=5, sticky="w")

        self.progress_threat = ttk.Progressbar(self.root, orient="horizontal", length=200, mode="determinate")
        self.progress_threat.grid(row=3, column=1, padx=10, pady=5, sticky="w")

        self.label_forecast = ttk.Label(self.root, text="Forecast: 0")
        self.label_forecast.grid(row=4, column=0, padx=10, pady=5, sticky="w")

        self.label_groups = ttk.Label(self.root, text="Loaded groups: -")
        self.label_groups.grid(row=5, column=0, padx=10, pady=5, sticky="w")

        self.label_plugins = ttk.Label(self.root, text="Plugins: -")
        self.label_plugins.grid(row=6, column=0, padx=10, pady=5, sticky="w")

        self.log_box = tk.Text(self.root, height=10, width=60)
        self.log_box.grid(row=7, column=0, columnspan=2, padx=10, pady=5, sticky="nsew")
        self.root.grid_rowconfigure(7, weight=1)
        self.root.grid_columnconfigure(1, weight=1)

        self.root.after(500, self.refresh)

    def _color_for_threat(self, level: int) -> str:
        if level >= 85:
            return "red"
        if level >= 70:
            return "orange red"
        if level >= 40:
            return "orange"
        return "green"

    def refresh(self):
        status = vcca_status()
        running_text = "RUNNING" if status["running"] else "STOPPED"
        self.label_running.config(text=f"Program: {running_text}")

        state = status["current_state"]
        self.label_state.config(text=f"State: {state}")

        strict = _strictness_level(state)
        self.label_strict.config(text=f"Strictness: {strict}")

        threat = status["threat_level"]
        forecast = status["threat_forecast"]
        self.label_threat.config(text=f"Threat: {threat}")
        self.progress_threat["value"] = threat
        color = self._color_for_threat(threat)
        self.label_threat.config(foreground=color)

        self.label_forecast.config(text=f"Forecast: {forecast}")

        loaded_pkgs = status["loaded_modules"]
        loaded_groups = set()
        for g, pkgs in DEPENDENCY_GROUPS.items():
            if any(p in loaded_pkgs for p in pkgs):
                loaded_groups.add(g)
        self.label_groups.config(text=f"Loaded groups: {', '.join(sorted(loaded_groups)) or '-'}")

        plugins = status["plugins"]
        self.label_plugins.config(text=f"Plugins: {', '.join(plugins) or '-'}")

        self.log_box.delete("1.0", tk.END)
        for line in status["errors"]:
            self.log_box.insert(tk.END, line + "\n")

        self.root.after(500, self.refresh)

    def run(self):
        if self.root is not None:
            self.root.mainloop()

def start_gui_in_thread():
    if tk is None:
        return
    gui = VCCAGUI()
    t = threading.Thread(target=gui.run, daemon=True)
    t.start()

# ------------------------------------------------------------
#  Background monitor + watchdog (autonomous)
# ------------------------------------------------------------

def monitor_loop():
    while PROGRAM_RUNNING:
        update_threat_and_cage()
        time.sleep(2)

def start_monitor_thread():
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()

def watchdog_loop():
    while WATCHDOG_ACTIVE:
        if not PROGRAM_RUNNING:
            log("[WATCHDOG] Program not running flag detected.")
        time.sleep(5)

def start_watchdog_thread():
    t = threading.Thread(target=watchdog_loop, daemon=True)
    t.start()

# ------------------------------------------------------------
#  Bootstrap
# ------------------------------------------------------------

def bootstrap_containment(mode: str | None = None):
    global PROGRAM_RUNNING
    PROGRAM_RUNNING = True

    env = _detect_environment()
    groups, state = _predict_groups(env, mode)
    CURRENT_STATE = state
    log(f"Bootstrapping containment (requested_mode={mode}, chosen_state={state})...")
    predictive_preload(mode=mode)

    scan_plugins()
    preload_plugin_dependencies()

    compliant = enforce_state(state)
    if not compliant:
        corrective_enforce(state)
    update_threat_and_cage()
    log("Containment cage lab X ready.")

if __name__ == "__main__":
    start_gui_in_thread()
    start_monitor_thread()
    start_watchdog_thread()
    bootstrap_containment(mode=None)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        PROGRAM_RUNNING = False
        log("Shutting down.")
