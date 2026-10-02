# ============================================================
#  VCCA LAB GOVERNOR (VCCA_LAB.py)
#  Variable Containment Cage + Autoloader + Threat Engine + GUI + Plugins
# ============================================================

import importlib
import subprocess
import sys
import time
import os
from types import ModuleType
from collections import defaultdict
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
}

CURRENT_STATE: str = "baseline"
PROGRAM_RUNNING: bool = False
THREAT_LEVEL: int = 0  # 0–100
PLUGIN_DIR: str = os.path.join(os.path.dirname(__file__), "plugins")
LOADED_PLUGINS: dict[str, ModuleType] = {}

# ------------------------------------------------------------
#  Low-level install / import
# ------------------------------------------------------------

def _install(pkg: str):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        print(f"[VCCA] Installed: {pkg}")
    except Exception as e:
        msg = f"Failed to install {pkg}: {e}"
        VCCA_ERRORS.append(msg)
        print(f"[VCCA] {msg}")

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
        print(f"[VCCA] Missing: {pkg} → enforcing install...")
        _install(pkg)
        try:
            module = importlib.import_module(pkg)
        except Exception as e:
            msg = f"Import failed after install for {pkg}: {e}"
            VCCA_ERRORS.append(msg)
            print(f"[VCCA] {msg}")
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
#  Plugin system
# ------------------------------------------------------------

def scan_plugins():
    if not os.path.isdir(PLUGIN_DIR):
        return
    for fname in os.listdir(PLUGIN_DIR):
        if not fname.endswith(".py"):
            continue
        mod_name = f"plugins.{fname[:-3]}"
        try:
            module = importlib.import_module(mod_name)
            LOADED_PLUGINS[mod_name] = module
            print(f"[VCCA][PLUGIN] Loaded {mod_name}")
        except Exception as e:
            msg = f"Failed to load plugin {mod_name}: {e}"
            VCCA_ERRORS.append(msg)
            print(f"[VCCA] {msg}")

def plugin_dependencies():
    deps = set()
    for mod in LOADED_PLUGINS.values():
        if hasattr(mod, "REQUIRES"):
            for pkg in getattr(mod, "REQUIRES"):
                deps.add(pkg)
    return list(deps)

def preload_plugin_dependencies():
    deps = plugin_dependencies()
    if not deps:
        return
    print(f"[VCCA][PLUGIN] Preloading plugin deps: {deps}")
    for pkg in deps:
        try:
            require(pkg, context="plugin")
        except Exception as e:
            msg = f"Failed to preload plugin dep {pkg}: {e}"
            VCCA_ERRORS.append(msg)
            print(f"[VCCA] {msg}")

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
    if mode in CONTAINMENT_STATES:
        return mode
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
#  Threat engine + cage logic
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

    error_factor = min(len(VCCA_ERRORS), 10) * 5
    activity_factor = min(recent_calls, 50) * 1
    novelty_factor = min(recent_new, 10) * 4

    level = activity_factor + novelty_factor + error_factor
    return max(0, min(100, level))

def update_threat_and_cage():
    global THREAT_LEVEL, CURRENT_STATE
    THREAT_LEVEL = compute_threat_level()
    current_strict = _strictness_level(CURRENT_STATE)

    if THREAT_LEVEL >= 70 and current_strict < 3:
        CURRENT_STATE = "security_lock"
        print(f"[VCCA][THREAT] HIGH ({THREAT_LEVEL}) → state={CURRENT_STATE}")
    elif THREAT_LEVEL >= 40 and current_strict < 2:
        CURRENT_STATE = "hyper_gpu"
        print(f"[VCCA][THREAT] MED ({THREAT_LEVEL}) → state={CURRENT_STATE}")
    elif THREAT_LEVEL < 20 and current_strict > 1:
        CURRENT_STATE = "baseline"
        print(f"[VCCA][THREAT] LOW ({THREAT_LEVEL}) → state={CURRENT_STATE}")

def predictive_preload(mode: str | None = None):
    env = _detect_environment()
    groups, state = _predict_groups(env, mode)
    global CURRENT_STATE
    CURRENT_STATE = state
    print(f"[VCCA] Predictive preload → state={state}, groups={groups}, env={env}")
    for g in groups:
        try:
            require_group(g, context=f"preload:{state}")
        except Exception as e:
            msg = f"Failed to preload group {g}: {e}"
            VCCA_ERRORS.append(msg)
            print(f"[VCCA] {msg}")

def enforce_state(state: str) -> bool:
    if state not in CONTAINMENT_STATES:
        print(f"[VCCA][ENFORCER] Unknown state={state}")
        return False

    required_groups = CONTAINMENT_STATES[state]["required_groups"]
    missing_groups = []

    for g in required_groups:
        for pkg in DEPENDENCY_GROUPS.get(g, []):
            if pkg not in VCCA_CACHE:
                missing_groups.append(g)
                break

    if missing_groups:
        print(f"[VCCA][ENFORCER] Non-compliant state={state}, missing={missing_groups}")
        return False

    print(f"[VCCA][ENFORCER] State={state} compliant.")
    return True

def corrective_enforce(state: str):
    print(f"[VCCA] Corrective enforcement for state={state}...")
    required_groups = CONTAINMENT_STATES[state]["required_groups"]
    for g in required_groups:
        try:
            require_group(g, context=f"corrective:{state}")
        except Exception as e:
            msg = f"Corrective preload failed for group {g}: {e}"
            VCCA_ERRORS.append(msg)
            print(f"[VCCA] {msg}")
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
        "errors": list(VCCA_ERRORS),
        "plugins": list(LOADED_PLUGINS.keys()),
    }

# ------------------------------------------------------------
#  GUI
# ------------------------------------------------------------

class VCCAGUI:
    def __init__(self):
        if tk is None:
            print("[VCCA][GUI] Tkinter not available, GUI disabled.")
            self.root = None
            return

        self.root = tk.Tk()
        self.root.title("Containment Cage Lab")

        self.label_running = ttk.Label(self.root, text="Program: UNKNOWN")
        self.label_running.pack(padx=10, pady=5)

        self.label_state = ttk.Label(self.root, text="State: UNKNOWN")
        self.label_state.pack(padx=10, pady=5)

        self.label_strict = ttk.Label(self.root, text="Strictness: UNKNOWN")
        self.label_strict.pack(padx=10, pady=5)

        self.label_threat = ttk.Label(self.root, text="Threat: 0")
        self.label_threat.pack(padx=10, pady=5)

        self.progress_threat = ttk.Progressbar(self.root, orient="horizontal", length=200, mode="determinate")
        self.progress_threat.pack(padx=10, pady=5)

        self.label_groups = ttk.Label(self.root, text="Loaded groups: -")
        self.label_groups.pack(padx=10, pady=5)

        self.label_plugins = ttk.Label(self.root, text="Plugins: -")
        self.label_plugins.pack(padx=10, pady=5)

        self.root.after(500, self.refresh)

    def _color_for_threat(self, level: int) -> str:
        if level >= 70:
            return "red"
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
        self.label_threat.config(text=f"Threat: {threat}")
        self.progress_threat["value"] = threat
        color = self._color_for_threat(threat)
        self.label_threat.config(foreground=color)

        loaded_pkgs = status["loaded_modules"]
        loaded_groups = set()
        for g, pkgs in DEPENDENCY_GROUPS.items():
            if any(p in loaded_pkgs for p in pkgs):
                loaded_groups.add(g)
        self.label_groups.config(text=f"Loaded groups: {', '.join(sorted(loaded_groups)) or '-'}")

        plugins = status["plugins"]
        self.label_plugins.config(text=f"Plugins: {', '.join(plugins) or '-'}")

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
#  Background monitor
# ------------------------------------------------------------

def monitor_loop():
    while PROGRAM_RUNNING:
        update_threat_and_cage()
        time.sleep(2)

def start_monitor_thread():
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()

# ------------------------------------------------------------
#  Bootstrap
# ------------------------------------------------------------

def bootstrap_containment(mode: str | None = None):
    global PROGRAM_RUNNING
    PROGRAM_RUNNING = True

    scan_plugins()
    preload_plugin_dependencies()

    env = _detect_environment()
    _, state = _predict_groups(env, mode)
    print(f"[VCCA] Bootstrapping containment (requested_mode={mode}, chosen_state={state})...")
    predictive_preload(mode=mode)
    compliant = enforce_state(state)
    if not compliant:
        corrective_enforce(state)
    update_threat_and_cage()
    print("[VCCA] Containment cage lab ready.")

if __name__ == "__main__":
    start_gui_in_thread()
    start_monitor_thread()
    bootstrap_containment(mode=None)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        PROGRAM_RUNNING = False
        print("[VCCA] Shutting down.")
