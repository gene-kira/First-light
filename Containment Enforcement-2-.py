# ============================================================
#  VARIABLE CONTAINMENT CAGE AUTLOADER + GUI (VCCA_GUI.py)
#  Resilient, predictive, state-driven, policy-enforced governor
#  with live status window
# ============================================================

import importlib
import subprocess
import sys
import time
import os
from types import ModuleType
from collections import defaultdict
import threading

# Simple GUI: Tkinter (standard library)
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

DEPENDENCY_GROUPS: dict[str, list[str]] = {
    "core": [
        "requests",
        "psutil",
        "pyyaml",
    ],
    "gpu": [
        "torch",
        "numpy",
        "cupy",
    ],
    "vision": [
        "opencv-python",
        "Pillow",
    ],
    "governor": [
        "pywin32",
        "wmi",
    ],
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

# ------------------------------------------------------------
#  Low-level install / import
# ------------------------------------------------------------

def _install(pkg: str):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        print(f"[VCCA] Installed: {pkg}")
    except Exception as e:
        print(f"[VCCA] Failed to install {pkg}: {e}")

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
        module = importlib.import_module(pkg)

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
#  Environment + scoring
# ------------------------------------------------------------

def _detect_environment() -> dict:
    env = {
        "has_gpu": False,
        "is_windows": os.name == "nt",
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
#  Variable cage logic
# ------------------------------------------------------------

def _strictness_level(state: str) -> int:
    return int(CONTAINMENT_STATES.get(state, CONTAINMENT_STATES["baseline"])["strictness"])

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
            print(f"[VCCA] Failed to preload group {g}: {e}")

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
            print(f"[VCCA] Corrective preload failed for group {g}: {e}")
    enforce_state(state)

def adaptive_cage_tightening():
    now = time.time()
    recent_new = 0
    for pkg, info in VCCA_USAGE.items():
        if info["last_used"] and now - info["last_used"] < 120 and info["count"] <= 2:
            recent_new += 1

    global CURRENT_STATE
    current_strict = _strictness_level(CURRENT_STATE)

    if recent_new >= 3 and current_strict < 3:
        if CURRENT_STATE == "baseline":
            CURRENT_STATE = "security_lock"
        elif CURRENT_STATE in ("vision_drift", "hyper_gpu"):
            CURRENT_STATE = "security_lock"
        print(f"[VCCA][CAGE] Tightened containment → state={CURRENT_STATE}")
    elif recent_new == 0 and current_strict > 1:
        CURRENT_STATE = "baseline"
        print(f"[VCCA][CAGE] Relaxed containment → state={CURRENT_STATE}")

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
    }

# ------------------------------------------------------------
#  GUI status window
# ------------------------------------------------------------

class VCCAGUI:
    def __init__(self):
        if tk is None:
            print("[VCCA][GUI] Tkinter not available, GUI disabled.")
            self.root = None
            return

        self.root = tk.Tk()
        self.root.title("Containment Cage Status")

        self.label_running = ttk.Label(self.root, text="Program: UNKNOWN")
        self.label_running.pack(padx=10, pady=5)

        self.label_state = ttk.Label(self.root, text="State: UNKNOWN")
        self.label_state.pack(padx=10, pady=5)

        self.label_strict = ttk.Label(self.root, text="Strictness: UNKNOWN")
        self.label_strict.pack(padx=10, pady=5)

        self.label_groups = ttk.Label(self.root, text="Loaded groups: -")
        self.label_groups.pack(padx=10, pady=5)

        self.root.after(500, self.refresh)

    def refresh(self):
        status = vcca_status()
        running_text = "RUNNING" if status["running"] else "STOPPED"
        self.label_running.config(text=f"Program: {running_text}")

        state = status["current_state"]
        self.label_state.config(text=f"State: {state}")

        strict = _strictness_level(state)
        self.label_strict.config(text=f"Strictness: {strict}")

        loaded_pkgs = status["loaded_modules"]
        loaded_groups = set()
        for g, pkgs in DEPENDENCY_GROUPS.items():
            if any(p in loaded_pkgs for p in pkgs):
                loaded_groups.add(g)
        self.label_groups.config(text=f"Loaded groups: {', '.join(sorted(loaded_groups)) or '-'}")

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
#  Bootstrap entrypoint
# ------------------------------------------------------------

def bootstrap_containment(mode: str | None = None):
    global PROGRAM_RUNNING
    PROGRAM_RUNNING = True

    env = _detect_environment()
    _, state = _predict_groups(env, mode)
    print(f"[VCCA] Bootstrapping containment (requested_mode={mode}, chosen_state={state})...")
    predictive_preload(mode=mode)
    compliant = enforce_state(state)
    if not compliant:
        corrective_enforce(state)
    adaptive_cage_tightening()
    print("[VCCA] Variable containment cage ready.")

if __name__ == "__main__":
    start_gui_in_thread()
    bootstrap_containment(mode=None)
    # Keep main thread alive so GUI stays up
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        PROGRAM_RUNNING = False
        print("[VCCA] Shutting down.")
