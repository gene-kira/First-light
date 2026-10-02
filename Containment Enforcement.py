# ============================================================
#  Containment Enforcement Autoloader (CEAL.py)
#  Autonomous, predictive, policy-driven dependency governor
# ============================================================

import importlib
import subprocess
import sys
import time
import os
from types import ModuleType
from collections import defaultdict

# ------------------------------------------------------------
#  Global state
# ------------------------------------------------------------

CEAL_CACHE: dict[str, ModuleType] = {}

CEAL_USAGE = defaultdict(lambda: {
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

# Policy: which groups are REQUIRED for each mode
MODE_POLICY: dict[str, dict[str, list[str]]] = {
    "gpu_governor": {
        "required_groups": ["core", "gpu", "governor"],
    },
    "vision": {
        "required_groups": ["core", "vision", "gpu"],
    },
    "security": {
        "required_groups": ["core", "governor"],
    },
    "default": {
        "required_groups": ["core"],
    },
}

# ------------------------------------------------------------
#  Low-level install / import
# ------------------------------------------------------------

def _install(pkg: str):
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        print(f"[CEAL] Installed: {pkg}")
    except Exception as e:
        print(f"[CEAL] Failed to install {pkg}: {e}")

def _record_usage(pkg: str, context: str | None = None):
    info = CEAL_USAGE[pkg]
    info["count"] += 1
    info["last_used"] = time.time()
    if context:
        info["contexts"].add(context)

def _import(pkg: str, context: str | None = None) -> ModuleType:
    if pkg in CEAL_CACHE:
        _record_usage(pkg, context)
        return CEAL_CACHE[pkg]

    try:
        module = importlib.import_module(pkg)
    except ImportError:
        print(f"[CEAL] Missing: {pkg} → enforcing install...")
        _install(pkg)
        module = importlib.import_module(pkg)

    CEAL_CACHE[pkg] = module
    _record_usage(pkg, context)
    return module

# ------------------------------------------------------------
#  Public require API
# ------------------------------------------------------------

def require(pkg: str, context: str | None = None) -> ModuleType:
    """
    Enforced import of a single package with usage telemetry.
    """
    return _import(pkg, context)

def require_group(group: str, context: str | None = None) -> dict[str, ModuleType]:
    """
    Enforced import of a full dependency group.
    """
    if group not in DEPENDENCY_GROUPS:
        raise ValueError(f"[CEAL] Unknown dependency group: {group}")

    loaded: dict[str, ModuleType] = {}
    for pkg in DEPENDENCY_GROUPS[group]:
        loaded[pkg] = require(pkg, context=context or group)
    return loaded

# ------------------------------------------------------------
#  Environment + reasoning
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

def _score_group(group: str) -> float:
    """
    Simple scoring based on usage telemetry:
    - sum of counts for all packages in group
    - recent usage gets a small boost
    """
    score = 0.0
    now = time.time()
    for pkg in DEPENDENCY_GROUPS.get(group, []):
        info = CEAL_USAGE.get(pkg)
        if not info:
            continue
        score += info["count"]
        if info["last_used"]:
            age = now - info["last_used"]
            # recent usage → small bonus
            if age < 300:      # last 5 minutes
                score += 2.0
            elif age < 3600:   # last hour
                score += 1.0
    return score

def _predict_groups(env: dict, mode: str | None = None) -> list[str]:
    """
    Reasoning:
    - Start from policy-required groups for mode.
    - Add environment-driven hints (GPU, Windows).
    - Add high-score groups from usage telemetry.
    """
    mode_key = mode if mode in MODE_POLICY else "default"
    base_required = set(MODE_POLICY[mode_key]["required_groups"])

    predicted = set(base_required)

    # Environment hints
    if env.get("has_gpu"):
        predicted.add("gpu")
        predicted.add("vision")
    if env.get("is_windows"):
        predicted.add("governor")

    # Telemetry-driven hot groups
    scores = {g: _score_group(g) for g in DEPENDENCY_GROUPS.keys()}
    hot_groups = sorted(scores.keys(), key=lambda g: scores[g], reverse=True)

    # Take top 2 hot groups if they have non-zero score
    for g in hot_groups[:2]:
        if scores[g] > 0:
            predicted.add(g)

    return list(predicted)

# ------------------------------------------------------------
#  Predictive preload + enforcement
# ------------------------------------------------------------

def predictive_preload(mode: str | None = None):
    """
    Predict and preload groups based on:
    - mode policy
    - environment
    - usage telemetry
    """
    env = _detect_environment()
    groups = _predict_groups(env, mode)
    print(f"[CEAL] Predictive preload → groups={groups}, mode={mode}, env={env}")
    for g in groups:
        try:
            require_group(g, context=f"preload:{mode or 'auto'}")
        except Exception as e:
            print(f"[CEAL] Failed to preload group {g}: {e}")

def enforce_mode_compliance(mode: str | None = None) -> bool:
    """
    Police-style enforcement:
    - Check that all required groups for the mode are loaded.
    - Returns True if compliant, False otherwise.
    """
    mode_key = mode if mode in MODE_POLICY else "default"
    required_groups = MODE_POLICY[mode_key]["required_groups"]
    missing_groups = []

    for g in required_groups:
        for pkg in DEPENDENCY_GROUPS.get(g, []):
            if pkg not in CEAL_CACHE:
                missing_groups.append(g)
                break

    if missing_groups:
        print(f"[CEAL][ENFORCER] Non-compliant mode={mode_key}, missing groups={missing_groups}")
        return False

    print(f"[CEAL][ENFORCER] Mode={mode_key} compliant.")
    return True

# ------------------------------------------------------------
#  Introspection
# ------------------------------------------------------------

def ceal_status() -> dict:
    return {
        "loaded_modules": list(CEAL_CACHE.keys()),
        "usage": {
            pkg: {
                "count": info["count"],
                "last_used": info["last_used"],
                "contexts": list(info["contexts"]),
            }
            for pkg, info in CEAL_USAGE.items()
        },
        "groups": list(DEPENDENCY_GROUPS.keys()),
        "policies": MODE_POLICY,
    }

# ------------------------------------------------------------
#  Bootstrap entrypoint for containment bot
# ------------------------------------------------------------

def bootstrap_containment(mode: str | None = None):
    """
    High-level bootstrap:
    - Predictive preload for given mode.
    - Enforce policy compliance.
    """
    print(f"[CEAL] Bootstrapping containment bot (mode={mode})...")
    predictive_preload(mode=mode)
    compliant = enforce_mode_compliance(mode=mode)
    if not compliant:
        print("[CEAL] Attempting corrective preload...")
        # Force-load required groups from policy
        mode_key = mode if mode in MODE_POLICY else "default"
        for g in MODE_POLICY[mode_key]["required_groups"]:
            try:
                require_group(g, context=f"corrective:{mode_key}")
            except Exception as e:
                print(f"[CEAL] Corrective preload failed for group {g}: {e}")
        enforce_mode_compliance(mode=mode)
    print("[CEAL] Containment enforcement ready.")

if __name__ == "__main__":
    # Example: GPU governor containment mode
    bootstrap_containment(mode="gpu_governor")
