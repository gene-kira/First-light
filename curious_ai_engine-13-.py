#!/usr/bin/env python3
"""
Curious AI Command Center v3.7 – Comparator Engine + Enhanced Curiosity + Flexible Add-on System

Core idea:
- The "engine" (your system + your code) is never rewritten automatically.
- The Command Center analyzes, observes, and then BOLTS ON add-ons:
    - Predictive telemetry add-ons (CPU/RAM/GPU trend + anomaly hints)
    - Code add-ons (helper blocks you can call, remove, or ignore)
    - Plugin add-ons (optional modules that extend behavior)
    - Universal multi-language add-ons (suggested tweaks for any codebase)
- All add-ons are reversible, non-destructive, and clearly marked.

New in v3.7:
- Comparator Engine (structural, non-executing):
    - Compares two static analysis snapshots (baseline vs current).
    - Highlights changes in functions, classes, branches, and TODO/issue counts.
    - Acts like a “shadow comparator” for code structure, not runtime.
- Enhanced Sherlock-style Curiosity Engine:
    - Uses trend + anomaly signals from telemetry history.
    - Mixes structural changes (comparator) with system load to suggest “what if” experiments.
- Flexible Universal Auto Add-on Engine:
    - Tags add-ons with categories (performance, memory, GPU, structure, game-loop).
    - Avoids duplicates more intelligently.
    - Still non-destructive and opt-in only.
- Code Lab comparator workflow:
    - You can set a baseline snapshot.
    - Later analyses are compared against that baseline and summarized.

Features:
- Multi-tab Tkinter GUI (Dashboard, Code Lab, Processes, Network, Plugins, Add-ons, Settings)
- Rotating logs, JSON config, history buffer, predictive engine
- Optional psutil + NVML telemetry (CPU/RAM/Disk/GPU)
- Live process and network snapshots
- AST-based Python static analysis (no execution of analyzed code)
- Conservative cleanup (tabs/whitespace/newlines)
- Drag-and-drop style zone (click-to-open) for .py files
- Plugin system:
    - Safe metadata listing
    - Full-power optional execution of plugin hooks (describe(), run())
- Auto-monitoring loop with profiles (Light / Balanced / Detailed)
- AI “thought bubble” status + event timeline
- Auto script generator (monitor scripts as text; not auto-executed)
- Persistent settings (auto-monitor, interval, profile, window geometry)
- Code Lab turbo add-ons:
    - Builds helper functions based on analysis (summary, hints)
    - Appends them as a bolt-on block (manual turbo)
    - Undo last add-on at any time
- Universal Auto Add-on Engine:
    - Automatically proposes add-ons based on analysis + telemetry
    - Adds them to the Add-ons tab (AUTO origin)
    - You can apply/uninstall them from the source

This is your system-wide turbocharger: it watches, predicts, compares, and adds helpers,
without rewriting the core engine.
"""

from __future__ import annotations

import ast
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import queue
import re
import socket
import sys
import threading
import time
import traceback
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from pathlib import Path
from collections import deque
from datetime import datetime
import importlib.util
import random
import statistics

APP_NAME = "Curious AI Command Center"
APP_VERSION = "3.7"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_PATH = BASE_DIR / "curious_ai_config.json"
LOG_PATH = BASE_DIR / "curious_ai.log"
PLUGIN_DIR = BASE_DIR / "plugins"
HISTORY_LIMIT = 600

# Optional dependencies
try:
    import psutil  # type: ignore
except Exception:
    psutil = None

try:
    import pynvml  # type: ignore
except Exception:
    pynvml = None


# -------------------------------------------------------------------
# Logging + Config
# -------------------------------------------------------------------

def setup_logging() -> logging.Logger:
    logger = logging.getLogger("curious_ai")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = RotatingFileHandler(
            LOG_PATH,
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(message)s"))
        logger.addHandler(handler)
    return logger


LOG = setup_logging()


def load_config() -> dict:
    defaults = {
        "sample_interval": 3,
        "profile": "Balanced",  # Light / Balanced / Detailed
        "history_limit": HISTORY_LIMIT,
        "temperature_warning_c": 82,
        "auto_monitor": False,
        "window_geometry": "1180x760",
        "auto_addons_enabled": True,
    }
    try:
        if CONFIG_PATH.exists():
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(data, dict):
                defaults.update({k: v for k, v in data.items() if k in defaults})
    except Exception:
        LOG.exception("Could not read config; using defaults")
    try:
        defaults["sample_interval"] = max(1, min(60, int(defaults["sample_interval"])))
    except Exception:
        defaults["sample_interval"] = 3
    return defaults


def save_config(config: dict) -> None:
    temp = CONFIG_PATH.with_suffix(".tmp")
    temp.write_text(json.dumps(config, indent=2), encoding="utf-8")
    temp.replace(CONFIG_PATH)


# -------------------------------------------------------------------
# Utility formatting
# -------------------------------------------------------------------

def fmt_bytes(value: int | float | None) -> str:
    if value is None:
        return "N/A"
    size = float(value)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.1f} {unit}"
        size /= 1024
    return f"{size:.1f} TB"


# -------------------------------------------------------------------
# Telemetry snapshots
# -------------------------------------------------------------------

def cpu_memory_snapshot() -> dict:
    if psutil is None:
        return {
            "cpu_percent": None,
            "memory_percent": None,
            "memory_used": None,
            "memory_total": None,
            "disk_percent": None,
            "disk_used": None,
            "disk_total": None,
        }
    try:
        vm = psutil.virtual_memory()
        disk = psutil.disk_usage(os.path.abspath(os.sep))
        return {
            "cpu_percent": psutil.cpu_percent(interval=None),
            "memory_percent": vm.percent,
            "memory_used": vm.used,
            "memory_total": vm.total,
            "disk_percent": disk.percent,
            "disk_used": disk.used,
            "disk_total": disk.total,
        }
    except Exception:
        LOG.exception("System telemetry sample failed")
        return {
            "cpu_percent": None,
            "memory_percent": None,
            "memory_used": None,
            "memory_total": None,
            "disk_percent": None,
            "disk_used": None,
            "disk_total": None,
        }


def gpu_snapshot() -> dict:
    result = {
        "name": "Unavailable",
        "temperature": None,
        "gpu_percent": None,
        "memory_used": None,
        "memory_total": None,
        "memory_percent": None,
        "note": "GPU telemetry unavailable",
    }
    if pynvml is None:
        result["note"] = "Optional package nvidia-ml-py not installed, or NVIDIA GPU not available"
        return result
    initialized = False
    try:
        pynvml.nvmlInit()
        initialized = True
        count = pynvml.nvmlDeviceGetCount()
        if count < 1:
            result["note"] = "No NVIDIA GPU found"
            return result
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        name = pynvml.nvmlDeviceGetName(handle)
        if isinstance(name, bytes):
            name = name.decode(errors="replace")
        result["name"] = str(name)
        try:
            result["temperature"] = pynvml.nvmlDeviceGetTemperature(
                handle, pynvml.NVML_TEMPERATURE_GPU
            )
        except Exception:
            pass
        try:
            result["gpu_percent"] = pynvml.nvmlDeviceGetUtilizationRates(handle).gpu
        except Exception:
            pass
        try:
            mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
            result["memory_used"], result["memory_total"] = int(mem.used), int(mem.total)
            result["memory_percent"] = (
                round(mem.used * 100 / mem.total, 1) if mem.total else None
            )
        except Exception:
            pass
        result["note"] = "NVIDIA telemetry active"
        return result
    except Exception as exc:
        result["note"] = f"GPU telemetry not available: {exc}"
        return result
    finally:
        if initialized:
            try:
                pynvml.nvmlShutdown()
            except Exception:
                pass


def process_snapshot(limit: int = 50) -> list[dict]:
    if psutil is None:
        return []
    rows = []
    try:
        for proc in psutil.process_iter(
            attrs=["pid", "name", "cpu_percent", "memory_info", "status"]
        ):
            try:
                info = proc.info
                mem = info.get("memory_info")
                rows.append(
                    {
                        "pid": info.get("pid"),
                        "name": info.get("name") or "?",
                        "cpu": float(info.get("cpu_percent") or 0),
                        "memory": int(mem.rss) if mem else 0,
                        "status": info.get("status") or "?",
                    }
                )
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        rows.sort(key=lambda x: (x["cpu"], x["memory"]), reverse=True)
    except Exception:
        LOG.exception("Process snapshot failed")
    return rows[:limit]


def connection_snapshot(limit: int = 80) -> list[dict]:
    if psutil is None:
        return []
    rows = []
    try:
        for c in psutil.net_connections(kind="inet"):
            local = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            remote = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            rows.append(
                {
                    "status": c.status or "-",
                    "local": local,
                    "remote": remote,
                    "pid": c.pid if c.pid is not None else "?",
                    "type": "TCP" if c.type == socket.SOCK_STREAM else "UDP",
                }
            )
        rows.sort(key=lambda x: (x["status"], x["local"]))
    except Exception as exc:
        LOG.info("Network connection snapshot unavailable: %s", exc)
    return rows[:limit]


# -------------------------------------------------------------------
# Code analysis + cleanup
# -------------------------------------------------------------------

class CodeAnalyzer:
    """Static analysis only: parses Python but never imports or executes it."""

    def analyze(self, source: str, filename: str = "<memory>") -> dict:
        lines = source.splitlines()
        report = {
            "filename": filename,
            "lines": len(lines),
            "characters": len(source),
            "functions": 0,
            "async_functions": 0,
            "classes": 0,
            "imports": 0,
            "branches": 0,
            "todos": [],
            "issues": [],
            "summary": [],
            "game_like_functions": [],
        }
        for i, line in enumerate(lines, 1):
            if re.search(r"\b(TODO|FIXME|XXX)\b", line, re.I):
                report["todos"].append(f"Line {i}: {line.strip()[:180]}")
            if len(line) > 120 and line.strip():
                report["issues"].append(
                    f"Line {i}: long line ({len(line)} characters). Consider wrapping it."
                )
            if line.rstrip("\r\n").endswith((" ", "\t")):
                report["issues"].append(f"Line {i}: trailing whitespace.")
        try:
            tree = ast.parse(source, filename=filename)
        except SyntaxError as exc:
            report["syntax_ok"] = False
            report["issues"].insert(
                0,
                f"Syntax error at line {exc.lineno}, column {exc.offset}: {exc.msg}",
            )
            report["summary"].append(
                "Python could not parse this file. Fix the syntax error before running it."
            )
            return report
        report["syntax_ok"] = True
        game_keywords = {"update", "tick", "frame", "loop", "render"}
        for node in ast.walk(tree):
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = node.name
                report["functions"] += isinstance(node, ast.FunctionDef)
                report["async_functions"] += isinstance(node, ast.AsyncFunctionDef)
                args_count = len(node.args.args) + len(node.args.kwonlyargs)
                if args_count >= 8:
                    report["issues"].append(
                        f"Line {node.lineno}: {name} has {args_count} parameters; consider grouping related options."
                    )
                if len(node.body) >= 60:
                    report["issues"].append(
                        f"Line {node.lineno}: {name} has a large body ({len(node.body)} top-level statements). Consider splitting it."
                    )
                if any(k in name.lower() for k in game_keywords):
                    report["game_like_functions"].append(
                        f"Line {node.lineno}: {name} looks like a game/update loop."
                    )
            elif isinstance(node, ast.ClassDef):
                report["classes"] += 1
            elif isinstance(node, (ast.Import, ast.ImportFrom)):
                report["imports"] += 1
            elif isinstance(node, (ast.If, ast.For, ast.AsyncFor, ast.While, ast.Try, ast.With, ast.Match)):
                report["branches"] += 1
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in {
                "eval",
                "exec",
            }:
                report["issues"].append(
                    f"Line {getattr(node, 'lineno', '?')}: dynamic {node.func.id}() call; review carefully if input can be untrusted."
                )
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "shell":
                report["issues"].append(
                    f"Line {getattr(node, 'lineno', '?')}: shell-related call; verify command arguments and trust boundaries."
                )
        report["summary"].append(
            f"Parsed {report['lines']} lines: {report['functions']} functions, "
            f"{report['async_functions']} async functions, {report['classes']} classes, "
            f"{report['imports']} import statements."
        )
        report["summary"].append(
            f"Found {len(report['issues'])} review item(s) and {len(report['todos'])} TODO/FIXME marker(s). "
            "These are heuristics, not proof of a defect or security issue."
        )
        if report["game_like_functions"]:
            report["summary"].append(
                f"Detected {len(report['game_like_functions'])} game-like loop function(s); timing hints may be useful."
            )
        if not report["issues"]:
            report["summary"].append(
                "No issues were found by the current lightweight checks; this does not guarantee correctness or safety."
            )
        return report


def conservative_cleanup(source: str) -> str:
    lines = source.replace("\r\n", "\n").replace("\r", "\n").split("\n")
    return (
        "\n".join(line.replace("\t", "    ").rstrip() for line in lines).rstrip("\n")
        + "\n"
    )


# -------------------------------------------------------------------
# Plugin system
# -------------------------------------------------------------------

def plugin_metadata_only() -> list[str]:
    PLUGIN_DIR.mkdir(exist_ok=True)
    items = []
    for path in sorted(PLUGIN_DIR.glob("*.py")):
        try:
            size = path.stat().st_size
            items.append(
                f"{path.name} — {size:,} bytes — metadata-only listing (safe mode)"
            )
        except OSError as exc:
            items.append(f"{path.name} — unable to inspect: {exc}")
    return items


def load_plugins_full() -> list[dict]:
    PLUGIN_DIR.mkdir(exist_ok=True)
    results: list[dict] = []
    for path in sorted(PLUGIN_DIR.glob("*.py")):
        entry = {"name": path.name, "describe": None, "run_result": None, "error": None}
        try:
            spec = importlib.util.spec_from_file_location(path.stem, path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "describe") and callable(mod.describe):
                    try:
                        entry["describe"] = str(mod.describe())
                    except Exception as e:
                        entry["error"] = f"describe() failed: {e}"
                if hasattr(mod, "run") and callable(mod.run):
                    try:
                        ctx = {"time": time.time(), "app": APP_NAME, "version": APP_VERSION}
                        entry["run_result"] = mod.run(ctx)
                    except Exception as e:
                        entry["error"] = f"run() failed: {e}"
        except Exception as e:
            entry["error"] = f"load error: {e}"
        results.append(entry)
    return results


# -------------------------------------------------------------------
# Predictive helpers
# -------------------------------------------------------------------

def compute_trend(values: list[float]) -> str:
    if len(values) < 4:
        return "Trend: insufficient data."
    try:
        mean = statistics.mean(values)
        stdev = statistics.pstdev(values)
        delta = values[-1] - values[0]
    except Exception:
        return "Trend: unable to compute."
    if abs(delta) < 3 and stdev < 5:
        return f"Trend: stable (mean {mean:.1f}, Δ{delta:.1f}, σ{stdev:.1f})."
    if delta > 5 and values[-1] > mean + stdev:
        return f"Trend: rising (mean {mean:.1f}, Δ{delta:.1f}, σ{stdev:.1f})."
    if stdev > 10:
        return f"Trend: volatile (mean {mean:.1f}, Δ{delta:.1f}, σ{stdev:.1f})."
    return f"Trend: mixed (mean {mean:.1f}, Δ{delta:.1f}, σ{stdev:.1f})."


def estimate_future(values: list[float], steps: int = 3) -> float | None:
    if len(values) < 3:
        return None
    try:
        slope = (values[-1] - values[0]) / (len(values) - 1)
        return values[-1] + slope * steps
    except Exception:
        return None


def anomaly_score(values: list[float]) -> str:
    if len(values) < 5:
        return "Anomaly: baseline building."
    try:
        mean = statistics.mean(values)
        stdev = statistics.pstdev(values)
        last = values[-1]
    except Exception:
        return "Anomaly: unable to compute."
    if stdev == 0:
        return "Anomaly: flat pattern."
    z = (last - mean) / (stdev or 1e-6)
    if z > 2.5:
        return f"Anomaly: high spike (z={z:.2f})."
    if z < -2.5:
        return f"Anomaly: sudden drop (z={z:.2f})."
    return f"Anomaly: normal range (z={z:.2f})."


# -------------------------------------------------------------------
# Comparator Engine (structural, non-executing)
# -------------------------------------------------------------------

class ComparatorEngine:
    """
    Compares two static analysis reports (baseline vs current).

    It does NOT execute code or measure runtime.
    It only compares structural metrics and counts.
    """

    def compare(self, baseline: dict, current: dict) -> list[str]:
        lines = ["COMPARATOR VS BASELINE", "=======================", ""]
        def diff(label: str, key: str):
            b = baseline.get(key, 0)
            c = current.get(key, 0)
            delta = c - b
            lines.append(f"{label}: baseline {b}, current {c}, Δ{delta}")
        diff("Lines", "lines")
        diff("Characters", "characters")
        diff("Functions", "functions")
        diff("Async functions", "async_functions")
        diff("Classes", "classes")
        diff("Imports", "imports")
        diff("Branches", "branches")
        diff("TODO/FIXME markers", "todos_count")
        diff("Issues (heuristics)", "issues_count")
        gl_b = len(baseline.get("game_like_functions", []))
        gl_c = len(current.get("game_like_functions", []))
        lines.append(f"Game-like loop hints: baseline {gl_b}, current {gl_c}, Δ{gl_c - gl_b}")
        lines.append("")
        lines.append("Note: comparator is structural only; it does not measure runtime or correctness.")
        return lines


# -------------------------------------------------------------------
# Curiosity Engine (Sherlock-style thought process)
# -------------------------------------------------------------------

class CuriosityEngine:
    """
    Generates narrative “thoughts” about possible optimizations.

    It does NOT execute experiments or change system behavior.
    It only produces text suggestions based on telemetry + history + code analysis.
    """

    def think(self, telemetry: dict, history: deque, report: dict | None) -> str:
        cpu = telemetry.get("cpu_percent")
        ram = telemetry.get("memory_percent")
        gpu_temp = telemetry.get("gpu_temp")
        gpu_util = telemetry.get("gpu_percent")

        candidates = []

        if cpu is not None and cpu > 70:
            candidates.append(
                "Observation: CPU is running hot. I wonder if batching tasks or trimming background loops could shave off latency."
            )
        if ram is not None and ram > 75:
            candidates.append(
                "Observation: RAM pressure is elevated. Perhaps streaming large assets instead of loading them all at once would help."
            )
        if gpu_temp is not None and gpu_temp > 80:
            candidates.append(
                "Observation: GPU temperature is high. A gentler frame pacing or reduced effect density might keep things smoother."
            )
        if gpu_util is not None and gpu_util > 85:
            candidates.append(
                "Observation: GPU utilization is intense. Maybe there is a render path that could be simplified or cached."
            )

        # History-based anomaly curiosity
        if history:
            ram_vals = [
                s.get("memory_percent")
                for s in history
                if s.get("memory_percent") is not None
            ]
            cpu_vals = [
                s.get("cpu_percent")
                for s in history
                if s.get("cpu_percent") is not None
            ]
            if ram_vals and len(ram_vals) >= 5:
                candidates.append(
                    f"Curiosity: RAM anomaly status – {anomaly_score(ram_vals)}"
                )
            if cpu_vals and len(cpu_vals) >= 5:
                candidates.append(
                    f"Curiosity: CPU anomaly status – {anomaly_score(cpu_vals)}"
                )

        if report is not None:
            if report.get("game_like_functions"):
                candidates.append(
                    "Curiosity: I see game-like update loops. I’m wondering if input handling and rendering could be decoupled for tighter timing."
                )
            if report.get("issues"):
                candidates.append(
                    "Curiosity: There are long functions and many parameters. Splitting responsibilities might open up faster shortcuts."
                )
            if report.get("todos"):
                candidates.append(
                    "Note: There are TODO/FIXME markers. Resolving them might unlock hidden performance improvements."
                )

        if not candidates:
            return "Idle curiosity: I’m watching the system quietly, waiting for a pattern worth investigating."

        return random.choice(candidates)


# -------------------------------------------------------------------
# Universal Auto Add-on Engine
# -------------------------------------------------------------------

class UniversalAddonEngine:
    """
    Universal multi-language add-on engine.

    It:
    - Watches telemetry + static analysis.
    - Proposes helper blocks (Python) and multi-language hints (comments).
    - Populates the Add-ons tab automatically (origin='AUTO').
    - Does not modify the source unless you apply the add-on.
    """

    def __init__(self):
        self.last_auto_id = 0

    def _next_id(self, base_counter: int) -> int:
        self.last_auto_id = max(self.last_auto_id + 1, base_counter + 1)
        return self.last_auto_id

    def _categorize_hint(self, hint: str) -> str:
        h = hint.lower()
        if "cpu" in h or "polling" in h or "async" in h:
            return "performance"
        if "ram" in h or "memory" in h or "streaming" in h or "generators" in h:
            return "memory"
        if "gpu" in h or "shader" in h or "vram" in h or "thermal" in h:
            return "gpu"
        if "refactor" in h or "functions" in h or "parameters" in h:
            return "structure"
        if "game-like" in h or "frame" in h or "rendering" in h or "loop" in h:
            return "game-loop"
        return "general"

    def generate_auto_addons(
        self,
        source: str,
        report: dict | None,
        telemetry: dict,
        base_counter: int,
    ) -> list[dict]:
        if not source.strip():
            return []
        if report is None:
            report = {
                "functions": 0,
                "classes": 0,
                "todos": [],
                "issues": [],
                "lines": len(source.splitlines()),
                "game_like_functions": [],
            }

        cpu = telemetry.get("cpu_percent")
        ram = telemetry.get("memory_percent")
        gpu_temp = telemetry.get("gpu_temp")
        gpu_util = telemetry.get("gpu_percent")

        hints: list[str] = []

        if cpu is not None and cpu > 70:
            hints.append(
                "High CPU usage detected; consider batching I/O, reducing polling, or using async for network calls."
            )
        if ram is not None and ram > 75:
            hints.append(
                "Elevated RAM usage; consider streaming large data, freeing caches, or using generators."
            )
        if gpu_temp is not None and gpu_temp > 80:
            hints.append(
                "GPU temperature is high; consider reducing workload intensity or adding throttling in GPU-heavy paths."
            )
        if gpu_util is not None and gpu_util > 85:
            hints.append(
                "GPU utilization is high; consider spreading work over time or optimizing shader/kernel hot paths."
            )

        if report.get("issues"):
            hints.append(
                "Static analysis found review items; consider refactoring long functions and reducing parameter count."
            )
        if report.get("todos"):
            hints.append(
                "There are TODO/FIXME markers; prioritizing them may stabilize behavior and performance."
            )
        if report.get("game_like_functions"):
            hints.append(
                "Game-like loops detected; consider separating input, simulation, and rendering for smoother frame pacing."
            )

        if not hints:
            return []

        auto_addons: list[dict] = []
        for hint in hints:
            addon_id = self._next_id(base_counter)
            ts = datetime.now().strftime("%H:%M:%S")
            category = self._categorize_hint(hint)
            header = (
                f"# --- Curious AI Universal Auto Add-on #{addon_id} (analysis-driven helper, non-destructive, category={category}) ---"
            )
            block_lines = [
                "",
                header,
                "# Origin: AUTO (generated by Universal Add-on Engine).",
                "# This block is a suggestion based on telemetry + static analysis.",
                "# It is safe to remove. It does not execute automatically.",
                "",
                "def curious_ai_auto_hint():",
                f"    \"\"\"Universal optimization hint ({category}): {hint}\"\"\"",
                "    return {",
                f"        'hint': " + repr(hint) + ",",
                f"        'category': " + repr(category) + ",",
                f"        'lines': {report.get('lines', 0)},",
                f"        'functions': {report.get('functions', 0)},",
                f"        'classes': {report.get('classes', 0)},",
                "    }",
                "",
                "# Multi-language note:",
                "# - This hint applies to Python, C/C++, C#, Java, JS, and other languages.",
                "# - You can adapt the idea (batching, async, streaming, throttling, loop separation) to your own stack.",
                "",
                f"# --- End of Curious AI Universal Auto Add-on #{addon_id} ---",
                "",
            ]
            block = "\n".join(block_lines)
            auto_addons.append(
                {
                    "id": addon_id,
                    "timestamp": ts,
                    "summary": f"[{category}] {hint[:120]}",
                    "block": block,
                    "origin": "AUTO",
                    "category": category,
                }
            )
        return auto_addons


# -------------------------------------------------------------------
# Command Center core
# -------------------------------------------------------------------

class CommandCenter:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.config = load_config()
        self.analyzer = CodeAnalyzer()
        self.addon_engine = UniversalAddonEngine()
        self.curiosity_engine = CuriosityEngine()
        self.comparator = ComparatorEngine()

        # Code lab state
        self.source_path: Path | None = None
        self.source_text = ""
        self.report: dict | None = None
        self.baseline_report: dict | None = None

        # Add-on state
        self.addon_history: list[dict] = []
        self.addon_counter: int = 0

        # Telemetry state
        self.latest_cpu: dict = {}
        self.latest_gpu: dict = {}
        self.history = deque(
            maxlen=int(self.config.get("history_limit", HISTORY_LIMIT))
        )

        # Auto-monitoring
        self.stop_event = threading.Event()
        self.worker: threading.Thread | None = None
        self.ui_queue: queue.Queue = queue.Queue()

        # UI state
        self.auto_var = tk.BooleanVar(
            value=bool(self.config.get("auto_monitor", False))
        )
        self.interval_var = tk.StringVar(
            value=str(self.config.get("sample_interval", 3))
        )
        self.profile_var = tk.StringVar(
            value=str(self.config.get("profile", "Balanced"))
        )
        self.auto_addons_var = tk.BooleanVar(
            value=bool(self.config.get("auto_addons_enabled", True))
        )
        self.status_var = tk.StringVar(value="Ready")
        self.cpu_var = tk.StringVar(value="CPU: —")
        self.mem_var = tk.StringVar(value="RAM: —")
        self.gpu_var = tk.StringVar(value="GPU: checking…")
        self.prediction_var = tk.StringVar(
            value="Prediction: collecting baseline…"
        )
        self.thought_var = tk.StringVar(value="Idle.")
        self.timeline = deque(maxlen=200)
        self.generated_scripts: list[str] = []
        self.plugins_full: list[dict] = []

        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.root.after(300, self._drain_queue)
        self.root.after(700, self.refresh_once)

        if self.auto_var.get():
            self.start_monitoring()

    # -------------------------------------------------------------------
    # UI construction
    # -------------------------------------------------------------------

    def _build_ui(self):
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry(self.config.get("window_geometry", "1180x760"))
        self.root.minsize(900, 580)

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=10, pady=(0, 8))

        self.dashboard_tab = ttk.Frame(self.tabs, padding=8)
        self.code_tab = ttk.Frame(self.tabs, padding=8)
        self.process_tab = ttk.Frame(self.tabs, padding=8)
        self.network_tab = ttk.Frame(self.tabs, padding=8)
        self.plugins_tab = ttk.Frame(self.tabs, padding=8)
        self.addons_tab = ttk.Frame(self.tabs, padding=8)
        self.settings_tab = ttk.Frame(self.tabs, padding=8)

        for frame, title in [
            (self.dashboard_tab, "Dashboard"),
            (self.code_tab, "Code Lab"),
            (self.process_tab, "Processes"),
            (self.network_tab, "Network"),
            (self.plugins_tab, "Plugins"),
            (self.addons_tab, "Add-ons"),
            (self.settings_tab, "Settings"),
        ]:
            self.tabs.add(frame, text=title)

        self._build_dashboard()
        self._build_code()
        self._build_processes()
        self._build_network()
        self._build_plugins()
        self._build_addons()
        self._build_settings()

        ttk.Label(
            self.root,
            text=(
                "Full-power turbo mode: plugins may be loaded and run. "
                "Analyzed code is not executed automatically. "
                "System changes (kill processes, settings) are not performed."
            ),
            padding=(10, 4),
        ).pack(fill="x")

    def _text_panel(self, parent, height=12):
        frame = ttk.Frame(parent)
        text = tk.Text(
            frame,
            wrap="word",
            height=height,
            undo=True,
            font=("Consolas", 9),
        )
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        return frame, text

    # -------------------------------------------------------------------
    # Dashboard
    # -------------------------------------------------------------------

    def _build_dashboard(self):
        toolbar = ttk.Frame(self.dashboard_tab)
        toolbar.pack(fill="x", pady=(0, 8))
        ttk.Button(toolbar, text="Refresh now", command=self.refresh_once).pack(
            side="left", padx=(0, 5)
        )
        ttk.Button(toolbar, text="Start monitoring", command=self.start_monitoring).pack(
            side="left", padx=5
        )
        ttk.Button(toolbar, text="Stop monitoring", command=self.stop_monitoring).pack(
            side="left", padx=5
        )
        ttk.Button(toolbar, text="Export snapshot…", command=self.export_snapshot).pack(
            side="left", padx=5
        )

        self.dashboard_frame, self.dashboard_text = self._text_panel(
            self.dashboard_tab, 22
        )
        self.dashboard_frame.pack(fill="both", expand=True)

        timeline_frame, self.timeline_box = self._text_panel(
            self.dashboard_tab, 10
        )
        ttk.Label(self.dashboard_tab, text="Event Timeline").pack(anchor="w")
        timeline_frame.pack(fill="both", expand=True)

    # -------------------------------------------------------------------
    # Code Lab
    # -------------------------------------------------------------------

    def _build_code(self):
        bar = ttk.Frame(self.code_tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Open Python file…", command=self.open_code).pack(
            side="left", padx=(0, 5)
        )
        ttk.Button(bar, text="Analyze", command=self.analyze_code).pack(
            side="left", padx=5
        )
        ttk.Button(bar, text="Set baseline for comparator", command=self.set_baseline).pack(
            side="left", padx=5
        )
        ttk.Button(bar, text="Preview cleanup", command=self.preview_cleanup).pack(
            side="left", padx=5
        )
        ttk.Button(bar, text="Save improved copy…", command=self.save_clean_copy).pack(
            side="left", padx=5
        )
        ttk.Button(bar, text="Build turbo add-on (manual)", command=self.build_addon).pack(
            side="left", padx=5
        )
        ttk.Button(bar, text="Undo last add-on", command=self.undo_addon).pack(
            side="left", padx=5
        )

        self.code_split = ttk.Panedwindow(self.code_tab, orient="horizontal")
        self.code_split.pack(fill="both", expand=True)

        left = ttk.Frame(self.code_split)
        right = ttk.Frame(self.code_split)
        self.code_split.add(left, weight=3)
        self.code_split.add(right, weight=2)

        ttk.Label(left, text="Drag & Drop Zone (.py)").pack(anchor="w")
        self.drop_zone = tk.Label(
            left,
            text="Drag a .py file here\n(or click to select)",
            relief="ridge",
            borderwidth=2,
            width=40,
            height=4,
            bg="#222222",
            fg="#dddddd",
        )
        self.drop_zone.pack(fill="x", pady=6)
        self.drop_zone.bind("<Button-1>", self.manual_drop_open)

        ttk.Label(left, text="Source code (static analysis only)").pack(anchor="w")
        f, self.source_box = self._text_panel(left, 18)
        f.pack(fill="both", expand=True)

        ttk.Label(right, text="Analysis / cleanup / add-on preview").pack(anchor="w")
        f, self.report_box = self._text_panel(right, 22)
        f.pack(fill="both", expand=True)

    # -------------------------------------------------------------------
    # Processes
    # -------------------------------------------------------------------

    def _build_processes(self):
        bar = ttk.Frame(self.process_tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Refresh processes", command=self.refresh_processes).pack(
            side="left"
        )
        ttk.Label(
            bar,
            text="Process metadata only; no kill/modify actions.",
        ).pack(side="left", padx=12)

        columns = ("pid", "name", "cpu", "memory", "status")
        self.proc_tree = ttk.Treeview(
            self.process_tab, columns=columns, show="headings", height=22
        )
        for col, title, width in [
            ("pid", "PID", 80),
            ("name", "Name", 220),
            ("cpu", "CPU %", 80),
            ("memory", "Memory", 140),
            ("status", "Status", 130),
        ]:
            self.proc_tree.heading(col, text=title)
            self.proc_tree.column(col, width=width, anchor="w")
        self.proc_tree.pack(fill="both", expand=True)

    # -------------------------------------------------------------------
    # Network
    # -------------------------------------------------------------------

    def _build_network(self):
        bar = ttk.Frame(self.network_tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Refresh connections", command=self.refresh_connections).pack(
            side="left"
        )
        ttk.Label(
            bar,
            text="Connection metadata only; visibility may require elevated permissions.",
        ).pack(side="left", padx=12)

        columns = ("status", "type", "local", "remote", "pid")
        self.net_tree = ttk.Treeview(
            self.network_tab, columns=columns, show="headings", height=22
        )
        for col, title, width in [
            ("status", "State", 110),
            ("type", "Type", 70),
            ("local", "Local address", 240),
            ("remote", "Remote address", 240),
            ("pid", "PID", 80),
        ]:
            self.net_tree.heading(col, text=title)
            self.net_tree.column(col, width=width, anchor="w")
        self.net_tree.pack(fill="both", expand=True)

    # -------------------------------------------------------------------
    # Plugins
    # -------------------------------------------------------------------

    def _build_plugins(self):
        bar = ttk.Frame(self.plugins_tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Refresh plugin list (safe)", command=self.refresh_plugins_safe).pack(
            side="left"
        )
        ttk.Button(bar, text="Run plugins (full-power)", command=self.refresh_plugins_full).pack(
            side="left", padx=6
        )
        ttk.Button(bar, text="Open plugins folder", command=self.open_plugins_folder).pack(
            side="left", padx=6
        )

        ttk.Label(
            self.plugins_tab,
            text=(
                "Safe mode lists plugins by filename only. "
                "Full-power mode loads plugins and calls optional describe()/run() hooks."
            ),
            wraplength=800,
        ).pack(anchor="w", pady=(0, 6))

        f, self.plugins_box = self._text_panel(self.plugins_tab, 20)
        f.pack(fill="both", expand=True)

        self.refresh_plugins_safe()

    # -------------------------------------------------------------------
    # Add-ons tab
    # -------------------------------------------------------------------

    def _build_addons(self):
        bar = ttk.Frame(self.addons_tab)
        bar.pack(fill="x", pady=(0, 6))
        ttk.Button(bar, text="Refresh add-ons list", command=self.refresh_addons_list).pack(
            side="left", padx=(0, 5)
        )
        ttk.Button(bar, text="Apply selected add-on to source", command=self.apply_selected_addon).pack(
            side="left", padx=5
        )
        ttk.Button(bar, text="Uninstall selected add-on", command=self.remove_selected_addon).pack(
            side="left", padx=5
        )

        ttk.Label(
            bar,
            text=(
                "This tab shows turbo add-ons generated for the current code session.\n"
                "Origin 'MANUAL' = you clicked Build turbo add-on.\n"
                "Origin 'AUTO'   = Universal Add-on Engine suggested it.\n"
                "Applying an add-on appends its block to the source panel only."
            ),
            justify="left",
        ).pack(side="left", padx=12)

        columns = ("id", "time", "origin", "summary")
        self.addons_tree = ttk.Treeview(
            self.addons_tab, columns=columns, show="headings", height=20
        )
        for col, title, width in [
            ("id", "ID", 60),
            ("time", "Created at", 140),
            ("origin", "Origin", 90),
            ("summary", "Summary", 430),
        ]:
            self.addons_tree.heading(col, text=title)
            self.addons_tree.column(col, width=width, anchor="w")
        self.addons_tree.pack(fill="both", expand=True, pady=(6, 0))

        f, self.addons_detail_box = self._text_panel(self.addons_tab, 10)
        ttk.Label(self.addons_tab, text="Selected add-on block preview").pack(anchor="w")
        f.pack(fill="both", expand=True)

        self.addons_tree.bind("<<TreeviewSelect>>", self._on_addon_select)

    # -------------------------------------------------------------------
    # Settings
    # -------------------------------------------------------------------

    def _build_settings(self):
        body = ttk.Frame(self.settings_tab)
        body.pack(anchor="nw", fill="x")

        ttk.Label(body, text="Sampling interval (seconds, 1–60):").grid(
            row=0, column=0, sticky="w", padx=5, pady=8
        )
        ttk.Entry(body, textvariable=self.interval_var, width=8).grid(
            row=0, column=1, sticky="w", padx=5, pady=8
        )

        ttk.Label(body, text="Monitoring profile:").grid(
            row=1, column=0, sticky="w", padx=5, pady=8
        )
        ttk.Combobox(
            body,
            textvariable=self.profile_var,
            values=("Light", "Balanced", "Detailed"),
            state="readonly",
            width=15,
        ).grid(row=1, column=1, sticky="w", padx=5, pady=8)

        ttk.Checkbutton(
            body,
            text="Start monitoring when the app opens",
            variable=self.auto_var,
        ).grid(row=2, column=0, columnspan=2, sticky="w", padx=5, pady=8)

        ttk.Checkbutton(
            body,
            text="Enable Universal Auto Add-ons",
            variable=self.auto_addons_var,
        ).grid(row=3, column=0, columnspan=2, sticky="w", padx=5, pady=8)

        ttk.Button(body, text="Save settings", command=self.save_settings).grid(
            row=4, column=0, sticky="w", padx=5, pady=12
        )

        ttk.Label(
            body,
            text=(
                f"Config: {CONFIG_PATH}\n"
                f"Log: {LOG_PATH}\n"
                f"Python: {sys.version.split()[0]} | OS: {platform.platform()}\n"
                f"psutil: {'available' if psutil else 'not installed'} | "
                f"NVML: {'available' if pynvml else 'not installed'}"
            ),
            justify="left",
        ).grid(row=5, column=0, columnspan=3, sticky="w", padx=5, pady=8)

        ttk.Label(
            body,
            text=(
                "Optional telemetry: pip install psutil nvidia-ml-py\n"
                "Tkinter is included with most standard Windows Python installations. "
                "No automatic package installation."
            ),
            justify="left",
        ).grid(row=6, column=0, columnspan=3, sticky="w", padx=5, pady=8)

    # -------------------------------------------------------------------
    # Helpers
    # -------------------------------------------------------------------

    def _set_text(self, widget: tk.Text, value: str):
        widget.delete("1.0", "end")
        widget.insert("1.0", value)
        widget.edit_modified(False)

    def log_event(self, msg: str):
        ts = datetime.now().strftime("%H:%M:%S")
        entry = f"[{ts}] {msg}"
        self.timeline.append(entry)
        LOG.info(msg)
        self.thought_var.set(msg)

    # -------------------------------------------------------------------
    # Telemetry + dashboard
    # -------------------------------------------------------------------

    def refresh_once(self):
        self.latest_cpu = cpu_memory_snapshot()
        self.latest_gpu = gpu_snapshot()
        now = time.time()
        snap = {
            "time": now,
            **self.latest_cpu,
            "gpu_temp": self.latest_gpu.get("temperature"),
            "gpu_percent": self.latest_gpu.get("gpu_percent"),
        }
        self.history.append(snap)
        self._update_metrics()
        self._render_dashboard()
        self._render_timeline()
        self.status_var.set(f"Updated {datetime.now().strftime('%H:%M:%S')}")

        # Curiosity thought
        thought = self.curiosity_engine.think(
            telemetry=snap,
            history=self.history,
            report=self.report,
        )
        self.thought_var.set(thought)

        # Auto add-ons
        if self.auto_addons_var.get():
            self._maybe_generate_auto_addons(snap)

    def _update_metrics(self):
        c = self.latest_cpu
        g = self.latest_gpu
        if c.get("cpu_percent") is not None:
            self.cpu_var.set(f"CPU: {c.get('cpu_percent'):.1f}%")
        else:
            self.cpu_var.set("CPU: unavailable")

        if c.get("memory_percent") is not None:
            self.mem_var.set(
                f"RAM: {c.get('memory_percent'):.1f}% "
                f"({fmt_bytes(c.get('memory_used'))}/{fmt_bytes(c.get('memory_total'))})"
            )
        else:
            self.mem_var.set("RAM: unavailable")

        temp = g.get("temperature")
        util = g.get("gpu_percent")
        self.gpu_var.set(
            f"GPU: {util if util is not None else '—'}% | "
            f"{temp if temp is not None else '—'}°C | "
            f"VRAM {fmt_bytes(g.get('memory_used'))}/{fmt_bytes(g.get('memory_total'))}"
        )
        self.prediction_var.set(self._predict_trend())

    def _predict_trend(self) -> str:
        if len(self.history) < 4:
            return f"Prediction: collecting baseline ({len(self.history)}/4 samples)"
        samples = list(self.history)[-16:]
        ram_vals = [
            s.get("memory_percent")
            for s in samples
            if s.get("memory_percent") is not None
        ]
        cpu_vals = [
            s.get("cpu_percent") for s in samples if s.get("cpu_percent") is not None
        ]
        gpu_temps = [
            s.get("gpu_temp") for s in samples if s.get("gpu_temp") is not None
        ]

        parts = []

        if ram_vals:
            parts.append(compute_trend(ram_vals))
            fut = estimate_future(ram_vals, steps=3)
            if fut is not None:
                parts.append(f"RAM future ~{fut:.1f}% in 3 steps.")
            parts.append(anomaly_score(ram_vals))

        if cpu_vals:
            parts.append(compute_trend(cpu_vals))
            fut = estimate_future(cpu_vals, steps=3)
            if fut is not None:
                parts.append(f"CPU future ~{fut:.1f}% in 3 steps.")
            parts.append(anomaly_score(cpu_vals))

        if gpu_temps:
            try:
                mean_t = statistics.mean(gpu_temps)
                last_t = gpu_temps[-1]
                limit = int(self.config.get("temperature_warning_c", 82))
                if last_t >= limit:
                    parts.append(
                        f"GPU thermal warning: {last_t}°C (mean {mean_t:.1f}°C, limit {limit}°C)."
                    )
                else:
                    parts.append(
                        f"GPU thermal status: {last_t}°C (mean {mean_t:.1f}°C)."
                    )
            except Exception:
                parts.append("GPU trend: unable to compute.")

        if not parts:
            return "Prediction: telemetry insufficient for predictive analysis."
        return " | ".join(parts)

    def _render_dashboard(self):
        c, g = self.latest_cpu, self.latest_gpu
        lines = [
            f"System: {platform.node()}",
            f"OS: {platform.platform()}",
            f"Python: {sys.version.split()[0]}",
            f"Telemetry provider: {'psutil' if psutil else 'built-in fallback (limited)'}",
            "",
            "SYSTEM SNAPSHOT",
            f"CPU usage: {c.get('cpu_percent') if c.get('cpu_percent') is not None else 'N/A'}%",
            f"RAM usage: {c.get('memory_percent') if c.get('memory_percent') is not None else 'N/A'}%",
            f"RAM: {fmt_bytes(c.get('memory_used'))} / {fmt_bytes(c.get('memory_total'))}",
            f"System disk usage: {c.get('disk_percent') if c.get('disk_percent') is not None else 'N/A'}%",
            f"Disk: {fmt_bytes(c.get('disk_used'))} / {fmt_bytes(c.get('disk_total'))}",
            "",
            "GPU SNAPSHOT",
            f"Device: {g.get('name')}",
            f"GPU utilization: {g.get('gpu_percent') if g.get('gpu_percent') is not None else 'N/A'}%",
            f"Temperature: {g.get('temperature') if g.get('temperature') is not None else 'N/A'}°C",
            f"VRAM: {fmt_bytes(g.get('memory_used'))} / {fmt_bytes(g.get('memory_total'))}",
            f"Provider note: {g.get('note')}",
            "",
            "RECENT TREND SAMPLES (most recent first)",
        ]
        for s in list(self.history)[-12:][::-1]:
            lines.append(
                f"{datetime.fromtimestamp(s['time']).strftime('%H:%M:%S')} | "
                f"CPU {s.get('cpu_percent') if s.get('cpu_percent') is not None else 'N/A'}% | "
                f"RAM {s.get('memory_percent') if s.get('memory_percent') is not None else 'N/A'}% | "
                f"GPU temp {s.get('gpu_temp') if s.get('gpu_temp') is not None else 'N/A'}°C"
            )
        self._set_text(self.dashboard_text, "\n".join(lines))

    def _render_timeline(self):
        self._set_text(self.timeline_box, "\n".join(self.timeline))

    # -------------------------------------------------------------------
    # Background worker
    # -------------------------------------------------------------------

    def _background(self, fn, on_success):
        def runner():
            try:
                result = fn()
                self.ui_queue.put((on_success, result, None))
            except Exception as exc:
                LOG.exception("Background task failed")
                self.ui_queue.put((on_success, None, exc))

        threading.Thread(target=runner, daemon=True).start()

    def _drain_queue(self):
        try:
            while True:
                callback, result, error = self.ui_queue.get_nowait()
                if error:
                    self.status_var.set(f"Task failed: {error}")
                    self.log_event(f"Background task error: {error}")
                else:
                    callback(result)
        except queue.Empty:
            pass
        if not self.stop_event.is_set():
            self.root.after(300, self._drain_queue)

    # -------------------------------------------------------------------
    # Auto monitoring
    # -------------------------------------------------------------------

    def start_monitoring(self):
        if self.worker and self.worker.is_alive():
            self.status_var.set("Monitoring already running")
            return
        self.stop_event.clear()

        def loop():
            while not self.stop_event.is_set():
                self.ui_queue.put((lambda _: self.refresh_once(), None, None))
                try:
                    delay = max(1, min(60, int(self.interval_var.get())))
                except Exception:
                    delay = 3
                profile = self.profile_var.get()
                if profile == "Light":
                    self.thought_var.set("Profile: Light – gentle sampling.")
                elif profile == "Balanced":
                    self.thought_var.set("Profile: Balanced – system + processes + network.")
                else:
                    self.thought_var.set("Profile: Detailed – aggressive sampling + script suggestions.")
                    if random.random() < 0.3:
                        script = self._generate_monitor_script()
                        self.generated_scripts.append(script)
                        if len(self.generated_scripts) > 10:
                            self.generated_scripts = self.generated_scripts[-10:]
                        self.log_event("Generated monitor script suggestion.")
                self.stop_event.wait(delay)

        self.worker = threading.Thread(
            target=loop, name="TelemetryWorker", daemon=True
        )
        self.worker.start()
        self.status_var.set("Monitoring running")
        self.log_event("Monitoring started.")

    def stop_monitoring(self):
        self.stop_event.set()
        self.status_var.set("Monitoring stopped")
        self.log_event("Monitoring stopped.")

    def _generate_monitor_script(self) -> str:
        cpu = self.latest_cpu
        gpu = self.latest_gpu
        lines = [
            "# Auto-generated monitor script (suggestion, not executed automatically)",
            "import psutil",
            "",
            "def monitor():",
            f"    print('CPU: {cpu.get('cpu_percent', 0)}%')",
            f"    print('MEM: {cpu.get('memory_percent', 0)}%')",
            f"    print('GPU TEMP: {gpu.get('temperature', 0)}°C')",
            "    for p in psutil.process_iter(attrs=['pid', 'name', 'cpu_percent']):",
            "        info = p.info",
            "        if info['cpu_percent'] > 50:",
            "            print('HOT PROCESS:', info['pid'], info['name'], info['cpu_percent'])",
            "",
            "if __name__ == '__main__':",
            "    monitor()",
        ]
        return "\n".join(lines)

    # -------------------------------------------------------------------
    # Processes / Network
    # -------------------------------------------------------------------

    def refresh_processes(self):
        def done(rows):
            self.proc_tree.delete(*self.proc_tree.get_children())
            for r in rows:
                self.proc_tree.insert(
                    "",
                    "end",
                    values=(
                        r["pid"],
                        r["name"],
                        f"{r['cpu']:.1f}",
                        fmt_bytes(r["memory"]),
                        r["status"],
                    ),
                )
            if psutil is None:
                self.status_var.set("Install optional psutil for process monitoring")
            self.log_event(f"Process snapshot updated ({len(rows)} rows).")

        self._background(process_snapshot, done)

    def refresh_connections(self):
        def done(rows):
            self.net_tree.delete(*self.net_tree.get_children())
            for r in rows:
                self.net_tree.insert(
                    "",
                    "end",
                    values=(
                        r["status"],
                        r["type"],
                        r["local"],
                        r["remote"],
                        r["pid"],
                    ),
                )
            if psutil is None:
                self.status_var.set("Install optional psutil for connection monitoring")
            self.log_event(f"Connection snapshot updated ({len(rows)} rows).")

        self._background(connection_snapshot, done)

    # -------------------------------------------------------------------
    # Code Lab actions
    # -------------------------------------------------------------------

    def manual_drop_open(self, event=None):
        self.open_code()

    def open_code(self):
        path = filedialog.askopenfilename(
            title="Open Python source",
            filetypes=[
                ("Python files", "*.py"),
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        try:
            source = Path(path).read_text(encoding="utf-8-sig")
        except Exception as exc:
            messagebox.showerror("Open failed", str(exc))
            return
        self.source_path = Path(path)
        self.source_text = source
        self.addon_history.clear()
        self.addon_counter = 0
        self.baseline_report = None
        self.refresh_addons_list()
        self._set_text(self.source_box, source)
        self._set_text(
            self.report_box,
            f"Loaded {path}\nChoose Analyze to inspect this file. Source code is never executed automatically.",
        )
        self.tabs.select(self.code_tab)
        self.status_var.set(f"Loaded {self.source_path.name}")
        self.log_event(f"Code file loaded: {self.source_path.name}")

    def _current_source(self) -> str:
        return self.source_box.get("1.0", "end-1c")

    def set_baseline(self):
        source = self._current_source()
        if not source.strip():
            messagebox.showinfo(
                "Code Lab",
                "Open or paste code before setting a baseline.",
            )
            return
        self.baseline_report = self.analyzer.analyze(
            source, str(self.source_path or "<editor>")
        )
        # Enrich baseline with counts for comparator
        self.baseline_report["todos_count"] = len(self.baseline_report.get("todos", []))
        self.baseline_report["issues_count"] = len(self.baseline_report.get("issues", []))
        self._set_text(
            self.report_box,
            "BASELINE SNAPSHOT SET\n======================\n"
            "Future analyses will be compared structurally against this baseline.\n",
        )
        self.status_var.set("Baseline snapshot set for comparator")
        self.log_event("Baseline snapshot set for comparator.")

    def analyze_code(self):
        source = self._current_source()
        if not source.strip():
            messagebox.showinfo(
                "Code Lab",
                "Open a Python file or paste code into the source panel first.",
            )
            return
        self.source_text = source
        self.report = self.analyzer.analyze(
            source, str(self.source_path or "<editor>")
        )
        # Enrich report with counts for comparator
        self.report["todos_count"] = len(self.report.get("todos", []))
        self.report["issues_count"] = len(self.report.get("issues", []))

        out = [
            "STATIC ANALYSIS REPORT",
            "=" * 26,
            f"File: {self.report['filename']}",
            f"Syntax valid: {self.report.get('syntax_ok', False)}",
            "",
        ]
        out.extend(self.report["summary"])
        out += ["", "REVIEW ITEMS"] + (
            [f"• {x}" for x in self.report["issues"]]
            or ["• None from the current heuristics."]
        )
        out += ["", "TODO / FIXME MARKERS"] + (
            [f"• {x}" for x in self.report["todos"]] or ["• None found."]
        )
        if self.report.get("game_like_functions"):
            out += ["", "GAME-LIKE LOOP FUNCTIONS"] + [
                f"• {x}" for x in self.report["game_like_functions"]
            ]
        out += [
            "",
            "Note: this is static analysis, not a security audit or correctness guarantee.",
        ]

        # Comparator section if baseline exists
        if self.baseline_report is not None:
            out.append("")
            out.extend(self.comparator.compare(self.baseline_report, self.report))

        self._set_text(self.report_box, "\n".join(out))
        self.status_var.set("Code analysis complete")
        self.log_event("Code analysis completed.")

        if self.auto_addons_var.get():
            self._maybe_generate_auto_addons_from_analysis()

    def preview_cleanup(self):
        source = self._current_source()
        if not source:
            messagebox.showinfo(
                "Code Lab", "Load or paste source code first."
            )
            return
        cleaned = conservative_cleanup(source)
        self._set_text(
            self.report_box,
            "CONSERVATIVE CLEANUP PREVIEW\n"
            "============================\n"
            "Only tabs, trailing whitespace, line endings, and final newline are normalized.\n\n"
            + cleaned,
        )
        self.status_var.set("Cleanup preview generated")
        self.log_event("Cleanup preview generated.")

    def save_clean_copy(self):
        source = self._current_source()
        if not source.strip():
            messagebox.showinfo(
                "Code Lab",
                "Load or paste source code first.",
            )
            return
        cleaned = conservative_cleanup(source)
        path = filedialog.asksaveasfilename(
            title="Save improved copy",
            defaultextension=".py",
            filetypes=[
                ("Python files", "*.py"),
                ("Text files", "*.txt"),
                ("All files", "*.*"),
            ],
        )
        if not path:
            return
        try:
            Path(path).write_text(cleaned, encoding="utf-8")
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        self.status_var.set(f"Improved copy saved to {path}")
        self.log_event(f"Improved copy saved: {path}")

    # -------------------------------------------------------------------
    # Turbo code add-ons + undo
    # -------------------------------------------------------------------

    def build_addon(self):
        source = self._current_source()
        if not source.strip():
            messagebox.showinfo(
                "Code Lab",
                "Load or paste source code first before building an add-on.",
            )
            return
        if self.report is None:
            self.report = self.analyzer.analyze(
                source, str(self.source_path or "<editor>")
            )
        fn_count = self.report.get("functions", 0)
        cls_count = self.report.get("classes", 0)
        todo_count = len(self.report.get("todos", []))
        self.addon_counter += 1
        addon_id = self.addon_counter
        ts = datetime.now().strftime("%H:%M:%S")
        header = (
            f"# --- Curious AI Turbo Add-on #{addon_id} (bolt-on helper, non-destructive) ---"
        )
        addon = [
            "",
            header,
            "# Origin: MANUAL (you clicked Build turbo add-on).",
            "# This block was generated by the Command Center. It is safe to remove.",
            "# It does not execute automatically; it only defines helper utilities.",
            "",
            "def curious_ai_summary():",
            f"    \"\"\"Auto-generated summary of this module: {fn_count} function(s), {cls_count} class(es), {todo_count} TODO/FIXME marker(s).\"\"\"",
            "    return {",
            f"        'functions': {fn_count},",
            f"        'classes': {cls_count},",
            f"        'todos': {todo_count},",
            "    }",
            "",
            "def curious_ai_print_summary():",
            "    info = curious_ai_summary()",
            "    print('Curious AI Summary:', info)",
            "",
            "# You can call curious_ai_print_summary() manually in your own runtime.",
            f"# --- End of Curious AI Turbo Add-on #{addon_id} ---",
            "",
        ]
        addon_block = "\n".join(addon)
        self.addon_history.append(
            {
                "id": addon_id,
                "timestamp": ts,
                "summary": f"{fn_count} fn / {cls_count} cls / {todo_count} TODO",
                "block": addon_block,
                "origin": "MANUAL",
            }
        )
        new_source = source + addon_block
        self._set_text(self.source_box, new_source)
        self._set_text(
            self.report_box,
            "TURBO ADD-ON GENERATED (MANUAL)\n===============================\n"
            "A non-destructive helper add-on was appended to the source panel.\n"
            "You can undo the last add-on using the 'Undo last add-on' button,\n"
            "or uninstall specific add-ons from the Add-ons tab.\n\n"
            + addon_block,
        )
        self.refresh_addons_list()
        self.status_var.set("Turbo add-on generated and appended to source")
        self.log_event(f"Turbo code add-on #{addon_id} generated and appended.")

    def undo_addon(self):
        if not self.addon_history:
            messagebox.showinfo(
                "Code Lab",
                "No add-on to undo. Build an add-on first.",
            )
            return
        last = self.addon_history[-1]
        source = self._current_source()
        block = last["block"]
        if block and block in source:
            self.addon_history.pop()
            new_source = source.replace(block, "")
            self._set_text(self.source_box, new_source)
            self._set_text(
                self.report_box,
                "ADD-ON UNDONE\n==============\n"
                f"The last add-on block (ID {last['id']}, origin {last.get('origin')}) was removed from the source panel.\n",
            )
            self.status_var.set("Last add-on removed from source")
            self.log_event(f"Last add-on #{last['id']} removed from source.")
        else:
            messagebox.showinfo(
                "Code Lab",
                "Could not locate the last add-on block in the current source.",
            )
        self.refresh_addons_list()

    # -------------------------------------------------------------------
    # Add-ons tab helpers
    # -------------------------------------------------------------------

    def refresh_addons_list(self):
        self.addons_tree.delete(*self.addons_tree.get_children())
        for entry in self.addon_history:
            self.addons_tree.insert(
                "",
                "end",
                iid=str(entry["id"]),
                values=(
                    entry["id"],
                    entry["timestamp"],
                    entry.get("origin", "MANUAL"),
                    entry["summary"],
                ),
            )
        if not self.addon_history:
            self._set_text(
                self.addons_detail_box,
                "No add-ons have been generated for this code session yet.\n"
                "Enable Universal Auto Add-ons in Settings to let the engine propose tweaks automatically.",
            )
        self.status_var.set("Add-ons list refreshed")

    def _on_addon_select(self, event=None):
        sel = self.addons_tree.selection()
        if not sel:
            return
        try:
            addon_id = int(sel[0])
        except ValueError:
            return
        for entry in self.addon_history:
            if entry["id"] == addon_id:
                self._set_text(self.addons_detail_box, entry["block"])
                return

    def apply_selected_addon(self):
        sel = self.addons_tree.selection()
        if not sel:
            messagebox.showinfo(
                "Add-ons",
                "Select an add-on in the list first.",
            )
            return
        try:
            addon_id = int(sel[0])
        except ValueError:
            messagebox.showerror("Add-ons", "Invalid add-on selection.")
            return
        entry = None
        for e in self.addon_history:
            if e["id"] == addon_id:
                entry = e
                break
        if entry is None:
            messagebox.showerror("Add-ons", "Selected add-on not found in history.")
            return
        source = self._current_source()
        block = entry["block"]
        if block in source:
            messagebox.showinfo(
                "Add-ons",
                "The selected add-on block is already present in the source.",
            )
            return
        new_source = source + block
        self._set_text(self.source_box, new_source)
        self._set_text(
            self.addons_detail_box,
            f"Add-on #{addon_id} (origin {entry.get('origin')}) has been applied to the source panel.",
        )
        self.status_var.set(f"Add-on #{addon_id} applied to source")
        self.log_event(f"Add-on #{addon_id} applied to source.")

    def remove_selected_addon(self):
        sel = self.addons_tree.selection()
        if not sel:
            messagebox.showinfo(
                "Add-ons",
                "Select an add-on in the list first.",
            )
            return
        try:
            addon_id = int(sel[0])
        except ValueError:
            messagebox.showerror("Add-ons", "Invalid add-on selection.")
            return
        entry = None
        for e in self.addon_history:
            if e["id"] == addon_id:
                entry = e
                break
        if entry is None:
            messagebox.showerror("Add-ons", "Selected add-on not found in history.")
            return
        source = self._current_source()
        block = entry["block"]
        if block in source:
            new_source = source.replace(block, "")
            self._set_text(self.source_box, new_source)
        self.addon_history = [e for e in self.addon_history if e["id"] != addon_id]
        self.refresh_addons_list()
        self._set_text(
            self.addons_detail_box,
            f"Add-on #{addon_id} (origin {entry.get('origin')}) has been uninstalled from the source panel.",
        )
        self.status_var.set(f"Add-on #{addon_id} uninstalled")
        self.log_event(f"Add-on #{addon_id} uninstalled from source.")

    # -------------------------------------------------------------------
    # Auto add-on generation
    # -------------------------------------------------------------------

    def _maybe_generate_auto_addons(self, telemetry_snap: dict):
        source = self._current_source()
        if not source.strip():
            return
        auto_addons = self.addon_engine.generate_auto_addons(
            source=source,
            report=self.report,
            telemetry=telemetry_snap,
            base_counter=self.addon_counter,
        )
        if not auto_addons:
            return
        for entry in auto_addons:
            self.addon_counter = max(self.addon_counter, entry["id"])
            if any(e["summary"] == entry["summary"] for e in self.addon_history):
                continue
            self.addon_history.append(entry)
        self.refresh_addons_list()
        self.log_event(f"Universal Add-on Engine proposed {len(auto_addons)} auto add-on(s).")

    def _maybe_generate_auto_addons_from_analysis(self):
        source = self._current_source()
        if not source.strip():
            return
        if self.history:
            telemetry_snap = self.history[-1]
        else:
            telemetry_snap = {
                "cpu_percent": None,
                "memory_percent": None,
                "gpu_temp": None,
                "gpu_percent": None,
            }
        auto_addons = self.addon_engine.generate_auto_addons(
            source=source,
            report=self.report,
            telemetry=telemetry_snap,
            base_counter=self.addon_counter,
        )
        if not auto_addons:
            return
        for entry in auto_addons:
            self.addon_counter = max(self.addon_counter, entry["id"])
            if any(e["summary"] == entry["summary"] for e in self.addon_history):
                continue
            self.addon_history.append(entry)
        self.refresh_addons_list()
        self.log_event(f"Universal Add-on Engine proposed {len(auto_addons)} analysis-driven add-on(s).")

    # -------------------------------------------------------------------
    # Plugins
    # -------------------------------------------------------------------

    def refresh_plugins_safe(self):
        items = plugin_metadata_only()
        self._set_text(
            self.plugins_box,
            "SAFE PLUGIN LISTING\n=====================\n"
            + "\n".join(items),
        )
        self.status_var.set("Plugins listed (safe mode)")
        self.log_event("Plugins listed in safe mode.")

    def refresh_plugins_full(self):
        def done(results):
            self.plugins_full = results
            lines = ["FULL-POWER PLUGIN REPORT", "==========================", ""]
            for r in results:
                lines.append(f"Plugin: {r['name']}")
                if r["describe"] is not None:
                    lines.append(f"  describe(): {r['describe']}")
                if r["run_result"] is not None:
                    lines.append(f"  run() result: {r['run_result']}")
                if r["error"] is not None:
                    lines.append(f"  error: {r['error']}")
                lines.append("")
            self._set_text(self.plugins_box, "\n".join(lines))
            self.status_var.set("Plugins loaded and run (full-power mode)")
            self.log_event(f"Plugins loaded in full-power mode ({len(results)}).")

        self._background(load_plugins_full, done)

    def open_plugins_folder(self):
        PLUGIN_DIR.mkdir(exist_ok=True)
        try:
            os.startfile(str(PLUGIN_DIR))
        except Exception as exc:
            messagebox.showerror("Open folder failed", str(exc))

    # -------------------------------------------------------------------
    # Settings + snapshot export
    # -------------------------------------------------------------------

    def save_settings(self):
        try:
            interval = max(1, min(60, int(self.interval_var.get())))
        except Exception:
            interval = 3
        self.config["sample_interval"] = interval
        self.config["profile"] = self.profile_var.get()
        self.config["auto_monitor"] = bool(self.auto_var.get())
        self.config["auto_addons_enabled"] = bool(self.auto_addons_var.get())
        self.config["window_geometry"] = self.root.geometry()
        save_config(self.config)
        self.status_var.set("Settings saved")
        self.log_event("Settings saved.")

    def export_snapshot(self):
        path = filedialog.asksaveasfilename(
            title="Export snapshot",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
        )
        if not path:
            return
        data = {
            "cpu": self.latest_cpu,
            "gpu": self.latest_gpu,
            "history": list(self.history),
            "timeline": list(self.timeline),
            "generated_scripts": self.generated_scripts,
            "addons": self.addon_history,
        }
        try:
            Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))
            return
        self.status_var.set(f"Snapshot exported to {path}")
        self.log_event(f"Snapshot exported: {path}")

    # -------------------------------------------------------------------
    # Close
    # -------------------------------------------------------------------

    def close(self):
        self.stop_event.set()
        self.config["window_geometry"] = self.root.geometry()
        save_config(self.config)
        self.root.destroy()


# -------------------------------------------------------------------
# Main
# -------------------------------------------------------------------

def main():
    root = tk.Tk()
    app = CommandCenter(root)
    root.mainloop()


if __name__ == "__main__":
    main()
