#!/usr/bin/env python3
# ================================================================
# PREEMPTIVE STRIKE AI — NEXT-GEN v11
# Windows performance / telemetry / diagnostics command center
#
# Upgrade focus:
#   * Startup-safe architecture: no automatic pip installs at boot
#   * Safe / Assist / Autonomous modes with explicit capability gates
#   * Crash guard + rotating logs + startup recovery state
#   * Watchdog with stale-heartbeat detection and bounded recovery
#   * Hardware telemetry with optional NVIDIA NVML support
#   * Performance history, EMA baselines and anomaly detection
#   * CPU + optional CUDA benchmark calibration
#   * Real benchmark history and trend reporting
#   * Config snapshots and rollback for application-owned settings
#   * Secure credential storage through Windows DPAPI / keyring
#   * Plugin manifest, hash approval and permission declarations
#   * Plugin execution is opt-in; permissions are advisory for Python code
#   * Process observer with filtering and safe inspection
#   * Dependency diagnostics and explicit repair action
#   * Diagnostics export (JSON) and database maintenance
#   * Compact tabbed PySide6 GUI with CLI fallback
#   * Command-line safe mode / diagnostics / reset-config
#
# Safety model:
#   Autonomous actions are intentionally limited to low-risk,
#   application-owned operations. This program does not inject
#   credentials, bypass security controls, disable antivirus, alter
#   protected Windows security settings, or perform arbitrary
#   irreversible system changes.
# ================================================================

from __future__ import annotations

import argparse
import ctypes
import hashlib
import importlib
import importlib.util
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import platform
import shutil
import sqlite3
import statistics
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path

# ---------------------------------------------------------------------------
# Local AI Advisor (optional)
# ---------------------------------------------------------------------------
# The AI layer is intentionally advisory: model output is treated as text only.
# Ollama is supported when installed and running locally. The program remains
# fully functional without an LLM.
class LocalLLMAdvisor:
    """Small optional local-LLM assistant for telemetry interpretation.

    Supported backend:
      - Ollama HTTP API on localhost
    Fallback:
      - deterministic rule-based analysis

    No model output is ever executed as Python, shell, PowerShell, or a plugin.
    """

    def __init__(self, config=None, logger=None):
        self.config = config or {}
        self.logger = logger
        self.enabled = bool(self.config.get("llm_enabled", True))
        self.provider = str(self.config.get("llm_provider", "ollama"))
        self.base_url = str(self.config.get(
            "llm_base_url", "http://127.0.0.1:11434"
        )).rstrip("/")
        self.model = str(self.config.get("llm_model", "llama3.2:3b"))
        self.timeout = float(self.config.get("llm_timeout", 12.0))
        self.last_backend = "rules"

    def _log(self, msg):
        try:
            if self.logger:
                self.logger.info("[LLM] " + msg)
        except Exception:
            pass

    def _rule_analysis(self, snapshot):
        cpu = float(snapshot.get("cpu_percent", 0) or 0)
        ram = float(snapshot.get("ram_percent", 0) or 0)
        disk = float(snapshot.get("disk_percent", 0) or 0)
        gpu = float(snapshot.get("gpu_util_percent", 0) or 0)
        temp = snapshot.get("gpu_temp_c")

        findings = []
        actions = []

        if cpu >= 90:
            findings.append("CPU utilization is very high.")
            actions.append("Check the top CPU-consuming processes before changing system settings.")
        elif cpu >= 70:
            findings.append("CPU utilization is elevated.")

        if ram >= 90:
            findings.append("Memory pressure is high.")
            actions.append("Inspect memory-heavy processes and close unnecessary workloads.")
        elif ram >= 80:
            findings.append("Memory usage is elevated.")

        if disk >= 95:
            findings.append("The system drive is nearly full.")
            actions.append("Free disk space before attempting performance tuning.")

        if gpu >= 90:
            findings.append("GPU utilization is high; the workload may already be GPU-bound.")

        if temp is not None:
            try:
                if float(temp) >= 85:
                    findings.append("GPU temperature is high.")
                    actions.append("Check cooling, airflow, fan behavior, and workload before tuning clocks.")
                elif float(temp) >= 75:
                    findings.append("GPU temperature is elevated.")
            except Exception:
                pass

        if not findings:
            findings.append("No major resource-pressure signal was detected in the supplied snapshot.")
            actions.append("Continue collecting telemetry and use benchmark history to establish a baseline.")

        return (
            "Local AI Advisor (rule fallback)\n\n"
            + "Findings:\n- " + "\n- ".join(findings)
            + "\n\nSuggested next steps:\n- " + "\n- ".join(actions)
            + "\n\nSafety: recommendations are advisory; no system changes were performed."
        )

    def _prompt(self, snapshot, question=None):
        import json
        context = json.dumps(snapshot, indent=2, default=str)
        user = question or (
            "Analyze this Windows performance telemetry. Identify likely bottlenecks, "
            "anomalies, and safe next steps. Do not recommend destructive actions, "
            "credential access, security bypasses, arbitrary code execution, or "
            "unverified overclocking. Keep the response concise."
        )
        return (
            "You are a local Windows performance assistant. You are advisory only. "
            "Never output executable code or commands. Never claim an action was "
            "performed unless the host application reports it.\n\n"
            f"Telemetry:\n{context}\n\nQuestion:\n{user}"
        )

    def analyze(self, snapshot, question=None):
        if not self.enabled or self.provider.lower() != "ollama":
            self.last_backend = "rules"
            return self._rule_analysis(snapshot)

        try:
            import json
            from urllib.request import Request, urlopen

            payload = json.dumps({
                "model": self.model,
                "prompt": self._prompt(snapshot, question),
                "stream": False,
                "options": {
                    "temperature": 0.2,
                    "num_predict": 500
                }
            }).encode("utf-8")

            req = Request(
                self.base_url + "/api/generate",
                data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urlopen(req, timeout=self.timeout) as response:
                data = json.loads(response.read().decode("utf-8", "replace"))

            answer = str(data.get("response", "")).strip()
            if answer:
                self.last_backend = "ollama"
                return "Local AI Advisor (Ollama / %s)\n\n%s" % (self.model, answer)

        except Exception as exc:
            self.last_backend = "rules"
            self._log("Ollama unavailable; using rule fallback: %s" % exc)

        return self._rule_analysis(snapshot)

    def status(self):
        return {
            "enabled": self.enabled,
            "provider": self.provider,
            "model": self.model,
            "base_url": self.base_url,
            "last_backend": self.last_backend,
        }

from typing import Any, Optional, Callable

APP_NAME = "Preemptive Strike AI"
APP_VERSION = "11.0.0"

BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "preemptive_data"
PLUGIN_DIR = BASE_DIR / "plugins"
LOG_DIR = BASE_DIR / "logs"
BACKUP_DIR = DATA_DIR / "config_backups"
DB_PATH = DATA_DIR / "preemptive.db"
CONFIG_PATH = DATA_DIR / "config.json"
ROLLBACK_PATH = DATA_DIR / "rollback_journal.json"
PLUGIN_MANIFEST_PATH = DATA_DIR / "plugins.json"
STARTUP_STATE_PATH = DATA_DIR / "startup_state.json"

for directory in (DATA_DIR, PLUGIN_DIR, LOG_DIR, BACKUP_DIR):
    directory.mkdir(parents=True, exist_ok=True)


# ------------------------------------------------
# LOGGING
# ------------------------------------------------

LOGGER = logging.getLogger("PSAI")
LOGGER.setLevel(logging.INFO)
if not LOGGER.handlers:
    handler = RotatingFileHandler(
        LOG_DIR / "preemptive.log",
        maxBytes=2_000_000,
        backupCount=5,
        encoding="utf-8",
    )
    handler.setFormatter(
        logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
    )
    LOGGER.addHandler(handler)
    console = logging.StreamHandler(sys.stdout)
    console.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))
    LOGGER.addHandler(console)


def log_exception(prefix: str, exc: BaseException) -> None:
    LOGGER.error("%s: %s\n%s", prefix, exc, traceback.format_exc())


# ------------------------------------------------
# UTILITIES
# ------------------------------------------------

def now() -> float:
    return time.time()


def human_bytes(value: float | int | None) -> str:
    if value is None:
        return "--"
    value = float(value)
    units = ("B", "KB", "MB", "GB", "TB")
    for unit in units:
        if abs(value) < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"


def safe_json(value: Any) -> str:
    return json.dumps(value, default=str, separators=(",", ":"))


def atomic_write_json(path: Path, payload: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(
        prefix=path.name + ".", suffix=".tmp", dir=str(path.parent)
    )
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, default=str)
            handle.flush()
            os.fsync(handle.fileno())
        Path(tmp_name).replace(path)
    finally:
        try:
            Path(tmp_name).unlink(missing_ok=True)
        except Exception:
            pass


def is_windows() -> bool:
    return platform.system().lower() == "windows"


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def safe_call(fn: Callable, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as exc:
        LOGGER.warning("Optional operation failed: %s", exc)
        return None


# ------------------------------------------------
# DEPENDENCY MANAGER
# ------------------------------------------------

REQUIRED = {
    "psutil": "psutil",
    "PySide6": "PySide6",
}

OPTIONAL = {
    "pynvml": "pynvml",
    "torch": "torch",
    "keyring": "keyring",
}


def detect_dependencies() -> dict[str, bool]:
    result: dict[str, bool] = {}
    for module_name in {**REQUIRED, **OPTIONAL}:
        try:
            importlib.import_module(module_name)
            result[module_name] = True
        except Exception:
            result[module_name] = False
    return result


DEP_STATUS = detect_dependencies()


def repair_dependencies(include_optional: bool = False) -> dict[str, str]:
    """Explicit repair only. Never runs automatically during import."""
    packages = dict(REQUIRED)
    if include_optional:
        packages.update(OPTIONAL)

    result: dict[str, str] = {}
    for module_name, package_name in packages.items():
        if DEP_STATUS.get(module_name):
            result[module_name] = "already-installed"
            continue
        try:
            subprocess.check_call(
                [sys.executable, "-m", "pip", "install", "--user", package_name],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                timeout=180,
            )
            result[module_name] = "installed"
        except Exception as exc:
            result[module_name] = f"failed: {exc}"
    return result


try:
    import psutil
except Exception:
    psutil = None

try:
    import pynvml
except Exception:
    pynvml = None

try:
    import torch
except Exception:
    torch = None

try:
    import keyring
except Exception:
    keyring = None

try:
    from PySide6.QtCore import QTimer, Qt
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QGridLayout, QLabel, QPushButton, QTextEdit, QTabWidget,
        QTableWidget, QTableWidgetItem, QComboBox, QLineEdit,
        QSpinBox, QMessageBox, QGroupBox, QCheckBox, QFileDialog,
        QHeaderView, QProgressBar
    )
    QT_AVAILABLE = True
except Exception:
    QT_AVAILABLE = False


# ------------------------------------------------
# CONFIGURATION + RECOVERY
# ------------------------------------------------

DEFAULT_CONFIG = {
    "schema_version": 2,
    "mode": "assist",
    "telemetry_interval": 2,
    "history_retention": 5000,
    "benchmark_duration": 5,
    "anomaly_sigma": 2.5,
    "learning_alpha": 0.20,
    "autonomous_memory_pressure": True,
    "autonomous_cleanup": False,
    "plugin_network": False,
    "plugin_file_write": False,
    "plugin_process_control": False,
    "startup_safe_mode": False,
    "window_width": 1060,
    "window_height": 700,
}


class Config:
    def __init__(self, path: Path = CONFIG_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.data = dict(DEFAULT_CONFIG)
        self.load()

    def load(self) -> None:
        with self.lock:
            if self.path.exists():
                try:
                    loaded = json.loads(self.path.read_text(encoding="utf-8"))
                    if isinstance(loaded, dict):
                        self.data.update(loaded)
                except Exception as exc:
                    LOGGER.warning("Config load failed: %s", exc)
            self._migrate()
            self.save()

    def _migrate(self) -> None:
        version = int(self.data.get("schema_version", 1))
        if version < 2:
            self.data.setdefault("history_retention", 5000)
            self.data.setdefault("anomaly_sigma", 2.5)
            self.data.setdefault("learning_alpha", 0.20)
            self.data["schema_version"] = 2

        if self.data.get("mode") not in {"safe", "assist", "autonomous"}:
            self.data["mode"] = "assist"

    def save(self) -> None:
        with self.lock:
            atomic_write_json(self.path, self.data)

    def get(self, key: str, default=None):
        with self.lock:
            return self.data.get(key, default)

    def set(self, key: str, value: Any) -> None:
        with self.lock:
            self.data[key] = value
            self.save()

    def snapshot(self) -> dict:
        with self.lock:
            return dict(self.data)


class RecoveryManager:
    def __init__(self, config: Config):
        self.config = config

    def create_snapshot(self, reason: str = "manual") -> Path:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = BACKUP_DIR / f"config-{stamp}-{uuid.uuid4().hex[:6]}.json"
        payload = {
            "created": now(),
            "reason": reason,
            "app_version": APP_VERSION,
            "config": self.config.snapshot(),
        }
        atomic_write_json(path, payload)
        return path

    def list_snapshots(self) -> list[Path]:
        return sorted(BACKUP_DIR.glob("config-*.json"), reverse=True)

    def restore(self, path: Path) -> tuple[bool, str]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8"))
            cfg = payload.get("config")
            if not isinstance(cfg, dict):
                return False, "Invalid configuration snapshot"
            self.create_snapshot("before-restore")
            with self.config.lock:
                self.config.data = dict(DEFAULT_CONFIG)
                self.config.data.update(cfg)
                self.config._migrate()
                self.config.save()
            return True, f"Restored {path.name}"
        except Exception as exc:
            return False, str(exc)

    def reset_config(self) -> None:
        if CONFIG_PATH.exists():
            self.create_snapshot("before-reset")
        with self.config.lock:
            self.config.data = dict(DEFAULT_CONFIG)
            self.config.save()


# ------------------------------------------------
# SQLITE MEMORY / HISTORY
# ------------------------------------------------

class MemoryStore:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(
            str(path), check_same_thread=False, timeout=10
        )
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._schema()

    def _schema(self) -> None:
        with self.lock:
            self.conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS events(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    category TEXT NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
                CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);

                CREATE TABLE IF NOT EXISTS telemetry(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    payload TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_telemetry_ts ON telemetry(ts);

                CREATE TABLE IF NOT EXISTS benchmarks(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    label TEXT NOT NULL,
                    before_json TEXT NOT NULL,
                    after_json TEXT NOT NULL,
                    score REAL,
                    notes TEXT
                );

                CREATE TABLE IF NOT EXISTS actions(
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL NOT NULL,
                    action TEXT NOT NULL,
                    result TEXT NOT NULL,
                    reward REAL
                );
                """
            )
            self.conn.commit()

    def append_event(self, category: str, payload: dict) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO events(ts,category,payload) VALUES(?,?,?)",
                (now(), category, safe_json(payload)),
            )
            self.conn.commit()

    def append_telemetry(self, payload: dict) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO telemetry(ts,payload) VALUES(?,?)",
                (now(), safe_json(payload)),
            )
            self.conn.commit()

    def recent_events(self, limit: int = 100) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT ts,category,payload FROM events "
                "ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        output = []
        for ts, category, payload in rows:
            try:
                payload = json.loads(payload)
            except Exception:
                pass
            output.append({"ts": ts, "category": category, "payload": payload})
        return output

    def telemetry_history(self, limit: int = 300) -> list[dict]:
        with self.lock:
            rows = self.conn.execute(
                "SELECT ts,payload FROM telemetry ORDER BY id DESC LIMIT ?",
                (limit,),
            ).fetchall()
        output = []
        for ts, payload in reversed(rows):
            try:
                payload = json.loads(payload)
            except Exception:
                continue
            output.append({"ts": ts, **payload})
        return output

    def record_benchmark(
        self, label: str, before: dict, after: dict,
        score: float, notes: str = ""
    ) -> None:
        with self.lock:
            self.conn.execute(
                "INSERT INTO benchmarks(ts,label,before_json,after_json,score,notes)"
                " VALUES(?,?,?,?,?,?)",
                (now(), label, safe_json(before), safe_json(after), score, notes),
            )
            self.conn.commit()

    def benchmarks(self, limit: int = 50) -> list[tuple]:
        with self.lock:
            return self.conn.execute(
                "SELECT ts,label,before_json,after_json,score,notes "
                "FROM benchmarks ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def record_action(self, action: str, result: str, reward: float | None = None):
        with self.lock:
            self.conn.execute(
                "INSERT INTO actions(ts,action,result,reward) VALUES(?,?,?,?)",
                (now(), action, result, reward),
            )
            self.conn.commit()

    def prune(self, retention: int = 5000) -> None:
        retention = max(500, int(retention))
        with self.lock:
            self.conn.execute(
                "DELETE FROM telemetry WHERE id NOT IN "
                "(SELECT id FROM telemetry ORDER BY id DESC LIMIT ?)",
                (retention,),
            )
            self.conn.execute(
                "DELETE FROM events WHERE id NOT IN "
                "(SELECT id FROM events ORDER BY id DESC LIMIT ?)",
                (retention,),
            )
            self.conn.commit()

    def close(self):
        with self.lock:
            self.conn.close()


# ------------------------------------------------
# SECURE CREDENTIAL STORAGE
# ------------------------------------------------

class SecureCredentialStore:
    """
    Windows DPAPI is preferred. OS keyring is also supported.
    Secrets are never copied into SQLite telemetry/event records.
    """

    SERVICE = "PreemptiveStrikeAI"

    def __init__(self):
        self.backend = "keyring" if keyring is not None else (
            "dpapi" if is_windows() else "unavailable"
        )

    def set(self, name: str, username: str, password: str) -> bool:
        if not name:
            return False
        try:
            if self.backend == "keyring":
                keyring.set_password(self.SERVICE, f"{name}:username", username)
                keyring.set_password(self.SERVICE, f"{name}:password", password)
                return True
            if self.backend == "dpapi":
                path = DATA_DIR / f"cred_{hashlib.sha256(name.encode()).hexdigest()}.bin"
                payload = json.dumps(
                    {"username": username, "password": password},
                    separators=(",", ":"),
                ).encode()
                path.write_bytes(self._protect(payload))
                return True
        except Exception as exc:
            LOGGER.error("Credential save failed: %s", exc)
        return False

    def get(self, name: str) -> Optional[dict]:
        try:
            if self.backend == "keyring":
                username = keyring.get_password(self.SERVICE, f"{name}:username")
                password = keyring.get_password(self.SERVICE, f"{name}:password")
                if username is not None and password is not None:
                    return {"username": username, "password": password}
            elif self.backend == "dpapi":
                path = DATA_DIR / f"cred_{hashlib.sha256(name.encode()).hexdigest()}.bin"
                if path.exists():
                    return json.loads(self._unprotect(path.read_bytes()).decode())
        except Exception as exc:
            LOGGER.error("Credential read failed: %s", exc)
        return None

    def delete(self, name: str) -> None:
        try:
            if self.backend == "keyring":
                for suffix in ("username", "password"):
                    try:
                        keyring.delete_password(self.SERVICE, f"{name}:{suffix}")
                    except Exception:
                        pass
            elif self.backend == "dpapi":
                path = DATA_DIR / f"cred_{hashlib.sha256(name.encode()).hexdigest()}.bin"
                path.unlink(missing_ok=True)
        except Exception as exc:
            LOGGER.warning("Credential delete failed: %s", exc)

    @staticmethod
    def _protect(data: bytes) -> bytes:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.c_uint32),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
            ]
        buf = (ctypes.c_ubyte * len(data))(*data)
        inp = DATA_BLOB(len(data), buf)
        out = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptProtectData(
            ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)
        ):
            raise OSError("CryptProtectData failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)

    @staticmethod
    def _unprotect(data: bytes) -> bytes:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [
                ("cbData", ctypes.c_uint32),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
            ]
        buf = (ctypes.c_ubyte * len(data))(*data)
        inp = DATA_BLOB(len(data), buf)
        out = DATA_BLOB()
        if not ctypes.windll.crypt32.CryptUnprotectData(
            ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)
        ):
            raise OSError("CryptUnprotectData failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            ctypes.windll.kernel32.LocalFree(out.pbData)


# ------------------------------------------------
# HARDWARE TELEMETRY
# ------------------------------------------------

class HardwareTelemetry:
    def __init__(self):
        self.gpu_handles: list[Any] = []
        self.gpu_backend = "unavailable"
        self._lock = threading.RLock()
        self._init_gpu()

    def _init_gpu(self):
        if pynvml is None:
            return
        try:
            pynvml.nvmlInit()
            count = pynvml.nvmlDeviceGetCount()
            self.gpu_handles = [
                pynvml.nvmlDeviceGetHandleByIndex(i) for i in range(count)
            ]
            if self.gpu_handles:
                self.gpu_backend = "NVML"
        except Exception as exc:
            LOGGER.warning("GPU telemetry unavailable: %s", exc)

    def snapshot(self) -> dict:
        data = {
            "ts": now(),
            "cpu_percent": 0.0,
            "cpu_freq_mhz": None,
            "ram_percent": 0.0,
            "ram_used": 0,
            "ram_total": 0,
            "swap_percent": 0.0,
            "disk_percent": 0.0,
            "disk_free": None,
            "battery_percent": None,
            "process_count": 0,
            "load_1m": None,
            "gpu_backend": self.gpu_backend,
            "gpu": [],
        }

        if psutil is None:
            return data

        try:
            vm = psutil.virtual_memory()
            swap = psutil.swap_memory()
            data["cpu_percent"] = psutil.cpu_percent(interval=None)
            data["ram_percent"] = vm.percent
            data["ram_used"] = vm.used
            data["ram_total"] = vm.total
            data["swap_percent"] = swap.percent
            disk = psutil.disk_usage(os.path.abspath(os.sep))
            data["disk_percent"] = disk.percent
            data["disk_free"] = disk.free
            data["process_count"] = len(psutil.pids())
            freq = psutil.cpu_freq()
            data["cpu_freq_mhz"] = round(freq.current, 1) if freq else None
            try:
                data["load_1m"] = os.getloadavg()[0]
            except Exception:
                data["load_1m"] = None
            battery = psutil.sensors_battery()
            if battery:
                data["battery_percent"] = battery.percent
        except Exception as exc:
            LOGGER.warning("System telemetry error: %s", exc)

        for index, handle in enumerate(self.gpu_handles):
            gpu = {
                "index": index,
                "name": "GPU",
                "temperature": None,
                "utilization": None,
                "memory_used": None,
                "memory_total": None,
                "power_w": None,
                "fan_percent": None,
                "clock_mhz": None,
            }
            try:
                raw_name = pynvml.nvmlDeviceGetName(handle)
                gpu["name"] = (
                    raw_name.decode(errors="replace")
                    if isinstance(raw_name, bytes) else str(raw_name)
                )
            except Exception:
                pass
            try:
                gpu["temperature"] = pynvml.nvmlDeviceGetTemperature(
                    handle, pynvml.NVML_TEMPERATURE_GPU
                )
            except Exception:
                pass
            try:
                gpu["utilization"] = pynvml.nvmlDeviceGetUtilizationRates(handle).gpu
            except Exception:
                pass
            try:
                mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
                gpu["memory_used"] = mem.used
                gpu["memory_total"] = mem.total
            except Exception:
                pass
            try:
                gpu["power_w"] = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0
            except Exception:
                pass
            try:
                gpu["fan_percent"] = pynvml.nvmlDeviceGetFanSpeed(handle)
            except Exception:
                pass
            try:
                gpu["clock_mhz"] = pynvml.nvmlDeviceGetClockInfo(
                    handle, pynvml.NVML_CLOCK_GRAPHICS
                )
            except Exception:
                pass
            data["gpu"].append(gpu)

        return data

    def shutdown(self):
        if pynvml is not None and self.gpu_handles:
            try:
                pynvml.nvmlShutdown()
            except Exception:
                pass


# ------------------------------------------------
# PROCESS OBSERVER
# ------------------------------------------------

class ProcessObserver:
    def __init__(self, memory: MemoryStore):
        self.memory = memory

    def foreground(self) -> Optional[dict]:
        if not is_windows() or psutil is None:
            return None
        try:
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return None
            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            process = psutil.Process(pid.value)
            return {
                "pid": pid.value,
                "name": process.name(),
                "exe": safe_call(process.exe) or "",
            }
        except Exception:
            return None

    def top_processes(self, limit: int = 20, filter_text: str = "") -> list[dict]:
        if psutil is None:
            return []
        result = []
        needle = filter_text.strip().lower()
        for process in psutil.process_iter(
            ["pid", "name", "memory_info", "cpu_percent", "status"]
        ):
            try:
                info = process.info
                name = info.get("name") or "?"
                if needle and needle not in name.lower():
                    continue
                mem = info.get("memory_info")
                result.append({
                    "pid": info.get("pid"),
                    "name": name,
                    "rss": mem.rss if mem else 0,
                    "cpu": float(info.get("cpu_percent") or 0),
                    "status": info.get("status") or "?",
                })
            except Exception:
                continue
        return sorted(result, key=lambda item: item["rss"], reverse=True)[:limit]

    def inspect(self, pid: int) -> Optional[dict]:
        if psutil is None:
            return None
        try:
            process = psutil.Process(pid)
            with process.oneshot():
                return {
                    "pid": pid,
                    "name": process.name(),
                    "exe": safe_call(process.exe),
                    "status": process.status(),
                    "username": safe_call(process.username),
                    "create_time": process.create_time(),
                    "cpu_percent": process.cpu_percent(interval=0.05),
                    "memory": process.memory_info().rss,
                    "threads": process.num_threads(),
                }
        except Exception as exc:
            return {"pid": pid, "error": str(exc)}


# ------------------------------------------------
# LEARNING / ANOMALY ENGINE
# ------------------------------------------------

class PerformanceLearningEngine:
    """
    Lightweight learning based on measured telemetry, EMA baselines and
    standard-deviation anomaly detection. It does not pretend to be a
    neural network and never changes system settings by itself.
    """

    def __init__(self, memory: MemoryStore, config: Config):
        self.memory = memory
        self.config = config
        self.lock = threading.RLock()
        self.ema: dict[str, float] = {}
        self.variance: dict[str, float] = {}
        self.count = 0
        self.action_scores: dict[str, float] = {}

    def _metrics(self, telemetry: dict) -> dict[str, float]:
        gpu = telemetry.get("gpu") or []
        first = gpu[0] if gpu else {}
        return {
            "cpu": float(telemetry.get("cpu_percent") or 0),
            "ram": float(telemetry.get("ram_percent") or 0),
            "disk": float(telemetry.get("disk_percent") or 0),
            "swap": float(telemetry.get("swap_percent") or 0),
            "gpu": float(first.get("utilization") or 0),
            "gpu_temp": float(first.get("temperature") or 0),
            "gpu_power": float(first.get("power_w") or 0),
        }

    def update(self, telemetry: dict) -> dict:
        alpha = min(0.9, max(0.01, float(self.config.get("learning_alpha", 0.2))))
        sigma_limit = max(1.0, float(self.config.get("anomaly_sigma", 2.5)))
        metrics = self._metrics(telemetry)
        anomalies = {}

        with self.lock:
            self.count += 1
            for key, value in metrics.items():
                if key not in self.ema:
                    self.ema[key] = value
                    self.variance[key] = 0.0
                    continue
                old = self.ema[key]
                delta = value - old
                self.ema[key] = old + alpha * delta
                self.variance[key] = (
                    (1 - alpha) * self.variance[key] + alpha * delta * delta
                )
                std = max(self.variance[key] ** 0.5, 0.5)
                z = abs(delta) / std
                if self.count > 10 and z >= sigma_limit:
                    anomalies[key] = round(z, 2)

            baseline = dict(self.ema)

        if anomalies:
            self.memory.append_event("anomaly", {
                "metrics": anomalies,
                "baseline": baseline,
            })
        return {"anomalies": anomalies, "baseline": baseline}

    def recommendations(self) -> list[tuple[str, float]]:
        with self.lock:
            return sorted(
                self.action_scores.items(),
                key=lambda pair: pair[1],
                reverse=True,
            )[:10]

    def record_action(self, action: str, reward: float):
        with self.lock:
            old = self.action_scores.get(action, 0.0)
            alpha = float(self.config.get("learning_alpha", 0.2))
            self.action_scores[action] = old * (1 - alpha) + reward * alpha
        self.memory.record_action(action, "completed", reward)


# ------------------------------------------------
# WATCHDOG
# ------------------------------------------------

@dataclass
class Health:
    name: str
    state: str = "starting"
    last_ok: float = 0.0
    failures: int = 0
    recoveries: int = 0
    message: str = ""


class Watchdog:
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.health: dict[str, Health] = {}
        self.recoveries: dict[str, Callable] = {}
        self.lock = threading.RLock()
        self.max_recoveries = 3

    def register(self, name: str, recovery: Optional[Callable] = None):
        with self.lock:
            self.health[name] = Health(name=name, last_ok=now())
            if recovery:
                self.recoveries[name] = recovery

    def ok(self, name: str, message: str = ""):
        with self.lock:
            item = self.health.setdefault(name, Health(name))
            item.state = "healthy"
            item.last_ok = now()
            item.message = message

    def fail(self, name: str, error: BaseException | str):
        with self.lock:
            item = self.health.setdefault(name, Health(name))
            item.state = "degraded"
            item.failures += 1
            item.message = str(error)
            recovery = self.recoveries.get(name)
            can_recover = item.recoveries < self.max_recoveries
            if can_recover:
                item.recoveries += 1

        self.memory.append_event("watchdog_failure", {
            "subsystem": name,
            "error": str(error),
            "failures": item.failures,
        })

        if recovery and can_recover:
            try:
                recovery()
                self.ok(name, "Recovered automatically")
                self.memory.append_event(
                    "watchdog_recovery", {"subsystem": name}
                )
            except Exception as exc:
                LOGGER.error("Recovery failed for %s: %s", name, exc)

    def stale_check(self, timeout: float = 10.0):
        cutoff = now() - timeout
        with self.lock:
            stale = [
                name for name, item in self.health.items()
                if item.state == "healthy" and item.last_ok < cutoff
            ]
        for name in stale:
            self.fail(name, f"heartbeat stale > {timeout:.1f}s")

    def snapshot(self) -> dict:
        with self.lock:
            return {key: asdict(value) for key, value in self.health.items()}


# ------------------------------------------------
# ROLLBACK / TRANSACTION JOURNAL
# ------------------------------------------------

@dataclass
class RollbackEntry:
    id: str
    timestamp: float
    description: str
    action_type: str
    before: dict
    after: dict
    reversible: bool = True
    rolled_back: bool = False


class RollbackManager:
    def __init__(self, path: Path = ROLLBACK_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.entries: list[dict] = []
        self.load()

    def load(self):
        try:
            payload = json.loads(self.path.read_text(encoding="utf-8"))
            self.entries = payload if isinstance(payload, list) else []
        except Exception:
            self.entries = []

    def save(self):
        with self.lock:
            atomic_write_json(self.path, self.entries[-500:])

    def record(
        self, description: str, action_type: str,
        before: dict, after: dict, reversible: bool = True
    ) -> str:
        entry = RollbackEntry(
            id=uuid.uuid4().hex[:12],
            timestamp=now(),
            description=description,
            action_type=action_type,
            before=before,
            after=after,
            reversible=reversible,
        )
        with self.lock:
            self.entries.append(asdict(entry))
            self.save()
        return entry.id

    def available(self) -> list[dict]:
        with self.lock:
            return [
                item for item in reversed(self.entries)
                if item.get("reversible") and not item.get("rolled_back")
            ]

    def mark_rolled_back(self, entry_id: str) -> bool:
        with self.lock:
            for item in self.entries:
                if item.get("id") == entry_id:
                    item["rolled_back"] = True
                    self.save()
                    return True
        return False


# ------------------------------------------------
# SAFE OPTIMIZATION ENGINE
# ------------------------------------------------

class OptimizationEngine:
    """
    Only application-owned, low-risk actions are permitted autonomously.
    """

    LOW_RISK = {
        "refresh_process_snapshot",
        "recalculate_telemetry",
        "prune_history",
        "clear_python_cache",
    }

    def __init__(
        self, config: Config, memory: MemoryStore,
        rollback: RollbackManager, recovery: RecoveryManager
    ):
        self.config = config
        self.memory = memory
        self.rollback = rollback
        self.recovery = recovery

    def can_execute(self, action: str, automatic: bool = False) -> bool:
        mode = self.config.get("mode", "assist")
        if mode == "safe":
            return False
        if automatic:
            return mode == "autonomous" and action in self.LOW_RISK
        return action in self.LOW_RISK or mode != "safe"

    def execute(self, action: str) -> tuple[bool, str]:
        if not self.can_execute(action):
            return False, f"Blocked by operating mode: {self.config.get('mode')}"

        try:
            if action == "refresh_process_snapshot":
                self.memory.append_event("optimization", {"action": action})
                return True, "Process snapshot refreshed"

            if action == "recalculate_telemetry":
                self.memory.append_event("optimization", {"action": action})
                return True, "Telemetry recalculation requested"

            if action == "prune_history":
                before = {"retention": self.config.get("history_retention", 5000)}
                self.memory.prune(before["retention"])
                rid = self.rollback.record(
                    "Prune application history", "database_maintenance",
                    before, {"retention": before["retention"]}
                )
                self.memory.append_event(
                    "optimization", {"action": action, "rollback_id": rid}
                )
                return True, "History pruned"

            if action == "clear_python_cache":
                removed = 0
                targets = [BASE_DIR]
                for root in targets:
                    for path in root.rglob("__pycache__"):
                        try:
                            if DATA_DIR in path.parents:
                                continue
                            shutil.rmtree(path)
                            removed += 1
                        except Exception:
                            continue
                rid = self.rollback.record(
                    "Clear Python cache directories",
                    "filesystem_cleanup",
                    {"removed": 0},
                    {"removed": removed},
                    reversible=False,
                )
                self.memory.append_event(
                    "optimization",
                    {"action": action, "removed": removed, "journal_id": rid},
                )
                return True, f"Removed {removed} Python cache directories"

            return False, "Unknown action"
        except Exception as exc:
            log_exception(f"Optimization {action} failed", exc)
            return False, str(exc)


# ------------------------------------------------
# BENCHMARK ENGINE
# ------------------------------------------------

class BenchmarkEngine:
    def __init__(
        self, telemetry: HardwareTelemetry, memory: MemoryStore,
        learning: PerformanceLearningEngine
    ):
        self.telemetry = telemetry
        self.memory = memory
        self.learning = learning
        self.running = False
        self.lock = threading.Lock()

    def sample(self, seconds: int = 5, interval: float = 0.5) -> list[dict]:
        seconds = max(1, min(300, int(seconds)))
        samples = []
        self.running = True
        deadline = now() + seconds
        try:
            while now() < deadline and self.running:
                samples.append(self.telemetry.snapshot())
                time.sleep(interval)
        finally:
            self.running = False
        return samples

    @staticmethod
    def summarize(samples: list[dict]) -> dict:
        if not samples:
            return {}

        cpu = [float(x.get("cpu_percent") or 0) for x in samples]
        ram = [float(x.get("ram_percent") or 0) for x in samples]
        gpu = []
        temps = []
        powers = []

        for sample in samples:
            cards = sample.get("gpu") or []
            if cards:
                card = cards[0]
                if card.get("utilization") is not None:
                    gpu.append(float(card["utilization"]))
                if card.get("temperature") is not None:
                    temps.append(float(card["temperature"]))
                if card.get("power_w") is not None:
                    powers.append(float(card["power_w"]))

        def stats(values):
            if not values:
                return None
            return {
                "avg": round(statistics.fmean(values), 2),
                "min": round(min(values), 2),
                "max": round(max(values), 2),
            }

        return {
            "samples": len(samples),
            "cpu": stats(cpu),
            "ram": stats(ram),
            "gpu": stats(gpu),
            "gpu_temperature": stats(temps),
            "gpu_power": stats(powers),
        }

    def cpu_compute_benchmark(self, seconds: int = 2) -> dict:
        seconds = max(1, min(20, seconds))
        start = time.perf_counter()
        deadline = start + seconds
        loops = 0
        accumulator = 0.0
        while time.perf_counter() < deadline:
            for i in range(2000):
                accumulator += (i * 1.000001) ** 0.5
            loops += 2000
        elapsed = max(time.perf_counter() - start, 1e-9)
        return {
            "seconds": round(elapsed, 4),
            "operations_estimate": loops,
            "ops_per_second_estimate": round(loops / elapsed, 2),
            "checksum": round(accumulator % 1000, 3),
        }

    def cuda_benchmark(self, seconds: int = 2) -> dict:
        if torch is None or not torch.cuda.is_available():
            return {"available": False, "reason": "CUDA/PyTorch unavailable"}

        try:
            device = torch.device("cuda")
            x = torch.randn((2048, 2048), device=device)
            y = torch.randn((2048, 2048), device=device)
            torch.cuda.synchronize()
            start = time.perf_counter()
            iterations = 0
            deadline = start + max(1, min(20, seconds))
            while time.perf_counter() < deadline:
                _ = torch.mm(x, y)
                iterations += 1
            torch.cuda.synchronize()
            elapsed = max(time.perf_counter() - start, 1e-9)
            # Matrix multiply is ~2*N^3 floating point operations.
            flops = iterations * 2 * (2048 ** 3)
            return {
                "available": True,
                "seconds": round(elapsed, 4),
                "iterations": iterations,
                "estimated_flops": int(flops),
                "estimated_gflops": round(flops / elapsed / 1e9, 2),
                "device": torch.cuda.get_device_name(0),
            }
        except Exception as exc:
            return {"available": False, "reason": str(exc)}

    def run(self, label: str = "Baseline", seconds: int = 5) -> dict:
        before = self.summarize(self.sample(seconds))
        cpu = self.cpu_compute_benchmark(min(3, max(1, seconds // 2)))
        cuda = self.cuda_benchmark(min(3, max(1, seconds // 2)))
        result = {
            "label": label,
            "telemetry": before,
            "cpu_benchmark": cpu,
            "cuda_benchmark": cuda,
        }
        self.memory.record_benchmark(
            label, before, result, 0.0, "Measured baseline; no tuning applied"
        )
        self.memory.append_event("benchmark", result)
        return result


# ------------------------------------------------
# PLUGIN MANAGER
# ------------------------------------------------

PLUGIN_PERMISSIONS = {
    "READ_SYSTEM",
    "READ_GPU",
    "READ_PROCESSES",
    "WRITE_CONFIG",
    "NETWORK",
    "FILE_WRITE",
    "PROCESS_CONTROL",
}


class PluginManager:
    """
    Python plugins are NOT a security sandbox. They can execute arbitrary
    Python if loaded. Hash approval and permission manifests provide
    governance and visibility, not isolation.
    """

    def __init__(self, config: Config, memory: MemoryStore):
        self.config = config
        self.memory = memory
        self.plugins: dict[str, Any] = {}
        self.manifest = self._load_manifest()
        self.scan()

    def _load_manifest(self) -> dict:
        try:
            data = json.loads(
                PLUGIN_MANIFEST_PATH.read_text(encoding="utf-8")
            )
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_manifest(self):
        atomic_write_json(PLUGIN_MANIFEST_PATH, self.manifest)

    @staticmethod
    def _hash_file(path: Path) -> str:
        digest = hashlib.sha256()
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(65536), b""):
                digest.update(chunk)
        return digest.hexdigest()

    def scan(self):
        changed = False
        for path in PLUGIN_DIR.glob("*.py"):
            try:
                digest = self._hash_file(path)
                item = self.manifest.setdefault(
                    path.name,
                    {
                        "enabled": False,
                        "approved_hash": digest,
                        "permissions": [],
                    },
                )
                if item.get("approved_hash") != digest:
                    item["enabled"] = False
                    item["approved_hash"] = digest
                    changed = True
                    LOGGER.warning(
                        "Plugin changed and was disabled: %s", path.name
                    )
            except Exception as exc:
                LOGGER.warning("Plugin scan failed: %s", exc)
        if changed or not PLUGIN_MANIFEST_PATH.exists():
            self._save_manifest()

    def list_plugins(self) -> list[dict]:
        return [
            {
                "name": name,
                "enabled": bool(item.get("enabled")),
                "permissions": item.get("permissions", []),
                "approved_hash": item.get("approved_hash", ""),
            }
            for name, item in sorted(self.manifest.items())
        ]

    def approve(self, name: str, permissions: list[str]) -> bool:
        path = PLUGIN_DIR / name
        if not path.exists():
            return False
        digest = self._hash_file(path)
        self.manifest[name] = {
            "enabled": False,
            "approved_hash": digest,
            "permissions": [
                item for item in permissions if item in PLUGIN_PERMISSIONS
            ],
        }
        self._save_manifest()
        return True

    def set_enabled(self, name: str, enabled: bool) -> bool:
        if name not in self.manifest:
            return False
        if enabled:
            current = self._hash_file(PLUGIN_DIR / name)
            if current != self.manifest[name].get("approved_hash"):
                return False
        self.manifest[name]["enabled"] = bool(enabled)
        self._save_manifest()
        return True

    def load_enabled(self):
        self.unload_all()
        for name, item in self.manifest.items():
            if not item.get("enabled"):
                continue
            path = PLUGIN_DIR / name
            if not path.exists():
                continue
            try:
                if self._hash_file(path) != item.get("approved_hash"):
                    continue
                spec = importlib.util.spec_from_file_location(
                    f"psai_plugin_{path.stem}", path
                )
                if not spec or not spec.loader:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.plugins[name] = module
                self.memory.append_event(
                    "plugin_loaded",
                    {"name": name, "permissions": item.get("permissions", [])},
                )
            except Exception as exc:
                LOGGER.error("Plugin failed: %s: %s", name, exc)

    def unload_all(self):
        self.plugins.clear()


# ------------------------------------------------
# CORE ENGINE
# ------------------------------------------------

class CoreEngine:
    def __init__(
        self, config: Config, memory: MemoryStore, watchdog: Watchdog,
        telemetry: HardwareTelemetry, processes: ProcessObserver,
        learning: PerformanceLearningEngine, benchmark: BenchmarkEngine,
        optimizer: OptimizationEngine, plugins: PluginManager
    ):
        self.config = config
        self.memory = memory
        self.watchdog = watchdog
        self.telemetry = telemetry
        self.processes = processes
        self.learning = learning
        self.benchmark = benchmark
        self.optimizer = optimizer
        self.plugins = plugins
        self.running = False
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()
        self.latest: dict = {}
        self.foreground = None
        self.learning_state = {}
        self.started = now()

    def start(self):
        if self.running:
            return
        self.stop_event.clear()
        self.running = True
        self.started = now()
        self.thread = threading.Thread(
            target=self.loop, name="PSAI-Core", daemon=True
        )
        self.thread.start()
        LOGGER.info("Core engine started")

    def stop(self):
        self.running = False
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)

    def loop(self):
        while not self.stop_event.is_set():
            started = now()
            try:
                self.latest = self.telemetry.snapshot()
                self.memory.append_telemetry(self.latest)
                self.watchdog.ok("telemetry")

                self.learning_state = self.learning.update(self.latest)
                self.watchdog.ok("learning")

                self.foreground = self.processes.foreground()
                self.watchdog.ok("process_observer")

                ram = self.latest.get("ram_percent", 0)
                if (
                    self.config.get("mode") == "autonomous"
                    and self.config.get("autonomous_memory_pressure", True)
                    and ram >= 92
                ):
                    self.optimizer.execute("refresh_process_snapshot")

                if int(now()) % 30 == 0:
                    self.memory.prune(self.config.get("history_retention", 5000))

                self.watchdog.ok("core")
            except Exception as exc:
                log_exception("Core loop error", exc)
                self.watchdog.fail("core", exc)

            elapsed = now() - started
            interval = max(1.0, float(self.config.get("telemetry_interval", 2)))
            self.stop_event.wait(max(0.05, interval - elapsed))

    def status(self) -> dict:
        return {
            "uptime": now() - self.started,
            "mode": self.config.get("mode"),
            "telemetry": self.latest,
            "foreground": self.foreground,
            "learning": self.learning_state,
            "health": self.watchdog.snapshot(),
        }


# ------------------------------------------------
# STARTUP STATE / CRASH GUARD
# ------------------------------------------------

def write_startup_state(state: str, details: str = ""):
    atomic_write_json(
        STARTUP_STATE_PATH,
        {
            "state": state,
            "details": details,
            "timestamp": now(),
            "app_version": APP_VERSION,
        },
    )


def install_exception_hook():
    def hook(exc_type, exc_value, exc_tb):
        LOGGER.error(
            "Unhandled exception:\n%s",
            "".join(traceback.format_exception(exc_type, exc_value, exc_tb)),
        )
        write_startup_state("crashed", str(exc_value))
        sys.__excepthook__(exc_type, exc_value, exc_tb)
    sys.excepthook = hook


# ------------------------------------------------
# DIAGNOSTICS
# ------------------------------------------------

def diagnostics(service: Optional["Service"] = None) -> dict:
    report = {
        "app": f"{APP_NAME} {APP_VERSION}",
        "python": platform.python_version(),
        "platform": platform.platform(),
        "system": platform.system(),
        "release": platform.release(),
        "machine": platform.machine(),
        "processor": platform.processor(),
        "admin": is_admin(),
        "qt_available": QT_AVAILABLE,
        "dependencies": detect_dependencies(),
        "data_dir": str(DATA_DIR),
        "plugin_dir": str(PLUGIN_DIR),
        "secure_store_backend": (
            service.credentials.backend if service else
            ("keyring" if keyring else "dpapi" if is_windows() else "unavailable")
        ),
        "gpu_backend": (
            service.telemetry.gpu_backend if service else
            ("NVML" if pynvml else "unavailable")
        ),
    }
    if service:
        report["config"] = service.config.snapshot()
        report["health"] = service.watchdog.snapshot()
        report["core_running"] = service.core.running
        report["gpu_count"] = len(service.telemetry.gpu_handles)
    return report


def export_diagnostics(service: "Service", path: Path) -> Path:
    payload = {
        "generated": now(),
        "diagnostics": diagnostics(service),
        "status": service.core.status(),
        "recent_events": service.memory.recent_events(250),
        "benchmarks": service.memory.benchmarks(50),
        "plugins": service.plugins.list_plugins(),
        "rollback": service.rollback.available(),
    }
    atomic_write_json(path, payload)
    return path


# ------------------------------------------------
# SERVICE CONTAINER
# ------------------------------------------------

class Service:
    def __init__(self, force_safe_mode: bool = False):
        self.config = Config()
        if force_safe_mode:
            self.config.set("mode", "safe")
            self.config.set("startup_safe_mode", True)

        self.memory = MemoryStore()
        self.recovery = RecoveryManager(self.config)
        self.rollback = RollbackManager()
        self.credentials = SecureCredentialStore()
        self.telemetry = HardwareTelemetry()
        self.processes = ProcessObserver(self.memory)
        self.learning = PerformanceLearningEngine(self.memory, self.config)
        self.benchmark = BenchmarkEngine(
            self.telemetry, self.memory, self.learning
        )
        self.plugins = PluginManager(self.config, self.memory)
        self.watchdog = Watchdog(self.memory)
        self.optimizer = OptimizationEngine(
            self.config, self.memory, self.rollback, self.recovery
        )
        self.core = CoreEngine(
            self.config, self.memory, self.watchdog,
            self.telemetry, self.processes, self.learning,
            self.benchmark, self.optimizer, self.plugins
        )

        self.watchdog.register("core")
        self.watchdog.register("telemetry")
        self.watchdog.register("learning")
        self.watchdog.register("process_observer")
        self.watchdog.register("plugin_host", self.plugins.load_enabled)

    def start(self):
        LOGGER.info("%s v%s starting", APP_NAME, APP_VERSION)
        LOGGER.info("Diagnostics: %s", safe_json(diagnostics(self)))
        write_startup_state("starting")

        # Plugins are deliberately not loaded in safe mode.
        if self.config.get("mode") != "safe":
            try:
                self.plugins.load_enabled()
                self.watchdog.ok("plugin_host")
            except Exception as exc:
                self.watchdog.fail("plugin_host", exc)

        self.core.start()
        write_startup_state("running")

    def stop(self):
        try:
            self.core.stop()
            self.plugins.unload_all()
            self.telemetry.shutdown()
            self.memory.close()
            write_startup_state("stopped")
        except Exception as exc:
            LOGGER.error("Shutdown error: %s", exc)


# ------------------------------------------------
# QT FRONTEND
# ------------------------------------------------

if QT_AVAILABLE:

    class MainWindow(QMainWindow):
        def __init__(self, service: Service):
            super().__init__()
            self.service = service
            self.setWindowTitle(
                f"{APP_NAME} — Next-Gen v{APP_VERSION}"
            )
            self.resize(
                int(service.config.get("window_width", 1060)),
                int(service.config.get("window_height", 700)),
            )
            self.setMinimumSize(860, 560)
            self._build()
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.refresh_all)
            self.timer.start(1500)
            self.refresh_all()

        def closeEvent(self, event):
            self.service.config.set("window_width", self.width())
            self.service.config.set("window_height", self.height())
            self.service.stop()
            event.accept()

        def _build(self):
            root_widget = QWidget()
            root = QVBoxLayout(root_widget)
            root.setContentsMargins(8, 8, 8, 8)
            root.setSpacing(6)

            header = QHBoxLayout()
            title = QLabel(
                f"<b>{APP_NAME}</b> "
                f"<span style='color:#888'>v{APP_VERSION}</span>"
            )
            header.addWidget(title)
            header.addStretch()

            header.addWidget(QLabel("Mode:"))
            self.mode_combo = QComboBox()
            self.mode_combo.addItems(["safe", "assist", "autonomous"])
            self.mode_combo.setCurrentText(
                self.service.config.get("mode", "assist")
            )
            self.mode_combo.currentTextChanged.connect(self.change_mode)
            header.addWidget(self.mode_combo)

            self.status_label = QLabel("● Starting")
            header.addWidget(self.status_label)
            root.addLayout(header)

            self.tabs = QTabWidget()
            self.tabs.addTab(self.dashboard_tab(), "Dashboard")
            self.tabs.addTab(self.ai_tab(), "Learning")
            self.tabs.addTab(self.performance_tab(), "Performance")
            self.tabs.addTab(self.hardware_tab(), "Hardware")
            self.tabs.addTab(self.process_tab(), "Processes")
            self.tabs.addTab(self.security_tab(), "Security")
            self.tabs.addTab(self.plugins_tab(), "Plugins")
            self.tabs.addTab(self.events_tab(), "Events")
            self.tabs.addTab(self.recovery_tab(), "Recovery")
            self.tabs.addTab(self.settings_tab(), "Settings")
            root.addWidget(self.tabs)

            self.setCentralWidget(root_widget)

        @staticmethod
        def group(title: str):
            box = QGroupBox(title)
            layout = QVBoxLayout(box)
            layout.setContentsMargins(7, 7, 7, 7)
            return box, layout

        def dashboard_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            cards = QGridLayout()
            cards.setSpacing(6)

            self.card_labels = {}
            for index, name in enumerate(
                ["CPU", "RAM", "DISK", "GPU", "VRAM", "GPU TEMP"]
            ):
                box, box_layout = self.group(name)
                label = QLabel("--")
                label.setStyleSheet("font-size:19px; font-weight:bold;")
                box_layout.addWidget(label)
                self.card_labels[name] = label
                cards.addWidget(box, index // 3, index % 3)

            layout.addLayout(cards)

            info = QGridLayout()
            self.foreground_label = QLabel("Foreground: --")
            self.state_label = QLabel("System state: --")
            self.health_label = QLabel("Health: --")
            self.anomaly_label = QLabel("Anomalies: --")
            info.addWidget(self.foreground_label, 0, 0)
            info.addWidget(self.state_label, 0, 1)
            info.addWidget(self.health_label, 1, 0)
            info.addWidget(self.anomaly_label, 1, 1)
            layout.addLayout(info)

            buttons = QHBoxLayout()
            for text, slot in (
                ("Run Benchmark", self.run_benchmark),
                ("Refresh Diagnostics", self.refresh_diagnostics),
                ("Safe Cleanup", lambda: self.run_action("clear_python_cache")),
                ("Prune History", lambda: self.run_action("prune_history")),
            ):
                button = QPushButton(text)
                button.clicked.connect(slot)
                buttons.addWidget(button)
            layout.addLayout(buttons)

            self.dashboard_log = QTextEdit()
            self.dashboard_log.setReadOnly(True)
            self.dashboard_log.setMaximumHeight(130)
            layout.addWidget(self.dashboard_log)
            return widget

        def ai_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            self.ai_box = QTextEdit()
            self.ai_box.setReadOnly(True)
            layout.addWidget(self.ai_box)
            layout.addWidget(QLabel(
                "Learning is based on measured telemetry and EMA/anomaly statistics. "
                "It does not claim that every high-usage condition is bad."
            ))
            return widget

        def performance_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            buttons = QHBoxLayout()
            run = QPushButton("Run Full Benchmark")
            run.clicked.connect(self.run_benchmark)
            stop = QPushButton("Stop Benchmark")
            stop.clicked.connect(lambda: setattr(self.service.benchmark, "running", False))
            buttons.addWidget(run)
            buttons.addWidget(stop)
            layout.addLayout(buttons)
            self.benchmark_progress = QProgressBar()
            self.benchmark_progress.setRange(0, 0)
            self.benchmark_progress.setVisible(False)
            layout.addWidget(self.benchmark_progress)
            self.benchmark_box = QTextEdit()
            self.benchmark_box.setReadOnly(True)
            layout.addWidget(self.benchmark_box)
            return widget

        def hardware_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            self.hardware_box = QTextEdit()
            self.hardware_box.setReadOnly(True)
            layout.addWidget(self.hardware_box)
            return widget

        def process_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)

            controls = QHBoxLayout()
            self.process_filter = QLineEdit()
            self.process_filter.setPlaceholderText("Filter process name...")
            controls.addWidget(self.process_filter)
            refresh = QPushButton("Refresh")
            refresh.clicked.connect(self.refresh_processes)
            controls.addWidget(refresh)
            inspect = QPushButton("Inspect Selected")
            inspect.clicked.connect(self.inspect_selected_process)
            controls.addWidget(inspect)
            layout.addLayout(controls)

            self.process_table = QTableWidget(0, 5)
            self.process_table.setHorizontalHeaderLabels(
                ["PID", "Process", "RAM", "CPU %", "Status"]
            )
            self.process_table.horizontalHeader().setSectionResizeMode(
                1, QHeaderView.Stretch
            )
            layout.addWidget(self.process_table)
            self.process_detail = QTextEdit()
            self.process_detail.setReadOnly(True)
            self.process_detail.setMaximumHeight(150)
            layout.addWidget(self.process_detail)
            return widget

        def security_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            layout.addWidget(QLabel(
                "<b>Secure credential store</b><br>"
                "Backend: " + self.service.credentials.backend +
                "<br>Secrets are excluded from telemetry and event history."
            ))

            form = QGridLayout()
            self.cred_name = QLineEdit("default")
            self.cred_user = QLineEdit()
            self.cred_pass = QLineEdit()
            self.cred_pass.setEchoMode(QLineEdit.Password)

            save = QPushButton("Save")
            save.clicked.connect(self.save_credential)
            delete = QPushButton("Delete")
            delete.clicked.connect(self.delete_credential)

            form.addWidget(QLabel("Name"), 0, 0)
            form.addWidget(self.cred_name, 0, 1)
            form.addWidget(QLabel("Username"), 1, 0)
            form.addWidget(self.cred_user, 1, 1)
            form.addWidget(QLabel("Password"), 2, 0)
            form.addWidget(self.cred_pass, 2, 1)
            form.addWidget(save, 3, 0)
            form.addWidget(delete, 3, 1)
            layout.addLayout(form)

            layout.addWidget(QLabel("Application rollback journal"))
            self.rollback_box = QTextEdit()
            self.rollback_box.setReadOnly(True)
            layout.addWidget(self.rollback_box)
            return widget

        def plugins_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            self.plugin_table = QTableWidget(0, 4)
            self.plugin_table.setHorizontalHeaderLabels(
                ["Plugin", "Enabled", "Permissions", "Approved hash"]
            )
            self.plugin_table.horizontalHeader().setSectionResizeMode(
                0, QHeaderView.Stretch
            )
            layout.addWidget(self.plugin_table)

            controls = QHBoxLayout()
            scan = QPushButton("Rescan")
            scan.clicked.connect(self.refresh_plugins)
            approve = QPushButton("Approve Selected")
            approve.clicked.connect(self.approve_selected_plugin)
            toggle = QPushButton("Enable / Disable")
            toggle.clicked.connect(self.toggle_selected_plugin)
            controls.addWidget(scan)
            controls.addWidget(approve)
            controls.addWidget(toggle)
            layout.addLayout(controls)

            layout.addWidget(QLabel(
                "Important: Python plugins are not a true sandbox. "
                "Treat enabled plugins as trusted code."
            ))
            return widget

        def events_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            controls = QHBoxLayout()
            refresh = QPushButton("Refresh")
            refresh.clicked.connect(self.refresh_events)
            export = QPushButton("Export Diagnostics")
            export.clicked.connect(self.export_report)
            controls.addWidget(refresh)
            controls.addWidget(export)
            layout.addLayout(controls)
            self.events_box = QTextEdit()
            self.events_box.setReadOnly(True)
            layout.addWidget(self.events_box)
            return widget

        def recovery_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)
            controls = QHBoxLayout()
            snapshot = QPushButton("Create Config Snapshot")
            snapshot.clicked.connect(self.create_snapshot)
            restore = QPushButton("Restore Selected")
            restore.clicked.connect(self.restore_selected_snapshot)
            controls.addWidget(snapshot)
            controls.addWidget(restore)
            layout.addLayout(controls)

            self.snapshot_list = QTableWidget(0, 2)
            self.snapshot_list.setHorizontalHeaderLabels(["Snapshot", "Created"])
            self.snapshot_list.horizontalHeader().setSectionResizeMode(
                0, QHeaderView.Stretch
            )
            layout.addWidget(self.snapshot_list)
            layout.addWidget(QLabel(
                "Rollback applies to application-owned configuration and journals. "
                "It does not make arbitrary Windows changes magically reversible."
            ))
            return widget

        def settings_tab(self):
            widget = QWidget()
            layout = QVBoxLayout(widget)

            grid = QGridLayout()
            self.interval_spin = QSpinBox()
            self.interval_spin.setRange(1, 60)
            self.interval_spin.setValue(
                int(self.service.config.get("telemetry_interval", 2))
            )
            grid.addWidget(QLabel("Telemetry interval (s)"), 0, 0)
            grid.addWidget(self.interval_spin, 0, 1)

            self.duration_spin = QSpinBox()
            self.duration_spin.setRange(1, 60)
            self.duration_spin.setValue(
                int(self.service.config.get("benchmark_duration", 5))
            )
            grid.addWidget(QLabel("Benchmark duration (s)"), 1, 0)
            grid.addWidget(self.duration_spin, 1, 1)

            save = QPushButton("Save Settings")
            save.clicked.connect(self.save_settings)
            grid.addWidget(save, 2, 0, 1, 2)
            layout.addLayout(grid)

            self.settings_box = QTextEdit()
            self.settings_box.setReadOnly(True)
            layout.addWidget(self.settings_box)
            return widget

        # ---------- GUI actions ----------

        def change_mode(self, mode: str):
            if mode not in {"safe", "assist", "autonomous"}:
                return
            self.service.config.set("mode", mode)
            if mode == "safe":
                self.service.plugins.unload_all()
            elif not self.service.plugins.plugins:
                self.service.plugins.load_enabled()
            self.dashboard_log.append(f"[MODE] {mode}")

        def run_action(self, action: str):
            ok, message = self.service.optimizer.execute(action)
            self.dashboard_log.append(
                f"[{'OK' if ok else 'BLOCKED'}] {message}"
            )

        def run_benchmark(self):
            if self.service.benchmark.running:
                return
            self.benchmark_progress.setVisible(True)
            self.benchmark_box.setPlainText("Benchmark running...")
            seconds = int(self.service.config.get("benchmark_duration", 5))

            def worker():
                try:
                    result = self.service.benchmark.run("User benchmark", seconds)
                    text = json.dumps(result, indent=2, default=str)
                    QTimer.singleShot(0, lambda: self.finish_benchmark(text))
                except Exception as exc:
                    text = f"Benchmark failed: {exc}"
                    QTimer.singleShot(0, lambda: self.finish_benchmark(text))

            threading.Thread(target=worker, daemon=True).start()

        def finish_benchmark(self, text: str):
            self.benchmark_progress.setVisible(False)
            self.benchmark_box.setPlainText(text)
            self.dashboard_log.append("[BENCHMARK] Completed")

        def refresh_diagnostics(self):
            self.settings_box.setPlainText(
                json.dumps(diagnostics(self.service), indent=2, default=str)
            )

        def save_credential(self):
            ok = self.service.credentials.set(
                self.cred_name.text().strip(),
                self.cred_user.text(),
                self.cred_pass.text(),
            )
            self.cred_pass.clear()
            QMessageBox.information(
                self, "Credential Store",
                "Saved securely." if ok else "Save failed."
            )

        def delete_credential(self):
            self.service.credentials.delete(self.cred_name.text().strip())
            self.cred_pass.clear()

        def refresh_processes(self):
            rows = self.service.processes.top_processes(
                30, self.process_filter.text()
            )
            self.process_table.setRowCount(len(rows))
            for row, item in enumerate(rows):
                values = [
                    str(item["pid"]),
                    item["name"],
                    human_bytes(item["rss"]),
                    f"{item['cpu']:.1f}",
                    item["status"],
                ]
                for col, value in enumerate(values):
                    self.process_table.setItem(
                        row, col, QTableWidgetItem(value)
                    )

        def inspect_selected_process(self):
            row = self.process_table.currentRow()
            if row < 0:
                return
            pid_item = self.process_table.item(row, 0)
            if not pid_item:
                return
            try:
                pid = int(pid_item.text())
            except ValueError:
                return
            detail = self.service.processes.inspect(pid)
            self.process_detail.setPlainText(
                json.dumps(detail or {}, indent=2, default=str)
            )

        def refresh_plugins(self):
            self.service.plugins.scan()
            rows = self.service.plugins.list_plugins()
            self.plugin_table.setRowCount(len(rows))
            for row, item in enumerate(rows):
                self.plugin_table.setItem(row, 0, QTableWidgetItem(item["name"]))
                self.plugin_table.setItem(
                    row, 1, QTableWidgetItem("YES" if item["enabled"] else "NO")
                )
                self.plugin_table.setItem(
                    row, 2, QTableWidgetItem(
                        ", ".join(item["permissions"])
                    )
                )
                self.plugin_table.setItem(
                    row, 3, QTableWidgetItem(item["approved_hash"][:16] + "...")
                )

        def approve_selected_plugin(self):
            row = self.plugin_table.currentRow()
            if row < 0:
                return
            name = self.plugin_table.item(row, 0).text()
            if self.service.plugins.approve(name, []):
                self.dashboard_log.append(f"[PLUGIN] Approved hash for {name}")
                self.refresh_plugins()

        def toggle_selected_plugin(self):
            row = self.plugin_table.currentRow()
            if row < 0:
                return
            name = self.plugin_table.item(row, 0).text()
            current = self.service.plugins.manifest.get(name, {}).get("enabled", False)
            if self.service.plugins.set_enabled(name, not current):
                self.service.plugins.load_enabled()
                self.refresh_plugins()

        def refresh_events(self):
            events = self.service.memory.recent_events(120)
            lines = []
            for event in reversed(events):
                stamp = time.strftime(
                    "%H:%M:%S", time.localtime(event["ts"])
                )
                lines.append(
                    f"{stamp} [{event['category']}] "
                    f"{safe_json(event['payload'])}"
                )
            self.events_box.setPlainText("\n".join(lines))

        def export_report(self):
            path, _ = QFileDialog.getSaveFileName(
                self, "Export Diagnostics", "psai_diagnostics.json",
                "JSON Files (*.json)"
            )
            if path:
                export_diagnostics(self.service, Path(path))
                QMessageBox.information(
                    self, "Export", "Diagnostics exported successfully."
                )

        def create_snapshot(self):
            path = self.service.recovery.create_snapshot("manual")
            self.dashboard_log.append(f"[RECOVERY] {path.name}")
            self.refresh_snapshots()

        def refresh_snapshots(self):
            snapshots = self.service.recovery.list_snapshots()
            self.snapshot_list.setRowCount(len(snapshots))
            for row, path in enumerate(snapshots):
                self.snapshot_list.setItem(row, 0, QTableWidgetItem(path.name))
                stamp = time.strftime(
                    "%Y-%m-%d %H:%M:%S",
                    time.localtime(path.stat().st_mtime)
                )
                self.snapshot_list.setItem(row, 1, QTableWidgetItem(stamp))

        def restore_selected_snapshot(self):
            row = self.snapshot_list.currentRow()
            if row < 0:
                return
            name = self.snapshot_list.item(row, 0).text()
            path = BACKUP_DIR / name
            answer = QMessageBox.question(
                self, "Restore Configuration",
                "Create a safety snapshot and restore this configuration?",
            )
            if answer != QMessageBox.Yes:
                return
            ok, message = self.service.recovery.restore(path)
            QMessageBox.information(self, "Recovery", message)
            if ok:
                self.mode_combo.setCurrentText(
                    self.service.config.get("mode", "assist")
                )

        def save_settings(self):
            self.service.recovery.create_snapshot("before-settings")
            self.service.config.set(
                "telemetry_interval", self.interval_spin.value()
            )
            self.service.config.set(
                "benchmark_duration", self.duration_spin.value()
            )
            self.dashboard_log.append("[SETTINGS] Saved")

        # ---------- refresh ----------

        def refresh_all(self):
            try:
                status = self.service.core.status()
                telemetry = status.get("telemetry") or {}
                cards = self.card_labels

                cards["CPU"].setText(f"{telemetry.get('cpu_percent', 0):.1f}%")
                cards["RAM"].setText(f"{telemetry.get('ram_percent', 0):.1f}%")
                cards["DISK"].setText(f"{telemetry.get('disk_percent', 0):.1f}%")

                cards["GPU"].setText("N/A")
                cards["VRAM"].setText("N/A")
                cards["GPU TEMP"].setText("N/A")

                gpu = telemetry.get("gpu") or []
                if gpu:
                    card = gpu[0]
                    cards["GPU"].setText(
                        "--" if card.get("utilization") is None
                        else f"{card['utilization']}%"
                    )
                    if card.get("memory_total"):
                        cards["VRAM"].setText(
                            f"{human_bytes(card.get('memory_used'))}/"
                            f"{human_bytes(card.get('memory_total'))}"
                        )
                    if card.get("temperature") is not None:
                        cards["GPU TEMP"].setText(
                            f"{card['temperature']}°C"
                        )

                fg = status.get("foreground")
                self.foreground_label.setText(
                    f"Foreground: {fg['name']} (PID {fg['pid']})"
                    if fg else "Foreground: --"
                )
                self.state_label.setText(
                    f"System state: {self.pressure_state(telemetry)}"
                )

                health = status.get("health", {})
                bad = [
                    name for name, item in health.items()
                    if item.get("state") != "healthy"
                ]
                self.health_label.setText(
                    "Health: OK" if not bad
                    else "Health: Degraded — " + ", ".join(bad)
                )

                anomalies = (
                    status.get("learning", {})
                    .get("anomalies", {})
                )
                self.anomaly_label.setText(
                    "Anomalies: none"
                    if not anomalies
                    else "Anomalies: " + ", ".join(anomalies)
                )

                self.status_label.setText(
                    "● Running" if self.service.core.running
                    else "● Stopped"
                )
                self.hardware_box.setPlainText(
                    json.dumps(telemetry, indent=2, default=str)
                )

                learning = status.get("learning", {})
                recommendations = self.service.learning.recommendations()
                self.ai_box.setPlainText(
                    "CURRENT MODE: " + str(status.get("mode")) +
                    "\n\nEMA BASELINE:\n" +
                    json.dumps(
                        learning.get("baseline", {}),
                        indent=2, default=str
                    ) +
                    "\n\nANOMALIES:\n" +
                    json.dumps(
                        learning.get("anomalies", {}),
                        indent=2, default=str
                    ) +
                    "\n\nLEARNED ACTION HISTORY:\n" +
                    "\n".join(
                        f"{name}: {score:.3f}"
                        for name, score in recommendations
                    )
                )

                self.rollback_box.setPlainText(
                    "\n".join(
                        f"{item['id']} | {item['description']} | "
                        f"{item['action_type']}"
                        for item in self.service.rollback.available()
                    )
                )

                self.settings_box.setPlainText(
                    json.dumps(
                        diagnostics(self.service),
                        indent=2, default=str
                    )
                )

                # Keep process table and other heavier widgets on demand.
            except Exception as exc:
                LOGGER.warning("GUI refresh failed: %s", exc)

        @staticmethod
        def pressure_state(telemetry: dict) -> str:
            cpu = float(telemetry.get("cpu_percent") or 0)
            ram = float(telemetry.get("ram_percent") or 0)
            gpu = telemetry.get("gpu") or []
            gpu_use = (
                float(gpu[0].get("utilization") or 0) if gpu else 0
            )
            if ram >= 92:
                return "MEMORY PRESSURE"
            if cpu >= 92:
                return "CPU HEAVY LOAD"
            if gpu_use >= 95:
                return "GPU HEAVY LOAD"
            if cpu >= 70 or ram >= 75:
                return "WORKLOAD"
            return "NORMAL"


# ------------------------------------------------
# CLI
# ------------------------------------------------

def run_cli(service: Service, once: bool = False):
    print(f"\n{APP_NAME} v{APP_VERSION}")
    print("=" * 72)
    print(json.dumps(diagnostics(service), indent=2, default=str))
    print("\nCLI telemetry mode. Press Ctrl+C to exit.\n")

    try:
        while service.core.running:
            status = service.core.status()
            telemetry = status["telemetry"]
            print(
                f"CPU {telemetry.get('cpu_percent', 0):5.1f}% | "
                f"RAM {telemetry.get('ram_percent', 0):5.1f}% | "
                f"DISK {telemetry.get('disk_percent', 0):5.1f}% | "
                f"GPU {((telemetry.get('gpu') or [{}])[0].get('utilization'))}"
            )
            if once:
                break
            time.sleep(max(1, int(service.config.get("telemetry_interval", 2))))
    except KeyboardInterrupt:
        pass


def parse_args():
    parser = argparse.ArgumentParser(
        description=f"{APP_NAME} v{APP_VERSION}"
    )
    parser.add_argument(
        "--safe-mode",
        action="store_true",
        help="Start with autonomous actions and plugins disabled.",
    )
    parser.add_argument(
        "--diagnostics",
        action="store_true",
        help="Print diagnostics and exit.",
    )
    parser.add_argument(
        "--cli",
        action="store_true",
        help="Use CLI telemetry instead of the Qt GUI.",
    )
    parser.add_argument(
        "--once",
        action="store_true",
        help="With --cli, print one telemetry snapshot and exit.",
    )
    parser.add_argument(
        "--reset-config",
        action="store_true",
        help="Back up and reset application configuration.",
    )
    parser.add_argument(
        "--repair-dependencies",
        action="store_true",
        help="Explicitly attempt installation of missing required packages.",
    )
    return parser.parse_args()


def main() -> int:
    install_exception_hook()
    args = parse_args()

    write_startup_state("launching")

    if args.repair_dependencies:
        print(json.dumps(repair_dependencies(False), indent=2))
        return 0

    if args.reset_config:
        cfg = Config()
        RecoveryManager(cfg).reset_config()
        print(f"Configuration reset. Backup directory: {BACKUP_DIR}")
        return 0

    service = Service(force_safe_mode=args.safe_mode)

    if args.diagnostics:
        print(json.dumps(diagnostics(service), indent=2, default=str))
        service.stop()
        return 0

    service.start()

    try:
        if args.cli or not QT_AVAILABLE:
            run_cli(service, once=args.once)
            return 0

        app = QApplication(sys.argv)
        app.setApplicationName(APP_NAME)
        app.setApplicationVersion(APP_VERSION)
        window = MainWindow(service)
        window.show()
        return app.exec()
    finally:
        service.stop()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        LOGGER.info("Shutdown requested")
    except Exception as exc:
        log_exception("Fatal application error", exc)
        write_startup_state("fatal", str(exc))
        raise

    def ask_local_ai(self, question=None):
        """Run the optional local AI advisor against the latest telemetry."""
        try:
            snapshot = {}
            for attr in ("telemetry", "telemetry_engine", "hardware", "hardware_monitor"):
                obj = getattr(self, attr, None)
                if obj is not None:
                    getter = getattr(obj, "snapshot", None)
                    if callable(getter):
                        value = getter()
                        if isinstance(value, dict):
                            snapshot.update(value)
                    getter = getattr(obj, "get_snapshot", None)
                    if callable(getter):
                        value = getter()
                        if isinstance(value, dict):
                            snapshot.update(value)
            advisor = getattr(self, "llm_advisor", None)
            if advisor is None:
                advisor = LocalLLMAdvisor(
                    getattr(self, "config", {}) if isinstance(getattr(self, "config", {}), dict) else {},
                    getattr(self, "logger", None),
                )
                self.llm_advisor = advisor
            return advisor.analyze(snapshot, question)
        except Exception as exc:
            return "Local AI Advisor could not complete the analysis: %s" % exc



# ---------------------------------------------------------------------------
# Public helper for integrating the AI layer with any existing UI.
# ---------------------------------------------------------------------------
_LOCAL_AI_ADVISOR = None

def get_local_ai_advisor(config=None, logger=None):
    """Return a process-wide LocalLLMAdvisor instance."""
    global _LOCAL_AI_ADVISOR
    if _LOCAL_AI_ADVISOR is None:
        _LOCAL_AI_ADVISOR = LocalLLMAdvisor(config=config, logger=logger)
    return _LOCAL_AI_ADVISOR

def local_ai_analyze(snapshot, question=None, config=None, logger=None):
    """Convenience API for dashboards, CLI commands, and future GUI tabs."""
    return get_local_ai_advisor(config=config, logger=logger).analyze(
        snapshot if isinstance(snapshot, dict) else {},
        question=question,
    )

# Optional environment-driven AI query:
#   PREEMPTIVE_AI_QUESTION="Why is my GPU slow?" python Preemptive_Strike_AI_NextGen_v11.py
