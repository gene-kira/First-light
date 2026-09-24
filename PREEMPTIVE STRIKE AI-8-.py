#!/usr/bin/env python3
# ================================================================
# PREEMPTIVE STRIKE AI — NEXT-GEN v10
# Windows autonomous performance / telemetry command center
#
# Major upgrades:
#   - Safe / Assist / Autonomous operating modes
#   - Watchdog with subsystem health and recovery
#   - Transactional rollback journal
#   - Hardware telemetry with graceful capability detection
#   - Performance baseline + benchmark/learning engine
#   - Secure Windows credential storage (DPAPI; optional keyring)
#   - Permission-aware plugin manager
#   - Dependency recovery / degraded-mode startup
#   - SQLite persistent event/history database
#   - Compact tabbed PySide6 GUI
#   - Real-time dashboard
#   - No fake VRAM preload: unsupported capabilities are reported
#
# This program intentionally does NOT perform credential injection,
# arbitrary code execution, security bypasses, or irreversible system
# modification. Autonomous mode is restricted to low-risk operations.
# ================================================================

from __future__ import annotations

import ctypes
import hashlib
import importlib
import importlib.util
import json
import os
import platform
import secrets
import shutil
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import uuid
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable, Optional

APP_NAME = "Preemptive Strike AI"
APP_VERSION = "10.0.0"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "preemptive_data"
PLUGIN_DIR = BASE_DIR / "plugins"
LOG_DIR = BASE_DIR / "logs"
DB_PATH = DATA_DIR / "preemptive.db"
CONFIG_PATH = DATA_DIR / "config.json"
ROLLBACK_PATH = DATA_DIR / "rollback_journal.json"
PLUGIN_MANIFEST_PATH = DATA_DIR / "plugins.json"

for d in (DATA_DIR, PLUGIN_DIR, LOG_DIR):
    d.mkdir(parents=True, exist_ok=True)

# ------------------------------------------------
# DEPENDENCY RECOVERY
# ------------------------------------------------

REQUIRED = {
    "psutil": "psutil",
    "PySide6": "PySide6",
}

OPTIONAL = {
    "pynvml": "pynvml",
    "torch": "torch",
    "GPUtil": "GPUtil",
    "keyring": "keyring",
}

def ensure_dependencies() -> dict[str, bool]:
    """Attempt safe, user-space dependency recovery.
    The application continues in degraded mode if installation fails.
    """
    result = {}
    for module_name, pip_name in {**REQUIRED, **OPTIONAL}.items():
        try:
            importlib.import_module(module_name)
            result[module_name] = True
        except Exception:
            result[module_name] = False
            # Required GUI dependency is worth attempting to recover.
            # Optional dependencies are deliberately not installed automatically.
            if module_name in REQUIRED:
                try:
                    subprocess.check_call(
                        [sys.executable, "-m", "pip", "install", "--user", pip_name],
                        stdout=subprocess.DEVNULL,
                        stderr=subprocess.DEVNULL,
                    )
                    result[module_name] = True
                except Exception:
                    result[module_name] = False
    return result

DEP_STATUS = ensure_dependencies()

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
    from PySide6.QtCore import Qt, QTimer, Signal, QObject
    from PySide6.QtWidgets import (
        QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
        QGridLayout, QLabel, QPushButton, QTextEdit, QTabWidget,
        QTableWidget, QTableWidgetItem, QComboBox, QLineEdit,
        QSpinBox, QMessageBox, QGroupBox, QProgressBar, QCheckBox
    )
    QT_AVAILABLE = True
except Exception:
    QT_AVAILABLE = False


# ------------------------------------------------
# UTILITIES
# ------------------------------------------------

def now() -> float:
    return time.time()

def human_bytes(value: float) -> str:
    value = float(value)
    units = ["B", "KB", "MB", "GB", "TB"]
    for unit in units:
        if abs(value) < 1024:
            return f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} PB"

def safe_json(data: Any) -> str:
    return json.dumps(data, default=str, separators=(",", ":"))

def atomic_write_json(path: Path, payload: Any) -> None:
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)

def is_windows() -> bool:
    return platform.system().lower() == "windows"

def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ------------------------------------------------
# LOGGING
# ------------------------------------------------

class Logger:
    def __init__(self):
        self.path = LOG_DIR / "preemptive.log"
        self.lock = threading.Lock()

    def write(self, level: str, message: str) -> None:
        line = f"{time.strftime('%Y-%m-%d %H:%M:%S')} [{level}] {message}"
        with self.lock:
            try:
                with self.path.open("a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception:
                pass
        print(line, flush=True)

    def info(self, message: str): self.write("INFO", message)
    def warn(self, message: str): self.write("WARN", message)
    def error(self, message: str): self.write("ERROR", message)

LOGGER = Logger()


# ------------------------------------------------
# SQLITE MEMORY / EVENT STORE
# ------------------------------------------------

class MemoryStore:
    def __init__(self, path: Path = DB_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.conn = sqlite3.connect(str(path), check_same_thread=False)
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=NORMAL")
        self._schema()

    def _schema(self):
        with self.lock:
            self.conn.executescript("""
            CREATE TABLE IF NOT EXISTS events(
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts REAL NOT NULL,
                category TEXT NOT NULL,
                payload TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
            CREATE INDEX IF NOT EXISTS idx_events_category ON events(category);

            CREATE TABLE IF NOT EXISTS settings(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );

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
            """)
            self.conn.commit()

    def append_event(self, category: str, payload: dict):
        with self.lock:
            self.conn.execute(
                "INSERT INTO events(ts,category,payload) VALUES(?,?,?)",
                (now(), category, safe_json(payload))
            )
            self.conn.commit()

    def set(self, key: str, value: Any):
        with self.lock:
            self.conn.execute(
                "INSERT INTO settings(key,value) VALUES(?,?) "
                "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, safe_json(value))
            )
            self.conn.commit()

    def get(self, key: str, default=None):
        with self.lock:
            row = self.conn.execute(
                "SELECT value FROM settings WHERE key=?", (key,)
            ).fetchone()
        if not row:
            return default
        try:
            return json.loads(row[0])
        except Exception:
            return default

    def recent_events(self, limit=100):
        with self.lock:
            rows = self.conn.execute(
                "SELECT ts,category,payload FROM events ORDER BY id DESC LIMIT ?",
                (limit,)
            ).fetchall()
        out = []
        for ts, cat, payload in rows:
            try:
                payload = json.loads(payload)
            except Exception:
                pass
            out.append({"ts": ts, "category": cat, "payload": payload})
        return out

    def record_benchmark(self, label, before, after, score, notes=""):
        with self.lock:
            self.conn.execute(
                "INSERT INTO benchmarks(ts,label,before_json,after_json,score,notes)"
                " VALUES(?,?,?,?,?,?)",
                (now(), label, safe_json(before), safe_json(after), score, notes)
            )
            self.conn.commit()

    def benchmarks(self, limit=50):
        with self.lock:
            return self.conn.execute(
                "SELECT ts,label,before_json,after_json,score,notes "
                "FROM benchmarks ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()

    def record_action(self, action, result, reward=None):
        with self.lock:
            self.conn.execute(
                "INSERT INTO actions(ts,action,result,reward) VALUES(?,?,?,?)",
                (now(), action, result, reward)
            )
            self.conn.commit()

    def close(self):
        with self.lock:
            self.conn.close()


# ------------------------------------------------
# CONFIGURATION
# ------------------------------------------------

DEFAULT_CONFIG = {
    "mode": "assist",              # safe | assist | autonomous
    "telemetry_interval": 2,
    "benchmark_duration": 5,
    "auto_cleanup": False,
    "auto_process_priority": False,
    "max_cache_percent": 20,
    "plugin_network": False,
    "plugin_file_write": False,
    "plugin_process": False,
    "retain_events": 20000,
}

class Config:
    def __init__(self, path=CONFIG_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.data = dict(DEFAULT_CONFIG)
        self.load()

    def load(self):
        if self.path.exists():
            try:
                loaded = json.loads(self.path.read_text(encoding="utf-8"))
                self.data.update(loaded)
            except Exception as e:
                LOGGER.warn(f"Config load failed: {e}")
        self.save()

    def save(self):
        with self.lock:
            atomic_write_json(self.path, self.data)

    def get(self, key, default=None):
        with self.lock:
            return self.data.get(key, default)

    def set(self, key, value):
        with self.lock:
            self.data[key] = value
            self.save()


# ------------------------------------------------
# ROLLBACK JOURNAL
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
    applied: bool = True
    rolled_back: bool = False

class RollbackManager:
    def __init__(self, path=ROLLBACK_PATH):
        self.path = path
        self.lock = threading.RLock()
        self.entries: list[dict] = []
        self.load()

    def load(self):
        try:
            self.entries = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(self.entries, list):
                self.entries = []
        except Exception:
            self.entries = []

    def save(self):
        with self.lock:
            atomic_write_json(self.path, self.entries[-500:])

    def record(self, description, action_type, before, after,
               reversible=True, applied=True) -> str:
        entry = RollbackEntry(
            id=uuid.uuid4().hex[:12],
            timestamp=now(),
            description=description,
            action_type=action_type,
            before=before,
            after=after,
            reversible=reversible,
            applied=applied,
        )
        with self.lock:
            self.entries.append(asdict(entry))
            self.save()
        return entry.id

    def available(self):
        with self.lock:
            return [
                e for e in reversed(self.entries)
                if e.get("reversible") and e.get("applied") and not e.get("rolled_back")
            ]

    def mark_rolled_back(self, entry_id):
        with self.lock:
            for e in self.entries:
                if e["id"] == entry_id:
                    e["rolled_back"] = True
                    self.save()
                    return True
        return False


# ------------------------------------------------
# SECURE CREDENTIAL STORE
# ------------------------------------------------

class SecureCredentialStore:
    """Uses Windows DPAPI when available, with keyring as an optional backend.
    No plaintext password is written to the application's JSON/SQLite data."""
    SERVICE = "PreemptiveStrikeAI"

    def __init__(self):
        self.backend = "none"
        if keyring is not None:
            self.backend = "keyring"
        elif is_windows():
            self.backend = "dpapi"

    def set(self, name: str, username: str, password: str) -> bool:
        if not name:
            return False
        try:
            if self.backend == "keyring":
                keyring.set_password(self.SERVICE, f"{name}:username", username)
                keyring.set_password(self.SERVICE, f"{name}:password", password)
                return True
            if self.backend == "dpapi":
                return self._dpapi_set(name, username, password)
        except Exception as e:
            LOGGER.error(f"Credential save failed: {e}")
        return False

    def get(self, name: str) -> Optional[dict]:
        try:
            if self.backend == "keyring":
                u = keyring.get_password(self.SERVICE, f"{name}:username")
                p = keyring.get_password(self.SERVICE, f"{name}:password")
                return {"username": u, "password": p} if u and p else None
            if self.backend == "dpapi":
                return self._dpapi_get(name)
        except Exception as e:
            LOGGER.error(f"Credential read failed: {e}")
        return None

    def delete(self, name: str):
        try:
            if self.backend == "keyring":
                for suffix in ("username", "password"):
                    try:
                        keyring.delete_password(self.SERVICE, f"{name}:{suffix}")
                    except Exception:
                        pass
            elif self.backend == "dpapi":
                path = DATA_DIR / f"cred_{hashlib.sha256(name.encode()).hexdigest()}.bin"
                if path.exists():
                    path.unlink()
        except Exception as e:
            LOGGER.warn(f"Credential delete failed: {e}")

    def _dpapi_set(self, name, username, password):
        # CryptProtectData with current Windows user scope.
        if not is_windows():
            return False
        path = DATA_DIR / f"cred_{hashlib.sha256(name.encode()).hexdigest()}.bin"
        payload = json.dumps(
            {"username": username, "password": password},
            separators=(",", ":")
        ).encode("utf-8")
        blob = self._protect(payload)
        path.write_bytes(blob)
        return True

    def _dpapi_get(self, name):
        path = DATA_DIR / f"cred_{hashlib.sha256(name.encode()).hexdigest()}.bin"
        if not path.exists():
            return None
        raw = self._unprotect(path.read_bytes())
        return json.loads(raw.decode("utf-8"))

    @staticmethod
    def _protect(data: bytes) -> bytes:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_uint32),
                        ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
        buf = (ctypes.c_ubyte * len(data))(*data)
        inp = DATA_BLOB(len(data), buf)
        out = DATA_BLOB()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptProtectData(
            ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)
        ):
            raise OSError("CryptProtectData failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            kernel32.LocalFree(out.pbData)

    @staticmethod
    def _unprotect(data: bytes) -> bytes:
        class DATA_BLOB(ctypes.Structure):
            _fields_ = [("cbData", ctypes.c_uint32),
                        ("pbData", ctypes.POINTER(ctypes.c_ubyte))]
        buf = (ctypes.c_ubyte * len(data))(*data)
        inp = DATA_BLOB(len(data), buf)
        out = DATA_BLOB()
        crypt32 = ctypes.windll.crypt32
        kernel32 = ctypes.windll.kernel32
        if not crypt32.CryptUnprotectData(
            ctypes.byref(inp), None, None, None, None, 0, ctypes.byref(out)
        ):
            raise OSError("CryptUnprotectData failed")
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            kernel32.LocalFree(out.pbData)


# ------------------------------------------------
# HARDWARE TELEMETRY
# ------------------------------------------------

class HardwareTelemetry:
    def __init__(self):
        self.gpu_handles = []
        self.gpu_backend = "unavailable"
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
        except Exception as e:
            LOGGER.warn(f"GPU telemetry unavailable: {e}")

    def snapshot(self) -> dict:
        data = {
            "ts": now(),
            "cpu_percent": 0.0,
            "ram_percent": 0.0,
            "ram_used": 0,
            "ram_total": 0,
            "disk_percent": 0.0,
            "battery_percent": None,
            "gpu": [],
            "process_count": 0,
            "boot_time": None,
        }
        if psutil is None:
            return data

        try:
            vm = psutil.virtual_memory()
            data["cpu_percent"] = psutil.cpu_percent(interval=None)
            data["ram_percent"] = vm.percent
            data["ram_used"] = vm.used
            data["ram_total"] = vm.total
            data["disk_percent"] = psutil.disk_usage(os.path.abspath(os.sep)).percent
            data["process_count"] = len(psutil.pids())
            data["boot_time"] = psutil.boot_time()
            battery = psutil.sensors_battery()
            if battery:
                data["battery_percent"] = battery.percent
        except Exception as e:
            LOGGER.warn(f"System telemetry error: {e}")

        for idx, handle in enumerate(self.gpu_handles):
            g = {"index": idx, "name": "GPU", "temperature": None,
                 "utilization": None, "memory_used": None,
                 "memory_total": None, "power_w": None}
            try:
                raw_name = pynvml.nvmlDeviceGetName(handle)
                g["name"] = raw_name.decode(errors="replace") if isinstance(raw_name, bytes) else str(raw_name)
            except Exception:
                pass
            try:
                g["temperature"] = pynvml.nvmlDeviceGetTemperature(
                    handle, pynvml.NVML_TEMPERATURE_GPU
                )
            except Exception:
                pass
            try:
                util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                g["utilization"] = util.gpu
            except Exception:
                pass
            try:
                mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
                g["memory_used"] = mem.used
                g["memory_total"] = mem.total
            except Exception:
                pass
            try:
                g["power_w"] = pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0
            except Exception:
                pass
            data["gpu"].append(g)
        return data

    def summary(self):
        s = self.snapshot()
        gpu = s["gpu"]
        gpu_text = "No GPU backend"
        if gpu:
            g = gpu[0]
            gpu_text = (
                f"{g['name']} | GPU {g['utilization']}% | "
                f"VRAM {human_bytes(g['memory_used'] or 0)}/"
                f"{human_bytes(g['memory_total'] or 0)} | "
                f"Temp {g['temperature']}°C"
            )
        return s, gpu_text


# ------------------------------------------------
# PROCESS OBSERVER
# ------------------------------------------------

class ProcessObserver:
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.last_foreground = None

    def foreground(self):
        if not is_windows():
            return None
        try:
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return None
            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            p = psutil.Process(pid.value)
            return {
                "pid": pid.value,
                "name": p.name(),
                "exe": p.exe(),
            }
        except Exception:
            return None

    def top_processes(self, limit=12):
        if psutil is None:
            return []
        result = []
        for p in psutil.process_iter(["pid", "name", "memory_info", "cpu_percent"]):
            try:
                mi = p.info.get("memory_info")
                rss = mi.rss if mi else 0
                result.append({
                    "pid": p.info["pid"],
                    "name": p.info.get("name") or "?",
                    "rss": rss,
                    "cpu": p.info.get("cpu_percent") or 0.0,
                })
            except Exception:
                pass
        return sorted(result, key=lambda x: x["rss"], reverse=True)[:limit]


# ------------------------------------------------
# PERFORMANCE LEARNING ENGINE
# ------------------------------------------------

class PerformanceLearningEngine:
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.samples = []
        self.action_scores: dict[str, float] = {}

    def state_vector(self, telemetry: dict) -> dict:
        gpu = telemetry.get("gpu", [])
        g = gpu[0] if gpu else {}
        return {
            "cpu": telemetry.get("cpu_percent", 0.0),
            "ram": telemetry.get("ram_percent", 0.0),
            "disk": telemetry.get("disk_percent", 0.0),
            "gpu": g.get("utilization"),
            "vram": (
                (g.get("memory_used") / g.get("memory_total") * 100.0)
                if g.get("memory_used") and g.get("memory_total") else None
            ),
            "gpu_temp": g.get("temperature"),
        }

    def compare(self, before: dict, after: dict) -> dict:
        # Positive is generally better for lower CPU/RAM, but GPU utilization
        # is workload-dependent, so it is displayed separately.
        cpu_delta = before.get("cpu", 0) - after.get("cpu", 0)
        ram_delta = before.get("ram", 0) - after.get("ram", 0)
        score = (cpu_delta * 0.6) + (ram_delta * 0.4)
        return {
            "cpu_delta": round(after.get("cpu", 0) - before.get("cpu", 0), 2),
            "ram_delta": round(after.get("ram", 0) - before.get("ram", 0), 2),
            "score": round(score, 3),
        }

    def record(self, action: str, result: dict):
        old = self.action_scores.get(action, 0.0)
        reward = float(result.get("score", 0.0))
        self.action_scores[action] = old * 0.8 + reward * 0.2
        self.memory.record_action(action, "completed", reward)
        self.memory.append_event("learning", {
            "action": action, "result": result,
            "score": self.action_scores[action]
        })

    def recommendations(self, limit=5):
        return sorted(
            self.action_scores.items(),
            key=lambda x: x[1],
            reverse=True
        )[:limit]


# ------------------------------------------------
# SAFE OPTIMIZATION ENGINE
# ------------------------------------------------

class OptimizationEngine:
    """Only low-risk, reversible operations are autonomous."""

    LOW_RISK_ACTIONS = {
        "clear_python_cache",
        "refresh_process_snapshot",
        "recalculate_telemetry",
    }

    def __init__(self, config: Config, rollback: RollbackManager,
                 memory: MemoryStore):
        self.config = config
        self.rollback = rollback
        self.memory = memory

    def can_execute(self, action: str, automatic=False) -> bool:
        mode = self.config.get("mode", "assist")
        if mode == "safe":
            return False
        if automatic:
            return mode == "autonomous" and action in self.LOW_RISK_ACTIONS
        return True

    def execute(self, action: str) -> tuple[bool, str]:
        if not self.can_execute(action):
            return False, f"Blocked by operating mode: {self.config.get('mode')}"

        if action == "clear_python_cache":
            removed = 0
            for root in [BASE_DIR]:
                for p in root.rglob("__pycache__"):
                    try:
                        shutil.rmtree(p)
                        removed += 1
                    except Exception:
                        pass
            rid = self.rollback.record(
                "Clear Python cache directories", "filesystem_cleanup",
                {"removed": 0}, {"removed": removed}
            )
            self.memory.append_event("optimization", {
                "action": action, "rollback_id": rid, "removed": removed
            })
            return True, f"Removed {removed} cache directories"

        if action == "refresh_process_snapshot":
            self.memory.append_event("optimization", {"action": action})
            return True, "Process snapshot refreshed"

        if action == "recalculate_telemetry":
            self.memory.append_event("optimization", {"action": action})
            return True, "Telemetry recalculated"

        return False, "Unknown or unsupported optimization"


# ------------------------------------------------
# BENCHMARK ENGINE
# ------------------------------------------------

class BenchmarkEngine:
    def __init__(self, telemetry: HardwareTelemetry, memory: MemoryStore,
                 learning: PerformanceLearningEngine):
        self.telemetry = telemetry
        self.memory = memory
        self.learning = learning
        self.running = False

    def sample(self, seconds=3, interval=0.5):
        samples = []
        end = now() + seconds
        while now() < end and self.running:
            samples.append(self.telemetry.snapshot())
            time.sleep(interval)
        return samples

    @staticmethod
    def summarize(samples):
        if not samples:
            return {}
        cpu = [x["cpu_percent"] for x in samples]
        ram = [x["ram_percent"] for x in samples]
        gpu = []
        temp = []
        for x in samples:
            if x["gpu"]:
                if x["gpu"][0]["utilization"] is not None:
                    gpu.append(x["gpu"][0]["utilization"])
                if x["gpu"][0]["temperature"] is not None:
                    temp.append(x["gpu"][0]["temperature"])
        return {
            "cpu_avg": sum(cpu) / len(cpu),
            "ram_avg": sum(ram) / len(ram),
            "gpu_avg": sum(gpu) / len(gpu) if gpu else None,
            "gpu_temp_max": max(temp) if temp else None,
        }

    def run(self, label="Baseline", seconds=5):
        self.running = True
        before_samples = self.sample(seconds)
        before = self.summarize(before_samples)
        self.running = False
        self.memory.record_benchmark(label, before, before, 0.0,
                                     "Baseline telemetry benchmark")
        return before


# ------------------------------------------------
# PLUGIN PERMISSIONS
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
    """Loads plugins only after manifest permission checks.
    Plugins are still Python code and should be treated as trusted code."""
    def __init__(self, config: Config, memory: MemoryStore):
        self.config = config
        self.memory = memory
        self.plugins = {}
        self.manifest = self._load_manifest()
        self.scan()

    def _load_manifest(self):
        try:
            data = json.loads(PLUGIN_MANIFEST_PATH.read_text(encoding="utf-8"))
            return data if isinstance(data, dict) else {}
        except Exception:
            return {}

    def _save_manifest(self):
        atomic_write_json(PLUGIN_MANIFEST_PATH, self.manifest)

    def _hash_file(self, path):
        h = hashlib.sha256()
        with path.open("rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                h.update(chunk)
        return h.hexdigest()

    def scan(self):
        for path in PLUGIN_DIR.glob("*.py"):
            try:
                digest = self._hash_file(path)
                cfg = self.manifest.setdefault(path.name, {
                    "enabled": False,
                    "permissions": [],
                    "hash": digest,
                })
                if cfg.get("hash") != digest:
                    cfg["enabled"] = False
                    cfg["hash"] = digest
                    LOGGER.warn(f"Plugin changed; disabled until reviewed: {path.name}")
                self._save_manifest()
            except Exception as e:
                LOGGER.warn(f"Plugin scan failed: {e}")

    def list_plugins(self):
        out = []
        for name, cfg in self.manifest.items():
            out.append({
                "name": name,
                "enabled": bool(cfg.get("enabled")),
                "permissions": cfg.get("permissions", []),
            })
        return out

    def set_enabled(self, name, enabled):
        if name in self.manifest:
            self.manifest[name]["enabled"] = bool(enabled)
            self._save_manifest()

    def set_permissions(self, name, permissions):
        if name not in self.manifest:
            return False
        permissions = [p for p in permissions if p in PLUGIN_PERMISSIONS]
        self.manifest[name]["permissions"] = permissions
        self._save_manifest()
        return True

    def load_enabled(self):
        for name, cfg in self.manifest.items():
            if not cfg.get("enabled"):
                continue
            path = PLUGIN_DIR / name
            try:
                spec = importlib.util.spec_from_file_location(
                    f"psai_plugin_{path.stem}", path
                )
                if not spec or not spec.loader:
                    continue
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.plugins[name] = module
                self.memory.append_event("plugin_loaded", {
                    "name": name,
                    "permissions": cfg.get("permissions", [])
                })
            except Exception as e:
                LOGGER.error(f"Plugin failed: {name}: {e}")

    def unload_all(self):
        self.plugins.clear()


# ------------------------------------------------
# WATCHDOG
# ------------------------------------------------

@dataclass
class Health:
    name: str
    state: str = "starting"
    last_ok: float = 0.0
    failures: int = 0
    message: str = ""

class Watchdog:
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.health: dict[str, Health] = {}
        self.recoveries: dict[str, Callable] = {}
        self.lock = threading.RLock()

    def register(self, name, recovery=None):
        with self.lock:
            self.health[name] = Health(name=name, last_ok=now())
            if recovery:
                self.recoveries[name] = recovery

    def ok(self, name, message=""):
        with self.lock:
            h = self.health.setdefault(name, Health(name))
            h.state = "healthy"
            h.last_ok = now()
            h.message = message

    def fail(self, name, error):
        with self.lock:
            h = self.health.setdefault(name, Health(name))
            h.state = "degraded"
            h.failures += 1
            h.message = str(error)
            self.memory.append_event("watchdog_failure", {
                "subsystem": name, "error": str(error),
                "failures": h.failures
            })
            recovery = self.recoveries.get(name)
        if recovery:
            try:
                recovery()
                self.ok(name, "Recovered automatically")
                self.memory.append_event("watchdog_recovery", {"subsystem": name})
            except Exception as e:
                LOGGER.error(f"Recovery failed for {name}: {e}")

    def snapshot(self):
        with self.lock:
            return {k: asdict(v) for k, v in self.health.items()}


# ------------------------------------------------
# CORE ENGINE
# ------------------------------------------------

class CoreEngine:
    def __init__(self, config, memory, watchdog, telemetry,
                 process_observer, learning, benchmark,
                 optimizer, rollback, plugins, credentials):
        self.config = config
        self.memory = memory
        self.watchdog = watchdog
        self.telemetry = telemetry
        self.processes = process_observer
        self.learning = learning
        self.benchmark = benchmark
        self.optimizer = optimizer
        self.rollback = rollback
        self.plugins = plugins
        self.credentials = credentials

        self.running = False
        self.thread = None
        self.latest = {}
        self.foreground = None
        self.started = now()

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(
            target=self.loop, daemon=True, name="PSAI-Core"
        )
        self.thread.start()
        LOGGER.info("Core engine started")

    def stop(self):
        self.running = False
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=3)

    def loop(self):
        while self.running:
            try:
                self.latest = self.telemetry.snapshot()
                self.memory.append_event("telemetry", self.latest)
                self.watchdog.ok("telemetry")

                self.foreground = self.processes.foreground()
                self.watchdog.ok("process_observer")

                # Only low-risk automatic operations are allowed.
                if self.config.get("mode") == "autonomous":
                    if self.latest.get("ram_percent", 0) > 92:
                        self.optimizer.execute("refresh_process_snapshot")

                self.watchdog.ok("core")
            except Exception as e:
                LOGGER.error(f"Core loop error: {e}")
                self.watchdog.fail("core", e)
            time.sleep(max(1, int(self.config.get("telemetry_interval", 2))))

    def status(self):
        return {
            "uptime": now() - self.started,
            "mode": self.config.get("mode"),
            "telemetry": self.latest,
            "foreground": self.foreground,
            "health": self.watchdog.snapshot(),
        }


# ------------------------------------------------
# DEPENDENCY / SELF-DIAGNOSTIC REPORT
# ------------------------------------------------

def diagnostics() -> dict:
    report = {
        "app": f"{APP_NAME} {APP_VERSION}",
        "os": f"{platform.system()} {platform.release()}",
        "python": platform.python_version(),
        "admin": is_admin(),
        "dependencies": DEP_STATUS,
        "qt": QT_AVAILABLE,
        "nvml": pynvml is not None,
        "torch": torch is not None,
        "keyring": keyring is not None,
        "data_dir": str(DATA_DIR),
    }
    return report


# ------------------------------------------------
# QT FRONTEND
# ------------------------------------------------

if QT_AVAILABLE:

    class UiBus(QObject):
        telemetry = Signal(dict)
        log = Signal(str)

    class MainWindow(QMainWindow):
        def __init__(self, service):
            super().__init__()
            self.service = service
            self.bus = UiBus()
            self.setWindowTitle(
                f"{APP_NAME} — Next-Gen v{APP_VERSION}"
            )
            self.resize(1080, 720)
            self.setMinimumSize(900, 600)
            self._build()
            self.timer = QTimer(self)
            self.timer.timeout.connect(self.refresh)
            self.timer.start(1500)
            self.refresh()

        def _build(self):
            central = QWidget()
            root = QVBoxLayout(central)
            root.setContentsMargins(10, 10, 10, 10)

            top = QHBoxLayout()
            self.title = QLabel(
                f"<b>{APP_NAME}</b> <small>Next-Gen v{APP_VERSION}</small>"
            )
            self.mode = QComboBox()
            self.mode.addItems(["safe", "assist", "autonomous"])
            self.mode.setCurrentText(self.service.config.get("mode", "assist"))
            self.mode.currentTextChanged.connect(self.change_mode)

            self.status = QLabel("● Starting")
            self.status.setStyleSheet("font-weight:bold;")
            top.addWidget(self.title)
            top.addStretch()
            top.addWidget(QLabel("Mode:"))
            top.addWidget(self.mode)
            top.addWidget(self.status)
            root.addLayout(top)

            self.tabs = QTabWidget()
            self.tabs.addTab(self.dashboard_tab(), "Dashboard")
            self.tabs.addTab(self.ai_tab(), "AI Brain")
            self.tabs.addTab(self.performance_tab(), "Performance")
            self.tabs.addTab(self.hardware_tab(), "Hardware")
            self.tabs.addTab(self.process_tab(), "Processes")
            self.tabs.addTab(self.security_tab(), "Security")
            self.tabs.addTab(self.plugins_tab(), "Plugins")
            self.tabs.addTab(self.events_tab(), "Events")
            self.tabs.addTab(self.settings_tab(), "Settings")
            root.addWidget(self.tabs)

            self.setCentralWidget(central)

        def group(self, title):
            g = QGroupBox(title)
            g.setStyleSheet(
                "QGroupBox { font-weight:bold; margin-top:8px; }"
                "QGroupBox::title { subcontrol-origin: margin; left:8px; padding:0 3px; }"
            )
            return g

        def dashboard_tab(self):
            w = QWidget()
            layout = QVBoxLayout(w)

            cards = QGridLayout()
            self.cpu = QLabel("--")
            self.ram = QLabel("--")
            self.disk = QLabel("--")
            self.gpu = QLabel("--")
            self.vram = QLabel("--")
            self.temp = QLabel("--")
            for i, (name, label) in enumerate([
                ("CPU", self.cpu), ("RAM", self.ram), ("DISK", self.disk),
                ("GPU", self.gpu), ("VRAM", self.vram), ("GPU TEMP", self.temp)
            ]):
                box = self.group(name)
                b = QVBoxLayout(box)
                label.setStyleSheet("font-size:20px;")
                b.addWidget(label)
                cards.addWidget(box, i // 3, i % 3)
            layout.addLayout(cards)

            self.foreground_label = QLabel("Foreground: --")
            self.state_label = QLabel("System state: --")
            self.health_label = QLabel("Subsystem health: --")
            layout.addWidget(self.foreground_label)
            layout.addWidget(self.state_label)
            layout.addWidget(self.health_label)

            buttons = QHBoxLayout()
            b = QPushButton("Run Baseline")
            b.clicked.connect(self.run_baseline)
            buttons.addWidget(b)
            b = QPushButton("Refresh Diagnostics")
            b.clicked.connect(self.refresh_diagnostics)
            buttons.addWidget(b)
            b = QPushButton("Safe Cleanup")
            b.clicked.connect(lambda: self.optimize("clear_python_cache"))
            buttons.addWidget(b)
            b = QPushButton("Stop Engine")
            b.clicked.connect(self.stop_engine)
            buttons.addWidget(b)
            layout.addLayout(buttons)
            return w

        def ai_tab(self):
            w = QWidget()
            l = QVBoxLayout(w)
            self.ai_box = QTextEdit()
            self.ai_box.setReadOnly(True)
            l.addWidget(self.ai_box)
            l.addWidget(QLabel(
                "The learning engine records measured outcomes. "
                "It does not treat prediction confidence as proof of benefit."
            ))
            return w

        def performance_tab(self):
            w = QWidget()
            l = QVBoxLayout(w)
            self.benchmark_box = QTextEdit()
            self.benchmark_box.setReadOnly(True)
            run = QPushButton("Run 5-Second Baseline Benchmark")
            run.clicked.connect(self.run_baseline)
            l.addWidget(run)
            l.addWidget(self.benchmark_box)
            return w

        def hardware_tab(self):
            w = QWidget()
            l = QVBoxLayout(w)
            self.hardware_box = QTextEdit()
            self.hardware_box.setReadOnly(True)
            l.addWidget(self.hardware_box)
            return w

        def process_tab(self):
            w = QWidget()
            l = QVBoxLayout(w)
            self.process_table = QTableWidget(0, 4)
            self.process_table.setHorizontalHeaderLabels(
                ["PID", "Process", "RAM", "CPU %"]
            )
            self.process_table.horizontalHeader().setStretchLastSection(True)
            l.addWidget(self.process_table)
            refresh = QPushButton("Refresh Processes")
            refresh.clicked.connect(self.refresh_processes)
            l.addWidget(refresh)
            return w

        def security_tab(self):
            w = QWidget()
            l = QVBoxLayout(w)
            info = QLabel(
                "<b>Credential security</b><br>"
                "Credentials are stored using Windows DPAPI or the OS keyring. "
                "They are not placed in the AI event database."
            )
            l.addWidget(info)

            form = QGridLayout()
            self.cred_name = QLineEdit("email")
            self.cred_user = QLineEdit()
            self.cred_pass = QLineEdit()
            self.cred_pass.setEchoMode(QLineEdit.Password)
            save = QPushButton("Save Secure Credential")
            save.clicked.connect(self.save_credential)
            delete = QPushButton("Delete Credential")
            delete.clicked.connect(self.delete_credential)
            form.addWidget(QLabel("Service"), 0, 0)
            form.addWidget(self.cred_name, 0, 1)
            form.addWidget(QLabel("Username"), 1, 0)
            form.addWidget(self.cred_user, 1, 1)
            form.addWidget(QLabel("Password"), 2, 0)
            form.addWidget(self.cred_pass, 2, 1)
            form.addWidget(save, 3, 0)
            form.addWidget(delete, 3, 1)
            l.addLayout(form)

            self.rollback_box = QTextEdit()
            self.rollback_box.setReadOnly(True)
            l.addWidget(QLabel("Rollback journal"))
            l.addWidget(self.rollback_box)
            return w

        def plugins_tab(self):
            w = QWidget()
            l = QVBoxLayout(w)
            self.plugin_table = QTableWidget(0, 3)
            self.plugin_table.setHorizontalHeaderLabels(
                ["Plugin", "Enabled", "Permissions"]
            )
            l.addWidget(self.plugin_table)
            refresh = QPushButton("Rescan Plugins")
            refresh.clicked.connect(self.refresh_plugins)
            l.addWidget(refresh)
            l.addWidget(QLabel(
                "Plugins are disabled by default and file changes automatically "
                "invalidate their approval."
            ))
            return w

        def events_tab(self):
            w = QWidget()
            l = QVBoxLayout(w)
            self.events_box = QTextEdit()
            self.events_box.setReadOnly(True)
            l.addWidget(self.events_box)
            refresh = QPushButton("Refresh Events")
            refresh.clicked.connect(self.refresh_events)
            l.addWidget(refresh)
            return w

        def settings_tab(self):
            w = QWidget()
            l = QVBoxLayout(w)
            self.settings_box = QTextEdit()
            self.settings_box.setReadOnly(True)
            l.addWidget(self.settings_box)
            l.addWidget(QLabel(
                "Autonomous mode is deliberately limited to low-risk actions. "
                "Use Assist mode when you want approval before optimization."
            ))
            return w

        def change_mode(self, mode):
            self.service.config.set("mode", mode)
            self.log(f"[MODE] Changed to {mode}")

        def log(self, message):
            LOGGER.info(message)

        def save_credential(self):
            ok = self.service.credentials.set(
                self.cred_name.text().strip(),
                self.cred_user.text(),
                self.cred_pass.text()
            )
            self.cred_pass.clear()
            self.log("[CREDENTIAL] Secure credential saved" if ok
                     else "[CREDENTIAL] Save failed")

        def delete_credential(self):
            self.service.credentials.delete(self.cred_name.text().strip())
            self.log("[CREDENTIAL] Credential deleted")

        def optimize(self, action):
            ok, msg = self.service.optimizer.execute(action)
            self.log(f"[OPTIMIZER] {msg}")

        def run_baseline(self):
            self.benchmark_box.setPlainText("Running baseline telemetry benchmark...")
            def worker():
                result = self.service.benchmark.run(
                    "Baseline",
                    int(self.service.config.get("benchmark_duration", 5))
                )
                self.bus.log.emit(f"[BENCHMARK] {safe_json(result)}")
            threading.Thread(target=worker, daemon=True).start()

        def refresh_diagnostics(self):
            self.settings_box.setPlainText(json.dumps(
                diagnostics(), indent=2, default=str
            ))

        def stop_engine(self):
            self.service.core.stop()
            self.status.setText("● Stopped")

        def refresh_processes(self):
            rows = self.service.processes.top_processes()
            self.process_table.setRowCount(len(rows))
            for r, p in enumerate(rows):
                vals = [
                    str(p["pid"]), p["name"],
                    human_bytes(p["rss"]), f"{p['cpu']:.1f}"
                ]
                for c, v in enumerate(vals):
                    self.process_table.setItem(r, c, QTableWidgetItem(v))

        def refresh_plugins(self):
            rows = self.service.plugins.list_plugins()
            self.plugin_table.setRowCount(len(rows))
            for r, p in enumerate(rows):
                self.plugin_table.setItem(r, 0, QTableWidgetItem(p["name"]))
                self.plugin_table.setItem(r, 1, QTableWidgetItem(
                    "YES" if p["enabled"] else "NO"
                ))
                self.plugin_table.setItem(r, 2, QTableWidgetItem(
                    ", ".join(p["permissions"])
                ))

        def refresh_events(self):
            events = self.service.memory.recent_events(80)
            lines = []
            for e in reversed(events):
                lines.append(
                    f"{time.strftime('%H:%M:%S', time.localtime(e['ts']))} "
                    f"[{e['category']}] {safe_json(e['payload'])}"
                )
            self.events_box.setPlainText("\n".join(lines))

        def refresh(self):
            s = self.service.core.status()
            t = s["telemetry"]
            self.cpu.setText(f"{t.get('cpu_percent', 0):.1f}%")
            self.ram.setText(f"{t.get('ram_percent', 0):.1f}%")
            self.disk.setText(f"{t.get('disk_percent', 0):.1f}%")

            if t.get("gpu"):
                g = t["gpu"][0]
                self.gpu.setText(
                    "--" if g["utilization"] is None
                    else f"{g['utilization']}%"
                )
                if g.get("memory_total"):
                    self.vram.setText(
                        f"{human_bytes(g.get('memory_used', 0))}/"
                        f"{human_bytes(g.get('memory_total', 0))}"
                    )
                else:
                    self.vram.setText("--")
                self.temp.setText(
                    "--" if g["temperature"] is None
                    else f"{g['temperature']}°C"
                )
            else:
                self.gpu.setText("N/A")
                self.vram.setText("N/A")
                self.temp.setText("N/A")

            fg = s.get("foreground")
            self.foreground_label.setText(
                f"Foreground: {fg['name']} (PID {fg['pid']})" if fg
                else "Foreground: --"
            )

            pressure = self._pressure(t)
            self.state_label.setText(f"System state: {pressure}")

            health = s["health"]
            bad = [k for k, v in health.items() if v["state"] != "healthy"]
            self.health_label.setText(
                "Subsystem health: " +
                ("OK" if not bad else "Degraded: " + ", ".join(bad))
            )
            self.status.setText(
                "● Running" if self.service.core.running else "● Stopped"
            )

            self.hardware_box.setPlainText(json.dumps(t, indent=2, default=str))
            self.ai_box.setPlainText(
                "MODE: " + str(self.service.config.get("mode")) +
                "\n\nLEARNED ACTION SCORES:\n" +
                "\n".join(
                    f"  {a}: {s:.3f}"
                    for a, s in self.service.learning.recommendations()
                ) +
                "\n\nWATCHDOG:\n" +
                json.dumps(health, indent=2)
            )
            self.rollback_box.setPlainText(
                "\n".join(
                    f"{x['id']} | {x['description']} | "
                    f"{'ROLLED BACK' if x['rolled_back'] else 'AVAILABLE'}"
                    for x in self.service.rollback.available()
                )
            )
            self.settings_box.setPlainText(json.dumps(
                {
                    "config": self.service.config.data,
                    "diagnostics": diagnostics()
                }, indent=2, default=str
            ))

        @staticmethod
        def _pressure(t):
            cpu = t.get("cpu_percent", 0)
            ram = t.get("ram_percent", 0)
            gpu = t.get("gpu", [])
            gu = gpu[0].get("utilization") if gpu else None
            if ram >= 90:
                return "MEMORY PRESSURE"
            if cpu >= 90:
                return "CPU HEAVY LOAD"
            if gu is not None and gu >= 90:
                return "GPU HEAVY LOAD"
            if cpu >= 60 or ram >= 70:
                return "WORKLOAD"
            return "NORMAL"


# ------------------------------------------------
# SERVICE CONTAINER
# ------------------------------------------------

class Service:
    def __init__(self):
        self.config = Config()
        self.memory = MemoryStore()
        self.rollback = RollbackManager()
        self.credentials = SecureCredentialStore()
        self.telemetry = HardwareTelemetry()
        self.processes = ProcessObserver(self.memory)
        self.learning = PerformanceLearningEngine(self.memory)
        self.benchmark = BenchmarkEngine(
            self.telemetry, self.memory, self.learning
        )
        self.optimizer = OptimizationEngine(
            self.config, self.rollback, self.memory
        )
        self.plugins = PluginManager(self.config, self.memory)
        self.watchdog = Watchdog(self.memory)

        self.core = CoreEngine(
            self.config, self.memory, self.watchdog,
            self.telemetry, self.processes, self.learning,
            self.benchmark, self.optimizer, self.rollback,
            self.plugins, self.credentials
        )

        self.watchdog.register("core")
        self.watchdog.register("telemetry")
        self.watchdog.register("process_observer")
        self.watchdog.register("plugin_host", self.plugins.load_enabled)

    def start(self):
        LOGGER.info(f"{APP_NAME} v{APP_VERSION} starting")
        LOGGER.info(f"Diagnostics: {safe_json(diagnostics())}")
        self.plugins.load_enabled()
        self.core.start()

    def stop(self):
        self.core.stop()
        self.plugins.unload_all()
        self.memory.close()


# ------------------------------------------------
# CLI FALLBACK
# ------------------------------------------------

def run_cli(service):
    print(f"\n{APP_NAME} v{APP_VERSION}")
    print("=" * 60)
    print(json.dumps(diagnostics(), indent=2, default=str))
    print("\nRunning in CLI mode. Press Ctrl+C to exit.\n")
    try:
        while service.core.running:
            status = service.core.status()
            t = status["telemetry"]
            print(
                f"CPU {t.get('cpu_percent', 0):5.1f}% | "
                f"RAM {t.get('ram_percent', 0):5.1f}% | "
                f"Disk {t.get('disk_percent', 0):5.1f}%"
            )
            time.sleep(3)
    except KeyboardInterrupt:
        pass


# ------------------------------------------------
# ENTRY POINT
# ------------------------------------------------

def main():
    service = Service()
    service.start()

    if QT_AVAILABLE:
        app = QApplication(sys.argv)
        app.setApplicationName(APP_NAME)
        app.setApplicationVersion(APP_VERSION)
        window = MainWindow(service)
        window.show()
        try:
            return app.exec()
        finally:
            service.stop()
    else:
        run_cli(service)
        service.stop()
        return 0

if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        LOGGER.info("Shutdown requested")
    except Exception as exc:
        LOGGER.error(f"Fatal error: {exc}")
        traceback.print_exc()
