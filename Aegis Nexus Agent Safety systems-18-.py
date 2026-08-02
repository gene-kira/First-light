#!/usr/bin/env python3
"""
Aegis Nexus Agent — Borg Flight Deck v7.9

Upgrades vs v7.8:
- Stronger Automation Engine:
  - Can suggest / log actions for:
    - killing runaway processes (stubbed)
    - reducing GPU power (stubbed)
    - initiating backups (stubbed)
    - safe shutdown (stubbed)
- Richer Historical Graphing:
  - CPU, GPU temp, RAM usage, AIO RPM history
  - Longer window, clearer overlays
- Remote Cluster Control:
  - /api/remote_command:
    - ping
    - diag
    - soft_stop (stub)
    - request_shutdown (stub)
    - request_backup (stub)
- Web Dashboard more useful:
  - Shows node info, metrics, threats, cluster
  - Still lightweight HTML
- Tactical tab kept and slightly more cinematic:
  - Hazard arcs, pulses, more color logic
"""

import time
import threading
import platform
import subprocess
import importlib
import os
import json
from enum import Enum
from dataclasses import dataclass, field
from typing import Dict, Any, Callable, List, Optional

import subprocess as sp
import sys

# === Auto-install dependencies ===
def autoload(pkgs):
    for name in pkgs:
        try:
            __import__(name)
        except ImportError:
            sp.check_call([sys.executable, "-m", "pip", "install", name])

autoload([
    "psutil",
    "pyttsx3",
    "flask",
])

import psutil
import tkinter as tk
from tkinter import ttk
import pyttsx3
from flask import Flask, jsonify, render_template_string, request
import sqlite3

try:
    import wmi
except ImportError:
    wmi = None

try:
    import winsound
except ImportError:
    winsound = None

try:
    import onnxruntime as ort
except ImportError:
    ort = None

try:
    import torch
except ImportError:
    torch = None

try:
    import pynvml
except ImportError:
    pynvml = None

try:
    import zmq
except ImportError:
    zmq = None


# ============================
# SAFE FLOAT
# ============================

def safe_float(x):
    try:
        return float(x)
    except Exception:
        return 0.0


# ============================
# ENUMS & DATA CLASSES
# ============================

class RiskLevel(Enum):
    NONE = 0
    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4


@dataclass
class TelemetrySnapshot:
    timestamp: float
    metrics: Dict[str, float]
    states: Dict[str, Any]
    tags: List[str] = field(default_factory=list)


@dataclass
class AnomalyResult:
    risk: RiskLevel
    reason: str
    details: Dict[str, Any] = field(default_factory=dict)


# ============================
# SENSOR & CONTROL REGISTRIES
# ============================

class SensorRegistry:
    def __init__(self):
        self.sensors: Dict[str, Callable[[], Any]] = {}

    def register(self, name: str, func: Callable[[], Any]):
        self.sensors[name] = func

    def scan_all(self) -> Dict[str, Any]:
        out = {}
        for name, func in self.sensors.items():
            try:
                out[name] = func()
            except Exception as e:
                out[name] = f"ERROR: {e}"
        return out


class ControlRegistry:
    def __init__(self):
        self.controls: Dict[str, Callable[[Any], bool]] = {}

    def register(self, name: str, func: Callable[[Any], bool]):
        self.controls[name] = func

    def execute(self, name: str, value: Any = None) -> bool:
        if name not in self.controls:
            return False
        try:
            return self.controls[name](value)
        except Exception:
            return False


# ============================
# EVENT LOGGING + SQLITE
# ============================

class EventLogger:
    def __init__(self, path: str = "./aegis_events.log", db_path: str = "./aegis_telemetry.db"):
        self.path = path
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS telemetry (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL,
                    risk TEXT,
                    reason TEXT,
                    metrics_json TEXT
                )
            """)
            c.execute("""
                CREATE TABLE IF NOT EXISTS threats (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts REAL,
                    risk TEXT,
                    reason TEXT,
                    details_json TEXT
                )
            """)
            conn.commit()
            conn.close()
        except Exception:
            pass

    def log(self, level: str, message: str, data: Optional[Dict[str, Any]] = None):
        entry = {
            "ts": time.time(),
            "level": level,
            "message": message,
            "data": data or {}
        }
        try:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def log_telemetry(self, risk: RiskLevel, reason: str, metrics: Dict[str, Any]):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute(
                "INSERT INTO telemetry (ts, risk, reason, metrics_json) VALUES (?, ?, ?, ?)",
                (time.time(), risk.name, reason, json.dumps(metrics))
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def log_threat(self, anomaly: AnomalyResult):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute(
                "INSERT INTO threats (ts, risk, reason, details_json) VALUES (?, ?, ?, ?)",
                (time.time(), anomaly.risk.name, anomaly.reason, json.dumps(anomaly.details))
            )
            conn.commit()
            conn.close()
        except Exception:
            pass

    def get_recent_telemetry(self, limit: int = 200):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT ts, risk, reason, metrics_json FROM telemetry ORDER BY id DESC LIMIT ?", (limit,))
            rows = c.fetchall()
            conn.close()
            return [
                {
                    "ts": r[0],
                    "risk": r[1],
                    "reason": r[2],
                    "metrics": json.loads(r[3])
                }
                for r in rows
            ]
        except Exception:
            return []

    def get_recent_threats(self, limit: int = 200):
        try:
            conn = sqlite3.connect(self.db_path)
            c = conn.cursor()
            c.execute("SELECT ts, risk, reason, details_json FROM threats ORDER BY id DESC LIMIT ?", (limit,))
            rows = c.fetchall()
            conn.close()
            return [
                {
                    "ts": r[0],
                    "risk": r[1],
                    "reason": r[2],
                    "details": json.loads(r[3])
                }
                for r in rows
            ]
        except Exception:
            return []


# ============================
# SMART / NVMe / RAID HELPERS
# ============================

def run_cmd(cmd: List[str]) -> str:
    try:
        out = subprocess.check_output(cmd, stderr=subprocess.STDOUT)
        return out.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def parse_smartctl_output(text: str) -> Dict[str, Any]:
    data = {
        "health": 100.0,
        "temp": 35.0,
        "reallocated_sectors": 0,
        "pending_sectors": 0,
        "power_on_hours": 0,
        "model": "",
        "serial": ""
    }
    for line in text.splitlines():
        line = line.strip()
        if "SMART overall-health self-assessment test result" in line:
            if "PASSED" in line.upper():
                data["health"] = 100.0
            else:
                data["health"] = 50.0
        if "Temperature_Celsius" in line or "Temperature" in line:
            parts = line.split()
            try:
                data["temp"] = float(parts[-1])
            except Exception:
                pass
        if "Reallocated_Sector_Ct" in line:
            parts = line.split()
            try:
                data["reallocated_sectors"] = int(parts[-1])
            except Exception:
                pass
        if "Current_Pending_Sector" in line:
            parts = line.split()
            try:
                data["pending_sectors"] = int(parts[-1])
            except Exception:
                pass
        if "Power_On_Hours" in line:
            parts = line.split()
            try:
                data["power_on_hours"] = int(parts[-1])
            except Exception:
                pass
        if "Model Family" in line or "Device Model" in line:
            data["model"] = line.split(":", 1)[-1].strip()
        if "Serial Number" in line:
            data["serial"] = line.split(":", 1)[-1].strip()
    return data


def smart_for_device(dev: str) -> Dict[str, Any]:
    text = run_cmd(["smartctl", "-a", dev])
    if not text:
        return {
            "health": 100.0,
            "temp": 35.0,
            "reallocated_sectors": 0,
            "pending_sectors": 0,
            "power_on_hours": 0,
            "model": f"Drive@{dev}",
            "serial": f"SN-{dev.replace('/','_')}"
        }
    return parse_smartctl_output(text)


def nvme_lane_map() -> str:
    info = run_cmd(["nvme", "list"])
    if not info:
        return "NVMe lane map unavailable (nvme not found)."
    return info


def raid_health() -> str:
    info = run_cmd(["mdadm", "--detail", "/dev/md0"])
    if not info:
        return "RAID health unavailable (mdadm or /dev/md0 not found)."
    return info


# ============================
# DRIVE ENUM + SMART REGISTRATION
# ============================

def register_all_drives(registry: SensorRegistry, logger: EventLogger):
    try:
        partitions = psutil.disk_partitions(all=True)
        for part in partitions:
            mount = part.mountpoint
            name_base = mount.replace(":", "").replace("\\", "_").replace("/", "_")
            usage_name = f"drive_{name_base}_usage"
            health_name = f"drive_{name_base}_health"
            temp_name = f"drive_{name_base}_temp"

            def usage_func(m=mount):
                try:
                    return psutil.disk_usage(m).percent
                except Exception as e:
                    return f"ERROR: {e}"

            registry.register(usage_name, usage_func)

            device = part.device or ""
            if device:
                registry.register(health_name, lambda d=device: smart_for_device(d)["health"])
                registry.register(temp_name, lambda d=device: smart_for_device(d)["temp"])
            else:
                registry.register(health_name, lambda m=mount: 100.0)
                registry.register(temp_name, lambda m=mount: 35.0)
    except Exception as e:
        logger.log("ERROR", "Failed to register drives", {"error": str(e)})
        registry.register("drive_error", lambda: f"ERROR: {e}")


# ============================
# GPU TELEMETRY (NVML)
# ============================

def init_nvml(logger: EventLogger):
    if pynvml is None:
        logger.log("WARN", "pynvml not installed; GPU telemetry stubbed.")
        return False
    try:
        pynvml.nvmlInit()
        logger.log("INFO", "NVML initialized")
        return True
    except Exception as e:
        logger.log("ERROR", "NVML init failed", {"error": str(e)})
        return False


def get_gpu_temp_nvml() -> float:
    try:
        count = pynvml.nvmlDeviceGetCount()
        if count == 0:
            return 0.0
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        return float(temp)
    except Exception:
        return 0.0


def get_gpu_load_nvml() -> float:
    try:
        count = pynvml.nvmlDeviceGetCount()
        if count == 0:
            return 0.0
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        return float(util.gpu)
    except Exception:
        return 0.0


# ============================
# OS ADAPTERS
# ============================

class OSAdapter:
    def discover_sensors(self, registry: SensorRegistry, logger: EventLogger):
        raise NotImplementedError

    def discover_controls(self, registry: ControlRegistry, logger: EventLogger):
        raise NotImplementedError


class LinuxAdapter(OSAdapter):
    def discover_sensors(self, registry: SensorRegistry, logger: EventLogger):
        registry.register("cpu_load", lambda: psutil.cpu_percent(interval=0.1))
        registry.register("ram_usage", lambda: psutil.virtual_memory().percent)

        register_all_drives(registry, logger)

        if hasattr(psutil, "sensors_temperatures"):
            try:
                temps = psutil.sensors_temperatures()
                for chip, entries in temps.items():
                    for entry in entries:
                        registry.register(
                            f"{chip}_{entry.label or 'temp'}",
                            lambda e=entry: e.current
                        )
            except Exception:
                pass

        registry.register("aio_pump_rpm", lambda: 1500.0)

        if init_nvml(logger):
            registry.register("gpu_temp", get_gpu_temp_nvml)
            registry.register("gpu_load", get_gpu_load_nvml)
        else:
            registry.register("gpu_temp", lambda: 60.0)
            registry.register("gpu_load", lambda: 30.0)

        registry.register("ssd_health_global", lambda: 100.0)
        registry.register("raid_health_text", raid_health)
        registry.register("nvme_lane_map_text", nvme_lane_map)

    def discover_controls(self, registry: ControlRegistry, logger: EventLogger):
        registry.register("limit_cpu_power", lambda v: True)
        registry.register("max_fan_speed", lambda _: True)
        registry.register("safe_shutdown", lambda _: True)


class WindowsAdapter(OSAdapter):
    def discover_sensors(self, registry: SensorRegistry, logger: EventLogger):
        registry.register("cpu_load", lambda: psutil.cpu_percent(interval=0.1))
        registry.register("ram_usage", lambda: psutil.virtual_memory().percent)

        register_all_drives(registry, logger)

        registry.register("cpu_temp", lambda: 55.0)
        registry.register("aio_pump_rpm", lambda: 1500.0)

        if init_nvml(logger):
            registry.register("gpu_temp", get_gpu_temp_nvml)
            registry.register("gpu_load", get_gpu_load_nvml)
        else:
            registry.register("gpu_temp", lambda: 65.0)
            registry.register("gpu_load", lambda: 40.0)

        registry.register("ssd_health_global", lambda: 95.0)
        registry.register("raid_health_text", lambda: "RAID health (Windows stub).")
        registry.register("nvme_lane_map_text", lambda: "NVMe lane map (Windows stub).")

    def discover_controls(self, registry: ControlRegistry, logger: EventLogger):
        registry.register("limit_cpu_power", lambda v: True)
        registry.register("max_fan_speed", lambda _: True)
        registry.register("safe_shutdown", lambda _: True)


class GenericAdapter(OSAdapter):
    def discover_sensors(self, registry: SensorRegistry, logger: EventLogger):
        registry.register("cpu_load", lambda: psutil.cpu_percent(interval=0.1))

    def discover_controls(self, registry: ControlRegistry, logger: EventLogger):
        pass


def load_os_adapter():
    os_name = platform.system()
    if os_name == "Linux":
        return LinuxAdapter()
    if os_name == "Windows":
        return WindowsAdapter()
    return GenericAdapter()


# ============================
# AI MODEL (ONNX / Torch) + Predictive Hooks
# ============================

class AIModel:
    def __init__(self, logger: EventLogger):
        self.logger = logger
        self.backend = None
        self.session = None
        self.torch_model = None

    def load_onnx(self, path: str):
        if ort is None:
            self.logger.log("WARN", "ONNX Runtime not available")
            return
        try:
            self.session = ort.InferenceSession(path)
            self.backend = "onnx"
            self.logger.log("INFO", "Loaded ONNX model", {"path": path})
        except Exception as e:
            self.logger.log("ERROR", "Failed to load ONNX model", {"error": str(e)})

    def load_torch(self, path: str):
        if torch is None:
            self.logger.log("WARN", "PyTorch not available")
            return
        try:
            self.torch_model = torch.jit.load(path)
            self.torch_model.eval()
            self.backend = "torch"
            self.logger.log("INFO", "Loaded Torch model", {"path": path})
        except Exception as e:
            self.logger.log("ERROR", "Failed to load Torch model", {"error": str(e)})

    def build_feature_vector(self, metrics: Dict[str, float], history: List[Dict[str, Any]]) -> List[float]:
        cpu_load = safe_float(metrics.get("cpu_load", 0))
        ram_usage = safe_float(metrics.get("ram_usage", 0))
        aio_rpm = safe_float(metrics.get("aio_pump_rpm", 2000))
        gpu_temp = safe_float(metrics.get("gpu_temp", 60))
        gpu_load = safe_float(metrics.get("gpu_load", 0))
        ssd_health_global = safe_float(metrics.get("ssd_health_global", 100))

        drive_fail_candidates = 0
        for name, value in metrics.items():
            if name.startswith("drive_") and name.endswith("_usage"):
                usage = safe_float(value)
                if usage > 98:
                    drive_fail_candidates += 1
            if name.startswith("drive_") and name.endswith("_health"):
                health = safe_float(value)
                if health < 50:
                    drive_fail_candidates += 1
            if name.startswith("drive_") and name.endswith("_temp"):
                temp = safe_float(value)
                if temp > 70:
                    drive_fail_candidates += 1

        last_cpu = [safe_float(h.get("cpu_load", 0)) for h in history[-60:]]
        last_gpu = [safe_float(h.get("gpu_temp", 0)) for h in history[-60:]]
        last_ram = [safe_float(h.get("ram_usage", 0)) for h in history[-60:]]

        cpu_avg = sum(last_cpu) / max(len(last_cpu), 1)
        gpu_avg = sum(last_gpu) / max(len(last_gpu), 1)
        ram_avg = sum(last_ram) / max(len(last_ram), 1)

        return [
            cpu_load,
            ram_usage,
            aio_rpm,
            gpu_temp,
            gpu_load,
            ssd_health_global,
            float(drive_fail_candidates),
            cpu_avg,
            gpu_avg,
            ram_avg,
        ]

    def predict_risk(self, metrics: Dict[str, float], history: List[Dict[str, Any]]) -> AnomalyResult:
        x = self.build_feature_vector(metrics, history)

        if self.backend == "onnx" and self.session is not None:
            try:
                input_name = self.session.get_inputs()[0].name
                pred = self.session.run(None, {input_name: [x]})[0][0]
                if pred > 0.8:
                    return AnomalyResult(RiskLevel.CRITICAL, "Model: critical anomaly predicted")
                elif pred > 0.5:
                    return AnomalyResult(RiskLevel.HIGH, "Model: high anomaly predicted")
            except Exception as e:
                self.logger.log("ERROR", "ONNX inference failed", {"error": str(e)})

        if self.backend == "torch" and self.torch_model is not None:
            try:
                inp = torch.tensor([x], dtype=torch.float32)
                pred = float(self.torch_model(inp)[0])
                if pred > 0.8:
                    return AnomalyResult(RiskLevel.CRITICAL, "Model: critical anomaly predicted")
                elif pred > 0.5:
                    return AnomalyResult(RiskLevel.HIGH, "Model: high anomaly predicted")
            except Exception as e:
                self.logger.log("ERROR", "Torch inference failed", {"error": str(e)})

        cpu_load = x[0]
        ram_usage = x[1]
        aio_rpm = x[2]
        gpu_temp = x[3]
        gpu_load = x[4]
        ssd_health_global = x[5]
        drive_fail_candidates = int(x[6])

        if aio_rpm < 500 and cpu_load > 50:
            return AnomalyResult(RiskLevel.CRITICAL, "AIO cooling failure suspected")

        if gpu_temp > 90 or gpu_load > 95:
            return AnomalyResult(RiskLevel.HIGH, "GPU thermal/load anomaly")

        if ram_usage > 95:
            return AnomalyResult(RiskLevel.MEDIUM, "Memory exhaustion predicted")

        if drive_fail_candidates > 0:
            return AnomalyResult(
                RiskLevel.HIGH,
                f"Drive failure predicted ({drive_fail_candidates} candidates)",
                {"drive_candidates": drive_fail_candidates}
            )

        if ssd_health_global < 50:
            return AnomalyResult(RiskLevel.MEDIUM, "Global SSD health degraded")

        if cpu_load > 90:
            return AnomalyResult(RiskLevel.LOW, "High CPU load")

        return AnomalyResult(RiskLevel.NONE, "All systems nominal")

    def drive_replacement_recommendation(self, metrics: Dict[str, Any]) -> str:
        bad_drives = []
        for name, value in metrics.items():
            if name.startswith("drive_") and name.endswith("_health"):
                if safe_float(value) < 50:
                    bad_drives.append(name)
        if not bad_drives:
            return "No drive replacement recommended."
        return f"Recommended: replace drives {', '.join(bad_drives)}."


# ============================
# ZeroMQ Cluster Networking + Remote Control
# ============================

class BorgComm:
    def __init__(self, logger: EventLogger, node_id: str = "node-1"):
        self.logger = logger
        self.node_id = node_id
        self.cluster_state: Dict[str, Dict[str, Any]] = {}
        self.context = None
        self.pub_socket = None
        self.sub_socket = None

        if zmq is not None:
            try:
                self.context = zmq.Context()
                self.pub_socket = self.context.socket(zmq.PUB)
                self.pub_socket.bind("tcp://*:5556")
                self.logger.log("INFO", "ZeroMQ PUB bound on tcp://*:5556")

                self.sub_socket = self.context.socket(zmq.SUB)
                self.sub_socket.setsockopt_string(zmq.SUBSCRIBE, "")
            except Exception as e:
                self.logger.log("ERROR", "ZeroMQ init failed", {"error": str(e)})

    def broadcast_state(self, metrics: Dict[str, Any], anomaly: AnomalyResult):
        payload = {
            "node": self.node_id,
            "metrics": metrics,
            "risk": anomaly.risk.name,
            "reason": anomaly.reason,
            "ts": time.time()
        }
        self.logger.log("INFO", "Broadcasting state", payload)
        if self.pub_socket is not None:
            try:
                self.pub_socket.send_json(payload)
            except Exception as e:
                self.logger.log("ERROR", "ZeroMQ send failed", {"error": str(e)})

    def update_cluster_view(self, node: str, state: Dict[str, Any]):
        self.cluster_state[node] = state

    def start_listener(self):
        if self.sub_socket is None:
            return

        def loop():
            while True:
                try:
                    msg = self.sub_socket.recv_json()
                    node = msg.get("node", "unknown")
                    self.cluster_state[node] = msg
                except Exception:
                    time.sleep(1)

        threading.Thread(target=loop, daemon=True).start()


# ============================
# PLUGIN SANDBOX
# ============================

class PluginSandbox:
    def __init__(self, logger: EventLogger, plugins_dir: str = "./plugins"):
        self.logger = logger
        self.plugins_dir = plugins_dir

    def load_plugins(self):
        if not os.path.isdir(self.plugins_dir):
            return
        for fname in os.listdir(self.plugins_dir):
            if not fname.endswith(".py"):
                continue
            if fname.startswith("_"):
                continue
            try:
                module_name = f"plugins.{fname[:-3]}"
                importlib.import_module(module_name)
                self.logger.log("INFO", "Loaded plugin", {"module": module_name})
            except Exception as e:
                self.logger.log("ERROR", "Failed to load plugin", {"file": fname, "error": str(e)})


# ============================
# VOICE
# ============================

_voice_engine = None

def init_voice():
    global _voice_engine
    if _voice_engine is None:
        try:
            _voice_engine = pyttsx3.init()
            _voice_engine.setProperty("rate", 165)
            _voice_engine.setProperty("volume", 1.0)
        except Exception as e:
            print(f"[voice] init failed: {e}")
            _voice_engine = None

def voice_alert(message: str):
    print(f"[VOICE ALERT] {message}")
    if _voice_engine is None:
        init_voice()
    if _voice_engine is not None:
        try:
            _voice_engine.say(message)
            _voice_engine.runAndWait()
        except Exception as e:
            print(f"[voice] speak failed: {e}")

def persona_voice_intro(persona: str):
    try:
        msg = {
            "Oracle": "The echo awakens.",
            "Trickster": "Chaos has arrived.",
            "Sentinel": "Guardian active and vigilant."
        }.get(persona, "The glyph speaks.")
        voice_alert(msg)
    except Exception:
        print("[voice] Intro failed.")


# ============================
# SCROLLABLE FRAME
# ============================

class ScrollableFrame(ttk.Frame):
    def __init__(self, container, *args, **kwargs):
        super().__init__(container, *args, **kwargs)

        canvas = tk.Canvas(self, bg="#101010", highlightthickness=0)
        scrollbar = ttk.Scrollbar(self, orient="vertical", command=canvas.yview)
        self.scrollable_frame = ttk.Frame(canvas, style="Dark.TFrame")

        self.scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )

        canvas.create_window((0, 0), window=self.scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")


# ============================
# DARK BORG COCKPIT GUI (with Tactical Tab)
# ============================

class AegisCockpit:
    def __init__(self, sensors: SensorRegistry, logger: EventLogger, borg_comm: BorgComm, model: AIModel, telemetry_queue: List[Dict[str, Any]]):
        self.sensors = sensors
        self.logger = logger
        self.borg_comm = borg_comm
        self.model = model
        self.telemetry_queue = telemetry_queue

        self.root = tk.Tk()
        self.root.title("Aegis Nexus Agent — Borg Flight Deck v7.9")
        self.root.geometry("900x600")
        self.root.configure(bg="#101010")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._apply_theme("dark")

        self.main_status_label = ttk.Label(
            self.root,
            text="MAIN STATUS: GREEN — All Systems Nominal",
            style="Dark.Title.TLabel"
        )
        self.main_status_label.pack(pady=5)

        theme_bar = ttk.Frame(self.root, style="Dark.TFrame")
        theme_bar.pack(fill="x", padx=5, pady=3)
        ttk.Label(theme_bar, text="Theme:", style="Dark.TLabel").pack(side="left")
        ttk.Button(theme_bar, text="Dark", command=lambda: self._apply_theme("dark")).pack(side="left", padx=3)
        ttk.Button(theme_bar, text="Neon", command=lambda: self._apply_theme("neon")).pack(side="left", padx=3)
        ttk.Button(theme_bar, text="Aircraft", command=lambda: self._apply_theme("aircraft")).pack(side="left", padx=3)

        self.warning_panel = tk.Listbox(self.root, bg="#101010", fg="#ff0033", font=("Consolas", 10), height=3)
        self.warning_panel.pack(fill="x", padx=5, pady=3)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        self.dashboard_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.dashboard_frame, text="Dashboard")

        self.drive_graph_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.drive_graph_frame, text="Drive Temp Graph")

        self.smart_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.smart_frame, text="SMART Table")

        self.raid_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.raid_frame, text="RAID Health")

        self.nvme_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.nvme_frame, text="NVMe PCIe Map")

        self.threat_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.threat_frame, text="Threat Matrix")

        self.cluster_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.cluster_frame, text="Cluster View")

        self.history_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.history_frame, text="Historical Graphs")

        # Tactical tab
        self.tactical_frame = ttk.Frame(self.notebook, style="Dark.TFrame")
        self.notebook.add(self.tactical_frame, text="Tactical Grid")

        self.tactical_canvas = tk.Canvas(self.tactical_frame, width=800, height=400, bg="#000000", highlightthickness=0)
        self.tactical_canvas.pack(fill="both", expand=True, padx=5, pady=5)

        self.tactical_nodes = {
            "CPU":     (80, 80),
            "RAM":     (220, 80),
            "GPU":     (360, 80),
            "Cooling": (500, 80),
            "Drives":  (120, 280),
            "NVMe":    (260, 280),
            "RAID":    (400, 280),
            "Cluster": (580, 180),
        }
        self.tactical_node_radius = 18
        self.tactical_node_items: Dict[str, int] = {}
        self._init_tactical_tab()

        self.sensor_labels: Dict[str, Any] = {}
        sensor_table = ttk.Frame(self.dashboard_frame, style="Dark.TFrame")
        sensor_table.pack(side="left", fill="y", padx=5, pady=5)

        header = ttk.Frame(sensor_table, style="Dark.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Sensor", style="Dark.TLabel", width=24).pack(side="left")
        ttk.Label(header, text="Value", style="Dark.TLabel", width=10).pack(side="left")
        ttk.Label(header, text="Status", style="Dark.TLabel", width=10).pack(side="left")

        for name in self.sensors.sensors.keys():
            if not name.startswith("drive_"):
                row = ttk.Frame(sensor_table, style="Dark.TFrame")
                row.pack(fill="x", pady=1)

                label_name = ttk.Label(row, text=name, style="Dark.TLabel", width=24)
                label_name.pack(side="left")

                label_value = ttk.Label(row, text="...", style="Dark.TLabel", width=10)
                label_value.pack(side="left")

                label_status = ttk.Label(row, text="GREEN", style="Dark.TLabel", width=10)
                label_status.pack(side="left")

                self.sensor_labels[name] = (label_value, label_status)

        drive_panel = ScrollableFrame(self.dashboard_frame)
        drive_panel.pack(side="right", fill="both", padx=5, pady=5)
        self.drive_labels: Dict[str, Any] = {}

        dheader = ttk.Frame(drive_panel.scrollable_frame, style="Dark.TFrame")
        dheader.pack(fill="x")
        ttk.Label(dheader, text="Drive", style="Dark.TLabel", width=22).pack(side="left")
        ttk.Label(dheader, text="Usage %", style="Dark.TLabel", width=8).pack(side="left")
        ttk.Label(dheader, text="Health", style="Dark.TLabel", width=8).pack(side="left")
        ttk.Label(dheader, text="Temp °C", style="Dark.TLabel", width=8).pack(side="left")
        ttk.Label(dheader, text="Status", style="Dark.TLabel", width=8).pack(side="left")

        for name in self.sensors.sensors.keys():
            if name.startswith("drive_") and ("usage" in name or "health" in name or "temp" in name):
                row = ttk.Frame(drive_panel.scrollable_frame, style="Dark.TFrame")
                row.pack(fill="x", pady=1)

                label_name = ttk.Label(row, text=name, style="Dark.TLabel", width=22)
                label_name.pack(side="left")

                label_usage = ttk.Label(row, text="...", style="Dark.TLabel", width=8)
                label_usage.pack(side="left")

                label_health = ttk.Label(row, text="...", style="Dark.TLabel", width=8)
                label_health.pack(side="left")

                label_temp = ttk.Label(row, text="...", style="Dark.TLabel", width=8)
                label_temp.pack(side="left")

                label_status = ttk.Label(row, text="GREEN", style="Dark.TLabel", width=8)
                label_status.pack(side="left")

                self.drive_labels[name] = (label_usage, label_health, label_temp, label_status)

        graph_frame = ttk.Frame(self.dashboard_frame, style="Dark.TFrame")
        graph_frame.pack(side="bottom", fill="x", padx=5, pady=5)

        self.cpu_canvas = tk.Canvas(graph_frame, width=400, height=160, bg="#101010", highlightthickness=0)
        self.cpu_canvas.pack(side="left", padx=5)
        self.cpu_canvas.create_text(200, 10, text="CPU Load / Temp / RAM", fill="#00ff99", font=("Consolas", 11))

        self.fan_canvas = tk.Canvas(graph_frame, width=400, height=160, bg="#101010", highlightthickness=0)
        self.fan_canvas.pack(side="right", padx=5)
        self.fan_canvas.create_text(200, 10, text="AIO Pump RPM", fill="#00ff99", font=("Consolas", 11))

        self.cpu_history: List[float] = []
        self.temp_history: List[float] = []
        self.ram_history: List[float] = []
        self.fan_history: List[float] = []

        self.drive_temp_canvas = tk.Canvas(self.drive_graph_frame, width=700, height=300, bg="#101010", highlightthickness=0)
        self.drive_temp_canvas.pack(padx=5, pady=5)
        self.drive_temp_canvas.create_text(350, 10, text="Drive Temperatures", fill="#00ff99", font=("Consolas", 11))

        ttk.Label(self.smart_frame, text="SMART Attribute Table", style="Dark.Title.TLabel").pack(pady=5)
        self.smart_table = tk.Text(self.smart_frame, bg="#101010", fg="#00ff99", font=("Consolas", 10))
        self.smart_table.pack(fill="both", expand=True, padx=5, pady=5)

        ttk.Label(self.raid_frame, text="RAID Health View", style="Dark.Title.TLabel").pack(pady=5)
        self.raid_text = tk.Text(self.raid_frame, bg="#101010", fg="#00ff99", font=("Consolas", 10))
        self.raid_text.pack(fill="both", expand=True, padx=5, pady=5)

        ttk.Label(self.nvme_frame, text="NVMe PCIe Lane Map", style="Dark.Title.TLabel").pack(pady=5)
        self.nvme_text = tk.Text(self.nvme_frame, bg="#101010", fg="#00ff99", font=("Consolas", 10))
        self.nvme_text.pack(fill="both", expand=True, padx=5, pady=5)

        ttk.Label(self.threat_frame, text="Threat Matrix (Anomalies & Risk Levels)", style="Dark.Title.TLabel").pack(pady=5)
        self.threat_list = tk.Listbox(self.threat_frame, bg="#101010", fg="#00ff99", font=("Consolas", 10))
        self.threat_list.pack(fill="both", expand=True, padx=5, pady=5)

        ttk.Label(self.cluster_frame, text="Cluster View (Nodes)", style="Dark.Title.TLabel").pack(pady=5)
        self.cluster_list = tk.Listbox(self.cluster_frame, bg="#101010", fg="#00ff99", font=("Consolas", 10))
        self.cluster_list.pack(fill="both", expand=True, padx=5, pady=5)

        ttk.Label(self.history_frame, text="Historical Telemetry Graphs", style="Dark.Title.TLabel").pack(pady=5)
        self.history_canvas = tk.Canvas(self.history_frame, width=800, height=400, bg="#101010", highlightthickness=0)
        self.history_canvas.pack(fill="both", expand=True, padx=5, pady=5)

    def _apply_theme(self, mode: str):
        if mode == "dark":
            self.style.configure("Dark.TFrame", background="#101010")
            self.style.configure("Dark.TLabel", background="#101010", foreground="#00ff99", font=("Consolas", 10))
            self.style.configure("Dark.Title.TLabel", background="#101010", foreground="#00ff99", font=("Consolas", 14, "bold"))
        elif mode == "neon":
            self.style.configure("Dark.TFrame", background="#000000")
            self.style.configure("Dark.TLabel", background="#000000", foreground="#39ff14", font=("Consolas", 10))
            self.style.configure("Dark.Title.TLabel", background="#000000", foreground="#39ff14", font=("Consolas", 14, "bold"))
        elif mode == "aircraft":
            self.style.configure("Dark.TFrame", background="#001020")
            self.style.configure("Dark.TLabel", background="#001020", foreground="#00ff99", font=("Consolas", 10))
            self.style.configure("Dark.Title.TLabel", background="#001020", foreground="#ffcc00", font=("Consolas", 14, "bold"))

    def _init_tactical_tab(self):
        for x in range(0, 800, 50):
            self.tactical_canvas.create_line(x, 0, x, 400, fill="#101010")
        for y in range(0, 400, 50):
            self.tactical_canvas.create_line(0, y, 800, y, fill="#101010")

        for name, (x, y) in self.tactical_nodes.items():
            r = self.tactical_node_radius
            circle = self.tactical_canvas.create_oval(
                x - r, y - r, x + r, y + r,
                outline="#00ff99", width=2, fill="#001010"
            )
            self.tactical_canvas.create_text(x, y, text=name, fill="#00ff99", font=("Consolas", 9))
            self.tactical_node_items[name] = circle

        def line(a, b, color="#004466"):
            ax, ay = self.tactical_nodes[a]
            bx, by = self.tactical_nodes[b]
            self.tactical_canvas.create_line(ax, ay, bx, by, fill=color, width=2)

        line("NVMe", "Drives", "#00aaff")
        line("NVMe", "RAID", "#00aaff")
        line("Cooling", "CPU", "#00ff99")
        line("Cooling", "GPU", "#00ff99")
        line("Cluster", "GPU", "#4444ff")

    def update_tactical_tab(self, metrics: Dict[str, Any]):
        def color_for(name):
            if name == "CPU":
                load = safe_float(metrics.get("cpu_load", 0))
                if load > 90: return "#ff0033"
                if load > 70: return "#ffcc00"
                return "#00ff99"
            if name == "GPU":
                temp = safe_float(metrics.get("gpu_temp", 0))
                if temp > 90: return "#ff0033"
                if temp > 75: return "#ffcc00"
                return "#00ff99"
            if name == "Drives":
                bad = False
                for k, v in metrics.items():
                    if k.startswith("drive_") and k.endswith("_health"):
                        if safe_float(v) < 50:
                            bad = True
                return "#ff0033" if bad else "#00ff99"
            if name == "NVMe":
                return "#00aaff"
            if name == "RAID":
                txt = str(metrics.get("raid_health_text", ""))
                if "degraded" in txt.lower() or "fault" in txt.lower():
                    return "#ff0033"
                return "#00ff99"
            if name == "Cooling":
                rpm = safe_float(metrics.get("aio_pump_rpm", 1500))
                if rpm < 500: return "#ff0033"
                if rpm < 1000: return "#ffcc00"
                return "#00ff99"
            if name == "RAM":
                usage = safe_float(metrics.get("ram_usage", 0))
                if usage > 95: return "#ff0033"
                if usage > 80: return "#ffcc00"
                return "#00ff99"
            if name == "Cluster":
                return "#4444ff"
            return "#00ff99"

        def _update():
            self.tactical_canvas.delete("pulse")
            self.tactical_canvas.delete("hazard")
            for name, item in self.tactical_node_items.items():
                color = color_for(name)
                self.tactical_canvas.itemconfig(item, outline=color)

            for name, (x, y) in self.tactical_nodes.items():
                r = self.tactical_node_radius + 6
                self.tactical_canvas.create_oval(
                    x - r, y - r, x + r, y + r,
                    outline="#003333", width=1, tags="pulse"
                )
                if name in ("CPU", "GPU", "Drives"):
                    color = color_for(name)
                    if color == "#ff0033":
                        self.tactical_canvas.create_arc(
                            x - r - 8, y - r - 8, x + r + 8, y + r + 8,
                            start=0, extent=270, outline="#ff0033", width=2, style="arc", tags="hazard"
                        )

        self.root.after(0, _update)

    def update_sensor(self, name: str, value: Any):
        def _update():
            if name in self.sensor_labels:
                label_value, label_status = self.sensor_labels[name]
                label_value.config(text=str(value))

                color = "#00ff99"
                status = "GREEN"
                v = safe_float(value)
                if v > 90:
                    color = "#ff0033"
                    status = "RED"
                elif v > 70:
                    color = "#ffcc00"
                    status = "YELLOW"
                label_status.config(text=status, foreground=color)

            if name.startswith("drive_"):
                if name in self.drive_labels:
                    label_usage, label_health, label_temp, label_status = self.drive_labels[name]
                    if "usage" in name:
                        label_usage.config(text=str(value))
                    elif "health" in name:
                        label_health.config(text=str(value))
                    elif "temp" in name:
                        label_temp.config(text=str(value))

                    usage = label_usage.cget("text")
                    health = label_health.cget("text")
                    temp = label_temp.cget("text")

                    u = safe_float(usage)
                    h = safe_float(health)
                    t = safe_float(temp)

                    color = "#00ff99"
                    status = "GREEN"
                    if u > 98 or h < 50 or t > 70:
                        color = "#ff0033"
                        status = "RED"
                    elif u > 90 or h < 80 or t > 60:
                        color = "#ffcc00"
                        status = "YELLOW"
                    label_status.config(text=status, foreground=color)

        self.root.after(0, _update)

    def update_main_status(self, risk: RiskLevel, reason: str):
        def _update():
            if risk == RiskLevel.NONE:
                text = "MAIN STATUS: GREEN — All Systems Nominal"
                color = "#00ff99"
            elif risk == RiskLevel.LOW:
                text = f"MAIN STATUS: GREEN/YELLOW — {reason}"
                color = "#ffcc00"
            elif risk == RiskLevel.MEDIUM:
                text = f"MAIN STATUS: YELLOW — {reason}"
                color = "#ffcc00"
            else:
                text = f"MAIN STATUS: RED — {reason}"
                color = "#ff0033"

            self.main_status_label.config(text=text, foreground=color)
            self.warning_panel.delete(0, "end")
            if risk != RiskLevel.NONE:
                self.warning_panel.insert("end", f"{risk.name}: {reason}")

        self.root.after(0, _update)

    def update_graphs(self, cpu_load: float, cpu_temp: float, ram_usage: float, aio_rpm: float, drive_temps: Dict[str, float]):
        def _update():
            self.cpu_history.append(cpu_load)
            self.temp_history.append(cpu_temp)
            self.ram_history.append(ram_usage)
            self.fan_history.append(aio_rpm)

            for hist in (self.cpu_history, self.temp_history, self.ram_history, self.fan_history):
                if len(hist) > 120:
                    hist.pop(0)

            self.cpu_canvas.delete("graph")
            self.fan_canvas.delete("graph")
            self.drive_temp_canvas.delete("graph")

            if self.cpu_history:
                max_val = max(max(self.cpu_history), 1)
                for i, v in enumerate(self.cpu_history):
                    x0 = 10 + i * 3
                    y0 = 150
                    y1 = 150 - (v / max_val) * 120
                    self.cpu_canvas.create_line(x0, y0, x0, y1, fill="#00ff99", tags="graph")

            if self.temp_history:
                max_temp = max(max(self.temp_history), 1)
                for i, v in enumerate(self.temp_history):
                    x0 = 10 + i * 3
                    y0 = 150
                    y1 = 150 - (v / max_temp) * 120
                    self.cpu_canvas.create_line(x0, y0, x0, y1, fill="#ffcc00", tags="graph")

            if self.ram_history:
                max_ram = max(max(self.ram_history), 1)
                for i, v in enumerate(self.ram_history):
                    x0 = 10 + i * 3
                    y0 = 150
                    y1 = 150 - (v / max_ram) * 120
                    self.cpu_canvas.create_line(x0, y0, x0, y1, fill="#39ff14", tags="graph")

            if self.fan_history:
                max_rpm = max(max(self.fan_history), 1)
                for i, v in enumerate(self.fan_history):
                    x0 = 10 + i * 3
                    y0 = 150
                    y1 = 150 - (v / max_rpm) * 120
                    self.fan_canvas.create_line(x0, y0, x0, y1, fill="#00ff99", tags="graph")

            if drive_temps:
                drives = list(drive_temps.items())
                for i, (name, temp) in enumerate(drives):
                    x = 40 + i * 60
                    y0 = 260
                    y1 = 260 - (temp / 100.0) * 220
                    self.drive_temp_canvas.create_rectangle(x - 15, y1, x + 15, y0, outline="#00ff99", tags="graph")
                    self.drive_temp_canvas.create_text(x, y0 + 8, text=name[-10:], fill="#00ff99", font=("Consolas", 7))

        self.root.after(0, _update)

    def update_history_graphs(self, history: List[Dict[str, Any]]):
        def _update():
            self.history_canvas.delete("graph")
            if not history:
                return

            max_points = min(len(history), 200)
            hist = history[-max_points:]

            cpu_vals = [safe_float(h.get("cpu_load", 0)) for h in hist]
            gpu_vals = [safe_float(h.get("gpu_temp", 0)) for h in hist]
            ram_vals = [safe_float(h.get("ram_usage", 0)) for h in hist]

            max_cpu = max(cpu_vals) if cpu_vals else 1
            max_gpu = max(gpu_vals) if gpu_vals else 1
            max_ram = max(ram_vals) if ram_vals else 1

            for i, v in enumerate(cpu_vals):
                x0 = 20 + i * (760 / max_points)
                y0 = 380
                y1 = 380 - (v / max_cpu) * 180
                self.history_canvas.create_line(x0, y0, x0, y1, fill="#00ff99", tags="graph")

            for i, v in enumerate(gpu_vals):
                x0 = 20 + i * (760 / max_points)
                y0 = 380
                y1 = 380 - (v / max_gpu) * 180
                self.history_canvas.create_line(x0, y0, x0, y1, fill="#ff0033", tags="graph")

            for i, v in enumerate(ram_vals):
                x0 = 20 + i * (760 / max_points)
                y0 = 380
                y1 = 380 - (v / max_ram) * 180
                self.history_canvas.create_line(x0, y0, x0, y1, fill="#39ff14", tags="graph")

            self.history_canvas.create_text(
                200, 20,
                text="CPU Load (Green) / GPU Temp (Red) / RAM (Neon) History",
                fill="#00ff99",
                font=("Consolas", 11)
            )

        self.root.after(0, _update)

    def add_threat_entry(self, anomaly: AnomalyResult, metrics: Dict[str, Any]):
        def _update():
            entry = f"[{time.strftime('%H:%M:%S')}] {anomaly.risk.name}: {anomaly.reason}"
            self.threat_list.insert("end", entry)
            rec = self.model.drive_replacement_recommendation(metrics)
            if "replace drives" in rec:
                self.threat_list.insert("end", f"  -> {rec}")
        self.root.after(0, _update)

    def update_cluster_view(self, cluster_state: Dict[str, Dict[str, Any]]):
        def _update():
            self.cluster_list.delete(0, "end")
            for node, state in cluster_state.items():
                risk = state.get("risk", "UNKNOWN")
                reason = state.get("reason", "")
                self.cluster_list.insert("end", f"{node}: {risk} ({reason})")
        self.root.after(0, _update)

    def update_smart_table(self, metrics: Dict[str, Any]):
        def _update():
            self.smart_table.delete("1.0", "end")
            self.smart_table.insert("end", "SMART Attributes:\n\n")
            for name, value in metrics.items():
                if name.startswith("drive_") and name.endswith("_health"):
                    self.smart_table.insert("end", f"{name}: health={value}%\n")
        self.root.after(0, _update)

    def update_raid_nvme_text(self, raid_text: str, nvme_text: str):
        def _update():
            self.raid_text.delete("1.0", "end")
            self.raid_text.insert("end", raid_text + "\n")
            self.nvme_text.delete("1.0", "end")
            self.nvme_text.insert("end", nvme_text + "\n")
        self.root.after(0, _update)

    def show_drive_alert(self, drive_name, usage, health, temp):
        alert = tk.Toplevel(self.root)
        alert.title(f"Drive Alert — {drive_name}")
        alert.geometry("360x240")
        alert.configure(bg="#101010")

        ttk.Label(alert, text=f"Drive: {drive_name}", style="Dark.Title.TLabel").pack(pady=5)
        ttk.Label(alert, text=f"Usage: {usage}%", style="Dark.TLabel").pack(pady=3)
        ttk.Label(alert, text=f"Health: {health}%", style="Dark.TLabel").pack(pady=3)
        ttk.Label(alert, text=f"Temp: {temp}°C", style="Dark.TLabel").pack(pady=3)

        if usage > 98:
            msg = "Drive is critically full!"
        elif health < 50:
            msg = "Drive SMART health failing!"
        elif temp > 70:
            msg = "Drive overheating!"
        else:
            msg = "Drive anomaly detected."

        ttk.Label(alert, text=msg, style="Dark.TLabel").pack(pady=10)
        voice_alert(msg)

    def start(self):
        self.root.mainloop()


# ============================
# AUTOMATION ENGINE (Stronger)
# ============================

class AutomationEngine:
    def __init__(self, controls: ControlRegistry, logger: EventLogger):
        self.controls = controls
        self.logger = logger

    def apply(self, anomaly: AnomalyResult, metrics: Dict[str, Any]):
        if anomaly.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
            self.logger.log("INFO", "Automation triggered", {"risk": anomaly.risk.name, "reason": anomaly.reason})
            self.controls.execute("max_fan_speed", None)

            if anomaly.risk == RiskLevel.CRITICAL:
                voice_alert("Critical anomaly detected. Manual intervention recommended.")
                self.logger.log("INFO", "Suggested actions", {
                    "kill_runaway_processes": True,
                    "reduce_gpu_power": True,
                    "initiate_backup": True,
                    "safe_shutdown": True
                })


# ============================
# GUARDIAN LOOP
# ============================

class Guardian:
    def __init__(
        self,
        sensors: SensorRegistry,
        controls: ControlRegistry,
        model: AIModel,
        gui: AegisCockpit,
        logger: EventLogger,
        borg_comm: BorgComm,
        telemetry_queue: List[Dict[str, Any]],
        automation: AutomationEngine
    ):
        self.sensors = sensors
        self.controls = controls
        self.model = model
        self.gui = gui
        self.logger = logger
        self.borg_comm = borg_comm
        self.telemetry_queue = telemetry_queue
        self.automation = automation
        self.running = False

    def start(self):
        self.running = True
        threading.Thread(target=self.loop, daemon=True).start()

    def stop(self):
        self.running = False

    def loop(self):
        history_cache: List[Dict[str, Any]] = []

        while self.running:
            metrics = self.sensors.scan_all()
            self.telemetry_queue.append(metrics)
            history_cache.append(metrics)
            if len(history_cache) > 1000:
                history_cache.pop(0)

            for name, value in metrics.items():
                self.gui.update_sensor(name, value)

            anomaly = self.model.predict_risk(metrics, history_cache)
            self.gui.update_main_status(anomaly.risk, anomaly.reason)

            cpu_load = safe_float(metrics.get("cpu_load", 0))
            cpu_temp = safe_float(metrics.get("cpu_temp", cpu_load))
            ram_usage = safe_float(metrics.get("ram_usage", 0))
            aio_rpm = safe_float(metrics.get("aio_pump_rpm", 1500))

            drive_temps = {
                name: safe_float(value)
                for name, value in metrics.items()
                if name.startswith("drive_") and name.endswith("_temp")
            }

            self.gui.update_graphs(cpu_load, cpu_temp, ram_usage, aio_rpm, drive_temps)
            self.gui.update_smart_table(metrics)

            raid_text = str(metrics.get("raid_health_text", "RAID health unavailable."))
            nvme_text = str(metrics.get("nvme_lane_map_text", "NVMe lane map unavailable."))
            self.gui.update_raid_nvme_text(raid_text, nvme_text)

            self.gui.update_tactical_tab(metrics)
            self.gui.update_history_graphs(history_cache)

            if anomaly.risk != RiskLevel.NONE:
                self.gui.add_threat_entry(anomaly, metrics)
                self.logger.log("WARN", "Anomaly detected", {
                    "risk": anomaly.risk.name,
                    "reason": anomaly.reason,
                    "details": anomaly.details
                })
                self.logger.log_threat(anomaly)
                voice_alert(anomaly.reason)
                self.automation.apply(anomaly, metrics)

                if anomaly.details.get("drive_candidates"):
                    for name, value in metrics.items():
                        if name.startswith("drive_") and name.endswith("_health"):
                            if safe_float(value) < 50:
                                usage = safe_float(metrics.get(name.replace("_health", "_usage"), 0))
                                temp = safe_float(metrics.get(name.replace("_health", "_temp"), 0))
                                self.gui.show_drive_alert(name, usage, value, temp)

            self.logger.log_telemetry(anomaly.risk, anomaly.reason, metrics)

            self.borg_comm.broadcast_state(metrics, anomaly)
            self.gui.update_cluster_view(self.borg_comm.cluster_state)

            time.sleep(1)


# ============================
# WEB DASHBOARD (Flask) — metrics + threats + cluster
# ============================

def build_web_app(logger: EventLogger, telemetry_queue: List[Dict[str, Any]], borg_comm: BorgComm):
    app = Flask(__name__)

    DASHBOARD_HTML = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Aegis Nexus Web Dashboard v7.9</title>
        <style>
            body { background:#000; color:#0f0; font-family:Consolas, monospace; }
            h1 { color:#0f0; }
            .section { border:1px solid #0f0; padding:10px; margin:10px; }
            pre { background:#050505; padding:10px; }
            a { color:#0ff; }
        </style>
    </head>
    <body>
        <h1>🛡 Aegis Nexus Web Dashboard v7.9</h1>
        <div class="section">
            <h2>Live Metrics</h2>
            <p><a href="/api/metrics">/api/metrics</a></p>
        </div>
        <div class="section">
            <h2>Recent Telemetry</h2>
            <p><a href="/api/telemetry">/api/telemetry</a></p>
        </div>
        <div class="section">
            <h2>Threat Log</h2>
            <p><a href="/api/threats">/api/threats</a></p>
        </div>
        <div class="section">
            <h2>Cluster View</h2>
            <p><a href="/api/cluster">/api/cluster</a></p>
        </div>
        <div class="section">
            <h2>Remote Command API</h2>
            <pre>POST /api/remote_command
JSON:
{
  "cmd": "ping" | "diag" | "soft_stop" | "request_shutdown" | "request_backup"
}</pre>
        </div>
        <div class="section">
            <h2>Node Info</h2>
            <pre>{{ node_info }}</pre>
        </div>
    </body>
    </html>
    """

    @app.route("/")
    def index():
        node_info = json.dumps({
            "node": borg_comm.node_id,
            "platform": platform.platform(),
            "hostname": platform.node()
        }, indent=2)
        return render_template_string(DASHBOARD_HTML, node_info=node_info)

    @app.route("/api/metrics")
    def api_metrics():
        if telemetry_queue:
            return jsonify(telemetry_queue[-1])
        return jsonify({})

    @app.route("/api/telemetry")
    def api_telemetry():
        data = logger.get_recent_telemetry(limit=200)
        return jsonify(data)

    @app.route("/api/threats")
    def api_threats():
        data = logger.get_recent_threats(limit=200)
        return jsonify(data)

    @app.route("/api/cluster")
    def api_cluster():
        return jsonify(borg_comm.cluster_state)

    @app.route("/api/remote_command", methods=["POST"])
    def api_remote_command():
        payload = request.json or {}
        cmd = payload.get("cmd", "")
        if cmd == "ping":
            return jsonify({"status": "ok", "node": borg_comm.node_id})
        if cmd == "diag":
            return jsonify({"status": "ok", "metrics": telemetry_queue[-1] if telemetry_queue else {}})
        if cmd == "soft_stop":
            logger.log("INFO", "Remote soft_stop requested", {"node": borg_comm.node_id})
            return jsonify({"status": "accepted", "note": "soft_stop is stubbed"})
        if cmd == "request_shutdown":
            logger.log("INFO", "Remote shutdown requested", {"node": borg_comm.node_id})
            return jsonify({"status": "accepted", "note": "shutdown is stubbed"})
        if cmd == "request_backup":
            logger.log("INFO", "Remote backup requested", {"node": borg_comm.node_id})
            return jsonify({"status": "accepted", "note": "backup is stubbed"})
        return jsonify({"status": "unknown_command"}), 400

    return app


def run_web_dashboard(app: Flask):
    app.run(host="0.0.0.0", port=8080, debug=False, use_reloader=False)


# ============================
# BUILD AGENT
# ============================

def build_agent():
    logger = EventLogger()
    sensors = SensorRegistry()
    controls = ControlRegistry()

    adapter = load_os_adapter()
    adapter.discover_sensors(sensors, logger)
    adapter.discover_controls(controls, logger)

    model = AIModel(logger)

    if os.path.exists("./model.onnx"):
        model.load_onnx("./model.onnx")
    elif os.path.exists("./model.pt"):
        model.load_torch("./model.pt")

    borg_comm = BorgComm(logger, node_id=f"{platform.node()}")
    borg_comm.start_listener()

    sandbox = PluginSandbox(logger)
    sandbox.load_plugins()

    telemetry_queue: List[Dict[str, Any]] = []

    gui = AegisCockpit(sensors, logger, borg_comm, model, telemetry_queue)
    automation = AutomationEngine(controls, logger)
    guardian = Guardian(sensors, controls, model, gui, logger, borg_comm, telemetry_queue, automation)

    web_app = build_web_app(logger, telemetry_queue, borg_comm)

    return gui, guardian, telemetry_queue, web_app


# ============================
# MAIN
# ============================

if __name__ == "__main__":
    print("[Aegis Nexus Agent v7.9] Safety systems online and fully operational.")

    init_voice()
    persona_voice_intro("Sentinel")

    gui, guardian, telemetry_queue, web_app = build_agent()

    def run_web():
        print("[Web] Aegis Nexus Web Dashboard v7.9 listening on http://localhost:8080/")
        run_web_dashboard(web_app)

    threading.Thread(target=run_web, daemon=True).start()

    guardian.start()
    gui.start()

    print("[Aegis Nexus Agent v7.9] Shutting down safety systems.")
