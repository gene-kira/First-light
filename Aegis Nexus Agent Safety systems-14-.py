#!/usr/bin/env python3
"""
Aegis Nexus Agent — Borg Flight Deck v7.5 (Web + Prometheus Edition)

Upgrades vs v7.4:
- Same safety core (safe_float, SMART, NVML, NVMe, RAID, ONNX, ZeroMQ, hardware stubs)
- Same Guardian + GUI cockpit + voice persona + 3D cave map
- NEW:
  - Web dashboard (Flask) with:
    - Live metrics JSON
    - Threat log
    - Cluster view
    - Simple HTML cockpit
  - Telemetry logging to SQLite
  - Web dashboard auto-start on launch
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
    "moderngl",
    "moderngl_window",
    "numpy",
    "flask",
    "sqlite3"  # stdlib, but harmless
])

import psutil
import tkinter as tk
from tkinter import ttk
import pyttsx3
import moderngl
from moderngl_window import WindowConfig, run_window_config
import moderngl_window
import numpy as np
from flask import Flask, jsonify, render_template_string, request

# Optional external libs
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

import sqlite3

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

    def get_recent_telemetry(self, limit: int = 50):
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

    def get_recent_threats(self, limit: int = 50):
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
        def safe_shutdown(_: Any) -> bool:
            try:
                subprocess.run(["shutdown", "/s", "/t", "0"], check=True)
                return True
            except Exception:
                return False

        registry.register("limit_cpu_power", lambda v: True)
        registry.register("max_fan_speed", lambda _: True)
        registry.register("safe_shutdown", safe_shutdown)


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
# AI MODEL (ONNX / Torch)
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

    def predict_risk(self, metrics: Dict[str, float]) -> AnomalyResult:
        cpu_load = safe_float(metrics.get("cpu_load", 0))
        ram_usage = safe_float(metrics.get("ram_usage", 0))
        aio_rpm = safe_float(metrics.get("aio_pump_rpm", 2000))
        gpu_temp = safe_float(metrics.get("gpu_temp", 60))
        gpu_load = safe_float(metrics.get("gpu_load", 0))
        ssd_health_global = safe_float(metrics.get("ssd_health_global", 100))

        drive_fail_candidates = []
        for name, value in metrics.items():
            if name.startswith("drive_") and name.endswith("_usage"):
                usage = safe_float(value)
                if usage > 98:
                    drive_fail_candidates.append((name, "usage", usage))
            if name.startswith("drive_") and name.endswith("_health"):
                health = safe_float(value)
                if health < 50:
                    drive_fail_candidates.append((name, "health", health))
            if name.startswith("drive_") and name.endswith("_temp"):
                temp = safe_float(value)
                if temp > 70:
                    drive_fail_candidates.append((name, "temp", temp))

        if self.backend == "onnx" and self.session is not None:
            try:
                input_name = self.session.get_inputs()[0].name
                x = [
                    cpu_load,
                    ram_usage,
                    aio_rpm,
                    gpu_temp,
                    gpu_load,
                    ssd_health_global,
                    float(len(drive_fail_candidates))
                ]
                pred = self.session.run(None, {input_name: [x]})[0][0]
                if pred > 0.8:
                    return AnomalyResult(RiskLevel.CRITICAL, "Model: critical anomaly predicted")
                elif pred > 0.5:
                    return AnomalyResult(RiskLevel.HIGH, "Model: high anomaly predicted")
            except Exception as e:
                self.logger.log("ERROR", "ONNX inference failed", {"error": str(e)})

        if aio_rpm < 500 and cpu_load > 50:
            return AnomalyResult(RiskLevel.CRITICAL, "AIO cooling failure suspected")

        if gpu_temp > 90 or gpu_load > 95:
            return AnomalyResult(RiskLevel.HIGH, "GPU thermal/load anomaly")

        if ram_usage > 95:
            return AnomalyResult(RiskLevel.MEDIUM, "Memory exhaustion predicted")

        if drive_fail_candidates:
            return AnomalyResult(
                RiskLevel.HIGH,
                f"Drive failure predicted: {drive_fail_candidates[:3]}",
                {"drives": drive_fail_candidates}
            )

        if ssd_health_global < 50:
            return AnomalyResult(RiskLevel.MEDIUM, "Global SSD health degraded")

        if cpu_load > 90:
            return AnomalyResult(RiskLevel.LOW, "High CPU load")

        return AnomalyResult(RiskLevel.NONE, "All systems nominal")

    def drive_replacement_recommendation(self, anomaly: AnomalyResult) -> str:
        if not anomaly.details.get("drives"):
            return "No drive replacement recommended."
        drives = anomaly.details["drives"]
        names = [d[0] for d in drives]
        return f"Recommended: replace drives {', '.join(names)}."


# ============================
# ZeroMQ Cluster Networking
# ============================

class BorgComm:
    def __init__(self, logger: EventLogger, node_id: str = "node-1"):
        self.logger = logger
        self.node_id = node_id
        self.cluster_state: Dict[str, Dict[str, Any]] = {}
        self.context = None
        self.socket = None

        if zmq is not None:
            try:
                self.context = zmq.Context()
                self.socket = self.context.socket(zmq.PUB)
                self.socket.bind("tcp://*:5556")
                self.logger.log("INFO", "ZeroMQ PUB bound on tcp://*:5556")
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
        if self.socket is not None:
            try:
                self.socket.send_json(payload)
            except Exception as e:
                self.logger.log("ERROR", "ZeroMQ send failed", {"error": str(e)})

    def update_cluster_view(self, node: str, state: Dict[str, Any]):
        self.cluster_state[node] = state


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
# VOICE (Arkforge-style)
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
# 3D CAVE MAP ENGINE (Prometheus Cinematic)
# ============================

class CaveMap3D(WindowConfig):
    gl_version = (3, 3)
    title = "Aegis Nexus — Prometheus Cave Map v7.5"
    window_size = (1280, 720)
    aspect_ratio = 16 / 9
    resizable = True

    telemetry_queue: List[Dict[str, Any]] = None  # set externally

    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.ctx: moderngl.Context = self.ctx

        self.prog = self.ctx.program(
            vertex_shader='''
                #version 330
                in vec3 in_position;
                in vec3 in_color;
                uniform mat4 mvp;
                out vec3 v_color;
                void main() {
                    gl_Position = mvp * vec4(in_position, 1.0);
                    v_color = in_color;
                }
            ''',
            fragment_shader='''
                #version 330
                in vec3 v_color;
                out vec4 f_color;
                void main() {
                    float glow = 1.0;
                    f_color = vec4(v_color * glow, 1.0);
                }
            '''
        )

        self.line_prog = self.ctx.program(
            vertex_shader='''
                #version 330
                in vec3 in_position;
                uniform mat4 mvp;
                void main() {
                    gl_Position = mvp * vec4(in_position, 1.0);
                }
            ''',
            fragment_shader='''
                #version 330
                uniform vec3 color;
                out vec4 f_color;
                void main() {
                    f_color = vec4(color, 1.0);
                }
            '''
        )

        self.camera_pos = [0.0, 0.0, -10.0]
        self.time_acc = 0.0
        self.last_metrics_update = 0.0

        self.nodes = {
            "CPU":   (-3.0,  1.5, 0.0),
            "RAM":   (-1.0,  1.5, 0.0),
            "GPU":   ( 1.0,  1.5, 0.0),
            "Cooling": ( 3.0, 1.5, 0.0),
            "Drives": (-2.0, -1.5, 0.0),
            "NVMe":   ( 0.0, -1.5, 0.0),
            "RAID":   ( 2.0, -1.5, 0.0),
            "Cluster":( 0.0,  0.0, 2.0),
        }

        self.node_colors = {name: (0.0, 0.6, 0.0) for name in self.nodes}
        self.node_vbos = {}
        self.node_vaos = {}

        self._build_nodes()

        self.drones = [
            {"center": "CPU", "radius": 0.8, "speed": 0.9, "phase": 0.0},
            {"center": "GPU", "radius": 0.9, "speed": 1.1, "phase": 1.5},
            {"center": "Drives", "radius": 0.7, "speed": 0.7, "phase": 2.3},
            {"center": "NVMe", "radius": 0.7, "speed": 1.3, "phase": 3.1},
        ]

        self.tunnel_lines = [
            ("NVMe", "Drives"),
            ("NVMe", "RAID"),
        ]

        self.cooling_streams = [
            ("Cooling", "CPU"),
            ("Cooling", "GPU"),
        ]

        self.cluster_beam = ("Cluster", "GPU")

    def _build_nodes(self):
        base_positions = [
            (0.0,  0.5, 0.0),
            (0.5,  0.0, 0.0),
            (0.0, -0.5, 0.0),
            (-0.5, 0.0, 0.0),
            (0.0,  0.0, 0.5),
            (0.0,  0.0,-0.5),
        ]
        indices = [
            0, 1, 4,
            1, 2, 4,
            2, 3, 4,
            3, 0, 4,
            0, 1, 5,
            1, 2, 5,
            2, 3, 5,
            3, 0, 5,
        ]

        self.node_vbos.clear()
        self.node_vaos.clear()

        for name, pos in self.nodes.items():
            px, py, pz = pos
            color = self.node_colors[name]
            cx, cy, cz = color

            vertices = []
            for idx in indices:
                vx, vy, vz = base_positions[idx]
                vertices.extend([vx + px, vy + py, vz + pz, cx, cy, cz])

            vertex_data = np.array(vertices, dtype="f4")
            vbo = self.ctx.buffer(vertex_data.tobytes())
            vao = self.ctx.vertex_array(
                self.prog,
                [
                    (vbo, "3f 3f", "in_position", "in_color")
                ]
            )
            self.node_vbos[name] = vbo
            self.node_vaos[name] = vao

    def update_node_colors_from_metrics(self, metrics: Dict[str, Any]):
        def color_for(name):
            base_pulse = 0.4 + 0.2 * np.sin(self.time_acc * 2.0)
            if name == "CPU":
                load = safe_float(metrics.get("cpu_load", 0))
                if load > 90: return (1.0, 0.1, 0.1)
                if load > 70: return (1.0, 0.7, 0.1)
                return (0.0, 0.6 + base_pulse, 0.0)
            if name == "GPU":
                temp = safe_float(metrics.get("gpu_temp", 0))
                if temp > 90: return (1.0, 0.1, 0.1)
                if temp > 75: return (1.0, 0.7, 0.1)
                return (0.0, 0.6 + base_pulse, 0.0)
            if name == "Drives":
                bad = False
                for k, v in metrics.items():
                    if k.startswith("drive_") and k.endswith("_health"):
                        if safe_float(v) < 50:
                            bad = True
                return (1.0, 0.1, 0.1) if bad else (0.0, 0.6 + base_pulse, 0.0)
            if name == "NVMe":
                return (0.0, 0.7 + base_pulse, 0.9)
            if name == "RAID":
                txt = str(metrics.get("raid_health_text", ""))
                if "degraded" in txt.lower() or "fault" in txt.lower():
                    return (1.0, 0.1, 0.1)
                return (0.0, 0.6 + base_pulse, 0.0)
            if name == "Cooling":
                rpm = safe_float(metrics.get("aio_pump_rpm", 1500))
                if rpm < 500: return (1.0, 0.1, 0.1)
                if rpm < 1000: return (1.0, 0.7, 0.1)
                return (0.0, 0.6 + base_pulse, 0.0)
            if name == "RAM":
                usage = safe_float(metrics.get("ram_usage", 0))
                if usage > 95: return (1.0, 0.1, 0.1)
                if usage > 80: return (1.0, 0.7, 0.1)
                return (0.0, 0.6 + base_pulse, 0.0)
            if name == "Cluster":
                return (0.0, 0.4 + base_pulse, 1.0)
            return (0.0, 0.6 + base_pulse, 0.0)

        for name in self.nodes:
            self.node_colors[name] = color_for(name)

        self._build_nodes()

    def _camera_mvp(self):
        import math
        self.time_acc += 0.0

        drift = 0.3 * math.sin(self.time_acc * 0.1)
        angle = self.time_acc * 0.15
        cos_a = math.cos(angle)
        sin_a = math.sin(angle)

        rot_y = [
            cos_a, 0.0, sin_a, 0.0,
            0.0,  1.0, 0.0,  0.0,
            -sin_a,0.0, cos_a,0.0,
            0.0,  drift, 0.0,  1.0
        ]

        fov = math.radians(60.0)
        aspect = self.window_size[0] / self.window_size[1]
        near = 0.1
        far = 100.0
        f = 1.0 / math.tan(fov / 2.0)
        proj = [
            f/aspect, 0.0, 0.0, 0.0,
            0.0, f,   0.0, 0.0,
            0.0, 0.0, (far+near)/(near-far), -1.0,
            0.0, 0.0, (2*far*near)/(near-far), 0.0
        ]

        mvp = np.matmul(np.array(proj).reshape(4,4), np.array(rot_y).reshape(4,4))
        return mvp.astype("f4")

    def _render_drones(self, mvp):
        import math
        for drone in self.drones:
            center_name = drone["center"]
            if center_name not in self.nodes:
                continue
            cx, cy, cz = self.nodes[center_name]
            r = drone["radius"]
            speed = drone["speed"]
            phase = drone["phase"]

            t = self.time_acc * speed + phase
            dx = cx + r * math.cos(t)
            dy = cy + 0.3 * math.sin(t * 2.0)
            dz = cz + r * math.sin(t)

            vertices = np.array([
                dx, dy, dz,
                dx + 0.1, dy, dz,
                dx, dy + 0.1, dz,
            ], dtype="f4")
            vbo = self.ctx.buffer(vertices.tobytes())
            vao = self.ctx.vertex_array(
                self.line_prog,
                [(vbo, "3f", "in_position")]
            )
            self.line_prog["mvp"].write(mvp.tobytes())
            self.line_prog["color"].value = (0.9, 0.9, 0.2)
            vao.render(mode=moderngl.TRIANGLES)

    def _render_lines(self, mvp, pairs, color, pulsate=False):
        import math
        for a, b in pairs:
            if a not in self.nodes or b not in self.nodes:
                continue
            ax, ay, az = self.nodes[a]
            bx, by, bz = self.nodes[b]

            vertices = np.array([
                ax, ay, az,
                bx, by, bz,
            ], dtype="f4")
            vbo = self.ctx.buffer(vertices.tobytes())
            vao = self.ctx.vertex_array(
                self.line_prog,
                [(vbo, "3f", "in_position")]
            )
            self.line_prog["mvp"].write(mvp.tobytes())
            if pulsate:
                pulse = 0.5 + 0.5 * math.sin(self.time_acc * 3.0)
                c = (color[0] * pulse, color[1] * pulse, color[2] * pulse)
                self.line_prog["color"].value = c
            else:
                self.line_prog["color"].value = color
            vao.render(mode=moderngl.LINES)

    def render(self, time_delta: float):
        self.time_acc += time_delta
        self.ctx.clear(0.0, 0.0, 0.0)
        self.ctx.enable(moderngl.DEPTH_TEST)

        mvp = self._camera_mvp()
        self.prog["mvp"].write(mvp.tobytes())

        if self.telemetry_queue is not None and len(self.telemetry_queue) > 0:
            if self.time_acc - self.last_metrics_update > 0.2:
                metrics = self.telemetry_queue[-1]
                self.update_node_colors_from_metrics(metrics)
                self.last_metrics_update = self.time_acc

        for name, vao in self.node_vaos.items():
            vao.render()

        self._render_drones(mvp)

        self._render_lines(mvp, self.tunnel_lines, (0.0, 0.8, 1.0), pulsate=True)
        self._render_lines(mvp, self.cooling_streams, (0.0, 1.0, 0.6), pulsate=True)
        self._render_lines(mvp, [self.cluster_beam], (0.4, 0.4, 1.0), pulsate=True)

    def on_render(self, time: float, frame_time: float):
        self.render(frame_time)


# ============================
# DARK BORG COCKPIT GUI
# ============================

class AegisCockpit:
    def __init__(self, sensors: SensorRegistry, logger: EventLogger, borg_comm: BorgComm, model: AIModel, telemetry_queue: List[Dict[str, Any]]):
        self.sensors = sensors
        self.logger = logger
        self.borg_comm = borg_comm
        self.model = model
        self.telemetry_queue = telemetry_queue

        self.root = tk.Tk()
        self.root.title("Aegis Nexus Agent — Borg Flight Deck v7.5")
        self.root.geometry("1400x900")
        self.root.configure(bg="#101010")

        self.style = ttk.Style()
        self.style.theme_use("clam")
        self._apply_theme("dark")

        self.main_status_label = ttk.Label(
            self.root,
            text="MAIN STATUS: GREEN — All Systems Nominal",
            style="Dark.Title.TLabel"
        )
        self.main_status_label.pack(pady=10)

        theme_bar = ttk.Frame(self.root, style="Dark.TFrame")
        theme_bar.pack(fill="x", padx=10, pady=5)
        ttk.Label(theme_bar, text="Theme:", style="Dark.TLabel").pack(side="left")
        ttk.Button(theme_bar, text="Dark", command=lambda: self._apply_theme("dark")).pack(side="left", padx=5)
        ttk.Button(theme_bar, text="Neon", command=lambda: self._apply_theme("neon")).pack(side="left", padx=5)
        ttk.Button(theme_bar, text="Aircraft", command=lambda: self._apply_theme("aircraft")).pack(side="left", padx=5)

        self.warning_panel = tk.Listbox(self.root, bg="#101010", fg="#ff0033", font=("Consolas", 11), height=3)
        self.warning_panel.pack(fill="x", padx=10, pady=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

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

        self.sensor_labels: Dict[str, Any] = {}
        sensor_table = ttk.Frame(self.dashboard_frame, style="Dark.TFrame")
        sensor_table.pack(side="left", fill="y", padx=10, pady=10)

        header = ttk.Frame(sensor_table, style="Dark.TFrame")
        header.pack(fill="x")
        ttk.Label(header, text="Sensor", style="Dark.TLabel", width=30).pack(side="left")
        ttk.Label(header, text="Value", style="Dark.TLabel", width=12).pack(side="left")
        ttk.Label(header, text="Status", style="Dark.TLabel", width=12).pack(side="left")

        for name in self.sensors.sensors.keys():
            if not name.startswith("drive_"):
                row = ttk.Frame(sensor_table, style="Dark.TFrame")
                row.pack(fill="x", pady=2)

                label_name = ttk.Label(row, text=name, style="Dark.TLabel", width=30)
                label_name.pack(side="left")

                label_value = ttk.Label(row, text="...", style="Dark.TLabel", width=12)
                label_value.pack(side="left")

                label_status = ttk.Label(row, text="GREEN", style="Dark.TLabel", width=12)
                label_status.pack(side="left")

                self.sensor_labels[name] = (label_value, label_status)

        drive_panel = ScrollableFrame(self.dashboard_frame)
        drive_panel.pack(side="right", fill="both", padx=10, pady=10)
        self.drive_labels: Dict[str, Any] = {}

        dheader = ttk.Frame(drive_panel.scrollable_frame, style="Dark.TFrame")
        dheader.pack(fill="x")
        ttk.Label(dheader, text="Drive", style="Dark.TLabel", width=25).pack(side="left")
        ttk.Label(dheader, text="Usage %", style="Dark.TLabel", width=10).pack(side="left")
        ttk.Label(dheader, text="Health", style="Dark.TLabel", width=10).pack(side="left")
        ttk.Label(dheader, text="Temp °C", style="Dark.TLabel", width=10).pack(side="left")
        ttk.Label(dheader, text="Status", style="Dark.TLabel", width=10).pack(side="left")

        for name in self.sensors.sensors.keys():
            if name.startswith("drive_") and ("usage" in name or "health" in name or "temp" in name):
                row = ttk.Frame(drive_panel.scrollable_frame, style="Dark.TFrame")
                row.pack(fill="x", pady=2)

                label_name = ttk.Label(row, text=name, style="Dark.TLabel", width=25)
                label_name.pack(side="left")

                label_usage = ttk.Label(row, text="...", style="Dark.TLabel", width=10)
                label_usage.pack(side="left")

                label_health = ttk.Label(row, text="...", style="Dark.TLabel", width=10)
                label_health.pack(side="left")

                label_temp = ttk.Label(row, text="...", style="Dark.TLabel", width=10)
                label_temp.pack(side="left")

                label_status = ttk.Label(row, text="GREEN", style="Dark.TLabel", width=10)
                label_status.pack(side="left")

                self.drive_labels[name] = (label_usage, label_health, label_temp, label_status)

        graph_frame = ttk.Frame(self.dashboard_frame, style="Dark.TFrame")
        graph_frame.pack(side="bottom", fill="x", padx=10, pady=10)

        self.cpu_canvas = tk.Canvas(graph_frame, width=500, height=200, bg="#101010", highlightthickness=0)
        self.cpu_canvas.pack(side="left", padx=10)
        self.cpu_canvas.create_text(250, 10, text="CPU Load / Temp", fill="#00ff99", font=("Consolas", 12))

        self.fan_canvas = tk.Canvas(graph_frame, width=500, height=200, bg="#101010", highlightthickness=0)
        self.fan_canvas.pack(side="right", padx=10)
        self.fan_canvas.create_text(250, 10, text="AIO Pump RPM", fill="#00ff99", font=("Consolas", 12))

        self.cpu_history: List[float] = []
        self.temp_history: List[float] = []
        self.fan_history: List[float] = []

        self.drive_temp_canvas = tk.Canvas(self.drive_graph_frame, width=800, height=400, bg="#101010", highlightthickness=0)
        self.drive_temp_canvas.pack(padx=10, pady=10)
        self.drive_temp_canvas.create_text(400, 10, text="Drive Temperatures", fill="#00ff99", font=("Consolas", 12))

        ttk.Label(self.smart_frame, text="SMART Attribute Table", style="Dark.Title.TLabel").pack(pady=10)
        self.smart_table = tk.Text(self.smart_frame, bg="#101010", fg="#00ff99", font=("Consolas", 11))
        self.smart_table.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(self.raid_frame, text="RAID Health View", style="Dark.Title.TLabel").pack(pady=10)
        self.raid_text = tk.Text(self.raid_frame, bg="#101010", fg="#00ff99", font=("Consolas", 11))
        self.raid_text.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(self.nvme_frame, text="NVMe PCIe Lane Map", style="Dark.Title.TLabel").pack(pady=10)
        self.nvme_text = tk.Text(self.nvme_frame, bg="#101010", fg="#00ff99", font=("Consolas", 11))
        self.nvme_text.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(self.threat_frame, text="Threat Matrix (Anomalies & Risk Levels)", style="Dark.Title.TLabel").pack(pady=10)
        self.threat_list = tk.Listbox(self.threat_frame, bg="#101010", fg="#00ff99", font=("Consolas", 11))
        self.threat_list.pack(fill="both", expand=True, padx=10, pady=10)

        ttk.Label(self.cluster_frame, text="Cluster View (Nodes)", style="Dark.Title.TLabel").pack(pady=10)
        self.cluster_list = tk.Listbox(self.cluster_frame, bg="#101010", fg="#00ff99", font=("Consolas", 11))
        self.cluster_list.pack(fill="both", expand=True, padx=10, pady=10)

    def _apply_theme(self, mode: str):
        if mode == "dark":
            self.style.configure("Dark.TFrame", background="#101010")
            self.style.configure("Dark.TLabel", background="#101010", foreground="#00ff99", font=("Consolas", 11))
            self.style.configure("Dark.Title.TLabel", background="#101010", foreground="#00ff99", font=("Consolas", 18, "bold"))
        elif mode == "neon":
            self.style.configure("Dark.TFrame", background="#000000")
            self.style.configure("Dark.TLabel", background="#000000", foreground="#39ff14", font=("Consolas", 11))
            self.style.configure("Dark.Title.TLabel", background="#000000", foreground="#39ff14", font=("Consolas", 18, "bold"))
        elif mode == "aircraft":
            self.style.configure("Dark.TFrame", background="#001020")
            self.style.configure("Dark.TLabel", background="#001020", foreground="#00ff99", font=("Consolas", 11))
            self.style.configure("Dark.Title.TLabel", background="#001020", foreground="#ffcc00", font=("Consolas", 18, "bold"))

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

    def update_graphs(self, cpu_load: float, cpu_temp: float, aio_rpm: float, drive_temps: Dict[str, float]):
        def _update():
            self.cpu_history.append(cpu_load)
            self.temp_history.append(cpu_temp)
            self.fan_history.append(aio_rpm)

            for hist in (self.cpu_history, self.temp_history, self.fan_history):
                if len(hist) > 80:
                    hist.pop(0)

            self.cpu_canvas.delete("graph")
            self.fan_canvas.delete("graph")
            self.drive_temp_canvas.delete("graph")

            if self.cpu_history:
                max_val = max(max(self.cpu_history), 1)
                for i, v in enumerate(self.cpu_history):
                    x0 = 10 + i * 6
                    y0 = 190
                    y1 = 190 - (v / max_val) * 160
                    self.cpu_canvas.create_line(x0, y0, x0, y1, fill="#00ff99", tags="graph")

            if self.temp_history:
                max_temp = max(max(self.temp_history), 1)
                for i, v in enumerate(self.temp_history):
                    x0 = 10 + i * 6
                    y0 = 190
                    y1 = 190 - (v / max_temp) * 160
                    self.cpu_canvas.create_line(x0, y0, x0, y1, fill="#ffcc00", tags="graph")

            if self.fan_history:
                max_rpm = max(max(self.fan_history), 1)
                for i, v in enumerate(self.fan_history):
                    x0 = 10 + i * 6
                    y0 = 190
                    y1 = 190 - (v / max_rpm) * 160
                    self.fan_canvas.create_line(x0, y0, x0, y1, fill="#00ff99", tags="graph")

            if drive_temps:
                drives = list(drive_temps.items())
                for i, (name, temp) in enumerate(drives):
                    x = 50 + i * 80
                    y0 = 350
                    y1 = 350 - (temp / 100.0) * 300
                    self.drive_temp_canvas.create_rectangle(x - 20, y1, x + 20, y0, outline="#00ff99", tags="graph")
                    self.drive_temp_canvas.create_text(x, y0 + 10, text=name[-10:], fill="#00ff99", font=("Consolas", 8))

        self.root.after(0, _update)

    def add_threat_entry(self, anomaly: AnomalyResult):
        def _update():
            entry = f"[{time.strftime('%H:%M:%S')}] {anomaly.risk.name}: {anomaly.reason}"
            self.threat_list.insert("end", entry)
            if anomaly.details.get("drives"):
                rec = self.model.drive_replacement_recommendation(anomaly)
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
        alert.geometry("400x300")
        alert.configure(bg="#101010")

        ttk.Label(alert, text=f"Drive: {drive_name}", style="Dark.Title.TLabel").pack(pady=10)
        ttk.Label(alert, text=f"Usage: {usage}%", style="Dark.TLabel").pack(pady=5)
        ttk.Label(alert, text=f"Health: {health}%", style="Dark.TLabel").pack(pady=5)
        ttk.Label(alert, text=f"Temp: {temp}°C", style="Dark.TLabel").pack(pady=5)

        if usage > 98:
            msg = "Drive is critically full!"
        elif health < 50:
            msg = "Drive SMART health failing!"
        elif temp > 70:
            msg = "Drive overheating!"
        else:
            msg = "Drive anomaly detected."

        ttk.Label(alert, text=msg, style="Dark.TLabel").pack(pady=20)
        voice_alert(msg)

    def start(self):
        self.root.mainloop()


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
        telemetry_queue: List[Dict[str, Any]]
    ):
        self.sensors = sensors
        self.controls = controls
        self.model = model
        self.gui = gui
        self.logger = logger
        self.borg_comm = borg_comm
        self.telemetry_queue = telemetry_queue
        self.running = False

    def start(self):
        self.running = True
        threading.Thread(target=self.loop, daemon=True).start()

    def stop(self):
        self.running = False

    def loop(self):
        while self.running:
            metrics = self.sensors.scan_all()

            self.telemetry_queue.append(metrics)

            for name, value in metrics.items():
                self.gui.update_sensor(name, value)

            anomaly = self.model.predict_risk(metrics)
            self.gui.update_main_status(anomaly.risk, anomaly.reason)

            cpu_load = safe_float(metrics.get("cpu_load", 0))
            cpu_temp = safe_float(metrics.get("cpu_temp", cpu_load))
            aio_rpm = safe_float(metrics.get("aio_pump_rpm", 1500))

            drive_temps = {
                name: safe_float(value)
                for name, value in metrics.items()
                if name.startswith("drive_") and name.endswith("_temp")
            }

            self.gui.update_graphs(cpu_load, cpu_temp, aio_rpm, drive_temps)
            self.gui.update_smart_table(metrics)

            raid_text = str(metrics.get("raid_health_text", "RAID health unavailable."))
            nvme_text = str(metrics.get("nvme_lane_map_text", "NVMe lane map unavailable."))
            self.gui.update_raid_nvme_text(raid_text, nvme_text)

            if anomaly.risk != RiskLevel.NONE:
                self.gui.add_threat_entry(anomaly)
                self.logger.log("WARN", "Anomaly detected", {
                    "risk": anomaly.risk.name,
                    "reason": anomaly.reason,
                    "details": anomaly.details
                })
                self.logger.log_threat(anomaly)
                if anomaly.risk in (RiskLevel.HIGH, RiskLevel.CRITICAL):
                    voice_alert(anomaly.reason)
                    self.controls.execute("max_fan_speed", None)
                    if anomaly.details.get("drives"):
                        for dname, dtype, dval in anomaly.details["drives"]:
                            usage = safe_float(metrics.get(dname.replace(dtype, "usage"), 0))
                            health = safe_float(metrics.get(dname.replace(dtype, "health"), 100))
                            temp = safe_float(metrics.get(dname.replace(dtype, "temp"), 0))
                            self.gui.show_drive_alert(dname, usage, health, temp)

            self.logger.log_telemetry(anomaly.risk, anomaly.reason, metrics)

            self.borg_comm.broadcast_state(metrics, anomaly)
            self.gui.update_cluster_view(self.borg_comm.cluster_state)

            time.sleep(1)


# ============================
# WEB DASHBOARD (Flask)
# ============================

def build_web_app(logger: EventLogger, telemetry_queue: List[Dict[str, Any]], borg_comm: BorgComm):
    app = Flask(__name__)

    DASHBOARD_HTML = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Aegis Nexus Web Dashboard v7.5</title>
        <style>
            body { background:#000; color:#0f0; font-family:Consolas, monospace; }
            h1 { color:#0f0; }
            .section { border:1px solid #0f0; padding:10px; margin:10px; }
            pre { background:#050505; padding:10px; }
            a { color:#0ff; }
        </style>
    </head>
    <body>
        <h1>🛡 Aegis Nexus Web Dashboard v7.5</h1>
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
        data = logger.get_recent_telemetry(limit=50)
        return jsonify(data)

    @app.route("/api/threats")
    def api_threats():
        data = logger.get_recent_threats(limit=50)
        return jsonify(data)

    @app.route("/api/cluster")
    def api_cluster():
        return jsonify(borg_comm.cluster_state)

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

    sandbox = PluginSandbox(logger)
    sandbox.load_plugins()

    telemetry_queue: List[Dict[str, Any]] = []

    gui = AegisCockpit(sensors, logger, borg_comm, model, telemetry_queue)
    guardian = Guardian(sensors, controls, model, gui, logger, borg_comm, telemetry_queue)

    web_app = build_web_app(logger, telemetry_queue, borg_comm)

    return gui, guardian, telemetry_queue, web_app


# ============================
# MAIN
# ============================

if __name__ == "__main__":
    print("[Aegis Nexus Agent v7.5] Safety systems online and fully operational.")

    init_voice()
    persona_voice_intro("Sentinel")

    gui, guardian, telemetry_queue, web_app = build_agent()

    def run_cave_map():
        CaveMap3D.telemetry_queue = telemetry_queue
        run_window_config(CaveMap3D)

    def run_web():
        print("[Web] Aegis Nexus Web Dashboard v7.5 listening on http://localhost:8080/")
        run_web_dashboard(web_app)

    threading.Thread(target=run_cave_map, daemon=True).start()
    threading.Thread(target=run_web, daemon=True).start()

    guardian.start()
    gui.start()

    print("[Aegis Nexus Agent v7.5] Shutting down safety systems.")
