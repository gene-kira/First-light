#!/usr/bin/env python3
"""
Beast Swarm Engine v8.3 — Multi-Host Swarm + Charts + Secure REST + Sandbox Plugins + Job History

- Multi-core + GPU + NPU job system
- Local + multi-host swarm (nodes) with predictive tuner
- Swarm-wide global scheduler (single queue, node selection)
- Auto-spawn nodes based on load
- Multi-host swarm networking (TCP, JSON, simple protocol)
- PyQt6 desktop GUI Command Center (side nav + panels)
- Real-time charts (CPU, memory, disk, VRAM fragmentation) via PyQtGraph
- VRAM compute modules (bandwidth, fragmentation stress)
- VRAM fragmentation visualizer (time-series in GUI)
- Plugin system for custom jobs (sandboxed in subprocesses)
- Queen consensus engine (global risk aggregation)
- Queen risk decay + anomaly detection
- Live data jobs (no flow-state simulation; uses real system metrics)
- Fault tolerance (health, retry, guarded demo jobs)
- ZMQ swarm OFF by default (manual start from GUI)
- ZMQ "port stacking": first process binds (server), others connect (client)
- ZMQ client can submit jobs to server (cpu/io/gpu/npu/async/live/plugin/vram)
- Persistent memory across reboots (swarm_state.json) with throttled saves
- Persistent job history database (SQLite)
- REST API for metrics + job submission (HTTP JSON) with token authentication
"""

import importlib
import importlib.util
import subprocess
import sys
import os
import time
import queue
import threading
import asyncio
import json
import math
import platform
import socket
import sqlite3
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from itertools import count
from collections import defaultdict, deque
from dataclasses import dataclass, field

# ---------------------------------------------------------------------------
# CONFIG
# ---------------------------------------------------------------------------

CONFIG = {
    "autoload_libs": True,
    "optional_libs": [
        "psutil",
        "numpy",
        "torch",
        "onnxruntime",
        "tensorflow",
        "pyqt6",
        "pyzmq",
        "nvidia-ml-py",
        "flask",
        "pyqtgraph",
    ],
    "enable_gpu": True,
    "enable_npu": True,
    "local_nodes": 2,
    "metrics_window": 200,
    "tuner_interval_sec": 2.0,
    "cpu_worker_min": 2,
    "cpu_worker_max": 32,
    "io_worker_min": 4,
    "io_worker_max": 64,
    "predictive_alpha": 0.3,
    "plugins_dir": "plugins",
    "zmq_bind": "tcp://*:6000",
    "health_check_interval": 3.0,
    "job_retry_limit": 3,
    "state_file": "swarm_state.json",
    "memory_save_interval_sec": 5.0,
    "queen_risk_decay_half_life_sec": 60.0,
    "queen_anomaly_window": 64,
    "queen_anomaly_zscore": 2.5,
    "gpu_governor_interval_sec": 1.0,
    "gpu_target_util_percent": 70.0,
    "gpu_target_temp_c": 75.0,
    "gpu_vram_stress_size_mb": 512,
    "gpu_vram_frag_chunks": 64,
    "rest_api_host": "127.0.0.1",
    "rest_api_port": 5000,
    "rest_api_token": "swarm-secret-token",
    "auto_spawn_max_nodes": 8,
    "auto_spawn_load_threshold": 200,
    "auto_spawn_interval_sec": 5.0,
    "job_history_db": "job_history.db",
    "multi_host_listen_host": "0.0.0.0",
    "multi_host_listen_port": 7000,
    "multi_host_peers": [],  # list of "host:port"
}

# ---------------------------------------------------------------------------
# Autoloader
# ---------------------------------------------------------------------------

def autoload_libraries(libs):
    import_names = {
        "pyqt6": "PyQt6",
        "pyzmq": "zmq",
        "nvidia-ml-py": "pynvml",
        "pyqtgraph": "pyqtgraph",
    }
    for lib in libs:
        import_name = import_names.get(lib, lib)
        try:
            importlib.import_module(import_name)
        except ImportError:
            print(f"[AUTOLOAD] Missing '{lib}', attempting install...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
                importlib.import_module(import_name)
                print(f"[AUTOLOAD] Installed '{lib}' successfully.")
            except Exception as e:
                print(f"[AUTOLOAD] Failed to install '{lib}': {e}")


if CONFIG["autoload_libs"]:
    autoload_libraries(CONFIG["optional_libs"])

try:
    import psutil
except ImportError:
    psutil = None

try:
    import numpy as np
except ImportError:
    np = None

try:
    import torch
except ImportError:
    torch = None

try:
    import onnxruntime as ort
except ImportError:
    ort = None

try:
    import tensorflow as tf
except ImportError:
    tf = None

try:
    import zmq
except ImportError:
    zmq = None

try:
    from PyQt6 import QtWidgets, QtCore, QtGui
except ImportError:
    QtWidgets = None
    QtCore = None
    QtGui = None

try:
    import pynvml
except ImportError:
    pynvml = None

try:
    from flask import Flask, request, jsonify
except ImportError:
    Flask = None

try:
    import pyqtgraph as pg
except ImportError:
    pg = None

# ---------------------------------------------------------------------------
# Job history (SQLite)
# ---------------------------------------------------------------------------

class JobHistory:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.path)
        try:
            c = conn.cursor()
            c.execute("""
                CREATE TABLE IF NOT EXISTS jobs (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    node_id TEXT,
                    task_type TEXT,
                    name TEXT,
                    status TEXT,
                    duration REAL,
                    info TEXT
                )
            """)
            conn.commit()
        finally:
            conn.close()

    def record(self, node_id, task_type, name, status, duration, info=None):
        with self.lock:
            conn = sqlite3.connect(self.path)
            try:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO jobs (timestamp, node_id, task_type, name, status, duration, info) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?)",
                    (time.time(), node_id, task_type, name, status, duration, json.dumps(info or {})),
                )
                conn.commit()
            finally:
                conn.close()

    def recent(self, limit=100):
        with self.lock:
            conn = sqlite3.connect(self.path)
            try:
                c = conn.cursor()
                c.execute(
                    "SELECT timestamp, node_id, task_type, name, status, duration, info "
                    "FROM jobs ORDER BY id DESC LIMIT ?",
                    (limit,),
                )
                rows = c.fetchall()
            finally:
                conn.close()
        out = []
        for ts, node_id, ttype, name, status, dur, info in rows:
            try:
                info_obj = json.loads(info) if info else {}
            except Exception:
                info_obj = {}
            out.append({
                "timestamp": ts,
                "node_id": node_id,
                "task_type": ttype,
                "name": name,
                "status": status,
                "duration": dur,
                "info": info_obj,
            })
        return out

# ---------------------------------------------------------------------------
# Persistent memory
# ---------------------------------------------------------------------------

class MemoryManager:
    def __init__(self, path):
        self.path = path
        self.state = {
            "queen_nodes": {},
            "queen_risk_state": {},
            "config_overrides": {},
            "gpu_governor_state": {},
            "vram_frag_history": [],
        }
        self.last_save_time = 0.0
        self.load()

    def load(self):
        if not os.path.isfile(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                self.state = json.load(f)
            print(f"[MEMORY] Loaded state from {self.path}")
        except Exception as e:
            print(f"[MEMORY] Failed to load state: {e}")

    def save(self, force=False):
        now = time.time()
        if not force and (now - self.last_save_time) < CONFIG["memory_save_interval_sec"]:
            return
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(self.state, f, indent=2)
            self.last_save_time = now
            print(f"[MEMORY] Saved state to {self.path}")
        except Exception as e:
            print(f"[MEMORY] Failed to save state: {e}")

    def update_queen_nodes(self, queen_nodes):
        self.state["queen_nodes"] = queen_nodes

    def update_queen_risk_state(self, risk_state):
        self.state["queen_risk_state"] = risk_state

    def update_gpu_governor_state(self, governor_state):
        self.state["gpu_governor_state"] = governor_state

    def append_vram_frag_history(self, entry):
        hist = self.state.get("vram_frag_history", [])
        hist.append(entry)
        if len(hist) > 256:
            hist = hist[-256:]
        self.state["vram_frag_history"] = hist

    def get_vram_frag_history(self):
        return self.state.get("vram_frag_history", [])

    def apply_config_overrides(self):
        overrides = self.state.get("config_overrides", {})
        for k, v in overrides.items():
            if k in CONFIG:
                CONFIG[k] = v

    def set_config_override(self, key, value):
        self.state.setdefault("config_overrides", {})[key] = value
        self.save(force=True)

# ---------------------------------------------------------------------------
# Task abstraction
# ---------------------------------------------------------------------------

class TaskType:
    CPU = "cpu"
    IO = "io"
    ASYNC = "async"
    GPU = "gpu"
    NPU = "npu"
    LIVE = "live"
    PLUGIN = "plugin"
    VRAM = "vram"


@dataclass
class Task:
    func: callable
    args: tuple = field(default_factory=tuple)
    kwargs: dict = field(default_factory=dict)
    task_type: str = TaskType.CPU
    priority: int = 0
    name: str = ""
    retries: int = 0

    def __post_init__(self):
        if not self.name:
            self.name = getattr(self.func, "__name__", "task")


class PriorityTaskQueue:
    def __init__(self):
        self._q = queue.PriorityQueue()
        self._counter = count()

    def put(self, task: Task):
        self._q.put((-task.priority, next(self._counter), task))

    def get(self, block=True, timeout=None):
        _, _, task = self._q.get(block==block, timeout=timeout)
        return task

    def empty(self):
        return self._q.empty()

    def qsize(self):
        return self._q.qsize()

# ---------------------------------------------------------------------------
# Metrics and predictive model
# ---------------------------------------------------------------------------

class NodeMetrics:
    def __init__(self, window=200, alpha=0.3):
        self.window = window
        self.alpha = alpha
        self.lock = threading.Lock()
        self.task_durations = defaultdict(lambda: deque(maxlen=self.window))
        self.queue_sizes = {
            "io": 0,
            "cpu": 0,
            "gpu": 0,
            "npu": 0,
            "live": 0,
            "plugin": 0,
            "vram": 0,
        }
        self.predicted_duration = defaultdict(float)

    def record_task(self, task_type, duration):
        with self.lock:
            self.task_durations[task_type].append(duration)
            prev = self.predicted_duration[task_type]
            if prev == 0.0:
                self.predicted_duration[task_type] = duration
            else:
                self.predicted_duration[task_type] = (
                    self.alpha * duration + (1 - self.alpha) * prev
                )

    def set_queue_sizes(self, io_q, cpu_q, gpu_q, npu_q, live_q, plugin_q, vram_q):
        with self.lock:
            self.queue_sizes["io"] = io_q
            self.queue_sizes["cpu"] = cpu_q
            self.queue_sizes["gpu"] = gpu_q
            self.queue_sizes["npu"] = npu_q
            self.queue_sizes["live"] = live_q
            self.queue_sizes["plugin"] = plugin_q
            self.queue_sizes["vram"] = vram_q

    def snapshot(self):
        with self.lock:
            durations = {k: list(v) for k, v in self.task_durations.items()}
            queues = dict(self.queue_sizes)
            preds = dict(self.predicted_duration)
        return durations, queues, preds

# ---------------------------------------------------------------------------
# Queen consensus engine with risk decay + anomaly detection
# ---------------------------------------------------------------------------

class Queen:
    def __init__(self, memory: MemoryManager = None):
        self.nodes = {}
        self.lock = threading.Lock()
        self.memory = memory
        self.risk_state = {}
        if self.memory:
            if self.memory.state.get("queen_nodes"):
                self.nodes = self.memory.state["queen_nodes"]
                print("[QUEEN] Restored nodes from memory.")
            if self.memory.state.get("queen_risk_state"):
                self.risk_state = self.memory.state["queen_risk_state"]
                print("[QUEEN] Restored risk state from memory.")

        self.half_life = CONFIG["queen_risk_decay_half_life_sec"]
        self.anomaly_window = CONFIG["queen_anomaly_window"]
        self.anomaly_zscore = CONFIG["queen_anomaly_zscore"]

    def _decay_factor(self, dt):
        if self.half_life <= 0:
            return 1.0
        return 0.5 ** (dt / self.half_life)

    def update(self, node_id, events):
        now = time.time()
        with self.lock:
            self.nodes[node_id] = events
            for e in events:
                entity = e["entity"]
                score = float(e["score"])
                rs = self.risk_state.get(entity, {
                    "score": 0.0,
                    "last_update": now,
                    "history": [],
                })
                dt = max(0.0, now - rs["last_update"])
                decay = self._decay_factor(dt)
                rs["score"] = rs["score"] * decay + score
                rs["last_update"] = now
                hist = rs["history"]
                hist.append(score)
                if len(hist) > self.anomaly_window:
                    hist.pop(0)
                rs["history"] = hist
                self.risk_state[entity] = rs

        if self.memory:
            self.memory.update_queen_nodes(self.nodes)
            self.memory.update_queen_risk_state(self.risk_state)

    def _compute_anomalies(self):
        anomalies = {}
        for entity, rs in self.risk_state.items():
            hist = rs.get("history", [])
            if len(hist) < max(8, self.anomaly_window // 4):
                continue
            mean = sum(hist) / len(hist)
            var = sum((x - mean) ** 2 for x in hist) / max(1, len(hist) - 1)
            std = math.sqrt(max(var, 1e-9))
            last = hist[-1]
            z = (last - mean) / std if std > 0 else 0.0
            if abs(z) >= self.anomaly_zscore:
                anomalies[entity] = {
                    "zscore": z,
                    "last": last,
                    "mean": mean,
                    "std": std,
                }
        return anomalies

    def global_risk(self):
        now = time.time()
        risk = {}
        with self.lock:
            for entity, rs in self.risk_state.items():
                dt = max(0.0, now - rs["last_update"])
                decay = self._decay_factor(dt)
                effective = rs["score"] * decay
                if effective > 1.5:
                    risk[entity] = effective
        anomalies = self._compute_anomalies()
        return {
            "risk": risk,
            "anomalies": anomalies,
        }

# ---------------------------------------------------------------------------
# Real-time system telemetry
# ---------------------------------------------------------------------------

def _safe_cpu_percent(percpu=False):
    if psutil is None:
        return [0.0] if percpu else 0.0
    try:
        return psutil.cpu_percent(interval=None, percpu=percpu)
    except Exception:
        return [0.0] if percpu else 0.0


def _process_thread_cpu_percent():
    if psutil is None:
        return 0.0, 0
    try:
        p = psutil.Process(os.getpid())
        return float(p.cpu_percent(interval=None)), int(p.num_threads())
    except Exception:
        return 0.0, 0


class LiveTelemetry:
    def __init__(self, interval=0.5):
        self.interval = max(0.1, float(interval))
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.data = {
            "cpu_percent": 0.0,
            "cpu_per_core": [],
            "logical_threads": os.cpu_count() or 1,
            "physical_cores": 0,
            "memory_percent": 0.0,
            "disk_percent": 0.0,
            "process_cpu_percent": 0.0,
            "process_threads": 0,
            "load_1m": 0.0,
            "load_5m": 0.0,
            "load_15m": 0.0,
            "timestamp": 0.0,
        }
        self._thread = threading.Thread(
            target=self._loop, daemon=True, name="LiveTelemetry"
        )
        self._thread.start()

    def sample_now(self):
        if psutil is None:
            return dict(self.data)
        try:
            per_core = psutil.cpu_percent(interval=None, percpu=True)
            cpu = float(sum(per_core) / len(per_core)) if per_core else 0.0
            mem = float(psutil.virtual_memory().percent)
            root = os.environ.get("SystemDrive", "C:") + os.sep if os.name == "nt" else "/"
            disk = float(psutil.disk_usage(root).percent)
            proc_cpu, proc_threads = _process_thread_cpu_percent()
            physical = psutil.cpu_count(logical=False) or 0
            logical = psutil.cpu_count(logical=True) or (os.cpu_count() or 1)
            loads = (0.0, 0.0, 0.0)
            try:
                if hasattr(os, "getloadavg"):
                    loads = os.getloadavg()
            except Exception:
                pass
            new = {
                "cpu_percent": max(0.0, min(100.0, cpu)),
                "cpu_per_core": list(per_core),
                "logical_threads": int(logical),
                "physical_cores": int(physical),
                "memory_percent": max(0.0, min(100.0, mem)),
                "disk_percent": max(0.0, min(100.0, disk)),
                "process_cpu_percent": max(0.0, proc_cpu),
                "process_threads": int(proc_threads),
                "load_1m": float(loads[0]),
                "load_5m": float(loads[1]),
                "load_15m": float(loads[2]),
                "timestamp": time.time(),
            }
            with self.lock:
                self.data = new
            return dict(new)
        except Exception:
            with self.lock:
                return dict(self.data)

    def _loop(self):
        if psutil is not None:
            try:
                psutil.cpu_percent(interval=None, percpu=True)
            except Exception:
                pass
        while not self.stop_event.wait(self.interval):
            self.sample_now()

    def snapshot(self):
        with self.lock:
            return dict(self.data)

    def stop(self):
        self.stop_event.set()

# ---------------------------------------------------------------------------
# GPU telemetry + governor hooks
# ---------------------------------------------------------------------------

class GPUTelemetry:
    def __init__(self):
        self.available = False
        self.lock = threading.RLock()
        self.data = {
            "gpu_count": 0,
            "devices": [],
            "timestamp": 0.0,
        }
        if pynvml is not None:
            try:
                pynvml.nvmlInit()
                self.available = True
                print("[GPU] NVML initialized.")
            except Exception as e:
                print(f"[GPU] NVML init failed: {e}")

    def sample_now(self):
        if not self.available:
            return dict(self.data)
        try:
            count = pynvml.nvmlDeviceGetCount()
            devices = []
            for i in range(count):
                h = pynvml.nvmlDeviceGetHandleByIndex(i)
                raw_name = pynvml.nvmlDeviceGetName(h)
                if isinstance(raw_name, bytes):
                    name = raw_name.decode("utf-8", errors="ignore")
                else:
                    name = str(raw_name)
                util = pynvml.nvmlDeviceGetUtilizationRates(h)
                mem = pynvml.nvmlDeviceGetMemoryInfo(h)
                temp = pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU)
                devices.append({
                    "index": i,
                    "name": name,
                    "gpu_util": float(util.gpu),
                    "mem_util": float(util.memory),
                    "mem_used_mb": float(mem.used) / (1024 * 1024),
                    "mem_total_mb": float(mem.total) / (1024 * 1024),
                    "temp_c": float(temp),
                })
            new = {
                "gpu_count": count,
                "devices": devices,
                "timestamp": time.time(),
            }
            with self.lock:
                self.data = new
            return dict(new)
        except Exception as e:
            print(f"[GPU] Telemetry error: {e}")
            with self.lock:
                return dict(self.data)

    def snapshot(self):
        with self.lock:
            return dict(self.data)


class GPUGovernor:
    def __init__(self, telemetry: GPUTelemetry, memory: MemoryManager = None):
        self.telemetry = telemetry
        self.memory = memory
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.state = {
            "last_policy": {},
        }
        if self.memory and self.memory.state.get("gpu_governor_state"):
            self.state = self.memory.state["gpu_governor_state"]
            print("[GPU-GOV] Restored governor state from memory.")

        self.thread = threading.Thread(
            target=self._loop,
            name="GPUGovernor",
            daemon=True,
        )
        self.thread.start()

    def _compute_policy(self, snapshot):
        target_util = CONFIG["gpu_target_util_percent"]
        target_temp = CONFIG["gpu_target_temp_c"]
        policies = {}
        for dev in snapshot.get("devices", []):
            idx = dev["index"]
            util = dev["gpu_util"]
            temp = dev["temp_c"]
            mem_used = dev["mem_used_mb"]
            mem_total = dev["mem_total_mb"]
            mem_ratio = mem_used / max(mem_total, 1.0)

            policy = {
                "index": idx,
                "name": dev["name"],
                "util": util,
                "temp": temp,
                "mem_ratio": mem_ratio,
                "suggest_reduce_load": False,
                "suggest_increase_load": False,
                "suggest_vram_relief": False,
            }

            if temp > target_temp + 5 or util > target_util + 15:
                policy["suggest_reduce_load"] = True
            elif temp < target_temp - 10 and util < target_util - 20:
                policy["suggest_increase_load"] = True

            if mem_ratio > 0.9:
                policy["suggest_vram_relief"] = True

            policies[idx] = policy
        return policies

    def _loop(self):
        interval = CONFIG["gpu_governor_interval_sec"]
        while not self.stop_event.wait(interval):
            snap = self.telemetry.sample_now()
            policy = self._compute_policy(snap)
            with self.lock:
                self.state["last_policy"] = policy
            if self.memory:
                self.memory.update_gpu_governor_state(self.state)

    def snapshot_policy(self):
        with self.lock:
            return dict(self.state.get("last_policy", {}))

    def stop(self):
        self.stop_event.set()

# ---------------------------------------------------------------------------
# VRAM compute modules
# ---------------------------------------------------------------------------

def vram_bandwidth_job(size_mb=None, device_index=0):
    if torch is None or not torch.cuda.is_available():
        return {"error": "torch CUDA not available"}
    size_mb = size_mb or CONFIG["gpu_vram_stress_size_mb"]
    n_bytes = int(size_mb * 1024 * 1024)
    n_float = n_bytes // 4
    try:
        torch.cuda.set_device(device_index)
        start = time.time()
        x = torch.randn(n_float, device=f"cuda:{device_index}")
        y = x * 2.0
        torch.cuda.synchronize()
        duration = time.time() - start
        gb = size_mb / 1024.0
        bw = gb / max(duration, 1e-6)
        return {
            "device_index": device_index,
            "size_mb": size_mb,
            "duration_sec": duration,
            "bandwidth_gb_s": bw,
        }
    except Exception as e:
        return {"error": str(e)}


def vram_fragmentation_stress_job(chunks=None, device_index=0):
    if torch is None or not torch.cuda.is_available():
        return {"error": "torch CUDA not available"}
    chunks = chunks or CONFIG["gpu_vram_frag_chunks"]
    try:
        torch.cuda.set_device(device_index)
        tensors = []
        start = time.time()
        for i in range(chunks):
            sz = (1024 * (i % 64 + 1),)
            t = torch.randn(sz, device=f"cuda:{device_index}")
            tensors.append(t)
        mid = time.time()
        while tensors:
            tensors.pop()
        torch.cuda.empty_cache()
        end = time.time()
        return {
            "device_index": device_index,
            "chunks": chunks,
            "alloc_sec": mid - start,
            "free_sec": end - mid,
            "total_sec": end - start,
        }
    except Exception as e:
        return {"error": str(e)}

# ---------------------------------------------------------------------------
# Plugin system (sandboxed)
# ---------------------------------------------------------------------------

class PluginManager:
    def __init__(self, plugins_dir):
        self.plugins_dir = plugins_dir
        self.plugins = {}
        self._load_plugins()

    def _load_plugins(self):
        if not os.path.isdir(self.plugins_dir):
            return
        for fname in os.listdir(self.plugins_dir):
            if not fname.endswith(".py"):
                continue
            path = os.path.join(self.plugins_dir, fname)
            mod_name = f"plugin_{os.path.splitext(fname)[0]}"
            self.plugins[mod_name] = path
            print(f"[PLUGIN] Registered {mod_name} from {fname}")

    def sandbox_run(self, plugin_name, job_name, *args, **kwargs):
        path = self.plugins.get(plugin_name)
        if not path:
            return {"error": f"plugin {plugin_name} not found"}
        payload = {
            "job_name": job_name,
            "args": args,
            "kwargs": kwargs,
        }
        try:
            proc = subprocess.Popen(
                [sys.executable, path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            out, err = proc.communicate(json.dumps(payload), timeout=60)
            if proc.returncode != 0:
                return {"error": f"plugin error: {err.strip()}"}
            try:
                return json.loads(out)
            except Exception:
                return {"result": out}
        except Exception as e:
            return {"error": str(e)}

# ---------------------------------------------------------------------------
# Beast Node
# ---------------------------------------------------------------------------

class BeastNode:
    def __init__(self,
                 node_id: str,
                 max_io_workers=None,
                 max_cpu_workers=None,
                 enable_gpu=True,
                 enable_npu=True,
                 metrics_window=200,
                 predictive_alpha=0.3,
                 queen: Queen = None,
                 plugin_manager: PluginManager = None,
                 gpu_telemetry: GPUTelemetry = None,
                 gpu_governor: GPUGovernor = None,
                 memory: MemoryManager = None,
                 job_history: JobHistory = None):
        self.node_id = node_id
        cpu_count = os.cpu_count() or 4

        self.max_io_workers = max_io_workers or min(32, cpu_count * 2)
        self.max_cpu_workers = max_cpu_workers or max(1, cpu_count - 1)

        self.io_executor = ThreadPoolExecutor(max_workers=self.max_io_workers)
        self.cpu_executor = ProcessPoolExecutor(max_workers=self.max_cpu_workers)

        self.enable_gpu = enable_gpu and (torch is not None or tf is not None)
        self.enable_npu = enable_npu and (ort is not None or tf is not None)

        self.io_queue = PriorityTaskQueue()
        self.cpu_queue = PriorityTaskQueue()
        self.gpu_queue = PriorityTaskQueue()
        self.npu_queue = PriorityTaskQueue()
        self.live_queue = PriorityTaskQueue()
        self.plugin_queue = PriorityTaskQueue()
        self.vram_queue = PriorityTaskQueue()

        self._stop_event = threading.Event()

        self.metrics = NodeMetrics(window=metrics_window, alpha=predictive_alpha)
        self.telemetry = LiveTelemetry(interval=0.5)
        self.queen = queen
        self.plugin_manager = plugin_manager
        self.gpu_telemetry = gpu_telemetry
        self.gpu_governor = gpu_governor
        self.memory = memory
        self.job_history = job_history

        self.health_ok = True
        self.last_health_check = time.time()

        self._async_loop = asyncio.new_event_loop()
        self._async_thread = threading.Thread(
            target=self._run_async_loop,
            name=f"{self.node_id}_AsyncLoop",
            daemon=True
        )
        self._async_thread.start()

        self._io_worker = threading.Thread(
            target=self._io_worker_loop,
            name=f"{self.node_id}_IOWorker",
            daemon=True
        )
        self._cpu_worker = threading.Thread(
            target=self._cpu_worker_loop,
            name=f"{self.node_id}_CPUWorker",
            daemon=True
        )
        self._gpu_worker = threading.Thread(
            target=self._gpu_worker_loop,
            name=f"{self.node_id}_GPUWorker",
            daemon=True
        )
        self._npu_worker = threading.Thread(
            target=self._npu_worker_loop,
            name=f"{self.node_id}_NPUWorker",
            daemon=True
        )
        self._live_worker = threading.Thread(
            target=self._live_worker_loop,
            name=f"{self.node_id}_LiveWorker",
            daemon=True
        )
        self._plugin_worker = threading.Thread(
            target=self._plugin_worker_loop,
            name=f"{self.node_id}_PluginWorker",
            daemon=True
        )
        self._vram_worker = threading.Thread(
            target=self._vram_worker_loop,
            name=f"{self.node_id}_VRAMWorker",
            daemon=True
        )

        self._io_worker.start()
        self._cpu_worker.start()
        self._gpu_worker.start()
        self._npu_worker.start()
        self._live_worker.start()
        self._plugin_worker.start()
        self._vram_worker.start()

        self._set_affinity()
        self._detect_devices()

        self._health_thread = threading.Thread(
            target=self._health_loop,
            name=f"{self.node_id}_Health",
            daemon=True
        )
        self._health_thread.start()

    def _set_affinity(self):
        if psutil is None:
            return
        try:
            p = psutil.Process(os.getpid())
            cpu_count = os.cpu_count() or 4
            p.cpu_affinity(list(range(cpu_count)))
            print(f"[{self.node_id}][AFFINITY] Using all {cpu_count} cores.")
        except Exception as e:
            print(f"[{self.node_id}][AFFINITY] Failed: {e}")

    def _detect_devices(self):
        if self.enable_gpu:
            if torch is not None and torch.cuda.is_available():
                print(f"[{self.node_id}][GPU] Torch CUDA: {torch.cuda.device_count()} device(s).")
            elif tf is not None:
                gpus = tf.config.list_physical_devices("GPU")
                if gpus:
                    print(f"[{self.node_id}][GPU] TF GPU: {len(gpus)} device(s).")
                else:
                    print(f"[{self.node_id}][GPU] No GPU devices.")
            else:
                print(f"[{self.node_id}][GPU] No backend.")
        else:
            print(f"[{self.node_id}][GPU] Disabled.")

        if self.enable_npu:
            if ort is not None:
                providers = ort.get_available_providers()
                print(f"[{self.node_id}][NPU] ORT providers: {providers}")
            elif tf is not None:
                tpus = tf.config.list_physical_devices("TPU")
                if tpus:
                    print(f"[{self.node_id}][NPU] TF TPU: {len(tpus)} device(s).")
                else:
                    print(f"[{self.node_id}][NPU] No TPU devices.")
            else:
                print(f"[{self.node_id}][NPU] No backend.")
        else:
            print(f"[{self.node_id}][NPU] Disabled.")

    def _run_async_loop(self):
        asyncio.set_event_loop(self._async_loop)
        self._async_loop.run_forever()

    def submit_async(self, coro_factory, priority=0, name=None):
        task = Task(coro_factory, task_type=TaskType.ASYNC, priority=priority, name=name)
        asyncio.run_coroutine_threadsafe(self._async_task_wrapper(task), self._async_loop)

    async def _async_task_wrapper(self, task: Task):
        start = time.time()
        try:
            coro = task.func(*task.args, **task.kwargs)
            await coro
            status = "ok"
        except Exception as e:
            print(f"[{self.node_id}][ASYNC][{task.name}] Error: {e}")
            status = "error"
        finally:
            duration = time.time() - start
            self.metrics.record_task(TaskType.ASYNC, duration)
            if self.job_history:
                self.job_history.record(self.node_id, TaskType.ASYNC, task.name, status, duration)

    def submit_cpu(self, func, *args, priority=0, name=None, **kwargs):
        task = Task(func, args, kwargs, task_type=TaskType.CPU, priority=priority, name=name)
        self.cpu_queue.put(task)

    def submit_io(self, func, *args, priority=0, name=None, **kwargs):
        task = Task(func, args, kwargs, task_type=TaskType.IO, priority=priority, name=name)
        self.io_queue.put(task)

    def submit_gpu(self, func, *args, priority=0, name=None, **kwargs):
        if not self.enable_gpu:
            print(f"[{self.node_id}][GPU] Disabled/unavailable, skip '{name or func.__name__}'")
            return
        task = Task(func, args, kwargs, task_type=TaskType.GPU, priority=priority, name=name)
        self.gpu_queue.put(task)

    def submit_npu(self, func, *args, priority=0, name=None, **kwargs):
        if not self.enable_npu:
            print(f"[{self.node_id}][NPU] Disabled/unavailable, skip '{name or func.__name__}'")
            return
        task = Task(func, args, kwargs, task_type=TaskType.NPU, priority=priority, name=name)
        self.npu_queue.put(task)

    def submit_live(self, name="live", priority=0):
        task = Task(live_data_job, (name,), {}, task_type=TaskType.LIVE, priority=priority, name=name)
        self.live_queue.put(task)

    def submit_plugin(self, plugin_name, job_name, *args, priority=0, name=None, **kwargs):
        if not self.plugin_manager:
            print(f"[{self.node_id}][PLUGIN] No plugin manager.")
            return
        def sandbox_wrapper(plugin_name, job_name, *args, **kwargs):
            return self.plugin_manager.sandbox_run(plugin_name, job_name, *args, **kwargs)
        task = Task(sandbox_wrapper, (plugin_name, job_name, *args), kwargs,
                    task_type=TaskType.PLUGIN, priority=priority, name=name or job_name)
        self.plugin_queue.put(task)

    def submit_vram_bandwidth(self, size_mb=None, device_index=0, priority=0, name=None):
        if not self.enable_gpu:
            print(f"[{self.node_id}][VRAM] GPU disabled/unavailable.")
            return
        task = Task(
            vram_bandwidth_job,
            (size_mb, device_index),
            {},
            task_type=TaskType.VRAM,
            priority=priority,
            name=name or "vram_bandwidth",
        )
        self.vram_queue.put(task)

    def submit_vram_fragmentation(self, chunks=None, device_index=0, priority=0, name=None):
        if not self.enable_gpu:
            print(f"[{self.node_id}][VRAM] GPU disabled/unavailable.")
            return
        task = Task(
            vram_fragmentation_stress_job,
            (chunks, device_index),
            {},
            task_type=TaskType.VRAM,
            priority=priority,
            name=name or "vram_fragmentation",
        )
        self.vram_queue.put(task)

    def _update_queues_metrics(self):
        self.metrics.set_queue_sizes(
            self.io_queue.qsize(),
            self.cpu_queue.qsize(),
            self.gpu_queue.qsize(),
            self.npu_queue.qsize(),
            self.live_queue.qsize(),
            self.plugin_queue.qsize(),
            self.vram_queue.qsize(),
        )

    def _io_worker_loop(self):
        while not self._stop_event.is_set():
            self._update_queues_metrics()
            try:
                task = self.io_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.io_executor.submit(self._run_task, task)

    def _cpu_worker_loop(self):
        while not self._stop_event.is_set():
            self._update_queues_metrics()
            try:
                task = self.cpu_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.cpu_executor.submit(self._run_task, task)

    def _gpu_worker_loop(self):
        while not self._stop_event.is_set():
            self._update_queues_metrics()
            try:
                task = self.gpu_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.io_executor.submit(self._run_task, task)

    def _npu_worker_loop(self):
        while not self._stop_event.is_set():
            self._update_queues_metrics()
            try:
                task = self.npu_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.io_executor.submit(self._run_task, task)

    def _live_worker_loop(self):
        while not self._stop_event.is_set():
            self._update_queues_metrics()
            try:
                task = self.live_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.io_executor.submit(self._run_task, task)

    def _plugin_worker_loop(self):
        while not self._stop_event.is_set():
            self._update_queues_metrics()
            try:
                task = self.plugin_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.io_executor.submit(self._run_task, task)

    def _vram_worker_loop(self):
        while not self._stop_event.is_set():
            self._update_queues_metrics()
            try:
                task = self.vram_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.io_executor.submit(self._run_task, task)

    def _run_task(self, task: Task):
        start = time.time()
        events = []
        status = "ok"
        info = None
        try:
            result = task.func(*task.args, **task.kwargs)
            info = result if isinstance(result, dict) else {"result": str(result)}
            if task.task_type == TaskType.VRAM and isinstance(result, dict):
                if "bandwidth_gb_s" in result:
                    bw = result["bandwidth_gb_s"]
                    events.append({"entity": "vram_bandwidth", "score": bw})
                if "chunks" in result:
                    events.append({"entity": "vram_frag_chunks", "score": float(result["chunks"])})
                if "total_sec" in result and self.memory:
                    self.memory.append_vram_frag_history({
                        "timestamp": time.time(),
                        "chunks": result["chunks"],
                        "total_sec": result["total_sec"],
                        "alloc_sec": result["alloc_sec"],
                        "free_sec": result["free_sec"],
                    })
            return result
        except Exception as e:
            print(f"[{self.node_id}][TASK][{task.task_type}][{task.name}] Error: {e}")
            status = "error"
            info = {"error": str(e)}
            task.retries += 1
            events.append({"entity": task.name, "score": 0.8})
            if task.retries <= CONFIG["job_retry_limit"]:
                print(f"[{self.node_id}][TASK][{task.name}] Retrying ({task.retries})")
                task.priority = max(task.priority - 1, 0)
                if task.task_type == TaskType.CPU:
                    self.cpu_queue.put(task)
                elif task.task_type == TaskType.IO:
                    self.io_queue.put(task)
                elif task.task_type == TaskType.GPU:
                    self.gpu_queue.put(task)
                elif task.task_type == TaskType.NPU:
                    self.npu_queue.put(task)
                elif task.task_type == TaskType.LIVE:
                    self.live_queue.put(task)
                elif task.task_type == TaskType.PLUGIN:
                    self.plugin_queue.put(task)
                elif task.task_type == TaskType.VRAM:
                    self.vram_queue.put(task)
        finally:
            duration = time.time() - start
            self.metrics.record_task(task.task_type, duration)
            events.append({"entity": f"{task.task_type}_latency", "score": duration})
            if self.queen:
                self.queen.update(self.node_id, events)
            if self.job_history:
                self.job_history.record(self.node_id, task.task_type, task.name, status, duration, info)

    def approx_load(self):
        _, queues, _ = self.metrics.snapshot()
        return sum(queues.values())

    def get_metrics_snapshot(self):
        return self.metrics.snapshot()

    def get_live_load(self):
        d = self.telemetry.snapshot()
        return {
            "cpu_percent": d.get("cpu_percent", 0.0),
            "cpu_per_core": d.get("cpu_per_core", []),
            "logical_threads": d.get("logical_threads", os.cpu_count() or 1),
            "physical_cores": d.get("physical_cores", 0),
            "memory_percent": d.get("memory_percent", 0.0),
            "disk_percent": d.get("disk_percent", 0.0),
            "process_cpu_percent": d.get("process_cpu_percent", 0.0),
            "process_threads": d.get("process_threads", 0),
            "load_1m": d.get("load_1m", 0.0),
            "load_5m": d.get("load_5m", 0.0),
            "load_15m": d.get("load_15m", 0.0),
            "timestamp": d.get("timestamp", 0.0),
        }

    def get_gpu_policy(self):
        if not self.gpu_governor:
            return {}
        return self.gpu_governor.snapshot_policy()

    def set_cpu_workers(self, new_count):
        new_count = max(CONFIG["cpu_worker_min"], min(CONFIG["cpu_worker_max"], new_count))
        if new_count != self.max_cpu_workers:
            print(f"[{self.node_id}][TUNER] CPU workers {self.max_cpu_workers} -> {new_count}")
            self.max_cpu_workers = new_count

    def set_io_workers(self, new_count):
        new_count = max(CONFIG["io_worker_min"], min(CONFIG["io_worker_max"], new_count))
        if new_count != self.max_io_workers:
            print(f"[{self.node_id}][TUNER] IO workers {self.max_io_workers} -> {new_count}")
            self.max_io_workers = new_count

    def _health_loop(self):
        while not self._stop_event.is_set():
            time.sleep(CONFIG["health_check_interval"])
            _, queues, _ = self.get_metrics_snapshot()
            total_q = sum(queues.values())
            if total_q > 1000:
                self.health_ok = False
                print(f"[{self.node_id}][HEALTH] Degraded (queues={total_q})")
            else:
                self.health_ok = True

    def shutdown(self, wait=True):
        self._stop_event.set()
        try:
            self.telemetry.stop()
        except Exception:
            pass
        if wait:
            for t in [
                self._io_worker,
                self._cpu_worker,
                self._gpu_worker,
                self._npu_worker,
                self._live_worker,
                self._plugin_worker,
                self._vram_worker,
                self._health_thread,
                self._async_thread,
            ]:
                try:
                    t.join(timeout=1.0)
                except Exception:
                    pass
        try:
            self.io_executor.shutdown(wait=wait)
        except Exception:
            pass
        try:
            self.cpu_executor.shutdown(wait=wait)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Live data job
# ---------------------------------------------------------------------------

def live_data_job(name="live"):
    if psutil is None:
        return {"name": name, "error": "psutil not available"}
    cpu = psutil.cpu_percent(interval=0.1)
    mem = psutil.virtual_memory().percent
    disk = psutil.disk_usage(os.environ.get("SystemDrive", "C:") + os.sep).percent
    return {
        "name": name,
        "cpu_percent": cpu,
        "mem_percent": mem,
        "disk_percent": disk,
    }

# ---------------------------------------------------------------------------
# Swarm-wide scheduler + auto-spawn
# ---------------------------------------------------------------------------

class GlobalScheduler:
    def __init__(self, nodes, memory: MemoryManager):
        self.nodes = nodes
        self.memory = memory
        self.global_queue = PriorityTaskQueue()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._loop,
            name="GlobalScheduler",
            daemon=True,
        )
        self.thread.start()

    def submit(self, task: Task):
        self.global_queue.put(task)

    def _select_node(self):
        healthy = [n for n in self.nodes if n.health_ok]
        if not healthy:
            healthy = self.nodes
        return min(healthy, key=lambda n: n.approx_load())

    def _loop(self):
        while not self.stop_event.is_set():
            try:
                task = self.global_queue.get(timeout=0.1)
            except queue.Empty:
                time.sleep(0.05)
                continue
            node = self._select_node()
            if task.task_type == TaskType.CPU:
                node.cpu_queue.put(task)
            elif task.task_type == TaskType.IO:
                node.io_queue.put(task)
            elif task.task_type == TaskType.GPU:
                node.gpu_queue.put(task)
            elif task.task_type == TaskType.NPU:
                node.npu_queue.put(task)
            elif task.task_type == TaskType.LIVE:
                node.live_queue.put(task)
            elif task.task_type == TaskType.PLUGIN:
                node.plugin_queue.put(task)
            elif task.task_type == TaskType.VRAM:
                node.vram_queue.put(task)

    def stop(self):
        self.stop_event.set()
        try:
            self.thread.join(timeout=1.0)
        except Exception:
            pass


class BeastSwarm:
    def __init__(self, nodes, scheduler: GlobalScheduler):
        self.nodes = nodes
        self.scheduler = scheduler

    def submit_cpu(self, func, *args, priority=0, name=None, **kwargs):
        self.scheduler.submit(Task(func, args, kwargs, TaskType.CPU, priority, name))

    def submit_io(self, func, *args, priority=0, name=None, **kwargs):
        self.scheduler.submit(Task(func, args, kwargs, TaskType.IO, priority, name))

    def submit_gpu(self, func, *args, priority=0, name=None, **kwargs):
        self.scheduler.submit(Task(func, args, kwargs, TaskType.GPU, priority, name))

    def submit_npu(self, func, *args, priority=0, name=None, **kwargs):
        self.scheduler.submit(Task(func, args, kwargs, TaskType.NPU, priority, name))

    def submit_live(self, name="live", priority=0):
        self.scheduler.submit(Task(live_data_job, (name,), {}, TaskType.LIVE, priority, name))

    def submit_plugin(self, plugin_name, job_name, *args, priority=0, name=None, **kwargs):
        def plugin_wrapper(plugin_name, job_name, *args, **kwargs):
            return {"plugin": plugin_name, "job": job_name}
        self.scheduler.submit(Task(plugin_wrapper, (plugin_name, job_name, *args), kwargs,
                                   TaskType.PLUGIN, priority, name or job_name))

    def submit_vram_bandwidth(self, size_mb=None, device_index=0, priority=0, name=None):
        self.scheduler.submit(Task(vram_bandwidth_job, (size_mb, device_index), {},
                                   TaskType.VRAM, priority, name or "vram_bandwidth"))

    def submit_vram_fragmentation(self, chunks=None, device_index=0, priority=0, name=None):
        self.scheduler.submit(Task(vram_fragmentation_stress_job, (chunks, device_index), {},
                                   TaskType.VRAM, priority, name or "vram_fragmentation"))

    def shutdown(self):
        for n in self.nodes:
            n.shutdown()
        self.scheduler.stop()


class SwarmTuner:
    def __init__(self, nodes):
        self.nodes = nodes
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._loop,
            name="SwarmTuner",
            daemon=True,
        )
        self.thread.start()

    def _loop(self):
        interval = CONFIG["tuner_interval_sec"]
        while not self.stop_event.wait(interval):
            for node in self.nodes:
                durations, queues, preds = node.get_metrics_snapshot()
                cpu_q = queues.get("cpu", 0)
                io_q = queues.get("io", 0)
                cpu_pred = preds.get(TaskType.CPU, 0.0)
                io_pred = preds.get(TaskType.IO, 0.0)

                if cpu_q > 0 and cpu_pred > 0.2:
                    node.set_cpu_workers(node.max_cpu_workers + 1)
                elif cpu_q == 0 and cpu_pred < 0.05:
                    node.set_cpu_workers(max(CONFIG["cpu_worker_min"], node.max_cpu_workers - 1))

                if io_q > 0 and io_pred > 0.1:
                    node.set_io_workers(node.max_io_workers + 1)
                elif io_q == 0 and io_pred < 0.02:
                    node.set_io_workers(max(CONFIG["io_worker_min"], node.max_io_workers - 1))

    def stop(self):
        self.stop_event.set()


class AutoSpawner:
    def __init__(self, nodes, queen: Queen, memory: MemoryManager,
                 gpu_telemetry: GPUTelemetry, gpu_governor: GPUGovernor,
                 plugin_manager: PluginManager, scheduler: GlobalScheduler,
                 job_history: JobHistory):
        self.nodes = nodes
        self.queen = queen
        self.memory = memory
        self.gpu_telemetry = gpu_telemetry
        self.gpu_governor = gpu_governor
        self.plugin_manager = plugin_manager
        self.scheduler = scheduler
        self.job_history = job_history
        self.stop_event = threading.Event()
        self.thread = threading.Thread(
            target=self._loop,
            name="AutoSpawner",
            daemon=True,
        )
        self.thread.start()

    def _loop(self):
        interval = CONFIG["auto_spawn_interval_sec"]
        while not self.stop_event.wait(interval):
            total_load = sum(n.approx_load() for n in self.nodes)
            if total_load > CONFIG["auto_spawn_load_threshold"] and len(self.nodes) < CONFIG["auto_spawn_max_nodes"]:
                idx = len(self.nodes)
                print(f"[AUTOSPAWN] Spawning node{idx} (load={total_load})")
                node = BeastNode(
                    node_id=f"node{idx}",
                    max_io_workers=CONFIG["io_worker_max"],
                    max_cpu_workers=CONFIG["cpu_worker_max"],
                    enable_gpu=CONFIG["enable_gpu"],
                    enable_npu=CONFIG["enable_npu"],
                    metrics_window=CONFIG["metrics_window"],
                    predictive_alpha=CONFIG["predictive_alpha"],
                    queen=self.queen,
                    plugin_manager=self.plugin_manager,
                    gpu_telemetry=self.gpu_telemetry,
                    gpu_governor=self.gpu_governor,
                    memory=self.memory,
                    job_history=self.job_history,
                )
                self.nodes.append(node)

    def stop(self):
        self.stop_event.set()
        try:
            self.thread.join(timeout=1.0)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Multi-host swarm networking (simple TCP JSON)
# ---------------------------------------------------------------------------

class MultiHostSwarm:
    """
    Simple multi-host swarm:
    - Listens on TCP for JSON messages: {"type": "job", "task_type": "...", "args": [...], "kwargs": {...}}
    - Forwards jobs into local BeastSwarm.
    - Can send jobs to peers.
    """
    def __init__(self, swarm: BeastSwarm):
        self.swarm = swarm
        self.stop_event = threading.Event()
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True, name="MultiHostServer")
        self.server_thread.start()

    def _server_loop(self):
        host = CONFIG["multi_host_listen_host"]
        port = CONFIG["multi_host_listen_port"]
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((host, port))
        sock.listen(5)
        print(f"[MULTI] Listening on {host}:{port}")
        sock.settimeout(1.0)
        while not self.stop_event.is_set():
            try:
                conn, addr = sock.accept()
            except socket.timeout:
                continue
            threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
        try:
            sock.close()
        except Exception:
            pass

    def _handle_client(self, conn, addr):
        try:
            data = conn.recv(65536)
            if not data:
                return
            try:
                msg = json.loads(data.decode("utf-8"))
            except Exception:
                return
            if msg.get("type") == "job":
                ttype = msg.get("task_type", "cpu")
                args = msg.get("args", [])
                kwargs = msg.get("kwargs", {})
                if ttype == TaskType.CPU:
                    self.swarm.submit_cpu(demo_cpu_job, *args, **kwargs)
                elif ttype == TaskType.IO:
                    self.swarm.submit_io(demo_io_job, *args, **kwargs)
                elif ttype == TaskType.GPU:
                    self.swarm.submit_gpu(demo_gpu_job, *args, **kwargs)
                elif ttype == TaskType.NPU:
                    self.swarm.submit_npu(demo_npu_job, *args, **kwargs)
                elif ttype == TaskType.LIVE:
                    self.swarm.submit_live(*args, **kwargs)
                elif ttype == TaskType.VRAM:
                    self.swarm.submit_vram_bandwidth(*args, **kwargs)
            conn.sendall(b'{"status":"ok"}')
        except Exception as e:
            try:
                conn.sendall(b'{"status":"error"}')
            except Exception:
                pass
        finally:
            try:
                conn.close()
            except Exception:
                pass

    def send_job_to_peer(self, peer, task_type, *args, **kwargs):
        host, port_str = peer.split(":")
        port = int(port_str)
        msg = {
            "type": "job",
            "task_type": task_type,
            "args": args,
            "kwargs": kwargs,
        }
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, port))
            s.sendall(json.dumps(msg).encode("utf-8"))
            resp = s.recv(4096)
            try:
                return json.loads(resp.decode("utf-8"))
            except Exception:
                return {"status": "unknown"}
        except Exception as e:
            return {"status": "error", "error": str(e)}
        finally:
            try:
                s.close()
            except Exception:
                pass

    def stop(self):
        self.stop_event.set()
        try:
            self.server_thread.join(timeout=1.0)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# ZMQ swarm
# ---------------------------------------------------------------------------

class ZMQSwarm:
    def __init__(self, swarm: BeastSwarm, bind_addr: str):
        self.swarm = swarm
        self.bind_addr = bind_addr
        self.context = zmq.Context() if zmq is not None else None
        self.socket = None
        self.is_server = False
        self.thread = None
        self.stop_event = threading.Event()

    def start_server(self):
        if self.context is None:
            print("[ZMQ] pyzmq not available.")
            return
        if self.socket is not None:
            return
        self.socket = self.context.socket(zmq.REP)
        self.socket.bind(self.bind_addr)
        self.is_server = True
        self.thread = threading.Thread(target=self._server_loop, daemon=True, name="ZMQServer")
        self.thread.start()
        print(f"[ZMQ] Server bound at {self.bind_addr}")

    def start_client(self):
        if self.context is None:
            print("[ZMQ] pyzmq not available.")
            return
        if self.socket is not None:
            return
        self.socket = self.context.socket(zmq.REQ)
        self.socket.connect(self.bind_addr)
        self.is_server = False
        print(f"[ZMQ] Client connected to {self.bind_addr}")

    def _server_loop(self):
        while not self.stop_event.is_set():
            try:
                msg = self.socket.recv_json(flags=zmq.NOBLOCK)
            except zmq.Again:
                time.sleep(0.01)
                continue
            jtype = msg.get("type", "cpu")
            args = msg.get("args", [])
            kwargs = msg.get("kwargs", {})
            if jtype == "cpu":
                self.swarm.submit_cpu(demo_cpu_job, *args, **kwargs)
            elif jtype == "io":
                self.swarm.submit_io(demo_io_job, *args, **kwargs)
            elif jtype == "gpu":
                self.swarm.submit_gpu(demo_gpu_job, *args, **kwargs)
            elif jtype == "npu":
                self.swarm.submit_npu(demo_npu_job, *args, **kwargs)
            elif jtype == "live":
                self.swarm.submit_live(*args, **kwargs)
            elif jtype == "vram_bw":
                self.swarm.submit_vram_bandwidth(*args, **kwargs)
            elif jtype == "vram_frag":
                self.swarm.submit_vram_fragmentation(*args, **kwargs)
            self.socket.send_json({"status": "ok"})

    def send_job(self, jtype, *args, **kwargs):
        if self.socket is None or self.is_server:
            print("[ZMQ] Client not started.")
            return
        payload = {
            "type": jtype,
            "args": args,
            "kwargs": kwargs,
        }
        self.socket.send_json(payload)
        try:
            reply = self.socket.recv_json()
            return reply
        except Exception:
            return {"status": "error"}

    def stop(self):
        self.stop_event.set()
        if self.thread:
            try:
                self.thread.join(timeout=1.0)
            except Exception:
                pass
        if self.socket is not None:
            try:
                self.socket.close()
            except Exception:
                pass
        if self.context is not None:
            try:
                self.context.term()
            except Exception:
                pass

# ---------------------------------------------------------------------------
# Demo jobs
# ---------------------------------------------------------------------------

def demo_cpu_job(n=10_000_000):
    s = 0
    for i in range(n):
        s += i * i
    return s


def demo_io_job(delay=0.2):
    time.sleep(delay)
    return {"slept": delay}


async def demo_async_job(delay=0.3):
    await asyncio.sleep(delay)
    return {"async_slept": delay}


def demo_gpu_job(size=1024, device_index=0):
    if torch is None or not torch.cuda.is_available():
        return {"error": "torch CUDA not available"}
    torch.cuda.set_device(device_index)
    x = torch.randn(size, size, device=f"cuda:{device_index}")
    y = torch.matmul(x, x)
    torch.cuda.synchronize()
    return {"size": size, "device_index": device_index}


def demo_npu_job():
    if ort is None:
        return {"error": "onnxruntime not available"}
    return {"status": "npu_demo_ok"}

# ---------------------------------------------------------------------------
# REST API (secure token)
# ---------------------------------------------------------------------------

class SwarmREST:
    def __init__(self, swarm: BeastSwarm, queen: Queen, memory: MemoryManager, job_history: JobHistory):
        self.swarm = swarm
        self.queen = queen
        self.memory = memory
        self.job_history = job_history
        self.app = Flask(__name__) if Flask is not None else None
        self.thread = None
        if self.app:
            self._setup_routes()
            self.thread = threading.Thread(target=self._run, daemon=True, name="SwarmREST")
            self.thread.start()
            print(f"[REST] API listening on {CONFIG['rest_api_host']}:{CONFIG['rest_api_port']}")

    def _check_auth(self, req):
        token = req.headers.get("X-Auth-Token", "")
        return token == CONFIG["rest_api_token"]

    def _setup_routes(self):
        @self.app.route("/metrics", methods=["GET"])
        def metrics():
            if not self._check_auth(request):
                return jsonify({"error": "unauthorized"}), 401
            nodes_data = []
            for n in self.swarm.nodes:
                load = n.get_live_load()
                _, queues, _ = n.get_metrics_snapshot()
                nodes_data.append({
                    "node_id": n.node_id,
                    "load": load,
                    "queues": queues,
                })
            queen_risk = self.queen.global_risk()
            vram_frag = self.memory.get_vram_frag_history()
            jobs = self.job_history.recent(50)
            return jsonify({
                "nodes": nodes_data,
                "queen": queen_risk,
                "vram_frag_history": vram_frag,
                "job_history": jobs,
            })

        @self.app.route("/job/cpu", methods=["POST"])
        def job_cpu():
            if not self._check_auth(request):
                return jsonify({"error": "unauthorized"}), 401
            payload = request.json or {}
            n = int(payload.get("n", 1_000_000))
            self.swarm.submit_cpu(demo_cpu_job, n, priority=1, name="rest_cpu")
            return jsonify({"status": "submitted", "type": "cpu", "n": n})

        @self.app.route("/job/vram_bw", methods=["POST"])
        def job_vram_bw():
            if not self._check_auth(request):
                return jsonify({"error": "unauthorized"}), 401
            payload = request.json or {}
            size_mb = int(payload.get("size_mb", CONFIG["gpu_vram_stress_size_mb"]))
            self.swarm.submit_vram_bandwidth(size_mb=size_mb, priority=1, name="rest_vram_bw")
            return jsonify({"status": "submitted", "type": "vram_bw", "size_mb": size_mb})

        @self.app.route("/job/vram_frag", methods=["POST"])
        def job_vram_frag():
            if not self._check_auth(request):
                return jsonify({"error": "unauthorized"}), 401
            payload = request.json or {}
            chunks = int(payload.get("chunks", CONFIG["gpu_vram_frag_chunks"]))
            self.swarm.submit_vram_fragmentation(chunks=chunks, priority=1, name="rest_vram_frag")
            return jsonify({"status": "submitted", "type": "vram_frag", "chunks": chunks})

    def _run(self):
        self.app.run(host=CONFIG["rest_api_host"], port=CONFIG["rest_api_port"], debug=False, use_reloader=False)

# ---------------------------------------------------------------------------
# GUI — Command Center with real-time charts
# ---------------------------------------------------------------------------

class NodeCard(QtWidgets.QFrame):
    def __init__(self, node: BeastNode, parent=None):
        super().__init__(parent)
        self.node = node
        self.setFrameShape(QtWidgets.QFrame.Shape.StyledPanel)
        self.setFrameShadow(QtWidgets.QFrame.Shadow.Raised)
        layout = QtWidgets.QVBoxLayout(self)
        self.title = QtWidgets.QLabel(f"Node {self.node.node_id}")
        self.title.setStyleSheet("font-weight: bold;")
        layout.addWidget(self.title)

        self.cpu_label = QtWidgets.QLabel("CPU: - %")
        self.mem_label = QtWidgets.QLabel("Mem: - %")
        self.disk_label = QtWidgets.QLabel("Disk: - %")
        self.thread_label = QtWidgets.QLabel("Threads: -")
        self.queue_label = QtWidgets.QLabel("Queues: cpu/io/gpu/npu/live/plugin/vram")

        for w in [self.cpu_label, self.mem_label, self.disk_label,
                  self.thread_label, self.queue_label]:
            layout.addWidget(w)

    def refresh(self):
        load = self.node.get_live_load()
        self.cpu_label.setText(f"CPU: {load['cpu_percent']:.1f} %")
        self.mem_label.setText(f"Mem: {load['memory_percent']:.1f} %")
        self.disk_label.setText(f"Disk: {load['disk_percent']:.1f} %")
        self.thread_label.setText(f"Threads: {load['process_threads']}")
        _, queues, _ = self.node.get_metrics_snapshot()
        qtxt = "Queues: " + ", ".join(f"{k}={v}" for k, v in queues.items())
        self.queue_label.setText(qtxt)


class SwarmGUI(QtWidgets.QMainWindow):
    def __init__(self, swarm: BeastSwarm, queen: Queen,
                 gpu_governor: GPUGovernor, zmq_swarm: ZMQSwarm,
                 plugin_manager: PluginManager, memory: MemoryManager,
                 job_history: JobHistory, multi_host: MultiHostSwarm):
        super().__init__()
        self.swarm = swarm
        self.queen = queen
        self.gpu_governor = gpu_governor
        self.zmq_swarm = zmq_swarm
        self.plugin_manager = plugin_manager
        self.memory = memory
        self.job_history = job_history
        self.multi_host = multi_host

        self.setWindowTitle("Beast Swarm Engine v8.3 — Command Center")
        self.resize(1400, 800)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        root_layout = QtWidgets.QHBoxLayout(central)

        # Sidebar
        self.sidebar = QtWidgets.QFrame()
        self.sidebar.setFixedWidth(220)
        self.sidebar.setStyleSheet("""
            QFrame {
                background-color: #2b2b2b;
            }
            QPushButton {
                color: #f0f0f0;
                background-color: #3b3b3b;
                border: none;
                padding: 8px 12px;
                text-align: left;
            }
            QPushButton:hover {
                background-color: #505050;
            }
            QPushButton:checked {
                background-color: #007acc;
            }
        """)
        side_layout = QtWidgets.QVBoxLayout(self.sidebar)
        side_layout.setContentsMargins(8, 8, 8, 8)
        side_layout.setSpacing(6)

        self.btn_overview = QtWidgets.QPushButton("Overview")
        self.btn_nodes = QtWidgets.QPushButton("Nodes")
        self.btn_gpu = QtWidgets.QPushButton("GPU")
        self.btn_vram = QtWidgets.QPushButton("VRAM")
        self.btn_queen = QtWidgets.QPushButton("Queen")
        self.btn_zmq = QtWidgets.QPushButton("ZMQ")
        self.btn_plugins = QtWidgets.QPushButton("Plugins")
        self.btn_history = QtWidgets.QPushButton("Job History")
        self.btn_multi = QtWidgets.QPushButton("Multi-Host")

        for b in [self.btn_overview, self.btn_nodes, self.btn_gpu,
                  self.btn_vram, self.btn_queen, self.btn_zmq,
                  self.btn_plugins, self.btn_history, self.btn_multi]:
            b.setCheckable(True)
            side_layout.addWidget(b)

        side_layout.addStretch()

        # Main stacked panel
        self.stack = QtWidgets.QStackedWidget()
        root_layout.addWidget(self.sidebar)
        root_layout.addWidget(self.stack, 1)

        # Panels
        self.overview_panel = self._build_overview_panel()
        self.nodes_panel = self._build_nodes_panel()
        self.gpu_panel = self._build_gpu_panel()
        self.vram_panel = self._build_vram_panel()
        self.queen_panel = self._build_queen_panel()
        self.zmq_panel = self._build_zmq_panel()
        self.plugins_panel = self._build_plugins_panel()
        self.history_panel = self._build_history_panel()
        self.multi_panel = self._build_multi_panel()

        self.stack.addWidget(self.overview_panel)  # 0
        self.stack.addWidget(self.nodes_panel)     # 1
        self.stack.addWidget(self.gpu_panel)       # 2
        self.stack.addWidget(self.vram_panel)      # 3
        self.stack.addWidget(self.queen_panel)     # 4
        self.stack.addWidget(self.zmq_panel)       # 5
        self.stack.addWidget(self.plugins_panel)   # 6
        self.stack.addWidget(self.history_panel)   # 7
        self.stack.addWidget(self.multi_panel)     # 8

        # Connect navigation
        self.btn_overview.clicked.connect(lambda: self._set_panel(0, self.btn_overview))
        self.btn_nodes.clicked.connect(lambda: self._set_panel(1, self.btn_nodes))
        self.btn_gpu.clicked.connect(lambda: self._set_panel(2, self.btn_gpu))
        self.btn_vram.clicked.connect(lambda: self._set_panel(3, self.btn_vram))
        self.btn_queen.clicked.connect(lambda: self._set_panel(4, self.btn_queen))
        self.btn_zmq.clicked.connect(lambda: self._set_panel(5, self.btn_zmq))
        self.btn_plugins.clicked.connect(lambda: self._set_panel(6, self.btn_plugins))
        self.btn_history.clicked.connect(lambda: self._set_panel(7, self.btn_history))
        self.btn_multi.clicked.connect(lambda: self._set_panel(8, self.btn_multi))

        self.btn_overview.setChecked(True)
        self.stack.setCurrentIndex(0)

        # Timer for refresh
        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.refresh_all)
        self.timer.start(500)

        # Chart buffers
        self.cpu_series = deque(maxlen=200)
        self.mem_series = deque(maxlen=200)
        self.disk_series = deque(maxlen=200)
        self.vram_frag_series = deque(maxlen=200)

    # ----------------- panel builders -----------------

    def _build_overview_panel(self):
        w = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.global_cpu_bar = QtWidgets.QProgressBar()
        self.global_cpu_bar.setRange(0, 100)
        self.global_mem_bar = QtWidgets.QProgressBar()
        self.global_mem_bar.setRange(0, 100)
        self.global_disk_bar = QtWidgets.QProgressBar()
        self.global_disk_bar.setRange(0, 100)

        layout.addWidget(QtWidgets.QLabel("Global CPU"))
        layout.addWidget(self.global_cpu_bar)
        layout.addWidget(QtWidgets.QLabel("Global Memory"))
        layout.addWidget(self.global_mem_bar)
        layout.addWidget(QtWidgets.QLabel("Global Disk"))
        layout.addWidget(self.global_disk_bar)

        self.overview_risk_label = QtWidgets.QLabel("Queen risk: -")
        self.overview_gpu_label = QtWidgets.QLabel("GPU governor: -")
        layout.addWidget(self.overview_risk_label)
        layout.addWidget(self.overview_gpu_label)

        if pg is not None:
            chart_group = QtWidgets.QGroupBox("Real-time Charts")
            chart_layout = QtWidgets.QHBoxLayout(chart_group)
            self.cpu_plot = pg.PlotWidget()
            self.mem_plot = pg.PlotWidget()
            self.disk_plot = pg.PlotWidget()
            self.cpu_curve = self.cpu_plot.plot(pen='y')
            self.mem_curve = self.mem_plot.plot(pen='g')
            self.disk_curve = self.disk_plot.plot(pen='c')
            chart_layout.addWidget(self.cpu_plot)
            chart_layout.addWidget(self.mem_plot)
            chart_layout.addWidget(self.disk_plot)
            layout.addWidget(chart_group)

        btn_row = QtWidgets.QHBoxLayout()
        self.btn_run_demo = QtWidgets.QPushButton("Run demo jobs (swarm-wide)")
        self.btn_run_demo.clicked.connect(self.run_demo_jobs_all)
        btn_row.addWidget(self.btn_run_demo)
        layout.addLayout(btn_row)

        layout.addStretch()
        return w

    def _build_nodes_panel(self):
        w = QtWidgets.QWidget()
        layout = QtWidgets.QGridLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        self.node_cards = []
        cols = 2
        for idx, node in enumerate(self.swarm.nodes):
            card = NodeCard(node)
            row = idx // cols
            col = idx % cols
            layout.addWidget(card, row, col)
            self.node_cards.append(card)

        return w

    def _build_gpu_panel(self):
        w = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.gpu_info_label = QtWidgets.QLabel("GPU devices:")
        self.gpu_list = QtWidgets.QTextEdit()
        self.gpu_list.setReadOnly(True)

        self.gpu_policy_label = QtWidgets.QLabel("GPU governor policy:")
        self.gpu_policy_text = QtWidgets.QTextEdit()
        self.gpu_policy_text.setReadOnly(True)

        layout.addWidget(self.gpu_info_label)
        layout.addWidget(self.gpu_list)
        layout.addWidget(self.gpu_policy_label)
        layout.addWidget(self.gpu_policy_text)
        layout.addStretch()
        return w

    def _build_vram_panel(self):
        w = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        bw_group = QtWidgets.QGroupBox("VRAM Bandwidth Test")
        bw_layout = QtWidgets.QHBoxLayout(bw_group)
        self.vram_bw_size = QtWidgets.QSpinBox()
        self.vram_bw_size.setRange(64, 4096)
        self.vram_bw_size.setValue(CONFIG["gpu_vram_stress_size_mb"])
        self.vram_bw_btn = QtWidgets.QPushButton("Run bandwidth test")
        self.vram_bw_btn.clicked.connect(self.run_vram_bw_test)
        bw_layout.addWidget(QtWidgets.QLabel("Size (MB):"))
        bw_layout.addWidget(self.vram_bw_size)
        bw_layout.addWidget(self.vram_bw_btn)

        frag_group = QtWidgets.QGroupBox("VRAM Fragmentation Test")
        frag_layout = QtWidgets.QHBoxLayout(frag_group)
        self.vram_frag_chunks = QtWidgets.QSpinBox()
        self.vram_frag_chunks.setRange(8, 1024)
        self.vram_frag_chunks.setValue(CONFIG["gpu_vram_frag_chunks"])
        self.vram_frag_btn = QtWidgets.QPushButton("Run fragmentation test")
        self.vram_frag_btn.clicked.connect(self.run_vram_frag_test)
        frag_layout.addWidget(QtWidgets.QLabel("Chunks:"))
        frag_layout.addWidget(self.vram_frag_chunks)
        frag_layout.addWidget(self.vram_frag_btn)

        self.vram_result = QtWidgets.QTextEdit()
        self.vram_result.setReadOnly(True)

        self.vram_frag_list = QtWidgets.QListWidget()

        if pg is not None:
            self.vram_plot = pg.PlotWidget()
            self.vram_curve = self.vram_plot.plot(pen='m')
            layout.addWidget(self.vram_plot)

        layout.addWidget(bw_group)
        layout.addWidget(frag_group)
        layout.addWidget(QtWidgets.QLabel("Results:"))
        layout.addWidget(self.vram_result)
        layout.addWidget(QtWidgets.QLabel("VRAM fragmentation history (chunks vs total_sec):"))
        layout.addWidget(self.vram_frag_list)
        layout.addStretch()
        return w

    def _build_queen_panel(self):
        w = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.queen_risk_text = QtWidgets.QTextEdit()
        self.queen_risk_text.setReadOnly(True)

        self.btn_refresh_queen = QtWidgets.QPushButton("Refresh Queen risk")
        self.btn_refresh_queen.clicked.connect(self.refresh_queen_panel)

        layout.addWidget(QtWidgets.QLabel("Queen risk + anomalies"))
        layout.addWidget(self.queen_risk_text)
        layout.addWidget(self.btn_refresh_queen)
        layout.addStretch()
        return w

    def _build_zmq_panel(self):
        w = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.zmq_status_label = QtWidgets.QLabel("ZMQ status: idle")

        self.btn_zmq_server = QtWidgets.QPushButton("Start ZMQ server")
        self.btn_zmq_server.clicked.connect(self.start_zmq_server)

        self.btn_zmq_client_demo = QtWidgets.QPushButton("Send ZMQ demo jobs")
        self.btn_zmq_client_demo.clicked.connect(self.send_zmq_demo)

        layout.addWidget(self.zmq_status_label)
        layout.addWidget(self.btn_zmq_server)
        layout.addWidget(self.btn_zmq_client_demo)
        layout.addStretch()
        return w

    def _build_plugins_panel(self):
        w = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.plugins_list = QtWidgets.QListWidget()
        self.plugin_jobs_list = QtWidgets.QListWidget()
        self.btn_run_plugin_job = QtWidgets.QPushButton("Run selected plugin job")
        self.btn_run_plugin_job.clicked.connect(self.run_selected_plugin_job)

        layout.addWidget(QtWidgets.QLabel("Registered plugins (sandboxed)"))
        layout.addWidget(self.plugins_list)
        layout.addWidget(QtWidgets.QLabel("Plugin jobs (manual listing)"))
        layout.addWidget(self.plugin_jobs_list)
        layout.addWidget(self.btn_run_plugin_job)
        layout.addStretch()

        self.refresh_plugins_panel()
        return w

    def _build_history_panel(self):
        w = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.history_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Recent job history (from SQLite)"))
        layout.addWidget(self.history_list)

        layout.addStretch()
        return w

    def _build_multi_panel(self):
        w = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(w)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(8)

        self.multi_status = QtWidgets.QLabel("Multi-host: listening on "
                                             f"{CONFIG['multi_host_listen_host']}:{CONFIG['multi_host_listen_port']}")
        self.multi_peer_input = QtWidgets.QLineEdit()
        self.multi_peer_input.setPlaceholderText("peer_host:port")
        self.multi_send_btn = QtWidgets.QPushButton("Send demo job to peer")
        self.multi_send_btn.clicked.connect(self.send_multi_demo)

        layout.addWidget(self.multi_status)
        layout.addWidget(QtWidgets.QLabel("Peer address"))
        layout.addWidget(self.multi_peer_input)
        layout.addWidget(self.multi_send_btn)
        layout.addStretch()
        return w

    # ----------------- navigation -----------------

    def _set_panel(self, index, btn):
        for b in [self.btn_overview, self.btn_nodes, self.btn_gpu,
                  self.btn_vram, self.btn_queen, self.btn_zmq,
                  self.btn_plugins, self.btn_history, self.btn_multi]:
            b.setChecked(False)
        btn.setChecked(True)
        self.stack.setCurrentIndex(index)

    # ----------------- actions -----------------

    def run_demo_jobs_all(self):
        self.swarm.submit_cpu(demo_cpu_job, 1_000_000, priority=1, name="demo_cpu")
        self.swarm.submit_io(demo_io_job, 0.2, priority=1, name="demo_io")
        self.swarm.submit_gpu(demo_gpu_job, 512, priority=1, name="demo_gpu")
        self.swarm.submit_live(name="live", priority=1)
        self.swarm.submit_vram_bandwidth(priority=1)
        self.swarm.submit_vram_fragmentation(priority=1)

    def run_vram_bw_test(self):
        size_mb = self.vram_bw_size.value()
        self.swarm.submit_vram_bandwidth(size_mb=size_mb, priority=1, name="gui_vram_bw")
        self.vram_result.append(f"[VRAM BW] Submitted test size={size_mb} MB")

    def run_vram_frag_test(self):
        chunks = self.vram_frag_chunks.value()
        self.swarm.submit_vram_fragmentation(chunks=chunks, priority=1, name="gui_vram_frag")
        self.vram_result.append(f"[VRAM FRAG] Submitted test chunks={chunks}")

    def refresh_queen_panel(self):
        gr = self.queen.global_risk()
        risk = gr.get("risk", {})
        anomalies = gr.get("anomalies", {})
        text = "Risk:\n"
        for k, v in risk.items():
            text += f"  {k}: {v:.3f}\n"
        text += "\nAnomalies:\n"
        for k, a in anomalies.items():
            text += f"  {k}: z={a['zscore']:.2f}, last={a['last']:.3f}, mean={a['mean']:.3f}\n"
        self.queen_risk_text.setPlainText(text)

    def start_zmq_server(self):
        if self.zmq_swarm is None:
            QtWidgets.QMessageBox.warning(self, "ZMQ", "pyzmq not available.")
            return
        self.zmq_swarm.start_server()
        self.zmq_status_label.setText("ZMQ status: server running")

    def send_zmq_demo(self):
        if self.zmq_swarm is None:
            QtWidgets.QMessageBox.warning(self, "ZMQ", "pyzmq not available.")
            return
        self.zmq_swarm.start_client()
        self.zmq_swarm.send_job("cpu", 1_000_000)
        self.zmq_swarm.send_job("gpu", 512)
        self.zmq_swarm.send_job("vram_bw", 256)
        self.zmq_swarm.send_job("vram_frag", 32)
        self.zmq_status_label.setText("ZMQ status: client demo sent")

    def refresh_plugins_panel(self):
        self.plugins_list.clear()
        self.plugin_jobs_list.clear()
        if not self.plugin_manager:
            self.plugins_list.addItem("(no plugin manager)")
            return
        for name, path in self.plugin_manager.plugins.items():
            self.plugins_list.addItem(name)
        # Jobs listing is manual; user can type job names or extend this.

    def run_selected_plugin_job(self):
        plugin_item = self.plugins_list.currentItem()
        job_item = self.plugin_jobs_list.currentItem()
        if not plugin_item or not job_item:
            QtWidgets.QMessageBox.warning(self, "Plugins", "Select plugin and job.")
            return
        plugin_name = plugin_item.text()
        job_name = job_item.text()
        self.swarm.submit_plugin(plugin_name, job_name, priority=1, name=f"plugin_{job_name}")
        QtWidgets.QMessageBox.information(self, "Plugins", f"Submitted {job_name} from {plugin_name}")

    def send_multi_demo(self):
        peer = self.multi_peer_input.text().strip()
        if not peer:
            QtWidgets.QMessageBox.warning(self, "Multi-Host", "Enter peer host:port.")
            return
        if self.multi_host is None:
            QtWidgets.QMessageBox.warning(self, "Multi-Host", "Multi-host not available.")
            return
        resp = self.multi_host.send_job_to_peer(peer, TaskType.CPU, 500_000)
        QtWidgets.QMessageBox.information(self, "Multi-Host", f"Peer response: {resp}")

    # ----------------- refresh loop -----------------

    def refresh_all(self):
        # Overview global metrics
        cpu_vals = []
        mem_vals = []
        disk_vals = []
        for node in self.swarm.nodes:
            load = node.get_live_load()
            cpu_vals.append(load["cpu_percent"])
            mem_vals.append(load["memory_percent"])
            disk_vals.append(load["disk_percent"])
        if cpu_vals:
            cpu_avg = sum(cpu_vals) / len(cpu_vals)
            self.global_cpu_bar.setValue(int(cpu_avg))
            self.cpu_series.append(cpu_avg)
        if mem_vals:
            mem_avg = sum(mem_vals) / len(mem_vals)
            self.global_mem_bar.setValue(int(mem_avg))
            self.mem_series.append(mem_avg)
        if disk_vals:
            disk_avg = sum(disk_vals) / len(disk_vals)
            self.global_disk_bar.setValue(int(disk_avg))
            self.disk_series.append(disk_avg)

        gr = self.queen.global_risk()
        risk = gr.get("risk", {})
        anomalies = gr.get("anomalies", {})
        self.overview_risk_label.setText(
            f"Queen risk entities={len(risk)}, anomalies={len(anomalies)}"
        )

        if self.gpu_governor:
            pol = self.gpu_governor.snapshot_policy()
            txt = ""
            for idx, p in pol.items():
                txt += f"[GPU{idx} {p['name']} util={p['util']:.1f}% temp={p['temp']:.1f}C "
                if p["suggest_reduce_load"]:
                    txt += "↓load "
                if p["suggest_increase_load"]:
                    txt += "↑load "
                if p["suggest_vram_relief"]:
                    txt += "VRAM-relief "
                txt += "]\n"
            self.overview_gpu_label.setText("GPU governor: active")
            self.gpu_policy_text.setPlainText(txt)
        else:
            self.overview_gpu_label.setText("GPU governor: disabled")
            self.gpu_policy_text.setPlainText("")

        # Node cards
        for card in self.node_cards:
            card.refresh()

        # GPU panel telemetry
        if self.gpu_governor and self.gpu_governor.telemetry:
            snap = self.gpu_governor.telemetry.snapshot()
            txt = f"GPU count: {snap.get('gpu_count', 0)}\n"
            for dev in snap.get("devices", []):
                txt += (f"GPU{dev['index']} {dev['name']} "
                        f"util={dev['gpu_util']:.1f}% temp={dev['temp_c']:.1f}C "
                        f"VRAM={dev['mem_used_mb']:.1f}/{dev['mem_total_mb']:.1f} MB\n")
            self.gpu_list.setPlainText(txt)
        else:
            self.gpu_list.setPlainText("No GPU telemetry available.")

        # VRAM fragmentation visualizer
        self.vram_frag_list.clear()
        hist = self.memory.get_vram_frag_history()
        self.vram_frag_series.clear()
        for entry in hist:
            ts = time.strftime("%H:%M:%S", time.localtime(entry["timestamp"]))
            self.vram_frag_list.addItem(
                f"{ts} chunks={entry['chunks']} total_sec={entry['total_sec']:.3f} "
                f"alloc={entry['alloc_sec']:.3f} free={entry['free_sec']:.3f}"
            )
            self.vram_frag_series.append(entry["total_sec"])

        # Charts update
        if pg is not None:
            x = list(range(len(self.cpu_series)))
            self.cpu_curve.setData(x, list(self.cpu_series))
            x = list(range(len(self.mem_series)))
            self.mem_curve.setData(x, list(self.mem_series))
            x = list(range(len(self.disk_series)))
            self.disk_curve.setData(x, list(self.disk_series))
            x = list(range(len(self.vram_frag_series)))
            if hasattr(self, "vram_curve"):
                self.vram_curve.setData(x, list(self.vram_frag_series))

        # Job history panel
        self.history_list.clear()
        jobs = self.job_history.recent(50)
        for j in jobs:
            ts = time.strftime("%H:%M:%S", time.localtime(j["timestamp"]))
            self.history_list.addItem(
                f"{ts} node={j['node_id']} type={j['task_type']} name={j['name']} "
                f"status={j['status']} dur={j['duration']:.3f}"
            )

# ---------------------------------------------------------------------------
# Build + main
# ---------------------------------------------------------------------------

def build_local_swarm():
    memory = MemoryManager(CONFIG["state_file"])
    memory.apply_config_overrides()

    job_history = JobHistory(CONFIG["job_history_db"])
    queen = Queen(memory=memory)
    gpu_telemetry = GPUTelemetry()
    gpu_governor = GPUGovernor(gpu_telemetry, memory=memory) if gpu_telemetry.available else None
    plugin_manager = PluginManager(CONFIG["plugins_dir"])

    nodes = []
    for i in range(CONFIG["local_nodes"]):
        node = BeastNode(
            node_id=f"node{i}",
            max_io_workers=CONFIG["io_worker_max"],
            max_cpu_workers=CONFIG["cpu_worker_max"],
            enable_gpu=CONFIG["enable_gpu"],
            enable_npu=CONFIG["enable_npu"],
            metrics_window=CONFIG["metrics_window"],
            predictive_alpha=CONFIG["predictive_alpha"],
            queen=queen,
            plugin_manager=plugin_manager,
            gpu_telemetry=gpu_telemetry,
            gpu_governor=gpu_governor,
            memory=memory,
            job_history=job_history,
        )
        nodes.append(node)

    scheduler = GlobalScheduler(nodes, memory)
    swarm = BeastSwarm(nodes, scheduler)
    tuner = SwarmTuner(nodes)
    auto_spawner = AutoSpawner(nodes, queen, memory, gpu_telemetry, gpu_governor,
                               plugin_manager, scheduler, job_history)
    zmq_swarm = ZMQSwarm(swarm, CONFIG["zmq_bind"]) if zmq is not None else None
    rest_api = SwarmREST(swarm, queen, memory, job_history) if Flask is not None else None
    multi_host = MultiHostSwarm(swarm)

    return swarm, queen, gpu_governor, tuner, zmq_swarm, memory, plugin_manager, auto_spawner, scheduler, rest_api, job_history, multi_host


def main():
    swarm, queen, gpu_governor, tuner, zmq_swarm, memory, plugin_manager, auto_spawner, scheduler, rest_api, job_history, multi_host = build_local_swarm()

    if QtWidgets is None:
        print("[GUI] PyQt6 not available, running headless.")
        swarm.submit_cpu(demo_cpu_job, 1_000_000, priority=1, name="demo_cpu")
        swarm.submit_io(demo_io_job, 0.2, priority=1, name="demo_io")
        swarm.submit_gpu(demo_gpu_job, 512, priority=1, name="demo_gpu")
        swarm.submit_live(name="live", priority=1)
        swarm.submit_vram_bandwidth(priority=1)
        swarm.submit_vram_fragmentation(priority=1)

        try:
            for _ in range(10):
                time.sleep(1.0)
                gr = queen.global_risk()
                print("[HEADLESS] Queen risk:", gr)
        finally:
            tuner.stop()
            auto_spawner.stop()
            swarm.shutdown()
            if gpu_governor:
                gpu_governor.stop()
            if zmq_swarm:
                zmq_swarm.stop()
            if multi_host:
                multi_host.stop()
            memory.save(force=True)
        return

    app = QtWidgets.QApplication(sys.argv)
    gui = SwarmGUI(swarm, queen, gpu_governor, zmq_swarm, plugin_manager, memory, job_history, multi_host)
    gui.show()

    swarm.submit_cpu(demo_cpu_job, 1_000_000, priority=1, name="demo_cpu")
    swarm.submit_io(demo_io_job, 0.2, priority=1, name="demo_io")
    swarm.submit_gpu(demo_gpu_job, 512, priority=1, name="demo_gpu")
    swarm.submit_live(name="live", priority=1)
    swarm.submit_vram_bandwidth(priority=1)
    swarm.submit_vram_fragmentation(priority=1)

    ret = app.exec()

    tuner.stop()
    auto_spawner.stop()
    swarm.shutdown()
    if gpu_governor:
        gpu_governor.stop()
    if zmq_swarm:
        zmq_swarm.stop()
    if multi_host:
        multi_host.stop()
    memory.save(force=True)

    sys.exit(ret)


if __name__ == "__main__":
    main()
