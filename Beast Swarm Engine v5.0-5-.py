#!/usr/bin/env python3
"""
Beast Swarm Engine v8.1

- Multi-core + GPU + NPU job system
- Local swarm (nodes) with predictive tuner
- PyQt6 desktop GUI dashboard (green light, workload bars)
- Auto-start demo jobs and tuner (no button required)
- Plugin system for custom jobs
- Queen consensus engine (global risk aggregation)
- Queen risk decay + anomaly detection
- Live data jobs (no flow-state simulation; uses real system metrics)
- Fault tolerance (health, retry, guarded demo jobs)
- ZMQ swarm OFF by default (manual start from GUI)
- ZMQ "port stacking": first process binds (server), others connect (client)
- ZMQ client can submit jobs to server (cpu/io/gpu/npu/async/live/plugin/vram)
- Persistent memory across reboots (swarm_state.json) with throttled saves
- VRAM compute modules (bandwidth, allocation, fragmentation stress)
- GPU governor hooks (telemetry + soft policy decisions)
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
}

# ---------------------------------------------------------------------------
# Autoloader
# ---------------------------------------------------------------------------

def autoload_libraries(libs):
    # pip distribution name -> Python import name
    import_names = {
        "pyqt6": "PyQt6",
        "pyzmq": "zmq",
        "nvidia-ml-py": "pynvml",
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
    LIVE = "live"      # live data jobs (system metrics)
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
        _, _, task = self._q.get(block=block, timeout=timeout)
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

        # risk_state: entity -> {score, last_update, history}
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
    """Return current process CPU usage and process thread count."""
    if psutil is None:
        return 0.0, 0
    try:
        p = psutil.Process(os.getpid())
        return float(p.cpu_percent(interval=None)), int(p.num_threads())
    except Exception:
        return 0.0, 0


class LiveTelemetry:
    """Non-blocking live telemetry sampler.

    The GUI reads this object directly, so displayed workload percentages come
    from the operating system rather than queue-size estimates.
    """
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
        # Prime psutil's non-blocking CPU counters.
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
                name = pynvml.nvmlDeviceGetName(h).decode("utf-8", errors="ignore")
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
    """
    Soft GPU governor: reads telemetry, computes policy signals.
    Does NOT directly change clocks or fans; instead exposes hints.
    """
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
    """
    Allocate a tensor on GPU and perform a simple bandwidth test.
    """
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
    """
    Allocate and free many small tensors to stress VRAM fragmentation.
    """
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
# Plugin system
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
            spec = importlib.util.spec_from_file_location(mod_name, path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(module)
                    self.plugins[mod_name] = module
                    print(f"[PLUGIN] Loaded {mod_name} from {fname}")
                except Exception as e:
                    print(f"[PLUGIN] Failed to load {fname}: {e}")

    def get_job(self, plugin_name, job_name):
        module = self.plugins.get(plugin_name)
        if not module:
            return None
        return getattr(module, job_name, None)

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
                 gpu_governor: GPUGovernor = None):
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

    # ----------------- affinity -----------------

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

    # ----------------- device detection -----------------

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

    # ----------------- async loop -----------------

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
        except Exception as e:
            print(f"[{self.node_id}][ASYNC][{task.name}] Error: {e}")
        finally:
            duration = time.time() - start
            self.metrics.record_task(TaskType.ASYNC, duration)

    # ----------------- submit APIs -----------------

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
        func = self.plugin_manager.get_job(plugin_name, job_name)
        if not func:
            print(f"[{self.node_id}][PLUGIN] Job {job_name} not found in {plugin_name}.")
            return
        task = Task(func, args, kwargs, task_type=TaskType.PLUGIN, priority=priority, name=name or job_name)
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

    # ----------------- worker loops -----------------

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

    # ----------------- core runner with retry + Queen events -----------------

    def _run_task(self, task: Task):
        start = time.time()
        events = []
        try:
            result = task.func(*task.args, **task.kwargs)
            # GPU governor hint: if VRAM job reports high bandwidth or stress, we can emit events
            if task.task_type == TaskType.VRAM and isinstance(result, dict):
                if "bandwidth_gb_s" in result:
                    bw = result["bandwidth_gb_s"]
                    events.append({"entity": "vram_bandwidth", "score": bw})
                if "chunks" in result:
                    events.append({"entity": "vram_frag_chunks", "score": float(result["chunks"])})
            return result
        except Exception as e:
            print(f"[{self.node_id}][TASK][{task.task_type}][{task.name}] Error: {e}")
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

    # ----------------- metrics -----------------

    def approx_load(self):
        return (
            self.io_queue.qsize()
            + self.cpu_queue.qsize()
            + self.gpu_queue.qsize()
            + self.npu_queue.qsize()
            + self.live_queue.qsize()
            + self.plugin_queue.qsize()
            + self.vram_queue.qsize()
        )

    def get_metrics_snapshot(self):
        return self.metrics.snapshot()

    def get_live_load(self):
        """Return OS-measured CPU/thread utilization for this node."""
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

    # ----------------- dynamic worker tuning -----------------

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

    # ----------------- health monitoring -----------------

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

    # ----------------- shutdown -----------------

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
# Live data job (no flow-state simulation)
# ---------------------------------------------------------------------------

def live_data_job(name="live"):
    """
    Uses real system metrics (CPU, memory, disk) instead of synthetic flow simulation.
    """
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
# Swarm + tuner
# ---------------------------------------------------------------------------

class BeastSwarm:
    def __init__(self, nodes):
        self.nodes = nodes

    def _best_node(self):
        healthy = [n for n in self.nodes if n.health_ok]
        if not healthy:
            healthy = self.nodes
        return min(healthy, key=lambda n: n.approx_load())

    def submit_cpu(self, func, *args, **kwargs):
        node = self._best_node()
        node.submit_cpu(func, *args, **kwargs)

    def submit_io(self, func, *args, **kwargs):
        node = self._best_node()
        node.submit_io(func, *args, **kwargs)

    def submit_gpu(self, func, *args, **kwargs):
        node = self._best_node()
        node.submit_gpu(func, *args, **kwargs)

    def submit_npu(self, func, *args, **kwargs):
        node = self._best_node()
        node.submit_npu(func, *args, **kwargs)

    def submit_live(self, *args, **kwargs):
        node = self._best_node()
        node.submit_live(*args, **kwargs)

    def submit_plugin(self, *args, **kwargs):
        node = self._best_node()
        node.submit_plugin(*args, **kwargs)

    def submit_vram_bandwidth(self, *args, **kwargs):
        node = self._best_node()
        node.submit_vram_bandwidth(*args, **kwargs)

    def submit_vram_fragmentation(self, *args, **kwargs):
        node = self._best_node()
        node.submit_vram_fragmentation(*args, **kwargs)

    def shutdown(self):
        for n in self.nodes:
            n.shutdown()


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
            job = msg.get("job")
            args = msg.get("args", [])
            kwargs = msg.get("kwargs", {})
            jtype = msg.get("type", "cpu")
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
            elif jtype == "plugin":
                self.swarm.submit_plugin(*args, **kwargs)
            elif jtype == "vram_bw":
                self.swarm.submit_vram_bandwidth(*args, **kwargs)
            elif jtype == "vram_frag":
                self.swarm.submit_vram_fragmentation(*args, **kwargs)
            self.socket.send_json({"status": "ok"})

    def send_job(self, jtype, job, *args, **kwargs):
        if self.socket is None or self.is_server:
            print("[ZMQ] Client not started.")
            return
        payload = {
            "type": jtype,
            "job": job,
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
# GUI
# ---------------------------------------------------------------------------

class SwarmGUI(QtWidgets.QMainWindow):
    def __init__(self, swarm: BeastSwarm, queen: Queen, gpu_governor: GPUGovernor, zmq_swarm: ZMQSwarm):
        super().__init__()
        self.swarm = swarm
        self.queen = queen
        self.gpu_governor = gpu_governor
        self.zmq_swarm = zmq_swarm

        self.setWindowTitle("Beast Swarm Engine v8.1")
        self.resize(900, 600)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)

        self.global_cpu_bar = QtWidgets.QProgressBar()
        self.global_cpu_bar.setRange(0, 100)
        layout.addWidget(QtWidgets.QLabel("Global CPU"))
        layout.addWidget(self.global_cpu_bar)

        self.node_bars = []
        for i, node in enumerate(self.swarm.nodes):
            lbl = QtWidgets.QLabel(f"Node {node.node_id}")
            bar = QtWidgets.QProgressBar()
            bar.setRange(0, 100)
            layout.addWidget(lbl)
            layout.addWidget(bar)
            self.node_bars.append(bar)

        self.risk_label = QtWidgets.QLabel("Queen risk: (decayed + anomalies)")
        layout.addWidget(self.risk_label)

        self.gpu_policy_label = QtWidgets.QLabel("GPU governor policy")
        layout.addWidget(self.gpu_policy_label)

        btn_row = QtWidgets.QHBoxLayout()
        layout.addLayout(btn_row)

        self.btn_demo = QtWidgets.QPushButton("Run demo jobs")
        self.btn_demo.clicked.connect(self.run_demo_jobs)
        btn_row.addWidget(self.btn_demo)

        self.btn_risk = QtWidgets.QPushButton("Show Queen risk")
        self.btn_risk.clicked.connect(self.show_risk)
        btn_row.addWidget(self.btn_risk)

        self.btn_zmq_server = QtWidgets.QPushButton("Start ZMQ server")
        self.btn_zmq_server.clicked.connect(self.start_zmq_server)
        btn_row.addWidget(self.btn_zmq_server)

        self.btn_zmq_client_demo = QtWidgets.QPushButton("Send ZMQ demo jobs")
        self.btn_zmq_client_demo.clicked.connect(self.send_zmq_demo)
        btn_row.addWidget(self.btn_zmq_client_demo)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.refresh)
        self.timer.start(500)

    def run_demo_jobs(self):
        for node in self.swarm.nodes:
            node.submit_cpu(demo_cpu_job, priority=1, name="demo_cpu")
            node.submit_io(demo_io_job, priority=1, name="demo_io")
            node.submit_gpu(demo_gpu_job, priority=1, name="demo_gpu")
            node.submit_live(name="live", priority=1)
            node.submit_vram_bandwidth(priority=1)
            node.submit_vram_fragmentation(priority=1)

    def show_risk(self):
        gr = self.queen.global_risk()
        risk = gr.get("risk", {})
        anomalies = gr.get("anomalies", {})
        text = "Risk:\n"
        for k, v in risk.items():
            text += f"  {k}: {v:.3f}\n"
        text += "Anomalies:\n"
        for k, a in anomalies.items():
            text += f"  {k}: z={a['zscore']:.2f}, last={a['last']:.3f}, mean={a['mean']:.3f}\n"
        QtWidgets.QMessageBox.information(self, "Queen Risk", text)

    def start_zmq_server(self):
        if zmq is None:
            QtWidgets.QMessageBox.warning(self, "ZMQ", "pyzmq not available.")
            return
        self.zmq_swarm.start_server()

    def send_zmq_demo(self):
        if zmq is None:
            QtWidgets.QMessageBox.warning(self, "ZMQ", "pyzmq not available.")
            return
        self.zmq_swarm.start_client()
        self.zmq_swarm.send_job("cpu", "demo_cpu_job", 1_000_000)
        self.zmq_swarm.send_job("gpu", "demo_gpu_job", 512)
        self.zmq_swarm.send_job("vram_bw", "vram_bandwidth_job", 256)
        self.zmq_swarm.send_job("vram_frag", "vram_fragmentation_stress_job", 32)

    def refresh(self):
        # Global CPU
        cpu_vals = []
        for node in self.swarm.nodes:
            load = node.get_live_load()
            cpu_vals.append(load["cpu_percent"])
        if cpu_vals:
            self.global_cpu_bar.setValue(int(sum(cpu_vals) / len(cpu_vals)))

        # Node bars
        for i, node in enumerate(self.swarm.nodes):
            load = node.get_live_load()
            val = int(load["cpu_percent"])
            self.node_bars[i].setValue(val)

        # Queen risk summary
        gr = self.queen.global_risk()
        risk = gr.get("risk", {})
        anomalies = gr.get("anomalies", {})
        self.risk_label.setText(
            f"Queen risk entities={len(risk)}, anomalies={len(anomalies)}"
        )

        # GPU governor policy
        if self.gpu_governor:
            pol = self.gpu_governor.snapshot_policy()
            txt = "GPU policy: "
            for idx, p in pol.items():
                txt += f"[{idx} {p['name']} util={p['util']:.1f}% temp={p['temp']:.1f}C "
                if p["suggest_reduce_load"]:
                    txt += "↓load "
                if p["suggest_increase_load"]:
                    txt += "↑load "
                if p["suggest_vram_relief"]:
                    txt += "VRAM-relief "
                txt += "] "
            self.gpu_policy_label.setText(txt)
        else:
            self.gpu_policy_label.setText("GPU governor policy: (disabled)")

# ---------------------------------------------------------------------------
# Build + main
# ---------------------------------------------------------------------------

def build_local_swarm():
    memory = MemoryManager(CONFIG["state_file"])
    memory.apply_config_overrides()

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
        )
        nodes.append(node)

    swarm = BeastSwarm(nodes)
    tuner = SwarmTuner(nodes)
    zmq_swarm = ZMQSwarm(swarm, CONFIG["zmq_bind"]) if zmq is not None else None

    return swarm, queen, gpu_governor, tuner, zmq_swarm, memory


def main():
    swarm, queen, gpu_governor, tuner, zmq_swarm, memory = build_local_swarm()

    if QtWidgets is None:
        print("[GUI] PyQt6 not available, running headless.")
        # Headless demo: run some jobs and print risk periodically
        for node in swarm.nodes:
            node.submit_cpu(demo_cpu_job, priority=1, name="demo_cpu")
            node.submit_io(demo_io_job, priority=1, name="demo_io")
            node.submit_gpu(demo_gpu_job, priority=1, name="demo_gpu")
            node.submit_live(name="live", priority=1)
            node.submit_vram_bandwidth(priority=1)
            node.submit_vram_fragmentation(priority=1)

        try:
            for _ in range(10):
                time.sleep(1.0)
                gr = queen.global_risk()
                print("[HEADLESS] Queen risk:", gr)
        finally:
            tuner.stop()
            swarm.shutdown()
            if gpu_governor:
                gpu_governor.stop()
            memory.save(force=True)
        return

    app = QtWidgets.QApplication(sys.argv)
    gui = SwarmGUI(swarm, queen, gpu_governor, zmq_swarm)
    gui.show()

    # Auto-start demo jobs and tuner already running
    for node in swarm.nodes:
        node.submit_cpu(demo_cpu_job, priority=1, name="demo_cpu")
        node.submit_io(demo_io_job, priority=1, name="demo_io")
        node.submit_gpu(demo_gpu_job, priority=1, name="demo_gpu")
        node.submit_live(name="live", priority=1)
        node.submit_vram_bandwidth(priority=1)
        node.submit_vram_fragmentation(priority=1)

    ret = app.exec()

    tuner.stop()
    swarm.shutdown()
    if gpu_governor:
        gpu_governor.stop()
    if zmq_swarm:
        zmq_swarm.stop()
    memory.save(force=True)

    sys.exit(ret)


if __name__ == "__main__":
    main()
