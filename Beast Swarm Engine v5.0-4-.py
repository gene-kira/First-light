#!/usr/bin/env python3
"""
Beast Swarm Engine v8.0
- Multi-core + GPU + NPU job system
- Local swarm (nodes) with predictive tuner
- PyQt6 desktop GUI dashboard (green light, workload bars)
- Auto-start demo jobs and tuner (no button required)
- Plugin system for custom jobs
- Queen consensus engine (global risk aggregation)
- Live data jobs (no flow-state simulation; uses real system metrics)
- Fault tolerance (health, retry, guarded demo jobs)
- ZMQ swarm OFF by default (manual start from GUI)
- ZMQ "port stacking": first process binds (server), others connect (client)
- ZMQ client can submit jobs to server (cpu/io/gpu/npu/async/live/plugin)
- Persistent memory across reboots (swarm_state.json) with throttled saves
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
                importlib.import_module(lib)
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

# ---------------------------------------------------------------------------
# Persistent memory
# ---------------------------------------------------------------------------

class MemoryManager:
    def __init__(self, path):
        self.path = path
        self.state = {
            "queen_nodes": {},
            "config_overrides": {},
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

    def set_queue_sizes(self, io_q, cpu_q, gpu_q, npu_q, live_q, plugin_q):
        with self.lock:
            self.queue_sizes["io"] = io_q
            self.queue_sizes["cpu"] = cpu_q
            self.queue_sizes["gpu"] = gpu_q
            self.queue_sizes["npu"] = npu_q
            self.queue_sizes["live"] = live_q
            self.queue_sizes["plugin"] = plugin_q

    def snapshot(self):
        with self.lock:
            durations = {k: list(v) for k, v in self.task_durations.items()}
            queues = dict(self.queue_sizes)
            preds = dict(self.predicted_duration)
        return durations, queues, preds

# ---------------------------------------------------------------------------
# Queen consensus engine
# ---------------------------------------------------------------------------

class Queen:
    def __init__(self, memory: MemoryManager = None):
        self.nodes = {}
        self.lock = threading.Lock()
        self.memory = memory
        if self.memory and self.memory.state.get("queen_nodes"):
            self.nodes = self.memory.state["queen_nodes"]
            print("[QUEEN] Restored nodes from memory.")

    def update(self, node_id, events):
        with self.lock:
            self.nodes[node_id] = events
        if self.memory:
            self.memory.update_queen_nodes(self.nodes)

    def global_risk(self):
        risk = {}
        with self.lock:
            for node, evts in self.nodes.items():
                for e in evts:
                    risk[e["entity"]] = risk.get(e["entity"], 0) + e["score"]
        return {k: v for k, v in risk.items() if v > 1.5}


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
                 plugin_manager: PluginManager = None):
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

        self._stop_event = threading.Event()

        self.metrics = NodeMetrics(window=metrics_window, alpha=predictive_alpha)
        self.telemetry = LiveTelemetry(interval=0.5)
        self.queen = queen
        self.plugin_manager = plugin_manager

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

        self._io_worker.start()
        self._cpu_worker.start()
        self._gpu_worker.start()
        self._npu_worker.start()
        self._live_worker.start()
        self._plugin_worker.start()

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

    # ----------------- worker loops -----------------

    def _update_queues_metrics(self):
        self.metrics.set_queue_sizes(
            self.io_queue.qsize(),
            self.cpu_queue.qsize(),
            self.gpu_queue.qsize(),
            self.npu_queue.qsize(),
            self.live_queue.qsize(),
            self.plugin_queue.qsize(),
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

    # ----------------- core runner with retry + Queen events -----------------

    def _run_task(self, task: Task):
        start = time.time()
        events = []
        try:
            result = task.func(*task.args, **task.kwargs)
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
        self.io_executor.shutdown(wait=wait)
        self.cpu_executor.shutdown(wait=wait)
        try:
            self._async_loop.call_soon_threadsafe(self._async_loop.stop)
        except Exception:
            pass

# ---------------------------------------------------------------------------
# Swarm Controller
# ---------------------------------------------------------------------------

class BeastSwarm:
    def __init__(self, nodes, queen: Queen):
        self.nodes = nodes
        self._rr_counter = count()
        self.queen = queen

    def _next_node_rr(self):
        idx = next(self._rr_counter) % len(self.nodes)
        return self.nodes[idx]

    def _best_node_load(self):
        return min(self.nodes, key=lambda n: n.approx_load())

    def _best_node_health(self):
        healthy_nodes = [n for n in self.nodes if n.health_ok]
        if healthy_nodes:
            return min(healthy_nodes, key=lambda n: n.approx_load())
        return self._best_node_load()

    def submit_cpu(self, func, *args, priority=0, name=None, strategy="load", **kwargs):
        node = self._best_node_health() if strategy == "load" else self._next_node_rr()
        node.submit_cpu(func, *args, priority=priority, name=name, **kwargs)

    def submit_io(self, func, *args, priority=0, name=None, strategy="rr", **kwargs):
        node = self._next_node_rr() if strategy == "rr" else self._best_node_health()
        node.submit_io(func, *args, priority=priority, name=name, **kwargs)

    def submit_gpu(self, func, *args, priority=0, name=None, strategy="load", **kwargs):
        node = self._best_node_health() if strategy == "load" else self._next_node_rr()
        node.submit_gpu(func, *args, priority=priority, name=name, **kwargs)

    def submit_npu(self, func, *args, priority=0, name=None, strategy="load", **kwargs):
        node = self._best_node_health() if strategy == "load" else self._next_node_rr()
        node.submit_npu(func, *args, priority=priority, name=name, **kwargs)

    def submit_async(self, coro_factory, priority=0, name=None, strategy="rr"):
        node = self._next_node_rr() if strategy == "rr" else self._best_node_health()
        node.submit_async(coro_factory, priority=priority, name=name)

    def submit_live(self, name="live", priority=0, strategy="load"):
        node = self._best_node_health() if strategy == "load" else self._next_node_rr()
        node.submit_live(name=name, priority=priority)

    def submit_plugin(self, plugin_name, job_name, *args, priority=0, name=None, strategy="load", **kwargs):
        node = self._best_node_health() if strategy == "load" else self._next_node_rr()
        node.submit_plugin(plugin_name, job_name, *args, priority=priority, name=name, **kwargs)

    def shutdown(self):
        for n in self.nodes:
            n.shutdown()

    def total_load(self):
        """Backwards-compatible queue load."""
        return sum(n.approx_load() for n in self.nodes)

    def global_live_load(self):
        """Aggregate real OS CPU utilization across local nodes."""
        if not self.nodes:
            return {
                "cpu_percent": 0.0, "memory_percent": 0.0,
                "logical_threads": 0, "physical_cores": 0,
                "process_cpu_percent": 0.0, "process_threads": 0,
                "load_1m": 0.0, "load_5m": 0.0, "load_15m": 0.0,
                "per_core": []
            }
        samples = [n.get_live_load() for n in self.nodes]
        logical = sum(s["logical_threads"] for s in samples)
        physical = sum(s["physical_cores"] for s in samples)
        return {
            "cpu_percent": sum(s["cpu_percent"] for s in samples) / len(samples),
            "memory_percent": sum(s["memory_percent"] for s in samples) / len(samples),
            "logical_threads": logical,
            "physical_cores": physical,
            "process_cpu_percent": sum(s["process_cpu_percent"] for s in samples),
            "process_threads": sum(s["process_threads"] for s in samples),
            "load_1m": sum(s["load_1m"] for s in samples),
            "load_5m": sum(s["load_5m"] for s in samples),
            "load_15m": sum(s["load_15m"] for s in samples),
            "per_core": [x for s in samples for x in s["cpu_per_core"]],
        }

# ---------------------------------------------------------------------------
# Swarm Tuner
# ---------------------------------------------------------------------------

class SwarmTuner:
    def __init__(self, swarm: BeastSwarm, interval_sec: float = 2.0):
        self.swarm = swarm
        self.interval_sec = interval_sec
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="SwarmTuner")

    def start(self):
        if self._thread.is_alive():
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="SwarmTuner")
        self._thread.start()
        print("[TUNER] Started.")

    def stop(self):
        self._stop_event.set()
        print("[TUNER] Stopped.")

    def _loop(self):
        while not self._stop_event.is_set():
            time.sleep(self.interval_sec)
            for node in self.swarm.nodes:
                durations, queues, preds = node.get_metrics_snapshot()

                cpu_pred = preds.get(TaskType.CPU, 0.0)
                io_pred = preds.get(TaskType.IO, 0.0)
                cpu_q = queues["cpu"]
                io_q = queues["io"]

                if cpu_q > 0 and cpu_pred > 0.05:
                    node.set_cpu_workers(node.max_cpu_workers + 1)
                elif cpu_q == 0 and cpu_pred < 0.01 and node.max_cpu_workers > CONFIG["cpu_worker_min"]:
                    node.set_cpu_workers(node.max_cpu_workers - 1)

                if io_q > 0 and io_pred > 0.05:
                    node.set_io_workers(node.max_io_workers + 1)
                elif io_q == 0 and io_pred < 0.01 and node.max_io_workers > CONFIG["io_worker_min"]:
                    node.set_io_workers(node.max_io_workers - 1)

# ---------------------------------------------------------------------------
# ZMQ Swarm (manual start, port stacking, client jobs)
# ---------------------------------------------------------------------------

class ZMQSwarm:
    def __init__(self, swarm: BeastSwarm):
        self.swarm = swarm
        self.context = zmq.Context() if zmq else None
        self._stop_event = threading.Event()
        self._thread = None
        self.running = False
        self.mode = None  # "server" or "client"
        self.client_socket = None

    def start(self):
        if not self.context:
            print("[ZMQ] pyzmq not available.")
            return
        if self.running:
            print("[ZMQ] Already running.")
            return
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="ZMQSwarm")
        self._thread.start()
        self.running = True
        print("[ZMQ] Swarm started (manual).")

    def stop(self):
        if not self.running:
            return
        self._stop_event.set()
        self.running = False
        print("[ZMQ] Swarm stopped.")

    def _loop(self):
        try:
            socket = self.context.socket(zmq.REP)
            socket.bind(CONFIG["zmq_bind"])
            self.mode = "server"
            print(f"[ZMQ] Server bound to {CONFIG['zmq_bind']}")
        except Exception as e:
            print(f"[ZMQ] Bind failed (likely another server already running): {e}")
            socket = self.context.socket(zmq.REQ)
            socket.connect("tcp://localhost:6000")
            self.mode = "client"
            self.client_socket = socket
            print("[ZMQ] Client connected to tcp://localhost:6000")

        if self.mode == "server":
            self._server_loop(socket)
        else:
            self._client_loop(socket)

    def _server_loop(self, socket):
        while not self._stop_event.is_set():
            try:
                msg = socket.recv_json(flags=zmq.NOBLOCK)
            except zmq.Again:
                time.sleep(0.1)
                continue
            resp = self._handle_msg(msg)
            socket.send_json(resp)

    def _client_loop(self, socket):
        while not self._stop_event.is_set():
            try:
                socket.send_json({"type": "heartbeat", "name": "client"})
                _ = socket.recv_json()
                time.sleep(1.0)
            except Exception as e:
                print(f"[ZMQ][CLIENT] Error: {e}")
                time.sleep(2.0)

    def _handle_msg(self, msg):
        try:
            job_type = msg.get("type")
            if job_type == "heartbeat":
                return {"status": "ok", "detail": "alive"}

            name = msg.get("name", job_type)
            args = msg.get("args", [])
            kwargs = msg.get("kwargs", {})
            priority = msg.get("priority", 0)

            if job_type == "cpu":
                self.swarm.submit_cpu(heavy_cpu_job, *args, priority=priority, name=name, **kwargs)
            elif job_type == "io":
                self.swarm.submit_io(io_job, *args, priority=priority, name=name, **kwargs)
            elif job_type == "gpu":
                self.swarm.submit_gpu(gpu_job, *args, priority=priority, name=name, **kwargs)
            elif job_type == "npu":
                self.swarm.submit_npu(npu_job, *args, priority=priority, name=name, **kwargs)
            elif job_type == "async":
                self.swarm.submit_async(lambda: async_job(*args, **kwargs), priority=priority, name=name)
            elif job_type == "live":
                self.swarm.submit_live(name=name, priority=priority)
            elif job_type == "plugin":
                self.swarm.submit_plugin(msg.get("plugin"), msg.get("job"), *args, priority=priority, name=name, **kwargs)
            else:
                return {"status": "error", "detail": f"Unknown job type {job_type}"}
            return {"status": "ok"}
        except Exception as e:
            return {"status": "error", "detail": str(e)}

    def send_job(self, job_type, name=None, args=None, kwargs=None, priority=0, plugin=None, job=None):
        if self.mode != "client" or not self.client_socket:
            print("[ZMQ][CLIENT] Not in client mode or socket not ready.")
            return None
        msg = {
            "type": job_type,
            "name": name or job_type,
            "args": args or [],
            "kwargs": kwargs or {},
            "priority": priority,
        }
        if job_type == "plugin":
            msg["plugin"] = plugin
            msg["job"] = job
        try:
            self.client_socket.send_json(msg)
            resp = self.client_socket.recv_json()
            print(f"[ZMQ][CLIENT] Sent {job_type} job '{msg['name']}', resp={resp}")
            return resp
        except Exception as e:
            print(f"[ZMQ][CLIENT] send_job error: {e}")
            return None

# ---------------------------------------------------------------------------
# Example jobs
# ---------------------------------------------------------------------------

def heavy_cpu_job(n=500_000):
    total = 0
    for i in range(n):
        total += i * i
    return total

def io_job(name, duration=0.5):
    print(f"[IO] {name} start")
    time.sleep(duration)
    print(f"[IO] {name} done")

async def async_job(name, duration=0.5):
    print(f"[ASYNC] {name} start")
    await asyncio.sleep(duration)
    print(f"[ASYNC] {name} done")

def gpu_job(name):
    print(f"[GPU] {name} start")
    try:
        if torch is not None and torch.cuda.is_available():
            x = torch.randn(1024, 1024, device="cuda")
            y = torch.matmul(x, x)
            _ = y.mean().item()
        elif tf is not None:
            gpus = tf.config.list_physical_devices("GPU")
            if gpus:
                with tf.device("/GPU:0"):
                    x = tf.random.normal((1024, 1024))
                    y = tf.matmul(x, x)
                    _ = tf.reduce_mean(y).numpy()
            else:
                print("[GPU] No TF GPU devices.")
        else:
            print("[GPU] No backend, dummy run.")
    except Exception as e:
        print(f"[GPU] Error: {e}")
    print(f"[GPU] {name} done")

def npu_job(name):
    print(f"[NPU] {name} start")
    try:
        if ort is not None:
            print("[NPU] ORT available (wire real ONNX model here).")
        elif tf is not None:
            tpus = tf.config.list_physical_devices("TPU")
            if tpus:
                print(f"[NPU] TPU devices: {tpus}")
            else:
                print("[NPU] No TPU, dummy run.")
        else:
            print("[NPU] No NPU backend, dummy run.")
    except Exception as e:
        print(f"[NPU] Error: {e}")
    print(f"[NPU] {name} done")

# ---------------------------------------------------------------------------
# PyQt6 GUI
# ---------------------------------------------------------------------------

class SwarmGUI(QtWidgets.QMainWindow):
    def __init__(self, swarm: BeastSwarm, tuner: SwarmTuner, queen: Queen, memory: MemoryManager, zmq_swarm: ZMQSwarm):
        super().__init__()
        self.swarm = swarm
        self.tuner = tuner
        self.queen = queen
        self.memory = memory
        self.zmq_swarm = zmq_swarm

        self.setWindowTitle("Beast Swarm Engine v8.1 - Live Workload Monitor")
        self.resize(1150, 700)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)

        self.global_group = QtWidgets.QGroupBox("Global Workload — LIVE OS DATA")
        global_layout = QtWidgets.QHBoxLayout(self.global_group)
        self.global_bar = QtWidgets.QProgressBar()
        self.global_bar.setRange(0, 100)
        self.global_bar.setFormat("GLOBAL LIVE CPU: %p%")
        global_layout.addWidget(self.global_bar)

        self.global_cpu_label = QtWidgets.QLabel("CPU: 0.0%")
        self.global_threads_label = QtWidgets.QLabel("Threads: 0 / 0")
        self.global_mem_label = QtWidgets.QLabel("RAM: 0.0%")
        self.global_process_label = QtWidgets.QLabel("Engine CPU: 0.0%")
        global_layout.addWidget(self.global_cpu_label)
        global_layout.addWidget(self.global_threads_label)
        global_layout.addWidget(self.global_mem_label)
        global_layout.addWidget(self.global_process_label)
        layout.addWidget(self.global_group)

        self.node_group = QtWidgets.QGroupBox("Nodes")
        layout.addWidget(self.node_group)
        self.node_layout = QtWidgets.QHBoxLayout(self.node_group)

        self.node_widgets = {}
        for node in self.swarm.nodes:
            frame = QtWidgets.QGroupBox(node.node_id)
            v = QtWidgets.QVBoxLayout(frame)

            status_layout = QtWidgets.QHBoxLayout()
            status_label = QtWidgets.QLabel("Status:")
            status_indicator = QtWidgets.QLabel()
            status_indicator.setFixedSize(18, 18)
            status_indicator.setStyleSheet("background-color: gray; border-radius: 9px; border: 1px solid #333;")
            workload_bar = QtWidgets.QProgressBar()
            workload_bar.setRange(0, 100)
            workload_bar.setFormat("CPU/threads load: %p%")
            status_layout.addWidget(status_label)
            status_layout.addWidget(status_indicator)
            status_layout.addWidget(workload_bar)

            lbl_live_cpu = QtWidgets.QLabel("LIVE CPU load: 0.0%")
            lbl_threads = QtWidgets.QLabel("Threads: 0 process / 0 logical CPU threads")
            lbl_cpu_workers = QtWidgets.QLabel("CPU workers: ?")
            lbl_io_workers = QtWidgets.QLabel("IO workers: ?")
            lbl_queues = QtWidgets.QLabel("Queues: io=?, cpu=?, gpu=?, npu=?, live=?, plugin=?")
            lbl_avg = QtWidgets.QLabel("Avg dur (s): cpu=?, io=?, async=?, live=?, plugin=?")
            lbl_pred = QtWidgets.QLabel("Pred dur (s): cpu=?, io=?, async=?, live=?, plugin=?")
            lbl_health = QtWidgets.QLabel("Health: ?")

            v.addLayout(status_layout)
            v.addWidget(lbl_live_cpu)
            v.addWidget(lbl_threads)
            v.addWidget(lbl_cpu_workers)
            v.addWidget(lbl_io_workers)
            v.addWidget(lbl_queues)
            v.addWidget(lbl_avg)
            v.addWidget(lbl_pred)
            v.addWidget(lbl_health)

            self.node_layout.addWidget(frame)
            self.node_widgets[node.node_id] = {
                "status_indicator": status_indicator,
                "workload_bar": workload_bar,
                "live_cpu": lbl_live_cpu,
                "threads": lbl_threads,
                "cpu_workers": lbl_cpu_workers,
                "io_workers": lbl_io_workers,
                "queues": lbl_queues,
                "avg": lbl_avg,
                "pred": lbl_pred,
                "health": lbl_health,
            }

        ctrl_group = QtWidgets.QGroupBox("Controls")
        layout.addWidget(ctrl_group)
        ctrl_layout = QtWidgets.QHBoxLayout(ctrl_group)

        self.btn_start_tuner = QtWidgets.QPushButton("Start Tuner")
        self.btn_stop_tuner = QtWidgets.QPushButton("Stop Tuner")
        self.btn_demo_jobs = QtWidgets.QPushButton("Run Local Demo Jobs")
        self.btn_show_risk = QtWidgets.QPushButton("Show Global Risk")
        self.btn_start_zmq = QtWidgets.QPushButton("Start ZMQ Swarm")
        self.btn_stop_zmq = QtWidgets.QPushButton("Stop ZMQ Swarm")
        self.btn_zmq_demo = QtWidgets.QPushButton("Send ZMQ Demo Jobs")

        ctrl_layout.addWidget(self.btn_start_tuner)
        ctrl_layout.addWidget(self.btn_stop_tuner)
        ctrl_layout.addWidget(self.btn_demo_jobs)
        ctrl_layout.addWidget(self.btn_show_risk)
        ctrl_layout.addWidget(self.btn_start_zmq)
        ctrl_layout.addWidget(self.btn_stop_zmq)
        ctrl_layout.addWidget(self.btn_zmq_demo)

        self.btn_start_tuner.clicked.connect(self.tuner.start)
        self.btn_stop_tuner.clicked.connect(self.tuner.stop)
        self.btn_demo_jobs.clicked.connect(self.run_demo_jobs_safe)
        self.btn_show_risk.clicked.connect(self.show_risk)
        self.btn_start_zmq.clicked.connect(self.start_zmq)
        self.btn_stop_zmq.clicked.connect(self.stop_zmq)
        self.btn_zmq_demo.clicked.connect(self.send_zmq_demo_jobs)

        self.zmq_status = QtWidgets.QLabel("ZMQ: OFF")
        layout.addWidget(self.zmq_status)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_gui)
        self.timer.start(500)

    def run_demo_jobs_safe(self):
        try:
            self.run_demo_jobs()
        except Exception as e:
            QtWidgets.QMessageBox.critical(self, "Demo Jobs Error", str(e))

    def run_demo_jobs(self):
        for i in range(8):
            self.swarm.submit_cpu(heavy_cpu_job, 500_000, priority=10, name=f"cpu_{i}", strategy="load")
        for i in range(8):
            self.swarm.submit_io(io_job, f"io_{i}", 0.3, priority=5, strategy="rr")
        for i in range(8):
            self.swarm.submit_async(
                lambda i=i: async_job(f"async_{i}", duration=0.2),
                priority=3,
                name=f"async_{i}",
                strategy="rr",
            )
        for i in range(4):
            self.swarm.submit_gpu(gpu_job, f"gpu_{i}", priority=7, strategy="load")
        for i in range(2):
            self.swarm.submit_npu(npu_job, f"npu_{i}", priority=6, strategy="load")
        for i in range(4):
            self.swarm.submit_live(name=f"live_{i}", priority=4, strategy="load")

    def show_risk(self):
        risk = self.queen.global_risk()
        msg = "\n".join([f"{k}: {v:.3f}" for k, v in risk.items()]) or "No significant risk."
        QtWidgets.QMessageBox.information(self, "Global Risk (Queen)", msg)

    def start_zmq(self):
        self.zmq_swarm.start()

    def stop_zmq(self):
        self.zmq_swarm.stop()

    def send_zmq_demo_jobs(self):
        if self.zmq_swarm.mode != "client":
            QtWidgets.QMessageBox.warning(self, "ZMQ Client", "This instance is not in client mode.")
            return
        self.zmq_swarm.send_job("cpu", name="zmq_cpu_0", args=[500_000], kwargs={}, priority=5)
        self.zmq_swarm.send_job("io", name="zmq_io_0", args=["zmq_io_0"], kwargs={"duration": 0.4}, priority=4)
        self.zmq_swarm.send_job("gpu", name="zmq_gpu_0", args=["zmq_gpu_0"], kwargs={}, priority=6)
        self.zmq_swarm.send_job("npu", name="zmq_npu_0", args=["zmq_npu_0"], kwargs={}, priority=6)
        self.zmq_swarm.send_job("async", name="zmq_async_0", args=["zmq_async_0"], kwargs={"duration": 0.3}, priority=3)
        self.zmq_swarm.send_job("live", name="zmq_live_0", args=[], kwargs={}, priority=4)
        QtWidgets.QMessageBox.information(self, "ZMQ Client", "ZMQ demo jobs submitted to server.")

    def update_gui(self):
        live = self.swarm.global_live_load()
        global_percent = int(max(0.0, min(100.0, live["cpu_percent"])))
        self.global_bar.setValue(global_percent)
        self.global_cpu_label.setText(f"CPU: {live['cpu_percent']:.1f}%")
        self.global_threads_label.setText(
            f"Threads: {live['process_threads']} process / {live['logical_threads']} logical"
        )
        self.global_mem_label.setText(f"RAM: {live['memory_percent']:.1f}%")
        self.global_process_label.setText(
            f"Engine CPU: {live['process_cpu_percent']:.1f}%"
        )

        for node in self.swarm.nodes:
            labels = self.node_widgets[node.node_id]
            durations, queues, preds = node.get_metrics_snapshot()

            def avg(lst):
                return sum(lst) / len(lst) if lst else 0.0

            cpu_durs = durations.get(TaskType.CPU, [])
            io_durs = durations.get(TaskType.IO, [])
            async_durs = durations.get(TaskType.ASYNC, [])
            live_durs = durations.get(TaskType.LIVE, [])
            plugin_durs = durations.get(TaskType.PLUGIN, [])

            avg_cpu = avg(cpu_durs)
            avg_io = avg(io_durs)
            avg_async = avg(async_durs)
            avg_live = avg(live_durs)
            avg_plugin = avg(plugin_durs)

            pred_cpu = preds.get(TaskType.CPU, 0.0)
            pred_io = preds.get(TaskType.IO, 0.0)
            pred_async = preds.get(TaskType.ASYNC, 0.0)
            pred_live = preds.get(TaskType.LIVE, 0.0)
            pred_plugin = preds.get(TaskType.PLUGIN, 0.0)

            live_node = node.get_live_load()
            cpu_live = float(live_node.get("cpu_percent", 0.0) or 0.0)
            process_threads = int(live_node.get("process_threads", 0) or 0)
            logical_threads = int(live_node.get("logical_threads", os.cpu_count() or 1) or 1)
            labels["live_cpu"].setText(
                f"LIVE CPU load: {cpu_live:.1f}%"
            )
            labels["threads"].setText(
                f"Threads: {process_threads} active process / "
                f"{logical_threads} logical CPU threads"
            )
            labels["cpu_workers"].setText(f"CPU workers: {node.max_cpu_workers}")
            labels["io_workers"].setText(f"IO workers: {node.max_io_workers}")
            labels["queues"].setText(
                f"Queues: io={queues['io']}, cpu={queues['cpu']}, gpu={queues['gpu']}, "
                f"npu={queues['npu']}, live={queues['live']}, plugin={queues['plugin']}"
            )
            labels["avg"].setText(
                f"Avg dur (s): cpu={avg_cpu:.3f}, io={avg_io:.3f}, async={avg_async:.3f}, "
                f"live={avg_live:.3f}, plugin={avg_plugin:.3f}"
            )
            labels["pred"].setText(
                f"Pred dur (s): cpu={pred_cpu:.3f}, io={pred_io:.3f}, async={pred_async:.3f}, "
                f"live={pred_live:.3f}, plugin={pred_plugin:.3f}"
            )
            labels["health"].setText(f"Health: {'OK' if node.health_ok else 'DEGRADED'}")

            status_indicator = labels["status_indicator"]
            workload_bar = labels["workload_bar"]

            if node.health_ok:
                status_indicator.setStyleSheet(
                    "background-color: #00cc00; border-radius: 9px; border: 1px solid #003300;"
                )
            else:
                status_indicator.setStyleSheet(
                    "background-color: #cc0000; border-radius: 9px; border: 1px solid #330000;"
                )

            node_percent = int(max(0.0, min(100.0, live_node["cpu_percent"])))
            workload_bar.setFormat("LIVE CPU/threads load: %p%")
            workload_bar.setValue(node_percent)

        if self.memory:
            self.memory.update_queen_nodes(self.queen.nodes)
            self.memory.save()

        if self.zmq_swarm.running:
            self.zmq_status.setText(f"ZMQ: {self.zmq_swarm.mode.upper()}")
        else:
            self.zmq_status.setText("ZMQ: OFF")

# ---------------------------------------------------------------------------
# Build swarm
# ---------------------------------------------------------------------------

def build_local_swarm(memory: MemoryManager):
    memory.apply_config_overrides()
    queen = Queen(memory=memory)
    plugin_manager = PluginManager(CONFIG["plugins_dir"])
    nodes = []
    for i in range(CONFIG["local_nodes"]):
        node = BeastNode(
            node_id=f"node{i}",
            enable_gpu=CONFIG["enable_gpu"],
            enable_npu=CONFIG["enable_npu"],
            metrics_window=CONFIG["metrics_window"],
            predictive_alpha=CONFIG["predictive_alpha"],
            queen=queen,
            plugin_manager=plugin_manager,
        )
        nodes.append(node)
    swarm = BeastSwarm(nodes, queen)
    return swarm, queen

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    if QtWidgets is None or QtCore is None:
        print("PyQt6 not available. Install pyqt6 to use GUI.")
        return

    memory = MemoryManager(CONFIG["state_file"])
    swarm, queen = build_local_swarm(memory)
    tuner = SwarmTuner(swarm, interval_sec=CONFIG["tuner_interval_sec"])
    zmq_swarm = ZMQSwarm(swarm)

    app = QtWidgets.QApplication(sys.argv)
    gui = SwarmGUI(swarm, tuner, queen, memory, zmq_swarm)
    gui.show()

    tuner.start()
    QtCore.QTimer.singleShot(500, gui.run_demo_jobs_safe)

    try:
        app.exec()
    finally:
        tuner.stop()
        zmq_swarm.stop()
        swarm.shutdown()
        memory.save(force=True)


if __name__ == "__main__":
    main()
