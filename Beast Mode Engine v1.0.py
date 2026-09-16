#!/usr/bin/env python3
"""
Beast Swarm Engine v4.0
- Multi-core + GPU + NPU job system
- Local swarm (multiple nodes per machine)
- Tkinter desktop GUI dashboard
- Simple AI auto-tuner for worker counts
"""

import importlib
import subprocess
import sys
import os
import time
import queue
import threading
import asyncio
import json
from concurrent.futures import ThreadPoolExecutor, ProcessPoolExecutor
from itertools import count
from collections import defaultdict, deque

import tkinter as tk
from tkinter import ttk

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
    ],
    "enable_gpu": True,
    "enable_npu": True,
    "local_nodes": 2,
    "tuner_interval_sec": 2.0,
    "metrics_window": 100,  # last N tasks per node
    "cpu_worker_min": 2,
    "cpu_worker_max": 32,
    "io_worker_min": 4,
    "io_worker_max": 64,
}


# ---------------------------------------------------------------------------
# Autoloader
# ---------------------------------------------------------------------------

def autoload_libraries(libs):
    for lib in libs:
        try:
            importlib.import_module(lib)
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


# ---------------------------------------------------------------------------
# Task abstraction
# ---------------------------------------------------------------------------

class TaskType:
    CPU = "cpu"
    IO = "io"
    ASYNC = "async"
    GPU = "gpu"
    NPU = "npu"


class Task:
    __slots__ = ("func", "args", "kwargs", "task_type", "priority", "name")

    def __init__(self, func, *args, task_type=TaskType.CPU, priority=0, name=None, **kwargs):
        self.func = func
        self.args = args
        self.kwargs = kwargs
        self.task_type = task_type
        self.priority = priority
        self.name = name or func.__name__


class PriorityTaskQueue:
    """
    Priority queue with a monotonic counter to avoid Task comparisons.
    """
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
# Metrics
# ---------------------------------------------------------------------------

class NodeMetrics:
    """
    Stores recent task durations and queue sizes.
    """
    def __init__(self, window=100):
        self.window = window
        self.lock = threading.Lock()
        self.task_durations = defaultdict(lambda: deque(maxlen=self.window))
        self.queue_sizes = {
            "io": 0,
            "cpu": 0,
            "gpu": 0,
            "npu": 0,
        }

    def record_task(self, task_type, duration):
        with self.lock:
            self.task_durations[task_type].append(duration)

    def set_queue_sizes(self, io_q, cpu_q, gpu_q, npu_q):
        with self.lock:
            self.queue_sizes["io"] = io_q
            self.queue_sizes["cpu"] = cpu_q
            self.queue_sizes["gpu"] = gpu_q
            self.queue_sizes["npu"] = npu_q

    def snapshot(self):
        with self.lock:
            durations = {k: list(v) for k, v in self.task_durations.items()}
            queues = dict(self.queue_sizes)
        return durations, queues


# ---------------------------------------------------------------------------
# Beast Node (single machine)
# ---------------------------------------------------------------------------

class BeastNode:
    def __init__(self,
                 node_id: str,
                 max_io_workers=None,
                 max_cpu_workers=None,
                 enable_gpu=True,
                 enable_npu=True,
                 metrics_window=100):
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

        self._stop_event = threading.Event()

        self.metrics = NodeMetrics(window=metrics_window)

        # Async loop
        self._async_loop = asyncio.new_event_loop()
        self._async_thread = threading.Thread(
            target=self._run_async_loop,
            name=f"{self.node_id}_AsyncLoop",
            daemon=True
        )
        self._async_thread.start()

        # Workers
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

        self._io_worker.start()
        self._cpu_worker.start()
        self._gpu_worker.start()
        self._npu_worker.start()

        self._set_affinity()
        self._detect_devices()

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
        task = Task(func, *args, task_type=TaskType.CPU, priority=priority, name=name, **kwargs)
        self.cpu_queue.put(task)

    def submit_io(self, func, *args, priority=0, name=None, **kwargs):
        task = Task(func, *args, task_type=TaskType.IO, priority=priority, name=name, **kwargs)
        self.io_queue.put(task)

    def submit_gpu(self, func, *args, priority=0, name=None, **kwargs):
        if not self.enable_gpu:
            print(f"[{self.node_id}][GPU] Disabled/unavailable, skip '{name or func.__name__}'")
            return
        task = Task(func, *args, task_type=TaskType.GPU, priority=priority, name=name, **kwargs)
        self.gpu_queue.put(task)

    def submit_npu(self, func, *args, priority=0, name=None, **kwargs):
        if not self.enable_npu:
            print(f"[{self.node_id}][NPU] Disabled/unavailable, skip '{name or func.__name__}'")
            return
        task = Task(func, *args, task_type=TaskType.NPU, priority=priority, name=name, **kwargs)
        self.npu_queue.put(task)

    # ----------------- worker loops -----------------

    def _io_worker_loop(self):
        while not self._stop_event.is_set():
            self.metrics.set_queue_sizes(
                self.io_queue.qsize(),
                self.cpu_queue.qsize(),
                self.gpu_queue.qsize(),
                self.npu_queue.qsize(),
            )
            try:
                task = self.io_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.io_executor.submit(self._run_task, task)

    def _cpu_worker_loop(self):
        while not self._stop_event.is_set():
            self.metrics.set_queue_sizes(
                self.io_queue.qsize(),
                self.cpu_queue.qsize(),
                self.gpu_queue.qsize(),
                self.npu_queue.qsize(),
            )
            try:
                task = self.cpu_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.cpu_executor.submit(self._run_task, task)

    def _gpu_worker_loop(self):
        while not self._stop_event.is_set():
            self.metrics.set_queue_sizes(
                self.io_queue.qsize(),
                self.cpu_queue.qsize(),
                self.gpu_queue.qsize(),
                self.npu_queue.qsize(),
            )
            try:
                task = self.gpu_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.io_executor.submit(self._run_task, task)

    def _npu_worker_loop(self):
        while not self._stop_event.is_set():
            self.metrics.set_queue_sizes(
                self.io_queue.qsize(),
                self.cpu_queue.qsize(),
                self.gpu_queue.qsize(),
                self.npu_queue.qsize(),
            )
            try:
                task = self.npu_queue.get(timeout=0.1)
            except queue.Empty:
                continue
            self.io_executor.submit(self._run_task, task)

    # ----------------- core runner -----------------

    def _run_task(self, task: Task):
        start = time.time()
        try:
            result = task.func(*task.args, **task.kwargs)
            return result
        except Exception as e:
            print(f"[{self.node_id}][TASK][{task.task_type}][{task.name}] Error: {e}")
        finally:
            duration = time.time() - start
            self.metrics.record_task(task.task_type, duration)

    # ----------------- metrics -----------------

    def approx_load(self):
        return (
            self.io_queue.qsize()
            + self.cpu_queue.qsize()
            + self.gpu_queue.qsize()
            + self.npu_queue.qsize()
        )

    def get_metrics_snapshot(self):
        return self.metrics.snapshot()

    # ----------------- dynamic worker tuning -----------------

    def set_cpu_workers(self, new_count):
        new_count = max(CONFIG["cpu_worker_min"], min(CONFIG["cpu_worker_max"], new_count))
        if new_count != self.max_cpu_workers:
            print(f"[{self.node_id}][TUNER] CPU workers {self.max_cpu_workers} -> {new_count}")
            self.max_cpu_workers = new_count
            # ProcessPoolExecutor cannot resize easily; in real system you'd recreate it.
            # Here we just store the value for reference.

    def set_io_workers(self, new_count):
        new_count = max(CONFIG["io_worker_min"], min(CONFIG["io_worker_max"], new_count))
        if new_count != self.max_io_workers:
            print(f"[{self.node_id}][TUNER] IO workers {self.max_io_workers} -> {new_count}")
            self.max_io_workers = new_count
            # ThreadPoolExecutor cannot resize easily; same note as above.

    # ----------------- shutdown -----------------

    def shutdown(self, wait=True):
        self._stop_event.set()
        self.io_executor.shutdown(wait=wait)
        self.cpu_executor.shutdown(wait=wait)
        try:
            self._async_loop.call_soon_threadsafe(self._async_loop.stop)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Swarm Controller (local nodes)
# ---------------------------------------------------------------------------

class BeastSwarm:
    def __init__(self, nodes):
        self.nodes = nodes
        self._rr_counter = count()

    def _next_node_rr(self):
        idx = next(self._rr_counter) % len(self.nodes)
        return self.nodes[idx]

    def _best_node_load(self):
        return min(self.nodes, key=lambda n: n.approx_load())

    def submit_cpu(self, func, *args, priority=0, name=None, strategy="load", **kwargs):
        node = self._best_node_load() if strategy == "load" else self._next_node_rr()
        node.submit_cpu(func, *args, priority=priority, name=name, **kwargs)

    def submit_io(self, func, *args, priority=0, name=None, strategy="rr", **kwargs):
        node = self._next_node_rr() if strategy == "rr" else self._best_node_load()
        node.submit_io(func, *args, priority=priority, name=name, **kwargs)

    def submit_gpu(self, func, *args, priority=0, name=None, strategy="load", **kwargs):
        node = self._best_node_load() if strategy == "load" else self._next_node_rr()
        node.submit_gpu(func, *args, priority=priority, name=name, **kwargs)

    def submit_npu(self, func, *args, priority=0, name=None, strategy="load", **kwargs):
        node = self._best_node_load() if strategy == "load" else self._next_node_rr()
        node.submit_npu(func, *args, priority=priority, name=name, **kwargs)

    def submit_async(self, coro_factory, priority=0, name=None, strategy="rr"):
        node = self._next_node_rr() if strategy == "rr" else self._best_node_load()
        node.submit_async(coro_factory, priority=priority, name=name)

    def shutdown(self):
        for n in self.nodes:
            n.shutdown()


# ---------------------------------------------------------------------------
# AI Tuner
# ---------------------------------------------------------------------------

class SwarmTuner:
    """
    Simple rule-based tuner:
    - If queues grow and avg duration is high, increase workers.
    - If queues shrink and avg duration is low, decrease workers.
    """

    def __init__(self, swarm: BeastSwarm, interval_sec: float = 2.0):
        self.swarm = swarm
        self.interval_sec = interval_sec
        self._stop_event = threading.Event()
        self._thread = threading.Thread(target=self._loop, daemon=True, name="SwarmTuner")

    def start(self):
        self._thread.start()

    def stop(self):
        self._stop_event.set()

    def _loop(self):
        while not self._stop_event.is_set():
            time.sleep(self.interval_sec)
            for node in self.swarm.nodes:
                durations, queues = node.get_metrics_snapshot()

                # Simple heuristics
                cpu_durs = durations.get(TaskType.CPU, [])
                io_durs = durations.get(TaskType.IO, [])
                avg_cpu = sum(cpu_durs) / len(cpu_durs) if cpu_durs else 0.0
                avg_io = sum(io_durs) / len(io_durs) if io_durs else 0.0

                cpu_q = queues["cpu"]
                io_q = queues["io"]

                # CPU tuning
                if cpu_q > 0 and avg_cpu > 0.05:
                    node.set_cpu_workers(node.max_cpu_workers + 1)
                elif cpu_q == 0 and avg_cpu < 0.01 and node.max_cpu_workers > CONFIG["cpu_worker_min"]:
                    node.set_cpu_workers(node.max_cpu_workers - 1)

                # IO tuning
                if io_q > 0 and avg_io > 0.05:
                    node.set_io_workers(node.max_io_workers + 1)
                elif io_q == 0 and avg_io < 0.01 and node.max_io_workers > CONFIG["io_worker_min"]:
                    node.set_io_workers(node.max_io_workers - 1)


# ---------------------------------------------------------------------------
# Example jobs
# ---------------------------------------------------------------------------

def heavy_cpu_job(n=5_000_00):
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
    print(f"[GPU] {name} done")

def npu_job(name):
    print(f"[NPU] {name} start")
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
    print(f"[NPU] {name} done")


# ---------------------------------------------------------------------------
# GUI
# ---------------------------------------------------------------------------

class SwarmGUI:
    def __init__(self, root: tk.Tk, swarm: BeastSwarm, tuner: SwarmTuner):
        self.root = root
        self.swarm = swarm
        self.tuner = tuner

        self.root.title("Beast Swarm Engine v4.0")
        self.root.geometry("800x400")

        self.main_frame = ttk.Frame(self.root, padding=10)
        self.main_frame.pack(fill=tk.BOTH, expand=True)

        self.node_frames = []
        for i, node in enumerate(self.swarm.nodes):
            frame = ttk.LabelFrame(self.main_frame, text=f"Node {node.node_id}")
            frame.grid(row=0, column=i, padx=10, pady=10, sticky="n")
            self.node_frames.append((node, frame))

        self._build_controls()
        self._build_node_views()

        self.update_gui()

    def _build_controls(self):
        ctrl_frame = ttk.LabelFrame(self.main_frame, text="Controls")
        ctrl_frame.grid(row=1, column=0, columnspan=len(self.swarm.nodes), pady=10, sticky="ew")

        self.btn_start_tuner = ttk.Button(ctrl_frame, text="Start Tuner", command=self.tuner.start)
        self.btn_start_tuner.grid(row=0, column=0, padx=5, pady=5)

        self.btn_stop_tuner = ttk.Button(ctrl_frame, text="Stop Tuner", command=self.tuner.stop)
        self.btn_stop_tuner.grid(row=0, column=1, padx=5, pady=5)

        self.btn_demo_jobs = ttk.Button(ctrl_frame, text="Run Demo Jobs", command=self.run_demo_jobs)
        self.btn_demo_jobs.grid(row=0, column=2, padx=5, pady=5)

    def _build_node_views(self):
        self.node_labels = {}
        for node, frame in self.node_frames:
            lbl_cpu_workers = ttk.Label(frame, text="CPU workers: ?")
            lbl_cpu_workers.pack(anchor="w")
            lbl_io_workers = ttk.Label(frame, text="IO workers: ?")
            lbl_io_workers.pack(anchor="w")

            lbl_queues = ttk.Label(frame, text="Queues: io=?, cpu=?, gpu=?, npu=?")
            lbl_queues.pack(anchor="w")

            lbl_avg = ttk.Label(frame, text="Avg dur (s): cpu=?, io=?, async=?")
            lbl_avg.pack(anchor="w")

            self.node_labels[node.node_id] = {
                "cpu_workers": lbl_cpu_workers,
                "io_workers": lbl_io_workers,
                "queues": lbl_queues,
                "avg": lbl_avg,
            }

    def run_demo_jobs(self):
        for i in range(8):
            self.swarm.submit_cpu(heavy_cpu_job, n=5_000_00, priority=10, name=f"cpu_{i}", strategy="load")
        for i in range(8):
            self.swarm.submit_io(io_job, f"io_{i}", duration=0.3, priority=5, strategy="rr")
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

    def update_gui(self):
        for node, frame in self.node_frames:
            labels = self.node_labels[node.node_id]
            durations, queues = node.get_metrics_snapshot()

            cpu_durs = durations.get(TaskType.CPU, [])
            io_durs = durations.get(TaskType.IO, [])
            async_durs = durations.get(TaskType.ASYNC, [])

            avg_cpu = sum(cpu_durs) / len(cpu_durs) if cpu_durs else 0.0
            avg_io = sum(io_durs) / len(io_durs) if io_durs else 0.0
            avg_async = sum(async_durs) / len(async_durs) if async_durs else 0.0

            labels["cpu_workers"].config(text=f"CPU workers: {node.max_cpu_workers}")
            labels["io_workers"].config(text=f"IO workers: {node.max_io_workers}")
            labels["queues"].config(
                text=f"Queues: io={queues['io']}, cpu={queues['cpu']}, gpu={queues['gpu']}, npu={queues['npu']}"
            )
            labels["avg"].config(
                text=f"Avg dur (s): cpu={avg_cpu:.3f}, io={avg_io:.3f}, async={avg_async:.3f}"
            )

        self.root.after(500, self.update_gui)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def build_local_swarm():
    nodes = []
    for i in range(CONFIG["local_nodes"]):
        node = BeastNode(
            node_id=f"node{i}",
            enable_gpu=CONFIG["enable_gpu"],
            enable_npu=CONFIG["enable_npu"],
            metrics_window=CONFIG["metrics_window"],
        )
        nodes.append(node)
    return BeastSwarm(nodes)


def main():
    swarm = build_local_swarm()
    tuner = SwarmTuner(swarm, interval_sec=CONFIG["tuner_interval_sec"])

    root = tk.Tk()
    gui = SwarmGUI(root, swarm, tuner)

    try:
        root.mainloop()
    finally:
        tuner.stop()
        swarm.shutdown()


if __name__ == "__main__":
    main()
