#!/usr/bin/env python3
"""
=============================================================
HYBRID GPU/RAM MOD v14
=============================================================

Supervisor-booted experimental hybrid memory / CUDA monitor.

BOOT ARCHITECTURE
-----------------
    main()
      |
      v
    Supervisor
      |
      +-- HybridMemoryManager
      +-- CUDA subsystem
      +-- Swarm simulator
      +-- Safety analyzer
      +-- Suricata reader worker
      +-- GUI
      |
      v
    application running

IMPORTANT
---------
System RAM and NVIDIA VRAM are NOT physically merged.

RAM is authoritative backing storage.

VRAM is an optional accelerated cache:

        SYSTEM RAM
            |
            | promote
            v
          VRAM
            |
            | demote
            v
        SYSTEM RAM

This is not an operating-system virtual-memory replacement.

SCHEDULERS
----------
Periodic application schedulers have been removed.

There is no:

    * periodic monitor thread
    * tkinter after() refresh loop
    * watchdog scheduler
    * scheduled task manager

Workers are still used where blocking work makes sense:

    * Suricata file reader
    * CUDA turbo worker
    * optional GUI worker actions

METRICS
-------
Metrics are collected explicitly when:

    * the application starts
    * the user presses Refresh
    * a major operation completes

CUDA
----
    * Numba CUDA
    * grid-stride kernel
    * CUDA streams
    * pinned host memory where supported
    * explicit synchronization
    * VRAM budgeting
    * LRU eviction
    * CPU fallback

TARGET
------
Python 3.10+

Optional:
    NumPy
    Numba
    scikit-learn
    Tkinter
    NVIDIA CUDA driver

CPU-only operation is supported.
=============================================================
"""

from __future__ import annotations

import gc
import importlib.util
import json
import os
import random
import signal
import subprocess
import sys
import threading
import time
import traceback

from collections import deque
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Optional


# ============================================================
# APPLICATION CONFIGURATION
# ============================================================

APP_NAME = "Hybrid GPU/RAM Mod v14"

DEFAULT_SURICATA_EVE = "/var/log/suricata/eve.json"

DEFAULT_SWARM_NODES = 8

DEFAULT_GPU_ELEMENTS = 2_000_000

VRAM_TARGET_PERCENT = 70
VRAM_MIN_RESERVE_BYTES = 256 * 1024 * 1024

CUDA_THREADS_PER_BLOCK = 256

MAX_DEMO_ELEMENTS = 32_000_000

SURICATA_IDLE_SLEEP = 0.25


# ============================================================
# LOGGING
# ============================================================

_LOG_LOCK = threading.Lock()


def log(message: str) -> None:
    """Thread-safe console logger."""
    timestamp = time.strftime(
        "%Y-%m-%d %H:%M:%S",
        time.localtime(),
    )

    with _LOG_LOCK:
        print(
            f"[{timestamp}] {message}",
            flush=True,
        )


# ============================================================
# OPTIONAL DEPENDENCY MANAGEMENT
# ============================================================

AUTOLOAD_ENABLED = (
    os.environ.get(
        "HYBRID_NO_AUTOLOAD",
        "0",
    )
    != "1"
)


def module_available(name: str) -> bool:
    try:
        return (
            importlib.util.find_spec(name)
            is not None
        )
    except Exception:
        return False


def try_install_package(
    module_name: str,
    package_name: str,
) -> bool:
    if module_available(module_name):
        return True

    if not AUTOLOAD_ENABLED:
        log(
            f"[DEPS] {module_name} unavailable; "
            "autoload disabled"
        )
        return False

    log(
        f"[DEPS] Attempting installation: "
        f"{package_name}"
    )

    try:
        subprocess.check_call(
            [
                sys.executable,
                "-m",
                "pip",
                "install",
                "--disable-pip-version-check",
                package_name,
            ]
        )

        return module_available(
            module_name
        )

    except Exception as exc:
        log(
            f"[DEPS] Could not install "
            f"{package_name}: {exc}"
        )

        return False


def load_dependencies() -> None:
    """
    Best-effort optional dependency loader.

    Import failures do not prevent the supervisor from booting.
    """
    try_install_package(
        "numpy",
        "numpy",
    )

    try_install_package(
        "numba",
        "numba",
    )

    try_install_package(
        "sklearn",
        "scikit-learn",
    )


load_dependencies()


# ============================================================
# NUMPY
# ============================================================

try:
    import numpy as np

    NUMPY_AVAILABLE = True

except Exception as exc:
    np = None
    NUMPY_AVAILABLE = False

    log(
        f"[DEPS] NumPy unavailable: {exc}"
    )


# ============================================================
# NUMBA / CUDA
# ============================================================

try:
    from numba import cuda

    NUMBA_AVAILABLE = True

except Exception as exc:
    cuda = None
    NUMBA_AVAILABLE = False

    log(
        f"[DEPS] Numba unavailable: {exc}"
    )


# ============================================================
# SCIKIT-LEARN
# ============================================================

try:
    from sklearn.ensemble import IsolationForest

    SKLEARN_AVAILABLE = True

except Exception as exc:
    IsolationForest = None
    SKLEARN_AVAILABLE = False

    log(
        f"[DEPS] scikit-learn unavailable: {exc}"
    )


# ============================================================
# CUDA KERNEL
# ============================================================

if NUMBA_AVAILABLE:

    @cuda.jit
    def turbo_add_kernel(
        x,
        y,
        output,
        count,
    ):
        """
        Grid-stride CUDA vector addition.
        """
        index = cuda.grid(1)
        stride = cuda.gridsize(1)

        for i in range(
            index,
            count,
            stride,
        ):
            output[i] = (
                x[i] +
                y[i]
            )


# ============================================================
# CUDA HELPERS
# ============================================================

def cuda_is_available() -> bool:
    if not NUMBA_AVAILABLE:
        return False

    try:
        return bool(
            cuda.is_available()
        )

    except Exception as exc:
        log(
            f"[CUDA] Availability check failed: "
            f"{exc}"
        )

        return False


def get_cuda_stream():
    if not cuda_is_available():
        return None

    try:
        return cuda.stream()

    except Exception:
        return None


def allocate_pinned_float32(
    elements: int,
):
    """
    Allocate page-locked host memory when possible.

    Falls back to ordinary NumPy memory.
    """
    if (
        NUMBA_AVAILABLE and
        cuda_is_available()
    ):
        try:
            return cuda.pinned_array(
                elements,
                dtype=np.float32,
            )

        except Exception as exc:
            log(
                f"[CUDA] Pinned allocation "
                f"fallback: {exc}"
            )

    return np.empty(
        elements,
        dtype=np.float32,
    )


# ============================================================
# FORMATTING
# ============================================================

def format_bytes(
    value: int,
) -> str:
    value = max(
        0,
        int(value),
    )

    if value < 1024:
        return f"{value} B"

    number = float(value)

    for unit in (
        "KB",
        "MB",
        "GB",
        "TB",
    ):
        number /= 1024.0

        if number < 1024.0:
            return (
                f"{number:.2f} {unit}"
            )

    return (
        f"{number:.2f} PB"
    )


# ============================================================
# GPU INFORMATION
# ============================================================

@dataclass
class GPUInfo:
    available: bool = False
    name: str = "No CUDA GPU"
    total_vram: int = 0
    free_vram: int = 0
    compute_capability: str = "N/A"


def get_gpu_info() -> GPUInfo:
    """
    CUDA discovery is isolated so a broken CUDA environment
    cannot prevent application boot.
    """
    if not cuda_is_available():
        return GPUInfo()

    try:
        device = (
            cuda.get_current_device()
        )

        free_vram = 0
        total_vram = 0

        try:
            (
                free_vram,
                total_vram,
            ) = (
                cuda
                .current_context()
                .get_memory_info()
            )

        except Exception:
            pass

        try:
            name = device.name

            if isinstance(
                name,
                bytes,
            ):
                name = name.decode(
                    errors="replace"
                )

            name = str(name)

        except Exception:
            name = "NVIDIA CUDA GPU"

        try:
            cc = (
                f"{device.compute_capability[0]}."
                f"{device.compute_capability[1]}"
            )

        except Exception:
            cc = "N/A"

        return GPUInfo(
            available=True,
            name=name,
            total_vram=int(
                total_vram
            ),
            free_vram=int(
                free_vram
            ),
            compute_capability=cc,
        )

    except Exception as exc:
        log(
            f"[CUDA] GPU discovery failed: "
            f"{exc}"
        )

        return GPUInfo()


# ============================================================
# HYBRID MEMORY
# ============================================================

@dataclass
class HybridBlock:
    block_id: int
    host_array: Any
    device_array: Any = None
    device_resident: bool = False
    last_used: float = 0.0

    @property
    def nbytes(self) -> int:
        return int(
            self.host_array.nbytes
        )


class HybridMemoryManager:
    """
    Host-backed memory tier with optional VRAM cache.
    """

    def __init__(
        self,
        target_percent: int = VRAM_TARGET_PERCENT,
    ):
        if not NUMPY_AVAILABLE:
            raise RuntimeError(
                "NumPy is required for "
                "hybrid memory management"
            )

        self.target_percent = max(
            10,
            min(
                int(target_percent),
                90,
            ),
        )

        self.lock = threading.RLock()

        self.blocks: dict[
            int,
            HybridBlock,
        ] = {}

        self.next_id = 1

        self.gpu = GPUInfo()

        self.vram_budget = 0
        self.vram_used = 0

        self.refresh_gpu()

    def calculate_budget(self) -> int:
        if not self.gpu.available:
            return 0

        usable = max(
            0,
            self.gpu.free_vram -
            VRAM_MIN_RESERVE_BYTES,
        )

        return int(
            usable *
            self.target_percent /
            100
        )

    def refresh_gpu(self) -> None:
        with self.lock:
            self.gpu = get_gpu_info()

            self.vram_budget = (
                self.calculate_budget()
            )

    def allocate(
        self,
        elements: int,
        dtype=None,
        prefer_vram: bool = True,
    ) -> int:
        if dtype is None:
            dtype = np.float32

        elements = int(elements)

        if elements <= 0:
            raise ValueError(
                "elements must be positive"
            )

        if elements > MAX_DEMO_ELEMENTS:
            raise ValueError(
                "Allocation exceeds safety "
                f"limit of {MAX_DEMO_ELEMENTS:,}"
            )

        log(
            f"[MEM] Allocating "
            f"{elements:,} elements"
        )

        host = np.zeros(
            elements,
            dtype=dtype,
        )

        with self.lock:
            block_id = self.next_id
            self.next_id += 1

            self.blocks[block_id] = (
                HybridBlock(
                    block_id=block_id,
                    host_array=host,
                    last_used=time.monotonic(),
                )
            )

        if prefer_vram:
            self.promote(
                block_id
            )

        return block_id

    def promote(
        self,
        block_id: int,
    ) -> bool:
        if not cuda_is_available():
            return False

        with self.lock:
            block = self.blocks.get(
                block_id
            )

            if block is None:
                return False

            if block.device_resident:
                block.last_used = (
                    time.monotonic()
                )

                return True

            size = block.nbytes

            self.refresh_gpu()

            if size > self.vram_budget:
                log(
                    "[MEM] Block larger than "
                    "available VRAM budget"
                )

                return False

            if (
                self.vram_used +
                size >
                self.vram_budget
            ):
                self.evict_until_available(
                    size
                )

            if (
                self.vram_used +
                size >
                self.vram_budget
            ):
                return False

            try:
                stream = (
                    get_cuda_stream()
                )

                if stream is not None:
                    device_array = (
                        cuda.to_device(
                            block.host_array,
                            stream=stream,
                        )
                    )

                    stream.synchronize()

                else:
                    device_array = (
                        cuda.to_device(
                            block.host_array
                        )
                    )

                block.device_array = (
                    device_array
                )

                block.device_resident = (
                    True
                )

                block.last_used = (
                    time.monotonic()
                )

                self.vram_used += size

                log(
                    "[MEM] Promoted block "
                    f"{block_id} -> VRAM "
                    f"({format_bytes(size)})"
                )

                return True

            except Exception as exc:
                block.device_array = None
                block.device_resident = False

                log(
                    f"[MEM] VRAM promotion "
                    f"failed: {exc}"
                )

                return False

    def demote(
        self,
        block_id: int,
    ) -> bool:
        with self.lock:
            block = self.blocks.get(
                block_id
            )

            if (
                block is None or
                not block.device_resident
            ):
                return False

            size = block.nbytes

            try:
                block.host_array = (
                    block.device_array
                    .copy_to_host()
                )

                del block.device_array

                block.device_array = None
                block.device_resident = False

                self.vram_used = max(
                    0,
                    self.vram_used -
                    size,
                )

                log(
                    "[MEM] Demoted block "
                    f"{block_id} -> RAM"
                )

                return True

            except Exception as exc:
                log(
                    f"[MEM] VRAM demotion "
                    f"failed: {exc}"
                )

                return False

    def evict_until_available(
        self,
        required_bytes: int,
    ) -> None:
        while (
            self.vram_used +
            required_bytes >
            self.vram_budget
        ):
            candidates = [
                block
                for block in (
                    self.blocks.values()
                )
                if block.device_resident
            ]

            if not candidates:
                break

            victim = min(
                candidates,
                key=lambda block:
                    block.last_used,
            )

            if not self.demote(
                victim.block_id
            ):
                break

    def get_host(
        self,
        block_id: int,
    ):
        with self.lock:
            block = self.blocks[
                block_id
            ]

            if block.device_resident:
                block.host_array = (
                    block.device_array
                    .copy_to_host()
                )

            block.last_used = (
                time.monotonic()
            )

            return block.host_array

    def get_device(
        self,
        block_id: int,
    ):
        if not self.promote(
            block_id
        ):
            raise RuntimeError(
                "Block could not be "
                "promoted to VRAM"
            )

        with self.lock:
            block = self.blocks[
                block_id
            ]

            block.last_used = (
                time.monotonic()
            )

            return block.device_array

    def release(
        self,
        block_id: int,
    ) -> None:
        with self.lock:
            block = self.blocks.pop(
                block_id,
                None,
            )

            if block is None:
                return

            if block.device_resident:
                self.vram_used = max(
                    0,
                    self.vram_used -
                    block.nbytes,
                )

                try:
                    del block.device_array
                except Exception:
                    pass

        gc.collect()

    def stats(self) -> dict[str, Any]:
        with self.lock:
            resident = sum(
                1
                for block in (
                    self.blocks.values()
                )
                if block.device_resident
            )

            host_bytes = sum(
                block.nbytes
                for block in (
                    self.blocks.values()
                )
            )

            return {
                "blocks": len(
                    self.blocks
                ),
                "vram_resident_blocks": resident,
                "host_bytes": host_bytes,
                "vram_used": self.vram_used,
                "vram_budget": self.vram_budget,
            }


# ============================================================
# CUDA TURBO WORKER
# ============================================================

def gpu_turbo_boost(
    elements: int = DEFAULT_GPU_ELEMENTS,
):
    """
    CUDA vector addition.

    Uses:

        * pinned host buffers
        * CUDA stream
        * grid-stride kernel
        * explicit synchronization
    """
    log(
        "[GPU] Starting CUDA turbo"
    )

    if not NUMPY_AVAILABLE:
        log(
            "[GPU] NumPy unavailable"
        )

        return None

    if not cuda_is_available():
        log(
            "[GPU] CUDA unavailable"
        )

        return None

    elements = int(elements)

    if elements <= 0:
        return None

    if elements > MAX_DEMO_ELEMENTS:
        log(
            "[GPU] Workload exceeds "
            "configured limit"
        )

        return None

    try:
        x = allocate_pinned_float32(
            elements
        )

        y = allocate_pinned_float32(
            elements
        )

        output = np.empty(
            elements,
            dtype=np.float32,
        )

        rng = np.random.default_rng()

        rng.random(
            elements,
            dtype=np.float32,
            out=x,
        )

        rng.random(
            elements,
            dtype=np.float32,
            out=y,
        )

        stream = (
            get_cuda_stream()
        )

        if stream is None:
            d_x = cuda.to_device(x)
            d_y = cuda.to_device(y)

            d_output = (
                cuda.device_array(
                    elements,
                    dtype=np.float32,
                )
            )

            blocks = (
                elements +
                CUDA_THREADS_PER_BLOCK -
                1
            ) // CUDA_THREADS_PER_BLOCK

            turbo_add_kernel[
                blocks,
                CUDA_THREADS_PER_BLOCK,
            ](
                d_x,
                d_y,
                d_output,
                elements,
            )

            d_output.copy_to_host(
                output
            )

            cuda.synchronize()

        else:
            d_x = cuda.to_device(
                x,
                stream=stream,
            )

            d_y = cuda.to_device(
                y,
                stream=stream,
            )

            d_output = (
                cuda.device_array(
                    elements,
                    dtype=np.float32,
                    stream=stream,
                )
            )

            blocks = (
                elements +
                CUDA_THREADS_PER_BLOCK -
                1
            ) // CUDA_THREADS_PER_BLOCK

            turbo_add_kernel[
                blocks,
                CUDA_THREADS_PER_BLOCK,
                stream,
            ](
                d_x,
                d_y,
                d_output,
                elements,
            )

            d_output.copy_to_host(
                output,
                stream=stream,
            )

            stream.synchronize()

        sample = output[
            :5
        ]

        log(
            "[GPU] CUDA computation complete"
        )

        log(
            f"[GPU] Sample={sample}"
        )

        try:
            del d_x
            del d_y
            del d_output
        except Exception:
            pass

        return output

    except Exception as exc:
        log(
            f"[GPU] CUDA turbo failed: "
            f"{exc}"
        )

        traceback.print_exc()

        return None

    finally:
        gc.collect()


# ============================================================
# SWARM
# ============================================================

@dataclass
class SwarmNode:
    node_id: int
    generation: int = 0
    health: float = 1.0
    synchronized: bool = False


class SwarmSimulator:

    def __init__(
        self,
        count: int = DEFAULT_SWARM_NODES,
    ):
        count = max(
            1,
            int(count),
        )

        self.nodes = [
            SwarmNode(
                node_id=index + 1
            )
            for index in range(count)
        ]

        self.lock = threading.Lock()

        self.generation = 0

    def synchronize(self) -> None:
        with self.lock:
            self.generation += 1

            for node in self.nodes:
                node.generation = (
                    self.generation
                )

                node.health = max(
                    0.0,
                    min(
                        1.0,
                        node.health +
                        random.uniform(
                            -0.02,
                            0.02,
                        ),
                    ),
                )

                node.synchronized = True

    def simulate_failure(
        self,
        node_id: int,
    ) -> None:
        with self.lock:
            for node in self.nodes:
                if node.node_id == node_id:
                    node.health = 0.0
                    node.synchronized = False
                    return

    def resurrect(
        self,
        node_id: int,
    ) -> bool:
        with self.lock:
            for node in self.nodes:
                if node.node_id == node_id:
                    node.health = 1.0
                    node.synchronized = True
                    node.generation = (
                        self.generation
                    )

                    return True

        return False

    def summary(self) -> dict[str, Any]:
        with self.lock:
            healthy = sum(
                node.health > 0.5
                for node in self.nodes
            )

            synchronized = sum(
                node.synchronized
                for node in self.nodes
            )

            return {
                "generation": self.generation,
                "nodes": len(self.nodes),
                "healthy": healthy,
                "synchronized": synchronized,
            }


# ============================================================
# SAFETY ANALYZER
# ============================================================

class SafetyAnalyzer:

    def __init__(self):
        self.lock = threading.Lock()

        self.history = deque(
            maxlen=512
        )

        self.model = None

        if SKLEARN_AVAILABLE:
            try:
                self.model = (
                    IsolationForest(
                        n_estimators=100,
                        contamination=0.05,
                        random_state=42,
                        n_jobs=-1,
                    )
                )

            except Exception as exc:
                log(
                    f"[ML] Initialization "
                    f"failed: {exc}"
                )

    def add_sample(
        self,
        cpu: float,
        ram: float,
        vram: float,
        network_rate: float,
        swarm_health: float,
    ) -> Optional[int]:

        vector = np.asarray(
            [[
                cpu,
                ram,
                vram,
                network_rate,
                swarm_health,
            ]],
            dtype=np.float32,
        )

        with self.lock:
            self.history.append(
                vector[0]
            )

            if self.model is None:
                return None

            if len(self.history) < 32:
                return None

            try:
                matrix = np.asarray(
                    self.history,
                    dtype=np.float32,
                )

                self.model.fit(
                    matrix
                )

                return int(
                    self.model.predict(
                        vector
                    )[0]
                )

            except Exception as exc:
                log(
                    f"[ML] Prediction failed: "
                    f"{exc}"
                )

                return None

    def status(self) -> str:
        with self.lock:
            if self.model is None:
                return (
                    "ML unavailable / "
                    "baseline mode"
                )

            if len(self.history) < 32:
                return (
                    "ML warming up "
                    f"({len(self.history)}/32)"
                )

            return (
                "IsolationForest active"
            )


# ============================================================
# SURICATA WORKER
# ============================================================

class SuricataIngestor:

    def __init__(
        self,
        path: str = DEFAULT_SURICATA_EVE,
    ):
        self.path = Path(path)

        self.events = deque(
            maxlen=500
        )

        self.total_events = 0
        self.alerts = 0

        self.lock = threading.Lock()

        self.stop_event = (
            threading.Event()
        )

        self.thread: Optional[
            threading.Thread
        ] = None

    def start(self) -> None:
        if (
            self.thread is not None and
            self.thread.is_alive()
        ):
            return

        self.stop_event.clear()

        self.thread = threading.Thread(
            target=self._reader,
            name="SuricataReader",
            daemon=True,
        )

        self.thread.start()

        log(
            "[SURICATA] Reader worker started"
        )

    def stop(self) -> None:
        self.stop_event.set()

    def _reader(self) -> None:
        if not self.path.exists():
            log(
                f"[SURICATA] EVE file not found: "
                f"{self.path}"
            )

            return

        try:
            with self.path.open(
                "r",
                encoding="utf-8",
                errors="replace",
            ) as handle:

                handle.seek(
                    0,
                    os.SEEK_END,
                )

                while not (
                    self.stop_event.is_set()
                ):
                    line = (
                        handle.readline()
                    )

                    if line:
                        self.process_line(
                            line
                        )

                        continue

                    self.stop_event.wait(
                        SURICATA_IDLE_SLEEP
                    )

        except Exception as exc:
            log(
                f"[SURICATA] Reader error: "
                f"{exc}"
            )

    def process_line(
        self,
        line: str,
    ) -> None:
        try:
            event = json.loads(
                line
            )

        except json.JSONDecodeError:
            return

        with self.lock:
            self.total_events += 1

            if (
                event.get(
                    "event_type"
                )
                == "alert"
            ):
                self.alerts += 1

            self.events.append(
                event
            )

    def recent_rate(self) -> float:
        with self.lock:
            return float(
                min(
                    self.total_events,
                    1000,
                )
            )

    def summary(self) -> dict[str, int]:
        with self.lock:
            return {
                "events": self.total_events,
                "alerts": self.alerts,
            }


# ============================================================
# WATCHDOG
# ============================================================

class Watchdog:

    def __init__(self):
        self.lock = threading.Lock()

        self.components: dict[
            str,
            threading.Thread,
        ] = {}

        self.resurrections = 0

    def register(
        self,
        name: str,
        thread: threading.Thread,
    ) -> None:
        with self.lock:
            self.components[
                name
            ] = thread

    def check(self) -> list[str]:
        dead = []

        with self.lock:
            for name, thread in (
                self.components.items()
            ):
                if not thread.is_alive():
                    dead.append(
                        name
                    )

        return dead

    def record_dead(
        self,
        component: str,
    ) -> None:
        with self.lock:
            self.resurrections += 1

        log(
            f"[WATCHDOG] Worker stopped: "
            f"{component}"
        )


# ============================================================
# OVERLAY
# ============================================================

class DeceptionOverlay:

    GLYPHS = {
        "safe": "◆",
        "warning": "▲",
        "critical": "✖",
        "gpu": "⚡",
        "memory": "▣",
        "swarm": "◈",
        "network": "◇",
        "watchdog": "♜",
    }

    def render(
        self,
        status: str,
        message: str,
    ) -> str:
        glyph = self.GLYPHS.get(
            status,
            self.GLYPHS["safe"],
        )

        return (
            f"{glyph} {message}"
        )


# ============================================================
# SYSTEM METRICS
# ============================================================

_CPU_STATE = {
    "total": None,
    "idle": None,
}


def get_cpu_percent() -> float:
    """
    Linux /proc CPU measurement.

    No scheduler is created. The caller explicitly invokes this
    function when metrics are requested.
    """
    if not Path(
        "/proc/stat"
    ).exists():
        return 0.0

    try:
        line = (
            Path(
                "/proc/stat"
            )
            .read_text()
            .splitlines()[0]
        )

        values = line.split()[1:]

        if len(values) < 4:
            return 0.0

        numbers = [
            int(value)
            for value in values
        ]

        idle = numbers[3]

        if len(numbers) > 4:
            idle += numbers[4]

        total = sum(numbers)

        previous_total = (
            _CPU_STATE["total"]
        )

        previous_idle = (
            _CPU_STATE["idle"]
        )

        _CPU_STATE["total"] = total
        _CPU_STATE["idle"] = idle

        if (
            previous_total is None or
            previous_idle is None
        ):
            return 0.0

        total_delta = (
            total -
            previous_total
        )

        idle_delta = (
            idle -
            previous_idle
        )

        if total_delta <= 0:
            return 0.0

        return max(
            0.0,
            min(
                100.0,
                (
                    1.0 -
                    idle_delta /
                    total_delta
                ) *
                100.0,
            ),
        )

    except Exception:
        return 0.0


def get_system_metrics() -> dict[str, float]:
    metrics = {
        "cpu": get_cpu_percent(),
        "ram": 0.0,
    }

    try:
        meminfo = Path(
            "/proc/meminfo"
        )

        if meminfo.exists():
            values = {}

            for line in (
                meminfo
                .read_text()
                .splitlines()
            ):
                parts = line.split()

                if len(parts) >= 2:
                    try:
                        values[
                            parts[0]
                            .rstrip(":")
                        ] = (
                            float(parts[1])
                            * 1024
                        )

                    except ValueError:
                        pass

            total = values.get(
                "MemTotal",
                0,
            )

            available = values.get(
                "MemAvailable",
                0,
            )

            if total > 0:
                metrics["ram"] = (
                    (
                        total -
                        available
                    )
                    /
                    total
                    *
                    100.0
                )

    except Exception:
        pass

    return metrics


# ============================================================
# SUPERVISOR
# ============================================================

class Supervisor:
    """
    Central lifecycle manager.

    This follows the boot model from the working bridge code.

        Supervisor.start()
            |
            +-- initialize memory
            +-- initialize CUDA
            +-- start Suricata worker
            +-- perform initial metrics
            +-- report ready

    No periodic scheduler is created.
    """

    def __init__(self):
        self.running = False

        self.lock = threading.RLock()

        self.memory: Optional[
            HybridMemoryManager
        ] = None

        self.swarm: Optional[
            SwarmSimulator
        ] = None

        self.safety: Optional[
            SafetyAnalyzer
        ] = None

        self.suricata: Optional[
            SuricataIngestor
        ] = None

        self.overlay = (
            DeceptionOverlay()
        )

        self.watchdog = (
            Watchdog()
        )

        self.health_status = "safe"

        self.health_message = (
            "Supervisor not started"
        )

        self.last_metrics = {}

        self.last_ml_result = None

    # --------------------------------------------------------
    # START
    # --------------------------------------------------------

    def start(self) -> None:
        with self.lock:
            if self.running:
                return

            log(
                f"[SUP] Starting {APP_NAME}"
            )

            # ------------------------------------------------
            # CORE MEMORY
            # ------------------------------------------------

            try:
                self.memory = (
                    HybridMemoryManager()
                )

                log(
                    "[SUP] Hybrid memory "
                    "manager initialized"
                )

            except Exception as exc:
                log(
                    f"[SUP] Memory manager "
                    f"initialization failed: {exc}"
                )

                self.memory = None

            # ------------------------------------------------
            # SWARM
            # ------------------------------------------------

            try:
                self.swarm = (
                    SwarmSimulator()
                )

                log(
                    "[SUP] Swarm subsystem "
                    "initialized"
                )

            except Exception as exc:
                log(
                    f"[SUP] Swarm initialization "
                    f"failed: {exc}"
                )

                self.swarm = None

            # ------------------------------------------------
            # ML
            # ------------------------------------------------

            try:
                self.safety = (
                    SafetyAnalyzer()
                )

                log(
                    "[SUP] Safety analyzer "
                    "initialized"
                )

            except Exception as exc:
                log(
                    f"[SUP] Safety analyzer "
                    f"failed: {exc}"
                )

                self.safety = None

            # ------------------------------------------------
            # SURICATA
            # ------------------------------------------------

            try:
                self.suricata = (
                    SuricataIngestor(
                        os.environ.get(
                            "SURICATA_EVE",
                            DEFAULT_SURICATA_EVE,
                        )
                    )
                )

                self.suricata.start()

                if (
                    self.suricata.thread
                    is not None
                ):
                    self.watchdog.register(
                        "SuricataReader",
                        self.suricata.thread,
                    )

            except Exception as exc:
                log(
                    f"[SUP] Suricata startup "
                    f"failed: {exc}"
                )

                self.suricata = None

            # ------------------------------------------------
            # RUNNING STATE
            # ------------------------------------------------

            self.running = True

            self.health_status = "safe"

            self.health_message = (
                "Hybrid system online"
            )

            log(
                "[SUP] All available "
                "subsystems started"
            )

        # Initial metrics are explicit.
        self.refresh()

    # --------------------------------------------------------
    # STOP
    # --------------------------------------------------------

    def stop(self) -> None:
        with self.lock:
            if not self.running:
                return

            log(
                "[SUP] Stopping subsystems"
            )

            self.running = False

            if self.suricata is not None:
                self.suricata.stop()

                thread = (
                    self.suricata.thread
                )

                if (
                    thread is not None and
                    thread.is_alive()
                ):
                    thread.join(
                        timeout=1.5
                    )

            self.memory = None

            gc.collect()

            log(
                "[SUP] All subsystems stopped"
            )

    # --------------------------------------------------------
    # REFRESH
    # --------------------------------------------------------

    def refresh(self) -> None:
        """
        Explicit metrics refresh.

        There is intentionally no automatic timer.
        """
        with self.lock:
            if not self.running:
                return

            if self.memory is None:
                return

            try:
                self.memory.refresh_gpu()

                metrics = (
                    get_system_metrics()
                )

                gpu = self.memory.gpu

                vram_percent = 0.0

                if gpu.total_vram > 0:
                    used = (
                        gpu.total_vram -
                        gpu.free_vram
                    )

                    vram_percent = (
                        used /
                        gpu.total_vram
                        *
                        100.0
                    )

                swarm_summary = (
                    self.swarm.summary()
                    if self.swarm
                    else {
                        "healthy": 0,
                        "nodes": 1,
                    }
                )

                swarm_health = (
                    swarm_summary["healthy"]
                    /
                    max(
                        1,
                        swarm_summary["nodes"],
                    )
                )

                network_rate = 0.0

                if self.suricata:
                    network_rate = (
                        self.suricata
                        .recent_rate()
                    )

                ml_result = None

                if self.safety:
                    ml_result = (
                        self.safety
                        .add_sample(
                            metrics["cpu"],
                            metrics["ram"],
                            vram_percent,
                            network_rate,
                            swarm_health,
                        )
                    )

                self.last_metrics = {
                    **metrics,
                    "vram_percent":
                        vram_percent,
                }

                self.last_ml_result = (
                    ml_result
                )

                if (
                    metrics["ram"] >
                    95.0
                    or
                    vram_percent >
                    95.0
                ):
                    self.health_status = (
                        "critical"
                    )

                    self.health_message = (
                        "Memory pressure detected"
                    )

                elif ml_result == -1:
                    self.health_status = (
                        "warning"
                    )

                    self.health_message = (
                        "IsolationForest anomaly "
                        "detected"
                    )

                else:
                    self.health_status = (
                        "safe"
                    )

                    self.health_message = (
                        "Hybrid memory system nominal"
                    )

            except Exception as exc:
                self.health_status = (
                    "warning"
                )

                self.health_message = (
                    f"Refresh failed: {exc}"
                )

                log(
                    f"[SUP] Refresh error: {exc}"
                )

    # --------------------------------------------------------
    # WORKER CHECK
    # --------------------------------------------------------

    def check_workers(self) -> list[str]:
        dead = (
            self.watchdog.check()
        )

        for component in dead:
            self.watchdog.record_dead(
                component
            )

        return dead

    # --------------------------------------------------------
    # GPU TURBO
    # --------------------------------------------------------

    def run_turbo(
        self,
        elements: int = DEFAULT_GPU_ELEMENTS,
    ) -> None:
        def worker() -> None:
            gpu_turbo_boost(
                elements
            )

            self.refresh()

        thread = threading.Thread(
            target=worker,
            name="GPUTurboWorker",
            daemon=True,
        )

        thread.start()

    # --------------------------------------------------------
    # SWARM
    # --------------------------------------------------------

    def sync_swarm(self) -> None:
        if self.swarm is None:
            return

        self.swarm.synchronize()

        self.refresh()

    # --------------------------------------------------------
    # MEMORY TEST
    # --------------------------------------------------------

    def test_hybrid_memory(self) -> None:
        if self.memory is None:
            log(
                "[MEM] Memory subsystem "
                "unavailable"
            )

            return

        elements = 8_000_000

        log(
            "[MEM] Hybrid memory test: "
            f"{elements:,} float32 elements"
        )

        block_id = None

        try:
            block_id = (
                self.memory.allocate(
                    elements,
                    dtype=np.float32,
                    prefer_vram=True,
                )
            )

            stats = (
                self.memory.stats()
            )

            resident = False

            with self.memory.lock:
                block = (
                    self.memory.blocks.get(
                        block_id
                    )
                )

                if block:
                    resident = (
                        block.device_resident
                    )

            log(
                "[MEM] Host backing: "
                f"{format_bytes(stats['host_bytes'])}"
            )

            log(
                "[MEM] VRAM used: "
                f"{format_bytes(stats['vram_used'])}"
            )

            log(
                "[MEM] VRAM budget: "
                f"{format_bytes(stats['vram_budget'])}"
            )

            log(
                "[MEM] Device resident: "
                f"{resident}"
            )

        except Exception as exc:
            log(
                f"[MEM] Test failed: {exc}"
            )

        finally:
            if block_id is not None:
                self.memory.release(
                    block_id
                )

                log(
                    "[MEM] Test block released"
                )

            self.refresh()

    # --------------------------------------------------------
    # STATUS
    # --------------------------------------------------------

    def get_status(
        self,
    ) -> dict[str, Any]:

        gpu = (
            self.memory.gpu
            if self.memory
            else GPUInfo()
        )

        memory_stats = (
            self.memory.stats()
            if self.memory
            else {
                "blocks": 0,
                "vram_resident_blocks": 0,
                "host_bytes": 0,
                "vram_used": 0,
                "vram_budget": 0,
            }
        )

        swarm = (
            self.swarm.summary()
            if self.swarm
            else {
                "generation": 0,
                "nodes": 0,
                "healthy": 0,
                "synchronized": 0,
            }
        )

        suricata = (
            self.suricata.summary()
            if self.suricata
            else {
                "events": 0,
                "alerts": 0,
            }
        )

        return {
            "running": self.running,
            "health": self.health_status,
            "health_message": (
                self.health_message
            ),
            "cpu": self.last_metrics.get(
                "cpu",
                0.0,
            ),
            "ram": self.last_metrics.get(
                "ram",
                0.0,
            ),
            "vram_percent": (
                self.last_metrics.get(
                    "vram_percent",
                    0.0,
                )
            ),
            "gpu": {
                "available":
                    gpu.available,
                "name":
                    gpu.name,
                "total_vram":
                    gpu.total_vram,
                "free_vram":
                    gpu.free_vram,
                "compute_capability":
                    gpu.compute_capability,
            },
            "memory": {
                "blocks":
                    memory_stats["blocks"],
                "resident_blocks":
                    memory_stats[
                        "vram_resident_blocks"
                    ],
                "host_bytes":
                    memory_stats[
                        "host_bytes"
                    ],
                "vram_used":
                    memory_stats[
                        "vram_used"
                    ],
                "vram_budget":
                    memory_stats[
                        "vram_budget"
                    ],
            },
            "swarm": swarm,
            "suricata": suricata,
            "ml_prediction":
                self.last_ml_result,
            "watchdog": {
                "resurrections":
                    self.watchdog.resurrections,
            },
        }

    # --------------------------------------------------------
    # DASHBOARD
    # --------------------------------------------------------

    def snapshot(self) -> list[str]:
        self.refresh()

        status = (
            self.get_status()
        )

        gpu = status["gpu"]
        memory = status["memory"]
        swarm = status["swarm"]
        suricata = status["suricata"]

        overlay = (
            self.overlay.render(
                status["health"],
                status["health_message"],
            )
        )

        ml_status = (
            self.safety.status()
            if self.safety
            else "ML unavailable"
        )

        return [
            APP_NAME,
            "=" * 72,
            "",
            "SYSTEM",
            (
                f"  CPU:                "
                f"{status['cpu']:.1f}%"
            ),
            (
                f"  RAM:                "
                f"{status['ram']:.1f}%"
            ),
            "",
            "HYBRID MEMORY",
            (
                "  Host backing:       "
                f"{format_bytes(memory['host_bytes'])}"
            ),
            (
                "  VRAM tier:          "
                f"{format_bytes(memory['vram_used'])}"
            ),
            (
                "  VRAM budget:        "
                f"{format_bytes(memory['vram_budget'])}"
            ),
            (
                "  Resident blocks:    "
                f"{memory['resident_blocks']}"
            ),
            "",
            "GPU",
            (
                f"  CUDA available:     "
                f"{gpu['available']}"
            ),
            (
                f"  Device:             "
                f"{gpu['name']}"
            ),
            (
                f"  VRAM total:         "
                f"{format_bytes(gpu['total_vram'])}"
            ),
            (
                f"  VRAM free:          "
                f"{format_bytes(gpu['free_vram'])}"
            ),
            (
                f"  VRAM utilization:   "
                f"{status['vram_percent']:.1f}%"
            ),
            (
                f"  Compute capability: "
                f"{gpu['compute_capability']}"
            ),
            "",
            "CUDA OPTIMIZATION",
            (
                "  Kernel:             "
                "grid-stride"
            ),
            (
                "  Host buffers:       "
                "pinned when supported"
            ),
            (
                "  Transfers:          "
                "stream-aware"
            ),
            (
                "  Threads/block:      "
                f"{CUDA_THREADS_PER_BLOCK}"
            ),
            "",
            "SWARM",
            (
                f"  Generation:         "
                f"{swarm['generation']}"
            ),
            (
                f"  Nodes:              "
                f"{swarm['nodes']}"
            ),
            (
                f"  Healthy:            "
                f"{swarm['healthy']}"
            ),
            (
                f"  Synchronized:       "
                f"{swarm['synchronized']}"
            ),
            "",
            "SURICATA",
            (
                f"  EVE file:           "
                f"{self.suricata.path if self.suricata else 'N/A'}"
            ),
            (
                f"  Events:             "
                f"{suricata['events']}"
            ),
            (
                f"  Alerts:             "
                f"{suricata['alerts']}"
            ),
            "",
            "SAFETY ANALYZER",
            (
                f"  Status:             "
                f"{ml_status}"
            ),
            (
                f"  Prediction:         "
                f"{status['ml_prediction']}"
            ),
            "",
            "WATCHDOG",
            (
                f"  Worker stops:       "
                f"{status['watchdog']['resurrections']}"
            ),
            "",
            overlay,
        ]


# ============================================================
# GUI
# ============================================================

def launch_gui(
    supervisor: Supervisor,
) -> None:
    """
    Launch GUI only after Supervisor has successfully booted.

    No periodic Tk scheduler is used.
    """
    try:
        import tkinter as tk
        from tkinter import ttk

    except Exception as exc:
        log(
            f"[GUI] Tkinter unavailable: "
            f"{exc}"
        )

        return

    try:
        root = tk.Tk()

    except Exception as exc:
        log(
            f"[GUI] Could not create window: "
            f"{exc}"
        )

        return

    root.title(
        APP_NAME
    )

    root.geometry(
        "1150x760"
    )

    root.minsize(
        900,
        600,
    )

    # --------------------------------------------------------
    # WINDOWS DPI
    # --------------------------------------------------------

    if os.name == "nt":
        try:
            import ctypes

            ctypes.windll.shcore.SetProcessDpiAwareness(
                1
            )

        except Exception:
            pass

    # --------------------------------------------------------
    # STYLE
    # --------------------------------------------------------

    style = ttk.Style(
        root
    )

    try:
        style.theme_use(
            "clam"
        )

    except Exception:
        pass

    style.configure(
        "Ribbon.TFrame",
        background="#172033",
    )

    style.configure(
        "Ribbon.TButton",
        background="#26344D",
        foreground="white",
        padding=(12, 7),
    )

    style.configure(
        "Title.TLabel",
        background="#172033",
        foreground="white",
        font=(
            "Segoe UI",
            16,
            "bold",
        ),
    )

    # --------------------------------------------------------
    # RIBBON
    # --------------------------------------------------------

    ribbon = ttk.Frame(
        root,
        style="Ribbon.TFrame",
        padding=10,
    )

    ribbon.pack(
        side="top",
        fill="x",
    )

    ttk.Label(
        ribbon,
        text="HYBRID v14",
        style="Title.TLabel",
    ).pack(
        side="left",
        padx=(0, 20),
    )

    # --------------------------------------------------------
    # MAIN TEXT
    # --------------------------------------------------------

    text = tk.Text(
        root,
        bg="#101722",
        fg="#D7E3F4",
        insertbackground="white",
        font=(
            "Consolas",
            11,
        ),
        relief="flat",
        padx=15,
        pady=15,
    )

    text.pack(
        fill="both",
        expand=True,
        padx=15,
        pady=15,
    )

    status_var = tk.StringVar(
        value="Ready"
    )

    status_label = ttk.Label(
        root,
        textvariable=status_var,
        anchor="w",
        padding=8,
    )

    status_label.pack(
        side="bottom",
        fill="x",
    )

    # --------------------------------------------------------
    # EXPLICIT REFRESH
    # --------------------------------------------------------

    def refresh_view() -> None:
        try:
            lines = (
                supervisor.snapshot()
            )

            text.delete(
                "1.0",
                "end",
            )

            text.insert(
                "end",
                "\n".join(lines),
            )

            status_var.set(
                supervisor.overlay.render(
                    supervisor.health_status,
                    supervisor.health_message,
                )
            )

        except Exception as exc:
            log(
                f"[GUI] Refresh error: "
                f"{exc}"
            )

            status_var.set(
                f"GUI error: {exc}"
            )

    # --------------------------------------------------------
    # WORKER WRAPPERS
    # --------------------------------------------------------

    def turbo_worker() -> None:
        supervisor.run_turbo()

        try:
            root.after_idle(
                refresh_view
            )

        except Exception:
            pass

    def memory_worker() -> None:
        supervisor.test_hybrid_memory()

        try:
            root.after_idle(
                refresh_view
            )

        except Exception:
            pass

    # --------------------------------------------------------
    # BUTTONS
    # --------------------------------------------------------

    ttk.Button(
        ribbon,
        text="GPU Turbo",
        style="Ribbon.TButton",
        command=lambda: threading.Thread(
            target=turbo_worker,
            name="GPUTurboWorker",
            daemon=True,
        ).start(),
    ).pack(
        side="left",
        padx=4,
    )

    ttk.Button(
        ribbon,
        text="Sync Swarm",
        style="Ribbon.TButton",
        command=lambda: (
            supervisor.sync_swarm(),
            refresh_view(),
        ),
    ).pack(
        side="left",
        padx=4,
    )

    ttk.Button(
        ribbon,
        text="Hybrid Memory",
        style="Ribbon.TButton",
        command=lambda: threading.Thread(
            target=memory_worker,
            name="HybridMemoryWorker",
            daemon=True,
        ).start(),
    ).pack(
        side="left",
        padx=4,
    )

    ttk.Button(
        ribbon,
        text="Refresh",
        style="Ribbon.TButton",
        command=refresh_view,
    ).pack(
        side="left",
        padx=4,
    )

    ttk.Button(
        ribbon,
        text="Check Workers",
        style="Ribbon.TButton",
        command=lambda: (
            supervisor.check_workers(),
            refresh_view(),
        ),
    ).pack(
        side="left",
        padx=4,
    )

    # --------------------------------------------------------
    # INITIAL VIEW
    # --------------------------------------------------------

    refresh_view()

    # --------------------------------------------------------
    # CLOSE
    # --------------------------------------------------------

    def close_gui() -> None:
        log(
            "[GUI] Closing application"
        )

        supervisor.stop()

        try:
            root.destroy()

        except Exception:
            pass

    root.protocol(
        "WM_DELETE_WINDOW",
        close_gui,
    )

    root.mainloop()


# ============================================================
# SIGNAL HANDLING
# ============================================================

_APP: Optional[
    Supervisor
] = None


def handle_signal(
    signum,
    frame,
) -> None:
    del frame

    log(
        f"[MAIN] Signal received: "
        f"{signum}"
    )

    if _APP is not None:
        _APP.stop()

    raise SystemExit(0)


# ============================================================
# MAIN BOOT
# ============================================================

def main() -> None:
    global _APP

    log(
        "=" * 64
    )

    log(
        APP_NAME
    )

    log(
        "=" * 64
    )

    # --------------------------------------------------------
    # SIGNALS FIRST
    # --------------------------------------------------------

    try:
        signal.signal(
            signal.SIGINT,
            handle_signal,
        )

    except Exception as exc:
        log(
            f"[MAIN] SIGINT setup failed: "
            f"{exc}"
        )

    if hasattr(
        signal,
        "SIGTERM",
    ):
        try:
            signal.signal(
                signal.SIGTERM,
                handle_signal,
            )

        except Exception as exc:
            log(
                f"[MAIN] SIGTERM setup failed: "
                f"{exc}"
            )

    # --------------------------------------------------------
    # SUPERVISOR BOOT
    # --------------------------------------------------------

    supervisor = Supervisor()

    _APP = supervisor

    try:
        supervisor.start()

    except Exception as exc:
        log(
            f"[MAIN] Supervisor startup failed: "
            f"{exc}"
        )

        traceback.print_exc()

        supervisor.stop()

        return

    # --------------------------------------------------------
    # BOOT STATUS
    # --------------------------------------------------------

    log(
        "[MAIN] Supervisor boot complete"
    )

    if supervisor.memory:
        gpu = (
            supervisor.memory.gpu
        )

        if gpu.available:
            log(
                "[GPU] CUDA online | "
                f"{gpu.name} | "
                f"VRAM="
                f"{format_bytes(gpu.total_vram)} | "
                f"CC={gpu.compute_capability}"
            )

        else:
            log(
                "[GPU] CUDA unavailable"
            )

    log(
        "[MAIN] Scheduler-free mode enabled"
    )

    log(
        "[MAIN] Periodic monitor: disabled"
    )

    log(
        "[MAIN] Tkinter refresh scheduler: disabled"
    )

    log(
        "[MAIN] Watchdog scheduler: disabled"
    )

    # --------------------------------------------------------
    # GUI BOOT
    # --------------------------------------------------------

    log(
        "[MAIN] Launching GUI"
    )

    try:
        launch_gui(
            supervisor
        )

    except KeyboardInterrupt:
        log(
            "[MAIN] Keyboard interrupt"
        )

    except Exception as exc:
        log(
            f"[MAIN] GUI failed: "
            f"{exc}"
        )

        traceback.print_exc()

    finally:
        supervisor.stop()

        log(
            "[MAIN] Shutdown complete"
        )


# ============================================================
# ENTRY POINT
# ============================================================

if __name__ == "__main__":
    main()