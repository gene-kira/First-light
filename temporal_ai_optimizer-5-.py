#!/usr/bin/env python3
"""
Universal Temporal AI Optimizer + DominionDeck GPU Governor (Networked Command Center)
--------------------------------------------------------------------------------------

Integrated system with:

1. Temporal Conv3D ResNet training + optimization.
2. DominionDeck GPU Governor with NVML VRAM/temperature/power telemetry.
3. VRAM stress test + fragmentation probing (safe, bounded).
4. Optuna hyperparameter tuning with robust error handling.
5. Pruning + quantization (when supported).
6. Training curve visualization (PNG).
7. Real swarm sync over TCP (simple JSON protocol).
8. Plugin API for extensibility.
9. Animated GUI overlays (glyph-based status).
10. Auto-scaling of batch size based on VRAM readiness.
11. Threat matrix integration (CPU/GPU/system risk scoring).
12. Training telemetry streaming to swarm peers.
13. Daemonized watchdog loop.

Safety:
- Read-only telemetry only.
- No overclocking, no undervolting, no fan control.
- All optional features degrade gracefully when unavailable.

IMPORTANT:
- Synthetic dataset; replace load_temporal_data() with real video/sequence loader.
- Does NOT change Windows system settings or hardware parameters.
"""

from __future__ import annotations

import importlib
import json
import os
import platform
import socket
import subprocess
import sys
import time
import traceback
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any, Optional, Tuple, Callable, Dict, List

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

APP_NAME = "Universal Temporal AI Optimizer + DominionDeck"
APP_VERSION = "5.0"
BASE_DIR = Path(__file__).resolve().parent
OUTPUT_DIR = BASE_DIR / "temporal_optimizer_output"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

MODEL_FILE = OUTPUT_DIR / "temporal_resnet.keras"
OPTIMIZED_MODEL_FILE = OUTPUT_DIR / "temporal_resnet_optimized.keras"
REPORT_FILE = OUTPUT_DIR / "performance_report.json"
LOG_FILE = OUTPUT_DIR / "optimizer.log"
CURVE_FILE = OUTPUT_DIR / "training_curves.png"

SEQ_LENGTH = 5
IMAGE_HEIGHT = 64
IMAGE_WIDTH = 64
CHANNELS = 3
NUM_CLASSES = 10

SYNTHETIC_SAMPLES = 800
BASE_BATCH_SIZE = 16
TUNING_TRIALS = 5
TUNING_EPOCHS = 3
FINAL_EPOCHS = 15

GOVERNOR_POLL_INTERVAL = 2.0
GUI_REFRESH_INTERVAL_MS = 1000
WATCHDOG_ENABLED = True
GUI_ENABLED = True

VRAM_STRESS_MAX_GB = 1.0  # upper bound for stress test allocation
FRAGMENTATION_PROBE_BLOCK_MB = 64  # block size for fragmentation probing

SWARM_PORT = 55555
SWARM_PEERS = []  # e.g. ["127.0.0.1:55556", "192.168.1.10:55555"]

REQUIRED_PACKAGES = {
    "numpy": "numpy>=1.24",
    "tensorflow": "tensorflow>=2.15",
}

OPTIONAL_PACKAGES = {
    "optuna": "optuna>=3.5",
    "tensorflow_model_optimization": "tensorflow-model-optimization>=0.8",
    "psutil": "psutil>=5.9",
    "pynvml": "pynvml>=11.5",
    "matplotlib": "matplotlib>=3.8",
}

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------

def log(message: str) -> None:
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line, flush=True)
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def section(title: str) -> None:
    log("")
    log("=" * 72)
    log(title)
    log("=" * 72)


# ---------------------------------------------------------------------------
# Dependency loader
# ---------------------------------------------------------------------------

def package_import_name(package: str) -> str:
    return {
        "tensorflow-model-optimization": "tensorflow_model_optimization",
    }.get(package, package)


def pip_install(spec: str) -> bool:
    log(f"[LIB] Installing: {spec}")
    try:
        subprocess.check_call(
            [sys.executable, "-m", "pip", "install", spec],
            stdout=subprocess.DEVNULL,
        )
        return True
    except Exception as exc:
        log(f"[LIB] Installation failed: {exc}")
        return False


def ensure_libraries() -> dict[str, bool]:
    section("LIBRARY CHECK")

    auto_install = os.environ.get("TAI_AUTO_INSTALL", "1").lower() not in {
        "0", "false", "no"
    }

    status: dict[str, bool] = {}

    all_packages = {}
    all_packages.update(REQUIRED_PACKAGES)
    all_packages.update(OPTIONAL_PACKAGES)

    for package, spec in all_packages.items():
        module = package_import_name(package)
        try:
            importlib.import_module(module)
            status[package] = True
            log(f"[LIB] OK: {package}")
        except ImportError:
            if package in REQUIRED_PACKAGES and not auto_install:
                status[package] = False
                log(f"[LIB] MISSING REQUIRED: {package}")
            elif auto_install:
                status[package] = pip_install(spec)
                if status[package]:
                    try:
                        importlib.import_module(module)
                    except ImportError:
                        status[package] = False
            else:
                status[package] = False
                log(f"[LIB] Optional library unavailable: {package}")

    missing_required = [
        p for p in REQUIRED_PACKAGES if not status.get(p, False)
    ]
    if missing_required:
        raise RuntimeError(
            "Required libraries are missing: "
            + ", ".join(missing_required)
            + ". Run with TAI_AUTO_INSTALL=1 or install them manually."
        )

    return status


# ---------------------------------------------------------------------------
# Imports after dependency preparation
# ---------------------------------------------------------------------------

def load_runtime():
    import numpy as np
    import tensorflow as tf

    try:
        import optuna
    except ImportError:
        optuna = None

    try:
        import tensorflow_model_optimization as tfmot
    except ImportError:
        tfmot = None

    try:
        import psutil
    except ImportError:
        psutil = None

    try:
        import pynvml
    except ImportError:
        pynvml = None

    try:
        import matplotlib.pyplot as plt
    except Exception:
        plt = None

    try:
        import tkinter as tk
        from tkinter import ttk
    except Exception:
        tk = None
        ttk = None

    return np, tf, optuna, tfmot, psutil, pynvml, plt, tk, ttk


# ---------------------------------------------------------------------------
# Hardware detection
# ---------------------------------------------------------------------------

@dataclass
class HardwareInfo:
    system: str
    python: str
    tensorflow: str
    cpu_count: int
    gpu_count: int
    gpus: list[str]
    mixed_precision: bool


def detect_hardware(tf) -> HardwareInfo:
    section("HARDWARE DETECTION")

    gpus = tf.config.list_physical_devices("GPU")
    cpus = tf.config.list_physical_devices("CPU")

    gpu_names = [str(g) for g in gpus]

    for gpu in gpus:
        try:
            tf.config.experimental.set_memory_growth(gpu, True)
        except Exception as exc:
            log(f"[GPU] Memory-growth setup skipped: {exc}")

    mixed_precision_supported = bool(gpus)

    info = HardwareInfo(
        system=platform.platform(),
        python=platform.python_version(),
        tensorflow=tf.__version__,
        cpu_count=os.cpu_count() or 1,
        gpu_count=len(gpus),
        gpus=gpu_names,
        mixed_precision=mixed_precision_supported,
    )

    log(f"[HW] CPU threads: {info.cpu_count}")
    log(f"[HW] CPUs detected: {len(cpus)}")
    log(f"[HW] GPUs detected: {info.gpu_count}")

    if gpus:
        for index, gpu in enumerate(gpus):
            log(f"[HW] GPU {index}: {gpu}")
    else:
        log("[HW] No TensorFlow GPU detected; CPU mode will be used.")

    return info


def configure_precision(tf, hardware: HardwareInfo) -> None:
    try:
        from tensorflow.keras import mixed_precision

        if hardware.mixed_precision:
            mixed_precision.set_global_policy("mixed_float16")
            log("[PRECISION] mixed_float16 enabled")
        else:
            mixed_precision.set_global_policy("float32")
            log("[PRECISION] float32 selected")
    except Exception as exc:
        log(f"[PRECISION] Could not configure mixed precision: {exc}")


# ---------------------------------------------------------------------------
# Plugin API
# ---------------------------------------------------------------------------

class PluginManager:
    """
    Simple plugin API: plugins can register hooks for events.

    Events:
    - "post_benchmark": args=(report_dict)
    - "post_training": args=(history_dict)
    - "governor_tick": args=(telemetry_dict)
    - "threat_update": args=(threat_dict)
    - "telemetry_stream": args=(telemetry_dict)
    """

    def __init__(self):
        self._hooks: Dict[str, List[Callable[..., None]]] = {}

    def register(self, event: str, func: Callable[..., None]) -> None:
        self._hooks.setdefault(event, []).append(func)
        log(f"[PLUGIN] Registered hook for event '{event}': {func.__name__}")

    def emit(self, event: str, *args, **kwargs) -> None:
        for func in self._hooks.get(event, []):
            try:
                func(*args, **kwargs)
            except Exception as exc:
                log(f"[PLUGIN] Hook '{func.__name__}' failed on '{event}': {exc}")


# ---------------------------------------------------------------------------
# NVML Telemetry / GPU Governor
# ---------------------------------------------------------------------------

@dataclass
class VRAMTelemetry:
    total_gb: float
    used_gb: float
    free_gb: float
    utilization_percent: float
    governor_score: float
    temperature_c: float
    power_w: float
    fragmentation_score: float


class DominionDeckGPUGovernor:
    def __init__(self, tf, psutil: Optional[Any], pynvml: Optional[Any], plugin_mgr: PluginManager):
        self.tf = tf
        self.psutil = psutil
        self.pynvml = pynvml
        self.plugin_mgr = plugin_mgr
        self.last_telemetry: Optional[VRAMTelemetry] = None

        if self.pynvml is not None:
            try:
                self.pynvml.nvmlInit()
                log("[NVML] Initialized.")
            except Exception as exc:
                log(f"[NVML] Init failed: {exc}")
                self.pynvml = None

    def _query_nvml(self) -> Optional[VRAMTelemetry]:
        if self.pynvml is None:
            return None
        try:
            device_count = self.pynvml.nvmlDeviceGetCount()
            if device_count == 0:
                return None

            handle = self.pynvml.nvmlDeviceGetHandleByIndex(0)

            mem = self.pynvml.nvmlDeviceGetMemoryInfo(handle)
            total_gb = mem.total / (1024 ** 3)
            used_gb = mem.used / (1024 ** 3)
            free_gb = mem.free / (1024 ** 3)
            utilization_percent = (used_gb / total_gb) * 100.0 if total_gb > 0 else 0.0

            try:
                temp = self.pynvml.nvmlDeviceGetTemperature(
                    handle, self.pynvml.NVML_TEMPERATURE_GPU
                )
            except Exception:
                temp = 0.0

            try:
                power = self.pynvml.nvmlDeviceGetPowerUsage(handle) / 1000.0
            except Exception:
                power = 0.0

            fragmentation_score = self._probe_fragmentation(total_gb, free_gb)

            governor_score = max(
                0.0,
                min(
                    100.0,
                    (free_gb / total_gb) * 100.0 if total_gb > 0 else 0.0
                ),
            )

            return VRAMTelemetry(
                total_gb=total_gb,
                used_gb=used_gb,
                free_gb=free_gb,
                utilization_percent=utilization_percent,
                governor_score=governor_score,
                temperature_c=float(temp),
                power_w=float(power),
                fragmentation_score=fragmentation_score,
            )
        except Exception as exc:
            log(f"[NVML] Telemetry failed: {exc}")
            return None

    def _probe_fragmentation(self, total_gb: float, free_gb: float) -> float:
        """
        Heuristic fragmentation probe: we assume that if free_gb is high but
        large contiguous allocations fail, fragmentation is high. Here we
        only compute a simple ratio: free_gb / total_gb.
        """
        if total_gb <= 0.0:
            return 0.0
        frag = 1.0 - (free_gb / total_gb)
        score = max(0.0, min(100.0, frag * 100.0))
        return score

    def _query_tf_fallback(self) -> VRAMTelemetry:
        try:
            logical = self.tf.config.list_logical_devices("GPU")
            total_gb = 0.0
            for dev in logical:
                cfg = self.tf.config.experimental.get_device_details(dev)
                mem = cfg.get("memory_limit", 0)
                total_gb += mem / (1024 ** 3)

            if total_gb <= 0.0:
                total_gb = 4.0

            if self.psutil is not None:
                vm = self.psutil.virtual_memory()
                used_ratio = (vm.used / vm.total) if vm.total else 0.0
            else:
                used_ratio = 0.5

            used_gb = total_gb * used_ratio
            free_gb = max(total_gb - used_gb, 0.0)
            utilization_percent = used_ratio * 100.0
            governor_score = max(0.0, min(100.0, (free_gb / total_gb) * 100.0))

            fragmentation_score = self._probe_fragmentation(total_gb, free_gb)

            return VRAMTelemetry(
                total_gb=total_gb,
                used_gb=used_gb,
                free_gb=free_gb,
                utilization_percent=utilization_percent,
                governor_score=governor_score,
                temperature_c=0.0,
                power_w=0.0,
                fragmentation_score=fragmentation_score,
            )
        except Exception as exc:
            log(f"[GOVERNOR] TF fallback telemetry failed: {exc}")
            return VRAMTelemetry(
                total_gb=0.0,
                used_gb=0.0,
                free_gb=0.0,
                utilization_percent=0.0,
                governor_score=0.0,
                temperature_c=0.0,
                power_w=0.0,
                fragmentation_score=0.0,
            )

    def poll(self) -> VRAMTelemetry:
        telemetry = self._query_nvml()
        if telemetry is None:
            telemetry = self._query_tf_fallback()

        self.last_telemetry = telemetry
        log(
            "[GOVERNOR] VRAM total={:.2f}GB used={:.2f}GB free={:.2f}GB "
            "util={:.1f}% score={:.1f} temp={:.1f}C power={:.1f}W frag={:.1f}".format(
                telemetry.total_gb,
                telemetry.used_gb,
                telemetry.free_gb,
                telemetry.utilization_percent,
                telemetry.governor_score,
                telemetry.temperature_c,
                telemetry.power_w,
                telemetry.fragmentation_score,
            )
        )

        self.plugin_mgr.emit("governor_tick", asdict(telemetry))
        self.plugin_mgr.emit("telemetry_stream", asdict(telemetry))
        return telemetry


# ---------------------------------------------------------------------------
# Threat Matrix
# ---------------------------------------------------------------------------

@dataclass
class ThreatMatrix:
    cpu_risk: float
    gpu_risk: float
    memory_risk: float
    thermal_risk: float
    overall_risk: float


def compute_threat_matrix(psutil, telemetry: VRAMTelemetry) -> ThreatMatrix:
    cpu_risk = 0.0
    memory_risk = 0.0
    thermal_risk = 0.0

    if psutil is not None:
        try:
            cpu_percent = psutil.cpu_percent(interval=0.2)
            cpu_risk = min(100.0, cpu_percent)

            mem = psutil.virtual_memory()
            memory_risk = min(100.0, mem.percent)
        except Exception as exc:
            log(f"[THREAT] psutil metrics failed: {exc}")

    if telemetry.temperature_c > 80.0:
        thermal_risk = min(100.0, (telemetry.temperature_c - 70.0) * 3.0)
    else:
        thermal_risk = max(0.0, (telemetry.temperature_c - 40.0) * 1.0)

    gpu_risk = max(
        0.0,
        min(
            100.0,
            telemetry.utilization_percent * 0.7
            + telemetry.fragmentation_score * 0.3,
        ),
    )

    overall = min(
        100.0,
        (cpu_risk + memory_risk + thermal_risk + gpu_risk) / 4.0,
    )

    tm = ThreatMatrix(
        cpu_risk=cpu_risk,
        gpu_risk=gpu_risk,
        memory_risk=memory_risk,
        thermal_risk=thermal_risk,
        overall_risk=overall,
    )
    return tm


# ---------------------------------------------------------------------------
# Swarm Networking
# ---------------------------------------------------------------------------

class SwarmNetwork:
    """
    Simple TCP-based JSON swarm sync.

    Each node:
    - Listens on SWARM_PORT.
    - Sends JSON packets to peers in SWARM_PEERS.
    """

    def __init__(self, plugin_mgr: PluginManager, port: int, peers: List[str]):
        self.plugin_mgr = plugin_mgr
        self.port = port
        self.peers = peers
        self.running = False

    def start_listener(self):
        import threading
        t = threading.Thread(target=self._listener_loop, daemon=True)
        t.start()
        log(f"[SWARM] Listener started on port {self.port}.")

    def _listener_loop(self):
        self.running = True
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            s.bind(("0.0.0.0", self.port))
            s.listen(5)
        except Exception as exc:
            log(f"[SWARM] Listener bind failed: {exc}")
            return

        while self.running:
            try:
                conn, addr = s.accept()
                data = conn.recv(65536)
                conn.close()
                if not data:
                    continue
                try:
                    msg = json.loads(data.decode("utf-8", errors="ignore"))
                    self._handle_message(msg)
                except Exception as exc:
                    log(f"[SWARM] Invalid message: {exc}")
            except Exception as exc:
                log(f"[SWARM] Listener error: {exc}")
                time.sleep(1.0)

    def _handle_message(self, msg: dict[str, Any]):
        kind = msg.get("kind", "")
        if kind == "telemetry":
            self.plugin_mgr.emit("telemetry_stream", msg.get("payload", {}))
        elif kind == "threat":
            self.plugin_mgr.emit("threat_update", msg.get("payload", {}))
        elif kind == "training":
            self.plugin_mgr.emit("post_training", msg.get("payload", {}))

    def broadcast(self, kind: str, payload: dict[str, Any]):
        msg = json.dumps({"kind": kind, "payload": payload}).encode("utf-8")
        for peer in self.peers:
            try:
                host, port_str = peer.split(":")
                port = int(port_str)
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((host, port))
                s.sendall(msg)
                s.close()
            except Exception:
                # Silent failure; swarm is best-effort
                continue


# ---------------------------------------------------------------------------
# Swarm State
# ---------------------------------------------------------------------------

@dataclass
class SwarmNodeState:
    node_id: str
    governor_score: float
    vram_free_gb: float
    temperature_c: float
    overall_risk: float


class DominionDeckSwarm:
    """
    Swarm of nodes sharing governor scores and threat matrix.
    """

    def __init__(self, plugin_mgr: PluginManager, network: SwarmNetwork):
        self.plugin_mgr = plugin_mgr
        self.network = network
        self.nodes: List[SwarmNodeState] = []
        self.local_id = f"{socket.gethostname()}:{SWARM_PORT}"

    def update_local(self, telemetry: VRAMTelemetry, threat: ThreatMatrix):
        local = SwarmNodeState(
            node_id=self.local_id,
            governor_score=telemetry.governor_score,
            vram_free_gb=telemetry.free_gb,
            temperature_c=telemetry.temperature_c,
            overall_risk=threat.overall_risk,
        )
        self._upsert_node(local)
        self.network.broadcast(
            "telemetry",
            {
                "node_id": local.node_id,
                "governor_score": local.governor_score,
                "vram_free_gb": local.vram_free_gb,
                "temperature_c": local.temperature_c,
                "overall_risk": local.overall_risk,
            },
        )

    def ingest_remote(self, payload: dict[str, Any]):
        try:
            node = SwarmNodeState(
                node_id=payload.get("node_id", "remote"),
                governor_score=float(payload.get("governor_score", 0.0)),
                vram_free_gb=float(payload.get("vram_free_gb", 0.0)),
                temperature_c=float(payload.get("temperature_c", 0.0)),
                overall_risk=float(payload.get("overall_risk", 0.0)),
            )
            self._upsert_node(node)
        except Exception as exc:
            log(f"[SWARM] Remote ingest failed: {exc}")

    def _upsert_node(self, node: SwarmNodeState):
        for i, n in enumerate(self.nodes):
            if n.node_id == node.node_id:
                self.nodes[i] = node
                break
        else:
            self.nodes.append(node)

    def summary(self) -> dict[str, Any]:
        if not self.nodes:
            return {"nodes": []}
        avg_score = sum(n.governor_score for n in self.nodes) / len(self.nodes)
        avg_risk = sum(n.overall_risk for n in self.nodes) / len(self.nodes)
        return {
            "nodes": [asdict(n) for n in self.nodes],
            "average_governor_score": avg_score,
            "average_overall_risk": avg_risk,
        }


# ---------------------------------------------------------------------------
# VRAM Stress Test
# ---------------------------------------------------------------------------

def vram_stress_test(tf, np, telemetry: VRAMTelemetry) -> dict[str, Any]:
    section("VRAM STRESS TEST")

    if telemetry.total_gb <= 0.0:
        log("[STRESS] No VRAM info; skipping.")
        return {"status": "skipped", "reason": "no_vram_info"}

    target_gb = min(VRAM_STRESS_MAX_GB, telemetry.free_gb * 0.5)
    if target_gb <= 0.0:
        log("[STRESS] No free VRAM; skipping.")
        return {"status": "skipped", "reason": "no_free_vram"}

    bytes_to_alloc = int(target_gb * (1024 ** 3))
    log(f"[STRESS] Attempting allocation of ~{target_gb:.2f}GB ({bytes_to_alloc} bytes).")

    try:
        gpus = tf.config.list_physical_devices("GPU")
        if gpus:
            with tf.device("/GPU:0"):
                arr = tf.zeros(bytes_to_alloc // 4, dtype=tf.float32)
                _ = arr + 1.0
        else:
            arr = np.zeros(bytes_to_alloc // 4, dtype="float32")
            _ = arr + 1.0

        log("[STRESS] Allocation succeeded.")
        return {
            "status": "success",
            "allocated_gb": target_gb,
        }
    except Exception as exc:
        log(f"[STRESS] Allocation failed safely: {exc}")
        return {
            "status": "failed",
            "reason": str(exc),
        }


# ---------------------------------------------------------------------------
# GUI Panel (Animated Glyph Overlays)
# ---------------------------------------------------------------------------

class DominionDeckGUI:
    def __init__(
        self,
        tk,
        ttk,
        hardware: HardwareInfo,
        governor: DominionDeckGPUGovernor,
        swarm: DominionDeckSwarm,
        training_state: dict[str, Any],
    ):
        self.tk = tk
        self.ttk = ttk
        self.hardware = hardware
        self.governor = governor
        self.swarm = swarm
        self.training_state = training_state
        self.root = None
        self.labels = {}
        self.animation_phase = 0

    def _create_layout(self):
        self.root = self.tk.Tk()
        self.root.title(f"{APP_NAME} Dashboard")

        frame = self.ttk.Frame(self.root, padding=10)
        frame.grid(row=0, column=0, sticky="nsew")

        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)

        def add_label(row, text):
            lbl = self.ttk.Label(frame, text=text, anchor="w")
            lbl.grid(row=row, column=0, sticky="w", pady=2)
            return lbl

        row = 0
        self.labels["system"] = add_label(
            row,
            f"System: {self.hardware.system}",
        )
        row += 1
        self.labels["python"] = add_label(
            row,
            f"Python: {self.hardware.python}",
        )
        row += 1
        self.labels["tensorflow"] = add_label(
            row,
            f"TensorFlow: {self.hardware.tensorflow}",
        )
        row += 1
        self.labels["gpus"] = add_label(
            row,
            f"GPUs: {self.hardware.gpu_count} ({', '.join(self.hardware.gpus)})",
        )
        row += 1

        self.labels["vram"] = add_label(row, "VRAM: n/a")
        row += 1
        self.labels["score"] = add_label(row, "Governor score: n/a")
        row += 1
        self.labels["temp"] = add_label(row, "Temperature: n/a")
        row += 1
        self.labels["power"] = add_label(row, "Power: n/a")
        row += 1
        self.labels["frag"] = add_label(row, "Fragmentation: n/a")
        row += 1

        self.labels["training"] = add_label(
            row,
            "Training: not started",
        )
        row += 1
        self.labels["accuracy"] = add_label(
            row,
            "Best val accuracy: n/a",
        )
        row += 1

        self.labels["swarm"] = add_label(
            row,
            "Swarm: n/a",
        )
        row += 1

        self.labels["glyph"] = add_label(
            row,
            "Glyph: [idle]",
        )

    def _glyph_for_state(self, telemetry: VRAMTelemetry, threat: ThreatMatrix) -> str:
        if threat.overall_risk > 80.0:
            return "⛔ CRITICAL"
        elif threat.overall_risk > 60.0:
            return "⚠ HIGH"
        elif telemetry.governor_score < 30.0:
            return "🌀 LOW_READY"
        else:
            return "✅ STABLE"

    def _animate_overlay(self, telemetry: VRAMTelemetry, threat: ThreatMatrix):
        self.animation_phase = (self.animation_phase + 1) % 3
        phase_colors = ["#00ff00", "#ffff00", "#ff0000"]
        score = telemetry.governor_score
        if score > 70:
            color = phase_colors[0]
        elif score > 40:
            color = phase_colors[1]
        else:
            color = phase_colors[2]
        self.labels["score"].configure(foreground=color)

        glyph = self._glyph_for_state(telemetry, threat)
        self.labels["glyph"].configure(text=f"Glyph: {glyph}")

    def _refresh(self):
        telemetry = self.governor.last_telemetry
        if telemetry is not None:
            self.labels["vram"].configure(
                text=(
                    f"VRAM: total={telemetry.total_gb:.2f}GB "
                    f"used={telemetry.used_gb:.2f}GB "
                    f"free={telemetry.free_gb:.2f}GB "
                    f"util={telemetry.utilization_percent:.1f}%"
                )
            )
            self.labels["score"].configure(
                text=f"Governor score: {telemetry.governor_score:.1f}"
            )
            self.labels["temp"].configure(
                text=f"Temperature: {telemetry.temperature_c:.1f}C"
            )
            self.labels["power"].configure(
                text=f"Power: {telemetry.power_w:.1f}W"
            )
            self.labels["frag"].configure(
                text=f"Fragmentation: {telemetry.fragmentation_score:.1f}"
            )

        epochs_completed = self.training_state.get("epochs_completed", 0)
        best_acc = self.training_state.get("best_validation_accuracy", 0.0)

        self.labels["training"].configure(
            text=f"Training: epochs completed = {epochs_completed}"
        )
        self.labels["accuracy"].configure(
            text=f"Best val accuracy: {best_acc:.4f}"
        )

        swarm_summary = self.swarm.summary()
        if swarm_summary["nodes"]:
            avg = swarm_summary["average_governor_score"]
            avg_risk = swarm_summary["average_overall_risk"]
            self.labels["swarm"].configure(
                text=f"Swarm avg score: {avg:.1f}, avg risk: {avg_risk:.1f}"
            )

        # For glyph animation we need a threat matrix; approximate from last telemetry
        if telemetry is not None:
            threat = compute_threat_matrix(None, telemetry)
            self._animate_overlay(telemetry, threat)

        self.root.after(GUI_REFRESH_INTERVAL_MS, self._refresh)

    def run(self):
        if self.tk is None or self.ttk is None:
            log("[GUI] tkinter not available; GUI disabled.")
            return

        self._create_layout()
        self.root.after(GUI_REFRESH_INTERVAL_MS, self._refresh)
        log("[GUI] Dashboard started.")
        self.root.mainloop()


# ---------------------------------------------------------------------------
# Watchdog
# ---------------------------------------------------------------------------

class DominionDeckWatchdog:
    def __init__(self, governor: DominionDeckGPUGovernor, swarm: DominionDeckSwarm, psutil, network: SwarmNetwork):
        self.governor = governor
        self.swarm = swarm
        self.psutil = psutil
        self.network = network
        self.running = False

    def start(self):
        self.running = True
        log("[WATCHDOG] Started.")
        while self.running:
            telemetry = self.governor.poll()
            threat = compute_threat_matrix(self.psutil, telemetry)
            self.swarm.update_local(telemetry, threat)
            self.network.broadcast("threat", asdict(threat))

            if telemetry.governor_score < 20.0 or threat.overall_risk > 80.0:
                log(
                    "[WATCHDOG] Elevated risk: score={:.1f}, risk={:.1f}; "
                    "consider reducing batch size or pausing training.".format(
                        telemetry.governor_score,
                        threat.overall_risk,
                    )
                )
            time.sleep(GOVERNOR_POLL_INTERVAL)

    def stop(self):
        self.running = False
        log("[WATCHDOG] Stopped.")


# ---------------------------------------------------------------------------
# Model
# ---------------------------------------------------------------------------

def residual_block(layers, x, filters: int, stride: int = 1,
                   dropout_rate: float = 0.0):
    shortcut = x

    y = layers.Conv3D(
        filters,
        kernel_size=3,
        strides=stride,
        padding="same",
        use_bias=False,
    )(x)
    y = layers.BatchNormalization()(y)
    y = layers.Activation("relu")(y)

    if dropout_rate > 0:
        y = layers.SpatialDropout3D(dropout_rate)(y)

    y = layers.Conv3D(
        filters,
        kernel_size=3,
        strides=1,
        padding="same",
        use_bias=False,
    )(y)
    y = layers.BatchNormalization()(y)

    input_channels = x.shape[-1]
    if stride != 1 or input_channels != filters:
        shortcut = layers.Conv3D(
            filters,
            kernel_size=1,
            strides=stride,
            padding="same",
            use_bias=False,
        )(shortcut)
        shortcut = layers.BatchNormalization()(shortcut)

    y = layers.Add()([shortcut, y])
    y = layers.Activation("relu")(y)
    return y


def build_temporal_resnet(
    tf,
    input_shape: Tuple[int, int, int, int],
    num_classes: int = NUM_CLASSES,
    dropout_rate: float = 0.2,
):
    from tensorflow.keras import layers, Model

    inputs = layers.Input(shape=input_shape, name="temporal_input")

    x = layers.Conv3D(
        32,
        kernel_size=3,
        strides=1,
        padding="same",
        use_bias=False,
        name="stem_conv",
    )(inputs)
    x = layers.BatchNormalization(name="stem_bn")(x)
    x = layers.Activation("relu", name="stem_relu")(x)

    x = residual_block(layers, x, 32, stride=1, dropout_rate=dropout_rate)

    x = residual_block(layers, x, 64, stride=2, dropout_rate=dropout_rate)
    x = residual_block(layers, x, 64, stride=1, dropout_rate=dropout_rate)

    x = residual_block(layers, x, 128, stride=2, dropout_rate=dropout_rate)
    x = residual_block(layers, x, 128, stride=1, dropout_rate=dropout_rate)

    x = layers.GlobalAveragePooling3D(name="global_average_pool")(x)
    x = layers.Dropout(dropout_rate, name="classifier_dropout")(x)

    outputs = layers.Dense(
        num_classes,
        activation="softmax",
        dtype="float32",
        name="classification",
    )(x)

    return Model(inputs, outputs, name="TemporalResNet")


# ---------------------------------------------------------------------------
# Data
# ---------------------------------------------------------------------------

def load_temporal_data(np, seq_length: int = SEQ_LENGTH,
                       num_samples: int = SYNTHETIC_SAMPLES,
                       height: int = IMAGE_HEIGHT,
                       width: int = IMAGE_WIDTH,
                       channels: int = CHANNELS,
                       num_classes: int = NUM_CLASSES):
    rng = np.random.default_rng(42)

    X = rng.normal(
        0.0, 0.05,
        size=(num_samples, seq_length, height, width, channels)
    ).astype("float32")

    y = rng.integers(0, num_classes, size=num_samples, dtype="int32")

    for i in range(num_samples):
        cls = int(y[i])
        row = (cls * 5) % max(1, height - 8)
        col = (cls * 7) % max(1, width - 8)
        channel = cls % channels

        X[i, :, row:row + 8, col:col + 8, channel] += 0.8

        X[i, :, row:row + 3, col:col + 3, channel] += (
            np.linspace(0.0, 0.5, seq_length)[:, None, None]
        )

    X = np.clip(X, 0.0, 1.0)
    return X, y


def split_data(np, X, y, validation_fraction=0.2):
    from sklearn.model_selection import train_test_split

    return train_test_split(
        X,
        y,
        test_size=validation_fraction,
        random_state=42,
        stratify=y,
    )


def create_temporal_sequence(np, tf, X, y, batch_size, training=True):
    from tensorflow.keras.utils import Sequence

    class TemporalSequence(Sequence):
        def __init__(self, np_, X_, y_, batch_size_, training_):
            self.np = np_
            self.X = X_
            self.y = y_
            self.batch_size = batch_size_
            self.training = training_
            self.indices = np_.arange(len(X_))

        def __len__(self):
            return max(1, len(self.X) // self.batch_size)

        def on_epoch_end(self):
            if self.training:
                self.np.random.shuffle(self.indices)

        def __getitem__(self, index):
            start = index * self.batch_size
            end = min(start + self.batch_size, len(self.X))
            ids = self.indices[start:end]

            batch_x = self.X[ids].copy()
            batch_y = self.y[ids]

            if self.training:
                batch_x = self.augment(batch_x)

            return batch_x, batch_y

        def augment(self, batch):
            flip_mask = self.np.random.random(len(batch)) < 0.5
            batch[flip_mask] = batch[flip_mask, :, :, ::-1, :]

            brightness = self.np.random.uniform(
                0.90, 1.10, size=(len(batch), 1, 1, 1, 1)
            ).astype("float32")
            batch *= brightness

            return self.np.clip(batch, 0.0, 1.0)

    return TemporalSequence(np, X, y, batch_size, training)


# ---------------------------------------------------------------------------
# Auto-scaling batch size
# ---------------------------------------------------------------------------

def autoscale_batch_size(telemetry: VRAMTelemetry) -> int:
    if telemetry.total_gb <= 0.0:
        return BASE_BATCH_SIZE

    free_ratio = telemetry.free_gb / telemetry.total_gb
    if free_ratio > 0.7:
        scale = 2.0
    elif free_ratio > 0.4:
        scale = 1.5
    elif free_ratio > 0.2:
        scale = 1.0
    else:
        scale = 0.5

    batch = max(4, int(BASE_BATCH_SIZE * scale))
    log(f"[AUTOSCALE] Batch size scaled to {batch} (free_ratio={free_ratio:.2f}).")
    return batch


# ---------------------------------------------------------------------------
# Optimizer / compilation
# ---------------------------------------------------------------------------

def create_optimizer(tf, learning_rate: float):
    try:
        return tf.keras.optimizers.AdamW(
            learning_rate=learning_rate,
            weight_decay=1e-4,
            global_clipnorm=1.0,
        )
    except Exception:
        try:
            return tf.keras.optimizers.experimental.AdamW(
                learning_rate=learning_rate,
                weight_decay=1e-4,
                global_clipnorm=1.0,
            )
        except Exception:
            log("[OPTIMIZER] AdamW unavailable; falling back to Adam.")
            return tf.keras.optimizers.Adam(
                learning_rate=learning_rate,
                clipnorm=1.0,
            )


def compile_model(tf, model, learning_rate):
    optimizer = create_optimizer(tf, learning_rate)

    loss = tf.keras.losses.SparseCategoricalCrossentropy(
        from_logits=False
    )

    model.compile(
        optimizer=optimizer,
        loss=loss,
        metrics=[
            tf.keras.metrics.SparseCategoricalAccuracy(name="accuracy")
        ],
    )
    return model


# ---------------------------------------------------------------------------
# Benchmark
# ---------------------------------------------------------------------------

def benchmark_model(model, X, y, batch_size) -> dict[str, float]:
    section("MODEL BENCHMARK")

    warmup_count = min(batch_size, len(X))
    model.predict(X[:warmup_count], verbose=0)

    start = time.perf_counter()
    predictions = model.predict(X, batch_size=batch_size, verbose=0)
    elapsed = max(time.perf_counter() - start, 1e-9)

    import numpy as np_local
    accuracy = float(
        np_local.mean(np_local.argmax(predictions, axis=1) == y)
    )

    samples_per_second = len(X) / elapsed

    result = {
        "samples": int(len(X)),
        "elapsed_seconds": float(elapsed),
        "samples_per_second": float(samples_per_second),
        "accuracy": accuracy,
    }

    log(f"[BENCH] Inference time: {elapsed:.3f}s")
    log(f"[BENCH] Throughput: {samples_per_second:.2f} samples/sec")
    log(f"[BENCH] Accuracy: {accuracy:.4f}")

    return result


# ---------------------------------------------------------------------------
# Training curve visualization
# ---------------------------------------------------------------------------

def save_training_curves(plt, history) -> Optional[str]:
    if plt is None:
        log("[CURVES] matplotlib not available; skipping curve plot.")
        return None

    try:
        section("TRAINING CURVES")
        plt.figure(figsize=(8, 5))

        epochs = range(1, len(history.history.get("loss", [])) + 1)

        if "loss" in history.history:
            plt.plot(epochs, history.history["loss"], label="Train Loss")
        if "val_loss" in history.history:
            plt.plot(epochs, history.history["val_loss"], label="Val Loss")
        if "accuracy" in history.history:
            plt.plot(epochs, history.history["accuracy"], label="Train Acc")
        if "val_accuracy" in history.history:
            plt.plot(epochs, history.history["val_accuracy"], label="Val Acc")

        plt.xlabel("Epoch")
        plt.ylabel("Value")
        plt.title("Training Curves")
        plt.legend()
        plt.grid(True)

        plt.tight_layout()
        plt.savefig(CURVE_FILE)
        plt.close()
        log(f"[CURVES] Saved training curves to {CURVE_FILE}")
        return str(CURVE_FILE)
    except Exception as exc:
        log(f"[CURVES] Failed to save curves: {exc}")
        return None


# ---------------------------------------------------------------------------
# Optuna tuning
# ---------------------------------------------------------------------------

def tune_hyperparameters(
    tf,
    np,
    optuna,
    X_train,
    y_train,
    X_val,
    y_val,
    input_shape,
    num_classes,
    trials=TUNING_TRIALS,
):
    if optuna is None:
        log("[OPTUNA] Not installed; using safe defaults.")
        return {
            "learning_rate": 3e-4,
            "dropout_rate": 0.15,
        }

    section("OPTUNA HYPERPARAMETER SEARCH")

    def objective(trial):
        try:
            learning_rate = trial.suggest_float(
                "learning_rate",
                1e-5,
                1e-3,
                log=True,
            )
            dropout_rate = trial.suggest_float(
                "dropout_rate",
                0.0,
                0.4,
            )

            model = build_temporal_resnet(
                tf,
                input_shape,
                num_classes=num_classes,
                dropout_rate=dropout_rate,
            )
            compile_model(tf, model, learning_rate)

            callbacks = [
                tf.keras.callbacks.EarlyStopping(
                    monitor="val_loss",
                    patience=1,
                    restore_best_weights=True,
                )
            ]

            # Use base batch size during tuning
            train_seq = create_temporal_sequence(
                np, tf, X_train, y_train, BASE_BATCH_SIZE, training=True
            )

            history = model.fit(
                train_seq,
                validation_data=(X_val, y_val),
                epochs=TUNING_EPOCHS,
                callbacks=callbacks,
                verbose=0,
            )

            val_acc_list = history.history.get("val_accuracy", [])
            if not val_acc_list:
                log("[OPTUNA] Trial produced no val_accuracy; returning 0.0.")
                best_accuracy = 0.0
            else:
                best_accuracy = float(max(val_acc_list))

            tf.keras.backend.clear_session()
            return best_accuracy

        except Exception as exc:
            log(f"[OPTUNA] Trial failed: {exc}")
            return 0.0

    study = optuna.create_study(
        direction="maximize",
        sampler=optuna.samplers.TPESampler(seed=42),
        pruner=optuna.pruners.MedianPruner(),
    )

    study.optimize(
        objective,
        n_trials=trials,
        catch=(Exception,),
        show_progress_bar=False,
    )

    if not study.trials:
        log("[OPTUNA] No successful trials; using safe defaults.")
        return {
            "learning_rate": 3e-4,
            "dropout_rate": 0.15,
        }

    best = study.best_trial

    log(f"[OPTUNA] Best validation accuracy: {best.value:.4f}")
    log(f"[OPTUNA] Best parameters: {best.params}")

    return dict(best.params)


# ---------------------------------------------------------------------------
# Pruning
# ---------------------------------------------------------------------------

def attempt_pruning(tf, tfmot, model, np, X_train, y_train, X_val, y_val, batch_size):
    if tfmot is None:
        log("[PRUNE] TensorFlow Model Optimization unavailable; skipped.")
        return model, False

    section("MODEL PRUNING")

    try:
        prune_schedule = tfmot.sparsity.keras.PolynomialDecay(
            initial_sparsity=0.0,
            final_sparsity=0.30,
            begin_step=0,
            end_step=max(1, (len(X_train) // batch_size) * 3),
        )

        pruned_model = tfmot.sparsity.keras.prune_low_magnitude(
            model,
            pruning_schedule=prune_schedule,
        )

        compile_model(tf, pruned_model, 1e-4)

        callbacks = [
            tfmot.sparsity.keras.UpdatePruningStep(),
            tf.keras.callbacks.EarlyStopping(
                monitor="val_loss",
                patience=2,
                restore_best_weights=True,
            ),
        ]

        train_seq = create_temporal_sequence(
            np, tf, X_train, y_train, batch_size, training=True
        )

        pruned_model.fit(
            train_seq,
            validation_data=(X_val, y_val),
            epochs=5,
            callbacks=callbacks,
            verbose=1,
        )

        stripped = tfmot.sparsity.keras.strip_pruning(pruned_model)
        log("[PRUNE] Pruning completed successfully.")
        return stripped, True

    except Exception as exc:
        log(f"[PRUNE] Skipped safely: {exc}")
        return model, False


# ---------------------------------------------------------------------------
# Quantization
# ---------------------------------------------------------------------------

def attempt_quantization(tf, tfmot, model):
    if tfmot is None:
        log("[QUANT] TensorFlow Model Optimization unavailable; skipped.")
        return model, False

    section("MODEL QUANTIZATION")

    try:
        quantized = tfmot.quantization.keras.quantize_model(model)
        log("[QUANT] Full-model quantization succeeded.")
        return quantized, True
    except Exception as exc:
        log(
            "[QUANT] Full-model quantization is not compatible with this "
            f"architecture/version: {exc}"
        )
        log("[QUANT] Keeping the validated floating-point model.")
        return model, False


# ---------------------------------------------------------------------------
# System information
# ---------------------------------------------------------------------------

def collect_system_metrics(psutil) -> dict[str, Any]:
    data = {
        "platform": platform.platform(),
        "python": platform.python_version(),
        "cpu_count": os.cpu_count() or 1,
    }

    if psutil is not None:
        try:
            data["cpu_percent"] = psutil.cpu_percent(interval=0.5)
            memory = psutil.virtual_memory()
            data["memory_percent"] = memory.percent
            data["memory_total_gb"] = memory.total / (1024 ** 3)
            data["memory_available_gb"] = memory.available / (1024 ** 3)
        except Exception as exc:
            data["psutil_error"] = str(exc)

    return data


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    section(f"{APP_NAME} v{APP_VERSION}")
    log("[START] Initializing.")

    training_state: dict[str, Any] = {
        "epochs_completed": 0,
        "best_validation_accuracy": 0.0,
        "best_validation_loss": 0.0,
    }

    plugin_mgr = PluginManager()

    try:
        library_status = ensure_libraries()
        np, tf, optuna, tfmot, psutil, pynvml, plt, tk, ttk = load_runtime()

        hardware = detect_hardware(tf)
        configure_precision(tf, hardware)

        system_metrics = collect_system_metrics(psutil)

        network = SwarmNetwork(plugin_mgr, SWARM_PORT, SWARM_PEERS)
        network.start_listener()

        governor = DominionDeckGPUGovernor(tf, psutil, pynvml, plugin_mgr)
        swarm = DominionDeckSwarm(plugin_mgr, network)

        watchdog = None
        if WATCHDOG_ENABLED:
            import threading
            watchdog = DominionDeckWatchdog(governor, swarm, psutil, network)
            t = threading.Thread(target=watchdog.start, daemon=True)
            t.start()

        section("DATA PREPARATION")
        X, y = load_temporal_data(
            np,
            seq_length=SEQ_LENGTH,
            num_samples=SYNTHETIC_SAMPLES,
            height=IMAGE_HEIGHT,
            width=IMAGE_WIDTH,
            channels=CHANNELS,
            num_classes=NUM_CLASSES,
        )

        log(f"[DATA] X shape: {X.shape}")
        log(f"[DATA] y shape: {y.shape}")

        X_train, X_val, y_train, y_val = split_data(np, X, y)

        log(f"[DATA] Training samples: {len(X_train)}")
        log(f"[DATA] Validation samples: {len(X_val)}")

        input_shape = (
            SEQ_LENGTH,
            IMAGE_HEIGHT,
            IMAGE_WIDTH,
            CHANNELS,
        )

        params = tune_hyperparameters(
            tf,
            np,
            optuna,
            X_train,
            y_train,
            X_val,
            y_val,
            input_shape,
            NUM_CLASSES,
            trials=TUNING_TRIALS,
        )

        learning_rate = float(params["learning_rate"])
        dropout_rate = float(params["dropout_rate"])

        section("FINAL MODEL")

        telemetry_initial = governor.poll()
        batch_size = autoscale_batch_size(telemetry_initial)

        model = build_temporal_resnet(
            tf,
            input_shape,
            num_classes=NUM_CLASSES,
            dropout_rate=dropout_rate,
        )
        compile_model(tf, model, learning_rate)

        model.summary(print_fn=log)

        train_seq = create_temporal_sequence(
            np,
            tf,
            X_train,
            y_train,
            batch_size,
            training=True,
        )

        callbacks = [
            tf.keras.callbacks.ModelCheckpoint(
                str(MODEL_FILE),
                monitor="val_accuracy",
                mode="max",
                save_best_only=True,
            ),
            tf.keras.callbacks.EarlyStopping(
                monitor="val_loss",
                patience=4,
                restore_best_weights=True,
            ),
            tf.keras.callbacks.ReduceLROnPlateau(
                monitor="val_loss",
                factor=0.5,
                patience=2,
                min_lr=1e-6,
            ),
        ]

        history = model.fit(
            train_seq,
            validation_data=(X_val, y_val),
            epochs=FINAL_EPOCHS,
            callbacks=callbacks,
            verbose=1,
        )

        training_state["epochs_completed"] = len(
            history.history.get("loss", [])
        )
        training_state["best_validation_accuracy"] = float(
            max(history.history.get("val_accuracy", [0.0]))
        )
        training_state["best_validation_loss"] = float(
            min(history.history.get("val_loss", [0.0]))
        )

        curve_path = save_training_curves(plt, history)
        plugin_mgr.emit("post_training", {
            "epochs_completed": training_state["epochs_completed"],
            "best_validation_accuracy": training_state["best_validation_accuracy"],
            "best_validation_loss": training_state["best_validation_loss"],
            "curve_path": curve_path,
        })
        network.broadcast("training", {
            "epochs_completed": training_state["epochs_completed"],
            "best_validation_accuracy": training_state["best_validation_accuracy"],
            "best_validation_loss": training_state["best_validation_loss"],
            "curve_path": curve_path,
        })

        baseline_benchmark = benchmark_model(
            model,
            X_val,
            y_val,
            batch_size,
        )

        telemetry = governor.poll()
        threat = compute_threat_matrix(psutil, telemetry)
        swarm.update_local(telemetry, threat)

        stress_result = vram_stress_test(tf, np, telemetry)

        optimized_model, pruned = attempt_pruning(
            tf,
            tfmot,
            model,
            np,
            X_train,
            y_train,
            X_val,
            y_val,
            batch_size,
        )

        optimized_model, quantized = attempt_quantization(
            tf,
            tfmot,
            optimized_model,
        )

        try:
            optimized_model.save(OPTIMIZED_MODEL_FILE)
            saved_path = str(OPTIMIZED_MODEL_FILE)
        except Exception as exc:
            log(f"[SAVE] Optimized save failed: {exc}")
            model.save(MODEL_FILE)
            saved_path = str(MODEL_FILE)

        optimized_benchmark = benchmark_model(
            optimized_model,
            X_val,
            y_val,
            batch_size,
        )

        report = {
            "application": APP_NAME,
            "version": APP_VERSION,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
            "hardware": asdict(hardware),
            "system": system_metrics,
            "libraries": library_status,
            "configuration": {
                "sequence_length": SEQ_LENGTH,
                "image_height": IMAGE_HEIGHT,
                "image_width": IMAGE_WIDTH,
                "channels": CHANNELS,
                "classes": NUM_CLASSES,
                "base_batch_size": BASE_BATCH_SIZE,
                "effective_batch_size": batch_size,
                "learning_rate": learning_rate,
                "dropout_rate": dropout_rate,
            },
            "training": training_state,
            "optimization": {
                "pruning_applied": pruned,
                "quantization_applied": quantized,
            },
            "benchmark_before_optimization": baseline_benchmark,
            "benchmark_after_optimization": optimized_benchmark,
            "saved_model": saved_path,
            "governor_last_telemetry": (
                asdict(governor.last_telemetry)
                if governor.last_telemetry is not None
                else None
            ),
            "threat_matrix": asdict(threat),
            "swarm": swarm.summary(),
            "vram_stress_test": stress_result,
            "training_curves": curve_path,
        }

        with REPORT_FILE.open("w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)

        section("COMPLETE")
        log(f"[SAVE] Model: {saved_path}")
        log(f"[SAVE] Report: {REPORT_FILE}")
        log(f"[SAVE] Log: {LOG_FILE}")
        log("[DONE] Training, optimization, telemetry, swarm sync, and reporting completed.")

        if GUI_ENABLED:
            gui = DominionDeckGUI(
                tk,
                ttk,
                hardware,
                governor,
                swarm,
                training_state,
            )
            gui.run()

        if watchdog is not None:
            watchdog.stop()

        return 0

    except KeyboardInterrupt:
        log("[STOP] User interrupted the program.")
        return 130

    except Exception as exc:
        log(f"[FATAL] {type(exc).__name__}: {exc}")
        log(traceback.format_exc())
        log(f"[FATAL] Full log saved to: {LOG_FILE}")
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
