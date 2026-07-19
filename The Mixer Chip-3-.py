"""
Golden Star MPU – Security NPU Fusion v5

Includes:
- Loader (env + hardware + config)
- Security workload classes (packet/flow/DPI/inference/etc.)
- Unified Memory Fabric + Telemetry + Scheduler
- ReplicaNPU integrated as real NPU organ
- Legacy CPU/GPU adapters + NPU fusion
- Process Manager + Service Mode
- GUI: main panel + live curves (CPU/GPU/NPU)
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Any, List, Optional
import time
import random
import os
import json
import logging
import platform
import subprocess
import threading
import math

# GUI
import tkinter as tk
from tkinter import ttk


# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("GoldenStarMPU")


# ============================================================
# REPLICA NPU (YOUR NPU)
# ============================================================

class ReplicaNPU:
    """
    Software-simulated Neural Processing Unit (NPU)
    """

    def __init__(self, cores=8, frequency_ghz=1.2):
        self.cores = cores
        self.frequency_ghz = frequency_ghz
        self.cycles = 0
        self.energy = 0.0  # arbitrary units

    def mac(self, a, b):
        self.cycles += 1
        self.energy += 0.001
        return a * b

    def vector_mac(self, v1, v2):
        assert len(v1) == len(v2)
        chunk = math.ceil(len(v1) / self.cores)
        result = 0.0
        for i in range(0, len(v1), chunk):
            partial = 0.0
            for j in range(i, min(i + chunk, len(v1))):
                partial += self.mac(v1[j], v2[j])
            result += partial
        return result

    def matmul(self, A, B):
        result = [[0] * len(B[0]) for _ in range(len(A))]
        for i in range(len(A)):
            for j in range(len(B[0])):
                col = [B[k][j] for k in range(len(B))]
                result[i][j] = self.vector_mac(A[i], col)
        return result

    def relu(self, x):
        self.cycles += 1
        return max(0.0, x)

    def sigmoid(self, x):
        self.cycles += 2
        return 1 / (1 + math.exp(-x))

    def activate(self, tensor, mode="relu"):
        for i in range(len(tensor)):
            for j in range(len(tensor[0])):
                if mode == "relu":
                    tensor[i][j] = self.relu(tensor[i][j])
                elif mode == "sigmoid":
                    tensor[i][j] = self.sigmoid(tensor[i][j])
        return tensor

    def stats(self):
        time_ns = self.cycles / (self.frequency_ghz * 1e9)
        return {
            "cores": self.cores,
            "cycles": self.cycles,
            "estimated_time_sec": time_ns,
            "energy_units": round(self.energy, 6)
        }


# ============================================================
# 1. LOADER
# ============================================================

@dataclass
class LoaderContext:
    python_version: str
    os_name: str
    hardware: Dict[str, Any]
    config: Dict[str, Any]


class Loader:
    @staticmethod
    def probe_environment() -> Dict[str, Any]:
        import sys
        env = {
            "python": sys.version.split()[0],
            "os": platform.system(),
        }
        log.info(f"Environment: Python {env['python']} on {env['os']}")
        return env

    @staticmethod
    def parse_nvidia_smi() -> Dict[str, Any]:
        info = {"name": "Unknown", "util": 0.0, "mem_used_mb": 0.0, "mem_total_mb": 0.0}
        try:
            result = subprocess.run(
                ["nvidia-smi", "--query-gpu=name,utilization.gpu,memory.used,memory.total",
                 "--format=csv,noheader,nounits"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2,
            )
            if result.returncode == 0:
                line = result.stdout.strip().split("\n")[0]
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 4:
                    info["name"] = parts[0]
                    info["util"] = float(parts[1])
                    info["mem_used_mb"] = float(parts[2])
                    info["mem_total_mb"] = float(parts[3])
        except Exception:
            pass
        return info

    @staticmethod
    def detect_gpu() -> Dict[str, Any]:
        gpu_info = Loader.parse_nvidia_smi()
        if gpu_info["name"] != "Unknown":
            gpu_info["type"] = "NVIDIA"
        else:
            gpu_info["type"] = "Legacy/Unknown"
        return gpu_info

    @staticmethod
    def detect_npu() -> str:
        return "ReplicaNPU (software-simulated)"

    @staticmethod
    def detect_ram_gb() -> float:
        try:
            if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names:
                pages = os.sysconf("SC_PHYS_PAGES")
                page_size = os.sysconf("SC_PAGE_SIZE")
                return round(pages * page_size / (1024 ** 3), 2)
        except Exception:
            pass
        return 0.0

    @staticmethod
    def probe_hardware() -> Dict[str, Any]:
        hw = {
            "cpu": platform.processor() or "Unknown CPU",
            "machine": platform.machine(),
            "gpu": Loader.detect_gpu(),
            "npu": Loader.detect_npu(),
            "ram_gb": Loader.detect_ram_gb(),
        }
        log.info(f"Hardware: {hw}")
        return hw

    @staticmethod
    def load_config() -> Dict[str, Any]:
        default_cfg = {
            "mpu_enabled": True,
            "legacy_mode": True,
            "board_memory_gb": 16,
            "service_interval_sec": 2.0,
        }
        cfg_path = "mpu_config.json"
        if os.path.exists(cfg_path):
            try:
                with open(cfg_path, "r", encoding="utf-8") as f:
                    file_cfg = json.load(f)
                default_cfg.update(file_cfg)
                log.info(f"Loaded config from {cfg_path}")
            except Exception as e:
                log.warning(f"Failed to load {cfg_path}, using defaults: {e}")
        else:
            log.info("Config file mpu_config.json not found, using defaults.")
        return default_cfg

    @staticmethod
    def build_context() -> LoaderContext:
        env = Loader.probe_environment()
        hw = Loader.probe_hardware()
        cfg = Loader.load_config()
        return LoaderContext(
            python_version=env["python"],
            os_name=env["os"],
            hardware=hw,
            config=cfg,
        )


# ============================================================
# 2. ADAPTER LAYER
# ============================================================

class OrganType(Enum):
    LEGACY_CPU = auto()
    LEGACY_GPU = auto()
    LEGACY_NPU = auto()


@dataclass
class LegacyCPUAdapter:
    def utilization(self): return random.uniform(0.10, 0.60)
    def temperature(self): return random.uniform(40.0, 65.0)
    def power(self): return random.uniform(20.0, 60.0)
    def bandwidth(self): return random.uniform(5.0, 20.0)


@dataclass
class LegacyGPUAdapter:
    gpu_info: Dict[str, Any]

    def utilization(self):
        util = self.gpu_info.get("util", 0.0)
        if util > 0:
            return util / 100.0
        return random.uniform(0.05, 0.80)

    def temperature(self):
        return random.uniform(45.0, 75.0)

    def power(self):
        return random.uniform(10.0, 150.0)

    def bandwidth(self):
        return random.uniform(10.0, 40.0)


@dataclass
class LegacyNPUAdapter:
    npu: ReplicaNPU

    def utilization(self):
        # Approximate utilization from cycles
        return min(1.0, self.npu.cycles / 10000.0 + random.uniform(0.0, 0.2))

    def temperature(self):
        return random.uniform(35.0, 60.0)

    def power(self):
        return 5.0 + self.npu.energy * 0.5

    def bandwidth(self):
        return random.uniform(2.0, 15.0)

    def run_inference(self, tensor_a, tensor_b):
        out = self.npu.matmul(tensor_a, tensor_b)
        out = self.npu.activate(out, mode="relu")
        return out


@dataclass
class BoardMemoryAdapter:
    legacy_total_gb: float

    def translate_pressure(self, near_usage, far_usage, near_total, far_total):
        near_p = near_usage / max(1.0, near_total)
        far_p = far_usage / max(1.0, far_total)
        far_p = min(1.0, far_p * (far_total / max(1.0, self.legacy_total_gb)))
        return near_p, far_p


@dataclass
class LegacyBusTranslator:
    def list_devices(self):
        return [
            {"bus": "PCI0", "type": "Storage", "bw": 4.0},
            {"bus": "PCI1", "type": "GPU", "bw": 8.0},
            {"bus": "USB0", "type": "Input", "bw": 0.5},
        ]


@dataclass
class BIOSCompatibilityShim:
    vendor: str = "LegacyVendor"
    version: str = "1.0.0"

    def report(self):
        return {
            "vendor": self.vendor,
            "version": self.version,
            "mpu_compatible": True,
            "organs": ["LEGACY_CPU", "LEGACY_GPU", "LEGACY_NPU"],
        }


# ============================================================
# 3. NEW SYSTEM (MPU) – SECURITY WORKLOADS
# ============================================================

class MemoryTier(Enum):
    NEAR = auto()
    FAR = auto()


@dataclass
class MemoryRegion:
    name: str
    size_gb: float
    tier: MemoryTier
    owner: Optional[OrganType] = None


@dataclass
class UnifiedMemoryFabric:
    near_total: float = 128.0
    far_total: float = 512.0
    regions: List[MemoryRegion] = field(default_factory=list)

    def __post_init__(self):
        self.regions.extend([
            MemoryRegion("os_core", 16.0, MemoryTier.NEAR, OrganType.LEGACY_CPU),
            MemoryRegion("gpu_tensors", 48.0, MemoryTier.NEAR, OrganType.LEGACY_GPU),
            MemoryRegion("npu_models", 32.0, MemoryTier.NEAR, OrganType.LEGACY_NPU),
            MemoryRegion("scratch", 32.0, MemoryTier.NEAR, None),
            MemoryRegion("archive", 128.0, MemoryTier.FAR, OrganType.LEGACY_NPU),
            MemoryRegion("datasets", 256.0, MemoryTier.FAR, OrganType.LEGACY_GPU),
            MemoryRegion("background", 128.0, MemoryTier.FAR, OrganType.LEGACY_CPU),
        ])

    def usage(self):
        near = sum(r.size_gb for r in self.regions if r.tier == MemoryTier.NEAR)
        far = sum(r.size_gb for r in self.regions if r.tier == MemoryTier.FAR)
        return near, far


@dataclass
class TelemetrySample:
    timestamp: float
    organ: OrganType
    util: float
    temp: float
    power: float
    bw: float
    near_pressure: float
    far_pressure: float


@dataclass
class TelemetrySpine:
    samples: List[TelemetrySample] = field(default_factory=list)

    def record(self, s: TelemetrySample):
        self.samples.append(s)
        if len(self.samples) > 1000:
            self.samples.pop(0)


class SecurityWorkload(Enum):
    PACKET_CAPTURE = auto()
    FLOW_RECONSTRUCTION = auto()
    DEEP_PACKET_INSPECTION = auto()
    THREAT_INFERENCE = auto()
    MALWARE_SANDBOX = auto()
    LOG_INGEST = auto()
    SIGNATURE_UPDATE = auto()
    FULL_PIPELINE = auto()


@dataclass
class Workload:
    id: str
    cls: SecurityWorkload
    payload: Any = None
    latency: bool = True


@dataclass
class Scheduler:
    fabric: UnifiedMemoryFabric
    telemetry: TelemetrySpine
    cpu: LegacyCPUAdapter
    gpu: LegacyGPUAdapter
    npu: LegacyNPUAdapter
    board: BoardMemoryAdapter

    def schedule(self, w: Workload):
        cls = w.cls

        if cls == SecurityWorkload.PACKET_CAPTURE:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_GPU]

        elif cls == SecurityWorkload.FLOW_RECONSTRUCTION:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_GPU]

        elif cls == SecurityWorkload.DEEP_PACKET_INSPECTION:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_GPU, OrganType.LEGACY_NPU]

        elif cls == SecurityWorkload.THREAT_INFERENCE:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_GPU, OrganType.LEGACY_NPU]

        elif cls == SecurityWorkload.MALWARE_SANDBOX:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_GPU, OrganType.LEGACY_NPU]

        elif cls == SecurityWorkload.LOG_INGEST:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_GPU, OrganType.LEGACY_NPU]

        elif cls == SecurityWorkload.SIGNATURE_UPDATE:
            organs = [OrganType.LEGACY_CPU]

        elif cls == SecurityWorkload.FULL_PIPELINE:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_GPU, OrganType.LEGACY_NPU]

        else:
            organs = [OrganType.LEGACY_CPU]

        near_usage, far_usage = self.fabric.usage()
        near_p, far_p = self.board.translate_pressure(
            near_usage, far_usage,
            self.fabric.near_total, self.fabric.far_total
        )

        # Example: when NPU is involved, run a tiny inference
        if OrganType.LEGACY_NPU in organs:
            A = [[1.2, 0.5, -0.3], [0.8, -1.1, 2.0]]
            B = [[0.4, 1.0], [-0.7, 0.2], [1.5, -0.6]]
            _ = self.npu.run_inference(A, B)

        for organ in organs:
            if organ == OrganType.LEGACY_CPU:
                util = self.cpu.utilization()
                temp = self.cpu.temperature()
                power = self.cpu.power()
                bw = self.cpu.bandwidth()
            elif organ == OrganType.LEGACY_GPU:
                util = self.gpu.utilization()
                temp = self.gpu.temperature()
                power = self.gpu.power()
                bw = self.gpu.bandwidth()
            else:
                util = self.npu.utilization()
                temp = self.npu.temperature()
                power = self.npu.power()
                bw = self.npu.bandwidth()

            sample = TelemetrySample(
                timestamp=time.time(),
                organ=organ,
                util=util,
                temp=temp,
                power=power,
                bw=bw,
                near_pressure=near_p,
                far_pressure=far_p,
            )
            self.telemetry.record(sample)


# ============================================================
# PROCESS MANAGER + SERVICE MODE
# ============================================================

@dataclass
class ProcessManager:
    queue: List[Workload] = field(default_factory=list)

    def add(self, w: Workload):
        self.queue.append(w)

    def next(self) -> Optional[Workload]:
        if self.queue:
            return self.queue.pop(0)
        return None


@dataclass
class GoldenStarMPU:
    ctx: LoaderContext
    fabric: UnifiedMemoryFabric = field(default_factory=UnifiedMemoryFabric)
    telemetry: TelemetrySpine = field(default_factory=TelemetrySpine)
    cpu: LegacyCPUAdapter = field(default_factory=LegacyCPUAdapter)
    gpu: LegacyGPUAdapter = field(init=False)
    npu_core: ReplicaNPU = field(default_factory=lambda: ReplicaNPU(cores=16, frequency_ghz=1.5))
    npu: LegacyNPUAdapter = field(init=False)
    board: BoardMemoryAdapter = field(init=False)
    bus: LegacyBusTranslator = field(default_factory=LegacyBusTranslator)
    bios: BIOSCompatibilityShim = field(default_factory=BIOSCompatibilityShim)
    scheduler: Scheduler = field(init=False)
    pm: ProcessManager = field(default_factory=ProcessManager)
    service_thread: Optional[threading.Thread] = field(default=None)
    service_running: bool = field(default=False)

    def __post_init__(self):
        self.gpu = LegacyGPUAdapter(self.ctx.hardware["gpu"])
        self.npu = LegacyNPUAdapter(self.npu_core)
        self.board = BoardMemoryAdapter(self.ctx.config["board_memory_gb"])
        self.scheduler = Scheduler(
            fabric=self.fabric,
            telemetry=self.telemetry,
            cpu=self.cpu,
            gpu=self.gpu,
            npu=self.npu,
            board=self.board,
        )
        self._boot_panel()

    def _boot_panel(self):
        print("=" * 60)
        print("GoldenStarMPU Boot Panel")
        print(f"Python: {self.ctx.python_version} | OS: {self.ctx.os_name}")
        print("Hardware:", self.ctx.hardware)
        print("BIOS:", self.bios.report())
        print("Devices:")
        for dev in self.bus.list_devices():
            print(f"  - {dev['bus']}: {dev['type']} (bw={dev['bw']} Gbps)")
        print("Config:", self.ctx.config)
        print("=" * 60)

    def submit(self, w: Workload):
        self.pm.add(w)

    def _service_loop(self):
        interval = self.ctx.config.get("service_interval_sec", 2.0)
        log.info(f"Service mode started (interval={interval}s)")
        while self.service_running:
            w = self.pm.next()
            if w:
                self.scheduler.schedule(w)
                log.info(f"Service processed workload {w.id} ({w.cls.name})")
            time.sleep(interval)
        log.info("Service mode stopped.")

    def start_service(self):
        if self.service_running:
            return
        self.service_running = True
        self.service_thread = threading.Thread(target=self._service_loop, daemon=True)
        self.service_thread.start()

    def stop_service(self):
        self.service_running = False
        if self.service_thread:
            self.service_thread.join()
            self.service_thread = None


# ============================================================
# GUI: MAIN PANEL + GRAPHS WINDOW
# ============================================================

class MPUGui:
    def __init__(self, mpu: GoldenStarMPU):
        self.mpu = mpu
        self.root = tk.Tk()
        self.root.title("GoldenStar MPU Panel")
        self.root.geometry("600x600")

        self.build_layout()
        self.refresh_panel()

    def build_layout(self):
        self.title = ttk.Label(self.root, text="GoldenStar MPU Status", font=("Arial", 16))
        self.title.pack(pady=10)

        self.info_box = tk.Text(self.root, height=15, width=70)
        self.info_box.pack(pady=10)

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack()

        ttk.Button(btn_frame, text="PACKET_CAPTURE", command=lambda: self.submit(SecurityWorkload.PACKET_CAPTURE)).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="FLOW_RECON", command=lambda: self.submit(SecurityWorkload.FLOW_RECONSTRUCTION)).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="DPI", command=lambda: self.submit(SecurityWorkload.DEEP_PACKET_INSPECTION)).grid(row=1, column=0, padx=5)
        ttk.Button(btn_frame, text="INFERENCE", command=lambda: self.submit(SecurityWorkload.THREAT_INFERENCE)).grid(row=1, column=1, padx=5)
        ttk.Button(btn_frame, text="PIPELINE", command=lambda: self.submit(SecurityWorkload.FULL_PIPELINE)).grid(row=2, column=0, padx=5)

        ttk.Button(self.root, text="Refresh", command=self.refresh_panel).pack(pady=5)
        ttk.Button(self.root, text="Open Graphs", command=self.open_graphs).pack(pady=5)
        ttk.Button(self.root, text="Start Service", command=self.start_service).pack(pady=5)
        ttk.Button(self.root, text="Stop Service", command=self.stop_service).pack(pady=5)

    def submit(self, cls):
        w = Workload(f"gui-{int(time.time())}", cls)
        self.mpu.submit(w)
        self.refresh_panel()

    def refresh_panel(self):
        self.info_box.delete("1.0", tk.END)

        self.info_box.insert(tk.END, f"Python: {self.mpu.ctx.python_version}\n")
        self.info_box.insert(tk.END, f"OS: {self.mpu.ctx.os_name}\n")
        self.info_box.insert(tk.END, f"Hardware: {self.mpu.ctx.hardware}\n\n")

        self.info_box.insert(tk.END, "Telemetry Samples: " + str(len(self.mpu.telemetry.samples)) + "\n")

        if self.mpu.telemetry.samples:
            last = self.mpu.telemetry.samples[-1]
            self.info_box.insert(tk.END, f"Last Organ: {last.organ.name}\n")
            self.info_box.insert(tk.END, f"Utilization: {last.util:.2f}\n")
            self.info_box.insert(tk.END, f"Temperature: {last.temp:.1f} C\n")
            self.info_box.insert(tk.END, f"Power: {last.power:.1f} W\n")
            self.info_box.insert(tk.END, f"Bandwidth: {last.bw:.1f} GB/s\n")
            self.info_box.insert(tk.END, f"Near Pressure: {last.near_pressure:.2f}\n")
            self.info_box.insert(tk.END, f"Far Pressure: {last.far_pressure:.2f}\n")

            self.info_box.insert(tk.END, "\nNPU Stats:\n")
            self.info_box.insert(tk.END, str(self.mpu.npu_core.stats()) + "\n")
        else:
            self.info_box.insert(tk.END, "No telemetry yet.\n")

    def open_graphs(self):
        GraphWindow(self.mpu)

    def start_service(self):
        self.mpu.start_service()
        self.info_box.insert(tk.END, "\nService mode started.\n")

    def stop_service(self):
        self.mpu.stop_service()
        self.info_box.insert(tk.END, "\nService mode stopped.\n")

    def run(self):
        self.root.mainloop()


class GraphWindow:
    def __init__(self, mpu: GoldenStarMPU):
        self.mpu = mpu
        self.win = tk.Toplevel()
        self.win.title("MPU Live Graphs")
        self.win.geometry("600x400")

        self.canvas = tk.Canvas(self.win, width=580, height=350, bg="black")
        self.canvas.pack(pady=10)

        self.update_graphs()

    def update_graphs(self):
        self.canvas.delete("all")

        samples = self.mpu.telemetry.samples[-50:]
        if not samples:
            self.canvas.create_text(290, 175, text="No telemetry yet", fill="white")
        else:
            width = 580
            height = 350
            step = max(1, width // max(1, len(samples)))

            def draw_curve(color, organ_type):
                points = []
                x = 10
                for s in samples:
                    if s.organ == organ_type:
                        y = height - int(s.util * (height - 20))
                        points.append((x, y))
                    x += step
                if len(points) > 1:
                    for i in range(len(points) - 1):
                        x1, y1 = points[i]
                        x2, y2 = points[i + 1]
                        self.canvas.create_line(x1, y1, x2, y2, fill=color, width=2)

            draw_curve("red", OrganType.LEGACY_CPU)
            draw_curve("green", OrganType.LEGACY_GPU)
            draw_curve("blue", OrganType.LEGACY_NPU)

            self.canvas.create_text(50, 20, text="CPU", fill="red")
            self.canvas.create_text(100, 20, text="GPU", fill="green")
            self.canvas.create_text(150, 20, text="NPU", fill="blue")

        self.win.after(1000, self.update_graphs)


# ============================================================
# COMMAND SHELL (OPTIONAL)
# ============================================================

def command_shell(mpu: GoldenStarMPU):
    print("MPU Command Shell")
    print("Commands: submit, status, devices, bios, start, stop, exit")
    while True:
        cmd = input("mpu> ").strip().lower()
        if cmd == "exit":
            print("Exiting shell.")
            break
        elif cmd == "status":
            print(f"Samples: {len(mpu.telemetry.samples)}")
            if mpu.telemetry.samples:
                last = mpu.telemetry.samples[-1]
                print("Last sample:", last)
                print("NPU stats:", mpu.npu_core.stats())
        elif cmd == "devices":
            print("Devices:")
            for dev in mpu.bus.list_devices():
                print(f"  - {dev['bus']}: {dev['type']} (bw={dev['bw']} Gbps)")
        elif cmd == "bios":
            print("BIOS:", mpu.bios.report())
        elif cmd.startswith("submit"):
            parts = cmd.split()
            if len(parts) >= 2:
                wtype = parts[1].upper()
                try:
                    cls = SecurityWorkload[wtype]
                except KeyError:
                    print("Unknown workload class.")
                    continue
                w = Workload(f"shell-{int(time.time())}", cls)
                mpu.submit(w)
                print(f"Submitted workload {w.id} ({cls.name}).")
            else:
                print("Usage: submit CLASS")
        elif cmd == "start":
            mpu.start_service()
            print("Service mode started.")
        elif cmd == "stop":
            mpu.stop_service()
            print("Service mode stopped.")
        else:
            print("Unknown command.")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    ctx = Loader.build_context()
    mpu = GoldenStarMPU(ctx)

    # Seed a few security workloads
    auto_workloads = [
        Workload("pcap1", SecurityWorkload.PACKET_CAPTURE),
        Workload("flow1", SecurityWorkload.FLOW_RECONSTRUCTION),
        Workload("dpi1", SecurityWorkload.DEEP_PACKET_INSPECTION),
        Workload("infer1", SecurityWorkload.THREAT_INFERENCE),
        Workload("pipe1", SecurityWorkload.FULL_PIPELINE),
    ]
    for w in auto_workloads:
        mpu.submit(w)

    gui = MPUGui(mpu)
    gui.run()

    command_shell(mpu)
