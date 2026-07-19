"""
Golden Star MPU – Loader + Adapters + New System v3

Upgrades:
- Real hardware probing (best-effort, non-fatal)
- GPU/NPU detection (heuristic)
- Config file loading (mpu_config.json)
- Logging system
- MPU console GUI panel
- MPU command shell
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


# ============================================================
# LOGGING SETUP
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("GoldenStarMPU")


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
    def detect_gpu() -> str:
        # Best-effort GPU detection
        try:
            result = subprocess.run(
                ["nvidia-smi"],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2,
            )
            if result.returncode == 0:
                return "NVIDIA GPU (nvidia-smi detected)"
        except Exception:
            pass
        return "Unknown / Legacy GPU"

    @staticmethod
    def detect_npu() -> str:
        # No standard NPU detection; simulated
        return "No dedicated NPU (simulated via CPU)"

    @staticmethod
    def detect_ram_gb() -> float:
        # Best-effort using os.sysconf on POSIX
        try:
            if hasattr(os, "sysconf") and "SC_PAGE_SIZE" in os.sysconf_names:
                pages = os.sysconf("SC_PHYS_PAGES")
                page_size = os.sysconf("SC_PAGE_SIZE")
                return round(pages * page_size / (1024 ** 3), 2)
        except Exception:
            pass
        return 0.0

    @staticmethod
    def load_config() -> Dict[str, Any]:
        default_cfg = {
            "mpu_enabled": True,
            "legacy_mode": True,
            "board_memory_gb": 16,
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
        ctx = LoaderContext(
            python_version=env["python"],
            os_name=env["os"],
            hardware=hw,
            config=cfg,
        )
        return ctx


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
    def utilization(self): return random.uniform(0.05, 0.80)
    def temperature(self): return random.uniform(45.0, 75.0)
    def power(self): return random.uniform(10.0, 150.0)
    def bandwidth(self): return random.uniform(10.0, 40.0)


@dataclass
class LegacyNPUAdapter:
    def utilization(self): return random.uniform(0.01, 0.50)
    def temperature(self): return random.uniform(35.0, 60.0)
    def power(self): return random.uniform(5.0, 30.0)
    def bandwidth(self): return random.uniform(2.0, 15.0)


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
# 3. NEW SYSTEM (MPU)
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


class WorkloadClass(Enum):
    CONTROL = auto()
    RENDER = auto()
    TENSOR = auto()
    INFERENCE = auto()
    MIXED = auto()


@dataclass
class Workload:
    id: str
    cls: WorkloadClass
    size: int
    latency: bool


@dataclass
class Scheduler:
    fabric: UnifiedMemoryFabric
    telemetry: TelemetrySpine
    cpu: LegacyCPUAdapter
    gpu: LegacyGPUAdapter
    npu: LegacyNPUAdapter
    board: BoardMemoryAdapter

    def schedule(self, w: Workload):
        if w.cls == WorkloadClass.CONTROL:
            organs = [OrganType.LEGACY_CPU]
        elif w.cls == WorkloadClass.RENDER:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_GPU]
        elif w.cls == WorkloadClass.TENSOR:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_GPU]
        elif w.cls == WorkloadClass.INFERENCE:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_NPU]
        else:
            organs = [OrganType.LEGACY_CPU, OrganType.LEGACY_GPU, OrganType.LEGACY_NPU]

        near_usage, far_usage = self.fabric.usage()
        near_p, far_p = self.board.translate_pressure(
            near_usage, far_usage,
            self.fabric.near_total, self.fabric.far_total
        )

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


@dataclass
class GoldenStarMPU:
    ctx: LoaderContext
    fabric: UnifiedMemoryFabric = field(default_factory=UnifiedMemoryFabric)
    telemetry: TelemetrySpine = field(default_factory=TelemetrySpine)
    cpu: LegacyCPUAdapter = field(default_factory=LegacyCPUAdapter)
    gpu: LegacyGPUAdapter = field(default_factory=LegacyGPUAdapter)
    npu: LegacyNPUAdapter = field(default_factory=LegacyNPUAdapter)
    board: BoardMemoryAdapter = field(init=False)
    bus: LegacyBusTranslator = field(default_factory=LegacyBusTranslator)
    bios: BIOSCompatibilityShim = field(default_factory=BIOSCompatibilityShim)
    scheduler: Scheduler = field(init=False)

    def __post_init__(self):
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
        self.scheduler.schedule(w)


# ============================================================
# MPU "GUI" PANEL + COMMAND SHELL (CONSOLE)
# ============================================================

def show_mpu_panel(mpu: GoldenStarMPU):
    print("\n=== MPU Status Panel ===")
    print(f"Samples: {len(mpu.telemetry.samples)}")
    if mpu.telemetry.samples:
        last = mpu.telemetry.samples[-1]
        print("Last sample:")
        print(f"  Organ: {last.organ.name}")
        print(f"  Util: {last.util:.2f}")
        print(f"  Temp: {last.temp:.1f} C")
        print(f"  Power: {last.power:.1f} W")
        print(f"  BW: {last.bw:.1f} GB/s")
        print(f"  Near pressure: {last.near_pressure:.2f}")
        print(f"  Far pressure: {last.far_pressure:.2f}")
    else:
        print("No telemetry yet.")
    print("========================\n")


def command_shell(mpu: GoldenStarMPU):
    print("MPU Command Shell")
    print("Commands: submit, status, devices, bios, exit")
    while True:
        cmd = input("mpu> ").strip().lower()
        if cmd == "exit":
            print("Exiting shell.")
            break
        elif cmd == "status":
            show_mpu_panel(mpu)
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
                    cls = WorkloadClass[wtype]
                except KeyError:
                    print("Unknown workload class. Use CONTROL/RENDER/TENSOR/INFERENCE/MIXED.")
                    continue
                w = Workload(f"user-{int(time.time())}", cls, 1000, True)
                mpu.submit(w)
                print(f"Submitted workload {w.id} ({cls.name}).")
            else:
                print("Usage: submit CLASS")
        else:
            print("Unknown command.")


# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    ctx = Loader.build_context()
    mpu = GoldenStarMPU(ctx)

    # Run a few automatic workloads
    auto_workloads = [
        Workload("w1", WorkloadClass.CONTROL, 100, True),
        Workload("w2", WorkloadClass.RENDER, 5000, True),
        Workload("w3", WorkloadClass.INFERENCE, 2000, True),
        Workload("w4", WorkloadClass.MIXED, 3000, False),
    ]

    for w in auto_workloads:
        mpu.submit(w)
        log.info(f"Auto workload {w.id} ({w.cls.name}) processed.")

    show_mpu_panel(mpu)
    command_shell(mpu)
