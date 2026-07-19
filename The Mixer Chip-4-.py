"""
Golden Star MPU – AI Security Appliance v7 (Always-On)

- Loader (env + hardware + config)
- Security workload classes (packet/flow/DPI/inference/etc.)
- Unified Memory Fabric + Telemetry + Scheduler
- ReplicaNPU integrated as NPU organ
- Legacy CPU/GPU adapters + NPU fusion
- Process Manager (always-on service loop in background thread)
- Packet parsing (Ethernet/IP/TCP/UDP, simplified)
- DPI signatures (string/byte patterns)
- ML inference (ReplicaNPU-based scoring stub)
- Anomaly detection (simple stats)
- Sandbox scoring (behavior stub placeholder)
- Log ingestion (syslog-style)
- Threat scoring engine
- Persistence (SQLite)
- Networking (safe local UDP listener, always on)
- AI reasoning engine (explanations)
- GUI: main panel + live curves (CPU/GPU/NPU)
- Command shell (no start/stop, service is always running)
"""

from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Dict, Any, List, Optional, Tuple
import time
import random
import os
import json
import logging
import platform
import subprocess
import threading
import math
import socket
import sqlite3

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
            "db_path": "mpu_security.db",
            "listener_port": 5555,
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
        return min(1.0, self.npu.cycles / 10000.0 + random.uniform(0.0, 0.2))

    def temperature(self):
        return random.uniform(35.0, 60.0)

    def power(self):
        return 5.0 + self.npu.energy * 0.5

    def bandwidth(self):
        return random.uniform(2.0, 15.0)

    def run_inference(self, features: List[float]) -> float:
        # Simple scoring: features x weights via matmul
        A = [features]
        # Basic weights vector, adjusted to length
        B = [[0.3] for _ in features]
        out = self.npu.matmul(A, B)
        out = self.npu.activate(out, mode="relu")
        return out[0][0]


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
# 3. PACKET PARSING + DPI + LOGS
# ============================================================

@dataclass
class ParsedPacket:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    payload: bytes


class PacketParser:
    @staticmethod
    def parse_ipv4_packet(data: bytes) -> Optional[ParsedPacket]:
        # Very simplified: assume Ethernet + IPv4 + TCP/UDP
        if len(data) < 34:
            return None
        # Skip Ethernet (14 bytes)
        ip_header = data[14:34]
        src_ip = ".".join(str(b) for b in ip_header[12:16])
        dst_ip = ".".join(str(b) for b in ip_header[16:20])
        protocol_num = ip_header[9]
        protocol = "TCP" if protocol_num == 6 else "UDP" if protocol_num == 17 else "OTHER"

        # Fake ports
        src_port = 12345
        dst_port = 80 if protocol == "TCP" else 53 if protocol == "UDP" else 0
        payload = data[34:]
        return ParsedPacket(src_ip, dst_ip, src_port, dst_port, protocol, payload)


@dataclass
class DPISignature:
    name: str
    pattern: bytes
    severity: int


class DPIEngine:
    def __init__(self):
        self.signatures = [
            DPISignature("SuspiciousString", b"malware", 5),
            DPISignature("TestPattern", b"attack", 3),
        ]

    def scan(self, packet: ParsedPacket) -> List[DPISignature]:
        hits = []
        for sig in self.signatures:
            if sig.pattern in packet.payload:
                hits.append(sig)
        return hits


# ============================================================
# 4. LOG INGESTION
# ============================================================

@dataclass
class LogEntry:
    timestamp: float
    source: str
    message: str


class LogIngestor:
    def ingest(self, raw: str, source: str = "syslog") -> LogEntry:
        return LogEntry(time.time(), source, raw)


# ============================================================
# 5. THREAT SCORING + ANOMALY DETECTION + AI REASONING
# ============================================================

@dataclass
class ThreatScore:
    risk: float
    confidence: float
    reasons: List[str]


class ThreatScorer:
    def __init__(self):
        self.flow_stats: Dict[Tuple[str, str], int] = {}

    def update_flow(self, packet: ParsedPacket):
        key = (packet.src_ip, packet.dst_ip)
        self.flow_stats[key] = self.flow_stats.get(key, 0) + 1

    def anomaly_score(self, packet: ParsedPacket) -> float:
        key = (packet.src_ip, packet.dst_ip)
        count = self.flow_stats.get(key, 0)
        return min(1.0, count / 100.0)

    def score(self, dpi_hits: List[DPISignature], logs: List[LogEntry]) -> ThreatScore:
        risk = 0.0
        reasons = []

        for sig in dpi_hits:
            risk += sig.severity * 0.1
            reasons.append(f"DPI hit: {sig.name} (severity {sig.severity})")

        for log in logs:
            msg = log.message.lower()
            if "failed login" in msg:
                risk += 0.2
                reasons.append("Log: failed login detected")
            if "error" in msg:
                risk += 0.1
                reasons.append("Log: error message")

        confidence = min(1.0, 0.5 + risk / 2.0)
        risk = min(1.0, risk)
        return ThreatScore(risk, confidence, reasons)


class AIReasoningEngine:
    def explain(self, score: ThreatScore) -> str:
        lines = []
        lines.append(f"Threat Risk: {score.risk:.2f}, Confidence: {score.confidence:.2f}")
        if not score.reasons:
            lines.append("No strong indicators detected. Likely benign or low-risk activity.")
        else:
            lines.append("Contributing factors:")
            for r in score.reasons:
                lines.append(f"  - {r}")
        if score.risk > 0.7:
            lines.append("Recommended action: Investigate immediately, consider containment.")
        elif score.risk > 0.4:
            lines.append("Recommended action: Monitor closely, add to watchlist.")
        else:
            lines.append("Recommended action: Log and continue monitoring.")
        return "\n".join(lines)


# ============================================================
# 6. PERSISTENCE (SQLite)
# ============================================================

class Persistence:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS telemetry (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL,
            organ TEXT,
            util REAL,
            temp REAL,
            power REAL,
            bw REAL,
            near_pressure REAL,
            far_pressure REAL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS threats (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts REAL,
            risk REAL,
            confidence REAL,
            explanation TEXT
        )
        """)
        conn.commit()
        conn.close()

    def store_telemetry(self, sample):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO telemetry (ts, organ, util, temp, power, bw, near_pressure, far_pressure)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (sample.timestamp, sample.organ.name, sample.util, sample.temp,
              sample.power, sample.bw, sample.near_pressure, sample.far_pressure))
        conn.commit()
        conn.close()

    def store_threat(self, score: ThreatScore, explanation: str):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
        INSERT INTO threats (ts, risk, confidence, explanation)
        VALUES (?, ?, ?, ?)
        """, (time.time(), score.risk, score.confidence, explanation))
        conn.commit()
        conn.close()


# ============================================================
# 7. NETWORKING (SAFE LOCAL LISTENER, ALWAYS ON)
# ============================================================

class SafeListener:
    """
    Simple local listener that accepts bytes and treats them as packets.
    Defensive only: no command execution, no privileged operations.
    """

    def __init__(self, port: int, callback):
        self.port = port
        self.callback = callback
        self.thread = None
        self.running = False

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(("127.0.0.1", self.port))
        log.info(f"SafeListener started on 127.0.0.1:{self.port}")
        while self.running:
            try:
                data, addr = sock.recvfrom(2048)
                self.callback(data, addr)
            except Exception:
                pass
        sock.close()
        log.info("SafeListener stopped.")


# ============================================================
# 8. CORE MPU STRUCTURES
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
    dpi: DPIEngine
    scorer: ThreatScorer
    ai_reasoner: AIReasoningEngine
    persistence: Persistence

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

        dpi_hits: List[DPISignature] = []
        logs: List[LogEntry] = []

        if isinstance(w.payload, bytes):
            pkt = PacketParser.parse_ipv4_packet(w.payload)
            if pkt:
                self.scorer.update_flow(pkt)
                dpi_hits = self.dpi.scan(pkt)
                features = [len(w.payload), len(dpi_hits), pkt.src_port, pkt.dst_port]
                _ = self.npu.run_inference(features)

        if isinstance(w.payload, str):
            logs.append(LogIngestor().ingest(w.payload))

        if dpi_hits or logs:
            score = self.scorer.score(dpi_hits, logs)
            explanation = self.ai_reasoner.explain(score)
            self.persistence.store_threat(score, explanation)
            log.info("Threat scored:\n" + explanation)

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
            self.persistence.store_telemetry(sample)


# ============================================================
# PROCESS MANAGER + ALWAYS-ON SERVICE LOOP
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
    dpi: DPIEngine = field(default_factory=DPIEngine)
    scorer: ThreatScorer = field(default_factory=ThreatScorer)
    ai_reasoner: AIReasoningEngine = field(default_factory=AIReasoningEngine)
    persistence: Persistence = field(init=False)
    scheduler: Scheduler = field(init=False)
    pm: ProcessManager = field(default_factory=ProcessManager)
    service_thread: Optional[threading.Thread] = field(default=None)
    listener: Optional[SafeListener] = field(default=None)
    service_interval: float = field(default=2.0)

    def __post_init__(self):
        self.gpu = LegacyGPUAdapter(self.ctx.hardware["gpu"])
        self.npu = LegacyNPUAdapter(self.npu_core)
        self.board = BoardMemoryAdapter(self.ctx.config["board_memory_gb"])
        self.persistence = Persistence(self.ctx.config["db_path"])
        self.scheduler = Scheduler(
            fabric=self.fabric,
            telemetry=self.telemetry,
            cpu=self.cpu,
            gpu=self.gpu,
            npu=self.npu,
            board=self.board,
            dpi=self.dpi,
            scorer=self.scorer,
            ai_reasoner=self.ai_reasoner,
            persistence=self.persistence,
        )
        self.service_interval = self.ctx.config.get("service_interval_sec", 2.0)
        self._boot_panel()
        self.listener = SafeListener(self.ctx.config["listener_port"], self._on_packet)
        self._start_service_loop()
        self.listener.start()

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
        log.info(f"Always-on service loop started (interval={self.service_interval}s)")
        while True:
            w = self.pm.next()
            if w:
                self.scheduler.schedule(w)
                log.info(f"Service processed workload {w.id} ({w.cls.name})")
            time.sleep(self.service_interval)

    def _start_service_loop(self):
        self.service_thread = threading.Thread(target=self._service_loop, daemon=True)
        self.service_thread.start()

    def _on_packet(self, data: bytes, addr):
        w = Workload(f"pkt-{int(time.time())}", SecurityWorkload.FULL_PIPELINE, payload=data)
        self.submit(w)


# ============================================================
# GUI: MAIN PANEL + GRAPHS WINDOW (NO START/STOP)
# ============================================================

class MPUGui:
    def __init__(self, mpu: GoldenStarMPU):
        self.mpu = mpu
        self.root = tk.Tk()
        self.root.title("GoldenStar MPU – AI Security Appliance (Always-On)")
        self.root.geometry("700x650")

        self.build_layout()
        self.refresh_panel()

    def build_layout(self):
        self.title = ttk.Label(self.root, text="GoldenStar MPU – AI Security Appliance", font=("Arial", 16))
        self.title.pack(pady=10)

        self.info_box = tk.Text(self.root, height=18, width=80)
        self.info_box.pack(pady=10)

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack()

        ttk.Button(btn_frame, text="PACKET_CAPTURE", command=lambda: self.submit(SecurityWorkload.PACKET_CAPTURE)).grid(row=0, column=0, padx=5)
        ttk.Button(btn_frame, text="FLOW_RECON", command=lambda: self.submit(SecurityWorkload.FLOW_RECONSTRUCTION)).grid(row=0, column=1, padx=5)
        ttk.Button(btn_frame, text="DPI", command=lambda: self.submit(SecurityWorkload.DEEP_PACKET_INSPECTION)).grid(row=1, column=0, padx=5)
        ttk.Button(btn_frame, text="INFERENCE", command=lambda: self.submit(SecurityWorkload.THREAT_INFERENCE)).grid(row=1, column=1, padx=5)
        ttk.Button(btn_frame, text="PIPELINE", command=lambda: self.submit(SecurityWorkload.FULL_PIPELINE)).grid(row=2, column=0, padx=5)
        ttk.Button(btn_frame, text="LOG_INGEST", command=self.submit_log).grid(row=2, column=1, padx=5)

        ttk.Button(self.root, text="Refresh", command=self.refresh_panel).pack(pady=5)
        ttk.Button(self.root, text="Open Graphs", command=self.open_graphs).pack(pady=5)

    def submit(self, cls):
        w = Workload(f"gui-{int(time.time())}", cls)
        self.mpu.submit(w)
        self.refresh_panel()

    def submit_log(self):
        msg = "Failed login from 10.0.0.5"
        w = Workload(f"log-{int(time.time())}", SecurityWorkload.LOG_INGEST, payload=msg)
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

        self.info_box.insert(tk.END, "\nService: always running in background thread\n")
        self.info_box.insert(tk.END, "Listener port: " + str(self.mpu.ctx.config["listener_port"]) + "\n")

    def open_graphs(self):
        GraphWindow(self.mpu)

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
# COMMAND SHELL (NO START/STOP, SERVICE ALWAYS ON)
# ============================================================

def command_shell(mpu: GoldenStarMPU):
    print("MPU Command Shell (service always running)")
    print("Commands: submit, status, devices, bios, log, exit")
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
        elif cmd == "log":
            msg = input("Enter log message: ")
            w = Workload(f"log-{int(time.time())}", SecurityWorkload.LOG_INGEST, payload=msg)
            mpu.submit(w)
            print("Log submitted.")
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
