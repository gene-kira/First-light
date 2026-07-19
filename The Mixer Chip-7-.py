"""
Golden Star MPU – AI Security Engine v10

Upgrades in this revision:
- MLInferenceEngine:
  - Real ONNX runtime wiring (onnxruntime) when available
  - Per-model session, input name, threshold, weighting
  - Graceful fallback to ReplicaNPU math if ONNX not present or model load fails
- DPIEngine:
  - Loader for Suricata-style rule files (simplified)
  - Loader for YARA rule files (if yara-python available)
  - Rule objects enriched with external rule metadata

This is still a safe skeleton:
- No privileged capture; listener is local UDP only
- PCAP ingestion is stubbed
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
import re
import struct

# GUI
import tkinter as tk
from tkinter import ttk

# Optional external libs
try:
    import onnxruntime as ort
except ImportError:
    ort = None

try:
    import yara
except ImportError:
    yara = None

# ============================================================
# LOGGING
# ============================================================

logging.basicConfig(
    level=logging.INFO,
    format="[%(asctime)s] %(levelname)s: %(message)s",
)
log = logging.getLogger("GoldenStarMPU")


# ============================================================
# REPLICA NPU
# ============================================================

class ReplicaNPU:
    def __init__(self, cores=8, frequency_ghz=1.2):
        self.cores = cores
        self.frequency_ghz = frequency_ghz
        self.cycles = 0
        self.energy = 0.0

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
# LOADER
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
            "db_path": "mpu_ai_security.db",
            "listener_port": 5555,
            "pcap_path": "sample.pcap",
            "ml_models": {
                "anomaly": "anomaly.onnx",
                "malware": "malware.onnx",
                "behavior": "behavior.onnx",
            },
            "suricata_rules": "suricata.rules",
            "yara_rules": "yara_rules.yar",
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
# ADAPTER LAYER
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
        A = [features]
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
# PACKET PARSING
# ============================================================

class L4Proto(Enum):
    TCP = auto()
    UDP = auto()
    OTHER = auto()


@dataclass
class ParsedPacket:
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: L4Proto
    payload: bytes
    is_dns: bool = False
    is_http: bool = False
    is_tls: bool = False


class PacketParser:
    @staticmethod
    def parse_ethernet(data: bytes) -> Optional[Tuple[int, bytes]]:
        if len(data) < 14:
            return None
        eth_type = struct.unpack("!H", data[12:14])[0]
        return eth_type, data[14:]

    @staticmethod
    def parse_ipv4(header: bytes) -> Optional[Tuple[str, str, int, bytes]]:
        if len(header) < 20:
            return None
        version_ihl = header[0]
        version = version_ihl >> 4
        if version != 4:
            return None
        src_ip = ".".join(str(b) for b in header[12:16])
        dst_ip = ".".join(str(b) for b in header[16:20])
        proto = header[9]
        ihl = (version_ihl & 0x0F) * 4
        return src_ip, dst_ip, proto, header[ihl:]

    @staticmethod
    def parse_ipv6(header: bytes) -> Optional[Tuple[str, str, int, bytes]]:
        if len(header) < 40:
            return None
        version = header[0] >> 4
        if version != 6:
            return None
        src_ip = ":".join(f"{header[i]:02x}{header[i+1]:02x}" for i in range(8, 24, 2))
        dst_ip = ":".join(f"{header[i]:02x}{header[i+1]:02x}" for i in range(24, 40, 2))
        next_header = header[6]
        return src_ip, dst_ip, next_header, header[40:]

    @staticmethod
    def parse_l4(proto: int, data: bytes) -> Optional[Tuple[L4Proto, int, int, bytes]]:
        if proto == 6:
            if len(data) < 20:
                return None
            src_port, dst_port = struct.unpack("!HH", data[0:4])
            payload = data[20:]
            return L4Proto.TCP, src_port, dst_port, payload
        elif proto == 17:
            if len(data) < 8:
                return None
            src_port, dst_port = struct.unpack("!HH", data[0:4])
            payload = data[8:]
            return L4Proto.UDP, src_port, dst_port, payload
        else:
            return L4Proto.OTHER, 0, 0, data

    @staticmethod
    def detect_dns(proto: L4Proto, src_port: int, dst_port: int) -> bool:
        return proto == L4Proto.UDP and (src_port == 53 or dst_port == 53)

    @staticmethod
    def detect_http(proto: L4Proto, src_port: int, dst_port: int, payload: bytes) -> bool:
        if proto != L4Proto.TCP:
            return False
        if src_port in (80, 8080) or dst_port in (80, 8080):
            return True
        if payload.startswith(b"GET ") or payload.startswith(b"POST "):
            return True
        return False

    @staticmethod
    def detect_tls(proto: L4Proto, src_port: int, dst_port: int, payload: bytes) -> bool:
        if proto != L4Proto.TCP:
            return False
        if src_port in (443,) or dst_port in (443,):
            return True
        if payload.startswith(b"\x16\x03"):
            return True
        return False

    @staticmethod
    def parse_packet(data: bytes) -> Optional[ParsedPacket]:
        eth = PacketParser.parse_ethernet(data)
        if not eth:
            return None
        eth_type, ip_data = eth

        src_ip = dst_ip = ""
        proto = 0
        l4_data = b""

        if eth_type == 0x0800:
            ipv4 = PacketParser.parse_ipv4(ip_data)
            if not ipv4:
                return None
            src_ip, dst_ip, proto, l4_data = ipv4
        elif eth_type == 0x86DD:
            ipv6 = PacketParser.parse_ipv6(ip_data)
            if not ipv6:
                return None
            src_ip, dst_ip, proto, l4_data = ipv6
        else:
            return None

        l4 = PacketParser.parse_l4(proto, l4_data)
        if not l4:
            return None
        l4_proto, src_port, dst_port, payload = l4

        is_dns = PacketParser.detect_dns(l4_proto, src_port, dst_port)
        is_http = PacketParser.detect_http(l4_proto, src_port, dst_port, payload)
        is_tls = PacketParser.detect_tls(l4_proto, src_port, dst_port, payload)

        return ParsedPacket(
            src_ip=src_ip,
            dst_ip=dst_ip,
            src_port=src_port,
            dst_port=dst_port,
            protocol=l4_proto,
            payload=payload,
            is_dns=is_dns,
            is_http=is_http,
            is_tls=is_tls,
        )


# ============================================================
# DPI ENGINE – WITH SURICATA/YARA LOADING
# ============================================================

class FlowDirection(Enum):
    ANY = auto()
    SRC_TO_DST = auto()
    DST_TO_SRC = auto()


class DPIGroup(Enum):
    GENERIC = auto()
    HTTP = auto()
    DNS = auto()
    TLS = auto()


@dataclass
class DPIRule:
    name: str
    group: DPIGroup
    severity: int
    confidence: float
    pcre: Optional[str] = None
    raw_pattern: Optional[bytes] = None
    ports: Optional[List[int]] = None
    proto: Optional[L4Proto] = None
    direction: FlowDirection = FlowDirection.ANY
    tags: List[str] = field(default_factory=list)
    source: str = "builtin"  # builtin / suricata / yara

    def matches(self, packet: ParsedPacket) -> bool:
        if self.proto and packet.protocol != self.proto:
            return False
        if self.ports:
            if packet.src_port not in self.ports and packet.dst_port not in self.ports:
                return False
        if self.group == DPIGroup.HTTP and not packet.is_http:
            return False
        if self.group == DPIGroup.DNS and not packet.is_dns:
            return False
        if self.group == DPIGroup.TLS and not packet.is_tls:
            return False

        payload = packet.payload
        if self.raw_pattern and self.raw_pattern not in payload:
            return False

        if self.pcre:
            try:
                if not re.search(self.pcre.encode("utf-8"), payload):
                    return False
            except Exception:
                return False

        return True


@dataclass
class DPIMatch:
    rule: DPIRule
    packet: ParsedPacket


class DPIEngine:
    def __init__(self, cfg: Dict[str, Any]):
        self.rules: List[DPIRule] = self._build_default_rules()
        self.yara_ruleset = None
        self._load_suricata_rules(cfg.get("suricata_rules"))
        self._load_yara_rules(cfg.get("yara_rules"))

    def _build_default_rules(self) -> List[DPIRule]:
        rules = [
            DPIRule(
                name="GENERIC_MALWARE_STRING",
                group=DPIGroup.GENERIC,
                severity=5,
                confidence=0.7,
                raw_pattern=b"malware",
                tags=["malware", "generic"],
            ),
            DPIRule(
                name="HTTP_EXPLOIT_PAYLOAD",
                group=DPIGroup.HTTP,
                severity=7,
                confidence=0.8,
                pcre=r"exploit|shellcode",
                ports=[80, 8080],
                proto=L4Proto.TCP,
                tags=["exploit", "http"],
            ),
            DPIRule(
                name="DNS_SUSPICIOUS_DOMAIN",
                group=DPIGroup.DNS,
                severity=4,
                confidence=0.6,
                pcre=r"evil\.example\.com",
                ports=[53],
                proto=L4Proto.UDP,
                tags=["dns", "c2"],
            ),
            DPIRule(
                name="TLS_SUSPICIOUS_CLIENT_HELLO",
                group=DPIGroup.TLS,
                severity=6,
                confidence=0.75,
                raw_pattern=b"\x16\x03",
                ports=[443],
                proto=L4Proto.TCP,
                tags=["tls", "c2"],
            ),
        ]
        return rules

    def _load_suricata_rules(self, path: Optional[str]):
        if not path or not os.path.exists(path):
            log.info("Suricata rules file not found, using builtin DPI rules only.")
            return
        log.info(f"Loading Suricata rules from {path}")
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    # Very simplified Suricata rule parsing:
                    # alert tcp any any -> any 80 (msg:"Example"; content:"malware"; sid:1000001;)
                    if "content:" in line:
                        name = "SURICATA_RULE"
                        severity = 5
                        confidence = 0.6
                        ports = None
                        proto = None
                        group = DPIGroup.GENERIC
                        tags = ["suricata"]

                        if "http" in line.lower():
                            group = DPIGroup.HTTP
                        if "dns" in line.lower():
                            group = DPIGroup.DNS
                        if "tls" in line.lower():
                            group = DPIGroup.TLS

                        if "tcp" in line.lower():
                            proto = L4Proto.TCP
                        elif "udp" in line.lower():
                            proto = L4Proto.UDP

                        m = re.search(r'content:"([^"]+)"', line)
                        raw_pattern = None
                        if m:
                            raw_pattern = m.group(1).encode("utf-8")

                        rule = DPIRule(
                            name=name,
                            group=group,
                            severity=severity,
                            confidence=confidence,
                            raw_pattern=raw_pattern,
                            ports=ports,
                            proto=proto,
                            tags=tags,
                            source="suricata",
                        )
                        self.rules.append(rule)
            log.info(f"Suricata rules loaded, total DPI rules: {len(self.rules)}")
        except Exception as e:
            log.warning(f"Failed to load Suricata rules: {e}")

    def _load_yara_rules(self, path: Optional[str]):
        if yara is None:
            log.info("yara-python not available, skipping YARA rules.")
            return
        if not path or not os.path.exists(path):
            log.info("YARA rules file not found, skipping.")
            return
        try:
            self.yara_ruleset = yara.compile(filepath=path)
            log.info(f"YARA rules loaded from {path}")
        except Exception as e:
            log.warning(f"Failed to compile YARA rules: {e}")
            self.yara_ruleset = None

    def scan(self, packet: ParsedPacket) -> List[DPIMatch]:
        matches: List[DPIMatch] = []
        for rule in self.rules:
            if rule.matches(packet):
                matches.append(DPIMatch(rule=rule, packet=packet))

        if self.yara_ruleset:
            try:
                res = self.yara_ruleset.match(data=packet.payload)
                for r in res:
                    rule = DPIRule(
                        name=f"YARA_{r.rule}",
                        group=DPIGroup.GENERIC,
                        severity=6,
                        confidence=0.8,
                        tags=["yara"],
                        source="yara",
                    )
                    matches.append(DPIMatch(rule=rule, packet=packet))
            except Exception as e:
                log.debug(f"YARA match error: {e}")

        return matches


# ============================================================
# LOG INGESTION
# ============================================================

@dataclass
class LogEntry:
    timestamp: float
    source: str
    message: str
    raw: Dict[str, Any] = field(default_factory=dict)


class LogIngestor:
    def ingest_windows_event(self, raw: Dict[str, Any]) -> LogEntry:
        msg = raw.get("Message", "")
        return LogEntry(time.time(), "windows_event", msg, raw)

    def ingest_syslog_rfc5424(self, line: str) -> LogEntry:
        return LogEntry(time.time(), "syslog", line, {"raw": line})

    def ingest_cloud_log(self, provider: str, raw: Dict[str, Any]) -> LogEntry:
        msg = raw.get("message", "")
        return LogEntry(time.time(), f"cloud_{provider}", msg, raw)

    def ingest_generic(self, msg: str, source: str = "generic") -> LogEntry:
        return LogEntry(time.time(), source, msg, {"message": msg})


# ============================================================
# ML INFERENCE – WITH ONNXRUNTIME
# ============================================================

@dataclass
class MLModelConfig:
    path: str
    kind: str
    threshold: float
    weight: float


@dataclass
class MLModelRuntime:
    cfg: MLModelConfig
    session: Any = None
    input_name: Optional[str] = None


@dataclass
class MLFeatureVector:
    packet_features: List[float]
    dpi_features: List[float]
    log_features: List[float]
    sandbox_features: List[float]

    def as_flat(self) -> List[float]:
        return self.packet_features + self.dpi_features + self.log_features + self.sandbox_features


class MLInferenceEngine:
    """
    Production-style skeleton with real ONNX runtime:
    - MLModelConfig defines ONNX path, kind, threshold, weight
    - MLModelRuntime holds session + input name
    - If onnxruntime or model load fails, falls back to ReplicaNPU math
    """

    def __init__(self, npu: LegacyNPUAdapter, cfg: Dict[str, str]):
        self.npu = npu
        self.model_cfgs: List[MLModelConfig] = [
            MLModelConfig(cfg.get("anomaly", "anomaly.onnx"), "anomaly", threshold=0.6, weight=0.4),
            MLModelConfig(cfg.get("malware", "malware.onnx"), "malware", threshold=0.7, weight=0.5),
            MLModelConfig(cfg.get("behavior", "behavior.onnx"), "behavior", threshold=0.5, weight=0.3),
        ]
        self.models: List[MLModelRuntime] = []
        self._init_models()

    def _init_models(self):
        for cfg in self.model_cfgs:
            runtime = MLModelRuntime(cfg=cfg)
            if ort is not None and os.path.exists(cfg.path):
                try:
                    sess = ort.InferenceSession(cfg.path, providers=["CPUExecutionProvider"])
                    input_name = sess.get_inputs()[0].name
                    runtime.session = sess
                    runtime.input_name = input_name
                    log.info(f"Loaded ONNX model {cfg.kind} from {cfg.path}")
                except Exception as e:
                    log.warning(f"Failed to load ONNX model {cfg.path}: {e}")
            else:
                if ort is None:
                    log.info(f"onnxruntime not available, using NPU fallback for {cfg.kind}")
                else:
                    log.info(f"ONNX model path {cfg.path} not found, using NPU fallback for {cfg.kind}")
            self.models.append(runtime)

    def build_features(
        self,
        packet: Optional[ParsedPacket],
        dpi_matches: List[DPIMatch],
        logs: List[LogEntry],
        sandbox: Optional["SandboxResult"],
    ) -> MLFeatureVector:
        packet_features = []
        if packet:
            packet_features = [
                len(packet.payload),
                packet.src_port,
                packet.dst_port,
                1.0 if packet.is_http else 0.0,
                1.0 if packet.is_dns else 0.0,
                1.0 if packet.is_tls else 0.0,
            ]
        else:
            packet_features = [0.0] * 6

        dpi_features = [
            float(len(dpi_matches)),
            sum(m.rule.severity for m in dpi_matches),
            sum(m.rule.confidence for m in dpi_matches),
        ]

        log_features = [
            float(len(logs)),
            sum(1.0 for l in logs if "failed login" in l.message.lower()),
            sum(1.0 for l in logs if "error" in l.message.lower()),
        ]

        sandbox_features = []
        if sandbox:
            sandbox_features = [
                sandbox.memory_diff_score,
                sandbox.syscall_score,
                sandbox.behavior_score,
            ]
        else:
            sandbox_features = [0.0, 0.0, 0.0]

        return MLFeatureVector(
            packet_features=packet_features,
            dpi_features=dpi_features,
            log_features=log_features,
            sandbox_features=sandbox_features,
        )

    def infer(self, features: MLFeatureVector) -> Dict[str, float]:
        flat = features.as_flat()
        scores: Dict[str, float] = {}
        for runtime in self.models:
            cfg = runtime.cfg
            if runtime.session and runtime.input_name:
                try:
                    import numpy as np
                    inp = np.array([flat], dtype=np.float32)
                    out = runtime.session.run(None, {runtime.input_name: inp})
                    val = float(out[0].ravel()[0])
                    score = max(0.0, min(1.0, val))
                except Exception as e:
                    log.debug(f"ONNX inference error for {cfg.kind}: {e}")
                    base = self.npu.run_inference(flat)
                    score = min(1.0, base / 1000.0)
            else:
                base = self.npu.run_inference(flat)
                score = min(1.0, base / 1000.0)

            scores[cfg.kind] = score
        return scores


# ============================================================
# SANDBOX
# ============================================================

@dataclass
class SandboxResult:
    memory_diff_score: float
    syscall_score: float
    behavior_score: float
    notes: List[str]


class SandboxEngine:
    def analyze(self, payload: bytes) -> SandboxResult:
        length = len(payload)
        memory_diff_score = min(1.0, length / 10000.0)
        syscall_score = random.uniform(0.0, 0.5)
        behavior_score = (memory_diff_score + syscall_score) / 2.0
        notes = []
        if memory_diff_score > 0.5:
            notes.append("Large payload suggests complex behavior.")
        if syscall_score > 0.3:
            notes.append("Simulated syscall pattern suggests suspicious activity.")
        return SandboxResult(memory_diff_score, syscall_score, behavior_score, notes)


# ============================================================
# THREAT SCORING + MITRE + AI REASONING
# ============================================================

class RiskCategory(Enum):
    LOW = auto()
    MEDIUM = auto()
    HIGH = auto()
    CRITICAL = auto()


@dataclass
class ThreatScore:
    risk: float
    confidence: float
    reasons: List[str]
    mitre_techniques: List[str]
    category: RiskCategory


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

    def map_mitre(self, dpi_matches: List[DPIMatch], logs: List[LogEntry]) -> List[str]:
        techniques = []
        for m in dpi_matches:
            name = m.rule.name.lower()
            if "malware" in name:
                techniques.append("T1059: Command and Scripting Interpreter")
            if "exploit" in name:
                techniques.append("T1190: Exploit Public-Facing Application")
            if "dns" in m.rule.tags:
                techniques.append("T1071: Application Layer Protocol")
            if "yara" in m.rule.tags:
                techniques.append("T1020: Data Exfiltration")
        for log in logs:
            msg = log.message.lower()
            if "failed login" in msg:
                techniques.append("T1110: Brute Force")
        return list(set(techniques))

    def categorize(self, risk: float) -> RiskCategory:
        if risk < 0.3:
            return RiskCategory.LOW
        elif risk < 0.6:
            return RiskCategory.MEDIUM
        elif risk < 0.8:
            return RiskCategory.HIGH
        else:
            return RiskCategory.CRITICAL

    def score(
        self,
        dpi_matches: List[DPIMatch],
        logs: List[LogEntry],
        ml_scores: Dict[str, float],
        sandbox: Optional[SandboxResult],
    ) -> ThreatScore:
        risk = 0.0
        reasons = []

        for m in dpi_matches:
            risk += m.rule.severity * 0.08
            reasons.append(f"DPI rule {m.rule.name} (sev={m.rule.severity}, conf={m.rule.confidence:.2f}, src={m.rule.source})")

        for log in logs:
            msg = log.message.lower()
            if "failed login" in msg:
                risk += 0.2
                reasons.append("Log: failed login detected")
            if "error" in msg:
                risk += 0.1
                reasons.append("Log: error message")

        for kind, score in ml_scores.items():
            if score > 0.5:
                risk += 0.2
                reasons.append(f"ML {kind} score high ({score:.2f})")

        if sandbox:
            risk += sandbox.behavior_score * 0.3
            reasons.append(f"Sandbox behavior score {sandbox.behavior_score:.2f}")
            for n in sandbox.notes:
                reasons.append(f"Sandbox note: {n}")

        risk = min(1.0, risk)
        confidence = min(1.0, 0.5 + risk / 2.0)
        mitre = self.map_mitre(dpi_matches, logs)
        category = self.categorize(risk)

        return ThreatScore(risk, confidence, reasons, mitre, category)


class AIReasoningEngine:
    def explain(self, score: ThreatScore) -> str:
        lines = []
        lines.append(f"Threat Risk: {score.risk:.2f}, Confidence: {score.confidence:.2f}, Category: {score.category.name}")
        if score.mitre_techniques:
            lines.append("Mapped MITRE ATT&CK techniques:")
            for t in score.mitre_techniques:
                lines.append(f"  - {t}")
        if not score.reasons:
            lines.append("No strong indicators detected. Likely benign or low-risk activity.")
        else:
            lines.append("Contributing factors:")
            for r in score.reasons:
                lines.append(f"  - {r}")

        lines.append("\nSummary:")
        if score.risk > 0.8:
            lines.append("Activity appears highly suspicious with multiple indicators across DPI, logs, ML, and sandbox.")
        elif score.risk > 0.5:
            lines.append("Activity shows several moderate indicators that warrant closer monitoring.")
        else:
            lines.append("Activity shows limited indicators and may be routine or benign.")

        lines.append("\nRecommended remediation steps:")
        if score.category in (RiskCategory.HIGH, RiskCategory.CRITICAL):
            lines.append("  - Isolate affected hosts from the network.")
            lines.append("  - Capture full packet traces and logs for forensic analysis.")
            lines.append("  - Review authentication logs for brute-force or credential misuse.")
        elif score.category == RiskCategory.MEDIUM:
            lines.append("  - Add the source to a watchlist and increase logging verbosity.")
            lines.append("  - Review recent configuration changes and access patterns.")
        else:
            lines.append("  - Continue monitoring and retain logs for future correlation.")

        lines.append("\nAttack path reconstruction (hypothetical):")
        lines.append("  - Initial access via suspicious network payload or failed login attempts.")
        lines.append("  - Potential lateral movement indicated by repeated flows between hosts.")
        lines.append("  - Possible command-and-control or data exfiltration if TLS/HTTP patterns persist.")

        return "\n".join(lines)


# ============================================================
# PERSISTENCE
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
            category TEXT,
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
        INSERT INTO threats (ts, risk, confidence, category, explanation)
        VALUES (?, ?, ?, ?, ?)
        """, (time.time(), score.risk, score.confidence, score.category.name, explanation))
        conn.commit()
        conn.close()

    def get_recent_threats(self, limit: int = 10) -> List[Tuple]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT ts, risk, confidence, category FROM threats ORDER BY ts DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        conn.close()
        return rows

    def get_threat_timeline(self) -> List[Tuple]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT ts, risk, category FROM threats ORDER BY ts ASC")
        rows = cur.fetchall()
        conn.close()
        return rows


# ============================================================
# NETWORKING
# ============================================================

class PCAPIngestor:
    def ingest_file(self, path: str) -> List[bytes]:
        if not os.path.exists(path):
            return []
        frames = []
        try:
            with open(path, "rb") as f:
                data = f.read()
            frames.append(data)
        except Exception:
            pass
        return frames


class SafeListener:
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
                data, addr = sock.recvfrom(4096)
                self.callback(data, addr)
            except Exception:
                pass
        sock.close()
        log.info("SafeListener stopped.")


# ============================================================
# CORE MPU STRUCTURES
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
    ml_engine: MLInferenceEngine
    sandbox: SandboxEngine
    log_ingestor: LogIngestor

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

        dpi_matches: List[DPIMatch] = []
        logs: List[LogEntry] = []
        ml_scores: Dict[str, float] = {}
        sandbox_result: Optional[SandboxResult] = None
        packet: Optional[ParsedPacket] = None

        if isinstance(w.payload, bytes):
            packet = PacketParser.parse_packet(w.payload)
            if packet:
                self.scorer.update_flow(packet)
                dpi_matches = self.dpi.scan(packet)
                sandbox_result = self.sandbox.analyze(packet.payload)

        if isinstance(w.payload, str):
            logs.append(self.log_ingestor.ingest_generic(w.payload, source="generic"))

        if isinstance(w.payload, dict):
            src = w.payload.get("source", "generic")
            if src == "windows":
                logs.append(self.log_ingestor.ingest_windows_event(w.payload))
            elif src == "syslog":
                logs.append(self.log_ingestor.ingest_syslog_rfc5424(w.payload.get("line", "")))
            elif src in ("aws", "azure", "gcp"):
                logs.append(self.log_ingestor.ingest_cloud_log(src, w.payload))
            else:
                logs.append(self.log_ingestor.ingest_generic(str(w.payload), source=src))

        features = self.ml_engine.build_features(packet, dpi_matches, logs, sandbox_result)
        ml_scores = self.ml_engine.infer(features)

        if dpi_matches or logs or ml_scores or sandbox_result:
            score = self.scorer.score(dpi_matches, logs, ml_scores, sandbox_result)
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
    dpi: DPIEngine = field(init=False)
    scorer: ThreatScorer = field(default_factory=ThreatScorer)
    ai_reasoner: AIReasoningEngine = field(default_factory=AIReasoningEngine)
    persistence: Persistence = field(init=False)
    ml_engine: MLInferenceEngine = field(init=False)
    sandbox: SandboxEngine = field(default_factory=SandboxEngine)
    log_ingestor: LogIngestor = field(default_factory=LogIngestor)
    scheduler: Scheduler = field(init=False)
    pm: ProcessManager = field(default_factory=ProcessManager)
    service_thread: Optional[threading.Thread] = field(default=None)
    listener: Optional[SafeListener] = field(default=None)
    service_interval: float = field(default=2.0)
    pcap_ingestor: PCAPIngestor = field(default_factory=PCAPIngestor)

    def __post_init__(self):
        self.gpu = LegacyGPUAdapter(self.ctx.hardware["gpu"])
        self.npu = LegacyNPUAdapter(self.npu_core)
        self.board = BoardMemoryAdapter(self.ctx.config["board_memory_gb"])
        self.persistence = Persistence(self.ctx.config["db_path"])
        self.dpi = DPIEngine(self.ctx.config)
        self.ml_engine = MLInferenceEngine(self.npu, self.ctx.config.get("ml_models", {}))
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
            ml_engine=self.ml_engine,
            sandbox=self.sandbox,
            log_ingestor=self.log_ingestor,
        )
        self.service_interval = self.ctx.config.get("service_interval_sec", 2.0)
        self._boot_panel()
        self.listener = SafeListener(self.ctx.config["listener_port"], self._on_packet)
        self._start_service_loop()
        self.listener.start()
        self._ingest_initial_pcap()

    def _boot_panel(self):
        print("=" * 60)
        print("GoldenStarMPU AI Security Engine Boot Panel")
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

    def _ingest_initial_pcap(self):
        frames = self.pcap_ingestor.ingest_file(self.ctx.config.get("pcap_path", "sample.pcap"))
        for i, frame in enumerate(frames):
            w = Workload(f"pcap-{i}", SecurityWorkload.FULL_PIPELINE, payload=frame)
            self.submit(w)


# ============================================================
# GUI
# ============================================================

class MPUGui:
    def __init__(self, mpu: GoldenStarMPU):
        self.mpu = mpu
        self.root = tk.Tk()
        self.root.title("GoldenStar MPU – AI Security Engine (Always-On)")
        self.root.geometry("900x700")

        self.build_layout()
        self.refresh_panel()

    def build_layout(self):
        self.title = ttk.Label(self.root, text="GoldenStar MPU – AI Security Engine", font=("Arial", 16))
        self.title.pack(pady=10)

        self.info_box = tk.Text(self.root, height=18, width=100)
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
        ttk.Button(self.root, text="Threat Dashboard", command=self.open_dashboard).pack(pady=5)

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
        self.info_box.insert(tk.END, "PCAP path: " + str(self.mpu.ctx.config.get("pcap_path", "sample.pcap")) + "\n")

        self.info_box.insert(tk.END, "\nDPI rules loaded: " + str(len(self.mpu.dpi.rules)) + "\n")
        if self.mpu.dpi.yara_ruleset:
            self.info_box.insert(tk.END, "YARA ruleset: loaded\n")
        else:
            self.info_box.insert(tk.END, "YARA ruleset: not loaded\n")

    def open_graphs(self):
        GraphWindow(self.mpu)

    def open_dashboard(self):
        DashboardWindow(self.mpu)

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


class DashboardWindow:
    def __init__(self, mpu: GoldenStarMPU):
        self.mpu = mpu
        self.win = tk.Toplevel()
        self.win.title("Threat Dashboard")
        self.win.geometry("700x500")

        self.text = tk.Text(self.win, height=25, width=80)
        self.text.pack(pady=10)

        self.update_dashboard()

    def update_dashboard(self):
        self.text.delete("1.0", tk.END)
        recent = self.mpu.persistence.get_recent_threats(10)
        self.text.insert(tk.END, "Recent Threats:\n")
        for ts, risk, conf, cat in recent:
            t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
            self.text.insert(tk.END, f"  [{t_str}] Risk={risk:.2f}, Conf={conf:.2f}, Category={cat}\n")

        timeline = self.mpu.persistence.get_threat_timeline()
        self.text.insert(tk.END, "\nThreat Timeline:\n")
        for ts, risk, cat in timeline[-20:]:
            t_str = time.strftime("%H:%M:%S", time.localtime(ts))
            self.text.insert(tk.END, f"  {t_str}: Risk={risk:.2f}, Category={cat}\n")

        self.win.after(3000, self.update_dashboard)


# ============================================================
# COMMAND SHELL
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
            recent = mpu.persistence.get_recent_threats(5)
            print("Recent threats:")
            for ts, risk, conf, cat in recent:
                t_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(ts))
                print(f"  [{t_str}] Risk={risk:.2f}, Conf={conf:.2f}, Category={cat}")
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
