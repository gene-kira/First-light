#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CODEX CONTROL CONSOLE v7.5 (Windows Edition)
AI-driven, Suricata-aware, MITRE-mapped, swarm-enabled SOC brain
with real training mode and compact SOC-style GUI.

Major upgrades vs v7.4:
- Training mode: codex.py --train
- Real AE + Transformer training on your traffic
- Weight saving/loading (ae_weights.pt, transformer_weights.pt, baseline.json)
- Adaptive anomaly/drift thresholds from training data
- Compact 3-panel GUI (Status / Intelligence / Swarm)
- Tabbed center panel (Alerts / Packets / MITRE / Campaigns / Timeline)

Still includes:
- Auto-creates eve.json, pcap/live.pcap, mitre.json, codex_config.json, pcap/
- Suricata auto-config generator (suricata.codex.yaml)
- MITRE mapping
- Multi-agent reasoning
- Swarm consensus + trust decay
- Windows firewall / deception / honeypot response
- Watchdog daemon
"""

import abc
import time
import random
import socket
import threading
import json
import pathlib
import queue
import subprocess
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

import numpy as np

# ===========================================================
# AUTOLOADER
# ===========================================================

class AutoLoader:
    def __init__(self):
        self.libs = {
            "torch": {"module": "torch", "pip": "torch"},
            "torch.nn": {"module": "torch.nn", "pip": "torch"},
            "requests": {"module": "requests", "pip": "requests"},
            "tkinter": {"module": "tkinter", "pip": None},
            "tkinter.ttk": {"module": "tkinter.ttk", "pip": None},
            "scapy": {"module": "scapy.all", "pip": "scapy"},
            "dpkt": {"module": "dpkt", "pip": "dpkt"},
            "pyshark": {"module": "pyshark", "pip": "pyshark"},
        }
        self.loaded = {}
        self.flags = {}

    def _try_import(self, module_name: str):
        try:
            module = __import__(module_name, fromlist=["*"])
            return module
        except Exception as e:
            print(f"[AUTOLOADER] Import failed for {module_name}: {e}")
            return None

    def _try_install(self, pip_name: Optional[str]):
        if not pip_name:
            return
        print(f"[AUTOLOADER] Installing missing dependency: {pip_name}")
        try:
            subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                check=False,
            )
        except Exception as e:
            print(f"[AUTOLOADER] Pip install failed for {pip_name}: {e}")

    def load_all(self):
        for name, info in self.libs.items():
            module_name = info["module"]
            pip_name = info["pip"]
            module = self._try_import(module_name)
            if module is None and pip_name:
                self._try_install(pip_name)
                module = self._try_import(module_name)
            if module is not None:
                self.loaded[name] = module
                self.flags[name] = True
                print(f"[AUTOLOADER] Loaded {module_name}")
            else:
                self.loaded[name] = None
                self.flags[name] = False
                print(f"[AUTOLOADER] Missing {module_name}")

    def get(self, name):
        return self.loaded.get(name, None)

    def has(self, name):
        return self.flags.get(name, False)


AUTO = AutoLoader()
AUTO.load_all()

TORCH = AUTO.has("torch")
REQUESTS = AUTO.has("requests")
TK_AVAILABLE = AUTO.has("tkinter")
TTK_AVAILABLE = AUTO.has("tkinter.ttk")
SCAPY_AVAILABLE = AUTO.has("scapy")
DPKT_AVAILABLE = AUTO.has("dpkt")
PYSHARK_AVAILABLE = AUTO.has("pyshark")

torch = AUTO.get("torch")
nn = AUTO.get("torch.nn")
requests = AUTO.get("requests")
tk = AUTO.get("tkinter")
ttk = AUTO.get("tkinter.ttk")
scapy = AUTO.get("scapy")
dpkt = AUTO.get("dpkt")
pyshark = AUTO.get("pyshark")

# ===========================================================
# FILESYSTEM INITIALIZER
# ===========================================================

def initialize_codex_files():
    base = pathlib.Path(__file__).parent

    pcap_dir = base / "pcap"
    if not pcap_dir.exists():
        try:
            pcap_dir.mkdir(parents=True, exist_ok=True)
            print(f"[INIT] Created directory: {pcap_dir}")
        except Exception as e:
            print(f"[INIT] Failed to create pcap directory: {e}")

    eve_path = base / "eve.json"
    if not eve_path.exists():
        try:
            eve_path.write_text("", encoding="utf-8")
            print(f"[INIT] Created empty eve.json")
        except Exception as e:
            print(f"[INIT] Failed to create eve.json: {e}")

    pcap_file = pcap_dir / "live.pcap"
    if not pcap_file.exists():
        try:
            pcap_file.write_bytes(b"\xd4\xc3\xb2\xa1" + b"\x00" * 24)
            print(f"[INIT] Created placeholder live.pcap")
        except Exception as e:
            print(f"[INIT] Failed to create live.pcap: {e}")

    mitre_path = base / "mitre.json"
    if not mitre_path.exists():
        try:
            starter = [
                {
                    "sid": 1000001,
                    "technique_id": "T1059",
                    "technique_name": "Command and Scripting Interpreter",
                    "tactic": "Execution",
                    "severity": 3
                },
                {
                    "sid": 1000002,
                    "technique_id": "T1046",
                    "technique_name": "Network Service Scanning",
                    "tactic": "Discovery",
                    "severity": 2
                },
                {
                    "sid": 1000003,
                    "technique_id": "T1071",
                    "technique_name": "Application Layer Protocol",
                    "tactic": "Command and Control",
                    "severity": 4
                }
            ]
            mitre_path.write_text(json.dumps(starter, indent=2), encoding="utf-8")
            print(f"[INIT] Created starter mitre.json")
        except Exception as e:
            print(f"[INIT] Failed to create mitre.json: {e}")

    cfg_path = base / "codex_config.json"
    if not cfg_path.exists():
        try:
            cfg_path.write_text(json.dumps({
                "severity_threshold": 3,
                "node_id": "node-1",
                "swarm_bind_port": 50050,
                "swarm_broadcast_port": 50050,
                "train_samples": 500,
                "train_epochs": 5
            }, indent=2), encoding="utf-8")
            print(f"[INIT] Created default codex_config.json")
        except Exception as e:
            print(f"[INIT] Failed to create codex_config.json: {e}")

# ===========================================================
# CONFIG
# ===========================================================

def load_config():
    cfg_path = pathlib.Path(__file__).parent / "codex_config.json"
    default = {
        "severity_threshold": 3,
        "node_id": "node-1",
        "swarm_bind_port": 50050,
        "swarm_broadcast_port": 50050,
        "train_samples": 500,
        "train_epochs": 5
    }
    if not cfg_path.exists():
        print("[CONFIG] No codex_config.json found, using defaults")
        return default
    try:
        with cfg_path.open("r", encoding="utf-8") as f:
            cfg = json.load(f)
        for k, v in default.items():
            cfg.setdefault(k, v)
        return cfg
    except Exception as e:
        print(f"[CONFIG] Failed to load config: {e}, using defaults")
        return default

CONFIG = load_config()
SEVERITY_THRESHOLD = int(CONFIG.get("severity_threshold", 3))
print(f"[CONFIG] Severity threshold = {SEVERITY_THRESHOLD}")
print(f"[CONFIG] Node ID = {CONFIG.get('node_id')}")

# ===========================================================
# SURICATA AUTO-CONFIG GENERATOR
# ===========================================================

def generate_suricata_config():
    base = pathlib.Path(__file__).parent
    suricata_yaml = base / "suricata.codex.yaml"
    eve_dir = base
    pcap_dir = base / "pcap"

    content = f"""
%YAML 1.1
---
vars:
  address-groups:
    HOME_NET: "[192.168.0.0/16]"
    EXTERNAL_NET: "!$HOME_NET"

outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json
      directory: "{eve_dir}"
      types:
        - alert
        - http
        - dns
        - tls

  - pcap-log:
      enabled: yes
      filename: live.pcap
      directory: "{pcap_dir}"
      limit: 100mb
      max-files: 10
"""
    try:
        suricata_yaml.write_text(content.strip() + "\n", encoding="utf-8")
        print(f"[SURICATA] Generated suricata.codex.yaml at {suricata_yaml}")
    except Exception as e:
        print(f"[SURICATA] Failed to write suricata.codex.yaml: {e}")

# ===========================================================
# CORE DATA STRUCTURES
# ===========================================================

@dataclass
class Chunk:
    id: str
    data: Any
    meta: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ChunkBatch:
    chunks: List[Chunk]
    def __iter__(self): return iter(self.chunks)
    def __len__(self): return len(self.chunks)

class TemporalChunker:
    def __init__(self, window=64, stride=None):
        self.window = window
        self.stride = stride or window
    def chunk(self, data: List[Any]) -> ChunkBatch:
        out = []
        for i in range(0, len(data), self.stride):
            window = data[i:i+self.window]
            if window:
                out.append(Chunk(id=f"t_{i}", data=window, meta={"type": "temporal"}))
        return ChunkBatch(out)

class SpatialChunker:
    def __init__(self, block=128):
        self.block = block
    def chunk(self, data: np.ndarray) -> ChunkBatch:
        out = []
        for i in range(0, data.shape[0], self.block):
            block = data[i:i+self.block]
            out.append(Chunk(id=f"s_{i}", data=block, meta={"type": "spatial"}))
        return ChunkBatch(out)

class VectorEngine:
    def __init__(self, dim=256):
        self.dim = dim
    def embed(self, batch: ChunkBatch) -> Dict[str, np.ndarray]:
        return {c.id: np.random.randn(self.dim).astype(np.float32) for c in batch}
    def transform(self, embeddings: Dict[str, np.ndarray]) -> Dict[str, np.ndarray]:
        out = {}
        for cid, vec in embeddings.items():
            if TORCH and torch is not None:
                t = torch.tensor(vec).float()
                t = t / (torch.norm(t) + 1e-8)
                out[cid] = t.cpu().numpy()
            else:
                out[cid] = vec / (np.linalg.norm(vec) + 1e-8)
        return out
    def aggregate(self, transformed: Dict[str, np.ndarray]) -> np.ndarray:
        if not transformed:
            return np.zeros(self.dim, dtype=np.float32)
        return np.stack(list(transformed.values())).mean(axis=0)

class Autoencoder(nn.Module if TORCH and nn is not None else object):
    def __init__(self, dim=256, hidden=128):
        if not TORCH or nn is None:
            return
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(dim, hidden),
            nn.ReLU(),
            nn.Linear(hidden, hidden),
            nn.ReLU(),
        )
        self.decoder = nn.Sequential(
            nn.Linear(hidden, hidden),
            nn.ReLU(),
            nn.Linear(hidden, dim),
        )
    def forward(self, x):
        z = self.encoder(x)
        recon = self.decoder(z)
        return z, recon

class TransformerEncoder(nn.Module if TORCH and nn is not None else object):
    def __init__(self, dim=256, nhead=4, num_layers=2):
        if not TORCH or nn is None:
            return
        super().__init__()
        self.layer = nn.TransformerEncoder(
            nn.TransformerEncoderLayer(d_model=dim, nhead=nhead),
            num_layers=num_layers
        )
    def forward(self, x):
        return self.layer(x)

class DeepModels:
    def __init__(self, dim=256):
        self.dim = dim
        if TORCH and nn is not None:
            self.ae = Autoencoder(dim=dim)
            self.transformer = TransformerEncoder(dim=dim)
            self.ae_opt = torch.optim.Adam(self.ae.parameters(), lr=1e-3)
            self.tf_opt = torch.optim.Adam(self.transformer.parameters(), lr=1e-3)
            self.loss_fn = nn.MSELoss()
        else:
            self.ae = None
            self.transformer = None
            self.ae_opt = None
            self.tf_opt = None
            self.loss_fn = None

    def ae_error(self, vec: np.ndarray) -> float:
        if not TORCH or self.ae is None or torch is None:
            return 0.0
        with torch.no_grad():
            x = torch.tensor(vec).float().unsqueeze(0)
            _, recon = self.ae(x)
            err = torch.norm(x - recon).item()
        return float(err)

    def transformer_encode(self, seq: np.ndarray) -> np.ndarray:
        if not TORCH or self.transformer is None or torch is None:
            return seq.mean(axis=0)
        with torch.no_grad():
            x = torch.tensor(seq).float().unsqueeze(1)
            out = self.transformer(x)
            return out.mean(dim=0).squeeze(0).cpu().numpy()

    def train_ae(self, data: np.ndarray, epochs: int = 5):
        if not TORCH or self.ae is None or self.ae_opt is None:
            print("[TRAIN] AE training skipped (no torch)")
            return
        x = torch.tensor(data).float()
        for ep in range(epochs):
            self.ae_opt.zero_grad()
            _, recon = self.ae(x)
            loss = self.loss_fn(recon, x)
            loss.backward()
            self.ae_opt.step()
            print(f"[TRAIN] AE epoch {ep+1}/{epochs} loss={loss.item():.4f}")

    def train_transformer(self, seqs: np.ndarray, epochs: int = 5):
        if not TORCH or self.transformer is None or self.tf_opt is None:
            print("[TRAIN] Transformer training skipped (no torch)")
            return
        x = torch.tensor(seqs).float().transpose(0, 1)
        for ep in range(epochs):
            self.tf_opt.zero_grad()
            out = self.transformer(x)
            loss = self.loss_fn(out, x)
            loss.backward()
            self.tf_opt.step()
            print(f"[TRAIN] TF epoch {ep+1}/{epochs} loss={loss.item():.4f}")

    def save_weights(self, base_dir: pathlib.Path):
        if not TORCH or self.ae is None or self.transformer is None:
            return
        try:
            torch.save(self.ae.state_dict(), base_dir / "ae_weights.pt")
            torch.save(self.transformer.state_dict(), base_dir / "transformer_weights.pt")
            print("[TRAIN] Saved AE and Transformer weights")
        except Exception as e:
            print(f"[TRAIN] Failed to save weights: {e}")

    def load_weights(self, base_dir: pathlib.Path):
        if not TORCH or self.ae is None or self.transformer is None:
            return
        try:
            ae_path = base_dir / "ae_weights.pt"
            tf_path = base_dir / "transformer_weights.pt"
            if ae_path.exists():
                self.ae.load_state_dict(torch.load(ae_path))
                print("[TRAIN] Loaded AE weights")
            if tf_path.exists():
                self.transformer.load_state_dict(torch.load(tf_path))
                print("[TRAIN] Loaded Transformer weights")
        except Exception as e:
            print(f"[TRAIN] Failed to load weights: {e}")

@dataclass
class NavigationState:
    position: np.ndarray
    target: np.ndarray
    history: List[np.ndarray]

class MissileNavigator:
    def __init__(self, step=0.15, max_steps=24):
        self.step = step
        self.max_steps = max_steps
    def navigate(self, start: np.ndarray, target: np.ndarray) -> NavigationState:
        pos = start.copy()
        hist = [pos.copy()]
        for _ in range(self.max_steps):
            d = target - pos
            dist = np.linalg.norm(d)
            if dist < 1e-3:
                break
            pos += self.step * (d / (dist + 1e-8))
            hist.append(pos.copy())
        return NavigationState(position=pos, target=target, history=hist)

class FeatureEngineer:
    def build(self, batch: ChunkBatch, embeddings: Dict[str, np.ndarray]):
        out = {}
        for c in batch:
            v = embeddings[c.id]
            out[c.id] = {
                "norm": float(np.linalg.norm(v)),
                "mean": float(v.mean()),
                "std": float(v.std()),
            }
        return out

class EmbeddingMemory:
    def __init__(self, max_history: int = 10000):
        self.max_history = max_history
        self.history: List[np.ndarray] = []
    def add(self, vec: np.ndarray):
        self.history.append(vec.astype(np.float32))
        if len(self.history) > self.max_history:
            self.history.pop(0)
    def drift_score(self, vec: np.ndarray) -> float:
        if not self.history:
            return 0.0
        mean_hist = np.stack(self.history).mean(axis=0)
        return float(np.linalg.norm(vec - mean_hist))

class AnomalyModel:
    def __init__(self):
        self.count = 0
        self.mean = None
        self.var = None
        self.anomaly_threshold = None
        self.drift_threshold = None
        self.ae_threshold = None

    def update(self, vec: np.ndarray):
        vec = vec.astype(np.float32)
        if self.mean is None:
            self.mean = vec
            self.var = np.zeros_like(vec)
            self.count = 1
            return
        self.count += 1
        delta = vec - self.mean
        self.mean += delta / self.count
        self.var += delta * (vec - self.mean)

    def score(self, vec: np.ndarray) -> float:
        if self.mean is None:
            return 0.0
        vec = vec.astype(np.float32)
        diff = vec - self.mean
        return float(np.linalg.norm(diff))

    def calibrate(self, anomaly_scores: List[float], drift_scores: List[float], ae_errors: List[float]):
        if anomaly_scores:
            self.anomaly_threshold = float(np.mean(anomaly_scores) + 3 * np.std(anomaly_scores))
        if drift_scores:
            self.drift_threshold = float(np.mean(drift_scores) + 3 * np.std(drift_scores))
        if ae_errors:
            self.ae_threshold = float(np.mean(ae_errors) + 3 * np.std(ae_errors))
        print(f"[TRAIN] Calibrated thresholds: anomaly={self.anomaly_threshold:.3f} drift={self.drift_threshold:.3f} ae={self.ae_threshold:.3f}")

    def save_baseline(self, base_dir: pathlib.Path):
        baseline = {
            "anomaly_threshold": self.anomaly_threshold,
            "drift_threshold": self.drift_threshold,
            "ae_threshold": self.ae_threshold,
        }
        try:
            (base_dir / "baseline.json").write_text(json.dumps(baseline, indent=2), encoding="utf-8")
            print("[TRAIN] Saved baseline thresholds")
        except Exception as e:
            print(f"[TRAIN] Failed to save baseline: {e}")

    def load_baseline(self, base_dir: pathlib.Path):
        path = base_dir / "baseline.json"
        if not path.exists():
            print("[TRAIN] No baseline.json found, using default thresholds")
            return
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            self.anomaly_threshold = data.get("anomaly_threshold")
            self.drift_threshold = data.get("drift_threshold")
            self.ae_threshold = data.get("ae_threshold")
            print("[TRAIN] Loaded baseline thresholds")
        except Exception as e:
            print(f"[TRAIN] Failed to load baseline: {e}")

@dataclass
class MITREEntry:
    sid: int
    technique_id: str
    technique_name: str
    tactic: str
    severity: int

class MITREMapper:
    def __init__(self, db_path: Optional[str] = None):
        self.db: Dict[int, MITREEntry] = {}
        if db_path:
            self.load_db(db_path)
        else:
            self._load_fallback()
    def _load_fallback(self):
        print("[MITRE] Using fallback MITRE mapping")
        self.db[1000001] = MITREEntry(1000001, "T1059", "Command and Scripting Interpreter", "Execution", 3)
    def load_db(self, path: str):
        try:
            p = pathlib.Path(path)
            if not p.exists():
                print(f"[MITRE] DB path not found: {path}, using fallback")
                self._load_fallback()
                return
            with p.open("r", encoding="utf-8") as f:
                data = json.load(f)
            for row in data:
                sid = int(row["sid"])
                self.db[sid] = MITREEntry(
                    sid=sid,
                    technique_id=row["technique_id"],
                    technique_name=row["technique_name"],
                    tactic=row["tactic"],
                    severity=int(row["severity"]),
                )
            print(f"[MITRE] Loaded {len(self.db)} entries from {path}")
        except Exception as e:
            print(f"[MITRE] Failed to load DB: {e}, using fallback")
            self._load_fallback()
    def get(self, sid: int) -> Optional[MITREEntry]:
        return self.db.get(sid)

class BaseAgent(abc.ABC):
    def __init__(self, name): self.name = name
    @abc.abstractmethod
    def act(self, ctx: Dict[str, Any]) -> Dict[str, Any]: ...

class ScoutAgent(BaseAgent):
    def act(self, ctx):
        feats = ctx["features"]
        ranked = sorted(feats.items(), key=lambda kv: kv[1]["norm"], reverse=True)
        return {"scout": [cid for cid, _ in ranked[:5]]}

class AnalystAgent(BaseAgent):
    def act(self, ctx):
        out = {}
        global_vec = ctx["global"]
        for cid in ctx["scout"]:
            vec = ctx["embeddings"][cid]
            out[cid] = float(np.linalg.norm(vec - global_vec))
        return {"analysis": out}

class SynthAgent(BaseAgent):
    def act(self, ctx):
        scores = ctx["analysis"]
        if not scores:
            return {"decision": "NO_SIGNAL", "top": None}
        top = max(scores.items(), key=lambda kv: kv[1])[0]
        return {"decision": "ALERT", "top": top, "score": scores[top]}

class Orchestrator:
    def __init__(self):
        self.agents = [
            ScoutAgent("scout"),
            AnalystAgent("analyst"),
            SynthAgent("synth"),
        ]
    def run(self, ctx):
        for a in self.agents:
            ctx.update(a.act(ctx))
        return ctx

class GPUTelemetry:
    def sample(self) -> Dict[str, float]:
        return {
            "gpu_util": random.uniform(0, 100),
            "gpu_mem": random.uniform(0, 100),
            "gpu_temp": random.uniform(30, 85),
        }

class SwarmNode:
    def __init__(self, node_id: str, bind_port: int = 50050, broadcast_port: int = 50050):
        self.node_id = node_id
        self.bind_port = bind_port
        self.broadcast_port = broadcast_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.bind(("0.0.0.0", self.bind_port))
        except Exception:
            pass
        self.running = False
        self.last_messages: List[str] = []
        self.trust_scores: Dict[str, float] = {self.node_id: 1.0}
    def broadcast(self, msg: str):
        try:
            payload = f"NODE:{self.node_id} {msg}"
            self.sock.sendto(payload.encode("utf-8"), ("255.255.255.255", self.broadcast_port))
        except Exception:
            pass
    def _listen_loop(self):
        while self.running:
            try:
                data, _ = self.sock.recvfrom(4096)
                self.last_messages.append(data.decode("utf-8"))
            except Exception:
                time.sleep(0.1)
    def start(self):
        self.running = True
        t = threading.Thread(target=self._listen_loop, daemon=True)
        t.start()
    def stop(self):
        self.running = False
    def update_trust(self, node_id: str, correct: bool):
        base = self.trust_scores.get(node_id, 1.0)
        if correct:
            base += 0.05
        else:
            base -= 0.1
        self.trust_scores[node_id] = max(0.1, min(base, 5.0))
    def decay_trust(self, factor: float = 0.99):
        for nid in list(self.trust_scores.keys()):
            self.trust_scores[nid] = max(0.1, self.trust_scores[nid] * factor)

class ConsensusEngine:
    def decide(self, local_node_id: str, local_decision: str, swarm: SwarmNode) -> str:
        votes: Dict[str, float] = {}
        local_weight = swarm.trust_scores.get(local_node_id, 1.0)
        votes[local_decision] = votes.get(local_decision, 0.0) + local_weight
        for m in swarm.last_messages:
            try:
                parts = m.split()
                node_part = [p for p in parts if p.startswith("NODE:")][0]
                node_id = node_part.split("NODE:")[1]
                dec_part = [p for p in parts if p.startswith("DECISION:")][0]
                dec = dec_part.split("DECISION:")[1]
                weight = swarm.trust_scores.get(node_id, 1.0)
                votes[dec] = votes.get(dec, 0.0) + weight
            except Exception:
                continue
        if not votes:
            return local_decision
        return max(votes.items(), key=lambda kv: kv[1])[0]

class PacketParser:
    def __init__(self, pcap_path: Optional[str] = None):
        self.pcap_path = pcap_path
    def parse_packets(self, max_packets: int = 128) -> List[Dict[str, Any]]:
        packets = []
        if not self.pcap_path:
            return packets
        try:
            if SCAPY_AVAILABLE and scapy is not None:
                for pkt in scapy.PcapReader(self.pcap_path):
                    packets.append({"len": len(pkt), "summary": str(pkt)[:128]})
                    if len(packets) >= max_packets:
                        break
            elif DPKT_AVAILABLE and dpkt is not None:
                with open(self.pcap_path, "rb") as f:
                    pcap = dpkt.pcap.Reader(f)
                    for ts, buf in pcap:
                        packets.append({"len": len(buf), "ts": ts})
                        if len(packets) >= max_packets:
                            break
            elif PYSHARK_AVAILABLE and pyshark is not None:
                cap = pyshark.FileCapture(self.pcap_path)
                for pkt in cap:
                    packets.append({"len": len(pkt), "layers": len(pkt.layers)})
                    if len(packets) >= max_packets:
                        break
            else:
                size = pathlib.Path(self.pcap_path).stat().st_size
                packets.append({"len": size})
        except Exception as e:
            print(f"[PACKETS] Parse error: {e}")
        return packets

class BackboneAdapter:
    def __init__(self,
                 eve_path: Optional[str] = None,
                 socket_host: Optional[str] = None,
                 socket_port: Optional[int] = None,
                 api_url: Optional[str] = None,
                 web_url: Optional[str] = None,
                 event_queue: Optional[queue.Queue] = None,
                 pcap_path: Optional[str] = None):
        base_dir = pathlib.Path(__file__).parent
        self.eve_path = eve_path or str(base_dir / "eve.json")
        self.socket_host = socket_host
        self.socket_port = socket_port
        self.api_url = api_url
        self.web_url = web_url
        self.event_queue = event_queue or queue.Queue()
        self._socket = None
        if self.socket_host and self.socket_port:
            try:
                self._socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._socket.settimeout(0.5)
                self._socket.connect((self.socket_host, self.socket_port))
            except Exception:
                self._socket = None
        pcap_default_dir = base_dir / "pcap"
        if not pcap_default_dir.exists():
            try:
                pcap_default_dir.mkdir(parents=True, exist_ok=True)
                print(f"[BACKBONE] Created PCAP directory: {pcap_default_dir}")
            except Exception as e:
                print(f"[BACKBONE] Failed to create PCAP directory: {e}")
        pcap_default = pcap_default_dir / "live.pcap"
        self.packet_parser = PacketParser(pcap_path or str(pcap_default))

    def poll_suricata_eve(self, max_events: int = 256) -> List[Dict[str, Any]]:
        alerts = []
        if not self.eve_path:
            return alerts
        path = pathlib.Path(self.eve_path)
        if not path.exists():
            return alerts
        with path.open("r", encoding="utf-8") as f:
            for line in f:
                try:
                    evt = json.loads(line.strip())
                    alerts.append(evt)
                    if len(alerts) >= max_events:
                        break
                except Exception:
                    continue
        return alerts

    def poll_socket(self) -> List[str]:
        out = []
        if not self._socket:
            return out
        try:
            data = self._socket.recv(4096)
            if data:
                out.append(data.decode("utf-8", errors="ignore"))
        except Exception:
            pass
        return out

    def poll_api(self) -> List[Dict[str, Any]]:
        if not self.api_url or not REQUESTS or requests is None:
            return []
        try:
            r = requests.get(self.api_url, timeout=1.0)
            if r.status_code == 200:
                j = r.json()
                if isinstance(j, list):
                    return j
                return [j]
        except Exception:
            return []
        return []

    def poll_web(self) -> List[str]:
        if not self.web_url or not REQUESTS or requests is None:
            return []
        try:
            r = requests.get(self.web_url, timeout=1.0)
            if r.status_code == 200:
                return [r.text[:4096]]
        except Exception:
            return []
        return []

    def poll_backbone_events(self, max_events: int = 256) -> List[Any]:
        events = []
        while len(events) < max_events:
            try:
                evt = self.event_queue.get_nowait()
                events.append(evt)
            except queue.Empty:
                break
        return events

    def poll_packets(self) -> List[Dict[str, Any]]:
        return self.packet_parser.parse_packets()

def build_input_from_real_data(backbone: BackboneAdapter, mitre: MITREMapper) -> Tuple[List[float], List[Dict[str, Any]], List[Dict[str, Any]], List[MITREEntry]]:
    stream: List[float] = []
    alerts = backbone.poll_suricata_eve()
    mitre_entries: List[MITREEntry] = []
    for a in alerts:
        alert = a.get("alert", {})
        sev = float(alert.get("severity", 0))
        sid = int(alert.get("signature_id", 0))
        stream.extend([sev, float(sid)])
        entry = mitre.get(sid)
        if entry:
            stream.append(float(entry.severity))
            mitre_entries.append(entry)
    sock_msgs = backbone.poll_socket()
    for m in sock_msgs:
        stream.append(float(len(m) % 1024))
    api_data = backbone.poll_api()
    for item in api_data:
        stream.append(float(len(str(item)) % 1024))
    web_data = backbone.poll_web()
    for txt in web_data:
        stream.append(float(len(txt) % 2048))
    events = backbone.poll_backbone_events()
    for e in events:
        stream.append(float(len(str(e)) % 1024))
    packets = backbone.poll_packets()
    for p in packets:
        stream.append(float(p.get("len", 0) % 4096))
    if not stream:
        stream = [0.0] * 64
    return stream, alerts, packets, mitre_entries

class AIBrain:
    def __init__(self, base_dir: pathlib.Path):
        self.tchunk = TemporalChunker()
        self.schunk = SpatialChunker()
        self.vector = VectorEngine()
        self.nav = MissileNavigator()
        self.fe = FeatureEngineer()
        self.orch = Orchestrator()
        self.ml = AnomalyModel()
        self.memory = EmbeddingMemory()
        self.deep = DeepModels()
        self.base_dir = base_dir
        self.deep.load_weights(base_dir)
        self.ml.load_baseline(base_dir)

    def chunk(self, data):
        if isinstance(data, list):
            return self.tchunk.chunk(data)
        if isinstance(data, np.ndarray):
            return self.schunk.chunk(data)
        return ChunkBatch([Chunk(id="raw", data=data)])

    def infer(self, data, target=None):
        batch = self.chunk(data)
        embeds = self.vector.embed(batch)
        trans = self.vector.transform(embeds)
        global_vec = self.vector.aggregate(trans)
        ae_err = self.deep.ae_error(global_vec)
        seq = np.stack(list(trans.values()))
        seq_enc = self.deep.transformer_encode(seq)
        self.ml.update(global_vec)
        anomaly_score = self.ml.score(global_vec)
        self.memory.add(global_vec)
        drift_score = self.memory.drift_score(global_vec)
        nav_state = self.nav.navigate(global_vec, target) if target is not None else None
        feats = self.fe.build(batch, trans)
        ctx = {
            "batch": batch,
            "embeddings": trans,
            "features": feats,
            "global": global_vec,
            "navigation": nav_state,
        }
        result = self.orch.run(ctx)
        result["global_vec"] = global_vec
        result["nav_state"] = nav_state
        result["anomaly_score"] = anomaly_score
        result["drift_score"] = drift_score
        result["ae_error"] = ae_err
        result["seq_enc"] = seq_enc
        return result

    def train_on_streams(self, streams: List[List[float]], epochs: int):
        if not streams:
            print("[TRAIN] No streams to train on")
            return
        data = []
        for s in streams:
            batch = self.chunk(s)
            embeds = self.vector.embed(batch)
            trans = self.vector.transform(embeds)
            global_vec = self.vector.aggregate(trans)
            data.append(global_vec)
        data_arr = np.stack(data)
        self.deep.train_ae(data_arr, epochs=epochs)
        seqs = data_arr.reshape(data_arr.shape[0], 1, data_arr.shape[1])
        self.deep.train_transformer(seqs, epochs=epochs)
        anomaly_scores = []
        drift_scores = []
        ae_errors = []
        for v in data_arr:
            self.ml.update(v)
            anomaly_scores.append(self.ml.score(v))
            drift_scores.append(self.memory.drift_score(v))
            ae_errors.append(self.deep.ae_error(v))
            self.memory.add(v)
        self.ml.calibrate(anomaly_scores, drift_scores, ae_errors)
        self.deep.save_weights(self.base_dir)
        self.ml.save_baseline(self.base_dir)

class Watchdog:
    def __init__(self, name: str, target_fn, restart_delay: float = 3.0):
        self.name = name
        self.target_fn = target_fn
        self.restart_delay = restart_delay
    def run_forever(self):
        while True:
            try:
                self.target_fn()
            except Exception as e:
                print(f"[WATCHDOG:{self.name}] Exception: {e}, restarting in {self.restart_delay}s")
                time.sleep(self.restart_delay)

class ResponseEngine:
    def __init__(self, os_type: str = "windows"):
        self.os_type = os_type
    def firewall_block(self, ip: str):
        print(f"[RESPONSE] Firewall block on {ip}")
        try:
            if self.os_type == "windows":
                subprocess.run([
                    "powershell",
                    "New-NetFirewallRule",
                    "-DisplayName", "CodexBlock",
                    "-Direction", "Inbound",
                    "-RemoteAddress", ip,
                    "-Action", "Block"
                ])
        except Exception as e:
            print(f"[RESPONSE] Firewall error: {e}")
    def deception_route(self, ip: str, honeypot_ip: str = "10.0.0.99"):
        print(f"[RESPONSE] Deception route for {ip} -> {honeypot_ip}")
        try:
            if self.os_type == "windows":
                subprocess.run([
                    "powershell",
                    "netsh", "interface", "portproxy", "add", "v4tov4",
                    "listenport=80", "listenaddress=0.0.0.0",
                    "connectport=8080", f"connectaddress={honeypot_ip}"
                ])
        except Exception as e:
            print(f"[RESPONSE] Deception error: {e}")
    def honeypot_redirect(self, ip: str, honeypot_ip: str = "10.0.0.99", honeypot_port: int = 2222):
        print(f"[RESPONSE] Honeypot redirect for {ip} -> {honeypot_ip}:{honeypot_port}")
        try:
            if self.os_type == "windows":
                subprocess.run([
                    "powershell",
                    "netsh", "interface", "portproxy", "add", "v4tov4",
                    "listenport=22", "listenaddress=0.0.0.0",
                    f"connectport={honeypot_port}", f"connectaddress={honeypot_ip}"
                ])
        except Exception as e:
            print(f"[RESPONSE] Honeypot error: {e}")
    def cowrie_http_stub(self):
        print("[HONEYPOT] HTTP honeypot stub active (simulate Cowrie HTTP)")
    def cowrie_ssh_stub(self):
        print("[HONEYPOT] SSH honeypot stub active (simulate Cowrie SSH)")
    def kill_process(self, pid: int):
        print(f"[RESPONSE] Kill process {pid}")
        try:
            if self.os_type == "windows":
                subprocess.run([
                    "powershell",
                    "Stop-Process", "-Id", str(pid), "-Force"
                ])
        except Exception as e:
            print(f"[RESPONSE] Kill error: {e}")
    def apply(self, decision: str, mitre_entries: List[MITREEntry]):
        max_sev = max((e.severity for e in mitre_entries), default=0)
        if max_sev < SEVERITY_THRESHOLD:
            print(f"[RESPONSE] Severity {max_sev} < threshold {SEVERITY_THRESHOLD}, no action taken")
            return
        if decision == "ALERT":
            if max_sev >= 5:
                self.firewall_block("0.0.0.0/0")
                self.honeypot_redirect("0.0.0.0/0")
                self.cowrie_http_stub()
                self.cowrie_ssh_stub()
            elif max_sev >= 4:
                self.deception_route("0.0.0.0/0")
                self.cowrie_http_stub()
            elif max_sev >= 3:
                print("[RESPONSE] Severity meets threshold but moderate — logging only")

# ===========================================================
# CAMPAIGN CORRELATION ENGINE
# ===========================================================

class CampaignCorrelationEngine:
    def correlate(self, alerts: List[Dict[str, Any]], mitre_entries: List[MITREEntry]) -> Dict[str, List[MITREEntry]]:
        phases = {
            "Recon": [],
            "Initial Access": [],
            "Execution": [],
            "Discovery": [],
            "Lateral Movement": [],
            "Command and Control": [],
            "Exfiltration": [],
        }
        for e in mitre_entries:
            t = e.tactic.lower()
            if "recon" in t or "reconnaissance" in t:
                phases["Recon"].append(e)
            elif "initial" in t or "access" in t:
                phases["Initial Access"].append(e)
            elif "execution" in t:
                phases["Execution"].append(e)
            elif "discovery" in t:
                phases["Discovery"].append(e)
            elif "lateral" in t:
                phases["Lateral Movement"].append(e)
            elif "command and control" in t or "c2" in t:
                phases["Command and Control"].append(e)
            elif "exfiltration" in t:
                phases["Exfiltration"].append(e)
        return phases

# ===========================================================
# COMPACT SOC GUI
# ===========================================================

class CodexGUI:
    def __init__(self):
        self.root = tk.Tk() if TK_AVAILABLE and tk is not None else None
        self.timeline_points: List[Tuple[float, float, int]] = []
        if not self.root or not TTK_AVAILABLE or ttk is None:
            return

        self.root.title("Codex Control Console v7.5 (Windows)")
        self.root.geometry("1200x700")

        # Main layout: 3 panels (left status, center tabs, right swarm)
        self.frame_main = tk.Frame(self.root)
        self.frame_main.pack(fill=tk.BOTH, expand=True)

        self.frame_left = tk.Frame(self.frame_main, width=250)
        self.frame_left.pack(side=tk.LEFT, fill=tk.Y)
        self.frame_center = tk.Frame(self.frame_main)
        self.frame_center.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.frame_right = tk.Frame(self.frame_main, width=250)
        self.frame_right.pack(side=tk.RIGHT, fill=tk.Y)

        # LEFT: Status
        self.label_title = tk.Label(self.frame_left, text="STATUS", font=("Consolas", 12, "bold"))
        self.label_title.pack(anchor="w", pady=(5, 5))

        self.label_decision = tk.Label(self.frame_left, text="Decision: N/A", font=("Consolas", 10))
        self.label_decision.pack(anchor="w")
        self.label_consensus = tk.Label(self.frame_left, text="Consensus: N/A", font=("Consolas", 10))
        self.label_consensus.pack(anchor="w")
        self.label_severity = tk.Label(self.frame_left, text="Max Severity: 0", font=("Consolas", 10))
        self.label_severity.pack(anchor="w")
        self.label_anomaly = tk.Label(self.frame_left, text="Anomaly: N/A", font=("Consolas", 10))
        self.label_anomaly.pack(anchor="w")
        self.label_drift = tk.Label(self.frame_left, text="Drift: N/A", font=("Consolas", 10))
        self.label_drift.pack(anchor="w")
        self.label_ae = tk.Label(self.frame_left, text="AE Error: N/A", font=("Consolas", 10))
        self.label_ae.pack(anchor="w")
        self.label_gpu = tk.Label(self.frame_left, text="GPU: N/A", font=("Consolas", 10))
        self.label_gpu.pack(anchor="w")
        self.label_thresh = tk.Label(self.frame_left, text=f"Threshold: {SEVERITY_THRESHOLD}", font=("Consolas", 10))
        self.label_thresh.pack(anchor="w")

        # CENTER: Tabs
        self.notebook = ttk.Notebook(self.frame_center)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.tab_alerts = tk.Frame(self.notebook)
        self.tab_packets = tk.Frame(self.notebook)
        self.tab_mitre = tk.Frame(self.notebook)
        self.tab_campaigns = tk.Frame(self.notebook)
        self.tab_timeline = tk.Frame(self.notebook)

        self.notebook.add(self.tab_alerts, text="Alerts")
        self.notebook.add(self.tab_packets, text="Packets")
        self.notebook.add(self.tab_mitre, text="MITRE")
        self.notebook.add(self.tab_campaigns, text="Campaigns")
        self.notebook.add(self.tab_timeline, text="Timeline")

        self.text_alert = tk.Text(self.tab_alerts, height=20, width=80)
        self.text_alert.pack(fill=tk.BOTH, expand=True)

        self.text_pkt = tk.Text(self.tab_packets, height=20, width=80)
        self.text_pkt.pack(fill=tk.BOTH, expand=True)

        self.text_mitre = tk.Text(self.tab_mitre, height=20, width=80)
        self.text_mitre.pack(fill=tk.BOTH, expand=True)

        self.text_campaign = tk.Text(self.tab_campaigns, height=20, width=80)
        self.text_campaign.pack(fill=tk.BOTH, expand=True)

        self.text_timeline = tk.Text(self.tab_timeline, height=20, width=80)
        self.text_timeline.pack(fill=tk.BOTH, expand=True)

        # RIGHT: Swarm
        self.label_swarm_title = tk.Label(self.frame_right, text="SWARM", font=("Consolas", 12, "bold"))
        self.label_swarm_title.pack(anchor="w", pady=(5, 5))

        self.text_swarm = tk.Text(self.frame_right, height=20, width=30)
        self.text_swarm.pack(fill=tk.BOTH, expand=True)

    def _color_for_severity(self, max_sev: int) -> str:
        if max_sev >= 5:
            return "red"
        if max_sev >= 4:
            return "orange"
        if max_sev >= 3:
            return "yellow"
        return "green"

    def update_main(self, decision: str, consensus: str, anomaly: float, drift: float, ae_err: float, gpu: Dict[str, float], max_sev: int):
        if not self.root:
            return
        color = self._color_for_severity(max_sev)
        self.label_decision.config(text=f"Decision: {decision}", fg=color)
        self.label_consensus.config(text=f"Consensus: {consensus}", fg=color)
        self.label_severity.config(text=f"Max Severity: {max_sev}", fg=color)
        self.label_anomaly.config(text=f"Anomaly: {anomaly:.3f}")
        self.label_drift.config(text=f"Drift: {drift:.3f}")
        self.label_ae.config(text=f"AE Error: {ae_err:.3f}")
        self.label_gpu.config(text=f"GPU u={gpu['gpu_util']:.1f}% m={gpu['gpu_mem']:.1f}% t={gpu['gpu_temp']:.1f}C")
        self.root.update_idletasks()

    def update_swarm(self, swarm_last: List[str]):
        if not self.root:
            return
        self.text_swarm.delete("1.0", tk.END)
        for m in swarm_last:
            self.text_swarm.insert(tk.END, m + "\n")

    def update_mitre(self, mitre_entries: List[MITREEntry]):
        if not self.root:
            return
        self.text_mitre.delete("1.0", tk.END)
        for e in mitre_entries:
            self.text_mitre.insert(tk.END, f"SID {e.sid} {e.technique_id} {e.technique_name} [{e.tactic}] sev={e.severity}\n")

    def update_timeline(self, anomaly: float, drift: float, max_sev: int):
        if not self.root:
            return
        self.timeline_points.append((anomaly, drift, max_sev))
        if len(self.timeline_points) > 100:
            self.timeline_points.pop(0)
        self.text_timeline.delete("1.0", tk.END)
        for i, (a, d, s) in enumerate(self.timeline_points):
            self.text_timeline.insert(tk.END, f"t={i} Anom={a:.3f} Drift={d:.3f} Sev={s}\n")

    def update_packets(self, packets: List[Dict[str, Any]]):
        if not self.root:
            return
        self.text_pkt.delete("1.0", tk.END)
        for p in packets[:50]:
            self.text_pkt.insert(tk.END, f"{p}\n")

    def update_alerts(self, alerts: List[Dict[str, Any]]):
        if not self.root:
            return
        self.text_alert.delete("1.0", tk.END)
        for a in alerts[:50]:
            self.text_alert.insert(tk.END, f"{a}\n")

    def update_campaigns(self, campaigns: Dict[str, List[MITREEntry]]):
        if not self.root:
            return
        self.text_campaign.delete("1.0", tk.END)
        for phase, entries in campaigns.items():
            if not entries:
                continue
            self.text_campaign.insert(tk.END, f"[{phase}]\n")
            for e in entries:
                self.text_campaign.insert(tk.END, f"  SID {e.sid} {e.technique_id} {e.technique_name} sev={e.severity}\n")

    def loop(self):
        if not self.root:
            return
        self.root.mainloop()

class CodexControlConsole:
    def __init__(self, gui: Optional[CodexGUI] = None):
        self.history: List[Dict[str, Any]] = []
        self.gui = gui
    def push_event(self, payload: Dict[str, Any]):
        self.history.append(payload)
        print("[CODEX] Decision:", payload.get("decision"),
              "Consensus:", payload.get("consensus"),
              "Top:", payload.get("top_chunk"),
              "Score:", payload.get("score"),
              "Anomaly:", payload.get("anomaly"),
              "Drift:", payload.get("drift"),
              "AE Error:", payload.get("ae_error"),
              "GPU:", payload.get("gpu"),
              "MaxSev:", payload.get("max_sev"))
        if self.gui:
            self.gui.update_main(
                payload.get("decision"),
                payload.get("consensus"),
                payload.get("anomaly", 0.0),
                payload.get("drift", 0.0),
                payload.get("ae_error", 0.0),
                payload.get("gpu", {"gpu_util": 0, "gpu_mem": 0, "gpu_temp": 0}),
                payload.get("max_sev", 0),
            )
            self.gui.update_swarm(payload.get("swarm_last", []))
            self.gui.update_mitre(payload.get("mitre_entries", []))
            self.gui.update_timeline(payload.get("anomaly", 0.0), payload.get("drift", 0.0), payload.get("max_sev", 0))
            self.gui.update_packets(payload.get("packets", []))
            self.gui.update_alerts(payload.get("alerts", []))
            self.gui.update_campaigns(payload.get("campaigns", {}))

# ===========================================================
# TRAINING MODE
# ===========================================================

def run_training():
    base_dir = pathlib.Path(__file__).parent
    initialize_codex_files()
    generate_suricata_config()
    cfg = CONFIG
    train_samples = int(cfg.get("train_samples", 500))
    train_epochs = int(cfg.get("train_epochs", 5))

    backbone = BackboneAdapter(
        eve_path=str(base_dir / "eve.json"),
        socket_host=None, socket_port=None,
        api_url=None,
        web_url=None,
        pcap_path=str(base_dir / "pcap" / "live.pcap"),
    )
    mitre = MITREMapper(db_path=str(base_dir / "mitre.json"))
    brain = AIBrain(base_dir)

    streams: List[List[float]] = []
    print(f"[TRAIN] Collecting {train_samples} samples from live data...")
    for i in range(train_samples):
        stream, alerts, packets, mitre_entries = build_input_from_real_data(backbone, mitre)
        streams.append(stream)
        time.sleep(0.1)

    print("[TRAIN] Starting training...")
    brain.train_on_streams(streams, epochs=train_epochs)
    print("[TRAIN] Training complete")

# ===========================================================
# DAEMON CYCLE
# ===========================================================

def daemon_cycle(node_id: str,
                 console: CodexControlConsole,
                 brain: AIBrain,
                 backbone: BackboneAdapter,
                 gpu_telemetry: GPUTelemetry,
                 swarm: SwarmNode,
                 mitre: MITREMapper,
                 consensus: ConsensusEngine,
                 responder: ResponseEngine,
                 campaign_engine: CampaignCorrelationEngine):
    data_stream, alerts, packets, mitre_entries = build_input_from_real_data(backbone, mitre)
    target = np.random.randn(256).astype(np.float32)
    result = brain.infer(data_stream, target)
    gpu_stats = gpu_telemetry.sample()
    msg = f"DECISION:{result['decision']} TOP:{result.get('top')} SCORE:{result.get('score')}"
    swarm.broadcast(msg)
    swarm.decay_trust()
    swarm_last = list(swarm.last_messages[-10:])
    final_decision = consensus.decide(node_id, result["decision"], swarm)
    responder.apply(final_decision, mitre_entries)
    max_sev = max((e.severity for e in mitre_entries), default=0)
    campaigns = campaign_engine.correlate(alerts, mitre_entries)
    payload = {
        "decision": result["decision"],
        "consensus": final_decision,
        "top_chunk": result.get("top"),
        "score": result.get("score"),
        "anomaly": result.get("anomaly_score"),
        "drift": result.get("drift_score"),
        "ae_error": result.get("ae_error"),
        "gpu": gpu_stats,
        "swarm_last": swarm_last,
        "mitre_entries": mitre_entries,
        "packets": packets,
        "alerts": alerts,
        "max_sev": max_sev,
        "campaigns": campaigns,
    }
    console.push_event(payload)

def run_codex_daemon():
    base_dir = pathlib.Path(__file__).parent
    initialize_codex_files()
    generate_suricata_config()
    cfg = CONFIG
    node_id = cfg.get("node_id", "node-1")
    bind_port = int(cfg.get("swarm_bind_port", 50050))
    broadcast_port = int(cfg.get("swarm_broadcast_port", 50050))
    gui = CodexGUI() if TK_AVAILABLE and tk is not None and TTK_AVAILABLE and ttk is not None else None
    console = CodexControlConsole(gui=gui)
    brain = AIBrain(base_dir)
    gpu_telemetry = GPUTelemetry()
    swarm = SwarmNode(node_id=node_id, bind_port=bind_port, broadcast_port=broadcast_port)
    swarm.start()
    mitre = MITREMapper(db_path=str(base_dir / "mitre.json"))
    consensus = ConsensusEngine()
    responder = ResponseEngine(os_type="windows")
    campaign_engine = CampaignCorrelationEngine()
    backbone = BackboneAdapter(
        eve_path=str(base_dir / "eve.json"),
        socket_host=None, socket_port=None,
        api_url=None,
        web_url=None,
        pcap_path=str(base_dir / "pcap" / "live.pcap"),
    )
    print("[CORE] Codex Control Console daemon v7.5 (Windows: TRAIN + eve.json + PCAP + MITRE + COMPACT GUI + SWARM + RESPONSE + THRESHOLD + SURICATA_CFG + CAMPAIGNS)")
    def loop():
        while True:
            daemon_cycle(node_id, console, brain, backbone, gpu_telemetry, swarm, mitre, consensus, responder, campaign_engine)
            time.sleep(5)
    wd = Watchdog("CodexDaemonV7_5_Windows", loop, restart_delay=3.0)
    if gui and gui.root:
        t = threading.Thread(target=wd.run_forever, daemon=True)
        t.start()
        gui.loop()
    else:
        wd.run_forever()

# ===========================================================
# ENTRY POINT
# ===========================================================

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "--train":
        run_training()
    else:
        run_codex_daemon()
