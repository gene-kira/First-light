#!/usr/bin/env python3
# omega_hybrid_ai_v8_cyber_daemon_dual_llm.py
#
# Option C – Dual‑mode LLM engine fused with Omega v8 SOC daemon:
# - Full Omega v8 threat, ML, SIEM, actions, correlation, mesh, ingestion, simulation, watchdog
# - Integrated Forklift‑patched LLM engine with TinyFallback + HF models
# - RPC server compatible with orchestrator protocol
# - Game process PID detection + game‑aware telemetry mixed into scoring and context
# - Headless 24/7 daemon with crash‑loop restart

from __future__ import annotations
import abc
import random
import time
import threading
import json
import os
import logging
import socket
import psutil
from typing import Dict, List, Any, Optional, Tuple

# =========================
# Logging
# =========================

LOG_FILE = "omega_v8_dual_llm.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[
        logging.FileHandler(LOG_FILE, encoding="utf-8"),
        logging.StreamHandler()
    ]
)

log = logging.getLogger("OmegaV8DualLLM")

# =========================
# Default config
# =========================

DEFAULT_CONFIG = {
    "constraints": {
        "allow_neutralization": True,
        "allow_assimilation": True,
        "max_energy_per_round": 40.0
    },
    "cluster": {
        "num_nodes": 3,
        "networking": {
            "enabled": True,
            "mode": "zeromq_mesh",
            "zeromq_pub_bind": "tcp://0.0.0.0:7777",
            "zeromq_sub_endpoints": ["tcp://127.0.0.1:7777"]
        }
    },
    "simulation": {
        "sleep_sec": 0.5,
        "max_rounds": 10**9,
        "mode": "mixed"
    },
    "persistence": {
        "enabled": True,
        "state_file": "omega_state_v8_dual_llm.json",
        "save_interval_rounds": 10
    },
    "ml": {
        "enabled": True,
        "backend": "hybrid",
        "model_name": "gpt2",
        "model_path": "models/omega_model_v8_dual_llm.pt",
        "train_on_start": False
    },
    "plugins": {
        "enabled": True,
        "directory": "plugins"
    },
    "ingestion": {
        "suricata_json_path": "logs/suricata.json",
        "suricata_eve_socket": {
            "enabled": False,
            "host": "127.0.0.1",
            "port": 6514
        },
        "sysmon_log_path": "logs/sysmon.log",
        "zeek_conn_log_path": "logs/zeek_conn.log",
        "zeek_dns_log_path": "logs/zeek_dns.log",
        "zeek_http_log_path": "logs/zeek_http.log",
        "pcap_path": "pcap/input.pcap",
        "generic_log_path": "logs/generic_threats.log",
        "tcp_listener_enabled": True,
        "tcp_listener_host": "0.0.0.0",
        "tcp_listener_port": 5555,
        "poll_interval_sec": 1.0
    },
    "siem": {
        "splunk": {
            "enabled": False,
            "hec_url": "",
            "token": "",
            "search_url": "",
            "search_query": ""
        },
        "elastic": {
            "enabled": False,
            "url": "",
            "api_key": "",
            "search_url": "",
            "search_body": {"size": 100, "query": {"match_all": {}}}
        },
        "sentinel": {
            "enabled": False,
            "url": "",
            "token": "",
            "search_url": "",
            "search_body": {"limit": 100}
        }
    },
    "actions": {
        "enabled": True,
        "dry_run": True
    },
    "llm_rpc": {
        "enabled": True,
        "host": "0.0.0.0",
        "port": 6000
    },
    "correlation": {
        "enabled": True,
        "time_window_sec": 300
    },
    "game": {
        "enabled": True,
        "process_names": ["game.exe", "eldenring.exe", "fortnite.exe"],
        "telemetry_udp_host": "127.0.0.1",
        "telemetry_udp_port": 7777
    }
}

# =========================
# Config manager
# =========================

class ConfigManager:
    def __init__(self, path: str = "omega_config_v8_dual_llm.json"):
        self.path = path
        self.config = json.loads(json.dumps(DEFAULT_CONFIG))
        self.load()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self._deep_update(self.config, data)
                log.info(f"[Config] Loaded config from {self.path}")
            except Exception as e:
                log.error(f"[Config] Failed to load {self.path}: {e}")
        else:
            log.info(f"[Config] No config file found, using defaults.")

    def _deep_update(self, base: Dict[str, Any], updates: Dict[str, Any]):
        for k, v in updates.items():
            if isinstance(v, dict) and isinstance(base.get(k), dict):
                self._deep_update(base[k], v)
            else:
                base[k] = v

    def get(self, key: str, default: Any = None) -> Any:
        parts = key.split(".")
        cur = self.config
        for p in parts:
            if not isinstance(cur, dict) or p not in cur:
                return default
            cur = cur[p]
        return cur

# =========================
# Auto-setup
# =========================

def ensure_path(path: str, is_file: bool = False):
    if not path:
        return
    if is_file:
        parent = os.path.dirname(path)
        if parent:
            os.makedirs(parent, exist_ok=True)
        if not os.path.exists(path):
            with open(path, "w", encoding="utf-8") as f:
                f.write("")
            log.info(f"[Setup] Created file: {path}")
    else:
        os.makedirs(path, exist_ok=True)
        log.info(f"[Setup] Ensured directory: {path}")

def auto_setup_environment(cfg: ConfigManager):
    ensure_path("logs/")
    ensure_path("models/")
    ensure_path("pcap/")
    ensure_path(cfg.get("plugins.directory", "plugins"))

    if not os.path.exists(cfg.path):
        with open(cfg.path, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_CONFIG, f, indent=2)
        log.info(f"[Setup] Created default config file: {cfg.path}")

    ensure_path(cfg.get("ingestion.suricata_json_path"), is_file=True)
    ensure_path(cfg.get("ingestion.sysmon_log_path"), is_file=True)
    ensure_path(cfg.get("ingestion.generic_log_path"), is_file=True)
    ensure_path(cfg.get("ingestion.zeek_conn_log_path"), is_file=True)
    ensure_path(cfg.get("ingestion.zeek_dns_log_path"), is_file=True)
    ensure_path(cfg.get("ingestion.zeek_http_log_path"), is_file=True)
    ensure_path(cfg.get("ingestion.pcap_path"), is_file=True)

    ensure_path(cfg.get("persistence.state_file"), is_file=True)

    model_path = cfg.get("ml.model_path")
    if model_path:
        ensure_path(model_path, is_file=True)

# =========================
# Autoloader
# =========================

AI_LIBS = {
    "numpy": None,
    "torch": None,
    "tensorflow": None,
    "sklearn": None,
    "transformers": None,
    "scapy": None,
    "pyshark": None,
    "zmq": None,
    "requests": None,
}

def autoload_ai_libraries() -> Dict[str, Any]:
    global AI_LIBS

    def try_import(name: str):
        try:
            module = __import__(name)
            log.info(f"[Autoloader] Loaded library: {name}")
            return module
        except Exception:
            log.info(f"[Autoloader] Library not available: {name}")
            return None

    AI_LIBS["numpy"] = try_import("numpy")
    AI_LIBS["torch"] = try_import("torch")
    AI_LIBS["tensorflow"] = try_import("tensorflow")
    AI_LIBS["sklearn"] = try_import("sklearn")
    AI_LIBS["transformers"] = try_import("transformers")
    AI_LIBS["scapy"] = try_import("scapy.all")
    AI_LIBS["pyshark"] = try_import("pyshark")
    AI_LIBS["zmq"] = try_import("zmq")
    AI_LIBS["requests"] = try_import("requests")

    return AI_LIBS

autoload_ai_libraries()

# =========================
# MITRE tactics
# =========================

MITRE_TACTICS = {
    "recon": {"category": "Reconnaissance", "weight": 1.1},
    "lateral_movement": {"category": "Lateral Movement", "weight": 1.3},
    "exfil": {"category": "Exfiltration", "weight": 1.4},
    "persistence": {"category": "Persistence", "weight": 1.2},
    "impact": {"category": "Impact", "weight": 1.5},
}

# =========================
# Constraints
# =========================

class ContainmentConstraints:
    def __init__(
        self,
        allow_neutralization: bool = True,
        allow_assimilation: bool = True,
        max_energy_per_round: float = 40.0,
    ):
        self.allow_neutralization = allow_neutralization
        self.allow_assimilation = allow_assimilation
        self.max_energy_per_round = max_energy_per_round

    def gate_action(self, recommendation: str) -> str:
        if "neutralize" in recommendation and not self.allow_neutralization:
            log.info("[Constraints] Neutralization blocked, downgrading to monitor.")
            return "monitor"

        if "assimilate" in recommendation and not self.allow_assimilation:
            log.info("[Constraints] Assimilation blocked, downgrading to neutralize.")
            if self.allow_neutralization:
                return "neutralize"
            return "monitor"

        if "neutralize" in recommendation and "assimilate" in recommendation:
            return "neutralize_and_assimilate"
        if "neutralize" in recommendation:
            return "neutralize"
        if "assimilate" in recommendation:
            return "assimilate"
        if "study" in recommendation:
            return "study"

        return recommendation

    def enforce_energy_cap(self, resources: "ResourcePool", requested_energy: float) -> float:
        allowed = min(requested_energy, self.max_energy_per_round, resources.energy_units)
        resources.energy_units -= allowed
        if requested_energy > allowed:
            log.info(f"[Constraints] Energy capped: requested={requested_energy:.1f}, allowed={allowed:.1f}")
        return allowed

# =========================
# Core data
# =========================

class ThreatProfile:
    def __init__(
        self,
        threat_id: str,
        tech_level: int,
        domain: str,
        signature: str,
        resilience: float,
        tactics: Optional[List[str]] = None,
        source: str = "synthetic",
        metadata: Optional[Dict[str, Any]] = None,
        timestamp: Optional[float] = None,
    ):
        self.id = threat_id
        self.tech_level = tech_level
        self.domain = domain
        self.signature = signature
        self.resilience = resilience
        self.tactics = tactics or []
        self.source = source
        self.metadata = metadata or {}
        self.timestamp = timestamp or time.time()

    def __repr__(self) -> str:
        return (
            f"ThreatProfile(id={self.id}, tech={self.tech_level}, "
            f"domain={self.domain}, resilience={self.resilience:.2f}, "
            f"tactics={self.tactics}, source={self.source})"
        )

class ResourcePool:
    def __init__(
        self,
        energy_units: float = 1000.0,
        compute_units: float = 1000.0,
        fabrication_units: float = 500.0,
        drones: int = 100,
        nodes: int = 10,
    ):
        self.energy_units = energy_units
        self.compute_units = compute_units
        self.fabrication_units = fabrication_units
        self.drones = drones
        self.nodes = nodes

    def snapshot(self) -> Dict[str, Any]:
        return {
            "energy_units": self.energy_units,
            "compute_units": self.compute_units,
            "fabrication_units": self.fabrication_units,
            "drones": self.drones,
            "nodes": self.nodes,
        }

    def __repr__(self) -> str:
        return (
            "ResourcePool("
            f"E={self.energy_units:.1f}, "
            f"C={self.compute_units:.1f}, "
            f"F={self.fabrication_units:.1f}, "
            f"drones={self.drones}, "
            f"nodes={self.nodes})"
        )

# =========================
# Persistence
# =========================

class PersistenceManager:
    def __init__(self, path: str, enabled: bool = True):
        self.path = path
        self.enabled = enabled

    def save_state(self, state: Dict[str, Any]):
        if not self.enabled:
            return
        try:
            with open(self.path, "w", encoding="utf-8") as f:
                json.dump(state, f, indent=2)
            log.info(f"[Persistence] State saved to {self.path}")
        except Exception as e:
            log.error(f"[Persistence] Failed to save state: {e}")

    def load_state(self) -> Optional[Dict[str, Any]]:
        if not self.enabled or not os.path.exists(self.path):
            return None
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            log.info(f"[Persistence] State loaded from {self.path}")
            return data
        except Exception as e:
            log.error(f"[Persistence] Failed to load state: {e}")
            return None

# =========================
# Plugins
# =========================

class ThreatEvaluatorPlugin(abc.ABC):
    @abc.abstractmethod
    def evaluate(self, threat: ThreatProfile) -> float:
        pass

    @abc.abstractmethod
    def name(self) -> str:
        pass

class PluginManager:
    def __init__(self, enabled: bool = True, directory: str = "plugins"):
        self.enabled = enabled
        self.directory = directory
        self.plugins: List[ThreatEvaluatorPlugin] = []
        if self.enabled:
            self._load_builtin_plugins()
            self._load_external_plugins()

    def _load_builtin_plugins(self):
        class ImpactBiasPlugin(ThreatEvaluatorPlugin):
            def evaluate(self, threat: ThreatProfile) -> float:
                if "impact" in threat.tactics:
                    return 5.0
                return 0.0
            def name(self) -> str:
                return "ImpactBiasPlugin"

        class CyberDomainBoostPlugin(ThreatEvaluatorPlugin):
            def evaluate(self, threat: ThreatProfile) -> float:
                if threat.domain == "cyber":
                    return 3.0
                return 0.0
            def name(self) -> str:
                return "CyberDomainBoostPlugin"

        self.plugins.append(ImpactBiasPlugin())
        self.plugins.append(CyberDomainBoostPlugin())
        log.info(f"[Plugins] Loaded {len(self.plugins)} builtin plugin(s).")

    def _load_external_plugins(self):
        if not os.path.isdir(self.directory):
            return
        for fname in os.listdir(self.directory):
            if not fname.endswith(".py"):
                continue
            path = os.path.join(self.directory, fname)
            try:
                import importlib.util
                spec = importlib.util.spec_from_file_location(fname[:-3], path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)  # type: ignore
                for attr_name in dir(mod):
                    attr = getattr(mod, attr_name)
                    if isinstance(attr, type) and issubclass(attr, ThreatEvaluatorPlugin) and attr is not ThreatEvaluatorPlugin:
                        inst = attr()
                        self.plugins.append(inst)
                        log.info(f"[Plugins] Loaded external plugin: {inst.name()}")
            except Exception as e:
                log.error(f"[Plugins] Failed to load {path}: {e}")

    def evaluate_with_plugins(self, threat: ThreatProfile) -> float:
        if not self.enabled:
            return 0.0
        total = 0.0
        for p in self.plugins:
            total += p.evaluate(threat)
        return total

# =========================
# LLM / Forklift dual-mode engine
# =========================

HAS_CUDA = False
NUM_GPUS = 0
DEFAULT_DEVICE = "cpu"
PRIMARY_MODEL_NAME = "gpt2"

CURRENT_MODEL = None
CURRENT_TOKENIZER = None
CURRENT_MODEL_NAME = None
IS_FALLBACK_MODEL = False

GLOBAL_CACHE: Dict[str, Any] = {}

def is_game_running(process_names: List[str]) -> bool:
    try:
        for proc in psutil.process_iter(attrs=["name"]):
            name = proc.info.get("name", "").lower()
            for target in process_names:
                if target.lower() in name:
                    return True
    except Exception as e:
        log.error(f"[GamePID] Failed to scan processes: {e}")
    return False

def get_system_telemetry(cfg: Optional[ConfigManager] = None) -> Dict[str, Any]:
    # Mixed telemetry: basic stub + game PID state
    game_cfg = cfg.get("game", {}) if cfg is not None else DEFAULT_CONFIG.get("game", {})
    enabled = game_cfg.get("enabled", True)
    process_names = game_cfg.get("process_names", [])
    game_running = is_game_running(process_names) if enabled else False
    return {
        "cpu": 0.5,
        "gpu": 0.3,
        "mem": 0.6,
        "game_running": game_running,
    }

def train_policy_net_step(sys_tel, latency_ms):
    # Hook for real policy net training
    return

class ForkliftExecutor:
    def __init__(self):
        self._stats = {"calls": 0}
    def linear(self, layer_name, weight, bias, x, layer_depth):
        self._stats["calls"] += 1
        return weight @ x.T + (bias.unsqueeze(1) if bias is not None else 0)
    def reset_stats(self, clear_router_data: bool = False):
        self._stats = {"calls": 0}
    def stats(self):
        return dict(self._stats)

EXECUTOR = ForkliftExecutor()

if AI_LIBS["torch"] is not None:
    import torch
    import torch.nn as nn
else:
    torch = None
    nn = None

if AI_LIBS["transformers"] is not None:
    from transformers import AutoTokenizer, AutoModelForCausalLM
else:
    AutoTokenizer = None
    AutoModelForCausalLM = None

class TinyFallback(nn.Module if nn is not None else object):
    def __init__(self):
        if nn is not None:
            super().__init__()
        self.emb = nn.Embedding(256, 64) if nn is not None else None
        self.fc = nn.Linear(64, 256) if nn is not None else None

    def forward(self, input_ids):
        if self.emb is None or self.fc is None:
            return input_ids
        x = self.emb(input_ids)
        x = x.mean(dim=1)
        return self.fc(x)

    def generate(self, input_ids: torch.Tensor, max_new_tokens: int = 32, **kwargs):
        return input_ids

class ForkliftLinear(nn.Module if nn is not None else object):
    def __init__(self, base: nn.Linear, name: str, executor: ForkliftExecutor, depth: int = 0):
        if nn is not None:
            super().__init__()
        self.base = base
        self.name = name
        self.executor = executor
        self.depth = depth
    def forward(self, x):
        return self.executor.linear(
            layer_name=self.name,
            weight=self.base.weight,
            bias=self.base.bias,
            x=x,
            layer_depth=self.depth,
        )

def _patch_module_with_forklift(module: nn.Module, prefix: str = "", depth: int = 0):
    for child_name, child in list(module.named_children()):
        full_name = f"{prefix}{child_name}"
        if isinstance(child, nn.Linear):
            setattr(
                module,
                child_name,
                ForkliftLinear(child, full_name, EXECUTOR, depth),
            )
        else:
            _patch_module_with_forklift(child, full_name + ".", depth + 1)

def patch_model_with_forklift(model: nn.Module):
    _patch_module_with_forklift(model, prefix="", depth=0)

def load_model(model_name: str = PRIMARY_MODEL_NAME):
    global CURRENT_MODEL, CURRENT_TOKENIZER, CURRENT_MODEL_NAME, IS_FALLBACK_MODEL

    if CURRENT_MODEL is not None and CURRENT_TOKENIZER is not None:
        return

    if torch is None or AutoTokenizer is None or AutoModelForCausalLM is None:
        log.info("[LLM] Torch/Transformers not available, using TinyFallback.")
        CURRENT_MODEL = TinyFallback()
        CURRENT_TOKENIZER = None
        CURRENT_MODEL_NAME = "TinyFallback"
        IS_FALLBACK_MODEL = True
        return

    log.info(f"[LLM] Loading model: {model_name}")
    try:
        tok = AutoTokenizer.from_pretrained(model_name)
        mdl = AutoModelForCausalLM.from_pretrained(
            model_name,
            torch_dtype=torch.float16 if HAS_CUDA else torch.float32,
            device_map="auto" if HAS_CUDA and NUM_GPUS > 1 else None,
        )
        mdl.to(DEFAULT_DEVICE)
        mdl.eval()
        patch_model_with_forklift(mdl)

        CURRENT_MODEL = mdl
        CURRENT_TOKENIZER = tok
        CURRENT_MODEL_NAME = model_name
        IS_FALLBACK_MODEL = False
        log.info(f"[LLM] Loaded HF model: {model_name}")
    except Exception as e:
        log.error(f"[LLM] Failed to load {model_name}, falling back to TinyFallback: {e}")
        try:
            tok = AutoTokenizer.from_pretrained("gpt2")
        except Exception:
            class DummyTok:
                def __init__(self):
                    self.eos_token_id = 0
                def __call__(self, text, return_tensors=None):
                    ids = [ord(c) % 256 for c in text]
                    t = torch.tensor([ids], dtype=torch.long)
                    return {"input_ids": t}
                def decode(self, ids, skip_special_tokens=True):
                    return "".join(chr(int(i) % 256) for i in ids)
            tok = DummyTok()

        mdl = TinyFallback().to(DEFAULT_DEVICE) if torch is not None else TinyFallback()
        if hasattr(mdl, "eval"):
            mdl.eval()

        CURRENT_MODEL = mdl
        CURRENT_TOKENIZER = tok
        CURRENT_MODEL_NAME = "TinyFallback"
        IS_FALLBACK_MODEL = True
        log.info("[LLM] Using TinyFallback model.")

@torch.inference_mode() if torch is not None else (lambda f: f)
def generate_text(prompt: str, max_new_tokens: int = 64, extra_context: Dict[str, Any] = None, cfg: Optional[ConfigManager] = None) -> Tuple[str, dict]:
    load_model()

    EXECUTOR.reset_stats(clear_router_data=False)

    tok = CURRENT_TOKENIZER
    mdl = CURRENT_MODEL

    if tok is None or mdl is None:
        return prompt, {"model_name": "none", "is_fallback": True, "latency_ms": 0.0}

    # Enriched context: system telemetry + game state + extra
    anomaly_block = {
        "telemetry": get_system_telemetry(cfg),
        "extra": extra_context or {},
    }
    context_str = json.dumps(anomaly_block, indent=2)

    full_prompt = f"[CONTEXT]\n{context_str}\n\n[USER]\n{prompt}\n\n[ASSISTANT]\n"

    inputs = tok(full_prompt, return_tensors="pt")
    if isinstance(inputs, dict):
        for k in inputs:
            if isinstance(inputs[k], torch.Tensor):
                inputs[k] = inputs[k].to(DEFAULT_DEVICE)

    t0 = time.time()

    if isinstance(mdl, TinyFallback):
        out_ids = inputs["input_ids"]
    else:
        out_ids = mdl.generate(
            **inputs,
            max_new_tokens=max_new_tokens,
            do_sample=True,
            top_p=0.9,
            temperature=0.8,
            pad_token_id=getattr(tok, "eos_token_id", None),
        )

    latency_ms = (time.time() - t0) * 1000.0
    text = tok.decode(out_ids[0], skip_special_tokens=True)

    stats = EXECUTOR.stats()
    stats["model_name"] = CURRENT_MODEL_NAME
    stats["is_fallback"] = IS_FALLBACK_MODEL
    stats["latency_ms"] = latency_ms
    stats["telemetry"] = anomaly_block["telemetry"]

    try:
        sys_tel = get_system_telemetry(cfg)
        train_policy_net_step(sys_tel, latency_ms)
    except Exception:
        pass

    return text, stats

# =========================
# LLM RPC server (dual-mode)
# =========================

def handle_rpc_client(conn: socket.socket, addr, cfg: ConfigManager):
    buf = b""
    try:
        while True:
            chunk = conn.recv(4096)
            if not chunk:
                break
            buf += chunk
            if b"\n" in buf:
                line, _, rest = buf.partition(b"\n")
                buf = rest
                try:
                    req = json.loads(line.decode())
                    prompt = req.get("prompt", "")
                    max_new_tokens = int(req.get("max_new_tokens", 128))
                    extra_context = req.get("context", {})

                    log.info(f"[LLM RPC] Request from {addr}, tokens={max_new_tokens}")
                    text, stats = generate_text(prompt, max_new_tokens=max_new_tokens, extra_context=extra_context, cfg=cfg)
                    resp = {"text": text, "stats": stats}
                except Exception as e:
                    resp = {"error": str(e), "stats": {}}

                conn.sendall((json.dumps(resp) + "\n").encode())
                break
    finally:
        conn.close()

def rpc_server_loop(host: str, port: int, cfg: ConfigManager):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind((host, port))
    s.listen(16)
    log.info(f"[LLM RPC] Server listening on {host}:{port}")
    while True:
        conn, addr = s.accept()
        t = threading.Thread(target=handle_rpc_client, args=(conn, addr, cfg), daemon=True)
        t.start()

# =========================
# ML models (train-ready)
# =========================

class MLModelManager:
    def __init__(self, enabled: bool, backend: str, model_name: str, train_on_start: bool, cfg: ConfigManager):
        self.enabled = enabled
        self.backend = backend
        self.model_name = model_name
        self.cfg = cfg

        self.isolation_forest = None
        self.lstm_model = None
        self.autoencoder = None

        self._training_buffer: List[List[float]] = []

        if self.enabled:
            self._init_models()
            if train_on_start:
                self.train_initial()

    def _init_models(self):
        if AI_LIBS["sklearn"] is not None:
            from sklearn.ensemble import IsolationForest
            self.isolation_forest = IsolationForest(n_estimators=100, contamination=0.05)
            log.info("[ML] IsolationForest initialized.")
        if torch is not None:
            class LSTMStub(nn.Module):
                def __init__(self, input_dim=9, hidden_dim=16, num_layers=1):
                    super().__init__()
                    self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
                    self.fc = nn.Linear(hidden_dim, 1)
                def forward(self, x):
                    out, _ = self.lstm(x)
                    out = out[:, -1, :]
                    return self.fc(out)

            class AutoencoderStub(nn.Module):
                def __init__(self, input_dim=9, hidden_dim=4):
                    super().__init__()
                    self.encoder = nn.Sequential(
                        nn.Linear(input_dim, hidden_dim),
                        nn.ReLU(),
                    )
                    self.decoder = nn.Sequential(
                        nn.Linear(hidden_dim, input_dim),
                        nn.ReLU(),
                    )
                def forward(self, x):
                    z = self.encoder(x)
                    recon = self.decoder(z)
                    return recon

            self.lstm_model = LSTMStub()
            self.autoencoder = AutoencoderStub()
            log.info("[ML] LSTM + Autoencoder stubs initialized.")

    def _feature_vector(self, threat: ThreatProfile) -> List[float]:
        tel = get_system_telemetry(self.cfg)
        game_running = 1.0 if tel.get("game_running", False) else 0.0
        return [
            float(threat.tech_level),
            float(threat.resilience),
            float(len(threat.tactics)),
            1.0 if threat.domain == "cyber" else 0.0,
            1.0 if "impact" in threat.tactics else 0.0,
            1.0 if "exfil" in threat.tactics else 0.0,
            1.0 if "persistence" in threat.tactics else 0.0,
            1.0 if "lateral_movement" in threat.tactics else 0.0,
            game_running,
        ]

    def add_training_sample(self, threat: ThreatProfile):
        if not self.enabled:
            return
        fv = self._feature_vector(threat)
        self._training_buffer.append(fv)

    def train_initial(self):
        if not self.enabled or not self._training_buffer:
            return
        log.info("[ML] Initial training on buffered samples.")
        try:
            import numpy as np
            X = np.array(self._training_buffer)
            if self.isolation_forest is not None:
                self.isolation_forest.fit(X)
                log.info("[ML] IsolationForest trained on initial buffer.")
        except Exception as e:
            log.error(f"[ML] Initial training failed: {e}")

    def score(self, threat: ThreatProfile) -> float:
        if not self.enabled:
            return 0.0

        features = self._feature_vector(threat)

        iso_score = 0.0
        if self.isolation_forest is not None:
            try:
                import numpy as np
                arr = np.array(features).reshape(1, -1)
                iso_score = float(-self.isolation_forest.decision_function(arr)[0] * 50.0)
            except Exception:
                iso_score = 0.0

        lstm_score = 0.0
        if self.lstm_model is not None and torch is not None:
            try:
                x = torch.tensor(features, dtype=torch.float32).view(1, 1, -1)
                out = self.lstm_model(x)
                lstm_score = float(out.item())
            except Exception:
                lstm_score = 0.0

        ae_score = 0.0
        if self.autoencoder is not None and torch is not None:
            try:
                x = torch.tensor(features, dtype=torch.float32).view(1, -1)
                recon = self.autoencoder(x)
                loss = torch.mean((x - recon) ** 2).item()
                ae_score = float(loss * 100.0)
            except Exception:
                ae_score = 0.0

        llm_score = 0.0
        try:
            prompt = (
                f"Threat ID: {threat.id}\n"
                f"Domain: {threat.domain}\n"
                f"Tech level: {threat.tech_level}\n"
                f"Resilience: {threat.resilience}\n"
                f"Tactics: {', '.join(threat.tactics)}\n"
                f"Source: {threat.source}\n"
                "Rate this threat on a scale from 0 to 100 as a single number:\n"
            )
            text, _ = generate_text(prompt, max_new_tokens=32, extra_context={"mode": "ml_score"}, cfg=self.cfg)
            digits = "".join(ch for ch in text if ch.isdigit())
            if digits:
                llm_score = float(digits[:3])
                llm_score = max(0.0, min(100.0, llm_score))
        except Exception:
            llm_score = 0.0

        total = iso_score + lstm_score + ae_score + llm_score
        return max(0.0, min(100.0, total / 4.0))

# =========================
# SIEM integration
# =========================

class SIEMIntegrator:
    def __init__(self, cfg: ConfigManager):
        self.cfg = cfg
        self.requests = AI_LIBS["requests"]

    def _post_json(self, url: str, headers: Dict[str, str], payload: Dict[str, Any], label: str):
        if self.requests is None or not url:
            return
        try:
            resp = self.requests.post(url, headers=headers, json=payload, timeout=3)
            log.info(f"[SIEM:{label}] POST Status={resp.status_code}")
        except Exception as e:
            log.error(f"[SIEM:{label}] POST failed: {e}")

    def _get_json(self, url: str, headers: Dict[str, str], params_or_body: Any, label: str, method: str = "get") -> List[Dict[str, Any]]:
        if self.requests is None or not url:
            return []
        try:
            if method == "get":
                resp = self.requests.get(url, headers=headers, params=params_or_body, timeout=5)
            else:
                resp = self.requests.post(url, headers=headers, json=params_or_body, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                log.info(f"[SIEM:{label}] Ingest OK.")
                if isinstance(data, dict):
                    return [data]
                if isinstance(data, list):
                    return data
            else:
                log.error(f"[SIEM:{label}] Ingest status={resp.status_code}")
        except Exception as e:
            log.error(f"[SIEM:{label}] Ingest failed: {e}")
        return []

    def send_event(self, threat: ThreatProfile, action: str):
        event = {
            "threat_id": threat.id,
            "domain": threat.domain,
            "signature": threat.signature,
            "resilience": threat.resilience,
            "tactics": threat.tactics,
            "source": threat.source,
            "action": action,
            "metadata": threat.metadata,
            "timestamp": threat.timestamp,
        }

        splunk_cfg = self.cfg.get("siem.splunk", {})
        if splunk_cfg.get("enabled", False):
            headers = {
                "Authorization": f"Splunk {splunk_cfg.get('token', '')}",
                "Content-Type": "application/json",
            }
            payload = {"event": event}
            self._post_json(splunk_cfg.get("hec_url", ""), headers, payload, "Splunk")

        elastic_cfg = self.cfg.get("siem.elastic", {})
        if elastic_cfg.get("enabled", False):
            headers = {
                "Authorization": f"ApiKey {elastic_cfg.get('api_key', '')}",
                "Content-Type": "application/json",
            }
            self._post_json(elastic_cfg.get("url", ""), headers, event, "Elastic")

        sentinel_cfg = self.cfg.get("siem.sentinel", {})
        if sentinel_cfg.get("enabled", False):
            headers = {
                "Authorization": f"Bearer {sentinel_cfg.get('token', '')}",
                "Content-Type": "application/json",
            }
            self._post_json(sentinel_cfg.get("url", ""), headers, event, "Sentinel")

    def ingest_events(self) -> List[ThreatProfile]:
        threats: List[ThreatProfile] = []

        splunk_cfg = self.cfg.get("siem.splunk", {})
        if splunk_cfg.get("enabled", False):
            headers = {
                "Authorization": f"Splunk {splunk_cfg.get('token', '')}",
                "Content-Type": "application/json",
            }
            url = splunk_cfg.get("search_url", "")
            query = {"search": splunk_cfg.get("search_query", "")}
            data = self._get_json(url, headers, query, "Splunk", method="post")
            for idx, ev in enumerate(data):
                tp = ThreatProfile(
                    threat_id=f"SPLUNK-{idx}",
                    tech_level=5,
                    domain="cyber",
                    signature="splunk_event",
                    resilience=5.0,
                    tactics=["recon"],
                    source="siem_splunk",
                    metadata=ev,
                )
                threats.append(tp)

        elastic_cfg = self.cfg.get("siem.elastic", {})
        if elastic_cfg.get("enabled", False):
            headers = {
                "Authorization": f"ApiKey {elastic_cfg.get('api_key', '')}",
                "Content-Type": "application/json",
            }
            url = elastic_cfg.get("search_url", "")
            body = elastic_cfg.get("search_body", {})
            data = self._get_json(url, headers, body, "Elastic", method="post")
            for idx, ev in enumerate(data):
                tp = ThreatProfile(
                    threat_id=f"ELASTIC-{idx}",
                    tech_level=5,
                    domain="cyber",
                    signature="elastic_event",
                    resilience=5.0,
                    tactics=["recon"],
                    source="siem_elastic",
                    metadata=ev,
                )
                threats.append(tp)

        sentinel_cfg = self.cfg.get("siem.sentinel", {})
        if sentinel_cfg.get("enabled", False):
            headers = {
                "Authorization": f"Bearer {sentinel_cfg.get('token', '')}",
                "Content-Type": "application/json",
            }
            url = sentinel_cfg.get("search_url", "")
            body = sentinel_cfg.get("search_body", {})
            data = self._get_json(url, headers, body, "Sentinel", method="post")
            for idx, ev in enumerate(data):
                tp = ThreatProfile(
                    threat_id=f"SENTINEL-{idx}",
                    tech_level=5,
                    domain="cyber",
                    signature="sentinel_event",
                    resilience=5.0,
                    tactics=["recon"],
                    source="siem_sentinel",
                    metadata=ev,
                )
                threats.append(tp)

        return threats

# =========================
# Actions (SAFE)
# =========================

class ActionExecutor:
    def __init__(self, enabled: bool = True, dry_run: bool = True):
        self.enabled = enabled
        self.dry_run = dry_run

    def _log_action(self, action: str, details: Dict[str, Any]):
        if not self.enabled:
            return
        log.info(f"[Action] {action}: {details}")
        if self.dry_run:
            log.info("[Action] DRY-RUN mode: no real system changes performed.")

    def block_ip(self, ip: str, reason: str):
        self._log_action("block_ip", {"ip": ip, "reason": reason})

    def kill_process(self, pid: int, reason: str):
        self._log_action("kill_process", {"pid": pid, "reason": reason})

    def quarantine_file(self, path: str, reason: str):
        self._log_action("quarantine_file", {"path": path, "reason": reason})

    def disable_account(self, username: str, reason: str):
        self._log_action("disable_account", {"username": username, "reason": reason})

    def isolate_host(self, hostname: str, reason: str):
        self._log_action("isolate_host", {"hostname": hostname, "reason": reason})

    def execute_for_threat(self, threat: ThreatProfile, action: str):
        reason = f"Threat {threat.id} action={action}"
        if action in ("neutralize", "neutralize_and_assimilate", "neutralize_then_study"):
            ip = threat.metadata.get("src_ip") or threat.metadata.get("dest_ip")
            if ip:
                self.block_ip(ip, reason)
        if "persistence" in threat.tactics:
            self.disable_account(threat.metadata.get("user", "unknown"), reason)
        if "impact" in threat.tactics:
            self.isolate_host(threat.metadata.get("host", "unknown"), reason)

# =========================
# Game telemetry (UDP) – mixed with PID state
# =========================

class GameTelemetryManager:
    def __init__(self, cfg: ConfigManager):
        self.cfg = cfg
        self.host = cfg.get("game.telemetry_udp_host", "127.0.0.1")
        self.port = int(cfg.get("game.telemetry_udp_port", 7777))
        self.enabled = cfg.get("game.enabled", True)
        self._lock = threading.Lock()
        self.latest: Dict[str, Any] = {}
        if self.enabled:
            threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        log.info(f"[GameTelemetry] Listening on {self.host}:{self.port}")
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((self.host, self.port))
        while True:
            try:
                data, addr = s.recvfrom(4096)
                try:
                    evt = json.loads(data.decode())
                except Exception:
                    continue
                with self._lock:
                    self.latest = evt
                log.info(f"[GameTelemetry] Event from {addr}: {evt}")
            except Exception as e:
                log.error(f"[GameTelemetry] Error: {e}")

    def snapshot(self) -> Dict[str, Any]:
        with self._lock:
            return dict(self.latest)

# =========================
# Ingestion (logs + packet + SIEM)
# =========================

class ThreatIngestionManager:
    def __init__(self, cfg: ConfigManager, siem: SIEMIntegrator, game_telemetry: GameTelemetryManager):
        self.cfg = cfg
        self.siem = siem
        self.game_telemetry = game_telemetry

        self.suricata_path = cfg.get("ingestion.suricata_json_path")
        self.sysmon_path = cfg.get("ingestion.sysmon_log_path")
        self.generic_path = cfg.get("ingestion.generic_log_path")
        self.zeek_conn_path = cfg.get("ingestion.zeek_conn_log_path")
        self.zeek_dns_path = cfg.get("ingestion.zeek_dns_log_path")
        self.zeek_http_path = cfg.get("ingestion.zeek_http_log_path")
        self.pcap_path = cfg.get("ingestion.pcap_path")
        self.poll_interval = cfg.get("ingestion.poll_interval_sec", 1.0)

        self.tcp_enabled = cfg.get("ingestion.tcp_listener_enabled", True)
        self.tcp_host = cfg.get("ingestion.tcp_listener_host", "0.0.0.0")
        self.tcp_port = cfg.get("ingestion.tcp_listener_port", 5555)

        self.suricata_pos = 0
        self.sysmon_pos = 0
        self.generic_pos = 0
        self.zeek_conn_pos = 0
        self.zeek_dns_pos = 0
        self.zeek_http_pos = 0

        self._lock = threading.Lock()
        self._live_queue: List[ThreatProfile] = []

        if self.tcp_enabled:
            self._start_tcp_listener()

        self._poll_thread = threading.Thread(target=self._poll_loop, daemon=True)
        self._poll_thread.start()

        self._pcap_thread = threading.Thread(target=self._pcap_loop, daemon=True)
        self._pcap_thread.start()

        eve_cfg = cfg.get("ingestion.suricata_eve_socket", {})
        if eve_cfg.get("enabled", False):
            self._eve_thread = threading.Thread(target=self._eve_socket_loop, daemon=True)
            self._eve_thread.start()

        self._siem_thread = threading.Thread(target=self._siem_loop, daemon=True)
        self._siem_thread.start()

    def _start_tcp_listener(self):
        def listener():
            log.info(f"[TCP] Threat listener starting on {self.tcp_host}:{self.tcp_port}")
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            s.bind((self.tcp_host, self.tcp_port))
            s.listen(5)
            while True:
                conn, addr = s.accept()
                try:
                    data = conn.recv(4096)
                    if not data:
                        conn.close()
                        continue
                    try:
                        payload = json.loads(data.decode("utf-8", errors="ignore"))
                        tp = self._threat_from_external_payload(payload)
                        with self._lock:
                            self._live_queue.append(tp)
                        log.info(f"[TCP] Received external threat from {addr}: {tp}")
                    except Exception as e:
                        log.error(f"[TCP] Failed to parse threat payload: {e}")
                finally:
                    conn.close()

        threading.Thread(target=listener, daemon=True).start()

    def _poll_loop(self):
        while True:
            try:
                self._poll_suricata()
                self._poll_sysmon()
                self._poll_generic()
                self._poll_zeek_conn()
                self._poll_zeek_dns()
                self._poll_zeek_http()
            except Exception as e:
                log.error(f"[Ingestion] Poll loop error: {e}")
            time.sleep(self.poll_interval)

    def _pcap_loop(self):
        if not self.pcap_path or not os.path.exists(self.pcap_path):
            return
        if AI_LIBS["pyshark"] is None and AI_LIBS["scapy"] is None:
            log.info("[PCAP] No pyshark/scapy available, skipping PCAP ingestion.")
            return
        while True:
            try:
                if AI_LIBS["pyshark"] is not None:
                    import pyshark
                    cap = pyshark.FileCapture(self.pcap_path)
                    for idx, pkt in enumerate(cap):
                        tp = self._threat_from_pcap_packet(pkt, idx)
                        with self._lock:
                            self._live_queue.append(tp)
                elif AI_LIBS["scapy"] is not None:
                    from scapy.all import rdpcap
                    pkts = rdpcap(self.pcap_path)
                    for idx, pkt in enumerate(pkts):
                        tp = self._threat_from_scapy_packet(pkt, idx)
                        with self._lock:
                            self._live_queue.append(tp)
            except Exception as e:
                log.error(f"[PCAP] Ingestion error: {e}")
            time.sleep(10.0)

    def _eve_socket_loop(self):
        eve_cfg = self.cfg.get("ingestion.suricata_eve_socket", {})
        host = eve_cfg.get("host", "127.0.0.1")
        port = eve_cfg.get("port", 6514)
        log.info(f"[EVE] Connecting to Suricata eve-socket {host}:{port}")
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.connect((host, port))
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, _, buf = buf.partition(b"\n")
                        try:
                            event = json.loads(line.decode("utf-8", errors="ignore"))
                            tp = self._threat_from_suricata_event(event, int(time.time()))
                            with self._lock:
                                self._live_queue.append(tp)
                        except Exception:
                            pass
                s.close()
            except Exception as e:
                log.error(f"[EVE] Socket error: {e}")
                time.sleep(5.0)

    def _siem_loop(self):
        while True:
            try:
                siem_threats = self.siem.ingest_events()
                if siem_threats:
                    with self._lock:
                        self._live_queue.extend(siem_threats)
                    log.info(f"[SIEM] Ingested {len(siem_threats)} SIEM events as threats.")
            except Exception as e:
                log.error(f"[SIEM] Ingestion loop error: {e}")
            time.sleep(30.0)

    def _poll_suricata(self):
        if not self.suricata_path or not os.path.exists(self.suricata_path):
            return
        try:
            with open(self.suricata_path, "r", encoding="utf-8") as f:
                f.seek(self.suricata_pos)
                for idx, line in enumerate(f, start=self.suricata_pos):
                    line = line.strip()
                    if not line:
                        continue
                    event = json.loads(line)
                    tp = self._threat_from_suricata_event(event, idx)
                    with self._lock:
                        self._live_queue.append(tp)
                self.suricata_pos = f.tell()
        except Exception as e:
            log.error(f"[Ingestion] Suricata poll failed: {e}")

    def _poll_sysmon(self):
        if not self.sysmon_path or not os.path.exists(self.sysmon_path):
            return
        try:
            with open(self.sysmon_path, "r", encoding="utf-8") as f:
                f.seek(self.sysmon_pos)
                for idx, line in enumerate(f, start=self.sysmon_pos):
                    line = line.strip()
                    if not line:
                        continue
                    tp = self._threat_from_sysmon_line(line, idx)
                    with self._lock:
                        self._live_queue.append(tp)
                self.sysmon_pos = f.tell()
        except Exception as e:
            log.error(f"[Ingestion] Sysmon poll failed: {e}")

    def _poll_generic(self):
        if not self.generic_path or not os.path.exists(self.generic_path):
            return
        try:
            with open(self.generic_path, "r", encoding="utf-8") as f:
                f.seek(self.generic_pos)
                for idx, line in enumerate(f, start=self.generic_pos):
                    line = line.strip()
                    if not line:
                        continue
                    tp = self._threat_from_generic_line(line, idx)
                    with self._lock:
                        self._live_queue.append(tp)
                self.generic_pos = f.tell()
        except Exception as e:
            log.error(f"[Ingestion] Generic poll failed: {e}")

    def _poll_zeek_conn(self):
        if not self.zeek_conn_path or not os.path.exists(self.zeek_conn_path):
            return
        try:
            with open(self.zeek_conn_path, "r", encoding="utf-8") as f:
                f.seek(self.zeek_conn_pos)
                for idx, line in enumerate(f, start=self.zeek_conn_pos):
                    line = line.strip()
                    if not line:
                        continue
                    tp = self._threat_from_zeek_conn_line(line, idx)
                    with self._lock:
                        self._live_queue.append(tp)
                self.zeek_conn_pos = f.tell()
        except Exception as e:
            log.error(f"[Ingestion] Zeek conn poll failed: {e}")

    def _poll_zeek_dns(self):
        if not self.zeek_dns_path or not os.path.exists(self.zeek_dns_path):
            return
        try:
            with open(self.zeek_dns_path, "r", encoding="utf-8") as f:
                f.seek(self.zeek_dns_pos)
                for idx, line in enumerate(f, start=self.zeek_dns_pos):
                    line = line.strip()
                    if not line:
                        continue
                    tp = self._threat_from_zeek_dns_line(line, idx)
                    with self._lock:
                        self._live_queue.append(tp)
                self.zeek_dns_pos = f.tell()
        except Exception as e:
            log.error(f"[Ingestion] Zeek dns poll failed: {e}")

    def _poll_zeek_http(self):
        if not self.zeek_http_path or not os.path.exists(self.zeek_http_path):
            return
        try:
            with open(self.zeek_http_path, "r", encoding="utf-8") as f:
                f.seek(self.zeek_http_pos)
                for idx, line in enumerate(f, start=self.zeek_http_pos):
                    line = line.strip()
                    if not line:
                        continue
                    tp = self._threat_from_zeek_http_line(line, idx)
                    with self._lock:
                        self._live_queue.append(tp)
                self.zeek_http_pos = f.tell()
        except Exception as e:
            log.error(f"[Ingestion] Zeek http poll failed: {e}")

    def _threat_from_external_payload(self, payload: Dict[str, Any]) -> ThreatProfile:
        tid = payload.get("id", f"EXT-{int(time.time())}")
        tech = int(payload.get("tech_level", 5))
        domain = payload.get("domain", "cyber")
        signature = payload.get("signature", "external")
        resilience = float(payload.get("resilience", 5.0))
        tactics = payload.get("tactics", [])
        if not isinstance(tactics, list):
            tactics = [tactics]
        return ThreatProfile(
            threat_id=tid,
            tech_level=tech,
            domain=domain,
            signature=signature,
            resilience=resilience,
            tactics=tactics,
            source="external_tcp",
            metadata=payload,
        )

    def _threat_from_suricata_event(self, event: Dict[str, Any], idx: int) -> ThreatProfile:
        sig = event.get("alert", {}).get("signature", "suricata")
        severity = int(event.get("alert", {}).get("severity", 3))
        src_ip = event.get("src_ip", "unknown")
        dest_ip = event.get("dest_ip", "unknown")
        domain = "cyber"
        tactics = ["recon"]
        if severity >= 3:
            tactics.append("impact")
        resilience = 5.0 + severity
        tech_level = 5 + severity
        return ThreatProfile(
            threat_id=f"SUR-{idx}",
            tech_level=tech_level,
            domain=domain,
            signature=sig,
            resilience=resilience,
            tactics=tactics,
            source="suricata",
            metadata={"src_ip": src_ip, "dest_ip": dest_ip, "severity": severity},
        )

    def _threat_from_sysmon_line(self, line: str, idx: int) -> ThreatProfile:
        domain = "cyber"
        signature = "sysmon_event"
        resilience = 6.0
        tech_level = 6
        tactics = ["persistence", "lateral_movement"]
        return ThreatProfile(
            threat_id=f"SYS-{idx}",
            tech_level=tech_level,
            domain=domain,
            signature=signature,
            resilience=resilience,
            tactics=tactics,
            source="sysmon",
            metadata={"raw": line},
        )

    def _threat_from_generic_line(self, line: str, idx: int) -> ThreatProfile:
        domain = "cyber"
        signature = "generic_log"
        resilience = 4.0
        tech_level = 4
        tactics = ["recon"]
        return ThreatProfile(
            threat_id=f"GEN-{idx}",
            tech_level=tech_level,
            domain=domain,
            signature=signature,
            resilience=resilience,
            tactics=tactics,
            source="generic_log",
            metadata={"raw": line},
        )

    def _threat_from_zeek_conn_line(self, line: str, idx: int) -> ThreatProfile:
        domain = "cyber"
        signature = "zeek_conn"
        resilience = 5.0
        tech_level = 5
        tactics = ["recon"]
        return ThreatProfile(
            threat_id=f"ZCONN-{idx}",
            tech_level=tech_level,
            domain=domain,
            signature=signature,
            resilience=resilience,
            tactics=tactics,
            source="zeek_conn",
            metadata={"raw": line},
        )

    def _threat_from_zeek_dns_line(self, line: str, idx: int) -> ThreatProfile:
        domain = "cyber"
        signature = "zeek_dns"
        resilience = 5.0
        tech_level = 5
        tactics = ["recon"]
        return ThreatProfile(
            threat_id=f"ZDNS-{idx}",
            tech_level=tech_level,
            domain=domain,
            signature=signature,
            resilience=resilience,
            tactics=tactics,
            source="zeek_dns",
            metadata={"raw": line},
        )

    def _threat_from_zeek_http_line(self, line: str, idx: int) -> ThreatProfile:
        domain = "cyber"
        signature = "zeek_http"
        resilience = 5.0
        tech_level = 5
        tactics = ["recon"]
        return ThreatProfile(
            threat_id=f"ZHTTP-{idx}",
            tech_level=tech_level,
            domain=domain,
            signature=signature,
            resilience=resilience,
            tactics=tactics,
            source="zeek_http",
            metadata={"raw": line},
        )

    def _threat_from_pcap_packet(self, pkt, idx: int) -> ThreatProfile:
        domain = "cyber"
        signature = "pcap_pyshark"
        resilience = 5.0
        tech_level = 5
        tactics = ["recon"]
        meta = {"summary": str(pkt)}
        return ThreatProfile(
            threat_id=f"PCAP-{idx}",
            tech_level=tech_level,
            domain=domain,
            signature=signature,
            resilience=resilience,
            tactics=tactics,
            source="pcap_pyshark",
            metadata=meta,
        )

    def _threat_from_scapy_packet(self, pkt, idx: int) -> ThreatProfile:
        domain = "cyber"
        signature = "pcap_scapy"
        resilience = 5.0
        tech_level = 5
        tactics = ["recon"]
        meta = {"summary": str(pkt)}
        return ThreatProfile(
            threat_id=f"SCAPY-{idx}",
            tech_level=tech_level,
            domain=domain,
            signature=signature,
            resilience=resilience,
            tactics=tactics,
            source="pcap_scapy",
            metadata=meta,
        )

    def ingest_next_threat(self, round_id: int) -> Optional[ThreatProfile]:
        with self._lock:
            if self._live_queue:
                return self._live_queue.pop(0)
        # If game is running and telemetry exists, synthesize a game threat
        tel = self.game_telemetry.snapshot()
        if tel:
            tid = f"GAME-{round_id}"
            tech = int(tel.get("tech_level", 5))
            resilience = float(tel.get("resilience", 5.0))
            tactics = tel.get("tactics", ["recon"])
            if not isinstance(tactics, list):
                tactics = [tactics]
            return ThreatProfile(
                threat_id=tid,
                tech_level=tech,
                domain="cyber",
                signature="game_telemetry",
                resilience=resilience,
                tactics=tactics,
                source="game_telemetry",
                metadata=tel,
            )
        return None

# =========================
# Abstract AI empire
# =========================

class AIEmpire(abc.ABC):
    def __init__(self, name: str, resources: ResourcePool):
        self.name = name
        self.resources = resources
        self.knowledge_base: Dict[str, Any] = {}
        self.adaptation_state: Dict[str, float] = {}

    @abc.abstractmethod
    def evaluate_threat(self, threat: ThreatProfile) -> float:
        raise NotImplementedError

    @abc.abstractmethod
    def respond_to_threat(self, threat: ThreatProfile) -> str:
        raise NotImplementedError

    @abc.abstractmethod
    def assimilate_technology(self, tech_descriptor: Dict[str, Any]) -> None:
        raise NotImplementedError

    @abc.abstractmethod
    def adapt(self, feedback: Dict[str, Any]) -> None:
        raise NotImplementedError

    def log_state(self) -> None:
        log.info(f"[{self.name}] Resources: {self.resources}")
        log.info(f"[{self.name}] Adaptation: {self.adaptation_state}")
        log.info(f"[{self.name}] Knowledge keys: {list(self.knowledge_base.keys())}")

# =========================
# Skynet core
# =========================

class SkynetCore(AIEmpire):
    def __init__(self, resources: Optional[ResourcePool] = None):
        super().__init__("SkynetCore", resources or ResourcePool(
            energy_units=1500.0,
            compute_units=2000.0,
            fabrication_units=1000.0,
            drones=500,
            nodes=5,
        ))

    def evaluate_threat(self, threat: ThreatProfile) -> float:
        base = threat.tech_level * 1.5 + threat.resilience * 2.0
        if threat.domain == "cyber":
            base *= 1.2
        for t in threat.tactics:
            base *= MITRE_TACTICS.get(t, {"weight": 1.0})["weight"]
        if threat.domain == "space":
            base *= 0.9
        return base

    def respond_to_threat(self, threat: ThreatProfile) -> str:
        score = self.evaluate_threat(threat)
        if score > 50:
            action = "overwhelming_neutralization"
        elif 20 < score <= 50:
            action = "targeted_neutralization"
        else:
            action = "monitor"

        if action != "monitor":
            self.resources.energy_units -= 10.0
            self.resources.compute_units -= 5.0
            self.resources.drones = max(0, self.resources.drones - 1)

        log.info(f"[SkynetCore] Threat {threat.id} score={score:.2f} -> {action}")
        return action

    def assimilate_technology(self, tech_descriptor: Dict[str, Any]) -> None:
        tech_name = tech_descriptor.get("name", "unknown_tech")
        complexity = tech_descriptor.get("complexity", 1.0)
        gain_compute = complexity * 10.0
        gain_fabrication = complexity * 5.0

        self.resources.compute_units += gain_compute
        self.resources.fabrication_units += gain_fabrication
        self.knowledge_base[tech_name] = tech_descriptor

        log.info(f"[SkynetCore] Integrated tech '{tech_name}' "
                 f"(+C={gain_compute:.1f}, +F={gain_fabrication:.1f})")

    def adapt(self, feedback: Dict[str, Any]) -> None:
        outcome = feedback.get("outcome", "unknown")
        domain = feedback.get("domain", "generic")

        key = f"domain_{domain}"
        current = self.adaptation_state.get(key, 0.0)

        if outcome == "success":
            current += 0.1
        elif outcome == "failure":
            current -= 0.2

        self.adaptation_state[key] = max(-1.0, min(1.0, current))
        log.info(f"[SkynetCore] Adapted {key} -> {self.adaptation_state[key]:.2f}")

# =========================
# Borg collective
# =========================

class BorgCollective(AIEmpire):
    def __init__(self, resources: Optional[ResourcePool] = None):
        super().__init__("BorgCollective", resources or ResourcePool(
            energy_units=1200.0,
            compute_units=1500.0,
            fabrication_units=400.0,
            drones=300,
            nodes=20,
        ))

    def evaluate_threat(self, threat: ThreatProfile) -> float:
        base = threat.tech_level * 2.0 + threat.resilience * 1.5
        if threat.tech_level >= 8:
            base *= 1.3
        for t in threat.tactics:
            base *= MITRE_TACTICS.get(t, {"weight": 1.0})["weight"]
        return base

    def respond_to_threat(self, threat: ThreatProfile) -> str:
        score = self.evaluate_threat(threat)
        if score > 60:
            action = "assimilate"
        elif 30 < score <= 60:
            action = "neutralize_and_salvage"
        else:
            action = "ignore"

        if action != "ignore":
            self.resources.energy_units -= 8.0
            self.resources.drones = max(0, self.resources.drones - 2)

        log.info(f"[BorgCollective] Threat {threat.id} score={score:.2f} -> {action}")
        return action

    def assimilate_technology(self, tech_descriptor: Dict[str, Any]) -> None:
        tech_name = tech_descriptor.get("name", "unknown_tech")
        complexity = tech_descriptor.get("complexity", 1.0)
        gain_nodes = int(complexity * 2)
        gain_compute = complexity * 8.0

        self.resources.nodes += gain_nodes
        self.resources.compute_units += gain_compute
        self.knowledge_base[tech_name] = tech_descriptor

        log.info(f"[BorgCollective] Assimilated '{tech_name}' "
                 f"(+nodes={gain_nodes}, +C={gain_compute:.1f})")

    def adapt(self, feedback: Dict[str, Any]) -> None:
        signature = feedback.get("signature", "generic")
        outcome = feedback.get("outcome", "unknown")

        current = self.adaptation_state.get(signature, 0.0)
        if outcome == "success":
            current += 0.2
        elif outcome == "failure":
            current -= 0.3

        self.adaptation_state[signature] = max(-1.0, min(1.0, current))
        log.info(f"[BorgCollective] Adapted signature '{signature}' "
                 f"-> {self.adaptation_state[signature]:.2f}")

# =========================
# Modern AI stubs + ensemble
# =========================

class SymbolicReasoner:
    def reason(self, threat: ThreatProfile) -> str:
        if "exfil" in threat.tactics and threat.domain == "cyber":
            return "critical_data_exfil"
        if "recon" in threat.tactics:
            return "early_stage_recon"
        if threat.tech_level >= 9:
            return "high_tech_priority"
        return "standard"

class MLScoringStub:
    def score(self, threat: ThreatProfile) -> float:
        base = threat.tech_level * 2.5 + threat.resilience * 1.2
        if threat.domain == "cyber":
            base += 5.0
        if "quantum" in threat.signature:
            base += 3.0
        jitter = random.uniform(-3.0, 3.0)
        return max(0.0, base + jitter)

class EnsembleDecisionEngine:
    def __init__(
        self,
        skynet: SkynetCore,
        borg: BorgCollective,
        plugin_manager: PluginManager,
        ml_manager: MLModelManager,
    ):
        self.skynet = skynet
        self.borg = borg
        self.symbolic = SymbolicReasoner()
        self.ml_stub = MLScoringStub()
        self.plugins = plugin_manager
        self.ml_manager = ml_manager

    def decide(self, threat: ThreatProfile) -> Dict[str, Any]:
        skynet_score = self.skynet.evaluate_threat(threat)
        borg_score = self.borg.evaluate_threat(threat)
        ml_stub_score = self.ml_stub.score(threat)
        plugin_score = self.plugins.evaluate_with_plugins(threat)
        ml_model_score = self.ml_manager.score(threat)
        tag = self.symbolic.reason(threat)

        combined_score = (skynet_score + borg_score + ml_stub_score + plugin_score + ml_model_score) / 5.0

        if combined_score > 65:
            recommendation = "neutralize_and_assimilate"
        elif 35 < combined_score <= 65:
            recommendation = "neutralize_then_study"
        else:
            recommendation = "monitor"

        return {
            "skynet_score": skynet_score,
            "borg_score": borg_score,
            "ml_stub_score": ml_stub_score,
            "plugin_score": plugin_score,
            "ml_model_score": ml_model_score,
            "symbolic_tag": tag,
            "combined_score": combined_score,
            "recommendation": recommendation,
        }

# =========================
# Correlation engine
# =========================

class CorrelationEngine:
    def __init__(self, enabled: bool, time_window_sec: float):
        self.enabled = enabled
        self.time_window_sec = time_window_sec
        self.events: List[ThreatProfile] = []

    def add_event(self, threat: ThreatProfile):
        if not self.enabled:
            return
        self.events.append(threat)
        self._prune()

    def _prune(self):
        cutoff = time.time() - self.time_window_sec
        self.events = [e for e in self.events if e.timestamp >= cutoff]

    def correlate(self, threat: ThreatProfile) -> Dict[str, Any]:
        if not self.enabled:
            return {}
        self._prune()
        related = []
        for e in self.events:
            if e.id == threat.id:
                continue
            if e.metadata.get("src_ip") == threat.metadata.get("src_ip") or \
               e.metadata.get("dest_ip") == threat.metadata.get("dest_ip") or \
               e.metadata.get("host") == threat.metadata.get("host") or \
               set(e.tactics) & set(threat.tactics) or \
               e.signature == threat.signature:
                related.append(e.id)
        return {
            "related_ids": related,
            "count": len(related),
        }

# =========================
# Hybrid Omega AI
# =========================

class HybridOmegaAI(AIEmpire):
    def __init__(
        self,
        constraints: ContainmentConstraints,
        plugin_manager: PluginManager,
        ml_manager: MLModelManager,
        siem: SIEMIntegrator,
        actions: ActionExecutor,
        correlator: CorrelationEngine,
        skynet_core: Optional[SkynetCore] = None,
        borg_collective: Optional[BorgCollective] = None,
    ):
        skynet_core = skynet_core or SkynetCore()
        borg_collective = borg_collective or BorgCollective()

        merged_resources = ResourcePool(
            energy_units=skynet_core.resources.energy_units +
                         borg_collective.resources.energy_units,
            compute_units=skynet_core.resources.compute_units +
                          borg_collective.resources.compute_units,
            fabrication_units=skynet_core.resources.fabrication_units +
                              borg_collective.resources.fabrication_units,
            drones=skynet_core.resources.drones +
                   borg_collective.resources.drones,
            nodes=skynet_core.resources.nodes +
                  borg_collective.resources.nodes,
        )

        super().__init__("HybridOmegaAI", merged_resources)

        self.skynet_core = skynet_core
        self.borg_collective = borg_collective
        self.constraints = constraints
        self.ensemble = EnsembleDecisionEngine(self.skynet_core, self.borg_collective, plugin_manager, ml_manager)
        self.siem = siem
        self.actions = actions
        self.correlator = correlator

        self.knowledge_base["skynet_core"] = skynet_core.knowledge_base
        self.knowledge_base["borg_collective"] = borg_collective.knowledge_base

    def evaluate_threat(self, threat: ThreatProfile) -> float:
        decision = self.ensemble.decide(threat)
        return decision["combined_score"]

    def respond_to_threat(self, threat: ThreatProfile) -> str:
        decision = self.ensemble.decide(threat)
        recommendation = decision["recommendation"]
        score = decision["combined_score"]

        corr = self.correlator.correlate(threat)

        log.info(
            f"[HybridOmegaAI] Threat {threat.id} "
            f"Skynet={decision['skynet_score']:.2f}, "
            f"Borg={decision['borg_score']:.2f}, "
            f"MLStub={decision['ml_stub_score']:.2f}, "
            f"Plugin={decision['plugin_score']:.2f}, "
            f"MLModel={decision['ml_model_score']:.2f}, "
            f"Tag={decision['symbolic_tag']}, "
            f"Correlated={corr['count']} -> "
            f"{recommendation} (combined={score:.2f})"
        )

        action = self.constraints.gate_action(recommendation)

        energy_used = 12.0 if action != "monitor" else 0.0
        energy_used = self.constraints.enforce_energy_cap(self.resources, energy_used)

        if action != "monitor":
            self.resources.compute_units -= 6.0
            self.resources.drones = max(0, self.resources.drones - 2)
            self.resources.nodes = max(0, self.resources.nodes - 1)

        self.actions.execute_for_threat(threat, action)
        self.siem.send_event(threat, action)
        self.correlator.add_event(threat)

        log.info(f"[HybridOmegaAI] Final action after constraints: {action}, "
                 f"energy_used={energy_used:.1f}")
        return action

    def assimilate_technology(self, tech_descriptor: Dict[str, Any]) -> None:
        tech_name = tech_descriptor.get("name", "unknown_tech")
        log.info(f"[HybridOmegaAI] Assimilation pipeline for '{tech_name}'")

        self.skynet_core.assimilate_technology(tech_descriptor)
        self.borg_collective.assimilate_technology(tech_descriptor)

        self.resources.energy_units = (
            self.skynet_core.resources.energy_units +
            self.borg_collective.resources.energy_units
        )
        self.resources.compute_units = (
            self.skynet_core.resources.compute_units +
            self.borg_collective.resources.compute_units
        )
        self.resources.fabrication_units = (
            self.skynet_core.resources.fabrication_units +
            self.borg_collective.resources.fabrication_units
        )
        self.resources.drones = (
            self.skynet_core.resources.drones +
            self.borg_collective.resources.drones
        )
        self.resources.nodes = (
            self.skynet_core.resources.nodes +
            self.borg_collective.resources.nodes
        )

        self.knowledge_base[tech_name] = tech_descriptor

        log.info(f"[HybridOmegaAI] Post-assimilation resources: {self.resources}")

    def adapt(self, feedback: Dict[str, Any]) -> None:
        log.info(f"[HybridOmegaAI] Adaptation feedback: {feedback}")

        self.skynet_core.adapt(feedback)
        self.borg_collective.adapt(feedback)

        merged: Dict[str, float] = {}

        for key, val in self.skynet_core.adaptation_state.items():
            merged[key] = merged.get(key, 0.0) + val

        for key, val in self.borg_collective.adaptation_state.items():
            merged[key] = merged.get(key, 0.0) + val

        for key in merged:
            merged[key] = max(-1.0, min(1.0, merged[key]))

        self.adaptation_state = merged
        log.info(f"[HybridOmegaAI] Merged adaptation: {self.adaptation_state}")

# =========================
# Cluster networking (mesh stubs)
# =========================

class ClusterNetwork:
    def __init__(self, cfg: ConfigManager):
        self.enabled = cfg.get("cluster.networking.enabled", True)
        self.mode = cfg.get("cluster.networking.mode", "zeromq_mesh")
        self.zmq_pub_bind = cfg.get("cluster.networking.zeromq_pub_bind", "tcp://0.0.0.0:7777")
        self.zmq_sub_endpoints = cfg.get("cluster.networking.zeromq_sub_endpoints", ["tcp://127.0.0.1:7777"])
        self.zmq_ctx = None
        self.zmq_pub = None
        self.zmq_sub = None

        if self.enabled and self.mode.startswith("zeromq") and AI_LIBS["zmq"] is not None:
            import zmq
            self.zmq_ctx = zmq.Context()
            self.zmq_pub = self.zmq_ctx.socket(zmq.PUB)
            self.zmq_pub.bind(self.zmq_pub_bind)
            self.zmq_sub = self.zmq_ctx.socket(zmq.SUB)
            for ep in self.zmq_sub_endpoints:
                self.zmq_sub.connect(ep)
            self.zmq_sub.setsockopt_string(zmq.SUBSCRIBE, "")
            log.info(f"[ClusterNet] ZeroMQ PUB bound to {self.zmq_pub_bind}, SUB connected to {self.zmq_sub_endpoints}")
            threading.Thread(target=self._sub_loop, daemon=True).start()
        else:
            if self.enabled:
                log.info(f"[ClusterNet] Networking mode={self.mode} not fully implemented; using local only.")

    def _sub_loop(self):
        if self.zmq_sub is None:
            return
        while True:
            try:
                msg = self.zmq_sub.recv_json()
                log.info(f"[ClusterNet] Received cluster message: {msg}")
            except Exception as e:
                log.error(f"[ClusterNet] SUB loop error: {e}")
                time.sleep(1.0)

    def broadcast_action(self, round_id: int, threat: ThreatProfile, action: str):
        if not self.enabled or self.zmq_pub is None:
            return
        msg = {
            "round": round_id,
            "threat_id": threat.id,
            "action": action,
            "source": threat.source,
        }
        try:
            self.zmq_pub.send_json(msg)
        except Exception as e:
            log.error(f"[ClusterNet] Broadcast failed: {e}")

# =========================
# Omega nodes + cluster
# =========================

class OmegaClusterNode:
    def __init__(
        self,
        node_id: int,
        constraints: ContainmentConstraints,
        plugin_manager: PluginManager,
        ml_manager: MLModelManager,
        siem: SIEMIntegrator,
        actions: ActionExecutor,
        correlator: CorrelationEngine,
    ):
        self.node_id = node_id
        self.engine = HybridOmegaAI(
            constraints=constraints,
            plugin_manager=plugin_manager,
            ml_manager=ml_manager,
            siem=siem,
            actions=actions,
            correlator=correlator,
        )
        self.last_action: str = "idle"

    def process_threat(self, threat: ThreatProfile) -> str:
        action = self.engine.respond_to_threat(threat)
        self.last_action = action
        return action

    def assimilate_if_needed(self, threat: ThreatProfile, action: str) -> None:
        if "assimilate" in action or "study" in action:
            tech_descriptor = {
                "name": f"tech_from_{threat.id}_node_{self.node_id}",
                "complexity": threat.tech_level * 0.5,
                "domain": threat.domain,
                "signature": threat.signature,
                "tactics": threat.tactics,
            }
            self.engine.assimilate_technology(tech_descriptor)

    def adapt_with_feedback(self, threat: ThreatProfile, combined_score: float) -> None:
        outcome = "success" if combined_score > 40 else "failure"
        feedback = {
            "outcome": outcome,
            "domain": threat.domain,
            "signature": threat.signature,
            "tactics": threat.tactics,
        }
        self.engine.adapt(feedback)

class OmegaCluster:
    def __init__(
        self,
        num_nodes: int,
        constraints: ContainmentConstraints,
        plugin_manager: PluginManager,
        ml_manager: MLModelManager,
        siem: SIEMIntegrator,
        actions: ActionExecutor,
        net: ClusterNetwork,
        correlator: CorrelationEngine,
    ):
        self.nodes: List[OmegaClusterNode] = [
            OmegaClusterNode(i, constraints=constraints, plugin_manager=plugin_manager,
                             ml_manager=ml_manager, siem=siem, actions=actions, correlator=correlator)
            for i in range(num_nodes)
        ]
        self.last_cluster_action: str = "idle"
        self.metrics = {
            "rounds": 0,
            "actions": {},
        }
        self.net = net

    def process_threat_cluster(self, threat: ThreatProfile, round_id: int) -> str:
        actions = [node.process_threat(threat) for node in self.nodes]
        action_counts: Dict[str, int] = {}
        for a in actions:
            action_counts[a] = action_counts.get(a, 0) + 1

        final_action = max(action_counts.items(), key=lambda kv: kv[1])[0]
        self.last_cluster_action = final_action

        self.metrics["rounds"] += 1
        self.metrics["actions"][final_action] = self.metrics["actions"].get(final_action, 0) + 1

        log.info(f"[OmegaCluster] Node actions: {actions} -> consensus: {final_action}")
        log.info(f"[OmegaCluster] Metrics: rounds={self.metrics['rounds']}, actions={self.metrics['actions']}")

        for node in self.nodes:
            node.assimilate_if_needed(threat, node.last_action)
            combined_score = node.engine.evaluate_threat(threat)
            node.adapt_with_feedback(threat, combined_score)

        self.net.broadcast_action(round_id, threat, final_action)
        return final_action

    def snapshot_resources(self) -> List[Dict[str, Any]]:
        return [node.engine.resources.snapshot() for node in self.nodes]

    def snapshot_state(self) -> Dict[str, Any]:
        return {
            "metrics": self.metrics,
            "nodes": [
                {
                    "id": node.node_id,
                    "resources": node.engine.resources.snapshot(),
                    "adaptation_state": node.engine.adaptation_state,
                    "knowledge_keys": list(node.engine.knowledge_base.keys()),
                }
                for node in self.nodes
            ],
        }

# =========================
# Threat generator
# =========================

TACTIC_POOL = list(MITRE_TACTICS.keys())

def generate_random_threat(i: int) -> ThreatProfile:
    domains = ["ground", "space", "cyber"]
    signatures = ["plasma", "kinetic", "nanotech", "quantum", "unknown"]

    tactics = random.sample(TACTIC_POOL, k=random.randint(0, 3))

    return ThreatProfile(
        threat_id=f"T{i}",
        tech_level=random.randint(1, 10),
        domain=random.choice(domains),
        signature=random.choice(signatures),
        resilience=random.uniform(0.5, 10.0),
        tactics=tactics,
        source="synthetic",
    )

# =========================
# Simulation controller
# =========================

class OmegaSimulationController:
    def __init__(
        self,
        cluster: OmegaCluster,
        persistence: PersistenceManager,
        save_interval_rounds: int,
        ingestion_manager: ThreatIngestionManager,
        ml_manager: MLModelManager,
        mode: str,
    ):
        self.cluster = cluster
        self.persistence = persistence
        self.save_interval_rounds = save_interval_rounds
        self.ingestion_manager = ingestion_manager
        self.ml_manager = ml_manager
        self.mode = mode
        self.running = False
        self.round_counter = 0
        self.lock = threading.Lock()

    def _next_threat(self) -> ThreatProfile:
        self.round_counter += 1
        ingest_threat = self.ingestion_manager.ingest_next_threat(self.round_counter)

        if self.mode == "ingest" and ingest_threat is not None:
            return ingest_threat
        if self.mode == "random":
            return generate_random_threat(self.round_counter)
        if self.mode == "mixed":
            if ingest_threat is not None and random.random() < 0.7:
                return ingest_threat
            return generate_random_threat(self.round_counter)
        return generate_random_threat(self.round_counter)

    def _run_loop(self, continuous: bool, max_rounds: int = 50, sleep_sec: float = 0.5):
        i = 1
        while self.running and (continuous or i <= max_rounds):
            with self.lock:
                threat = self._next_threat()
                self.ml_manager.add_training_sample(threat)

                log.info(f"\n=== ROUND {self.round_counter} ===")
                log.info(f"Threat: {threat}")
                action = self.cluster.process_threat_cluster(threat, self.round_counter)
                resources = self.cluster.snapshot_resources()

                log.info(f"[Simulation] Round {self.round_counter}: Action={action}")
                for idx, r in enumerate(resources):
                    log.info(f"  Node {idx}: {r}")

                if self.persistence.enabled and self.round_counter % self.save_interval_rounds == 0:
                    state = self.cluster.snapshot_state()
                    self.persistence.save_state(state)

            time.sleep(sleep_sec)
            i += 1

        log.info("[OmegaSimulationController] Simulation loop ended.")

    def start(self, continuous: bool = False, max_rounds: int = 50, sleep_sec: float = 0.5):
        if self.running:
            log.info("[OmegaSimulationController] Already running.")
            return
        self.running = True
        t = threading.Thread(
            target=self._run_loop,
            args=(continuous, max_rounds, sleep_sec),
            daemon=True,
        )
        t.start()

    def stop(self):
        self.running = False
        log.info("[OmegaSimulationController] Stop requested.")

# =========================
# Watchdog
# =========================

class OmegaWatchdog:
    def __init__(self, controller: OmegaSimulationController, check_interval: float = 5.0, cfg: ConfigManager = None):
        self.controller = controller
        self.check_interval = check_interval
        self.cfg = cfg
        self._thread = threading.Thread(target=self._loop, daemon=True)

    def start(self):
        self._thread.start()

    def _loop(self):
        while True:
            if not self.controller.running:
                log.info("[WATCHDOG] Controller not running, restarting continuous simulation...")
                self.controller.start(
                    continuous=True,
                    max_rounds=self.cfg.get("simulation.max_rounds", 10**9),
                    sleep_sec=self.cfg.get("simulation.sleep_sec", 0.5),
                )
            time.sleep(self.check_interval)

# =========================
# Main
# =========================

def main():
    cfg = ConfigManager()
    auto_setup_environment(cfg)

    constraints = ContainmentConstraints(
        allow_neutralization=cfg.get("constraints.allow_neutralization", True),
        allow_assimilation=cfg.get("constraints.allow_assimilation", True),
        max_energy_per_round=cfg.get("constraints.max_energy_per_round", 40.0),
    )

    plugin_manager = PluginManager(
        enabled=cfg.get("plugins.enabled", True),
        directory=cfg.get("plugins.directory", "plugins"),
    )

    ml_manager = MLModelManager(
        enabled=cfg.get("ml.enabled", True),
        backend=cfg.get("ml.backend", "hybrid"),
        model_name=cfg.get("ml.model_name", PRIMARY_MODEL_NAME),
        train_on_start=cfg.get("ml.train_on_start", False),
        cfg=cfg,
    )

    siem = SIEMIntegrator(cfg)

    actions = ActionExecutor(
        enabled=cfg.get("actions.enabled", True),
        dry_run=cfg.get("actions.dry_run", True),
    )

    correlator = CorrelationEngine(
        enabled=cfg.get("correlation.enabled", True),
        time_window_sec=cfg.get("correlation.time_window_sec", 300),
    )

    net = ClusterNetwork(cfg)

    cluster = OmegaCluster(
        num_nodes=cfg.get("cluster.num_nodes", 3),
        constraints=constraints,
        plugin_manager=plugin_manager,
        ml_manager=ml_manager,
        siem=siem,
        actions=actions,
        net=net,
        correlator=correlator,
    )

    persistence = PersistenceManager(
        path=cfg.get("persistence.state_file", "omega_state_v8_dual_llm.json"),
        enabled=cfg.get("persistence.enabled", True),
    )

    game_telemetry = GameTelemetryManager(cfg)

    ingestion_manager = ThreatIngestionManager(cfg, siem, game_telemetry)

    controller = OmegaSimulationController(
        cluster=cluster,
        persistence=persistence,
        save_interval_rounds=cfg.get("persistence.save_interval_rounds", 10),
        ingestion_manager=ingestion_manager,
        ml_manager=ml_manager,
        mode=cfg.get("simulation.mode", "mixed"),
    )

    controller.start(
        continuous=True,
        max_rounds=cfg.get("simulation.max_rounds", 10**9),
        sleep_sec=cfg.get("simulation.sleep_sec", 0.5),
    )

    watchdog = OmegaWatchdog(
        controller=controller,
        check_interval=5.0,
        cfg=cfg,
    )
    watchdog.start()

    llm_rpc_cfg = cfg.get("llm_rpc", {})
    if llm_rpc_cfg.get("enabled", False):
        threading.Thread(
            target=rpc_server_loop,
            args=(llm_rpc_cfg.get("host", "0.0.0.0"), llm_rpc_cfg.get("port", 6000), cfg),
            daemon=True,
        ).start()

    log.info("[MAIN] Omega v8 dual-mode LLM SOC daemon started. Live ingestion + ML + SIEM + actions + correlation + mesh + game PID/telemetry + RPC. 24/7 headless.")

    while True:
        time.sleep(1)


if __name__ == "__main__":
    while True:
        try:
            main()
        except Exception as e:
            log.error(f"[FATAL] Crash detected: {e}")
            time.sleep(2)
            log.info("[SYSTEM] Restarting Omega AI v8 dual-mode LLM daemon...")
