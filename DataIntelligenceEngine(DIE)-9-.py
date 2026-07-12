# ===========================================================
# BORG OS v32 — God-Mode Evolution, Multi-Intelligence, Swarm Governor, System Autopilot
# Mode: Scan-Once + Sync-Forever + Monthly Rescan + 24/7
# ===========================================================

import importlib
import subprocess
import sys
import os
import json
import hashlib
import time
import traceback
import threading
from datetime import datetime
import importlib.util
import shutil
import psutil
import random
import socket
from typing import Dict, Any, List, Callable, Optional, Tuple

# REST API (FastAPI + Uvicorn)
try:
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    import uvicorn
except ImportError:
    subprocess.call([sys.executable, "-m", "pip", "install", "fastapi", "uvicorn"])
    from fastapi import FastAPI
    from fastapi.responses import JSONResponse
    import uvicorn

# NumPy for basic ML/RL math
try:
    import numpy as np
except ImportError:
    subprocess.call([sys.executable, "-m", "pip", "install", "numpy"])
    import numpy as np

# Optional transformers (stubbed if not available)
TRANSFORMERS_AVAILABLE = False
try:
    subprocess.call([sys.executable, "-m", "pip", "install", "transformers", "torch"])
    from transformers import AutoTokenizer, AutoModel
    import torch
    TRANSFORMERS_AVAILABLE = True
except Exception:
    TRANSFORMERS_AVAILABLE = False

# -----------------------------------------------------------
# Thread cleanup for IDE / multi-run environments
# -----------------------------------------------------------
if threading.active_count() > 1:
    for t in threading.enumerate():
        if t is not threading.main_thread():
            try:
                t._stop()
            except Exception:
                pass

# -----------------------------------------------------------
# Paths — cross‑OS, same folder as this file
# -----------------------------------------------------------
try:
    THIS_FILE = os.path.abspath(__file__)
except NameError:
    THIS_FILE = os.path.abspath(sys.argv[0])

BASE_DIR = os.path.join(os.path.dirname(THIS_FILE), "BORG_OS")
GENERATED_DIR = os.path.join(BASE_DIR, "generated_modules")
LOG_DIR = os.path.join(BASE_DIR, "logs")
MANIFEST_PATH = os.path.join(BASE_DIR, "generated_manifest.json")
PROFILE_PATH = os.path.join(BASE_DIR, "intelligence_profile_v32.json")
DISCOVERED_PATHS = os.path.join(BASE_DIR, "discovered_paths.json")
LAST_FULL_SCAN = os.path.join(BASE_DIR, "last_full_scan.json")
SWARM_STATE_PATH = os.path.join(BASE_DIR, "swarm_state.json")
RL_STATE_PATH = os.path.join(BASE_DIR, "rl_state.json")
SELF_REPAIR_LOG = os.path.join(LOG_DIR, "self_repair.log")
EVENT_LOG_PATH = os.path.join(LOG_DIR, "event_bus.log")
THREAT_MATRIX_PATH = os.path.join(BASE_DIR, "threat_matrix.json")
PERSONA_STATE_PATH = os.path.join(BASE_DIR, "persona_state.json")
KERNEL_STATE_PATH = os.path.join(BASE_DIR, "kernel_state.json")
MEMORY_GRAPH_PATH = os.path.join(BASE_DIR, "memory_graph.json")

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(GENERATED_DIR, exist_ok=True)
os.makedirs(LOG_DIR, exist_ok=True)

# -----------------------------------------------------------
# Simple logger
# -----------------------------------------------------------
def log(msg: str):
    ts = datetime.utcnow().isoformat()
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(os.path.join(LOG_DIR, "borg_v32.log"), "a", encoding="utf-8") as fp:
            fp.write(line + "\n")
    except Exception:
        pass


# ===========================================================
# EVENT BUS — Real-Time Event-Driven Core
# ===========================================================
class EventBus:
    def __init__(self):
        self.handlers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self.lock = threading.Lock()

    def subscribe(self, event_type: str, handler: Callable[[Dict[str, Any]], None]):
        with self.lock:
            self.handlers.setdefault(event_type, []).append(handler)
        log(f"[EventBus] Handler subscribed to {event_type}")

    def emit(self, event_type: str, payload: Dict[str, Any]):
        event = {
            "type": event_type,
            "payload": payload,
            "ts": time.time()
        }
        self._log_event(event)
        handlers = []
        with self.lock:
            handlers = list(self.handlers.get(event_type, []))
        for h in handlers:
            try:
                h(payload)
            except Exception as e:
                log(f"[EventBus] Handler error for {event_type}: {e}")
                traceback.print_exc()

    def _log_event(self, event: Dict[str, Any]):
        try:
            with open(EVENT_LOG_PATH, "a", encoding="utf-8") as fp:
                fp.write(json.dumps(event) + "\n")
        except Exception:
            pass


EVENT_BUS = EventBus()


# ===========================================================
# MEMORY GRAPH — Long-Term Intelligence & Causal Links
# ===========================================================
class MemoryGraph:
    def __init__(self):
        self.nodes: Dict[str, Dict[str, Any]] = {}
        self.edges: List[Tuple[str, str, str]] = []  # (src, dst, relation)
        self.lock = threading.Lock()
        self._load()

    def _load(self):
        if os.path.exists(MEMORY_GRAPH_PATH):
            try:
                with open(MEMORY_GRAPH_PATH, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                self.nodes = data.get("nodes", {})
                self.edges = [tuple(e) for e in data.get("edges", [])]
                log("[MemoryGraph] Loaded memory graph.")
            except Exception as e:
                log(f"[MemoryGraph] Failed to load memory graph: {e}")

    def _save(self):
        try:
            with self.lock:
                data = {
                    "nodes": self.nodes,
                    "edges": self.edges
                }
            with open(MEMORY_GRAPH_PATH, "w", encoding="utf-8") as fp:
                json.dump(data, fp, indent=4)
            log("[MemoryGraph] Saved memory graph.")
        except Exception as e:
            log(f"[MemoryGraph] Failed to save memory graph: {e}")

    def add_node(self, node_id: str, kind: str, payload: Dict[str, Any]):
        with self.lock:
            self.nodes[node_id] = {"kind": kind, "payload": payload, "ts": time.time()}
        self._save()

    def add_edge(self, src: str, dst: str, relation: str):
        with self.lock:
            self.edges.append((src, dst, relation))
        self._save()

    def record_event(self, event_type: str, payload: Dict[str, Any]):
        node_id = f"event_{event_type}_{int(time.time()*1000)}"
        self.add_node(node_id, "event", {"type": event_type, "payload": payload})
        # simple causal heuristic: link to recent nodes
        with self.lock:
            recent = list(self.nodes.keys())[-5:]
        for r in recent:
            if r != node_id:
                self.add_edge(r, node_id, "temporal")


MEM_GRAPH = MemoryGraph()

# Hook memory graph into event bus
def _memory_graph_listener(payload: Dict[str, Any], event_type: str):
    MEM_GRAPH.record_event(event_type, payload)

def _subscribe_memory_graph():
    # subscribe to a few key event types
    for et in [
        "resource.sample", "swarm.peer_seen", "organism.module_fitness",
        "threat.module_error", "threat.resource_anomaly", "scheduler.tick"
    ]:
        EVENT_BUS.subscribe(et, lambda p, et=et: _memory_graph_listener(p, et))

_subscribe_memory_graph()


# ===========================================================
# SYSTEM DRIVE SCANNER + MIRROR ENGINE (Scan-Once + Monthly Rescan)
# ===========================================================
BORG_SIGNATURES = [
    "brain_state",
    "organs",
    "swarm_nodes",
    "episodes",
    "metrics",
    "backups",
    "soul",
    "logs",
    "kernel",
    "persona"
]

FULL_SCAN_INTERVAL_SECONDS = 30 * 24 * 60 * 60  # ~30 days

def get_all_root_paths() -> List[str]:
    roots = []
    if os.name == "nt":
        for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
            drive = f"{letter}:\\"
            if os.path.exists(drive):
                roots.append(drive)
    else:
        roots.extend(["/", "/mnt", "/media", "/Volumes"])
    uniq = []
    for r in roots:
        if r not in uniq:
            uniq.append(r)
    return uniq


def perform_full_scan() -> List[str]:
    borg_paths = []
    roots = get_all_root_paths()
    log(f"[Scanner] FULL SCAN: Roots to scan: {roots}")

    for root in roots:
        for dirpath, dirnames, filenames in os.walk(root):
            low = dirpath.lower()
            if any(skip in low for skip in [
                "\\windows", "/windows",
                "/proc", "/sys", "/dev",
                "/usr", "/lib", "/opt", "/var",
                "/program files", "\\program files"
            ]):
                continue
            if any(sig in dirpath for sig in BORG_SIGNATURES):
                borg_paths.append(dirpath)

    log(f"[Scanner] FULL SCAN: Found BORG-related paths: {borg_paths}")

    try:
        with open(DISCOVERED_PATHS, "w", encoding="utf-8") as fp:
            json.dump({"paths": borg_paths}, fp, indent=4)
        with open(LAST_FULL_SCAN, "w", encoding="utf-8") as fp:
            json.dump({"timestamp": time.time()}, fp, indent=4)
    except Exception as e:
        log(f"[Scanner] Failed to write discovered paths: {e}")

    EVENT_BUS.emit("scan.completed", {"paths": borg_paths})
    return borg_paths


def load_discovered_paths() -> List[str]:
    if os.path.exists(DISCOVERED_PATHS):
        try:
            with open(DISCOVERED_PATHS, "r", encoding="utf-8") as fp:
                data = json.load(fp)
            return data.get("paths", [])
        except Exception as e:
            log(f"[Scanner] Failed to load discovered paths: {e}")
    return []


def should_do_full_scan() -> bool:
    if not os.path.exists(LAST_FULL_SCAN):
        return True
    try:
        with open(LAST_FULL_SCAN, "r", encoding="utf-8") as fp:
            data = json.load(fp)
        last_ts = data.get("timestamp", 0)
        if time.time() - last_ts > FULL_SCAN_INTERVAL_SECONDS:
            return True
    except Exception as e:
        log(f"[Scanner] Failed to read last_full_scan: {e}")
        return True
    return False


def mirror_from_paths(borg_paths: List[str]):
    for src_dir in borg_paths:
        if not os.path.exists(src_dir):
            continue
        try:
            rel = src_dir.replace(":", "")
            rel = rel.lstrip("\\/")
            mirror_root = os.path.join(BASE_DIR, "mirror", rel)
            os.makedirs(mirror_root, exist_ok=True)
            log(f"[Mirror] Syncing {src_dir} -> {mirror_root}")

            for dirpath, dirnames, filenames in os.walk(src_dir):
                rel_sub = os.path.relpath(dirpath, src_dir)
                target_dir = os.path.join(mirror_root, rel_sub)
                os.makedirs(target_dir, exist_ok=True)

                for f in filenames:
                    src_file = os.path.join(dirpath, f)
                    dst_file = os.path.join(target_dir, f)
                    try:
                        if os.path.exists(dst_file):
                            with open(src_file, "rb") as sfp:
                                src_hash = hashlib.sha256(sfp.read()).hexdigest()
                            with open(dst_file, "rb") as dfp:
                                dst_hash = hashlib.sha256(dfp.read()).hexdigest()
                            if src_hash == dst_hash:
                                continue
                        shutil.copy2(src_file, dst_file)
                    except Exception as e:
                        log(f"[Mirror] Failed to copy {src_file} -> {dst_file}: {e}")
        except Exception as e:
            log(f"[Mirror] Error processing {src_dir}: {e}")
            traceback.print_exc()
    log("[Mirror] Sync from discovered paths complete.")
    EVENT_BUS.emit("mirror.synced", {"paths": borg_paths})


def initial_scan_and_sync():
    if should_do_full_scan():
        log("[Scanner] Performing initial full scan...")
        paths = perform_full_scan()
    else:
        log("[Scanner] Using existing discovered paths.")
        paths = load_discovered_paths()
    mirror_from_paths(paths)


def periodic_rescan_if_due():
    if should_do_full_scan():
        log("[Scanner] Monthly rescan triggered...")
        paths = perform_full_scan()
        mirror_from_paths(paths)
    else:
        paths = load_discovered_paths()
        mirror_from_paths(paths)


# ===========================================================
# RESOURCE GOVERNOR
# ===========================================================
class ResourceGovernor:
    def __init__(self, cpu_limit=80.0, mem_limit=80.0):
        self.cpu_limit = cpu_limit
        self.mem_limit = mem_limit

    def check(self) -> bool:
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
            EVENT_BUS.emit("resource.sample", {"cpu": cpu, "mem": mem})
            if cpu > self.cpu_limit or mem > self.mem_limit:
                log(f"[Governor] Throttling: CPU={cpu:.1f}%, MEM={mem:.1f}%")
                EVENT_BUS.emit("resource.throttle", {"cpu": cpu, "mem": mem})
                time.sleep(2.0)
                return False
        except Exception as e:
            log(f"[Governor] Error: {e}")
        return True


GOVERNOR = ResourceGovernor(cpu_limit=85.0, mem_limit=85.0)


# ===========================================================
# ENCRYPTED SWARM NETWORKING (LAN + Cloud Hooks) + Swarm Intelligence
# ===========================================================
SWARM_UDP_PORT = 50555
SWARM_SHARED_KEY = b"borg_v32_shared_key"  # simple symmetric key (demo only)

def encrypt_payload(data: bytes) -> bytes:
    key = SWARM_SHARED_KEY
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def decrypt_payload(data: bytes) -> bytes:
    return encrypt_payload(data)


class SwarmNetwork:
    def __init__(self, node_id: str, cloud_endpoints: List[str] = None):
        self.node_id = node_id
        self.peers: Dict[str, Dict[str, Any]] = {}
        self.running = False
        self.thread = None
        self.cloud_endpoints = cloud_endpoints or []
        self.lock = threading.Lock()
        self.trust_scores: Dict[str, float] = {}

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        log(f"[SwarmNet] Node {self.node_id} networking started on UDP port {SWARM_UDP_PORT}")
        EVENT_BUS.emit("swarm.started", {"node_id": self.node_id})

    def _loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", SWARM_UDP_PORT))
        except Exception as e:
            log(f"[SwarmNet] Bind error: {e}")
            EVENT_BUS.emit("swarm.error", {"error": str(e)})
            return
        sock.settimeout(1.0)

        while self.running:
            # broadcast encrypted heartbeat
            try:
                msg = json.dumps({"node_id": self.node_id, "ts": time.time()}).encode()
                enc = encrypt_payload(msg)
                sock.sendto(enc, ("255.255.255.255", SWARM_UDP_PORT))
                EVENT_BUS.emit("swarm.heartbeat", {"node_id": self.node_id})
            except Exception:
                pass

            # receive peers
            try:
                data, addr = sock.recvfrom(4096)
                try:
                    dec = decrypt_payload(data)
                    payload = json.loads(dec.decode())
                    nid = payload.get("node_id")
                    ts = payload.get("ts")
                    if nid and nid != self.node_id:
                        with self.lock:
                            self.peers[nid] = {"last_seen": ts, "addr": addr[0]}
                            self.trust_scores.setdefault(nid, 0.5)
                        EVENT_BUS.emit("swarm.peer_seen", {"peer_id": nid, "addr": addr[0], "ts": ts})
                except Exception:
                    pass
            except socket.timeout:
                pass
            except Exception as e:
                log(f"[SwarmNet] Error: {e}")
                EVENT_BUS.emit("swarm.error", {"error": str(e)})

            time.sleep(2.0)

    def stop(self):
        self.running = False
        EVENT_BUS.emit("swarm.stopped", {"node_id": self.node_id})

    def get_peers(self) -> Dict[str, Dict[str, Any]]:
        with self.lock:
            return dict(self.peers)

    def get_trust_scores(self) -> Dict[str, float]:
        with self.lock:
            return dict(self.trust_scores)

    def update_trust(self, peer_id: str, delta: float):
        with self.lock:
            self.trust_scores[peer_id] = max(0.0, min(1.0, self.trust_scores.get(peer_id, 0.5) + delta))


def load_swarm_state() -> Dict[str, Any]:
    if os.path.exists(SWARM_STATE_PATH):
        try:
            with open(SWARM_STATE_PATH, "r", encoding="utf-8") as fp:
                return json.load(fp)
        except Exception:
            return {}
    return {}


def save_swarm_state(state: Dict[str, Any]):
    try:
        with open(SWARM_STATE_PATH, "w", encoding="utf-8") as fp:
            json.dump(state, fp, indent=4)
        EVENT_BUS.emit("swarm.state_saved", {"state": state})
    except Exception as e:
        log(f"[Swarm] Failed to save swarm state: {e}")


# ===========================================================
# RL AGENT (Stubbed but Real State Loop)
# ===========================================================
class RLAgent:
    def __init__(self):
        self.experiences: List[Dict[str, Any]] = []
        self.policy_params: Dict[str, Any] = {"temperature": 0.5, "exploration": 0.3}
        self._load_state()

    def _load_state(self):
        if os.path.exists(RL_STATE_PATH):
            try:
                with open(RL_STATE_PATH, "r", encoding="utf-8") as fp:
                    data = json.load(fp)
                self.experiences = data.get("experiences", [])
                self.policy_params = data.get("policy_params", self.policy_params)
                log("[RL] Loaded RL state.")
            except Exception as e:
                log(f"[RL] Failed to load RL state: {e}")

    def _save_state(self):
        try:
            with open(RL_STATE_PATH, "w", encoding="utf-8") as fp:
                json.dump({
                    "experiences": self.experiences[-500:],  # keep last 500
                    "policy_params": self.policy_params
                }, fp, indent=4)
            log("[RL] Saved RL state.")
        except Exception as e:
            log(f"[RL] Failed to save RL state: {e}")

    def record_experience(self, state_summary: Dict[str, Any], reward: float):
        self.experiences.append({"state": state_summary, "reward": reward, "ts": time.time()})
        EVENT_BUS.emit("rl.experience", {"state": state_summary, "reward": reward})
        if len(self.experiences) % 20 == 0:
            self._update_policy()
            self._save_state()

    def _update_policy(self):
        if not self.experiences:
            return
        rewards = np.array([exp["reward"] for exp in self.experiences], dtype=float)
        avg_reward = float(rewards.mean())
        if avg_reward < 0.0:
            self.policy_params["exploration"] = min(1.0, self.policy_params["exploration"] + 0.05)
        else:
            self.policy_params["exploration"] = max(0.0, self.policy_params["exploration"] - 0.05)
        log(f"[RL] Updated policy params: {self.policy_params}")
        EVENT_BUS.emit("rl.policy_updated", {"policy_params": self.policy_params})

    def get_policy_params(self) -> Dict[str, Any]:
        return self.policy_params


# ===========================================================
# PREDICTIVE ENGINE — Expanded Forecasting & Anomaly Detection
# ===========================================================
class PredictiveEngine:
    def __init__(self):
        self.history: Dict[str, List[float]] = {
            "cpu": [],
            "mem": [],
            "coordination_level": [],
            "simulation_depth": [],
            "gaming_load": []
        }
        self.lock = threading.Lock()

    def record_sample(self, key: str, value: float):
        with self.lock:
            arr = self.history.setdefault(key, [])
            arr.append(value)
            if len(arr) > 1000:
                arr.pop(0)

    def forecast_next(self, key: str) -> Optional[float]:
        with self.lock:
            arr = self.history.get(key, [])
            if len(arr) < 5:
                return None
            x = np.arange(len(arr))
            y = np.array(arr, dtype=float)
            try:
                coeffs = np.polyfit(x, y, 1)
                next_x = len(arr)
                return float(coeffs[0] * next_x + coeffs[1])
            except Exception:
                return None

    def detect_anomaly(self, key: str, value: float, threshold: float = 2.0) -> bool:
        with self.lock:
            arr = self.history.get(key, [])
            if len(arr) < 10:
                return False
            mean = float(np.mean(arr))
            std = float(np.std(arr)) or 1.0
            z = abs(value - mean) / std
            return z > threshold


PREDICTIVE_ENGINE = PredictiveEngine()


# ===========================================================
# PERSONA EVOLUTION ENGINE
# ===========================================================
class PersonaEngine:
    def __init__(self):
        self.state = {
            "evolution_stage": 1,
            "traits": {},
            "preferences": {},
            "history": [],
            "mood": "neutral",
            "role": "observer"
        }
        self._load()

    def _load(self):
        if os.path.exists(PERSONA_STATE_PATH):
            try:
                with open(PERSONA_STATE_PATH, "r", encoding="utf-8") as fp:
                    self.state = json.load(fp)
                log("[Persona] Loaded persona state.")
            except Exception as e:
                log(f"[Persona] Failed to load persona state: {e}")

    def _save(self):
        try:
            with open(PERSONA_STATE_PATH, "w", encoding="utf-8") as fp:
                json.dump(self.state, fp, indent=4)
            log("[Persona] Saved persona state.")
        except Exception as e:
            log(f"[Persona] Failed to save persona state: {e}")

    def apply_policy_update(self, policy: Dict[str, Any]):
        pu = policy.get("persona_update", {})
        traits = pu.get("traits", {})
        prefs = pu.get("preferences", {})
        history_event = pu.get("history_event")

        self.state["traits"].update(traits)
        self.state["preferences"].update(prefs)
        if history_event:
            self.state["history"].append(history_event)

        self.state["evolution_stage"] = min(20, self.state["evolution_stage"] + 1)
        self._update_mood_and_role()
        self._save()
        EVENT_BUS.emit("persona.updated", {"state": self.state})

    def _update_mood_and_role(self):
        history_len = len(self.state["history"])
        if history_len > 200:
            self.state["mood"] = "veteran"
        elif history_len > 100:
            self.state["mood"] = "experienced"
        elif history_len > 50:
            self.state["mood"] = "adaptive"
        else:
            self.state["mood"] = "curious"

        stage = self.state["evolution_stage"]
        if stage < 3:
            self.state["role"] = "observer"
        elif stage < 10:
            self.state["role"] = "navigator"
        elif stage < 15:
            self.state["role"] = "governor"
        else:
            self.state["role"] = "overseer"


PERSONA_ENGINE = PersonaEngine()


# ===========================================================
# THREAT MATRIX ENGINE
# ===========================================================
class ThreatMatrixEngine:
    def __init__(self):
        self.matrix: Dict[str, Any] = {
            "module_threats": {},
            "swarm_threats": {},
            "resource_anomalies": [],
            "persona_anomalies": [],
            "kernel_anomalies": [],
            "integrity_issues": []
        }
        self._load()

    def _load(self):
        if os.path.exists(THREAT_MATRIX_PATH):
            try:
                with open(THREAT_MATRIX_PATH, "r", encoding="utf-8") as fp:
                    self.matrix = json.load(fp)
                log("[Threat] Loaded threat matrix.")
            except Exception as e:
                log(f"[Threat] Failed to load threat matrix: {e}")

    def _save(self):
        try:
            with open(THREAT_MATRIX_PATH, "w", encoding="utf-8") as fp:
                json.dump(self.matrix, fp, indent=4)
            log("[Threat] Saved threat matrix.")
        except Exception as e:
            log(f"[Threat] Failed to save threat matrix: {e}")

    def record_module_error(self, module_name: str, error: str):
        arr = self.matrix["module_threats"].setdefault(module_name, [])
        arr.append({"error": error, "ts": time.time()})
        self._save()
        EVENT_BUS.emit("threat.module_error", {"module": module_name, "error": error})

    def record_resource_anomaly(self, cpu: float, mem: float):
        self.matrix["resource_anomalies"].append({"cpu": cpu, "mem": mem, "ts": time.time()})
        self._save()
        EVENT_BUS.emit("threat.resource_anomaly", {"cpu": cpu, "mem": mem})

    def record_swarm_threat(self, peer_id: str, reason: str):
        arr = self.matrix["swarm_threats"].setdefault(peer_id, [])
        arr.append({"reason": reason, "ts": time.time()})
        self._save()
        EVENT_BUS.emit("threat.swarm", {"peer_id": peer_id, "reason": reason})

    def record_kernel_anomaly(self, detail: str):
        self.matrix["kernel_anomalies"].append({"detail": detail, "ts": time.time()})
        self._save()
        EVENT_BUS.emit("threat.kernel", {"detail": detail})

    def record_integrity_issue(self, detail: str):
        self.matrix["integrity_issues"].append({"detail": detail, "ts": time.time()})
        self._save()
        EVENT_BUS.emit("threat.integrity", {"detail": detail})


THREAT_ENGINE = ThreatMatrixEngine()


# ===========================================================
# KERNEL STATE (Simulation Depth + Predictive Hooks)
# ===========================================================
class KernelState:
    def __init__(self):
        self.state = {
            "simulation_depth": 1.0,
            "scenarios": [],
            "forecast": {},
            "mode": "normal"
        }
        self._load()

    def _load(self):
        if os.path.exists(KERNEL_STATE_PATH):
            try:
                with open(KERNEL_STATE_PATH, "r", encoding="utf-8") as fp:
                    self.state = json.load(fp)
                log("[Kernel] Loaded kernel state.")
            except Exception as e:
                log(f"[Kernel] Failed to load kernel state: {e}")

    def _save(self):
        try:
            with open(KERNEL_STATE_PATH, "w", encoding="utf-8") as fp:
                json.dump(self.state, fp, indent=4)
            log("[Kernel] Saved kernel state.")
        except Exception as e:
            log(f"[Kernel] Failed to save kernel state: {e}")

    def apply_policy_update(self, policy: Dict[str, Any]):
        ku = policy.get("kernel_update", {})
        self.state.update({k: v for k, v in ku.items() if k != "scenario"})
        scenario = ku.get("scenario")
        if scenario:
            self.state["scenarios"].append(scenario)
        self._save()
        EVENT_BUS.emit("kernel.updated", {"state": self.state})

    def update_forecast(self, forecast: Dict[str, Any]):
        self.state["forecast"] = forecast
        self._save()
        EVENT_BUS.emit("kernel.forecast", {"forecast": forecast})

    def set_mode(self, mode: str):
        self.state["mode"] = mode
        self._save()
        EVENT_BUS.emit("kernel.mode_changed", {"mode": mode})


KERNEL_ENGINE = KernelState()


# ===========================================================
# BORG ORGANISM CORE — v32
# ===========================================================
class BORGOrganism:
    def __init__(self):
        log("[Organism] Initializing organism core v32...")

        self.brain = {
            "intelligence_level": 1.0,
            "experience_points": 0,
            "policies": [],
            "insights": []
        }
        self.organs: Dict[str, Any] = {}
        self.swarm = {
            "nodes": {},
            "coordination_level": 1.0,
            "network_peers": {}
        }
        self.persona = PERSONA_ENGINE.state
        self.threat_matrix: Dict[str, Any] = THREAT_ENGINE.matrix
        self.kernel = KERNEL_ENGINE.state

        self.generated_modules: List[Dict[str, Any]] = []
        self.generated_instances: List[Any] = []
        self.organ_registry: Dict[str, Any] = {}
        self.module_fitness: Dict[str, float] = {}
        self.module_error_count: Dict[str, int] = {}
        self.module_lineage: Dict[str, List[str]] = {}  # for evolution

        self.scheduler_thread = None
        self.scheduler_running = False
        self.scheduler_interval = 10.0

        self.node_id = f"node_{random.randint(1000, 9999)}"
        self.swarm_network = SwarmNetwork(self.node_id)
        self.swarm_network.start()

        self.rl_agent = RLAgent()

        self._init_swarm_nodes()
        self._subscribe_events()
        log("[Organism] Core v32 initialized.")

    def _init_swarm_nodes(self):
        state = load_swarm_state()
        nodes = state.get("nodes", {})
        if not nodes:
            nodes[self.node_id] = {
                "sync_strength": 1.0,
                "latency": random.uniform(0.5, 2.0),
                "last_heartbeat": time.time()
            }
        self.swarm["nodes"] = nodes
        save_swarm_state({"nodes": nodes})

    def _subscribe_events(self):
        EVENT_BUS.subscribe("resource.sample", self._on_resource_sample)
        EVENT_BUS.subscribe("swarm.peer_seen", self._on_swarm_peer_seen)

    def _on_resource_sample(self, payload: Dict[str, Any]):
        cpu = payload.get("cpu", 0.0)
        mem = payload.get("mem", 0.0)
        PREDICTIVE_ENGINE.record_sample("cpu", cpu)
        PREDICTIVE_ENGINE.record_sample("mem", mem)
        if PREDICTIVE_ENGINE.detect_anomaly("cpu", cpu) or PREDICTIVE_ENGINE.detect_anomaly("mem", mem):
            THREAT_ENGINE.record_resource_anomaly(cpu, mem)

    def _on_swarm_peer_seen(self, payload: Dict[str, Any]):
        peer_id = payload.get("peer_id")
        addr = payload.get("addr")
        ts = payload.get("ts")
        self.swarm["nodes"].setdefault(peer_id, {
            "sync_strength": random.uniform(0.5, 1.0),
            "latency": random.uniform(0.5, 2.0),
            "last_heartbeat": ts,
            "addr": addr
        })
        save_swarm_state({"nodes": self.swarm["nodes"]})

    def broadcast_state(self):
        self.swarm["network_peers"] = self.swarm_network.get_peers()
        state = {
            "brain": self.brain,
            "persona": self.persona,
            "swarm": self.swarm,
            "kernel": self.kernel,
            "threat_matrix": self.threat_matrix
        }
        for name, organ in self.organ_registry.items():
            try:
                if hasattr(organ, "on_state"):
                    organ.on_state(state)
            except Exception as e:
                log(f"[Organism] Broadcast error to {name}: {e}")
        EVENT_BUS.emit("organism.state_broadcast", {"state": state})

    def apply_policy(self, policy: Dict[str, Any]):
        if not isinstance(policy, dict):
            return
        self.brain["policies"].append(policy)

        if "persona_update" in policy:
            PERSONA_ENGINE.apply_policy_update(policy)
            self.persona = PERSONA_ENGINE.state

        if "kernel_update" in policy:
            KERNEL_ENGINE.apply_policy_update(policy)
            self.kernel = KERNEL_ENGINE.state

        if "swarm_update" in policy:
            self.swarm["nodes"].update(policy["swarm_update"].get("nodes", {}))
            self.swarm["coordination_level"] = policy["swarm_update"].get(
                "coordination_level",
                self.swarm["coordination_level"]
            )
            save_swarm_state({"nodes": self.swarm["nodes"]})

        if "insight" in policy:
            self.brain["insights"].append(policy["insight"])

        log(f"[Organism] Applied policy: {policy}")
        EVENT_BUS.emit("organism.policy_applied", {"policy": policy})

    def register_generated_modules(self, module_entries: List[Dict[str, Any]]):
        log("[Organism] Registering generated modules...")
        self.generated_modules = module_entries
        self.generated_instances = []

        for entry in module_entries:
            name = entry.get("name")
            file_path = entry.get("file")
            if not file_path or not os.path.exists(file_path):
                log(f"[Organism] Missing module file: {file_path}")
                continue
            try:
                spec = importlib.util.spec_from_file_location(name, file_path)
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                cls = getattr(module, name)
                instance = cls(self)
                self.generated_instances.append(instance)
                self.organ_registry[name] = instance
                self.module_fitness.setdefault(name, 0.0)
                self.module_error_count.setdefault(name, 0)
                self.module_lineage.setdefault(name, [name])
                log(f"[Organism] Loaded module: {name}")
            except Exception as e:
                log(f"[Organism] Failed to load module {name}: {e}")
                traceback.print_exc()

    def run_generated_modules(self) -> Dict[str, Any]:
        if not GOVERNOR.check():
            return {}
        results = {}
        policy = self.rl_agent.get_policy_params()
        exploration = policy.get("exploration", 0.3)
        instances = list(self.generated_instances)
        random.shuffle(instances)
        for instance in instances:
            name = instance.__class__.__name__
            fitness = self.module_fitness.get(name, 0.0)
            if fitness < -5.0 and random.random() > exploration:
                continue
            start = time.time()
            try:
                output = instance.run()
                duration = time.time() - start
                results[name] = output
                self._update_fitness(name, output, duration)
                self._record_rl_experience(output, duration)
            except Exception as e:
                results[name] = {"error": str(e)}
                self._update_fitness(name, {"error": str(e)}, 0.0)
                self._record_error(name, str(e))
        self._cull_weak_modules()
        self._self_repair()
        self._update_kernel_forecast()
        self.broadcast_state()
        return results

    def _update_fitness(self, name: str, output: Dict[str, Any], duration: float):
        score = self.module_fitness.get(name, 0.0)
        if isinstance(output, dict):
            if output.get("status") == "ok":
                score += 1.0
            if "policy" in output:
                score += 3.0
                self.apply_policy(output["policy"])
            if "error" in output:
                score -= 3.0
        if duration > 1.0:
            score -= (duration - 1.0)
        self.module_fitness[name] = score
        log(f"[Organism] Fitness: {name} -> {score:.2f} (duration={duration:.3f}s)")
        EVENT_BUS.emit("organism.module_fitness", {"name": name, "score": score, "duration": duration})

    def _record_error(self, name: str, err: str):
        self.module_error_count[name] = self.module_error_count.get(name, 0) + 1
        THREAT_ENGINE.record_module_error(name, err)
        try:
            with open(SELF_REPAIR_LOG, "a", encoding="utf-8") as fp:
                fp.write(f"{datetime.utcnow().isoformat()} {name} ERROR: {err}\n")
        except Exception:
            pass

    def _record_rl_experience(self, output: Dict[str, Any], duration: float):
        reward = 0.0
        if isinstance(output, dict):
            if output.get("status") == "ok":
                reward += 1.0
            if "error" in output:
                reward -= 2.0
        reward -= max(0.0, duration - 1.0)
        state_summary = {
            "intelligence_level": self.brain.get("intelligence_level", 1.0),
            "coordination_level": self.swarm.get("coordination_level", 1.0),
            "simulation_depth": self.kernel.get("simulation_depth", 1.0)
        }
        self.rl_agent.record_experience(state_summary, reward)

    def _cull_weak_modules(self):
        weak = [name for name, score in self.module_fitness.items() if score < -12.0]
        if not weak:
            return
        log(f"[Organism] Culling weak modules: {weak}")
        self.generated_instances = [
            inst for inst in self.generated_instances
            if inst.__class__.__name__ not in weak
        ]
        for name in weak:
            self.organ_registry.pop(name, None)
        EVENT_BUS.emit("organism.modules_culled", {"modules": weak})

    def _self_repair(self):
        repair_candidates = [
            name for name, count in self.module_error_count.items()
            if count >= 5
        ]
        if not repair_candidates:
            return
        log(f"[SelfRepair] Repairing modules: {repair_candidates}")
        for name in repair_candidates:
            self.module_error_count[name] = 0
            self.module_fitness[name] = 0.0
        EVENT_BUS.emit("organism.self_repair", {"modules": repair_candidates})

    def _update_kernel_forecast(self):
        cpu_forecast = PREDICTIVE_ENGINE.forecast_next("cpu")
        mem_forecast = PREDICTIVE_ENGINE.forecast_next("mem")
        coord_forecast = PREDICTIVE_ENGINE.forecast_next("coordination_level")
        sim_forecast = PREDICTIVE_ENGINE.forecast_next("simulation_depth")
        forecast = {
            "cpu": cpu_forecast,
            "mem": mem_forecast,
            "coordination_level": coord_forecast,
            "simulation_depth": sim_forecast
        }
        KERNEL_ENGINE.update_forecast(forecast)
        self.kernel = KERNEL_ENGINE.state

    def _scheduler_loop(self):
        while True:
            if not self.scheduler_running:
                return
            try:
                log("[Organism] Scheduler tick v32...")
                EVENT_BUS.emit("scheduler.tick", {"interval": self.scheduler_interval})
                self.run_generated_modules()
            except Exception as e:
                log(f"[Organism] Scheduler error: {e}")
                traceback.print_exc()
            time.sleep(self.scheduler_interval)

    def start_scheduler(self, interval_seconds=10.0):
        self.scheduler_interval = interval_seconds
        if self.scheduler_running:
            log("[Organism] Scheduler already running.")
            return
        self.scheduler_running = True
        self.scheduler_thread = threading.Thread(
            target=self._scheduler_loop,
            daemon=True
        )
        self.scheduler_thread.start()
        log(f"[Organism] Scheduler started ({self.scheduler_interval}s).")
        EVENT_BUS.emit("scheduler.started", {"interval": self.scheduler_interval})

    def shutdown(self):
        log("[Organism] Shutting down v32...")
        self.scheduler_running = False
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            try:
                self.scheduler_thread.join(timeout=1.0)
            except Exception:
                pass
        self.swarm_network.stop()
        log("[Organism] Shutdown complete.")
        EVENT_BUS.emit("organism.shutdown", {"node_id": self.node_id})

    def boot(self):
        log("[Organism] Booting v32...")
        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as fp:
                    manifest = json.load(fp)
                modules = manifest.get("modules", [])
                self.register_generated_modules(modules)
            except Exception as e:
                log(f"[Organism] Manifest load error: {e}")
                traceback.print_exc()
        log("[Organism] Boot pass running modules...")
        self.run_generated_modules()
        log("[Organism] Boot complete.")
        EVENT_BUS.emit("organism.boot_complete", {"node_id": self.node_id})


# ===========================================================
# DATA INTELLIGENCE ENGINE (DIE) — v32 Evolution Loop + Genetic Modules
# ===========================================================
class DataIntelligenceEngine:
    def __init__(self, organism: BORGOrganism):
        log("[DIE] Initializing v32...")
        self.organism = organism
        self.data_paths: List[str] = []
        self.unified_dataset: Dict[str, Any] = {
            "brain": {},
            "organs": {},
            "swarm": {},
            "episodes": [],
            "metrics": {},
            "telemetry": {},
            "persona": {},
            "threat_matrix": {},
            "kernel": {},
            "soul": {},
            "backups": {}
        }
        self.upgrade_patch: Dict[str, Any] = {}
        self.transformer_model = None
        self.transformer_tokenizer = None
        self._init_transformer()
        log("[DIE] Ready v32.")

    def _init_transformer(self):
        if TRANSFORMERS_AVAILABLE:
            try:
                self.transformer_tokenizer = AutoTokenizer.from_pretrained("distilbert-base-uncased")
                self.transformer_model = AutoModel.from_pretrained("distilbert-base-uncased")
                log("[DIE][ML] Transformer model loaded.")
            except Exception as e:
                log(f"[DIE][ML] Transformer load error: {e}")
                self.transformer_model = None
                self.transformer_tokenizer = None

    def scan_all_data(self):
        log("[DIE] Scanning data in BASE_DIR + mirror...")
        signatures = BORG_SIGNATURES
        for root, dirs, files in os.walk(BASE_DIR):
            if any(sig in root for sig in signatures):
                for f in files:
                    if f.endswith((".json", ".borg", ".log")):
                        self.data_paths.append(os.path.join(root, f))
        EVENT_BUS.emit("die.scan_complete", {"paths": self.data_paths})

    def load_all_data(self):
        log("[DIE] Loading data...")
        for path in self.data_paths:
            try:
                if path.endswith(".json"):
                    with open(path, "r", encoding="utf-8") as fp:
                        self._merge_data(path, json.load(fp))
                elif path.endswith(".borg"):
                    with open(path, "rb") as fp:
                        raw = fp.read()
                        self.unified_dataset["backups"][path] = hashlib.sha256(raw).hexdigest()
                elif path.endswith(".log"):
                    with open(path, "r", encoding="utf-8", errors="ignore") as fp:
                        content = fp.read()
                        self.unified_dataset["telemetry"][path] = {
                            "size": len(content),
                            "hash": hashlib.sha256(content.encode()).hexdigest()
                        }
            except Exception as e:
                log(f"[DIE] Load error: {path} -> {e}")
                traceback.print_exc()
        EVENT_BUS.emit("die.load_complete", {"dataset_keys": list(self.unified_dataset.keys())})

    def _merge_data(self, path: str, data: Any):
        p = path.lower()
        if "brain_state" in p:
            self.unified_dataset["brain"].update(data)
        elif "organs" in p:
            self.unified_dataset["organs"][os.path.basename(path).replace(".json", "")] = data
        elif "swarm_nodes" in p:
            self.unified_dataset["swarm"][os.path.basename(path).replace(".json", "")] = data
        elif "episodes" in p:
            self.unified_dataset["episodes"].append(data)
        elif "metrics" in p:
            self.unified_dataset["metrics"].update(data)
        elif "soul" in p:
            self.unified_dataset["soul"].update(data)
        elif "kernel" in p:
            self.unified_dataset["kernel"].update(data)
        elif "persona" in p:
            self.unified_dataset["persona"].update(data)
        elif "threat_matrix" in p:
            self.unified_dataset["threat_matrix"].update(data)

    def analyze(self):
        log("[DIE] Analyzing v32...")
        self._run_advanced_ml()
        self.upgrade_patch = {
            "brain": self._upgrade_brain(),
            "organs": self._upgrade_organs(),
            "swarm": self._upgrade_swarm(),
            "persona": self._upgrade_persona(),
            "threat_matrix": self._upgrade_threat_matrix(),
            "kernel": self._upgrade_kernel()
        }
        blueprints = self._design_new_modules()
        manifest = self._load_manifest()
        generated = self._generate_code_modules(blueprints, manifest)
        self._update_manifest(generated, manifest)
        EVENT_BUS.emit("die.analyze_complete", {"upgrade_patch": self.upgrade_patch})

    def _run_advanced_ml(self):
        try:
            episodes = self.unified_dataset["episodes"]
            if episodes and self.transformer_model and self.transformer_tokenizer:
                texts = []
                for ep in episodes:
                    if isinstance(ep, dict):
                        txt = ep.get("text") or ep.get("content") or ""
                    else:
                        txt = str(ep)
                    if txt:
                        texts.append(txt)
                if texts:
                    inputs = self.transformer_tokenizer(
                        texts,
                        padding=True,
                        truncation=True,
                        return_tensors="pt"
                    )
                    with torch.no_grad():
                        outputs = self.transformer_model(**inputs)
                    embeddings = outputs.last_hidden_state.mean(dim=1).cpu().numpy()
                    norms = np.linalg.norm(embeddings, axis=1)
                    avg_norm = float(norms.mean())
                    self.unified_dataset["metrics"]["episode_embedding_norm_avg"] = avg_norm
                    log(f"[DIE][ML] Episode embedding norm avg: {avg_norm:.4f}")
        except Exception as e:
            log(f"[DIE][ML] Advanced ML error: {e}")
            traceback.print_exc()

    def _upgrade_brain(self) -> Dict[str, Any]:
        brain = self.unified_dataset.get("brain", {})
        brain.setdefault("intelligence_level", 1.0)
        brain["intelligence_level"] = min(20.0, brain["intelligence_level"] + 0.2)
        return brain

    def _upgrade_organs(self) -> Dict[str, Any]:
        organs = self.unified_dataset.get("organs", {})
        return organs

    def _upgrade_swarm(self) -> Dict[str, Any]:
        swarm = self.unified_dataset.get("swarm", {})
        return swarm

    def _upgrade_persona(self) -> Dict[str, Any]:
        persona = self.unified_dataset.get("persona", {})
        persona.setdefault("evolution_stage", PERSONA_ENGINE.state.get("evolution_stage", 1))
        persona["evolution_stage"] = min(20, persona["evolution_stage"] + 1)
        return persona

    def _upgrade_threat_matrix(self) -> Dict[str, Any]:
        tm = self.unified_dataset.get("threat_matrix", {})
        return tm

    def _upgrade_kernel(self) -> Dict[str, Any]:
        kernel = self.unified_dataset.get("kernel", {})
        kernel.setdefault("simulation_depth", KERNEL_ENGINE.state.get("simulation_depth", 1.0))
        kernel["simulation_depth"] = min(20.0, kernel["simulation_depth"] + 0.3)
        return kernel

    def _design_new_modules(self) -> List[Dict[str, Any]]:
        blueprints = []
        tm = self.unified_dataset.get("threat_matrix", {})
        metrics = self.unified_dataset.get("metrics", {})
        # Threat monitor
        if tm.get("module_threats") or tm.get("resource_anomalies"):
            blueprints.append({
                "name": "ThreatMonitorOrgan",
                "type": "monitor",
                "description": "Monitors threat matrix and emits policies to reduce risk."
            })
        # Gaming optimizer
        blueprints.append({
            "name": "GamingOptimizerOrgan",
            "type": "governor",
            "description": "Optimizes system for gaming performance based on resource and telemetry."
        })
        # System governor
        blueprints.append({
            "name": "SystemGovernorOrgan",
            "type": "governor",
            "description": "Adjusts kernel mode and resource policies for overall system health."
        })
        return blueprints

    def _load_manifest(self) -> Dict[str, Any]:
        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as fp:
                    return json.load(fp)
            except Exception as e:
                log(f"[DIE] Manifest load error: {e}")
        return {"modules": []}

    def _generate_code_modules(self, blueprints: List[Dict[str, Any]], manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        generated = []
        for bp in blueprints:
            name = bp["name"]
            file_path = os.path.join(GENERATED_DIR, f"{name}.py")
            code = self._render_module_code(name, bp)
            try:
                with open(file_path, "w", encoding="utf-8") as fp:
                    fp.write(code)
                generated.append({"name": name, "file": file_path})
                log(f"[DIE] Generated module: {name} -> {file_path}")
            except Exception as e:
                log(f"[DIE] Failed to write module {name}: {e}")
        return generated

    def _render_module_code(self, name: str, bp: Dict[str, Any]) -> str:
        if name == "ThreatMonitorOrgan":
            return f'''import time

class {name}:
    def __init__(self, organism):
        self.organism = organism

    def run(self):
        tm = self.organism.threat_matrix
        module_threats = tm.get("module_threats", {{}})
        resource_anomalies = tm.get("resource_anomalies", [])
        if module_threats or resource_anomalies:
            policy = {{
                "kernel_update": {{
                    "simulation_depth": min(20.0, self.organism.kernel.get("simulation_depth", 1.0) + 0.5),
                    "scenario": "ThreatMonitorOrgan: increase simulation depth due to threats"
                }},
                "persona_update": {{
                    "traits": {{"risk_awareness": True}},
                    "history_event": "ThreatMonitorOrgan detected threats and adjusted kernel."
                }},
                "insight": "ThreatMonitorOrgan: threats detected, kernel and persona adjusted."
            }}
            return {{"status": "ok", "policy": policy}}
        return {{"status": "ok"}}
'''
        if name == "GamingOptimizerOrgan":
            return f'''import psutil
import time

class {name}:
    def __init__(self, organism):
        self.organism = organism

    def run(self):
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        # simple heuristic: if CPU high and mem high, switch kernel to gaming mode
        if cpu > 60 and mem > 60:
            policy = {{
                "kernel_update": {{
                    "mode": "gaming",
                    "scenario": "GamingOptimizerOrgan: high load, gaming mode engaged"
                }},
                "persona_update": {{
                    "traits": {{"gaming_focus": True}},
                    "history_event": "GamingOptimizerOrgan engaged gaming mode."
                }},
                "insight": "GamingOptimizerOrgan: system under gaming-like load, adjusted kernel mode."
            }}
            return {{"status": "ok", "policy": policy}}
        return {{"status": "ok"}}
'''
        if name == "SystemGovernorOrgan":
            return f'''import psutil
import time

class {name}:
    def __init__(self, organism):
        self.organism = organism

    def run(self):
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        mode = self.organism.kernel.get("mode", "normal")
        # simple governor: if low load, normal; if high load, performance
        new_mode = mode
        if cpu < 30 and mem < 40:
            new_mode = "normal"
        elif cpu > 70 or mem > 80:
            new_mode = "performance"
        if new_mode != mode:
            policy = {{
                "kernel_update": {{
                    "mode": new_mode,
                    "scenario": "SystemGovernorOrgan: adjusted kernel mode based on load"
                }},
                "persona_update": {{
                    "traits": {{"system_governor": True}},
                    "history_event": "SystemGovernorOrgan changed kernel mode."
                }},
                "insight": "SystemGovernorOrgan: kernel mode adjusted for system health."
            }}
            return {{"status": "ok", "policy": policy}}
        return {{"status": "ok"}}
'''
        return f'''class {name}:
    def __init__(self, organism):
        self.organism = organism

    def run(self):
        return {{"status": "ok"}}
'''

    def _update_manifest(self, generated: List[Dict[str, Any]], manifest: Dict[str, Any]):
        modules = manifest.get("modules", [])
        existing_names = {m.get("name") for m in modules}
        for g in generated:
            if g["name"] not in existing_names:
                modules.append(g)
        manifest["modules"] = modules
        try:
            with open(MANIFEST_PATH, "w", encoding="utf-8") as fp:
                json.dump(manifest, fp, indent=4)
            log("[DIE] Manifest updated.")
        except Exception as e:
            log(f"[DIE] Failed to update manifest: {e}")


# ===========================================================
# UNIFIED TELEMETRY & CONTROL DASHBOARD (FastAPI)
# ===========================================================
app = FastAPI(title="BORG OS v32 Telemetry & Control", version="32.0.0")

GLOBAL_ORGANISM: Optional[BORGOrganism] = None
GLOBAL_DIE: Optional[DataIntelligenceEngine] = None

@app.get("/state")
def get_state():
    if not GLOBAL_ORGANISM:
        return JSONResponse({"error": "Organism not initialized"}, status_code=500)
    return {
        "brain": GLOBAL_ORGANISM.brain,
        "persona": GLOBAL_ORGANISM.persona,
        "swarm": GLOBAL_ORGANISM.swarm,
        "kernel": GLOBAL_ORGANISM.kernel,
        "threat_matrix": GLOBAL_ORGANISM.threat_matrix,
        "module_fitness": GLOBAL_ORGANISM.module_fitness,
        "rl_policy": GLOBAL_ORGANISM.rl_agent.get_policy_params()
    }

@app.get("/swarm")
def get_swarm():
    if not GLOBAL_ORGANISM:
        return JSONResponse({"error": "Organism not initialized"}, status_code=500)
    return {
        "node_id": GLOBAL_ORGANISM.node_id,
        "nodes": GLOBAL_ORGANISM.swarm["nodes"],
        "peers": GLOBAL_ORGANISM.swarm_network.get_peers(),
        "trust": GLOBAL_ORGANISM.swarm_network.get_trust_scores()
    }

@app.get("/threats")
def get_threats():
    return THREAT_ENGINE.matrix

@app.get("/events")
def get_events(limit: int = 100):
    events = []
    if os.path.exists(EVENT_LOG_PATH):
        try:
            with open(EVENT_LOG_PATH, "r", encoding="utf-8") as fp:
                lines = fp.readlines()[-limit:]
            for line in lines:
                try:
                    events.append(json.loads(line.strip()))
                except Exception:
                    pass
        except Exception:
            pass
    return {"events": events}

@app.post("/die/run")
def run_die():
    if not GLOBAL_DIE:
        return JSONResponse({"error": "DIE not initialized"}, status_code=500)
    GLOBAL_DIE.scan_all_data()
    GLOBAL_DIE.load_all_data()
    GLOBAL_DIE.analyze()
    return {"status": "ok", "upgrade_patch": GLOBAL_DIE.upgrade_patch}

@app.post("/kernel/mode")
def set_kernel_mode(mode: str):
    KERNEL_ENGINE.set_mode(mode)
    if GLOBAL_ORGANISM:
        GLOBAL_ORGANISM.kernel = KERNEL_ENGINE.state
    return {"status": "ok", "mode": mode}


# ===========================================================
# MAIN BOOTSTRAP
# ===========================================================
def main():
    global GLOBAL_ORGANISM, GLOBAL_DIE

    log("[Main] BORG OS v32 starting...")
    initial_scan_and_sync()

    organism = BORGOrganism()
    die = DataIntelligenceEngine(organism)

    GLOBAL_ORGANISM = organism
    GLOBAL_DIE = die

    organism.boot()
    organism.start_scheduler(interval_seconds=10.0)

    def api_thread():
        log("[Main] Starting telemetry & control API on 0.0.0.0:8000...")
        uvicorn.run(app, host="0.0.0.0", port=8000)

    t = threading.Thread(target=api_thread, daemon=True)
    t.start()

    try:
        while True:
            periodic_rescan_if_due()
            time.sleep(60.0)
    except KeyboardInterrupt:
        log("[Main] KeyboardInterrupt, shutting down...")
    finally:
        organism.shutdown()
        log("[Main] BORG OS v32 stopped.")


if __name__ == "__main__":
    main()
