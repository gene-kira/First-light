# ===========================================================
# BORG OS v30 — RL-Ready, Cloud Swarm, Encrypted Mesh, Autonomous Evolution
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
from typing import Dict, Any, List

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
PROFILE_PATH = os.path.join(BASE_DIR, "intelligence_profile_v30.json")
DISCOVERED_PATHS = os.path.join(BASE_DIR, "discovered_paths.json")
LAST_FULL_SCAN = os.path.join(BASE_DIR, "last_full_scan.json")
SWARM_STATE_PATH = os.path.join(BASE_DIR, "swarm_state.json")
RL_STATE_PATH = os.path.join(BASE_DIR, "rl_state.json")
SELF_REPAIR_LOG = os.path.join(LOG_DIR, "self_repair.log")

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
        with open(os.path.join(LOG_DIR, "borg_v30.log"), "a", encoding="utf-8") as fp:
            fp.write(line + "\n")
    except Exception:
        pass


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
            if cpu > self.cpu_limit or mem > self.mem_limit:
                log(f"[Governor] Throttling: CPU={cpu:.1f}%, MEM={mem:.1f}%")
                time.sleep(2.0)
                return False
        except Exception as e:
            log(f"[Governor] Error: {e}")
        return True


GOVERNOR = ResourceGovernor(cpu_limit=85.0, mem_limit=85.0)


# ===========================================================
# ENCRYPTED SWARM NETWORKING (LAN + Cloud Hooks)
# ===========================================================
SWARM_UDP_PORT = 50555
SWARM_SHARED_KEY = b"borg_v30_shared_key"  # simple symmetric key (demo only)

def encrypt_payload(data: bytes) -> bytes:
    # XOR-based toy encryption (for demo; not secure)
    key = SWARM_SHARED_KEY
    return bytes([b ^ key[i % len(key)] for i, b in enumerate(data)])


def decrypt_payload(data: bytes) -> bytes:
    # XOR decrypt (same as encrypt)
    return encrypt_payload(data)


class SwarmNetwork:
    def __init__(self, node_id: str, cloud_endpoints: List[str] = None):
        self.node_id = node_id
        self.peers: Dict[str, Dict[str, Any]] = {}
        self.running = False
        self.thread = None
        self.cloud_endpoints = cloud_endpoints or []

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        log(f"[SwarmNet] Node {self.node_id} networking started on UDP port {SWARM_UDP_PORT}")

    def _loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            sock.bind(("", SWARM_UDP_PORT))
        except Exception as e:
            log(f"[SwarmNet] Bind error: {e}")
            return
        sock.settimeout(1.0)

        while self.running:
            # broadcast encrypted heartbeat
            try:
                msg = json.dumps({"node_id": self.node_id, "ts": time.time()}).encode()
                enc = encrypt_payload(msg)
                sock.sendto(enc, ("255.255.255.255", SWARM_UDP_PORT))
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
                        self.peers[nid] = {"last_seen": ts, "addr": addr[0]}
                except Exception:
                    pass
            except socket.timeout:
                pass
            except Exception as e:
                log(f"[SwarmNet] Error: {e}")

            time.sleep(2.0)

    def stop(self):
        self.running = False

    def get_peers(self) -> Dict[str, Dict[str, Any]]:
        return self.peers


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
        if len(self.experiences) % 20 == 0:
            self._update_policy()
            self._save_state()

    def _update_policy(self):
        if not self.experiences:
            return
        rewards = np.array([exp["reward"] for exp in self.experiences], dtype=float)
        avg_reward = float(rewards.mean())
        # simple heuristic: increase exploration if reward low, decrease if high
        if avg_reward < 0.0:
            self.policy_params["exploration"] = min(1.0, self.policy_params["exploration"] + 0.05)
        else:
            self.policy_params["exploration"] = max(0.0, self.policy_params["exploration"] - 0.05)
        log(f"[RL] Updated policy params: {self.policy_params}")

    def get_policy_params(self) -> Dict[str, Any]:
        return self.policy_params


# ===========================================================
# BORG ORGANISM CORE
# ===========================================================
class BORGOrganism:
    def __init__(self):
        log("[Organism] Initializing organism core...")

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
        self.persona = {
            "evolution_stage": 1,
            "traits": {},
            "preferences": {},
            "history": []
        }
        self.threat_matrix: Dict[str, Any] = {}
        self.kernel = {
            "simulation_depth": 1.0,
            "scenarios": []
        }

        self.generated_modules: List[Dict[str, Any]] = []
        self.generated_instances: List[Any] = []
        self.organ_registry: Dict[str, Any] = {}
        self.module_fitness: Dict[str, float] = {}
        self.module_error_count: Dict[str, int] = {}

        self.scheduler_thread = None
        self.scheduler_running = False
        self.scheduler_interval = 10.0

        self.node_id = f"node_{random.randint(1000, 9999)}"
        self.swarm_network = SwarmNetwork(self.node_id)
        self.swarm_network.start()

        self.rl_agent = RLAgent()

        self._init_swarm_nodes()
        log("[Organism] Core initialized.")

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

    def broadcast_state(self):
        self.swarm["network_peers"] = self.swarm_network.get_peers()
        state = {
            "brain": self.brain,
            "persona": self.persona,
            "swarm": self.swarm,
            "kernel": self.kernel
        }
        for name, organ in self.organ_registry.items():
            try:
                if hasattr(organ, "on_state"):
                    organ.on_state(state)
            except Exception as e:
                log(f"[Organism] Broadcast error to {name}: {e}")

    def apply_policy(self, policy: Dict[str, Any]):
        if not isinstance(policy, dict):
            return
        self.brain["policies"].append(policy)

        if "persona_update" in policy:
            self.persona["traits"].update(policy["persona_update"].get("traits", {}))
            self.persona["preferences"].update(policy["persona_update"].get("preferences", {}))
            if "history_event" in policy["persona_update"]:
                self.persona["history"].append(policy["persona_update"]["history_event"])

        if "kernel_update" in policy:
            self.kernel.update(policy["kernel_update"])
            if "scenario" in policy["kernel_update"]:
                self.kernel["scenarios"].append(policy["kernel_update"]["scenario"])

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
                log(f"[Organism] Loaded module: {name}")
            except Exception as e:
                log(f"[Organism] Failed to load module {name}: {e}")
                traceback.print_exc()

    def run_generated_modules(self) -> Dict[str, Any]:
        if not GOVERNOR.check():
            return {}
        results = {}
        for instance in list(self.generated_instances):
            name = instance.__class__.__name__
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

    def _record_error(self, name: str, err: str):
        self.module_error_count[name] = self.module_error_count.get(name, 0) + 1
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
        # DIE will regenerate modules on next evolution cycle

    def _scheduler_loop(self):
        while True:
            if not self.scheduler_running:
                return
            try:
                log("[Organism] Scheduler tick...")
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

    def shutdown(self):
        log("[Organism] Shutting down...")
        self.scheduler_running = False
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            try:
                self.scheduler_thread.join(timeout=1.0)
            except Exception:
                pass
        self.swarm_network.stop()
        log("[Organism] Shutdown complete.")

    def boot(self):
        log("[Organism] Booting...")
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


# ===========================================================
# DATA INTELLIGENCE ENGINE (DIE) — v30
# ===========================================================
class DataIntelligenceEngine:
    def __init__(self, organism: BORGOrganism):
        log("[DIE] Initializing...")
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
        log("[DIE] Ready.")

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

    def analyze(self):
        log("[DIE] Analyzing...")
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

    def _run_advanced_ml(self):
        try:
            episodes = self.unified_dataset["episodes"]
            if episodes and self.transformer_model and self.transformer_tokenizer:
                texts = []
                for ep in episodes:
                    if isinstance(ep, dict):
                        txt = ep.get("text") or ep.get("content") or ""
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
                    embeddings = outputs.last_hidden_state.mean(dim=1).detach().cpu().numpy().tolist()
                    self.unified_dataset["metrics"]["episode_embeddings"] = embeddings
                    log("[DIE][ML] Generated transformer embeddings for episodes.")
        except Exception as e:
            log(f"[DIE][ML] Advanced ML error: {e}")

    def _upgrade_brain(self) -> Dict[str, Any]:
        b = self.unified_dataset["brain"]
        b["intelligence_level"] = b.get("intelligence_level", 1) + 1.2
        b["experience_points"] = b.get("experience_points", 0) + len(self.unified_dataset["episodes"])
        return b

    def _upgrade_organs(self) -> Dict[str, Any]:
        out = {}
        for organ, data in self.unified_dataset["organs"].items():
            data["efficiency"] = data.get("efficiency", 1.0) * 1.18
            out[organ] = data
        return out

    def _upgrade_swarm(self) -> Dict[str, Any]:
        out = {}
        for node, data in self.unified_dataset["swarm"].items():
            data["sync_strength"] = data.get("sync_strength", 1.0) * 1.25
            data["latency"] = max(0.0, data.get("latency", 1.0) * 0.88)
            out[node] = data
        return out

    def _upgrade_persona(self) -> Dict[str, Any]:
        p = self.unified_dataset["persona"]
        p["evolution_stage"] = p.get("evolution_stage", 1) + 1
        return p

    def _upgrade_threat_matrix(self) -> Dict[str, Any]:
        tm = self.unified_dataset["threat_matrix"]
        tm["revision"] = tm.get("revision", 0) + 1
        return tm

    def _upgrade_kernel(self) -> Dict[str, Any]:
        k = self.unified_dataset["kernel"]
        k["simulation_depth"] = k.get("simulation_depth", 1) + 1.8
        return k

    def _design_new_modules(self) -> List[Dict[str, Any]]:
        bp = []
        if self.unified_dataset["episodes"]:
            bp.append({
                "name": "EpisodeAnalyzer",
                "purpose": "Analyze episodes, derive insights, and generate persona/kernel policies.",
                "inputs": ["episodes", "persona", "kernel"],
                "outputs": ["policy", "insight"]
            })
        if self.unified_dataset["swarm"]:
            bp.append({
                "name": "SwarmCoordinator",
                "purpose": "Coordinate swarm nodes, optimize sync, and adjust coordination level.",
                "inputs": ["swarm", "kernel"],
                "outputs": ["policy"]
            })
        bp.append({
            "name": "PersonaEvolutionEngine",
            "purpose": "Evolve persona traits and preferences based on episodes and insights.",
            "inputs": ["persona", "episodes", "brain"],
            "outputs": ["policy"]
        })
        bp.append({
            "name": "KernelScenarioEngine",
            "purpose": "Generate and refine simulation scenarios for kernel.",
            "inputs": ["kernel", "swarm", "persona"],
            "outputs": ["policy"]
        })
        return bp

    def _load_manifest(self) -> Dict[str, Any]:
        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as fp:
                    return json.load(fp)
            except Exception:
                return {}
        return {}

    def _mutate_blueprint(self, bp: Dict[str, Any], gen: int) -> Dict[str, Any]:
        m = dict(bp)
        m["name"] = f"{bp['name']}_Gen{gen}"
        m["purpose"] += f" (gen {gen})"
        return m

    def _generate_code_modules(self, blueprints: List[Dict[str, Any]], manifest: Dict[str, Any]) -> List[Dict[str, Any]]:
        gen = int(manifest.get("generation", 0)) + 1
        out = []
        for bp in blueprints:
            variants = [bp, self._mutate_blueprint(bp, gen)]
            for v in variants:
                name = v["name"]
                file_path = os.path.join(GENERATED_DIR, f"{name}.py")
                code = self._build_module_code(v, gen)
                with open(file_path, "w", encoding="utf-8") as fp:
                    fp.write(code)
                out.append({
                    "name": name,
                    "file": file_path,
                    "timestamp": datetime.utcnow().isoformat(),
                    "generation": gen
                })
                log(f"[DIE] Generated: {file_path}")
        return out

    def _build_module_code(self, bp: Dict[str, Any], gen: int) -> str:
        name = bp["name"]
        return f'''"""
Auto-generated module: {bp["name"]}
Purpose: {bp["purpose"]}
Generation: {gen}
"""

import time
import random

class {bp["name"]}:
    def __init__(self, organism):
        self.organism = organism
        self.state = {{}}

    def on_state(self, state):
        self.state = state

    def run(self):
        brain = self.state.get("brain", {{}})
        persona = self.state.get("persona", {{}})
        swarm = self.state.get("swarm", {{}})
        kernel = self.state.get("kernel", {{}})

        policy = {{}}
        insight = None

        if "{name}".startswith("EpisodeAnalyzer"):
            episodes_seen = len(self.organism.brain.get("policies", []))
            insight = {{
                "type": "episode_pattern",
                "episodes_seen": episodes_seen,
                "hint": "keep_evolving"
            }}
            policy = {{
                "persona_update": {{
                    "traits": {{
                        "adaptivity": persona.get("traits", {{}}).get("adaptivity", 1.0) + 0.10
                    }},
                    "preferences": {{
                        "risk_tolerance": persona.get("preferences", {{}}).get("risk_tolerance", 0.5) + 0.04
                    }},
                    "history_event": "EpisodeAnalyzer_gen_{gen}"
                }},
                "kernel_update": {{
                    "last_activity_ts": time.time(),
                    "simulation_depth": kernel.get("simulation_depth", 1.0) + 0.07,
                    "scenario": "episode_refinement_gen_{gen}"
                }},
                "insight": insight
            }}

        elif "{name}".startswith("SwarmCoordinator"):
            nodes = swarm.get("nodes", {{}})
            coord = swarm.get("coordination_level", 1.0)
            new_coord = coord + 0.10
            policy = {{
                "swarm_update": {{
                    "nodes": nodes,
                    "coordination_level": new_coord
                }},
                "kernel_update": {{
                    "last_activity_ts": time.time(),
                    "simulation_depth": kernel.get("simulation_depth", 1.0) + 0.05,
                    "scenario": "swarm_sync_gen_{gen}"
                }}
            }}

        elif "{name}".startswith("PersonaEvolutionEngine"):
            traits = persona.get("traits", {{}})
            prefs = persona.get("preferences", {{}})
            traits["resilience"] = traits.get("resilience", 1.0) + 0.06
            prefs["exploration"] = prefs.get("exploration", 0.5) + 0.05
            policy = {{
                "persona_update": {{
                    "traits": traits,
                    "preferences": prefs,
                    "history_event": "PersonaEvolution_gen_{gen}"
                }},
                "kernel_update": {{
                    "last_activity_ts": time.time(),
                    "simulation_depth": kernel.get("simulation_depth", 1.0) + 0.08,
                    "scenario": "persona_scenario_gen_{gen}"
                }}
            }}

        elif "{name}".startswith("KernelScenarioEngine"):
            scenario = {{
                "id": f"scenario_gen_{gen}_{{int(time.time())}}",
                "complexity": kernel.get("simulation_depth", 1.0) + random.uniform(0.05, 0.20),
                "swarm_nodes": len(swarm.get("nodes", {{}})),
                "persona_stage": persona.get("evolution_stage", 1)
            }}
            policy = {{
                "kernel_update": {{
                    "last_activity_ts": time.time(),
                    "simulation_depth": scenario["complexity"],
                    "scenario": scenario
                }}
            }}

        else:
            policy = {{
                "kernel_update": {{
                    "last_activity_ts": time.time()
                }}
            }}

        return {{
            "status": "ok",
            "generation": {gen},
            "timestamp": time.time(),
            "policy": policy
        }}
'''

    def _update_manifest(self, generated: List[Dict[str, Any]], manifest: Dict[str, Any]):
        manifest.setdefault("modules", [])
        manifest["modules"].extend(generated)
        manifest["generation"] = int(manifest.get("generation", 0)) + 1
        with open(MANIFEST_PATH, "w", encoding="utf-8") as fp:
            json.dump(manifest, fp, indent=4)
        log("[DIE] Manifest updated.")

    def inject(self):
        for key, patch in self.upgrade_patch.items():
            setattr(self.organism, key, patch)
        if os.path.exists(MANIFEST_PATH):
            try:
                with open(MANIFEST_PATH, "r", encoding="utf-8") as fp:
                    manifest = json.load(fp)
                self.organism.register_generated_modules(manifest.get("modules", []))
            except Exception as e:
                log(f"[DIE] Inject error: {e}")
                traceback.print_exc()

    def write_profile(self):
        try:
            with open(PROFILE_PATH, "w", encoding="utf-8") as fp:
                json.dump({
                    "timestamp": time.time(),
                    "dataset": self.unified_dataset,
                    "upgrade_patch": self.upgrade_patch
                }, fp, indent=4)
            log("[DIE] Profile written.")
        except Exception as e:
            log(f"[DIE] Profile write error: {e}")

    def run(self):
        log("[DIE] Running evolution cycle...")
        self.scan_all_data()
        self.load_all_data()
        self.analyze()
        self.inject()
        self.write_profile()
        log("[DIE] Evolution complete.")


# ===========================================================
# REST API
# ===========================================================
app = FastAPI()
GLOBAL_ORGANISM: BORGOrganism | None = None

@app.get("/status")
def get_status():
    if GLOBAL_ORGANISM is None:
        return JSONResponse({"error": "organism_not_ready"})
    return {
        "brain": GLOBAL_ORGANISM.brain,
        "persona": GLOBAL_ORGANISM.persona,
        "swarm": GLOBAL_ORGANISM.swarm,
        "kernel": GLOBAL_ORGANISM.kernel,
        "module_fitness": GLOBAL_ORGANISM.module_fitness,
        "rl_policy": GLOBAL_ORGANISM.rl_agent.get_policy_params()
    }

@app.get("/swarm")
def get_swarm():
    if GLOBAL_ORGANISM is None:
        return JSONResponse({"error": "organism_not_ready"})
    return GLOBAL_ORGANISM.swarm

@app.get("/peers")
def get_peers():
    if GLOBAL_ORGANISM is None:
        return JSONResponse({"error": "organism_not_ready"})
    return GLOBAL_ORGANISM.swarm_network.get_peers()

@app.post("/policy")
def inject_policy(policy: dict):
    if GLOBAL_ORGANISM is None:
        return JSONResponse({"error": "organism_not_ready"})
    GLOBAL_ORGANISM.apply_policy(policy)
    return {"status": "ok"}


def start_api_server():
    def _run():
        uvicorn.run(app, host="127.0.0.1", port=8080, log_level="info")
    t = threading.Thread(target=_run, daemon=True)
    t.start()
    log("[API] REST server started at http://127.0.0.1:8080")


# ===========================================================
# ENTRYPOINT — 24/7 daemon mode
# ===========================================================
if __name__ == "__main__":
    organism: BORGOrganism | None = None
    try:
        log("[MAIN] Starting BORG OS v30 backbone...")
        initial_scan_and_sync()
        organism = BORGOrganism()
        GLOBAL_ORGANISM = organism
        organism.boot()
        die = DataIntelligenceEngine(organism)
        die.run()
        organism.start_scheduler(10)
        start_api_server()
        log("[MAIN] BORG OS v30 running in 24/7 autonomous, RL-ready, encrypted swarm mode.")
        while True:
            try:
                time.sleep(1800)  # 30 minutes
                log("[MAIN] 24/7 cycle: sync + DIE evolution...")
                periodic_rescan_if_due()
                die = DataIntelligenceEngine(organism)
                die.run()
                if not organism.scheduler_running:
                    organism.start_scheduler(10)
            except Exception as e:
                log(f"[MAIN] 24/7 loop error: {e}")
                traceback.print_exc()
                time.sleep(5)
    except Exception as e:
        log("[CRITICAL ERROR] Startup crash detected!")
        log(str(e))
        traceback.print_exc()
    finally:
        if organism is not None:
            organism.shutdown()
