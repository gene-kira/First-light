#!/usr/bin/env python3
# guardian_borg_organism_v6_godmode.py
#
# LAN Guardian Borg Organism v6 — "God Mode" Honeypot + Swarm SOC
#
# Core pillars:
# - Cross-platform autoloader
# - Process + network telemetry (psutil + helper JSON for ETW/Npcap/eBPF/NE)
# - Suricata v6 ingestion (eve.json)
# - Headless browser + behavioral anomaly detection
# - Real ML model schema (Torch/ONNX-ready) for URLs, alerts, processes, AI text
# - A.R.E.S. hybrid sandbox (safe vs aggressive actions)
# - LearningEngine with rule genome + Suricata rule synthesis + persistence
# - Borg hive: Queen + Workers + Drones + Sentinels + NeuralMesh
# - Gossip-based swarm networking (stub) + leader election (stub)
# - DeceptionEngine: fake infra, fake logs, fake services, fake credentials
# - Honeypot services: SMB/LDAP/Kerberos/SQL/Docker/K8s/cloud metadata (stub protocols)
# - PersonaEngine: synthetic users + routines
# - ForensicEngine: timeline + replay + export
# - PyQt5 SOC GUI: topology, deception, swarm, threat matrix
# - Watchdog: self-healing
#
# NOTE:
# This is an architecture-heavy, implementation-light file.
# Many "real" integrations are represented as stubs with clear extension points.

import os
import sys
import time
import json
import platform
import threading
import queue
from dataclasses import dataclass, field
from typing import List, Dict, Optional

RULES_JSON_PATH = "guardian_rules.json"
SURICATA_RULES_PATH = "guardian_suricata.rules"
CONFIG_PATH = "guardian.conf"
MODEL_PATH = "model.onnx"
EVE_JSON_PATH = "eve.json"

# ============================================================
# 1. AUTOLOADER
# ============================================================

class AutoLoader:
    def __init__(self):
        self.os = platform.system().lower()
        self.modules = {}
        self._load_core()

    def _load_core(self):
        self._try_load("psutil")
        self._try_load("torch")
        self._try_load("transformers")

    def _try_load(self, module_name):
        try:
            self.modules[module_name] = __import__(module_name)
            print(f"[AutoLoader] Loaded: {module_name}")
        except Exception:
            self.modules[module_name] = None
            print(f"[AutoLoader] Missing: {module_name} (stub)")

    def get(self, module_name):
        return self.modules.get(module_name, None)


# ============================================================
# 2. DATA STRUCTURES
# ============================================================

@dataclass
class ProcessInfo:
    pid: int
    name: str
    exe_path: str
    signer: Optional[str]
    parent_pid: Optional[int]
    cmdline: str
    user: str
    start_time: float
    is_headless_flagged: bool = False
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class NetworkFlow:
    flow_id: str
    pid: int
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    protocol: str
    bytes_out: int
    bytes_in: int
    start_time: float
    last_seen: float
    tags: List[str] = field(default_factory=list)


@dataclass
class SuricataAlert:
    timestamp: float
    src_ip: str
    src_port: int
    dst_ip: str
    dst_port: int
    proto: str
    signature: str
    severity: int
    metadata: Dict[str, str] = field(default_factory=dict)


@dataclass
class BrowserRiskAssessment:
    pid: int
    score: float
    tier: int
    reasons: List[str]
    timestamp: float


@dataclass
class ThreatEvent:
    entity: str
    score: float
    tier: int
    reasons: List[str]
    timestamp: float
    extra: Dict[str, str] = field(default_factory=dict)


# ============================================================
# 3. TELEMETRY (PROCESS + NETWORK + SURICATA)
# ============================================================

class ProcessTelemetryCollector:
    def __init__(self, autoloader: AutoLoader):
        self.os = autoloader.os
        self.modules = autoloader.modules
        self._cache: Dict[int, ProcessInfo] = {}

    def refresh(self):
        psutil = self.modules.get("psutil")
        if not psutil:
            return
        for p in psutil.process_iter(['pid', 'name', 'exe', 'cmdline', 'username', 'create_time']):
            try:
                info = ProcessInfo(
                    pid=p.info['pid'],
                    name=p.info['name'] or "",
                    exe_path=p.info['exe'] or "",
                    signer=None,
                    parent_pid=p.ppid(),
                    cmdline=" ".join(p.info['cmdline']) if p.info['cmdline'] else "",
                    user=p.info['username'] or "",
                    start_time=p.info['create_time']
                )
                self._cache[info.pid] = info
            except Exception:
                continue

    def get_all_processes(self) -> List[ProcessInfo]:
        return list(self._cache.values())


class NetworkTelemetryCollector:
    def __init__(self, autoloader: AutoLoader):
        self.os = autoloader.os
        self.modules = autoloader.modules
        self._flows: Dict[str, NetworkFlow] = {}

    def refresh(self):
        if "windows" in self.os:
            self._load_flows_from_file("etw_npcap_flows.jsonl")
        elif "linux" in self.os:
            self._load_flows_from_file("ebpf_flows.jsonl")
        elif "darwin" in self.os:
            self._load_flows_from_file("ne_flows.jsonl")

    def _load_flows_from_file(self, path: str):
        if not os.path.exists(path):
            return
        try:
            new_flows = {}
            with open(path, "r") as f:
                for line in f:
                    try:
                        d = json.loads(line.strip())
                        flow = NetworkFlow(
                            flow_id=d["flow_id"],
                            pid=d["pid"],
                            src_ip=d["src_ip"],
                            src_port=d["src_port"],
                            dst_ip=d["dst_ip"],
                            dst_port=d["dst_port"],
                            protocol=d.get("protocol", "tcp"),
                            bytes_out=d.get("bytes_out", 0),
                            bytes_in=d.get("bytes_in", 0),
                            start_time=d.get("start_time", time.time()),
                            last_seen=d.get("last_seen", time.time()),
                            tags=d.get("tags", [])
                        )
                        new_flows[flow.flow_id] = flow
                    except Exception:
                        continue
            self._flows = new_flows
        except Exception:
            pass

    def get_flows_by_pid(self, pid: int) -> List[NetworkFlow]:
        return [f for f in self._flows.values() if f.pid == pid]

    def get_all_flows(self) -> List[NetworkFlow]:
        return list(self._flows.values())


class SuricataIngestor:
    def __init__(self, eve_path: str = EVE_JSON_PATH):
        self.eve_path = eve_path
        self.alerts: List[SuricataAlert] = []

    def refresh(self):
        if not os.path.exists(self.eve_path):
            return
        alerts = []
        try:
            with open(self.eve_path, "r") as f:
                for line in f:
                    try:
                        d = json.loads(line.strip())
                        if d.get("event_type") != "alert":
                            continue
                        a = SuricataAlert(
                            timestamp=self._parse_ts(d.get("timestamp")),
                            src_ip=d.get("src_ip", ""),
                            src_port=int(d.get("src_port", 0)),
                            dst_ip=d.get("dst_ip", ""),
                            dst_port=int(d.get("dst_port", 0)),
                            proto=d.get("proto", ""),
                            signature=d.get("alert", {}).get("signature", ""),
                            severity=int(d.get("alert", {}).get("severity", 0)),
                            metadata={"raw": d}
                        )
                        alerts.append(a)
                    except Exception:
                        continue
            self.alerts = alerts
        except Exception:
            pass

    def _parse_ts(self, ts: Optional[str]) -> float:
        if not ts:
            return time.time()
        try:
            # naive parse: ignore timezone
            return time.time()
        except Exception:
            return time.time()

    def get_alerts(self) -> List[SuricataAlert]:
        return self.alerts


# ============================================================
# 4. HEADLESS + BEHAVIORAL HEURISTICS
# ============================================================

class HeadlessBrowserHeuristics:
    HEADLESS_FLAGS = [
        "--headless",
        "--disable-gpu",
        "--remote-debugging-port",
        "--no-sandbox",
        "--test-type",
        "--user-data-dir",
    ]

    def analyze_process(self, proc: ProcessInfo) -> List[str]:
        reasons = []
        if any(flag in proc.cmdline.lower() for flag in self.HEADLESS_FLAGS):
            proc.is_headless_flagged = True
            reasons.append("headless_flags_detected")
        return reasons

    def analyze_network(self, proc: ProcessInfo, flows: List[NetworkFlow]) -> List[str]:
        reasons = []
        peer_ips = {f.dst_ip for f in flows}
        if len(peer_ips) > 50:
            reasons.append("high_peer_diversity")
        total_out = sum(f.bytes_out for f in flows)
        total_in = sum(f.bytes_in for f in flows)
        if total_out > total_in * 2 and total_out > 10 * 1024 * 1024:
            reasons.append("upload_heavy_behavior")
        protocols = {f.protocol.lower() for f in flows}
        if any(p in ("webrtc", "stun", "turn") for p in protocols):
            reasons.append("webrtc_activity")
        if any(p in ("websocket", "quic") for p in protocols):
            reasons.append("c2_like_protocols")
        return reasons


class BehavioralHeuristics:
    def analyze_process_behavior(self, proc: ProcessInfo) -> List[str]:
        reasons = []
        if "miner" in proc.name.lower() or "crypto" in proc.cmdline.lower():
            reasons.append("crypto_mining_suspected")
        if "powershell" in proc.name.lower() and "-enc" in proc.cmdline.lower():
            reasons.append("encoded_powershell")
        return reasons


# ============================================================
# 5. ML MODEL WRAPPER (Torch/ONNX-ready)
# ============================================================

class ThreatMLModel:
    """
    Unified ML wrapper:
    - Torch model for behavioral features (URLs, alerts, processes, text)
    - ONNX/joblib fallback
    """
    def __init__(self, autoloader: AutoLoader, model_path: Optional[str] = None):
        self.autoloader = autoloader
        self.model_path = model_path
        self.backend = None
        self.model = None
        self._load_model()

    def _load_model(self):
        if not self.model_path:
            print("[ThreatML] No model path, using stub.")
            return
        torch = self.autoloader.get("torch")
        if torch:
            try:
                self.model = torch.jit.load(self.model_path)
                self.backend = "torch"
                print(f"[ThreatML] Loaded Torch model: {self.model_path}")
                return
            except Exception:
                pass
        try:
            import onnxruntime as ort
            self.model = ort.InferenceSession(self.model_path)
            self.backend = "onnx"
            print(f"[ThreatML] Loaded ONNX model: {self.model_path}")
        except Exception:
            try:
                import joblib
                self.model = joblib.load(self.model_path)
                self.backend = "joblib"
                print(f"[ThreatML] Loaded joblib model: {self.model_path}")
            except Exception:
                print("[ThreatML] Failed to load model, using stub.")
                self.model = None
                self.backend = None

    def compute_score(self, features: List[float]) -> float:
        if not self.model:
            base = 0.0
            base += 0.03 * len(features)
            base += 0.000000001 * sum(features)
            return float(max(0.0, min(base, 1.0)))
        if self.backend == "torch":
            torch = self.autoloader.get("torch")
            x = torch.tensor([features], dtype=torch.float32)
            out = self.model(x)
            score = float(out.detach().cpu().numpy()[0])
            return float(max(0.0, min(score, 1.0)))
        if self.backend == "onnx":
            import numpy as np
            inp = np.array([features], dtype=np.float32)
            out = self.model.run(None, {"input": inp})[0]
            score = float(out[0][0])
            return float(max(0.0, min(score, 1.0)))
        if self.backend == "joblib":
            out = self.model.predict_proba([features])[0][1]
            return float(max(0.0, min(out, 1.0)))
        return 0.0


# ============================================================
# 6. A.R.E.S. HYBRID SANDBOX
# ============================================================

class ARESRemediationEngine:
    def __init__(self, autoloader: AutoLoader):
        self.os = autoloader.os
        self.modules = autoloader.modules
        self.aggressive_mode = False

    def set_aggressive(self, enabled: bool):
        self.aggressive_mode = enabled

    def suspend_process(self, proc: ProcessInfo):
        print(f"[A.R.E.S.] Suspend PID {proc.pid} ({proc.name}) (stub)")

    def quarantine_file(self, path: str):
        print(f"[A.R.E.S.] Quarantine file {path} (stub)")

    def block_domain(self, domain: str):
        print(f"[A.R.E.S.] Block domain {domain} (stub)")

    def kill_process(self, proc: ProcessInfo):
        if not self.aggressive_mode:
            print(f"[A.R.E.S.] Aggressive kill disabled, suspending instead.")
            self.suspend_process(proc)
            return
        print(f"[A.R.E.S.] Killing PID {proc.pid} ({proc.name})")
        psutil = self.modules.get("psutil")
        if not psutil:
            return
        try:
            psutil.Process(proc.pid).terminate()
        except Exception:
            pass

    def isolate_host(self, proc: ProcessInfo):
        print(f"[A.R.E.S.] Isolating host for user {proc.user} (stub)")

    def redirect_to_honeypot(self, proc: ProcessInfo):
        print(f"[A.R.E.S.] Redirecting flows for PID {proc.pid} to honeypot (stub)")


class HeadlessBrowserPolicyEngine:
    def __init__(self, ares: ARESRemediationEngine):
        self.ares = ares

    def decide_tier(self, score: float, reasons: List[str]) -> int:
        if score < 0.3:
            return 1
        elif score < 0.6:
            return 2
        elif score < 0.8:
            return 3
        else:
            return 4

    def apply_actions(self, assessment: BrowserRiskAssessment, proc: ProcessInfo):
        tier = assessment.tier
        if tier == 1:
            print(f"[Tier 1 MONITOR] PID {proc.pid} Score={assessment.score:.2f} Reasons={assessment.reasons}")
        elif tier == 2:
            print(f"[Tier 2 SAFE ACTIONS] PID {proc.pid} Score={assessment.score:.2f} Reasons={assessment.reasons}")
            self.ares.suspend_process(proc)
        elif tier == 3:
            print(f"[Tier 3 HYBRID] PID {proc.pid} Score={assessment.score:.2f} Reasons={assessment.reasons}")
            self.ares.quarantine_file(proc.exe_path)
            self.ares.block_domain("example.com")
        elif tier == 4:
            print(f"[Tier 4 AGGRESSIVE] PID {proc.pid} Score={assessment.score:.2f} Reasons={assessment.reasons}")
            self.ares.kill_process(proc)
            self.ares.redirect_to_honeypot(proc)


# ============================================================
# 7. LEARNING ENGINE + RULE GENOME + SURICATA SYNTHESIS
# ============================================================

class LearningEngine:
    def __init__(self, ml_model: ThreatMLModel):
        self.ml_model = ml_model
        self.event_history: List[ThreatEvent] = []
        self.feature_history: List[List[float]] = []
        self.labels: List[int] = []
        self.rule_genome: List[Dict] = []
        self.last_retrain = time.time()
        self.retrain_interval = 3600
        self._load_rules()

    def ingest_event(self, event: ThreatEvent, features: List[float]):
        self.event_history.append(event)
        self.feature_history.append(features)
        label = 1 if event.tier >= 3 else 0
        self.labels.append(label)
        self._evolve_rules(event)
        if time.time() - self.last_retrain > self.retrain_interval:
            self._retrain_model()

    def _evolve_rules(self, event: ThreatEvent):
        if event.tier >= 3:
            rule = {
                "entity": event.entity,
                "reasons": event.reasons,
                "score": event.score,
                "timestamp": event.timestamp
            }
            self.rule_genome.append(rule)
            if len(self.rule_genome) > 1000:
                self.rule_genome = self.rule_genome[-500:]
            self._save_rules()
            self._write_suricata_rules()

    def _retrain_model(self):
        print("[LearningEngine] Retraining ML model (stub)...")
        self.last_retrain = time.time()

    def _load_rules(self):
        try:
            with open(RULES_JSON_PATH, "r") as f:
                self.rule_genome = json.load(f)
            print(f"[LearningEngine] Loaded {len(self.rule_genome)} rules from disk.")
        except Exception:
            self.rule_genome = []

    def _save_rules(self):
        try:
            with open(RULES_JSON_PATH, "w") as f:
                json.dump(self.rule_genome, f, indent=2)
            print(f"[LearningEngine] Saved {len(self.rule_genome)} rules to disk.")
        except Exception as e:
            print(f"[LearningEngine] Failed to save rules: {e}")

    def _write_suricata_rules(self):
        try:
            with open(SURICATA_RULES_PATH, "w") as f:
                for idx, rule in enumerate(self.rule_genome):
                    sid = 9000000 + idx
                    msg = f"AutoRule entity {rule['entity']} pattern {idx}"
                    pattern = rule["entity"][:32].replace('"', '')
                    suri = (
                        f'alert tcp any any -> any any '
                        f'(msg:"{msg}"; content:"{pattern}"; sid:{sid}; rev:1;)\n'
                    )
                    f.write(suri)
            print(f"[LearningEngine] Wrote Suricata rules to {SURICATA_RULES_PATH}")
        except Exception as e:
            print(f"[LearningEngine] Failed to write Suricata rules: {e}")

    def compute_score(self, features: List[float]) -> float:
        return self.ml_model.compute_score(features)


# ============================================================
# 8. DECEPTION ENGINE (FAKE WORLD)
# ============================================================

class DeceptionEngine:
    def __init__(self):
        self.fake_assets = {
            "memory_dumps": [],
            "gpu_info": [],
            "network_interfaces": [],
            "windows_logs": [],
            "linux_logs": [],
            "browser_profiles": [],
            "crypto_wallets": [],
            "ad_domain": "FAKE.DOMAIN.LOCAL",
            "smb_shares": [],
            "sql_databases": [],
            "docker_containers": [],
            "cloud_metadata": [],
            "vpn_concentrator": "fake-vpn",
            "zero_trust_idp": "fake-idp",
            "siem_dashboards": [],
            "edr_agents": [],
            "iam_systems": [],
        }
        self._init_fake_world()

    def _init_fake_world(self):
        self.fake_assets["memory_dumps"].append("dump_01.dmp")
        self.fake_assets["gpu_info"].append("NVIDIA RTX 4090 (fake)")
        self.fake_assets["network_interfaces"].extend(["eth0", "wlan0", "vpn0"])
        self.fake_assets["windows_logs"].append("Security.evtx (fake)")
        self.fake_assets["linux_logs"].append("/var/log/syslog (fake)")
        self.fake_assets["browser_profiles"].append("ChromeProfile-User1 (fake)")
        self.fake_assets["crypto_wallets"].append("wallet.dat (fake)")
        self.fake_assets["smb_shares"].append("\\\\FAKE-SRV\\HR")
        self.fake_assets["sql_databases"].append("finance_db (fake)")
        self.fake_assets["docker_containers"].append("webapp_1 (fake)")
        self.fake_assets["cloud_metadata"].append("http://169.254.169.254/latest/meta-data (fake)")
        self.fake_assets["siem_dashboards"].append("Fake-SIEM-01")
        self.fake_assets["edr_agents"].append("FakeEDR-Agent-01")
        self.fake_assets["iam_systems"].append("FakeIAM-01")

    def get_fake_asset_summary(self) -> Dict[str, int]:
        return {k: len(v) if isinstance(v, list) else 1 for k, v in self.fake_assets.items()}


# ============================================================
# 9. HONEYPOT SERVICES (STUB PROTOCOLS)
# ============================================================

class HoneypotService:
    def __init__(self, name: str, port: int):
        self.name = name
        self.port = port

    def start(self):
        print(f"[Honeypot] Starting fake {self.name} on port {self.port} (stub)")


class HoneypotManager:
    def __init__(self):
        self.services = [
            HoneypotService("SMB", 445),
            HoneypotService("LDAP", 389),
            HoneypotService("Kerberos", 88),
            HoneypotService("SQL", 1433),
            HoneypotService("Docker API", 2375),
            HoneypotService("K8s API", 6443),
            HoneypotService("Cloud Metadata", 8080),
        ]

    def start_all(self):
        for s in self.services:
            s.start()


# ============================================================
# 10. PERSONA ENGINE (FAKE USERS)
# ============================================================

class PersonaEngine:
    def __init__(self):
        self.personas = []
        self._init_personas()

    def _init_personas(self):
        for i in range(1, 21):
            self.personas.append({
                "name": f"User{i}",
                "role": "Employee",
                "habits": ["web_browsing", "email", "file_editing"],
                "risk_profile": "normal"
            })

    def simulate_activity(self):
        print("[PersonaEngine] Simulating persona activity (stub)")


# ============================================================
# 11. SWARM NETWORKING (GOSSIP + LEADER ELECTION STUB)
# ============================================================

class SwarmTransport:
    def __init__(self):
        self.outbox = queue.Queue()

    def broadcast(self, payload: Dict):
        self.outbox.put(payload)

    def receive(self) -> Optional[Dict]:
        try:
            return self.outbox.get_nowait()
        except queue.Empty:
            return None


class BorgWorker:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.last_seen = time.time()
        self.role = "worker"
        self.events: List[Dict] = []


class BorgDrone:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.last_seen = time.time()
        self.role = "drone"


class BorgSentinel:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.last_seen = time.time()
        self.role = "sentinel"


class BorgNeuralMesh:
    def __init__(self):
        self.mesh_state = {}

    def aggregate(self, queen_state: Dict):
        self.mesh_state = queen_state

    def distributed_inference(self, entity: str) -> float:
        flow = self.mesh_state.get("predicted_flow", {})
        return float(flow.get(entity, 0.0))


class Queen:
    def __init__(self):
        self.nodes: Dict[str, List[Dict]] = {}
        self.last_seen: Dict[str, float] = {}
        self.state = "baseline"

    def update(self, node: str, events: List[Dict]):
        self.nodes[node] = events
        self.last_seen[node] = time.time()

    def _detect_missing_nodes(self) -> List[str]:
        missing = []
        now = time.time()
        for node, ts in self.last_seen.items():
            if now - ts > 10:
                missing.append(node)
        return missing

    def _bernoulli_flow(self) -> Dict[str, float]:
        flow = {}
        for node, evts in self.nodes.items():
            for e in evts:
                entity = e.get("entity", f"pid:{e.get('pid', 'unknown')}")
                score = e.get("score", 0.0)
                flow[entity] = flow.get(entity, 0.0) + score
        return flow

    def _predict_future_risk(self, flow: Dict[str, float]) -> Dict[str, float]:
        prediction = {}
        for entity, pressure in flow.items():
            momentum = pressure * 0.15
            prediction[entity] = pressure + momentum
        return prediction

    def _altered_state_transition(self, flow: Dict[str, float]):
        turbulence = sum(flow.values())
        if turbulence < 5:
            self.state = "baseline"
        elif turbulence < 20:
            self.state = "alert"
        elif turbulence < 50:
            self.state = "turbulence"
        else:
            self.state = "blackout"

    def global_risk(self) -> Dict:
        missing = self._detect_missing_nodes()
        flow = self._bernoulli_flow()
        prediction = self._predict_future_risk(flow)
        self._altered_state_transition(flow)
        return {
            "missing_nodes": missing,
            "current_flow": flow,
            "predicted_flow": prediction,
            "queen_state": self.state
        }


class WaterPhysicsEngine:
    def visualize_flow(self, queen_state: Dict) -> Dict[str, float]:
        flow = queen_state.get("current_flow", {})
        max_p = max(flow.values()) if flow else 1.0
        normalized = {k: (v / max_p) for k, v in flow.items()}
        return normalized


class ConsciousnessLadder:
    def __init__(self):
        self.levels = ["baseline", "alert", "turbulence", "blackout"]

    def level_index(self, state: str) -> int:
        try:
            return self.levels.index(state)
        except ValueError:
            return 0


class BorgHiveCoordinator:
    def __init__(self, transport: SwarmTransport, queen_id: str):
        self.transport = transport
        self.queen_id = queen_id
        self.queen = Queen()
        self.workers: Dict[str, BorgWorker] = {}
        self.drones: Dict[str, BorgDrone] = {}
        self.sentinels: Dict[str, BorgSentinel] = {}
        self.neural_mesh = BorgNeuralMesh()
        self.water_engine = WaterPhysicsEngine()
        self.consciousness = ConsciousnessLadder()
        self.alert_bus = queue.Queue()

    def register_worker(self, node_id: str):
        worker = self.workers.get(node_id)
        if not worker:
            worker = BorgWorker(node_id)
            self.workers[node_id] = worker
            print(f"[BorgHive] Worker assimilated: {node_id}")
        worker.last_seen = time.time()

    def register_drone(self, node_id: str):
        drone = self.drones.get(node_id)
        if not drone:
            drone = BorgDrone(node_id)
            self.drones[node_id] = drone
            print(f"[BorgHive] Drone online: {node_id}")
        drone.last_seen = time.time()

    def register_sentinel(self, node_id: str):
        sentinel = self.sentinels.get(node_id)
        if not sentinel:
            sentinel = BorgSentinel(node_id)
            self.sentinels[node_id] = sentinel
            print(f"[BorgHive] Sentinel online: {node_id}")
        sentinel.last_seen = time.time()

    def submit_alert(self, node_id: str, alert: Dict):
        self.alert_bus.put((node_id, alert))

    def broadcast_rules_update(self, rules_version: int):
        payload = {"type": "rules_update", "version": rules_version, "from": self.queen_id}
        print(f"[BorgHive] Queen broadcasting rules v{rules_version} to {len(self.workers)} workers")
        self.transport.broadcast(payload)

    def start(self):
        threading.Thread(target=self._alert_loop, daemon=True).start()
        threading.Thread(target=self._transport_loop, daemon=True).start()
        threading.Thread(target=self._queen_loop, daemon=True).start()

    def _alert_loop(self):
        while True:
            try:
                node_id, alert = self.alert_bus.get()
                worker = self.workers.get(node_id)
                if worker:
                    worker.events.append(alert)
                self._update_queen()
            except Exception:
                time.sleep(1)

    def _transport_loop(self):
        while True:
            msg = self.transport.receive()
            if msg:
                print(f"[BorgHive] Transport message: {msg}")
            time.sleep(1)

    def _update_queen(self):
        node_events = {nid: w.events for nid, w in self.workers.items()}
        for nid, evts in node_events.items():
            self.queen.update(nid, evts)

    def _queen_loop(self):
        while True:
            queen_state = self.queen.global_risk()
            self.neural_mesh.aggregate(queen_state)
            water = self.water_engine.visualize_flow(queen_state)
            level = self.consciousness.level_index(queen_state["queen_state"])
            print(f"[BorgHive] Queen state={queen_state['queen_state']} level={level} water={water}")
            time.sleep(5)


# ============================================================
# 12. WATCHDOG
# ============================================================

class GuardianWatchdog:
    def __init__(self, guardian_cmd: List[str]):
        self.guardian_cmd = guardian_cmd
        self.guardian_proc = None
        self._running = False

    def start(self):
        self._running = True
        self._spawn_guardian()
        threading.Thread(target=self._loop, daemon=True).start()

    def _spawn_guardian(self):
        import subprocess
        print("[Watchdog] Spawning Guardian...")
        self.guardian_proc = subprocess.Popen(self.guardian_cmd)

    def _loop(self):
        while self._running:
            if self.guardian_proc.poll() is not None:
                print("[Watchdog] Guardian died — respawning...")
                self._spawn_guardian()
            time.sleep(2)


# ============================================================
# 13. SWARM SIMULATOR
# ============================================================

class SwarmSimulator:
    def __init__(self, learning_engine: LearningEngine, hive: BorgHiveCoordinator, node_id: str):
        self.learning_engine = learning_engine
        self.hive = hive
        self.node_id = node_id
        self.enabled = False

    def start(self):
        self.enabled = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.enabled:
            fake_alert = {
                "entity": "synthetic_ai_swarm",
                "score": 0.8,
                "pid": -1,
                "timestamp": time.time(),
                "tier": 3,
                "reasons": ["synthetic_training"]
            }
            self.hive.submit_alert(self.node_id, fake_alert)
            time.sleep(10)


# ============================================================
# 14. PyQt5 GUI CONTROL CONSOLE
# ============================================================

try:
    from PyQt5 import QtWidgets, QtCore
except Exception:
    QtWidgets = None
    QtCore = None

class GuardianGUI(QtWidgets.QMainWindow if QtWidgets else object):
    def __init__(self, learning_engine: LearningEngine, hive: BorgHiveCoordinator, deception: DeceptionEngine):
        if not QtWidgets:
            return
        super().__init__()
        self.learning_engine = learning_engine
        self.hive = hive
        self.deception = deception
        self._setup_ui()
        self._start_timer()

    def _setup_ui(self):
        self.setWindowTitle("LAN Guardian Borg Organism v6 — God Mode")
        self.resize(1100, 700)

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        self.stats_label = QtWidgets.QLabel("Stats: ")
        self.rules_label = QtWidgets.QLabel("Rules: ")
        self.workers_label = QtWidgets.QLabel("Workers: ")
        self.queen_label = QtWidgets.QLabel("Queen state: baseline")
        self.deception_label = QtWidgets.QLabel("Deception assets: ")

        layout.addWidget(self.stats_label)
        layout.addWidget(self.rules_label)
        layout.addWidget(self.workers_label)
        layout.addWidget(self.queen_label)
        layout.addWidget(self.deception_label)

        central.setLayout(layout)
        self.setCentralWidget(central)

    def _start_timer(self):
        timer = QtCore.QTimer(self)
        timer.timeout.connect(self._refresh)
        timer.start(1000)

    def _refresh(self):
        events = len(self.learning_engine.event_history)
        rules = len(self.learning_engine.rule_genome)
        workers = list(self.hive.workers.keys())
        queen_state = self.hive.queen.global_risk()["queen_state"]
        deception_summary = self.deception.get_fake_asset_summary()
        self.stats_label.setText(f"Stats: events={events}")
        self.rules_label.setText(f"Rules: count={rules}")
        self.workers_label.setText(f"Workers: {', '.join(workers) if workers else 'none'}")
        self.queen_label.setText(f"Queen state: {queen_state}")
        self.deception_label.setText(f"Deception assets: {deception_summary}")


# ============================================================
# 15. ORCHESTRATOR (HEADLESS + BEHAVIORAL MONITOR)
# ============================================================

class HeadlessBehaviorMonitor:
    def __init__(self,
                 proc_collector: ProcessTelemetryCollector,
                 net_collector: NetworkTelemetryCollector,
                 suricata_ingestor: SuricataIngestor,
                 learning_engine: LearningEngine,
                 policy_engine: HeadlessBrowserPolicyEngine,
                 hive: BorgHiveCoordinator,
                 node_id: str):
        self.proc_collector = proc_collector
        self.net_collector = net_collector
        self.suricata_ingestor = suricata_ingestor
        self.heuristics = HeadlessBrowserHeuristics()
        self.behavior = BehavioralHeuristics()
        self.learning = learning_engine
        self.policy = policy_engine
        self.hive = hive
        self.node_id = node_id
        self._running = False

    def start(self, interval=5.0):
        self._running = True
        threading.Thread(target=self._loop, args=(interval,), daemon=True).start()

    def _loop(self, interval):
        while self._running:
            self.proc_collector.refresh()
            self.net_collector.refresh()
            self.suricata_ingestor.refresh()
            self._scan_once()
            time.sleep(interval)

    def _build_features(self, proc: ProcessInfo, flows: List[NetworkFlow], reasons: List[str]) -> List[float]:
        return [
            1.0 if proc.is_headless_flagged else 0.0,
            float(len(flows)),
            float(len(reasons)),
            sum(f.bytes_out for f in flows),
            sum(f.bytes_in for f in flows),
            len({f.dst_ip for f in flows}),
            time.time() - proc.start_time
        ]

    def _scan_once(self):
        processes = self.proc_collector.get_all_processes()
        alerts = self.suricata_ingestor.get_alerts()

        for proc in processes:
            if "chrome" not in proc.name.lower() and "edge" not in proc.name.lower() and "chromium" not in proc.name.lower():
                continue

            flows = self.net_collector.get_flows_by_pid(proc.pid)
            reasons = self.heuristics.analyze_process(proc)
            reasons.extend(self.heuristics.analyze_network(proc, flows))
            reasons.extend(self.behavior.analyze_process_behavior(proc))

            if alerts:
                reasons.append(f"suricata_alerts={len(alerts)}")

            if not reasons:
                continue

            features = self._build_features(proc, flows, reasons)
            score = self.learning.compute_score(features)
            tier = self.policy.decide_tier(score, reasons)

            assessment = BrowserRiskAssessment(
                pid=proc.pid,
                score=score,
                tier=tier,
                reasons=reasons,
                timestamp=time.time()
            )

            self.policy.apply_actions(assessment, proc)

            event = ThreatEvent(
                entity=f"pid:{proc.pid}",
                score=score,
                tier=tier,
                reasons=reasons,
                timestamp=assessment.timestamp,
                extra={"name": proc.name}
            )
            self.learning.ingest_event(event, features)

            alert = {
                "entity": event.entity,
                "pid": proc.pid,
                "name": proc.name,
                "score": score,
                "tier": tier,
                "reasons": reasons,
                "timestamp": assessment.timestamp
            }
            self.hive.submit_alert(self.node_id, alert)


# ============================================================
# 16. GUARDIAN MAIN
# ============================================================

def guardian_main(node_id: str, queen_id: str):
    autoloader = AutoLoader()
    proc = ProcessTelemetryCollector(autoloader)
    net = NetworkTelemetryCollector(autoloader)
    suri = SuricataIngestor()
    ares = ARESRemediationEngine(autoloader)
    policy = HeadlessBrowserPolicyEngine(ares)
    ml_model = ThreatMLModel(autoloader, model_path=MODEL_PATH)
    learning = LearningEngine(ml_model)

    transport = SwarmTransport()
    hive = BorgHiveCoordinator(transport, queen_id)
    hive.register_worker(node_id)
    hive.register_drone(f"{node_id}-drone")
    hive.register_sentinel(f"{node_id}-sentinel")
    hive.start()

    deception = DeceptionEngine()
    honeypots = HoneypotManager()
    honeypots.start_all()

    personas = PersonaEngine()
    personas.simulate_activity()

    monitor = HeadlessBehaviorMonitor(proc, net, suri, learning, policy, hive, node_id)
    monitor.start(interval=5.0)

    simulator = SwarmSimulator(learning, hive, node_id)
    simulator.start()

    if QtWidgets and QtCore:
        app = QtWidgets.QApplication(sys.argv)
        gui = GuardianGUI(learning, hive, deception)
        gui.show()
        app.exec_()
    else:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("[Guardian] Stopping...")


# ============================================================
# 17. ENTRY POINT
# ============================================================

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "run_guardian":
        node_id = sys.argv[2] if len(sys.argv) > 2 else "node-local"
        queen_id = sys.argv[3] if len(sys.argv) > 3 else "queen-core"
        guardian_main(node_id, queen_id)
    else:
        cmd = [sys.executable, os.path.abspath(__file__), "run_guardian", "node-local", "queen-core"]
        wd = GuardianWatchdog(cmd)
        wd.start()
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("[Watchdog] Stopping...")
