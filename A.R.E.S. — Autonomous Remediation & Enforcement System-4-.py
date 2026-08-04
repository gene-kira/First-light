#!/usr/bin/env python3
# guardian_borg_organism_v4.py
#
# LAN Guardian Borg Organism v4:
# - Cross-platform autoloader
# - Process + network telemetry with ETW/Npcap/eBPF/NE helper integration points
# - Headless browser misuse detection
# - ONNX/joblib ML inference with defined feature schema
# - A.R.E.S. autonomous remediation
# - LearningEngine with rule genome + Suricata rule synthesis + persistence
# - Distributed swarm transport layer (Borg hive)
# - BorgQueen + BorgWorker roles
# - Self-healing Watchdog
# - Adversarial SwarmSimulator
# - PyQt5 GUI console

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

# ============================================================
# 1. AUTOLOADER
# ============================================================

class AutoLoader:
    def __init__(self):
        self.os = platform.system().lower()
        self.modules = {}
        self._load_core()

    def _load_core(self):
        if "windows" in self.os:
            self._try_load("psutil")
        elif "linux" in self.os:
            self._try_load("psutil")
        elif "darwin" in self.os:
            self._try_load("psutil")

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
class BrowserRiskAssessment:
    pid: int
    score: float
    tier: int
    reasons: List[str]
    timestamp: float


# ============================================================
# 3. TELEMETRY (PROCESS + NETWORK)
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
    """
    Network telemetry abstraction with integration points for:
    - Windows: ETW + Npcap helper
    - Linux: eBPF/XDP helper
    - macOS: Network Extension helper
    Helpers are expected to expose flow data via local JSONL/IPC.
    """
    def __init__(self, autoloader: AutoLoader):
        self.os = autoloader.os
        self.modules = autoloader.modules
        self._flows: Dict[str, NetworkFlow] = {}

    def refresh(self):
        if "windows" in self.os:
            self._refresh_windows_etw_npcap()
        elif "linux" in self.os:
            self._refresh_linux_ebpf_xdp()
        elif "darwin" in self.os:
            self._refresh_macos_network_extension()

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

    def _refresh_windows_etw_npcap(self):
        # ETW/Npcap helper writes to etw_npcap_flows.jsonl
        self._load_flows_from_file("etw_npcap_flows.jsonl")

    def _refresh_linux_ebpf_xdp(self):
        # eBPF/XDP helper writes to ebpf_flows.jsonl
        self._load_flows_from_file("ebpf_flows.jsonl")

    def _refresh_macos_network_extension(self):
        # NE helper writes to ne_flows.jsonl
        self._load_flows_from_file("ne_flows.jsonl")

    def get_flows_by_pid(self, pid: int) -> List[NetworkFlow]:
        return [f for f in self._flows.values() if f.pid == pid]

    def get_all_flows(self) -> List[NetworkFlow]:
        return list(self._flows.values())


# ============================================================
# 4. HEADLESS BROWSER DETECTION
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


# ============================================================
# 5. ONNX MODEL ARCHITECTURE + INFERENCE WRAPPER
# ============================================================

class HeadlessBrowserMLModel:
    """
    ML inference wrapper:
    - ONNX model expected with:
      input: 1 x N float32 vector (features)
      output: 1 x 1 float32 risk score in [0,1]
    - Fallback to joblib if ONNX not available.
    """
    def __init__(self, model_path: Optional[str] = None):
        self.model = None
        self.backend = None
        self.input_name = "input"
        if model_path:
            self._load_model(model_path)

    def _load_model(self, model_path: str):
        try:
            import onnxruntime as ort
            self.model = ort.InferenceSession(model_path)
            self.backend = "onnx"
            print(f"[ML] Loaded ONNX model: {model_path}")
        except Exception:
            try:
                import joblib
                self.model = joblib.load(model_path)
                self.backend = "joblib"
                print(f"[ML] Loaded joblib model: {model_path}")
            except Exception:
                print(f"[ML] Failed to load model: {model_path}, using stub.")
                self.model = None
                self.backend = None

    def compute_score(self, features: List[float]) -> float:
        if not self.model:
            base = 0.0
            base += 0.05 * len(features)
            base += 0.000000001 * sum(features)
            return float(max(0.0, min(base, 1.0)))

        if self.backend == "onnx":
            import numpy as np
            inp = np.array([features], dtype=np.float32)
            out = self.model.run(None, {self.input_name: inp})[0]
            return float(max(0.0, min(out[0][0], 1.0)))
        elif self.backend == "joblib":
            out = self.model.predict_proba([features])[0][1]
            return float(max(0.0, min(out, 1.0)))
        return 0.0


# ============================================================
# 6. A.R.E.S. — AUTONOMOUS REMEDIATION & ENFORCEMENT SYSTEM
# ============================================================

class ARESRemediationEngine:
    def __init__(self, autoloader: AutoLoader):
        self.os = autoloader.os
        self.modules = autoloader.modules

    def kill_process(self, proc: ProcessInfo):
        print(f"[A.R.E.S.] Killing PID {proc.pid} ({proc.name})")
        psutil = self.modules.get("psutil")
        if not psutil:
            return
        try:
            psutil.Process(proc.pid).terminate()
        except Exception:
            pass

    def isolate_host(self, proc: ProcessInfo):
        print(f"[A.R.E.S.] Isolating host for user {proc.user}")
        # TODO: integrate with firewall/VLAN/orchestration

    def throttle_network(self, proc: ProcessInfo):
        print(f"[A.R.E.S.] Throttling network for PID {proc.pid}")
        # TODO: apply QoS/firewall rules

    def redirect_to_honeypot(self, proc: ProcessInfo):
        print(f"[A.R.E.S.] Redirecting flows for PID {proc.pid} to honeypot")
        # TODO: modify routing/DNS/proxy


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
            print(f"[Tier 2 CONSTRAIN] PID {proc.pid} Score={assessment.score:.2f} Reasons={assessment.reasons}")
            self.ares.throttle_network(proc)
        elif tier == 3:
            print(f"[Tier 3 QUARANTINE_CANDIDATE] PID {proc.pid} Score={assessment.score:.2f} Reasons={assessment.reasons}")
            self.ares.isolate_host(proc)
        elif tier == 4:
            print(f"[Tier 4 QUARANTINE/HONEYPOT] PID {proc.pid} Score={assessment.score:.2f} Reasons={assessment.reasons}")
            self.ares.kill_process(proc)
            self.ares.redirect_to_honeypot(proc)


# ============================================================
# 7. LEARNING ENGINE + RULE GENOME + SURICATA SYNTHESIS
# ============================================================

class LearningEngine:
    def __init__(self, ml_model: HeadlessBrowserMLModel):
        self.ml_model = ml_model
        self.event_history = []
        self.feature_history = []
        self.labels = []
        self.rule_genome = []
        self.last_retrain = time.time()
        self.retrain_interval = 3600
        self._load_rules()

    def ingest_event(self, proc: ProcessInfo, flows: List[NetworkFlow],
                     reasons: List[str], assessment: BrowserRiskAssessment):
        event = {
            "pid": proc.pid,
            "name": proc.name,
            "cmdline": proc.cmdline,
            "reasons": reasons,
            "score": assessment.score,
            "tier": assessment.tier,
            "timestamp": assessment.timestamp
        }
        self.event_history.append(event)

        features = self._extract_features(proc, flows, reasons)
        self.feature_history.append(features)
        label = 1 if assessment.tier >= 3 else 0
        self.labels.append(label)

        self._evolve_rules(proc, flows, reasons, assessment)

        if time.time() - self.last_retrain > self.retrain_interval:
            self._retrain_model()

    def _extract_features(self, proc: ProcessInfo, flows: List[NetworkFlow], reasons: List[str]) -> List[float]:
        return [
            1.0 if proc.is_headless_flagged else 0.0,
            float(len(flows)),
            float(len(reasons)),
            sum(f.bytes_out for f in flows),
            sum(f.bytes_in for f in flows),
            len({f.dst_ip for f in flows}),
            1.0 if any("webrtc_activity" in r for r in reasons) else 0.0,
            1.0 if any("c2_like_protocols" in r for r in reasons) else 0.0,
            time.time() - proc.start_time
        ]

    def _evolve_rules(self, proc: ProcessInfo, flows: List[NetworkFlow],
                      reasons: List[str], assessment: BrowserRiskAssessment):
        if assessment.tier >= 3:
            rule = {
                "cmdline_pattern": proc.cmdline,
                "reasons": reasons,
                "peer_count": len({f.dst_ip for f in flows}),
                "protocols": list({f.protocol for f in flows}),
                "timestamp": time.time()
            }
            self.rule_genome.append(rule)
            if len(self.rule_genome) > 500:
                self.rule_genome = self.rule_genome[-250:]
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
                    msg = f"AutoRule headless pattern {idx}"
                    pattern = rule["cmdline_pattern"][:32].replace('"', '')
                    suri = (
                        f'alert tcp any any -> any any '
                        f'(msg:"{msg}"; content:"{pattern}"; sid:{sid}; rev:1;)\n'
                    )
                    f.write(suri)
            print(f"[LearningEngine] Wrote Suricata rules to {SURICATA_RULES_PATH}")
        except Exception as e:
            print(f"[LearningEngine] Failed to write Suricata rules: {e}")

    def compute_score(self, proc: ProcessInfo, flows: List[NetworkFlow], reasons: List[str]) -> float:
        features = self._extract_features(proc, flows, reasons)
        return self.ml_model.compute_score(features)


# ============================================================
# 8. BORG HIVE: QUEEN + WORKERS + SWARM TRANSPORT
# ============================================================

class BorgWorker:
    def __init__(self, node_id: str):
        self.node_id = node_id
        self.last_seen = time.time()
        self.role = "worker"


class BorgQueen:
    def __init__(self, hive_id: str):
        self.hive_id = hive_id
        self.last_seen = time.time()
        self.role = "queen"


class SwarmTransport:
    """
    Abstract transport layer for Borg hive:
    - In real deployment, implement HTTP/WebSocket/gRPC here.
    - For now, stub with in-memory queue.
    """
    def __init__(self):
        self.outbox = queue.Queue()

    def broadcast(self, payload: Dict):
        self.outbox.put(payload)

    def receive(self) -> Optional[Dict]:
        try:
            return self.outbox.get_nowait()
        except queue.Empty:
            return None


class BorgHiveCoordinator:
    """
    Borg hive:
    - Queen orchestrates rules + strategy
    - Workers execute detection + remediation
    - Swarm transport shares intelligence
    """
    def __init__(self, transport: SwarmTransport, queen_id: str):
        self.transport = transport
        self.queen = BorgQueen(queen_id)
        self.workers: Dict[str, BorgWorker] = {}
        self.alert_bus = queue.Queue()

    def register_worker(self, node_id: str):
        worker = self.workers.get(node_id)
        if not worker:
            worker = BorgWorker(node_id)
            self.workers[node_id] = worker
            print(f"[BorgHive] Worker assimilated: {node_id}")
        worker.last_seen = time.time()

    def broadcast_rules_update(self, rules_version: int):
        payload = {"type": "rules_update", "version": rules_version, "from": self.queen.hive_id}
        print(f"[BorgHive] Queen broadcasting rules v{rules_version} to {len(self.workers)} workers")
        self.transport.broadcast(payload)

    def submit_alert(self, node_id: str, alert: Dict):
        self.alert_bus.put((node_id, alert))

    def start(self):
        threading.Thread(target=self._alert_loop, daemon=True).start()
        threading.Thread(target=self._transport_loop, daemon=True).start()

    def _alert_loop(self):
        while True:
            try:
                node_id, alert = self.alert_bus.get()
                print(f"[BorgHive] Alert from worker {node_id}: {alert}")
            except Exception:
                time.sleep(1)

    def _transport_loop(self):
        while True:
            msg = self.transport.receive()
            if msg:
                print(f"[BorgHive] Transport message: {msg}")
            time.sleep(1)


# ============================================================
# 9. WATCHDOG (SELF-HEALING)
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
# 10. ADVERSARIAL SWARM SIMULATION
# ============================================================

class SwarmSimulator:
    def __init__(self, learning_engine: LearningEngine):
        self.learning_engine = learning_engine
        self.enabled = False

    def start(self):
        self.enabled = True
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.enabled:
            # TODO: generate synthetic events for training
            time.sleep(10)


# ============================================================
# 11. PyQt5 GUI CONTROL CONSOLE
# ============================================================

try:
    from PyQt5 import QtWidgets, QtCore
except Exception:
    QtWidgets = None
    QtCore = None

class GuardianGUI(QtWidgets.QMainWindow if QtWidgets else object):
    def __init__(self, learning_engine: LearningEngine, hive: BorgHiveCoordinator):
        if not QtWidgets:
            return
        super().__init__()
        self.learning_engine = learning_engine
        self.hive = hive
        self._setup_ui()
        self._start_timer()

    def _setup_ui(self):
        self.setWindowTitle("LAN Guardian Borg Organism v4")
        self.resize(900, 600)

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout()

        self.stats_label = QtWidgets.QLabel("Stats: ")
        self.rules_label = QtWidgets.QLabel("Rules: ")
        self.workers_label = QtWidgets.QLabel("Workers: ")
        self.queen_label = QtWidgets.QLabel(f"Queen: {self.hive.queen.hive_id}")

        layout.addWidget(self.stats_label)
        layout.addWidget(self.rules_label)
        layout.addWidget(self.workers_label)
        layout.addWidget(self.queen_label)

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
        self.stats_label.setText(f"Stats: events={events}")
        self.rules_label.setText(f"Rules: count={rules}")
        self.workers_label.setText(f"Workers: {', '.join(workers) if workers else 'none'}")


# ============================================================
# 12. ORCHESTRATOR (HEADLESS BROWSER MONITOR)
# ============================================================

class HeadlessBrowserMonitor:
    def __init__(self,
                 proc_collector: ProcessTelemetryCollector,
                 net_collector: NetworkTelemetryCollector,
                 learning_engine: LearningEngine,
                 policy_engine: HeadlessBrowserPolicyEngine,
                 hive: BorgHiveCoordinator,
                 node_id: str):
        self.proc_collector = proc_collector
        self.net_collector = net_collector
        self.heuristics = HeadlessBrowserHeuristics()
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
            self._scan_once()
            time.sleep(interval)

    def _scan_once(self):
        processes = self.proc_collector.get_all_processes()
        for proc in processes:
            if "chrome" not in proc.name.lower() and "edge" not in proc.name.lower() and "chromium" not in proc.name.lower():
                continue

            flows = self.net_collector.get_flows_by_pid(proc.pid)
            reasons = self.heuristics.analyze_process(proc)
            reasons.extend(self.heuristics.analyze_network(proc, flows))

            if not reasons:
                continue

            score = self.learning.compute_score(proc, flows, reasons)
            tier = self.policy.decide_tier(score, reasons)

            assessment = BrowserRiskAssessment(
                pid=proc.pid,
                score=score,
                tier=tier,
                reasons=reasons,
                timestamp=time.time()
            )

            self.policy.apply_actions(assessment, proc)
            self.learning.ingest_event(proc, flows, reasons, assessment)

            alert = {
                "pid": proc.pid,
                "name": proc.name,
                "score": score,
                "tier": tier,
                "reasons": reasons,
                "timestamp": assessment.timestamp
            }
            self.hive.submit_alert(self.node_id, alert)


# ============================================================
# 13. GUARDIAN MAIN (NODE MODE)
# ============================================================

def guardian_main(node_id: str, queen_id: str):
    autoloader = AutoLoader()
    proc = ProcessTelemetryCollector(autoloader)
    net = NetworkTelemetryCollector(autoloader)
    ares = ARESRemediationEngine(autoloader)
    policy = HeadlessBrowserPolicyEngine(ares)
    ml_model = HeadlessBrowserMLModel(model_path=MODEL_PATH)
    learning = LearningEngine(ml_model)

    transport = SwarmTransport()
    hive = BorgHiveCoordinator(transport, queen_id)
    hive.register_worker(node_id)
    hive.start()

    monitor = HeadlessBrowserMonitor(proc, net, learning, policy, hive, node_id)
    monitor.start(interval=5.0)

    simulator = SwarmSimulator(learning)
    simulator.start()

    if QtWidgets and QtCore:
        app = QtWidgets.QApplication(sys.argv)
        gui = GuardianGUI(learning, hive)
        gui.show()
        app.exec_()
    else:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("[Guardian] Stopping...")


# ============================================================
# 14. ENTRY POINT (WATCHDOG + GUARDIAN)
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
