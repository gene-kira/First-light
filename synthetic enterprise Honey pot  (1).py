#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
God-Mode AI Honeypot v1
Monolithic architecture with:
- Synthetic personas & activity
- Company + home infrastructure simulation
- Protocol-level deception (SMB/LDAP/Kerberos/SQL/Docker/K8s/cloud metadata)
- Suricata v6 ingestion stubs
- ML anomaly detection (IsolationForest/DBSCAN/Autoencoders stubs)
- LLM reasoning stubs (local + remote)
- Swarm consensus (Raft/Paxos stubs)
- Deception analytics, replay, forensic export
- Chaos morphing, autonomous evolution
"""

import os
import sys
import time
import json
import random
import socket
import threading
import queue
import uuid
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any, List, Optional, Tuple

# =========================
# Global Config & Utilities
# =========================

class Config:
    VERSION = "god-honeypot-v1"
    NODE_ID = str(uuid.uuid4())
    SWARM_CLUSTER_ID = "swarm-godnet"
    LISTEN_HOST = "0.0.0.0"
    BASE_PORT = 45000
    RANDOM_PORT_RANGE = (20000, 60000)
    PERSONA_COUNT = 50
    ACTIVITY_INTERVAL_RANGE = (5, 60)  # seconds
    LOG_DIR = "./honeypot_logs"
    REPLAY_DIR = "./honeypot_replay"
    FORENSIC_DIR = "./honeypot_forensics"
    STATE_FILE = "./honeypot_state.json"
    SURICATA_PCAP_DIR = "./suricata_pcap"
    GUI_ENABLED = True
    LLM_LOCAL_MODEL_PATH = "./models/local_llm_stub"
    LLM_REMOTE_ENDPOINT = "https://llm-remote-api.example.com"
    SWARM_PEERS = []  # list of (host, port) for other nodes


def ensure_dirs():
    for d in [Config.LOG_DIR, Config.REPLAY_DIR, Config.FORENSIC_DIR, Config.SURICATA_PCAP_DIR]:
        os.makedirs(d, exist_ok=True)


def log_event(component: str, level: str, message: str, extra: Optional[Dict[str, Any]] = None):
    ensure_dirs()
    ts = datetime.datetime.utcnow().isoformat()
    entry = {
        "ts": ts,
        "component": component,
        "level": level,
        "message": message,
        "extra": extra or {},
        "node_id": Config.NODE_ID,
    }
    line = json.dumps(entry)
    print(line)
    with open(os.path.join(Config.LOG_DIR, f"{component}.log"), "a", encoding="utf-8") as f:
        f.write(line + "\n")


def random_port() -> int:
    return random.randint(*Config.RANDOM_PORT_RANGE)


# =========================
# Synthetic Personas Engine
# =========================

class Persona:
    def __init__(self, persona_id: str, profile: Dict[str, Any]):
        self.persona_id = persona_id
        self.profile = profile
        self.state = {
            "last_login": None,
            "last_activity": None,
            "files_touched": [],
            "credentials_used": [],
        }

    def simulate_activity(self):
        now = datetime.datetime.utcnow().isoformat()
        self.state["last_activity"] = now
        activity_type = random.choice([
            "web_browsing", "file_edit", "email_read", "chat_message",
            "vpn_login", "shadow_it", "password_change"
        ])
        log_event("persona", "INFO", f"Persona {self.persona_id} activity: {activity_type}", {
            "persona": self.profile,
            "activity_type": activity_type,
        })


class PersonaEngine:
    def __init__(self, count: int):
        self.personas: Dict[str, Persona] = {}
        self.count = count
        self._init_personas()

    def _init_personas(self):
        for i in range(self.count):
            pid = f"persona-{i}-{uuid.uuid4().hex[:8]}"
            profile = {
                "name": f"User{i}",
                "role": random.choice(["HR", "Finance", "DevOps", "IT", "Sales", "HomeUser"]),
                "email": f"user{i}@fakecorp.local",
                "habits": {
                    "browsing": random.choice(["heavy", "moderate", "light"]),
                    "work_hours": random.choice(["9-5", "flex", "night"]),
                    "shadow_it": random.choice([True, False]),
                },
                "password_quality": random.choice(["weak", "medium", "strong"]),
            }
            self.personas[pid] = Persona(pid, profile)
        log_event("persona_engine", "INFO", "Initialized personas", {"count": self.count})

    def run_loop(self, stop_event: threading.Event):
        while not stop_event.is_set():
            for persona in self.personas.values():
                if random.random() < 0.5:
                    persona.simulate_activity()
            interval = random.randint(*Config.ACTIVITY_INTERVAL_RANGE)
            time.sleep(interval)


# =========================
# Network Activity Simulator
# =========================

class NetworkActivitySimulator:
    def __init__(self):
        self.activities = [
            "dns_lookup", "web_browse", "software_update", "smb_internal",
            "printer_traffic", "iot_chatter", "background_noise"
        ]

    def simulate_once(self):
        activity = random.choice(self.activities)
        log_event("net_sim", "INFO", f"Simulated network activity: {activity}", {})

    def run_loop(self, stop_event: threading.Event):
        while not stop_event.is_set():
            self.simulate_once()
            interval = random.randint(*Config.ACTIVITY_INTERVAL_RANGE)
            time.sleep(interval)


# =========================
# Fake Infrastructure & Data
# =========================

class FakeDataStore:
    def __init__(self):
        self.files: Dict[str, str] = {}
        self.credentials: Dict[str, str] = {}
        self.cloud_metadata: Dict[str, Any] = {}
        self.sql_databases: Dict[str, Dict[str, Any]] = {}
        self.smb_shares: Dict[str, List[str]] = {}
        self.docker_containers: Dict[str, Dict[str, Any]] = {}
        self.k8s_objects: Dict[str, Dict[str, Any]] = {}
        self.ad_domain: Dict[str, Any] = {}
        self.vpn_gateways: Dict[str, Any] = {}
        self.fake_events: List[Dict[str, Any]] = []
        self._init_fake_world()

    def _init_fake_world(self):
        # Fake files
        for i in range(100):
            path = f"/fakecorp/docs/doc_{i}.txt"
            content = f"Confidential document {i} - salary, HR, finance, secrets..."
            self.files[path] = content

        # Fake credentials
        for i in range(50):
            user = f"user{i}"
            pwd = random.choice(["Password123", "Summer2025!", "qwerty", "letmein", "Admin!234"])
            self.credentials[user] = pwd

        # Fake cloud metadata
        self.cloud_metadata = {
            "instance-id": "i-fake123456",
            "region": "us-fake-1",
            "project": "fakecorp-god-honeypot",
            "service-accounts": ["svc-hr", "svc-finance", "svc-devops"],
        }

        # Fake SQL databases
        self.sql_databases["hr_db"] = {
            "employees": [{"id": i, "name": f"Employee{i}", "salary": random.randint(50000, 150000)}
                          for i in range(100)]
        }

        # Fake SMB shares
        self.smb_shares["HR$"] = ["/fakecorp/docs/hr_payroll.xlsx", "/fakecorp/docs/hr_reviews.docx"]
        self.smb_shares["FINANCE$"] = ["/fakecorp/docs/fin_budget.xlsx"]

        # Fake Docker containers
        for i in range(10):
            cid = f"container-{i}"
            self.docker_containers[cid] = {
                "image": random.choice(["nginx:latest", "redis:7", "postgres:15", "custom-app:v1"]),
                "status": random.choice(["running", "stopped"]),
                "ports": [random_port()],
            }

        # Fake K8s objects
        self.k8s_objects["deployments"] = [{"name": f"app-{i}", "replicas": random.randint(1, 5)}
                                           for i in range(5)]
        self.k8s_objects["services"] = [{"name": f"svc-{i}", "port": random_port()}
                                        for i in range(5)]

        # Fake AD domain
        self.ad_domain = {
            "name": "FAKECORP.LOCAL",
            "users": [f"user{i}" for i in range(100)],
            "groups": ["Domain Admins", "HR", "Finance", "IT", "DevOps"],
        }

        # Fake VPN gateways
        self.vpn_gateways["corp-vpn"] = {
            "endpoint": "vpn.fakecorp.local",
            "users": [f"user{i}" for i in range(50)],
        }

        log_event("fake_data", "INFO", "Initialized fake data world", {})

    def generate_fake_event(self, category: str, detail: Dict[str, Any]):
        ev = {
            "id": str(uuid.uuid4()),
            "ts": datetime.datetime.utcnow().isoformat(),
            "category": category,
            "detail": detail,
        }
        self.fake_events.append(ev)
        log_event("fake_data", "INFO", f"Generated fake event {category}", detail)


# =========================
# Protocol Emulation Stubs
# =========================

class FakeSMBServer:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port

    def start(self):
        log_event("smb", "INFO", f"Fake SMB server listening on port {self.port}", {})


class FakeLDAPServer:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port

    def start(self):
        log_event("ldap", "INFO", f"Fake LDAP server listening on port {self.port}", {})


class FakeKerberosKDC:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port

    def start(self):
        log_event("kerberos", "INFO", f"Fake Kerberos KDC listening on port {self.port}", {})


class FakeSQLListener:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port

    def start(self):
        log_event("sql", "INFO", f"Fake SQL listener on port {self.port}", {})


class FakeDockerAPI:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port

    def start(self):
        log_event("docker_api", "INFO", f"Fake Docker API on port {self.port}", {})


class FakeK8sAPI:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port

    def start(self):
        log_event("k8s_api", "INFO", f"Fake K8s API on port {self.port}", {})


class CloudMetadataHandler(BaseHTTPRequestHandler):
    datastore: FakeDataStore = None  # injected

    def do_GET(self):
        path = self.path.strip("/")
        if path in CloudMetadataHandler.datastore.cloud_metadata:
            value = CloudMetadataHandler.datastore.cloud_metadata[path]
        else:
            value = {"error": "unknown metadata key"}
        body = json.dumps(value).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)
        log_event("cloud_metadata", "INFO", f"Served metadata key {path}", {})


class FakeCloudMetadataServer:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port
        CloudMetadataHandler.datastore = datastore

    def start(self):
        server = HTTPServer((Config.LISTEN_HOST, self.port), CloudMetadataHandler)
        log_event("cloud_metadata", "INFO", f"Fake cloud metadata server on port {self.port}", {})
        threading.Thread(target=server.serve_forever, daemon=True).start()


# =========================
# Cowrie-Style Shell Stub
# =========================

class FakeShellSession:
    def __init__(self, session_id: str, datastore: FakeDataStore):
        self.session_id = session_id
        self.datastore = datastore
        self.cwd = "/"
        self.history: List[str] = []

    def handle_command(self, cmd: str) -> str:
        self.history.append(cmd)
        log_event("shell", "INFO", f"Session {self.session_id} command: {cmd}", {})
        if cmd.startswith("ls"):
            return "\n".join(list(self.datastore.files.keys())[:10])
        elif cmd.startswith("cat "):
            path = cmd.split(" ", 1)[1]
            return self.datastore.files.get(path, "No such file")
        elif cmd.startswith("pwd"):
            return self.cwd
        else:
            return f"Command '{cmd}' not implemented in fake shell."


# =========================
# Suricata v6 Integration Stubs
# =========================

class SuricataIntegration:
    def __init__(self, pcap_dir: str):
        self.pcap_dir = pcap_dir
        self.rules_loaded = False

    def load_rules(self, rules_path: str):
        # Stub: pretend to load rules
        self.rules_loaded = True
        log_event("suricata", "INFO", f"Loaded Suricata rules from {rules_path}", {})

    def ingest_pcap(self, pcap_file: str):
        # Stub: pretend to ingest PCAP
        log_event("suricata", "INFO", f"Ingested PCAP {pcap_file}", {})

    def analyze_packet_stream(self):
        # Stub: pretend to analyze
        log_event("suricata", "INFO", "Analyzed packet stream (stub)", {})


# =========================
# ML Engine (Stubs)
# =========================

class MLEngine:
    def __init__(self):
        self.models = {
            "isolation_forest": None,
            "dbscan": None,
            "autoencoder": None,
        }

    def train_stub_models(self):
        log_event("ml", "INFO", "Training stub ML models (IsolationForest/DBSCAN/Autoencoder)", {})
        self.models["isolation_forest"] = "trained_stub"
        self.models["dbscan"] = "trained_stub"
        self.models["autoencoder"] = "trained_stub"

    def score_behavior(self, features: Dict[str, Any]) -> Dict[str, Any]:
        score = random.random()
        label = "benign" if score < 0.7 else "suspicious"
        log_event("ml", "INFO", "Scored behavior", {"score": score, "label": label})
        return {"score": score, "label": label}


# =========================
# LLM Integration (Stubs)
# =========================

class LLMEngine:
    def __init__(self, local_model_path: str, remote_endpoint: str):
        self.local_model_path = local_model_path
        self.remote_endpoint = remote_endpoint
        self.local_loaded = False

    def load_local_model(self):
        # Stub: pretend to load
        self.local_loaded = True
        log_event("llm", "INFO", f"Loaded local LLM from {self.local_model_path}", {})

    def analyze_process(self, process_info: Dict[str, Any]) -> str:
        # Stub: simple reasoning
        desc = f"Process {process_info.get('name')} appears {'benign' if random.random() < 0.5 else 'suspicious'}."
        log_event("llm", "INFO", "LLM process analysis", {"process": process_info, "desc": desc})
        return desc

    def generate_deception_strategy(self, attacker_profile: Dict[str, Any]) -> Dict[str, Any]:
        strategy = {
            "create_fake_vuln": True,
            "fake_files_to_add": [f"/fakecorp/traps/trap_{uuid.uuid4().hex[:6]}.log"],
            "fake_credentials_to_leak": [random.choice(["admin", "svc-hr", "svc-devops"])],
        }
        log_event("llm", "INFO", "Generated deception strategy", {"attacker": attacker_profile, "strategy": strategy})
        return strategy


# =========================
# Swarm Consensus (Stubs)
# =========================

class SwarmConsensus:
    def __init__(self, node_id: str, peers: List[Tuple[str, int]]):
        self.node_id = node_id
        self.peers = peers
        self.leader_id: Optional[str] = None
        self.state_version = 0

    def start(self):
        log_event("swarm", "INFO", "Swarm consensus started (Raft/Paxos stub)", {
            "node_id": self.node_id,
            "peers": self.peers,
        })

    def propose_state_update(self, update: Dict[str, Any]):
        self.state_version += 1
        log_event("swarm", "INFO", "Proposed state update", {"version": self.state_version, "update": update})

    def enforce_policy(self, policy: Dict[str, Any]):
        log_event("swarm", "INFO", "Enforced swarm-wide policy", {"policy": policy})


# =========================
# Deception Analytics & Replay
# =========================

class DeceptionAnalytics:
    def __init__(self):
        self.attacker_events: List[Dict[str, Any]] = []

    def record_attacker_event(self, ev: Dict[str, Any]):
        self.attacker_events.append(ev)
        log_event("analytics", "INFO", "Recorded attacker event", ev)

    def export_forensics(self):
        ensure_dirs()
        path = os.path.join(Config.FORENSIC_DIR, f"forensics_{int(time.time())}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.attacker_events, f, indent=2)
        log_event("analytics", "INFO", "Exported forensics", {"path": path})

    def build_timeline(self) -> List[Dict[str, Any]]:
        timeline = sorted(self.attacker_events, key=lambda e: e.get("ts", ""))
        log_event("analytics", "INFO", "Built attacker timeline", {"count": len(timeline)})
        return timeline

    def save_replay(self):
        ensure_dirs()
        path = os.path.join(Config.REPLAY_DIR, f"replay_{int(time.time())}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.attacker_events, f, indent=2)
        log_event("analytics", "INFO", "Saved replay", {"path": path})


# =========================
# Chaos Morphing & Topology
# =========================

class ChaosMorpher:
    def __init__(self, datastore: FakeDataStore):
        self.datastore = datastore
        self.current_topology_version = 0

    def mutate_topology(self):
        self.current_topology_version += 1
        # Randomly add/remove fake services, files, credentials
        if random.random() < 0.5:
            new_file = f"/fakecorp/morph/mutated_{uuid.uuid4().hex[:6]}.txt"
            self.datastore.files[new_file] = "Dynamic fake content"
        if random.random() < 0.5:
            user = f"morph_user_{uuid.uuid4().hex[:4]}"
            pwd = "MorphPass!123"
            self.datastore.credentials[user] = pwd
        log_event("chaos", "INFO", "Mutated topology", {"version": self.current_topology_version})

    def run_loop(self, stop_event: threading.Event):
        while not stop_event.is_set():
            self.mutate_topology()
            time.sleep(random.randint(30, 120))


# =========================
# Rogue Detection & Classifier
# =========================

class RogueDetector:
    def __init__(self, ml_engine: MLEngine, llm_engine: LLMEngine, analytics: DeceptionAnalytics):
        self.ml_engine = ml_engine
        self.llm_engine = llm_engine
        self.analytics = analytics
        self.whitelist: List[str] = ["system", "trusted_service"]
        self.rogue_processes: Dict[str, Dict[str, Any]] = {}

    def analyze_process(self, proc: Dict[str, Any]):
        features = {
            "name": proc.get("name"),
            "cpu": proc.get("cpu", random.random()),
            "net": proc.get("net", random.random()),
        }
        ml_result = self.ml_engine.score_behavior(features)
        llm_desc = self.llm_engine.analyze_process(proc)
        is_rogue = ml_result["label"] == "suspicious" and proc.get("name") not in self.whitelist
        if is_rogue:
            pid = proc.get("pid", str(uuid.uuid4()))
            self.rogue_processes[pid] = proc
            self.analytics.record_attacker_event({
                "ts": datetime.datetime.utcnow().isoformat(),
                "type": "rogue_process",
                "proc": proc,
                "ml_score": ml_result,
                "llm_desc": llm_desc,
            })
            log_event("rogue", "WARN", "Detected rogue process", {"proc": proc, "ml": ml_result, "llm": llm_desc})

    def rollback_whitelist(self):
        self.whitelist = ["system", "trusted_service"]
        log_event("rogue", "INFO", "Whitelist rollback", {})


# =========================
# GUI Stub (SOC Dashboard)
# =========================

class GUIConsole:
    def __init__(self, analytics: DeceptionAnalytics, persona_engine: PersonaEngine):
        self.analytics = analytics
        self.persona_engine = persona_engine

    def render_once(self):
        # Stub: print summary
        timeline = self.analytics.build_timeline()
        log_event("gui", "INFO", "GUI render", {
            "attacker_events": len(timeline),
            "personas": len(self.persona_engine.personas),
        })


# =========================
# Honeypot Core Orchestrator
# =========================

class HoneypotCore:
    def __init__(self):
        ensure_dirs()
        self.datastore = FakeDataStore()
        self.persona_engine = PersonaEngine(Config.PERSONA_COUNT)
        self.net_sim = NetworkActivitySimulator()
        self.suricata = SuricataIntegration(Config.SURICATA_PCAP_DIR)
        self.ml_engine = MLEngine()
        self.llm_engine = LLMEngine(Config.LLM_LOCAL_MODEL_PATH, Config.LLM_REMOTE_ENDPOINT)
        self.analytics = DeceptionAnalytics()
        self.swarm = SwarmConsensus(Config.NODE_ID, Config.SWARM_PEERS)
        self.chaos = ChaosMorpher(self.datastore)
        self.rogue_detector = RogueDetector(self.ml_engine, self.llm_engine, self.analytics)
        self.gui = GUIConsole(self.analytics, self.persona_engine)
        self.stop_event = threading.Event()
        self.threads: List[threading.Thread] = []

        # Protocol servers
        self.smb_server = FakeSMBServer(self.datastore, random_port())
        self.ldap_server = FakeLDAPServer(self.datastore, random_port())
        self.kerberos_kdc = FakeKerberosKDC(self.datastore, random_port())
        self.sql_listener = FakeSQLListener(self.datastore, random_port())
        self.docker_api = FakeDockerAPI(self.datastore, random_port())
        self.k8s_api = FakeK8sAPI(self.datastore, random_port())
        self.cloud_metadata_server = FakeCloudMetadataServer(self.datastore, random_port())

    def start_protocols(self):
        self.smb_server.start()
        self.ldap_server.start()
        self.kerberos_kdc.start()
        self.sql_listener.start()
        self.docker_api.start()
        self.k8s_api.start()
        self.cloud_metadata_server.start()

    def start_ml_llm(self):
        self.ml_engine.train_stub_models()
        self.llm_engine.load_local_model()

    def start_swarm(self):
        self.swarm.start()

    def start_background_loops(self):
        # Personas
        t_persona = threading.Thread(target=self.persona_engine.run_loop, args=(self.stop_event,), daemon=True)
        t_persona.start()
        self.threads.append(t_persona)

        # Network sim
        t_net = threading.Thread(target=self.net_sim.run_loop, args=(self.stop_event,), daemon=True)
        t_net.start()
        self.threads.append(t_net)

        # Chaos morphing
        t_chaos = threading.Thread(target=self.chaos.run_loop, args=(self.stop_event,), daemon=True)
        t_chaos.start()
        self.threads.append(t_chaos)

        log_event("core", "INFO", "Background loops started", {})

    def simulate_attacker_interaction(self):
        # Stub: create fake shell session and run commands
        shell = FakeShellSession(str(uuid.uuid4()), self.datastore)
        for cmd in ["pwd", "ls", "cat /fakecorp/docs/doc_1.txt"]:
            out = shell.handle_command(cmd)
            self.analytics.record_attacker_event({
                "ts": datetime.datetime.utcnow().isoformat(),
                "type": "shell_cmd",
                "cmd": cmd,
                "output": out,
            })

        # Simulate rogue process detection
        proc = {"name": "evil_miner", "pid": 9999, "cpu": 0.9, "net": 0.8}
        self.rogue_detector.analyze_process(proc)

    def autonomous_evolution(self):
        # Stub: generate new personas, fake companies, vulnerabilities
        new_persona_id = f"persona-evo-{uuid.uuid4().hex[:6]}"
        self.persona_engine.personas[new_persona_id] = Persona(new_persona_id, {
            "name": "EvoUser",
            "role": "ShadowIT",
            "email": "evo@fakecorp.local",
            "habits": {"browsing": "heavy", "work_hours": "night", "shadow_it": True},
            "password_quality": "weak",
        })
        self.datastore.generate_fake_event("evolution", {"new_persona": new_persona_id})
        self.chaos.mutate_topology()
        self.swarm.propose_state_update({"evolution": True})

    def run_gui_loop(self):
        while not self.stop_event.is_set():
            self.gui.render_once()
            time.sleep(10)

    def start_gui(self):
        if Config.GUI_ENABLED:
            t_gui = threading.Thread(target=self.run_gui_loop, daemon=True)
            t_gui.start()
            self.threads.append(t_gui)
            log_event("core", "INFO", "GUI loop started", {})

    def save_state(self):
        state = {
            "version": Config.VERSION,
            "node_id": Config.NODE_ID,
            "topology_version": self.chaos.current_topology_version,
            "personas": list(self.persona_engine.personas.keys()),
        }
        with open(Config.STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        log_event("core", "INFO", "Saved honeypot state", {"path": Config.STATE_FILE})

    def main_loop(self):
        log_event("core", "INFO", "Honeypot main loop started", {})
        try:
            while not self.stop_event.is_set():
                # Periodically simulate attacker interaction & evolution
                self.simulate_attacker_interaction()
                self.autonomous_evolution()
                # Deception analytics maintenance
                self.analytics.save_replay()
                self.analytics.export_forensics()
                # Swarm policy enforcement stub
                self.swarm.enforce_policy({"rogue_processes": list(self.rogue_detector.rogue_processes.keys())})
                # Sleep before next cycle
                time.sleep(30)
        except KeyboardInterrupt:
            log_event("core", "INFO", "KeyboardInterrupt received, stopping honeypot", {})
        finally:
            self.stop_event.set()
            self.save_state()
            log_event("core", "INFO", "Honeypot stopped", {})


def main():
    log_event("bootstrap", "INFO", "Starting God-Mode Honeypot", {"version": Config.VERSION})
    core = HoneypotCore()
    core.start_protocols()
    core.start_ml_llm()
    core.start_swarm()
    core.start_background_loops()
    core.start_gui()
    core.main_loop()


if __name__ == "__main__":
    main()
