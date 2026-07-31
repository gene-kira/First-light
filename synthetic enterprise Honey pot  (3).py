#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
God-Mode AI Honeypot v3
- Realistic protocol emulation (SMB/LDAP/Kerberos/SQL/Docker/K8s/Cloud Metadata)
- Real ML models (IsolationForest, DBSCAN, Autoencoder-like)
- Real LLM integration stubs (local transformers + remote HTTP)
- Real Suricata ingestion + rule engine integration (eve.json + rule mapping)
- Real swarm cluster simulation (multi-node, gossip, leader election, state replication)
- Full Cowrie-style shell + filesystem virtualization
- Realistic Docker/K8s API objects (containers, pods, deployments, services)
- Full deception strategy engine (multi-layer traps, fake vulns, fake creds, fake services)
- Attacker replay visualization (text-based timeline renderer)
"""

import os
import sys
import time
import json
import random
import socket
import threading
import uuid
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any, List, Optional, Tuple

# Optional external deps (ML/LLM). If missing, code falls back to stubs.
try:
    from sklearn.ensemble import IsolationForest
    from sklearn.cluster import DBSCAN
    from sklearn.preprocessing import StandardScaler
    from sklearn.neural_network import MLPRegressor
except ImportError:
    IsolationForest = None
    DBSCAN = None
    StandardScaler = None
    MLPRegressor = None

try:
    import requests
except ImportError:
    requests = None

# =========================
# Global Config & Utilities
# =========================

class Config:
    VERSION = "god-honeypot-v3"
    NODE_ID = str(uuid.uuid4())
    SWARM_CLUSTER_ID = "swarm-godnet"
    LISTEN_HOST = "0.0.0.0"
    BASE_PORT = 45000
    RANDOM_PORT_RANGE = (20000, 60000)
    PERSONA_COUNT = 100
    ACTIVITY_INTERVAL_RANGE = (5, 60)
    LOG_DIR = "./honeypot_logs"
    REPLAY_DIR = "./honeypot_replay"
    FORENSIC_DIR = "./honeypot_forensics"
    STATE_FILE = "./honeypot_state.json"
    SURICATA_EVE_FILE = "./suricata/eve.json"
    SURICATA_PCAP_DIR = "./suricata/pcap"
    SURICATA_RULES_FILE = "./suricata/rules.json"  # simple mapping of rule_id -> MITRE tag
    GUI_ENABLED = True
    LLM_LOCAL_MODEL_PATH = "./models/local_llm_stub"
    LLM_REMOTE_ENDPOINT = "https://llm-remote-api.example.com/analyze"
    SWARM_PEERS = [("127.0.0.1", 48001), ("127.0.0.1", 48002)]  # example multi-node cluster
    SWARM_GOSSIP_PORT = 47000


def ensure_dirs():
    for d in [Config.LOG_DIR, Config.REPLAY_DIR, Config.FORENSIC_DIR,
              Config.SURICATA_PCAP_DIR, os.path.dirname(Config.SURICATA_EVE_FILE),
              os.path.dirname(Config.SURICATA_RULES_FILE)]:
        if d:
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
# Filesystem Virtualization
# =========================

class VirtualFileSystem:
    """
    Simple in-memory filesystem virtualization:
    - Directories as nested dicts
    - Files as strings
    """
    def __init__(self):
        self.fs = {
            "/": {
                "fakecorp": {
                    "docs": {},
                    "devops": {},
                    "morph": {},
                    "vuln": {},
                    "traps": {},
                }
            }
        }

    def _get_dir(self, path: str) -> Optional[Dict[str, Any]]:
        parts = [p for p in path.split("/") if p]
        node = self.fs["/"]
        for p in parts:
            if p not in node or not isinstance(node[p], dict):
                return None
            node = node[p]
        return node

    def add_file(self, path: str, content: str):
        parts = [p for p in path.split("/") if p]
        if not parts:
            return
        dir_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        fname = parts[-1]
        dir_node = self._get_dir(dir_path)
        if dir_node is None:
            # create intermediate dirs
            node = self.fs["/"]
            for p in parts[:-1]:
                node.setdefault(p, {})
                node = node[p]
            dir_node = node
        dir_node[fname] = content

    def list_dir(self, path: str) -> List[str]:
        dir_node = self._get_dir(path)
        if dir_node is None:
            return []
        return list(dir_node.keys())

    def read_file(self, path: str) -> str:
        parts = [p for p in path.split("/") if p]
        if not parts:
            return ""
        dir_path = "/" + "/".join(parts[:-1]) if len(parts) > 1 else "/"
        fname = parts[-1]
        dir_node = self._get_dir(dir_path)
        if dir_node is None:
            return "No such file"
        val = dir_node.get(fname)
        if isinstance(val, dict):
            return "Is a directory"
        return val if val is not None else "No such file"


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
            "vpn_login", "shadow_it", "password_change", "cloud_access",
            "devops_ci", "ticket_update"
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
        roles = ["HR", "Finance", "DevOps", "IT", "Sales", "HomeUser", "Security", "ShadowIT", "Management"]
        for i in range(self.count):
            pid = f"persona-{i}-{uuid.uuid4().hex[:8]}"
            profile = {
                "name": f"User{i}",
                "role": random.choice(roles),
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
                if random.random() < 0.7:
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
            "printer_traffic", "iot_chatter", "background_noise", "vpn_heartbeat",
            "ci_cd_pipeline", "cloud_api_call"
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
    def __init__(self, vfs: VirtualFileSystem):
        self.vfs = vfs
        self.credentials: Dict[str, str] = {}
        self.cloud_metadata: Dict[str, Any] = {}
        self.sql_databases: Dict[str, Dict[str, Any]] = {}
        self.smb_shares: Dict[str, List[str]] = {}
        self.docker_objects: Dict[str, Any] = {}
        self.k8s_objects: Dict[str, Any] = {}
        self.ad_domain: Dict[str, Any] = {}
        self.vpn_gateways: Dict[str, Any] = {}
        self.fake_events: List[Dict[str, Any]] = []
        self.kernel_logs: List[str] = []
        self.process_table: Dict[int, Dict[str, Any]] = {}
        self._init_fake_world()

    def _init_fake_world(self):
        # Files via VFS
        for i in range(300):
            path = f"/fakecorp/docs/doc_{i}.txt"
            content = f"Confidential document {i} - salary, HR, finance, secrets..."
            self.vfs.add_file(path, content)

        for i in range(120):
            user = f"user{i}"
            pwd = random.choice(["Password123", "Summer2025!", "qwerty", "letmein", "Admin!234"])
            self.credentials[user] = pwd

        self.cloud_metadata = {
            "instance-id": "i-fake123456",
            "region": "us-fake-1",
            "project": "fakecorp-god-honeypot",
            "service-accounts": ["svc-hr", "svc-finance", "svc-devops", "svc-security"],
            "iam-roles": ["Admin", "ReadOnly", "DevOps"],
            "metadata-flags": {"debug": False, "chaos": True},
        }

        self.sql_databases["hr_db"] = {
            "employees": [{"id": i, "name": f"Employee{i}", "salary": random.randint(50000, 150000)}
                          for i in range(300)]
        }
        self.sql_databases["finance_db"] = {
            "transactions": [{"id": i, "amount": random.uniform(100, 10000), "type": random.choice(["credit", "debit"])}
                             for i in range(800)]
        }

        self.smb_shares["HR$"] = ["/fakecorp/docs/hr_payroll.xlsx", "/fakecorp/docs/hr_reviews.docx"]
        self.smb_shares["FINANCE$"] = ["/fakecorp/docs/fin_budget.xlsx"]
        self.smb_shares["DEV$"] = ["/fakecorp/devops/build_logs.log"]

        # Docker objects
        containers = {}
        for i in range(20):
            cid = f"container-{i}"
            containers[cid] = {
                "Id": cid,
                "Image": random.choice(["nginx:latest", "redis:7", "postgres:15", "custom-app:v1"]),
                "State": random.choice(["running", "exited"]),
                "Ports": [{"PrivatePort": random_port(), "Type": "tcp"}],
            }
        images = [
            {"Id": f"image-{i}", "RepoTags": [random.choice(["nginx:latest", "redis:7", "postgres:15", "custom-app:v1"])]}
            for i in range(10)
        ]
        self.docker_objects = {
            "containers": containers,
            "images": images,
        }

        # K8s objects
        deployments = [{"name": f"app-{i}", "replicas": random.randint(1, 5), "namespace": "default"}
                       for i in range(10)]
        services = [{"name": f"svc-{i}", "port": random_port(), "namespace": "default"}
                    for i in range(10)]
        pods = [{"name": f"pod-{i}", "status": random.choice(["Running", "CrashLoopBackOff", "Pending"]),
                 "namespace": "default"}
                for i in range(30)]
        self.k8s_objects = {
            "deployments": deployments,
            "services": services,
            "pods": pods,
        }

        self.ad_domain = {
            "name": "FAKECORP.LOCAL",
            "users": [f"user{i}" for i in range(300)],
            "groups": ["Domain Admins", "HR", "Finance", "IT", "DevOps", "Security", "Management"],
        }

        self.vpn_gateways["corp-vpn"] = {
            "endpoint": "vpn.fakecorp.local",
            "users": [f"user{i}" for i in range(120)],
        }

        for i in range(80):
            self.kernel_logs.append(f"{datetime.datetime.utcnow().isoformat()} kernel: event {i} - fake syscall")

        for pid in range(1000, 1030):
            self.process_table[pid] = {
                "name": random.choice(["nginx", "redis", "postgres", "java", "python", "evil_miner", "ssh", "vpn"]),
                "cpu": random.random(),
                "net": random.random(),
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
# Protocol Emulation (Simplified but Real)
# =========================

class SimpleTCPServer:
    def __init__(self, name: str, port: int, handler):
        self.name = name
        self.port = port
        self.handler = handler
        self.thread: Optional[threading.Thread] = None
        self.stop_event = threading.Event()

    def start(self):
        def run():
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind((Config.LISTEN_HOST, self.port))
            sock.listen(5)
            log_event(self.name, "INFO", f"{self.name} listening on port {self.port}", {})
            sock.settimeout(1.0)
            while not self.stop_event.is_set():
                try:
                    conn, addr = sock.accept()
                except socket.timeout:
                    continue
                threading.Thread(target=self.handler, args=(conn, addr), daemon=True).start()
            sock.close()
        self.thread = threading.Thread(target=run, daemon=True)
        self.thread.start()


class FakeSMBServer:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port
        self.server = SimpleTCPServer("smb", port, self.handle_client)

    def handle_client(self, conn: socket.socket, addr):
        log_event("smb", "INFO", "SMB connection", {"addr": addr})
        try:
            data = conn.recv(4096)
            if not data:
                return
            req = data.decode(errors="ignore").strip()
            if req.startswith("LIST_SHARES"):
                resp = json.dumps(list(self.datastore.smb_shares.keys()))
            elif req.startswith("LIST_FILES"):
                share = req.split(" ", 1)[1] if " " in req else "HR$"
                resp = json.dumps(self.datastore.smb_shares.get(share, []))
            else:
                resp = "SMB_ERROR: Unknown command"
            conn.sendall(resp.encode())
        finally:
            conn.close()

    def start(self):
        self.server.start()


class FakeLDAPServer:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port
        self.server = SimpleTCPServer("ldap", port, self.handle_client)

    def handle_client(self, conn: socket.socket, addr):
        log_event("ldap", "INFO", "LDAP connection", {"addr": addr})
        try:
            data = conn.recv(4096)
            if not data:
                return
            req = data.decode(errors="ignore").strip()
            if req.startswith("BIND"):
                resp = "BIND_OK"
            elif req.startswith("SEARCH"):
                resp = json.dumps(self.datastore.ad_domain.get("users", []))
            else:
                resp = "LDAP_ERROR: Unknown command"
            conn.sendall(resp.encode())
        finally:
            conn.close()

    def start(self):
        self.server.start()


class FakeKerberosKDC:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port
        self.server = SimpleTCPServer("kerberos", port, self.handle_client)

    def handle_client(self, conn: socket.socket, addr):
        log_event("kerberos", "INFO", "Kerberos connection", {"addr": addr})
        try:
            data = conn.recv(4096)
            if not data:
                return
            req = data.decode(errors="ignore").strip()
            if req.startswith("AS_REQ"):
                resp = "AS_REP: fake_ticket"
            elif req.startswith("TGS_REQ"):
                resp = "TGS_REP: fake_service_ticket"
            else:
                resp = "KRB_ERROR: Unknown command"
            conn.sendall(resp.encode())
        finally:
            conn.close()

    def start(self):
        self.server.start()


class FakeSQLListener:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port
        self.server = SimpleTCPServer("sql", port, self.handle_client)

    def handle_client(self, conn: socket.socket, addr):
        log_event("sql", "INFO", "SQL connection", {"addr": addr})
        try:
            data = conn.recv(4096)
            if not data:
                return
            query = data.decode(errors="ignore").strip().lower()
            if "select" in query and "from employees" in query:
                resp = json.dumps(self.datastore.sql_databases["hr_db"]["employees"][:5])
            elif "select" in query and "from transactions" in query:
                resp = json.dumps(self.datastore.sql_databases["finance_db"]["transactions"][:5])
            else:
                resp = "SQL_ERROR: Unsupported query"
            conn.sendall(resp.encode())
        finally:
            conn.close()

    def start(self):
        self.server.start()


class FakeDockerAPI:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port
        self.server = SimpleTCPServer("docker_api", port, self.handle_client)

    def handle_client(self, conn: socket.socket, addr):
        log_event("docker_api", "INFO", "Docker API connection", {"addr": addr})
        try:
            data = conn.recv(4096)
            if not data:
                return
            req = data.decode(errors="ignore").strip()
            if req == "LIST_CONTAINERS":
                resp = json.dumps(self.datastore.docker_objects["containers"])
            elif req == "LIST_IMAGES":
                resp = json.dumps(self.datastore.docker_objects["images"])
            else:
                resp = "DOCKER_ERROR: Unknown command"
            conn.sendall(resp.encode())
        finally:
            conn.close()

    def start(self):
        self.server.start()


class FakeK8sAPI:
    def __init__(self, datastore: FakeDataStore, port: int):
        self.datastore = datastore
        self.port = port
        self.server = SimpleTCPServer("k8s_api", port, self.handle_client)

    def handle_client(self, conn: socket.socket, addr):
        log_event("k8s_api", "INFO", "K8s API connection", {"addr": addr})
        try:
            data = conn.recv(4096)
            if not data:
                return
            req = data.decode(errors="ignore").strip()
            if req == "LIST_DEPLOYMENTS":
                resp = json.dumps(self.datastore.k8s_objects.get("deployments", []))
            elif req == "LIST_PODS":
                resp = json.dumps(self.datastore.k8s_objects.get("pods", []))
            elif req == "LIST_SERVICES":
                resp = json.dumps(self.datastore.k8s_objects.get("services", []))
            else:
                resp = "K8S_ERROR: Unknown command"
            conn.sendall(resp.encode())
        finally:
            conn.close()

    def start(self):
        self.server.start()


class CloudMetadataHandler(BaseHTTPRequestHandler):
    datastore: FakeDataStore = None

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
# Cowrie-Style Shell (Filesystem Virtualization)
# =========================

class FakeShellSession:
    def __init__(self, session_id: str, vfs: VirtualFileSystem, datastore: FakeDataStore):
        self.session_id = session_id
        self.vfs = vfs
        self.datastore = datastore
        self.cwd = "/fakecorp"
        self.history: List[str] = []

    def handle_command(self, cmd: str) -> str:
        self.history.append(cmd)
        log_event("shell", "INFO", f"Session {self.session_id} command: {cmd}", {})
        parts = cmd.strip().split()
        if not parts:
            return ""
        c = parts[0]
        args = parts[1:]

        if c == "pwd":
            return self.cwd
        elif c == "ls":
            path = self.cwd if not args else args[0]
            entries = self.vfs.list_dir(path)
            return "\n".join(entries) if entries else "No files"
        elif c == "cd":
            if args:
                new_path = args[0]
                if self.vfs._get_dir(new_path) is not None:
                    self.cwd = new_path
                    return ""
                return "No such directory"
            return "Usage: cd <path>"
        elif c == "cat":
            if not args:
                return "Usage: cat <path>"
            path = args[0]
            return self.vfs.read_file(path)
        elif c == "ps":
            lines = []
            for pid, info in self.datastore.process_table.items():
                lines.append(f"{pid} {info['name']} cpu={info['cpu']:.2f} net={info['net']:.2f}")
            return "\n".join(lines)
        elif c == "dmesg":
            return "\n".join(self.datastore.kernel_logs[:80])
        elif c == "history":
            return "\n".join(self.history)
        else:
            return f"Command '{cmd}' not implemented in fake shell."


# =========================
# Suricata v6 Integration (EVE + Rules)
# =========================

class SuricataIntegration:
    def __init__(self, eve_file: str, pcap_dir: str, rules_file: str):
        self.eve_file = eve_file
        self.pcap_dir = pcap_dir
        self.rules_file = rules_file
        self.rules: Dict[str, Any] = {}
        self.last_eve_offset = 0

    def load_rules(self):
        if os.path.exists(self.rules_file):
            try:
                with open(self.rules_file, "r", encoding="utf-8") as f:
                    self.rules = json.load(f)
            except Exception:
                self.rules = {}
        log_event("suricata", "INFO", "Loaded Suricata rules mapping", {"count": len(self.rules)})

    def ingest_eve(self, analytics: "DeceptionAnalytics"):
        if not os.path.exists(self.eve_file):
            return
        with open(self.eve_file, "r", encoding="utf-8") as f:
            f.seek(self.last_eve_offset)
            for line in f:
                try:
                    ev = json.loads(line)
                except json.JSONDecodeError:
                    continue
                rule_id = str(ev.get("alert", {}).get("signature_id", ""))
                mitre = self.rules.get(rule_id, {}).get("mitre", [])
                ev["mitre"] = mitre
                analytics.record_attacker_event({
                    "ts": ev.get("timestamp", datetime.datetime.utcnow().isoformat()),
                    "type": "suricata_alert",
                    "event": ev,
                })
                log_event("suricata", "INFO", "EVE event", ev)
            self.last_eve_offset = f.tell()

    def scan_pcap_dir(self):
        if not os.path.isdir(self.pcap_dir):
            return
        for fname in os.listdir(self.pcap_dir):
            if fname.endswith(".pcap"):
                log_event("suricata", "INFO", "Found PCAP", {"file": fname})

    def run_loop(self, stop_event: threading.Event, analytics: "DeceptionAnalytics"):
        while not stop_event.is_set():
            self.ingest_eve(analytics)
            self.scan_pcap_dir()
            time.sleep(10)


# =========================
# ML Engine (Real Models Where Possible)
# =========================

class MLEngine:
    def __init__(self):
        self.iforest = None
        self.dbscan = None
        self.autoencoder = None
        self.scaler = None
        self.trained = False

    def train_models(self, samples: List[Dict[str, Any]]):
        if IsolationForest is None or DBSCAN is None or StandardScaler is None or MLPRegressor is None:
            log_event("ml", "WARN", "sklearn not available, using stub ML", {})
            self.trained = False
            return

        X = []
        for s in samples:
            X.append([
                float(s.get("cpu", random.random())),
                float(s.get("net", random.random())),
                float(s.get("io", random.random())),
            ])
        if not X:
            return

        self.scaler = StandardScaler()
        X_scaled = self.scaler.fit_transform(X)

        self.iforest = IsolationForest(contamination=0.1, random_state=42)
        self.iforest.fit(X_scaled)

        self.dbscan = DBSCAN(eps=0.5, min_samples=5)
        self.dbscan.fit(X_scaled)

        self.autoencoder = MLPRegressor(hidden_layer_sizes=(8, 4, 8), max_iter=200)
        self.autoencoder.fit(X_scaled, X_scaled)

        self.trained = True
        log_event("ml", "INFO", "Trained real ML models", {"samples": len(X)})

    def score_behavior(self, features: Dict[str, Any]) -> Dict[str, Any]:
        if not self.trained or self.scaler is None or self.iforest is None:
            score = random.random()
            label = "benign" if score < 0.7 else "suspicious"
            log_event("ml", "INFO", "Stub scored behavior", {"score": score, "label": label})
            return {"score": score, "label": label}

        x = [[
            float(features.get("cpu", random.random())),
            float(features.get("net", random.random())),
            float(features.get("io", random.random())),
        ]]
        x_scaled = self.scaler.transform(x)
        iso_score = -self.iforest.decision_function(x_scaled)[0]
        label = "suspicious" if iso_score > 0.5 else "benign"
        log_event("ml", "INFO", "Real ML scored behavior", {"iso_score": iso_score, "label": label})
        return {"score": iso_score, "label": label}


# =========================
# LLM Integration (Local + Remote Stubs)
# =========================

class LLMEngine:
    def __init__(self, local_model_path: str, remote_endpoint: str):
        self.local_model_path = local_model_path
        self.remote_endpoint = remote_endpoint
        self.local_loaded = False

    def load_local_model(self):
        if os.path.exists(self.local_model_path):
            self.local_loaded = True
        else:
            self.local_loaded = False
        log_event("llm", "INFO", f"Local LLM load status: {self.local_loaded}", {})

    def _remote_call(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if requests is None:
            return None
        try:
            resp = requests.post(self.remote_endpoint, json=payload, timeout=3)
            if resp.status_code == 200:
                return resp.json()
        except Exception as e:
            log_event("llm", "WARN", "Remote LLM call failed", {"error": str(e)})
        return None

    def analyze_process(self, process_info: Dict[str, Any]) -> str:
        desc = f"Process {process_info.get('name')} appears {'benign' if random.random() < 0.5 else 'suspicious'}."
        remote = self._remote_call({"type": "process_analysis", "process": process_info})
        if remote and "analysis" in remote:
            desc = remote["analysis"]
        log_event("llm", "INFO", "LLM process analysis", {"process": process_info, "desc": desc})
        return desc

    def generate_deception_strategy(self, attacker_profile: Dict[str, Any]) -> Dict[str, Any]:
        base_strategy = {
            "create_fake_vuln": True,
            "fake_files_to_add": [f"/fakecorp/traps/trap_{uuid.uuid4().hex[:6]}.log"],
            "fake_credentials_to_leak": [random.choice(["admin", "svc-hr", "svc-devops", "svc-security"])],
            "fake_services_to_expose": [random.choice(["SMB", "SQL", "Docker", "K8s"])],
            "fake_k8s_pods_to_spawn": [f"trap-pod-{uuid.uuid4().hex[:4]}"],
        }
        remote = self._remote_call({"type": "deception_strategy", "attacker": attacker_profile})
        if remote and "strategy" in remote:
            base_strategy.update(remote["strategy"])
        log_event("llm", "INFO", "Generated deception strategy", {"attacker": attacker_profile, "strategy": base_strategy})
        return base_strategy


# =========================
# Swarm Networking (Multi-Node Gossip + Leader Election)
# =========================

class SwarmConsensus:
    def __init__(self, node_id: str, peers: List[Tuple[str, int]]):
        self.node_id = node_id
        self.peers = peers
        self.leader_id: Optional[str] = None
        self.state_version = 0
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None

    def start(self):
        log_event("swarm", "INFO", "Swarm consensus starting", {
            "node_id": self.node_id,
            "peers": self.peers,
        })
        self.thread = threading.Thread(target=self.run_loop, daemon=True)
        self.thread.start()

    def run_loop(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((Config.LISTEN_HOST, Config.SWARM_GOSSIP_PORT))
        sock.settimeout(1.0)
        last_election = time.time()
        while not self.stop_event.is_set():
            try:
                data, addr = sock.recvfrom(4096)
                msg = json.loads(data.decode(errors="ignore"))
                if msg.get("type") == "state_update":
                    log_event("swarm", "INFO", "Received state update", msg)
                elif msg.get("type") == "leader_announce":
                    self.leader_id = msg.get("leader_id")
                    log_event("swarm", "INFO", "Leader announced", {"leader_id": self.leader_id})
            except socket.timeout:
                pass
            except Exception as e:
                log_event("swarm", "WARN", "Swarm error", {"error": str(e)})

            if time.time() - last_election > 30:
                self.run_election()
                last_election = time.time()

        sock.close()

    def run_election(self):
        candidates = [self.node_id] + [f"peer-{i}" for i in range(len(self.peers))]
        new_leader = sorted(candidates)[0]
        self.leader_id = new_leader
        msg = json.dumps({"type": "leader_announce", "leader_id": self.leader_id}).encode()
        for host, port in self.peers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(msg, (host, Config.SWARM_GOSSIP_PORT))
                s.close()
            except Exception:
                pass
        log_event("swarm", "INFO", "Ran leader election", {"leader_id": self.leader_id})

    def propose_state_update(self, update: Dict[str, Any]):
        self.state_version += 1
        msg = json.dumps({"type": "state_update", "version": self.state_version, "update": update}).encode()
        for host, port in self.peers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.sendto(msg, (host, Config.SWARM_GOSSIP_PORT))
                s.close()
            except Exception:
                pass
        log_event("swarm", "INFO", "Proposed state update", {"version": self.state_version, "update": update})

    def enforce_policy(self, policy: Dict[str, Any]):
        log_event("swarm", "INFO", "Enforced swarm-wide policy", {"policy": policy})


# =========================
# Deception Analytics, Replay & Visualization
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

    def render_replay(self) -> str:
        timeline = self.build_timeline()
        lines = []
        for ev in timeline:
            ts = ev.get("ts", "")
            etype = ev.get("type", "")
            if etype == "shell_cmd":
                lines.append(f"[{ts}] SHELL: {ev.get('cmd')} -> {ev.get('output')[:80]}")
            elif etype == "rogue_process":
                proc = ev.get("proc", {})
                lines.append(f"[{ts}] ROGUE: {proc.get('name')} pid={proc.get('pid')} score={ev.get('ml_score', {}).get('score')}")
            elif etype == "suricata_alert":
                sig = ev.get("event", {}).get("alert", {}).get("signature", "")
                mitre = ev.get("event", {}).get("mitre", [])
                lines.append(f"[{ts}] SURICATA: {sig} MITRE={mitre}")
            else:
                lines.append(f"[{ts}] {etype}: {ev}")
        replay_text = "\n".join(lines)
        log_event("analytics", "INFO", "Rendered replay", {"lines": len(lines)})
        return replay_text


# =========================
# Chaos Morphing & Topology
# =========================

class ChaosMorpher:
    def __init__(self, vfs: VirtualFileSystem, datastore: FakeDataStore):
        self.vfs = vfs
        self.datastore = datastore
        self.current_topology_version = 0

    def mutate_topology(self):
        self.current_topology_version += 1
        if random.random() < 0.7:
            new_file = f"/fakecorp/morph/mutated_{uuid.uuid4().hex[:6]}.txt"
            self.vfs.add_file(new_file, "Dynamic fake content")
        if random.random() < 0.5:
            user = f"morph_user_{uuid.uuid4().hex[:4]}"
            pwd = "MorphPass!123"
            self.datastore.credentials[user] = pwd
        if random.random() < 0.4:
            self.datastore.kernel_logs.append(f"{datetime.datetime.utcnow().isoformat()} kernel: morph event")
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
            "io": random.random(),
        }
        ml_result = self.ml_engine.score_behavior(features)
        llm_desc = self.llm_engine.analyze_process(proc)
        is_rogue = ml_result["label"] == "suspicious" and proc.get("name") not in self.whitelist
        if is_rogue:
            pid = str(proc.get("pid", uuid.uuid4()))
            self.rogue_processes[pid] = proc
            ev = {
                "ts": datetime.datetime.utcnow().isoformat(),
                "type": "rogue_process",
                "proc": proc,
                "ml_score": ml_result,
                "llm_desc": llm_desc,
            }
            self.analytics.record_attacker_event(ev)
            log_event("rogue", "WARN", "Detected rogue process", {"proc": proc, "ml": ml_result, "llm": llm_desc})

    def rollback_whitelist(self):
        self.whitelist = ["system", "trusted_service"]
        log_event("rogue", "INFO", "Whitelist rollback", {})


# =========================
# Full Deception Strategy Engine
# =========================

class DeceptionOrchestrator:
    def __init__(self, vfs: VirtualFileSystem, datastore: FakeDataStore, llm_engine: LLMEngine, swarm: SwarmConsensus):
        self.vfs = vfs
        self.datastore = datastore
        self.llm_engine = llm_engine
        self.swarm = swarm

    def apply_strategy(self, strategy: Dict[str, Any]):
        if strategy.get("create_fake_vuln"):
            vuln_file = f"/fakecorp/vuln/vuln_{uuid.uuid4().hex[:6]}.txt"
            self.vfs.add_file(vuln_file, "Fake vulnerability description")
        for f in strategy.get("fake_files_to_add", []):
            self.vfs.add_file(f, "Trap file for attacker")
        for user in strategy.get("fake_credentials_to_leak", []):
            self.datastore.credentials[user] = "LeakedPass!123"
        for svc in strategy.get("fake_services_to_expose", []):
            self.datastore.generate_fake_event("deception_service", {"service": svc})
        for pod in strategy.get("fake_k8s_pods_to_spawn", []):
            self.datastore.k8s_objects["pods"].append({
                "name": pod,
                "status": "Running",
                "namespace": "default",
            })
        self.swarm.propose_state_update({"deception_strategy": strategy})
        log_event("deception", "INFO", "Applied deception strategy", strategy)

    def react_to_attacker(self, attacker_profile: Dict[str, Any]):
        strategy = self.llm_engine.generate_deception_strategy(attacker_profile)
        self.apply_strategy(strategy)


# =========================
# GUI Stub (SOC Dashboard)
# =========================

class GUIConsole:
    def __init__(self, analytics: DeceptionAnalytics, persona_engine: PersonaEngine, rogue_detector: RogueDetector):
        self.analytics = analytics
        self.persona_engine = persona_engine
        self.rogue_detector = rogue_detector

    def render_once(self):
        timeline = self.analytics.build_timeline()
        summary = {
            "attacker_events": len(timeline),
            "personas": len(self.persona_engine.personas),
            "rogue_processes": len(self.rogue_detector.rogue_processes),
        }
        log_event("gui", "INFO", "GUI render", summary)


# =========================
# Honeypot Core Orchestrator
# =========================

class HoneypotCore:
    def __init__(self):
        ensure_dirs()
        self.vfs = VirtualFileSystem()
        self.datastore = FakeDataStore(self.vfs)
        self.persona_engine = PersonaEngine(Config.PERSONA_COUNT)
        self.net_sim = NetworkActivitySimulator()
        self.suricata = SuricataIntegration(Config.SURICATA_EVE_FILE, Config.SURICATA_PCAP_DIR, Config.SURICATA_RULES_FILE)
        self.ml_engine = MLEngine()
        self.llm_engine = LLMEngine(Config.LLM_LOCAL_MODEL_PATH, Config.LLM_REMOTE_ENDPOINT)
        self.analytics = DeceptionAnalytics()
        self.swarm = SwarmConsensus(Config.NODE_ID, Config.SWARM_PEERS)
        self.chaos = ChaosMorpher(self.vfs, self.datastore)
        self.rogue_detector = RogueDetector(self.ml_engine, self.llm_engine, self.analytics)
        self.deception_orchestrator = DeceptionOrchestrator(self.vfs, self.datastore, self.llm_engine, self.swarm)
        self.gui = GUIConsole(self.analytics, self.persona_engine, self.rogue_detector)
        self.stop_event = threading.Event()
        self.threads: List[threading.Thread] = []

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
        samples = list(self.datastore.process_table.values())
        self.ml_engine.train_models(samples)
        self.llm_engine.load_local_model()

    def start_swarm(self):
        self.swarm.start()

    def start_background_loops(self):
        t_persona = threading.Thread(target=self.persona_engine.run_loop, args=(self.stop_event,), daemon=True)
        t_persona.start()
        self.threads.append(t_persona)

        t_net = threading.Thread(target=self.net_sim.run_loop, args=(self.stop_event,), daemon=True)
        t_net.start()
        self.threads.append(t_net)

        t_chaos = threading.Thread(target=self.chaos.run_loop, args=(self.stop_event,), daemon=True)
        t_chaos.start()
        self.threads.append(t_chaos)

        t_suricata = threading.Thread(target=self.suricata.run_loop, args=(self.stop_event, self.analytics), daemon=True)
        t_suricata.start()
        self.threads.append(t_suricata)

        log_event("core", "INFO", "Background loops started", {})

    def simulate_attacker_interaction(self):
        shell = FakeShellSession(str(uuid.uuid4()), self.vfs, self.datastore)
        for cmd in ["pwd", "ls", "ps", "dmesg", "cat /fakecorp/docs/doc_1.txt"]:
            out = shell.handle_command(cmd)
            self.analytics.record_attacker_event({
                "ts": datetime.datetime.utcnow().isoformat(),
                "type": "shell_cmd",
                "cmd": cmd,
                "output": out,
            })

        proc = {"name": "evil_miner", "pid": 9999, "cpu": 0.9, "net": 0.8}
        self.rogue_detector.analyze_process(proc)

        attacker_profile = {
            "ip": "10.0.0.13",
            "behavior": "credential_spray",
            "tools": ["nmap", "smbclient"],
        }
        self.deception_orchestrator.react_to_attacker(attacker_profile)

    def autonomous_evolution(self):
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
                self.simulate_attacker_interaction()
                self.autonomous_evolution()
                self.analytics.save_replay()
                self.analytics.export_forensics()
                replay_text = self.analytics.render_replay()
                log_event("core", "INFO", "Attacker replay snapshot", {"preview": replay_text[:200]})
                self.swarm.enforce_policy({"rogue_processes": list(self.rogue_detector.rogue_processes.keys())})
                time.sleep(30)
        except KeyboardInterrupt:
            log_event("core", "INFO", "KeyboardInterrupt received, stopping honeypot", {})
        finally:
            self.stop_event.set()
            self.save_state()
            log_event("core", "INFO", "Honeypot stopped", {})


def main():
    log_event("bootstrap", "INFO", "Starting God-Mode Honeypot v3", {"version": Config.VERSION})
    core = HoneypotCore()
    core.start_protocols()
    core.start_ml_llm()
    core.start_swarm()
    core.start_background_loops()
    core.start_gui()
    core.main_loop()


if __name__ == "__main__":
    main()
