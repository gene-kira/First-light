#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys
import subprocess
import importlib

REQUIRED_MODULES = ["psutil", "sklearn", "requests"]

def ensure_modules(modules):
    for m in modules:
        try:
            importlib.import_module(m)
            print(f"[Autoloader] Module '{m}' found.")
        except ImportError:
            print(f"[Autoloader] Module '{m}' missing. Installing via pip...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", m])
                importlib.import_module(m)
                print(f"[Autoloader] Module '{m}' installed and loaded.")
            except Exception as e:
                print(f"[Autoloader] Failed to install module '{m}': {e}")

ensure_modules(REQUIRED_MODULES)

import os
import time
import json
import random
import socket
import threading
import uuid
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from typing import Dict, Any, List, Optional, Tuple
from collections import deque

import psutil
import hashlib
from datetime import timedelta
import queue

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

import tkinter as tk
from tkinter import ttk

# =========================
# Global Config & Utilities
# =========================

class Config:
    VERSION = "overwatch-god-honeypot-v8-queen"
    NODE_ID = str(uuid.uuid4())
    SWARM_CLUSTER_ID = "swarm-godnet"
    LISTEN_HOST = "0.0.0.0"
    BASE_PORT = 45000
    RANDOM_PORT_RANGE = (20000, 60000)
    PERSONA_COUNT = 50
    ACTIVITY_INTERVAL_RANGE = (5, 60)
    LOG_DIR = "./honeypot_logs"
    REPLAY_DIR = "./honeypot_replay"
    FORENSIC_DIR = "./honeypot_forensics"
    STATE_FILE = "./honeypot_state.json"
    SURICATA_EVE_FILE = "./suricata/eve.json"
    SURICATA_PCAP_DIR = "./suricata/pcap"
    SURICATA_RULES_FILE = "./suricata/rules.json"
    GUI_ENABLED = True
    LLM_LOCAL_MODEL_PATH = "./models/local_llm_stub"
    LLM_REMOTE_ENDPOINT = "https://llm-remote-api.example.com/analyze"
    SWARM_PEERS = [("127.0.0.1", 48001), ("127.0.0.1", 48002)]
    SWARM_GOSSIP_PORT = 47000

    BASELINE_FILE = "overwatch_baseline_v8.json"
    SLEEPER_WINDOW_MINUTES = 60
    SCAN_INTERVAL_SECONDS = 5
    MAX_BEHAVIOR_POINTS = 200

    THREAT_INTEL_URL = "https://threat-intel.example.com/feeds/basic"
    THREAT_INTEL_LOCAL = "./threat_intel_local.json"

    SANDBOX_DIR = "./sandbox_quarantine"
    AUTO_REMEDIATE = True

    QUEEN_RISK_THRESHOLD = 1.5


def ensure_dirs():
    for d in [Config.LOG_DIR, Config.REPLAY_DIR, Config.FORENSIC_DIR,
              Config.SURICATA_PCAP_DIR, os.path.dirname(Config.SURICATA_EVE_FILE),
              os.path.dirname(Config.SURICATA_RULES_FILE), Config.SANDBOX_DIR]:
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
        for i in range(200):
            path = f"/fakecorp/docs/doc_{i}.txt"
            content = f"Confidential document {i} - salary, HR, finance, secrets..."
            self.vfs.add_file(path, content)

        for i in range(80):
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
                          for i in range(200)]
        }
        self.sql_databases["finance_db"] = {
            "transactions": [{"id": i, "amount": random.uniform(100, 10000), "type": random.choice(["credit", "debit"])}
                             for i in range(400)]
        }

        self.smb_shares["HR$"] = ["/fakecorp/docs/hr_payroll.xlsx", "/fakecorp/docs/hr_reviews.docx"]
        self.smb_shares["FINANCE$"] = ["/fakecorp/docs/fin_budget.xlsx"]
        self.smb_shares["DEV$"] = ["/fakecorp/devops/build_logs.log"]

        containers = {}
        for i in range(10):
            cid = f"container-{i}"
            containers[cid] = {
                "Id": cid,
                "Image": random.choice(["nginx:latest", "redis:7", "postgres:15", "custom-app:v1"]),
                "State": random.choice(["running", "exited"]),
                "Ports": [{"PrivatePort": random_port(), "Type": "tcp"}],
            }
        images = [
            {"Id": f"image-{i}", "RepoTags": [random.choice(["nginx:latest", "redis:7", "postgres:15", "custom-app:v1"])]}
            for i in range(5)
        ]
        self.docker_objects = {
            "containers": containers,
            "images": images,
        }

        deployments = [{"name": f"app-{i}", "replicas": random.randint(1, 3), "namespace": "default"}
                       for i in range(5)]
        services = [{"name": f"svc-{i}", "port": random_port(), "namespace": "default"}
                    for i in range(5)]
        pods = [{"name": f"pod-{i}", "status": random.choice(["Running", "CrashLoopBackOff", "Pending"]),
                 "namespace": "default"}
                for i in range(15)]
        self.k8s_objects = {
            "deployments": deployments,
            "services": services,
            "pods": pods,
        }

        self.ad_domain = {
            "name": "FAKECORP.LOCAL",
            "users": [f"user{i}" for i in range(200)],
            "groups": ["Domain Admins", "HR", "Finance", "IT", "DevOps", "Security", "Management"],
        }

        self.vpn_gateways["corp-vpn"] = {
            "endpoint": "vpn.fakecorp.local",
            "users": [f"user{i}" for i in range(80)],
        }

        for i in range(40):
            self.kernel_logs.append(f"{datetime.datetime.utcnow().isoformat()} kernel: event {i} - fake syscall")

        for pid in range(1000, 1020):
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
# Protocol Emulation
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
# Cowrie-Style Shell
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
# Suricata Integration + Packet Capture Stub
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

    def ingest_eve(self, analytics: "DeceptionAnalytics", event_bus: "EventBus"):
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
                event_bus.publish(SecEvent("net_conn", ev.get("src_ip", "unknown"), {"suricata": ev}))
                log_event("suricata", "INFO", "EVE event", ev)
            self.last_eve_offset = f.tell()

    def scan_pcap_dir(self):
        if not os.path.isdir(self.pcap_dir):
            return
        for fname in os.listdir(self.pcap_dir):
            if fname.endswith(".pcap"):
                log_event("suricata", "INFO", "Found PCAP", {"file": fname})
                # Stub: here you would call Suricata or a parser on the PCAP

    def run_loop(self, stop_event: threading.Event, analytics: "DeceptionAnalytics", event_bus: "EventBus"):
        self.load_rules()
        while not stop_event.is_set():
            self.ingest_eve(analytics, event_bus)
            self.scan_pcap_dir()
            time.sleep(10)


# =========================
# Kernel-Level Monitoring Stub
# =========================

class KernelMonitor:
    def __init__(self, event_bus: "EventBus"):
        self.events: List[Dict[str, Any]] = []
        self.stop_event = threading.Event()
        self.event_bus = event_bus

    def run_loop(self):
        while not self.stop_event.is_set():
            ev = {
                "ts": datetime.datetime.utcnow().isoformat(),
                "type": "kernel_stub",
                "detail": "Simulated kernel event (ETW/driver hook placeholder)."
            }
            self.events.append(ev)
            self.event_bus.publish(SecEvent("kernel_event", "kernel", ev))
            log_event("kernel", "INFO", "Kernel monitor stub event", ev)
            time.sleep(15)


# =========================
# ML Engine
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
# LLM Engine
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
# Threat Intelligence Feeds
# =========================

class ThreatIntel:
    def __init__(self):
        self.malicious_hashes = set()
        self.malicious_ips = set()
        self.malicious_names = set()
        self.load_local()
        self.fetch_remote()

    def load_local(self):
        if os.path.exists(Config.THREAT_INTEL_LOCAL):
            try:
                with open(Config.THREAT_INTEL_LOCAL, "r", encoding="utf-8") as f:
                    data = json.load(f)
                self.malicious_hashes.update(data.get("hashes", []))
                self.malicious_ips.update(data.get("ips", []))
                self.malicious_names.update(data.get("names", []))
            except Exception as e:
                log_event("intel", "WARN", "Failed to load local threat intel", {"error": str(e)})

    def fetch_remote(self):
        if requests is None:
            return
        try:
            resp = requests.get(Config.THREAT_INTEL_URL, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                self.malicious_hashes.update(data.get("hashes", []))
                self.malicious_ips.update(data.get("ips", []))
                self.malicious_names.update(data.get("names", []))
                log_event("intel", "INFO", "Fetched remote threat intel", {
                    "hashes": len(self.malicious_hashes),
                    "ips": len(self.malicious_ips),
                    "names": len(self.malicious_names),
                })
        except Exception as e:
            log_event("intel", "WARN", "Failed to fetch remote threat intel", {"error": str(e)})

    def is_malicious_hash(self, h: str) -> bool:
        return h in self.malicious_hashes

    def is_malicious_ip(self, ip: str) -> bool:
        return ip in self.malicious_ips

    def is_malicious_name(self, name: str) -> bool:
        return name in self.malicious_names


# =========================
# Swarm Consensus
# =========================

class SwarmConsensus:
    def __init__(self, node_id: str, peers: List[Tuple[str, int]]):
        self.node_id = node_id
        self.peers = peers
        self.leader_id: Optional[str] = None
        self.state_version = 0
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.cluster_state: Dict[str, Any] = {}

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
                    self.cluster_state[msg.get("source", "unknown")] = msg.get("update", {})
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
        msg = json.dumps({
            "type": "state_update",
            "version": self.state_version,
            "update": update,
            "source": Config.NODE_ID,
        }).encode()
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
# Deception Analytics
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
# Chaos Morphing
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
# Rogue Detector
# =========================

class RogueDetector:
    def __init__(self, ml_engine: MLEngine, llm_engine: LLMEngine, analytics: DeceptionAnalytics, event_bus: "EventBus"):
        self.ml_engine = ml_engine
        self.llm_engine = llm_engine
        self.analytics = analytics
        self.whitelist: List[str] = ["system", "trusted_service"]
        self.rogue_processes: Dict[str, Dict[str, Any]] = {}
        self.event_bus = event_bus

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
            self.event_bus.publish(SecEvent("proc_start", proc.get("pid", pid), {"rogue": ev}))
            log_event("rogue", "WARN", "Detected rogue process", {"proc": proc, "ml": ml_result, "llm": llm_desc})

    def rollback_whitelist(self):
        self.whitelist = ["system", "trusted_service"]
        log_event("rogue", "INFO", "Whitelist rollback", {})


# =========================
# Deception Orchestrator
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
# Sandboxing & Auto-Remediation
# =========================

class SandboxManager:
    def __init__(self):
        ensure_dirs()

    def quarantine_process(self, proc: psutil.Process, reason: str):
        try:
            info = {
                "pid": proc.pid,
                "name": proc.name(),
                "exe": proc.exe(),
                "cmdline": proc.cmdline(),
                "reason": reason,
                "ts": datetime.datetime.utcnow().isoformat(),
            }
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            info = {
                "pid": proc.pid,
                "reason": reason,
                "ts": datetime.datetime.utcnow().isoformat(),
            }

        path = os.path.join(Config.SANDBOX_DIR, f"quarantine_{proc.pid}_{int(time.time())}.json")
        with open(path, "w", encoding="utf-8") as f:
            json.dump(info, f, indent=2)
        log_event("sandbox", "WARN", "Quarantined process", info)

    def kill_process(self, proc: psutil.Process, reason: str):
        try:
            proc.kill()
            log_event("sandbox", "WARN", "Killed process", {"pid": proc.pid, "reason": reason})
        except (psutil.NoSuchProcess, psutil.AccessDenied) as e:
            log_event("sandbox", "WARN", "Failed to kill process", {"pid": proc.pid, "error": str(e)})


class AutoRemediator:
    def __init__(self, sandbox: SandboxManager, intel: ThreatIntel):
        self.sandbox = sandbox
        self.intel = intel

    def maybe_remediate(self, proc: psutil.Process, profile, score: int, level: str, queen_risk: float):
        if not Config.AUTO_REMEDIATE:
            return

        try:
            exe = proc.exe()
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            exe = None

        exe_hash = hash_executable(exe) if exe else None

        malicious = False
        if exe_hash and self.intel.is_malicious_hash(exe_hash):
            malicious = True
        if self.intel.is_malicious_name(profile.name):
            malicious = True

        if malicious or level == "RED" or queen_risk > Config.QUEEN_RISK_THRESHOLD:
            self.sandbox.quarantine_process(proc, reason=f"Threat level {level}, malicious={malicious}, queen_risk={queen_risk}")
            self.sandbox.kill_process(proc, reason=f"Threat level {level}, malicious={malicious}, queen_risk={queen_risk}")


# =========================
# Queen (Global Consensus Engine)
# =========================

class Queen:
    def __init__(self):
        self.nodes: Dict[str, List[Dict[str, Any]]] = {}
        self.global_field: Dict[str, "ProbabilisticField"] = {}

    def update(self, node: str, events: List[Dict[str, Any]]):
        self.nodes[node] = events

    def global_risk(self) -> Dict[str, float]:
        risk: Dict[str, float] = {}
        for node, evts in self.nodes.items():
            for e in evts:
                entity = e.get("entity")
                score = e.get("score", 0.0)
                if entity is None:
                    continue
                risk[entity] = risk.get(entity, 0.0) + score

        filtered = {k: v for k, v in risk.items() if v > Config.QUEEN_RISK_THRESHOLD}
        for entity, r in filtered.items():
            if entity not in self.global_field:
                self.global_field[entity] = ProbabilisticField(mean=r, var=1.0)
            else:
                self.global_field[entity].update(r, weight=1.0)
        return filtered

    def get_entity_risk(self, entity: str) -> float:
        pf = self.global_field.get(entity)
        if pf:
            return pf.mean
        return 0.0


# =========================
# Attack Chain Engine
# =========================

class AttackChainEngine:
    def __init__(self):
        self.events = deque()
        self.window = 120  # seconds

    def add_event(self, event_type: str, data: Dict[str, Any]):
        now = time.time()
        self.events.append((now, event_type, data))
        self._cleanup(now)

    def _cleanup(self, now: float):
        cutoff = now - self.window
        while self.events and self.events[0][0] < cutoff:
            self.events.popleft()

    def detect(self) -> List[Tuple[str, float]]:
        types = [e[1] for e in self.events]
        chains: List[Tuple[str, float]] = []

        if all(x in types for x in ["proc_spawn", "powershell", "net_connect"]):
            chains.append(("LOLBIN_ATTACK", 0.9))

        if types.count("proc_spawn") > 5 and "net_connect" in types:
            chains.append(("PROCESS_STORM", 0.8))

        if "file_mod" in types and "net_connect" in types:
            chains.append(("PERSISTENCE_EXFIL", 0.85))

        return chains


# =========================
# Probabilistic Field (Data Physics / Intelligent Water)
# =========================

class ProbabilisticField:
    def __init__(self, mean: float, var: float):
        self.mean = mean
        self.var = var

    def sample(self) -> float:
        return random.gauss(self.mean, self.var)

    def update(self, observation: float, weight: float = 1.0):
        self.mean = (self.mean + weight * observation) / (1.0 + weight)
        self.var = max(1e-6, self.var * 0.9)


# =========================
# Event Bus & SecEvent
# =========================

class SecEvent:
    def __init__(self, etype: str, entity: Any, meta: Optional[Dict[str, Any]] = None):
        self.ts = time.time()
        self.type = etype
        self.entity = entity
        self.meta = meta or {}


class EventBus:
    def __init__(self):
        self.subscribers: List[Any] = []
        self.queue = deque()
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run, daemon=True)

    def start(self):
        self.thread.start()

    def publish(self, event: SecEvent):
        self.queue.append(event)

    def subscribe(self, fn):
        self.subscribers.append(fn)

    def run(self):
        while not self.stop_event.is_set():
            if self.queue:
                evt = self.queue.popleft()
                for fn in self.subscribers:
                    try:
                        fn(evt)
                    except Exception as e:
                        log_event("eventbus", "ERROR", "subscriber error", {"error": str(e)})
            time.sleep(0.01)


# =========================
# Honeypot Core
# =========================

class HoneypotCore:
    def __init__(self, shared_ml: MLEngine, shared_llm: LLMEngine,
                 shared_analytics: DeceptionAnalytics, shared_swarm: SwarmConsensus,
                 event_bus: EventBus, queen: Queen, chain_engine: AttackChainEngine):
        ensure_dirs()
        self.vfs = VirtualFileSystem()
        self.datastore = FakeDataStore(self.vfs)
        self.persona_engine = PersonaEngine(Config.PERSONA_COUNT)
        self.net_sim = NetworkActivitySimulator()
        self.suricata = SuricataIntegration(Config.SURICATA_EVE_FILE, Config.SURICATA_PCAP_DIR, Config.SURICATA_RULES_FILE)
        self.ml_engine = shared_ml
        self.llm_engine = shared_llm
        self.analytics = shared_analytics
        self.swarm = shared_swarm
        self.chaos = ChaosMorpher(self.vfs, self.datastore)
        self.event_bus = event_bus
        self.chain_engine = chain_engine
        self.rogue_detector = RogueDetector(self.ml_engine, self.llm_engine, self.analytics, self.event_bus)
        self.deception_orchestrator = DeceptionOrchestrator(self.vfs, self.datastore, self.llm_engine, self.swarm)
        self.stop_event = threading.Event()
        self.threads: List[threading.Thread] = []

        self.kernel_monitor = KernelMonitor(self.event_bus)

        self.smb_server = FakeSMBServer(self.datastore, random_port())
        self.ldap_server = FakeLDAPServer(self.datastore, random_port())
        self.kerberos_kdc = FakeKerberosKDC(self.datastore, random_port())
        self.sql_listener = FakeSQLListener(self.datastore, random_port())
        self.docker_api = FakeDockerAPI(self.datastore, random_port())
        self.k8s_api = FakeK8sAPI(self.datastore, random_port())
        self.cloud_metadata_server = FakeCloudMetadataServer(self.datastore, random_port())

        def chain_subscriber(evt: SecEvent):
            if evt.type in ("proc_spawn", "net_connect", "file_mod", "powershell"):
                self.chain_engine.add_event(evt.type, {"entity": evt.entity, "meta": evt.meta})
                chains = self.chain_engine.detect()
                for cname, score in chains:
                    if score > 0.8:
                        log_event("attack_chain", "CRITICAL", cname, {"score": score})
                        self.event_bus.publish(SecEvent("attack_chain", cname, {"score": score}))

        self.event_bus.subscribe(chain_subscriber)

    def start_protocols(self):
        self.smb_server.start()
        self.ldap_server.start()
        self.kerberos_kdc.start()
        self.sql_listener.start()
        self.docker_api.start()
        self.k8s_api.start()
        self.cloud_metadata_server.start()

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

        t_suricata = threading.Thread(target=self.suricata.run_loop, args=(self.stop_event, self.analytics, self.event_bus), daemon=True)
        t_suricata.start()
        self.threads.append(t_suricata)

        t_kernel = threading.Thread(target=self.kernel_monitor.run_loop, daemon=True)
        t_kernel.start()
        self.threads.append(t_kernel)

        log_event("core", "INFO", "Honeypot background loops started", {})

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
            self.event_bus.publish(SecEvent("file_mod", "/fakecorp/docs/doc_1.txt", {"cmd": cmd}))

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


# =========================
# OverWatch Data Models
# =========================

class ProcessProfile:
    def __init__(self, name, path, ppid, exe_hash):
        self.name = name
        self.path = path
        self.ppid = ppid
        self.exe_hash = exe_hash
        self.first_seen = datetime.datetime.now()
        self.last_seen = datetime.datetime.now()
        self.seen_count = 1
        self.interrogation_notes = []
        self.behavior_log = []
        self.sleeper_flag = False
        self.data_tx_flag = False
        self.honeypot_flag = False

    def to_dict(self):
        return {
            "name": self.name,
            "path": self.path,
            "ppid": self.ppid,
            "exe_hash": self.exe_hash,
            "first_seen": self.first_seen.isoformat(),
            "last_seen": self.last_seen.isoformat(),
            "seen_count": self.seen_count,
            "interrogation_notes": self.interrogation_notes,
            "behavior_log": self.behavior_log,
            "sleeper_flag": self.sleeper_flag,
            "data_tx_flag": self.data_tx_flag,
            "honeypot_flag": self.honeypot_flag,
        }

    @staticmethod
    def from_dict(d):
        p = ProcessProfile(
            d["name"],
            d["path"],
            d["ppid"],
            d["exe_hash"]
        )
        p.first_seen = datetime.datetime.fromisoformat(d["first_seen"])
        p.last_seen = datetime.datetime.fromisoformat(d["last_seen"])
        p.seen_count = d["seen_count"]
        p.interrogation_notes = d.get("interrogation_notes", [])
        p.behavior_log = d.get("behavior_log", [])
        p.sleeper_flag = d.get("sleeper_flag", False)
        p.data_tx_flag = d.get("data_tx_flag", False)
        p.honeypot_flag = d.get("honeypot_flag", False)
        return p


class Baseline:
    def __init__(self):
        self.data = {}
        self.load()

    def _key(self, name, path):
        return f"{name}|{path}"

    def load(self):
        if os.path.exists(Config.BASELINE_FILE):
            with open(Config.BASELINE_FILE, "r") as f:
                raw = json.load(f)
            self.data = {k: ProcessProfile.from_dict(v) for k, v in raw.items()}
        else:
            self.data = {}

    def save(self):
        raw = {k: v.to_dict() for k, v in self.data.items()}
        with open(Config.BASELINE_FILE, "w") as f:
            json.dump(raw, f, indent=4)

    def get(self, name, path):
        return self.data.get(self._key(name, path))

    def add_or_update(self, name, path, ppid, exe_hash):
        key = self._key(name, path)
        if key not in self.data:
            profile = ProcessProfile(name, path, ppid, exe_hash)
            self.data[key] = profile
        else:
            profile = self.data[key]
            profile.last_seen = datetime.datetime.now()
            profile.seen_count += 1
        self.save()
        return self.data[key]

    def all_profiles(self):
        return list(self.data.values())


def hash_executable(path):
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return None


def is_private_ip(ip):
    if not ip:
        return True
    try:
        parts = ip.split(".")
        if len(parts) != 4:
            return False
        p0 = int(parts[0])
        p1 = int(parts[1])
        if p0 == 10:
            return True
        if p0 == 172 and 16 <= p1 <= 31:
            return True
        if p0 == 192 and p1 == 168:
            return True
        if ip.startswith("127."):
            return True
        return False
    except Exception:
        return False


class Interrogator:
    @staticmethod
    def interrogate(proc, profile: ProcessProfile):
        notes = []
        notes.append(f"WHO: Name={profile.name}, Path={profile.path}, PPID={profile.ppid}")

        try:
            cpu = proc.cpu_percent(interval=0.1)
            mem = proc.memory_info().rss
            threads = proc.num_threads()
            notes.append(f"WHAT: CPU={cpu}%, MEM={mem} bytes, Threads={threads}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            notes.append("WHAT: Unable to read CPU/MEM/Threads")

        try:
            conns = proc.connections()
            if conns:
                conn_summary = []
                outbound_flag = False
                for c in conns[:10]:
                    conn_summary.append(f"{c.laddr}->{c.raddr} [{c.status}]")
                    if c.raddr:
                        ip = None
                        if isinstance(c.raddr, tuple) and len(c.raddr) >= 1:
                            ip = c.raddr[0]
                        elif hasattr(c.raddr, "ip"):
                            ip = c.raddr.ip
                        else:
                            ip = str(c.raddr)
                        if ip and not is_private_ip(ip):
                            outbound_flag = True
                notes.append("WHERE: " + "; ".join(conn_summary))
                if outbound_flag:
                    profile.data_tx_flag = True
                    notes.append("DATA-TX: Outbound connection to non-private IP detected (potential data transmission).")
            else:
                notes.append("WHERE: No active network connections")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            notes.append("WHERE: Unable to read connections")

        profile.interrogation_notes.extend(notes)
        return notes


class AnomalyEngine:
    @staticmethod
    def score(proc, profile: ProcessProfile, intel: ThreatIntel):
        score = 0

        if profile.seen_count == 1:
            score += 50

        try:
            cpu = proc.cpu_percent(interval=0.0)
            mem = proc.memory_info().rss
            threads = proc.num_threads()
            timestamp = datetime.datetime.now().isoformat()
            entry = {
                "timestamp": timestamp,
                "cpu": cpu,
                "mem": mem,
                "threads": threads,
            }
            profile.behavior_log.append(entry)
            if len(profile.behavior_log) > Config.MAX_BEHAVIOR_POINTS:
                profile.behavior_log = profile.behavior_log[-Config.MAX_BEHAVIOR_POINTS:]
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        try:
            now = datetime.datetime.now()
            window_start = now - timedelta(minutes=Config.SLEEPER_WINDOW_MINUTES)
            recent = [b for b in profile.behavior_log
                      if datetime.datetime.fromisoformat(b["timestamp"]) >= window_start]

            if len(recent) >= 3:
                avg_cpu = sum(b["cpu"] for b in recent) / len(recent)
                avg_threads = sum(b["threads"] for b in recent) / len(recent)
                if avg_cpu < 5 and avg_threads < 5:
                    current_cpu = proc.cpu_percent(interval=0.0)
                    current_threads = proc.num_threads()
                    if current_cpu > 20 or current_threads > 20:
                        profile.sleeper_flag = True
                        score += 80
        except Exception:
            pass

        current_hash = hash_executable(profile.path)
        if current_hash and profile.exe_hash and current_hash != profile.exe_hash:
            score += 100

        if profile.data_tx_flag:
            score += 40

        if current_hash and intel.is_malicious_hash(current_hash):
            score += 120

        if intel.is_malicious_name(profile.name):
            score += 80

        if profile.data_tx_flag and score >= 120:
            profile.honeypot_flag = True

        return score

    @staticmethod
    def threat_level(score, sleeper_flag, honeypot_flag):
        if honeypot_flag or sleeper_flag or score >= 150:
            return "RED"
        elif score >= 80:
            return "YELLOW"
        elif score >= 30:
            return "GREEN"
        else:
            return "NONE"


class OverWatchCore(threading.Thread):
    def __init__(self, event_queue: queue.Queue, baseline: Baseline,
                 honeypot: HoneypotCore, intel: ThreatIntel, remediator: AutoRemediator,
                 queen: Queen, event_bus: EventBus):
        super().__init__(daemon=True)
        self.baseline = baseline
        self.event_queue = event_queue
        self.running = True
        self.honeypot = honeypot
        self.intel = intel
        self.remediator = remediator
        self.queen = queen
        self.event_bus = event_bus

    def run(self):
        while self.running:
            self.scan_once()
            time.sleep(Config.SCAN_INTERVAL_SECONDS)

    def stop(self):
        self.running = False

    def scan_once(self):
        node_events_for_queen: List[Dict[str, Any]] = []

        for proc in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
            try:
                name = proc.info['name']
                path = proc.info['exe'] or "UNKNOWN"
                ppid = proc.info['ppid']
                exe_hash = hash_executable(path)

                profile = self.baseline.add_or_update(name, path, ppid, exe_hash)

                interrogation_notes = []
                if profile.seen_count == 1 or profile.sleeper_flag or profile.data_tx_flag:
                    interrogation_notes = Interrogator.interrogate(proc, profile)

                score = AnomalyEngine.score(proc, profile, self.intel)
                level = AnomalyEngine.threat_level(score, profile.sleeper_flag, profile.honeypot_flag)

                event_proc = {
                    "type": "process_update",
                    "timestamp": datetime.datetime.now().isoformat(),
                    "name": name,
                    "path": path,
                    "pid": proc.pid,
                    "ppid": ppid,
                    "score": score,
                    "sleeper": profile.sleeper_flag,
                    "seen_count": profile.seen_count,
                    "level": level,
                    "data_tx": profile.data_tx_flag,
                    "honeypot": profile.honeypot_flag,
                }
                self.event_queue.put(event_proc)

                node_events_for_queen.append({
                    "entity": f"pid:{proc.pid}",
                    "score": float(score) / 100.0
                })

                self.event_bus.publish(SecEvent("proc_spawn", proc.pid, {"name": name, "path": path, "score": score}))

                if score >= 50:
                    event_anom = {
                        "type": "anomaly",
                        "timestamp": datetime.datetime.now().isoformat(),
                        "name": name,
                        "path": path,
                        "pid": proc.pid,
                        "ppid": ppid,
                        "score": score,
                        "sleeper": profile.sleeper_flag,
                        "seen_count": profile.seen_count,
                        "level": level,
                        "data_tx": profile.data_tx_flag,
                        "honeypot": profile.honeypot_flag,
                        "notes": interrogation_notes,
                    }
                    self.event_queue.put(event_anom)

                    if profile.honeypot_flag or profile.data_tx_flag or level in ("YELLOW", "RED"):
                        self.honeypot.rogue_detector.analyze_process({
                            "name": name,
                            "pid": proc.pid,
                            "cpu": proc.cpu_percent(interval=0.0),
                            "net": random.random(),
                        })

                    queen_risk_map = self.queen.global_risk()
                    queen_risk = queen_risk_map.get(f"pid:{proc.pid}", 0.0)
                    self.remediator.maybe_remediate(proc, profile, score, level, queen_risk)

            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self.baseline.save()
        self.queen.update(Config.NODE_ID, node_events_for_queen)


# =========================
# Agent-Based Architecture (Local Agent Stub)
# =========================

class LocalAgent:
    def __init__(self, node_id: str, event_queue: queue.Queue, swarm: SwarmConsensus):
        self.node_id = node_id
        self.event_queue = event_queue
        self.swarm = swarm
        self.stop_event = threading.Event()
        self.thread = threading.Thread(target=self.run_loop, daemon=True)

    def start(self):
        self.thread.start()

    def run_loop(self):
        while not self.stop_event.is_set():
            try:
                event = self.event_queue.get(timeout=1.0)
                if event["type"] in ("anomaly", "process_update"):
                    self.swarm.propose_state_update({"agent_event": event})
            except queue.Empty:
                pass


# =========================
# GUI (Fusion + Multi-Node Awareness)
# =========================

class FusionGUI:
    def __init__(self, root, baseline: Baseline, event_queue: queue.Queue,
                 honeypot: HoneypotCore, analytics: DeceptionAnalytics, swarm: SwarmConsensus, queen: Queen):
        self.root = root
        self.root.title("OverWatch + God-Mode Honeypot v8 Queen")
        self.root.geometry("1700x950")

        style = ttk.Style()
        style.theme_use("default")
        style.configure("Treeview",
                        background="#111111",
                        foreground="#EEEEEE",
                        fieldbackground="#111111")
        style.map("Treeview",
                  background=[("selected", "#333333")])

        self.baseline = baseline
        self.event_queue = event_queue
        self.honeypot = honeypot
        self.analytics = analytics
        self.swarm = swarm
        self.queen = queen

        self.selected_pid = None
        self.selected_profile = None

        self.build_ribbon()
        self.build_tabs()

        self.root.after(500, self.process_events)
        self.root.after(3000, self.update_honeypot_view)
        self.root.after(5000, self.update_cluster_view)
        self.root.after(5000, self.update_queen_view)

    def build_ribbon(self):
        self.ribbon = ttk.Notebook(self.root)
        self.ribbon.pack(fill=tk.BOTH, expand=True)

        self.tab_processes = ttk.Frame(self.ribbon)
        self.tab_anomalies = ttk.Frame(self.ribbon)
        self.tab_baseline = ttk.Frame(self.ribbon)
        self.tab_honeypot = ttk.Frame(self.ribbon)
        self.tab_cluster = ttk.Frame(self.ribbon)
        self.tab_queen = ttk.Frame(self.ribbon)
        self.tab_settings = ttk.Frame(self.ribbon)

        self.ribbon.add(self.tab_processes, text="Processes")
        self.ribbon.add(self.tab_anomalies, text="Anomalies")
        self.ribbon.add(self.tab_baseline, text="Baseline")
        self.ribbon.add(self.tab_honeypot, text="Honeypot Replay")
        self.ribbon.add(self.tab_cluster, text="Cluster / Agents")
        self.ribbon.add(self.tab_queen, text="Queen / Global Risk")
        self.ribbon.add(self.tab_settings, text="Settings")

    def build_tabs(self):
        self.build_processes_tab()
        self.build_anomalies_tab()
        self.build_baseline_tab()
        self.build_honeypot_tab()
        self.build_cluster_tab()
        self.build_queen_tab()
        self.build_settings_tab()

    def build_processes_tab(self):
        top_frame = ttk.Frame(self.tab_processes)
        top_frame.pack(fill=tk.BOTH, expand=True)

        bottom_frame = ttk.Frame(self.tab_processes)
        bottom_frame.pack(fill=tk.BOTH, expand=True)

        pid_container = ttk.Frame(top_frame)
        pid_container.pack(fill=tk.BOTH, expand=True)

        self.pid_tree = ttk.Treeview(
            pid_container,
            columns=("PID", "Name", "Path", "PPID", "Score", "Sleeper", "Level", "DataTX", "HoneyPot"),
            show="headings"
        )
        for col, w in [
            ("PID", 80), ("Name", 150), ("Path", 500),
            ("PPID", 80), ("Score", 80), ("Sleeper", 80),
            ("Level", 80), ("DataTX", 80), ("HoneyPot", 90)
        ]:
            self.pid_tree.heading(col, text=col)
            self.pid_tree.column(col, width=w, anchor=tk.W)

        self.pid_tree.tag_configure("RED", foreground="#FF5555")
        self.pid_tree.tag_configure("YELLOW", foreground="#FFFF55")
        self.pid_tree.tag_configure("GREEN", foreground="#55FF55")
        self.pid_tree.tag_configure("NONE", foreground="#EEEEEE")

        pid_scroll_y = ttk.Scrollbar(pid_container, orient=tk.VERTICAL, command=self.pid_tree.yview)
        pid_scroll_x = ttk.Scrollbar(pid_container, orient=tk.HORIZONTAL, command=self.pid_tree.xview)
        self.pid_tree.configure(yscrollcommand=pid_scroll_y.set, xscrollcommand=pid_scroll_x.set)

        pid_scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        pid_scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.pid_tree.pack(fill=tk.BOTH, expand=True)

        self.pid_tree.bind("<<TreeviewSelect>>", self.on_pid_select)

        graph_container = ttk.Frame(bottom_frame)
        graph_container.pack(fill=tk.BOTH, expand=True)

        self.graph_canvas = tk.Canvas(graph_container, bg="#000000", height=220)
        self.graph_canvas.pack(fill=tk.BOTH, expand=True)

    def build_anomalies_tab(self):
        container = ttk.Frame(self.tab_anomalies)
        container.pack(fill=tk.BOTH, expand=True)

        self.anom_tree = ttk.Treeview(
            container,
            columns=("Time", "PID", "Name", "Score", "Sleeper", "Level", "DataTX", "HoneyPot"),
            show="headings"
        )
        for col, w in [
            ("Time", 220), ("PID", 80), ("Name", 200),
            ("Score", 80), ("Sleeper", 80), ("Level", 80),
            ("DataTX", 80), ("HoneyPot", 90)
        ]:
            self.anom_tree.heading(col, text=col)
            self.anom_tree.column(col, width=w, anchor=tk.W)

        self.anom_tree.tag_configure("RED", foreground="#FF5555")
        self.anom_tree.tag_configure("YELLOW", foreground="#FFFF55")
        self.anom_tree.tag_configure("GREEN", foreground="#55FF55")
        self.anom_tree.tag_configure("NONE", foreground="#EEEEEE")

        scroll_y = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.anom_tree.yview)
        scroll_x = ttk.Scrollbar(container, orient=tk.HORIZONTAL, command=self.anom_tree.xview)
        self.anom_tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.anom_tree.pack(fill=tk.BOTH, expand=True)

        notes_frame = ttk.Frame(self.tab_anomalies)
        notes_frame.pack(fill=tk.BOTH, expand=True)

        self.notes_text = tk.Text(notes_frame, bg="#000000", fg="#00FF00", height=10)
        self.notes_text.pack(fill=tk.BOTH, expand=True)

    def build_baseline_tab(self):
        container = ttk.Frame(self.tab_baseline)
        container.pack(fill=tk.BOTH, expand=True)

        self.base_tree = ttk.Treeview(
            container,
            columns=("Name", "Path", "PPID", "FirstSeen", "LastSeen", "SeenCount", "Sleeper", "DataTX", "HoneyPot"),
            show="headings"
        )
        for col, w in [
            ("Name", 150), ("Path", 500), ("PPID", 80),
            ("FirstSeen", 200), ("LastSeen", 200),
            ("SeenCount", 100), ("Sleeper", 80),
            ("DataTX", 80), ("HoneyPot", 90)
        ]:
            self.base_tree.heading(col, text=col)
            self.base_tree.column(col, width=w, anchor=tk.W)

        scroll_y = ttk.Scrollbar(container, orient=tk.VERTICAL, command=self.base_tree.yview)
        scroll_x = ttk.Scrollbar(container, orient=tk.HORIZONTAL, command=self.base_tree.xview)
        self.base_tree.configure(yscrollcommand=scroll_y.set, xscrollcommand=scroll_x.set)

        scroll_y.pack(side=tk.RIGHT, fill=tk.Y)
        scroll_x.pack(side=tk.BOTTOM, fill=tk.X)
        self.base_tree.pack(fill=tk.BOTH, expand=True)

        self.refresh_baseline_table()

    def build_honeypot_tab(self):
        container = ttk.Frame(self.tab_honeypot)
        container.pack(fill=tk.BOTH, expand=True)

        self.hp_text = tk.Text(container, bg="#000000", fg="#00FF00")
        self.hp_text.pack(fill=tk.BOTH, expand=True)

    def build_cluster_tab(self):
        container = ttk.Frame(self.tab_cluster)
        container.pack(fill=tk.BOTH, expand=True)

        self.cluster_text = tk.Text(container, bg="#000000", fg="#00FFFF")
        self.cluster_text.pack(fill=tk.BOTH, expand=True)

    def build_queen_tab(self):
        container = ttk.Frame(self.tab_queen)
        container.pack(fill=tk.BOTH, expand=True)

        self.queen_text = tk.Text(container, bg="#000000", fg="#FF00FF")
        self.queen_text.pack(fill=tk.BOTH, expand=True)

    def build_settings_tab(self):
        frame = ttk.Frame(self.tab_settings)
        frame.pack(fill=tk.BOTH, expand=True)

        lbl = ttk.Label(frame, text="Fusion Settings", font=("Segoe UI", 14))
        lbl.pack(pady=10)

        info = ttk.Label(
            frame,
            text=f"Scan interval: {Config.SCAN_INTERVAL_SECONDS}s\n"
                 f"Sleeper window: {Config.SLEEPER_WINDOW_MINUTES} minutes\n"
                 f"Data-TX flag: outbound connections to non-private IPs.\n"
                 f"Honeypot: God-Mode v3 integrated with OverWatch.\n"
                 f"Auto-remediation: {'ENABLED' if Config.AUTO_REMEDIATE else 'DISABLED'}\n"
                 f"Queen risk threshold: {Config.QUEEN_RISK_THRESHOLD}",
            font=("Segoe UI", 10),
            justify=tk.LEFT
        )
        info.pack(pady=10)

    def process_events(self):
        try:
            while True:
                event = self.event_queue.get_nowait()
                if event["type"] == "process_update":
                    self.update_pid_table(event)
                elif event["type"] == "anomaly":
                    self.update_anomaly_table(event)
        except queue.Empty:
            pass

        self.root.after(500, self.process_events)

    def update_pid_table(self, event):
        pid = event["pid"]
        row_values = (
            pid,
            event["name"],
            event["path"],
            event["ppid"],
            event["score"],
            "YES" if event["sleeper"] else "NO",
            event["level"],
            "YES" if event["data_tx"] else "NO",
            "YES" if event["honeypot"] else "NO",
        )
        tag = event["level"]

        existing = None
        for item in self.pid_tree.get_children():
            vals = self.pid_tree.item(item, "values")
            if vals and int(vals[0]) == pid:
                existing = item
                break

        if existing:
            self.pid_tree.item(existing, values=row_values, tags=(tag,))
        else:
            self.pid_tree.insert("", tk.END, values=row_values, tags=(tag,))

    def update_anomaly_table(self, event):
        row_values = (
            event["timestamp"],
            event["pid"],
            event["name"],
            event["score"],
            "YES" if event["sleeper"] else "NO",
            event["level"],
            "YES" if event["data_tx"] else "NO",
            "YES" if event["honeypot"] else "NO",
        )
        tag = event["level"]
        self.anom_tree.insert("", tk.END, values=row_values, tags=(tag,))

        self.notes_text.insert(
            tk.END,
            f"[{event['timestamp']}] PID={event['pid']} Name={event['name']} "
            f"Score={event['score']} Level={event['level']} "
            f"DataTX={'YES' if event['data_tx'] else 'NO'} "
            f"HoneyPot={'YES' if event['honeypot'] else 'NO'}\n"
        )
        for n in event.get("notes", []):
            self.notes_text.insert(tk.END, f"    {n}\n")
        self.notes_text.insert(tk.END, "\n")
        self.notes_text.see(tk.END)

    def refresh_baseline_table(self):
        for item in self.base_tree.get_children():
            self.base_tree.delete(item)

        for profile in self.baseline.all_profiles():
            row_values = (
                profile.name,
                profile.path,
                profile.ppid,
                profile.first_seen.isoformat(),
                profile.last_seen.isoformat(),
                profile.seen_count,
                "YES" if profile.sleeper_flag else "NO",
                "YES" if profile.data_tx_flag else "NO",
                "YES" if profile.honeypot_flag else "NO",
            )
            self.base_tree.insert("", tk.END, values=row_values)

    def on_pid_select(self, event):
        sel = self.pid_tree.selection()
        if not sel:
            return
        item = sel[0]
        vals = self.pid_tree.item(item, "values")
        if not vals:
            return
        pid = int(vals[0])
        name = vals[1]
        path = vals[2]

        self.selected_pid = pid
        self.selected_profile = self.baseline.get(name, path)
        self.draw_graph()

    def draw_graph(self):
        self.graph_canvas.delete("all")
        if not self.selected_profile or not self.selected_profile.behavior_log:
            self.graph_canvas.create_text(
                10, 10, anchor="nw",
                fill="#00FF00",
                text="No behavior data yet for selected PID."
            )
            return

        w = self.graph_canvas.winfo_width()
        h = self.graph_canvas.winfo_height()
        if w <= 0:
            w = 800
        if h <= 0:
            h = 220

        data = self.selected_profile.behavior_log[-Config.MAX_BEHAVIOR_POINTS:]
        cpus = [b["cpu"] for b in data]
        mems = [b["mem"] for b in data]

        max_cpu = max(cpus) if cpus else 1
        max_mem = max(mems) if mems else 1

        margin = 20
        plot_w = w - 2 * margin
        plot_h = h - 2 * margin

        def scale_x(i, n):
            if n <= 1:
                return margin
            return margin + (plot_w * i) / (n - 1)

        def scale_y_cpu(v):
            return margin + plot_h - (plot_h * v / max_cpu)

        def scale_y_mem(v):
            return margin + plot_h - (plot_h * v / max_mem)

        self.graph_canvas.create_rectangle(
            margin, margin,
            margin + plot_w, margin + plot_h,
            outline="#444444"
        )

        n = len(data)
        for i in range(1, n):
            x1 = scale_x(i - 1, n)
            x2 = scale_x(i, n)

            y1_cpu = scale_y_cpu(cpus[i - 1])
            y2_cpu = scale_y_cpu(cpus[i])
            self.graph_canvas.create_line(x1, y1_cpu, x2, y2_cpu, fill="#00FF00", width=2)

            y1_mem = scale_y_mem(mems[i - 1])
            y2_mem = scale_y_mem(mems[i])
            self.graph_canvas.create_line(x1, y1_mem, x2, y2_mem, fill="#00AAFF", width=1)

        self.graph_canvas.create_text(
            margin + 5, margin + 5, anchor="nw",
            fill="#00FF00",
            text=f"CPU (green) max={max_cpu:.1f}%"
        )
        self.graph_canvas.create_text(
            margin + 5, margin + 25, anchor="nw",
            fill="#00AAFF",
            text=f"MEM (blue) max={max_mem} bytes"
        )

    def update_honeypot_view(self):
        replay_text = self.analytics.render_replay()
        self.hp_text.delete("1.0", tk.END)
        self.hp_text.insert(tk.END, replay_text)
        self.hp_text.see(tk.END)
        self.root.after(5000, self.update_honeypot_view)

    def update_cluster_view(self):
        self.cluster_text.delete("1.0", tk.END)
        self.cluster_text.insert(tk.END, f"Node ID: {Config.NODE_ID}\n")
        self.cluster_text.insert(tk.END, f"Leader ID: {self.swarm.leader_id}\n")
        self.cluster_text.insert(tk.END, f"State version: {self.swarm.state_version}\n\n")
        self.cluster_text.insert(tk.END, "Cluster state:\n")
        for node, state in self.swarm.cluster_state.items():
            self.cluster_text.insert(tk.END, f"  {node}: {json.dumps(state)[:200]}\n")
        self.cluster_text.see(tk.END)
        self.root.after(5000, self.update_cluster_view)

    def update_queen_view(self):
        self.queen_text.delete("1.0", tk.END)
        self.queen_text.insert(tk.END, "Queen Global Risk Field:\n\n")
        risk_map = self.queen.global_risk()
        for entity, risk in risk_map.items():
            self.queen_text.insert(tk.END, f"  {entity}: risk={risk:.3f}\n")
        self.queen_text.see(tk.END)
        self.root.after(5000, self.update_queen_view)


# =========================
# Fusion Core
# =========================

class FusionCore:
    def __init__(self):
        self.baseline = Baseline()
        self.event_queue = queue.Queue()

        self.ml_engine = MLEngine()
        self.llm_engine = LLMEngine(Config.LLM_LOCAL_MODEL_PATH, Config.LLM_REMOTE_ENDPOINT)
        self.analytics = DeceptionAnalytics()
        self.swarm = SwarmConsensus(Config.NODE_ID, Config.SWARM_PEERS)
        self.intel = ThreatIntel()
        self.sandbox = SandboxManager()
        self.queen = Queen()
        self.chain_engine = AttackChainEngine()
        self.event_bus = EventBus()
        self.remediator = AutoRemediator(self.sandbox, self.intel)

        samples = []
        self.ml_engine.train_models(samples)
        self.llm_engine.load_local_model()
        self.swarm.start()
        self.event_bus.start()

        self.honeypot = HoneypotCore(self.ml_engine, self.llm_engine, self.analytics, self.swarm,
                                     self.event_bus, self.queen, self.chain_engine)
        self.honeypot.start_protocols()
        self.honeypot.start_background_loops()

        self.overwatch_core = OverWatchCore(self.event_queue, self.baseline, self.honeypot,
                                            self.intel, self.remediator, self.queen, self.event_bus)
        self.overwatch_core.start()

        self.agent = LocalAgent(Config.NODE_ID, self.event_queue, self.swarm)
        self.agent.start()

    def shutdown(self):
        self.overwatch_core.stop()
        self.honeypot.stop_event.set()
        self.honeypot.save_state()
        self.swarm.stop_event.set()
        self.event_bus.stop_event.set()


def main():
    log_event("bootstrap", "INFO", "Starting OverWatch + God-Mode Honeypot v8 Queen", {"version": Config.VERSION})
    fusion = FusionCore()

    root = tk.Tk()
    gui = FusionGUI(root, fusion.baseline, fusion.event_queue, fusion.honeypot, fusion.analytics, fusion.swarm, fusion.queen)

    def on_close():
        fusion.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
