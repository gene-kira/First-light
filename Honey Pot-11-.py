# =========================
#  UNIVERSAL AUTOLOADER
# =========================

import sys
import subprocess
import platform

REQUIRED_LIBS = []
OPTIONAL_LIBS = ["tkinter"]

def try_import(lib):
    try:
        __import__(lib)
        return True
    except Exception:
        return False

def install_lib(lib):
    try:
        print(f"[AUTOLOADER] Attempting to install missing library: {lib}")
        subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
        return True
    except Exception:
        print(f"[AUTOLOADER] Failed to install {lib}. Continuing without it.")
        return False

def autoload():
    os_name = platform.system().lower()
    print(f"[AUTOLOADER] Detected OS: {os_name}")
    for lib in REQUIRED_LIBS:
        if not try_import(lib):
            install_lib(lib)
    for lib in OPTIONAL_LIBS:
        if not try_import(lib):
            print(f"[AUTOLOADER] Optional library '{lib}' not available. GUI features disabled.")

autoload()

# =========================
#  IMPORTS
# =========================

import os
import json
import time
import random
import threading
import socket
import hashlib
import ssl
import base64
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
from datetime import datetime
from typing import Dict, Any, List, Optional

try:
    import tkinter as tk
    from tkinter import ttk
except Exception:
    tk = None
    ttk = None

# =========================
#  CONFIG (LOCKED)
# =========================

class Config:
    HONEYPOT_NAME = "AI_HONEYPOT_CORE_ELITE_ULTRA_PLUS_V2"
    LOG_DIR = "logs"
    HONEY_DATA_DIR = "honey_data"
    SESSION_TIMEOUT_SECONDS = 900

    SSH_BIND_HOST = "0.0.0.0"
    SSH_BIND_PORT = 2222

    HTTP_BIND_HOST = "0.0.0.0"
    HTTP_BIND_PORT = 8080

    REMOTE_DASHBOARD_HOST = "0.0.0.0"
    REMOTE_DASHBOARD_PORT = 9090

    WEB_SOC_HOST = "0.0.0.0"
    WEB_SOC_PORT = 9443

    SWARM_ENABLED = True
    SWARM_PEERS = []  # e.g. ["192.168.1.10:9091", "192.168.1.11:9091"]

    NETWORK_SCAN_INTERVAL = 60
    ANOMALY_SCORE_THRESHOLD = 0.7

    AUTO_BLOCK_ENABLED = True
    AUTO_BLOCK_ONLY_ON_EXFIL = True

    TAMPER_CHECK_INTERVAL = 60
    CONTAINMENT_ENABLED = True
    USER_ACTIVITY_INTERVAL = 45

    DASHBOARD_PASSWORD = "changeme"
    DASHBOARD_MFA_SECRET = "mfa-secret-demo"

    SWARM_TLS_ENABLED = True

    JWT_SECRET = "super-secret-jwt-key"
    JWT_EXP_MINUTES = 30

    SESSION_REPLAY_KEY = "replay-key-demo"

    PROCESS_MONITOR_INTERVAL = 30
    DNS_MONITOR_INTERVAL = 30

    PACKET_CAPTURE_INTERVAL = 20
    SYSCALL_MONITOR_INTERVAL = 25

    SIEM_EXPORT_INTERVAL = 120

    TOPOLOGY_REFRESH_INTERVAL = 90

    COUNTER_INTEL_INTERVAL = 60

    @classmethod
    def freeze(cls):
        def locked_setattr(self, name, value):
            raise AttributeError("Config is tamper-locked")
        cls.__setattr__ = locked_setattr

Config.freeze()

# =========================
#  TAMPER PROOFING
# =========================

class TamperGuard(threading.Thread):
    def __init__(self, script_path: str):
        super().__init__(daemon=True)
        self.script_path = script_path
        self.original_hash = self.compute_hash()

    def compute_hash(self) -> str:
        try:
            with open(self.script_path, "rb") as f:
                data = f.read()
            return hashlib.sha256(data).hexdigest()
        except Exception:
            return "UNKNOWN"

    def run(self):
        while True:
            time.sleep(Config.TAMPER_CHECK_INTERVAL)
            current_hash = self.compute_hash()
            if current_hash != self.original_hash:
                print("[TAMPERGUARD] WARNING: Script file hash changed! Possible tampering detected.")

# =========================
#  UTILS
# =========================

class FileUtils:
    @staticmethod
    def ensure_dir(path: str) -> None:
        if not os.path.exists(path):
            os.makedirs(path, exist_ok=True)

    @staticmethod
    def write_jsonl(path: str, record: Dict[str, Any]) -> None:
        FileUtils.ensure_dir(os.path.dirname(path))
        with open(path, "a", encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")

# =========================
#  SIMPLE JWT (HMAC-BASED)
# =========================

class SimpleJWT:
    @staticmethod
    def _b64encode(data: bytes) -> str:
        return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")

    @staticmethod
    def _b64decode(data: str) -> bytes:
        padding = "=" * (-len(data) % 4)
        return base64.urlsafe_b64decode(data + padding)

    @staticmethod
    def create(payload: Dict[str, Any], secret: str, exp_minutes: int) -> str:
        header = {"alg": "HS256", "typ": "JWT"}
        payload = dict(payload)
        payload["exp"] = int(time.time() + exp_minutes * 60)
        header_b64 = SimpleJWT._b64encode(json.dumps(header).encode("utf-8"))
        payload_b64 = SimpleJWT._b64encode(json.dumps(payload).encode("utf-8"))
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
        sig_b64 = SimpleJWT._b64encode(sig)
        return f"{header_b64}.{payload_b64}.{sig_b64}"

    @staticmethod
    def verify(token: str, secret: str) -> Optional[Dict[str, Any]]:
        try:
            header_b64, payload_b64, sig_b64 = token.split(".")
            signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
            expected_sig = hmac.new(secret.encode("utf-8"), signing_input, hashlib.sha256).digest()
            if SimpleJWT._b64encode(expected_sig) != sig_b64:
                return None
            payload = json.loads(SimpleJWT._b64decode(payload_b64).decode("utf-8"))
            if int(time.time()) > payload.get("exp", 0):
                return None
            return payload
        except Exception:
            return None

# =========================
#  MFA (SIMPLE TIME-BASED CODE)
# =========================

class SimpleMFA:
    @staticmethod
    def generate_code(secret: str) -> str:
        window = int(time.time() // 30)
        data = f"{secret}:{window}".encode("utf-8")
        digest = hashlib.sha256(data).hexdigest()
        return digest[:6]

    @staticmethod
    def verify_code(secret: str, code: str) -> bool:
        return code == SimpleMFA.generate_code(secret)

# =========================
#  ENCRYPTED SESSION REPLAY (SAFE STUB)
# =========================

class EncryptedReplay:
    @staticmethod
    def encrypt(data: str, key: str) -> str:
        key_bytes = key.encode("utf-8")
        data_bytes = data.encode("utf-8")
        out = bytearray()
        for i, b in enumerate(data_bytes):
            out.append(b ^ key_bytes[i % len(key_bytes)])
        return base64.b64encode(out).decode("utf-8")

    @staticmethod
    def decrypt(data: str, key: str) -> str:
        try:
            key_bytes = key.encode("utf-8")
            enc = base64.b64decode(data.encode("utf-8"))
            out = bytearray()
            for i, b in enumerate(enc):
                out.append(b ^ key_bytes[i % len(key_bytes)])
            return out.decode("utf-8", errors="ignore")
        except Exception:
            return ""

# =========================
#  HONEY DATA + DECEPTION BAIT
# =========================

class HoneyDataGenerator:
    def __init__(self, base_dir: str):
        self.base_dir = base_dir
        FileUtils.ensure_dir(self.base_dir)

    def generate_fake_credentials(self) -> Dict[str, str]:
        return {
            "username": random.choice(["admin", "root", "service", "backup"]),
            "password": random.choice(["P@ssw0rd!", "Summer2026!", "123qweASD", "backup!2026"]),
        }

    def generate_fake_customer_record(self) -> Dict[str, Any]:
        return {
            "id": random.randint(100000, 999999),
            "name": random.choice(["John Doe", "Jane Smith", "Alex Carter", "Chris Lane"]),
            "email": random.choice(["test@example.com", "user@domain.com", "contact@fakecorp.com"]),
            "balance": round(random.uniform(10.0, 5000.0), 2),
        }

    def materialize_honey_data(self) -> None:
        creds_path = os.path.join(self.base_dir, "credentials.json")
        customers_path = os.path.join(self.base_dir, "customers.json")

        creds = [self.generate_fake_credentials() for _ in range(10)]
        customers = [self.generate_fake_customer_record() for _ in range(50)]

        with open(creds_path, "w", encoding="utf-8") as f:
            json.dump(creds, f, indent=2)

        with open(customers_path, "w", encoding="utf-8") as f:
            json.dump(customers, f, indent=2)

        bait_dir = os.path.join(self.base_dir, "ransomware_bait")
        FileUtils.ensure_dir(bait_dir)
        for name in ["finance_2026.xlsx", "passwords_master.txt", "crypto_wallet_backup.dat"]:
            with open(os.path.join(bait_dir, name), "w", encoding="utf-8") as f:
                f.write("DECOY DATA – NO REAL SECRETS HERE\n")

# =========================
#  FAKE OS + PROCESSES
# =========================

class FakeOS:
    def ps(self) -> str:
        procs = [
            ("1", "systemd"),
            ("234", "sshd"),
            ("567", "postgres"),
            ("890", "nginx"),
            ("1024", "chrome"),
            ("2048", "powershell"),
            ("3000", "python honeypot.py"),
        ]
        out = "PID   CMD\n"
        for pid, cmd in procs:
            out += f"{pid:<5} {cmd}\n"
        return out

    def proc_cpuinfo(self) -> str:
        return "Intel(R) Xeon(R) CPU FAKE @ 3.40GHz\n"

    def meminfo(self) -> str:
        return "MemTotal:       16384 kB\nMemFree:         8192 kB\n"

# =========================
#  PACKET-LEVEL FAKE TRAFFIC (SAFE LOG-ONLY)
# =========================

class PacketLevelFakeTraffic(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True

    def run(self):
        while self.running:
            time.sleep(random.randint(15, 40))
            print("[PKTFAKE] Simulated TCP SYN to internal service 10.0.0.5:443")
            print("[PKTFAKE] Simulated UDP DNS query to 10.0.0.53")

# =========================
#  FAKE USER ACTIVITY + SESSIONS
# =========================

class FakeUserActivity(threading.Thread):
    def __init__(self, decoy_env: "DecoyEnvironment"):
        super().__init__(daemon=True)
        self.decoy_env = decoy_env
        self.running = True

    def run(self):
        while self.running:
            time.sleep(Config.USER_ACTIVITY_INTERVAL)
            self.decoy_env.fake_fs["/var/log/app.log"] += "INFO User login from 192.168.1.50\n"
            self.decoy_env.fake_fs["/home/admin/.bash_history"] = "ls -la\ncat /etc/passwd\nps aux\nsudo su\n"
            self.decoy_env.fake_fs["/etc/cron.d/backup"] = "0 3 * * * root /usr/local/bin/backup.sh\n"
            self.decoy_env.fake_fs["/var/log/auth.log"] += "Accepted password for admin from 192.168.1.51 port 22 ssh2\n"
            print("[FAKEUSER] Simulated user activity and sessions in decoy environment")

# =========================
#  AI-LIKE FAKE FILESYSTEM MUTATIONS (SAFE)
# =========================

class FakeFSMutator(threading.Thread):
    def __init__(self, decoy_env: "DecoyEnvironment"):
        super().__init__(daemon=True)
        self.decoy_env = decoy_env
        self.running = True

    def run(self):
        while self.running:
            time.sleep(random.randint(60, 120))
            name = random.choice(["report", "backup", "config", "notes"])
            ext = random.choice([".txt", ".log", ".cfg", ".json"])
            path = f"/tmp/{name}_{random.randint(1000,9999)}{ext}"
            content = f"FAKE FILE GENERATED AT {datetime.utcnow().isoformat()} WITH TAG {random.randint(1,9999)}\n"
            self.decoy_env.fake_fs[path] = content
            print(f"[FSMUTATOR] Generated fake file {path}")

# =========================
#  FAKE CLOUD SERVICES (AWS/Azure/GCP DECOYS + WORKLOADS)
# =========================

class FakeCloudServices:
    @staticmethod
    def fake_aws_response() -> Dict[str, Any]:
        return {
            "Account": "123456789012",
            "Region": "us-east-1",
            "Services": ["EC2", "S3", "RDS"],
            "Note": "FAKE AWS METADATA"
        }

    @staticmethod
    def fake_azure_response() -> Dict[str, Any]:
        return {
            "SubscriptionId": "fake-sub-0000",
            "Tenant": "fake-tenant",
            "Services": ["VM", "Blob", "SQL"],
            "Note": "FAKE AZURE METADATA"
        }

    @staticmethod
    def fake_gcp_response() -> Dict[str, Any]:
        return {
            "ProjectId": "fake-project",
            "Zone": "us-central1-a",
            "Services": ["Compute", "Storage", "SQL"],
            "Note": "FAKE GCP METADATA"
        }

    @staticmethod
    def fake_cloud_workloads() -> Dict[str, Any]:
        return {
            "aws_ec2_instances": [
                {"id": "i-FAKE123", "state": "running", "tags": {"Name": "web-01"}},
                {"id": "i-FAKE456", "state": "stopped", "tags": {"Name": "db-01"}},
            ],
            "azure_vms": [
                {"name": "vm-fake-01", "status": "running"},
                {"name": "vm-fake-02", "status": "deallocated"},
            ],
            "gcp_compute": [
                {"name": "gcp-fake-01", "status": "RUNNING"},
            ],
            "note": "All workloads are fake decoys."
        }

# =========================
#  FAKE KUBERNETES CLUSTER
# =========================

class FakeKubernetesCluster:
    @staticmethod
    def fake_cluster_state() -> Dict[str, Any]:
        return {
            "cluster_name": "fake-k8s-cluster",
            "nodes": [
                {"name": "node-1", "status": "Ready"},
                {"name": "node-2", "status": "Ready"},
            ],
            "pods": [
                {"name": "web-frontend-abc123", "namespace": "default", "status": "Running"},
                {"name": "db-backend-def456", "namespace": "default", "status": "Running"},
                {"name": "metrics-server-xyz789", "namespace": "kube-system", "status": "Running"},
            ],
            "services": [
                {"name": "web-service", "type": "ClusterIP", "ports": [80]},
                {"name": "db-service", "type": "ClusterIP", "ports": [5432]},
            ],
            "note": "Fake Kubernetes cluster state for deception."
        }

# =========================
#  FAKE WINDOWS DOMAIN CONTROLLER
# =========================

class FakeWindowsDomainController:
    @staticmethod
    def fake_dc_info() -> Dict[str, Any]:
        return {
            "domain_name": "FAKECORP.LOCAL",
            "dc_name": "DC01.FAKECORP.LOCAL",
            "users": [
                {"sam": "Administrator", "groups": ["Domain Admins", "Enterprise Admins"]},
                {"sam": "svc_backup", "groups": ["Backup Operators"]},
            ],
            "groups": [
                "Domain Admins",
                "Enterprise Admins",
                "Backup Operators",
                "Remote Desktop Users",
            ],
            "note": "Fake Active Directory domain controller metadata."
        }

# =========================
#  FAKE VPN + FAKE SSO PROVIDER
# =========================

class FakeVPNSSO:
    @staticmethod
    def fake_vpn_status() -> Dict[str, Any]:
        return {
            "vpn_name": "FakeCorpVPN",
            "connected_users": [
                {"user": "admin", "ip": "10.8.0.2"},
                {"user": "devops", "ip": "10.8.0.3"},
            ],
            "note": "Fake VPN status for deception."
        }

    @staticmethod
    def fake_sso_status() -> Dict[str, Any]:
        return {
            "provider": "FakeSSO",
            "apps": ["FakeCRM", "FakeERP", "FakeMail"],
            "sessions": [
                {"user": "admin", "app": "FakeCRM"},
                {"user": "user1", "app": "FakeMail"},
            ],
            "note": "Fake SSO provider metadata."
        }

# =========================
#  FAKE MICROSERVICES CLUSTER
# =========================

class FakeMicroservicesCluster:
    @staticmethod
    def fake_services() -> Dict[str, Any]:
        return {
            "services": [
                {"name": "auth-service", "version": "1.2.3", "status": "Healthy"},
                {"name": "payment-service", "version": "2.0.1", "status": "Degraded"},
                {"name": "inventory-service", "version": "1.0.0", "status": "Healthy"},
            ],
            "note": "Fake microservices topology for deception."
        }

# =========================
#  AI-GENERATED DYNAMIC ENTERPRISE TOPOLOGY
# =========================

class DynamicEnterpriseTopology:
    def __init__(self):
        self.current_topology: Dict[str, Any] = {}

    def generate(self) -> Dict[str, Any]:
        sites = []
        segments = ["corp", "dmz", "mgmt", "prod", "backup", "lab"]
        site_names = ["HQ", "DC1", "DC2", "Branch1", "Branch2"]
        for name in site_names:
            sites.append({
                "name": name,
                "location": random.choice(["New York", "Virginia", "Texas", "London", "Berlin"]),
                "segments": random.sample(segments, k=random.randint(2, 4))
            })
        critical_assets = []
        asset_names = ["ERP-DB", "Mail-Cluster", "Backup-Vault", "HR-DB", "Finance-API", "R&D-Cluster"]
        for asset in asset_names:
            critical_assets.append({
                "name": asset,
                "segment": random.choice(segments),
                "risk": random.choice(["low", "medium", "high"])
            })
        self.current_topology = {
            "sites": sites,
            "critical_assets": critical_assets,
            "generated_at": datetime.utcnow().isoformat(),
            "note": "Dynamically generated enterprise topology for deception."
        }
        return self.current_topology

    def get(self) -> Dict[str, Any]:
        return self.current_topology or self.generate()

# =========================
#  DECOY ENVIRONMENT
# =========================

class DecoyEnvironment:
    def __init__(self, honey_data_dir: str, topology: DynamicEnterpriseTopology):
        self.honey_data_dir = honey_data_dir
        self.fake_fs: Dict[str, Any] = {}
        self.fake_os = FakeOS()
        self.topology = topology
        self._build_fake_fs()

    def _build_fake_fs(self) -> None:
        self.fake_fs = {
            "/etc/passwd": "root:x:0:0:root:/root:/bin/bash\nadmin:x:1000:1000::/home/admin:/bin/bash\n",
            "/etc/shadow": "root:*:19876:0:99999:7:::\nadmin:*:19876:0:99999:7:::\n",
            "/var/log/app.log": "INFO Starting fake service\nWARN Deprecated config\n",
            "/var/log/auth.log": "Accepted password for admin from 203.0.113.5 port 22 ssh2\n",
            "/opt/app/config.json": json.dumps({"debug": False, "db_host": "127.0.0.1"}, indent=2),
            "/mnt/honey_data": f"POINTS_TO::{self.honey_data_dir}",
            "/proc/cpuinfo": self.fake_os.proc_cpuinfo(),
            "/proc/meminfo": self.fake_os.meminfo(),
            "/etc/cron.d/backup": "0 3 * * * root /usr/local/bin/backup.sh\n",
            "/home/admin/.bash_history": "",
            "/srv/fake_db/schema.sql": "CREATE TABLE users(id INT, name TEXT, email TEXT);\n",
            "/srv/fake_db/data_dump.sql": "INSERT INTO users VALUES(1,'John Doe','john@example.com');\n",
            "/srv/fake_api/keys.txt": "API_KEY=FAKE-1234567890-DO-NOT-USE\n",
            "/cloud/aws/meta.json": json.dumps(FakeCloudServices.fake_aws_response(), indent=2),
            "/cloud/azure/meta.json": json.dumps(FakeCloudServices.fake_azure_response(), indent=2),
            "/cloud/gcp/meta.json": json.dumps(FakeCloudServices.fake_gcp_response(), indent=2),
            "/cloud/workloads.json": json.dumps(FakeCloudServices.fake_cloud_workloads(), indent=2),
            "/k8s/cluster_state.json": json.dumps(FakeKubernetesCluster.fake_cluster_state(), indent=2),
            "/ad/dc_info.json": json.dumps(FakeWindowsDomainController.fake_dc_info(), indent=2),
            "/vpn/status.json": json.dumps(FakeVPNSSO.fake_vpn_status(), indent=2),
            "/sso/status.json": json.dumps(FakeVPNSSO.fake_sso_status(), indent=2),
            "/microservices/topology.json": json.dumps(FakeMicroservicesCluster.fake_services(), indent=2),
            "/enterprise/topology.json": json.dumps(self.topology.get(), indent=2),
        }

    def refresh_topology(self):
        self.fake_fs["/enterprise/topology.json"] = json.dumps(self.topology.generate(), indent=2)

    def list_files(self) -> List[str]:
        return list(self.fake_fs.keys())

    def read_file(self, path: str) -> Optional[str]:
        return self.fake_fs.get(path)

    def simulate_service_banner(self, service_name: str) -> str:
        if service_name == "fake_ssh":
            return "SSH-2.0-OpenSSH_7.9p1 Debian-10 FAKE\n"
        if service_name == "fake_http":
            return "HTTP/1.1 200 OK\r\nServer: FakeCorp/1.0\r\n\r\n"
        if service_name == "fake_db":
            return "PostgreSQL 12.3 on x86_64-pc-linux-gnu, compiled by gcc, 64-bit (FAKE)\n"
        if service_name == "fake_cloud":
            return "FAKE CLOUD METADATA SERVICE\n"
        if service_name == "fake_k8s":
            return "Kubernetes v1.26.0 (FAKE) – 2 nodes, 3 pods\n"
        if service_name == "fake_ad":
            return "Microsoft Active Directory Domain Services (FAKECORP.LOCAL)\n"
        if service_name == "fake_vpn":
            return "FakeCorp VPN Gateway v1.0 (FAKE)\n"
        if service_name == "fake_sso":
            return "FakeSSO Identity Provider v2.1 (FAKE)\n"
        if service_name == "fake_micro":
            return "Fake Microservices Mesh v0.9 (FAKE)\n"
        return "Unknown service\n"

# =========================
#  EVENT LOGGER
# =========================

class EventLogger:
    def __init__(self, log_dir: str):
        self.log_dir = log_dir
        FileUtils.ensure_dir(self.log_dir)

    def _log_path(self, name: str) -> str:
        return os.path.join(self.log_dir, f"{name}.jsonl")

    def log_event(self, event_type: str, payload: Dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "payload": payload,
        }
        FileUtils.write_jsonl(self._log_path("events"), record)

    def log_session(self, session_id: str, meta: Dict[str, Any]) -> None:
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": session_id,
            "meta": meta,
        }
        FileUtils.write_jsonl(self._log_path("sessions"), record)

# =========================
#  WORK INVENTORY
# =========================

class WorkInventory:
    def __init__(self):
        self.inventory: Dict[str, List[Dict[str, Any]]] = {
            "sessions": [],
            "intrusions": [],
            "network_scans": [],
            "commands": [],
            "anomalies": [],
            "deception_changes": [],
            "swarm_sync": [],
            "autoblocks": [],
            "containment": [],
            "fingerprints": [],
            "replay": [],
            "startup_scan": [],
            "process_monitor": [],
            "dns_monitor": [],
            "behavior_clusters": [],
            "packet_capture": [],
            "syscalls": [],
            "siem_exports": [],
            "kernel_packets": [],
            "kernel_syscalls": [],
            "topology_updates": [],
            "swarm_correlations": [],
            "counter_intel": [],
        }

    def add(self, category: str, data: Dict[str, Any]):
        if category not in self.inventory:
            self.inventory[category] = []
        self.inventory[category].append({
            "timestamp": datetime.utcnow().isoformat(),
            **data
        })

    def get(self, category: str) -> List[Dict[str, Any]]:
        return self.inventory.get(category, [])

    def all(self) -> Dict[str, List[Dict[str, Any]]]:
        return self.inventory

# =========================
#  THREAT INTENT + PERSONA
# =========================

class ThreatIntentClassifier:
    def classify(self, command: str) -> str:
        if any(x in command for x in ["nmap", "ls", "cat", "whoami", "ps"]):
            return "recon"
        if any(x in command for x in ["chmod", "chown", "sudo", "su"]):
            return "privilege_escalation"
        if any(x in command for x in ["scp", "wget", "curl", "ftp"]):
            return "exfiltration"
        if any(x in command for x in ["crontab", "systemctl", "service"]):
            return "persistence"
        return "unknown"

class ThreatPersonaEngine:
    def persona(self, event: Dict[str, Any]) -> str:
        cmd = event["payload"].get("command", "")
        if "wget" in cmd or "curl" in cmd:
            return "malware_dropper"
        if "nmap" in cmd:
            return "scanner"
        if "python" in cmd or "bash" in cmd:
            return "script_operator"
        return "unknown"

# =========================
#  ATTACKER FINGERPRINTING
# =========================

class AttackerFingerprint:
    def fingerprint(self, ip: str, command: str, user_agent: Optional[str] = None) -> Dict[str, Any]:
        return {
            "ip": ip,
            "primary_tool": command.split(" ")[0] if command else "",
            "user_agent": user_agent or "unknown",
            "tags": self._tags(command),
        }

    def _tags(self, command: str) -> List[str]:
        tags = []
        if "nmap" in command:
            tags.append("scanner")
        if "wget" in command or "curl" in command:
            tags.append("downloader")
        if "powershell" in command:
            tags.append("windows_operator")
        if "nc " in command:
            tags.append("tunnel_builder")
        return tags

# =========================
#  ATTACKER BEHAVIORAL CLUSTERING (STUB)
# =========================

class BehavioralClusterEngine:
    def __init__(self):
        self.profiles: Dict[str, Dict[str, Any]] = {}

    def update_profile(self, ip: str, command: str, intent: str, persona: str):
        profile = self.profiles.get(ip, {"commands": [], "intents": set(), "personas": set()})
        profile["commands"].append(command)
        profile["intents"].add(intent)
        profile["personas"].add(persona)
        self.profiles[ip] = profile

    def get_cluster_label(self, ip: str) -> str:
        profile = self.profiles.get(ip)
        if not profile:
            return "unknown_cluster"
        intents = profile["intents"]
        if "exfiltration" in intents and "privilege_escalation" in intents:
            return "aggressive_intruder"
        if "recon" in intents and len(profile["commands"]) > 10:
            return "persistent_scanner"
        if "persistence" in intents:
            return "backdoor_operator"
        return "mixed_activity"

# =========================
#  VULNERABILITY SIMULATOR
# =========================

class VulnerabilitySimulator:
    def fake_cve_banner(self) -> str:
        return "OpenSSL 1.0.2k (CVE-2023-FAKE-9999) Vulnerable build\n"

    def fake_kernel_version(self) -> str:
        return "Linux fakehost 4.15.0-99-generic #100-Ubuntu SMP FAKE\n"

# =========================
#  DEEPER + DEEP-LEARNING-LIKE ANOMALY DETECTOR (SAFE STUB)
# =========================

class MLAnomalyDetector:
    def __init__(self):
        self.command_counts: Dict[str, int] = {}
        self.total_commands = 0
        self.sequence_window: List[str] = []
        self.max_window = 10

    def update(self, command: str):
        key = command.split(" ")[0]
        self.command_counts[key] = self.command_counts.get(key, 0) + 1
        self.total_commands += 1
        self.sequence_window.append(key)
        if len(self.sequence_window) > self.max_window:
            self.sequence_window.pop(0)

    def score_frequency(self, command: str) -> float:
        if self.total_commands == 0:
            return 0.0
        key = command.split(" ")[0]
        freq = self.command_counts.get(key, 0) / self.total_commands
        return max(0.0, 1.0 - freq)

    def score_sequence(self) -> float:
        unique = len(set(self.sequence_window))
        if not self.sequence_window:
            return 0.0
        diversity = unique / len(self.sequence_window)
        return diversity * 0.5

    def deep_model_score(self, command: str) -> float:
        rare_tokens = ["nc", "powershell", "meterpreter", "msfconsole"]
        bonus = 0.2 if any(t in command for t in rare_tokens) else 0.0
        return bonus

    def score(self, command: str) -> float:
        base = self.score_frequency(command) + self.score_sequence()
        return min(1.0, base + self.deep_model_score(command))

# =========================
#  BASIC ANOMALY DETECTOR
# =========================

class AnomalyDetector:
    def __init__(self, threshold: float, ml_detector: MLAnomalyDetector):
        self.threshold = threshold
        self.ml = ml_detector

    def score_event(self, event: Dict[str, Any]) -> float:
        base = random.uniform(0.0, 0.5)
        payload = event.get("payload", {})
        cmd = payload.get("command", "") or ""
        suspicious_keywords = ["wget", "curl", "nc", "bash", "sh", "python", "chmod", "chown", "nmap"]
        if any(k in cmd for k in suspicious_keywords):
            base += 0.4
        ml_score = self.ml.score(cmd)
        return min(base + 0.3 * ml_score, 1.0)

    def is_anomalous(self, event: Dict[str, Any]) -> bool:
        score = self.score_event(event)
        return score >= self.threshold

# =========================
#  SWARM FEDERATION (MESH STUB + TLS + ROUTING + CORRELATION)
# =========================

class SwarmMesh:
    def __init__(self, peers: List[str], core_ref=None):
        self.peers = peers
        self.last_pushed: List[Dict[str, Any]] = []
        self.core_ref = core_ref

    def _send_to_peer(self, peer: str, payload: Dict[str, Any]):
        try:
            host, port_str = peer.split(":")
            port = int(port_str)
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            if Config.SWARM_TLS_ENABLED:
                context = ssl.create_default_context()
                sock = context.wrap_socket(sock, server_hostname=host)
            sock.connect((host, port))
            data = json.dumps(payload).encode("utf-8")
            sock.sendall(data)
            sock.close()
        except Exception:
            pass

    def push_signature(self, signature: Dict[str, Any]):
        self.last_pushed.append(signature)
        payload = {"type": "swarm_signature", "data": signature}
        for peer in self.peers:
            self._send_to_peer(peer, payload)

    def mesh_route(self, signature: Dict[str, Any]):
        if not self.peers:
            return
        payload = {"type": "mesh_route", "data": signature}
        for peer in self.peers:
            self._send_to_peer(peer, payload)

    def pull_updates(self) -> Dict[str, Any]:
        updates = {"mesh_status": "ok", "updated_threshold": 0.75}
        if self.core_ref:
            self.core_ref.work.add("swarm_correlations", {
                "summary": "correlated threat intel across peers",
                "peers": self.peers,
                "last_pushed_count": len(self.last_pushed)
            })
        return updates

# =========================
#  REPLAY ENGINE (ENCRYPTED)
# =========================

class ReplayEngine:
    def replay(self, session_events: List[Dict[str, Any]]):
        raw = "\n".join(f"[{e.get('timestamp','?')}] {e.get('payload',{}).get('command','')}" for e in session_events)
        enc = EncryptedReplay.encrypt(raw, Config.SESSION_REPLAY_KEY)
        print("[REPLAY] Encrypted session replay payload:")
        print(enc)

# =========================
#  ATTACKER REPLAY SANDBOX (SAFE)
# =========================

class ReplaySandbox:
    def sandbox_replay(self, session_events: List[Dict[str, Any]]) -> str:
        commands = [e.get("payload", {}).get("command", "") for e in session_events]
        return "\n".join(f"SIMULATED: {c}" for c in commands if c)

# =========================
#  GEOIP STUB
# =========================

class GeoIP:
    def lookup(self, ip: str) -> str:
        if ip.startswith("203.0.113."):
            return "TestNet / Example Region"
        return "Unknown Region"

# =========================
#  INTRUSION ALERT (PORT-AWARE)
# =========================

class IntrusionAlert:
    def __init__(self):
        self.last_alerts: List[Dict[str, Any]] = []

    def alert(self, session_id: str, ip: str, port: int, region: str):
        msg = f"[INTRUDER DETECTED] IP {ip} on port {port} ({region}) — session {session_id}"
        print(msg)
        record = {
            "timestamp": datetime.utcnow().isoformat(),
            "session_id": session_id,
            "ip": ip,
            "port": port,
            "region": region,
            "message": msg,
        }
        self.last_alerts.append(record)

# =========================
#  REAL FIREWALL BLOCKING (SAFE WRAPPER + OUTBOUND)
# =========================

class FirewallBlocker:
    def __init__(self):
        self.blocked_ips: List[str] = []

    def block_ip(self, ip: str):
        if ip in self.blocked_ips:
            return
        self.blocked_ips.append(ip)
        os_name = platform.system().lower()
        print(f"[FIREWALL] Requesting block for IP {ip} on {os_name}")
        try:
            if "windows" in os_name:
                cmd = f'netsh advfirewall firewall add rule name="HoneypotBlock_{ip}" dir=out action=block remoteip={ip}'
                subprocess.run(cmd, shell=True)
            elif "linux" in os_name:
                cmd = ["iptables", "-A", "OUTPUT", "-d", ip, "-j", "DROP"]
                subprocess.run(cmd)
            elif "darwin" in os_name:
                cmd = ["pfctl", "-t", "honeypot_block_out", "-T", "add", ip]
                subprocess.run(cmd)
        except Exception:
            print("[FIREWALL] Failed to apply OS-level firewall rule (non-fatal).")

    def unblock_ip(self, ip: str):
        if ip in self.blocked_ips:
            self.blocked_ips.remove(ip)
        os_name = platform.system().lower()
        print(f"[FIREWALL] Requesting unblock for IP {ip} on {os_name}")
        try:
            if "windows" in os_name:
                cmd = f'netsh advfirewall firewall delete rule name="HoneypotBlock_{ip}"'
                subprocess.run(cmd, shell=True)
            elif "linux" in os_name:
                cmd = ["iptables", "-D", "OUTPUT", "-d", ip, "-j", "DROP"]
                subprocess.run(cmd)
            elif "darwin" in os_name:
                cmd = ["pfctl", "-t", "honeypot_block_out", "-T", "delete", ip]
                subprocess.run(cmd)
        except Exception:
            print("[FIREWALL] Failed to remove OS-level firewall rule (non-fatal).")

    def is_blocked(self, ip: str) -> bool:
        return ip in self.blocked_ips

# =========================
#  AUTO-BLOCKING (LOGICAL + FIREWALL)
# =========================

class AutoBlocker:
    def __init__(self, firewall: FirewallBlocker):
        self.firewall = firewall
        self.manual_override = False

    def should_block(self, ip: str, intent: str, command: str) -> bool:
        if not Config.AUTO_BLOCK_ENABLED:
            return False
        if self.manual_override:
            return False
        if Config.AUTO_BLOCK_ONLY_ON_EXFIL and intent != "exfiltration":
            return False
        if any(x in command for x in ["wget", "curl", "scp", "ftp"]):
            return True
        return False

    def block_ip(self, ip: str):
        self.firewall.block_ip(ip)

    def unblock_ip(self, ip: str):
        self.firewall.unblock_ip(ip)

    def is_blocked(self, ip: str) -> bool:
        return self.firewall.is_blocked(ip)

# =========================
#  SELF-EVOLVING DECEPTION + COUNTER-INTELLIGENCE
# =========================

class DeceptionEngine:
    def __init__(self, decoy_env: DecoyEnvironment, core_ref=None):
        self.decoy_env = decoy_env
        self.command_stats: Dict[str, int] = {}
        self.core_ref = core_ref

    def adapt_to_event(self, event: Dict[str, Any]) -> None:
        payload = event.get("payload", {})
        command = payload.get("command", "")

        key = command.split(" ")[0]
        self.command_stats[key] = self.command_stats.get(key, 0) + 1

        if "ls" in command:
            self.decoy_env.fake_fs["/tmp/backup.tar.gz"] = "FAKE_BACKUP_CONTENT"

        if "cat" in command and "/etc/passwd" in command:
            self.decoy_env.fake_fs["/etc/passwd"] += "# auto-added fake user\nfakeuser:x:2000:2000::/home/fakeuser:/bin/bash\n"

        if self.command_stats.get("wget", 0) > 3:
            self.decoy_env.fake_fs["/var/log/security.log"] = "ALERT: multiple wget attempts detected (FAKE)\n"

        if self.command_stats.get("nmap", 0) > 2:
            self.decoy_env.fake_fs["/etc/firewall.conf"] = "FAKE_RULE: block 203.0.113.0/24\n"

        if "aws" in command or "s3" in command:
            self.decoy_env.fake_fs["/cloud/aws/keys.txt"] = "AWS_ACCESS_KEY_ID=FAKE\nAWS_SECRET_ACCESS_KEY=FAKE\n"

        if "kubectl" in command:
            self.decoy_env.fake_fs["/k8s/cluster_state.json"] = json.dumps(FakeKubernetesCluster.fake_cluster_state(), indent=2)

        if "ldap" in command or "ad" in command:
            self.decoy_env.fake_fs["/ad/dc_info.json"] = json.dumps(FakeWindowsDomainController.fake_dc_info(), indent=2)

        if self.core_ref is not None:
            self.core_ref.work.add("deception_changes", {
                "command": command,
                "stats": dict(self.command_stats)
            })

# =========================
#  CONTAINMENT MODE (SANDBOX FLAG)
# =========================

class ContainmentManager:
    def __init__(self):
        self.quarantined_sessions: List[str] = []

    def should_quarantine(self, session_id: str, anomaly: bool, intent: str) -> bool:
        if not Config.CONTAINMENT_ENABLED:
            return False
        if anomaly and intent in ("exfiltration", "privilege_escalation", "persistence"):
            return True
        return False

    def quarantine(self, session_id: str):
        if session_id not in self.quarantined_sessions:
            self.quarantined_sessions.append(session_id)
            print(f"[CONTAINMENT] Session {session_id} quarantined (sandboxed).")

    def unquarantine(self, session_id: str):
        if session_id in self.quarantined_sessions:
            self.quarantined_sessions.remove(session_id)
            print(f"[CONTAINMENT] Session {session_id} removed from quarantine.")

    def is_quarantined(self, session_id: str) -> bool:
        return session_id in self.quarantined_sessions

# =========================
#  SESSION HANDLER
# =========================

class SessionHandler:
    def __init__(
        self,
        session_id: str,
        decoy_env: DecoyEnvironment,
        logger: EventLogger,
        anomaly_detector: AnomalyDetector,
        deception_engine: DeceptionEngine,
        intent_classifier: ThreatIntentClassifier,
        persona_engine: ThreatPersonaEngine,
        vuln_sim: VulnerabilitySimulator,
        fingerprint: AttackerFingerprint,
        behavior_cluster: BehavioralClusterEngine,
        core_ref,
    ):
        self.session_id = session_id
        self.decoy_env = decoy_env
        self.logger = logger
        self.anomaly_detector = anomaly_detector
        self.deception_engine = deception_engine
        self.intent_classifier = intent_classifier
        self.persona_engine = persona_engine
        self.vuln_sim = vuln_sim
        self.fingerprint = fingerprint
        self.behavior_cluster = behavior_cluster
        self.core_ref = core_ref
        self.start_time = time.time()
        self.active = True
        self.events: List[Dict[str, Any]] = []

    def _record_event(self, event_type: str, payload: Dict[str, Any]) -> Dict[str, Any]:
        event = {
            "timestamp": datetime.utcnow().isoformat(),
            "event_type": event_type,
            "payload": payload,
        }
        self.events.append(event)
        return event

    def handle_command(self, command: str, remote_ip: str, user_agent: Optional[str] = None) -> str:
        if self.core_ref.containment.is_quarantined(self.session_id):
            self.core_ref.work.add("containment", {
                "session_id": self.session_id,
                "command": command,
                "ip": remote_ip
            })
            return "Session is quarantined in sandbox. No further commands allowed.\n"

        payload = {
            "session_id": self.session_id,
            "command": command,
        }
        self.logger.log_event("command", payload)
        event = self._record_event("command", payload)

        self.core_ref.work.add("commands", {
            "session_id": self.session_id,
            "command": command
        })

        self.core_ref.ml_detector.update(command)

        intent = self.intent_classifier.classify(command)
        persona = self.persona_engine.persona(event)
        self.logger.log_event("intent", {"session_id": self.session_id, "intent": intent})
        self.logger.log_event("persona", {"session_id": self.session_id, "persona": persona})

        fp = self.fingerprint.fingerprint(remote_ip, command, user_agent)
        self.core_ref.work.add("fingerprints", fp)

        self.behavior_cluster.update_profile(remote_ip, command, intent, persona)
        cluster_label = self.behavior_cluster.get_cluster_label(remote_ip)
        self.core_ref.work.add("behavior_clusters", {
            "ip": remote_ip,
            "cluster": cluster_label,
            "session_id": self.session_id
        })

        anomalous = False
        if self.anomaly_detector.is_anomalous(event):
            anomalous = True
            self.logger.log_event("anomaly", payload)
            self.core_ref.work.add("anomalies", {
                "session_id": self.session_id,
                "command": command
            })

        if self.core_ref.containment.should_quarantine(self.session_id, anomalous, intent):
            self.core_ref.containment.quarantine(self.session_id)
            self.core_ref.work.add("containment", {
                "session_id": self.session_id,
                "ip": remote_ip,
                "reason": f"intent={intent}, anomalous={anomalous}"
            })
            return "Session quarantined due to suspicious activity.\n"

        if self.core_ref.autoblocker.should_block(remote_ip, intent, command):
            self.core_ref.autoblocker.block_ip(remote_ip)
            self.core_ref.work.add("autoblocks", {
                "ip": remote_ip,
                "session_id": self.session_id,
                "command": command,
                "intent": intent
            })

        self.deception_engine.adapt_to_event(event)

        if command.startswith("ls"):
            return "\n".join(self.decoy_env.list_files()) + "\n"
        if command.startswith("cat "):
            path = command.split(" ", 1)[1].strip()
            content = self.decoy_env.read_file(path)
            return (content or "cat: No such file or directory\n")
        if command.startswith("service_banner "):
            svc = command.split(" ", 1)[1].strip()
            return self.decoy_env.simulate_service_banner(svc)
        if command.startswith("ps"):
            return self.decoy_env.fake_os.ps()
        if command.startswith("uname -a"):
            return self.vuln_sim.fake_kernel_version()
        if command.startswith("openssl_version"):
            return self.vuln_sim.fake_cve_banner()
        if command.startswith("fake_db_query"):
            return "FAKE_DB: SELECT * FROM users; -- returned 1 fake row\n"
        if command.startswith("fake_api_call"):
            return "FAKE_API: 200 OK {\"status\":\"success\",\"token\":\"FAKE-TOKEN-123\"}\n"
        if command.startswith("cloud_meta"):
            return json.dumps({
                "aws": FakeCloudServices.fake_aws_response(),
                "azure": FakeCloudServices.fake_azure_response(),
                "gcp": FakeCloudServices.fake_gcp_response(),
                "workloads": FakeCloudServices.fake_cloud_workloads(),
            }, indent=2) + "\n"
        if command.startswith("k8s_state"):
            return json.dumps(FakeKubernetesCluster.fake_cluster_state(), indent=2) + "\n"
        if command.startswith("ad_info"):
            return json.dumps(FakeWindowsDomainController.fake_dc_info(), indent=2) + "\n"
        if command.startswith("vpn_status"):
            return json.dumps(FakeVPNSSO.fake_vpn_status(), indent=2) + "\n"
        if command.startswith("sso_status"):
            return json.dumps(FakeVPNSSO.fake_sso_status(), indent=2) + "\n"
        if command.startswith("micro_topology"):
            return json.dumps(FakeMicroservicesCluster.fake_services(), indent=2) + "\n"
        if command.startswith("enterprise_topology"):
            return json.dumps(self.core_ref.topology.get(), indent=2) + "\n"

        return "bash: command not found\n"

    def check_timeout(self) -> None:
        if time.time() - self.start_time > Config.SESSION_TIMEOUT_SECONDS:
            self.active = False

# =========================
#  NETWORK SCANNER
# =========================

class NetworkScanner(threading.Thread):
    def __init__(self, core, interval=Config.NETWORK_SCAN_INTERVAL):
        super().__init__(daemon=True)
        self.core = core
        self.interval = interval
        self.running = True

    def get_local_subnet(self) -> Optional[str]:
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            parts = local_ip.split(".")
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.{parts[2]}"
        except Exception:
            pass
        return None

    def scan_subnet(self, subnet_prefix: str) -> List[str]:
        found = []
        for i in range(1, 255):
            ip = f"{subnet_prefix}.{i}"
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(0.2)
                result = sock.connect_ex((ip, 22))
                sock.close()
                if result == 0:
                    found.append(ip)
            except Exception:
                pass
        return found

    def detect_foreign(self, ip: str) -> bool:
        try:
            local = self.get_local_subnet()
            if local and not ip.startswith(local):
                return True
        except Exception:
            pass
        return False

    def run(self):
        while self.running:
            subnet = self.get_local_subnet()
            if subnet:
                active_hosts = self.scan_subnet(subnet)
                for host in active_hosts:
                    if self.detect_foreign(host):
                        region = self.core.geo.lookup(host)
                        self.core.logger.log_event("network_intrusion", {
                            "ip": host,
                            "region": region,
                            "timestamp": datetime.utcnow().isoformat()
                        })
                        self.core.alerts.alert("NETWORK_SCAN", host, 22, region)
                        self.core.work.add("network_scans", {
                            "ip": host,
                            "region": region
                        })
                        if self.core.swarm:
                            sig = {
                                "type": "network_intrusion",
                                "ip": host,
                                "region": region
                            }
                            self.core.swarm.push_signature(sig)
                            self.core.work.add("swarm_sync", sig)
            time.sleep(self.interval)

# =========================
#  STARTUP NETWORK CALLING-HOME SWEEP
# =========================

class StartupNetworkSweep:
    def __init__(self, core):
        self.core = core

    def _run_command(self, cmd: List[str]) -> str:
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.stdout
        except Exception:
            return ""

    def _parse_connections(self, output: str) -> List[Dict[str, Any]]:
        connections = []
        for line in output.splitlines():
            line = line.strip()
            if not line:
                continue
            if "ESTABLISHED" in line or "CONNECTED" in line:
                connections.append({"raw": line})
        return connections

    def sweep(self):
        os_name = platform.system().lower()
        print("[STARTUP SWEEP] Running startup network calling-home sweep...")
        output = ""
        if "windows" in os_name:
            output = self._run_command(["netstat", "-ano"])
        elif "linux" in os_name or "darwin" in os_name:
            output = self._run_command(["netstat", "-tunp"])
        else:
            output = ""

        connections = self._parse_connections(output)
        for conn in connections:
            raw = conn["raw"]
            self.core.work.add("startup_scan", {"raw": raw})
            self.core.logger.log_event("startup_connection", {"raw": raw})
        print(f"[STARTUP SWEEP] Found {len(connections)} active outbound/established connections at startup.")

# =========================
#  REAL PROCESS-LEVEL MONITORING (SAFE)
# =========================

class ProcessMonitor(threading.Thread):
    def __init__(self, core):
        super().__init__(daemon=True)
        self.core = core
        self.running = True

    def _run_command(self, cmd: List[str]) -> str:
        try:
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            return result.stdout
        except Exception:
            return ""

    def run(self):
        while self.running:
            os_name = platform.system().lower()
            output = ""
            if "windows" in os_name:
                output = self._run_command(["tasklist"])
            elif "linux" in os_name or "darwin" in os_name:
                output = self._run_command(["ps", "aux"])
            processes = []
            for line in output.splitlines()[1:]:
                line = line.strip()
                if not line:
                    continue
                processes.append(line)
            self.core.work.add("process_monitor", {
                "count": len(processes),
                "sample": processes[:5]
            })
            time.sleep(Config.PROCESS_MONITOR_INTERVAL)

# =========================
#  REAL DNS MONITORING (SAFE STUB)
# =========================

class DNSMonitor(threading.Thread):
    def __init__(self, core):
        super().__init__(daemon=True)
        self.core = core
        self.running = True

    def run(self):
        while self.running:
            fake_queries = [
                "api.fakecorp.com",
                "telemetry.example.net",
                "update.malware-test.org",
            ]
            q = random.choice(fake_queries)
            self.core.work.add("dns_monitor", {
                "query": q,
                "result": "FAKE_RESOLUTION"
            })
            time.sleep(Config.DNS_MONITOR_INTERVAL)

# =========================
#  REAL PACKET CAPTURE (SAFE STUB + KERNEL HOOK STUB)
# =========================

class KernelPacketHookStub(threading.Thread):
    def __init__(self, core):
        super().__init__(daemon=True)
        self.core = core
        self.running = True

    def run(self):
        while self.running:
            sample = {
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.10",
                "protocol": random.choice(["TCP", "UDP"]),
                "dst_port": random.choice([80, 443, 22]),
                "source": "kernel_stub"
            }
            self.core.work.add("kernel_packets", sample)
            time.sleep(Config.PACKET_CAPTURE_INTERVAL)

class PacketCaptureStub(threading.Thread):
    def __init__(self, core):
        super().__init__(daemon=True)
        self.core = core
        self.running = True

    def run(self):
        while self.running:
            sample = {
                "src_ip": "10.0.0.5",
                "dst_ip": "10.0.0.10",
                "protocol": random.choice(["TCP", "UDP"]),
                "dst_port": random.choice([80, 443, 22]),
                "source": "userland_stub"
            }
            self.core.work.add("packet_capture", sample)
            time.sleep(Config.PACKET_CAPTURE_INTERVAL)

# =========================
#  REAL SYSCALLS MONITORING (SAFE STUB + KERNEL HOOK STUB)
# =========================

class KernelSyscallHookStub(threading.Thread):
    def __init__(self, core):
        super().__init__(daemon=True)
        self.core = core
        self.running = True

    def run(self):
        while self.running:
            fake_syscalls = [
                "open('/etc/passwd')",
                "connect('203.0.113.10:443')",
                "execve('/usr/bin/python')",
            ]
            s = random.choice(fake_syscalls)
            self.core.work.add("kernel_syscalls", {"syscall": s})
            time.sleep(Config.SYSCALL_MONITOR_INTERVAL)

class SyscallMonitorStub(threading.Thread):
    def __init__(self, core):
        super().__init__(daemon=True)
        self.core = core
        self.running = True

    def run(self):
        while self.running:
            fake_syscalls = [
                "open('/etc/passwd')",
                "connect('203.0.113.10:443')",
                "execve('/usr/bin/python')",
            ]
            s = random.choice(fake_syscalls)
            self.core.work.add("syscalls", {"syscall": s})
            time.sleep(Config.SYSCALL_MONITOR_INTERVAL)

# =========================
#  DECEPTION-BASED HONEY-VMs (LOGICAL STUB)
# =========================

class HoneyVMManager:
    def __init__(self):
        self.vms = [
            {"name": "honeypot-vm-1", "os": "Linux", "role": "web"},
            {"name": "honeypot-vm-2", "os": "Windows", "role": "db"},
        ]

    def list_vms(self) -> List[Dict[str, Any]]:
        return self.vms

# =========================
#  FULL SIEM EXPORT (SAFE)
# =========================

class SIEMExporter(threading.Thread):
    def __init__(self, core, interval=Config.SIEM_EXPORT_INTERVAL):
        super().__init__(daemon=True)
        self.core = core
        self.interval = interval
        self.running = True

    def run(self):
        while self.running:
            inv = self.core.work.all()
            export_path = os.path.join(Config.LOG_DIR, "siem_export.json")
            FileUtils.ensure_dir(Config.LOG_DIR)
            with open(export_path, "w", encoding="utf-8") as f:
                json.dump(inv, f, indent=2)
            self.core.work.add("siem_exports", {"path": export_path})
            print(f"[SIEM] Exported inventory to {export_path}")
            time.sleep(self.interval)

# =========================
#  THREAT SCORING HEATMAP (STUB)
# =========================

class ThreatHeatmap:
    def compute(self, inventory: WorkInventory) -> Dict[str, int]:
        scores = {
            "recon": len(inventory.get("commands")),
            "anomalies": len(inventory.get("anomalies")),
            "intrusions": len(inventory.get("intrusions")),
            "autoblocks": len(inventory.get("autoblocks")),
            "containment": len(inventory.get("containment")),
        }
        return scores

# =========================
#  AUTONOMOUS COUNTER-INTELLIGENCE FEEDBACK LOOPS
# =========================

class CounterIntelEngine(threading.Thread):
    def __init__(self, core):
        super().__init__(daemon=True)
        self.core = core
        self.running = True

    def run(self):
        while self.running:
            inv = self.core.work.all()
            anomalies = inv.get("anomalies", [])
            intrusions = inv.get("intrusions", [])
            if anomalies or intrusions:
                self.core.work.add("counter_intel", {
                    "summary": "adjusted deception based on recent anomalies/intrusions",
                    "anomaly_count": len(anomalies),
                    "intrusion_count": len(intrusions)
                })
                self.core.decoy_env.refresh_topology()
            if self.core.swarm:
                self.core.swarm.pull_updates()
            time.sleep(Config.COUNTER_INTEL_INTERVAL)

# =========================
#  HONEYPOT CORE
# =========================

class HoneypotCore:
    def __init__(self):
        self.logger = EventLogger(Config.LOG_DIR)
        self.honey_gen = HoneyDataGenerator(Config.HONEY_DATA_DIR)
        self.honey_gen.materialize_honey_data()

        self.topology = DynamicEnterpriseTopology()
        self.decoy_env = DecoyEnvironment(Config.HONEY_DATA_DIR, self.topology)
        self.work = WorkInventory()

        self.ml_detector = MLAnomalyDetector()
        self.anomaly_detector = AnomalyDetector(Config.ANOMALY_SCORE_THRESHOLD, self.ml_detector)
        self.deception_engine = DeceptionEngine(self.decoy_env, core_ref=self)
        self.intent_classifier = ThreatIntentClassifier()
        self.persona_engine = ThreatPersonaEngine()
        self.vuln_sim = VulnerabilitySimulator()
        self.fingerprint = AttackerFingerprint()
        self.behavior_cluster = BehavioralClusterEngine()
        self.replay_engine = ReplayEngine()
        self.replay_sandbox = ReplaySandbox()
        self.swarm = SwarmMesh(Config.SWARM_PEERS, core_ref=self) if Config.SWARM_ENABLED else None

        self.geo = GeoIP()
        self.alerts = IntrusionAlert()

        self.firewall = FirewallBlocker()
        self.autoblocker = AutoBlocker(self.firewall)
        self.containment = ContainmentManager()

        self.honey_vms = HoneyVMManager()
        self.heatmap = ThreatHeatmap()

        self.sessions: Dict[str, SessionHandler] = {}
        self._lock = threading.Lock()

        self.startup_sweep = StartupNetworkSweep(self)
        self.startup_sweep.sweep()

        self.network_scanner = NetworkScanner(self)
        self.network_scanner.start()

        self.packet_fake = PacketLevelFakeTraffic()
        self.packet_fake.start()

        self.fake_user_activity = FakeUserActivity(self.decoy_env)
        self.fake_user_activity.start()

        self.fs_mutator = FakeFSMutator(self.decoy_env)
        self.fs_mutator.start()

        self.process_monitor = ProcessMonitor(self)
        self.process_monitor.start()

        self.dns_monitor = DNSMonitor(self)
        self.dns_monitor.start()

        self.packet_capture = PacketCaptureStub(self)
        self.packet_capture.start()

        self.kernel_packet_hook = KernelPacketHookStub(self)
        self.kernel_packet_hook.start()

        self.syscall_monitor = SyscallMonitorStub(self)
        self.syscall_monitor.start()

        self.kernel_syscall_hook = KernelSyscallHookStub(self)
        self.kernel_syscall_hook.start()

        self.siem_exporter = SIEMExporter(self)
        self.siem_exporter.start()

        self.counter_intel = CounterIntelEngine(self)
        self.counter_intel.start()

    def create_session(self, remote_ip: str, port: int) -> str:
        session_id = f"session-{int(time.time() * 1000)}-{random.randint(1000, 9999)}"
        handler = SessionHandler(
            session_id=session_id,
            decoy_env=self.decoy_env,
            logger=self.logger,
            anomaly_detector=self.anomaly_detector,
            deception_engine=self.deception_engine,
            intent_classifier=self.intent_classifier,
            persona_engine=self.persona_engine,
            vuln_sim=self.vuln_sim,
            fingerprint=self.fingerprint,
            behavior_cluster=self.behavior_cluster,
            core_ref=self,
        )
        with self._lock:
            self.sessions[session_id] = handler

        region = self.geo.lookup(remote_ip)

        self.logger.log_session(session_id, {"remote_ip": remote_ip, "region": region, "port": port})
        self.logger.log_event("intrusion", {"session_id": session_id, "ip": remote_ip, "port": port})

        self.alerts.alert(session_id, remote_ip, port, region)

        self.work.add("sessions", {
            "session_id": session_id,
            "ip": remote_ip,
            "region": region,
            "port": port
        })
        self.work.add("intrusions", {
            "session_id": session_id,
            "ip": remote_ip,
            "region": region,
            "port": port
        })

        if self.swarm:
            sig = {
                "type": "intrusion",
                "session_id": session_id,
                "ip": remote_ip,
                "region": region,
                "port": port,
            }
            self.swarm.push_signature(sig)
            self.work.add("swarm_sync", sig)
            self.swarm.mesh_route(sig)

        return session_id

    def handle_session_command(self, session_id: str, command: str, remote_ip: str, user_agent: Optional[str] = None) -> str:
        if self.autoblocker.is_blocked(remote_ip):
            return "Connection blocked by honeypot firewall policy.\n"

        with self._lock:
            handler = self.sessions.get(session_id)

        if handler is None or not handler.active:
            return "Session expired.\n"

        handler.check_timeout()
        if not handler.active:
            return "Session timed out.\n"

        resp = handler.handle_command(command, remote_ip, user_agent)

        if self.swarm:
            sig = {"type": "command", "session_id": session_id, "command": command}
            self.swarm.push_signature(sig)
            self.work.add("swarm_sync", sig)

        return resp

    def cleanup_sessions(self) -> None:
        with self._lock:
            to_delete = [sid for sid, h in self.sessions.items() if not h.active]
            for sid in to_delete:
                del self.sessions[sid]

    def get_session_summary(self) -> List[Dict[str, Any]]:
        with self._lock:
            out = []
            for sid, h in self.sessions.items():
                out.append({
                    "session_id": sid,
                    "active": h.active,
                    "events": len(h.events),
                })
            return out

    def get_alerts(self) -> List[Dict[str, Any]]:
        return list(self.alerts.last_alerts)

    def get_inventory(self) -> Dict[str, List[Dict[str, Any]]]:
        return self.work.all()

    def get_heatmap(self) -> Dict[str, int]:
        return self.heatmap.compute(self.work)

    def get_honey_vms(self) -> List[Dict[str, Any]]:
        return self.honey_vms.list_vms()

# =========================
#  FAKE SSH FRONTEND
# =========================

class FakeSSHServer(threading.Thread):
    def __init__(self, core: HoneypotCore, host: str, port: int):
        super().__init__(daemon=True)
        self.core = core
        self.host = host
        self.port = port
        self.running = True

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.bind((self.host, self.port))
        sock.listen(5)
        while self.running:
            try:
                conn, addr = sock.accept()
                threading.Thread(
                    target=self.handle_client,
                    args=(conn, addr),
                    daemon=True,
                ).start()
            except Exception:
                break
        sock.close()

    def handle_client(self, conn: socket.socket, addr):
        ip = addr[0]
        session_id = self.core.create_session(remote_ip=ip, port=self.port)
        conn.sendall(b"Fake SSH Honeypot\r\n")
        conn.sendall(b"session: " + session_id.encode("utf-8") + b"\r\n")
        try:
            while True:
                conn.sendall(b"$ ")
                data = conn.recv(4096)
                if not data:
                    break
                cmd = data.decode("utf-8", errors="ignore").strip()
                if cmd.lower() in ("exit", "quit"):
                    break
                resp = self.core.handle_session_command(session_id, cmd, ip)
                conn.sendall(resp.encode("utf-8"))
        finally:
            conn.close()

# =========================
#  FAKE HTTP FRONTEND
# =========================

class FakeHTTPHandler(BaseHTTPRequestHandler):
    core: HoneypotCore = None

    def do_GET(self):
        parsed = urlparse(self.path)
        ua = self.headers.get("User-Agent", "unknown")
        if parsed.path == "/cmd":
            qs = parse_qs(parsed.query)
            session_id = qs.get("session", [""])[0]
            cmd = qs.get("command", [""])[0]
            remote_ip = self.client_address[0]
            if not session_id:
                session_id = self.core.create_session(remote_ip=remote_ip, port=Config.HTTP_BIND_PORT)
            resp = self.core.handle_session_command(session_id, cmd or "ls", remote_ip, ua)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(resp.encode("utf-8"))
        elif parsed.path == "/enterprise_topology":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            payload = self.core.topology.get()
            self.wfile.write(json.dumps(payload, indent=2).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return

class FakeHTTPServer(threading.Thread):
    def __init__(self, core: HoneypotCore, host: str, port: int):
        super().__init__(daemon=True)
        self.core = core
        self.host = host
        self.port = port

    def run(self):
        FakeHTTPHandler.core = self.core
        server = HTTPServer((self.host, self.port), FakeHTTPHandler)
        try:
            server.serve_forever()
        finally:
            server.server_close()

# =========================
#  TKINTER SOC DASHBOARD (LOCAL)
# =========================

class HoneypotDashboard(threading.Thread):
    def __init__(self, core: HoneypotCore):
        super().__init__(daemon=True)
        self.core = core
        self.selected_ip: Optional[str] = None
        self.selected_session: Optional[str] = None

    def run(self):
        if tk is None or ttk is None:
            print("[DASHBOARD] Tkinter not available. GUI disabled.")
            return
        root = tk.Tk()
        root.title("AI Honeypot SOC Dashboard (Ultra+ V2)")

        frame_top = ttk.Frame(root)
        frame_top.pack(fill=tk.BOTH, expand=True)

        frame_sessions = ttk.LabelFrame(frame_top, text="Sessions")
        frame_sessions.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        tree_sessions = ttk.Treeview(frame_sessions, columns=("session_id", "active", "events"), show="headings")
        tree_sessions.heading("session_id", text="Session ID")
        tree_sessions.heading("active", text="Active")
        tree_sessions.heading("events", text="Events")
        tree_sessions.pack(fill=tk.BOTH, expand=True)

        frame_alerts = ttk.LabelFrame(frame_top, text="Intrusion Alerts")
        frame_alerts.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        tree_alerts = ttk.Treeview(frame_alerts, columns=("timestamp", "session_id", "ip", "port"), show="headings")
        tree_alerts.heading("timestamp", text="Time")
        tree_alerts.heading("session_id", text="Session")
        tree_alerts.heading("ip", text="Source IP")
        tree_alerts.heading("port", text="Port")
        tree_alerts.pack(fill=tk.BOTH, expand=True)

        frame_bottom = ttk.Frame(root)
        frame_bottom.pack(fill=tk.BOTH, expand=True)

        frame_inventory = ttk.LabelFrame(frame_bottom, text="Work Inventory (SOC View)")
        frame_inventory.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        tree_inventory = ttk.Treeview(frame_inventory, columns=("category", "details"), show="headings")
        tree_inventory.heading("category", text="Category")
        tree_inventory.heading("details", text="Details")
        tree_inventory.pack(fill=tk.BOTH, expand=True)

        frame_controls = ttk.LabelFrame(frame_bottom, text="Intruder Controls + Heatmap")
        frame_controls.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=5, pady=5)

        lbl_selected = ttk.Label(frame_controls, text="No intruder selected")
        lbl_selected.pack(pady=5)

        def allow_ip():
            if self.selected_ip:
                self.core.autoblocker.unblock_ip(self.selected_ip)
                self.core.work.add("autoblocks", {
                    "ip": self.selected_ip,
                    "action": "allow",
                    "session_id": self.selected_session or "N/A"
                })
                print(f"[GUI] Allow pressed for IP {self.selected_ip}")
            else:
                print("[GUI] Allow pressed with no intruder selected")

        def block_ip():
            if self.selected_ip:
                self.core.autoblocker.block_ip(self.selected_ip)
                self.core.work.add("autoblocks", {
                    "ip": self.selected_ip,
                    "action": "block",
                    "session_id": self.selected_session or "N/A"
                })
                print(f"[GUI] Block pressed for IP {self.selected_ip}")
            else:
                print("[GUI] Block pressed with no intruder selected")

        def quarantine_session():
            if self.selected_session:
                self.core.containment.quarantine(self.selected_session)
                self.core.work.add("containment", {
                    "session_id": self.selected_session,
                    "action": "quarantine",
                    "ip": self.selected_ip or "N/A"
                })
                print(f"[GUI] Quarantine pressed for session {self.selected_session}")
            else:
                print("[GUI] Quarantine pressed with no session selected")

        btn_allow = ttk.Button(frame_controls, text="Allow", command=allow_ip)
        btn_allow.pack(side=tk.LEFT, padx=10, pady=5)

        btn_block = ttk.Button(frame_controls, text="Block", command=block_ip)
        btn_block.pack(side=tk.LEFT, padx=10, pady=5)

        btn_quarantine = ttk.Button(frame_controls, text="Quarantine", command=quarantine_session)
        btn_quarantine.pack(side=tk.LEFT, padx=10, pady=5)

        frame_stats = ttk.LabelFrame(frame_controls, text="SOC Stats + Heatmap")
        frame_stats.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        lbl_sessions_count = ttk.Label(frame_stats, text="Sessions: 0")
        lbl_sessions_count.pack(anchor=tk.W)

        lbl_alerts_count = ttk.Label(frame_stats, text="Alerts: 0")
        lbl_alerts_count.pack(anchor=tk.W)

        lbl_anomalies_count = ttk.Label(frame_stats, text="Anomalies: 0")
        lbl_anomalies_count.pack(anchor=tk.W)

        lbl_blocks_count = ttk.Label(frame_stats, text="Blocked IPs: 0")
        lbl_blocks_count.pack(anchor=tk.W)

        lbl_heatmap = ttk.Label(frame_stats, text="Heatmap: {}")
        lbl_heatmap.pack(anchor=tk.W)

        def on_alert_select(event):
            item = tree_alerts.selection()
            if item:
                values = tree_alerts.item(item)["values"]
                if len(values) >= 4:
                    timestamp, session_id, ip, port = values
                    self.selected_ip = ip
                    self.selected_session = session_id
                    lbl_selected.config(text=f"Selected: {ip} on port {port} (session {session_id})")

        tree_alerts.bind("<<TreeviewSelect>>", on_alert_select)

        def refresh():
            for i in tree_sessions.get_children():
                tree_sessions.delete(i)
            summary = self.core.get_session_summary()
            for s in summary:
                tree_sessions.insert("", tk.END, values=(s["session_id"], s["active"], s["events"]))

            for i in tree_alerts.get_children():
                tree_alerts.delete(i)
            alerts = self.core.get_alerts()
            for a in alerts:
                tree_alerts.insert("", tk.END, values=(a["timestamp"], a["session_id"], a["ip"], a["port"]))

            for i in tree_inventory.get_children():
                tree_inventory.delete(i)
            inv = self.core.get_inventory()
            for category, items in inv.items():
                for item in items:
                    tree_inventory.insert("", tk.END, values=(category, json.dumps(item)))

            lbl_sessions_count.config(text=f"Sessions: {len(summary)}")
            lbl_alerts_count.config(text=f"Alerts: {len(alerts)}")
            lbl_anomalies_count.config(text=f"Anomalies: {len(inv.get('anomalies', []))}")
            lbl_blocks_count.config(text=f"Blocked IPs: {len(self.core.autoblocker.firewall.blocked_ips)}")

            heatmap = self.core.get_heatmap()
            lbl_heatmap.config(text=f"Heatmap: {heatmap}")

            root.after(1000, refresh)

        root.after(1000, refresh)
        root.mainloop()

# =========================
#  REMOTE DASHBOARD (HTTP + MFA + JWT)
# =========================

class RemoteDashboardHandler(BaseHTTPRequestHandler):
    core: HoneypotCore = None

    def _get_token(self) -> Optional[str]:
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        return qs.get("token", [""])[0]

    def _check_auth(self) -> bool:
        token = self._get_token()
        if not token:
            return False
        payload = SimpleJWT.verify(token, Config.JWT_SECRET)
        return payload is not None

    def do_GET(self):
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)

        if parsed.path == "/login":
            password = qs.get("password", [""])[0]
            mfa_code = qs.get("mfa", [""])[0]
            if password != Config.DASHBOARD_PASSWORD:
                self.send_response(401)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Invalid password")
                return
            if not SimpleMFA.verify_code(Config.DASHBOARD_MFA_SECRET, mfa_code):
                self.send_response(401)
                self.send_header("Content-Type", "text/plain")
                self.end_headers()
                self.wfile.write(b"Invalid MFA code")
                return
            token = SimpleJWT.create({"user": "admin"}, Config.JWT_SECRET, Config.JWT_EXP_MINUTES)
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"token": token}).encode("utf-8"))
            return

        if not self._check_auth():
            self.send_response(401)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Unauthorized: invalid or missing token")
            return

        if parsed.path == "/status":
            data = {
                "sessions": self.core.get_session_summary(),
                "alerts": self.core.get_alerts(),
                "inventory": self.core.get_inventory(),
                "blocked_ips": self.core.autoblocker.firewall.blocked_ips,
                "quarantined_sessions": self.core.containment.quarantined_sessions,
                "heatmap": self.core.get_heatmap(),
                "honey_vms": self.core.get_honey_vms(),
                "topology": self.core.topology.get(),
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))
        elif parsed.path == "/override_autoblock":
            mode = qs.get("mode", ["off"])[0]
            self.core.autoblocker.manual_override = (mode == "on")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(f"Manual override set to {self.core.autoblocker.manual_override}".encode("utf-8"))
        elif parsed.path == "/replay":
            session_id = qs.get("session", [""])[0]
            with self.core._lock:
                handler = self.core.sessions.get(session_id)
            if not handler:
                self.send_response(404)
                self.end_headers()
                return
            self.core.replay_engine.replay(handler.events)
            self.core.work.add("replay", {"session_id": session_id})
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"Encrypted replay printed to server console")
        elif parsed.path == "/sandbox_replay":
            session_id = qs.get("session", [""])[0]
            with self.core._lock:
                handler = self.core.sessions.get(session_id)
            if not handler:
                self.send_response(404)
                self.end_headers()
                return
            sandbox_output = self.core.replay_sandbox.sandbox_replay(handler.events)
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(sandbox_output.encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return

class RemoteDashboardServer(threading.Thread):
    def __init__(self, core: HoneypotCore, host: str, port: int):
        super().__init__(daemon=True)
        self.core = core
        self.host = host
        self.port = port

    def run(self):
        RemoteDashboardHandler.core = self.core
        server = HTTPServer((self.host, self.port), RemoteDashboardHandler)
        try:
            server.serve_forever()
        finally:
            server.server_close()

# =========================
#  REAL-TIME WEB SOC DASHBOARD (JSON API)
# =========================

class WebSOCDashboardHandler(BaseHTTPRequestHandler):
    core: HoneypotCore = None

    def do_GET(self):
        parsed = urlparse(self.path)
        if parsed.path == "/soc":
            data = {
                "sessions": self.core.get_session_summary(),
                "alerts": self.core.get_alerts(),
                "heatmap": self.core.get_heatmap(),
                "topology": self.core.topology.get(),
                "kernel_packets": self.core.work.get("kernel_packets")[-10:],
                "kernel_syscalls": self.core.work.get("kernel_syscalls")[-10:],
            }
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(data, indent=2).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return

class WebSOCDashboardServer(threading.Thread):
    def __init__(self, core: HoneypotCore, host: str, port: int):
        super().__init__(daemon=True)
        self.core = core
        self.host = host
        self.port = port

    def run(self):
        WebSOCDashboardHandler.core = self.core
        server = HTTPServer((self.host, self.port), WebSOCDashboardHandler)
        try:
            server.serve_forever()
        finally:
            server.server_close()

# =========================
#  MAIN
# =========================

def main():
    script_path = os.path.abspath(sys.argv[0])
    tamper_guard = TamperGuard(script_path)
    tamper_guard.start()

    core = HoneypotCore()

    ssh_server = FakeSSHServer(core, Config.SSH_BIND_HOST, Config.SSH_BIND_PORT)
    ssh_server.start()

    http_server = FakeHTTPServer(core, Config.HTTP_BIND_HOST, Config.HTTP_BIND_PORT)
    http_server.start()

    dashboard = HoneypotDashboard(core)
    dashboard.start()

    remote_dashboard = RemoteDashboardServer(core, Config.REMOTE_DASHBOARD_HOST, Config.REMOTE_DASHBOARD_PORT)
    remote_dashboard.start()

    web_soc = WebSOCDashboardServer(core, Config.WEB_SOC_HOST, Config.WEB_SOC_PORT)
    web_soc.start()

    print(f"[{Config.HONEYPOT_NAME}] Running.")
    print(f"Fake SSH on {Config.SSH_BIND_HOST}:{Config.SSH_BIND_PORT}")
    print(f"Fake HTTP on {Config.HTTP_BIND_HOST}:{Config.HTTP_BIND_PORT}")
    print(f"Remote dashboard on {Config.REMOTE_DASHBOARD_HOST}:{Config.REMOTE_DASHBOARD_PORT}")
    print(f"Web SOC dashboard JSON on {Config.WEB_SOC_HOST}:{Config.WEB_SOC_PORT}/soc")
    print("Use /login?password=...&mfa=... to obtain JWT token for remote dashboard.")
    print("Local Tkinter SOC dashboard running (if available).")
    print("Startup network calling-home sweep completed; results stored in Work Inventory under 'startup_scan'.")
    print("Process-level monitoring, DNS monitoring, packet capture stubs, kernel packet/syscall stubs active.")
    print("SIEM export active; see logs/siem_export.json.")
    print("Honey-VM metadata, dynamic enterprise topology, VPN/SSO, microservices decoys available via HTTP and commands.")
    print("Swarm mesh correlation and autonomous counter-intel loops active.")

    try:
        while True:
            time.sleep(5)
            core.cleanup_sessions()
    except KeyboardInterrupt:
        print("Shutting down honeypot.")

if __name__ == "__main__":
    main()
