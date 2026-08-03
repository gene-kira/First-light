#!/usr/bin/env python3
# codex_honeypot_godmode_v11.py
#
# S1: Suricata + process monitoring + AI-driven deception assets
# S2: Honeypot protocol stubs (SMB/LDAP/Kerberos/SQL/Docker/K8s/cloud metadata)
# S3: ML + swarm + persona simulation + autonomous remediation + forensic export
# Compact GUI with collapsible top panel, vertical list-style controls, left-side tabs

import os
import sys
import json
import time
import threading
import subprocess
import importlib
import traceback
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

# ============================================================
# PATHS / CONFIG / STATE
# ============================================================

BASE_DIR = os.path.join(os.path.expanduser("~"), "CodexHoneypotGodmode")
os.makedirs(BASE_DIR, exist_ok=True)

CONFIG_PATH = Path(BASE_DIR) / "codex_honeypot_config.json"
STATE_PATH = Path(BASE_DIR) / "codex_honeypot_state.json"
SURICATA_EVE_PATH = Path(BASE_DIR) / "eve.json"  # point to real Suricata eve.json if desired

DEFAULT_CONFIG = {
    "honeypot_mode": "C",
    "window_scope_mode": 2,
    "autoloader_enabled": True,
    "headless": False,
    "win32_hooks_enabled": True,
    "suricata_enabled": True,
    "process_monitor_enabled": True,
    "ai_deception_enabled": True,
    "protocol_honeypots_enabled": True,
    "ml_enabled": True,
    "swarm_enabled": True,
    "personas_enabled": True,
    "remediation_enabled": True,
    "node_id": "node-1",
    "swarm_peers": [],
}

DEFAULT_STATE = {
    "known_window_classes": [
        "Progman", "Shell_TrayWnd", "Chrome_WidgetWin_0",
        "ApplicationFrameWindow", "Windows.UI.Core.CoreWindow"
    ],
    "trapped_windows": [],
    "behavior_log": [],
    "ai_model_state": {},
    "suricata_events": [],
    "process_events": [],
    "deception_assets": [],
    "protocol_events": [],
    "ml_threats": [],
    "swarm_messages": [],
    "personas": [],
    "persona_events": [],
}

def load_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        print(f"[WARN] JSON corrupted: {path}. Resetting to default.")
    return default.copy()

def save_json(path: Path, data: Dict[str, Any]):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[WARN] Failed to save {path}: {e}")

config = load_json(CONFIG_PATH, DEFAULT_CONFIG)
state = load_json(STATE_PATH, DEFAULT_STATE)

# ============================================================
# AUTOLOADER
# ============================================================

class Autoloader:
    def __init__(self):
        self.dependency_map: Dict[str, Dict[str, Any]] = {
            "network": {"modules": ["requests"], "install": True},
            "notify": {"modules": ["win10toast"], "install": True},
            "win32": {"modules": ["ctypes"], "install": False},
            "honeypot": {"modules": ["psutil"], "install": True},
            "ai": {"modules": ["numpy"], "install": False},
        }
        self.loaded_modules: Dict[str, Any] = {}
        self.missing_modules: Dict[str, List[str]] = {}
        self.lock = threading.Lock()
        self.predictive_thread: Optional[threading.Thread] = None
        self.predictive_running = False

    def _soft_import(self, module_name: str) -> Optional[Any]:
        try:
            return importlib.import_module(module_name)
        except ImportError:
            return None

    def _hard_install(self, module_name: str) -> bool:
        try:
            print(f"[Autoloader] Installing {module_name}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
            return True
        except Exception as e:
            print(f"[Autoloader] Failed to install {module_name}: {e}")
            return False

    def ensure_group(self, group_name: str):
        group = self.dependency_map.get(group_name, {})
        modules = group.get("modules", [])
        allow_install = group.get("install", False)
        missing = []
        for m in modules:
            mod = self._soft_import(m)
            if mod is None:
                missing.append(m)
                if allow_install and self._hard_install(m):
                    mod = self._soft_import(m)
            if mod is not None:
                with self.lock:
                    self.loaded_modules[m] = mod
        if missing:
            with self.lock:
                self.missing_modules[group_name] = missing

    def start_predictive_daemon(self):
        if self.predictive_running:
            return

        def _daemon():
            self.predictive_running = True
            for g in list(self.dependency_map.keys()):
                self.ensure_group(g)
                time.sleep(0.5)
            self.predictive_running = False

        self.predictive_thread = threading.Thread(target=_daemon, daemon=True)
        self.predictive_thread.start()

    def get_module(self, name: str) -> Optional[Any]:
        return self.loaded_modules.get(name)

AUTOLOADER = Autoloader()
if config.get("autoloader_enabled", True):
    AUTOLOADER.start_predictive_daemon()

# ============================================================
# MODE / SCOPE
# ============================================================

def set_honeypot_mode(mode: str):
    assert mode in ("A", "B", "C")
    config["honeypot_mode"] = mode
    save_json(CONFIG_PATH, config)
    print(f"[Mode] Honeypot mode -> {mode}")

def get_honeypot_mode() -> str:
    return config.get("honeypot_mode", "C")

def set_window_scope_mode(scope: int):
    assert scope in (1, 2, 3)
    config["window_scope_mode"] = scope
    save_json(CONFIG_PATH, config)
    print(f"[Scope] Window scope -> {scope}")

def get_window_scope_mode() -> int:
    return config.get("window_scope_mode", 2)

def is_known_window_class(cls_name: str) -> bool:
    return cls_name in state["known_window_classes"]

def ai_decide_trap(cls_name: str) -> bool:
    if not is_known_window_class(cls_name):
        return True
    return False

def should_trap_window(cls_name: str) -> bool:
    scope = get_window_scope_mode()
    if scope == 1:
        return cls_name == "wuiconwindow"
    if scope == 2:
        return not is_known_window_class(cls_name)
    if scope == 3:
        return ai_decide_trap(cls_name)
    return False

# ============================================================
# AI SCORING PIPELINE (NUMPY STUB)
# ============================================================

def ai_score_window(cls_name: str) -> float:
    np = AUTOLOADER.get_module("numpy")
    base = 0.3
    name = cls_name.lower()
    if "wuico" in name:
        base = 0.85
    elif "unknown" in name:
        base = 0.75
    if np is None:
        return base
    vec = np.array([len(name), base])
    score = float(vec[1] + (vec[0] % 5) * 0.02)
    return max(0.0, min(1.0, score))

# ============================================================
# LOGGING / HONEYPOT
# ============================================================

def log_behavior(pid: int, cls_name: str, action: str, extra: Optional[Dict[str, Any]] = None):
    entry = {
        "pid": pid,
        "class": cls_name,
        "action": action,
        "timestamp": datetime.now().isoformat(),
        "extra": extra or {},
    }
    state["behavior_log"].append(entry)
    save_json(STATE_PATH, state)

def trap_window_in_honeypot(hwnd: int, cls_name: str, pid: int):
    entry = {
        "hwnd": hwnd,
        "class": cls_name,
        "pid": pid,
        "timestamp": datetime.now().isoformat()
    }
    state["trapped_windows"].append(entry)
    save_json(STATE_PATH, state)

    mode = get_honeypot_mode()
    if mode == "A":
        apply_soft_honeypot(hwnd, cls_name, pid)
    elif mode == "B":
        apply_hard_honeypot(hwnd, cls_name, pid)
    elif mode == "C":
        apply_hybrid_ai_honeypot(hwnd, cls_name, pid)
    else:
        apply_soft_honeypot(hwnd, cls_name, pid)

def apply_soft_honeypot(hwnd, cls_name, pid):
    log_behavior(pid, cls_name, "soft_honeypot")
    print(f"[Soft Honeypot] Trapped {cls_name} (PID {pid}, HWND {hwnd})")

def apply_hard_honeypot(hwnd, cls_name, pid):
    log_behavior(pid, cls_name, "hard_honeypot")
    print(f"[Hard Honeypot] Isolated {cls_name} (PID {pid}, HWND {hwnd})")

def apply_hybrid_ai_honeypot(hwnd, cls_name, pid):
    score = ai_score_window(cls_name)
    if score > 0.7:
        apply_hard_honeypot(hwnd, cls_name, pid)
    else:
        apply_soft_honeypot(hwnd, cls_name, pid)

def auto_nuke_process(pid: int, reason: str):
    log_behavior(pid, "unknown", f"auto_nuke:{reason}")
    print(f"[Auto-Nuke] PID {pid} reason={reason}")
    # Stub: implement real kill/quarantine later

# ============================================================
# DECEPTION ENGINE (basic assets + AI strategy)
# ============================================================

def add_deception_asset(kind: str, details: Dict[str, Any]):
    asset = {
        "kind": kind,
        "details": details,
        "timestamp": datetime.now().isoformat(),
    }
    state["deception_assets"].append(asset)
    save_json(STATE_PATH, state)
    print(f"[Deception] Added {kind}: {details}")

def fake_memory_dump(pid: int):
    path = Path(BASE_DIR) / "fake" / "memdumps"
    os.makedirs(path, exist_ok=True)
    fname = path / f"memdump_pid{pid}_{int(time.time())}.txt"
    content = f"FAKE MEMORY DUMP FOR PID {pid}\nRandom bytes: {os.urandom(32).hex()}\n"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(content)
    add_deception_asset("memory_dump", {"pid": pid, "path": str(fname)})

def fake_gpu_info():
    info = {
        "gpus": [
            {"name": "Fake RTX 5090", "vram_gb": 48, "driver": "FAKE-555.55"},
            {"name": "Fake A100", "vram_gb": 80, "driver": "FAKE-600.00"},
        ]
    }
    add_deception_asset("gpu_info", info)

def fake_net_interfaces():
    info = {
        "interfaces": [
            {"name": "eth0", "ip": "10.0.0.10", "mac": "FA:KE:00:00:00:01"},
            {"name": "vpn0", "ip": "172.16.0.5", "mac": "FA:KE:00:00:00:02"},
        ]
    }
    add_deception_asset("net_interfaces", info)

def fake_windows_logs():
    info = {"source": "windows", "events": ["User logon", "Service start", "Group policy applied"]}
    add_deception_asset("windows_logs", info)

def fake_linux_logs():
    info = {"source": "linux", "events": ["sshd accepted", "sudo command", "systemd service restart"]}
    add_deception_asset("linux_logs", info)

def fake_browser_profile():
    info = {"profile": "fake_user", "history": ["https://example.com", "https://bank.example"], "cookies": ["session=FAKE"]}
    add_deception_asset("browser_profile", info)

def fake_crypto_wallet():
    info = {"rpc": "http://127.0.0.1:8545", "addresses": ["0xFAKE...", "0xDEAD..."], "balance": "0.00"}
    add_deception_asset("crypto_wallet", info)

def fake_ad_domain():
    info = {"domain": "FAKECORP.LOCAL", "users": ["alice", "bob", "charlie"], "groups": ["Domain Admins", "HR", "IT"]}
    add_deception_asset("ad_domain", info)

def fake_smb_share():
    info = {"share": "\\\\FAKECORP\\HR", "files": ["payroll.xlsx", "employees.docx"]}
    add_deception_asset("smb_share", info)

def fake_sql_db():
    info = {"dsn": "FAKE-SQL", "tables": ["users", "transactions"], "rows": 1000}
    add_deception_asset("sql_db", info)

def fake_docker():
    info = {"containers": ["web", "db", "redis"], "images": ["fake/web:latest", "fake/db:latest"]}
    add_deception_asset("docker", info)

def fake_k8s():
    info = {"pods": ["api-0", "api-1", "worker-0"], "namespaces": ["default", "prod", "dev"]}
    add_deception_asset("k8s", info)

def fake_cloud_metadata():
    info = {"instance_id": "i-FAKE123456", "iam_role": "FakeRole", "region": "us-fake-1"}
    add_deception_asset("cloud_metadata", info)

def ai_deception_strategy(event: Dict[str, Any]) -> List[str]:
    kinds: List[str] = []

    etype = event.get("event_type") or event.get("action") or ""
    sig = event.get("signature", "") or str(event.get("extra", {}).get("name", ""))

    text = f"{etype} {sig}".lower()

    if "scan" in text or "recon" in text:
        kinds += ["net_interfaces", "windows_logs", "linux_logs", "cloud_metadata"]

    if "trojan" in text or "c2" in text or "command and control" in text:
        kinds += ["browser_profile", "crypto_wallet", "ad_domain"]

    if "exploit" in text or "sql" in text or "db" in text:
        kinds += ["sql_db", "smb_share"]

    if "process" in text or "spawn" in text:
        kinds += ["memory_dump", "gpu_info", "docker", "k8s"]

    if not kinds:
        kinds = ["net_interfaces", "windows_logs"]

    return kinds

def trigger_ai_deception_from_kinds(kinds: List[str], pid_for_mem: int = 0):
    if not config.get("ai_deception_enabled", True):
        return
    for k in kinds:
        if k == "memory_dump":
            fake_memory_dump(pid_for_mem)
        elif k == "gpu_info":
            fake_gpu_info()
        elif k == "net_interfaces":
            fake_net_interfaces()
        elif k == "windows_logs":
            fake_windows_logs()
        elif k == "linux_logs":
            fake_linux_logs()
        elif k == "browser_profile":
            fake_browser_profile()
        elif k == "crypto_wallet":
            fake_crypto_wallet()
        elif k == "ad_domain":
            fake_ad_domain()
        elif k == "smb_share":
            fake_smb_share()
        elif k == "sql_db":
            fake_sql_db()
        elif k == "docker":
            fake_docker()
        elif k == "k8s":
            fake_k8s()
        elif k == "cloud_metadata":
            fake_cloud_metadata()

# ============================================================
# PROCESS MONITOR (psutil)
# ============================================================

PROCESS_MONITOR_RUNNING = False

def start_process_monitor():
    global PROCESS_MONITOR_RUNNING
    if PROCESS_MONITOR_RUNNING:
        return
    psutil = AUTOLOADER.get_module("psutil")
    if psutil is None:
        print("[ProcessMonitor] psutil not available.")
        return

    def monitor_loop():
        known_pids = set()
        while True:
            try:
                for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
                    pid = p.info["pid"]
                    if pid not in known_pids:
                        known_pids.add(pid)
                        evt = {
                            "pid": pid,
                            "name": p.info.get("name"),
                            "cmdline": p.info.get("cmdline"),
                            "timestamp": datetime.now().isoformat(),
                        }
                        state["process_events"].append(evt)
                        log_behavior(pid, "process", "spawn", {"name": evt["name"], "cmdline": evt["cmdline"]})

                        kinds = ai_deception_strategy({
                            "event_type": "process",
                            "extra": {"name": evt["name"], "cmdline": evt["cmdline"]}
                        })
                        trigger_ai_deception_from_kinds(kinds, pid_for_mem=pid)

                save_json(STATE_PATH, state)
                time.sleep(2.0)
            except Exception as e:
                print(f"[ProcessMonitor] Error: {e}")
                time.sleep(2.0)

    PROCESS_MONITOR_RUNNING = True
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    print("[ProcessMonitor] Started.")

# ============================================================
# SURICATA INGESTION (eve.json)
# ============================================================

SURICATA_RUNNING = False

MITRE_MAP = {
    "ET SCAN": "Reconnaissance",
    "ET TROJAN": "Command and Control",
    "ET POLICY": "Policy Violation",
    "ET EXPLOIT": "Execution",
}

def start_suricata_ingestion():
    global SURICATA_RUNNING
    if SURICATA_RUNNING:
        return
    if not SURICATA_EVE_PATH.exists():
        print(f"[Suricata] eve.json not found at {SURICATA_EVE_PATH}, running stub.")
        return

    def tail_loop():
        try:
            with open(SURICATA_EVE_PATH, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(1.0)
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except Exception:
                        continue
                    handle_suricata_event(evt)
        except Exception as e:
            print(f"[Suricata] Error: {e}")

    SURICATA_RUNNING = True
    t = threading.Thread(target=tail_loop, daemon=True)
    t.start()
    print("[Suricata] Ingestion started.")

def handle_suricata_event(evt: Dict[str, Any]):
    kind = evt.get("event_type")
    sig = evt.get("alert", {}).get("signature", "") if "alert" in evt else ""
    src_ip = evt.get("src_ip")
    dest_ip = evt.get("dest_ip")
    mitre = None
    for key, val in MITRE_MAP.items():
        if key in sig:
            mitre = val
            break
    record = {
        "event_type": kind,
        "signature": sig,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "mitre": mitre,
        "timestamp": datetime.now().isoformat(),
    }
    state["suricata_events"].append(record)
    save_json(STATE_PATH, state)
    log_behavior(0, "suricata", "event", record)
    print(f"[Suricata] {kind} {sig} {src_ip}->{dest_ip} MITRE={mitre}")

    kinds = ai_deception_strategy(record)
    trigger_ai_deception_from_kinds(kinds, pid_for_mem=0)

# ============================================================
# PROTOCOL HONEYPOTS (S2 stubs)
# ============================================================

PROTOCOL_THREADS: List[threading.Thread] = []

def record_protocol_event(proto: str, details: Dict[str, Any]):
    evt = {
        "protocol": proto,
        "details": details,
        "timestamp": datetime.now().isoformat(),
    }
    state["protocol_events"].append(evt)
    save_json(STATE_PATH, state)
    print(f"[Proto-{proto}] {details}")

def start_smb_honeypot(port: int = 4450):
    import socket
    def loop():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        print(f"[SMB] Fake SMB listening on {port}")
        while True:
            conn, addr = s.accept()
            record_protocol_event("SMB", {"remote": addr, "event": "connect"})
            conn.sendall(b"\xFFSMBFAKE")
            conn.close()
    t = threading.Thread(target=loop, daemon=True)
    PROTOCOL_THREADS.append(t)
    t.start()

def start_ldap_honeypot(port: int = 3890):
    import socket
    def loop():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        print(f"[LDAP] Fake LDAP listening on {port}")
        while True:
            conn, addr = s.accept()
            record_protocol_event("LDAP", {"remote": addr, "event": "bind"})
            conn.sendall(b"FAKE_LDAP_RESPONSE")
            conn.close()
    t = threading.Thread(target=loop, daemon=True)
    PROTOCOL_THREADS.append(t)
    t.start()

def start_kerberos_honeypot(port: int = 8800):
    import socket
    def loop():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        print(f"[Kerberos] Fake KDC listening on {port}")
        while True:
            conn, addr = s.accept()
            record_protocol_event("Kerberos", {"remote": addr, "event": "ticket_request"})
            conn.sendall(b"FAKE_TICKET")
            conn.close()
    t = threading.Thread(target=loop, daemon=True)
    PROTOCOL_THREADS.append(t)
    t.start()

def start_sql_honeypot(port: int = 14330):
    import socket
    def loop():
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind(("0.0.0.0", port))
        s.listen(5)
        print(f"[SQL] Fake SQL listening on {port}")
        while True:
            conn, addr = s.accept()
            data = conn.recv(4096)
            record_protocol_event("SQL", {"remote": addr, "query": data.decode(errors="ignore")})
            conn.sendall(b"FAKE_ROW: id=1, name='admin'")
            conn.close()
    t = threading.Thread(target=loop, daemon=True)
    PROTOCOL_THREADS.append(t)
    t.start()

def start_docker_api_honeypot(port: int = 23760):
    from http.server import HTTPServer, BaseHTTPRequestHandler
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            record_protocol_event("DockerAPI", {"path": self.path, "method": "GET"})
            if self.path.startswith("/containers/json"):
                resp = json.dumps([{"Id": "fake1", "Image": "fake/web:latest"}]).encode()
            else:
                resp = json.dumps({"message": "fake docker api"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp)
    def loop():
        srv = HTTPServer(("0.0.0.0", port), Handler)
        print(f"[DockerAPI] Fake Docker API on {port}")
        srv.serve_forever()
    t = threading.Thread(target=loop, daemon=True)
    PROTOCOL_THREADS.append(t)
    t.start()

def start_k8s_api_honeypot(port: int = 64440):
    from http.server import HTTPServer, BaseHTTPRequestHandler
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            record_protocol_event("K8sAPI", {"path": self.path, "method": "GET"})
            if self.path.startswith("/api/v1/pods"):
                resp = json.dumps({"items": [{"metadata": {"name": "fake-pod"}}]}).encode()
            else:
                resp = json.dumps({"message": "fake k8s api"}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp)
    def loop():
        srv = HTTPServer(("0.0.0.0", port), Handler)
        print(f"[K8sAPI] Fake K8s API on {port}")
        srv.serve_forever()
    t = threading.Thread(target=loop, daemon=True)
    PROTOCOL_THREADS.append(t)
    t.start()

def start_cloud_metadata_honeypot(port: int = 16900):
    from http.server import HTTPServer, BaseHTTPRequestHandler
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            record_protocol_event("CloudMeta", {"path": self.path, "method": "GET"})
            resp = json.dumps({
                "instance-id": "i-FAKE123456",
                "iam-role": "FakeRole",
                "region": "us-fake-1"
            }).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(resp)
    def loop():
        srv = HTTPServer(("0.0.0.0", port), Handler)
        print(f"[CloudMeta] Fake cloud metadata on {port}")
        srv.serve_forever()
    t = threading.Thread(target=loop, daemon=True)
    PROTOCOL_THREADS.append(t)
    t.start()

def start_protocol_honeypots():
    if not config.get("protocol_honeypots_enabled", True):
        print("[Proto] Honeypots disabled.")
        return
    start_smb_honeypot()
    start_ldap_honeypot()
    start_kerberos_honeypot()
    start_sql_honeypot()
    start_docker_api_honeypot()
    start_k8s_api_honeypot()
    start_cloud_metadata_honeypot()

# ============================================================
# ML THREAT ENGINE (S3 stub)
# ============================================================

ML_RUNNING = False

def start_ml_threat_engine():
    global ML_RUNNING
    if ML_RUNNING or not config.get("ml_enabled", True):
        return
    np = AUTOLOADER.get_module("numpy")
    if np is None:
        print("[ML] numpy not available, running stub.")
    def loop():
        while True:
            try:
                threats = []
                for s in state["suricata_events"]:
                    score = 0.5
                    if s["mitre"] == "Execution":
                        score = 0.9
                    elif s["mitre"] == "Command and Control":
                        score = 0.8
                    threats.append({
                        "source": "suricata",
                        "event": s,
                        "score": score,
                    })
                for p in state["process_events"]:
                    score = 0.4
                    name = (p.get("name") or "").lower()
                    if "powershell" in name or "cmd.exe" in name:
                        score = 0.8
                    threats.append({
                        "source": "process",
                        "event": p,
                        "score": score,
                    })
                state["ml_threats"] = threats
                save_json(STATE_PATH, state)
                time.sleep(5.0)
            except Exception as e:
                print(f"[ML] Error: {e}")
                time.sleep(5.0)
    ML_RUNNING = True
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    print("[ML] Threat engine started.")

# ============================================================
# AUTONOMOUS REMEDIATION
# ============================================================

def autonomous_remediation():
    threats = state.get("ml_threats", [])
    for t in threats:
        score = t.get("score", 0)
        evt = t.get("event", {})
        src = t.get("source")

        if score >= 0.85:
            pid = evt.get("pid")
            if pid:
                auto_nuke_process(pid, "autonomous_remediation")
                print(f"[Remediation] Auto-nuked PID {pid} (score={score})")
        elif score >= 0.70:
            print(f"[Remediation] Triggering deception for medium threat (score={score})")
            kinds = ai_deception_strategy(evt)
            trigger_ai_deception_from_kinds(kinds)

    save_json(STATE_PATH, state)

def start_autonomous_remediation():
    def loop():
        while True:
            autonomous_remediation()
            time.sleep(5)
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    print("[Remediation] Autonomous remediation started.")

# ============================================================
# SWARM NODE (S3 stub)
# ============================================================

SWARM_RUNNING = False

def start_swarm_node():
    global SWARM_RUNNING
    if SWARM_RUNNING or not config.get("swarm_enabled", True):
        return
    node_id = config.get("node_id", "node-1")
    peers = config.get("swarm_peers", [])

    def loop():
        while True:
            msg = {
                "from": node_id,
                "timestamp": datetime.now().isoformat(),
                "threats": state.get("ml_threats", []),
            }
            state["swarm_messages"].append(msg)
            save_json(STATE_PATH, state)
            print(f"[Swarm] Broadcast from {node_id} to {len(peers)} peers (stub).")
            time.sleep(10.0)
    SWARM_RUNNING = True
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    print("[Swarm] Node started.")

# ============================================================
# PERSONA ENGINE (S3 stub)
# ============================================================

PERSONAS_RUNNING = False

def init_personas():
    if state["personas"]:
        return
    personas = []
    for i in range(5):
        personas.append({
            "id": f"persona-{i}",
            "name": f"User{i}",
            "role": "Employee",
            "habits": ["web_browsing", "file_edit", "login"],
        })
    state["personas"] = personas
    save_json(STATE_PATH, state)
    print("[Persona] Initialized personas.")

def start_persona_simulation():
    global PERSONAS_RUNNING
    if PERSONAS_RUNNING or not config.get("personas_enabled", True):
        return
    init_personas()
    def loop():
        import random
        while True:
            try:
                p = random.choice(state["personas"])
                action = random.choice(p["habits"])
                evt = {
                    "persona_id": p["id"],
                    "action": action,
                    "timestamp": datetime.now().isoformat(),
                }
                state["persona_events"].append(evt)
                save_json(STATE_PATH, state)
                print(f"[Persona] {p['id']} -> {action}")
                time.sleep(random.randint(5, 30))
            except Exception as e:
                print(f"[Persona] Error: {e}")
                time.sleep(5.0)
    PERSONAS_RUNNING = True
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    print("[Persona] Simulation started.")

# ============================================================
# WIN32 HOOKS + ENUMWINDOWS
# ============================================================

WIN32_AVAILABLE = False
user32 = None
ctypes = AUTOLOADER.get_module("ctypes")
if ctypes is not None and os.name == "nt":
    try:
        user32 = ctypes.windll.user32
        WIN32_AVAILABLE = True
    except Exception:
        WIN32_AVAILABLE = False

EVENT_OBJECT_CREATE = 0x8000
WINEVENT_OUTOFCONTEXT = 0x0000
HOOK_THREAD = None

def get_window_class_name(hwnd: int) -> str:
    if not WIN32_AVAILABLE:
        return "UnknownClass"
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value

def enum_windows_callback(hwnd, lParam):
    cls = get_window_class_name(hwnd)
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    pid_val = pid.value
    if should_trap_window(cls):
        trap_window_in_honeypot(hwnd, cls, pid_val)
    return True

def enum_all_windows_once():
    if not WIN32_AVAILABLE:
        print("[Win32] EnumWindows not available, using simulation.")
        simulate_window_events()
        return
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
    cb = EnumWindowsProc(enum_windows_callback)
    user32.EnumWindows(cb, 0)

def win_event_proc(hWinEventHook, event, hwnd, idObject, idChild, dwEventThread, dwmsEventTime):
    if event == EVENT_OBJECT_CREATE and hwnd:
        cls = get_window_class_name(hwnd)
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pid_val = pid.value
        if should_trap_window(cls):
            trap_window_in_honeypot(hwnd, cls, pid_val)

def start_win32_hooks():
    global HOOK_THREAD
    if not WIN32_AVAILABLE or not config.get("win32_hooks_enabled", True):
        print("[Win32] Hooks disabled or unavailable.")
        return

    def hook_thread():
        WinEventProcType = ctypes.WINFUNCTYPE(
            None, ctypes.c_void_p, ctypes.c_uint, ctypes.c_int,
            ctypes.c_long, ctypes.c_long, ctypes.c_uint, ctypes.c_uint
        )
        proc = WinEventProcType(win_event_proc)
        hook = user32.SetWinEventHook(
            EVENT_OBJECT_CREATE, EVENT_OBJECT_CREATE,
            0, proc, 0, 0, WINEVENT_OUTOFCONTEXT
        )
        if not hook:
            print("[Win32] Failed to set hook, falling back to enum.")
            enum_all_windows_once()
            return
        print("[Win32] SetWinEventHook active.")
        msg = ctypes.wintypes.MSG()
        while True:
            if user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) == 0:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    HOOK_THREAD = threading.Thread(target=hook_thread, daemon=True)
    HOOK_THREAD.start()

# ============================================================
# SIMULATION (fallback)
# ============================================================

def simulate_window_events():
    fake_events = [
        (0x001, "wuiconwindow", 1234),
        (0x002, "UnknownClassX", 5678),
        (0x003, "Chrome_WidgetWin_0", 9999),
        (0x004, "RandomUIClass", 2222),
    ]
    print("[Sim] Simulating window events...")
    for hwnd, cls_name, pid in fake_events:
        if should_trap_window(cls_name):
            trap_window_in_honeypot(hwnd, cls_name, pid)
        else:
            print(f"[Monitor] Allowed {cls_name} (PID {pid}, HWND {hwnd})")

# ============================================================
# FORENSIC EXPORT
# ============================================================

def forensic_export():
    bundle = {
        "timestamp": datetime.now().isoformat(),
        "suricata": state.get("suricata_events", []),
        "process": state.get("process_events", []),
        "protocol": state.get("protocol_events", []),
        "deception": state.get("deception_assets", []),
        "ml": state.get("ml_threats", []),
        "personas": state.get("persona_events", []),
        "swarm": state.get("swarm_messages", []),
    }

    export_dir = Path(BASE_DIR) / "forensics"
    export_dir.mkdir(exist_ok=True)

    fname = export_dir / f"forensic_{int(time.time())}.json"
    with open(fname, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)

    print(f"[Forensics] Exported bundle -> {fname}")
    return fname

# ============================================================
# CLI
# ============================================================

def cli(args: List[str]):
    import argparse
    parser = argparse.ArgumentParser(description="Codex Honeypot Godmode CLI")
    parser.add_argument("--honeypot-mode", choices=["A", "B", "C"])
    parser.add_argument("--window-scope", type=int, choices=[1, 2, 3])
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--list-trapped", action="store_true")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--no-win32-hooks", action="store_true")
    parser.add_argument("--no-suricata", action="store_true")
    parser.add_argument("--no-process-monitor", action="store_true")
    parser.add_argument("--no-ai-deception", action="store_true")
    parser.add_argument("--no-protocols", action="store_true")
    parser.add_argument("--no-ml", action="store_true")
    parser.add_argument("--no-swarm", action="store_true")
    parser.add_argument("--no-personas", action="store_true")
    parser.add_argument("--no-remediation", action="store_true")

    opts = parser.parse_args(args)

    if opts.honeypot_mode:
        set_honeypot_mode(opts.honeypot_mode)
    if opts.window_scope is not None:
        set_window_scope_mode(opts.window_scope)
    if opts.headless:
        config["headless"] = True
        save_json(CONFIG_PATH, config)
    if opts.no_win32_hooks:
        config["win32_hooks_enabled"] = False
        save_json(CONFIG_PATH, config)
    if opts.no_suricata:
        config["suricata_enabled"] = False
        save_json(CONFIG_PATH, config)
    if opts.no_process_monitor:
        config["process_monitor_enabled"] = False
        save_json(CONFIG_PATH, config)
    if opts.no_ai_deception:
        config["ai_deception_enabled"] = False
        save_json(CONFIG_PATH, config)
    if opts.no_protocols:
        config["protocol_honeypots_enabled"] = False
        save_json(CONFIG_PATH, config)
    if opts.no_ml:
        config["ml_enabled"] = False
        save_json(CONFIG_PATH, config)
    if opts.no_swarm:
        config["swarm_enabled"] = False
        save_json(CONFIG_PATH, config)
    if opts.no_personas:
        config["personas_enabled"] = False
        save_json(CONFIG_PATH, config)
    if opts.no_remediation:
        config["remediation_enabled"] = False
        save_json(CONFIG_PATH, config)

    if opts.replay:
        print("=== Behavior Replay ===")
        for entry in state["behavior_log"]:
            print(f"{entry['timestamp']} | PID {entry['pid']} | {entry['class']} | {entry['action']} | {entry.get('extra')}")
    if opts.list_trapped:
        print("=== Trapped Windows ===")
        for w in state["trapped_windows"]:
            print(f"{w['timestamp']} | HWND {w['hwnd']} | PID {w['pid']} | {w['class']}")

# ============================================================
# GUI (compact, vertical tab-style, collapsible top panel)
# ============================================================

def start_gui():
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title("Codex Honeypot Godmode v11")
    root.geometry("900x600")

    mode_var = tk.StringVar(value=get_honeypot_mode())
    scope_var = tk.IntVar(value=get_window_scope_mode())

    # Collapsible top panel container
    top_container = ttk.Frame(root)
    top_container.pack(side="top", fill="x")

    # Top bar: vertical list-style controls
    top_frame = ttk.Frame(top_container, padding=(10, 10))
    top_frame.pack(side="top", fill="x")

    # Mode section (vertical list)
    mode_section = ttk.LabelFrame(top_frame, text="Honeypot Mode", padding=(8, 8))
    mode_section.pack(side="top", fill="x", pady=4)
    for text, val in [("Mode A (Soft)", "A"), ("Mode B (Hard)", "B"), ("Mode C (Hybrid AI)", "C")]:
        ttk.Radiobutton(
            mode_section, text=text, value=val, variable=mode_var,
            command=lambda v=mode_var: set_honeypot_mode(v.get())
        ).pack(side="top", anchor="w", padx=8, pady=2)

    # Scope section (vertical list)
    scope_section = ttk.LabelFrame(top_frame, text="Window Scope", padding=(8, 8))
    scope_section.pack(side="top", fill="x", pady=4)
    for text, val in [("Scope 1 (wuiconwindow only)", 1),
                      ("Scope 2 (unknown classes)", 2),
                      ("Scope 3 (AI decide)", 3)]:
        ttk.Radiobutton(
            scope_section, text=text, value=val, variable=scope_var,
            command=lambda v=scope_var: set_window_scope_mode(v.get())
        ).pack(side="top", anchor="w", padx=8, pady=2)

    # Toggles section (vertical list)
    toggles_section = ttk.LabelFrame(top_frame, text="Subsystem Toggles", padding=(8, 8))
    toggles_section.pack(side="top", fill="x", pady=4)

    def toggle_flag(key: str):
        config[key] = not config.get(key, True)
        save_json(CONFIG_PATH, config)
        print(f"[Config] {key} -> {config[key]}")

    for label, key in [
        ("AI Deception", "ai_deception_enabled"),
        ("Suricata", "suricata_enabled"),
        ("Process Monitor", "process_monitor_enabled"),
        ("Protocol Honeypots", "protocol_honeypots_enabled"),
        ("ML Threat Engine", "ml_enabled"),
        ("Swarm Node", "swarm_enabled"),
        ("Persona Simulation", "personas_enabled"),
        ("Autonomous Remediation", "remediation_enabled"),
    ]:
        btn = ttk.Checkbutton(
            toggles_section,
            text=label,
            command=lambda k=key: toggle_flag(k)
        )
        if config.get(key, True):
            btn.state(["selected"])
        btn.pack(side="top", anchor="w", padx=8, pady=2)

    # Separator under top panel
    separator = ttk.Separator(root, orient="horizontal")
    separator.pack(fill="x", pady=6)

    # Collapsible toggle button
    top_visible = {"value": True}

    def toggle_top_panel():
        if top_visible["value"]:
            top_container.pack_forget()
            separator.pack_forget()
            top_visible["value"] = False
            collapse_btn.config(text="Show Control Panel")
        else:
            top_container.pack(side="top", fill="x")
            separator.pack(fill="x", pady=6)
            top_visible["value"] = True
            collapse_btn.config(text="Hide Control Panel")

    collapse_btn = ttk.Button(root, text="Hide Control Panel", command=toggle_top_panel)
    collapse_btn.pack(side="top", fill="x", padx=4, pady=4)

    # Main area: left tabs, right content
    main_frame = ttk.Frame(root)
    main_frame.pack(side="top", fill="both", expand=True, padx=2, pady=2)

    tab_frame = ttk.Frame(main_frame)
    tab_frame.pack(side="left", fill="y", padx=2, pady=2)

    content_frame = ttk.Frame(main_frame)
    content_frame.pack(side="left", fill="both", expand=True, padx=2, pady=2)

    events_tab = ttk.Frame(content_frame)
    deception_tab = ttk.Frame(content_frame)
    system_tab = ttk.Frame(content_frame)

    for f in (events_tab, deception_tab, system_tab):
        f.place(relx=0, rely=0, relwidth=1, relheight=1)

    current_tab = {"frame": events_tab}

    def show_tab(frame):
        current_tab["frame"] = frame
        events_tab.lower()
        deception_tab.lower()
        system_tab.lower()
        frame.lift()

    ttk.Button(tab_frame, text="Events", command=lambda: show_tab(events_tab)).pack(fill="x", pady=2)
    ttk.Button(tab_frame, text="Deception", command=lambda: show_tab(deception_tab)).pack(fill="x", pady=2)
    ttk.Button(tab_frame, text="System", command=lambda: show_tab(system_tab)).pack(fill="x", pady=2)

    # ===== Events Tab =====
    trapped_frame = ttk.LabelFrame(events_tab, text="Trapped Windows")
    trapped_frame.pack(fill="x", padx=2, pady=2)
    trapped_list = tk.Listbox(trapped_frame, height=3)
    trapped_list.pack(fill="x", expand=False)

    suricata_frame = ttk.LabelFrame(events_tab, text="Suricata Events")
    suricata_frame.pack(fill="x", padx=2, pady=2)
    suricata_list = tk.Listbox(suricata_frame, height=3)
    suricata_list.pack(fill="x", expand=False)

    process_frame = ttk.LabelFrame(events_tab, text="Process Events")
    process_frame.pack(fill="x", padx=2, pady=2)
    process_list = tk.Listbox(process_frame, height=3)
    process_list.pack(fill="x", expand=False)

    proto_frame = ttk.LabelFrame(events_tab, text="Protocol Honeypot Events")
    proto_frame.pack(fill="x", padx=2, pady=2)
    proto_list = tk.Listbox(proto_frame, height=3)
    proto_list.pack(fill="x", expand=False)

    ml_frame = ttk.LabelFrame(events_tab, text="ML Threats")
    ml_frame.pack(fill="x", padx=2, pady=2)
    ml_list = tk.Listbox(ml_frame, height=3)
    ml_list.pack(fill="x", expand=False)

    # ===== Deception Tab =====
    deception_frame = ttk.LabelFrame(deception_tab, text="Deception Assets (AI-driven)")
    deception_frame.pack(fill="both", expand=True, padx=2, pady=2)
    deception_list = tk.Listbox(deception_frame, height=4)
    deception_list.pack(fill="both", expand=True)

    deception_btn_frame = ttk.Frame(deception_tab)
    deception_btn_frame.pack(fill="x", padx=2, pady=2)

    def clear_deception():
        state["deception_assets"] = []
        save_json(STATE_PATH, state)
        refresh_views()

    def manual_deception():
        fake_net_interfaces()
        fake_windows_logs()
        fake_linux_logs()
        refresh_views()

    ttk.Button(deception_btn_frame, text="Generate Deception", command=manual_deception).pack(side="left", padx=2)
    ttk.Button(deception_btn_frame, text="Clear Deception", command=clear_deception).pack(side="left", padx=2)

    # ===== System Tab =====
    swarm_frame = ttk.LabelFrame(system_tab, text="Swarm Messages")
    swarm_frame.pack(fill="x", padx=2, pady=2)
    swarm_list = tk.Listbox(swarm_frame, height=3)
    swarm_list.pack(fill="x", expand=False)

    persona_frame = ttk.LabelFrame(system_tab, text="Persona Events")
    persona_frame.pack(fill="x", padx=2, pady=2)
    persona_list = tk.Listbox(persona_frame, height=3)
    persona_list.pack(fill="x", expand=False)

    node_frame = ttk.LabelFrame(system_tab, text="Node / Peers")
    node_frame.pack(fill="x", padx=2, pady=2)
    ttk.Label(node_frame, text=f"Node ID: {config.get('node_id', 'node-1')}").pack(side="left", padx=2)
    ttk.Label(node_frame, text=f"Peers: {config.get('swarm_peers', [])}").pack(side="left", padx=2)

    ttk.Button(system_tab, text="Export Forensics", command=forensic_export).pack(side="top", padx=4, pady=4)

    # ===== Bottom control bar =====
    control_frame = ttk.Frame(root)
    control_frame.pack(side="bottom", fill="x", padx=2, pady=2)

    def refresh_views():
        trapped_list.delete(0, tk.END)
        for w in state["trapped_windows"][-20:]:
            trapped_list.insert(tk.END, f"{w['timestamp']} | {w['class']} | PID {w['pid']}")

        suricata_list.delete(0, tk.END)
        for s in state["suricata_events"][-20:]:
            suricata_list.insert(tk.END, f"{s['timestamp']} | {s['event_type']} | {s['signature']}")

        process_list.delete(0, tk.END)
        for p in state["process_events"][-20:]:
            process_list.insert(tk.END, f"{p['timestamp']} | PID {p['pid']} | {p['name']}")

        proto_list.delete(0, tk.END)
        for pe in state["protocol_events"][-20:]:
            proto_list.insert(tk.END, f"{pe['timestamp']} | {pe['protocol']} | {pe['details']}")

        ml_list.delete(0, tk.END)
        for mt in state["ml_threats"][-20:]:
            ml_list.insert(tk.END, f"{mt['source']} | score={mt['score']:.2f}")

        deception_list.delete(0, tk.END)
        for d in state["deception_assets"][-20:]:
            deception_list.insert(tk.END, f"{d['timestamp']} | {d['kind']} | {d['details']}")

        swarm_list.delete(0, tk.END)
        for sm in state["swarm_messages"][-20:]:
            swarm_list.insert(tk.END, f"{sm['timestamp']} | from={sm['from']} | threats={len(sm['threats'])}")

        persona_list.delete(0, tk.END)
        for pe in state["persona_events"][-20:]:
            persona_list.insert(tk.END, f"{pe['timestamp']} | {pe['persona_id']} | {pe['action']}")

    def simulate_btn():
        simulate_window_events()
        refresh_views()

    def auto_nuke_selected():
        sel = trapped_list.curselection()
        if not sel:
            return
        idx = sel[0]
        if idx >= len(state["trapped_windows"]):
            return
        w = state["trapped_windows"][idx]
        auto_nuke_process(w["pid"], "manual_gui")
        refresh_views()

    ttk.Button(control_frame, text="Simulate Events", command=simulate_btn).pack(side="left", padx=2)
    ttk.Button(control_frame, text="Auto-Nuke Selected", command=auto_nuke_selected).pack(side="left", padx=2)
    ttk.Button(control_frame, text="Refresh", command=refresh_views).pack(side="left", padx=2)

    show_tab(events_tab)
    refresh_views()

    # Start backends
    if WIN32_AVAILABLE and config.get("win32_hooks_enabled", True):
        start_win32_hooks()
    else:
        print("[GUI] Win32 hooks not active; using simulation + manual refresh.")

    if config.get("suricata_enabled", True):
        start_suricata_ingestion()
    if config.get("process_monitor_enabled", True):
        start_process_monitor()
    if config.get("protocol_honeypots_enabled", True):
        start_protocol_honeypots()
    if config.get("ml_enabled", True):
        start_ml_threat_engine()
    if config.get("swarm_enabled", True):
        start_swarm_node()
    if config.get("personas_enabled", True):
        start_persona_simulation()
    if config.get("remediation_enabled", True):
        start_autonomous_remediation()

    root.mainloop()

# ============================================================
# SAFE STARTUP
# ============================================================

def safe_startup():
    try:
        args = sys.argv[1:]
        if args:
            cli(args)
        headless = config.get("headless", False)
        if headless:
            if WIN32_AVAILABLE and config.get("win32_hooks_enabled", True):
                start_win32_hooks()
                time.sleep(2)
                enum_all_windows_once()
            else:
                simulate_window_events()
            if config.get("suricata_enabled", True):
                start_suricata_ingestion()
            if config.get("process_monitor_enabled", True):
                start_process_monitor()
            if config.get("protocol_honeypots_enabled", True):
                start_protocol_honeypots()
            if config.get("ml_enabled", True):
                start_ml_threat_engine()
            if config.get("swarm_enabled", True):
                start_swarm_node()
            if config.get("personas_enabled", True):
                start_persona_simulation()
            if config.get("remediation_enabled", True):
                start_autonomous_remediation()
            while True:
                time.sleep(5)
        else:
            start_gui()
    except SystemExit:
        raise
    except Exception as e:
        print("\n[CRITICAL] Codex Honeypot Godmode crashed.")
        print("Reason:", e)
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    safe_startup()
