#!/usr/bin/env python3
# codex_security_bridge_v4_2_hybrid_deception.py
# Headless AI security + deception daemon:
# - 3 stacks (Security / Gaming / HighRisk)
# - Suricata eve.json ingestion (safe file reader)
# - GPU ML threat scoring (Torch optional, heuristic fallback)
# - Hybrid sandbox (safe actions + gated aggressive stubs)
# - Persistence (SQLite: events, modes, actions)
# - Multi-node sync (HTTP peers, gossip-style stub)
# - Process monitoring (psutil, optional)
# - Deception engine (fake infra, fake data, fake services)
# - Honeypot protocol stubs (SMB/LDAP/Kerberos/SQL/Docker/K8s/cloud metadata)
# - Swarm stub (peer gossip + leader flag)
# - HTTP bridge: /bridge, /status, /ai, /events, /deception

import sys
import subprocess
import importlib
import threading
import time
import json
import sqlite3
import os
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import dataclass
from typing import Optional, Dict, Any, List

# ============================================================
# PATHS / CONFIG
# ============================================================

BASE_DIR = os.path.join(os.path.expanduser("~"), "CodexSecurityBridgeV4_2")
DB_PATH = os.path.join(BASE_DIR, "codex_v4_2.db")
SURICATA_EVE = os.path.join(BASE_DIR, "eve.json")  # point to real eve.json if available
PEERS = ["http://127.0.0.1:6001/peer"]  # simple multi-node sync stub

AGGRESSIVE_ENABLED = True  # hybrid: aggressive stubs only when high-risk + high score

os.makedirs(BASE_DIR, exist_ok=True)
os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
os.makedirs(os.path.dirname(SURICATA_EVE), exist_ok=True)

# ============================================================
# LOGGING
# ============================================================

def log(msg: str) -> None:
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    print(f"[{ts}] {msg}")

# ============================================================
# AUTOLOADER (safe)
# ============================================================

class Autoloader:
    def __init__(self) -> None:
        self.dependency_map: Dict[str, Dict[str, Any]] = {
            "notify": {"modules": ["win10toast"], "install": True},
            "network": {"modules": ["requests"], "install": True},
            "ml": {"modules": ["torch"], "install": True},
            "proc": {"modules": ["psutil"], "install": True},
        }
        self.loaded_modules: Dict[str, Any] = {}
        self.lock = threading.Lock()

    def _soft_import(self, name: str) -> Optional[Any]:
        try:
            return importlib.import_module(name)
        except ImportError:
            return None
        except Exception as e:
            log(f"[AUTOLOADER] Unexpected import error for {name}: {e}")
            return None

    def _install(self, name: str) -> bool:
        try:
            log(f"[AUTOLOADER] Installing {name}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", name])
            return True
        except Exception as e:
            log(f"[AUTOLOADER] Install failed for {name}: {e}")
            return False

    def ensure_group(self, group: str) -> None:
        cfg = self.dependency_map.get(group, {})
        mods = cfg.get("modules", [])
        allow_install = cfg.get("install", False)
        for m in mods:
            mod = self._soft_import(m)
            if mod is None and allow_install and self._install(m):
                mod = self._soft_import(m)
            if mod is not None:
                with self.lock:
                    self.loaded_modules[m] = mod
                log(f"[AUTOLOADER] Loaded module {m} for group {group}")
            else:
                log(f"[AUTOLOADER] Missing module {m} for group {group}")

    def get(self, name: str) -> Optional[Any]:
        with self.lock:
            return self.loaded_modules.get(name)

AUTOLOADER = Autoloader()
for g in ("notify", "network", "ml", "proc"):
    AUTOLOADER.ensure_group(g)

# ============================================================
# PERSISTENCE (SQLite)
# ============================================================

class Persistence:
    def __init__(self, path: str = DB_PATH) -> None:
        self.path = path
        os.makedirs(os.path.dirname(self.path), exist_ok=True)
        self._init_db()

    def _init_db(self) -> None:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                stack TEXT,
                kind TEXT,
                payload TEXT,
                score REAL,
                mode TEXT,
                action TEXT,
                timestamp TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS modes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                mode TEXT,
                sec_events INTEGER,
                game_events INTEGER,
                hrisk_events INTEGER,
                timestamp TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS deception (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT,
                payload TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()
        log("[DB] Initialized codex_v4_2.db")

    def record_event(self, stack: str, kind: str, payload: str,
                     score: Optional[float], mode: str, action: str) -> None:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events (stack, kind, payload, score, mode, action, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
        """, (stack, kind, payload, score if score is not None else None, mode, action))
        conn.commit()
        conn.close()

    def record_mode(self, mode: str, sec: int, game: int, hrisk: int) -> None:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO modes (mode, sec_events, game_events, hrisk_events, timestamp)
            VALUES (?, ?, ?, ?, datetime('now'))
        """, (mode, sec, game, hrisk))
        conn.commit()
        conn.close()

    def record_deception(self, kind: str, payload: str) -> None:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO deception (kind, payload, timestamp)
            VALUES (?, ?, datetime('now'))
        """, (kind, payload))
        conn.commit()
        conn.close()

    def recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            SELECT stack, kind, payload, score, mode, action, timestamp
            FROM events ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        conn.close()
        out = []
        for r in rows:
            out.append({
                "stack": r[0],
                "kind": r[1],
                "payload": r[2],
                "score": r[3],
                "mode": r[4],
                "action": r[5],
                "timestamp": r[6],
            })
        return out

    def recent_deception(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            SELECT kind, payload, timestamp
            FROM deception ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        conn.close()
        out = []
        for r in rows:
            out.append({
                "kind": r[0],
                "payload": r[1],
                "timestamp": r[2],
            })
        return out

PERSIST = Persistence()

# ============================================================
# GPU ML THREAT SCORING (Torch optional + heuristic)
# ============================================================

class ThreatScorer:
    def __init__(self) -> None:
        self.torch = AUTOLOADER.get("torch")
        self.model = None
        if self.torch:
            log("[ML] torch available (stub model)")
            self._init_model()
        else:
            log("[ML] torch not available, using heuristic scoring only")

    def _init_model(self) -> None:
        torch = self.torch

        class DummyModel(torch.nn.Module):
            def __init__(self):
                super().__init__()
                self.fc = torch.nn.Linear(16, 1)

            def forward(self, x):
                return self.fc(x)

        self.model = DummyModel()
        self.model.eval()

    def score(self, kind: str, payload: str) -> float:
        text = payload.lower()
        base = 0.0
        bad_words = [
            "crack", "warez", "keygen", "malware", "trojan", "ransom",
            "exploit", "phishing", "c2", "backdoor"
        ]
        for w in bad_words:
            if w in text:
                base += 3.0
        if "exe" in text or ".dll" in text or ".sys" in text:
            base += 1.5
        if "download" in text or "http" in text or "https" in text:
            base += 1.0
        if kind in ("ai_text", "suricata", "process", "deception"):
            base *= 1.2

        if self.model:
            vec = [len(text) % 100, sum(1 for w in bad_words if w in text)]
            vec += [0] * (16 - len(vec))
            x = self.torch.tensor([vec], dtype=self.torch.float32)
            with self.torch.no_grad():
                out = float(self.model(x).item())
            return max(base, base + out / 10.0)
        return base

SCORER = ThreatScorer()

# ============================================================
# STACKS
# ============================================================

@dataclass
class StackStatus:
    events: int = 0
    last_event: Optional[str] = None

class BaseStack:
    def __init__(self, label: str) -> None:
        self.label = label
        self.status = StackStatus()
        self.lock = threading.Lock()

    def handle(self, payload: str, kind: str, score: float, mode: str, action: str) -> None:
        with self.lock:
            self.status.events += 1
            self.status.last_event = payload
        log(f"[{self.label}] {payload} (score={score:.2f}, mode={mode}, action={action})")
        PERSIST.record_event(self.label, kind, payload, score, mode, action)

    def get_status(self) -> StackStatus:
        with self.lock:
            return StackStatus(self.status.events, self.status.last_event)

class SecurityStack(BaseStack):
    def __init__(self) -> None:
        super().__init__("SEC")

class GamingStack(BaseStack):
    def __init__(self) -> None:
        super().__init__("GAME")

class HighRiskStack(BaseStack):
    def __init__(self) -> None:
        super().__init__("HRISK")

# ============================================================
# SURICATA v6 INGESTION (eve.json)
# ============================================================

class SuricataIngestor:
    def __init__(self, sec_stack: SecurityStack) -> None:
        self.sec_stack = sec_stack
        self.running = False
        self.offset = 0

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[SURICATA] Ingestor started (eve.json)")

    def _loop(self) -> None:
        while self.running:
            time.sleep(5.0)
            if not os.path.exists(SURICATA_EVE):
                continue
            try:
                with open(SURICATA_EVE, "r", encoding="utf-8") as f:
                    f.seek(self.offset)
                    for line in f:
                        self.offset = f.tell()
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            evt = json.loads(line)
                        except Exception:
                            continue
                        sig = evt.get("alert", {}).get("signature", "event")
                        src = evt.get("src_ip", "")
                        dst = evt.get("dest_ip", "")
                        payload = f"Suricata alert: {sig} {src}->{dst}"
                        score = SCORER.score("suricata", payload)
                        self.sec_stack.handle(payload, "suricata", score, "security_priority", "suricata_ingest")
            except Exception as e:
                log(f"[SURICATA] Error: {e}")

    def stop(self) -> None:
        self.running = False
        log("[SURICATA] Ingestor stopped")

# ============================================================
# SANDBOX ENGINE (hybrid, safe stubs)
# ============================================================

class SandboxEngine:
    def __init__(self) -> None:
        self.quarantine_dir = os.path.join(BASE_DIR, "quarantine")
        os.makedirs(self.quarantine_dir, exist_ok=True)

    def move_process_to_honeypot(self, desc: str) -> str:
        log(f"[SANDBOX] move process to honeypot (stub): {desc}")
        return "honeypot_stub"

    def quarantine_file(self, path: str) -> str:
        try:
            base = os.path.basename(path)
            target = os.path.join(self.quarantine_dir, base)
            if os.path.exists(path):
                os.rename(path, target)
                log(f"[SANDBOX] quarantined file {path} -> {target}")
                return f"quarantine:{target}"
            else:
                log(f"[SANDBOX] file not found for quarantine: {path}")
                return "quarantine_missing"
        except Exception as e:
            log(f"[SANDBOX] quarantine error: {e}")
            return "quarantine_error"

    def block_domain_hosts(self, domain: str) -> str:
        try:
            hosts = r"C:\Windows\System32\drivers\etc\hosts" if os.name == "nt" else "/etc/hosts"
            line = f"0.0.0.0 {domain}\n"
            with open(hosts, "a", encoding="utf-8") as f:
                f.write(line)
            log(f"[SANDBOX] blocked domain via hosts: {domain}")
            return "block_hosts"
        except Exception as e:
            log(f"[SANDBOX] block domain error: {e}")
            return "block_error"

    def aggressive_stub(self, desc: str) -> str:
        log(f"[SANDBOX] aggressive action stub: {desc}")
        return "aggressive_stub"

SANDBOX = SandboxEngine()

# ============================================================
# PROCESS MONITORING (psutil, optional)
# ============================================================

class ProcessMonitor:
    def __init__(self, sec_stack: SecurityStack) -> None:
        self.sec_stack = sec_stack
        self.running = False
        self.psutil = AUTOLOADER.get("psutil")

    def start(self) -> None:
        if self.running or not self.psutil:
            if not self.psutil:
                log("[PROC] psutil not available, process monitor disabled")
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[PROC] Monitor started")

    def _loop(self) -> None:
        seen = set()
        while self.running:
            time.sleep(10.0)
            try:
                for p in self.psutil.process_iter(attrs=["pid", "name", "exe"]):
                    pid = p.info.get("pid")
                    name = p.info.get("name") or ""
                    exe = p.info.get("exe") or ""
                    key = (pid, exe)
                    if key in seen:
                        continue
                    seen.add(key)
                    payload = f"Process: {pid} {name} {exe}"
                    score = SCORER.score("process", payload)
                    self.sec_stack.handle(payload, "process", score, "balanced", "proc_monitor")
            except Exception as e:
                log(f"[PROC] Error: {e}")

    def stop(self) -> None:
        self.running = False
        log("[PROC] Monitor stopped")

# ============================================================
# MULTI-NODE SYNC / SWARM STUB
# ============================================================

class PeerSync:
    def __init__(self) -> None:
        self.requests = AUTOLOADER.get("requests")
        self.running = False
        self.leader = False

    def start(self) -> None:
        if self.running or not self.requests:
            if not self.requests:
                log("[PEER] requests not available, peer sync disabled")
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[PEER] Sync started")

    def _loop(self) -> None:
        while self.running:
            time.sleep(20.0)
            try:
                for p in PEERS:
                    self.requests.post(p, json={"ping": "codex_v4_2", "leader": self.leader})
            except Exception as e:
                log(f"[PEER] Sync error: {e}")

    def stop(self) -> None:
        self.running = False
        log("[PEER] Sync stopped")

    def set_leader(self, flag: bool) -> None:
        self.leader = flag
        log(f"[PEER] leader={self.leader}")

PEER_SYNC = PeerSync()

# ============================================================
# NOTIFICATIONS
# ============================================================

class Notifier:
    def __init__(self) -> None:
        win10toast = AUTOLOADER.get("win10toast")
        if win10toast:
            self.toaster = win10toast.ToastNotifier()
        else:
            self.toaster = None
            log("[NOTIFY] win10toast not available")

    def notify(self, title: str, msg: str) -> None:
        if self.toaster:
            self.toaster.show_toast(title, msg, duration=5, threaded=True)
        log(f"[NOTIFY] {title} -> {msg}")

NOTIFY = Notifier()

# ============================================================
# DECEPTION ENGINE (fake infra/data/services)
# ============================================================

class DeceptionEngine:
    def __init__(self) -> None:
        pass

    # Fake system info
    def fake_memory_dump(self) -> Dict[str, Any]:
        return {"segments": ["0x1000-0x1FFF", "0x2000-0x2FFF"], "entropy": 7.3}

    def fake_gpu_info(self) -> Dict[str, Any]:
        return {"vendor": "FakeNVIDIA", "model": "RTX 9999", "vram_gb": 64}

    def fake_network_interfaces(self) -> List[Dict[str, Any]]:
        return [
            {"name": "eth0", "ip": "10.0.0.10", "mac": "AA:BB:CC:DD:EE:FF"},
            {"name": "wifi0", "ip": "192.168.1.42", "mac": "11:22:33:44:55:66"},
        ]

    # Fake logs
    def fake_windows_event_logs(self) -> List[str]:
        return ["Security: Logon success", "System: Service started", "Application: Error 0xDEADBEEF"]

    def fake_linux_journal(self) -> List[str]:
        return ["kernel: eth0 link up", "sshd: Accepted password", "sudo: user ran apt-get"]

    # Fake user world
    def fake_browser_profiles(self) -> List[Dict[str, Any]]:
        return [{"user": "alice", "history": ["bank.com", "social.com"], "cookies": 42}]

    def fake_crypto_wallets(self) -> List[Dict[str, Any]]:
        return [{"wallet": "0xFAKE", "balance": "3.1415 ETH", "tx_count": 1337}]

    # Fake infra
    def fake_ad_domain(self) -> Dict[str, Any]:
        return {"domain": "FAKECORP.LOCAL", "users": ["alice", "bob", "charlie"], "groups": ["HR", "IT", "Finance"]}

    def fake_smb_shares(self) -> List[str]:
        return ["\\\\FAKECORP\\HR", "\\\\FAKECORP\\Finance", "\\\\FAKECORP\\Dev"]

    def fake_sql_databases(self) -> List[str]:
        return ["hr_db", "finance_db", "logs_db"]

    def fake_docker_containers(self) -> List[Dict[str, Any]]:
        return [{"name": "webapp", "image": "fakecorp/web:latest", "status": "running"}]

    def fake_cloud_metadata(self) -> Dict[str, Any]:
        return {"instance_id": "i-FAKE123", "region": "us-fake-1", "role": "web-server"}

    # Fake SOC/EDR/SIEM/IAM
    def fake_soc_dashboard(self) -> Dict[str, Any]:
        return {"alerts": 5, "severity": ["low", "medium", "high"], "panels": ["timeline", "map", "matrix"]}

    def fake_edr_agent(self) -> Dict[str, Any]:
        return {"agent_id": "EDR-FAKE-01", "status": "online", "events": 123}

    def fake_siem(self) -> Dict[str, Any]:
        return {"events_per_minute": 300, "correlation_rules": 42}

    def fake_cloud_iam(self) -> Dict[str, Any]:
        return {"users": ["alice", "bob"], "roles": ["admin", "viewer"], "policies": ["allow_s3_read"]}

    # Protocol honeypot stubs
    def fake_smb_server(self) -> str:
        return "Fake SMB server listening (stub)"

    def fake_ldap_server(self) -> str:
        return "Fake LDAP server listening (stub)"

    def fake_kerberos_kdc(self) -> str:
        return "Fake Kerberos KDC listening (stub)"

    def fake_sql_listener(self) -> str:
        return "Fake SQL listener (stub)"

    def fake_docker_api(self) -> str:
        return "Fake Docker API (stub)"

    def fake_k8s_api(self) -> str:
        return "Fake K8s API (stub)"

    def fake_cloud_metadata_http(self) -> str:
        return "Fake cloud metadata HTTP server (stub)"

    def generate_deception_snapshot(self) -> Dict[str, Any]:
        snap = {
            "memory": self.fake_memory_dump(),
            "gpu": self.fake_gpu_info(),
            "net": self.fake_network_interfaces(),
            "win_logs": self.fake_windows_event_logs(),
            "linux_logs": self.fake_linux_journal(),
            "browser": self.fake_browser_profiles(),
            "wallets": self.fake_crypto_wallets(),
            "ad": self.fake_ad_domain(),
            "smb": self.fake_smb_shares(),
            "sql": self.fake_sql_databases(),
            "docker": self.fake_docker_containers(),
            "cloud_meta": self.fake_cloud_metadata(),
            "soc": self.fake_soc_dashboard(),
            "edr": self.fake_edr_agent(),
            "siem": self.fake_siem(),
            "iam": self.fake_cloud_iam(),
        }
        PERSIST.record_deception("snapshot", json.dumps(snap))
        return snap

DECEPTION = DeceptionEngine()

# ============================================================
# AI CONTROLLER (adaptive modes)
# ============================================================

class AIController:
    def __init__(self,
                 sec: SecurityStack,
                 game: GamingStack,
                 hrisk: HighRiskStack) -> None:
        self.sec = sec
        self.game = game
        self.hrisk = hrisk
        self.mode = "balanced"
        self.running = False
        self.lock = threading.Lock()

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[AI] Controller started")

    def stop(self) -> None:
        self.running = False
        log("[AI] Controller stopped")

    def _loop(self) -> None:
        while self.running:
            time.sleep(1.0)
            sec_s = self.sec.get_status()
            game_s = self.game.get_status()
            hrisk_s = self.hrisk.get_status()

            sec_events = sec_s.events
            game_events = game_s.events
            hrisk_events = hrisk_s.events

            if hrisk_events > 20 and hrisk_events >= sec_events:
                mode = "highrisk_lockdown"
            elif sec_events > 50 and sec_events > 2 * game_events:
                mode = "security_priority"
            elif game_events > 50 and game_events > 2 * sec_events:
                mode = "gaming_priority"
            else:
                mode = "balanced"

            with self.lock:
                self.mode = mode

            PERSIST.record_mode(mode, sec_events, game_events, hrisk_events)
            log(f"[AI] mode={mode} sec={sec_events} game={game_events} hrisk={hrisk_events}")

    def get_mode(self) -> str:
        with self.lock:
            return self.mode

# ============================================================
# HTTP BRIDGE + STATUS + EVENTS + DECEPTION
# ============================================================

class BridgeHandler(BaseHTTPRequestHandler):
    supervisor = None  # type: ignore

    def _send_json(self, obj: Dict[str, Any], code: int = 200) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length) if length > 0 else b"{}"
        try:
            payload = json.loads(body.decode("utf-8", errors="ignore"))
        except Exception:
            payload = {}

        kind = payload.get("kind")
        value = str(payload.get("value", ""))

        if kind in ("security", "url"):
            self.supervisor.handle_security(kind, value)
            self._send_json({"ok": True, "stack": "security"})
        elif kind in ("gaming", "query"):
            self.supervisor.handle_gaming(kind, value)
            self._send_json({"ok": True, "stack": "gaming"})
        elif kind in ("highrisk", "ai_text"):
            self.supervisor.handle_highrisk(kind, value)
            self._send_json({"ok": True, "stack": "highrisk"})
        elif kind == "deception_snapshot":
            snap = self.supervisor.generate_deception_snapshot()
            self._send_json({"ok": True, "snapshot": snap})
        else:
            self._send_json({"error": "unknown kind"}, 400)

    def do_GET(self) -> None:
        if self.path == "/status":
            self._send_json(self.supervisor.get_status())
        elif self.path == "/ai":
            self._send_json({"mode": self.supervisor.ai.get_mode()})
        elif self.path == "/events":
            self._send_json({"events": PERSIST.recent_events(50)})
        elif self.path == "/deception":
            self._send_json({"deception": PERSIST.recent_deception(50)})
        else:
            self._send_json({"error": "not found"}, 404)

    def log_message(self, format: str, *args: Any) -> None:
        pass

class BridgeServer:
    def __init__(self, host: str = "127.0.0.1", port: int = 5000, supervisor: "Supervisor" = None) -> None:
        self.host = host
        self.port = port
        self.supervisor = supervisor
        self.httpd: Optional[HTTPServer] = None

    def start(self) -> None:
        BridgeHandler.supervisor = self.supervisor
        self.httpd = HTTPServer((self.host, self.port), BridgeHandler)
        log(f"[BRIDGE] Listening on http://{self.host}:{self.port}/bridge")
        threading.Thread(target=self.httpd.serve_forever, daemon=True).start()

    def stop(self) -> None:
        if self.httpd:
            self.httpd.shutdown()
            self.httpd.server_close()
        log("[BRIDGE] Stopped")

# ============================================================
# SUPERVISOR
# ============================================================

class Supervisor:
    def __init__(self) -> None:
        self.sec = SecurityStack()
        self.game = GamingStack()
        self.hrisk = HighRiskStack()
        self.ai = AIController(self.sec, self.game, self.hrisk)
        self.bridge = BridgeServer(supervisor=self)
        self.suricata = SuricataIngestor(self.sec)
        self.procmon = ProcessMonitor(self.sec)
        self.running = False

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        log("[SUP] Starting Codex Security Bridge v4.2 Hybrid Deception")
        self.ai.start()
        self.bridge.start()
        self.suricata.start()
        self.procmon.start()
        PEER_SYNC.start()
        PEER_SYNC.set_leader(True)
        log("[SUP] All subsystems started")

    def stop(self) -> None:
        if not self.running:
            return
        self.running = False
        log("[SUP] Stopping subsystems")
        self.ai.stop()
        self.bridge.stop()
        self.suricata.stop()
        self.procmon.stop()
        PEER_SYNC.stop()
        log("[SUP] All subsystems stopped")

    # Bridge handlers
    def handle_security(self, kind: str, payload: str) -> None:
        score = SCORER.score(kind, payload)
        mode = self.ai.get_mode()
        action = "log"
        if mode in ("security_priority", "highrisk_lockdown") and score >= 3.0:
            NOTIFY.notify("Security event", payload)
            action = "notify"
        self.sec.handle(payload, kind, score, mode, action)

    def handle_gaming(self, kind: str, payload: str) -> None:
        score = SCORER.score(kind, payload)
        mode = self.ai.get_mode()
        self.game.handle(payload, kind, score, mode, "log")

    def handle_highrisk(self, kind: str, payload: str) -> None:
        score = SCORER.score(kind, payload)
        mode = self.ai.get_mode()
        action = "log"
        if score >= 3.0:
            NOTIFY.notify("High-risk activity", payload)
            action = "notify"
            SANDBOX.move_process_to_honeypot(payload)
            if ".exe" in payload:
                qa = SANDBOX.quarantine_file(payload)
                action = qa
            if "http" in payload or "https" in payload:
                ba = SANDBOX.block_domain_hosts(payload)
                action = ba
            if AGGRESSIVE_ENABLED and mode == "highrisk_lockdown" and score >= 5.0:
                ag = SANDBOX.aggressive_stub(payload)
                action = ag
        self.hrisk.handle(payload, kind, score, mode, action)

    def generate_deception_snapshot(self) -> Dict[str, Any]:
        return DECEPTION.generate_deception_snapshot()

    def get_status(self) -> Dict[str, Any]:
        sec = self.sec.get_status()
        game = self.game.get_status()
        hrisk = self.hrisk.get_status()
        return {
            "running": self.running,
            "mode": self.ai.get_mode(),
            "security": {"events": sec.events, "last_event": sec.last_event},
            "gaming": {"events": game.events, "last_event": game.last_event},
            "highrisk": {"events": hrisk.events, "last_event": hrisk.last_event},
        }

# ============================================================
# MAIN
# ============================================================

def main() -> None:
    sup = Supervisor()
    sup.start()
    log("[MAIN] Codex Security Bridge v4.2 Hybrid Deception running. Ctrl+C to exit.")
    try:
        while True:
            time.sleep(5.0)
            status = sup.get_status()
            log(f"[STATUS] {status}")
    except KeyboardInterrupt:
        log("[MAIN] Ctrl+C detected, stopping.")
        sup.stop()

if __name__ == "__main__":
    main()
