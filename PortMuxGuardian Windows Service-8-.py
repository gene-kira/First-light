#!/usr/bin/env python3
# codex_security_bridge_v4_3_1_hybrid_deception.py
# Headless AI security + deception daemon (v4.3.1):
# - 3 stacks (Security / Gaming / HighRisk)
# - Suricata eve.json ingestion (safe file reader)
# - GPU ML threat scoring (Torch optional, heuristic fallback)
# - Hybrid sandbox (safe actions + gated aggressive stubs)
# - Persistence (SQLite: events, modes, deception)
# - Swarm mesh stub (HTTP gossip + leader flag)
# - Process monitoring (psutil, optional)
# - Deception engine (fake infra, fake data, fake services + honeypot events)
# - HTTP bridge: /bridge, /status, /ai, /events, /deception, /mode, /peer
# - Safe notifier (headless, log-only)

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

BASE_DIR = os.path.join(os.path.expanduser("~"), "CodexSecurityBridgeV4_3_1")
DB_PATH = os.path.join(BASE_DIR, "codex_v4_3_1.db")
SURICATA_EVE = os.path.join(BASE_DIR, "eve.json")
PEERS = ["http://127.0.0.1:6001/peer"]

AGGRESSIVE_ENABLED = True

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
for g in ("network", "ml", "proc"):
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
        log("[DB] Initialized codex_v4_3_1.db")

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
        out: List[Dict[str, Any]] = []
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
        out: List[Dict[str, Any]] = []
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
            log("[ML] torch available (dummy model)")
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
        self.lock = threading.Lock()

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
                with self.lock:
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
    def __init__(self, hrisk_stack: HighRiskStack) -> None:
        self.psutil = AUTOLOADER.get("psutil")
        self.hrisk_stack = hrisk_stack
        self.running = False

    def start(self) -> None:
        if self.running or not self.psutil:
            if not self.psutil:
                log("[PROC] psutil not available, process monitoring disabled")
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[PROC] Process monitor started")

    def _loop(self) -> None:
        while self.running:
            try:
                procs = list(self.psutil.process_iter(attrs=["pid", "name", "username", "exe"]))
                for p in procs:
                    name = (p.info.get("name") or "").lower()
                    exe = (p.info.get("exe") or "").lower()
                    if any(bad in name for bad in ("miner", "hack", "crack", "keygen", "cheat")):
                        payload = f"Suspicious process: pid={p.info.get('pid')} name={p.info.get('name')} user={p.info.get('username')} exe={p.info.get('exe')}"
                        score = SCORER.score("process", payload)
                        self.hrisk_stack.handle(payload, "process", score, "high_risk", "proc_monitor")
                time.sleep(10.0)
            except Exception as e:
                log(f"[PROC] Error: {e}")
                time.sleep(10.0)

    def stop(self) -> None:
        self.running = False
        log("[PROC] Process monitor stopped")

# ============================================================
# SAFE NOTIFIER (headless)
# ============================================================

class Notifier:
    def __init__(self) -> None:
        log("[NOTIFY] Headless notifier active (log-only)")

    def notify(self, title: str, msg: str) -> None:
        log(f"[NOTIFY] {title} -> {msg}")

NOTIFY = Notifier()

# ============================================================
# DECEPTION ENGINE
# ============================================================

class DeceptionEngine:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.fake_infra = {
            "smb_shares": ["\\\\FAKECORP\\HR", "\\\\FAKECORP\\Finance", "\\\\FAKECORP\\Dev"],
            "ldap_dn": ["CN=Admin,CN=Users,DC=fakecorp,DC=local"],
            "kerberos_realms": ["FAKECORP.LOCAL"],
            "sql_endpoints": ["sql.fakecorp.local:1433"],
            "docker_hosts": ["tcp://fake-docker:2375"],
            "k8s_clusters": ["https://fake-k8s:6443"],
            "cloud_metadata": ["http://169.254.169.254/latest/meta-data/fake"],
        }
        self.fake_data = {
            "credentials": [
                {"user": "admin", "pass": "Password123!", "source": "fake_ldap"},
                {"user": "svc_backup", "pass": "Backup!2024", "source": "fake_smb"},
            ],
            "api_keys": [
                {"key": "FAKE-API-KEY-123", "service": "fake-cloud"},
            ],
        }
        self.fake_services = {
            "smb": False,
            "ldap": False,
            "kerberos": False,
            "sql": False,
            "docker": False,
            "k8s": False,
            "cloud": False,
        }

    def _record(self, kind: str, payload: Dict[str, Any]) -> None:
        PERSIST.record_deception(kind, json.dumps(payload))

    def enable_service(self, name: str) -> None:
        with self.lock:
            if name in self.fake_services:
                self.fake_services[name] = True
                payload = {"service": name, "enabled": True}
                log(f"[DECEPTION] Enabled fake service: {name}")
                self._record("service_toggle", payload)

    def disable_service(self, name: str) -> None:
        with self.lock:
            if name in self.fake_services:
                self.fake_services[name] = False
                payload = {"service": name, "enabled": False}
                log(f"[DECEPTION] Disabled fake service: {name}")
                self._record("service_toggle", payload)

    def list_services(self) -> Dict[str, bool]:
        with self.lock:
            return dict(self.fake_services)

    def honeypot_event(self, proto: str, detail: str) -> None:
        payload = {"proto": proto, "detail": detail}
        log(f"[DECEPTION] Honeypot event: {proto} {detail}")
        self._record("honeypot_event", payload)

    def generate_snapshot(self) -> Dict[str, Any]:
        snap = {
            "infra": self.fake_infra,
            "data": self.fake_data,
            "services": self.list_services(),
        }
        log("[DECEPTION] Generated deception snapshot")
        self._record("snapshot", snap)
        return snap

DECEPTION = DeceptionEngine()

# ============================================================
# HONEYPOT PROTOCOL STUBS
# ============================================================

class HoneypotProtocols:
    def smb(self, path: str) -> str:
        desc = f"SMB access to {path}"
        DECEPTION.honeypot_event("SMB", desc)
        return "smb_stub"

    def ldap(self, dn: str) -> str:
        desc = f"LDAP bind/search on {dn}"
        DECEPTION.honeypot_event("LDAP", desc)
        return "ldap_stub"

    def kerberos(self, principal: str) -> str:
        desc = f"Kerberos ticket request for {principal}"
        DECEPTION.honeypot_event("KERBEROS", desc)
        return "kerberos_stub"

    def sql(self, query: str) -> str:
        desc = f"SQL query: {query[:128]}"
        DECEPTION.honeypot_event("SQL", desc)
        return "sql_stub"

    def docker(self, action: str) -> str:
        desc = f"Docker action: {action}"
        DECEPTION.honeypot_event("DOCKER", desc)
        return "docker_stub"

    def k8s(self, action: str) -> str:
        desc = f"K8s action: {action}"
        DECEPTION.honeypot_event("K8S", desc)
        return "k8s_stub"

    def cloud_metadata(self, path: str) -> str:
        desc = f"Cloud metadata access: {path}"
        DECEPTION.honeypot_event("CLOUD_META", desc)
        return "cloud_meta_stub"

HONEYPOT = HoneypotProtocols()

# ============================================================
# SWARM / PEER SYNC STUB
# ============================================================

class SwarmSync:
    def __init__(self) -> None:
        self.requests = AUTOLOADER.get("requests")
        self.leader = False
        self.running = False

    def start(self) -> None:
        if self.running or not self.requests:
            if not self.requests:
                log("[SWARM] requests not available, swarm disabled")
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[SWARM] Swarm sync started")

    def _loop(self) -> None:
        while self.running:
            try:
                for peer in PEERS:
                    payload = {
                        "node": os.getenv("COMPUTERNAME", "codex-node"),
                        "leader": self.leader,
                        "timestamp": time.time(),
                    }
                    try:
                        self.requests.post(peer, json=payload, timeout=2.0)
                        log(f"[SWARM] Gossip sent to {peer}")
                    except Exception as e:
                        log(f"[SWARM] Gossip error to {peer}: {e}")
                time.sleep(15.0)
            except Exception as e:
                log(f"[SWARM] Loop error: {e}")
                time.sleep(15.0)

    def stop(self) -> None:
        self.running = False
        log("[SWARM] Swarm sync stopped")

    def set_leader(self, flag: bool) -> None:
        self.leader = flag
        log(f"[SWARM] leader={self.leader}")

SWARM = SwarmSync()

# ============================================================
# MODES / RISK GATING + AI CONTROLLER
# ============================================================

class ModeManager:
    def __init__(self, sec: SecurityStack, game: GamingStack, hrisk: HighRiskStack) -> None:
        self.sec = sec
        self.game = game
        self.hrisk = hrisk
        self.mode = "balanced"
        self.lock = threading.Lock()

    def set_mode(self, mode: str) -> None:
        with self.lock:
            self.mode = mode
        st_sec = self.sec.get_status()
        st_game = self.game.get_status()
        st_hrisk = self.hrisk.get_status()
        PERSIST.record_mode(mode, st_sec.events, st_game.events, st_hrisk.events)
        log(f"[MODE] Switched mode to {mode}")
        NOTIFY.notify("Codex Mode Change", f"Mode -> {mode}")

    def get_mode(self) -> str:
        with self.lock:
            return self.mode

    def decide_action(self, score: float, stack_label: str) -> str:
        mode = self.get_mode()
        if mode == "security_priority":
            if score >= 5.0:
                return "aggressive" if AGGRESSIVE_ENABLED and stack_label == "HRISK" else "sandbox"
            return "log_only"
        elif mode == "high_risk":
            if score >= 4.0:
                return "aggressive" if AGGRESSIVE_ENABLED else "sandbox"
            return "log_only"
        elif mode == "gaming":
            return "log_only"
        else:  # balanced
            if score >= 6.0:
                return "sandbox"
            elif score >= 3.0:
                return "log_only"
            return "ignore"

class AIController:
    def __init__(self, sec: SecurityStack, game: GamingStack, hrisk: HighRiskStack, mode_mgr: ModeManager) -> None:
        self.sec = sec
        self.game = game
        self.hrisk = hrisk
        self.mode_mgr = mode_mgr
        self.running = False

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
                mode = "high_risk"
            elif sec_events > 50 and sec_events > 2 * game_events:
                mode = "security_priority"
            elif game_events > 50 and game_events > 2 * sec_events:
                mode = "gaming"
            else:
                mode = "balanced"

            current = self.mode_mgr.get_mode()
            if mode != current:
                self.mode_mgr.set_mode(mode)

# ============================================================
# STACKS / SUBSYSTEMS
# ============================================================

SEC_STACK = SecurityStack()
GAME_STACK = GamingStack()
HRISK_STACK = HighRiskStack()

SURICATA = SuricataIngestor(SEC_STACK)
PROC_MON = ProcessMonitor(HRISK_STACK)
MODE = ModeManager(SEC_STACK, GAME_STACK, HRISK_STACK)
AI = AIController(SEC_STACK, GAME_STACK, HRISK_STACK, MODE)

# ============================================================
# SUPERVISOR
# ============================================================

class Supervisor:
    def __init__(self) -> None:
        self.sec = SEC_STACK
        self.game = GAME_STACK
        self.hrisk = HRISK_STACK
        self.mode_mgr = MODE
        self.ai = AI
        self.suricata = SURICATA
        self.procmon = PROC_MON
        self.swarm = SWARM
        self.running = False

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        log("[SUP] Starting Codex Security Bridge v4.3.1 Hybrid Deception")
        self.mode_mgr.set_mode("balanced")
        self.ai.start()
        self.suricata.start()
        self.procmon.start()
        self.swarm.start()
        self.swarm.set_leader(True)
        DECEPTION.enable_service("smb")
        DECEPTION.enable_service("ldap")
        DECEPTION.enable_service("sql")
        log("[SUP] All subsystems started")

    def stop(self) -> None:
        if not self.running:
            return
        self.running = False
        log("[SUP] Stopping subsystems")
        self.ai.stop()
        self.suricata.stop()
        self.procmon.stop()
        self.swarm.stop()
        log("[SUP] All subsystems stopped")

    def handle_bridge(self, kind: str, payload: str, stack: str) -> Dict[str, Any]:
        stack = stack.upper()
        score = SCORER.score(kind, payload)
        action = self.mode_mgr.decide_action(score, stack)
        mode = self.mode_mgr.get_mode()

        if stack == "SEC":
            self.sec.handle(payload, kind, score, mode, action)
        elif stack == "GAME":
            self.game.handle(payload, kind, score, mode, action)
        else:
            self.hrisk.handle(payload, kind, score, mode, action)

        if action == "sandbox":
            SANDBOX.aggressive_stub(f"Sandboxed event: {payload}")
        elif action == "aggressive":
            SANDBOX.aggressive_stub(f"Aggressive response to: {payload}")

        return {"score": score, "action": action, "mode": mode}

    def handle_ai_text(self, text: str) -> float:
        score = SCORER.score("ai_text", text)
        self.sec.handle(text, "ai_text", score, self.mode_mgr.get_mode(), "ai_bridge")
        return score

    def handle_highrisk_detail(self, payload: str) -> None:
        score = SCORER.score("highrisk_detail", payload)
        mode = self.mode_mgr.get_mode()
        action = "log_only"
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
            if AGGRESSIVE_ENABLED and mode == "high_risk" and score >= 5.0:
                ag = SANDBOX.aggressive_stub(payload)
                action = ag
        self.hrisk.handle(payload, "highrisk_detail", score, mode, action)

    def generate_deception_snapshot(self) -> Dict[str, Any]:
        return DECEPTION.generate_snapshot()

    def get_status(self) -> Dict[str, Any]:
        sec = self.sec.get_status()
        game = self.game.get_status()
        hrisk = self.hrisk.get_status()
        return {
            "running": self.running,
            "mode": self.mode_mgr.get_mode(),
            "security": {"events": sec.events, "last_event": sec.last_event},
            "gaming": {"events": game.events, "last_event": game.last_event},
            "highrisk": {"events": hrisk.events, "last_event": hrisk.last_event},
            "services": DECEPTION.list_services(),
        }

SUPERVISOR = Supervisor()

# ============================================================
# HTTP BRIDGE
# ============================================================

class BridgeHandler(BaseHTTPRequestHandler):
    def _json_response(self, code: int, obj: Any) -> None:
        data = json.dumps(obj).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path.startswith("/status"):
            resp = SUPERVISOR.get_status()
            self._json_response(200, resp)
        elif self.path.startswith("/events"):
            limit = 50
            try:
                if "limit=" in self.path:
                    part = self.path.split("limit=", 1)[1]
                    limit = int(part.split("&", 1)[0])
            except Exception:
                pass
            resp = {
                "events": PERSIST.recent_events(limit),
                "deception": PERSIST.recent_deception(limit),
            }
            self._json_response(200, resp)
        elif self.path.startswith("/deception"):
            resp = SUPERVISOR.generate_deception_snapshot()
            self._json_response(200, resp)
        elif self.path.startswith("/ai"):
            self._json_response(200, {"mode": MODE.get_mode()})
        else:
            self._json_response(404, {"error": "unknown_endpoint"})

    def do_POST(self) -> None:
        length = int(self.headers.get("Content-Length", "0"))
        body = self.rfile.read(length).decode("utf-8") if length > 0 else ""
        try:
            data = json.loads(body) if body else {}
        except Exception:
            data = {}

        if self.path.startswith("/bridge"):
            kind = data.get("kind", "ai_text")
            payload = data.get("payload", "")
            stack = data.get("stack", "SEC")
            resp = SUPERVISOR.handle_bridge(kind, payload, stack)
            self._json_response(200, resp)

        elif self.path.startswith("/ai"):
            text = data.get("text", "")
            score = SUPERVISOR.handle_ai_text(text)
            self._json_response(200, {"score": score})

        elif self.path.startswith("/mode"):
            mode = data.get("mode", "balanced")
            MODE.set_mode(mode)
            self._json_response(200, {"mode": MODE.get_mode()})

        elif self.path.startswith("/peer"):
            self._json_response(200, {"status": "ok"})
        else:
            self._json_response(404, {"error": "unknown_endpoint"})

    def log_message(self, format: str, *args: Any) -> None:
        pass

# ============================================================
# MAIN DAEMON
# ============================================================

def main() -> None:
    log("[MAIN] Codex Security Bridge v4.3.1 hybrid deception starting")
    SUPERVISOR.start()

    server = HTTPServer(("0.0.0.0", 6000), BridgeHandler)
    log("[MAIN] HTTP bridge listening on 0.0.0.0:6000 (/bridge, /status, /ai, /events, /deception, /mode, /peer)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("[MAIN] KeyboardInterrupt, shutting down")
    finally:
        SUPERVISOR.stop()
        server.shutdown()
        log("[MAIN] Codex Security Bridge v4.3.1 stopped")

if __name__ == "__main__":
    main()
