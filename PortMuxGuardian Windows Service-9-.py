#!/usr/bin/env python3
# codex_security_bridge_v4_4_god_honeypot.py
# Headless AI security + deception daemon (v4.4 + God-Mode Honeypot v3):
# - Codex Security Bridge (SEC/GAME/HRISK stacks, Suricata, ML, sandbox, swarm, threat matrix)
# - Integrated God-Mode Honeypot v3 (multi-protocol honeypot + personas + ML/LLM + swarm + replay)
# - Unified HTTP bridge: /bridge, /status, /ai, /events, /deception, /mode, /peer, /matrix, /honeypot, /honeypot/replay

import sys
import subprocess
import importlib
import threading
import time
import json
import sqlite3
import os
import random
import socket
import uuid
import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer
from dataclasses import dataclass
from typing import Optional, Dict, Any, List, Tuple

# ============================================================
# PATHS / CONFIG
# ============================================================

BASE_DIR = os.path.join(os.path.expanduser("~"), "CodexSecurityBridgeV4_4_GodHoneypot")
DB_PATH = os.path.join(BASE_DIR, "codex_v4_4_god.db")
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

def log_event(component: str, level: str, message: str, extra: Optional[Dict[str, Any]] = None):
    ts = datetime.datetime.utcnow().isoformat()
    entry = {
        "ts": ts,
        "component": component,
        "level": level,
        "message": message,
        "extra": extra or {},
    }
    print(json.dumps(entry))

# ============================================================
# AUTOLOADER (safe)
# ============================================================

class Autoloader:
    def __init__(self) -> None:
        self.dependency_map: Dict[str, Dict[str, Any]] = {
            "network": {"modules": ["requests"], "install": True},
            "ml": {"modules": ["torch"], "install": True},
            "proc": {"modules": ["psutil"], "install": True},
            "pcap": {"modules": ["scapy"], "install": False},
            "sklearn": {"modules": ["sklearn"], "install": False},
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
for g in ("network", "ml", "proc", "pcap", "sklearn"):
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
                tactic TEXT,
                technique TEXT,
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
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_matrix (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                kind TEXT,
                signature TEXT,
                tactic TEXT,
                technique TEXT,
                score REAL,
                timestamp TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS honeypot_replay (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                text TEXT,
                timestamp TEXT
            )
        """)
        conn.commit()
        conn.close()
        log("[DB] Initialized codex_v4_4_god.db")

    def record_event(self, stack: str, kind: str, payload: str,
                     score: Optional[float], mode: str, action: str,
                     tactic: Optional[str], technique: Optional[str]) -> None:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO events (stack, kind, payload, score, mode, action, tactic, technique, timestamp)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, datetime('now'))
        """, (stack, kind, payload, score if score is not None else None,
              mode, action, tactic, technique))
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

    def record_matrix(self, kind: str, signature: str,
                      tactic: str, technique: str, score: float) -> None:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO threat_matrix (kind, signature, tactic, technique, score, timestamp)
            VALUES (?, ?, ?, ?, ?, datetime('now'))
        """, (kind, signature, tactic, technique, score))
        conn.commit()
        conn.close()

    def record_honeypot_replay(self, text: str) -> None:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            INSERT INTO honeypot_replay (text, timestamp)
            VALUES (?, datetime('now'))
        """, (text,))
        conn.commit()
        conn.close()

    def recent_events(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            SELECT stack, kind, payload, score, mode, action, tactic, technique, timestamp
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
                "tactic": r[6],
                "technique": r[7],
                "timestamp": r[8],
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

    def recent_matrix(self, limit: int = 50) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            SELECT kind, signature, tactic, technique, score, timestamp
            FROM threat_matrix ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        conn.close()
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append({
                "kind": r[0],
                "signature": r[1],
                "tactic": r[2],
                "technique": r[3],
                "score": r[4],
                "timestamp": r[5],
            })
        return out

    def recent_honeypot_replay(self, limit: int = 5) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.path)
        cur = conn.cursor()
        cur.execute("""
            SELECT text, timestamp
            FROM honeypot_replay ORDER BY id DESC LIMIT ?
        """, (limit,))
        rows = cur.fetchall()
        conn.close()
        out: List[Dict[str, Any]] = []
        for r in rows:
            out.append({"text": r[0], "timestamp": r[1]})
        return out

PERSIST = Persistence()

# ============================================================
# THREAT MATRIX (MITRE-style stub)
# ============================================================

class ThreatMatrix:
    def __init__(self) -> None:
        self.map = {
            "ET TROJAN": ("Execution", "T1204"),
            "ET EXPLOIT": ("Execution", "T1068"),
            "ET POLICY": ("Defense Evasion", "T1562"),
            "ET CNC": ("Command and Control", "T1071"),
            "ET SCAN": ("Discovery", "T1046"),
            "miner": ("Impact", "T1496"),
            "ransom": ("Impact", "T1486"),
            "phishing": ("Initial Access", "T1566"),
        }

    def classify(self, signature: str, payload: str) -> (Optional[str], Optional[str]):
        sig_upper = (signature or "").upper()
        text = (payload or "").lower()
        for key, (tactic, technique) in self.map.items():
            if key in sig_upper or key.lower() in text:
                return tactic, technique
        return None, None

MATRIX = ThreatMatrix()

# ============================================================
# GPU ML THREAT SCORING (Torch optional + richer heuristic)
# ============================================================

class ThreatScorer:
    def __init__(self) -> None:
        self.torch = AUTOLOADER.get("torch")
        self.model = None
        if self.torch:
            log("[ML] torch available (v4.4 dummy model)")
            self._init_model()
        else:
            log("[ML] torch not available, using heuristic scoring only")

    def _init_model(self) -> None:
        torch = self.torch

        class DummyModel(torch.nn.Module):
            def __init__(self):
                super().__init__()
                self.fc1 = torch.nn.Linear(32, 16)
                self.fc2 = torch.nn.Linear(16, 1)

            def forward(self, x):
                x = torch.relu(self.fc1(x))
                return self.fc2(x)

        self.model = DummyModel()
        self.model.eval()

    def _features(self, kind: str, payload: str) -> List[float]:
        text = payload.lower()
        bad_words = [
            "crack", "warez", "keygen", "malware", "trojan", "ransom",
            "exploit", "phishing", "c2", "backdoor", "miner", "cheat"
        ]
        length = len(text)
        bad_count = sum(1 for w in bad_words if w in text)
        has_exe = int("exe" in text or ".dll" in text or ".sys" in text)
        has_net = int("http" in text or "https" in text or "tcp" in text or "udp" in text)
        has_cred = int("password" in text or "pass=" in text or "token" in text or "key=" in text)
        kind_hash = sum(ord(c) for c in kind) % 256
        vec = [
            length % 512,
            bad_count,
            has_exe,
            has_net,
            has_cred,
            kind_hash,
        ]
        vec += [0.0] * (32 - len(vec))
        return vec

    def score(self, kind: str, payload: str) -> float:
        text = payload.lower()
        base = 0.0
        bad_words = [
            "crack", "warez", "keygen", "malware", "trojan", "ransom",
            "exploit", "phishing", "c2", "backdoor", "miner", "cheat"
        ]
        for w in bad_words:
            if w in text:
                base += 3.0
        if "exe" in text or ".dll" in text or ".sys" in text:
            base += 2.0
        if "download" in text or "http" in text or "https" in text:
            base += 1.5
        if "password" in text or "token" in text or "key=" in text:
            base += 2.5
        if kind in ("ai_text", "suricata", "process", "deception", "pcap", "honeypot"):
            base *= 1.3

        if self.model:
            feats = self._features(kind, payload)
            x = self.torch.tensor([feats], dtype=self.torch.float32)
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

    def handle(self, payload: str, kind: str, score: float,
               mode: str, action: str,
               tactic: Optional[str], technique: Optional[str]) -> None:
        with self.lock:
            self.status.events += 1
            self.status.last_event = payload
        log(f"[{self.label}] {payload} (score={score:.2f}, mode={mode}, action={action}, tactic={tactic}, technique={technique})")
        PERSIST.record_event(self.label, kind, payload, score, mode, action, tactic, technique)

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

SEC_STACK = SecurityStack()
GAME_STACK = GamingStack()
HRISK_STACK = HighRiskStack()

# ============================================================
# SURICATA v6 ENRICHED INGESTION
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
        log("[SURICATA] Ingestor started (eve.json, enriched)")

    def _parse_event(self, evt: Dict[str, Any]) -> Dict[str, Any]:
        alert = evt.get("alert", {})
        sig = alert.get("signature", "event")
        sig_id = alert.get("signature_id", 0)
        category = alert.get("category", "")
        src_ip = evt.get("src_ip", "")
        src_port = evt.get("src_port", "")
        dst_ip = evt.get("dest_ip", evt.get("dst_ip", ""))
        dst_port = evt.get("dest_port", evt.get("dst_port", ""))
        proto = evt.get("proto", "")
        http = evt.get("http", {})
        dns = evt.get("dns", {})
        tls = evt.get("tls", {})
        fileinfo = evt.get("fileinfo", {})

        payload_parts = [
            f"Suricata alert: {sig} (id={sig_id}, cat={category})",
            f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} proto={proto}",
        ]
        if http:
            payload_parts.append(f"HTTP {http.get('hostname','')} {http.get('url','')} {http.get('http_method','')}")
        if dns:
            payload_parts.append(f"DNS {dns.get('query_type','')} {dns.get('rrname','')}")
        if tls:
            payload_parts.append(f"TLS {tls.get('sni','')} {tls.get('subject','')}")
        if fileinfo:
            payload_parts.append(f"FILE {fileinfo.get('filename','')} size={fileinfo.get('size','')}")

        payload = " | ".join(p for p in payload_parts if p)
        return {
            "signature": sig,
            "signature_id": sig_id,
            "category": category,
            "payload": payload,
        }

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
                            parsed = self._parse_event(evt)
                            sig = parsed["signature"]
                            payload = parsed["payload"]
                            score = SCORER.score("suricata", payload)
                            tactic, technique = MATRIX.classify(sig, payload)
                            if tactic and technique:
                                PERSIST.record_matrix("suricata", sig, tactic, technique, score)
                            SEC_STACK.handle(payload, "suricata", score,
                                             "security_priority", "suricata_ingest",
                                             tactic, technique)
            except Exception as e:
                log(f"[SURICATA] Error: {e}")

    def stop(self) -> None:
        self.running = False
        log("[SURICATA] Ingestor stopped")

SURICATA = SuricataIngestor(SEC_STACK)

# ============================================================
# PACKET CAPTURE STUB
# ============================================================

class PacketCaptureStub:
    def __init__(self, sec_stack: SecurityStack) -> None:
        self.sec_stack = sec_stack
        self.running = False

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[PCAP] Packet capture stub started")

    def _loop(self) -> None:
        while self.running:
            time.sleep(15.0)
            payload = "PCAP stub: tcp 10.0.0.10:1234 -> 8.8.8.8:53 flags=SYN"
            score = SCORER.score("pcap", payload)
            tactic, technique = MATRIX.classify("", payload)
            SEC_STACK.handle(payload, "pcap", score,
                             "balanced", "pcap_stub",
                             tactic, technique)

    def stop(self) -> None:
        self.running = False
        log("[PCAP] Packet capture stub stopped")

PCAP_STUB = PacketCaptureStub(SEC_STACK)

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
                    if any(bad in name for bad in ("miner", "hack", "crack", "keygen", "cheat", "ransom")):
                        payload = f"Suspicious process: pid={p.info.get('pid')} name={p.info.get('name')} user={p.info.get('username')} exe={p.info.get('exe')}"
                        score = SCORER.score("process", payload)
                        tactic, technique = MATRIX.classify("miner", payload)
                        HRISK_STACK.handle(payload, "process", score,
                                           "high_risk", "proc_monitor",
                                           tactic, technique)
                time.sleep(10.0)
            except Exception as e:
                log(f"[PROC] Error: {e}")
                time.sleep(10.0)

    def stop(self) -> None:
        self.running = False
        log("[PROC] Process monitor stopped")

PROC_MON = ProcessMonitor(HRISK_STACK)

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
# DECEPTION ENGINE (Codex)
# ============================================================

class DeceptionEngine:
    def __init__(self) -> None:
        self.lock = threading.Lock()
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

    def list_services(self) -> Dict[str, bool]:
        with self.lock:
            return dict(self.fake_services)

    def generate_snapshot(self) -> Dict[str, Any]:
        snap = {"services": self.list_services()}
        self._record("snapshot", snap)
        return snap

DECEPTION = DeceptionEngine()

# ============================================================
# SWARM / PEER SYNC v2 (Codex)
# ============================================================

class SwarmSync:
    def __init__(self) -> None:
        self.requests = AUTOLOADER.get("requests")
        self.leader = False
        self.running = False
        self.node_id = os.getenv("COMPUTERNAME", "codex-node")

    def start(self) -> None:
        if self.running or not self.requests:
            if not self.requests:
                log("[SWARM] requests not available, swarm disabled")
            return
        self.running = True
        threading.Thread(target=self._loop, daemon=True).start()
        log("[SWARM] Swarm sync v2 started")

    def _loop(self) -> None:
        while self.running:
            try:
                for peer in PEERS:
                    payload = {
                        "node": self.node_id,
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
# MODES / AI CONTROLLER
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
        else:
            if score >= 6.0:
                return "sandbox"
            elif score >= 3.0:
                return "log_only"
            return "ignore"

class AIController:
    def __init__(self, sec: SecurityStack, game: GamingStack,
                 hrisk: HighRiskStack, mode_mgr: ModeManager) -> None:
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

MODE = ModeManager(SEC_STACK, GAME_STACK, HRISK_STACK)
AI = AIController(SEC_STACK, GAME_STACK, HRISK_STACK, MODE)

# ============================================================
# GOD-MODE HONEYPOT v3 (INTEGRATED)
# ============================================================

class Config:
    VERSION = "god-honeypot-v3"
    NODE_ID = str(uuid.uuid4())
    SWARM_CLUSTER_ID = "swarm-godnet"
    LISTEN_HOST = "0.0.0.0"
    RANDOM_PORT_RANGE = (20000, 60000)
    PERSONA_COUNT = 50
    ACTIVITY_INTERVAL_RANGE = (5, 60)
    LOG_DIR = os.path.join(BASE_DIR, "honeypot_logs")
    REPLAY_DIR = os.path.join(BASE_DIR, "honeypot_replay")
    FORENSIC_DIR = os.path.join(BASE_DIR, "honeypot_forensics")
    STATE_FILE = os.path.join(BASE_DIR, "honeypot_state.json")
    SURICATA_EVE_FILE = SURICATA_EVE
    SURICATA_PCAP_DIR = os.path.join(BASE_DIR, "suricata_pcap")
    SURICATA_RULES_FILE = os.path.join(BASE_DIR, "suricata_rules.json")
    GUI_ENABLED = False
    LLM_LOCAL_MODEL_PATH = os.path.join(BASE_DIR, "models/local_llm_stub")
    LLM_REMOTE_ENDPOINT = "https://llm-remote-api.example.com/analyze"
    SWARM_PEERS = [("127.0.0.1", 48001), ("127.0.0.1", 48002)]
    SWARM_GOSSIP_PORT = 47000

def ensure_dirs():
    for d in [Config.LOG_DIR, Config.REPLAY_DIR, Config.FORENSIC_DIR,
              Config.SURICATA_PCAP_DIR, os.path.dirname(Config.SURICATA_EVE_FILE),
              os.path.dirname(Config.SURICATA_RULES_FILE)]:
        if d:
            os.makedirs(d, exist_ok=True)

def random_port() -> int:
    return random.randint(*Config.RANDOM_PORT_RANGE)

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
        for i in range(100):
            path = f"/fakecorp/docs/doc_{i}.txt"
            content = f"Confidential document {i} - salary, HR, finance, secrets..."
            self.vfs.add_file(path, content)

        for i in range(50):
            user = f"user{i}"
            pwd = random.choice(["Password123", "Summer2025!", "qwerty", "letmein", "Admin!234"])
            self.credentials[user] = pwd

        self.cloud_metadata = {
            "instance-id": "i-fake123456",
            "region": "us-fake-1",
            "project": "fakecorp-god-honeypot",
        }

        self.sql_databases["hr_db"] = {
            "employees": [{"id": i, "name": f"Employee{i}", "salary": random.randint(50000, 150000)}
                          for i in range(50)]
        }

        self.smb_shares["HR$"] = ["/fakecorp/docs/hr_payroll.xlsx"]
        self.smb_shares["FINANCE$"] = ["/fakecorp/docs/fin_budget.xlsx"]

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
                for i in range(10)]
        self.k8s_objects = {
            "deployments": deployments,
            "services": services,
            "pods": pods,
        }

        self.ad_domain = {
            "name": "FAKECORP.LOCAL",
            "users": [f"user{i}" for i in range(50)],
            "groups": ["Domain Admins", "HR", "Finance", "IT", "DevOps", "Security", "Management"],
        }

        for i in range(20):
            self.kernel_logs.append(f"{datetime.datetime.utcnow().isoformat()} kernel: event {i} - fake syscall")

        for pid in range(1000, 1010):
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
            return "\n".join(self.datastore.kernel_logs[:50])
        elif c == "history":
            return "\n".join(self.history)
        else:
            return f"Command '{cmd}' not implemented in fake shell."

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

class MLEngine:
    def __init__(self):
        self.iforest = None
        self.dbscan = None
        self.autoencoder = None
        self.scaler = None
        self.trained = False

    def train_models(self, samples: List[Dict[str, Any]]):
        try:
            from sklearn.ensemble import IsolationForest
            from sklearn.cluster import DBSCAN
            from sklearn.preprocessing import StandardScaler
            from sklearn.neural_network import MLPRegressor
        except ImportError:
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

class LLMEngine:
    def __init__(self, local_model_path: str, remote_endpoint: str):
        self.local_model_path = local_model_path
        self.remote_endpoint = remote_endpoint
        self.local_loaded = False
        self.requests = AUTOLOADER.get("requests")

    def load_local_model(self):
        if os.path.exists(self.local_model_path):
            self.local_loaded = True
        else:
            self.local_loaded = False
        log_event("llm", "INFO", f"Local LLM load status: {self.local_loaded}", {})

    def _remote_call(self, payload: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        if self.requests is None:
            return None
        try:
            resp = self.requests.post(self.remote_endpoint, json=payload, timeout=3)
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
                PERSIST.record_honeypot_replay(replay_text)
                log_event("core", "INFO", "Attacker replay snapshot", {"preview": replay_text[:200]})
                self.swarm.enforce_policy({"rogue_processes": list(self.rogue_detector.rogue_processes.keys())})
                time.sleep(30)
        except KeyboardInterrupt:
            log_event("core", "INFO", "KeyboardInterrupt received, stopping honeypot", {})
        finally:
            self.stop_event.set()
            self.save_state()
            log_event("core", "INFO", "Honeypot stopped", {})

HONEYPOT = HoneypotCore()

# ============================================================
# SUPERVISOR (Codex + Honeypot)
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
        self.pcap = PCAP_STUB
        self.honeypot = HONEYPOT
        self.running = False

    def start(self) -> None:
        if self.running:
            return
        self.running = True
        log("[SUP] Starting Codex Security Bridge v4.4 + God-Mode Honeypot v3")
        self.mode_mgr.set_mode("balanced")
        self.ai.start()
        self.suricata.start()
        self.procmon.start()
        self.pcap.start()
        self.swarm.start()
        self.swarm.set_leader(True)
        DECEPTION.enable_service("smb")
        DECEPTION.enable_service("ldap")
        DECEPTION.enable_service("sql")
        self.honeypot.start_protocols()
        self.honeypot.start_ml_llm()
        self.honeypot.start_swarm()
        self.honeypot.start_background_loops()
        threading.Thread(target=self.honeypot.main_loop, daemon=True).start()
        log("[SUP] All subsystems started")

    def stop(self) -> None:
        if not self.running:
            return
        self.running = False
        log("[SUP] Stopping subsystems")
        self.ai.stop()
        self.suricata.stop()
        self.procmon.stop()
        self.pcap.stop()
        self.swarm.stop()
        self.honeypot.stop_event.set()
        log("[SUP] All subsystems stopped")

    def handle_bridge(self, kind: str, payload: str, stack: str) -> Dict[str, Any]:
        stack = stack.upper()
        score = SCORER.score(kind, payload)
        action = self.mode_mgr.decide_action(score, stack)
        mode = self.mode_mgr.get_mode()
        tactic, technique = MATRIX.classify("", payload)

        if stack == "SEC":
            self.sec.handle(payload, kind, score, mode, action, tactic, technique)
        elif stack == "GAME":
            self.game.handle(payload, kind, score, mode, action, tactic, technique)
        else:
            self.hrisk.handle(payload, kind, score, mode, action, tactic, technique)

        if action == "sandbox":
            SANDBOX.aggressive_stub(f"Sandboxed event: {payload}")
        elif action == "aggressive":
            SANDBOX.aggressive_stub(f"Aggressive response to: {payload}")

        return {"score": score, "action": action, "mode": mode, "tactic": tactic, "technique": technique}

    def handle_ai_text(self, text: str) -> float:
        score = SCORER.score("ai_text", text)
        tactic, technique = MATRIX.classify("", text)
        self.sec.handle(text, "ai_text", score, self.mode_mgr.get_mode(), "ai_bridge", tactic, technique)
        return score

    def handle_highrisk_detail(self, payload: str) -> None:
        score = SCORER.score("highrisk_detail", payload)
        mode = self.mode_mgr.get_mode()
        tactic, technique = MATRIX.classify("", payload)
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
        self.hrisk.handle(payload, "highrisk_detail", score, mode, action, tactic, technique)

    def generate_deception_snapshot(self) -> Dict[str, Any]:
        codex_snap = DECEPTION.generate_snapshot()
        honeypot_snap = {
            "personas": len(self.honeypot.persona_engine.personas),
            "topology_version": self.honeypot.chaos.current_topology_version,
        }
        return {"codex": codex_snap, "honeypot": honeypot_snap}

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
            "honeypot": {
                "personas": len(self.honeypot.persona_engine.personas),
                "topology_version": self.honeypot.chaos.current_topology_version,
            },
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
        elif self.path.startswith("/matrix"):
            limit = 50
            try:
                if "limit=" in self.path:
                    part = self.path.split("limit=", 1)[1]
                    limit = int(part.split("&", 1)[0])
            except Exception:
                pass
            resp = {"matrix": PERSIST.recent_matrix(limit)}
            self._json_response(200, resp)
        elif self.path.startswith("/honeypot"):
            if self.path.startswith("/honeypot/replay"):
                resp = {"replay": PERSIST.recent_honeypot_replay(5)}
            else:
                resp = {
                    "personas": len(HONEYPOT.persona_engine.personas),
                    "topology_version": HONEYPOT.chaos.current_topology_version,
                }
            self._json_response(200, resp)
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
    log("[MAIN] Codex Security Bridge v4.4 + God-Mode Honeypot v3 starting")
    SUPERVISOR.start()

    server = HTTPServer(("0.0.0.0", 6000), BridgeHandler)
    log("[MAIN] HTTP bridge listening on 0.0.0.0:6000 (/bridge, /status, /ai, /events, /deception, /mode, /peer, /matrix, /honeypot, /honeypot/replay)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        log("[MAIN] KeyboardInterrupt, shutting down")
    finally:
        SUPERVISOR.stop()
        server.shutdown()
        log("[MAIN] Codex Security Bridge v4.4 + God-Mode Honeypot v3 stopped")

if __name__ == "__main__":
    main()
