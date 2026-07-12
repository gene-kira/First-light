#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BORG OS v27.1 – FULL STACKING ORGANISM
(Q-Learning + Anomaly Detection + Secure Distributed Mesh Cluster)

Upgrades over v27:
- Replaced ASK popup with 5-day investigation mode
- Investigation table in SQLite with threat/safe hits
- Auto-allow after 5 days if no threat detected
- Auto-kill if threat detected during investigation
- Always allow System Idle Process (pid 0) and Idle/system idle names
"""

import sys
import os
import platform
import time
import random
import threading
import sqlite3
import socket
import math
import json
import glob
import hashlib
import hmac

OS_NAME = platform.system().lower()

FASTAPI_AVAILABLE = False
TK_AVAILABLE = False
HTTPX_AVAILABLE = False
CRYPTO_AVAILABLE = False
PSUTIL_AVAILABLE = False

try:
    from fastapi import FastAPI
    from pydantic import BaseModel
    import uvicorn
    FASTAPI_AVAILABLE = True
except Exception:
    FASTAPI_AVAILABLE = False

try:
    import tkinter as tk
    from tkinter import ttk, messagebox
    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False

try:
    import httpx
    HTTPX_AVAILABLE = True
except Exception:
    HTTPX_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    PSUTIL_AVAILABLE = False

PYNVML_AVAILABLE = False
try:
    import pynvml
    pynvml.nvmlInit()
    PYNVML_AVAILABLE = True
except Exception:
    PYNVML_AVAILABLE = False

NPU_AVAILABLE = False
try:
    NPU_AVAILABLE = False
except Exception:
    NPU_AVAILABLE = False

from enum import Enum, auto

KILL_MODE = "ASK"      # OFF / ASK / AUTO
MESH_ENABLED = False
DEV_MODE = False

INTEL_CONFIG_PATH = "borg_intel_config.json"
DB_PATH = "borg_memory.db"

SAFE_CORE_PROCESSES = {
    "System", "Idle", "explorer.exe", "wininit.exe",
    "services.exe", "lsass.exe", "csrss.exe",
    "smss.exe", "winlogon.exe", "svchost.exe",
    "dwm.exe", "ShellExperienceHost.exe", "StartMenuExperienceHost.exe",
    "SearchUI.exe", "MicrosoftEdge.exe", "msedge.exe",
    "SecurityHealthService.exe", "MsMpEng.exe",
}

SAFE_SECURITY_TOOLS = {
    "avp.exe", "ekrn.exe", "kaspersky", "eset", "norton", "mcshield.exe",
    "procmon.exe", "procexp.exe", "wireshark.exe",
}

SAFE_GAMING_PROCESSES = {
    "steam.exe", "Steam.exe",
    "EpicGamesLauncher.exe", "epicgameslauncher.exe",
    "Battle.net.exe", "battle.net.exe",
    "Origin.exe", "origin.exe",
    "RiotClientServices.exe", "riotclientservices.exe",
    "valorant.exe", "VALORANT.exe",
    "cs2.exe", "CS2.exe",
    "csgo.exe", "CSGO.exe",
    "fortnite.exe", "Fortnite.exe",
    "warzone.exe", "Warzone.exe",
    "eldenring.exe", "EldenRing.exe",
    "GTA5.exe", "gta5.exe",
    "LeagueClient.exe", "leagueclient.exe",
    "Overwatch.exe", "overwatch.exe",
}

class BorgState(Enum):
    DOMINANT   = auto()
    SUPPRESSED = auto()
    FLAGGED    = auto()
    TRANSITION = auto()
    BORG_CORE  = auto()

class BorgPersona(Enum):
    AGGRESSIVE = auto()
    DEFENSIVE  = auto()
    PASSIVE    = auto()

class BorgCell:
    def __init__(self, state=BorgState.SUPPRESSED):
        self.state = state

class BorgMemoryOrgan:
    def __init__(self, size):
        self.cells = [BorgCell() for _ in range(size)]

    def __len__(self):
        return len(self.cells)

class MemoryStack:
    def __init__(self, size_short=10, size_mid=10, size_long=10, size_threat=10, size_behavior=10):
        self.short_term   = BorgMemoryOrgan(size_short)
        self.mid_term     = BorgMemoryOrgan(size_mid)
        self.long_term    = BorgMemoryOrgan(size_long)
        self.threat_mem   = BorgMemoryOrgan(size_threat)
        self.behavior_mem = BorgMemoryOrgan(size_behavior)

    def organs(self):
        return [
            self.short_term,
            self.mid_term,
            self.long_term,
            self.threat_mem,
            self.behavior_mem,
        ]

class BorgLogicEngine:
    def __init__(self, organ: BorgMemoryOrgan):
        self.organ = organ

    def autonomous_step(self):
        try:
            for cell in self.organ.cells:
                s = cell.state
                if s == BorgState.TRANSITION:
                    cell.state = BorgState.FLAGGED
                elif s == BorgState.FLAGGED:
                    if random.random() < 0.10:
                        cell.state = BorgState.SUPPRESSED

            new_states = [cell.state for cell in self.organ.cells]
            for i, cell in enumerate(self.organ.cells):
                left  = self.organ.cells[i-1].state if i > 0 else None
                right = self.organ.cells[i+1].state if i < len(self.organ.cells)-1 else None
                if cell.state == BorgState.SUPPRESSED:
                    if left == BorgState.DOMINANT or right == BorgState.DOMINANT:
                        new_states[i] = BorgState.TRANSITION
            for i, s in enumerate(new_states):
                self.organ.cells[i].state = s

            for cell in self.organ.cells:
                r = random.random()
                if r < 0.02:
                    cell.state = BorgState.DOMINANT
                elif r < 0.04:
                    cell.state = BorgState.SUPPRESSED
        except Exception:
            pass

class BorgEventBus:
    def __init__(self, logger=None, storage=None):
        self.logger = logger or (lambda msg: None)
        self.storage = storage

    def emit(self, kind, detail, reason=""):
        try:
            msg = f"[EVENT] {kind}: {detail} ({reason})"
            self.logger(msg)
            if self.storage:
                self.storage.log_event(kind, detail, reason)
        except Exception:
            pass

class BorgStorage:
    def __init__(self, path=DB_PATH):
        self.path = path
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._init_schema()
        self._migrate_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_cells (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            organ TEXT NOT NULL,
            idx INTEGER NOT NULL,
            state TEXT NOT NULL,
            tick INTEGER NOT NULL,
            ts REAL NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            detail TEXT NOT NULL,
            ts REAL NOT NULL,
            reason TEXT DEFAULT ''
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_safe_processes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL UNIQUE,
            first_seen REAL NOT NULL,
            last_seen REAL NOT NULL,
            samples INTEGER NOT NULL,
            reputation REAL NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_mesh_intel (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            kind TEXT NOT NULL,
            payload TEXT NOT NULL,
            ts REAL NOT NULL,
            signature TEXT NOT NULL,
            peer_id TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_mesh_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            vote TEXT NOT NULL,
            weight REAL NOT NULL,
            ts REAL NOT NULL,
            peer_id TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_games (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            exe_path TEXT NOT NULL,
            name TEXT NOT NULL,
            ts REAL NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_settings (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_qtable (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            agent TEXT NOT NULL,
            state TEXT NOT NULL,
            action TEXT NOT NULL,
            value REAL NOT NULL
        )
        """)
        # Investigation table
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_investigation (
            pid INTEGER PRIMARY KEY,
            name TEXT,
            start_ts REAL,
            last_seen REAL,
            threat_hits INTEGER DEFAULT 0,
            safe_hits INTEGER DEFAULT 0
        )
        """)
        self.conn.commit()

    def _migrate_schema(self):
        cur = self.conn.cursor()
        cur.execute("PRAGMA table_info(borg_events)")
        cols = [row[1] for row in cur.fetchall()]
        if "reason" not in cols:
            cur.execute("ALTER TABLE borg_events ADD COLUMN reason TEXT DEFAULT ''")
            self.conn.commit()
        self.conn.commit()

    def get_setting(self, key, default=None):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT value FROM borg_settings WHERE key = ?", (key,))
            row = cur.fetchone()
            if row:
                return row[0]
            return default
        except Exception:
            return default

    def set_setting(self, key, value):
        try:
            cur = self.conn.cursor()
            cur.execute("INSERT OR REPLACE INTO borg_settings (key, value) VALUES (?, ?)", (key, str(value)))
            self.conn.commit()
        except Exception:
            pass

    def save_states(self, organ_name, states, tick):
        try:
            cur = self.conn.cursor()
            ts = time.time()
            for i, s in enumerate(states):
                cur.execute(
                    "INSERT INTO borg_cells (organ, idx, state, tick, ts) VALUES (?, ?, ?, ?, ?)",
                    (organ_name, i, s.name, tick, ts)
                )
            self.conn.commit()
        except Exception:
            pass

    def log_event(self, kind, detail, reason=""):
        try:
            cur = self.conn.cursor()
            ts = time.time()
            cur.execute(
                "INSERT INTO borg_events (kind, detail, ts, reason) VALUES (?, ?, ?, ?)",
                (kind, detail, ts, reason)
            )
            self.conn.commit()
        except Exception:
            pass

    def update_safe_process(self, name, delta_rep=1.0):
        try:
            cur = self.conn.cursor()
            ts = time.time()
            cur.execute("SELECT id, samples, reputation FROM borg_safe_processes WHERE name = ?", (name,))
            row = cur.fetchone()
            if row:
                pid, samples, rep = row
                new_rep = max(0.0, rep + delta_rep)
                cur.execute(
                    "UPDATE borg_safe_processes SET last_seen = ?, samples = ?, reputation = ? WHERE id = ?",
                    (ts, samples + 1, new_rep, pid)
                )
            else:
                cur.execute(
                    "INSERT INTO borg_safe_processes (name, first_seen, last_seen, samples, reputation) VALUES (?, ?, ?, ?, ?)",
                    (name, ts, ts, 1, max(0.0, delta_rep))
                )
            self.conn.commit()
        except Exception:
            pass

    def decay_reputation(self, factor=0.99):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT id, reputation FROM borg_safe_processes")
            rows = cur.fetchall()
            for pid, rep in rows:
                new_rep = rep * factor
                cur.execute("UPDATE borg_safe_processes SET reputation = ? WHERE id = ?", (new_rep, pid))
            self.conn.commit()
        except Exception:
            pass

    def load_safe_processes(self):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT name, samples, reputation FROM borg_safe_processes")
            rows = cur.fetchall()
            safe = {}
            for name, samples, rep in rows:
                safe[name] = (samples, rep)
            return safe
        except Exception:
            return {}

    def store_mesh_intel(self, kind, payload, signature, peer_id):
        try:
            cur = self.conn.cursor()
            ts = time.time()
            cur.execute(
                "INSERT INTO borg_mesh_intel (kind, payload, ts, signature, peer_id) VALUES (?, ?, ?, ?, ?)",
                (kind, payload, ts, signature, peer_id)
            )
            self.conn.commit()
        except Exception:
            pass

    def load_mesh_intel(self, kind=None):
        try:
            cur = self.conn.cursor()
            if kind:
                cur.execute("SELECT payload, signature, peer_id FROM borg_mesh_intel WHERE kind = ?", (kind,))
            else:
                cur.execute("SELECT payload, signature, peer_id FROM borg_mesh_intel")
            rows = cur.fetchall()
            return rows
        except Exception:
            return []

    def store_mesh_vote(self, subject, vote, weight, peer_id):
        try:
            cur = self.conn.cursor()
            ts = time.time()
            cur.execute(
                "INSERT INTO borg_mesh_votes (subject, vote, weight, ts, peer_id) VALUES (?, ?, ?, ?, ?)",
                (subject, vote, weight, ts, peer_id)
            )
            self.conn.commit()
        except Exception:
            pass

    def load_mesh_votes(self, subject):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT vote, weight, peer_id FROM borg_mesh_votes WHERE subject = ?", (subject,))
            rows = cur.fetchall()
            return rows
        except Exception:
            return []

    def store_game(self, exe_path, name):
        try:
            cur = self.conn.cursor()
            ts = time.time()
            cur.execute(
                "INSERT INTO borg_games (exe_path, name, ts) VALUES (?, ?, ?)",
                (exe_path, name, ts)
            )
            self.conn.commit()
        except Exception:
            pass

    def load_games(self):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT exe_path, name FROM borg_games")
            rows = cur.fetchall()
            return rows
        except Exception:
            return []

    def load_qtable(self, agent_name):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT state, action, value FROM borg_qtable WHERE agent = ?", (agent_name,))
            rows = cur.fetchall()
            table = {}
            for state, action, value in rows:
                table.setdefault(state, {})[action] = value
            return table
        except Exception:
            return {}

    def save_qtable(self, agent_name, table):
        try:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM borg_qtable WHERE agent = ?", (agent_name,))
            for state, actions in table.items():
                for action, value in actions.items():
                    cur.execute(
                        "INSERT INTO borg_qtable (agent, state, action, value) VALUES (?, ?, ?, ?)",
                        (agent_name, state, action, float(value))
                    )
            self.conn.commit()
        except Exception:
            pass

    # Investigation helpers
    def start_investigation(self, pid, name):
        try:
            ts = time.time()
            cur = self.conn.cursor()
            cur.execute(
                "INSERT OR REPLACE INTO borg_investigation (pid, name, start_ts, last_seen, threat_hits, safe_hits) "
                "VALUES (?, ?, ?, ?, COALESCE((SELECT threat_hits FROM borg_investigation WHERE pid=?),0), "
                "COALESCE((SELECT safe_hits FROM borg_investigation WHERE pid=?),0))",
                (pid, name, ts, ts, pid, pid)
            )
            self.conn.commit()
        except Exception:
            pass

    def update_investigation(self, pid, threat=False):
        try:
            ts = time.time()
            cur = self.conn.cursor()
            if threat:
                cur.execute(
                    "UPDATE borg_investigation SET last_seen=?, threat_hits=threat_hits+1 WHERE pid=?",
                    (ts, pid)
                )
            else:
                cur.execute(
                    "UPDATE borg_investigation SET last_seen=?, safe_hits=safe_hits+1 WHERE pid=?",
                    (ts, pid)
                )
            self.conn.commit()
        except Exception:
            pass

    def get_investigation(self, pid):
        try:
            cur = self.conn.cursor()
            cur.execute(
                "SELECT pid, name, start_ts, last_seen, threat_hits, safe_hits FROM borg_investigation WHERE pid=?",
                (pid,)
            )
            return cur.fetchone()
        except Exception:
            return None

    def end_investigation(self, pid):
        try:
            cur = self.conn.cursor()
            cur.execute("DELETE FROM borg_investigation WHERE pid=?", (pid,))
            self.conn.commit()
        except Exception:
            pass

if CRYPTO_AVAILABLE:
    SHARED_KEY = Fernet.generate_key()
    CIPHER = Fernet(SHARED_KEY)
else:
    SHARED_KEY = b"borg_shared_key_v27"
    CIPHER = None

MESH_SECRET = b"borg_mesh_secret_v27"
LOCAL_PEER_ID = "NODE-" + hashlib.sha256(platform.node().encode("utf-8")).hexdigest()[:12]

def encrypt_payload(payload: dict) -> str:
    raw = json.dumps(payload).encode("utf-8")
    if CIPHER:
        return CIPHER.encrypt(raw).decode("utf-8")
    return raw.hex()

def decrypt_payload(token: str) -> dict:
    try:
        if CIPHER:
            raw = CIPHER.decrypt(token.encode("utf-8"))
        else:
            raw = bytes.fromhex(token)
        return json.loads(raw.decode("utf-8"))
    except Exception:
        return {}

def sign_payload(payload: dict) -> str:
    raw = json.dumps(payload, sort_keys=True).encode("utf-8")
    return hmac.new(MESH_SECRET, raw, hashlib.sha256).hexdigest()

def verify_payload(payload: dict, signature: str) -> bool:
    expected = sign_payload(payload)
    return hmac.compare_digest(expected, signature)

class ThreatSignatureEngine:
    def __init__(self):
        self.signatures = [
            ("HIGH_CPU_MEM", lambda cpu, mem, io_r, io_w, net: cpu > 95.0 and mem > 90.0),
            ("HEAVY_IO", lambda cpu, mem, io_r, io_w, net: io_r > 200 * 1024 * 1024 or io_w > 100 * 1024 * 1024),
            ("HEAVY_NET", lambda cpu, mem, io_r, io_w, net: net > 100 * 1024 * 1024),
        ]

    def match(self, cpu, mem, io_read, io_write, net_bytes):
        matched = []
        for name, fn in self.signatures:
            try:
                if fn(cpu, mem, io_read, io_write, net_bytes):
                    matched.append(name)
            except Exception:
                continue
        return matched

class AnomalyDetector:
    def __init__(self, logger=None):
        self.logger = logger or (lambda msg: None)
        self.baselines = {}
        self.max_samples = 200

    def _update_series(self, series, value):
        series.append(value)
        if len(series) > self.max_samples:
            series.pop(0)

    def observe(self, name, cpu, mem, io_read, io_write, net_bytes):
        if not name:
            return
        b = self.baselines.setdefault(name, {
            "cpu": [], "mem": [], "io": [], "net": []
        })
        self._update_series(b["cpu"], cpu)
        self._update_series(b["mem"], mem)
        self._update_series(b["io"], io_read + io_write)
        self._update_series(b["net"], net_bytes)

    def _zscore(self, series, value):
        if len(series) < 20:
            return 0.0
        mean = sum(series) / len(series)
        var = sum((x - mean) ** 2 for x in series) / len(series)
        std = math.sqrt(var) if var > 0 else 1.0
        return (value - mean) / std

    def is_anomalous(self, name, cpu, mem, io_read, io_write, net_bytes):
        if name not in self.baselines:
            return False, {}
        b = self.baselines[name]
        z_cpu = self._zscore(b["cpu"], cpu)
        z_mem = self._zscore(b["mem"], mem)
        z_io  = self._zscore(b["io"], io_read + io_write)
        z_net = self._zscore(b["net"], net_bytes)

        flags = {}
        if abs(z_cpu) > 3.0:
            flags["cpu"] = z_cpu
        if abs(z_mem) > 3.0:
            flags["mem"] = z_mem
        if abs(z_io) > 3.0:
            flags["io"] = z_io
        if abs(z_net) > 3.0:
            flags["net"] = z_net

        if flags:
            msg = f"Anomaly for {name}: {flags}"
            self.logger(f"[ANOMALY] {msg}")
            return True, flags
        return False, {}

class ProcessReputation:
    def __init__(self, storage: BorgStorage | None = None):
        self.storage = storage
        self.safe_names = set(SAFE_CORE_PROCESSES) | set(SAFE_GAMING_PROCESSES)
        self.suspicious_patterns = [
            "miner", "crypto", "bot", "rat", "hack", "inject", "cheat", "keylog", "steal"
        ]
        self.learned_safe = {}
        if self.storage:
            self.learned_safe = self.storage.load_safe_processes()
        self.sig_engine = ThreatSignatureEngine()

    def is_hard_protected(self, name):
        if not name:
            return False
        if name in self.safe_names:
            return True
        n = name.lower()
        protected_keywords = [
            "steam", "epic",
            "teams", "copilot", "microsoft",
            "chrome", "edge", "firefox", "brave", "opera",
            "game", "games", "launcher", "client", "battle.net", "riot", "origin"
        ]
        if any(k in n for k in protected_keywords):
            return True
        if any(sec in n for sec in SAFE_SECURITY_TOOLS):
            return True
        return False

    def is_learned_safe(self, name):
        if not name:
            return False
        if name not in self.learned_safe:
            return False
        samples, rep = self.learned_safe[name]
        return samples >= 5 and rep >= 3.0

    def observe_safe(self, name, cpu, mem):
        if not name or not self.storage:
            return
        delta = 1.0
        if cpu < 10.0 and mem < 5.0:
            delta = 1.5
        self.storage.update_safe_process(name, delta_rep=delta)
        self.learned_safe = self.storage.load_safe_processes()

    def observe_suspicious(self, name):
        if not name or not self.storage:
            return
        self.storage.update_safe_process(name, delta_rep=-2.0)
        self.learned_safe = self.storage.load_safe_processes()

    def decay(self):
        if self.storage:
            self.storage.decay_reputation()
            self.learned_safe = self.storage.load_safe_processes()

    def score(self, name, cpu, mem, io_read, io_write, net_bytes, anomaly_flags):
        name_l = (name or "").lower()
        score = 0.0

        if self.is_hard_protected(name):
            score -= 200.0

        if self.is_learned_safe(name):
            score -= 120.0

        for pat in self.suspicious_patterns:
            if pat in name_l:
                score += 80.0

        score += cpu * 0.8
        score += mem * 0.8

        if io_read > 100 * 1024 * 1024:
            score += 35.0
        if io_write > 50 * 1024 * 1024:
            score += 35.0

        if net_bytes > 50 * 1024 * 1024:
            score += 45.0

        sigs = self.sig_engine.match(cpu, mem, io_read, io_write, net_bytes)
        if sigs:
            score += 60.0

        if anomaly_flags:
            score += 40.0

        return score, sigs

class GameScanner:
    def __init__(self, storage: BorgStorage, logger=None):
        self.storage = storage
        self.logger = logger or (lambda msg: None)
        self.detected_games = set()
        self.steam_paths = [
            os.path.expandvars(r"%ProgramFiles(x86)%\Steam\steamapps"),
            os.path.expandvars(r"%ProgramFiles%\Steam\steamapps"),
            os.path.expandvars(r"%LocalAppData%\Steam\steamapps"),
        ]
        self.epic_manifest = os.path.expandvars(
            r"%ProgramData%\Epic\EpicGamesLauncher\Data\Manifests"
        )
        self.last_steam_manifest_mtime = 0.0
        self.last_epic_manifest_mtime = 0.0

    def _existing_game_paths(self):
        rows = self.storage.load_games()
        return {exe for exe, _ in rows}

    def _update_manifest_times(self):
        try:
            steam_mtime = 0.0
            for base in self.steam_paths:
                if os.path.exists(base):
                    for acf in glob.glob(os.path.join(base, "*.acf")):
                        m = os.path.getmtime(acf)
                        if m > steam_mtime:
                            steam_mtime = m
            self.last_steam_manifest_mtime = steam_mtime
        except Exception:
            pass

        try:
            epic_mtime = 0.0
            if os.path.exists(self.epic_manifest):
                for item in glob.glob(os.path.join(self.epic_manifest, "*.item")):
                    m = os.path.getmtime(item)
                    if m > epic_mtime:
                        epic_mtime = m
            self.last_epic_manifest_mtime = epic_mtime
        except Exception:
            pass

    def full_scan_once(self):
        self.logger("[GAMESCAN] First run: full game scan (Steam/Epic/drives)...")
        existing = self._existing_game_paths()
        self.scan_steam(existing_only=False, existing=existing)
        self.scan_epic(existing_only=False, existing=existing)
        self.scan_drives(existing_only=False, existing=existing)
        self._update_manifest_times()
        self.logger(f"[GAMESCAN] Full scan complete. Found {len(self.detected_games)} games.")
        return list(self.detected_games)

    def incremental_scan(self):
        self.logger("[GAMESCAN] Incremental scan: checking for new installs...")
        existing = self._existing_game_paths()
        new_steam = self._steam_manifest_changed()
        new_epic = self._epic_manifest_changed()
        if new_steam:
            self.logger("[GAMESCAN] Steam manifests changed – scanning Steam only.")
            self.scan_steam(existing_only=True, existing=existing)
        if new_epic:
            self.logger("[GAMESCAN] Epic manifests changed – scanning Epic only.")
            self.scan_epic(existing_only=True, existing=existing)
        self.logger(f"[GAMESCAN] Incremental scan complete. New games: {len(self.detected_games)}")
        return list(self.detected_games)

    def _steam_manifest_changed(self):
        try:
            steam_mtime = 0.0
            for base in self.steam_paths:
                if os.path.exists(base):
                    for acf in glob.glob(os.path.join(base, "*.acf")):
                        m = os.path.getmtime(acf)
                        if m > steam_mtime:
                            steam_mtime = m
            changed = steam_mtime > self.last_steam_manifest_mtime
            if changed:
                self.last_steam_manifest_mtime = steam_mtime
            return changed
        except Exception:
            return False

    def _epic_manifest_changed(self):
        try:
            epic_mtime = 0.0
            if os.path.exists(self.epic_manifest):
                for item in glob.glob(os.path.join(self.epic_manifest, "*.item")):
                    m = os.path.getmtime(item)
                    if m > epic_mtime:
                        epic_mtime = m
            changed = epic_mtime > self.last_epic_manifest_mtime
            if changed:
                self.last_epic_manifest_mtime = epic_mtime
            return changed
        except Exception:
            return False

    def find_exe(self, folder):
        if not os.path.exists(folder):
            return None
        for root, dirs, files in os.walk(folder):
            for f in files:
                if f.lower().endswith(".exe"):
                    return os.path.join(root, f)
        return None

    def scan_steam(self, existing_only=False, existing=None):
        existing = existing or set()
        for base in self.steam_paths:
            if not os.path.exists(base):
                continue
            acf_files = glob.glob(os.path.join(base, "*.acf"))
            for acf in acf_files:
                try:
                    with open(acf, "r", encoding="utf-8", errors="ignore") as f:
                        data = f.read()
                    if "installdir" in data:
                        folder = data.split("installdir")[1].split('"')[1]
                        game_path = os.path.join(base, "common", folder)
                        exe = self.find_exe(game_path)
                        if exe:
                            if existing_only and exe in existing:
                                continue
                            self.detected_games.add(exe)
                            name = os.path.basename(exe)
                            self.storage.store_game(exe, name)
                            self.logger(f"[GAMESCAN] Steam game detected: {exe}")
                except Exception:
                    continue

    def scan_epic(self, existing_only=False, existing=None):
        existing = existing or set()
        if not os.path.exists(self.epic_manifest):
            return
        for item in glob.glob(os.path.join(self.epic_manifest, "*.item")):
            try:
                with open(item, "r", encoding="utf-8", errors="ignore") as f:
                    data = json.loads(f.read())
                install_location = data.get("InstallLocation")
                if install_location:
                    exe = self.find_exe(install_location)
                    if exe:
                        if existing_only and exe in existing:
                            continue
                        self.detected_games.add(exe)
                        name = os.path.basename(exe)
                        self.storage.store_game(exe, name)
                        self.logger(f"[GAMESCAN] Epic game detected: {exe}")
            except Exception:
                continue

    def scan_drives(self, existing_only=False, existing=None):
        existing = existing or set()
        try:
            drives = []
            if OS_NAME == "windows":
                import string
                from ctypes import windll
                bitmask = windll.kernel32.GetLogicalDrives()
                for letter in string.ascii_uppercase:
                    if bitmask & 1:
                        drives.append(f"{letter}:\\")
                    bitmask >>= 1
            else:
                drives = ["/"]
            for d in drives:
                for root, dirs, files in os.walk(d):
                    for f in files:
                        if f.lower().endswith(".exe"):
                            exe = os.path.join(root, f)
                            if existing_only and exe in existing:
                                continue
                            self.detected_games.add(exe)
                            name = os.path.basename(exe)
                            self.storage.store_game(exe, name)
                            self.logger(f"[GAMESCAN] Drive game detected: {exe}")
        except Exception:
            pass

class GameManifestWatcher:
    def __init__(self, scanner: GameScanner, governor, mesh_stack, storage, logger=None, interval=30.0):
        self.scanner = scanner
        self.governor = governor
        self.mesh_stack = mesh_stack
        self.storage = storage
        self.logger = logger or (lambda msg: None)
        self.interval = interval
        self.running = True
        t = threading.Thread(target=self.loop, daemon=True)
        t.start()

    def loop(self):
        while self.running:
            try:
                new_games = self.scanner.incremental_scan()
                for exe in new_games:
                    name = os.path.basename(exe)
                    self.governor.reputation.safe_names.add(name)
                    self.storage.update_safe_process(name, delta_rep=10.0)
                    self.mesh_stack.vote_safe(name, weight=2.0)
                    self.logger(f"[GAMESCAN] Watcher auto-protected new game: {name}")
                time.sleep(self.interval)
            except Exception:
                time.sleep(self.interval)

class NetworkSampler:
    def __init__(self):
        self.last_bytes = None

    def sample(self):
        if not PSUTIL_AVAILABLE:
            return 0
        try:
            io = psutil.net_io_counters()
            total = io.bytes_sent + io.bytes_recv
            if self.last_bytes is None:
                self.last_bytes = total
                return 0
            delta = total - self.last_bytes
            self.last_bytes = total
            return delta
        except Exception:
            return 0

class PortClassifier:
    def classify(self, conn):
        try:
            raddr = conn.raddr
            if not raddr:
                return False, "no_remote"
            port = raddr.port
            suspicious_port = port in (4444, 5555, 6666, 1337, 8081, 31337)
            if suspicious_port:
                return True, "port"
            return False, "normal"
        except Exception:
            return False, "error"

class StatusClassifier:
    def classify(self, conn):
        try:
            status = conn.status
            suspicious_status = status not in ("ESTABLISHED", "TIME_WAIT")
            if suspicious_status:
                return True, "status"
            return False, "normal"
        except Exception:
            return False, "error"

class GeoClassifier:
    def classify(self, conn):
        try:
            raddr = conn.raddr
            if not raddr:
                return False, "no_remote"
            ip = raddr.ip
            if ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172."):
                return False, "local"
            return False, "normal"
        except Exception:
            return False, "error"

class FrequencyClassifier:
    def __init__(self):
        self.conn_counts = {}

    def classify(self, conn):
        try:
            raddr = conn.raddr
            if not raddr:
                return False, "no_remote"
            key = (raddr.ip, raddr.port)
            self.conn_counts[key] = self.conn_counts.get(key, 0) + 1
            if self.conn_counts[key] > 100:
                return True, "freq"
            return False, "normal"
        except Exception:
            return False, "error"

class PatternClassifier:
    def classify(self, conn):
        try:
            return False, "normal"
        except Exception:
            return False, "error"

class DPIStack:
    def __init__(self, logger=None, event_bus=None, deep_rl=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.deep_rl = deep_rl
        self.port_cls     = PortClassifier()
        self.status_cls   = StatusClassifier()
        self.geo_cls      = GeoClassifier()
        self.freq_cls     = FrequencyClassifier()
        self.pattern_cls  = PatternClassifier()
        self.last_scan = 0.0

    def scan(self):
        if not PSUTIL_AVAILABLE:
            return
        now = time.time()
        if now - self.last_scan < 2.0:
            return
        self.last_scan = now
        try:
            conns = psutil.net_connections(kind='inet')
        except Exception:
            return
        suspicious = []
        for c in conns:
            flags = []
            for cls in [self.port_cls, self.status_cls, self.geo_cls, self.freq_cls, self.pattern_cls]:
                flagged, reason = cls.classify(c)
                if flagged:
                    flags.append(reason)
            if flags:
                try:
                    laddr = c.laddr
                    raddr = c.raddr
                    suspicious.append(f"{laddr.ip}:{laddr.port}->{raddr.ip}:{raddr.port} [{'+'.join(flags)}]")
                except Exception:
                    continue
        if suspicious:
            msg = f"DPI anomalies: {', '.join(suspicious[:5])}"
            self.logger(f"[DPI] {msg}")
            if self.event_bus:
                self.event_bus.emit("DPI_ANOMALY", msg, reason="dpi_stack")
            if self.deep_rl:
                self.deep_rl.record_overload()

def sample_gpu_load():
    try:
        import subprocess
        out = subprocess.check_output(
            ["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
            stderr=subprocess.DEVNULL
        ).decode("utf-8").strip()
        vals = [float(x) for x in out.splitlines() if x.strip()]
        if vals:
            return sum(vals) / len(vals)
        return 0.0
    except Exception:
        return 0.0

def map_gpu_processes():
    mapping = {}
    if not PYNVML_AVAILABLE:
        return mapping
    try:
        device_count = pynvml.nvmlGetDeviceCount()
        for i in range(device_count):
            handle = pynvml.nvmlGetDeviceHandleByIndex(i)
            procs = pynvml.nvmlDeviceGetComputeRunningProcesses(handle)
            for p in procs:
                pid = p.pid
                gpu_mem = p.usedGpuMemory
                mapping[pid] = gpu_mem
    except Exception:
        pass
    return mapping

class AcceleratorMode(Enum):
    CPU_ONLY = auto()
    GPU      = auto()
    NPU      = auto()

class Accelerator:
    def __init__(self, logger=None, event_bus=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.mode = AcceleratorMode.CPU_ONLY
        self._detect()

    def _detect(self):
        try:
            gpu_present = PYNVML_AVAILABLE or self._probe_nvidia_smi()
            npu_present = NPU_AVAILABLE
            if npu_present:
                self.mode = AcceleratorMode.NPU
            elif gpu_present:
                self.mode = AcceleratorMode.GPU
            else:
                self.mode = AcceleratorMode.CPU_ONLY
            msg = f"Accelerator mode: {self.mode.name}"
            self.logger(f"[ACCEL] {msg}")
            if self.event_bus:
                self.event_bus.emit("ACCEL_MODE", msg, reason=self.mode.name)
        except Exception:
            self.mode = AcceleratorMode.CPU_ONLY

    def _probe_nvidia_smi(self):
        try:
            import subprocess
            subprocess.check_output(["nvidia-smi"], stderr=subprocess.DEVNULL)
            return True
        except Exception:
            return False

    def refresh(self):
        self._detect()

    def accelerate_rl(self, scores):
        if self.mode == AcceleratorMode.NPU:
            return [s * 1.05 for s in scores]
        if self.mode == AcceleratorMode.GPU:
            return [s * 1.02 for s in scores]
        return scores

    def accelerate_threat_score(self, score):
        if self.mode == AcceleratorMode.NPU:
            return score * 1.1
        if self.mode == AcceleratorMode.GPU:
            return score * 1.05
        return score

class GPUGovernor:
    def __init__(self, logger=None, event_bus=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus

    def adjust_for_gpu(self, gpu_load, persona: BorgPersona):
        if gpu_load < 10.0:
            return "idle"
        if persona == BorgPersona.AGGRESSIVE and gpu_load > 85.0:
            msg = f"GPU overload under AGGRESSIVE persona: {gpu_load:.1f}%"
            self.logger(f"[GPU] {msg}")
            if self.event_bus:
                self.event_bus.emit("GPU_OVERLOAD", msg, reason="persona")
            return "overload"
        if persona == BorgPersona.DEFENSIVE and gpu_load > 90.0:
            msg = f"GPU overload under DEFENSIVE persona: {gpu_load:.1f}%"
            self.logger(f"[GPU] {msg}")
            if self.event_bus:
                self.event_bus.emit("GPU_OVERLOAD", msg, reason="persona")
            return "overload"
        if persona == BorgPersona.PASSIVE and gpu_load > 95.0:
            msg = f"GPU overload under PASSIVE persona: {gpu_load:.1f}%"
            self.logger(f"[GPU] {msg}")
            if self.event_bus:
                self.event_bus.emit("GPU_OVERLOAD", msg, reason="persona")
            return "overload"
        return "normal"

class SystemLoadGovernor:
    def __init__(self, logger=None, event_bus=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.overloaded = False
        self.last_check = 0.0
        self.cpu_high = 85.0
        self.mem_high = 80.0
        self.gpu_high = 90.0

    def check_load(self):
        if not PSUTIL_AVAILABLE:
            self.overloaded = False
            return self.overloaded
        now = time.time()
        if now - self.last_check < 1.0:
            return self.overloaded
        self.last_check = now
        try:
            cpu = psutil.cpu_percent(interval=0.1)
            mem = psutil.virtual_memory().percent
        except Exception:
            cpu = 0.0
            mem = 0.0
        gpu = sample_gpu_load()
        overloaded = (
            cpu >= self.cpu_high or
            mem >= self.mem_high or
            gpu >= self.gpu_high
        )
        if overloaded and not self.overloaded:
            msg = f"System overload: CPU={cpu:.1f} MEM={mem:.1f} GPU={gpu:.1f}"
            self.logger(f"[LOAD] {msg}")
            if self.event_bus:
                self.event_bus.emit("LOAD_OVERLOAD", msg, reason="threshold")
        if not overloaded and self.overloaded:
            msg = f"System normalized: CPU={cpu:.1f} MEM={mem:.1f} GPU={gpu:.1f}"
            self.logger(f"[LOAD] {msg}")
            if self.event_bus:
                self.event_bus.emit("LOAD_NORMAL", msg, reason="threshold")
        self.overloaded = overloaded
        return self.overloaded

class KernelLayer:
    def __init__(self, name, logger=None, event_bus=None):
        self.name = name
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus

    def hook(self, pid, name):
        msg = f"{self.name} hook pid={pid} name={name}"
        self.logger(f"[KERNEL-{self.name}] {msg}")
        if self.event_bus:
            self.event_bus.emit(f"KERNEL_{self.name}_HOOK", msg, reason="hook")

    def enforce(self, pid, name, action):
        msg = f"{self.name} enforce {action} pid={pid} name={name}"
        self.logger(f"[KERNEL-{self.name}] {msg}")
        if self.event_bus:
            self.event_bus.emit(f"KERNEL_{self.name}_POLICY", msg, reason=action)

class KernelStack:
    def __init__(self, logger=None, event_bus=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.hook_kernel     = KernelLayer("HOOK", logger=self.logger, event_bus=self.event_bus)
        self.policy_kernel   = KernelLayer("POLICY", logger=self.logger, event_bus=self.event_bus)
        self.behavior_kernel = KernelLayer("BEHAVIOR", logger=self.logger, event_bus=self.event_bus)
        self.threat_kernel   = KernelLayer("THREAT", logger=self.logger, event_bus=self.event_bus)
        self.kill_kernel     = KernelLayer("KILL", logger=self.logger, event_bus=self.event_bus)

    def hook_process(self, pid, name):
        self.hook_kernel.hook(pid, name)

    def enforce_policy(self, pid, name, action):
        self.policy_kernel.enforce(pid, name, action)

    def enforce_behavior(self, pid, name, action):
        self.behavior_kernel.enforce(pid, name, action)

    def enforce_threat(self, pid, name, action):
        self.threat_kernel.enforce(pid, name, action)

    def enforce_kill(self, pid, name):
        self.kill_kernel.enforce(pid, name, "kill")

class QLearningAgent:
    def __init__(self, name, storage: BorgStorage, logger=None, event_bus=None, accelerator=None):
        self.name = name
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.accelerator = accelerator
        self.storage = storage
        self.qtable = self.storage.load_qtable(self.name)
        self.alpha = 0.1
        self.gamma = 0.9
        self.epsilon = 0.1
        self.kill_count = 0
        self.overload_count = 0
        self.safe_count = 0
        self.last_eval = time.time()

    def _state_repr(self):
        return json.dumps({
            "kills": self.kill_count,
            "overloads": self.overload_count,
            "safe": self.safe_count,
        })

    def _actions(self):
        return ["AGGRESSIVE", "DEFENSIVE", "PASSIVE"]

    def _choose_action(self, state):
        actions = self._actions()
        if random.random() < self.epsilon:
            return random.choice(actions)
        qs = self.qtable.get(state, {})
        if not qs:
            return random.choice(actions)
        return max(actions, key=lambda a: qs.get(a, 0.0))

    def _update_q(self, state, action, reward, next_state):
        qs = self.qtable.setdefault(state, {})
        old_q = qs.get(action, 0.0)
        next_qs = self.qtable.get(next_state, {})
        max_next = max(next_qs.values()) if next_qs else 0.0
        new_q = old_q + self.alpha * (reward + self.gamma * max_next - old_q)
        qs[action] = new_q

    def record_kill(self, overloaded=False):
        self.kill_count += 1
        if overloaded:
            self.overload_count += 1

    def record_overload(self):
        self.overload_count += 1

    def record_safe(self):
        self.safe_count += 1

    def evaluate(self):
        now = time.time()
        if now - self.last_eval < 20.0:
            return None
        self.last_eval = now
        try:
            state = self._state_repr()
            action = self._choose_action(state)
            reward = 0.0
            if self.kill_count > self.safe_count * 2:
                reward -= 1.0
            elif self.safe_count > self.kill_count * 2:
                reward += 1.0
            if self.overload_count > 0:
                reward -= 0.5
            next_state = json.dumps({
                "kills": 0,
                "overloads": 0,
                "safe": 0,
            })
            self._update_q(state, action, reward, next_state)
            self.storage.save_qtable(self.name, self.qtable)
            persona_map = {
                "AGGRESSIVE": BorgPersona.AGGRESSIVE,
                "DEFENSIVE": BorgPersona.DEFENSIVE,
                "PASSIVE": BorgPersona.PASSIVE,
            }
            best_persona = persona_map[action]
            msg = f"QRL-{self.name} persona suggestion: {best_persona.name} (action={action}, reward={reward:.2f})"
            self.logger(f"[QRL-{self.name}] {msg}")
            if self.event_bus:
                self.event_bus.emit(f"QRL_{self.name}_PERSONA", msg, reason="q_learning")
            self.kill_count = 0
            self.overload_count = 0
            self.safe_count = 0
            return best_persona
        except Exception:
            return None

class DeepRLStack:
    def __init__(self, logger=None, event_bus=None, accelerator=None, intel_cfg=None, storage=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.accelerator = accelerator
        self.storage = storage
        self.rl_threat   = QLearningAgent("THREAT", storage=self.storage, logger=self.logger, event_bus=self.event_bus, accelerator=self.accelerator)
        self.rl_load     = QLearningAgent("LOAD", storage=self.storage, logger=self.logger, event_bus=self.event_bus, accelerator=self.accelerator)
        self.rl_behavior = QLearningAgent("BEHAVIOR", storage=self.storage, logger=self.logger, event_bus=self.event_bus, accelerator=self.accelerator)
        base = 120.0
        aggressive = 100.0
        passive = 150.0
        if intel_cfg:
            base = intel_cfg.get("kill_threshold", base)
        self.kill_threshold_base = base
        self.kill_threshold_aggressive = aggressive
        self.kill_threshold_passive = passive

    def record_kill(self, overloaded=False):
        self.rl_threat.record_kill(overloaded=overloaded)
        self.rl_load.record_kill(overloaded=overloaded)
        self.rl_behavior.record_kill(overloaded=overloaded)

    def record_overload(self):
        self.rl_threat.record_overload()
        self.rl_load.record_overload()
        self.rl_behavior.record_overload()

    def record_safe(self):
        self.rl_threat.record_safe()
        self.rl_load.record_safe()
        self.rl_behavior.record_safe()

    def adaptive_threshold(self, persona: BorgPersona):
        base = self.kill_threshold_base
        if persona == BorgPersona.AGGRESSIVE:
            base = self.kill_threshold_aggressive
        elif persona == BorgPersona.PASSIVE:
            base = self.kill_threshold_passive
        return max(80.0, min(200.0, base))

    def evaluate_persona(self, current_persona: BorgPersona):
        suggestions = []
        for agent in [self.rl_threat, self.rl_load, self.rl_behavior]:
            p = agent.evaluate()
            if p is not None:
                suggestions.append(p)
        if not suggestions:
            return current_persona
        counts = {BorgPersona.AGGRESSIVE: 0, BorgPersona.DEFENSIVE: 0, BorgPersona.PASSIVE: 0}
        for p in suggestions:
            counts[p] += 1
        best_persona = max(counts.keys(), key=lambda k: counts[k])
        if best_persona != current_persona:
            msg = f"QRL-STACK persona shift: {current_persona.name} -> {best_persona.name} (votes: {counts})"
            self.logger(f"[QRL-STACK] {msg}")
            if self.event_bus:
                self.event_bus.emit("PERSONA_SHIFT_STACK", msg, reason="qrl_stack")
        return best_persona

class MeshConsensus:
    def __init__(self, storage: BorgStorage, logger=None, event_bus=None, name="LOCAL", quorum=2.0):
        self.storage = storage
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.quorum_threshold = quorum
        self.name = name

    def vote(self, subject: str, vote: str, weight: float = 1.0):
        if not MESH_ENABLED:
            return
        try:
            self.storage.store_mesh_vote(subject, vote, weight, LOCAL_PEER_ID)
            msg = f"{self.name} Mesh vote: {subject} -> {vote} (w={weight})"
            self.logger(f"[MESH-{self.name}] {msg}")
            if self.event_bus:
                self.event_bus.emit(f"MESH_{self.name}_VOTE", msg, reason=vote)
        except Exception:
            pass

    def consensus(self, subject: str):
        if not MESH_ENABLED:
            return None
        try:
            votes = self.storage.load_mesh_votes(subject)
            if not votes:
                return None
            score = 0.0
            for v, w, peer_id in votes:
                if v.upper() == "SAFE":
                    score -= w
                elif v.upper() == "THREAT":
                    score += w
            if abs(score) < self.quorum_threshold:
                result = "UNKNOWN"
            elif score > 0.0:
                result = "THREAT"
            else:
                result = "SAFE"
            msg = f"{self.name} Mesh consensus for {subject}: {result} (score={score:.2f})"
            self.logger(f"[MESH-{self.name}] {msg}")
            if self.event_bus:
                self.event_bus.emit(f"MESH_{self.name}_CONSENSUS", msg, reason=result)
            return result
        except Exception:
            return None

class MeshStack:
    def __init__(self, storage: BorgStorage, logger=None, event_bus=None, intel_cfg=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        quorum_local = 2.0
        if intel_cfg:
            quorum_local = intel_cfg.get("mesh_quorum", quorum_local)
        self.local_mesh      = MeshConsensus(storage, logger=self.logger, event_bus=self.event_bus, name="LOCAL", quorum=quorum_local)
        self.historical_mesh = MeshConsensus(storage, logger=self.logger, event_bus=self.event_bus, name="HIST", quorum=1.5)
        self.behavior_mesh   = MeshConsensus(storage, logger=self.logger, event_bus=self.event_bus, name="BEHAV", quorum=1.5)

    def vote_safe(self, subject, weight=1.0):
        self.local_mesh.vote(subject, "SAFE", weight)
        self.historical_mesh.vote(subject, "SAFE", weight * 0.5)
        self.behavior_mesh.vote(subject, "SAFE", weight * 0.5)

    def vote_threat(self, subject, weight=1.0):
        self.local_mesh.vote(subject, "THREAT", weight)
        self.historical_mesh.vote(subject, "THREAT", weight * 0.5)
        self.behavior_mesh.vote(subject, "THREAT", weight * 0.5)

    def fused_consensus(self, subject):
        results = []
        for mesh in [self.local_mesh, self.historical_mesh, self.behavior_mesh]:
            r = mesh.consensus(subject)
            if r is not None:
                results.append(r)
        if not results:
            return None
        score = 0
        for r in results:
            if r == "SAFE":
                score -= 1
            elif r == "THREAT":
                score += 1
        if score > 0:
            return "THREAT"
        elif score < 0:
            return "SAFE"
        else:
            return "UNKNOWN"

class ThreatScoreStack:
    def __init__(self, reputation: ProcessReputation, mesh_stack: MeshStack, logger=None, accelerator=None, intel_cfg=None):
        self.reputation = reputation
        self.mesh_stack = mesh_stack
        self.logger = logger or (lambda msg: None)
        self.accelerator = accelerator
        self.dpi_weight = 0.20
        if intel_cfg:
            self.dpi_weight = intel_cfg.get("dpi_sensitivity", self.dpi_weight)

    def compute_scores(self, name, cpu, mem, io_read, io_write, net_bytes, gpu_mem, dpi_flags, anomaly_flags):
        base_score, sigs = self.reputation.score(name, cpu, mem, io_read, io_write, net_bytes, anomaly_flags)
        cpu_mem_score = base_score
        gpu_score = 0.0
        if gpu_mem > 0:
            gpu_score = min(50.0, gpu_mem / (1024 * 1024))
        dpi_score = 0.0
        if dpi_flags:
            dpi_score = 40.0
        behavior_score = 0.0
        if "miner" in (name or "").lower():
            behavior_score += 60.0
        mesh_result = self.mesh_stack.fused_consensus(name)
        mesh_score = 0.0
        if mesh_result == "SAFE":
            mesh_score -= 60.0
        elif mesh_result == "THREAT":
            mesh_score += 60.0
        scores = {
            "cpu_mem": cpu_mem_score,
            "gpu": gpu_score,
            "dpi": dpi_score,
            "behavior": behavior_score,
            "mesh": mesh_score,
            "sigs": sigs,
            "anomaly": anomaly_flags,
        }
        if self.accelerator:
            scores["cpu_mem"] = self.accelerator.accelerate_threat_score(scores["cpu_mem"])
        final_score = (
            scores["cpu_mem"] * 0.25 +
            scores["gpu"]     * 0.25 +
            scores["dpi"]     * self.dpi_weight +
            scores["behavior"]* 0.20 +
            scores["mesh"]    * 0.10
        )
        self.logger(f"[THREAT-STACK] {name} scores={scores} final={final_score:.1f}")
        return final_score, scores["sigs"], mesh_result

class PersonaStack:
    def __init__(self, logger=None, event_bus=None, intel_cfg=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.bias = {
            BorgPersona.AGGRESSIVE: 0.0,
            BorgPersona.DEFENSIVE: 0.0,
            BorgPersona.PASSIVE: 0.0,
        }
        if intel_cfg:
            pb = intel_cfg.get("persona_bias", {})
            self.bias[BorgPersona.AGGRESSIVE] = pb.get("AGGRESSIVE", 0.0)
            self.bias[BorgPersona.DEFENSIVE]  = pb.get("DEFENSIVE", 0.0)
            self.bias[BorgPersona.PASSIVE]    = pb.get("PASSIVE", 0.0)

    def fuse(self, suggestions, current_persona: BorgPersona):
        if not suggestions:
            return current_persona
        counts = {BorgPersona.AGGRESSIVE: 0, BorgPersona.DEFENSIVE: 0, BorgPersona.PASSIVE: 0}
        for p in suggestions:
            counts[p] += 1
        for p in counts:
            counts[p] += self.bias.get(p, 0.0)
        best_persona = max(counts.keys(), key=lambda k: counts[k])
        if best_persona != current_persona:
            msg = f"Persona-STACK shift: {current_persona.name} -> {best_persona.name} (votes={counts})"
            self.logger(f"[PERSONA-STACK] {msg}")
            if self.event_bus:
                self.event_bus.emit("PERSONA_STACK_SHIFT", msg, reason="persona_stack")
        return best_persona

class PreFilterGovernor:
    def __init__(self, reputation: ProcessReputation, game_exes, logger=None):
        self.reputation = reputation
        self.game_exes = game_exes
        self.logger = logger or (lambda msg: None)

    def classify(self, p, name, exe_path):
        lname = (name or "").lower()
        is_known_game_exe = exe_path and exe_path.lower() in self.game_exes
        is_launcher_like = (
            "steam" in lname or "epic" in lname or "battle.net" in lname or
            "riot" in lname or "origin" in lname or
            "game" in lname or "launcher" in lname or "client" in lname
        )
        hard_protected = self.reputation.is_hard_protected(name)
        learned_safe = self.reputation.is_learned_safe(name)
        if is_known_game_exe or is_launcher_like or hard_protected:
            tag = "GAME_EXE" if is_known_game_exe else "LAUNCHER" if is_launcher_like else "HARD_PROTECTED"
            msg = f"[PREFILTER] NEVER-KILL {p.pid} {name} ({tag})"
            self.logger(msg)
            return "never_kill", hard_protected, learned_safe
        return "normal", hard_protected, learned_safe

class ThreatGovernor:
    def __init__(self, threat_stack: ThreatScoreStack, logger=None):
        self.threat_stack = threat_stack
        self.logger = logger or (lambda msg: None)

    def decide(self, name, cpu, mem, io_read, io_write, net_bytes, gpu_mem, dpi_flags, anomaly_flags):
        score, sigs, mesh_result = self.threat_stack.compute_scores(
            name, cpu, mem, io_read, io_write, net_bytes, gpu_mem, dpi_flags, anomaly_flags
        )
        return score, sigs, mesh_result

class LoadGovernorStack:
    def __init__(self, load_governor: SystemLoadGovernor, gpu_governor: GPUGovernor, logger=None):
        self.load_governor = load_governor
        self.gpu_governor = gpu_governor
        self.logger = logger or (lambda msg: None)

    def check(self, persona: BorgPersona):
        overloaded = self.load_governor.check_load()
        gpu_load = sample_gpu_load()
        gpu_mode = self.gpu_governor.adjust_for_gpu(gpu_load, persona)
        if gpu_mode == "overload":
            overloaded = True
        return overloaded, gpu_load

class KillGovernor:
    def __init__(self, kernel_stack: KernelStack, rl_stack: DeepRLStack, storage: BorgStorage, logger=None, event_bus=None):
        self.kernel_stack = kernel_stack
        self.rl_stack = rl_stack
        self.storage = storage
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.user_approval_window_until = 0.0

    def in_safe_window(self):
        return time.time() < self.user_approval_window_until

    def kill(self, p, score, gpu_load, sigs, overloaded, mesh_result):
        try:
            name = p.info.get('name') or ""
            lname = name.lower()
            pid = p.info.get('pid')

            # Always allow System Idle Process / Idle / pid 0
            if pid == 0 or "system idle process" in lname or lname == "idle":
                msg = f"[KILL-GOV] ALWAYS-ALLOW {pid} {name} (System Idle)"
                self.logger(msg)
                if self.event_bus:
                    self.event_bus.emit("ALWAYS_ALLOW_IDLE", msg, reason="idle")
                self.rl_stack.record_safe()
                return False

            if ("steam" in lname or "epic" in lname or "battle.net" in lname or
                "riot" in lname or "origin" in lname or
                "game" in lname or "launcher" in lname or "client" in lname):
                return False

            sig_str = ",".join(sigs) if sigs else "none"
            reason = f"threat score={score:.1f}, gpu={gpu_load:.1f}, sigs={sig_str}, mesh={mesh_result}"

            if KILL_MODE == "OFF":
                msg = f"[KILL-GOV] KILL_MODE=OFF, would kill {p.pid} {name} | {reason}"
                self.logger(msg)
                if self.event_bus:
                    self.event_bus.emit("KILL_SKIPPED", msg, reason="kill_off")
                self.rl_stack.record_safe()
                return False

            if KILL_MODE == "ASK":
                # Replace popup with 5-day investigation mode
                self.storage.start_investigation(p.pid, name)
                msg = f"[KILL-GOV] Investigation started for {p.pid} {name} | {reason}"
                self.logger(msg)
                if self.event_bus:
                    self.event_bus.emit("INVESTIGATION_START", msg, reason="investigation")
                self.rl_stack.record_safe()
                return False

            elif KILL_MODE == "AUTO":
                if mesh_result != "THREAT" or not sigs or score < self.rl_stack.kill_threshold_base:
                    msg = f"[KILL-GOV] AUTO mode but multi-factor not met, spared {p.pid} {name} | {reason}"
                    self.logger(msg)
                    if self.event_bus:
                        self.event_bus.emit("AUTO_SPARED", msg, reason="multi_factor")
                    self.rl_stack.record_safe()
                    return False

            self.user_approval_window_until = time.time() + 300.0
            msg_window = f"User/auto approved kill; entering 5-minute SAFE WINDOW until {self.user_approval_window_until:.0f}"
            self.logger(f"[KILL-GOV] {msg_window}")
            if self.event_bus:
                self.event_bus.emit("SAFE_WINDOW", msg_window, reason="user_approval")

            msg = f"[KILL-GOV] KILL THREAT {p.pid} {name} | {reason}"
            self.logger(msg)
            if self.event_bus:
                self.event_bus.emit("KILL", msg, reason=reason)

            self.kernel_stack.enforce_threat(p.pid, name, "kill")
            self.kernel_stack.enforce_kill(p.pid, name)
            if not DEV_MODE:
                p.terminate()
            self.rl_stack.record_kill(overloaded=overloaded)
            return True
        except Exception:
            return False

class SafeWindowGovernor:
    def __init__(self, kill_governor: KillGovernor, logger=None):
        self.kill_governor = kill_governor
        self.logger = logger or (lambda msg: None)

    def in_safe_window(self):
        return self.kill_governor.in_safe_window()

class GameGovernor:
    def __init__(self, reputation: ProcessReputation, mesh_stack: MeshStack, logger=None):
        self.reputation = reputation
        self.mesh_stack = mesh_stack
        self.logger = logger or (lambda msg: None)

    def protect(self, p, name):
        self.reputation.observe_safe(name, 0.0, 0.0)
        self.mesh_stack.vote_safe(name, weight=2.0)
        msg = f"[GAME-GOV] Protect {p.pid} {name}"
        self.logger(msg)

class BorgOSGovernor:
    def __init__(self, logger=None, storage=None, event_bus=None,
                 persona=BorgPersona.DEFENSIVE, rl_stack=None,
                 kernel_stack=None, mesh_stack=None, accelerator=None,
                 intel_cfg=None):
        self.logger = logger or (lambda msg: None)
        self.storage = storage
        self.event_bus = event_bus
        self.reputation = ProcessReputation(storage=storage)
        self.net_sampler = NetworkSampler()
        self.last_decay = time.time()
        self.load_governor = SystemLoadGovernor(logger=self.logger, event_bus=self.event_bus)
        self.persona = persona
        self.accelerator = accelerator
        self.anomaly_detector = AnomalyDetector(logger=self.logger)
        self.rl_stack = rl_stack or DeepRLStack(logger=self.logger, event_bus=self.event_bus, accelerator=self.accelerator, intel_cfg=intel_cfg, storage=self.storage)
        self.kernel_stack = kernel_stack or KernelStack(logger=self.logger, event_bus=self.event_bus)
        self.mesh_stack = mesh_stack or MeshStack(storage=storage, logger=self.logger, event_bus=self.event_bus, intel_cfg=intel_cfg)
        self.dpi_stack = DPIStack(logger=self.logger, event_bus=self.event_bus, deep_rl=self.rl_stack)
        self.gpu_governor = GPUGovernor(logger=self.logger, event_bus=self.event_bus)
        self.game_exes = {exe_path.lower() for exe_path, _ in (self.storage.load_games() if self.storage else [])}
        self.threat_stack = ThreatScoreStack(self.reputation, self.mesh_stack, logger=self.logger, accelerator=self.accelerator, intel_cfg=intel_cfg)
        self.persona_stack = PersonaStack(logger=self.logger, event_bus=self.event_bus, intel_cfg=intel_cfg)
        self.prefilter_governor = PreFilterGovernor(self.reputation, self.game_exes, logger=self.logger)
        self.threat_governor = ThreatGovernor(self.threat_stack, logger=self.logger)
        self.load_governor_stack = LoadGovernorStack(self.load_governor, self.gpu_governor, logger=self.logger)
        self.kill_governor = KillGovernor(self.kernel_stack, self.rl_stack, storage=self.storage, logger=self.logger, event_bus=self.event_bus)
        self.safe_window_governor = SafeWindowGovernor(self.kill_governor, logger=self.logger)
        self.game_governor = GameGovernor(self.reputation, self.mesh_stack, logger=self.logger)

    def refresh_game_cache(self):
        if self.storage:
            self.game_exes = {exe_path.lower() for exe_path, _ in self.storage.load_games()}

    def apply(self, organ_states_stack):
        if not PSUTIL_AVAILABLE:
            return
        try:
            now = time.time()
            overloaded, gpu_load = self.load_governor_stack.check(self.persona)
            self.dpi_stack.scan()
            if overloaded:
                self.rl_stack.record_overload()
            kill_threshold = self.rl_stack.adaptive_threshold(self.persona)
            if now - self.last_decay > 60.0:
                self.reputation.decay()
                self.last_decay = now
            procs = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'io_counters']))
            if not procs:
                return
            net_delta = self.net_sampler.sample()
            gpu_map = map_gpu_processes()
            if self.accelerator:
                self.accelerator.refresh()
            in_approval_window = self.safe_window_governor.in_safe_window()
            chunk = max(1, len(procs) // max(1, len(organ_states_stack[0])))
            for organ_idx, states in enumerate(organ_states_stack):
                for i, state in enumerate(states):
                    start = i * chunk
                    end = min(len(procs), start + chunk)
                    for p in procs[start:end]:
                        try:
                            name = p.info.get('name') or ""
                            pid = p.info.get('pid')
                            cpu = p.info.get('cpu_percent') or 0.0
                            mem = p.info.get('memory_percent') or 0.0
                            io = p.info.get('io_counters')
                            io_read = io.read_bytes if io else 0
                            io_write = io.write_bytes if io else 0
                            gpu_mem = gpu_map.get(pid, 0)
                            exe_path = None
                            try:
                                exe_path = p.exe()
                            except Exception:
                                exe_path = None
                            dpi_flags = False
                            self.anomaly_detector.observe(name, cpu, mem, io_read, io_write, net_delta)
                            anomalous, anomaly_flags = self.anomaly_detector.is_anomalous(name, cpu, mem, io_read, io_write, net_delta)
                            pre_class, hard_protected, learned_safe = self.prefilter_governor.classify(p, name, exe_path)

                            # Investigation handling
                            inv = self.storage.get_investigation(pid)
                            if inv:
                                pid_i, name_i, start_ts, last_seen, threat_hits, safe_hits = inv
                                days = (time.time() - start_ts) / 86400.0
                                # compute threat for this tick
                                score, sigs, mesh_result = self.threat_governor.decide(
                                    name, cpu, mem, io_read, io_write, net_delta, gpu_mem, dpi_flags, anomaly_flags if anomalous else {}
                                )
                                threat_now = (
                                    score > kill_threshold or
                                    (cpu > 97.0 and mem > 90.0 and sigs)
                                ) and not hard_protected and not learned_safe
                                self.storage.update_investigation(pid, threat=threat_now)
                                if threat_now:
                                    self._kill_process(p, score, gpu_load, hard_protected, learned_safe, sigs, gpu_mem, overloaded, mesh_result)
                                    self.storage.end_investigation(pid)
                                    continue
                                if days >= 5.0:
                                    self.reputation.observe_safe(name, cpu, mem)
                                    self.mesh_stack.vote_safe(name, weight=2.0)
                                    msg = f"[INVESTIGATION] {name} marked SAFE after 5 days"
                                    self.logger(msg)
                                    if self.event_bus:
                                        self.event_bus.emit("INVESTIGATION_SAFE", msg, reason="no_threat")
                                    self.storage.end_investigation(pid)
                                    continue
                                self._monitor_process(p, score, hard_protected, learned_safe, sigs, gpu_mem)
                                continue

                            if in_approval_window:
                                self.reputation.observe_safe(name, cpu, mem)
                                self.mesh_stack.vote_safe(name, weight=0.5)
                                self._monitor_process(p, 0.0, hard_protected, learned_safe, [], gpu_mem, overload=overloaded)
                                continue

                            if pre_class == "never_kill":
                                self.game_governor.protect(p, name)
                                self._monitor_process(p, 0.0, True, True, [], gpu_mem, overload=overloaded)
                                continue

                            score, sigs, mesh_result = self.threat_governor.decide(
                                name, cpu, mem, io_read, io_write, net_delta, gpu_mem, dpi_flags, anomaly_flags if anomalous else {}
                            )

                            if cpu < 20.0 and mem < 10.0 and not hard_protected:
                                self.reputation.observe_safe(name, cpu, mem)
                                self.rl_stack.record_safe()
                                self.mesh_stack.vote_safe(name, weight=0.5)

                            if sigs and not hard_protected and not learned_safe:
                                self.reputation.observe_suspicious(name)
                                self.mesh_stack.vote_threat(name, weight=1.0)

                            threat = (
                                score > kill_threshold or
                                (cpu > 97.0 and mem > 90.0 and sigs)
                            ) and not hard_protected and not learned_safe

                            self.kernel_stack.hook_process(pid, name)

                            if overloaded:
                                self._monitor_process(p, score, hard_protected, learned_safe, sigs, gpu_mem, overload=True)
                                continue

                            if state == BorgState.DOMINANT:
                                if not hard_protected and not learned_safe:
                                    self._boost_process(p, score, hard_protected, learned_safe, sigs, gpu_mem)
                                else:
                                    self._monitor_process(p, score, hard_protected, learned_safe, sigs, gpu_mem)
                            elif state == BorgState.SUPPRESSED:
                                if threat:
                                    self._kill_process(p, score, gpu_load, hard_protected, learned_safe, sigs, gpu_mem, overloaded, mesh_result)
                                elif not hard_protected and not learned_safe:
                                    self._suppress_process(p, score, sigs, gpu_mem)
                                else:
                                    self._monitor_process(p, score, hard_protected, learned_safe, sigs, gpu_mem)
                            elif state == BorgState.FLAGGED:
                                if threat:
                                    self._kill_process(p, score, gpu_load, hard_protected, learned_safe, sigs, gpu_mem, overloaded, mesh_result)
                                else:
                                    self._monitor_process(p, score, hard_protected, learned_safe, sigs, gpu_mem)
                            elif state == BorgState.BORG_CORE:
                                self._protect_process(p, hard_protected, learned_safe, sigs, gpu_mem)
                        except Exception:
                            continue

            suggestions = []
            p_threat = self.rl_stack.rl_threat.evaluate()
            p_load = self.rl_stack.rl_load.evaluate()
            p_beh = self.rl_stack.rl_behavior.evaluate()
            for p in [p_threat, p_load, p_beh]:
                if p is not None:
                    suggestions.append(p)
            self.persona = self.persona_stack.fuse(suggestions, self.persona)
        except Exception:
            pass

    def _boost_process(self, p, score, hard_protected, learned_safe, sigs, gpu_mem):
        tag = self._tag(hard_protected, learned_safe, sigs, gpu_mem)
        try:
            if OS_NAME == "windows":
                p.nice(psutil.HIGH_PRIORITY_CLASS)
            else:
                p.nice(-5)
            msg = f"[OS] Boosted {p.pid} {p.info.get('name')} | score={score:.1f} [{tag}]"
            self.logger(msg)
            if self.event_bus:
                self.event_bus.emit("BOOST", msg, reason=tag)
            self.kernel_stack.enforce_policy(p.pid, p.info.get('name'), "boost")
        except Exception:
            pass

    def _suppress_process(self, p, score, sigs, gpu_mem):
        reason = "non-protected"
        if sigs:
            reason += f" sigs={','.join(sigs)}"
        if gpu_mem > 0:
            reason += f" gpu_mem={gpu_mem}"
        try:
            if OS_NAME == "windows":
                p.nice(psutil.IDLE_PRIORITY_CLASS)
            else:
                p.nice(10)
            msg = f"[OS] Suppressed {p.pid} {p.info.get('name')} | score={score:.1f} ({reason})"
            self.logger(msg)
            if self.event_bus:
                self.event_bus.emit("SUPPRESS", msg, reason=reason)
            self.kernel_stack.enforce_behavior(p.pid, p.info.get('name'), "suppress")
        except Exception:
            pass

    def _kill_process(self, p, score, gpu_load, hard_protected, learned_safe, sigs, gpu_mem, overloaded, mesh_result):
        killed = self.kill_governor.kill(p, score, gpu_load, sigs, overloaded, mesh_result)
        if killed:
            self.mesh_stack.vote_threat(p.info.get('name') or "", weight=1.5)

    def _monitor_process(self, p, score, hard_protected, learned_safe, sigs, gpu_mem, overload=False):
        try:
            name = p.info.get('name')
            tag = self._tag(hard_protected, learned_safe, sigs, gpu_mem)
            sig_str = ",".join(sigs) if sigs else "none"
            mode = "SAFE-LOAD" if overload else "NORMAL"
            msg = f"[OS] Monitor {p.pid} {name} | score={score:.1f} sigs={sig_str} [{tag}] mode={mode}"
            self.logger(msg)
            if self.event_bus:
                self.event_bus.emit("MONITOR", msg, reason=f"{tag}/{mode}")
        except Exception:
            pass

    def _protect_process(self, p, hard_protected, learned_safe, sigs, gpu_mem):
        try:
            name = p.info.get('name')
            tag = self._tag(hard_protected, learned_safe, sigs, gpu_mem)
            msg = f"[OS] Protect {p.pid} {name} [{tag}]"
            self.logger(msg)
            if self.event_bus:
                self.event_bus.emit("PROTECT", msg, reason=tag)
        except Exception:
            pass

    def _tag(self, hard_protected, learned_safe, sigs, gpu_mem):
        base = []
        if hard_protected:
            base.append("HARD_PROTECTED")
        if learned_safe:
            base.append("LEARNED_SAFE")
        if sigs:
            base.append("SIG_MATCH")
        if gpu_mem > 0:
            base.append("GPU_PROC")
        if not base:
            return "NORMAL"
        return "+".join(base)

class BorgCore:
    def __init__(self, memory_stack: MemoryStack, logger=None, storage=None, governor=None, event_bus=None, persona=BorgPersona.DEFENSIVE):
        self.memory_stack = memory_stack
        self.engines = [BorgLogicEngine(organ) for organ in self.memory_stack.organs()]
        self.logger = logger or (lambda msg: None)
        self.storage = storage
        self.event_bus = event_bus
        self.governor = governor
        self.tick_counter = 0
        self.watchdog = None
        self.persona = persona

    def attach_watchdog(self, watchdog):
        self.watchdog = watchdog

    def tick(self):
        try:
            for engine in self.engines:
                engine.autonomous_step()
            self.tick_counter += 1
            organ_states_stack = []
            organ_names = ["short", "mid", "long", "threat", "behavior"]
            for organ_name, organ in zip(organ_names, self.memory_stack.organs()):
                states = [cell.state for cell in organ.cells]
                organ_states_stack.append(states)
                if self.storage:
                    self.storage.save_states(organ_name, states, self.tick_counter)
            if self.governor:
                self.governor.apply(organ_states_stack)
                self.persona = self.governor.persona
            msg = f"BorgCore tick {self.tick_counter} persona={self.persona.name}"
            self.logger(f"[HEARTBEAT] {msg}")
            if self.event_bus:
                self.event_bus.emit("HEARTBEAT", msg, reason="tick")
            if self.watchdog:
                self.watchdog.notify_tick()
        except Exception:
            pass

    def get_states(self):
        organ_states_stack = []
        for organ in self.memory_stack.organs():
            organ_states_stack.append([cell.state for cell in organ.cells])
        return organ_states_stack

class BorgWatchdog:
    def __init__(self, core: BorgCore, timeout=5.0, event_bus=None):
        self.core = core
        self.timeout = timeout
        self.last_tick = time.time()
        self.running = True
        self.event_bus = event_bus
        t = threading.Thread(target=self.loop, daemon=True)
        t.start()

    def notify_tick(self):
        self.last_tick = time.time()

    def loop(self):
        while self.running:
            try:
                if time.time() - self.last_tick > self.timeout:
                    msg = "Tick stall detected, resetting BorgCore memory stack"
                    self.core.logger(f"[WATCHDOG] {msg}")
                    if self.event_bus:
                        self.event_bus.emit("WATCHDOG_RESET", msg, reason="stall")
                    self.core.memory_stack = MemoryStack()
                    self.core.engines = [BorgLogicEngine(organ) for organ in self.core.memory_stack.organs()]
                    self.last_tick = time.time()
                time.sleep(1.0)
            except Exception:
                time.sleep(1.0)

class BorgIntel:
    def __init__(self, db_path=DB_PATH):
        self.conn = sqlite3.connect(db_path)

    def _fetch_events(self):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT kind, detail, ts, reason FROM borg_events")
            return cur.fetchall()
        except Exception:
            return []

    def analyze(self):
        events = self._fetch_events()
        kills = 0
        spared = 0
        overloads = 0
        for kind, detail, ts, reason in events:
            if kind == "KILL":
                kills += 1
            elif kind in ("USER_SPARED", "AUTO_SPARED", "KILL_SKIPPED"):
                spared += 1
            elif kind in ("LOAD_OVERLOAD", "GPU_OVERLOAD", "DPI_ANOMALY"):
                overloads += 1
        kill_threshold = 120.0
        if kills > spared * 2:
            kill_threshold -= 10.0
        elif spared > kills * 2:
            kill_threshold += 10.0
        persona_bias = {
            "AGGRESSIVE": -0.1 if spared > kills else 0.0,
            "DEFENSIVE": 0.08,
            "PASSIVE": 0.02 if overloads > 0 else 0.0,
        }
        dpi_sensitivity = 0.20
        mesh_quorum = 2.0
        cfg = {
            "kill_threshold": kill_threshold,
            "persona_bias": persona_bias,
            "dpi_sensitivity": dpi_sensitivity,
            "mesh_quorum": mesh_quorum,
        }
        return cfg

    def generate_config(self, path=INTEL_CONFIG_PATH):
        cfg = self.analyze()
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=2)
        except Exception:
            pass
        return cfg

def load_intel_config(path=INTEL_CONFIG_PATH):
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

storage = BorgStorage(DB_PATH)
event_bus = BorgEventBus(logger=lambda msg: print(msg), storage=storage)
accelerator = Accelerator(logger=lambda msg: print(msg), event_bus=event_bus)
intel_cfg = load_intel_config()
if intel_cfg is None:
    intel_engine = BorgIntel(DB_PATH)
    intel_cfg = intel_engine.generate_config(INTEL_CONFIG_PATH)
rl_stack = DeepRLStack(logger=lambda msg: print(msg), event_bus=event_bus, accelerator=accelerator, intel_cfg=intel_cfg, storage=storage)
kernel_stack = KernelStack(logger=lambda msg: print(msg), event_bus=event_bus)
mesh_stack = MeshStack(storage=storage, logger=lambda msg: print(msg), event_bus=event_bus, intel_cfg=intel_cfg)
governor = BorgOSGovernor(logger=lambda msg: print(msg), storage=storage, event_bus=event_bus,
                          persona=BorgPersona.DEFENSIVE, rl_stack=rl_stack,
                          kernel_stack=kernel_stack, mesh_stack=mesh_stack,
                          accelerator=accelerator, intel_cfg=intel_cfg)
game_scanner = GameScanner(storage, logger=lambda msg: print(msg))
first_scan_done = storage.get_setting("first_scan_done", "0")
if first_scan_done == "0":
    detected_games = game_scanner.full_scan_once()
    storage.set_setting("first_scan_done", "1")
else:
    detected_games = []
for exe in detected_games:
    name = os.path.basename(exe)
    governor.reputation.safe_names.add(name)
    storage.update_safe_process(name, delta_rep=10.0)
    mesh_stack.vote_safe(name, weight=2.0)
    print(f"[GAMESCAN] Auto-protected game (first scan): {name}")
for exe_path, name in storage.load_games():
    governor.reputation.safe_names.add(name)
    storage.update_safe_process(name, delta_rep=10.0)
    mesh_stack.vote_safe(name, weight=2.0)
governor.refresh_game_cache()
manifest_watcher = GameManifestWatcher(game_scanner, governor, mesh_stack, storage,
                                       logger=lambda msg: print(msg), interval=30.0)
memory_stack = MemoryStack(size_short=10, size_mid=10, size_long=10, size_threat=10, size_behavior=10)
core = BorgCore(memory_stack, logger=lambda msg: print(msg), storage=storage, governor=governor,
                event_bus=event_bus, persona=BorgPersona.DEFENSIVE)
watchdog = BorgWatchdog(core, event_bus=event_bus)
core.attach_watchdog(watchdog)

class BorgRunner:
    def __init__(self, core: BorgCore, interval=0.5):
        self.core = core
        self.interval = interval
        self.running = True
        t = threading.Thread(target=self.loop, daemon=True)
        t.start()

    def loop(self):
        while self.running:
            try:
                self.core.tick()
                time.sleep(self.interval)
            except Exception:
                time.sleep(self.interval)

runner = BorgRunner(core, interval=0.5)

PEERS = []

def discover_peers(port=8000, timeout=0.2):
    if not MESH_ENABLED:
        return
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        msg = b"BORG_DISCOVERY_V27"
        sock.sendto(msg, ("255.255.255.255", port))
        sock.close()
    except Exception:
        pass

def broadcast_mesh_intel():
    if not HTTPX_AVAILABLE or not MESH_ENABLED:
        return
    try:
        safe_rows = storage.load_mesh_intel("SAFE")
        threat_rows = storage.load_mesh_intel("THREAT")
        safe_payloads = [p for (p, sig, peer_id) in safe_rows]
        threat_payloads = [p for (p, sig, peer_id) in threat_rows]
        payload = {
            "safe": safe_payloads,
            "threat": threat_payloads,
            "peer_id": LOCAL_PEER_ID,
        }
        signature = sign_payload(payload)
        token = encrypt_payload({"payload": payload, "signature": signature})
        for peer in PEERS:
            try:
                httpx.post(f"{peer}/mesh/intel", json={"token": token}, timeout=1.0)
            except Exception:
                continue
    except Exception:
        pass

if FASTAPI_AVAILABLE:
    app = FastAPI(title="Borg OS Node", version="27.1.0")

    class SyncPushRequest(BaseModel):
        token: str

    class MeshIntelRequest(BaseModel):
        token: str

    @app.get("/states")
    def get_states():
        organ_states_stack = core.get_states()
        return {
            "organs": [[s.name for s in organ_states] for organ_states in organ_states_stack],
            "os": OS_NAME,
            "tick": core.tick_counter,
            "persona": core.persona.name,
            "accelerator": accelerator.mode.name,
            "peer_id": LOCAL_PEER_ID,
        }

    @app.get("/metrics")
    def get_metrics():
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available"}
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        gpu = sample_gpu_load()
        return {
            "cpu": cpu,
            "mem": mem,
            "gpu": gpu,
            "tick": core.tick_counter,
            "persona": core.persona.name,
            "accelerator": accelerator.mode.name,
        }

    @app.get("/processes")
    def get_processes():
        if not PSUTIL_AVAILABLE:
            return {"error": "psutil not available"}
        procs_info = []
        for p in psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent']):
            try:
                procs_info.append({
                    "pid": p.info.get('pid'),
                    "name": p.info.get('name'),
                    "cpu": p.info.get('cpu_percent'),
                    "mem": p.info.get('memory_percent'),
                })
            except Exception:
                continue
        return {"processes": procs_info, "count": len(procs_info)}

    @app.get("/games")
    def get_games():
        rows = storage.load_games()
        return {"games": [{"exe": exe, "name": name} for exe, name in rows]}

    @app.post("/sync/push")
    def sync_push():
        if not HTTPX_AVAILABLE or not MESH_ENABLED:
            return {"error": "mesh/httpx not available"}
        organ_states_stack = core.get_states()
        payload = {
            "organs": [[s.name for s in organ_states] for organ_states in organ_states_stack],
            "tick": core.tick_counter,
            "peer_id": LOCAL_PEER_ID,
        }
        signature = sign_payload(payload)
        token = encrypt_payload({"payload": payload, "signature": signature})
        for peer in PEERS:
            try:
                httpx.post(f"{peer}/sync/pull", json={"token": token}, timeout=1.0)
            except Exception:
                pass
        return {"status": "ok"}

    @app.post("/sync/pull")
    def sync_pull(req: SyncPushRequest):
        data = decrypt_payload(req.token)
        payload = data.get("payload", {})
        signature = data.get("signature", "")
        if not verify_payload(payload, signature):
            return {"status": "invalid_signature"}
        organs = payload.get("organs", [])
        for organ_idx, organ_states in enumerate(organs):
            try:
                organ = core.memory_stack.organs()[organ_idx]
                for i, name in enumerate(organ_states):
                    try:
                        state = BorgState[name]
                        organ.cells[i].state = state
                    except KeyError:
                        continue
            except Exception:
                continue
        return {"status": "ok"}

    @app.post("/mesh/intel")
    def mesh_intel(req: MeshIntelRequest):
        data = decrypt_payload(req.token)
        payload = data.get("payload", {})
        signature = data.get("signature", "")
        if not verify_payload(payload, signature):
            return {"status": "invalid_signature"}
        peer_id = payload.get("peer_id", "UNKNOWN")
        safe_payloads = payload.get("safe", [])
        threat_payloads = payload.get("threat", [])
        for p_str in safe_payloads:
            try:
                storage.store_mesh_intel("SAFE", p_str, signature, peer_id)
            except Exception:
                continue
        for p_str in threat_payloads:
            try:
                storage.store_mesh_intel("THREAT", p_str, signature, peer_id)
            except Exception:
                continue
        return {"status": "ok"}

if TK_AVAILABLE:
    class BorgGUI:
        def __init__(self, root, core_obj: BorgCore):
            self.root = root
            self.core = core_obj
            self.root.title("BORG OS v27.1 – Full Stacking Organism")
            self.root.configure(bg="#111111")
            self.cell_frames_stack = []
            self.cell_labels_stack = []
            self.cpu_history = []
            self.mem_history = []
            self.gpu_history = []
            self.max_history = 200
            self.peer_var = tk.StringVar(value="No peers")
            self.games_var = tk.StringVar(value="None")
            self.accel_var = tk.StringVar(value="Accelerator: ?")
            frame_cells = tk.Frame(self.root, bg="#111111")
            frame_cells.pack(padx=20, pady=10)
            organ_names = ["short", "mid", "long", "threat", "behavior"]
            for row_idx, organ in enumerate(self.core.memory_stack.organs()):
                row_frames = []
                row_labels = []
                row_frame = tk.Frame(frame_cells, bg="#111111")
                row_frame.grid(row=row_idx, column=0, pady=5)
                tk.Label(row_frame, text=organ_names[row_idx], bg="#111111", fg="#ffffff", font=("Consolas", 10)).pack(side="left", padx=5)
                cells_frame = tk.Frame(row_frame, bg="#111111")
                cells_frame.pack(side="left", padx=5)
                for i in range(len(organ.cells)):
                    f = tk.Frame(cells_frame, width=40, height=40, bg="#1a1a1a",
                                 highlightthickness=2, highlightbackground="#333333")
                    f.grid(row=0, column=i, padx=2)
                    lbl = tk.Label(f, text="", bg="#1a1a1a", fg="#ffffff", font=("Consolas", 14))
                    lbl.place(relx=0.5, rely=0.5, anchor="center")
                    row_frames.append(f)
                    row_labels.append(lbl)
                self.cell_frames_stack.append(row_frames)
                self.cell_labels_stack.append(row_labels)
            frame_info = tk.Frame(self.root, bg="#111111")
            frame_info.pack(padx=20, pady=5, fill="x")
            self.info_label = tk.Label(frame_info, text="", bg="#111111", fg="#00ff66", font=("Consolas", 12))
            self.info_label.pack(side="left", padx=5)
            self.persona_label = tk.Label(frame_info, text="", bg="#111111", fg="#ffaa00", font=("Consolas", 12))
            self.persona_label.pack(side="right", padx=5)
            frame_metrics = tk.Frame(self.root, bg="#111111")
            frame_metrics.pack(padx=20, pady=5, fill="x")
            self.cpu_var = tk.StringVar(value="CPU: ?")
            self.mem_var = tk.StringVar(value="MEM: ?")
            self.gpu_var = tk.StringVar(value="GPU: ?")
            tk.Label(frame_metrics, textvariable=self.cpu_var, bg="#111111", fg="#00ff66", font=("Consolas", 11)).pack(side="left", padx=5)
            tk.Label(frame_metrics, textvariable=self.mem_var, bg="#111111", fg="#00ff66", font=("Consolas", 11)).pack(side="left", padx=5)
            tk.Label(frame_metrics, textvariable=self.gpu_var, bg="#111111", fg="#00ff66", font=("Consolas", 11)).pack(side="left", padx=5)
            tk.Label(frame_metrics, textvariable=self.accel_var, bg="#111111", fg="#00aaff", font=("Consolas", 11)).pack(side="right", padx=5)
            frame_persona = tk.Frame(self.root, bg="#111111")
            frame_persona.pack(padx=20, pady=5, fill="x")
            tk.Label(frame_persona, text="Persona:", bg="#111111", fg="#ffffff", font=("Consolas", 11)).pack(side="left", padx=5)
            self.persona_combo = ttk.Combobox(frame_persona, values=[p.name for p in BorgPersona], state="readonly")
            self.persona_combo.set(self.core.persona.name)
            self.persona_combo.pack(side="left", padx=5)
            self.persona_combo.bind("<<ComboboxSelected>>", self.on_persona_change)
            frame_command = tk.Frame(self.root, bg="#111111")
            frame_command.pack(padx=20, pady=10, fill="x")
            tk.Label(frame_command, text="Mesh peers:", bg="#111111", fg="#ffffff", font=("Consolas", 11)).pack(side="left", padx=5)
            self.peer_label = tk.Label(frame_command, textvariable=self.peer_var, bg="#111111", fg="#00aaff", font=("Consolas", 11))
            self.peer_label.pack(side="left", padx=5)
            self.refresh_peers_button = tk.Button(frame_command, text="Refresh peers", command=self.refresh_peers,
                                                  bg="#222222", fg="#ffffff", font=("Consolas", 10))
            self.refresh_peers_button.pack(side="right", padx=5)
            frame_games = tk.Frame(self.root, bg="#111111")
            frame_games.pack(padx=20, pady=5, fill="x")
            tk.Label(frame_games, text="Games detected:", bg="#111111", fg="#ffffff", font=("Consolas", 11)).pack(side="left", padx=5)
            tk.Label(frame_games, textvariable=self.games_var, bg="#111111", fg="#00ffcc", font=("Consolas", 10)).pack(side="left", padx=5)
            frame_graphs = tk.Frame(self.root, bg="#111111")
            frame_graphs.pack(padx=20, pady=10, fill="both", expand=True)
            self.canvas = tk.Canvas(frame_graphs, bg="#000000", height=200)
            self.canvas.pack(fill="both", expand=True)
            self.refresh_games_label()
            self.safe_refresh()

        def on_persona_change(self, event):
            name = self.persona_combo.get()
            try:
                new_persona = BorgPersona[name]
                core.persona = new_persona
                governor.persona = new_persona
            except KeyError:
                pass

        def refresh_peers(self):
            if PEERS:
                self.peer_var.set(", ".join(PEERS))
            else:
                self.peer_var.set("No peers")

        def refresh_games_label(self):
            rows = storage.load_games()
            names = sorted({name for _, name in rows})
            if names:
                self.games_var.set(", ".join(names[:10]) + (" ..." if len(names) > 10 else ""))
            else:
                self.games_var.set("None")
            self.root.after(5000, self.refresh_games_label)

        def safe_refresh(self):
            try:
                self.update_display()
            except Exception:
                pass
            self.root.after(250, self.safe_refresh)

        def update_display(self):
            glyphs = {
                BorgState.DOMINANT:   "🟩",
                BorgState.SUPPRESSED: "⬛",
                BorgState.FLAGGED:    "🟧",
                BorgState.TRANSITION: "🟪",
                BorgState.BORG_CORE:  "🟦",
            }
            organ_states_stack = core.get_states()
            for row_idx, states in enumerate(organ_states_stack):
                for i, state in enumerate(states):
                    f = self.cell_frames_stack[row_idx][i]
                    lbl = self.cell_labels_stack[row_idx][i]
                    if state == BorgState.DOMINANT:
                        color = "#00ff66"
                    elif state == BorgState.SUPPRESSED:
                        color = "#444444"
                    elif state == BorgState.FLAGGED:
                        color = "#ffaa00"
                    elif state == BorgState.TRANSITION:
                        color = "#ff00ff"
                    elif state == BorgState.BORG_CORE:
                        color = "#00aaff"
                    else:
                        color = "#222222"
                    f.configure(bg=color)
                    lbl.configure(text=glyphs[state], bg=color)
            self.info_label.configure(
                text=f"Tick: {core.tick_counter} | OS: {OS_NAME} | Peer: {LOCAL_PEER_ID}"
            )
            self.persona_label.configure(
                text=f"Persona: {core.persona.name}"
            )
            self.accel_var.set(f"Accelerator: {accelerator.mode.name}")
            if PSUTIL_AVAILABLE:
                cpu = psutil.cpu_percent(interval=0.0)
                mem = psutil.virtual_memory().percent
                gpu = sample_gpu_load()
                self.cpu_var.set(f"CPU: {cpu:.1f}%")
                self.mem_var.set(f"MEM: {mem:.1f}%")
                self.gpu_var.set(f"GPU: {gpu:.1f}%")
                self.cpu_history.append(cpu)
                self.mem_history.append(mem)
                self.gpu_history.append(gpu)
                if len(self.cpu_history) > self.max_history:
                    self.cpu_history.pop(0)
                    self.mem_history.pop(0)
                    self.gpu_history.pop(0)
                self.draw_graphs()

        def draw_graphs(self):
            self.canvas.delete("all")
            w = self.canvas.winfo_width()
            h = self.canvas.winfo_height()
            if w <= 0 or h <= 0:
                return
            def draw_series(series, color, offset):
                if len(series) < 2:
                    return
                max_val = max(100.0, max(series))
                scale_x = w / max(1, len(series) - 1)
                scale_y = (h / 3) / max_val
                base_y = offset * (h / 3) + (h / 3)
                points = []
                for i, v in enumerate(series):
                    x = i * scale_x
                    y = base_y - v * scale_y
                    points.append((x, y))
                for i in range(len(points) - 1):
                    x1, y1 = points[i]
                    x2, y2 = points[i+1]
                    self.canvas.create_line(x1, y1, x2, y2, fill=color, width=2)
            draw_series(self.cpu_history, "#00ff66", 0)
            draw_series(self.mem_history, "#ffaa00", 1)
            draw_series(self.gpu_history, "#00aaff", 2)
            self.canvas.create_text(10, 10, anchor="nw", text="CPU", fill="#00ff66", font=("Consolas", 10))
            self.canvas.create_text(10, h/3 + 10, anchor="nw", text="MEM", fill="#ffaa00", font=("Consolas", 10))
            self.canvas.create_text(10, 2*h/3 + 10, anchor="nw", text="GPU", fill="#00aaff", font=("Consolas", 10))

def run_cli():
    print("BORG OS NODE v27.1 (CLI MODE, Full Stacking Organism – Q-Learning + Anomaly + Secure Mesh)")
    print(f"OS: {OS_NAME}")
    print(f"KILL_MODE={KILL_MODE} DEV_MODE={DEV_MODE} MESH_ENABLED={MESH_ENABLED}")
    print("Press Ctrl+C to exit.\n")
    try:
        while True:
            organ_states_stack = core.get_states()
            line = " | ".join("".join(s.name[0] for s in organ_states) for organ_states in organ_states_stack)
            print(f"STATE: {line} | TICK: {core.tick_counter} | Persona: {core.persona.name} | Accelerator: {accelerator.mode.name} | Peer: {LOCAL_PEER_ID}")
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nCLI Borg node terminated.")

def main():
    global KILL_MODE, MESH_ENABLED, DEV_MODE
    args = sys.argv[1:]
    if "--kill-off" in args:
        KILL_MODE = "OFF"
    elif "--kill-auto" in args:
        KILL_MODE = "AUTO"
    else:
        KILL_MODE = "ASK"
    if "--mesh" in args:
        MESH_ENABLED = True
    else:
        MESH_ENABLED = False
    if "--dev" in args:
        DEV_MODE = True
    else:
        DEV_MODE = False
    discover_peers()
    if FASTAPI_AVAILABLE and "--api" in args:
        uvicorn.run(__name__ + ":app", host="0.0.0.0", port=8000, log_level="info")
        return
    if TK_AVAILABLE and "--cli" not in args:
        root = tk.Tk()
        gui = BorgGUI(root, core)
        root.mainloop()
        return
    run_cli()

if __name__ == "__main__":
    main()
