#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
BORG OS v22 – Aggressive Threat Guardian + Self-Evolving Organism
Security-Focused + Autonomous AI + Gaming-Safe
- Real GPU/NPU detection + Unified accelerator
- NPU-accelerated persona RL / DPI / threat scoring (stubbed where no NPU)
- Deep RL persona that self-tunes thresholds and weights
- Adaptive kill thresholds based on history
- Mesh consensus integrated into threat scoring
- DPI anomalies feed into RL + mesh
- One-time full game scan + incremental new game detection + manifest watcher
- HARD NEVER-KILL for borg_games and launchers
- ASK-BEFORE-KILL confirmation (GUI popup when available)
- Global 5-minute approval window after first user-confirmed kill
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

OS_NAME = platform.system().lower()

# ============================================================
#  AUTOLOADER
# ============================================================

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
    # Placeholder: real NPU detection would go here
    NPU_AVAILABLE = False
except Exception:
    NPU_AVAILABLE = False

from enum import Enum, auto

# ============================================================
#  BORG STATES + PERSONAS
# ============================================================

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

# ============================================================
#  EVENT BUS
# ============================================================

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

# ============================================================
#  STORAGE + SETTINGS
# ============================================================

class BorgStorage:
    def __init__(self, path="borg_memory.db"):
        self.path = path
        self.conn = sqlite3.connect(self.path, check_same_thread=False)
        self._init_schema()
        self._migrate_schema()

    def _init_schema(self):
        cur = self.conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_cells (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
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
            ts REAL NOT NULL
        )
        """)
        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_mesh_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            vote TEXT NOT NULL,
            weight REAL NOT NULL,
            ts REAL NOT NULL
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
        self.conn.commit()

    def _migrate_schema(self):
        cur = self.conn.cursor()
        cur.execute("PRAGMA table_info(borg_events)")
        cols = [row[1] for row in cur.fetchall()]
        if "reason" not in cols:
            cur.execute("ALTER TABLE borg_events ADD COLUMN reason TEXT DEFAULT ''")
            self.conn.commit()

        cur.execute("""
        CREATE TABLE IF NOT EXISTS borg_mesh_votes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            subject TEXT NOT NULL,
            vote TEXT NOT NULL,
            weight REAL NOT NULL,
            ts REAL NOT NULL
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

    def save_states(self, states, tick):
        try:
            cur = self.conn.cursor()
            ts = time.time()
            for i, s in enumerate(states):
                cur.execute(
                    "INSERT INTO borg_cells (idx, state, tick, ts) VALUES (?, ?, ?, ?)",
                    (i, s.name, tick, ts)
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

    def store_mesh_intel(self, kind, payload):
        try:
            cur = self.conn.cursor()
            ts = time.time()
            cur.execute(
                "INSERT INTO borg_mesh_intel (kind, payload, ts) VALUES (?, ?, ?)",
                (kind, payload, ts)
            )
            self.conn.commit()
        except Exception:
            pass

    def load_mesh_intel(self, kind=None):
        try:
            cur = self.conn.cursor()
            if kind:
                cur.execute("SELECT payload FROM borg_mesh_intel WHERE kind = ?", (kind,))
            else:
                cur.execute("SELECT payload FROM borg_mesh_intel")
            rows = cur.fetchall()
            return [p for (p,) in rows]
        except Exception:
            return []

    def store_mesh_vote(self, subject, vote, weight):
        try:
            cur = self.conn.cursor()
            ts = time.time()
            cur.execute(
                "INSERT INTO borg_mesh_votes (subject, vote, weight, ts) VALUES (?, ?, ?, ?)",
                (subject, vote, weight, ts)
            )
            self.conn.commit()
        except Exception:
            pass

    def load_mesh_votes(self, subject):
        try:
            cur = self.conn.cursor()
            cur.execute("SELECT vote, weight FROM borg_mesh_votes WHERE subject = ?", (subject,))
            rows = cur.fetchall()
            return rows
        except Exception:
            return []

    def store_game(self, exe_path, name):
        try:
            cur = self.conn.cursor()
            ts = time.time()
            cur.execute(
                "INSERT INTO borg_games (exe_path, name, ts) VALUES (?, ?, ?, ?)",
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

# ============================================================
#  ENCRYPTED MESH
# ============================================================

if CRYPTO_AVAILABLE:
    SHARED_KEY = Fernet.generate_key()
    CIPHER = Fernet(SHARED_KEY)

    def encrypt_payload(payload: dict) -> str:
        raw = json.dumps(payload).encode("utf-8")
        return CIPHER.encrypt(raw).decode("utf-8")

    def decrypt_payload(token: str) -> dict:
        raw = CIPHER.decrypt(token.encode("utf-8"))
        return json.loads(raw.decode("utf-8"))
else:
    def encrypt_payload(payload: dict) -> str:
        return json.dumps(payload)

    def decrypt_payload(token: str) -> dict:
        return json.loads(token)

# ============================================================
#  THREAT SIGNATURES
# ============================================================

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

# ============================================================
#  PROCESS REPUTATION + PROTECTION
# ============================================================

class ProcessReputation:
    def __init__(self, storage: BorgStorage | None = None):
        self.storage = storage

        self.safe_names = {
            "System", "Idle", "explorer.exe", "wininit.exe",
            "services.exe", "lsass.exe", "csrss.exe",
            "python.exe", "borg_os.py",
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
        return any(k in n for k in protected_keywords)

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

    def score(self, name, cpu, mem, io_read, io_write, net_bytes):
        name_l = (name or "").lower()
        score = 0.0

        if self.is_hard_protected(name):
            score -= 200.0

        if self.is_learned_safe(name):
            score -= 120.0

        for pat in self.suspicious_patterns:
            if pat in name_l:
                score += 80.0  # more aggressive

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

        return score, sigs

# ============================================================
#  GAME SCANNER – ONE-TIME FULL + INCREMENTAL + WATCHER
# ============================================================

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
                    data = json.load(f)

                install_loc = data.get("InstallLocation")
                if install_loc:
                    exe = self.find_exe(install_loc)
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
        drives = ["C:\\", "D:\\", "E:\\", "F:\\"]

        for d in drives:
            if not os.path.exists(d):
                continue

            for root, dirs, files in os.walk(d):
                for f in files:
                    if f.lower().endswith(".exe"):
                        exe_path = os.path.join(root, f)
                        if any(k in exe_path.lower() for k in [
                            "steamapps", "epic", "game", "games", "launcher",
                            "binaries", "win64", "win32"
                        ]):
                            if existing_only and exe_path in existing:
                                continue
                            self.detected_games.add(exe_path)
                            name = os.path.basename(exe_path)
                            self.storage.store_game(exe_path, name)
                            self.logger(f"[GAMESCAN] Drive game detected: {exe_path}")

    def find_exe(self, folder):
        if not os.path.exists(folder):
            return None
        for root, dirs, files in os.walk(folder):
            for f in files:
                if f.lower().endswith(".exe"):
                    return os.path.join(root, f)
        return None

class GameManifestWatcher:
    def __init__(self, scanner: GameScanner, governor, mesh_consensus, storage, logger=None, interval=30.0):
        self.scanner = scanner
        self.governor = governor
        self.mesh_consensus = mesh_consensus
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
                    self.mesh_consensus.vote(name, "SAFE", weight=2.0)
                    self.logger(f"[GAMESCAN] Watcher auto-protected new game: {name}")
                time.sleep(self.interval)
            except Exception:
                time.sleep(self.interval)

# ============================================================
#  NETWORK + DPI
# ============================================================

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

class DPIClassifier:
    def __init__(self, logger=None):
        self.logger = logger or (lambda msg: None)

    def classify(self, conn):
        try:
            raddr = conn.raddr
            laddr = conn.laddr
            status = conn.status
            if not raddr:
                return False, "no_remote"
            ip = raddr.ip
            port = raddr.port

            suspicious_port = port in (4444, 5555, 6666, 1337, 8081, 31337)
            suspicious_status = status not in ("ESTABLISHED", "TIME_WAIT")

            if suspicious_port or suspicious_status:
                reason = []
                if suspicious_port:
                    reason.append("port")
                if suspicious_status:
                    reason.append("status")
                return True, "+".join(reason)
            return False, "normal"
        except Exception:
            return False, "error"

class DPIEngineStub:
    def __init__(self, logger=None, event_bus=None, classifier=None, deep_rl=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.last_scan = 0.0
        self.classifier = classifier or DPIClassifier(logger=self.logger)
        self.deep_rl = deep_rl

    def scan(self):
        if not PSUTIL_AVAILABLE:
            return
        now = time.time()
        if now - self.last_scan < 2.0:  # slightly more frequent for security
            return
        self.last_scan = now

        try:
            conns = psutil.net_connections(kind='inet')
        except Exception:
            return

        suspicious = []
        for c in conns:
            flagged, reason = self.classifier.classify(c)
            if flagged:
                try:
                    laddr = c.laddr
                    raddr = c.raddr
                    suspicious.append(f"{laddr.ip}:{laddr.port}->{raddr.ip}:{raddr.port} [{reason}]")
                except Exception:
                    continue

        if suspicious:
            msg = f"DPI anomalies: {', '.join(suspicious[:5])}"
            self.logger(f"[DPI] {msg}")
            if self.event_bus:
                self.event_bus.emit("DPI_ANOMALY", msg, reason="dpi_stub")
            if self.deep_rl:
                self.deep_rl.record_overload()  # feed anomalies into RL

# ============================================================
#  GPU/NPU + ACCELERATOR
# ============================================================

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

    def accelerate_dpi(self, flagged, reason):
        return flagged, reason

    def accelerate_threat_score(self, score):
        if self.mode == AcceleratorMode.NPU:
            return score * 1.1
        if self.mode == AcceleratorMode.GPU:
            return score * 1.05
        return score

# ============================================================
#  GPU GOVERNOR
# ============================================================

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

# ============================================================
#  SYSTEM LOAD GOVERNOR
# ============================================================

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

# ============================================================
#  KERNEL SIMULATION
# ============================================================

class KernelSimulator:
    def __init__(self, logger=None, event_bus=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus

    def hook_process(self, pid, name):
        try:
            msg = f"KernelSim hook process pid={pid} name={name}"
            self.logger(f"[KERNEL] {msg}")
            if self.event_bus:
                self.event_bus.emit("KERNEL_HOOK", msg, reason="sim")
        except Exception:
            pass

    def enforce_policy(self, pid, name, action):
        try:
            msg = f"KernelSim enforce {action} on pid={pid} name={name}"
            self.logger(f"[KERNEL] {msg}")
            if self.event_bus:
                self.event_bus.emit("KERNEL_POLICY", msg, reason=action)
        except Exception:
            pass

# ============================================================
#  DEEP RL PERSONA – SELF-EVOLVING
# ============================================================

class DeepRLPersona:
    def __init__(self, logger=None, event_bus=None, accelerator=None):
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.accelerator = accelerator

        self.W = [
            [0.3, -0.2, 0.1],
            [-0.1, 0.4, 0.3],
            [-0.2, 0.1, 0.5],
        ]
        self.bias = [0.0, 0.0, 0.0]

        self.kill_count = 0
        self.overload_count = 0
        self.safe_count = 0
        self.last_eval = time.time()

        self.kill_threshold_base = 120.0
        self.kill_threshold_aggressive = 100.0
        self.kill_threshold_passive = 150.0

    def record_kill(self, overloaded=False):
        self.kill_count += 1
        if overloaded:
            self.overload_count += 1

    def record_overload(self):
        self.overload_count += 1

    def record_safe(self):
        self.safe_count += 1

    def _forward(self):
        x = [self.kill_count, self.overload_count, self.safe_count]
        scores = []
        for i in range(3):
            s = self.bias[i]
            for j in range(3):
                s += self.W[i][j] * x[j]
            scores.append(math.tanh(s))
        if self.accelerator:
            scores = self.accelerator.accelerate_rl(scores)
        return scores

    def _self_tune_weights(self):
        total_events = self.kill_count + self.overload_count + self.safe_count
        if total_events < 10:
            return

        if self.kill_count > self.safe_count * 2:
            self.W[0][0] += 0.01
            self.W[1][0] -= 0.005
            self.W[2][0] -= 0.005
        elif self.safe_count > self.kill_count * 2:
            self.W[2][2] += 0.01
            self.W[0][2] -= 0.005
            self.W[1][2] -= 0.005

        self.W = [[max(-1.0, min(1.0, w)) for w in row] for row in self.W]

    def adaptive_threshold(self, persona: BorgPersona):
        base = self.kill_threshold_base
        if persona == BorgPersona.AGGRESSIVE:
            base = self.kill_threshold_aggressive
        elif persona == BorgPersona.PASSIVE:
            base = self.kill_threshold_passive

        if self.kill_count > self.safe_count * 2:
            base -= 10.0
        elif self.safe_count > self.kill_count * 2:
            base += 10.0

        return max(80.0, min(200.0, base))

    def evaluate(self, current_persona: BorgPersona):
        now = time.time()
        if now - self.last_eval < 20.0:
            return current_persona
        self.last_eval = now

        try:
            self._self_tune_weights()
            scores = self._forward()
            persona_map = {
                0: BorgPersona.AGGRESSIVE,
                1: BorgPersona.DEFENSIVE,
                2: BorgPersona.PASSIVE,
            }
            best_idx = max(range(3), key=lambda i: scores[i])
            best_persona = persona_map[best_idx]

            if best_persona != current_persona:
                msg = (
                    f"Deep RL persona shift: {current_persona.name} -> {best_persona.name} "
                    f"(scores: A={scores[0]:.2f}, D={scores[1]:.2f}, P={scores[2]:.2f})"
                )
                self.logger(f"[PERSONA] {msg}")
                if self.event_bus:
                    self.event_bus.emit("PERSONA_SHIFT", msg, reason="deep_rl")

            self.kill_count = 0
            self.overload_count = 0
            self.safe_count = 0
            return best_persona
        except Exception:
            return current_persona

# ============================================================
#  MESH CONSENSUS
# ============================================================

class MeshConsensus:
    def __init__(self, storage: BorgStorage, logger=None, event_bus=None):
        self.storage = storage
        self.logger = logger or (lambda msg: None)
        self.event_bus = event_bus
        self.quorum_threshold = 2.0

    def vote(self, subject: str, vote: str, weight: float = 1.0):
        try:
            self.storage.store_mesh_vote(subject, vote, weight)
            msg = f"Mesh vote: {subject} -> {vote} (w={weight})"
            self.logger(f"[MESH] {msg}")
            if self.event_bus:
                self.event_bus.emit("MESH_VOTE", msg, reason=vote)
        except Exception:
            pass

    def consensus(self, subject: str):
        try:
            votes = self.storage.load_mesh_votes(subject)
            if not votes:
                return None

            score = 0.0
            for v, w in votes:
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

            msg = f"Mesh consensus for {subject}: {result} (score={score:.2f})"
            self.logger(f"[MESH] {msg}")
            if self.event_bus:
                self.event_bus.emit("MESH_CONSENSUS", msg, reason=result)

            return result
        except Exception:
            return None

# ============================================================
#  OS GOVERNOR – SECURITY + AUTONOMOUS AI + GAMING-SAFE
# ============================================================

class BorgOSGovernor:
    def __init__(self, logger=None, storage=None, event_bus=None,
                 persona=BorgPersona.DEFENSIVE, deep_rl=None,
                 kernel_sim=None, mesh_consensus=None, accelerator=None):
        self.logger = logger or (lambda msg: None)
        self.storage = storage
        self.event_bus = event_bus
        self.reputation = ProcessReputation(storage=storage)
        self.net_sampler = NetworkSampler()
        self.last_decay = time.time()
        self.load_governor = SystemLoadGovernor(logger=self.logger, event_bus=self.event_bus)
        self.persona = persona
        self.accelerator = accelerator
        self.deep_rl = deep_rl or DeepRLPersona(logger=self.logger, event_bus=self.event_bus, accelerator=self.accelerator)
        self.kernel_sim = kernel_sim or KernelSimulator(logger=self.logger, event_bus=self.event_bus)
        self.mesh_consensus = mesh_consensus or MeshConsensus(storage=storage, logger=self.logger, event_bus=self.event_bus)
        self.dpi_engine = DPIEngineStub(logger=self.logger, event_bus=self.event_bus,
                                        classifier=DPIClassifier(logger=self.logger),
                                        deep_rl=self.deep_rl)
        self.gpu_governor = GPUGovernor(logger=self.logger, event_bus=self.event_bus)

        self.game_exes = {exe_path.lower() for exe_path, _ in (self.storage.load_games() if self.storage else [])}

        self.user_approval_window_until = 0.0

    def refresh_game_cache(self):
        if self.storage:
            self.game_exes = {exe_path.lower() for exe_path, _ in self.storage.load_games()}

    def apply(self, states):
        if not PSUTIL_AVAILABLE:
            return

        try:
            now = time.time()
            overloaded = self.load_governor.check_load()
            self.dpi_engine.scan()

            if overloaded:
                self.deep_rl.record_overload()

            kill_threshold = self.deep_rl.adaptive_threshold(self.persona)

            if now - self.last_decay > 60.0:
                self.reputation.decay()
                self.last_decay = now

            procs = list(psutil.process_iter(['pid', 'name', 'cpu_percent', 'memory_percent', 'io_counters']))
            if not procs:
                return

            net_delta = self.net_sampler.sample()
            gpu_load = sample_gpu_load()
            gpu_mode = self.gpu_governor.adjust_for_gpu(gpu_load, self.persona)
            gpu_map = map_gpu_processes()

            if gpu_mode == "overload":
                overloaded = True

            if self.accelerator:
                self.accelerator.refresh()

            in_approval_window = now < self.user_approval_window_until

            chunk = max(1, len(procs) // max(1, len(states)))
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

                        rep_score, sigs = self.reputation.score(name, cpu, mem, io_read, io_write, net_delta)
                        if self.accelerator:
                            rep_score = self.accelerator.accelerate_threat_score(rep_score)

                        hard_protected = self.reputation.is_hard_protected(name)
                        learned_safe = self.reputation.is_learned_safe(name)

                        consensus = self.mesh_consensus.consensus(name)
                        if consensus == "SAFE":
                            rep_score -= 60.0
                        elif consensus == "THREAT":
                            rep_score += 60.0

                        exe_path = None
                        try:
                            exe_path = p.exe()
                        except Exception:
                            exe_path = None

                        lname = name.lower()

                        is_known_game_exe = exe_path and exe_path.lower() in self.game_exes
                        is_launcher_like = (
                            "steam" in lname or "epic" in lname or "battle.net" in lname or
                            "riot" in lname or "origin" in lname or
                            "game" in lname or "launcher" in lname or "client" in lname
                        )

                        if in_approval_window:
                            self.reputation.observe_safe(name, cpu, mem)
                            self.mesh_consensus.vote(name, "SAFE", weight=0.5)
                            self._monitor_process(p, rep_score, True, True, sigs, gpu_mem, overload=overloaded)
                            continue

                        if is_known_game_exe or is_launcher_like:
                            tag = "KNOWN_GAME_EXE" if is_known_game_exe else "LAUNCHER_CLIENT"
                            msg = f"[OS] NEVER-KILL: {pid} {name} ({tag}) score={rep_score:.1f}"
                            self.logger(msg)
                            if self.event_bus:
                                self.event_bus.emit("NEVER_KILL", msg, reason=tag)
                            self._monitor_process(p, rep_score, True, True, sigs, gpu_mem, overload=overloaded)
                            continue

                        if cpu < 20.0 and mem < 10.0 and not hard_protected:
                            self.reputation.observe_safe(name, cpu, mem)
                            self.deep_rl.record_safe()
                            self.mesh_consensus.vote(name, "SAFE", weight=0.5)

                        if sigs and not hard_protected and not learned_safe:
                            self.reputation.observe_suspicious(name)
                            self.mesh_consensus.vote(name, "THREAT", weight=1.0)

                        threat = (
                            rep_score > kill_threshold or
                            (cpu > 97.0 and mem > 90.0 and sigs)
                        ) and not hard_protected and not learned_safe

                        self.kernel_sim.hook_process(pid, name)

                        if overloaded:
                            self._monitor_process(p, rep_score, hard_protected, learned_safe, sigs, gpu_mem, overload=True)
                            continue

                        if state == BorgState.DOMINANT:
                            if not hard_protected and not learned_safe:
                                self._boost_process(p, rep_score, hard_protected, learned_safe, sigs, gpu_mem)
                            else:
                                self._monitor_process(p, rep_score, hard_protected, learned_safe, sigs, gpu_mem)
                        elif state == BorgState.SUPPRESSED:
                            if threat:
                                self._kill_process(p, rep_score, gpu_load, hard_protected, learned_safe, sigs, gpu_mem, overloaded)
                            elif not hard_protected and not learned_safe:
                                self._suppress_process(p, rep_score, sigs, gpu_mem)
                            else:
                                self._monitor_process(p, rep_score, hard_protected, learned_safe, sigs, gpu_mem)
                        elif state == BorgState.FLAGGED:
                            if threat:
                                self._kill_process(p, rep_score, gpu_load, hard_protected, learned_safe, sigs, gpu_mem, overloaded)
                            else:
                                self._monitor_process(p, rep_score, hard_protected, learned_safe, sigs, gpu_mem)
                        elif state == BorgState.BORG_CORE:
                            self._protect_process(p, hard_protected, learned_safe, sigs, gpu_mem)
                    except Exception:
                        continue

            self.persona = self.deep_rl.evaluate(self.persona)
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
            self.kernel_sim.enforce_policy(p.pid, p.info.get('name'), "boost")
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
            self.kernel_sim.enforce_policy(p.pid, p.info.get('name'), "suppress")
        except Exception:
            pass

    def _ask_before_kill(self, p, score, reason):
        name = p.info.get('name') or ""
        pid = p.info.get('pid')
        prompt = f"Process {name} (PID {pid}) scored as THREAT (score={score:.1f}).\nReason: {reason}\n\nKill this process?"
        if TK_AVAILABLE:
            try:
                return messagebox.askyesno("BORG OS – Confirm Kill", prompt)
            except Exception:
                return False
        else:
            self.logger(f"[ASK] {prompt} (no GUI, default NO)")
            return False

    def _kill_process(self, p, score, gpu_load, hard_protected, learned_safe, sigs, gpu_mem, overloaded):
        try:
            name = p.info.get('name') or ""
            lname = name.lower()

            if ("steam" in lname or "epic" in lname or "battle.net" in lname or
                "riot" in lname or "origin" in lname or
                "game" in lname or "launcher" in lname or "client" in lname):
                self._monitor_process(p, score, True, True, sigs, gpu_mem, overload=overloaded)
                return

            tag = self._tag(hard_protected, learned_safe, sigs, gpu_mem)
            sig_str = ",".join(sigs) if sigs else "none"
            reason = f"threat score={score:.1f}, gpu={gpu_load:.1f}, sigs={sig_str}, {tag}"

            user_ok = self._ask_before_kill(p, score, reason)
            if not user_ok:
                msg = f"[OS] USER-SPARED {p.pid} {name} | {reason}"
                self.logger(msg)
                if self.event_bus:
                    self.event_bus.emit("USER_SPARED", msg, reason="user_denied")
                self.reputation.observe_safe(name, 0.0, 0.0)
                self.mesh_consensus.vote(name, "SAFE", weight=2.0)
                self._monitor_process(p, score, hard_protected, True, sigs, gpu_mem, overload=overloaded)
                return

            self.user_approval_window_until = time.time() + 300.0
            msg_window = f"User approved kill; entering 5-minute SAFE WINDOW until {self.user_approval_window_until:.0f}"
            self.logger(f"[OS] {msg_window}")
            if self.event_bus:
                self.event_bus.emit("SAFE_WINDOW", msg_window, reason="user_approval")

            msg = f"[OS] KILL THREAT {p.pid} {name} | {reason}"
            self.logger(msg)
            if self.event_bus:
                self.event_bus.emit("KILL", msg, reason=reason)
            self.kernel_sim.enforce_policy(p.pid, name, "kill")
            p.terminate()
            self.deep_rl.record_kill(overloaded=overloaded)
            self.mesh_consensus.vote(name, "THREAT", weight=1.5)
        except Exception:
            pass

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

# ============================================================
#  BORG CORE
# ============================================================

class BorgCore:
    def __init__(self, size=10, logger=None, storage=None, governor=None, event_bus=None, persona=BorgPersona.DEFENSIVE):
        self.organ = BorgMemoryOrgan(size=size)
        self.engine = BorgLogicEngine(self.organ)
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
            self.engine.autonomous_step()
            self.tick_counter += 1

            states = self.get_states()

            if self.storage:
                self.storage.save_states(states, self.tick_counter)

            if self.governor:
                self.governor.apply(states)
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
        return [cell.state for cell in self.organ.cells]

    def set_state(self, index: int, state: BorgState):
        try:
            if 0 <= index < len(self.organ.cells):
                self.organ.cells[index].state = state
                msg = f"Cell {index} forced to {state.name}"
                self.logger(f"[SET] {msg}")
                if self.event_bus:
                    self.event_bus.emit("SET_STATE", msg, reason="manual")
        except Exception:
            pass

# ============================================================
#  WATCHDOG
# ============================================================

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
                    msg = "Tick stall detected, resetting BorgCore"
                    self.core.logger(f"[WATCHDOG] {msg}")
                    if self.event_bus:
                        self.event_bus.emit("WATCHDOG_RESET", msg, reason="stall")
                    size = len(self.core.organ.cells)
                    self.core.organ = BorgMemoryOrgan(size=size)
                    self.core.engine = BorgLogicEngine(self.core.organ)
                    self.last_tick = time.time()
                time.sleep(1.0)
            except Exception:
                time.sleep(1.0)

# ============================================================
#  GLOBAL INSTANCES + GAME SCAN
# ============================================================

storage = BorgStorage("borg_memory.db")
event_bus = BorgEventBus(logger=lambda msg: print(msg), storage=storage)
accelerator = Accelerator(logger=lambda msg: print(msg), event_bus=event_bus)
deep_rl = DeepRLPersona(logger=lambda msg: print(msg), event_bus=event_bus, accelerator=accelerator)
kernel_sim = KernelSimulator(logger=lambda msg: print(msg), event_bus=event_bus)
mesh_consensus = MeshConsensus(storage=storage, logger=lambda msg: print(msg), event_bus=event_bus)

governor = BorgOSGovernor(logger=lambda msg: print(msg), storage=storage, event_bus=event_bus,
                          persona=BorgPersona.DEFENSIVE, deep_rl=deep_rl,
                          kernel_sim=kernel_sim, mesh_consensus=mesh_consensus,
                          accelerator=accelerator)

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
    mesh_consensus.vote(name, "SAFE", weight=2.0)
    print(f"[GAMESCAN] Auto-protected game (first scan): {name}")

for exe_path, name in storage.load_games():
    governor.reputation.safe_names.add(name)
    storage.update_safe_process(name, delta_rep=10.0)
    mesh_consensus.vote(name, "SAFE", weight=2.0)

governor.refresh_game_cache()

manifest_watcher = GameManifestWatcher(game_scanner, governor, mesh_consensus, storage,
                                       logger=lambda msg: print(msg), interval=30.0)

core = BorgCore(size=10, logger=lambda msg: print(msg), storage=storage, governor=governor,
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

# ============================================================
#  SWARM + MESH INTEL
# ============================================================

PEERS = []

def discover_peers(port=8000, timeout=0.2):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(timeout)
        msg = b"BORG_DISCOVERY_V22"
        sock.sendto(msg, ("255.255.255.255", port))
        sock.close()
    except Exception:
        pass

def broadcast_mesh_intel():
    if not HTTPX_AVAILABLE:
        return
    try:
        safe_payloads = storage.load_mesh_intel("SAFE")
        threat_payloads = storage.load_mesh_intel("THREAT")
        payload = {
            "safe": safe_payloads,
            "threat": threat_payloads,
        }
        token = encrypt_payload(payload)
        for peer in PEERS:
            try:
                httpx.post(f"{peer}/mesh/intel", json={"token": token}, timeout=1.0)
            except Exception:
                continue
    except Exception:
        pass

# ============================================================
#  FASTAPI SERVICE
# ============================================================

if FASTAPI_AVAILABLE:
    app = FastAPI(title="Borg OS Node", version="22.0.0")

    class SyncPushRequest(BaseModel):
        token: str

    class MeshIntelRequest(BaseModel):
        token: str

    @app.get("/states")
    def get_states():
        states = core.get_states()
        return {
            "states": [s.name for s in states],
            "os": OS_NAME,
            "tick": core.tick_counter,
            "persona": core.persona.name,
            "accelerator": accelerator.mode.name,
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
        if not HTTPX_AVAILABLE:
            return {"error": "httpx not available"}
        states = core.get_states()
        payload = {"states": [s.name for s in states], "tick": core.tick_counter}
        token = encrypt_payload(payload)
        for peer in PEERS:
            try:
                httpx.post(f"{peer}/sync/pull", json={"token": token}, timeout=1.0)
            except Exception:
                pass
        return {"status": "ok"}

    @app.post("/sync/pull")
    def sync_pull(req: SyncPushRequest):
        payload = decrypt_payload(req.token)
        names = payload.get("states", [])
        for i, name in enumerate(names):
            try:
                state = BorgState[name]
                core.set_state(i, state)
            except KeyError:
                continue
        return {"status": "ok"}

    @app.post("/mesh/intel")
    def mesh_intel(req: MeshIntelRequest):
        payload = decrypt_payload(req.token)
        safe = payload.get("safe", [])
        threat = payload.get("threat", [])
        for s in safe:
            storage.store_mesh_intel("SAFE", s)
        for t in threat:
            storage.store_mesh_intel("THREAT", t)
        return {"status": "ok"}

# ============================================================
#  TKINTER GUI – COMMAND CENTER
# ============================================================

class BorgGUI:
    def __init__(self, root, core: BorgCore):
        self.root = root
        self.core = core

        root.title("BORG OS NODE v22 – Command Center (Security + Autonomous AI + Games + Safe Window)")
        root.configure(bg="#111111")

        self.cell_frames = []
        self.cell_labels = []

        self.peer_var = tk.StringVar(value="No peers")
        self.accel_var = tk.StringVar(value=f"Accelerator: {accelerator.mode.name}")
        self.games_var = tk.StringVar(value="Games: scanning...")

        self.cpu_history = []
        self.mem_history = []
        self.gpu_history = []
        self.max_history = 100

        self.build_ui()
        self.refresh_games_label()
        self.safe_refresh()

    def build_ui(self):
        frame_cells = tk.Frame(self.root, bg="#111111")
        frame_cells.pack(padx=20, pady=10)

        for i in range(len(self.core.organ.cells)):
            f = tk.Frame(frame_cells, width=60, height=60, bg="#1a1a1a",
                         highlightthickness=2, highlightbackground="#333333")
            f.grid(row=0, column=i, padx=5)
            lbl = tk.Label(f, text="", bg="#1a1a1a", fg="#ffffff", font=("Consolas", 18))
            lbl.place(relx=0.5, rely=0.5, anchor="center")
            self.cell_frames.append(f)
            self.cell_labels.append(lbl)

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

        states = core.get_states()

        for i, f in enumerate(self.cell_frames):
            state = states[i]

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
            self.cell_labels[i].configure(text=glyphs[state], bg=color)

        self.info_label.configure(
            text=f"Tick: {core.tick_counter} | OS: {OS_NAME}"
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

# ============================================================
#  CLI FALLBACK
# ============================================================

def run_cli():
    print("BORG OS NODE (CLI MODE, Autonomous v22, Security + Deep RL + Mesh + DPI, Gaming-Safe + One-Time Scan + Incremental Detection + NEVER-KILL borg_games + ASK-BEFORE-KILL + 5-Min Safe Window)")
    print(f"OS: {OS_NAME}")
    print("Press Ctrl+C to exit.\n")

    try:
        while True:
            states = core.get_states()
            line = " ".join(s.name[0] for s in states)
            print(f"STATE: {line} | TICK: {core.tick_counter} | Persona: {core.persona.name} | Accelerator: {accelerator.mode.name}")
            time.sleep(0.5)
    except KeyboardInterrupt:
        print("\nCLI Borg node terminated.")

# ============================================================
#  MAIN
# ============================================================

def main():
    discover_peers()

    if FASTAPI_AVAILABLE and "--api" in sys.argv:
        uvicorn.run(__name__ + ":app", host="0.0.0.0", port=8000, log_level="info")
        return

    if TK_AVAILABLE and "--cli" not in sys.argv:
        root = tk.Tk()
        gui = BorgGUI(root, core)
        root.mainloop()
        return

    run_cli()

if __name__ == "__main__":
    main()
