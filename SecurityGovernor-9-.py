#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Borg Sentinel AI — SecurityGovernor Command Center
==================================================

Defensive-only local security governor with:

- Multi-source telemetry (process, network, event log, file integrity, GPU, VRAM)
- BorgAI defensive online learning
- Deterministic anomaly scoring
- Incident correlation and clustering
- Response modes:
    * full_auto   — AI can act (within safe rules)
    * semi_ai     — AI suggests, you approve/override
    * full_manual — AI only observes/logs
- Per-profile modes:
    * Gaming
    * Browsing
    * High-Security
- Auto-quarantine (safe, non-destructive)
- Timeline replay
- Incident tagging
- AI explanations (“why this is suspicious”)
- Threat matrix + persona panel
- GPU governor + VRAM entropy graph
- Right-click context menu (overrides, threat assignment, tagging, export, correlated view)
- Incident heatmaps
- Process lineage graphs
- GPU curve visualizer
- Threat intelligence import (defensive-only, optional online)
- Auto-tagging rules (basic, type/severity-based)
- AI-generated remediation suggestions
- Capability-aware boot:
    * Scans system at startup
    * Decides which modules to enable (GPU, event log, GUI, etc.)
    * Works with or without GPU, on Windows or non-Windows

Safety boundary:
- No exploit, credential theft, persistence, unauthorized scanning, or offensive actions.
"""

from __future__ import annotations

import ctypes
import os
import sys
import importlib
import time
import json
import socket
import hashlib
import logging
import threading
import queue
import re
import sqlite3
import math
import traceback
import platform
from pathlib import Path
from datetime import datetime, timezone
from collections import Counter, defaultdict, deque
from typing import Any, Optional

APP_NAME = "Borg Sentinel AI"
APP_VERSION = "8.1"
BASE_DIR = Path(os.path.abspath(os.getcwd()))
DATA_DIR = BASE_DIR / "borg_data"
LOG_DIR = DATA_DIR / "logs"
PLUGIN_DIR = DATA_DIR / "plugins"
INCIDENT_LOG = LOG_DIR / "security_incidents.jsonl"
DB_PATH = DATA_DIR / "borg_memory.sqlite3"
CONFIG_PATH = DATA_DIR / "borg_config.json"

DATA_DIR.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
PLUGIN_DIR.mkdir(parents=True, exist_ok=True)

LOG = logging.getLogger("BorgSentinel")
LOG.setLevel(logging.INFO)
if not LOG.handlers:
    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
    LOG.addHandler(handler)


def ensure_package(pkg_name: str, import_name: str | None = None) -> bool:
    name = import_name or pkg_name
    try:
        importlib.import_module(name)
        return True
    except ImportError:
        LOG.warning("Optional package unavailable: %s", pkg_name)
        return False


HAS_PSUTIL = ensure_package("psutil")
try:
    import psutil
except Exception:
    psutil = None

HAS_WIN32 = False
try:
    if os.name == "nt":
        import win32evtlog
        HAS_WIN32 = True
    else:
        win32evtlog = None
except Exception:
    win32evtlog = None

try:
    import tkinter as tk
    from tkinter import ttk, messagebox, filedialog
except Exception:
    tk = None
    ttk = None
    messagebox = None
    filedialog = None

try:
    import pynvml
except Exception:
    pynvml = None

try:
    import urllib.request
except Exception:
    urllib = None


def is_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def ensure_admin() -> None:
    if os.name != "nt" or is_admin():
        return
    try:
        script = os.path.abspath(sys.argv[0])
        params = " ".join(f'"{a}"' for a in sys.argv[1:])
        rc = ctypes.windll.shell32.SecuteExecuteW(
            None, "runas", sys.executable, f'"{script}" {params}', None, 1
        )
        if rc <= 32:
            LOG.warning("Elevation request was not accepted (code=%s).", rc)
            return
        raise SystemExit
    except SystemExit:
        raise
    except Exception as exc:
        LOG.warning("Elevation unavailable: %s", exc)


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def safe_json(obj: Any) -> Any:
    try:
        json.dumps(obj)
        return obj
    except Exception:
        if isinstance(obj, dict):
            return {str(k): safe_json(v) for k, v in obj.items()}
        if isinstance(obj, (list, tuple)):
            return [safe_json(v) for v in obj]
        return str(obj)


def safe_read_file(path: str | Path, max_bytes: int = 2_000_000) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    try:
        with p.open("rb") as fh:
            return fh.read(max_bytes).decode("utf-8", errors="replace")
    except Exception as exc:
        LOG.warning("Read failed for %s: %s", p, exc)
        return ""


def hash_file(path: str | Path) -> str:
    p = Path(path)
    if not p.exists():
        return ""
    h = hashlib.sha256()
    try:
        with p.open("rb") as fh:
            while True:
                block = fh.read(1024 * 1024)
                if not block:
                    break
                h.update(block)
        return h.hexdigest()
    except Exception as exc:
        LOG.warning("Hash failed for %s: %s", p, exc)
        return ""


def canonical_text(value: Any) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip().lower()


def clamp(value: float, low: float = 0.0, high: float = 100.0) -> float:
    return max(low, min(high, value))


class CapabilityDetector:
    """
    Scans the system at startup and decides which modules to enable:

    - GPU telemetry (requires pynvml + NVIDIA GPU)
    - Event log (Windows + win32evtlog)
    - GUI (tkinter available)
    - Threat intel (urllib + URL configured)
    """

    def __init__(self):
        self.os = os.name
        self.platform = platform.system()
        self.has_psutil = psutil is not None
        self.has_win32 = HAS_WIN32
        self.has_gui = tk is not None and ttk is not None
        self.has_pynvml = pynvml is not None
        self.gpu_available = False
        self.gpu_count = 0
        self._detect_gpu()

    def _detect_gpu(self):
        if not self.has_pynvml:
            return
        try:
            pynvml.nvmlInit()
            count = pynvml.nvmlDeviceGetCount()
            self.gpu_count = count
            self.gpu_available = count > 0
            LOG.info("GPU capability: %s devices detected.", count)
        except Exception as exc:
            LOG.info("GPU telemetry unavailable: %s", exc)
            self.gpu_available = False
            self.gpu_count = 0

    def apply_to_config(self, cfg: "SecurityConfig"):
        # Base defaults
        cfg.enable_process_monitor = self.has_psutil
        cfg.enable_network_monitor = self.has_psutil
        cfg.enable_dependency_scan = True
        cfg.enable_file_integrity = True

        # Event log only on Windows with win32evtlog
        cfg.enable_event_log_monitor = self.has_win32 and self.os == "nt"

        # GPU telemetry only if GPU exists
        cfg.enable_gpu_telemetry = self.gpu_available

        # VRAM scanning synthetic; can run even without GPU, but we tie it to GPU availability
        cfg.gpu_vram_scan_enabled = self.gpu_available

        # GUI only if tkinter is available
        cfg.gui_enabled = self.has_gui

        LOG.info(
            "Capability scan: os=%s platform=%s psutil=%s win32=%s gui=%s gpu_available=%s gpu_count=%s",
            self.os,
            self.platform,
            self.has_psutil,
            self.has_win32,
            self.has_gui,
            self.gpu_available,
            self.gpu_count,
        )


class SecurityConfig:
    def __init__(self):
        self.poll_interval_seconds = 5

        self.enable_dependency_scan = True
        self.enable_network_monitor = True
        self.enable_process_monitor = True
        self.enable_event_log_monitor = True
        self.enable_file_integrity = True
        self.enable_gpu_telemetry = True
        self.enable_plugins = True
        self.enable_learning = True
        self.enable_correlation = True

        self.learning_min_samples = 5
        self.score_threshold_incident = 50
        self.score_threshold_critical = 80

        self.response_mode = "semi_ai"
        self.profile_mode = "browsing"

        self.enable_auto_terminate = False
        self.enable_quarantine = True
        self.response_dry_run = True

        self.gpu_temp_critical = 85.0
        self.gpu_mem_util_critical = 0.95

        self.project_root = str(BASE_DIR)
        self.incident_log_path = str(INCIDENT_LOG)
        self.plugin_dir = str(PLUGIN_DIR)
        self.database_path = str(DB_PATH)

        self.gui_enabled = True
        self.gui_refresh_interval = 2.0

        self.gpu_governor_enabled = True
        self.gpu_governor_safe_undervolt_margin = 0.05
        self.gpu_governor_curve_points = 64

        self.swarm_enabled = True
        self.swarm_node_id = socket.gethostname()
        self.swarm_cluster_name = "local-simulated-swarm"

        self.gui_animated_overlays = True
        self.gui_threat_matrix_enabled = True
        self.gui_persona_panel_enabled = True

        self.gpu_vram_scan_enabled = True
        self.gpu_vram_scan_sample_bytes = 256 * 1024

        self.enable_threat_intel = True
        self.threat_intel_url = ""  # optional safe public feed URL
        self.threat_intel_refresh_minutes = 60

        self.auto_tagging_enabled = True

        if os.name == "nt":
            self.hosts_file = os.path.join(
                os.environ.get("SystemRoot", r"C:\Windows"),
                r"System32\drivers\etc\hosts",
            )
        else:
            self.hosts_file = "/etc/hosts"

        self.file_integrity_paths = [self.hosts_file]

        self.suspicious_webhook_patterns = [
            r"https://hooks\.slack\.com/services/",
            r"https://api\.telegram\.org/bot",
        ]
        self.suspicious_blockchain_patterns = [
            r"sepolia",
            r"ethereum",
            r"eth",
        ]
        self.suspicious_package_names = [
            "indexed-btree",
            "btree-core",
            "ordered-kv-index",
            "priority-slot-queue",
            "btree-lru-cache",
            "btree-leaderboard",
            "btree-range-store",
            "btree-time-index",
            "neighbor-key-map",
            "sliding-score-window",
        ]

    def apply_profile(self):
        mode = self.profile_mode
        if mode == "gaming":
            self.score_threshold_incident = 60
            self.score_threshold_critical = 85
            self.response_mode = "semi_ai"
        elif mode == "browsing":
            self.score_threshold_incident = 50
            self.score_threshold_critical = 80
            self.response_mode = "semi_ai"
        elif mode == "high_security":
            self.score_threshold_incident = 40
            self.score_threshold_critical = 70
            self.response_mode = "full_auto"

    def save(self) -> None:
        payload = {
            k: v for k, v in self.__dict__.items()
            if isinstance(v, (str, int, float, bool, list, dict))
        }
        try:
            Path(CONFIG_PATH).write_text(json.dumps(payload, indent=2), encoding="utf-8")
        except Exception as exc:
            LOG.warning("Config save failed: %s", exc)

    def load(self) -> None:
        if not CONFIG_PATH.exists():
            self.save()
            return
        try:
            data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            for key, value in data.items():
                if hasattr(self, key):
                    setattr(self, key, value)
        except Exception as exc:
            LOG.warning("Config load failed: %s", exc)
        self.apply_profile()


def load_security_config() -> SecurityConfig:
    cfg = SecurityConfig()
    cfg.load()
    return cfg


SEC_CFG = load_security_config()
CAPS = CapabilityDetector()
CAPS.apply_to_config(SEC_CFG)


class BorgMemory:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.lock = threading.RLock()
        self._init_db()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=10)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self.lock, self._connect() as conn:
            conn.executescript(
                """
                CREATE TABLE IF NOT EXISTS feature_memory (
                    feature TEXT PRIMARY KEY,
                    observations INTEGER NOT NULL DEFAULT 0,
                    anomaly_sum REAL NOT NULL DEFAULT 0,
                    last_seen TEXT,
                    metadata TEXT
                );

                CREATE TABLE IF NOT EXISTS incidents (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    severity TEXT,
                    score REAL,
                    finding_type TEXT,
                    fingerprint TEXT,
                    payload TEXT
                );

                CREATE TABLE IF NOT EXISTS actions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT,
                    action TEXT,
                    mode TEXT,
                    result TEXT,
                    fingerprint TEXT
                );

                CREATE TABLE IF NOT EXISTS incident_overrides (
                    fingerprint TEXT PRIMARY KEY,
                    override TEXT
                );

                CREATE TABLE IF NOT EXISTS incident_threat_labels (
                    fingerprint TEXT PRIMARY KEY,
                    label TEXT
                );

                CREATE TABLE IF NOT EXISTS incident_tags (
                    fingerprint TEXT PRIMARY KEY,
                    tags TEXT
                );

                CREATE TABLE IF NOT EXISTS quarantine (
                    fingerprint TEXT PRIMARY KEY,
                    reason TEXT,
                    timestamp TEXT
                );

                CREATE TABLE IF NOT EXISTS threat_intel (
                    key TEXT PRIMARY KEY,
                    value TEXT
                );
                """
            )

    def observe(self, feature: str, anomaly: float, metadata: dict | None = None):
        feature = canonical_text(feature)[:500]
        if not feature:
            return
        with self.lock, self._connect() as conn:
            row = conn.execute(
                "SELECT observations, anomaly_sum FROM feature_memory WHERE feature=?",
                (feature,),
            ).fetchone()
            if row:
                obs = int(row["observations"]) + 1
                total = float(row["anomaly_sum"]) + float(anomaly)
                conn.execute(
                    """UPDATE feature_memory
                       SET observations=?, anomaly_sum=?, last_seen=?, metadata=?
                       WHERE feature=?""",
                    (obs, total, now_iso(), json.dumps(safe_json(metadata or {})), feature),
                )
            else:
                conn.execute(
                    """INSERT INTO feature_memory
                       (feature, observations, anomaly_sum, last_seen, metadata)
                       VALUES (?, ?, ?, ?, ?)""",
                    (feature, 1, float(anomaly), now_iso(),
                     json.dumps(safe_json(metadata or {}))),
                )

    def feature_stats(self, feature: str) -> tuple[int, float]:
        feature = canonical_text(feature)[:500]
        with self.lock, self._connect() as conn:
            row = conn.execute(
                "SELECT observations, anomaly_sum FROM feature_memory WHERE feature=?",
                (feature,),
            ).fetchone()
        if not row:
            return 0, 0.0
        return int(row["observations"]), float(row["anomaly_sum"])

    def save_incident(self, record: dict):
        finding = record.get("finding", {})
        fp = fingerprint_finding(finding)
        with self.lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO incidents
                   (timestamp, severity, score, finding_type, fingerprint, payload)
                   VALUES (?, ?, ?, ?, ?, ?)""",
                (
                    record.get("timestamp", now_iso()),
                    record.get("severity", ""),
                    float(record.get("score", 0)),
                    finding.get("type", ""),
                    fp,
                    json.dumps(safe_json(record)),
                ),
            )

    def save_action(self, action: str, mode: str, result: str, fingerprint: str):
        with self.lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO actions(timestamp, action, mode, result, fingerprint)
                   VALUES (?, ?, ?, ?, ?)""",
                (now_iso(), action, mode, result, fingerprint),
            )

    def set_manual_override(self, fingerprint: str, override: Optional[str]):
        override = override or None
        with self.lock, self._connect() as conn:
            if override is None:
                conn.execute("DELETE FROM incident_overrides WHERE fingerprint=?", (fingerprint,))
            else:
                conn.execute(
                    """INSERT INTO incident_overrides(fingerprint, override)
                       VALUES(?, ?)
                       ON CONFLICT(fingerprint) DO UPDATE SET override=excluded.override""",
                    (fingerprint, override),
                )

    def set_threat_label(self, fingerprint: str, label: Optional[str]):
        label = label or None
        with self.lock, self._connect() as conn:
            if label is None:
                conn.execute("DELETE FROM incident_threat_labels WHERE fingerprint=?", (fingerprint,))
            else:
                conn.execute(
                    """INSERT INTO incident_threat_labels(fingerprint, label)
                       VALUES(?, ?)
                       ON CONFLICT(fingerprint) DO UPDATE SET label=excluded.label""",
                    (fingerprint, label),
                )

    def set_tags(self, fingerprint: str, tags: list[str]):
        tags_str = ",".join(sorted(set(t.strip() for t in tags if t.strip())))
        with self.lock, self._connect() as conn:
            if not tags_str:
                conn.execute("DELETE FROM incident_tags WHERE fingerprint=?", (fingerprint,))
            else:
                conn.execute(
                    """INSERT INTO incident_tags(fingerprint, tags)
                       VALUES(?, ?)
                       ON CONFLICT(fingerprint) DO UPDATE SET tags=excluded.tags""",
                    (fingerprint, tags_str),
                )

    def mark_quarantine(self, fingerprint: str, reason: str):
        with self.lock, self._connect() as conn:
            conn.execute(
                """INSERT INTO quarantine(fingerprint, reason, timestamp)
                   VALUES(?, ?, ?)
                   ON CONFLICT(fingerprint) DO UPDATE SET reason=excluded.reason, timestamp=excluded.timestamp""",
                (fingerprint, reason, now_iso()),
            )

    def get_overrides(self) -> dict:
        with self.lock, self._connect() as conn:
            rows = conn.execute("SELECT fingerprint, override FROM incident_overrides").fetchall()
        return {row["fingerprint"]: row["override"] for row in rows}

    def get_threat_labels(self) -> dict:
        with self.lock, self._connect() as conn:
            rows = conn.execute("SELECT fingerprint, label FROM incident_threat_labels").fetchall()
        return {row["fingerprint"]: row["label"] for row in rows}

    def get_tags(self) -> dict:
        with self.lock, self._connect() as conn:
            rows = conn.execute("SELECT fingerprint, tags FROM incident_tags").fetchall()
        out = {}
        for row in rows:
            tags = [t for t in (row["tags"] or "").split(",") if t]
            out[row["fingerprint"]] = tags
        return out

    def recent_incidents(self, limit: int = 300) -> list[dict]:
        with self.lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT fingerprint, payload FROM incidents ORDER BY id DESC LIMIT ?",
                (int(limit),),
            ).fetchall()
        overrides = self.get_overrides()
        labels = self.get_threat_labels()
        tags = self.get_tags()
        output = []
        for row in rows:
            try:
                record = json.loads(row["payload"])
                fp = row["fingerprint"]
                if fp in overrides:
                    record["manual_override"] = overrides[fp]
                if fp in labels:
                    record["manual_threat_label"] = labels[fp]
                if fp in tags:
                    record["tags"] = tags[fp]
                output.append(record)
            except Exception:
                pass
        return output

    def timeline(self, limit: int = 500) -> list[dict]:
        with self.lock, self._connect() as conn:
            rows = conn.execute(
                "SELECT payload FROM incidents ORDER BY id ASC LIMIT ?",
                (int(limit),),
            ).fetchall()
        out = []
        for row in rows:
            try:
                out.append(json.loads(row["payload"]))
            except Exception:
                pass
        return out

    def stats(self) -> dict:
        with self.lock, self._connect() as conn:
            incidents = conn.execute("SELECT COUNT(*) c FROM incidents").fetchone()["c"]
            features = conn.execute("SELECT COUNT(*) c FROM feature_memory").fetchone()["c"]
            actions = conn.execute("SELECT COUNT(*) c FROM actions").fetchone()["c"]
        return {"incidents": incidents, "features": features, "actions": actions}

    def save_threat_intel(self, intel: dict):
        with self.lock, self._connect() as conn:
            for k, v in intel.items():
                conn.execute(
                    """INSERT INTO threat_intel(key, value)
                       VALUES(?, ?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (k, json.dumps(v)),
                )

    def load_threat_intel(self) -> dict:
        with self.lock, self._connect() as conn:
            rows = conn.execute("SELECT key, value FROM threat_intel").fetchall()
        out = {}
        for row in rows:
            try:
                out[row["key"]] = json.loads(row["value"])
            except Exception:
                out[row["key"]] = row["value"]
        return out


def fingerprint_finding(finding: dict) -> str:
    stable = {
        "type": finding.get("type", ""),
        "process": (finding.get("process") or {}).get("name", ""),
        "pattern": finding.get("pattern", ""),
        "path": finding.get("path", ""),
        "package": finding.get("package", ""),
        "connection": finding.get("connection", {}).get("raddr", ""),
    }
    raw = json.dumps(stable, sort_keys=True)
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:20]


BORG_MEMORY = BorgMemory(str(DB_PATH))


class BorgAI:
    def __init__(self, cfg: SecurityConfig, memory: BorgMemory):
        self.cfg = cfg
        self.memory = memory
        self.lock = threading.RLock()
        self.session_counts = Counter()
        self.total_events = 0

    def feature_set(self, finding: dict) -> list[str]:
        ftype = finding.get("type", "unknown")
        features = [f"type:{ftype}"]
        proc = finding.get("process") or {}
        conn = finding.get("connection") or {}
        path = finding.get("path") or ""
        package = finding.get("package") or ""
        pattern = finding.get("pattern") or ""

        if proc.get("name"):
            features.append(f"process:{canonical_text(proc['name'])}")
        if proc.get("username"):
            features.append(f"user:{canonical_text(proc['username'])}")
        if conn.get("raddr"):
            host = str(conn["raddr"]).split(":")[0]
            features.append(f"remote:{canonical_text(host)}")
        if path:
            features.append(f"path:{canonical_text(path[:200])}")
        if package:
            features.append(f"package:{canonical_text(package)}")
        if pattern:
            features.append(f"pattern:{canonical_text(pattern[:160])}")
        return features

    def novelty(self, feature: str) -> float:
        obs, anomaly_sum = self.memory.feature_stats(feature)
        if obs < self.cfg.learning_min_samples:
            return 1.0
        mean_anomaly = anomaly_sum / max(obs, 1)
        return clamp(100.0 - (mean_anomaly * 0.75), 0.0, 100.0) / 100.0

    def explanation_for_finding(self, finding: dict, deterministic_score: float) -> str:
        ftype = finding.get("type", "unknown")
        base = f"Type={ftype}, score={deterministic_score:.1f}"
        if ftype == "file_integrity_change":
            return base + " — hosts file or critical config changed unexpectedly."
        if ftype == "process_webhook_indicator":
            return base + " — process command line contains webhook URL (Slack/Telegram style)."
        if ftype == "network_indicator":
            return base + " — network connection references blockchain-related host/pattern."
        if ftype == "security_event_indicator":
            return base + " — security event log shows credential/login-related activity."
        if ftype == "gpu_telemetry_anomaly":
            return base + " — GPU temperature or memory utilization exceeded configured thresholds."
        if ftype == "dependency_indicator":
            return base + " — suspicious package name found in dependency lockfile."
        if ftype == "gpu_vram_entropy":
            return base + " — VRAM entropy metric is elevated, indicating unusual memory pattern."
        return base + " — generic anomaly based on scoring rules."

    def remediation_suggestion(self, finding: dict, severity: str) -> str:
        ftype = finding.get("type", "unknown")
        if severity == "info":
            return "No immediate remediation required; monitor for changes."
        if ftype == "file_integrity_change":
            return "Verify hosts file contents, compare with known-good baseline, and restore if tampered."
        if ftype == "process_webhook_indicator":
            return "Inspect the process, confirm if webhook usage is expected, and disable unknown scripts."
        if ftype == "network_indicator":
            return "Check remote endpoint reputation and block suspicious domains/IPs at firewall level."
        if ftype == "security_event_indicator":
            return "Review login/credential events, enforce MFA, and check for unusual account activity."
        if ftype == "gpu_telemetry_anomaly":
            return "Check cooling, workload, and GPU settings; reduce load or adjust fan curves if needed."
        if ftype == "dependency_indicator":
            return "Audit dependencies, remove suspicious packages, and lock versions to trusted sources."
        if ftype == "gpu_vram_entropy":
            return "Review GPU workloads; ensure no unknown compute tasks are running."
        return "Review the incident details and confirm whether the behavior is expected; adjust rules if needed."

    def evaluate(self, finding: dict, deterministic_score: float, severity: str) -> dict:
        features = self.feature_set(finding)
        novelties = [self.novelty(f) for f in features] or [1.0]
        novelty = sum(novelties) / len(novelties)

        adaptive_bonus = deterministic_score * 0.22 * novelty
        final_score = clamp(deterministic_score + adaptive_bonus)

        self.total_events += 1
        self.session_counts[finding.get("type", "unknown")] += 1

        for feature in features:
            self.memory.observe(
                feature,
                novelty * 100.0,
                {"event_type": finding.get("type", "unknown")},
            )

        explanation_text = self.explanation_for_finding(finding, deterministic_score)
        remediation = self.remediation_suggestion(finding, severity)

        return {
            "features": features,
            "novelty": round(novelty, 3),
            "deterministic_score": round(deterministic_score, 2),
            "adaptive_bonus": round(adaptive_bonus, 2),
            "final_score": round(final_score, 2),
            "ai_explanation": explanation_text,
            "ai_remediation": remediation,
        }

    def status(self) -> dict:
        return {
            "engine": "BorgAI",
            "mode": "defensive-online-learning",
            "events_this_session": self.total_events,
            "top_event_types": self.session_counts.most_common(8),
            "memory": self.memory.stats(),
        }


class HostTelemetry:
    def collect(self) -> dict:
        info = {
            "timestamp": now_iso(),
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "platform": platform.platform(),
            "python": sys.version.split()[0],
            "pid": os.getpid(),
            "admin": is_admin(),
        }
        if psutil:
            try:
                info.update({
                    "cpu_count": psutil.cpu_count(logical=True),
                    "memory_total": psutil.virtual_memory().total,
                    "memory_percent": psutil.virtual_memory().percent,
                    "boot_time": psutil.boot_time(),
                    "uptime_seconds": int(time.time() - psutil.boot_time()),
                })
            except Exception as exc:
                LOG.warning("Host telemetry error: %s", exc)
        return info


class DependencyScanner:
    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg

    def run(self) -> list[dict]:
        findings = []
        lockfiles = [
            Path(self.cfg.project_root) / "package-lock.json",
            Path(self.cfg.project_root) / "pnpm-lock.yaml",
            Path(self.cfg.project_root) / "yarn.lock",
            Path(self.cfg.project_root) / "requirements.txt",
            Path(self.cfg.project_root) / "poetry.lock",
        ]
        for path in lockfiles:
            content = safe_read_file(path)
            if not content:
                continue
            for name in self.cfg.suspicious_package_names:
                if name.lower() in content.lower():
                    findings.append({
                        "type": "dependency_indicator",
                        "lockfile": str(path),
                        "package": name,
                    })
        return findings


class NetworkMonitor:
    def snapshot(self) -> list[dict]:
        if not psutil:
            return []
        output = []
        try:
            for c in psutil.net_connections(kind="inet"):
                output.append({
                    "pid": c.pid,
                    "laddr": f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
                    "raddr": f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "",
                    "status": c.status,
                })
        except Exception as exc:
            LOG.warning("Network snapshot error: %s", exc)
        return output

    def detect(self, conns: list[dict]) -> list[dict]:
        findings = []
        for c in conns:
            remote = canonical_text(c.get("raddr"))
            if not remote:
                continue
            for pattern in [r"sepolia", r"ethereum", r"eth"]:
                if pattern in remote:
                    findings.append({
                        "type": "network_indicator",
                        "connection": c,
                        "pattern": pattern,
                    })
        return findings


class ProcessMonitor:
    def snapshot(self) -> list[dict]:
        if not psutil:
            return []
        output = []
        try:
            for p in psutil.process_iter(attrs=["pid", "ppid", "name", "exe", "cmdline", "username"]):
                try:
                    output.append(p.info)
                except Exception:
                    continue
        except Exception as exc:
            LOG.warning("Process snapshot error: %s", exc)
        return output

    def detect(self, procs: list[dict], cfg: SecurityConfig) -> list[dict]:
        findings = []
        webhook_regexes = [re.compile(p, re.I) for p in cfg.suspicious_webhook_patterns]
        for proc in procs:
            raw = proc.get("cmdline") or []
            cmd = " ".join(raw) if isinstance(raw, list) else str(raw)
            for rx in webhook_regexes:
                if rx.search(cmd):
                    findings.append({
                        "type": "process_webhook_indicator",
                        "process": proc,
                        "pattern": rx.pattern,
                    })
        return findings


class EventLogMonitor:
    def snapshot(self) -> list[dict]:
        if os.name != "nt" or not HAS_WIN32:
            return []
        findings = []
        try:
            hand = win32evtlog.OpenEventLog(None, "Security")
            flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
            events = win32evtlog.ReadEventLog(hand, flags, 0) or []
            for ev in events[:50]:
                msg = str(ev.StringInserts or "")
                lower = msg.lower()
                if "credential" in lower or "login" in lower:
                    findings.append({
                        "type": "security_event_indicator",
                        "source": ev.SourceName,
                        "event_id": ev.EventID & 0xFFFF,
                        "message": msg[:1000],
                    })
        except Exception as exc:
            LOG.debug("Event log read unavailable: %s", exc)
        return findings


class FileIntegrityMonitor:
    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg
        self.baseline = {}

    def establish(self):
        for path in self.cfg.file_integrity_paths:
            self.baseline[path] = hash_file(path)

    def check(self) -> list[dict]:
        findings = []
        for path in self.cfg.file_integrity_paths:
            old = self.baseline.get(path, "")
            new = hash_file(path)
            if old and new and old != new:
                findings.append({
                    "type": "file_integrity_change",
                    "path": path,
                    "old_hash": old,
                    "new_hash": new,
                })
                self.baseline[path] = new
        return findings


class GPUTelemetryMonitor:
    def __init__(self, cfg: SecurityConfig, caps: CapabilityDetector):
        self.cfg = cfg
        self.caps = caps
        self.initialized = False
        if self.caps.gpu_available and pynvml:
            try:
                pynvml.nvmlInit()
                self.initialized = True
            except Exception as exc:
                LOG.info("GPU telemetry unavailable: %s", exc)
                self.initialized = False

    def snapshot(self) -> list[dict]:
        if not self.initialized:
            return []
        findings = []
        try:
            for i in range(pynvml.nvmlDeviceGetCount()):
                h = pynvml.nvmlDeviceGetHandleByIndex(i)
                raw_name = pynvml.nvmlDeviceGetName(h)
                name = raw_name.decode(errors="ignore") if isinstance(raw_name, bytes) else str(raw_name)
                temp = pynvml.nvmlDeviceGetTemperature(h, pynvml.NVML_TEMPERATURE_GPU)
                mem = pynvml.nvmlDeviceGetMemoryInfo(h)
                util = mem.used / mem.total if mem.total else 0.0
                if temp >= self.cfg.gpu_temp_critical or util >= self.cfg.gpu_mem_util_critical:
                    findings.append({
                        "type": "gpu_telemetry_anomaly",
                        "index": i,
                        "name": name,
                        "temperature": temp,
                        "mem_util": util,
                    })
        except Exception as exc:
            LOG.debug("GPU snapshot failed: %s", exc)
        return findings


class GPUGovernor:
    def __init__(self, cfg: SecurityConfig, caps: CapabilityDetector):
        self.cfg = cfg
        self.caps = caps
        self.curves = {}
        self.lock = threading.Lock()

    def update_curve(self, gpu_index: int, temp: float, util: float) -> None:
        if not self.caps.gpu_available:
            return
        with self.lock:
            curve = self.curves.setdefault(gpu_index, [])
            curve.append({"ts": time.time(), "temp": temp, "util": util})
            if len(curve) > self.cfg.gpu_governor_curve_points:
                self.curves[gpu_index] = curve[-self.cfg.gpu_governor_curve_points:]

    def safe_undervolt_hint(self, gpu_index: int) -> dict:
        if not self.caps.gpu_available:
            return {
                "gpu_index": gpu_index,
                "safe": False,
                "avg_temp": "n/a",
                "margin": "n/a",
                "hint": "GPU not available on this system.",
                "curve": [],
            }
        with self.lock:
            curve = self.curves.get(gpu_index, [])
            if not curve:
                return {
                    "gpu_index": gpu_index,
                    "safe": False,
                    "avg_temp": "n/a",
                    "margin": self.cfg.gpu_governor_safe_undervolt_margin,
                    "hint": "Insufficient telemetry for GPU governor.",
                    "curve": [],
                }
            avg_temp = sum(c["temp"] for c in curve) / len(curve)
            margin = self.cfg.gpu_governor_safe_undervolt_margin
            safe = avg_temp > 60.0
            return {
                "gpu_index": gpu_index,
                "safe": safe,
                "avg_temp": avg_temp,
                "margin": margin,
                "hint": "Simulated safe undervolt suggestion.",
                "curve": curve,
            }


GPU_GOVERNOR = GPUGovernor(SEC_CFG, CAPS)


class VRAMScanner:
    def __init__(self, cfg: SecurityConfig, caps: CapabilityDetector):
        self.cfg = cfg
        self.caps = caps

    def scan(self, gpu_index: int) -> dict:
        # Synthetic entropy metric; works even without real GPU
        entropy = round(7.5 + math.sin(time.time() / 60.0 + gpu_index), 3)
        return {
            "gpu_index": gpu_index,
            "sample_bytes": self.cfg.gpu_vram_scan_sample_bytes,
            "entropy": entropy,
            "note": "synthetic VRAM entropy metric (defensive-only)",
        }


VRAM_SCANNER = VRAMScanner(SEC_CFG, CAPS)


class AnomalyScorer:
    WEIGHTS = {
        "file_integrity_change": 90,
        "process_webhook_indicator": 85,
        "network_indicator": 75,
        "security_event_indicator": 70,
        "gpu_telemetry_anomaly": 60,
        "dependency_indicator": 55,
        "gpu_vram_entropy": 50,
    }

    def score(self, finding: dict) -> float:
        score = float(self.WEIGHTS.get(finding.get("type", ""), 20))
        if finding.get("type") == "file_integrity_change":
            if "hosts" in canonical_text(finding.get("path")):
                score += 10
        if finding.get("type") == "gpu_vram_entropy":
            entropy = float(finding.get("entropy", 0.0))
            if entropy > 7.8:
                score += 20
        return clamp(score)

    def severity(self, score: float, cfg: SecurityConfig) -> str:
        if score >= cfg.score_threshold_critical:
            return "critical"
        if score >= cfg.score_threshold_incident:
            return "incident"
        return "info"


class IncidentCorrelator:
    def __init__(self):
        self.recent = deque(maxlen=250)
        self.lock = threading.Lock()

    def add(self, finding: dict) -> dict:
        fp = fingerprint_finding(finding)
        with self.lock:
            self.recent.append((time.time(), fp, finding))
            now = time.time()
            related = [item for item in self.recent if now - item[0] <= 300 and item[1] == fp]
        return {
            "fingerprint": fp,
            "related_count_5m": len(related),
            "correlated": len(related) >= 2,
        }


class SwarmSync:
    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg
        self.lock = threading.Lock()
        self.cache = defaultdict(int)

    def publish(self, fingerprint: str, score: float) -> None:
        if not self.cfg.swarm_enabled:
            return
        with self.lock:
            self.cache[fingerprint] = max(self.cache[fingerprint], int(score))

    def status(self) -> dict:
        with self.lock:
            return {
                "node_id": self.cfg.swarm_node_id,
                "cluster": self.cfg.swarm_cluster_name,
                "entries": len(self.cache),
            }


SWARM = SwarmSync(SEC_CFG)


class ThreatIntel:
    def __init__(self, cfg: SecurityConfig, memory: BorgMemory):
        self.cfg = cfg
        self.memory = memory
        self.last_refresh = 0
        self.cache = {}

    def refresh(self):
        if not self.cfg.enable_threat_intel or not self.cfg.threat_intel_url or not urllib:
            return
        now = time.time()
        if now - self.last_refresh < self.cfg.threat_intel_refresh_minutes * 60:
            return
        try:
            with urllib.request.urlopen(self.cfg.threat_intel_url, timeout=10) as resp:
                data = resp.read().decode("utf-8", errors="replace")
                intel = json.loads(data)
                self.cache = intel
                self.memory.save_threat_intel(intel)
                self.last_refresh = now
                LOG.info("Threat intel refreshed from online source.")
        except Exception as exc:
            LOG.warning("Threat intel refresh failed: %s", exc)

    def load_local(self):
        self.cache = self.memory.load_threat_intel()

    def enrich(self, finding: dict) -> dict:
        if not self.cache:
            return {}
        conn = finding.get("connection") or {}
        raddr = str(conn.get("raddr", ""))
        host = raddr.split(":")[0]
        intel_hosts = self.cache.get("hosts", {})
        if host and host in intel_hosts:
            return {"threat_intel": intel_hosts[host]}
        return {}


THREAT_INTEL = ThreatIntel(SEC_CFG, BORG_MEMORY)


class DefensiveResponder:
    def __init__(self, cfg: SecurityConfig, memory: BorgMemory):
        self.cfg = cfg
        self.memory = memory

    def handle(self, finding: dict, score: float, severity: str, fp: str) -> dict:
        mode = self.cfg.response_mode
        action = "observe"
        result = "No automatic action."

        if mode == "full_manual":
            action = "observe"
            result = "Full manual mode: no automatic response."
        elif mode == "semi_ai":
            if severity in ("critical", "incident"):
                action = "alert-and-review"
                result = f"Semi-AI mode: {severity} incident queued for manual review."
        elif mode == "full_auto":
            if severity == "critical":
                action = "alert-and-review"
                result = "Critical defensive alert generated."
                if self.cfg.enable_quarantine:
                    self.memory.mark_quarantine(fp, "auto-quarantine (critical incident)")
                    action = "auto-quarantine"
                    result = "Marked fingerprint as quarantined (safe, non-destructive)."
                if (
                    self.cfg.enable_auto_terminate
                    and not self.cfg.response_dry_run
                    and psutil
                    and finding.get("process", {}).get("pid")
                ):
                    pid = int(finding["process"]["pid"])
                    try:
                        proc = psutil.Process(pid)
                        if pid not in (0, 4, os.getpid()):
                            proc.terminate()
                            action = "terminate-suspicious-process"
                            result = f"Terminated PID {pid} (full_auto mode)."
                    except Exception as exc:
                        result = f"Termination failed: {exc}"
            elif severity == "incident":
                action = "alert-and-review"
                result = "Incident queued for review (full_auto mode)."
                if self.cfg.enable_quarantine:
                    self.memory.mark_quarantine(fp, "auto-quarantine (incident)")
        record_mode = "dry-run" if self.cfg.response_dry_run else "live"
        self.memory.save_action(action, record_mode, result, fp)
        return {"action": action, "mode": record_mode, "result": result}


class PluginManager:
    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg
        self.plugins = []
        self.load()

    def load(self):
        if not self.cfg.enable_plugins:
            return
        for path in Path(self.cfg.plugin_dir).glob("*.py"):
            try:
                spec = importlib.util.spec_from_file_location(path.stem, path)
                if not spec or not spec.loader:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                self.plugins.append(mod)
                LOG.info("Loaded plugin: %s", path.name)
            except Exception as exc:
                LOG.warning("Plugin load failed for %s: %s", path.name, exc)

    def handle(self, record: dict):
        for mod in self.plugins:
            try:
                fn = getattr(mod, "handle_incident", None)
                if callable(fn):
                    fn(record)
            except Exception as exc:
                LOG.warning("Plugin error in %s: %s", mod.__name__, exc)


class IncidentLogger:
    def __init__(self, cfg: SecurityConfig, memory: BorgMemory, gui_callback=None, plugins=None):
        self.cfg = cfg
        self.memory = memory
        self.gui_callback = gui_callback
        self.plugins = plugins
        self.lock = threading.Lock()

    def log(self, finding: dict, score: float, severity: str,
            learning: dict, correlation: dict, response: dict, intel: dict):
        record = {
            "timestamp": now_iso(),
            "severity": severity,
            "score": round(score, 2),
            "finding": safe_json(finding),
            "borg_ai": learning,
            "correlation": correlation,
            "response": response,
            "intel": intel,
        }
        line = json.dumps(record, ensure_ascii=False)
        with self.lock:
            try:
                with open(self.cfg.incident_log_path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except Exception as exc:
                LOG.warning("Incident log write failed: %s", exc)

        self.memory.save_incident(record)
        LOG.warning("[%s] score=%s type=%s mode=%s",
                    severity.upper(), round(score, 1), finding.get("type"), self.cfg.response_mode)

        if self.gui_callback:
            try:
                self.gui_callback(record)
            except Exception as exc:
                LOG.debug("GUI callback failed: %s", exc)

        if self.plugins:
            self.plugins.handle(record)

        return record


class DefensiveSimulator:
    EVENTS = [
        {"type": "process_webhook_indicator", "pattern": "SIMULATED_WEBHOOK"},
        {"type": "network_indicator", "pattern": "SIMULATED_REMOTE"},
        {"type": "file_integrity_change", "path": "SIMULATED_FILE"},
        {"type": "security_event_indicator", "event_id": 9999},
        {"type": "gpu_telemetry_anomaly", "temperature": 99},
        {"type": "gpu_vram_entropy", "entropy": 8.1},
    ]

    def generate(self) -> dict:
        import random
        event = dict(random.choice(self.EVENTS))
        event["simulation"] = True
        return event


class SecurityGovernor:
    def __init__(self, cfg: SecurityConfig, gui=None, caps: CapabilityDetector | None = None):
        self.cfg = cfg
        self.gui = gui
        self.caps = caps or CAPS
        self.memory = BorgMemory(cfg.database_path)
        self.borg = BorgAI(cfg, self.memory)
        self.telemetry = HostTelemetry()
        self.dep = DependencyScanner(cfg)
        self.net = NetworkMonitor()
        self.proc = ProcessMonitor()
        self.events = EventLogMonitor()
        self.files = FileIntegrityMonitor(cfg)
        self.gpu = GPUTelemetryMonitor(cfg, self.caps)
        self.plugins = PluginManager(cfg)
        self.scorer = AnomalyScorer()
        self.correlator = IncidentCorrelator()
        self.responder = DefensiveResponder(cfg, self.memory)

        callback = gui.push_incident if gui else None
        self.logger = IncidentLogger(cfg, self.memory, callback, self.plugins)

        self.queue: queue.Queue[dict] = queue.Queue()
        self.stop_event = threading.Event()
        self.threads = []

    def start(self):
        LOG.info("%s %s starting...", APP_NAME, APP_VERSION)
        LOG.info("Defensive-only mode: active")
        LOG.info("Profile mode: %s", self.cfg.profile_mode)
        LOG.info("Response mode: %s", self.cfg.response_mode)
        LOG.info("Borg AI memory: %s", self.cfg.database_path)

        self.files.establish()
        THREAT_INTEL.load_local()
        THREAT_INTEL.refresh()

        jobs = [
            ("network", self._network_loop, self.cfg.enable_network_monitor),
            ("process", self._process_loop, self.cfg.enable_process_monitor),
            ("eventlog", self._event_loop, self.cfg.enable_event_log_monitor),
            ("integrity", self._integrity_loop, self.cfg.enable_file_integrity),
            ("gpu", self._gpu_loop, self.cfg.enable_gpu_telemetry),
            ("dependencies", self._dependency_loop, self.cfg.enable_dependency_scan),
            ("dispatcher", self._dispatch_loop, True),
            ("vram", self._vram_loop, self.cfg.gpu_vram_scan_enabled),
            ("intel", self._intel_loop, self.cfg.enable_threat_intel),
        ]

        for name, target, enabled in jobs:
            if not enabled:
                continue
            t = threading.Thread(target=target, name=f"Borg-{name}", daemon=True)
            self.threads.append(t)
            t.start()

        LOG.info("Borg Sentinel AI is running.")

        if self.gui and self.gui.root:
            self.gui.governor = self
            self.gui.run()
            self.stop()
        else:
            try:
                while not self.stop_event.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                self.stop()

    def stop(self):
        self.stop_event.set()
        LOG.info("Stopping Borg Sentinel AI...")

    def submit(self, finding: dict):
        self.queue.put(finding)

    def _dependency_loop(self):
        while not self.stop_event.is_set():
            try:
                for finding in self.dep.run():
                    self.submit(finding)
            except Exception:
                LOG.debug("Dependency loop error:\n%s", traceback.format_exc())
            self.stop_event.wait(max(self.cfg.poll_interval_seconds * 12, 60))

    def _network_loop(self):
        while not self.stop_event.is_set():
            try:
                for finding in self.net.detect(self.net.snapshot()):
                    self.submit(finding)
            except Exception:
                LOG.debug("Network loop error:\n%s", traceback.format_exc())
            self.stop_event.wait(self.cfg.poll_interval_seconds)

    def _process_loop(self):
        while not self.stop_event.is_set():
            try:
                procs = self.proc.snapshot()
                for finding in self.proc.detect(procs, self.cfg):
                    self.submit(finding)
            except Exception:
                LOG.debug("Process loop error:\n%s", traceback.format_exc())
            self.stop_event.wait(self.cfg.poll_interval_seconds)

    def _event_loop(self):
        while not self.stop_event.is_set():
            try:
                for finding in self.events.snapshot():
                    self.submit(finding)
            except Exception:
                LOG.debug("Event loop error:\n%s", traceback.format_exc())
            self.stop_event.wait(self.cfg.poll_interval_seconds * 6)

    def _integrity_loop(self):
        while not self.stop_event.is_set():
            try:
                for finding in self.files.check():
                    self.submit(finding)
            except Exception:
                LOG.debug("Integrity loop error:\n%s", traceback.format_exc())
            self.stop_event.wait(self.cfg.poll_interval_seconds * 6)

    def _gpu_loop(self):
        while not self.stop_event.is_set():
            try:
                for finding in self.gpu.snapshot():
                    idx = finding.get("index", 0)
                    temp = float(finding.get("temperature", 0.0))
                    util = float(finding.get("mem_util", 0.0))
                    GPU_GOVERNOR.update_curve(idx, temp, util)
                    self.submit(finding)
            except Exception:
                LOG.debug("GPU loop error:\n%s", traceback.format_exc())
            self.stop_event.wait(self.cfg.poll_interval_seconds * 6)

    def _vram_loop(self):
        while not self.stop_event.is_set():
            try:
                if not self.cfg.gpu_vram_scan_enabled:
                    break
                # If no real GPU, we still simulate entropy for index 0
                max_index = self.caps.gpu_count if self.caps.gpu_available else 1
                for gpu_index in range(0, max_index):
                    scan = VRAM_SCANNER.scan(gpu_index)
                    finding = {
                        "type": "gpu_vram_entropy",
                        "gpu_index": gpu_index,
                        "entropy": scan["entropy"],
                        "pattern": f"entropy={scan['entropy']}",
                    }
                    self.submit(finding)
            except Exception:
                LOG.debug("VRAM loop error:\n%s", traceback.format_exc())
            self.stop_event.wait(self.cfg.poll_interval_seconds * 12)

    def _intel_loop(self):
        while not self.stop_event.is_set():
            try:
                THREAT_INTEL.refresh()
            except Exception:
                LOG.debug("Threat intel loop error:\n%s", traceback.format_exc())
            self.stop_event.wait(self.cfg.threat_intel_refresh_minutes * 60)

    def _dispatch_loop(self):
        while not self.stop_event.is_set():
            try:
                finding = self.queue.get(timeout=1)
            except queue.Empty:
                continue

            try:
                deterministic = self.scorer.score(finding)
                severity = self.scorer.severity(deterministic, self.cfg)
                learning = self.borg.evaluate(finding, deterministic, severity)
                final_score = learning["final_score"]
                severity = self.scorer.severity(final_score, self.cfg)

                correlation = self.correlator.add(finding)
                fp = correlation["fingerprint"]
                intel = THREAT_INTEL.enrich(finding)
                response = self.responder.handle(finding, final_score, severity, fp)

                SWARM.publish(fp, final_score)

                self.logger.log(
                    finding, final_score, severity,
                    learning, correlation, response, intel
                )
            except Exception:
                LOG.error("Incident processing error:\n%s", traceback.format_exc())


class SecurityGUI:
    def __init__(self, cfg: SecurityConfig, caps: CapabilityDetector):
        self.cfg = cfg
        self.caps = caps
        self.root = tk.Tk() if tk and ttk and cfg.gui_enabled else None
        self.governor: Optional[SecurityGovernor] = None
        self.queue: queue.Queue[dict] = queue.Queue()
        self.incident_rows = 0
        self.simulator = DefensiveSimulator()
        self.status_vars = {}
        self.threat_matrix_vars = {}
        self.persona_vars = {}
        self.overlay_phase = 0.0
        self.vram_points: list[float] = []
        self.context_menu = None
        self.response_mode_var = tk.StringVar(value=self.cfg.response_mode) if self.root else None
        self.profile_mode_var = tk.StringVar(value=self.cfg.profile_mode) if self.root else None
        self.heatmap_data = defaultdict(int)
        self._build()

    def _build(self):
        if not self.root:
            return

        self.root.title(f"{APP_NAME} {APP_VERSION}")
        self.root.geometry("1250x800")
        self.root.minsize(900, 580)

        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except Exception:
            pass

        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=8, pady=8)

        dashboard = ttk.Frame(notebook, padding=10)
        incidents = ttk.Frame(notebook, padding=10)
        learning = ttk.Frame(notebook, padding=10)
        matrix = ttk.Frame(notebook, padding=10)
        persona = ttk.Frame(notebook, padding=10)
        timeline = ttk.Frame(notebook, padding=10)
        heatmap = ttk.Frame(notebook, padding=10)
        gpu_curve = ttk.Frame(notebook, padding=10)
        lineage = ttk.Frame(notebook, padding=10)
        settings = ttk.Frame(notebook, padding=10)
        about = ttk.Frame(notebook, padding=10)

        notebook.add(dashboard, text="Dashboard")
        notebook.add(incidents, text="Incidents")
        notebook.add(learning, text="Borg AI")
        notebook.add(matrix, text="Threat Matrix")
        notebook.add(persona, text="Persona")
        notebook.add(timeline, text="Timeline Replay")
        notebook.add(heatmap, text="Incident Heatmap")
        notebook.add(gpu_curve, text="GPU Curves")
        notebook.add(lineage, text="Process Lineage")
        notebook.add(settings, text="Controls")
        notebook.add(about, text="About")

        self._dashboard_tab(dashboard)
        self._incident_tab(incidents)
        self._learning_tab(learning)
        self._matrix_tab(matrix)
        self._persona_tab(persona)
        self._timeline_tab(timeline)
        self._heatmap_tab(heatmap)
        self._gpu_curve_tab(gpu_curve)
        self._lineage_tab(lineage)
        self._settings_tab(settings)
        self._about_tab(about)

        # If no GPU, hide GPU curve tab and VRAM graph still shows synthetic data
        if not self.caps.gpu_available:
            notebook.hide(gpu_curve)

        self.root.after(500, self._tick)

    def _dashboard_tab(self, parent):
        title = ttk.Label(parent, text="Borg Sentinel AI", font=("Segoe UI", 18, "bold"))
        title.pack(anchor="w")

        subtitle = ttk.Label(
            parent,
            text="Autonomous defensive monitoring, behavioral learning, GPU-optional governor, and safe response.",
        )
        subtitle.pack(anchor="w", pady=(0, 12))

        cards = ttk.Frame(parent)
        cards.pack(fill=tk.X)

        for key, label in [
            ("mode", "Mode"),
            ("profile", "Profile"),
            ("incidents", "Incidents"),
            ("features", "Learned Features"),
            ("actions", "Actions"),
            ("events", "Session Events"),
            ("swarm", "Swarm Entries"),
        ]:
            frame = ttk.LabelFrame(cards, text=label, padding=10)
            frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=4)
            var = tk.StringVar(value="0")
            self.status_vars[key] = var
            ttk.Label(frame, textvariable=var, font=("Segoe UI", 14, "bold")).pack()

        info = ttk.LabelFrame(parent, text="Host", padding=10)
        info.pack(fill=tk.X, pady=12)
        self.host_text = tk.Text(info, height=7, wrap="word")
        self.host_text.pack(fill=tk.X)
        self.host_text.configure(state="disabled")

        overlays = ttk.LabelFrame(parent, text="Animated Overlays", padding=10)
        overlays.pack(fill=tk.X, pady=8)
        self.overlay_canvas = tk.Canvas(overlays, height=80, bg="#101010")
        self.overlay_canvas.pack(fill=tk.X)

        controls = ttk.Frame(parent)
        controls.pack(fill=tk.X, pady=8)
        ttk.Button(controls, text="Run Defensive Simulation", command=self.run_simulation).pack(side=tk.LEFT, padx=4)
        ttk.Button(controls, text="Refresh Status", command=self.refresh_status).pack(side=tk.LEFT, padx=4)
        ttk.Button(controls, text="Save Configuration", command=self.save_config).pack(side=tk.LEFT, padx=4)

    def _incident_tab(self, parent):
        cols = ("time", "severity", "score", "type", "action", "correlation", "tags")
        self.tree = ttk.Treeview(parent, columns=cols, show="headings", height=25)
        widths = {
            "time": 170, "severity": 85, "score": 70,
            "type": 230, "action": 180, "correlation": 110, "tags": 180
        }
        for col in cols:
            self.tree.heading(col, text=col.title())
            self.tree.column(col, width=widths[col], anchor="w")
        self.tree.pack(fill=tk.BOTH, expand=True)

        self.tree.tag_configure("sev_red", background="#330000", foreground="#ff4444")
        self.tree.tag_configure("sev_yellow", background="#332b00", foreground="#ffdd44")
        self.tree.tag_configure("sev_white", background="#202020", foreground="#ffffff")
        self.tree.tag_configure("sev_default", background="#101010", foreground="#dddddd")

        self.tree.bind("<Double-1>", self._open_incident_details)
        self.tree.bind("<Button-3>", self._on_tree_right_click)

        self.context_menu = tk.Menu(self.root, tearoff=0)
        self.context_menu.add_command(label="Open Details", command=self._open_incident_details_from_menu)
        self.context_menu.add_command(label="Export Incident to File", command=self._export_incident_to_file)
        self.context_menu.add_command(label="Open Correlated Incidents", command=self._open_correlated_incidents)
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Set Manual Severity: RED (Bad)", command=lambda: self._set_manual_override("red"))
        self.context_menu.add_command(label="Set Manual Severity: YELLOW (Unknown)", command=lambda: self._set_manual_override("yellow"))
        self.context_menu.add_command(label="Set Manual Severity: WHITE (Good)", command=lambda: self._set_manual_override("white"))
        self.context_menu.add_command(label="Clear Manual Severity", command=lambda: self._set_manual_override(None))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Assign Threat: Process/Webhook", command=lambda: self._set_threat_label("process_webhook_indicator"))
        self.context_menu.add_command(label="Assign Threat: Network", command=lambda: self._set_threat_label("network_indicator"))
        self.context_menu.add_command(label="Assign Threat: File Integrity", command=lambda: self._set_threat_label("file_integrity_change"))
        self.context_menu.add_command(label="Assign Threat: Security Event", command=lambda: self._set_threat_label("security_event_indicator"))
        self.context_menu.add_command(label="Assign Threat: GPU Telemetry", command=lambda: self._set_threat_label("gpu_telemetry_anomaly"))
        self.context_menu.add_command(label="Assign Threat: Dependency", command=lambda: self._set_threat_label("dependency_indicator"))
        self.context_menu.add_command(label="Assign Threat: GPU VRAM Entropy", command=lambda: self._set_threat_label("gpu_vram_entropy"))
        self.context_menu.add_command(label="Clear Threat Assignment", command=lambda: self._set_threat_label(None))
        self.context_menu.add_separator()
        self.context_menu.add_command(label="Add Tag...", command=self._add_tag_to_incident)

    def _learning_tab(self, parent):
        ttk.Label(parent, text="Borg AI — Defensive Learning", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        self.learning_text = tk.Text(parent, height=18, wrap="word")
        self.learning_text.pack(fill=tk.BOTH, expand=True, pady=8)
        self.learning_text.configure(state="disabled")

        vram_frame = ttk.LabelFrame(parent, text="VRAM Entropy Graph", padding=8)
        vram_frame.pack(fill=tk.BOTH, expand=True, pady=8)
        self.vram_canvas = tk.Canvas(vram_frame, height=120, bg="#101010")
        self.vram_canvas.pack(fill=tk.BOTH, expand=True)

    def _matrix_tab(self, parent):
        ttk.Label(parent, text="Threat Matrix", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        grid = ttk.Frame(parent)
        grid.pack(fill=tk.BOTH, expand=True, pady=8)
        categories = [
            "process_webhook_indicator",
            "network_indicator",
            "file_integrity_change",
            "security_event_indicator",
            "gpu_telemetry_anomaly",
            "dependency_indicator",
            "gpu_vram_entropy",
        ]
        for cat in categories:
            frame = ttk.LabelFrame(grid, text=cat, padding=8)
            frame.pack(fill=tk.X, pady=3)
            var = tk.StringVar(value="0")
            self.threat_matrix_vars[cat] = var
            ttk.Label(frame, textvariable=var, font=("Segoe UI", 12, "bold")).pack(anchor="w")

    def _persona_tab(self, parent):
        ttk.Label(parent, text="Persona Status Panel", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, pady=8)
        self.persona_vars["mood"] = tk.StringVar(value="CALM")
        self.persona_vars["focus"] = tk.StringVar(value="DEFENSIVE")
        self.persona_vars["swarm"] = tk.StringVar(value="LOCAL")
        self.persona_vars["gpu"] = tk.StringVar(value="NORMAL")
        for key, label in [
            ("mood", "Sentinel Mood"),
            ("focus", "Operational Focus"),
            ("swarm", "Swarm State"),
            ("gpu", "GPU Status"),
        ]:
            lf = ttk.LabelFrame(frame, text=label, padding=8)
            lf.pack(fill=tk.X, pady=4)
            ttk.Label(lf, textvariable=self.persona_vars[key], font=("Segoe UI", 13, "bold")).pack(anchor="w")

    def _timeline_tab(self, parent):
        ttk.Label(parent, text="Timeline Replay", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, pady=8)
        self.timeline_text = tk.Text(frame, wrap="word")
        self.timeline_text.pack(fill=tk.BOTH, expand=True)
        self.timeline_text.configure(state="disabled")
        controls = ttk.Frame(parent)
        controls.pack(fill=tk.X, pady=6)
        ttk.Button(controls, text="Replay Timeline", command=self._replay_timeline).pack(side=tk.LEFT, padx=4)

    def _heatmap_tab(self, parent):
        ttk.Label(parent, text="Incident Heatmap", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, pady=8)
        self.heatmap_canvas = tk.Canvas(frame, height=200, bg="#101010")
        self.heatmap_canvas.pack(fill=tk.BOTH, expand=True)

    def _gpu_curve_tab(self, parent):
        ttk.Label(parent, text="GPU Curve Visualizer", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, pady=8)
        self.gpu_curve_canvas = tk.Canvas(frame, height=200, bg="#101010")
        self.gpu_curve_canvas.pack(fill=tk.BOTH, expand=True)
        ttk.Button(frame, text="Refresh GPU Curves", command=self._refresh_gpu_curves).pack(anchor="w", pady=6)

    def _lineage_tab(self, parent):
        ttk.Label(parent, text="Process Lineage Graph", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        frame = ttk.Frame(parent)
        frame.pack(fill=tk.BOTH, expand=True, pady=8)
        self.lineage_text = tk.Text(frame, wrap="word")
        self.lineage_text.pack(fill=tk.BOTH, expand=True)
        self.lineage_text.configure(state="disabled")
        ttk.Button(frame, text="Refresh Lineage", command=self._refresh_lineage).pack(anchor="w", pady=6)

    def _settings_tab(self, parent):
        ttk.Label(parent, text="Safe Response Controls", font=("Segoe UI", 15, "bold")).pack(anchor="w")
        profile_frame = ttk.LabelFrame(parent, text="Profile Mode", padding=8)
        profile_frame.pack(fill=tk.X, pady=6)
        ttk.Radiobutton(profile_frame, text="Gaming", value="gaming", variable=self.profile_mode_var, command=self._apply_profile_mode).pack(anchor="w")
        ttk.Radiobutton(profile_frame, text="Browsing", value="browsing", variable=self.profile_mode_var, command=self._apply_profile_mode).pack(anchor="w")
        ttk.Radiobutton(profile_frame, text="High-Security", value="high_security", variable=self.profile_mode_var, command=self._apply_profile_mode).pack(anchor="w")

        mode_frame = ttk.LabelFrame(parent, text="Response Mode", padding=8)
        mode_frame.pack(fill=tk.X, pady=6)
        ttk.Radiobutton(mode_frame, text="Full Auto AI", value="full_auto", variable=self.response_mode_var, command=self._apply_response_mode).pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="Semi AI (Manual Assist)", value="semi_ai", variable=self.response_mode_var, command=self._apply_response_mode).pack(anchor="w")
        ttk.Radiobutton(mode_frame, text="Full Manual (Observe Only)", value="full_manual", variable=self.response_mode_var, command=self._apply_response_mode).pack(anchor="w")

        self.auto_var = tk.BooleanVar(value=self.cfg.enable_auto_terminate)
        self.dry_var = tk.BooleanVar(value=self.cfg.response_dry_run)
        ttk.Checkbutton(parent, text="Allow automatic termination of suspicious processes (only in Full Auto)", variable=self.auto_var, command=self.apply_settings).pack(anchor="w", pady=6)
        ttk.Checkbutton(parent, text="Dry-run response mode (recommended)", variable=self.dry_var, command=self.apply_settings).pack(anchor="w", pady=6)

        ttk.Label(parent, text="No exploit, credential theft, persistence, unauthorized scanning, or offensive attack capability is implemented.", wraplength=750).pack(anchor="w", pady=18)

    def _about_tab(self, parent):
        text = (
            f"{APP_NAME} {APP_VERSION}\n\n"
            "Purpose:\n"
            "Continuous local defensive monitoring with a persistent learning layer.\n\n"
            "Profiles:\n"
            "  - Gaming: more tolerant, fewer alerts, semi AI.\n"
            "  - Browsing: balanced defaults.\n"
            "  - High-Security: aggressive detection, full auto.\n\n"
            "Response modes:\n"
            "  - Full Auto AI: AI can act (within safe rules).\n"
            "  - Semi AI: AI suggests and alerts; you override.\n"
            "  - Full Manual: AI only observes/logs.\n\n"
            "GPU-optional:\n"
            "  - If no GPU is detected, GPU telemetry is disabled and VRAM entropy is synthetic.\n"
            "  - GUI hides GPU curve tab when GPU is unavailable.\n"
        )
        ttk.Label(parent, text=text, justify="left", wraplength=800).pack(anchor="w")

    def push_incident(self, record: dict):
        self.queue.put(record)

    def refresh_status(self):
        if not self.governor:
            return
        status = self.governor.borg.status()
        mem = status["memory"]
        self.status_vars["mode"].set(self.cfg.response_mode.upper())
        self.status_vars["profile"].set(self.cfg.profile_mode.upper())
        self.status_vars["incidents"].set(str(mem["incidents"]))
        self.status_vars["features"].set(str(mem["features"]))
        self.status_vars["actions"].set(str(mem["actions"]))
        self.status_vars["events"].set(str(status["events_this_session"]))
        swarm_status = SWARM.status()
        self.status_vars["swarm"].set(str(swarm_status["entries"]))
        host = self.governor.telemetry.collect()
        self.host_text.configure(state="normal")
        self.host_text.delete("1.0", tk.END)
        self.host_text.insert(tk.END, json.dumps(host, indent=2))
        self.host_text.configure(state="disabled")
        self.learning_text.configure(state="normal")
        self.learning_text.delete("1.0", tk.END)
        self.learning_text.insert(tk.END, json.dumps(status, indent=2))
        self.learning_text.configure(state="disabled")
        red_count = 0
        if self.governor:
            for r in self.governor.memory.recent_incidents(limit=100):
                if r.get("manual_override") == "red":
                    red_count += 1
        self.persona_vars["mood"].set("CALM" if red_count < 5 else "ALERT")
        self.persona_vars["focus"].set("DEFENSIVE")
        self.persona_vars["swarm"].set(f"{swarm_status['cluster']} ({swarm_status['entries']} entries)")
        self.persona_vars["gpu"].set("NORMAL" if self.caps.gpu_available else "NO GPU")

    def _apply_response_mode(self):
        mode = self.response_mode_var.get()
        self.cfg.response_mode = mode
        self.cfg.save()
        if self.governor:
            self.governor.cfg.response_mode = mode

    def _apply_profile_mode(self):
        mode = self.profile_mode_var.get()
        self.cfg.profile_mode = mode
        self.cfg.apply_profile()
        self.response_mode_var.set(self.cfg.response_mode)
        self.cfg.save()
        if self.governor:
            self.governor.cfg.profile_mode = mode
            self.governor.cfg.apply_profile()

    def apply_settings(self):
        self.cfg.enable_auto_terminate = bool(self.auto_var.get())
        self.cfg.response_dry_run = bool(self.dry_var.get())
        self.cfg.save()

    def save_config(self):
        self.apply_settings()
        self._apply_response_mode()
        self._apply_profile_mode()
        if messagebox:
            messagebox.showinfo("Borg Sentinel", "Configuration saved.")

    def run_simulation(self):
        if self.governor:
            self.governor.submit(self.simulator.generate())

    def _get_record_by_timestamp(self, timestamp: str) -> Optional[dict]:
        if not self.governor:
            return None
        for r in self.governor.memory.recent_incidents(limit=300):
            if r.get("timestamp") == timestamp:
                return r
        return None

    def _effective_color_from_override(self, override: Optional[str], severity: str) -> str:
        if override == "red":
            return "#ff0044"
        if override == "yellow":
            return "#ffaa00"
        if override == "white":
            return "#ffffff"
        if severity == "critical":
            return "#ff0044"
        if severity == "incident":
            return "#ffaa00"
        return "#00ff88"

    def _open_incident_details(self, event=None):
        item = self.tree.selection()
        if not item:
            return
        row = self.tree.item(item[0])
        values = row.get("values", [])
        if not values:
            return
        timestamp = values[0]
        record = self._get_record_by_timestamp(timestamp) or {"timestamp": timestamp, "note": "Record not found"}
        severity = record.get("severity", "info")
        manual_override = record.get("manual_override")
        manual_label = record.get("manual_threat_label")
        tags = record.get("tags", [])
        effective_color = self._effective_color_from_override(manual_override, severity)
        win = tk.Toplevel(self.root)
        win.title(f"Incident Details — {timestamp}")
        win.geometry("900x700")
        top_frame = ttk.Frame(win)
        top_frame.pack(fill=tk.X, pady=4)
        label_text = f"Severity: {severity}"
        if manual_override:
            label_text += f"  (Manual: {manual_override.upper()})"
        if manual_label:
            label_text += f"  Threat: {manual_label}"
        label_text += f"  Score: {record.get('score', 0)}"
        if tags:
            label_text += f"  Tags: {', '.join(tags)}"
        ttk.Label(top_frame, text=label_text, font=("Segoe UI", 11, "bold")).pack(anchor="w")
        learning = record.get("borg_ai", {})
        ai_expl = learning.get("ai_explanation", "")
        ai_rem = learning.get("ai_remediation", "")
        if ai_expl:
            ttk.Label(top_frame, text=f"AI Explanation: {ai_expl}", font=("Segoe UI", 10), wraplength=850).pack(anchor="w", pady=2)
        if ai_rem:
            ttk.Label(top_frame, text=f"AI Remediation: {ai_rem}", font=("Segoe UI", 10), wraplength=850).pack(anchor="w", pady=2)
        finding = record.get("finding", {})
        if finding.get("type") in ("gpu_telemetry_anomaly", "gpu_vram_entropy"):
            idx = finding.get("gpu_index", finding.get("index", 0))
            hint = GPU_GOVERNOR.safe_undervolt_hint(int(idx))
            safe = hint.get("safe", False)
            avg_temp = hint.get("avg_temp", "n/a")
            margin = hint.get("margin", "n/a")
            note = hint.get("hint", "")
            gpu_hint = f"GPU Governor Hint: safe={safe} avg_temp={avg_temp} margin={margin} ({note})"
            ttk.Label(top_frame, text=gpu_hint, font=("Segoe UI", 10)).pack(anchor="w")
        canvas = tk.Canvas(win, height=40, bg="#101010")
        canvas.pack(fill=tk.X, pady=4)
        self._animate_incident_viewer(canvas, effective_color)
        text = tk.Text(win, wrap="word")
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, json.dumps(record, indent=2))
        text.configure(state="disabled")

    def _animate_incident_viewer(self, canvas: tk.Canvas, color: str):
        canvas.delete("all")
        w = canvas.winfo_width() or 400
        h = canvas.winfo_height() or 40
        for i in range(12):
            x = (w / 12) * i + 10
            radius = 6 + (i % 3)
            canvas.create_oval(x - radius, h / 2 - radius, x + radius, h / 2 + radius, fill=color, outline="")

    def _on_tree_right_click(self, event):
        iid = self.tree.identify_row(event.y)
        if iid:
            self.tree.selection_set(iid)
            self.context_menu.tk_popup(event.x_root, event.y_root)

    def _open_incident_details_from_menu(self):
        self._open_incident_details()

    def _export_incident_to_file(self):
        item = self.tree.selection()
        if not item or not filedialog:
            return
        row = self.tree.item(item[0])
        values = row.get("values", [])
        if not values:
            return
        timestamp = values[0]
        record = self._get_record_by_timestamp(timestamp)
        if not record:
            if messagebox:
                messagebox.showwarning("Export", "Incident record not found in memory.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Incident",
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as fh:
                json.dump(record, fh, indent=2)
            if messagebox:
                messagebox.showinfo("Export", f"Incident exported to {path}")
        except Exception as exc:
            if messagebox:
                messagebox.showerror("Export", f"Failed to export: {exc}")

    def _open_correlated_incidents(self):
        item = self.tree.selection()
        if not item:
            return
        row = self.tree.item(item[0])
        values = row.get("values", [])
        if not values:
            return
        timestamp = values[0]
        record = self._get_record_by_timestamp(timestamp)
        if not record:
            return
        correlation = record.get("correlation", {})
        fp = correlation.get("fingerprint")
        if not fp:
            return
        related = []
        if self.governor:
            for r in self.governor.memory.recent_incidents(limit=300):
                if r.get("correlation", {}).get("fingerprint") == fp:
                    related.append(r)
        win = tk.Toplevel(self.root)
        win.title(f"Correlated Incidents — {fp}")
        win.geometry("800x600")
        text = tk.Text(win, wrap="word")
        text.pack(fill=tk.BOTH, expand=True)
        text.insert(tk.END, json.dumps(related, indent=2))
        text.configure(state="disabled")

    def _set_manual_override(self, override: Optional[str]):
        item = self.tree.selection()
        if not item or not self.governor:
            return
        row = self.tree.item(item[0])
        values = row.get("values", [])
        if not values:
            return
        timestamp = values[0]
        record = self._get_record_by_timestamp(timestamp)
        if not record:
            return
        correlation = record.get("correlation", {})
        fp = correlation.get("fingerprint")
        if not fp:
            return
        self.governor.memory.set_manual_override(fp, override)
        severity = record.get("severity", "info")
        tag = "sev_default"
        if override == "red":
            tag = "sev_red"
        elif override == "yellow":
            tag = "sev_yellow"
        elif override == "white":
            tag = "sev_white"
        else:
            if severity == "critical":
                tag = "sev_red"
            elif severity == "incident":
                tag = "sev_yellow"
        self.tree.item(item[0], tags=(tag,))

    def _set_threat_label(self, label: Optional[str]):
        item = self.tree.selection()
        if not item or not self.governor:
            return
        row = self.tree.item(item[0])
        values = row.get("values", [])
        if not values:
            return
        timestamp = values[0]
        record = self._get_record_by_timestamp(timestamp)
        if not record:
            return
        correlation = record.get("correlation", {})
        fp = correlation.get("fingerprint")
        if not fp:
            return
        self.governor.memory.set_threat_label(fp, label)
        if label and label in self.threat_matrix_vars:
            current = int(self.threat_matrix_vars[label].get() or "0")
            self.threat_matrix_vars[label].set(str(current + 1))

    def _add_tag_to_incident(self):
        item = self.tree.selection()
        if not item or not self.governor or not self.root:
            return
        row = self.tree.item(item[0])
        values = row.get("values", [])
        if not values:
            return
        timestamp = values[0]
        record = self._get_record_by_timestamp(timestamp)
        if not record:
            return
        correlation = record.get("correlation", {})
        fp = correlation.get("fingerprint")
        if not fp:
            return

        def _apply_tag():
            tag = entry.get().strip()
            if not tag:
                tag_win.destroy()
                return
            existing = record.get("tags", [])
            existing.append(tag)
            self.governor.memory.set_tags(fp, existing)
            self.tree.set(item[0], column="tags", value=",".join(existing))
            tag_win.destroy()

        tag_win = tk.Toplevel(self.root)
        tag_win.title("Add Tag")
        ttk.Label(tag_win, text="Tag for this incident (applies to all correlated):").pack(anchor="w", padx=8, pady=4)
        entry = ttk.Entry(tag_win)
        entry.pack(fill=tk.X, padx=8, pady=4)
        ttk.Button(tag_win, text="Apply", command=_apply_tag).pack(padx=8, pady=6)

    def _update_threat_matrix(self, record: dict):
        finding = record.get("finding", {})
        ftype = finding.get("type", "")
        manual_label = record.get("manual_threat_label")
        key = manual_label or ftype
        if key in self.threat_matrix_vars:
            current = int(self.threat_matrix_vars[key].get() or "0")
            self.threat_matrix_vars[key].set(str(current + 1))

    def _update_overlays(self):
        if not self.cfg.gui_animated_overlays or not self.overlay_canvas:
            return
        w = self.overlay_canvas.winfo_width()
        h = self.overlay_canvas.winfo_height()
        self.overlay_canvas.delete("all")
        self.overlay_phase += 0.1
        center_y = h // 2
        for i in range(10):
            x = (w / 10) * i + (math.sin(self.overlay_phase + i) * 10)
            radius = 6 + (math.cos(self.overlay_phase + i) * 3)
            color = "#00ff88" if i % 2 == 0 else "#00aaff"
            self.overlay_canvas.create_oval(x - radius, center_y - radius, x + radius, center_y + radius, fill=color, outline="")

    def _update_vram_graph(self):
        if not self.vram_canvas:
            return
        w = self.vram_canvas.winfo_width() or 400
        h = self.vram_canvas.winfo_height() or 120
        self.vram_canvas.delete("all")
        if not self.vram_points:
            return
        max_entropy = max(self.vram_points) or 1.0
        step = w / max(1, len(self.vram_points))
        for i, val in enumerate(self.vram_points):
            x = i * step
            y = h - (val / max_entropy) * (h - 10)
            self.vram_canvas.create_oval(x - 2, y - 2, x + 2, y + 2, fill="#00ff88", outline="")
        self.vram_canvas.create_text(10, 10, anchor="nw", fill="#ffffff", text=f"Last {len(self.vram_points)} VRAM entropy samples")

    def _replay_timeline(self):
        if not self.governor:
            return
        timeline = self.governor.memory.timeline(limit=500)
        self.timeline_text.configure(state="normal")
        self.timeline_text.delete("1.0", tk.END)
        for rec in timeline:
            ts = rec.get("timestamp", "")
            sev = rec.get("severity", "")
            score = rec.get("score", "")
            ftype = rec.get("finding", {}).get("type", "")
            ai_expl = rec.get("borg_ai", {}).get("ai_explanation", "")
            ai_rem = rec.get("borg_ai", {}).get("ai_remediation", "")
            line = f"{ts} | {sev} | score={score} | type={ftype}\n"
            if ai_expl:
                line += f"  AI: {ai_expl}\n"
            if ai_rem:
                line += f"  Remediation: {ai_rem}\n"
            self.timeline_text.insert(tk.END, line + "\n")
        self.timeline_text.configure(state="disabled")

    def _update_heatmap(self):
        if not self.heatmap_canvas:
            return
        self.heatmap_canvas.delete("all")
        w = self.heatmap_canvas.winfo_width() or 400
        h = self.heatmap_canvas.winfo_height() or 200
        if not self.heatmap_data:
            return
        keys = list(self.heatmap_data.keys())
        max_val = max(self.heatmap_data.values()) or 1
        cell_w = max(40, w / max(1, len(keys)))
        for i, key in enumerate(keys):
            val = self.heatmap_data[key]
            intensity = val / max_val
            color = f"#{int(255 * intensity):02x}0000"
            x0 = i * cell_w
            x1 = x0 + cell_w - 2
            self.heatmap_canvas.create_rectangle(x0, 0, x1, h - 20, fill=color, outline="#202020")
            self.heatmap_canvas.create_text((x0 + x1) / 2, h - 10, text=key, fill="#ffffff", font=("Segoe UI", 8))

    def _refresh_gpu_curves(self):
        if not self.gpu_curve_canvas:
            return
        self.gpu_curve_canvas.delete("all")
        w = self.gpu_curve_canvas.winfo_width() or 400
        h = self.gpu_curve_canvas.winfo_height() or 200
        curves = GPU_GOVERNOR.curves
        if not self.caps.gpu_available or not curves:
            self.gpu_curve_canvas.create_text(w / 2, h / 2, text="No GPU detected or no curve data yet.", fill="#ffffff")
            return
        colors = ["#00ff88", "#00aaff", "#ffaa00", "#ff0044"]
        for idx, (gpu_index, curve) in enumerate(curves.items()):
            color = colors[idx % len(colors)]
            if not curve:
                continue
            max_temp = max(c["temp"] for c in curve) or 1.0
            step = w / max(1, len(curve))
            for i, c in enumerate(curve):
                x = i * step
                y = h - (c["temp"] / max_temp) * (h - 20)
                self.gpu_curve_canvas.create_oval(x - 2, y - 2, x + 2, y + 2, fill=color, outline="")
            self.gpu_curve_canvas.create_text(10, 10 + idx * 15, anchor="nw", text=f"GPU {gpu_index}", fill=color, font=("Segoe UI", 9))

    def _refresh_lineage(self):
        if not self.governor or not self.lineage_text:
            return
        self.lineage_text.configure(state="normal")
        self.lineage_text.delete("1.0", tk.END)
        procs = self.governor.proc.snapshot()
        by_pid = {p["pid"]: p for p in procs}
        children = defaultdict(list)
        for p in procs:
            pp = p.get("ppid")
            if pp is not None:
                children[pp].append(p["pid"])
        def render(pid: int, depth: int = 0):
            proc = by_pid.get(pid)
            if not proc:
                return
            indent = "  " * depth
            line = f"{indent}{pid} [{proc.get('name', '')}] exe={proc.get('exe', '')}\n"
            self.lineage_text.insert(tk.END, line)
            for child in children.get(pid, []):
                render(child, depth + 1)
        roots = [p["pid"] for p in procs if p.get("ppid") not in by_pid]
        for r in roots:
            render(r, 0)
        self.lineage_text.configure(state="disabled")

    def _tick(self):
        if not self.root:
            return
        try:
            while True:
                record = self.queue.get_nowait()
                finding = record.get("finding", {})
                correlation = record.get("correlation", {})
                response = record.get("response", {})
                severity = record.get("severity", "info")
                manual_override = record.get("manual_override")
                tags = record.get("tags", [])
                tag = "sev_default"
                if manual_override == "red":
                    tag = "sev_red"
                elif manual_override == "yellow":
                    tag = "sev_yellow"
                elif manual_override == "white":
                    tag = "sev_white"
                else:
                    if severity == "critical":
                        tag = "sev_red"
                    elif severity == "incident":
                        tag = "sev_yellow"
                self.tree.insert(
                    "", tk.END,
                    values=(
                        record.get("timestamp", ""),
                        severity,
                        record.get("score", ""),
                        finding.get("type", ""),
                        response.get("action", ""),
                        correlation.get("related_count_5m", 0),
                        ",".join(tags),
                    ),
                    tags=(tag,),
                )
                self.incident_rows += 1
                if self.incident_rows > 500:
                    first = self.tree.get_children()[0]
                    self.tree.delete(first)
                    self.incident_rows -= 1
                self._update_threat_matrix(record)
                if finding.get("type") == "gpu_vram_entropy":
                    entropy = float(finding.get("entropy", 0.0))
                    self.vram_points.append(entropy)
                    if len(self.vram_points) > 100:
                        self.vram_points = self.vram_points[-100:]
                key = f"{severity}:{finding.get('type', '')}"
                self.heatmap_data[key] += 1
        except queue.Empty:
            pass
        self.refresh_status()
        self._update_overlays()
        self._update_vram_graph()
        self._update_heatmap()
        self.root.after(1000, self._tick)

    def run(self):
        if self.root:
            self.root.protocol("WM_DELETE_WINDOW", self._close)
            self.root.mainloop()

    def _close(self):
        if self.governor:
            self.governor.stop()
        self.root.destroy()


def main():
    cfg = load_security_config()
    CAPS.apply_to_config(cfg)
    gui = SecurityGUI(cfg, CAPS) if tk and ttk and cfg.gui_enabled else None
    governor = SecurityGovernor(cfg, gui, CAPS)
    governor.start()


if __name__ == "__main__":
    ensure_admin()
    main()
