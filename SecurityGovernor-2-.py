#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
SecurityGovernor + Codex Sentinel
Fully automatic, single-file defensive runtime monitor with GUI.

Features:
- Auto-elevation on Windows
- Auto-loader for required Python libraries
- Host fingerprinting & baseline telemetry
- Dependency scanning (npm + Python lockfiles & installed packages)
- Process & network monitoring (psutil-based)
- Suspicious pattern detection (Slack/Telegram webhooks, Sepolia/Ethereum C2 hints)
- Anomaly scoring, incident logging, and auto-responder hints
- Live GUI dashboard showing evaluated threats in real time (tkinter)

Defensive only. No offensive capabilities.
"""

# === AUTO-ELEVATION CHECK (Windows) ===
import ctypes
import os
import sys

def ensure_admin():
    try:
        if os.name == "nt":
            if not ctypes.windll.shell32.IsUserAnAdmin():
                script = os.path.abspath(sys.argv[0])
                params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
                ctypes.windll.shell32.ShellExecuteW(
                    None,
                    "runas",
                    sys.executable,
                    f'"{script}" {params}',
                    None,
                    1
                )
                sys.exit()
    except Exception as e:
        print(f"[Codex Sentinel] Elevation failed: {e}")
        sys.exit()

ensure_admin()

# === AUTO-LOADER FOR REQUIRED LIBRARIES ===
import subprocess
import importlib

def ensure_package(pkg_name: str, import_name: str = None):
    if import_name is None:
        import_name = pkg_name
    try:
        importlib.import_module(import_name)
        return
    except ImportError:
        try:
            print(f"[Codex Sentinel] Installing missing package: {pkg_name}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg_name])
        except Exception as e:
            print(f"[Codex Sentinel] Failed to install {pkg_name}: {e}")
    try:
        importlib.import_module(import_name)
    except ImportError:
        print(f"[Codex Sentinel] Could not import {import_name} even after install.")

# Ensure core dependencies
ensure_package("psutil")
ensure_package("importlib_metadata", "importlib_metadata")

# Now safe to import
import time
import json
import socket
import hashlib
import logging
import threading
import queue
import re
from datetime import datetime

import psutil
try:
    import importlib.metadata as importlib_metadata
except ImportError:
    import importlib_metadata  # type: ignore

# GUI (tkinter is in stdlib)
try:
    import tkinter as tk
    from tkinter import ttk
except ImportError:
    tk = None
    ttk = None

# ---------------------------------------------------------------------------
# Basic logging setup
# ---------------------------------------------------------------------------

LOG = logging.getLogger("SecurityGovernor")
LOG.setLevel(logging.INFO)
_handler = logging.StreamHandler(sys.stdout)
_handler.setFormatter(logging.Formatter("[%(asctime)s] [%(levelname)s] %(message)s"))
LOG.addHandler(_handler)

# ---------------------------------------------------------------------------
# Config & constants
# ---------------------------------------------------------------------------

class SecurityConfig:
    """
    Central configuration for SecurityGovernor.
    """

    def __init__(self):
        # General
        self.poll_interval_seconds = 5
        self.enable_dependency_scan = True
        self.enable_network_monitor = True
        self.enable_process_monitor = True
        self.enable_host_fingerprint = True

        # Suspicious patterns (defensive detection only)
        self.suspicious_webhook_patterns = [
            r"https://hooks\.slack\.com/services/",
            r"https://api\.telegram\.org/bot",
        ]
        self.suspicious_blockchain_patterns = [
            r"sepolia",
            r"eth",
            r"ethereum",
        ]
        self.suspicious_crypto_libs = [
            "cryptography",
            "pyNaCl",
            "nacl",
        ]

        # Anomaly scoring thresholds
        self.score_threshold_incident = 50
        self.score_threshold_critical = 80

        # Paths to inspect
        self.project_root = os.path.abspath(os.getcwd())
        self.npm_lockfiles = [
            os.path.join(self.project_root, "package-lock.json"),
            os.path.join(self.project_root, "pnpm-lock.yaml"),
            os.path.join(self.project_root, "yarn.lock"),
        ]
        self.python_lockfiles = [
            os.path.join(self.project_root, "requirements.txt"),
            os.path.join(self.project_root, "poetry.lock"),
        ]

        # Incident output
        self.incident_log_path = os.path.join(self.project_root, "security_incidents.log")

# ---------------------------------------------------------------------------
# Utility helpers
# ---------------------------------------------------------------------------

def safe_read_file(path: str, max_bytes: int = 2_000_000) -> str:
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="replace")
    except Exception as e:
        LOG.warning(f"Failed to read {path}: {e}")
        return ""

def hash_string(s: str) -> str:
    return hashlib.sha256(s.encode("utf-8", errors="replace")).hexdigest()

def now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"

# ---------------------------------------------------------------------------
# Telemetry & host fingerprinting
# ---------------------------------------------------------------------------

class HostTelemetry:
    """
    Collects basic host fingerprinting data for baseline & anomaly comparison.
    """

    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg
        self.baseline = {}

    def collect(self) -> dict:
        info = {
            "timestamp": now_iso(),
            "hostname": socket.gethostname(),
            "fqdn": socket.getfqdn(),
            "platform": sys.platform,
            "python_version": sys.version,
            "pid": os.getpid(),
        }
        try:
            info["cpu_count"] = psutil.cpu_count(logical=True)
            info["memory_total"] = psutil.virtual_memory().total
            info["boot_time"] = datetime.utcfromtimestamp(psutil.boot_time()).isoformat() + "Z"
            info["uptime_seconds"] = int(time.time() - psutil.boot_time())
        except Exception as e:
            LOG.warning(f"psutil telemetry error: {e}")
        return info

    def establish_baseline(self):
        self.baseline = self.collect()
        LOG.info("Host baseline established.")
        LOG.info(json.dumps(self.baseline, indent=2))

# ---------------------------------------------------------------------------
# Dependency scanning (npm + Python)
# ---------------------------------------------------------------------------

class DependencyScanner:
    """
    Scans lockfiles and installed Python packages for suspicious indicators.
    """

    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg

    def scan_npm_lockfiles(self) -> list:
        findings = []
        for path in self.cfg.npm_lockfiles:
            content = safe_read_file(path)
            if not content:
                continue

            suspicious_names = [
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
            for name in suspicious_names:
                if name in content:
                    findings.append({
                        "type": "npm_lockfile_suspicious_package",
                        "lockfile": path,
                        "package": name,
                    })
        return findings

    def scan_python_lockfiles(self) -> list:
        findings = []
        for path in self.cfg.python_lockfiles:
            content = safe_read_file(path)
            if not content:
                continue

            for pattern in self.cfg.suspicious_crypto_libs:
                if pattern in content:
                    findings.append({
                        "type": "python_lockfile_crypto_lib",
                        "lockfile": path,
                        "library": pattern,
                    })
        return findings

    def scan_installed_python_packages(self) -> list:
        findings = []
        try:
            dists = importlib_metadata.distributions()
        except Exception as e:
            LOG.warning(f"Failed to enumerate distributions: {e}")
            return findings

        for dist in dists:
            name = dist.metadata.get("Name", dist.metadata.get("name", "")).lower()
            for pattern in self.cfg.suspicious_crypto_libs:
                if pattern.lower() in name:
                    findings.append({
                        "type": "python_installed_crypto_lib",
                        "package": name,
                        "version": dist.version,
                    })
        return findings

    def run_full_scan(self) -> list:
        findings = []
        findings.extend(self.scan_npm_lockfiles())
        findings.extend(self.scan_python_lockfiles())
        findings.extend(self.scan_installed_python_packages())
        return findings

# ---------------------------------------------------------------------------
# Network monitoring (psutil-based)
# ---------------------------------------------------------------------------

class NetworkMonitor:
    """
    Monitors network connections for suspicious endpoints or patterns.
    """

    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg

    def snapshot_connections(self) -> list:
        conns = []
        try:
            for c in psutil.net_connections(kind="inet"):
                laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                conns.append({
                    "pid": c.pid,
                    "laddr": laddr,
                    "raddr": raddr,
                    "status": c.status,
                })
        except Exception as e:
            LOG.warning(f"Network snapshot error: {e}")
        return conns

    def detect_suspicious(self, conns: list) -> list:
        findings = []
        for c in conns:
            raddr = c.get("raddr", "")
            if not raddr:
                continue

            for pattern in self.cfg.suspicious_blockchain_patterns:
                if pattern.lower() in raddr.lower():
                    findings.append({
                        "type": "network_blockchain_pattern",
                        "connection": c,
                        "pattern": pattern,
                    })
        return findings

# ---------------------------------------------------------------------------
# Process monitoring (psutil-based)
# ---------------------------------------------------------------------------

class ProcessMonitor:
    """
    Monitors processes for suspicious command lines or environment hints.
    """

    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg

    def snapshot_processes(self) -> list:
        procs = []
        try:
            for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
                info = p.info
                procs.append(info)
        except Exception as e:
            LOG.warning(f"Process snapshot error: {e}")
        return procs

    def detect_suspicious(self, procs: list) -> list:
        findings = []
        webhook_regexes = [re.compile(p) for p in self.cfg.suspicious_webhook_patterns]

        for proc in procs:
            raw_cmd = proc.get("cmdline", [])

            # Normalize cmdline safely
            if isinstance(raw_cmd, list):
                cmdline = " ".join(raw_cmd)
            elif isinstance(raw_cmd, str):
                cmdline = raw_cmd
            else:
                cmdline = ""

            # Heuristic: allow Python scripts in common Startup paths
            lower_cmd = cmdline.lower()
            if ".py" in lower_cmd and ("\\startup" in lower_cmd or "/startup" in lower_cmd):
                continue

            for rx in webhook_regexes:
                if rx.search(cmdline):
                    findings.append({
                        "type": "process_webhook_pattern",
                        "process": proc,
                        "pattern": rx.pattern,
                    })

        return findings

# ---------------------------------------------------------------------------
# Anomaly scoring & incident handling
# ---------------------------------------------------------------------------

class AnomalyScorer:
    """
    Assigns scores to findings and decides incident severity.
    """

    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg

    def score_finding(self, finding: dict) -> int:
        t = finding.get("type", "")
        if t.startswith("npm_lockfile_suspicious_package"):
            return 90
        if t.startswith("network_blockchain_pattern"):
            return 70
        if t.startswith("process_webhook_pattern"):
            return 80
        if t.startswith("python_lockfile_crypto_lib"):
            return 40
        if t.startswith("python_installed_crypto_lib"):
            return 30
        return 10

    def classify(self, score: int) -> str:
        if score >= self.cfg.score_threshold_critical:
            return "critical"
        if score >= self.cfg.score_threshold_incident:
            return "incident"
        return "info"

class IncidentLogger:
    """
    Persists incidents to disk and prints them to console.
    Also forwards incidents to GUI if available.
    """

    def __init__(self, cfg: SecurityConfig, gui_callback=None):
        self.cfg = cfg
        self._lock = threading.Lock()
        self.gui_callback = gui_callback

    def log_incident(self, finding: dict, score: int, severity: str):
        record = {
            "timestamp": now_iso(),
            "severity": severity,
            "score": score,
            "finding": finding,
        }
        line = json.dumps(record)

        with self._lock:
            try:
                with open(self.cfg.incident_log_path, "a", encoding="utf-8") as f:
                    f.write(line + "\n")
            except Exception as e:
                LOG.warning(f"Failed to write incident log: {e}")

        LOG.warning(f"[{severity.upper()}] score={score} finding={finding}")

        if self.gui_callback:
            try:
                self.gui_callback(record)
            except Exception as e:
                LOG.warning(f"GUI callback error: {e}")

class AutoResponder:
    """
    Placeholder for automatic defensive actions (rotate credentials, kill processes, etc.).
    Implement only safe, defensive actions here.
    """

    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg

    def handle(self, finding: dict, score: int, severity: str):
        if severity == "critical":
            LOG.warning("AutoResponder: CRITICAL incident detected. "
                        "Consider rotating credentials, rebuilding environments, "
                        "and isolating affected hosts.")
        elif severity == "incident":
            LOG.warning("AutoResponder: INCIDENT detected. "
                        "Consider manual review, dependency audit, and runtime forensics.")

# ---------------------------------------------------------------------------
# GUI Dashboard
# ---------------------------------------------------------------------------

class SecurityGUI:
    """
    Simple tkinter-based GUI to visualize incidents in real time.
    """

    def __init__(self, cfg: SecurityConfig):
        self.cfg = cfg
        self.root = tk.Tk() if tk else None
        self.incident_queue: "queue.Queue[dict]" = queue.Queue()
        self._setup_ui()

    def _setup_ui(self):
        if not self.root:
            LOG.warning("tkinter not available; GUI disabled.")
            return

        self.root.title("Codex Sentinel - SecurityGovernor Dashboard")

        main_frame = ttk.Frame(self.root, padding=8)
        main_frame.pack(fill=tk.BOTH, expand=True)

        header = ttk.Label(main_frame, text="Runtime Threat Evaluation", font=("Segoe UI", 12, "bold"))
        header.pack(side=tk.TOP, anchor="w")

        self.tree = ttk.Treeview(
            main_frame,
            columns=("time", "severity", "score", "summary"),
            show="headings",
            height=20
        )
        self.tree.heading("time", text="Time")
        self.tree.heading("severity", text="Severity")
        self.tree.heading("score", text="Score")
        self.tree.heading("summary", text="Summary")

        self.tree.column("time", width=160, anchor="w")
        self.tree.column("severity", width=80, anchor="center")
        self.tree.column("score", width=60, anchor="center")
        self.tree.column("summary", width=500, anchor="w")

        self.tree.pack(fill=tk.BOTH, expand=True)

        footer = ttk.Label(
            main_frame,
            text="Monitoring processes, network, and dependencies for suspicious activity...",
            font=("Segoe UI", 9)
        )
        footer.pack(side=tk.BOTTOM, anchor="w")

        self.root.after(500, self._drain_queue)

    def push_incident(self, record: dict):
        self.incident_queue.put(record)

    def _drain_queue(self):
        if not self.root:
            return
        try:
            while True:
                record = self.incident_queue.get_nowait()
                ts = record.get("timestamp", "")
                sev = record.get("severity", "")
                score = record.get("score", 0)
                finding = record.get("finding", {})
                summary = finding.get("type", "")
                self.tree.insert(
                    "",
                    tk.END,
                    values=(ts, sev, score, summary)
                )
        except queue.Empty:
            pass
        self.root.after(500, self._drain_queue)

    def run(self):
        if not self.root:
            LOG.warning("GUI not available; skipping.")
            return
        self.root.mainloop()

# ---------------------------------------------------------------------------
# Main governor orchestrator
# ---------------------------------------------------------------------------

class SecurityGovernor:
    """
    Orchestrates all components into a single runtime protection loop.
    """

    def __init__(self, cfg: SecurityConfig, gui: SecurityGUI = None):
        self.cfg = cfg
        self.telemetry = HostTelemetry(cfg)
        self.dep_scanner = DependencyScanner(cfg)
        self.net_monitor = NetworkMonitor(cfg)
        self.proc_monitor = ProcessMonitor(cfg)
        self.scorer = AnomalyScorer(cfg)
        self.gui = gui
        gui_callback = self.gui.push_incident if self.gui else None
        self.incident_logger = IncidentLogger(cfg, gui_callback=gui_callback)
        self.auto_responder = AutoResponder(cfg)
        self._stop_event = threading.Event()
        self._event_queue: "queue.Queue[dict]" = queue.Queue()

    def start(self):
        LOG.info("SecurityGovernor starting...")
        if self.cfg.enable_host_fingerprint:
            self.telemetry.establish_baseline()

        threads = []

        if self.cfg.enable_dependency_scan:
            t = threading.Thread(target=self._dependency_scan_loop, daemon=True)
            threads.append(t)
            t.start()

        if self.cfg.enable_network_monitor:
            t = threading.Thread(target=self._network_monitor_loop, daemon=True)
            threads.append(t)
            t.start()

        if self.cfg.enable_process_monitor:
            t = threading.Thread(target=self._process_monitor_loop, daemon=True)
            threads.append(t)
            t.start()

        dispatcher = threading.Thread(target=self._event_dispatch_loop, daemon=True)
        dispatcher.start()

        LOG.info("SecurityGovernor is now running.")

        if self.gui and self.gui.root:
            self.gui.run()
            self._stop_event.set()
        else:
            try:
                while not self._stop_event.is_set():
                    time.sleep(1)
            except KeyboardInterrupt:
                LOG.info("SecurityGovernor stopping (KeyboardInterrupt).")
                self._stop_event.set()

    def _dependency_scan_loop(self):
        while not self._stop_event.is_set():
            LOG.info("Running dependency scan...")
            findings = self.dep_scanner.run_full_scan()
            for f in findings:
                self._event_queue.put(f)
            time.sleep(max(self.cfg.poll_interval_seconds * 12, 60))

    def _network_monitor_loop(self):
        while not self._stop_event.is_set():
            conns = self.net_monitor.snapshot_connections()
            findings = self.net_monitor.detect_suspicious(conns)
            for f in findings:
                self._event_queue.put(f)
            time.sleep(self.cfg.poll_interval_seconds)

    def _process_monitor_loop(self):
        while not self._stop_event.is_set():
            procs = self.proc_monitor.snapshot_processes()
            findings = self.proc_monitor.detect_suspicious(procs)
            for f in findings:
                self._event_queue.put(f)
            time.sleep(self.cfg.poll_interval_seconds)

    def _event_dispatch_loop(self):
        while not self._stop_event.is_set():
            try:
                finding = self._event_queue.get(timeout=1)
            except queue.Empty:
                continue

            score = self.scorer.score_finding(finding)
            severity = self.scorer.classify(score)
            self.incident_logger.log_incident(finding, score, severity)
            self.auto_responder.handle(finding, score, severity)

# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    cfg = SecurityConfig()
    gui = SecurityGUI(cfg) if tk and ttk else None
    governor = SecurityGovernor(cfg, gui=gui)
    governor.start()

if __name__ == "__main__":
    main()
