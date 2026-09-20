#!/usr/bin/env python3
# ============================================================
# TargetingComputer_DominionDeck_BorgProbes_GameTelemetry_Advanced.py
# Cyber-Command Dashboard (Upgraded) with:
# - Active Autoloader + dependency validator
# - Async-friendly architecture (threaded but event-coordinated)
# - Threat list + AI control + manual override
# - VRAM-accelerated threat scoring (GPU-backed if available)
# - Predictive engine (Bernoulli/Beta-style risk estimation)
# - Missing-detail detection + best-guess scoring
# - “Intelligent water” data physics engine (score diffusion)
# - Threat timeline graph (score evolution)
# - Threat heatmap (matplotlib)
# - Swarm-sync nodes + swarm map visualization
# - Star Trek-style probes + trajectory visualization
# - Real game telemetry integration (CPU/GPU/process load)
# - GPU curve visualizer + VRAM stress test
# - Plugin API with sandboxed execution (multiprocessing)
# - DominionDeck integration hooks + purge-rule diff viewer (stubbed)
# - Windows Defender status + folder snapshot utilities
# ============================================================

import importlib
import subprocess
import sys
import os
import threading
import time
import random
import math
import socket
import json
import queue
import multiprocessing as mp

# ------------------------------------------------------------
# AUTOLOADER (active)
# ------------------------------------------------------------
REQUIRED_LIBS = [
    "tkinter",
    "numpy",
    "matplotlib",
    "psutil",
]

def autoload():
    missing = []
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            missing.append(lib)
    if not missing:
        return
    print("[AUTOLOADER] Missing libraries:", ", ".join(missing))
    print("[AUTOLOADER] Attempting installation...")
    for lib in missing:
        try:
            print(f"[AUTOLOADER] Installing {lib}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
        except Exception as e:
            print(f"[AUTOLOADER] Failed to install {lib}: {e}")

# Uncomment if you want auto-install on startup
# autoload()

# ------------------------------------------------------------
# IMPORTS
# ------------------------------------------------------------
import tkinter as tk
from tkinter import ttk

try:
    import numpy as np
except ImportError:
    np = None

try:
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except Exception:
    Figure = None
    FigureCanvasTkAgg = None

try:
    import winsound
except ImportError:
    winsound = None

try:
    import psutil
except ImportError:
    psutil = None

# Optional GPU backends
try:
    import cupy as cp
except ImportError:
    cp = None

try:
    import torch
except ImportError:
    torch = None

# Optional GPU telemetry (NVIDIA)
try:
    import pynvml
    pynvml.nvmlInit()
except Exception:
    pynvml = None

# ------------------------------------------------------------
# Persistence paths
# ------------------------------------------------------------
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATA_DIR = os.path.join(BASE_DIR, "data")
if not os.path.isdir(DATA_DIR):
    try:
        os.makedirs(DATA_DIR, exist_ok=True)
    except Exception:
        pass

THREAT_HISTORY_PATH = os.path.join(DATA_DIR, "threat_history.json")
PROBE_HISTORY_PATH = os.path.join(DATA_DIR, "probe_history.json")
SWARM_HISTORY_PATH = os.path.join(DATA_DIR, "swarm_history.json")
TELEMETRY_HISTORY_PATH = os.path.join(DATA_DIR, "telemetry_history.json")
PURGE_RULES_LOCAL_PATH = os.path.join(DATA_DIR, "purge_rules_local.json")
PURGE_RULES_REMOTE_PATH = os.path.join(DATA_DIR, "purge_rules_remote.json")

def safe_load_json(path, default):
    try:
        if os.path.isfile(path):
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return default

def safe_save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

# ------------------------------------------------------------
# Threat + Engine
# ------------------------------------------------------------
class Threat:
    def __init__(self, name, level, port=None):
        self.name = name
        self.level = level
        self.port = port
        self.status = "ACTIVE"
        self.score = 0.0
        self.predicted_risk = 0.0
        self.missing_details = []
        self.assimilated = False
        self.timeline = []  # (timestamp, score)

    def snapshot(self):
        return {
            "name": self.name,
            "level": self.level,
            "port": self.port,
            "status": self.status,
            "score": self.score,
            "predicted_risk": self.predicted_risk,
            "missing_details": list(self.missing_details),
            "assimilated": self.assimilated,
            "timeline": list(self.timeline),
        }

    def __repr__(self):
        return f"{self.name} (L{self.level}, S{self.score:.2f}, P{self.predicted_risk:.2f}) - {self.status}"

class ThreatEngine:
    def __init__(self, log_callback, scoring_callback, predictive_callback, water_callback):
        self.log = log_callback
        self.score_cb = scoring_callback
        self.predict_cb = predictive_callback
        self.water_cb = water_callback
        self.threats = []
        self.ai_enabled = True
        self.borg_mode = False
        self.load_factor = 0.0  # from game telemetry
        self.history = safe_load_json(THREAT_HISTORY_PATH, [])

    def add_threat(self, name, level, port=None):
        t = Threat(name, level, port)
        if level is None:
            t.missing_details.append("level")
        if port is None:
            t.missing_details.append("port")
        self.threats.append(t)
        self.log(f"[ENGINE] Threat added: {t}")
        self.update_all()
        self.persist()

    def remove_threat(self, threat):
        threat.status = "NEUTRALIZED"
        self.log(f"[ENGINE] Threat neutralized: {threat}")
        self.persist()

    def update_all(self):
        if not self.threats:
            return
        self.score_cb(self.threats, self.borg_mode, self.load_factor)
        self.predict_cb(self.threats)
        self.water_cb(self.threats)
        ts = time.time()
        for t in self.threats:
            t.timeline.append((ts, t.score))
        self.persist()

    def persist(self):
        snapshot = [t.snapshot() for t in self.threats]
        self.history = snapshot
        safe_save_json(THREAT_HISTORY_PATH, snapshot)

    def ai_cycle(self):
        # Safe behavior: AI may identify and log a candidate, but never neutralizes automatically.
        while True:
            time.sleep(2)
            if self.ai_enabled and self.threats:
                active = [t for t in self.threats if t.status == "ACTIVE"]
                if active:
                    target = max(active, key=lambda x: x.predicted_risk)
                    self.log(f"[AI] Review candidate: {target.name} (Predicted {target.predicted_risk:.2f})")

# ------------------------------------------------------------
# Swarm Sync Nodes + Swarm Map
# ------------------------------------------------------------
class SwarmNode:
    def __init__(self, node_id):
        self.node_id = node_id
        self.status = "ONLINE"
        self.load = random.uniform(0.1, 0.9)

    def snapshot(self):
        return {
            "node_id": self.node_id,
            "status": self.status,
            "load": self.load,
        }

    def __repr__(self):
        return f"Node-{self.node_id} [{self.status}] Load={self.load:.2f}"

class SwarmManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.nodes = [SwarmNode(i) for i in range(1, 6)]
        self.history = safe_load_json(SWARM_HISTORY_PATH, [])

    def sync_cycle(self):
        while True:
            time.sleep(3)
            for n in self.nodes:
                n.load = max(0.0, min(1.0, n.load + random.uniform(-0.1, 0.1)))
            self.log("[SWARM] Sync tick: " + ", ".join(f"{n.node_id}:{n.load:.2f}" for n in self.nodes))
            self.persist()

    def persist(self):
        snapshot = {
            "timestamp": time.time(),
            "nodes": [n.snapshot() for n in self.nodes],
        }
        self.history.append(snapshot)
        safe_save_json(SWARM_HISTORY_PATH, self.history)

# ------------------------------------------------------------
# Plugin API with sandbox (multiprocessing)
# ------------------------------------------------------------
class PluginManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.plugins = []
        self.plugin_dir = os.path.join(BASE_DIR, "plugins")
        if not os.path.isdir(self.plugin_dir):
            try:
                os.makedirs(self.plugin_dir, exist_ok=True)
            except Exception:
                pass

    def load_plugins(self):
        import importlib.util
        self.plugins.clear()
        if not os.path.isdir(self.plugin_dir):
            self.log("[PLUGIN] Plugin directory missing.")
            return
        for fname in os.listdir(self.plugin_dir):
            if fname.endswith(".py"):
                path = os.path.join(self.plugin_dir, fname)
                mod_name = f"plugin_{fname[:-3]}"
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if spec and spec.loader:
                    try:
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)
                        if hasattr(mod, "run"):
                            self.plugins.append((fname, path))
                            self.log(f"[PLUGIN] Loaded: {fname}")
                        else:
                            self.log(f"[PLUGIN] Skipped (no run()): {fname}")
                    except Exception as e:
                        self.log(f"[PLUGIN] Failed to load {fname}: {e}")

    @staticmethod
    def _sandbox_worker(path, context, out_q):
        try:
            import importlib.util
            spec = importlib.util.spec_from_file_location("sandbox_plugin", path)
            if spec and spec.loader:
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "run"):
                    mod.run(context)
                    out_q.put((os.path.basename(path), "OK", ""))
                else:
                    out_q.put((os.path.basename(path), "SKIP", "No run()"))
            else:
                out_q.put((os.path.basename(path), "ERROR", "Spec/loader missing"))
        except Exception as e:
            out_q.put((os.path.basename(path), "ERROR", str(e)))

    def run_plugins(self, context):
        if not self.plugins:
            self.log("[PLUGIN] No plugins to run.")
            return
        out_q = mp.Queue()
        procs = []
        for fname, path in self.plugins:
            p = mp.Process(target=self._sandbox_worker, args=(path, context, out_q))
            p.start()
            procs.append(p)
        for p in procs:
            p.join(timeout=10)
        while not out_q.empty():
            name, status, msg = out_q.get()
            if status == "OK":
                self.log(f"[PLUGIN] Executed plugin: {name}")
            elif status == "SKIP":
                self.log(f"[PLUGIN] Skipped plugin {name}: {msg}")
            else:
                self.log(f"[PLUGIN] Error in {name}: {msg}")

# ------------------------------------------------------------
# VRAM-Accelerated Threat Scoring + Borg + Load Factor
# ------------------------------------------------------------
def vram_accelerated_scoring(threats, borg_mode=False, load_factor=0.0):
    levels = [t.level if t.level is not None else 1 for t in threats]
    ports = [t.port if t.port is not None else 0 for t in threats]

    if cp is not None:
        base = cp.array(levels, dtype=cp.float32)
        port_weight = cp.array(ports, dtype=cp.float32)
        scores = base * 1.7 + (port_weight > 0) * 2.3 + cp.random.rand(len(threats)) * 0.7
        scores = cp.asnumpy(scores)
    elif torch is not None:
        base = torch.tensor(levels, dtype=torch.float32)
        port_weight = torch.tensor(ports, dtype=torch.float32)
        scores = base * 1.7 + (port_weight > 0) * 2.3 + torch.rand(len(threats)) * 0.7
        scores = scores.detach().cpu().numpy()
    elif np is not None:
        base = np.array(levels, dtype=float)
        port_weight = np.array(ports, dtype=float)
        scores = base * 1.7 + (port_weight > 0) * 2.3 + np.random.rand(len(threats)) * 0.7
    else:
        scores = []
        for l, p in zip(levels, ports):
            s = l * 1.7 + (1 if p > 0 else 0) * 2.3 + random.random() * 0.7
            scores.append(s)

    collective_boost = 0.0
    if borg_mode and threats:
        collective_boost = sum(scores) / len(scores) * 0.1

    load_boost = load_factor * 0.5

    for t, s in zip(threats, scores):
        t.score = float(s + collective_boost + load_boost)
        t.assimilated = borg_mode

# ------------------------------------------------------------
# Predictive Engine (Bernoulli/Beta-style)
# ------------------------------------------------------------
def predictive_engine(threats):
    for t in threats:
        alpha = 1.0 + (t.level if t.level is not None else 1)
        beta = 1.0
        if t.port is not None:
            alpha += 1.0
        if t.missing_details:
            beta += len(t.missing_details) * 0.5
        expected = alpha / (alpha + beta)
        t.predicted_risk = expected * (1.0 + t.score * 0.1)

# ------------------------------------------------------------
# Intelligent Water Data Physics Engine
# ------------------------------------------------------------
def water_engine(threats):
    if not threats:
        return
    if np is not None:
        scores = np.array([t.score for t in threats], dtype=float)
        smoothed = scores.copy()
        for i in range(len(scores)):
            neighbors = []
            if i > 0:
                neighbors.append(scores[i - 1])
            if i < len(scores) - 1:
                neighbors.append(scores[i + 1])
            if neighbors:
                smoothed[i] = 0.7 * scores[i] + 0.3 * sum(neighbors) / len(neighbors)
        for t, s in zip(threats, smoothed):
            t.score = float(s)
    else:
        new_scores = []
        for i, t in enumerate(threats):
            neighbors = []
            if i > 0:
                neighbors.append(threats[i - 1].score)
            if i < len(threats) - 1:
                neighbors.append(threats[i + 1].score)
            if neighbors:
                new_scores.append(0.7 * t.score + 0.3 * sum(neighbors) / len(neighbors))
            else:
                new_scores.append(t.score)
        for t, s in zip(threats, new_scores):
            t.score = float(s)

# ------------------------------------------------------------
# Network Scanner
# ------------------------------------------------------------
def scan_ports(host="127.0.0.1", ports=None, timeout=0.2):
    if ports is None:
        ports = [22, 35, 80, 443, 8080]
    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((host, p)) == 0:
                open_ports.append(p)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports

# ------------------------------------------------------------
# Sound Effects
# ------------------------------------------------------------
def play_beep():
    if winsound:
        winsound.Beep(1000, 150)

def play_target_lock():
    if winsound:
        winsound.Beep(1500, 200)
        winsound.Beep(1800, 200)

def play_neutralize():
    if winsound:
        winsound.Beep(800, 200)
        winsound.Beep(600, 200)

# ------------------------------------------------------------
# Star Trek-style Probes + Trajectory
# ------------------------------------------------------------
class Probe:
    def __init__(self, probe_id):
        self.probe_id = probe_id
        self.status = "IDLE"
        self.sector = "N/A"
        self.reading = 0.0
        self.history = []  # (timestamp, sector, reading)

    def snapshot(self):
        return {
            "probe_id": self.probe_id,
            "status": self.status,
            "sector": self.sector,
            "reading": self.reading,
            "history": list(self.history),
        }

    def __repr__(self):
        return f"Probe-{self.probe_id} [{self.status}] Sector={self.sector} Reading={self.reading:.2f}"

class ProbeManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.probes = [Probe(i) for i in range(1, 4)]
        self.running = True
        self.history = safe_load_json(PROBE_HISTORY_PATH, [])

    def cycle(self):
        sectors = ["Alpha", "Beta", "Gamma", "Delta", "Omega"]
        while self.running:
            time.sleep(2)
            ts = time.time()
            for p in self.probes:
                if p.status == "LAUNCHED":
                    p.sector = random.choice(sectors)
                    p.reading = random.uniform(0.0, 1.0)
                    p.history.append((ts, p.sector, p.reading))
            self.log("[PROBE] Telemetry tick: " + ", ".join(
                f"{p.probe_id}:{p.sector}:{p.reading:.2f}" for p in self.probes if p.status == "LAUNCHED"
            ))
            self.persist()

    def launch_probe(self, probe):
        probe.status = "LAUNCHED"
        self.log(f"[PROBE] Launched Probe-{probe.probe_id}")
        self.persist()

    def recall_probe(self, probe):
        probe.status = "IDLE"
        probe.sector = "N/A"
        probe.reading = 0.0
        self.log(f"[PROBE] Recalled Probe-{probe.probe_id}")
        self.persist()

    def persist(self):
        snapshot = {
            "timestamp": time.time(),
            "probes": [p.snapshot() for p in self.probes],
        }
        self.history.append(snapshot)
        safe_save_json(PROBE_HISTORY_PATH, self.history)

# ------------------------------------------------------------
# DominionDeck Integration Hooks + Purge Diff (stub)
# ------------------------------------------------------------
class DominionDeckHooks:
    def __init__(self, log_callback):
        self.log = log_callback
        self.local_rules = safe_load_json(PURGE_RULES_LOCAL_PATH, {"rules": []})
        self.remote_rules = safe_load_json(PURGE_RULES_REMOTE_PATH, {"rules": []})

    def push_threat_matrix(self, threats):
        self.log(f"[DOMINIONDECK] Pushed threat matrix ({len(threats)} entries).")

    def pull_purge_rules(self):
        # Stub: simulate remote rules change
        self.remote_rules = {
            "rules": [
                {"id": "R1", "pattern": "Rogue AI", "action": "NEUTRALIZE"},
                {"id": "R2", "pattern": "Hacker", "action": "FLAG"},
            ]
        }
        safe_save_json(PURGE_RULES_REMOTE_PATH, self.remote_rules)
        self.log("[DOMINIONDECK] Pulled purge rules (stub).")

    def diff_purge_rules(self):
        local_ids = {r.get("id") for r in self.local_rules.get("rules", [])}
        remote_ids = {r.get("id") for r in self.remote_rules.get("rules", [])}
        added = remote_ids - local_ids
        removed = local_ids - remote_ids
        changed = local_ids & remote_ids
        return {
            "added": [r for r in self.remote_rules.get("rules", []) if r.get("id") in added],
            "removed": [r for r in self.local_rules.get("rules", []) if r.get("id") in removed],
            "changed": [r for r in self.remote_rules.get("rules", []) if r.get("id") in changed],
        }

# ------------------------------------------------------------
# Game Telemetry Manager + GPU curves
# ------------------------------------------------------------
class GameTelemetryManager:
    def __init__(self, log_callback, engine):
        self.log = log_callback
        self.engine = engine
        self.running = True
        self.last_load_factor = 0.0
        self.last_snapshot = []
        self.history = safe_load_json(TELEMETRY_HISTORY_PATH, [])
        self.gpu_curve = []  # (timestamp, gpu_util)

    def sample(self):
        if not psutil:
            return
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        gpu_util = 0.0
        if pynvml:
            try:
                handle = pynvml.nvmlDeviceGetHandleByIndex(0)
                util = pynvml.nvmlDeviceGetUtilizationRates(handle)
                gpu_util = float(util.gpu)
            except Exception:
                gpu_util = 0.0

        load_factor = (cpu + mem + gpu_util) / 300.0
        self.engine.load_factor = load_factor
        self.last_load_factor = load_factor

        heavy_procs = []
        try:
            for p in psutil.process_iter(["name", "cpu_percent", "memory_info"]):
                name = p.info["name"] or ""
                cpu_p = p.info["cpu_percent"] or 0.0
                mem_p = (p.info["memory_info"].rss / (1024 * 1024)) if p.info["memory_info"] else 0.0
                if cpu_p > 5.0 or mem_p > 500.0:
                    heavy_procs.append((name, cpu_p, mem_p))
        except Exception:
            pass

        heavy_procs.sort(key=lambda x: x[1], reverse=True)
        self.last_snapshot = heavy_procs[:10]

        ts = time.time()
        self.gpu_curve.append((ts, gpu_util))
        snapshot = {
            "timestamp": ts,
            "cpu": cpu,
            "mem": mem,
            "gpu": gpu_util,
            "load_factor": load_factor,
            "heavy_procs": self.last_snapshot,
        }
        self.history.append(snapshot)
        safe_save_json(TELEMETRY_HISTORY_PATH, self.history)

        self.log(f"[GAME] Telemetry CPU={cpu:.1f}% MEM={mem:.1f}% GPU={gpu_util:.1f}% LoadFactor={load_factor:.3f}")
        self.engine.update_all()

    def cycle(self):
        while self.running:
            time.sleep(3)
            self.sample()

# ------------------------------------------------------------
# VRAM Stress Test
# ------------------------------------------------------------
def vram_stress_test(duration=5.0, log_callback=None):
    start = time.time()
    ops = 0
    if cp is None and torch is None:
        if log_callback:
            log_callback("[VRAM] No GPU backend available for stress test.")
        return 0
    if cp is not None:
        while time.time() - start < duration:
            try:
                a = cp.random.rand(1024, 1024, dtype=cp.float32)
                b = cp.random.rand(1024, 1024, dtype=cp.float32)
                c = a * b + cp.sin(a)
                del a, b, c
                ops += 1
            except Exception:
                break
    elif torch is not None:
        device = torch.device("cuda:0" if torch.cuda.is_available() else "cpu")
        while time.time() - start < duration:
            try:
                a = torch.rand((1024, 1024), device=device)
                b = torch.rand((1024, 1024), device=device)
                c = a * b + torch.sin(a)
                del a, b, c
                ops += 1
            except Exception:
                break
    if log_callback:
        log_callback(f"[VRAM] Stress test completed: {ops} heavy ops in {duration:.1f}s")
    return ops

# ------------------------------------------------------------
# Basic Windows defensive checks
# ------------------------------------------------------------
def windows_defender_status():
    if os.name != "nt":
        return "Windows Defender status requires Windows."
    cmd = [
        "powershell.exe", "-NoProfile", "-NonInteractive", "-Command",
        "Get-MpComputerStatus | Select RealTimeProtectionEnabled,BehaviorMonitorEnabled,IsTamperProtected | Format-List"
    ]
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=8).stdout.strip() or "Unable to read Defender status."
    except Exception as e:
        return f"Defender check failed: {e}"

def watch_folder_snapshot(folder):
    result = {}
    try:
        for name in os.listdir(folder):
            path = os.path.join(folder, name)
            if os.path.isfile(path):
                st = os.stat(path)
                result[path] = (st.st_size, st.st_mtime)
    except Exception:
        pass
    return result

# ------------------------------------------------------------
# GUI
# ------------------------------------------------------------
class TargetingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Targeting Computer — DominionDeck Borg Probes + Game Telemetry (Advanced)")
        self.root.geometry("1350x820")
        self.root.minsize(1000, 700)

        self.engine = ThreatEngine(
            self.write_log,
            vram_accelerated_scoring,
            predictive_engine,
            water_engine
        )

        self.swarm = SwarmManager(self.write_log)
        self.plugins = PluginManager(self.write_log)
        self.probes = ProbeManager(self.write_log)
        self.dd_hooks = DominionDeckHooks(self.write_log)
        self.game_telemetry = GameTelemetryManager(self.write_log, self.engine)

        self.main_frame = ttk.Frame(root, padding=6)
        self.main_frame.pack(fill="both", expand=True)

        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(fill="both", expand=True)

        self.overview_tab = ttk.Frame(self.notebook, padding=5)
        self.security_tab = ttk.Frame(self.notebook, padding=5)
        self.operations_tab = ttk.Frame(self.notebook, padding=5)
        self.telemetry_tab = ttk.Frame(self.notebook, padding=5)
        self.analytics_tab = ttk.Frame(self.notebook, padding=5)
        self.notebook.add(self.overview_tab, text="Overview")
        self.notebook.add(self.security_tab, text="Security")
        self.notebook.add(self.operations_tab, text="Operations")
        self.notebook.add(self.telemetry_tab, text="Telemetry")
        self.notebook.add(self.analytics_tab, text="Analytics")

        overview_left = ttk.Frame(self.overview_tab)
        overview_left.pack(side="left", fill="both", expand=True)
        overview_right = ttk.Frame(self.overview_tab)
        overview_right.pack(side="right", fill="both", expand=True)
        self.build_threat_panel(overview_left)
        self.build_targeting_panel(overview_left)
        self.build_reticle_panel(overview_right)

        security_left = ttk.Frame(self.security_tab)
        security_left.pack(side="left", fill="both", expand=True)
        security_right = ttk.Frame(self.security_tab)
        security_right.pack(side="right", fill="both", expand=True)
        self.build_network_panel(security_left)
        self.build_heatmap_panel(security_right)

        operations_left = ttk.Frame(self.operations_tab)
        operations_left.pack(side="left", fill="both", expand=True)
        operations_right = ttk.Frame(self.operations_tab)
        operations_right.pack(side="right", fill="both", expand=True)
        self.build_swarm_panel(operations_left)
        self.build_plugin_panel(operations_left)
        self.build_probe_panel(operations_right)

        telemetry_left = ttk.Frame(self.telemetry_tab)
        telemetry_left.pack(side="left", fill="both", expand=True)
        telemetry_right = ttk.Frame(self.telemetry_tab)
        telemetry_right.pack(side="right", fill="both", expand=True)
        self.build_game_panel(telemetry_left)
        self.build_gpu_curve_panel(telemetry_right)

        self.build_analytics_panel(self.analytics_tab)

        log_frame = ttk.LabelFrame(self.main_frame, text="Live Event Log")
        log_frame.pack(fill="x", pady=(6, 0))
        self.log_box = tk.Text(log_frame, height=5, bg="#111", fg="#0f0", wrap="word")
        self.log_box.pack(side="left", fill="both", expand=True)
        log_scroll = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_box.yview)
        log_scroll.pack(side="right", fill="y")
        self.log_box.configure(yscrollcommand=log_scroll.set)

        threading.Thread(target=self.engine.ai_cycle, daemon=True).start()
        threading.Thread(target=self.swarm.sync_cycle, daemon=True).start()
        threading.Thread(target=self.probes.cycle, daemon=True).start()
        threading.Thread(target=self.game_telemetry.cycle, daemon=True).start()

        self.plugins.load_plugins()

        self.reticle_running = True
        self.reticle_angle = 0.0
        self.reticle_radius = 100
        self.animate_reticle()

    # --------------------------------------------------------
    # LOGGING
    # --------------------------------------------------------
    def write_log(self, msg):
        self.root.after(0, self._write_log_main, str(msg))

    def _write_log_main(self, msg):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    # --------------------------------------------------------
    # THREAT PANEL
    # --------------------------------------------------------
    def build_threat_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Threats")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.threat_list = tk.Listbox(frame, height=12)
        self.threat_list.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(side="right", fill="y")

        tk.Button(btn_frame, text="Add Rogue AI",
                  command=lambda: self.add_threat("Rogue AI", 5)).pack(fill="x")
        tk.Button(btn_frame, text="Add Hacker",
                  command=lambda: self.add_threat("Hacker", 3)).pack(fill="x")
        tk.Button(btn_frame, text="Add Hacker on Port 35",
                  command=lambda: self.add_threat("Hacker on Port 35", 4, 35)).pack(fill="x")
        tk.Button(btn_frame, text="Add Rogue Shell Script",
                  command=lambda: self.add_threat("Rogue Shell Script", 2)).pack(fill="x")
        tk.Button(btn_frame, text="Add Unknown Threat (Missing Details)",
                  command=lambda: self.add_threat("Unknown Threat", None, None)).pack(fill="x")
        tk.Button(btn_frame, text="Refresh Threats",
                  command=self.refresh_threat_list).pack(fill="x")
        tk.Button(btn_frame, text="Push Threat Matrix to DominionDeck",
                  command=self.push_dd_matrix).pack(fill="x")

    def add_threat(self, name, level, port=None):
        self.engine.add_threat(name, level, port)
        play_beep()
        self.refresh_threat_list()
        self.update_heatmap()
        self.update_threat_timeline()

    def refresh_threat_list(self):
        self.threat_list.delete(0, "end")
        for t in self.engine.threats:
            missing = f" MD:{','.join(t.missing_details)}" if t.missing_details else ""
            borg = " [BORG]" if t.assimilated else ""
            self.threat_list.insert(
                "end",
                f"{t.name}{borg} — L{t.level if t.level is not None else '?'} — S{t.score:.2f} — P{t.predicted_risk:.2f} — {t.status}{missing}"
            )

    def push_dd_matrix(self):
        self.dd_hooks.push_threat_matrix(self.engine.threats)

    # --------------------------------------------------------
    # TARGETING PANEL
    # --------------------------------------------------------
    def build_targeting_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Targeting Computer")
        frame.pack(fill="x", padx=10, pady=10)

        self.ai_var = tk.BooleanVar(value=True)
        tk.Checkbutton(frame, text="AI-Controlled Mode",
                       variable=self.ai_var,
                       command=self.toggle_ai).pack(anchor="w")

        self.borg_var = tk.BooleanVar(value=False)
        tk.Checkbutton(frame, text="Borg Tech Mode (Collective Assimilation)",
                       variable=self.borg_var,
                       command=self.toggle_borg).pack(anchor="w")

        tk.Button(frame, text="Manual Target Neutralize",
                  command=self.manual_target).pack(fill="x")

        tk.Button(frame, text="Recompute Threat Scores (VRAM + Predictive + Water)",
                  command=self.recompute_scores).pack(fill="x")

        tk.Button(frame, text="Pull Purge Rules (DominionDeck)",
                  command=self.pull_dd_rules).pack(fill="x")

        tk.Button(frame, text="Show Purge Rule Diff",
                  command=self.show_purge_diff).pack(fill="x")

    def toggle_ai(self):
        self.engine.ai_enabled = self.ai_var.get()
        mode = "ENABLED" if self.engine.ai_enabled else "DISABLED"
        self.write_log(f"[SYSTEM] AI mode {mode}")
        play_beep()

    def toggle_borg(self):
        self.engine.borg_mode = self.borg_var.get()
        state = "ACTIVE" if self.engine.borg_mode else "INACTIVE"
        self.write_log(f"[SYSTEM] Borg tech mode {state}")
        self.engine.update_all()
        self.refresh_threat_list()
        self.update_heatmap()
        self.update_threat_timeline()

    def manual_target(self):
        idx = self.threat_list.curselection()
        if not idx:
            self.write_log("[MANUAL] No threat selected.")
            return

        threat = self.engine.threats[idx[0]]
        if threat.status != "ACTIVE":
            self.write_log("[MANUAL] Threat already neutralized.")
            return

        self.write_log(f"[MANUAL] Neutralizing: {threat.name}")
        play_target_lock()
        self.engine.remove_threat(threat)
        play_neutralize()
        self.refresh_threat_list()
        self.update_heatmap()
        self.update_threat_timeline()

    def recompute_scores(self):
        self.write_log("[SCORING] Recomputing threat scores (VRAM + predictive + water)...")
        self.engine.update_all()
        self.refresh_threat_list()
        self.update_heatmap()
        self.update_threat_timeline()

    def pull_dd_rules(self):
        self.dd_hooks.pull_purge_rules()
        self.write_log("[DOMINIONDECK] Remote purge rules updated.")

    def show_purge_diff(self):
        diff = self.dd_hooks.diff_purge_rules()
        self.write_log("[DOMINIONDECK] Purge rule diff:")
        self.write_log(f"  Added: {diff['added']}")
        self.write_log(f"  Removed: {diff['removed']}")
        self.write_log(f"  Changed: {diff['changed']}")

    # --------------------------------------------------------
    # RETICLE PANEL
    # --------------------------------------------------------
    def build_reticle_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Targeting Reticle")
        frame.pack(fill="x", padx=10, pady=10)

        self.reticle_canvas = tk.Canvas(frame, width=300, height=300, bg="#000")
        self.reticle_canvas.pack()

    def animate_reticle(self):
        if not self.reticle_running:
            return

        self.reticle_canvas.delete("all")

        cx, cy = 150, 150
        r = self.reticle_radius

        self.reticle_canvas.create_oval(cx - r, cy - r, cx + r, cy + r,
                                        outline="#0f0", width=2)
        self.reticle_canvas.create_line(cx - r, cy, cx + r, cy, fill="#0f0")
        self.reticle_canvas.create_line(cx, cy - r, cx, cy + r, fill="#0f0")

        angle = self.reticle_angle
        for offset in [0, math.pi / 2, math.pi, 3 * math.pi / 2]:
            a = angle + offset
            x1 = cx + r * 0.6 * math.cos(a)
            y1 = cy + r * 0.6 * math.sin(a)
            x2 = cx + r * 0.9 * math.cos(a)
            y2 = cy + r * 0.9 * math.sin(a)
            self.reticle_canvas.create_line(x1, y1, x2, y2, fill="#0f0", width=3)

        self.reticle_angle += 0.1
        self.root.after(50, self.animate_reticle)

    # --------------------------------------------------------
    # NETWORK PANEL
    # --------------------------------------------------------
    def build_network_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Network Scanner")
        frame.pack(fill="x", padx=10, pady=10)

        self.scan_result_box = tk.Listbox(frame, height=6)
        self.scan_result_box.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(side="right", fill="y")

        tk.Button(btn_frame, text="Scan Local Ports",
                  command=self.run_scan).pack(fill="x")

    def run_scan(self):
        self.write_log("[NET] Scanning local ports...")
        threading.Thread(target=self._scan_worker, daemon=True).start()

    def _scan_worker(self):
        ports = scan_ports()
        self.root.after(0, lambda: self._show_scan_results(ports))

    def _show_scan_results(self, ports):
        self.scan_result_box.delete(0, "end")
        if ports:
            for p in ports:
                self.scan_result_box.insert("end", f"Port {p} OPEN")
            self.write_log("[NET] Open ports: " + ", ".join(str(p) for p in ports))
        else:
            self.scan_result_box.insert("end", "No known ports open.")
            self.write_log("[NET] No known ports open.")

    # --------------------------------------------------------
    # SWARM PANEL + Swarm Map
    # --------------------------------------------------------
    def build_swarm_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Swarm Sync Nodes")
        frame.pack(fill="x", padx=10, pady=10)

        self.swarm_box = tk.Listbox(frame, height=6)
        self.swarm_box.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(side="right", fill="y")

        tk.Button(btn_frame, text="Refresh Swarm Status",
                  command=self.refresh_swarm).pack(fill="x")

        tk.Button(btn_frame, text="Show Swarm Map",
                  command=self.show_swarm_map).pack(fill="x")

    def refresh_swarm(self):
        self.swarm_box.delete(0, "end")
        for n in self.swarm.nodes:
            self.swarm_box.insert("end", f"Node-{n.node_id} — Load {n.load:.2f} — {n.status}")

    def show_swarm_map(self):
        top = tk.Toplevel(self.root)
        top.title("Swarm Map")
        canvas = tk.Canvas(top, width=400, height=300, bg="#000")
        canvas.pack(fill="both", expand=True)
        cx, cy = 200, 150
        radius = 100
        nodes = self.swarm.nodes
        count = len(nodes)
        for i, n in enumerate(nodes):
            angle = 2 * math.pi * i / count
            x = cx + radius * math.cos(angle)
            y = cy + radius * math.sin(angle)
            load_color = int(255 * n.load)
            color = f"#{load_color:02x}ff00"
            canvas.create_oval(x - 15, y - 15, x + 15, y + 15, fill=color, outline="#0f0")
            canvas.create_text(x, y - 25, text=f"N{n.node_id}", fill="#0f0")
            canvas.create_text(x, y + 25, text=f"{n.load:.2f}", fill="#0f0")

    # --------------------------------------------------------
    # PLUGIN PANEL
    # --------------------------------------------------------
    def build_plugin_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Plugin API (Sandboxed)")
        frame.pack(fill="x", padx=10, pady=10)

        self.plugin_box = tk.Listbox(frame, height=6)
        self.plugin_box.pack(fill="both", expand=True)

        tk.Button(frame, text="Reload Plugins",
                  command=self.reload_plugins).pack(fill="x")
        tk.Button(frame, text="Run Plugins (Threat + Swarm Context)",
                  command=self.run_plugins).pack(fill="x")

    def reload_plugins(self):
        self.plugins.load_plugins()
        self.plugin_box.delete(0, "end")
        if self.plugins.plugins:
            for fname, _ in self.plugins.plugins:
                self.plugin_box.insert("end", fname)
        else:
            self.plugin_box.insert("end", "No plugins loaded.")

    def run_plugins(self):
        context = {
            "threats": [t.snapshot() for t in self.engine.threats],
            "swarm_nodes": [n.snapshot() for n in self.swarm.nodes],
        }
        self.plugins.run_plugins(context)
        self.refresh_threat_list()
        self.refresh_swarm()
        self.update_heatmap()
        self.update_threat_timeline()

    # --------------------------------------------------------
    # PROBE PANEL + Trajectory
    # --------------------------------------------------------
    def build_probe_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Probes (Star Trek-style)")
        frame.pack(fill="x", padx=10, pady=10)

        self.probe_box = tk.Listbox(frame, height=6)
        self.probe_box.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(side="right", fill="y")

        tk.Button(btn_frame, text="Refresh Probes",
                  command=self.refresh_probes).pack(fill="x")
        tk.Button(btn_frame, text="Launch Selected Probe",
                  command=self.launch_selected_probe).pack(fill="x")
        tk.Button(btn_frame, text="Recall Selected Probe",
                  command=self.recall_selected_probe).pack(fill="x")
        tk.Button(btn_frame, text="Show Probe Trajectory",
                  command=self.show_probe_trajectory).pack(fill="x")

    def refresh_probes(self):
        self.probe_box.delete(0, "end")
        for p in self.probes.probes:
            self.probe_box.insert("end", f"Probe-{p.probe_id} — {p.status} — {p.sector} — {p.reading:.2f}")

    def get_selected_probe(self):
        idx = self.probe_box.curselection()
        if not idx:
            return None
        return self.probes.probes[idx[0]]

    def launch_selected_probe(self):
        probe = self.get_selected_probe()
        if not probe:
            self.write_log("[PROBE] No probe selected.")
            return
        self.probes.launch_probe(probe)
        self.refresh_probes()

    def recall_selected_probe(self):
        probe = self.get_selected_probe()
        if not probe:
            self.write_log("[PROBE] No probe selected.")
            return
        self.probes.recall_probe(probe)
        self.refresh_probes()

    def show_probe_trajectory(self):
        probe = self.get_selected_probe()
        if not probe:
            self.write_log("[PROBE] No probe selected for trajectory.")
            return
        if Figure is None or FigureCanvasTkAgg is None or np is None:
            self.write_log("[PROBE] Matplotlib/NumPy not available for trajectory.")
            return
        top = tk.Toplevel(self.root)
        top.title(f"Probe-{probe.probe_id} Trajectory")
        fig = Figure(figsize=(5, 3), dpi=100)
        ax = fig.add_subplot(111)
        if probe.history:
            ts = [h[0] for h in probe.history]
            readings = [h[2] for h in probe.history]
            ax.plot(ts, readings, marker="o")
        ax.set_title(f"Probe-{probe.probe_id} Reading Over Time")
        ax.set_xlabel("Time")
        ax.set_ylabel("Reading")
        canvas = FigureCanvasTkAgg(fig, master=top)
        canvas.get_tk_widget().pack(fill="both", expand=True)
        canvas.draw()

    # --------------------------------------------------------
    # HEATMAP PANEL
    # --------------------------------------------------------
    def build_heatmap_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Threat Heatmap")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.heatmap_frame = frame
        self.heatmap_canvas = None
        self.heatmap_fig = None

        if Figure is not None and FigureCanvasTkAgg is not None and np is not None:
            self.heatmap_fig = Figure(figsize=(4, 3), dpi=100)
            self.heatmap_ax = self.heatmap_fig.add_subplot(111)
            self.heatmap_canvas = FigureCanvasTkAgg(self.heatmap_fig, master=self.heatmap_frame)
            self.heatmap_canvas.get_tk_widget().pack(fill="both", expand=True)
            self.update_heatmap()
        else:
            lbl = tk.Label(frame, text="Matplotlib/NumPy not available — heatmap disabled.", fg="red")
            lbl.pack(fill="both", expand=True)

    def update_heatmap(self):
        if not hasattr(self, "heatmap_fig") or not self.heatmap_fig or not self.engine.threats or not np:
            return
        scores = [t.score for t in self.engine.threats]
        levels = [t.level if t.level is not None else 0 for t in self.engine.threats]
        data = np.zeros((10, 10), dtype=float)
        for i, (s, l) in enumerate(zip(scores, levels)):
            x = i % 10
            y = min(9, max(0, l))
            data[y, x] = s
        self.heatmap_ax.clear()
        self.heatmap_ax.set_title("Threat Heatmap")
        im = self.heatmap_ax.imshow(data, cmap="inferno", interpolation="nearest")
        self.heatmap_fig.colorbar(im, ax=self.heatmap_ax, fraction=0.046, pad=0.04)
        self.heatmap_canvas.draw()

    # --------------------------------------------------------
    # GAME TELEMETRY PANEL
    # --------------------------------------------------------
    def build_game_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Game Telemetry")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.game_box = tk.Listbox(frame, height=10)
        self.game_box.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(side="right", fill="y")

        self.game_load_label = tk.Label(btn_frame, text="LoadFactor: 0.000")
        self.game_load_label.pack(fill="x")

        tk.Button(btn_frame, text="Refresh Game Telemetry",
                  command=self.refresh_game_telemetry).pack(fill="x")

        tk.Button(btn_frame, text="Run VRAM Stress Test",
                  command=self.run_vram_stress).pack(fill="x")

    def refresh_game_telemetry(self):
        self.game_box.delete(0, "end")
        snapshot = self.game_telemetry.last_snapshot
        for name, cpu_p, mem_p in snapshot:
            self.game_box.insert("end", f"{name} — CPU {cpu_p:.1f}% — MEM {mem_p:.0f} MB")
        self.game_load_label.config(text=f"LoadFactor: {self.game_telemetry.last_load_factor:.3f}")

    def run_vram_stress(self):
        threading.Thread(target=self._vram_stress_worker, daemon=True).start()

    def _vram_stress_worker(self):
        vram_stress_test(duration=5.0, log_callback=self.write_log)

    # --------------------------------------------------------
    # GPU Curve Panel
    # --------------------------------------------------------
    def build_gpu_curve_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="GPU Utilization Curve")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.gpu_curve_frame = frame
        if Figure is not None and FigureCanvasTkAgg is not None and np is not None:
            self.gpu_curve_fig = Figure(figsize=(4, 3), dpi=100)
            self.gpu_curve_ax = self.gpu_curve_fig.add_subplot(111)
            self.gpu_curve_canvas = FigureCanvasTkAgg(self.gpu_curve_fig, master=self.gpu_curve_frame)
            self.gpu_curve_canvas.get_tk_widget().pack(fill="both", expand=True)
            tk.Button(frame, text="Refresh GPU Curve",
                      command=self.update_gpu_curve).pack(fill="x")
        else:
            lbl = tk.Label(frame, text="Matplotlib/NumPy not available — GPU curve disabled.", fg="red")
            lbl.pack(fill="both", expand=True)

    def update_gpu_curve(self):
        if not hasattr(self, "gpu_curve_fig") or not self.gpu_curve_fig or not np:
            return
        curve = self.game_telemetry.gpu_curve
        if not curve:
            return
        ts = np.array([c[0] for c in curve], dtype=float)
        gpu = np.array([c[1] for c in curve], dtype=float)
        self.gpu_curve_ax.clear()
        self.gpu_curve_ax.plot(ts - ts[0], gpu, marker="o")
        self.gpu_curve_ax.set_title("GPU Utilization Over Time")
        self.gpu_curve_ax.set_xlabel("Seconds")
        self.gpu_curve_ax.set_ylabel("GPU Util (%)")
        self.gpu_curve_canvas.draw()

    # --------------------------------------------------------
    # Analytics Panel (Threat Timeline + Defender)
    # --------------------------------------------------------
    def build_analytics_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Analytics & System Defense")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        top_frame = ttk.Frame(frame)
        top_frame.pack(side="top", fill="both", expand=True)

        bottom_frame = ttk.Frame(frame)
        bottom_frame.pack(side="bottom", fill="x")

        # Threat timeline graph
        self.timeline_frame = ttk.LabelFrame(top_frame, text="Threat Timeline")
        self.timeline_frame.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        if Figure is not None and FigureCanvasTkAgg is not None and np is not None:
            self.timeline_fig = Figure(figsize=(4, 3), dpi=100)
            self.timeline_ax = self.timeline_fig.add_subplot(111)
            self.timeline_canvas = FigureCanvasTkAgg(self.timeline_fig, master=self.timeline_frame)
            self.timeline_canvas.get_tk_widget().pack(fill="both", expand=True)
            tk.Button(self.timeline_frame, text="Refresh Threat Timeline",
                      command=self.update_threat_timeline).pack(fill="x")
        else:
            lbl = tk.Label(self.timeline_frame, text="Matplotlib/NumPy not available — timeline disabled.", fg="red")
            lbl.pack(fill="both", expand=True)

        # Defender status + folder snapshot
        self.defense_frame = ttk.LabelFrame(top_frame, text="Windows Defense")
        self.defense_frame.pack(side="right", fill="both", expand=True, padx=5, pady=5)

        self.defense_text = tk.Text(self.defense_frame, height=10, bg="#111", fg="#0f0", wrap="word")
        self.defense_text.pack(fill="both", expand=True)

        btn_def = tk.Button(self.defense_frame, text="Check Windows Defender",
                            command=self.check_defender)
        btn_def.pack(fill="x")

        self.snapshot_frame = ttk.LabelFrame(bottom_frame, text="Folder Snapshot")
        self.snapshot_frame.pack(fill="x", padx=5, pady=5)

        self.snapshot_entry = tk.Entry(self.snapshot_frame)
        self.snapshot_entry.insert(0, BASE_DIR)
        self.snapshot_entry.pack(side="left", fill="x", expand=True)

        tk.Button(self.snapshot_frame, text="Snapshot",
                  command=self.run_snapshot).pack(side="right")

        self.snapshot_box = tk.Listbox(self.snapshot_frame, height=5)
        self.snapshot_box.pack(fill="x")

    def update_threat_timeline(self):
        if not hasattr(self, "timeline_fig") or not self.timeline_fig or not np:
            return
        self.timeline_ax.clear()
        for t in self.engine.threats:
            if t.timeline:
                ts = np.array([p[0] for p in t.timeline], dtype=float)
                scores = np.array([p[1] for p in t.timeline], dtype=float)
                self.timeline_ax.plot(ts - ts[0], scores, label=t.name)
        self.timeline_ax.set_title("Threat Score Evolution")
        self.timeline_ax.set_xlabel("Seconds")
        self.timeline_ax.set_ylabel("Score")
        self.timeline_ax.legend(loc="upper left", fontsize=8)
        self.timeline_canvas.draw()

    def check_defender(self):
        status = windows_defender_status()
        self.defense_text.delete("1.0", "end")
        self.defense_text.insert("end", status + "\n")

    def run_snapshot(self):
        folder = self.snapshot_entry.get().strip()
        snap = watch_folder_snapshot(folder)
        self.snapshot_box.delete(0, "end")
        for path, (size, mtime) in snap.items():
            self.snapshot_box.insert("end", f"{path} — {size} bytes — mtime {mtime}")

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    gui = TargetingGUI(root)
    root.mainloop()
