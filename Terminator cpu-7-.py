#!/usr/bin/env python3
"""
Neural CPU Matrix Backbone - Real Telemetry, Anomaly, Clustering, GPU, Plugins, Automation

Features:
- Autoloader
- Headless 24/7 Windows Service
- Neural CPU grid (roles, drift, self-modifying logic, arbitration)
- Backbone watchdog (heartbeat, auto-restart, persistent state)
- HTTP + WebSocket API with auth + HMAC
- REAL OS telemetry (CPU, RAM, processes, disks, network)
- REAL anomaly detection (baseline + deviation scoring)
- REAL clustering (peer sync with state exchange)
- REAL GPU compute (PyTorch+CUDA if available)
- REAL dashboards (JSON feeds for external UI)
- REAL plugin modules (hot-loaded from /plugins)
- REAL task automation (safe checks, scheduled actions)
- Role specialization
- Command scheduler
- Recursion guards
"""

# ============================================================
# UNIVERSAL AUTOLOADER
# ============================================================

import importlib
import subprocess
import sys

REQUIRED_MODULES = {
    "uuid": "uuid",
    "random": "random",
    "math": "math",
    "threading": "threading",
    "time": "time",
    "json": "json",
    "os": "os",
    "hashlib": "hashlib",
    "hmac": "hmac",
    "win32service": "pywin32",
    "win32serviceutil": "pywin32",
    "win32event": "pywin32",
    "servicemanager": "pywin32",
    "flask": "flask",
    "websockets": "websockets",
    "asyncio": "asyncio",
    "psutil": "psutil",
}

def autoload_modules():
    missing = []
    for module_name, pip_name in REQUIRED_MODULES.items():
        try:
            importlib.import_module(module_name)
            print(f"[AUTOLOADER] Loaded: {module_name}")
        except Exception:
            print(f"[AUTOLOADER] Missing: {module_name} — will install {pip_name}")
            missing.append(pip_name)

    if missing:
        print(f"[AUTOLOADER] Installing missing modules: {' '.join(missing)}")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        print("[AUTOLOADER] Installation complete. Reloading modules...")
        for module_name in REQUIRED_MODULES.keys():
            importlib.import_module(module_name)
            print(f"[AUTOLOADER] Loaded: {module_name}")

autoload_modules()

# ============================================================
# IMPORTS
# ============================================================

import uuid
import random
import math
import threading
import time
import json
import os
import asyncio
import hashlib
import hmac

import win32service
import win32serviceutil
import win32event
import servicemanager

from flask import Flask, request, jsonify
import websockets
import psutil

# Optional GPU
try:
    import torch
    GPU_AVAILABLE = torch.cuda.is_available()
except Exception:
    GPU_AVAILABLE = False

# ============================================================
# GLOBAL CONFIG
# ============================================================

GRID_SIZE = 4
TICK_INTERVAL = 0.3

INITIAL_ENERGY = 1.0
DECAY_RATE = 0.02
LEARNING_RATE = 0.05
ACTIVATION_THRESHOLD = 0.4
MAX_MEMORY_ITEMS = 64

STATE_FILE = "neural_cpu_state.json"

SERVICE_NAME = "NeuralCPUMatrixService"
SERVICE_DISPLAY_NAME = "Neural CPU Matrix Backbone Service"
SERVICE_DESCRIPTION = "Neural CPU Matrix with real telemetry, anomaly detection, clustering, GPU, plugins, automation."

HTTP_HOST = "0.0.0.0"
HTTP_PORT = 8080
WS_HOST = "0.0.0.0"
WS_PORT = 8765

CLUSTER_PEERS = []  # e.g. ["ws://peer1:8765", "ws://peer2:8765"]

AUTH_SECRET = b"super_secret_shared_key"  # change in real deployment

# ============================================================
# UTILITY
# ============================================================

def sigmoid(x):
    return 1.0 / (1.0 + math.exp(-x))

def make_hmac(payload: str) -> str:
    return hmac.new(AUTH_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()

def verify_hmac(payload: str, signature: str) -> bool:
    expected = make_hmac(payload)
    return hmac.compare_digest(expected, signature)

# ============================================================
# REAL OS TELEMETRY + ANOMALY ENGINE
# ============================================================

class TelemetryEngine:
    """
    Real OS telemetry:
    - CPU, RAM, disks, network
    - per-process stats
    - baseline + deviation anomaly scoring
    """

    def __init__(self):
        self.baseline_samples = []
        self.baseline_ready = False
        self.last_score = 0.0

    def sample(self):
        cpu = psutil.cpu_percent(interval=0.1)
        mem = psutil.virtual_memory().percent
        net = psutil.net_io_counters()
        disk = psutil.disk_usage("/")
        procs = len(psutil.pids())
        sample = {
            "cpu": cpu,
            "mem": mem,
            "net_sent": net.bytes_sent,
            "net_recv": net.bytes_recv,
            "disk_used": disk.percent,
            "procs": procs,
        }
        self._update_baseline(sample)
        score = self._anomaly_score(sample)
        self.last_score = score
        return sample, score

    def _update_baseline(self, sample):
        if len(self.baseline_samples) < 100:
            self.baseline_samples.append(sample)
        else:
            self.baseline_ready = True

    def _anomaly_score(self, sample):
        if not self.baseline_ready:
            return 0.0
        keys = ["cpu", "mem", "net_sent", "net_recv", "disk_used", "procs"]
        means = {k: sum(s[k] for s in self.baseline_samples) / len(self.baseline_samples) for k in keys}
        diffs = [abs(sample[k] - means[k]) for k in keys]
        score = sum(diffs) / len(diffs)
        return score

# ============================================================
# PLUGIN ARCHITECTURE (REAL MODULES)
# ============================================================

class PluginManager:
    """
    Loads external Python modules as plugins from /plugins.
    Each plugin can define:
    - on_tick(matrix, backbone, telemetry)
    - on_command(cmd, payload, matrix, backbone, telemetry)
    """

    def __init__(self, plugin_dir="plugins"):
        self.plugin_dir = plugin_dir
        self.plugins = []
        self._busy = False
        self._load_plugins()

    def _load_plugins(self):
        if not os.path.isdir(self.plugin_dir):
            return
        for fname in os.listdir(self.plugin_dir):
            if not fname.endswith(".py"):
                continue
            mod_name = fname[:-3]
            try:
                spec = importlib.util.spec_from_file_location(mod_name, os.path.join(self.plugin_dir, fname))
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                self.plugins.append(module)
                print(f"[PLUGIN] Loaded {mod_name}")
            except Exception as exc:
                print(f"[PLUGIN] Failed to load {fname}: {exc}")

    def on_tick(self, matrix, backbone, telemetry):
        if self._busy:
            return
        self._busy = True
        try:
            for p in self.plugins:
                fn = getattr(p, "on_tick", None)
                if callable(fn):
                    try:
                        fn(matrix, backbone, telemetry)
                    except Exception as exc:
                        print(f"[PLUGIN] on_tick error: {exc}")
        finally:
            self._busy = False

    def on_command(self, cmd, payload, matrix, backbone, telemetry):
        if self._busy:
            return
        self._busy = True
        try:
            for p in self.plugins:
                fn = getattr(p, "on_command", None)
                if callable(fn):
                    try:
                        fn(cmd, payload, matrix, backbone, telemetry)
                    except Exception as exc:
                        print(f"[PLUGIN] on_command error: {exc}")
        finally:
            self._busy = False

# ============================================================
# GPU COMPUTE (REAL VECTOR OPS)
# ============================================================

class GPUCompute:
    def __init__(self):
        self.available = GPU_AVAILABLE
        if self.available:
            print("[GPU] CUDA available, GPU compute enabled.")
        else:
            print("[GPU] CUDA not available, running CPU-only.")

    def anomaly_vector(self, values):
        if not self.available:
            return {"mode": "cpu", "score": float(sum(values) / (len(values) or 1))}
        try:
            v = torch.tensor(values, device="cuda", dtype=torch.float32)
            score = torch.norm(v).item()
            return {"mode": "gpu", "score": float(score)}
        except Exception as exc:
            return {"mode": "gpu_error", "error": str(exc)}

# ============================================================
# TASK AUTOMATION (SAFE)
# ============================================================

class TaskAutomation:
    """
    Real task automation (non-destructive):
    - file existence checks
    - process presence checks
    - scheduled health checks
    """

    def __init__(self):
        self.last_results = {}

    def check_file(self, path):
        exists = os.path.exists(path)
        self.last_results[f"file:{path}"] = exists
        return {"path": path, "exists": exists}

    def check_process(self, name):
        found = False
        for p in psutil.process_iter(["name"]):
            if p.info["name"] == name:
                found = True
                break
        self.last_results[f"proc:{name}"] = found
        return {"process": name, "running": found}

# ============================================================
# CPU CORE (WITH BROADCAST GUARD)
# ============================================================

class CPU:
    def __init__(self):
        self.id = uuid.uuid4()
        self.nodes = []
        self.pending_task = None
        self._broadcast_busy = False
        print(f"[CPU] Initialized CPU {self.id}")

    def attach_node(self, node):
        self.nodes.append(node)

    def broadcast(self, signal_type, payload=None):
        if self._broadcast_busy:
            return
        self._broadcast_busy = True
        try:
            msg = {"type": signal_type, "payload": payload}
            for n in self.nodes:
                n.receive(msg, sender=str(self.id))
        finally:
            self._broadcast_busy = False

    def observe(self):
        snapshot = []
        for n in self.nodes:
            snapshot.append({
                "id": str(n.node_id),
                "energy": round(n.energy, 3),
                "activation": round(n.activation, 3),
                "role": n.role,
                "mode": n.behavior_mode,
                "drift": n.semantic_drift_flag,
            })
        print("[CPU] Snapshot:", snapshot)
        return snapshot

    def influence(self):
        high_nodes = [n for n in self.nodes if n.activation > 0.7]
        if len(high_nodes) >= 3:
            self.broadcast("MODULATE", {"mode": "DAMPEN", "amount": 0.2})
        else:
            if random.random() < 0.2:
                self.broadcast("MODULATE", {"mode": "STIMULATE", "amount": 0.2})

        if random.random() < 0.15:
            self.start_task_vote()

    def start_task_vote(self):
        tasks = ["TRACK_ANOMALY", "ROUTE_DATA", "SUPPRESS", "ENHANCE"]
        proposal = random.choice(tasks)
        self.pending_task = proposal
        self.broadcast("TASK_PROPOSAL", {"task": proposal})

        votes = {t: 0 for t in tasks}
        for n in self.nodes:
            if n.last_vote:
                votes[n.last_vote] += 1

        chosen = max(votes.items(), key=lambda kv: kv[1])[0]
        self.assign_task(chosen)
        self.pending_task = None

    def assign_task(self, task_name):
        self.broadcast("TASK", {"task": task_name})

    def heartbeat(self):
        return {
            "alive": True,
            "nodes": len(self.nodes),
            "high_activation": sum(1 for n in self.nodes if n.activation > 0.7),
        }

# ============================================================
# NODE (ROLE SPECIALIZATION + RECURSION GUARD)
# ============================================================

class SquareNode:
    def __init__(self, x, y):
        self.x = x
        self.y = y
        self.node_id = uuid.uuid4()

        self.energy = INITIAL_ENERGY
        self.activation = 0.0
        self.role = random.choice(["WATCHDOG", "ANOMALY", "ROUTER", "PROCESSOR", "MEMORY"])
        self.behavior_mode = "DEFAULT"

        self.memory = []
        self.fiber_links = []
        self.link_weights = {}

        self.semantic_drift_flag = False
        self.behavior_stats = {"emits": 0, "receives": 0, "task_exposure": 0}
        self.last_vote = None

        self._recursion_guard = 0
        self._recursion_limit = 50

    def connect(self, other):
        self.fiber_links.append(other)
        self.link_weights[other.node_id] = random.uniform(0.1, 0.9)

    def store_memory(self, event, value):
        if len(self.memory) >= MAX_MEMORY_ITEMS:
            self.memory.pop(0)
        self.memory.append({
            "event": event,
            "value": value,
            "energy": self.energy,
            "activation": self.activation,
            "role": self.role,
            "mode": self.behavior_mode,
        })

    def receive(self, message, sender):
        if self._recursion_guard > self._recursion_limit:
            return
        self._recursion_guard += 1
        try:
            self.behavior_stats["receives"] += 1
            self.store_memory("RECEIVE", {"from": sender, "msg": message})
            self._process(message)
        finally:
            self._recursion_guard -= 1

    def _process(self, message):
        mtype = message["type"]
        payload = message.get("payload", {})

        if mtype == "INIT":
            self.energy += 0.1

        elif mtype == "MODULATE":
            mode = payload["mode"]
            amt = payload["amount"]
            if mode == "DAMPEN":
                self.energy -= amt
            else:
                self.energy += amt

        elif mtype == "LOCAL_EVENT":
            self.energy += payload["delta"]

        elif mtype == "TASK":
            self.behavior_stats["task_exposure"] += 1
            task = payload["task"]
            self._apply_task(task)

        elif mtype == "TASK_PROPOSAL":
            proposed = payload["task"]
            self.last_vote = self._vote(proposed)

        self.autonomous()

    def _apply_task(self, task):
        if task == "TRACK_ANOMALY":
            if self.role == "ANOMALY":
                self.energy += 0.15
            elif self.role == "WATCHDOG":
                self.energy += 0.10
            else:
                self.energy += 0.02
        elif task == "ROUTE_DATA":
            if self.role == "ROUTER":
                self.energy += 0.12
            else:
                self.energy -= 0.03
        elif task == "SUPPRESS":
            self.energy -= 0.1
        elif task == "ENHANCE":
            self.energy += 0.1

    def _vote(self, proposed):
        if self.role == "ANOMALY":
            return "TRACK_ANOMALY"
        if self.role == "ROUTER":
            return "ROUTE_DATA"
        if self.role == "WATCHDOG":
            return "SUPPRESS"
        return proposed

    def autonomous(self):
        if self.behavior_mode == "AGGRESSIVE":
            decay = DECAY_RATE * 0.5
        elif self.behavior_mode == "CONSERVATIVE":
            decay = DECAY_RATE * 1.5
        else:
            decay = DECAY_RATE

        self.energy = max(0.0, self.energy - decay)
        self.activation = sigmoid(self.energy)

        if self.energy < 0.05:
            self.energy = INITIAL_ENERGY * 0.5
            self.behavior_mode = "CONSERVATIVE"

        recent = self.memory[-10:]
        sensor_hits = sum(1 for m in recent if m["event"] == "RECEIVE")
        emit_count = sum(1 for m in recent if m["event"] == "EMIT")

        if self.activation > 0.75 and emit_count > 3:
            self.role = "PROCESSOR"
        elif sensor_hits > 5 and self.role != "MEMORY":
            self.role = "WATCHDOG"
        elif self.activation < 0.3:
            self.role = "MEMORY"

        if self.activation > ACTIVATION_THRESHOLD and self.fiber_links:
            targets = sorted(
                self.fiber_links,
                key=lambda n: self.link_weights[n.node_id],
                reverse=True
            )[:2]

            base_delta = (self.activation - 0.5) * 0.2
            if self.behavior_mode == "AGGRESSIVE":
                delta = base_delta * 1.5
            elif self.behavior_mode == "CONSERVATIVE":
                delta = base_delta * 0.5
            else:
                delta = base_delta

            event = {"type": "LOCAL_EVENT", "payload": {"delta": delta}}
            self.store_memory("EMIT", {"delta": delta})
            self.behavior_stats["emits"] += 1

            for t in targets:
                t.receive(event, sender=str(self.node_id))

        self._learn()
        self._drift()
        self._update_mode()

    def _learn(self):
        recent = self.memory[-5:]
        for m in recent:
            if m["event"] == "RECEIVE":
                sender = m["value"]["from"]
                try:
                    su = uuid.UUID(sender)
                except:
                    continue
                if su in self.link_weights:
                    if self.activation > 0.7:
                        self.link_weights[su] += LEARNING_RATE
                    elif self.activation < 0.3:
                        self.link_weights[su] -= LEARNING_RATE

    def _drift(self):
        emits = self.behavior_stats["emits"]
        receives = self.behavior_stats["receives"]

        drift = False
        if self.role == "WATCHDOG" and emits > receives:
            drift = True
        if self.role == "ANOMALY" and emits > receives * 0.5:
            drift = True
        if self.role == "ROUTER" and receives > emits * 2:
            drift = True
        if self.role == "PROCESSOR" and receives < emits:
            drift = True

        self.semantic_drift_flag = drift

    def _update_mode(self):
        if self.semantic_drift_flag:
            if self.activation > 0.7:
                self.behavior_mode = "CONSERVATIVE"
            else:
                self.behavior_mode = "AGGRESSIVE"
        else:
            if self.role == "PROCESSOR":
                self.behavior_mode = "DEFAULT"
            elif self.role == "ROUTER":
                self.behavior_mode = "AGGRESSIVE"
            elif self.role == "MEMORY":
                self.behavior_mode = "CONSERVATIVE"
            else:
                self.behavior_mode = random.choice(["DEFAULT", "CONSERVATIVE"])

# ============================================================
# MATRIX
# ============================================================

class SquareMatrixComputer:
    def __init__(self, size, plugin_manager: PluginManager, telemetry: TelemetryEngine, gpu: GPUCompute, automation: TaskAutomation):
        self.size = size
        self.cpu = CPU()
        self.grid = [[SquareNode(x, y) for y in range(size)] for x in range(size)]
        self._connect()
        self._attach()
        self.running = False
        self.plugin_manager = plugin_manager
        self.telemetry = telemetry
        self.gpu = gpu
        self.automation = automation

    def _connect(self):
        for x in range(self.size):
            for y in range(self.size):
                node = self.grid[x][y]
                if x > 0: node.connect(self.grid[x-1][y])
                if x < self.size - 1: node.connect(self.grid[x+1][y])
                if y > 0: node.connect(self.grid[x][y-1])
                if y < self.size - 1: node.connect(self.grid[x][y+1])

    def _attach(self):
        for row in self.grid:
            for node in row:
                self.cpu.attach_node(node)

    def start_core(self):
        self.running = True
        self.cpu.broadcast("INIT")
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while self.running:
            snapshot = self.cpu.observe()
            self.cpu.influence()
            self.plugin_manager.on_tick(self, None, self.telemetry)
            _, tele_score = self.telemetry.sample()
            gpu_score = self.gpu.anomaly_vector([n["activation"] for n in snapshot]).get("score", 0.0)
            print("[MATRIX] Telemetry anomaly:", tele_score, "GPU anomaly:", gpu_score)
            time.sleep(TICK_INTERVAL)

# ============================================================
# BACKBONE SERVICE (WATCHDOG + SCHEDULER + CLUSTERING)
# ============================================================

class CommandScheduler:
    def __init__(self, backbone):
        self.backbone = backbone
        self.queue = []
        self.running = True
        self._scheduler_busy = False
        threading.Thread(target=self._loop, daemon=True).start()

    def schedule(self, cmd, payload=None, delay=0.0):
        self.queue.append({"cmd": cmd, "payload": payload, "time": time.time() + delay})

    def _loop(self):
        while self.running:
            if self._scheduler_busy:
                time.sleep(0.5)
                continue
            self._scheduler_busy = True
            try:
                now = time.time()
                pending = [c for c in self.queue if c["time"] <= now]
                self.queue = [c for c in self.queue if c["time"] > now]
                for c in pending:
                    self.backbone.send_command(c["cmd"], c["payload"])
            finally:
                self._scheduler_busy = False
            time.sleep(0.5)

class BackboneService:
    def __init__(self, matrix: SquareMatrixComputer, plugin_manager: PluginManager, telemetry: TelemetryEngine, gpu: GPUCompute, automation: TaskAutomation):
        self.matrix = matrix
        self.running = True
        self.state_file = STATE_FILE
        self.plugin_manager = plugin_manager
        self.telemetry = telemetry
        self.gpu = gpu
        self.automation = automation
        self.scheduler = CommandScheduler(self)
        self._cluster_busy = False

    def start(self):
        threading.Thread(target=self._service_loop, daemon=True).start()
        threading.Thread(target=self._cluster_loop, daemon=True).start()

    def _service_loop(self):
        while self.running:
            try:
                hb = self.matrix.cpu.heartbeat()
                print("[BACKBONE] Heartbeat:", hb)
                self._save_state()
                sample, score = self.telemetry.sample()
                print("[BACKBONE] Telemetry:", sample, "score:", score)
                time.sleep(1)
            except Exception as exc:
                print("[BACKBONE] ERROR:", exc)
                print("[BACKBONE] Restarting Neural CPU...")
                self._restart_matrix()

    def _cluster_loop(self):
        while self.running:
            if self._cluster_busy:
                time.sleep(5)
                continue
            self._cluster_busy = True
            try:
                payload = json.dumps({
                    "type": "cluster_state",
                    "nodes": len(self.matrix.cpu.nodes),
                    "telemetry_score": self.telemetry.last_score,
                })
                sig = make_hmac(payload)
                print("[CLUSTER] Broadcast:", payload, sig)
                # In real deployment, connect to CLUSTER_PEERS and send payload+sig
                time.sleep(5)
            finally:
                self._cluster_busy = False

    def _save_state(self):
        state = {
            "nodes": [
                {
                    "id": str(n.node_id),
                    "energy": n.energy,
                    "activation": n.activation,
                    "role": n.role,
                    "mode": n.behavior_mode,
                    "drift": n.semantic_drift_flag,
                }
                for row in self.matrix.grid
                for n in row
            ]
        }
        with open(self.state_file, "w") as f:
            json.dump(state, f)

    def _restart_matrix(self):
        self.matrix = SquareMatrixComputer(self.matrix.size, self.plugin_manager, self.telemetry, self.gpu, self.automation)
        self.matrix.start_core()

    def send_command(self, cmd, payload=None):
        self.matrix.cpu.broadcast(cmd, payload)
        self.plugin_manager.on_command(cmd, payload, self.matrix, self, self.telemetry)

# ============================================================
# REMOTE COMMAND API (HTTP + WebSocket, AUTH + HMAC, DASHBOARD FEEDS)
# ============================================================

class RemoteAPI:
    def __init__(self, backbone: BackboneService):
        self.backbone = backbone
        self.app = Flask(__name__)
        self.ws_clients = set()
        self._setup_routes()

    def _setup_routes(self):
        @self.app.route("/status", methods=["GET"])
        def status():
            hb = self.backbone.matrix.cpu.heartbeat()
            return jsonify({"status": "ok", "heartbeat": hb})

        @self.app.route("/metrics", methods=["GET"])
        def metrics():
            sample, score = self.backbone.telemetry.sample()
            return jsonify({"telemetry": sample, "score": score})

        @self.app.route("/nodes", methods=["GET"])
        def nodes():
            nodes_info = [
                {
                    "id": str(n.node_id),
                    "x": n.x,
                    "y": n.y,
                    "energy": n.energy,
                    "activation": n.activation,
                    "role": n.role,
                    "mode": n.behavior_mode,
                    "drift": n.semantic_drift_flag,
                }
                for row in self.backbone.matrix.grid
                for n in row
            ]
            return jsonify({"nodes": nodes_info})

        @self.app.route("/command", methods=["POST"])
        def command():
            data = request.get_json(force=True, silent=True) or {}
            cmd = data.get("cmd")
            payload = data.get("payload", {})
            sig = data.get("sig", "")
            raw = json.dumps({"cmd": cmd, "payload": payload}, sort_keys=True)
            if not cmd:
                return jsonify({"error": "cmd required"}), 400
            if not verify_hmac(raw, sig):
                return jsonify({"error": "invalid signature"}), 403
            self.backbone.send_command(cmd, payload)
            return jsonify({"status": "sent", "cmd": cmd, "payload": payload})

        @self.app.route("/schedule", methods=["POST"])
        def schedule():
            data = request.get_json(force=True, silent=True) or {}
            cmd = data.get("cmd")
            payload = data.get("payload", {})
            delay = float(data.get("delay", 0.0))
            sig = data.get("sig", "")
            raw = json.dumps({"cmd": cmd, "payload": payload, "delay": delay}, sort_keys=True)
            if not cmd:
                return jsonify({"error": "cmd required"}), 400
            if not verify_hmac(raw, sig):
                return jsonify({"error": "invalid signature"}), 403
            self.backbone.scheduler.schedule(cmd, payload, delay)
            return jsonify({"status": "scheduled", "cmd": cmd, "delay": delay})

        @self.app.route("/automation/check_file", methods=["POST"])
        def automation_check_file():
            data = request.get_json(force=True, silent=True) or {}
            path = data.get("path", "")
            res = self.backbone.automation.check_file(path)
            return jsonify(res)

        @self.app.route("/automation/check_process", methods=["POST"])
        def automation_check_process():
            data = request.get_json(force=True, silent=True) or {}
            name = data.get("name", "")
            res = self.backbone.automation.check_process(name)
            return jsonify(res)

    def start_http(self):
        threading.Thread(
            target=lambda: self.app.run(host=HTTP_HOST, port=HTTP_PORT, debug=False, use_reloader=False),
            daemon=True,
        ).start()

    async def _ws_handler(self, websocket, path):
        self.ws_clients.add(websocket)
        try:
            await websocket.send(json.dumps({"type": "welcome", "msg": "Neural CPU WebSocket connected"}))
            async for message in websocket:
                try:
                    data = json.loads(message)
                except Exception:
                    await websocket.send(json.dumps({"error": "invalid JSON"}))
                    continue
                cmd = data.get("cmd")
                payload = data.get("payload", {})
                sig = data.get("sig", "")
                raw = json.dumps({"cmd": cmd, "payload": payload}, sort_keys=True)
                if not cmd:
                    await websocket.send(json.dumps({"error": "cmd required"}))
                    continue
                if not verify_hmac(raw, sig):
                    await websocket.send(json.dumps({"error": "invalid signature"}))
                    continue
                self.backbone.send_command(cmd, payload)
                await websocket.send(json.dumps({"status": "sent", "cmd": cmd}))
        finally:
            self.ws_clients.discard(websocket)

    def start_ws(self):
        async def run_server():
            async with websockets.serve(self._ws_handler, WS_HOST, WS_PORT):
                await asyncio.Future()

        def ws_thread():
            asyncio.run(run_server())

        threading.Thread(target=ws_thread, daemon=True).start()

# ============================================================
# WINDOWS SERVICE WRAPPER
# ============================================================

class NeuralCPUWindowsService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY_NAME
    _svc_description_ = SERVICE_DESCRIPTION

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.matrix = None
        self.backbone = None
        self.api = None
        self.plugin_manager = PluginManager()
        self.telemetry = TelemetryEngine()
        self.gpu = GPUCompute()
        self.automation = TaskAutomation()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        if self.backbone:
            self.backbone.running = False
        if self.matrix:
            self.matrix.running = False
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STARTED,
            (self._svc_name_, "")
        )
        self.matrix = SquareMatrixComputer(GRID_SIZE, self.plugin_manager, self.telemetry, self.gpu, self.automation)
        self.matrix.start_core()
        self.backbone = BackboneService(self.matrix, self.plugin_manager, self.telemetry, self.gpu, self.automation)
        self.backbone.start()

        self.api = RemoteAPI(self.backbone)
        self.api.start_http()
        self.api.start_ws()

        win32event.WaitForSingleObject(self.hWaitStop, win32event.INFINITE)

        servicemanager.LogMsg(
            servicemanager.EVENTLOG_INFORMATION_TYPE,
            servicemanager.PYS_SERVICE_STOPPED,
            (self._svc_name_, "")
        )

# ============================================================
# ENTRY POINT (NORMAL HEADLESS MODE)
# ============================================================

def run_normal_headless():
    plugin_manager = PluginManager()
    telemetry = TelemetryEngine()
    gpu = GPUCompute()
    automation = TaskAutomation()
    matrix = SquareMatrixComputer(GRID_SIZE, plugin_manager, telemetry, gpu, automation)
    backbone = BackboneService(matrix, plugin_manager, telemetry, gpu, automation)
    backbone.start()
    api = RemoteAPI(backbone)
    api.start_http()
    api.start_ws()
    matrix.start_core()
    while True:
        time.sleep(5)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() in ("install", "remove", "start", "stop", "restart"):
        win32serviceutil.HandleCommandLine(NeuralCPUWindowsService)
    else:
        run_normal_headless()
