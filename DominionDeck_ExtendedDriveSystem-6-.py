#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DominionDeck_CommandCenter_FullSystem_WAN.py

Upgrades:
- Real-time event bus (no GUI-side polling for core data)
- Plugin system with hot-reload (file watcher on plugins directory)
- Real swarm networking:
    - LAN broadcast (UDP)
    - WAN support via configurable peer list (swarm_peers.json)
- Drive health monitoring (SMART-like via psutil + status heuristics)
- Windows service backend + GUI Command Center frontend
- Threat engine, AI brain, telemetry, VRAM scanner, GUID-based persistence
- Watchdog, logging, CLI, dark GUI with electric-blue tabs
"""

import os
import sys
import time
import json
import string
import itertools
import subprocess
import importlib
import threading
import random
import math
import socket
from pathlib import Path
from collections import deque

# ---------------------------------------------------------------------------
# AUTOLOADER
# ---------------------------------------------------------------------------

BASE_LIBS = [
    "tkinter",
    "numpy",
    "matplotlib",
    "psutil",
    "pynvml",
]

def ensure_package(pkg, pip_name=None):
    try:
        return importlib.import_module(pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name or pkg])
        return importlib.import_module(pkg)

modules = {}
for pkg in BASE_LIBS:
    modules[pkg] = ensure_package(pkg)

win32api = ensure_package("win32api", "pywin32")
win32service = ensure_package("win32service", "pywin32")
win32serviceutil = ensure_package("win32serviceutil", "pywin32")
win32event = ensure_package("win32event", "pywin32")
win32file = ensure_package("win32file", "pywin32")

tkinter = modules["tkinter"]
np = modules["numpy"]
matplotlib = modules["matplotlib"]
matplotlib.use("Agg")
psutil = modules["psutil"]
pynvml = modules["pynvml"]

from tkinter import ttk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import importlib.util

# ---------------------------------------------------------------------------
# PATHS / PERSISTENCE / LOGGING / PLUGINS
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROGRAMDATA = Path(os.getenv("PROGRAMDATA", "C:\\ProgramData")) / "DominionDeck"
PROGRAMDATA.mkdir(parents=True, exist_ok=True)

DATA_DIR = PROGRAMDATA / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

PLUGINS_DIR = PROGRAMDATA / "plugins"
PLUGINS_DIR.mkdir(parents=True, exist_ok=True)

REGISTRY_PATH = PROGRAMDATA / "registry.json"
REBOOT_PATH = PROGRAMDATA / "reboot.json"

THREAT_HISTORY_PATH = DATA_DIR / "threat_history.json"
SWARM_HISTORY_PATH = DATA_DIR / "swarm_history.json"
TELEMETRY_HISTORY_PATH = DATA_DIR / "telemetry_history.json"
AI_POLICY_PATH = DATA_DIR / "ai_policy.json"
SETTINGS_PATH = DATA_DIR / "settings.json"
LOG_PATH = DATA_DIR / "logs.txt"
DRIVE_HEALTH_PATH = DATA_DIR / "drive_health.json"
SWARM_PEERS_PATH = DATA_DIR / "swarm_peers.json"  # WAN peers config

LOG_BUFFER = deque(maxlen=500)

def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    LOG_BUFFER.append(line)
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def load_json(path, default):
    if not path.exists():
        return default
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default

def save_json(path, data):
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    tmp.replace(path)

# ---------------------------------------------------------------------------
# REAL-TIME EVENT BUS
# ---------------------------------------------------------------------------

class EventBus:
    def __init__(self):
        self.subscribers = {}
        self.lock = threading.Lock()

    def subscribe(self, topic, callback):
        with self.lock:
            self.subscribers.setdefault(topic, []).append(callback)

    def publish(self, topic, payload=None):
        with self.lock:
            callbacks = list(self.subscribers.get(topic, []))
        for cb in callbacks:
            try:
                cb(payload)
            except Exception as e:
                log(f"EventBus callback error on {topic}: {e}")

EVENT_BUS = EventBus()

# ---------------------------------------------------------------------------
# EXTENDED LABELS + GUID
# ---------------------------------------------------------------------------

def label_generator():
    alphabet = string.ascii_uppercase
    for combo in itertools.product(alphabet, repeat=2):
        yield "".join(combo)
    for combo in itertools.product(alphabet, repeat=3):
        yield "".join(combo)

def get_guid_from_mount(mount):
    try:
        return win32file.GetVolumeNameForVolumeMountPoint(mount)
    except Exception:
        return None

def get_mounts_from_guid(guid):
    try:
        return win32file.GetVolumePathNamesForVolumeName(guid)
    except Exception:
        return []

class MappingManager:
    def __init__(self):
        self.registry = load_json(REGISTRY_PATH, {"mounts": {}})
        self.reboot = load_json(REBOOT_PATH, {"mounts": {}})
        self.labels = label_generator()

    def get_next_label(self):
        used = set(self.registry["mounts"].keys())
        for label in self.labels:
            if label not in used:
                return label
        raise RuntimeError("No extended labels available.")

    def register_volume(self, mount):
        for label, info in self.registry["mounts"].items():
            if info["volume"] == mount:
                return label
        label = self.get_next_label()
        guid = get_guid_from_mount(mount)
        self.registry["mounts"][label] = {
            "volume": mount,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        if guid:
            self.reboot["mounts"][label] = {
                "guid": guid,
                "last_mount": mount,
            }
        save_json(REGISTRY_PATH, self.registry)
        save_json(REBOOT_PATH, self.reboot)
        log(f"Registered volume {mount} as {label}")
        EVENT_BUS.publish("drives.mapped.updated", self.registry)
        return label

    def sync_registry_to_reboot(self):
        changed = False
        for label, info in self.registry["mounts"].items():
            mount = info["volume"]
            guid = get_guid_from_mount(mount)
            if not guid:
                continue
            if label not in self.reboot["mounts"]:
                self.reboot["mounts"][label] = {
                    "guid": guid,
                    "last_mount": mount,
                }
                changed = True
        if changed:
            save_json(REBOOT_PATH, self.reboot)
            log("Sync registry → reboot.json")

    def sync_reboot_to_registry(self):
        changed = False
        for label, info in self.reboot["mounts"].items():
            guid = info["guid"]
            mounts = get_mounts_from_guid(guid)
            if not mounts:
                continue
            mount = mounts[0]
            if label not in self.registry["mounts"]:
                self.registry["mounts"][label] = {
                    "volume": mount,
                    "timestamp": None,
                }
                changed = True
            else:
                if self.registry["mounts"][label]["volume"] != mount:
                    self.registry["mounts"][label]["volume"] = mount
                    changed = True
        if changed:
            save_json(REGISTRY_PATH, self.registry)
            log("Sync reboot.json → registry")

    def full_sync(self):
        current_mounts = []
        try:
            for part in psutil.disk_partitions(all=False):
                if os.name == "nt":
                    if "cdrom" in part.opts or not part.fstype:
                        continue
                current_mounts.append(part.mountpoint)
        except Exception:
            pass

        existing_mounts = {info["volume"] for info in self.registry.get("mounts", {}).values()}
        for mount in current_mounts:
            if mount not in existing_mounts:
                self.register_volume(mount)

        self.sync_registry_to_reboot()
        self.sync_reboot_to_registry()
        log("Full mapping sync executed (auto-registered current mounts)")
        EVENT_BUS.publish("drives.mapped.updated", self.registry)

# ---------------------------------------------------------------------------
# DRIVE HEALTH (SMART-LIKE)
# ---------------------------------------------------------------------------

class DriveHealthMonitor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.health = {}

    def run(self):
        while self.running:
            self.scan()
            time.sleep(10)

    def stop(self):
        self.running = False

    def scan(self):
        health = {}
        try:
            for disk in psutil.disk_partitions(all=False):
                if os.name == "nt":
                    if "cdrom" in disk.opts or not disk.fstype:
                        continue
                usage = psutil.disk_usage(disk.mountpoint)
                percent = usage.percent
                status = "OK"
                if percent > 90:
                    status = "CRITICAL"
                elif percent > 80:
                    status = "WARN"
                health[disk.device] = {
                    "mountpoint": disk.mountpoint,
                    "fstype": disk.fstype,
                    "used_percent": percent,
                    "status": status,
                }
        except Exception as e:
            log(f"DriveHealth scan error: {e}")
        self.health = health
        save_json(DRIVE_HEALTH_PATH, health)
        EVENT_BUS.publish("drives.health.updated", health)

# ---------------------------------------------------------------------------
# THREAT ENGINE + AI BRAIN
# ---------------------------------------------------------------------------

class Threat:
    def __init__(self, name, level, port=None):
        self.name = name
        self.level = level
        self.port = port
        self.status = "ACTIVE"
        self.score = 0.0
        self.predicted_risk = 0.0
        self.missing_details = []
        self.timeline = []
        self.tags = []

    def snapshot(self):
        return {
            "name": self.name,
            "level": self.level,
            "port": self.port,
            "status": self.status,
            "score": self.score,
            "predicted_risk": self.predicted_risk,
            "missing_details": list(self.missing_details),
            "timeline": list(self.timeline),
            "tags": list(self.tags),
        }

    @staticmethod
    def from_snapshot(data):
        t = Threat(data.get("name"), data.get("level"), data.get("port"))
        t.status = data.get("status", "ACTIVE")
        t.score = data.get("score", 0.0)
        t.predicted_risk = data.get("predicted_risk", 0.0)
        t.missing_details = data.get("missing_details", [])
        t.timeline = data.get("timeline", [])
        t.tags = data.get("tags", [])
        return t

class ThreatEngine:
    def __init__(self):
        self.threats = []
        self.history = load_json(THREAT_HISTORY_PATH, [])
        for entry in self.history:
            self.threats.append(Threat.from_snapshot(entry))
        self.load_factor = 0.0
        self.ai_enabled = True

    def add_threat(self, name, level, port=None):
        t = Threat(name, level, port)
        if level is None:
            t.missing_details.append("level")
        if port is None:
            t.missing_details.append("port")
        self.threats.append(t)
        log(f"Threat added: {name} (L{level}, port {port})")
        self.update_all()
        self.persist()
        EVENT_BUS.publish("threats.updated", [th.snapshot() for th in self.threats])

    def update_all(self):
        ts = time.time()
        for t in self.threats:
            base = (t.level or 1) * 0.5
            if t.port == 35:
                base += 1.0
            if t.missing_details:
                base += 0.5
            t.score = base + self.load_factor
            t.predicted_risk = 1.0 - math.exp(-t.score / 5.0)
            t.timeline.append((ts, t.score))
        self.persist()
        EVENT_BUS.publish("threats.updated", [th.snapshot() for th in self.threats])

    def persist(self):
        save_json(THREAT_HISTORY_PATH, [t.snapshot() for t in self.threats])

class DominionDeckAIBrain:
    def __init__(self):
        self.policy = load_json(AI_POLICY_PATH, {
            "rules": [
                {"id": "P1", "pattern": "Rogue AI", "min_level": 4, "action": "NEUTRALIZE"},
                {"id": "P2", "pattern": "Hacker", "min_level": 3, "action": "FLAG"},
                {"id": "P3", "pattern": "Script", "min_level": 2, "action": "OBSERVE"},
            ]
        })

    def classify(self, threat):
        tags = []
        name = threat.name.lower()
        for rule in self.policy.get("rules", []):
            pat = rule.get("pattern", "").lower()
            if pat and pat in name:
                tags.append(rule.get("action", "TAG"))
        if threat.missing_details:
            tags.append("MISSING_DETAILS")
        if threat.port == 35:
            tags.append("PORT_35")
        threat.tags = tags
        return tags

    def suggest(self, threat):
        tags = self.classify(threat)
        if "NEUTRALIZE" in tags and threat.level and threat.level >= 4:
            return "Recommend NEUTRALIZE (manual only)."
        if "FLAG" in tags:
            return "Recommend FLAG."
        if "OBSERVE" in tags:
            return "Recommend OBSERVE."
        if "MISSING_DETAILS" in tags:
            return "Recommend GATHER_DETAILS."
        return "Recommend NO_ACTION."

# ---------------------------------------------------------------------------
# REAL SWARM NETWORKING (LAN + WAN)
# ---------------------------------------------------------------------------

def load_swarm_peers():
    """
    swarm_peers.json format:
    {
      "peers": [
        {"host": "1.2.3.4", "port": 35353},
        {"host": "example.com", "port": 35353}
      ]
    }
    """
    data = load_json(SWARM_PEERS_PATH, {"peers": []})
    peers = []
    for p in data.get("peers", []):
        host = p.get("host")
        port = p.get("port", 35353)
        if host:
            peers.append((host, int(port)))
    return peers

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

    @staticmethod
    def from_snapshot(data):
        n = SwarmNode(data.get("node_id"))
        n.status = data.get("status", "ONLINE")
        n.load = data.get("load", random.uniform(0.1, 0.9))
        return n

class SwarmNetwork(threading.Thread):
    def __init__(self, port=35353):
        super().__init__(daemon=True)
        self.port = port
        self.running = True
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        try:
            self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        except Exception:
            pass
        self.sock.bind(("", port))
        self.peers = {}
        self.local_load = random.uniform(0.1, 0.9)
        self.wan_peers = load_swarm_peers()

    def run(self):
        self.sock.settimeout(1.0)
        while self.running:
            try:
                data, addr = self.sock.recvfrom(4096)
                msg = json.loads(data.decode("utf-8"))
                peer_id = msg.get("id")
                load = msg.get("load")
                ts = time.time()
                self.peers[peer_id] = {"addr": addr, "load": load, "ts": ts}
                EVENT_BUS.publish("swarm.network.updated", self.snapshot())
            except socket.timeout:
                pass
            except Exception as e:
                log(f"SwarmNetwork recv error: {e}")
            self.broadcast()
            time.sleep(2)

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass

    def broadcast(self):
        msg = json.dumps({"id": socket.gethostname(), "load": self.local_load}).encode("utf-8")
        # LAN broadcast
        try:
            self.sock.sendto(msg, ("255.255.255.255", self.port))
        except Exception:
            pass
        # WAN peers (from config)
        for host, port in self.wan_peers:
            try:
                self.sock.sendto(msg, (host, port))
            except Exception as e:
                log(f"SwarmNetwork WAN send error to {host}:{port} -> {e}")

    def snapshot(self):
        return {
            "local": {"id": socket.gethostname(), "load": self.local_load},
            "peers": self.peers,
        }

class SwarmManager:
    def __init__(self):
        self.nodes = [SwarmNode(i) for i in range(1, 9)]
        hist = load_json(SWARM_HISTORY_PATH, [])
        if hist:
            last = hist[-1]
            self.nodes = [SwarmNode.from_snapshot(nd) for nd in last.get("nodes", [])]
        self.network = SwarmNetwork()

    def start_network(self):
        self.network.start()

    def stop_network(self):
        self.network.stop()

    def tick(self):
        for n in self.nodes:
            n.load = max(0.0, min(1.0, n.load + random.uniform(-0.05, 0.05)))
        save_json(SWARM_HISTORY_PATH, [{
            "timestamp": time.time(),
            "nodes": [n.snapshot() for n in self.nodes],
        }])
        EVENT_BUS.publish("swarm.local.updated", [n.snapshot() for n in self.nodes])

# ---------------------------------------------------------------------------
# TELEMETRY
# ---------------------------------------------------------------------------

class TelemetryManager:
    def __init__(self):
        self.history = deque(maxlen=200)

    def sample(self):
        cpu = psutil.cpu_percent(interval=0.1) if psutil else 0.0
        ram = psutil.virtual_memory().percent if psutil else 0.0
        gpu = []
        try:
            count = pynvml.nvmlDeviceGetCount()
            for i in range(count):
                h = pynvml.nvmlDeviceGetHandleByIndex(i)
                mem = pynvml.nvmlDeviceGetMemoryInfo(h)
                gpu.append({
                    "index": i,
                    "used": mem.used,
                    "total": mem.total,
                })
        except Exception:
            gpu = []
        snap = {
            "ts": time.time(),
            "cpu": cpu,
            "ram": ram,
            "gpu": gpu,
        }
        self.history.append(snap)
        save_json(TELEMETRY_HISTORY_PATH, list(self.history))
        EVENT_BUS.publish("telemetry.updated", snap)

# ---------------------------------------------------------------------------
# VRAM SCANNER
# ---------------------------------------------------------------------------

class VRAMScanner(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.data = []
        try:
            pynvml.nvmlInit()
            self.enabled = True
        except Exception:
            self.enabled = False

    def run(self):
        while self.running and self.enabled:
            try:
                count = pynvml.nvmlDeviceGetCount()
                snapshot = []
                for i in range(count):
                    h = pynvml.nvmlDeviceGetHandleByIndex(i)
                    name = pynvml.nvmlDeviceGetName(h).decode("utf-8")
                    mem = pynvml.nvmlDeviceGetMemoryInfo(h)
                    snapshot.append({
                        "index": i,
                        "name": name,
                        "used": mem.used,
                        "total": mem.total,
                    })
                self.data = snapshot
                EVENT_BUS.publish("vram.updated", snapshot)
            except Exception:
                pass
            time.sleep(2)

    def stop(self):
        self.running = False
        if self.enabled:
            try:
                pynvml.nvmlShutdown()
            except Exception:
                pass

    def snapshot(self):
        return list(self.data)

# ---------------------------------------------------------------------------
# WATCHDOG
# ---------------------------------------------------------------------------

class MountWatchdog(threading.Thread):
    def __init__(self, manager):
        super().__init__(daemon=True)
        self.manager = manager
        self.running = True
        self.last = set()

    def run(self):
        while self.running:
            current = set(p.device for p in psutil.disk_partitions(all=False)) if psutil else set()
            if current != self.last:
                self.manager.full_sync()
                self.last = current
                log("Drive change detected by watchdog")
            time.sleep(2)

    def stop(self):
        self.running = False

# ---------------------------------------------------------------------------
# WINDOWS SERVICE BACKEND
# ---------------------------------------------------------------------------

SERVICE_NAME = "DominionDeckCommandCenterService"
SERVICE_DISPLAY = "DominionDeck Command Center Service"

class DominionDeckService(win32serviceutil.ServiceFramework):
    _svc_name_ = SERVICE_NAME
    _svc_display_name_ = SERVICE_DISPLAY

    def __init__(self, args):
        win32serviceutil.ServiceFramework.__init__(self, args)
        self.hWaitStop = win32event.CreateEvent(None, 0, 0, None)
        self.mapping = MappingManager()
        self.watchdog = MountWatchdog(self.mapping)
        self.threat_engine = ThreatEngine()
        self.ai_brain = DominionDeckAIBrain()
        self.swarm = SwarmManager()
        self.telemetry = TelemetryManager()
        self.vram = VRAMScanner()
        self.drive_health = DriveHealthMonitor()

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.watchdog.stop()
        self.vram.stop()
        self.swarm.stop_network()
        self.drive_health.stop()
        win32event.SetEvent(self.hWaitStop)
        log("Service stop requested")

    def SvcDoRun(self):
        log("Service starting")
        self.mapping.full_sync()
        self.watchdog.start()
        self.vram.start()
        self.swarm.start_network()
        self.drive_health.start()
        while True:
            self.swarm.tick()
            self.telemetry.sample()
            if self.telemetry.history:
                self.threat_engine.load_factor = self.telemetry.history[-1]["cpu"] / 100.0
            else:
                self.threat_engine.load_factor = 0.0
            self.threat_engine.update_all()
            rc = win32event.WaitForSingleObject(self.hWaitStop, 5000)
            if rc == win32event.WAIT_OBJECT_0:
                break
        log("Service stopped")

# ---------------------------------------------------------------------------
# PLUGIN SYSTEM WITH HOT-RELOAD
# ---------------------------------------------------------------------------

def discover_plugins():
    plugins = []
    for p in PLUGINS_DIR.glob("*.py"):
        plugins.append(p.name)
    return plugins

def run_plugin(name):
    path = PLUGINS_DIR / name
    if not path.exists():
        log(f"Plugin not found: {name}")
        return "Plugin not found."
    try:
        spec = importlib.util.spec_from_file_location(name, str(path))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        if hasattr(mod, "run"):
            result = mod.run()
            log(f"Plugin {name} executed.")
            return str(result)
        else:
            log(f"Plugin {name} has no run()")
            return "Plugin has no run() function."
    except Exception as e:
        log(f"Plugin {name} error: {e}")
        return f"Error: {e}"

class PluginWatcher(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.last = set()

    def run(self):
        while self.running:
            current = set(discover_plugins())
            if current != self.last:
                self.last = current
                EVENT_BUS.publish("plugins.updated", list(current))
                log("Plugins updated (hot-reload)")
            time.sleep(3)

    def stop(self):
        self.running = False

# ---------------------------------------------------------------------------
# DRIVE ENUMERATION
# ---------------------------------------------------------------------------

def enumerate_physical_drives():
    drives = []
    try:
        for part in psutil.disk_partitions(all=False):
            if os.name == "nt":
                if "cdrom" in part.opts or not part.fstype:
                    continue
            drives.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
            })
    except Exception:
        pass
    return drives

# ---------------------------------------------------------------------------
# GUI COMMAND CENTER (Dark-style, electric-blue tabs)
# ---------------------------------------------------------------------------

def apply_dark_style(root):
    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except Exception:
        pass
    bg = "#1e1e1e"
    fg = "#e0e0e0"
    accent = "#00aaff"

    style.configure(".", background=bg, foreground=fg)
    style.configure("TFrame", background=bg)
    style.configure("TLabel", background=bg, foreground=fg)
    style.configure("TButton", background="#333333", foreground=fg)
    style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg)

    style.configure("TNotebook", background=bg, borderwidth=0)
    style.configure("TNotebook.Tab",
                    background="#252525",
                    foreground=fg,
                    padding=[10, 5],
                    font=("Segoe UI", 10, "bold"))
    style.map("TNotebook.Tab",
              background=[("selected", accent)],
              foreground=[("selected", "#ffffff")])

def launch_gui():
    root = tkinter.Tk()
    root.title("DominionDeck Command Center")
    root.geometry("1200x750")
    apply_dark_style(root)

    mgr = MappingManager()
    threats = ThreatEngine()
    swarm = SwarmManager()
    telemetry = TelemetryManager()
    vram_scanner = VRAMScanner()
    vram_scanner.start()
    drive_health = DriveHealthMonitor()
    drive_health.start()
    plugin_watcher = PluginWatcher()
    plugin_watcher.start()
    swarm.start_network()

    notebook = ttk.Notebook(root)
    notebook.pack(fill="both", expand=True)

    # Threats tab
    frame_threats = ttk.Frame(notebook)
    notebook.add(frame_threats, text="Threats")

    tree_threats = ttk.Treeview(frame_threats, columns=("name", "level", "port", "score", "risk"), show="headings")
    for col, txt in [("name", "Name"), ("level", "Level"), ("port", "Port"), ("score", "Score"), ("risk", "Risk")]:
        tree_threats.heading(col, text=txt)
        tree_threats.column(col, width=120, anchor="center")
    tree_threats.pack(fill="both", expand=True)

    def on_threats_updated(payload):
        tree_threats.delete(*tree_threats.get_children())
        for t in payload or []:
            tree_threats.insert("", "end", values=(
                t["name"], t["level"], t["port"],
                f"{t['score']:.2f}", f"{t['predicted_risk']:.2f}"
            ))

    EVENT_BUS.subscribe("threats.updated", on_threats_updated)
    on_threats_updated([t.snapshot() for t in threats.threats])

    # Swarm tab
    frame_swarm = ttk.Frame(notebook)
    notebook.add(frame_swarm, text="Swarm")

    tree_swarm_local = ttk.Treeview(frame_swarm, columns=("node", "status", "load"), show="headings", height=8)
    for col, txt in [("node", "Node"), ("status", "Status"), ("load", "Load")]:
        tree_swarm_local.heading(col, text=txt)
        tree_swarm_local.column(col, width=120, anchor="center")
    tree_swarm_local.pack(fill="x", padx=10, pady=(10, 5))

    tree_swarm_net = ttk.Treeview(frame_swarm, columns=("id", "addr", "load"), show="headings", height=8)
    for col, txt in [("id", "Peer ID"), ("addr", "Address"), ("load", "Load")]:
        tree_swarm_net.heading(col, text=txt)
        tree_swarm_net.column(col, width=180, anchor="center")
    tree_swarm_net.pack(fill="x", padx=10, pady=(5, 10))

    def on_swarm_local_updated(payload):
        tree_swarm_local.delete(*tree_swarm_local.get_children())
        for n in payload or []:
            tree_swarm_local.insert("", "end", values=(n["node_id"], "ONLINE", f"{n['load']:.2f}"))

    def on_swarm_network_updated(payload):
        tree_swarm_net.delete(*tree_swarm_net.get_children())
        if not payload:
            return
        for peer_id, info in payload.get("peers", {}).items():
            addr = f"{info['addr'][0]}:{info['addr'][1]}"
            tree_swarm_net.insert("", "end", values=(peer_id, addr, f"{info['load']:.2f}"))

    EVENT_BUS.subscribe("swarm.local.updated", on_swarm_local_updated)
    EVENT_BUS.subscribe("swarm.network.updated", on_swarm_network_updated)
    on_swarm_local_updated([n.snapshot() for n in swarm.nodes])

    # Telemetry tab
    frame_tel = ttk.Frame(notebook)
    notebook.add(frame_tel, text="Telemetry")

    fig = Figure(figsize=(5, 3), dpi=100)
    ax = fig.add_subplot(111)
    canvas = FigureCanvasTkAgg(fig, master=frame_tel)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    def on_telemetry_updated(snap):
        hist = load_json(TELEMETRY_HISTORY_PATH, [])
        ax.clear()
        if hist:
            xs = [h["ts"] - hist[0]["ts"] for h in hist]
            cpu = [h["cpu"] for h in hist]
            ram = [h["ram"] for h in hist]
            ax.plot(xs, cpu, label="CPU %", color="#00aaff")
            ax.plot(xs, ram, label="RAM %", color="#ffaa00")
            ax.legend()
        canvas.draw()

    EVENT_BUS.subscribe("telemetry.updated", on_telemetry_updated)

    # VRAM tab
    frame_vram = ttk.Frame(notebook)
    notebook.add(frame_vram, text="VRAM")

    tree_vram = ttk.Treeview(frame_vram, columns=("index", "name", "used", "total"), show="headings")
    for col, txt in [("index", "GPU"), ("name", "Name"), ("used", "Used MB"), ("total", "Total MB")]:
        tree_vram.heading(col, text=txt)
        tree_vram.column(col, width=150, anchor="center")
    tree_vram.pack(fill="both", expand=True)

    def on_vram_updated(snapshot):
        tree_vram.delete(*tree_vram.get_children())
        for g in snapshot or []:
            used_mb = g["used"] // (1024 * 1024)
            total_mb = g["total"] // (1024 * 1024)
            tree_vram.insert("", "end", values=(g["index"], g["name"], used_mb, total_mb))

    EVENT_BUS.subscribe("vram.updated", on_vram_updated)

    # Drives / Settings tab
    frame_settings = ttk.Frame(notebook)
    notebook.add(frame_settings, text="Drives / Settings")

    btn_sync = ttk.Button(frame_settings, text="Force Full Sync", command=mgr.full_sync)
    btn_sync.pack(pady=10)

    lbl_mapped = ttk.Label(frame_settings, text="Mapped Extended Drives")
    lbl_mapped.pack(pady=(10, 2))

    tree_mapped = ttk.Treeview(frame_settings, columns=("label", "mount", "guid"), show="headings", height=6)
    for col, txt in [("label", "Label"), ("mount", "Mount"), ("guid", "GUID")]:
        tree_mapped.heading(col, text=txt)
        tree_mapped.column(col, width=200, anchor="center")
    tree_mapped.pack(fill="x", padx=10)

    lbl_phys = ttk.Label(frame_settings, text="Physical Drives")
    lbl_phys.pack(pady=(15, 2))

    tree_phys = ttk.Treeview(frame_settings, columns=("device", "mount", "fstype", "health"), show="headings", height=6)
    for col, txt in [("device", "Device"), ("mount", "Mount"), ("fstype", "FS Type"), ("health", "Health")]:
        tree_phys.heading(col, text=txt)
        tree_phys.column(col, width=200, anchor="center")
    tree_phys.pack(fill="x", padx=10)

    def refresh_settings_tables():
        tree_mapped.delete(*tree_mapped.get_children())
        mgr.full_sync()
        for label, info in mgr.registry.get("mounts", {}).items():
            mount = info.get("volume", "")
            guid = mgr.reboot.get("mounts", {}).get(label, {}).get("guid", "")
            tree_mapped.insert("", "end", values=(label, mount, guid))

        tree_phys.delete(*tree_phys.get_children())
        phys = enumerate_physical_drives()
        health = load_json(DRIVE_HEALTH_PATH, {})
        for d in phys:
            h = health.get(d["device"], {})
            status = h.get("status", "UNKNOWN")
            tree_phys.insert("", "end", values=(d["device"], d["mountpoint"], d["fstype"], status))

    def on_mapped_updated(_payload):
        refresh_settings_tables()

    def on_health_updated(_payload):
        refresh_settings_tables()

    EVENT_BUS.subscribe("drives.mapped.updated", on_mapped_updated)
    EVENT_BUS.subscribe("drives.health.updated", on_health_updated)
    refresh_settings_tables()

    # Plugins tab
    frame_plugins = ttk.Frame(notebook)
    notebook.add(frame_plugins, text="Plugins")

    lbl_plugins = ttk.Label(frame_plugins, text="Available Plugins (.py in ProgramData\\DominionDeck\\plugins)")
    lbl_plugins.pack(pady=(10, 2))

    tree_plugins = ttk.Treeview(frame_plugins, columns=("name",), show="headings", height=8)
    tree_plugins.heading("name", text="Plugin")
    tree_plugins.column("name", width=300, anchor="w")
    tree_plugins.pack(fill="x", padx=10)

    txt_plugin_output = tkinter.Text(frame_plugins, height=10, bg="#111111", fg="#e0e0e0")
    txt_plugin_output.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh_plugins_list(names=None):
        tree_plugins.delete(*tree_plugins.get_children())
        if names is None:
            names = discover_plugins()
        for name in names:
            tree_plugins.insert("", "end", values=(name,))

    def on_plugins_updated(names):
        refresh_plugins_list(names)

    EVENT_BUS.subscribe("plugins.updated", on_plugins_updated)
    refresh_plugins_list()

    def run_selected_plugin():
        sel = tree_plugins.selection()
        if not sel:
            return
        name = tree_plugins.item(sel[0], "values")[0]
        result = run_plugin(name)
        txt_plugin_output.delete("1.0", "end")
        txt_plugin_output.insert("1.0", result)

    btn_run_plugin = ttk.Button(frame_plugins, text="Run Selected Plugin", command=run_selected_plugin)
    btn_run_plugin.pack(pady=5)

    # Logs tab
    frame_logs = ttk.Frame(notebook)
    notebook.add(frame_logs, text="Logs")

    txt_logs = tkinter.Text(frame_logs, bg="#111111", fg="#e0e0e0")
    txt_logs.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh_logs():
        txt_logs.delete("1.0", "end")
        for line in LOG_BUFFER:
            txt_logs.insert("end", line + "\n")
        root.after(3000, refresh_logs)

    def on_close():
        vram_scanner.stop()
        drive_health.stop()
        plugin_watcher.stop()
        swarm.stop_network()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    refresh_logs()
    root.mainloop()

# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def print_usage():
    print("""
Commands:
  install     Install DominionDeck service
  remove      Remove DominionDeck service
  start       Start DominionDeck service
  stop        Stop DominionDeck service
  restart     Restart DominionDeck service
  gui         Launch DominionDeck Command Center GUI
  sync        Force full mapping sync
(No arguments) Launch GUI by default.
""")

if __name__ == "__main__":
    if len(sys.argv) == 1:
        launch_gui()
        sys.exit(0)

    cmd = sys.argv[1].lower()

    if cmd == "install":
        win32serviceutil.InstallService(
            DominionDeckService._svc_name_,
            DominionDeckService._svc_display_name_,
            DominionDeckService._svc_display_name_,
        )
        print("Service installed.")
        log("Service installed via CLI")

    elif cmd == "remove":
        win32serviceutil.RemoveService(DominionDeckService._svc_name_)
        print("Service removed.")
        log("Service removed via CLI")

    elif cmd == "start":
        win32serviceutil.StartService(DominionDeckService._svc_name_)
        print("Service started.")
        log("Service started via CLI")

    elif cmd == "stop":
        win32serviceutil.StopService(DominionDeckService._svc_name_)
        print("Service stopped.")
        log("Service stopped via CLI")

    elif cmd == "restart":
        win32serviceutil.RestartService(DominionDeckService._svc_name_)
        print("Service restarted.")
        log("Service restarted via CLI")

    elif cmd == "gui":
        launch_gui()

    elif cmd == "sync":
        MappingManager().full_sync()
        print("Full sync complete.")
        log("Full sync via CLI")

    else:
        print_usage()
