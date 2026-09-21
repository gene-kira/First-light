#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DominionDeck_CommandCenter_FullSystem.py

Option C: BOTH
- Windows service backend (DominionDeck AI + ExtendedDrive backend)
- GUI Command Center frontend (multi-tab live panel)
- Threat engine, AI brain, swarm, telemetry, VRAM scanner
- GUID-based persistence, reboot-safe JSON, autoloader, watchdog
- Settings tab: two tables → Mapped drives + Physical drives
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

# pywin32 modules (imported as win32*)
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

# ---------------------------------------------------------------------------
# PATHS / PERSISTENCE
# ---------------------------------------------------------------------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
PROGRAMDATA = Path(os.getenv("PROGRAMDATA", "C:\\ProgramData")) / "DominionDeck"
PROGRAMDATA.mkdir(parents=True, exist_ok=True)

DATA_DIR = PROGRAMDATA / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

REGISTRY_PATH = PROGRAMDATA / "registry.json"
REBOOT_PATH = PROGRAMDATA / "reboot.json"

THREAT_HISTORY_PATH = DATA_DIR / "threat_history.json"
SWARM_HISTORY_PATH = DATA_DIR / "swarm_history.json"
TELEMETRY_HISTORY_PATH = DATA_DIR / "telemetry_history.json"
AI_POLICY_PATH = DATA_DIR / "ai_policy.json"
SETTINGS_PATH = DATA_DIR / "settings.json"

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

    def full_sync(self):
        self.sync_registry_to_reboot()
        self.sync_reboot_to_registry()

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
        self.update_all()
        self.persist()

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
# SWARM + TELEMETRY
# ---------------------------------------------------------------------------

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

class SwarmManager:
    def __init__(self):
        self.nodes = [SwarmNode(i) for i in range(1, 6)]
        hist = load_json(SWARM_HISTORY_PATH, [])
        if hist:
            last = hist[-1]
            self.nodes = [SwarmNode.from_snapshot(nd) for nd in last.get("nodes", [])]

    def tick(self):
        for n in self.nodes:
            n.load = max(0.0, min(1.0, n.load + random.uniform(-0.1, 0.1)))
        save_json(SWARM_HISTORY_PATH, [{
            "timestamp": time.time(),
            "nodes": [n.snapshot() for n in self.nodes],
        }])

class TelemetryManager:
    def __init__(self):
        self.history = deque(maxlen=100)

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

    def SvcStop(self):
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)
        self.watchdog.stop()
        self.vram.stop()
        win32event.SetEvent(self.hWaitStop)

    def SvcDoRun(self):
        self.mapping.full_sync()
        self.watchdog.start()
        self.vram.start()
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

# ---------------------------------------------------------------------------
# GUI COMMAND CENTER
# ---------------------------------------------------------------------------

def enumerate_physical_drives():
    drives = []
    try:
        for part in psutil.disk_partitions(all=False):
            drives.append({
                "device": part.device,
                "mountpoint": part.mountpoint,
                "fstype": part.fstype,
            })
    except Exception:
        pass
    return drives

def launch_gui():
    root = tkinter.Tk()
    root.title("DominionDeck Command Center")
    root.geometry("1000x650")

    mgr = MappingManager()
    threats = ThreatEngine()
    swarm = SwarmManager()
    telemetry = TelemetryManager()
    vram_scanner = VRAMScanner()
    vram_scanner.start()

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

    def refresh_threats():
        tree_threats.delete(*tree_threats.get_children())
        for t in threats.threats:
            tree_threats.insert("", "end", values=(t.name, t.level, t.port, f"{t.score:.2f}", f"{t.predicted_risk:.2f}"))
        root.after(2000, refresh_threats)

    # Swarm tab
    frame_swarm = ttk.Frame(notebook)
    notebook.add(frame_swarm, text="Swarm")

    tree_swarm = ttk.Treeview(frame_swarm, columns=("node", "status", "load"), show="headings")
    for col, txt in [("node", "Node"), ("status", "Status"), ("load", "Load")]:
        tree_swarm.heading(col, text=txt)
        tree_swarm.column(col, width=120, anchor="center")
    tree_swarm.pack(fill="both", expand=True)

    def refresh_swarm():
        tree_swarm.delete(*tree_swarm.get_children())
        for n in swarm.nodes:
            tree_swarm.insert("", "end", values=(n.node_id, n.status, f"{n.load:.2f}"))
        root.after(3000, refresh_swarm)

    # Telemetry tab
    frame_tel = ttk.Frame(notebook)
    notebook.add(frame_tel, text="Telemetry")

    fig = Figure(figsize=(5, 3), dpi=100)
    ax = fig.add_subplot(111)
    canvas = FigureCanvasTkAgg(fig, master=frame_tel)
    canvas.get_tk_widget().pack(fill="both", expand=True)

    def refresh_telemetry():
        hist = load_json(TELEMETRY_HISTORY_PATH, [])
        ax.clear()
        if hist:
            xs = [h["ts"] - hist[0]["ts"] for h in hist]
            cpu = [h["cpu"] for h in hist]
            ram = [h["ram"] for h in hist]
            ax.plot(xs, cpu, label="CPU %")
            ax.plot(xs, ram, label="RAM %")
            ax.legend()
        canvas.draw()
        root.after(3000, refresh_telemetry)

    # VRAM tab
    frame_vram = ttk.Frame(notebook)
    notebook.add(frame_vram, text="VRAM")

    tree_vram = ttk.Treeview(frame_vram, columns=("index", "name", "used", "total"), show="headings")
    for col, txt in [("index", "GPU"), ("name", "Name"), ("used", "Used MB"), ("total", "Total MB")]:
        tree_vram.heading(col, text=txt)
        tree_vram.column(col, width=150, anchor="center")
    tree_vram.pack(fill="both", expand=True)

    def refresh_vram():
        tree_vram.delete(*tree_vram.get_children())
        snap = vram_scanner.snapshot()
        for g in snap:
            used_mb = g["used"] // (1024 * 1024)
            total_mb = g["total"] // (1024 * 1024)
            tree_vram.insert("", "end", values=(g["index"], g["name"], used_mb, total_mb))
        root.after(2000, refresh_vram)

    # Settings tab
    frame_settings = ttk.Frame(notebook)
    notebook.add(frame_settings, text="Settings")

    btn_sync = ttk.Button(frame_settings, text="Force Full Sync", command=mgr.full_sync)
    btn_sync.pack(pady=10)

    # Mapped drives table
    lbl_mapped = ttk.Label(frame_settings, text="Mapped Extended Drives")
    lbl_mapped.pack(pady=(10, 2))

    tree_mapped = ttk.Treeview(frame_settings, columns=("label", "mount", "guid"), show="headings", height=6)
    for col, txt in [("label", "Label"), ("mount", "Mount"), ("guid", "GUID")]:
        tree_mapped.heading(col, text=txt)
        tree_mapped.column(col, width=200, anchor="center")
    tree_mapped.pack(fill="x", padx=10)

    # Physical drives table
    lbl_phys = ttk.Label(frame_settings, text="Physical Drives")
    lbl_phys.pack(pady=(15, 2))

    tree_phys = ttk.Treeview(frame_settings, columns=("device", "mount", "fstype"), show="headings", height=6)
    for col, txt in [("device", "Device"), ("mount", "Mount"), ("fstype", "FS Type")]:
        tree_phys.heading(col, text=txt)
        tree_phys.column(col, width=200, anchor="center")
    tree_phys.pack(fill="x", padx=10)

    def refresh_settings():
        # mapped drives
        tree_mapped.delete(*tree_mapped.get_children())
        mgr.full_sync()
        for label, info in mgr.registry.get("mounts", {}).items():
            mount = info.get("volume", "")
            guid = mgr.reboot.get("mounts", {}).get(label, {}).get("guid", "")
            tree_mapped.insert("", "end", values=(label, mount, guid))

        # physical drives
        tree_phys.delete(*tree_phys.get_children())
        phys = enumerate_physical_drives()
        for d in phys:
            tree_phys.insert("", "end", values=(d["device"], d["mountpoint"], d["fstype"]))
        root.after(4000, refresh_settings)

    def on_close():
        vram_scanner.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)

    refresh_threats()
    refresh_swarm()
    refresh_telemetry()
    refresh_vram()
    refresh_settings()
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

    elif cmd == "remove":
        win32serviceutil.RemoveService(DominionDeckService._svc_name_)
        print("Service removed.")

    elif cmd == "start":
        win32serviceutil.StartService(DominionDeckService._svc_name_)
        print("Service started.")

    elif cmd == "stop":
        win32serviceutil.StopService(DominionDeckService._svc_name_)
        print("Service stopped.")

    elif cmd == "restart":
        win32serviceutil.RestartService(DominionDeckService._svc_name_)
        print("Service restarted.")

    elif cmd == "gui":
        launch_gui()

    elif cmd == "sync":
        MappingManager().full_sync()
        print("Full sync complete.")

    else:
        print_usage()
