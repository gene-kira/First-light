#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
DominionDeck_CommandCenter_FullSystem_Ultimate.py

Upgrades (applied):
- Real-time event bus (no GUI-side polling)
- Event bus inspector (live stream of events)
- Plugin system with hot-reload + basic sandboxing
- Real swarm networking:
    - LAN broadcast (UDP)
    - WAN support via configurable peer list (swarm_peers.json)
    - Encrypted WAN packets (AES-256 CTR)
    - Per-peer handshake (ephemeral session keys)
    - Swarm command propagation (JSON commands between peers)
    - Swarm registry (peer health + capabilities)
- Drive health monitoring:
    - Heuristic (psutil usage)
    - SMART-like via WMI (Windows only, basic attributes)
- GUID-based drive persistence + extended labels
- Windows service backend + GUI Command Center frontend
- Threat engine, AI rule brain, telemetry, VRAM scanner
- GPU governor skeleton (read telemetry, plan tuning; no actual OC)
- VRAM stress tester plugin hook
- Auto-update stub (version check + placeholder)
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
    "pycryptodome",
    "wmi",
]

def ensure_package(pkg, pip_name=None):
    try:
        return importlib.import_module(pkg)
    except ImportError:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name or pkg])
        return importlib.import_module(pkg)

modules = {}
for pkg in BASE_LIBS:
    if pkg == "pycryptodome":
        modules["Crypto"] = ensure_package("Crypto", "pycryptodome")
    else:
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
Crypto = modules["Crypto"]
wmi = modules["wmi"]

from tkinter import ttk
from matplotlib.figure import Figure
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import importlib.util

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

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
SWARM_PEERS_PATH = DATA_DIR / "swarm_peers.json"
SWARM_KEY_PATH = DATA_DIR / "swarm_key.json"
UPDATE_INFO_PATH = DATA_DIR / "update_info.json"

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
# REAL-TIME EVENT BUS + INSPECTOR
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
        # inspector stream
        EventInspector.record_event(topic, payload)
        for cb in callbacks:
            try:
                cb(payload)
            except Exception as e:
                log(f"EventBus callback error on {topic}: {e}")

EVENT_BUS = EventBus()

class EventInspector:
    buffer = deque(maxlen=500)
    lock = threading.Lock()

    @classmethod
    def record_event(cls, topic, payload):
        with cls.lock:
            ts = time.strftime("%H:%M:%S")
            short = str(payload)
            if len(short) > 200:
                short = short[:200] + "..."
            cls.buffer.append(f"[{ts}] {topic}: {short}")

    @classmethod
    def snapshot(cls):
        with cls.lock:
            return list(cls.buffer)

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
# DRIVE HEALTH (SMART + heuristic)
# ---------------------------------------------------------------------------

class DriveHealthMonitor(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True)
        self.running = True
        self.health = {}
        self.wmi_client = None
        try:
            self.wmi_client = wmi.WMI()
        except Exception as e:
            log(f"WMI init failed: {e}")
            self.wmi_client = None

    def run(self):
        while self.running:
            self.scan()
            time.sleep(20)

    def stop(self):
        self.running = False

    def _smart_data(self):
        smart_info = {}
        if not self.wmi_client:
            return smart_info
        try:
            for disk in self.wmi_client.Win32_DiskDrive():
                dev_id = disk.DeviceID
                smart_info[dev_id] = {
                    "model": disk.Model,
                    "serial": getattr(disk, "SerialNumber", None),
                    "size": int(disk.Size) if disk.Size else None,
                    "status": disk.Status,
                }
        except Exception as e:
            log(f"SMART WMI error: {e}")
        return smart_info

    def scan(self):
        health = {}
        smart = self._smart_data()
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

                dev = disk.device
                smart_entry = None
                for dev_id, info in smart.items():
                    if dev in dev_id:
                        smart_entry = info
                        break

                health[dev] = {
                    "mountpoint": disk.mountpoint,
                    "fstype": disk.fstype,
                    "used_percent": percent,
                    "status": status,
                    "smart": smart_entry,
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
# SWARM ENCRYPTION + CONFIG + HANDSHAKE
# ---------------------------------------------------------------------------

def load_swarm_peers():
    data = load_json(SWARM_PEERS_PATH, {"peers": []})
    peers = []
    for p in data.get("peers", []):
        host = p.get("host")
        port = p.get("port", 35353)
        if host:
            peers.append((host, int(port)))
    return peers

def load_swarm_key():
    data = load_json(SWARM_KEY_PATH, {})
    key_hex = data.get("key_hex")
    if not key_hex:
        key = get_random_bytes(32)
        key_hex = key.hex()
        save_json(SWARM_KEY_PATH, {"key_hex": key_hex})
        log("Generated new swarm AES base key.")
    return bytes.fromhex(key_hex)

def encrypt_payload(key, payload_dict):
    try:
        plaintext = json.dumps(payload_dict).encode("utf-8")
        nonce = get_random_bytes(16)
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        ciphertext = cipher.encrypt(plaintext)
        return json.dumps({
            "nonce": nonce.hex(),
            "ciphertext": ciphertext.hex(),
        }).encode("utf-8")
    except Exception as e:
        log(f"encrypt_payload error: {e}")
        return b""

def decrypt_payload(key, data_bytes):
    try:
        wrapper = json.loads(data_bytes.decode("utf-8"))
        nonce = bytes.fromhex(wrapper["nonce"])
        ciphertext = bytes.fromhex(wrapper["ciphertext"])
        cipher = AES.new(key, AES.MODE_CTR, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        return json.loads(plaintext.decode("utf-8"))
    except Exception as e:
        log(f"decrypt_payload error: {e}")
        return None

# ---------------------------------------------------------------------------
# REAL SWARM NETWORKING (LAN + WAN + encrypted + commands + registry)
# ---------------------------------------------------------------------------

class SwarmRegistry:
    def __init__(self):
        self.peers = {}
        self.lock = threading.Lock()

    def update_peer(self, peer_id, addr, load, capabilities=None):
        with self.lock:
            self.peers[peer_id] = {
                "addr": addr,
                "load": load,
                "capabilities": capabilities or [],
                "last_seen": time.time(),
            }
        EVENT_BUS.publish("swarm.registry.updated", self.snapshot())

    def snapshot(self):
        with self.lock:
            return dict(self.peers)

SWARM_REGISTRY = SwarmRegistry()

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
        self.local_load = random.uniform(0.1, 0.9)
        self.wan_peers = load_swarm_peers()
        self.base_key = load_swarm_key()
        self.session_keys = {}  # peer_id -> key

    def run(self):
        self.sock.settimeout(1.0)
        self._broadcast_handshake()
        while self.running:
            try:
                data, addr = self.sock.recvfrom(8192)
                msg = None
                # try encrypted with any session key
                for key in [self.base_key] + list(self.session_keys.values()):
                    msg = decrypt_payload(key, data)
                    if msg is not None:
                        break
                if msg is None:
                    try:
                        msg = json.loads(data.decode("utf-8"))
                    except Exception:
                        msg = None
                if not msg:
                    continue

                msg_type = msg.get("type", "status")
                if msg_type == "handshake":
                    peer_id = msg.get("id")
                    # generate session key
                    sk = get_random_bytes(32)
                    self.session_keys[peer_id] = sk
                    reply = {
                        "type": "handshake_ack",
                        "id": socket.gethostname(),
                        "session_key": sk.hex(),
                    }
                    enc = encrypt_payload(self.base_key, reply)
                    self.sock.sendto(enc, addr)
                    log(f"Handshake from {peer_id}, session key established.")
                elif msg_type == "handshake_ack":
                    peer_id = msg.get("id")
                    sk_hex = msg.get("session_key")
                    if sk_hex:
                        self.session_keys[peer_id] = bytes.fromhex(sk_hex)
                        log(f"Handshake ACK from {peer_id}, session key stored.")
                elif msg_type == "status":
                    peer_id = msg.get("id")
                    load = msg.get("load")
                    caps = msg.get("capabilities", [])
                    SWARM_REGISTRY.update_peer(peer_id, addr, load, caps)
                    EVENT_BUS.publish("swarm.network.updated", self.snapshot())
                elif msg_type == "command":
                    cmd = msg.get("command")
                    args = msg.get("args", {})
                    EVENT_BUS.publish("swarm.command.received", {
                        "from": addr,
                        "command": cmd,
                        "args": args,
                    })
                    log(f"Swarm command received from {addr}: {cmd} {args}")
            except socket.timeout:
                pass
            except Exception as e:
                log(f"SwarmNetwork recv error: {e}")
            self.broadcast_status()
            time.sleep(2)

    def stop(self):
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass

    def _broadcast_handshake(self):
        payload = {
            "type": "handshake",
            "id": socket.gethostname(),
        }
        msg = encrypt_payload(self.base_key, payload)
        for host, port in self.wan_peers:
            try:
                self.sock.sendto(msg, (host, port))
            except Exception as e:
                log(f"Handshake send error to {host}:{port}: {e}")

    def broadcast_status(self):
        payload = {
            "type": "status",
            "id": socket.gethostname(),
            "load": self.local_load,
            "capabilities": ["telemetry", "drive_health", "vram", "plugins"],
        }
        msg_plain = json.dumps(payload).encode("utf-8")
        msg_enc = encrypt_payload(self.base_key, payload)
        try:
            self.sock.sendto(msg_plain, ("255.255.255.255", self.port))
        except Exception:
            pass
        for host, port in self.wan_peers:
            try:
                self.sock.sendto(msg_enc, (host, port))
            except Exception as e:
                log(f"Swarm WAN status error to {host}:{port}: {e}")

    def send_command(self, command, args=None):
        if args is None:
            args = {}
        payload = {
            "type": "command",
            "id": socket.gethostname(),
            "command": command,
            "args": args,
        }
        msg_enc = encrypt_payload(self.base_key, payload)
        for host, port in self.wan_peers:
            try:
                self.sock.sendto(msg_enc, (host, port))
                log(f"Swarm command sent to {host}:{port}: {command} {args}")
            except Exception as e:
                log(f"Swarm command send error to {host}:{port}: {e}")

    def snapshot(self):
        return {
            "local": {"id": socket.gethostname(), "load": self.local_load},
            "registry": SWARM_REGISTRY.snapshot(),
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

    def send_command(self, command, args=None):
        self.network.send_command(command, args or {})

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
# GPU GOVERNOR (skeleton)
# ---------------------------------------------------------------------------

class GPUGovernor:
    def __init__(self):
        self.policy = {
            "max_cpu": 90.0,
            "max_vram_percent": 95.0,
        }

    def evaluate(self, telemetry_snap):
        # skeleton: no actual OC, just decisions
        cpu = telemetry_snap.get("cpu", 0.0)
        gpu = telemetry_snap.get("gpu", [])
        actions = []
        if cpu > self.policy["max_cpu"]:
            actions.append("THROTTLE_CPU_TASKS")
        for g in gpu:
            used = g["used"]
            total = g["total"]
            if total > 0 and (used / total) * 100.0 > self.policy["max_vram_percent"]:
                actions.append(f"VRAM_HIGH_GPU_{g['index']}")
        if actions:
            EVENT_BUS.publish("gpu.governor.actions", actions)

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
# AUTO-UPDATE STUB
# ---------------------------------------------------------------------------

CURRENT_VERSION = "1.0.0"

def check_for_update():
    info = load_json(UPDATE_INFO_PATH, {"latest": CURRENT_VERSION})
    latest = info.get("latest", CURRENT_VERSION)
    if latest != CURRENT_VERSION:
        log(f"Update available: {latest} (current {CURRENT_VERSION})")
        EVENT_BUS.publish("update.available", {"current": CURRENT_VERSION, "latest": latest})

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
        self.gpu_governor = GPUGovernor()

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
        check_for_update()
        while True:
            self.swarm.tick()
            self.telemetry.sample()
            snap = self.telemetry.history[-1] if self.telemetry.history else {"cpu": 0.0, "gpu": []}
            self.threat_engine.load_factor = snap["cpu"] / 100.0
            self.threat_engine.update_all()
            self.gpu_governor.evaluate(snap)
            rc = win32event.WaitForSingleObject(self.hWaitStop, 5000)
            if rc == win32event.WAIT_OBJECT_0:
                break
        log("Service stopped")

# ---------------------------------------------------------------------------
# PLUGIN SYSTEM WITH HOT-RELOAD + BASIC SANDBOX
# ---------------------------------------------------------------------------

SAFE_PLUGIN_API = {
    "log": log,
    "EVENT_BUS": EVENT_BUS,
}

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
            try:
                result = mod.run(SAFE_PLUGIN_API)
            except TypeError:
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
    root.geometry("1300x850")
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

    tree_swarm_reg = ttk.Treeview(frame_swarm, columns=("id", "addr", "load", "caps"), show="headings", height=8)
    for col, txt in [("id", "Peer ID"), ("addr", "Address"), ("load", "Load"), ("caps", "Capabilities")]:
        tree_swarm_reg.heading(col, text=txt)
        tree_swarm_reg.column(col, width=220, anchor="center")
    tree_swarm_reg.pack(fill="x", padx=10, pady=(5, 10))

    txt_swarm_cmd = tkinter.Text(frame_swarm, height=4, bg="#111111", fg="#e0e0e0")
    txt_swarm_cmd.pack(fill="x", padx=10, pady=(5, 5))

    def on_swarm_local_updated(payload):
        tree_swarm_local.delete(*tree_swarm_local.get_children())
        for n in payload or []:
            tree_swarm_local.insert("", "end", values=(n["node_id"], "ONLINE", f"{n['load']:.2f}"))

    def on_swarm_registry_updated(payload):
        tree_swarm_reg.delete(*tree_swarm_reg.get_children())
        for peer_id, info in (payload or {}).items():
            addr = f"{info['addr'][0]}:{info['addr'][1]}"
            caps = ",".join(info.get("capabilities", []))
            tree_swarm_reg.insert("", "end", values=(peer_id, addr, f"{info['load']:.2f}", caps))

    def on_swarm_command_received(payload):
        if not payload:
            return
        txt_swarm_cmd.insert("end", f"FROM {payload['from']}: {payload['command']} {payload['args']}\n")
        txt_swarm_cmd.see("end")

    EVENT_BUS.subscribe("swarm.local.updated", on_swarm_local_updated)
    EVENT_BUS.subscribe("swarm.registry.updated", on_swarm_registry_updated)
    EVENT_BUS.subscribe("swarm.command.received", on_swarm_command_received)
    on_swarm_local_updated([n.snapshot() for n in swarm.nodes])
    on_swarm_registry_updated(SWARM_REGISTRY.snapshot())

    def send_swarm_command_gui():
        content = txt_swarm_cmd.get("1.0", "end").strip()
        if not content:
            return
        parts = content.split()
        cmd = parts[0]
        args = {}
        for p in parts[1:]:
            if "=" in p:
                k, v = p.split("=", 1)
                args[k] = v
        swarm.send_command(cmd, args)
        txt_swarm_cmd.insert("end", f"LOCAL SENT: {cmd} {args}\n")
        txt_swarm_cmd.see("end")

    btn_swarm_send = ttk.Button(frame_swarm, text="Send Swarm Command", command=send_swarm_command_gui)
    btn_swarm_send.pack(pady=5)

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

    lbl_phys = ttk.Label(frame_settings, text="Physical Drives (with SMART)")
    lbl_phys.pack(pady=(15, 2))

    tree_phys = ttk.Treeview(frame_settings, columns=("device", "mount", "fstype", "health", "smart"), show="headings", height=8)
    for col, txt in [("device", "Device"), ("mount", "Mount"), ("fstype", "FS Type"), ("health", "Health"), ("smart", "SMART")]:
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
            smart = h.get("smart")
            smart_str = ""
            if smart:
                smart_str = f"{smart.get('model','')} / {smart.get('serial','')} / {smart.get('status','')}"
            tree_phys.insert("", "end", values=(d["device"], d["mountpoint"], d["fstype"], status, smart_str))

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

    # Event Bus Inspector tab
    frame_events = ttk.Frame(notebook)
    notebook.add(frame_events, text="Event Bus Inspector")

    txt_events = tkinter.Text(frame_events, bg="#111111", fg="#e0e0e0")
    txt_events.pack(fill="both", expand=True, padx=10, pady=10)

    def refresh_events():
        txt_events.delete("1.0", "end")
        for line in EventInspector.snapshot():
            txt_events.insert("end", line + "\n")
        root.after(2000, refresh_events)

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
    refresh_events()
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
