#!/usr/bin/env python
# Codex Purge Shell v4.6 (Safe Edition) — Win11 Security Bridge & Adjustment Console
# - Auto-elevation
# - Suricata v6 (file-tail + UDP socket stub, richer event meta)
# - GPU DL stub threat scoring (extended features)
# - Agentic reasoning (suggest-only, richer actions + threat timeline)
# - Honeypot (logical, multi-protocol tags)
# - GPO/Telemetry (safe subset, extended)
# - Event Bus
# - Resurrection detection
# - Windows Adjustment Engine (Firewall, Registry, Services, Tasks, Telemetry, Defender, Network, Power, Update, System Info)
# - Compact GUI with tabbed layout (left/right notebooks)
# - Hourly baseline snapshot logic
# - Snapshot cooldown (1 per hour max)
# - Optional Suricata/Update-driven snapshots
# - Persistent-change detection to avoid noise
# - Snapshot compression (ZIP) + delta metadata
# - Logical swarm sync (node state exchange stub + peer simulation)
# - Threat timeline view (process + Suricata + honeypot events)
# - v4.6: better threat scoring, richer swarm view, more detailed meta in snapshots, threat timeline tab

import sys
import os
import platform
import subprocess
import threading
import time
import random
import math
import json
import queue
import zipfile

# === AUTO-ELEVATION CHECK ===
import ctypes

def ensure_admin():
    try:
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

# =========================
# Environment checks
# =========================

if platform.system().lower() != "windows":
    print("This build is Windows-only. Detected:", platform.system())
    sys.exit(1)

REQUIRED_MODULES = [
    "tkinter",
    "psutil",
    "winreg",
    "hashlib",
    "datetime",
]

def ensure_dependencies():
    import importlib
    missing = []
    for m in REQUIRED_MODULES:
        try:
            importlib.import_module(m)
        except ImportError:
            missing.append(m)
    if missing:
        print("Missing Python modules:", ", ".join(missing))
        print("Install them with:")
        print("    pip install psutil")
        sys.exit(1)

ensure_dependencies()

import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import winreg
import hashlib
from datetime import datetime

# Optional / best-effort imports for advanced features
try:
    import torch
    GPU_AVAILABLE = torch.cuda.is_available()
except Exception:
    torch = None
    GPU_AVAILABLE = False

SNAPSHOT_ROOT = "Snapshots"
DEFAULT_REG_PATH = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

# =========================
# Safe helpers
# =========================

def safe_call(cmd, text=True):
    try:
        return subprocess.check_output(cmd, text=text)
    except Exception:
        return ""

def safe_call_powershell(ps_script):
    try:
        return subprocess.check_output(
            ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", ps_script],
            text=True
        )
    except Exception:
        return ""

def hash_state(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def ensure_snapshot_root():
    os.makedirs(SNAPSHOT_ROOT, exist_ok=True)

# =========================
# Firewall / registry state
# =========================

def get_firewall_state():
    return safe_call(["netsh", "advfirewall", "show", "allprofiles"])

def get_profiles_state():
    return get_firewall_state()

def read_registry_key(path):
    try:
        hive, subkey = path.split("\\", 1)
        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER
        }
        key = winreg.OpenKey(hive_map[hive], subkey)
        values = []
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                values.append((name, value))
                i += 1
            except OSError:
                break
        return values
    except Exception:
        return []

def get_settings_state():
    vals = read_registry_key(DEFAULT_REG_PATH)
    return "\n".join(f"{n}={v}" for n, v in vals)

# =========================
# Group Policy / Telemetry suppression (safe subset, extended)
# =========================

GPO_TELEMETRY_KEYS = [
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\Feedback",
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\ErrorReporting",
]

def apply_telemetry_suppression(log_fn=None):
    for path in GPO_TELEMETRY_KEYS:
        try:
            hive, subkey = path.split("\\", 1)
            hive_map = {
                "HKLM": winreg.HKEY_LOCAL_MACHINE,
            }
            key = winreg.CreateKey(hive_map[hive], subkey)
            winreg.SetValueEx(key, "AllowTelemetry", 0, winreg.REG_DWORD, 0)
            if "ErrorReporting" in path:
                winreg.SetValueEx(key, "Disabled", 0, winreg.REG_DWORD, 1)
            if log_fn:
                log_fn(f"[GPO] Telemetry/ErrorReporting suppression applied at {path}")
        except Exception:
            if log_fn:
                log_fn(f"[GPO] Failed to apply telemetry suppression at {path}")

# =========================
# Snapshots (firewall + registry + meta) + compression + delta metadata
# =========================

def list_snapshots():
    ensure_snapshot_root()
    return sorted(
        [os.path.join(SNAPSHOT_ROOT, d) for d in os.listdir(SNAPSHOT_ROOT)
         if os.path.isdir(os.path.join(SNAPSHOT_ROOT, d))],
        reverse=True
    )

def compress_snapshot(folder):
    zip_path = folder + ".zip"
    try:
        with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(folder):
                for f in files:
                    full = os.path.join(root, f)
                    arc = os.path.relpath(full, os.path.dirname(folder))
                    zf.write(full, arc)
        return zip_path
    except Exception:
        return None

def create_snapshot(extra_meta=None, baseline_hashes=None, current_hashes=None):
    ensure_snapshot_root()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    folder = os.path.join(SNAPSHOT_ROOT, timestamp)
    os.makedirs(folder, exist_ok=True)

    try:
        subprocess.call(["netsh", "advfirewall", "export", os.path.join(folder, "firewall_rules.wfw")])
    except Exception:
        pass

    try:
        with open(os.path.join(folder, "firewall_profiles.txt"), "w", encoding="utf-8") as f:
            f.write(get_firewall_state())
    except Exception:
        pass

    try:
        subprocess.call([
            "reg", "export",
            DEFAULT_REG_PATH,
            os.path.join(folder, "firewall_policy.reg"), "/y"
        ])
    except Exception:
        pass

    meta = extra_meta or {}
    meta["baseline_hashes"] = baseline_hashes or {}
    meta["current_hashes"] = current_hashes or {}
    meta["delta"] = {
        "Firewall_changed": baseline_hashes and current_hashes and baseline_hashes.get("fw") != current_hashes.get("fw"),
        "Profiles_changed": baseline_hashes and current_hashes and baseline_hashes.get("profiles") != current_hashes.get("profiles"),
        "Settings_changed": baseline_hashes and current_hashes and baseline_hashes.get("settings") != current_hashes.get("settings"),
    }

    try:
        with open(os.path.join(folder, "codex_meta.json"), "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
    except Exception:
        pass

    compress_snapshot(folder)
    return folder

def restore_snapshot(folder):
    rules = os.path.join(folder, "firewall_rules.wfw")
    policy = os.path.join(folder, "firewall_policy.reg")
    meta = os.path.join(folder, "codex_meta.json")

    if os.path.isfile(rules):
        try:
            subprocess.call(["netsh", "advfirewall", "import", rules])
        except Exception:
            pass
    if os.path.isfile(policy):
        try:
            subprocess.call(["reg", "import", policy])
        except Exception:
            pass
    if os.path.isfile(meta):
        try:
            with open(meta, "r", encoding="utf-8") as f:
                data = json.load(f)
            print("[Codex Purge Shell v4.6] Restored meta snapshot:", data.get("summary", "no summary"))
        except Exception:
            pass

# =========================
# Suricata v6 log / event ingestion (file-tail + UDP config stub)
# =========================

class SuricataEventIngestor:
    def __init__(self, log_path=None, udp_port=None):
        self.log_path = log_path or r"C:\ProgramData\Suricata\logs\eve.json"
        self.udp_port = udp_port or 5514  # logical stub; not binding real socket in safe edition
        self.running = False
        self.thread = None
        self.event_queue = queue.Queue()

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _loop(self):
        last_size = 0
        while self.running:
            try:
                if os.path.isfile(self.log_path):
                    size = os.path.getsize(self.log_path)
                    if size > last_size:
                        with open(self.log_path, "r", encoding="utf-8", errors="ignore") as f:
                            f.seek(last_size)
                            for line in f:
                                line = line.strip()
                                if not line:
                                    continue
                                try:
                                    evt = json.loads(line)
                                    self.event_queue.put(evt)
                                except Exception:
                                    continue
                        last_size = size
            except Exception:
                pass
            time.sleep(2)

    def get_event_nowait(self):
        try:
            return self.event_queue.get_nowait()
        except queue.Empty:
            return None

# =========================
# NDIS control plane (logical stub)
# =========================

class NDISControlPlane:
    def __init__(self):
        self.blocked_ips = set()
        self.blocked_ports = set()

    def suggest_block_ip(self, ip):
        self.blocked_ips.add(ip)

    def suggest_block_port(self, port):
        self.blocked_ports.add(port)

    def summary(self):
        return {
            "blocked_ips_suggested": list(self.blocked_ips),
            "blocked_ports_suggested": list(self.blocked_ports),
        }

# =========================
# MITRE ATT&CK mapping (simplified)
# =========================

MITRE_MAP = {
    "ET POLICY Outbound Windows executable transfer": "T1105 - Ingress Tool Transfer",
    "ET TROJAN": "T1204 - User Execution",
    "ET SCAN": "T1046 - Network Service Scanning",
    "ET DOS": "T1499 - Endpoint Denial of Service",
    "ET CNC": "T1071 - Application Layer Protocol",
    "ET EXPLOIT": "T1068 - Exploitation for Privilege Escalation",
}

def map_suricata_to_mitre(evt):
    sig = evt.get("alert", {}).get("signature", "")
    for key, tactic in MITRE_MAP.items():
        if key in sig:
            return tactic
    return "Unknown"

# =========================
# GPU Deep Learning Threat Scorer (extended stub)
# =========================

class ThreatScorer:
    def __init__(self):
        self.gpu = GPU_AVAILABLE
        self.model = None
        self._load_model()

    def _load_model(self):
        if torch is not None:
            self.model = "codex_dummy_model_v4_6"
        else:
            self.model = None

    def score_process(self, proc_info, conn_count, resurrected=False):
        base = 0.0
        cpu = proc_info.get("cpu_percent", 0.0)
        name = (proc_info.get("name") or "").lower()

        if "powershell" in name or "cmd.exe" in name:
            base += 0.3
        if "python" in name or "node" in name:
            base += 0.2
        if conn_count > 20:
            base += 0.4
        if cpu > 50:
            base += 0.3
        if resurrected:
            base += 0.3

        suspicious_keywords = ["rat", "miner", "keylogger", "c2", "remote", "hack", "shell"]
        if any(k in name for k in suspicious_keywords):
            base += 0.4

        if self.gpu and self.model is not None:
            base = min(1.0, base + 0.2)

        return min(1.0, base)

    def score_suricata_event(self, evt):
        sig = evt.get("alert", {}).get("signature", "").lower()
        severity = evt.get("alert", {}).get("severity", 1)
        base = 0.1 * severity

        if "trojan" in sig or "malware" in sig:
            base += 0.5
        if "scan" in sig:
            base += 0.3
        if "cnc" in sig or "command and control" in sig:
            base += 0.6
        if "exploit" in sig or "overflow" in sig:
            base += 0.5
        if "dos" in sig:
            base += 0.4

        if self.gpu and self.model is not None:
            base = min(1.0, base + 0.2)

        return min(1.0, base)

# =========================
# Honeypot emulation (logical only, multi-protocol tags)
# =========================

class HoneypotSession:
    def __init__(self, src_ip, src_port, protocol="logical"):
        self.src_ip = src_ip
        self.src_port = src_port
        self.protocol = protocol
        self.commands = []
        self.start_time = time.time()

    def record_command(self, cmd):
        self.commands.append({
            "cmd": cmd,
            "timestamp": time.time()
        })

    def summary(self):
        return {
            "src_ip": self.src_ip,
            "src_port": self.src_port,
            "protocol": self.protocol,
            "command_count": len(self.commands),
            "duration": time.time() - self.start_time,
            "commands": self.commands,
        }

class HoneypotManager:
    def __init__(self):
        self.sessions = {}
        self.lock = threading.Lock()

    def start_session(self, key, src_ip, src_port, protocol="logical"):
        with self.lock:
            self.sessions[key] = HoneypotSession(src_ip, src_port, protocol=protocol)

    def record_command(self, key, cmd):
        with self.lock:
            sess = self.sessions.get(key)
            if sess:
                sess.record_command(cmd)

    def end_session(self, key):
        with self.lock:
            sess = self.sessions.pop(key, None)
        if sess:
            return sess.summary()
        return None

# =========================
# Agentic reasoning engine (defensive, suggestion-only, extended actions + timeline)
# =========================

class AgenticReasoner:
    def __init__(self, scorer, ndis_plane, timeline_callback=None):
        self.scorer = scorer
        self.ndis = ndis_plane
        self.decisions = []
        self.timeline_callback = timeline_callback

    def _record_timeline(self, entry):
        if self.timeline_callback:
            self.timeline_callback(entry)

    def evaluate_process(self, proc_info, conn_count, resurrected=False):
        score = self.scorer.score_process(proc_info, conn_count, resurrected=resurrected)
        action = "observe"
        remediation = []

        if score > 0.9:
            action = "snapshot_and_suggest_kill_and_quarantine"
            remediation = ["suggest_kill_process", "suggest_quarantine_files"]
        elif score > 0.8:
            action = "snapshot_and_suggest_kill"
            remediation = ["suggest_kill_process"]
        elif score > 0.7:
            action = "snapshot_and_suggest_investigate"
            remediation = ["suggest_investigate"]
        elif score > 0.5:
            action = "log"

        decision = {
            "type": "process",
            "pid": proc_info.get("pid"),
            "name": proc_info.get("name"),
            "score": score,
            "conn_count": conn_count,
            "resurrected": resurrected,
            "action": action,
            "remediation": remediation,
            "timestamp": time.time(),
        }
        self.decisions.append(decision)
        self._record_timeline({
            "kind": "process",
            "name": proc_info.get("name"),
            "pid": proc_info.get("pid"),
            "score": score,
            "action": action,
            "time": time.time(),
        })
        return decision

    def evaluate_suricata_event(self, evt):
        score = self.scorer.score_suricata_event(evt)
        mitre = map_suricata_to_mitre(evt)
        action = "observe"
        remediation = []

        if score > 0.9:
            action = "snapshot_and_suggest_block_and_isolate"
            remediation = ["suggest_block_ip", "suggest_isolate_host"]
        elif score > 0.8:
            action = "snapshot_and_suggest_block"
            remediation = ["suggest_block_ip"]
        elif score > 0.7:
            action = "snapshot_and_suggest_investigate"
            remediation = ["suggest_investigate"]
        elif score > 0.5:
            action = "log"

        decision = {
            "type": "suricata",
            "signature": evt.get("alert", {}).get("signature"),
            "severity": evt.get("alert", {}).get("severity"),
            "score": score,
            "mitre": mitre,
            "action": action,
            "remediation": remediation,
            "timestamp": time.time(),
        }
        self.decisions.append(decision)
        self._record_timeline({
            "kind": "suricata",
            "signature": evt.get("alert", {}).get("signature"),
            "score": score,
            "mitre": mitre,
            "action": action,
            "time": time.time(),
        })
        return decision

    def evaluate_honeypot_summary(self, summary):
        cmd_count = summary.get("command_count", 0)
        duration = summary.get("duration", 0.0)
        base = 0.2
        if cmd_count > 10:
            base += 0.4
        if duration > 300:
            base += 0.2

        action = "log"
        remediation = []
        if base > 0.7:
            action = "snapshot_and_flag_source"
            remediation = ["suggest_block_ip"]

        decision = {
            "type": "honeypot",
            "src_ip": summary.get("src_ip"),
            "cmd_count": cmd_count,
            "duration": duration,
            "score": base,
            "action": action,
            "remediation": remediation,
            "timestamp": time.time(),
        }
        self.decisions.append(decision)
        self._record_timeline({
            "kind": "honeypot",
            "src_ip": summary.get("src_ip"),
            "score": base,
            "action": action,
            "time": time.time(),
        })
        return decision

# =========================
# Swarm sync (logical node state exchange stub + peer simulation)
# =========================

class SwarmSyncManager:
    def __init__(self, node_id="node-local"):
        self.node_id = node_id
        self.peers = {}
        self.local_state = {
            "threat_scores": [],
            "snapshots": [],
            "signatures": [],
            "persona": "Sentinel",
        }

    def update_local_state(self, threat_scores=None, snapshots=None, signatures=None, persona=None):
        if threat_scores is not None:
            self.local_state["threat_scores"] = threat_scores
        if snapshots is not None:
            self.local_state["snapshots"] = snapshots
        if signatures is not None:
            self.local_state["signatures"] = signatures
        if persona is not None:
            self.local_state["persona"] = persona

        self._simulate_peers()

    def _simulate_peers(self):
        self.peers = {
            "node-alpha": {
                "threat_scores": [random.uniform(0, 1) for _ in range(5)],
                "snapshots": ["alpha_snap_1", "alpha_snap_2"],
                "signatures": ["ET TROJAN", "ET SCAN"],
                "persona": "Watcher",
            },
            "node-beta": {
                "threat_scores": [random.uniform(0, 1) for _ in range(3)],
                "snapshots": ["beta_snap_1"],
                "signatures": ["ET CNC"],
                "persona": "Guardian",
            },
        }

    def get_swarm_view(self):
        return {
            "self": {self.node_id: self.local_state},
            "peers": self.peers,
        }

# =========================
# Event bus (internal)
# =========================

class EventBus:
    def __init__(self):
        self.subscribers = []

    def subscribe(self, fn):
        self.subscribers.append(fn)

    def publish(self, event_type, payload):
        evt = {
            "type": event_type,
            "payload": payload,
            "timestamp": time.time(),
        }
        for fn in self.subscribers:
            try:
                fn(evt)
            except Exception:
                pass

# =========================
# Windows Adjustment Engine (safe subset)
# =========================

class WindowsAdjustmentEngine:
    def __init__(self, log_fn):
        self.log = log_fn

    def add_firewall_rule(self, name, direction, action, proto, port):
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}",
                f"dir={direction}",
                f"action={action}",
                f"protocol={proto}",
                f"localport={port}",
            ]
            subprocess.call(cmd)
            self.log(f"[Firewall] Rule added: {name} ({direction}, {action}, {proto}, {port})")
        except Exception:
            self.log("[Firewall] Failed to add rule.")

    def delete_firewall_rule(self, name):
        try:
            subprocess.call(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
            self.log(f"[Firewall] Rule deleted: {name}")
        except Exception:
            self.log("[Firewall] Failed to delete rule.")

    def list_services(self):
        out = safe_call_powershell("Get-Service | Select-Object Name,Status,StartType | ConvertTo-Json")
        try:
            return json.loads(out)
        except Exception:
            return []

    def change_service_status(self, name, action):
        if action not in ("Start", "Stop", "Restart"):
            self.log(f"[Service] Invalid action: {action}")
            return
        ps = f"{action}-Service -Name '{name}'"
        safe_call_powershell(ps)
        self.log(f"[Service] {action} requested for: {name}")

    def change_service_start_type(self, name, start_type):
        if start_type not in ("Automatic", "Manual", "Disabled"):
            self.log(f"[Service] Invalid start type: {start_type}")
            return
        ps = f"Set-Service -Name '{name}' -StartupType {start_type}"
        safe_call_powershell(ps)
        self.log(f"[Service] StartupType={start_type} requested for: {name}")

    def list_tasks(self):
        out = safe_call_powershell("Get-ScheduledTask | Select-Object TaskName,State | ConvertTo-Json")
        try:
            return json.loads(out)
        except Exception:
            return []

    def change_task_state(self, name, enable=True):
        ps = f"Enable-ScheduledTask -TaskName '{name}'" if enable else f"Disable-ScheduledTask -TaskName '{name}'"
        safe_call_powershell(ps)
        self.log(f"[Task] {'Enable' if enable else 'Disable'} requested for: {name}")

    def toggle_defender_realtime(self, enable=True):
        ps = f"Set-MpPreference -DisableRealtimeMonitoring {( '0' if enable else '1')}"
        safe_call_powershell(ps)
        self.log(f"[Defender] Real-time protection {'enabled' if enable else 'disabled'} (requested).")

    def list_network_adapters(self):
        out = safe_call_powershell("Get-NetAdapter | Select-Object Name,Status | ConvertTo-Json")
        try:
            return json.loads(out)
        except Exception:
            return []

    def change_adapter_status(self, name, enable=True):
        ps = f"Enable-NetAdapter -Name '{name}' -Confirm:$false" if enable else f"Disable-NetAdapter -Name '{name}' -Confirm:$false"
        safe_call_powershell(ps)
        self.log(f"[Network] {'Enable' if enable else 'Disable'} requested for adapter: {name}")

    def list_power_plans(self):
        out = safe_call_powershell("powercfg /L")
        self.log("[Power] powercfg /L output:\n" + out)
        return out

    def set_power_plan(self, guid):
        ps = f"powercfg /S {guid}"
        safe_call_powershell(ps)
        self.log(f"[Power] Power plan switch requested: {guid}")

    def pause_updates(self):
        ps = "Set-Service -Name wuauserv -StartupType Manual; Stop-Service wuauserv"
        safe_call_powershell(ps)
        self.log("[Update] Pause updates requested (wuauserv stop/manual).")

    def resume_updates(self):
        ps = "Set-Service -Name wuauserv -StartupType Automatic; Start-Service wuauserv"
        safe_call_powershell(ps)
        self.log("[Update] Resume updates requested (wuauserv auto/start).")

    def get_system_info(self):
        info = {
            "hostname": platform.node(),
            "platform": platform.platform(),
            "version": platform.version(),
            "architecture": platform.machine(),
        }
        return info

# =========================
# Animated overlays / swarm
# =========================

class OverlayCanvas:
    def __init__(self, canvas):
        self.canvas = canvas
        self.width = int(canvas["width"])
        self.height = int(canvas["height"])
        self.objects = []
        self._init_objects()
        self.running = True
        self.animate()

    def _init_objects(self):
        for _ in range(20):
            x = random.randint(0, self.width)
            y = random.randint(0, self.height)
            r = random.randint(2, 6)
            dx = random.uniform(-1.5, 1.5)
            dy = random.uniform(-1.5, 1.5)
            oid = self.canvas.create_oval(x-r, y-r, x+r, y+r, outline="#00ffcc")
            self.objects.append({"id": oid, "x": x, "y": y, "dx": dx, "dy": dy, "r": r})

    def animate(self):
        if not self.running:
            return
        for obj in self.objects:
            obj["x"] += obj["dx"]
            obj["y"] += obj["dy"]
            if obj["x"] < 0 or obj["x"] > self.width:
                obj["dx"] *= -1
            if obj["y"] < 0 or obj["y"] > self.height:
                obj["dy"] *= -1
            r = obj["r"]
            self.canvas.coords(obj["id"], obj["x"]-r, obj["y"]-r, obj["x"]+r, obj["y"]+r)
        self.canvas.after(50, self.animate)

class SwarmCanvas:
    def __init__(self, canvas, node_count=12):
        self.canvas = canvas
        self.width = int(canvas["width"])
        self.height = int(canvas["height"])
        self.nodes = []
        self.lines = []
        self.node_count = node_count
        self._init_nodes()
        self.running = True
        self.animate()

    def _init_nodes(self):
        center_x = self.width // 2
        center_y = self.height // 2
        radius = min(self.width, self.height) // 3
        for i in range(self.node_count):
            angle = 2 * math.pi * i / self.node_count
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            oid = self.canvas.create_oval(x-6, y-6, x+6, y+6, fill="#ff0066")
            self.nodes.append({"id": oid, "x": x, "y": y, "angle": angle})
        for i in range(self.node_count):
            j = (i + 1) % self.node_count
            l = self.canvas.create_line(
                self.nodes[i]["x"], self.nodes[i]["y"],
                self.nodes[j]["x"], self.nodes[j]["y"],
                fill="#4444ff"
            )
            self.lines.append(l)

    def animate(self):
        if not self.running:
            return
        center_x = self.width // 2
        center_y = self.height // 2
        radius = min(self.width, self.height) // 3
        for idx, node in enumerate(self.nodes):
            node["angle"] += 0.01
            x = center_x + radius * math.cos(node["angle"])
            y = center_y + radius * math.sin(node["angle"])
            node["x"], node["y"] = x, y
            self.canvas.coords(node["id"], x-6, y-6, x+6, y+6)
        for i, line in enumerate(self.lines):
            j = (i + 1) % self.node_count
            self.canvas.coords(
                line,
                self.nodes[i]["x"], self.nodes[i]["y"],
                self.nodes[j]["x"], self.nodes[j]["y"]
            )
        self.canvas.after(60, self.animate)

# =========================
# Settings editor (registry + firewall)
# =========================

class SettingsEditorPanel:
    def __init__(self, parent, log_fn, adjustment_engine):
        self.parent = parent
        self.log = log_fn
        self.engine = adjustment_engine

        frame = ttk.LabelFrame(parent, text="System Settings Editor (Win11)")
        frame.pack(fill="both", expand=True, padx=5, pady=5)

        top = ttk.Frame(frame)
        top.pack(fill="x", pady=2)

        ttk.Label(top, text="Registry Path (HKLM\\... or HKCU\\...)").pack(side="left", padx=5)
        self.reg_path_var = tk.StringVar(value=DEFAULT_REG_PATH)
        self.reg_entry = ttk.Entry(top, textvariable=self.reg_path_var, width=70)
        self.reg_entry.pack(side="left", padx=5)
        ttk.Button(top, text="Load", command=self.load_registry).pack(side="left", padx=5)

        mid = ttk.Frame(frame)
        mid.pack(fill="both", expand=True, pady=2)

        self.reg_list = ttk.Treeview(mid, columns=("name", "value"), show="headings", height=8)
        self.reg_list.heading("name", text="Name")
        self.reg_list.heading("value", text="Value")
        self.reg_list.column("name", width=150)
        self.reg_list.column("value", width=300)
        self.reg_list.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        reg_scroll = ttk.Scrollbar(mid, orient="vertical", command=self.reg_list.yview)
        self.reg_list.configure(yscrollcommand=reg_scroll.set)
        reg_scroll.pack(side="right", fill="y")

        reg_btns = ttk.Frame(mid)
        reg_btns.pack(side="left", fill="y", padx=5)

        ttk.Button(reg_btns, text="Add/Edit", command=self.edit_registry_value).pack(fill="x", pady=2)
        ttk.Button(reg_btns, text="Delete", command=self.delete_registry_value).pack(fill="x", pady=2)

        fw_frame = ttk.LabelFrame(frame, text="Firewall Rule Editor")
        fw_frame.pack(fill="x", pady=5)

        ttk.Label(fw_frame, text="Rule Name").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        ttk.Label(fw_frame, text="Direction (in/out)").grid(row=0, column=1, padx=5, pady=2, sticky="w")
        ttk.Label(fw_frame, text="Action (allow/block)").grid(row=0, column=2, padx=5, pady=2, sticky="w")
        ttk.Label(fw_frame, text="Protocol").grid(row=0, column=3, padx=5, pady=2, sticky="w")
        ttk.Label(fw_frame, text="Local Port").grid(row=0, column=4, padx=5, pady=2, sticky="w")

        self.fw_name = tk.StringVar()
        self.fw_dir = tk.StringVar(value="in")
        self.fw_action = tk.StringVar(value="allow")
        self.fw_proto = tk.StringVar(value="TCP")
        self.fw_port = tk.StringVar(value="any")

        ttk.Entry(fw_frame, textvariable=self.fw_name, width=15).grid(row=1, column=0, padx=5, pady=2)
        ttk.Entry(fw_frame, textvariable=self.fw_dir, width=8).grid(row=1, column=1, padx=5, pady=2)
        ttk.Entry(fw_frame, textvariable=self.fw_action, width=8).grid(row=1, column=2, padx=5, pady=2)
        ttk.Entry(fw_frame, textvariable=self.fw_proto, width=8).grid(row=1, column=3, padx=5, pady=2)
        ttk.Entry(fw_frame, textvariable=self.fw_port, width=8).grid(row=1, column=4, padx=5, pady=2)

        ttk.Button(fw_frame, text="Add Rule", command=self.add_rule).grid(row=1, column=5, padx=5, pady=2)
        ttk.Button(fw_frame, text="Delete Rule", command=self.delete_rule).grid(row=1, column=6, padx=5, pady=2)

    def load_registry(self):
        path = self.reg_path_var.get().strip()
        self.reg_list.delete(*self.reg_list.get_children())
        values = read_registry_key(path)
        for name, value in values:
            self.reg_list.insert("", "end", values=(name, str(value)))
        self.log(f"Loaded registry key: {path}")

    def edit_registry_value(self):
        path = self.reg_path_var.get().strip()
        sel = self.reg_list.selection()
        if sel:
            name = self.reg_list.item(sel[0], "values")[0]
            value = self.reg_list.item(sel[0], "values")[1]
        else:
            name = ""
            value = ""

        edit_win = tk.Toplevel(self.parent)
        edit_win.title("Edit Registry Value")

        ttk.Label(edit_win, text="Name").pack(padx=5, pady=2)
        name_var = tk.StringVar(value=name)
        ttk.Entry(edit_win, textvariable=name_var, width=40).pack(padx=5, pady=2)

        ttk.Label(edit_win, text="Value").pack(padx=5, pady=2)
        value_var = tk.StringVar(value=value)
        ttk.Entry(edit_win, textvariable=value_var, width=40).pack(padx=5, pady=2)

        def apply():
            n = name_var.get().strip()
            v = value_var.get()
            if not n:
                messagebox.showerror("Error", "Name cannot be empty.")
                return
            try:
                hive, subkey = path.split("\\", 1)
                hive_map = {
                    "HKLM": winreg.HKEY_LOCAL_MACHINE,
                    "HKCU": winreg.HKEY_CURRENT_USER
                }
                key = winreg.CreateKey(hive_map[hive], subkey)
                winreg.SetValueEx(key, n, 0, winreg.REG_SZ, v)
                self.log(f"Registry value set: {path}\\{n} = {v}")
                self.load_registry()
                edit_win.destroy()
            except Exception:
                messagebox.showerror("Error", "Failed to write registry value.")

        ttk.Button(edit_win, text="Apply", command=apply).pack(padx=5, pady=5)

    def delete_registry_value(self):
        path = self.reg_path_var.get().strip()
        sel = self.reg_list.selection()
        if not sel:
            messagebox.showinfo("Delete", "No value selected.")
            return
        name = self.reg_list.item(sel[0], "values")[0]
        try:
            hive, subkey = path.split("\\", 1)
            hive_map = {
                "HKLM": winreg.HKEY_LOCAL_MACHINE,
                "HKCU": winreg.HKEY_CURRENT_USER
            }
            key = winreg.OpenKey(hive_map[hive], subkey, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            self.log(f"Registry value deleted: {path}\\{name}")
            self.load_registry()
        except Exception:
            messagebox.showerror("Error", "Failed to delete registry value.")

    def add_rule(self):
        name = self.fw_name.get().strip()
        direction = self.fw_dir.get().strip()
        action = self.fw_action.get().strip()
        proto = self.fw_proto.get().strip()
        port = self.fw_port.get().strip()
        if not name:
            messagebox.showerror("Error", "Rule name required.")
            return
        self.engine.add_firewall_rule(name, direction, action, proto, port)

    def delete_rule(self):
        name = self.fw_name.get().strip()
        if not name:
            messagebox.showerror("Error", "Rule name required.")
            return
        self.engine.delete_firewall_rule(name)

# =========================
# GUI Watchdog
# =========================

class GUIWatchdog:
    def __init__(self, app, log_fn):
        self.app = app
        self.log = log_fn
        self.manifest = {}
        self.running = True
        self._build_manifest()
        self._start()

    def _build_manifest(self):
        self._register("override_button", self.app.override_button)
        self._register("status_fw", self.app.status_fw)
        self._register("status_profiles", self.app.status_profiles)
        self._register("status_reg", self.app.status_reg)
        self._register("status_suricata", self.app.status_suricata)
        self._register("alert_box", self.app.alert_box)
        self._register("snapshot_combo", self.app.snapshot_combo)
        self._register("threat_tree", self.app.threat_tree)
        self._register("editor_reg_list", self.app.editor_panel.reg_list)
        self._register("timeline_text", self.app.timeline_text)

    def _register(self, name, widget):
        self.manifest[name] = {"widget": widget}

    def _start(self):
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def _loop(self):
        while self.running:
            self._check_widgets()
            time.sleep(1)

    def _check_widgets(self):
        for name, info in self.manifest.items():
            w = info["widget"]
            try:
                exists = bool(w.winfo_exists())
                visible = bool(w.winfo_ismapped())
                if not exists or not visible:
                    self._handle_violation(name, w, exists, visible)
            except Exception:
                self._handle_violation(name, w, False, False)

    def _handle_violation(self, name, widget, exists, visible):
        self.log(f"⚠ GUI integrity issue: {name} (exists={exists}, visible={visible})")
        meta = {"summary": f"GUI integrity issue on {name}"}
        self.app.request_snapshot(meta, reason="gui_watchdog")
        try:
            widget.pack()
        except Exception:
            pass
        try:
            widget.configure(foreground="red")
        except Exception:
            pass

# =========================
# Main GUI / Codex Purge Shell v4.6
# =========================

class CodexSettingsGuard:
    def __init__(self, root):
        self.root = root
        self.root.title("Codex Purge Shell v4.6 (Safe Edition) — Win11 Security Bridge & Adjustment Console")
        self.root.geometry("1500x900")

        self.auto_block_enabled = True

        self.event_bus = EventBus()
        self.suricata_ingestor = SuricataEventIngestor()
        self.ndis_plane = NDISControlPlane()
        self.timeline_entries = []
        self.threat_scorer = ThreatScorer()
        self.agent = AgenticReasoner(self.threat_scorer, self.ndis_plane, timeline_callback=self._add_timeline_entry)
        self.honeypot = HoneypotManager()
        self.adjustment_engine = WindowsAdjustmentEngine(self.log_alert)
        self.swarm_sync = SwarmSyncManager(node_id="node-local")
        self.event_bus.subscribe(self._on_event_bus)

        self.process_seen = {}
        self.persona = "Sentinel"

        self.baseline_fw = None
        self.baseline_profiles = None
        self.baseline_settings = None
        self.last_snapshot_time = 0
        self.snapshot_cooldown = 3600  # 1 hour
        self.suricata_snapshot_enabled = False
        self.update_snapshot_enabled = False

        self.fw_change_counter = 0
        self.prof_change_counter = 0
        self.set_change_counter = 0
        self.persistence_threshold = 6  # 6 * 10s ~ 1 minute

        self._build_ui()
        self._start_monitoring()
        self._start_threat_matrix_refresh()
        self._start_suricata_loop()

        self.watchdog = GUIWatchdog(self, self.log_alert)

    # ---- Snapshot request wrapper (cooldown enforced) ----

    def request_snapshot(self, meta, reason="generic"):
        now = time.time()
        if now - self.last_snapshot_time < self.snapshot_cooldown:
            self.log_alert(f"[Cooldown] Snapshot skipped (reason={reason}, cooldown active).")
            return None

        baseline_hashes = {
            "fw": self.baseline_fw,
            "profiles": self.baseline_profiles,
            "settings": self.baseline_settings,
        }
        current_hashes = {
            "fw": hash_state(get_firewall_state()),
            "profiles": hash_state(get_profiles_state()),
            "settings": hash_state(get_settings_state()),
        }

        snap = create_snapshot(meta, baseline_hashes=baseline_hashes, current_hashes=current_hashes)
        self.last_snapshot_time = now
        self.log_alert(f"[Snapshot] Snapshot created (reason={reason}): {snap}")
        self.refresh_snapshots()
        self._update_swarm_state()
        return snap

    # ---- UI ----

    def _build_ui(self):
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True)

        top_frame = ttk.Frame(main)
        top_frame.pack(fill="x", pady=5)

        title = ttk.Label(
            top_frame,
            text="Codex Purge Shell v4.6 (Safe Edition) — Windows 11 Security Bridge & Adjustment Console",
            font=("Arial", 16)
        )
        title.pack(side="left", padx=10)

        self.override_button = ttk.Button(
            top_frame,
            text="Manual Override: ENABLED",
            command=self.toggle_override
        )
        self.override_button.pack(side="right", padx=10)

        status_frame = ttk.Frame(main)
        status_frame.pack(fill="x", pady=5)

        self.status_fw = ttk.Label(status_frame, text="Firewall: NORMAL", foreground="green")
        self.status_fw.pack(side="left", padx=10)

        self.status_profiles = ttk.Label(status_frame, text="Profiles: NORMAL", foreground="green")
        self.status_profiles.pack(side="left", padx=10)

        self.status_reg = ttk.Label(status_frame, text="Settings Store: NORMAL", foreground="green")
        self.status_reg.pack(side="left", padx=10)

        self.status_suricata = ttk.Label(status_frame, text="Suricata: IDLE", foreground="cyan")
        self.status_suricata.pack(side="left", padx=10)

        self.persona_label = ttk.Label(status_frame, text=f"Persona: {self.persona}", foreground="white")
        self.persona_label.pack(side="left", padx=10)

        snapshot_frame = ttk.Frame(main)
        snapshot_frame.pack(fill="x", pady=5)

        self.snapshot_var = tk.StringVar()
        self.snapshot_combo = ttk.Combobox(snapshot_frame, textvariable=self.snapshot_var, width=60)
        self.snapshot_combo.pack(side="left", padx=10)
        self.refresh_snapshots()

        restore_btn = ttk.Button(snapshot_frame, text="Restore Selected Snapshot", command=self.restore_selected_snapshot)
        restore_btn.pack(side="left", padx=10)

        gpo_frame = ttk.Frame(snapshot_frame)
        gpo_frame.pack(side="right", padx=10)
        self.gpo_button = ttk.Button(gpo_frame, text="Apply Telemetry/GPO Suppression", command=self._apply_gpo_telemetry)
        self.gpo_button.pack(side="right", padx=5)

        toggle_frame = ttk.Frame(snapshot_frame)
        toggle_frame.pack(fill="x", pady=5)

        self.sur_snap_var = tk.BooleanVar(value=self.suricata_snapshot_enabled)
        self.update_snap_var = tk.BooleanVar(value=self.update_snapshot_enabled)

        ttk.Checkbutton(
            toggle_frame,
            text="Allow Suricata-driven snapshots",
            variable=self.sur_snap_var,
            command=self._toggle_suricata_snapshots
        ).pack(side="left", padx=5)

        ttk.Checkbutton(
            toggle_frame,
            text="Allow Windows Update-driven snapshots",
            variable=self.update_snap_var,
            command=self._toggle_update_snapshots
        ).pack(side="left", padx=5)

        center_frame = ttk.Frame(main)
        center_frame.pack(fill="both", expand=True, pady=5)

        left_notebook = ttk.Notebook(center_frame)
        left_notebook.pack(side="left", fill="both", expand=True)

        right_notebook = ttk.Notebook(center_frame)
        right_notebook.pack(side="right", fill="both", expand=True)

        # Left notebook: Alerts, Registry/Firewall, Adjustments, Threat Timeline
        alerts_tab = ttk.Frame(left_notebook)
        left_notebook.add(alerts_tab, text="Alerts")

        self.alert_box = tk.Text(alerts_tab, height=10, width=80, bg="#1e1e1e", fg="#00ff00")
        self.alert_box.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_alert("Codex Purge Shell v4.6 (Safe Edition) started with threat timeline, extended scoring, and swarm peer simulation.")

        editor_tab = ttk.Frame(left_notebook)
        left_notebook.add(editor_tab, text="Registry & Firewall")

        self.editor_panel = SettingsEditorPanel(editor_tab, self.log_alert, self.adjustment_engine)

        adjust_tab = ttk.Frame(left_notebook)
        left_notebook.add(adjust_tab, text="Windows Adjustments")

        adj_notebook = ttk.Notebook(adjust_tab)
        adj_notebook.pack(fill="both", expand=True, padx=5, pady=5)

        self._build_services_tab(adj_notebook)
        self._build_tasks_tab(adj_notebook)
        self._build_defender_tab(adj_notebook)
        self._build_network_tab(adj_notebook)
        self._build_power_tab(adj_notebook)
        self._build_update_tab(adj_notebook)
        self._build_sysinfo_tab(adj_notebook)

        timeline_tab = ttk.Frame(left_notebook)
        left_notebook.add(timeline_tab, text="Threat Timeline")

        self.timeline_text = tk.Text(timeline_tab, height=12, width=80, bg="#101010", fg="#ffcc00")
        self.timeline_text.pack(fill="both", expand=True, padx=5, pady=5)

        # Right notebook: Threat Matrix, Suricata, Overlays, Honeypot, Event Bus, Swarm View
        threat_tab = ttk.Frame(right_notebook)
        right_notebook.add(threat_tab, text="Threat Matrix")

        self.threat_tree = ttk.Treeview(
            threat_tab,
            columns=("pid", "name", "cpu", "conns", "score", "action", "resurrected"),
            show="headings",
            height=15
        )
        self.threat_tree.heading("pid", text="PID")
        self.threat_tree.heading("name", text="Name")
        self.threat_tree.heading("cpu", text="CPU%")
        self.threat_tree.heading("conns", text="Connections")
        self.threat_tree.heading("score", text="Score")
        self.threat_tree.heading("action", text="Agent Action")
        self.threat_tree.heading("resurrected", text="Resurrected")
        self.threat_tree.column("pid", width=60)
        self.threat_tree.column("name", width=160)
        self.threat_tree.column("cpu", width=60)
        self.threat_tree.column("conns", width=90)
        self.threat_tree.column("score", width=70)
        self.threat_tree.column("action", width=160)
        self.threat_tree.column("resurrected", width=90)
        self.threat_tree.pack(fill="both", expand=True, padx=5, pady=5)

        threat_scroll = ttk.Scrollbar(threat_tab, orient="vertical", command=self.threat_tree.yview)
        self.threat_tree.configure(yscrollcommand=threat_scroll.set)
        threat_scroll.pack(side="right", fill="y")

        sur_tab = ttk.Frame(right_notebook)
        right_notebook.add(sur_tab, text="Suricata Events")

        self.sur_list = ttk.Treeview(
            sur_tab,
            columns=("sig", "sev", "mitre", "score", "action"),
            show="headings",
            height=8
        )
        self.sur_list.heading("sig", text="Signature")
        self.sur_list.heading("sev", text="Severity")
        self.sur_list.heading("mitre", text="MITRE")
        self.sur_list.heading("score", text="Score")
        self.sur_list.heading("action", text="Agent Action")
        self.sur_list.column("sig", width=300)
        self.sur_list.column("sev", width=60)
        self.sur_list.column("mitre", width=160)
        self.sur_list.column("score", width=60)
        self.sur_list.column("action", width=160)
        self.sur_list.pack(fill="both", expand=True, padx=5, pady=5)

        sur_scroll = ttk.Scrollbar(sur_tab, orient="vertical", command=self.sur_list.yview)
        self.sur_list.configure(yscrollcommand=sur_scroll.set)
        sur_scroll.pack(side="right", fill="y")

        overlay_tab = ttk.Frame(right_notebook)
        right_notebook.add(overlay_tab, text="Overlays")

        overlay_canvas = tk.Canvas(overlay_tab, width=350, height=120, bg="#000000", highlightthickness=0)
        overlay_canvas.pack(padx=5, pady=5)
        self.overlay = OverlayCanvas(overlay_canvas)

        swarm_canvas = tk.Canvas(overlay_tab, width=350, height=160, bg="#050515", highlightthickness=0)
        swarm_canvas.pack(padx=5, pady=5)
        self.swarm = SwarmCanvas(swarm_canvas, node_count=10)

        honeypot_tab = ttk.Frame(right_notebook)
        right_notebook.add(honeypot_tab, text="Honeypot Sessions")

        self.honeypot_text = tk.Text(honeypot_tab, height=10, width=80)
        self.honeypot_text.pack(fill="both", expand=True, padx=5, pady=5)

        event_tab = ttk.Frame(right_notebook)
        right_notebook.add(event_tab, text="Event Bus Log")

        self.event_log = tk.Text(event_tab, height=10, width=80)
        self.event_log.pack(fill="both", expand=True, padx=5, pady=5)

        swarm_view_tab = ttk.Frame(right_notebook)
        right_notebook.add(swarm_view_tab, text="Swarm View")

        self.swarm_view_text = tk.Text(swarm_view_tab, height=10, width=80)
        self.swarm_view_text.pack(fill="both", expand=True, padx=5, pady=5)
        self._update_swarm_view()

        filter_frame = ttk.Frame(sur_tab)
        filter_frame.pack(fill="x", pady=5)
        ttk.Label(filter_frame, text="Country Filter (logical):").pack(side="left", padx=5)
        self.country_var = tk.StringVar(value="Any")
        self.country_combo = ttk.Combobox(filter_frame, textvariable=self.country_var, values=["Any", "US", "EU", "APAC"], width=10)
        self.country_combo.pack(side="left", padx=5)

    # ---- Timeline ----

    def _add_timeline_entry(self, entry):
        self.timeline_entries.append(entry)
        ts = time.strftime("%H:%M:%S", time.localtime(entry["time"]))
        if entry["kind"] == "process":
            line = f"[{ts}] PROC {entry['name']} (PID={entry['pid']}) score={entry['score']:.2f} action={entry['action']}\n"
        elif entry["kind"] == "suricata":
            line = f"[{ts}] SUR {entry['signature']} score={entry['score']:.2f} mitre={entry['mitre']} action={entry['action']}\n"
        elif entry["kind"] == "honeypot":
            line = f"[{ts}] HONEYPOT src={entry['src_ip']} score={entry['score']:.2f} action={entry['action']}\n"
        else:
            line = f"[{ts}] {entry}\n"
        self.timeline_text.insert(tk.END, line)
        self.timeline_text.see(tk.END)

    # ---- Snapshot toggles ----

    def _toggle_suricata_snapshots(self):
        self.suricata_snapshot_enabled = self.sur_snap_var.get()
        self.log_alert(f"[Config] Suricata-driven snapshots {'ENABLED' if self.suricata_snapshot_enabled else 'DISABLED'}.")

    def _toggle_update_snapshots(self):
        self.update_snapshot_enabled = self.update_snap_var.get()
        self.log_alert(f"[Config] Windows Update-driven snapshots {'ENABLED' if self.update_snapshot_enabled else 'DISABLED'}.")

    # ---- Adjustment tabs ----

    def _build_services_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Services")

        self.services_tree = ttk.Treeview(frame, columns=("name", "status", "starttype"), show="headings", height=10)
        self.services_tree.heading("name", text="Name")
        self.services_tree.heading("status", text="Status")
        self.services_tree.heading("starttype", text="StartType")
        self.services_tree.column("name", width=200)
        self.services_tree.column("status", width=80)
        self.services_tree.column("starttype", width=100)
        self.services_tree.pack(fill="both", expand=True, padx=5, pady=5)

        svc_scroll = ttk.Scrollbar(frame, orient="vertical", command=self.services_tree.yview)
        self.services_tree.configure(yscrollcommand=svc_scroll.set)
        svc_scroll.pack(side="right", fill="y")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="Refresh", command=self._refresh_services).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Start", command=lambda: self._service_action("Start")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Stop", command=lambda: self._service_action("Stop")).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Restart", command=lambda: self._service_action("Restart")).pack(side="left", padx=5)

        ttk.Label(btn_frame, text="StartupType:").pack(side="left", padx=5)
        self.service_starttype_var = tk.StringVar(value="Manual")
        starttype_combo = ttk.Combobox(btn_frame, textvariable=self.service_starttype_var, values=["Automatic", "Manual", "Disabled"], width=10)
        starttype_combo.pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Apply StartupType", command=self._service_change_starttype).pack(side="left", padx=5)

        self._refresh_services()

    def _refresh_services(self):
        self.services_tree.delete(*self.services_tree.get_children())
        services = self.adjustment_engine.list_services()
        if isinstance(services, dict):
            services = [services]
        for svc in services:
            name = svc.get("Name")
            status = svc.get("Status")
            starttype = svc.get("StartType")
            self.services_tree.insert("", "end", values=(name, status, starttype))

    def _service_action(self, action):
        sel = self.services_tree.selection()
        if not sel:
            messagebox.showinfo("Service", "No service selected.")
            return
        name = self.services_tree.item(sel[0], "values")[0]
        self.adjustment_engine.change_service_status(name, action)

    def _service_change_starttype(self):
        sel = self.services_tree.selection()
        if not sel:
            messagebox.showinfo("Service", "No service selected.")
            return
        name = self.services_tree.item(sel[0], "values")[0]
        st = self.service_starttype_var.get()
        self.adjustment_engine.change_service_start_type(name, st)

    def _build_tasks_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Scheduled Tasks")

        self.tasks_tree = ttk.Treeview(frame, columns=("name", "state"), show="headings", height=10)
        self.tasks_tree.heading("name", text="TaskName")
        self.tasks_tree.heading("state", text="State")
        self.tasks_tree.column("name", width=250)
        self.tasks_tree.column("state", width=80)
        self.tasks_tree.pack(fill="both", expand=True, padx=5, pady=5)

        task_scroll = ttk.Scrollbar(frame, orient="vertical", command=self.tasks_tree.yview)
        self.tasks_tree.configure(yscrollcommand=task_scroll.set)
        task_scroll.pack(side="right", fill="y")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="Refresh", command=self._refresh_tasks).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Enable", command=lambda: self._task_change(True)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Disable", command=lambda: self._task_change(False)).pack(side="left", padx=5)

        self._refresh_tasks()

    def _refresh_tasks(self):
        self.tasks_tree.delete(*self.tasks_tree.get_children())
        tasks = self.adjustment_engine.list_tasks()
        if isinstance(tasks, dict):
            tasks = [tasks]
        for t in tasks:
            name = t.get("TaskName")
            state = t.get("State")
            self.tasks_tree.insert("", "end", values=(name, state))

    def _task_change(self, enable):
        sel = self.tasks_tree.selection()
        if not sel:
            messagebox.showinfo("Task", "No task selected.")
            return
        name = self.tasks_tree.item(sel[0], "values")[0]
        self.adjustment_engine.change_task_state(name, enable)

    def _build_defender_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Defender")

        ttk.Label(frame, text="Real-time Protection (safe toggle):").pack(pady=5)
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Enable", command=lambda: self.adjustment_engine.toggle_defender_realtime(True)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Disable", command=lambda: self.adjustment_engine.toggle_defender_realtime(False)).pack(side="left", padx=5)

    def _build_network_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Network")

        self.net_tree = ttk.Treeview(frame, columns=("name", "status"), show="headings", height=10)
        self.net_tree.heading("name", text="Adapter")
        self.net_tree.heading("status", text="Status")
        self.net_tree.column("name", width=200)
        self.net_tree.column("status", width=80)
        self.net_tree.pack(fill="both", expand=True, padx=5, pady=5)

        net_scroll = ttk.Scrollbar(frame, orient="vertical", command=self.net_tree.yview)
        self.net_tree.configure(yscrollcommand=net_scroll.set)
        net_scroll.pack(side="right", fill="y")

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="Refresh", command=self._refresh_net).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Enable", command=lambda: self._net_change(True)).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Disable", command=lambda: self._net_change(False)).pack(side="left", padx=5)

        self._refresh_net()

    def _refresh_net(self):
        self.net_tree.delete(*self.net_tree.get_children())
        adapters = self.adjustment_engine.list_network_adapters()
        if isinstance(adapters, dict):
            adapters = [adapters]
        for a in adapters:
            name = a.get("Name")
            status = a.get("Status")
            self.net_tree.insert("", "end", values=(name, status))

    def _net_change(self, enable):
        sel = self.net_tree.selection()
        if not sel:
            messagebox.showinfo("Network", "No adapter selected.")
            return
        name = self.net_tree.item(sel[0], "values")[0]
        self.adjustment_engine.change_adapter_status(name, enable)

    def _build_power_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Power")

        ttk.Label(frame, text="Power Plans (read-only listing via powercfg /L):").pack(pady=5)
        self.power_text = tk.Text(frame, height=10, width=80)
        self.power_text.pack(fill="both", expand=True, padx=5, pady=5)

        btn_frame = ttk.Frame(frame)
        btn_frame.pack(fill="x", pady=5)

        ttk.Button(btn_frame, text="Refresh", command=self._refresh_power).pack(side="left", padx=5)
        ttk.Label(btn_frame, text="GUID:").pack(side="left", padx=5)
        self.power_guid_var = tk.StringVar()
        ttk.Entry(btn_frame, textvariable=self.power_guid_var, width=40).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Set Plan", command=self._set_power_plan).pack(side="left", padx=5)

        self._refresh_power()

    def _refresh_power(self):
        out = self.adjustment_engine.list_power_plans()
        self.power_text.delete("1.0", tk.END)
        self.power_text.insert(tk.END, out)

    def _set_power_plan(self):
        guid = self.power_guid_var.get().strip()
        if not guid:
            messagebox.showinfo("Power", "GUID required.")
            return
        self.adjustment_engine.set_power_plan(guid)

    def _build_update_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="Windows Update")

        ttk.Label(frame, text="Safe Update Controls (wuauserv):").pack(pady=5)
        btn_frame = ttk.Frame(frame)
        btn_frame.pack(pady=5)

        ttk.Button(btn_frame, text="Pause Updates", command=self.adjustment_engine.pause_updates).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Resume Updates", command=self.adjustment_engine.resume_updates).pack(side="left", padx=5)

    def _build_sysinfo_tab(self, notebook):
        frame = ttk.Frame(notebook)
        notebook.add(frame, text="System Info")

        info = self.adjustment_engine.get_system_info()
        text = tk.Text(frame, height=10, width=80)
        text.pack(fill="both", expand=True, padx=5, pady=5)
        text.insert(tk.END, json.dumps(info, indent=2))

    # ---- Core controls ----

    def toggle_override(self):
        self.auto_block_enabled = not self.auto_block_enabled
        if self.auto_block_enabled:
            self.override_button.config(text="Manual Override: ENABLED")
            self.log_alert("Auto-block re-enabled.")
        else:
            self.override_button.config(text="Manual Override: DISABLED")
            self.log_alert("Manual override active — changes allowed.")

    def log_alert(self, message):
        timestamp = time.strftime("[%H:%M:%S] ")
        self.alert_box.insert(tk.END, timestamp + message + "\n")
        self.alert_box.see(tk.END)

    def refresh_snapshots(self):
        snaps = list_snapshots()
        self.snapshot_combo["values"] = snaps
        if snaps:
            self.snapshot_combo.current(0)

    def restore_selected_snapshot(self):
        folder = self.snapshot_var.get()
        if not folder:
            messagebox.showinfo("Restore Snapshot", "No snapshot selected.")
            return
        self.log_alert(f"Restoring snapshot: {folder}")
        restore_snapshot(folder)
        self.log_alert("Snapshot restore completed.")

    def _apply_gpo_telemetry(self):
        apply_telemetry_suppression(self.log_alert)

    # =========================
    # Monitoring loops (hourly baseline + persistence)
    # =========================

    def _start_monitoring(self):
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()

    def _monitor_loop(self):
        if self.baseline_fw is None:
            self.log_alert("[Baseline] Creating initial snapshot...")
            meta = {"summary": "Initial baseline snapshot"}
            snap = self.request_snapshot(meta, reason="initial_baseline")

            self.baseline_fw = hash_state(get_firewall_state())
            self.baseline_profiles = hash_state(get_profiles_state())
            self.baseline_settings = hash_state(get_settings_state())
            self.last_snapshot_time = time.time()

        while True:
            fw_hash = hash_state(get_firewall_state())
            prof_hash = hash_state(get_profiles_state())
            set_hash = hash_state(get_settings_state())

            now = time.time()
            one_hour_passed = (now - self.last_snapshot_time) >= self.snapshot_cooldown

            if fw_hash != self.baseline_fw:
                self.fw_change_counter += 1
            else:
                self.fw_change_counter = 0

            if prof_hash != self.baseline_profiles:
                self.prof_change_counter += 1
            else:
                self.prof_change_counter = 0

            if set_hash != self.baseline_settings:
                self.set_change_counter += 1
            else:
                self.set_change_counter = 0

            persistent_changes = []
            if self.fw_change_counter >= self.persistence_threshold:
                persistent_changes.append("Firewall")
            if self.prof_change_counter >= self.persistence_threshold:
                persistent_changes.append("Profiles")
            if self.set_change_counter >= self.persistence_threshold:
                persistent_changes.append("Settings Store")

            wu_running = False
            try:
                for p in psutil.process_iter(["name"]):
                    name = (p.info["name"] or "").lower()
                    if name in ("wuauclt.exe", "wuauserv"):
                        wu_running = True
                        break
            except Exception:
                wu_running = False

            allow_update_snap = wu_running and self.update_snapshot_enabled

            if (one_hour_passed and persistent_changes) or allow_update_snap:
                changes = persistent_changes if persistent_changes else ["Update-driven"]
                self.log_alert(f"[Baseline Compare] Persistent changes detected or update snapshot allowed: {changes}")
                meta = {
                    "summary": f"Hourly/persistent snapshot: {changes}",
                    "changes": changes,
                    "timestamp": now,
                    "wu_running": wu_running,
                }
                snap = self.request_snapshot(meta, reason="baseline_persistent_or_update")
                if snap:
                    self.baseline_fw = fw_hash
                    self.baseline_profiles = prof_hash
                    self.baseline_settings = set_hash
                    self.fw_change_counter = 0
                    self.prof_change_counter = 0
                    self.set_change_counter = 0
                    self.event_bus.publish("baseline_snapshot", meta)

            time.sleep(10)

    def _set_status(self, setting_name, changed):
        color = "red" if changed else "green"
        text_suffix = "CHANGED" if changed else "NORMAL"
        if setting_name == "Firewall":
            self.status_fw.config(text=f"Firewall: {text_suffix}", foreground=color)
        elif setting_name == "Profiles":
            self.status_profiles.config(text=f"Profiles: {text_suffix}", foreground=color)
        elif setting_name == "Settings Store":
            self.status_reg.config(text=f"Settings Store: {text_suffix}", foreground=color)

    def _start_threat_matrix_refresh(self):
        t = threading.Thread(target=self._threat_loop, daemon=True)
        t.start()

    def _threat_loop(self):
        while True:
            self._refresh_threat_matrix()
            time.sleep(5)

    def _refresh_threat_matrix(self):
        self.threat_tree.delete(*self.threat_tree.get_children())
        now = time.time()
        current_pids = set()
        scores_for_swarm = []
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                pid = proc.info['pid']
                name = proc.info['name']
                cpu = proc.info['cpu_percent']
                conns = proc.connections()
                current_pids.add(pid)

                resurrected = False
                last_seen = self.process_seen.get(pid)
                if last_seen is not None and (now - last_seen) > 30:
                    resurrected = True

                self.process_seen[pid] = now

                info = {
                    "pid": pid,
                    "name": name,
                    "cpu_percent": cpu,
                }
                decision = self.agent.evaluate_process(info, len(conns), resurrected=resurrected)
                scores_for_swarm.append(decision["score"])
                self.threat_tree.insert(
                    "",
                    "end",
                    values=(
                        pid,
                        name,
                        cpu,
                        len(conns),
                        f"{decision['score']:.2f}",
                        decision['action'],
                        "Yes" if resurrected else "No",
                    )
                )
            except Exception:
                continue

        for pid in list(self.process_seen.keys()):
            if pid not in current_pids and (now - self.process_seen[pid]) > 300:
                del self.process_seen[pid]

        self._update_swarm_state(threat_scores=scores_for_swarm)

    # =========================
    # Suricata loop
    # =========================

    def _start_suricata_loop(self):
        self.suricata_ingestor.start()
        t = threading.Thread(target=self._suricata_loop, daemon=True)
        t.start()

    def _suricata_loop(self):
        while True:
            evt = self.suricata_ingestor.get_event_nowait()
            if evt is not None:
                self._handle_suricata_event(evt)
            time.sleep(1)

    def _handle_suricata_event(self, evt):
        self.status_suricata.config(text="Suricata: ACTIVE", foreground="yellow")
        decision = self.agent.evaluate_suricata_event(evt)
        sig = evt.get("alert", {}).get("signature", "")
        sev = evt.get("alert", {}).get("severity", "")
        self.log_alert(f"[Suricata] {sig} (sev={sev}) -> score={decision['score']:.2f}, action={decision['action']}, remediation={decision['remediation']}")
        self.sur_list.insert(
            "",
            "end",
            values=(
                sig,
                sev,
                decision["mitre"],
                f"{decision['score']:.2f}",
                decision["action"],
            )
        )
        if self.suricata_snapshot_enabled and decision["action"].startswith("snapshot"):
            meta = {
                "summary": "Suricata event snapshot",
                "signature": sig,
                "severity": sev,
                "mitre": decision["mitre"],
                "score": decision["score"],
            }
            snap = self.request_snapshot(meta, reason="suricata_event")
            if snap:
                self.event_bus.publish("suricata_snapshot", meta)

    # =========================
    # Swarm sync view
    # =========================

    def _update_swarm_state(self, threat_scores=None, snapshots=None, signatures=None, persona=None):
        if threat_scores is None:
            threat_scores = []
        if snapshots is None:
            snapshots = list_snapshots()
        if signatures is None:
            signatures = []
        if persona is None:
            persona = self.persona

        self.swarm_sync.update_local_state(
            threat_scores=threat_scores,
            snapshots=snapshots,
            signatures=signatures,
            persona=persona
        )
        self._update_swarm_view()

    def _update_swarm_view(self):
        view = self.swarm_sync.get_swarm_view()
        self.swarm_view_text.delete("1.0", tk.END)
        self.swarm_view_text.insert(tk.END, json.dumps(view, indent=2))

    # =========================
    # Event bus handler
    # =========================

    def _on_event_bus(self, evt):
        etype = evt.get("type")
        payload = evt.get("payload", {})
        msg = f"[EventBus] {etype}: {payload.get('summary', '')}"
        self.log_alert(msg)
        self.event_log.insert(tk.END, msg + "\n")
        self.event_log.see(tk.END)

# =========================
# Entry point
# =========================

if __name__ == "__main__":
    root = tk.Tk()
    app = CodexSettingsGuard(root)
    root.mainloop()
