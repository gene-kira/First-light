#!/usr/bin/env python3
"""
Steam Malware Guard v5 – ETW + Suricata Live + GPU ML + Unified Bus + Fluent Ribbon

Upgrades vs v4:
- Real ETW-style ingestion stub (ready for krabsetw/pywintrace)
- Suricata live socket ingestion (eve.json + TCP stream stub)
- GPU-accelerated ML classifier (3D-ResNet / ConvLSTM skeleton)
- Unified event bus for all subsystems
- Process → network correlation
- Steam credential anomaly ML model stub
- Fluent Ribbon-style GUI with threat matrix panel
- Backbone streaming telemetry (continuous event feed)
- Auto-rollback with diff viewer for Steam config
- Multi-GPU support (torch.nn.DataParallel / device selection)
"""

# ==========================
# AUTO-ELEVATION CHECK
# ==========================
import ctypes
import sys
import os

def ensure_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            print("[ELEVATION] Admin rights required. Relaunching with elevation...")
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
        print(f"[ELEVATION ERROR] {e}")
        sys.exit()

ensure_admin()

# ==========================
# AUTOLOADER (BACKBONE STYLE)
# ==========================
import importlib
import subprocess

REQUIRED_MODULES = {
    "os": "os",
    "time": "time",
    "hashlib": "hashlib",
    "threading": "threading",
    "json": "json",
    "ctypes": "ctypes",
    "psutil": "psutil",
    "watchdog": "watchdog",
    "requests": "requests",
    "PySide6": "PySide6",
    "yara": "yara-python",
    "win32evtlog": "pywin32",
    "difflib": "difflib",
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
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        for module_name in REQUIRED_MODULES.keys():
            importlib.import_module(module_name)
            print(f"[AUTOLOADER] Loaded: {module_name}")

autoload_modules()

import os
import time
import hashlib
import threading
import json
import ctypes
import psutil
import requests
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from PySide6 import QtWidgets, QtGui, QtCore
import win32evtlog
import difflib

# Optional GPU / ML
try:
    import torch
    import torch.nn as nn
    import torch.nn.functional as F
    GPU_AVAILABLE = torch.cuda.is_available()
except Exception:
    GPU_AVAILABLE = False

try:
    import yara
    YARA_AVAILABLE = True
except Exception:
    YARA_AVAILABLE = False

# ==========================
# CONFIG
# ==========================
WATCH_DIRS = [
    os.path.expanduser(r"~\\Downloads"),
    os.path.expanduser(r"~\\Desktop"),
    os.path.expanduser(r"~\\AppData\\Local\\Steam\\steamapps\\common"),
]

SUSPICIOUS_NAME_TOKENS = [
    "fhjor",
    "save loader",
    "loader",
    "steamtools",
    "cheat",
    "hack",
    "injector",
    "trainer",
]

SUSPICIOUS_STRING_TOKENS = [
    b"discord",
    b"token",
    b"wallet",
    b"chrome",
    b"password",
    b"stealer",
    b"webhook",
]

QUARANTINE_DIR = os.path.join(os.getcwd(), "Quarantine")
os.makedirs(QUARANTINE_DIR, exist_ok=True)

VT_API_KEY = ""  # optional VirusTotal key

SURICATA_EVE_PATH = os.path.join(os.getcwd(), "eve.json")  # eve.json fallback
SURICATA_SOCKET_HOST = "127.0.0.1"
SURICATA_SOCKET_PORT = 5555  # example live socket port

STEAM_CONFIG = os.path.expanduser(r"~\\AppData\\Local\\Steam\\config\\loginusers.vdf")
STEAM_CONFIG_BACKUP = STEAM_CONFIG + ".bak"
STEAM_SSFN_DIR = os.path.expanduser(r"~\\Program Files (x86)\\Steam")

BACKBONE_HTTP = "http://127.0.0.1:8080"
AUTH_SECRET = b"super_secret_shared_key"  # must match backbone

AUTO_FS_WATCH = True
AUTO_KILL = True

BEHAVIOR_SCORE = 0
SCORE_THRESHOLD = 10

SEEN_IPS = set()
IP_COUNTS = {}

WHITELIST_PROCS = [
    "steam.exe",
    "steamservice.exe",
    "explorer.exe",
    "svchost.exe",
    "chrome.exe",
    "discord.exe",
    "epicgameslauncher.exe",
    "battle.net.exe",
    "nvcontainer.exe",
    "amdow.exe",
]

BLACKLIST_TOKENS = [
    "loader",
    "injector",
    "cheat",
    "hack",
    "stealer",
    "token",
    "save loader",
]

# Threat matrix categories (simple)
THREAT_CATEGORIES = [
    "Filesystem",
    "Process",
    "Network",
    "Kernel",
    "Steam",
    "Suricata",
    "ML",
]

# ==========================
# HMAC UTILS
# ==========================
import hmac

def make_hmac(payload: str) -> str:
    return hmac.new(AUTH_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()

# ==========================
# PRIVILEGE ENABLE (STUB)
# ==========================
def enable_kernel_privileges(gui, bus):
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        TOKEN_ADJUST_PRIVILEGES = 0x20
        TOKEN_QUERY = 0x8
        SE_PRIVILEGE_ENABLED = 0x2

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", ctypes.c_uint32),
                        ("HighPart", ctypes.c_int32)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID),
                        ("Attributes", ctypes.c_uint32)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", ctypes.c_uint32),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        hToken = ctypes.c_void_p()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                         ctypes.byref(hToken)):
            bus.emit("privilege_error", {"msg": "OpenProcessToken failed"})
            gui.log("[PRIV] OpenProcessToken failed")
            return

        def enable_priv(name):
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
                gui.log(f"[PRIV] LookupPrivilegeValueW failed for {name}")
                bus.emit("privilege_error", {"msg": f"LookupPrivilegeValueW failed for {name}"})
                return
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            if not advapi32.AdjustTokenPrivileges(hToken, False,
                                                  ctypes.byref(tp),
                                                  0, None, None):
                gui.log(f"[PRIV] AdjustTokenPrivileges failed for {name}")
                bus.emit("privilege_error", {"msg": f"AdjustTokenPrivileges failed for {name}"})
            else:
                gui.log(f"[PRIV] Enabled {name}")
                bus.emit("privilege_enabled", {"name": name})

        enable_priv("SeSecurityPrivilege")
        enable_priv("SeAuditPrivilege")
    except Exception as e:
        gui.log(f"[PRIV ERROR] {e}")
        bus.emit("privilege_error", {"msg": str(e)})

# ==========================
# UNIFIED EVENT BUS
# ==========================
class EventBus:
    """
    Simple synchronous event bus for v5.
    All subsystems publish events here; GUI and backbone consume.
    """
    def __init__(self):
        self.listeners = {}
        self.lock = threading.Lock()

    def on(self, event_type, callback):
        with self.lock:
            self.listeners.setdefault(event_type, []).append(callback)

    def emit(self, event_type, payload=None):
        with self.lock:
            callbacks = list(self.listeners.get(event_type, []))
        for cb in callbacks:
            try:
                cb(event_type, payload or {})
            except Exception:
                pass

# ==========================
# CORE UTILS
# ==========================
def sha256_file(path):
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except:
        return "ERROR"

def file_entropy(path, sample_size=256*1024):
    try:
        with open(path, "rb") as f:
            data = f.read(sample_size)
        if not data:
            return 0.0
        if GPU_AVAILABLE:
            device = "cuda"
            t = torch.tensor(list(data), dtype=torch.float32, device=device)
            hist = torch.histc(t, bins=256, min=0, max=255)
            p = hist / hist.sum()
            ent = -(p * (p + 1e-12).log2()).sum().item()
            return ent
        else:
            import math
            counts = [0] * 256
            for b in data:
                counts[b] += 1
            ent = 0.0
            total = len(data)
            for c in counts:
                if c == 0:
                    continue
                p = c / total
                ent -= p * math.log2(p)
            return ent
    except:
        return 0.0

def is_pe(path):
    try:
        with open(path, "rb") as f:
            return f.read(2) == b"MZ"
    except:
        return False

def has_suspicious_strings(path):
    try:
        with open(path, "rb") as f:
            data = f.read(256*1024)
        return any(token in data for token in SUSPICIOUS_STRING_TOKENS)
    except:
        return False

def suspicious_name(path):
    lower = os.path.basename(path).lower()
    return any(token in lower for token in SUSPICIOUS_NAME_TOKENS)

def vt_lookup(sha256):
    if not VT_API_KEY:
        return {"status": "disabled"}
    try:
        url = f"https://www.virustotal.com/api/v3/files/{sha256}"
        headers = {"x-apikey": VT_API_KEY}
        r = requests.get(url, headers=headers, timeout=10)
        if r.status_code == 200:
            data = r.json()
            stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
            return {"status": "ok", "stats": stats}
        else:
            return {"status": "error", "code": r.status_code}
    except Exception as e:
        return {"status": "error", "error": str(e)}

# ==========================
# YARA / SURICATA
# ==========================
YARA_RULES = None
if YARA_AVAILABLE:
    try:
        YARA_RULES = yara.compile(filepath="rules.yar")
        print("[YARA] Loaded rules.yar")
    except Exception as e:
        print(f"[YARA] Failed to load rules: {e}")
        YARA_RULES = None

def yara_scan(path):
    if not YARA_RULES:
        return []
    try:
        matches = YARA_RULES.match(filepath=path)
        return [m.rule for m in matches]
    except Exception:
        return []

def suricata_eve_stream(bus):
    """
    Fallback eve.json reader – still useful if live socket not available.
    """
    if not os.path.isfile(SURICATA_EVE_PATH):
        return
    try:
        with open(SURICATA_EVE_PATH, "r", errors="ignore") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                    bus.emit("suricata_event", ev)
                except:
                    continue
    except Exception:
        pass

def suricata_live_socket_loop(bus, gui):
    """
    Live Suricata ingestion stub – expects JSON lines over TCP.
    """
    import socket
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(5)
            s.connect((SURICATA_SOCKET_HOST, SURICATA_SOCKET_PORT))
            gui.log(f"[SURICATA] Connected live socket {SURICATA_SOCKET_HOST}:{SURICATA_SOCKET_PORT}")
            bus.emit("suricata_status", {"state": "connected"})
            with s:
                buf = b""
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
                    while b"\n" in buf:
                        line, buf = buf.split(b"\n", 1)
                        try:
                            ev = json.loads(line.decode("utf-8", errors="ignore"))
                            bus.emit("suricata_event", ev)
                        except Exception:
                            continue
        except Exception as e:
            gui.log(f"[SURICATA ERROR] {e}")
            bus.emit("suricata_status", {"state": "error", "msg": str(e)})
            time.sleep(5)

# ==========================
# GPU ML CLASSIFIER (3D-ResNet / ConvLSTM skeleton)
# ==========================
class ConvLSTMCell(nn.Module):
    def __init__(self, input_dim, hidden_dim, kernel_size, bias=True):
        super().__init__()
        padding = kernel_size // 2
        self.hidden_dim = hidden_dim
        self.conv = nn.Conv2d(
            in_channels=input_dim + hidden_dim,
            out_channels=4 * hidden_dim,
            kernel_size=kernel_size,
            padding=padding,
            bias=bias,
        )

    def forward(self, x, h_cur, c_cur):
        combined = torch.cat([x, h_cur], dim=1)
        conv_output = self.conv(combined)
        cc_i, cc_f, cc_o, cc_g = torch.split(conv_output, self.hidden_dim, dim=1)
        i = torch.sigmoid(cc_i)
        f = torch.sigmoid(cc_f)
        o = torch.sigmoid(cc_o)
        g = torch.tanh(cc_g)
        c_next = f * c_cur + i * g
        h_next = o * torch.tanh(c_next)
        return h_next, c_next

class Simple3DResNet(nn.Module):
    """
    Very small 3D-ResNet-like stub for temporal features.
    """
    def __init__(self, num_classes=2):
        super().__init__()
        self.conv1 = nn.Conv3d(1, 8, kernel_size=3, padding=1)
        self.bn1 = nn.BatchNorm3d(8)
        self.conv2 = nn.Conv3d(8, 16, kernel_size=3, padding=1)
        self.bn2 = nn.BatchNorm3d(16)
        self.fc = nn.Linear(16, num_classes)

    def forward(self, x):
        x = F.relu(self.bn1(self.conv1(x)))
        x = F.relu(self.bn2(self.conv2(x)))
        x = x.mean(dim=[2, 3, 4])  # global average pool
        x = self.fc(x)
        return x

class SteamAnomalyModel(nn.Module):
    """
    Steam credential anomaly model stub – takes simple feature vector.
    """
    def __init__(self):
        super().__init__()
        self.fc1 = nn.Linear(8, 32)
        self.fc2 = nn.Linear(32, 16)
        self.fc3 = nn.Linear(16, 2)

    def forward(self, x):
        x = F.relu(self.fc1(x))
        x = F.relu(self.fc2(x))
        x = self.fc3(x)
        return x

class MLManager:
    """
    Manages ML models, devices, and inference.
    """
    def __init__(self, gui, bus):
        self.gui = gui
        self.bus = bus
        self.device = "cuda" if GPU_AVAILABLE else "cpu"
        self.models = {}
        self._init_models()

    def _wrap_multi_gpu(self, model):
        if GPU_AVAILABLE and torch.cuda.device_count() > 1:
            self.gui.log(f"[ML] Using DataParallel across {torch.cuda.device_count()} GPUs")
            return nn.DataParallel(model)
        return model

    def _init_models(self):
        try:
            resnet3d = Simple3DResNet(num_classes=2).to(self.device)
            resnet3d = self._wrap_multi_gpu(resnet3d)
            steam_model = SteamAnomalyModel().to(self.device)
            steam_model = self._wrap_multi_gpu(steam_model)
            self.models["3d_resnet"] = resnet3d
            self.models["steam_anomaly"] = steam_model
            self.gui.log("[ML] Models initialized (3D-ResNet, SteamAnomaly)")
            self.bus.emit("ml_status", {"state": "ready"})
        except Exception as e:
            self.gui.log(f"[ML ERROR] {e}")
            self.bus.emit("ml_status", {"state": "error", "msg": str(e)})

    def classify_file(self, path, entropy, yara_hits):
        """
        Stub: build a simple feature vector and run through 3D-ResNet.
        """
        try:
            # Fake temporal tensor: [batch, channels, time, H, W]
            x = torch.randn(1, 1, 4, 4, 4, device=self.device)
            model = self.models.get("3d_resnet")
            if model is None:
                return None
            with torch.no_grad():
                logits = model(x)
                probs = torch.softmax(logits, dim=1)
                score = probs[0, 1].item()
            self.bus.emit("ml_file_classified", {
                "path": path,
                "entropy": entropy,
                "yara_hits": len(yara_hits),
                "score": score,
            })
            return score
        except Exception as e:
            self.gui.log(f"[ML FILE ERROR] {e}")
            return None

    def classify_steam_change(self, old_size, new_size, diff_len):
        """
        Stub: simple feature vector for Steam anomaly.
        """
        try:
            features = torch.tensor(
                [float(old_size), float(new_size), float(diff_len),
                 float(new_size - old_size), 0.0, 0.0, 0.0, 0.0],
                device=self.device
            ).unsqueeze(0)
            model = self.models.get("steam_anomaly")
            if model is None:
                return None
            with torch.no_grad():
                logits = model(features)
                probs = torch.softmax(logits, dim=1)
                score = probs[0, 1].item()
            self.bus.emit("ml_steam_classified", {
                "old_size": old_size,
                "new_size": new_size,
                "diff_len": diff_len,
                "score": score,
            })
            return score
        except Exception as e:
            self.gui.log(f"[ML STEAM ERROR] {e}")
            return None

# ==========================
# BEHAVIORAL ENGINE BRIDGE
# ==========================
def send_to_backbone(event_type, payload):
    try:
        raw = json.dumps({"type": event_type, "payload": payload}, sort_keys=True)
        sig = make_hmac(raw)
        url = f"{BACKBONE_HTTP}/command"
        data = {"cmd": event_type, "payload": payload, "sig": sig}
        requests.post(url, json=data, timeout=2)
    except Exception:
        pass

def backbone_streaming_loop(bus, gui):
    """
    Simple streaming telemetry: subscribes to all events and forwards to backbone.
    """
    def forwarder(event_type, payload):
        send_to_backbone(event_type, payload or {})

    # Subscribe to broad categories
    for ev in [
        "file_suspicious", "process_killed", "net_new_ip", "net_burst",
        "kernel_event", "steam_rollback", "steam_diff", "suricata_event",
        "ml_file_classified", "ml_steam_classified", "behavior_score",
    ]:
        bus.on(ev, forwarder)

    gui.log("[BACKBONE] Streaming telemetry enabled.")

def add_behavior_score(gui, bus, delta, reason):
    global BEHAVIOR_SCORE
    BEHAVIOR_SCORE += delta
    gui.update_score(BEHAVIOR_SCORE)
    gui.log(f"[SCORE] +{delta} ({reason}) → {BEHAVIOR_SCORE}")
    bus.emit("behavior_score", {"delta": delta, "reason": reason, "score": BEHAVIOR_SCORE})
    if BEHAVIOR_SCORE >= SCORE_THRESHOLD:
        gui.log("[ALERT] Behavior score threshold exceeded – aggressive actions enabled.")
        bus.emit("behavior_alert", {"score": BEHAVIOR_SCORE, "reason": reason})
        send_to_backbone("ALERT_THRESHOLD", {"score": BEHAVIOR_SCORE, "reason": reason})

# ==========================
# SANDBOX STUB
# ==========================
def sandbox_mark(path, gui, bus):
    gui.log(f"[SANDBOX] Marked {path} as sandboxed (no execution).")
    bus.emit("sandbox_mark", {"path": path})

# ==========================
# AUTO-ROLLBACK FOR STEAM + DIFF VIEWER
# ==========================
def backup_steam_config(gui, bus):
    if os.path.isfile(STEAM_CONFIG):
        try:
            if not os.path.isfile(STEAM_CONFIG_BACKUP):
                with open(STEAM_CONFIG, "rb") as src, open(STEAM_CONFIG_BACKUP, "wb") as dst:
                    dst.write(src.read())
                gui.log("[ROLLBACK] Steam config backup created.")
                bus.emit("steam_backup", {"path": STEAM_CONFIG_BACKUP})
        except Exception as e:
            gui.log(f"[ROLLBACK ERROR] {e}")
            bus.emit("steam_backup_error", {"msg": str(e)})

def diff_steam_config(gui, bus):
    if not (os.path.isfile(STEAM_CONFIG) and os.path.isfile(STEAM_CONFIG_BACKUP)):
        return ""
    try:
        with open(STEAM_CONFIG_BACKUP, "r", errors="ignore") as f_old, \
             open(STEAM_CONFIG, "r", errors="ignore") as f_new:
            old_lines = f_old.readlines()
            new_lines = f_new.readlines()
        diff = difflib.unified_diff(old_lines, new_lines,
                                    fromfile="loginusers.vdf.bak",
                                    tofile="loginusers.vdf",
                                    lineterm="")
        diff_text = "\n".join(diff)
        bus.emit("steam_diff", {"diff": diff_text})
        return diff_text
    except Exception as e:
        gui.log(f"[DIFF ERROR] {e}")
        bus.emit("steam_diff_error", {"msg": str(e)})
        return ""

def rollback_steam_config(gui, bus, ml_manager=None, last_size=None, new_size=None):
    if os.path.isfile(STEAM_CONFIG_BACKUP):
        try:
            diff_text = diff_steam_config(gui, bus)
            diff_len = len(diff_text)
            if last_size is not None and new_size is not None and ml_manager is not None:
                score = ml_manager.classify_steam_change(last_size, new_size, diff_len)
                gui.log(f"[STEAM ML] Anomaly score={score:.3f}" if score is not None else "[STEAM ML] No score")
            with open(STEAM_CONFIG_BACKUP, "rb") as src, open(STEAM_CONFIG, "wb") as dst:
                dst.write(src.read())
            gui.log("[ROLLBACK] Steam config restored from backup.")
            bus.emit("steam_rollback", {"diff_len": diff_len})
        except Exception as e:
            gui.log(f"[ROLLBACK ERROR] {e}")
            bus.emit("steam_rollback_error", {"msg": str(e)})

def monitor_ssfn(gui, bus):
    if not os.path.isdir(STEAM_SSFN_DIR):
        return
    while True:
        try:
            for f in os.listdir(STEAM_SSFN_DIR):
                if f.lower().startswith("ssfn"):
                    path = os.path.join(STEAM_SSFN_DIR, f)
                    gui.log(f"[STEAM] ssfn file present: {path}")
                    bus.emit("steam_ssfn", {"path": path})
            time.sleep(60)
        except Exception as e:
            gui.log(f"[STEAM SSFN ERROR] {e}")
            bus.emit("steam_ssfn_error", {"msg": str(e)})
            time.sleep(60)

# ==========================
# PROCESS REPUTATION + AUTO-KILL + PROCESS→NETWORK CORRELATION
# ==========================
def is_whitelisted_proc(name):
    return name.lower() in WHITELIST_PROCS

def kill_suspicious_processes(gui, bus):
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            name = (proc.info["name"] or "").lower()
            exe = (proc.info["exe"] or "").lower()
            cmd = " ".join(proc.info["cmdline"] or []).lower()
            combined = " ".join([name, exe, cmd])

            if is_whitelisted_proc(name):
                continue

            if any(token in combined for token in BLACKLIST_TOKENS):
                gui.log(f"[AUTO-KILL] PID={proc.pid} NAME={name}")
                proc.kill()
                add_behavior_score(gui, bus, 2, "Unknown process killed")
                bus.emit("process_killed", {"pid": proc.pid, "name": name})
        except Exception as e:
            gui.log(f"[AUTO-KILL ERROR] {e}")
            bus.emit("process_kill_error", {"msg": str(e)})

def process_network_map():
    """
    Build mapping: remote_ip -> list of (pid, name, exe)
    """
    mapping = {}
    for c in psutil.net_connections(kind="inet"):
        try:
            raddr = c.raddr
            if not raddr:
                continue
            ip = raddr.ip
            port = raddr.port
            pid = c.pid
            if pid is None:
                continue
            proc = psutil.Process(pid)
            name = proc.name()
            exe = proc.exe()
            mapping.setdefault(ip, []).append({
                "pid": pid,
                "name": name,
                "exe": exe,
                "port": port,
            })
        except Exception:
            continue
    return mapping

# ==========================
# ANALYSIS + ACTION
# ==========================
def quarantine(path, gui, bus):
    try:
        dest = os.path.join(QUARANTINE_DIR, os.path.basename(path))
        os.replace(path, dest)
        bus.emit("file_quarantined", {"src": path, "dest": dest})
        return dest
    except Exception as e:
        gui.log(f"[QUARANTINE ERROR] {e}")
        bus.emit("file_quarantine_error", {"path": path, "msg": str(e)})
        return path

def analyze_file(path, gui, bus, ml_manager=None):
    if not os.path.isfile(path):
        return
    if not is_pe(path):
        return

    name_flag = suspicious_name(path)
    string_flag = has_suspicious_strings(path)
    ent = file_entropy(path)
    ent_flag = ent > 7.0
    yara_hits = yara_scan(path)

    sha = sha256_file(path)
    vt = vt_lookup(sha)

    ml_score = None
    if ml_manager is not None:
        ml_score = ml_manager.classify_file(path, ent, yara_hits)

    suspicious = name_flag or string_flag or ent_flag or yara_hits or (ml_score is not None and ml_score > 0.5)

    if suspicious:
        gui.log(f"[SUSPICIOUS FILE] {path}")
        gui.log(f"  SHA256={sha}")
        gui.log(f"  entropy={ent:.2f} (flag={ent_flag})")
        gui.log(f"  name_flag={name_flag}, string_flag={string_flag}")
        if yara_hits:
            gui.log(f"  YARA hits={yara_hits}")
        gui.log(f"  VT={vt}")
        if ml_score is not None:
            gui.log(f"  ML score={ml_score:.3f}")
        sandbox_mark(path, gui, bus)
        qpath = quarantine(path, gui, bus)
        gui.log(f"  → QUARANTINED: {qpath}")
        bus.emit("file_suspicious", {
            "path": path,
            "sha256": sha,
            "entropy": ent,
            "name_flag": name_flag,
            "string_flag": string_flag,
            "yara_hits": yara_hits,
            "ml_score": ml_score,
        })
        add_behavior_score(gui, bus, 3, "Suspicious file drop")
        if ent_flag:
            add_behavior_score(gui, bus, 2, "High entropy file")
        if yara_hits:
            add_behavior_score(gui, bus, 5, "YARA hit")

# ==========================
# REAL-TIME FS WATCHER
# ==========================
class MalwareEventHandler(FileSystemEventHandler):
    def __init__(self, gui, bus, ml_manager):
        super().__init__()
        self.gui = gui
        self.bus = bus
        self.ml_manager = ml_manager

    def on_created(self, event):
        if not AUTO_FS_WATCH:
            return
        if event.is_directory:
            return
        path = event.src_path
        if not path.lower().endswith((".exe", ".dll")):
            return
        analyze_file(path, self.gui, self.bus, self.ml_manager)

def fs_watch_loop(gui, bus, ml_manager):
    observer = Observer()
    handler = MalwareEventHandler(gui, bus, ml_manager)
    for d in WATCH_DIRS:
        if os.path.isdir(d):
            observer.schedule(handler, d, recursive=True)
    observer.start()
    gui.log("[FS WATCH] Started.")
    bus.emit("fs_watch_started", {})
    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()
        bus.emit("fs_watch_stopped", {})

# ==========================
# KERNEL EVENT LOOP (EventLog + ETW-style stub)
# ==========================
def kernel_event_loop(gui, bus):
    enable_kernel_privileges(gui, bus)
    server = "localhost"
    log_types = ["Security", "System"]
    while True:
        try:
            for log_type in log_types:
                h = win32evtlog.OpenEventLog(server, log_type)
                flags = win32evtlog.EVENTLOG_BACKWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
                events = win32evtlog.ReadEventLog(h, flags, 0)
                for ev in events or []:
                    gui.log(f"[KERNEL] {log_type} event ID={ev.EventID}")
                    bus.emit("kernel_event", {"log": log_type, "id": ev.EventID})
                    add_behavior_score(gui, bus, 5, "Kernel anomaly")
            time.sleep(30)
        except Exception as e:
            gui.log(f"[KERNEL ERROR] {e}")
            bus.emit("kernel_error", {"msg": str(e)})
            time.sleep(30)

# ==========================
# STEAM SESSION MONITOR
# ==========================
def steam_session_monitor(gui, bus, ml_manager):
    backup_steam_config(gui, bus)
    last_size = None
    while True:
        if os.path.isfile(STEAM_CONFIG):
            size = os.path.getsize(STEAM_CONFIG)
            if last_size is not None and size != last_size:
                gui.log(f"[STEAM SESSION] loginusers.vdf size changed: {last_size} -> {size}")
                bus.emit("steam_config_change", {"old_size": last_size, "new_size": size})
                rollback_steam_config(gui, bus, ml_manager, last_size, size)
                add_behavior_score(gui, bus, 4, "Steam config change")
            last_size = size
        time.sleep(10)

# ==========================
# NETWORK ANOMALY DETECTION + PROCESS CORRELATION
# ==========================
def is_local_ip(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")

def network_monitor_loop(gui, bus):
    while True:
        try:
            mapping = process_network_map()
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                raddr = c.raddr
                if not raddr:
                    continue
                ip = raddr.ip
                port = raddr.port
                host = f"{ip}:{port}"

                if is_local_ip(ip):
                    continue

                IP_COUNTS[ip] = IP_COUNTS.get(ip, 0) + 1

                correlated = mapping.get(ip, [])

                if ip not in SEEN_IPS:
                    SEEN_IPS.add(ip)
                    gui.log(f"[NET NEW] {host} (procs={len(correlated)})")
                    bus.emit("net_new_ip", {"ip": ip, "port": port, "procs": correlated})
                    add_behavior_score(gui, bus, 3, "New remote IP")

                if IP_COUNTS[ip] > 50:
                    gui.log(f"[NET BURST] {host} count={IP_COUNTS[ip]} procs={len(correlated)}")
                    bus.emit("net_burst", {"ip": ip, "port": port, "count": IP_COUNTS[ip], "procs": correlated})
                    add_behavior_score(gui, bus, 3, "High-frequency outbound")
        except Exception as e:
            gui.log(f"[NET ERROR] {e}")
            bus.emit("net_error", {"msg": str(e)})
        time.sleep(10)

# ==========================
# GUI – FLUENT RIBBON DASHBOARD + THREAT MATRIX
# ==========================
class GuardGUI(QtWidgets.QMainWindow):
    def __init__(self, bus):
        super().__init__()
        self.bus = bus
        self.setWindowTitle("Steam Malware Guard v5")
        self.resize(1400, 800)
        self.setStyleSheet("""
            QMainWindow { background-color: #202020; }
            QTextEdit { background-color: #1e1e1e; color: #dcdcdc; font-family: Consolas; }
            QPushButton { background-color: #2d2d2d; color: #ffffff; padding: 6px; border-radius: 4px; }
            QPushButton:hover { background-color: #3a3a3a; }
            QLabel { color: #ffffff; }
            QTableWidget { background-color: #1e1e1e; color: #dcdcdc; gridline-color: #404040; }
        """)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        main_layout = QtWidgets.QVBoxLayout(central)

        # Ribbon bar
        ribbon = QtWidgets.QHBoxLayout()
        self.btn_manual_scan = QtWidgets.QPushButton("Manual Full Scan")
        self.btn_toggle_fs = QtWidgets.QPushButton("FS Watch: ON")
        self.btn_toggle_kill = QtWidgets.QPushButton("Auto-Kill: ON")
        self.btn_show_diff = QtWidgets.QPushButton("Show Steam Diff")
        self.score_label = QtWidgets.QLabel("Behavior Score: 0")
        ribbon.addWidget(self.btn_manual_scan)
        ribbon.addWidget(self.btn_toggle_fs)
        ribbon.addWidget(self.btn_toggle_kill)
        ribbon.addWidget(self.btn_show_diff)
        ribbon.addWidget(self.score_label)

        main_layout.addLayout(ribbon)

        # Splitter: log + threat matrix
        splitter = QtWidgets.QSplitter(QtCore.Qt.Horizontal)
        self.log_view = QtWidgets.QTextEdit()
        self.log_view.setReadOnly(True)

        right_panel = QtWidgets.QWidget()
        right_layout = QtWidgets.QVBoxLayout(right_panel)

        self.threat_table = QtWidgets.QTableWidget(len(THREAT_CATEGORIES), 2)
        self.threat_table.setHorizontalHeaderLabels(["Category", "Last Event"])
        self.threat_table.verticalHeader().setVisible(False)
        for i, cat in enumerate(THREAT_CATEGORIES):
            self.threat_table.setItem(i, 0, QtWidgets.QTableWidgetItem(cat))
            self.threat_table.setItem(i, 1, QtWidgets.QTableWidgetItem("—"))

        right_layout.addWidget(QtWidgets.QLabel("Threat Matrix"))
        right_layout.addWidget(self.threat_table)

        splitter.addWidget(self.log_view)
        splitter.addWidget(right_panel)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 2)

        main_layout.addWidget(splitter)

        # Connections
        self.btn_manual_scan.clicked.connect(self.on_manual_scan)
        self.btn_toggle_fs.clicked.connect(self.on_toggle_fs)
        self.btn_toggle_kill.clicked.connect(self.on_toggle_kill)
        self.btn_show_diff.clicked.connect(self.on_show_diff)

        # Event bus subscriptions to update threat matrix
        self._wire_bus()

        self._steam_diff_cache = ""

    def _wire_bus(self):
        def update_matrix(event_type, payload):
            mapping = {
                "file_suspicious": "Filesystem",
                "file_quarantined": "Filesystem",
                "process_killed": "Process",
                "net_new_ip": "Network",
                "net_burst": "Network",
                "kernel_event": "Kernel",
                "steam_config_change": "Steam",
                "steam_rollback": "Steam",
                "suricata_event": "Suricata",
                "ml_file_classified": "ML",
                "ml_steam_classified": "ML",
            }
            cat = mapping.get(event_type)
            if not cat:
                return
            row = THREAT_CATEGORIES.index(cat)
            text = json.dumps(payload, sort_keys=True)[:120]
            self.threat_table.setItem(row, 1, QtWidgets.QTableWidgetItem(text))

        for ev in [
            "file_suspicious", "file_quarantined", "process_killed",
            "net_new_ip", "net_burst", "kernel_event",
            "steam_config_change", "steam_rollback",
            "suricata_event", "ml_file_classified", "ml_steam_classified",
        ]:
            self.bus.on(ev, update_matrix)

        def cache_diff(event_type, payload):
            self._steam_diff_cache = payload.get("diff", "")

        self.bus.on("steam_diff", cache_diff)

    def log(self, msg):
        self.log_view.append(msg)

    def update_score(self, score):
        self.score_label.setText(f"Behavior Score: {score}")

    def on_manual_scan(self):
        threading.Thread(target=self.manual_full_scan, daemon=True).start()

    def manual_full_scan(self):
        self.log("[MANUAL SCAN] Starting full scan...")
        # EventBus and MLManager will be injected later via global
        global WATCH_DIRS, GLOBAL_BUS, GLOBAL_ML
        for base in WATCH_DIRS:
            if not os.path.isdir(base):
                continue
            for root_dir, dirs, files in os.walk(base):
                for f in files:
                    full = os.path.join(root_dir, f)
                    if full.lower().endswith((".exe", ".dll")):
                        analyze_file(full, self, GLOBAL_BUS, GLOBAL_ML)
        self.log("[MANUAL SCAN] Done.")

    def on_toggle_fs(self):
        global AUTO_FS_WATCH
        AUTO_FS_WATCH = not AUTO_FS_WATCH
        state = "ON" if AUTO_FS_WATCH else "OFF"
        self.btn_toggle_fs.setText(f"FS Watch: {state}")
        self.log(f"[OVERRIDE] FS Watch set to {state}")

    def on_toggle_kill(self):
        global AUTO_KILL
        AUTO_KILL = not AUTO_KILL
        state = "ON" if AUTO_KILL else "OFF"
        self.btn_toggle_kill.setText(f"Auto-Kill: {state}")
        self.log(f"[OVERRIDE] Auto-Kill set to {state}")

    def on_show_diff(self):
        if not self._steam_diff_cache:
            self.log("[DIFF] No cached Steam diff.")
            return
        dlg = QtWidgets.QDialog(self)
        dlg.setWindowTitle("Steam Config Diff")
        layout = QtWidgets.QVBoxLayout(dlg)
        text = QtWidgets.QTextEdit()
        text.setReadOnly(True)
        text.setPlainText(self._steam_diff_cache)
        layout.addWidget(text)
        btn_close = QtWidgets.QPushButton("Close")
        btn_close.clicked.connect(dlg.accept)
        layout.addWidget(btn_close)
        dlg.resize(800, 600)
        dlg.exec()

# ==========================
# AUTONOMOUS LOOPS
# ==========================
def auto_kill_loop(gui, bus):
    while True:
        if AUTO_KILL:
            kill_suspicious_processes(gui, bus)
        time.sleep(10)

def suricata_eve_loop(gui, bus):
    while True:
        suricata_eve_stream(bus)
        time.sleep(30)

def start_threads(gui, bus, ml_manager):
    threading.Thread(target=fs_watch_loop, args=(gui, bus, ml_manager), daemon=True).start()
    threading.Thread(target=steam_session_monitor, args=(gui, bus, ml_manager), daemon=True).start()
    threading.Thread(target=auto_kill_loop, args=(gui, bus), daemon=True).start()
    threading.Thread(target=network_monitor_loop, args=(gui, bus), daemon=True).start()
    threading.Thread(target=kernel_event_loop, args=(gui, bus), daemon=True).start()
    threading.Thread(target=monitor_ssfn, args=(gui, bus), daemon=True).start()
    threading.Thread(target=suricata_live_socket_loop, args=(bus, gui), daemon=True).start()
    threading.Thread(target=suricata_eve_loop, args=(gui, bus), daemon=True).start()
    threading.Thread(target=backbone_streaming_loop, args=(bus, gui), daemon=True).start()

# ==========================
# GLOBALS FOR GUI CALLBACKS
# ==========================
GLOBAL_BUS = None
GLOBAL_ML = None

# ==========================
# MAIN
# ==========================
def main():
    global GLOBAL_BUS, GLOBAL_ML
    app = QtWidgets.QApplication(sys.argv)
    bus = EventBus()
    gui = GuardGUI(bus)
    GLOBAL_BUS = bus
    GLOBAL_ML = MLManager(gui, bus)
    gui.log("[INIT] Steam Malware Guard v5 started.")
    start_threads(gui, bus, GLOBAL_ML)
    gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
