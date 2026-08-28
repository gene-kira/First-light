#!/usr/bin/env python3
"""
Steam Malware Guard v4 – Kernel Privileges + ETW-style Events + Behavioral Scoring + Fluent GUI

Features:
- Autoloader (backbone style)
- Kernel privilege enable (AdjustTokenPrivileges stub)
- EventLog-based kernel event loop (ETW-style placeholder)
- Real-time filesystem watcher
- Entropy + string + name-based detection
- YARA rule engine + Suricata eve.json correlation (stubs)
- Network anomaly detection (new IPs, bursts, non-whitelisted)
- Process reputation (whitelist + blacklist)
- Behavioral scoring (events contribute to score, threshold triggers alerts)
- Steam-specific protection (loginusers.vdf, ssfn files, rollback)
- Fluent-style GUI (PySide6 dashboard with score + log)
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


import importlib
import subprocess
import sys

# ==========================
# AUTOLOADER (BACKBONE STYLE)
# ==========================
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

# Optional GPU
try:
    import torch
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
SURICATA_EVE_PATH = os.path.join(os.getcwd(), "eve.json")  # optional Suricata log

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

# ==========================
# HMAC UTILS
# ==========================
import hmac

def make_hmac(payload: str) -> str:
    return hmac.new(AUTH_SECRET, payload.encode("utf-8"), hashlib.sha256).hexdigest()

# ==========================
# PRIVILEGE ENABLE (STUB)
# ==========================
def enable_kernel_privileges(gui):
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
            gui.log("[PRIV] OpenProcessToken failed")
            return

        def enable_priv(name):
            luid = LUID()
            if not advapi32.LookupPrivilegeValueW(None, name, ctypes.byref(luid)):
                gui.log(f"[PRIV] LookupPrivilegeValueW failed for {name}")
                return
            tp = TOKEN_PRIVILEGES()
            tp.PrivilegeCount = 1
            tp.Privileges[0].Luid = luid
            tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
            if not advapi32.AdjustTokenPrivileges(hToken, False,
                                                  ctypes.byref(tp),
                                                  0, None, None):
                gui.log(f"[PRIV] AdjustTokenPrivileges failed for {name}")
            else:
                gui.log(f"[PRIV] Enabled {name}")

        enable_priv("SeSecurityPrivilege")
        enable_priv("SeAuditPrivilege")
    except Exception as e:
        gui.log(f"[PRIV ERROR] {e}")

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
            t = torch.tensor(list(data), dtype=torch.float32, device="cuda")
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
# YARA / SURICATA STUBS
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

def suricata_correlate():
    if not os.path.isfile(SURICATA_EVE_PATH):
        return []
    try:
        events = []
        with open(SURICATA_EVE_PATH, "r", errors="ignore") as f:
            for line in f:
                try:
                    ev = json.loads(line)
                    events.append(ev)
                except:
                    continue
        return events
    except Exception:
        return []

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

def add_behavior_score(gui, delta, reason):
    global BEHAVIOR_SCORE
    BEHAVIOR_SCORE += delta
    gui.update_score(BEHAVIOR_SCORE)
    gui.log(f"[SCORE] +{delta} ({reason}) → {BEHAVIOR_SCORE}")
    if BEHAVIOR_SCORE >= SCORE_THRESHOLD:
        gui.log("[ALERT] Behavior score threshold exceeded – aggressive actions enabled.")
        send_to_backbone("ALERT_THRESHOLD", {"score": BEHAVIOR_SCORE, "reason": reason})

# ==========================
# SANDBOX STUB
# ==========================
def sandbox_mark(path, gui):
    gui.log(f"[SANDBOX] Marked {path} as sandboxed (no execution).")

# ==========================
# AUTO-ROLLBACK FOR STEAM
# ==========================
def backup_steam_config(gui):
    if os.path.isfile(STEAM_CONFIG):
        try:
            if not os.path.isfile(STEAM_CONFIG_BACKUP):
                with open(STEAM_CONFIG, "rb") as src, open(STEAM_CONFIG_BACKUP, "wb") as dst:
                    dst.write(src.read())
                gui.log("[ROLLBACK] Steam config backup created.")
        except Exception as e:
            gui.log(f"[ROLLBACK ERROR] {e}")

def rollback_steam_config(gui):
    if os.path.isfile(STEAM_CONFIG_BACKUP):
        try:
            with open(STEAM_CONFIG_BACKUP, "rb") as src, open(STEAM_CONFIG, "wb") as dst:
                dst.write(src.read())
            gui.log("[ROLLBACK] Steam config restored from backup.")
        except Exception as e:
            gui.log(f"[ROLLBACK ERROR] {e}")

def monitor_ssfn(gui):
    if not os.path.isdir(STEAM_SSFN_DIR):
        return
    while True:
        try:
            for f in os.listdir(STEAM_SSFN_DIR):
                if f.lower().startswith("ssfn"):
                    path = os.path.join(STEAM_SSFN_DIR, f)
                    gui.log(f"[STEAM] ssfn file present: {path}")
            time.sleep(60)
        except Exception as e:
            gui.log(f"[STEAM SSFN ERROR] {e}")
            time.sleep(60)

# ==========================
# PROCESS REPUTATION + AUTO-KILL
# ==========================
def is_whitelisted_proc(name):
    return name.lower() in WHITELIST_PROCS

def kill_suspicious_processes(gui):
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
                add_behavior_score(gui, 2, "Unknown process killed")
                send_to_backbone("PROCESS_KILLED", {"pid": proc.pid, "name": name})
        except Exception as e:
            gui.log(f"[AUTO-KILL ERROR] {e}")

# ==========================
# ANALYSIS + ACTION
# ==========================
def quarantine(path, gui):
    try:
        dest = os.path.join(QUARANTINE_DIR, os.path.basename(path))
        os.replace(path, dest)
        return dest
    except Exception as e:
        gui.log(f"[QUARANTINE ERROR] {e}")
        return path

def analyze_file(path, gui):
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

    if name_flag or string_flag or ent_flag or yara_hits:
        gui.log(f"[SUSPICIOUS FILE] {path}")
        gui.log(f"  SHA256={sha}")
        gui.log(f"  entropy={ent:.2f} (flag={ent_flag})")
        gui.log(f"  name_flag={name_flag}, string_flag={string_flag}")
        if yara_hits:
            gui.log(f"  YARA hits={yara_hits}")
        gui.log(f"  VT={vt}")
        sandbox_mark(path, gui)
        qpath = quarantine(path, gui)
        gui.log(f"  → QUARANTINED: {qpath}")
        add_behavior_score(gui, 3, "Suspicious file drop")
        if ent_flag:
            add_behavior_score(gui, 2, "High entropy file")
        if yara_hits:
            add_behavior_score(gui, 5, "YARA hit")
        send_to_backbone("FILE_QUARANTINED", {
            "path": path,
            "sha256": sha,
            "entropy": ent,
            "yara": yara_hits,
        })

# ==========================
# REAL-TIME FS WATCHER
# ==========================
class MalwareEventHandler(FileSystemEventHandler):
    def __init__(self, gui):
        super().__init__()
        self.gui = gui

    def on_created(self, event):
        if not AUTO_FS_WATCH:
            return
        if event.is_directory:
            return
        path = event.src_path
        if not path.lower().endswith((".exe", ".dll")):
            return
        analyze_file(path, self.gui)

def fs_watch_loop(gui):
    observer = Observer()
    handler = MalwareEventHandler(gui)
    for d in WATCH_DIRS:
        if os.path.isdir(d):
            observer.schedule(handler, d, recursive=True)
    observer.start()
    gui.log("[FS WATCH] Started.")
    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()

# ==========================
# KERNEL EVENT LOOP (EventLog stub)
# ==========================
def kernel_event_loop(gui):
    enable_kernel_privileges(gui)
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
                    add_behavior_score(gui, 5, "Kernel anomaly")
                    send_to_backbone("KERNEL_EVENT", {"log": log_type, "id": ev.EventID})
            time.sleep(30)
        except Exception as e:
            gui.log(f"[KERNEL ERROR] {e}")
            time.sleep(30)

# ==========================
# STEAM SESSION MONITOR
# ==========================
def steam_session_monitor(gui):
    backup_steam_config(gui)
    last_size = None
    while True:
        if os.path.isfile(STEAM_CONFIG):
            size = os.path.getsize(STEAM_CONFIG)
            if last_size is not None and size != last_size:
                gui.log(f"[STEAM SESSION] loginusers.vdf size changed: {last_size} -> {size}")
                rollback_steam_config(gui)
                add_behavior_score(gui, 4, "Steam config change")
                send_to_backbone("STEAM_ROLLBACK", {"old_size": last_size, "new_size": size})
            last_size = size
        time.sleep(10)

# ==========================
# NETWORK ANOMALY DETECTION
# ==========================
def is_local_ip(ip):
    return ip.startswith("10.") or ip.startswith("192.168.") or ip.startswith("172.16.")

def network_monitor_loop(gui):
    while True:
        try:
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

                if ip not in SEEN_IPS:
                    SEEN_IPS.add(ip)
                    gui.log(f"[NET NEW] {host}")
                    add_behavior_score(gui, 3, "New remote IP")
                    send_to_backbone("NET_NEW_IP", {"ip": ip, "port": port})

                if IP_COUNTS[ip] > 50:
                    gui.log(f"[NET BURST] {host} count={IP_COUNTS[ip]}")
                    add_behavior_score(gui, 3, "High-frequency outbound")
        except Exception as e:
            gui.log(f"[NET ERROR] {e}")
        time.sleep(10)

# ==========================
# GUI – FLUENT-STYLE DASHBOARD
# ==========================
class GuardGUI(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Steam Malware Guard v4")
        self.resize(1200, 700)
        self.setStyleSheet("""
            QMainWindow { background-color: #202020; }
            QTextEdit { background-color: #1e1e1e; color: #dcdcdc; font-family: Consolas; }
            QPushButton { background-color: #2d2d2d; color: #ffffff; padding: 6px; border-radius: 4px; }
            QPushButton:hover { background-color: #3a3a3a; }
            QLabel { color: #ffffff; }
        """)

        central = QtWidgets.QWidget()
        self.setCentralWidget(central)
        layout = QtWidgets.QVBoxLayout(central)

        top_bar = QtWidgets.QHBoxLayout()
        self.btn_manual_scan = QtWidgets.QPushButton("Manual Full Scan")
        self.btn_toggle_fs = QtWidgets.QPushButton("Toggle FS Watch (ON)")
        self.btn_toggle_kill = QtWidgets.QPushButton("Toggle Auto-Kill (ON)")
        self.score_label = QtWidgets.QLabel("Behavior Score: 0")
        top_bar.addWidget(self.btn_manual_scan)
        top_bar.addWidget(self.btn_toggle_fs)
        top_bar.addWidget(self.btn_toggle_kill)
        top_bar.addWidget(self.score_label)

        layout.addLayout(top_bar)

        self.log_view = QtWidgets.QTextEdit()
        self.log_view.setReadOnly(True)
        layout.addWidget(self.log_view)

        self.btn_manual_scan.clicked.connect(self.on_manual_scan)
        self.btn_toggle_fs.clicked.connect(self.on_toggle_fs)
        self.btn_toggle_kill.clicked.connect(self.on_toggle_kill)

    def log(self, msg):
        self.log_view.append(msg)

    def update_score(self, score):
        self.score_label.setText(f"Behavior Score: {score}")

    def on_manual_scan(self):
        threading.Thread(target=self.manual_full_scan, daemon=True).start()

    def manual_full_scan(self):
        self.log("[MANUAL SCAN] Starting full scan...")
        for base in WATCH_DIRS:
            if not os.path.isdir(base):
                continue
            for root_dir, dirs, files in os.walk(base):
                for f in files:
                    full = os.path.join(root_dir, f)
                    if full.lower().endswith((".exe", ".dll")):
                        analyze_file(full, self)
        self.log("[MANUAL SCAN] Done.")

    def on_toggle_fs(self):
        global AUTO_FS_WATCH
        AUTO_FS_WATCH = not AUTO_FS_WATCH
        state = "ON" if AUTO_FS_WATCH else "OFF"
        self.btn_toggle_fs.setText(f"Toggle FS Watch ({state})")
        self.log(f"[OVERRIDE] FS Watch set to {state}")

    def on_toggle_kill(self):
        global AUTO_KILL
        AUTO_KILL = not AUTO_KILL
        state = "ON" if AUTO_KILL else "OFF"
        self.btn_toggle_kill.setText(f"Toggle Auto-Kill ({state})")
        self.log(f"[OVERRIDE] Auto-Kill set to {state}")

# ==========================
# AUTONOMOUS LOOPS
# ==========================
def auto_kill_loop(gui):
    while True:
        if AUTO_KILL:
            kill_suspicious_processes(gui)
        time.sleep(10)

def start_threads(gui):
    threading.Thread(target=fs_watch_loop, args=(gui,), daemon=True).start()
    threading.Thread(target=steam_session_monitor, args=(gui,), daemon=True).start()
    threading.Thread(target=auto_kill_loop, args=(gui,), daemon=True).start()
    threading.Thread(target=network_monitor_loop, args=(gui,), daemon=True).start()
    threading.Thread(target=kernel_event_loop, args=(gui,), daemon=True).start()
    threading.Thread(target=monitor_ssfn, args=(gui,), daemon=True).start()

# ==========================
# MAIN
# ==========================
def main():
    app = QtWidgets.QApplication(sys.argv)
    gui = GuardGUI()
    gui.log("[INIT] Steam Malware Guard v4 started.")
    start_threads(gui)
    gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
