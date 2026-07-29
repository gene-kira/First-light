#!/usr/bin/env python3
# Security Daemon v10 – Mode C (Full Manual + Honeypot Auto-Containment)
# killer666 edition – unified monolithic architecture

import sys
import os
import time
import json
import threading
import importlib
import subprocess
import hashlib
from datetime import datetime

# ----------------- AUTOLOADER -----------------

REQUIRED_LIBS = [
    "PyQt6",
    "cryptography",
    "psutil",
    "scapy",          # packet capture stub
    "torch",          # GPU ML stub
]

def autoload_libraries():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            except Exception:
                pass
    globals().update({lib: importlib.import_module(lib) for lib in REQUIRED_LIBS if lib in sys.modules or importlib.util.find_spec(lib)})

autoload_libraries()

from PyQt6 import QtWidgets, QtCore, QtGui
from cryptography.fernet import Fernet
import psutil

# Optional imports (best-effort)
try:
    from scapy.all import sniff
except Exception:
    sniff = None

try:
    import torch
except Exception:
    torch = None

# ----------------- GLOBAL PATHS / SETTINGS / PERSISTENCE -----------------

BASE_DIR = os.path.dirname(os.path.abspath(__file__))

LOG_KEY_PATH        = os.path.join(BASE_DIR, "logkey.bin")
ENC_LOG_PATH        = os.path.join(BASE_DIR, "secure.log.enc")
SETTINGS_PATH       = os.path.join(BASE_DIR, "settings.json")
RULES_PATH          = os.path.join(BASE_DIR, "rules.json")
QUARANTINE_DIR      = os.path.join(BASE_DIR, "quarantine")
HONEYPOT_STATE_PATH = os.path.join(BASE_DIR, "honeypot_state.json")
PENDING_PATH        = os.path.join(BASE_DIR, "pending_decisions.json")
GLYPHS_PATH         = os.path.join(BASE_DIR, "resurrection_glyphs.json")

os.makedirs(QUARANTINE_DIR, exist_ok=True)

DEFAULT_SETTINGS = {
    "theme": "dark",
    "auto_quarantine": False,   # Mode C: no auto-quarantine
    "notify_blocks": True,
    "gui_update_interval_ms": 15000,  # 15 seconds GUI refresh
}

DEFAULT_RULES = {
    "blocked_paths": [],
    "blocked_ips": [],
    "blocked_hashes": [],
    "blocked_ports": [],
    "suspicious_patterns": [
        {"pattern": "temp", "score": 10},
        {"pattern": "appdata", "score": 10},
        {"pattern": "downloads", "score": 10}
    ],
    "max_score_honeypot": 60,       # above this -> auto honeypot redirect
    "max_score_recommend_kill": 80, # recommendation only, manual
    "max_score_recommend_quar": 100 # recommendation only, manual
}

CORE_STATUS    = {"state": "STOPPED", "error": ""}
WATCHER_STATUS = {"state": "STOPPED", "error": ""}

PROCESS_CACHE  = {}
NETWORK_CACHE  = {}

PENDING_DECISIONS = []   # in-memory queue, persisted to PENDING_PATH
HONEYPOT_STATE    = {}   # persisted to HONEYPOT_STATE_PATH
RESURRECTION_GLYPHS = {} # persisted to GLYPHS_PATH

def load_json(path, default):
    if not os.path.exists(path):
        save_json(path, default)
        return default.copy()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in default.items():
            if k not in data:
                data[k] = v
        return data
    except Exception:
        return default.copy()

def save_json(path, data):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception:
        pass

SETTINGS = load_json(SETTINGS_PATH, DEFAULT_SETTINGS)
RULES    = load_json(RULES_PATH, DEFAULT_RULES)

HONEYPOT_STATE    = load_json(HONEYPOT_STATE_PATH, {})
RESURRECTION_GLYPHS = load_json(GLYPHS_PATH, {})
PENDING_DECISIONS = load_json(PENDING_PATH, [])

def persist_pending():
    save_json(PENDING_PATH, PENDING_DECISIONS)

def persist_honeypot():
    save_json(HONEYPOT_STATE_PATH, HONEYPOT_STATE)

def persist_glyphs():
    save_json(GLYPHS_PATH, RESURRECTION_GLYPHS)

# ----------------- LOGGING / CRYPTO -----------------

def load_log_key():
    if not os.path.exists(LOG_KEY_PATH):
        key = Fernet.generate_key()
        with open(LOG_KEY_PATH, "wb") as f:
            f.write(key)
        return key
    return open(LOG_KEY_PATH, "rb").read()

LOG_KEY    = load_log_key()
LOG_CIPHER = Fernet(LOG_KEY)

def enc_log(message: str, level: str = "INFO"):
    ts = time.strftime('%Y-%m-%d %H:%M:%S')
    data = f"[{ts}] [{level}] {message}".encode()
    try:
        token = LOG_CIPHER.encrypt(data)
        with open(ENC_LOG_PATH, "ab") as f:
            f.write(token + b"\n")
    except Exception:
        pass

def tail_decrypted_logs(max_lines=500):
    if not os.path.exists(ENC_LOG_PATH):
        return []
    lines = []
    with open(ENC_LOG_PATH, "rb") as f:
        data = f.readlines()
    for line in data[-max_lines:]:
        try:
            dec = LOG_CIPHER.decrypt(line.strip()).decode(errors="ignore")
            lines.append(dec)
        except Exception:
            continue
    return lines

# ----------------- UTILS -----------------

def file_hash(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def quarantine_file(path):
    try:
        if not os.path.exists(path):
            return None
        h = file_hash(path)
        if h is None:
            return None
        base = os.path.basename(path)
        qname = f"{base}.{h[:8]}.quar"
        qpath = os.path.join(QUARANTINE_DIR, qname)
        os.rename(path, qpath)
        enc_log(f"QUARANTINE file={path} -> {qpath}", "WARN")
        return qpath
    except Exception as e:
        enc_log(f"QUARANTINE ERROR path={path} err={e}", "ERROR")
        return None

def kill_pid(pid):
    try:
        psutil.Process(pid).terminate()
        enc_log(f"KILL pid={pid}", "WARN")
    except Exception as e:
        enc_log(f"KILL ERROR pid={pid} err={e}", "ERROR")

def get_proc_path(proc):
    try:
        return proc.exe()
    except Exception:
        return None

def get_proc_cmdline(proc):
    try:
        return " ".join(proc.cmdline())
    except Exception:
        return ""

def get_proc_parent(proc):
    try:
        p = proc.parent()
        return p.pid if p else None
    except Exception:
        return None

def get_proc_create_time(proc):
    try:
        ct = proc.create_time()
        return datetime.fromtimestamp(ct).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        return ""

# ----------------- HONEYPOT / RESURRECTION GLYPHS -----------------

def honeypot_redirect(event):
    """
    Mode C: auto-containment via honeypot only.
    We mark the process as redirected; real emulation can be added later.
    """
    pid = event.get("pid")
    path = event.get("path", "")
    cmdline = event.get("cmdline", "")
    key = f"{pid}:{path}"
    HONEYPOT_STATE[key] = {
        "pid": pid,
        "path": path,
        "cmdline": cmdline,
        "timestamp": time.time(),
        "status": "redirected"
    }
    persist_honeypot()
    enc_log(f"HONEYPOT_REDIRECT pid={pid} path={path}", "WARN")

def track_resurrection(pid, path):
    """
    Resurrection glyphs: track processes that reappear after kill/quarantine.
    """
    key = f"{pid}:{path}"
    glyph = RESURRECTION_GLYPHS.get(key, {"count": 0, "last_seen": 0})
    glyph["count"] += 1
    glyph["last_seen"] = time.time()
    RESURRECTION_GLYPHS[key] = glyph
    persist_glyphs()
    enc_log(f"RESURRECTION_GLYPH pid={pid} path={path} count={glyph['count']}", "INFO")

# ----------------- GPU ML ANOMALY DETECTION (STUB) -----------------

def ml_score_process(path, cmdline, parent_pid):
    """
    Stub ML scoring. If torch is available, we could build a real model.
    For now, we just add a small heuristic bonus.
    """
    bonus = 0
    if "powershell" in cmdline.lower() or "cmd.exe" in cmdline.lower():
        bonus += 5
    if "python" in cmdline.lower():
        bonus += 3
    return bonus, ["ml_stub_bonus"]

def ml_score_network(remote_ip, remote_port):
    bonus = 0
    if remote_port in (4444, 8080):
        bonus += 5
    return bonus, ["ml_stub_bonus"]

# ----------------- SURICATA / PACKET CAPTURE STUBS -----------------

def suricata_score(event):
    """
    Stub for Suricata v6 rule integration.
    In a real build, this would parse alerts and correlate with process/network.
    """
    return 0, []

def start_packet_capture():
    """
    Stub for packet capture using scapy.
    """
    if sniff is None:
        enc_log("PACKET_CAPTURE not available (scapy missing)", "WARN")
        return

    def _capture():
        try:
            sniff(count=0, store=False)
        except Exception as e:
            enc_log(f"PACKET_CAPTURE ERROR {e}", "ERROR")

    threading.Thread(target=_capture, daemon=True).start()
    enc_log("PACKET_CAPTURE STARTED", "INFO")

# ----------------- KERNEL DRIVER / ETW STUBS -----------------

def init_kernel_stubs():
    enc_log("KERNEL_STUBS initialized (placeholder)", "INFO")

def init_etw_hooks():
    enc_log("ETW_HOOKS initialized (placeholder)", "INFO")

# ----------------- RULE ENGINE / THREAT SCORING -----------------

def score_process(path, cmdline, parent_pid):
    score = 0
    reasons = []

    # Path rules
    for b in RULES["blocked_paths"]:
        if b.lower() in path.lower():
            score += 50
            reasons.append(f"path matches blocked pattern: {b}")

    # Suspicious patterns
    for sp in RULES["suspicious_patterns"]:
        pat = sp.get("pattern", "")
        val = sp.get("score", 0)
        if pat and pat.lower() in path.lower():
            score += val
            reasons.append(f"path contains suspicious pattern: {pat} (+{val})")
        if pat and pat.lower() in cmdline.lower():
            score += val
            reasons.append(f"cmdline contains suspicious pattern: {pat} (+{val})")

    # Parent process heuristic
    if parent_pid in (0, 1, None):
        score += 5
        reasons.append("no valid parent process (+5)")

    # ML bonus
    ml_bonus, ml_reasons = ml_score_process(path, cmdline, parent_pid)
    score += ml_bonus
    reasons.extend(ml_reasons)

    # Suricata stub
    sur_score, sur_reasons = suricata_score({"type": "exec", "path": path, "cmdline": cmdline})
    score += sur_score
    reasons.extend(sur_reasons)

    return score, reasons

def score_network(remote_ip, remote_port):
    score = 0
    reasons = []

    # IP rules
    for ip in RULES["blocked_ips"]:
        if ip == remote_ip:
            score += 50
            reasons.append(f"remote IP blocked: {ip}")

    # Port rules
    for port in RULES["blocked_ports"]:
        if port == remote_port:
            score += 30
            reasons.append(f"remote port blocked: {port}")

    # High-risk ports
    if remote_port in (22, 23, 445, 3389):
        score += 10
        reasons.append(f"high-risk port: {remote_port} (+10)")

    # ML bonus
    ml_bonus, ml_reasons = ml_score_network(remote_ip, remote_port)
    score += ml_bonus
    reasons.extend(ml_reasons)

    # Suricata stub
    sur_score, sur_reasons = suricata_score({"type": "net", "remote_ip": remote_ip, "remote_port": remote_port})
    score += sur_score
    reasons.extend(sur_reasons)

    return score, reasons

def core_decide_exec(event):
    path       = event.get("path", "")
    pid        = event.get("pid")
    cmdline    = event.get("cmdline", "")
    parent_pid = event.get("parent_pid")

    score, reasons = score_process(path, cmdline, parent_pid)

    # Mode C: no auto-kill/quarantine. We only recommend and possibly honeypot.
    decision = {
        "allow": True,
        "score": score,
        "reasons": reasons,
        "recommended_action": "allow",
        "type": "exec",
        "pid": pid,
        "path": path,
        "cmdline": cmdline,
        "parent_pid": parent_pid,
        "honeypot_redirect": False,
    }

    if score >= RULES["max_score_recommend_quar"]:
        decision["recommended_action"] = "quarantine"
    elif score >= RULES["max_score_recommend_kill"]:
        decision["recommended_action"] = "kill"
    elif score >= RULES["max_score_honeypot"]:
        decision["recommended_action"] = "honeypot"

    if score >= RULES["max_score_honeypot"]:
        decision["honeypot_redirect"] = True

    enc_log(f"EXEC DECISION pid={pid} path={path} score={score} rec_action={decision['recommended_action']} reasons={reasons}", "INFO")
    return decision

def core_decide_net(event):
    path  = event.get("path", "")
    pid   = event.get("pid")
    rip   = event.get("remote_ip", "")
    rport = event.get("remote_port")

    score, reasons = score_network(rip, rport)

    decision = {
        "allow": True,
        "score": score,
        "reasons": reasons,
        "recommended_action": "allow",
        "type": "net",
        "pid": pid,
        "path": path,
        "remote_ip": rip,
        "remote_port": rport,
        "honeypot_redirect": False,
    }

    if score >= RULES["max_score_recommend_quar"]:
        decision["recommended_action"] = "quarantine"
    elif score >= RULES["max_score_recommend_kill"]:
        decision["recommended_action"] = "kill"
    elif score >= RULES["max_score_honeypot"]:
        decision["recommended_action"] = "honeypot"

    if score >= RULES["max_score_honeypot"]:
        decision["honeypot_redirect"] = True

    enc_log(f"NET DECISION pid={pid} ip={rip} port={rport} score={score} rec_action={decision['recommended_action']} reasons={reasons}", "INFO")
    return decision

def enqueue_decision(decision):
    """
    Mode C: AI only enqueues decisions. You choose kill/quarantine/ignore in GUI.
    """
    decision["timestamp"] = time.time()
    PENDING_DECISIONS.append(decision)
    persist_pending()
    enc_log(f"ENQUEUE_DECISION type={decision['type']} pid={decision.get('pid')} rec_action={decision['recommended_action']}", "INFO")

# ----------------- CORE LOOP -----------------

def core_loop():
    global CORE_STATUS
    CORE_STATUS["state"] = "RUNNING"
    enc_log("CORE START", "INFO")
    try:
        init_kernel_stubs()
        init_etw_hooks()
        start_packet_capture()
        while True:
            time.sleep(1.0)
    except Exception as e:
        CORE_STATUS["state"] = "ERROR"
        CORE_STATUS["error"] = str(e)
        enc_log(f"CORE ERROR {e}", "ERROR")

# ----------------- WATCHER -----------------

known_pids     = set()
baseline_done  = False

def baseline_scan():
    global known_pids, baseline_done
    if baseline_done:
        return
    enc_log("WATCHER BASELINE START", "INFO")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            path = get_proc_path(proc)
            if not path:
                continue
            cmdline    = get_proc_cmdline(proc)
            parent_pid = get_proc_parent(proc)
            event = {
                "type": "exec",
                "pid": proc.pid,
                "path": path,
                "cmdline": cmdline,
                "parent_pid": parent_pid
            }
            decision = core_decide_exec(event)
            if decision.get("honeypot_redirect"):
                honeypot_redirect(event)
            enqueue_decision(decision)
            known_pids.add(proc.pid)
        except Exception:
            continue
    baseline_done = True
    enc_log("WATCHER BASELINE DONE", "INFO")

def monitor_processes():
    global known_pids
    while True:
        current_pids = set()
        for proc in psutil.process_iter(['pid', 'name']):
            pid = proc.pid
            current_pids.add(pid)
            if pid not in known_pids:
                try:
                    path = get_proc_path(proc)
                    if not path:
                        continue
                    cmdline    = get_proc_cmdline(proc)
                    parent_pid = get_proc_parent(proc)
                    event = {
                        "type": "exec",
                        "pid": pid,
                        "path": path,
                        "cmdline": cmdline,
                        "parent_pid": parent_pid
                    }
                    decision = core_decide_exec(event)
                    if decision.get("honeypot_redirect"):
                        honeypot_redirect(event)
                    enqueue_decision(decision)
                    known_pids.add(pid)
                except Exception:
                    continue
        # detect resurrection
        resurrected = known_pids.intersection(current_pids)
        for pid in resurrected:
            try:
                proc = psutil.Process(pid)
                path = get_proc_path(proc) or ""
                track_resurrection(pid, path)
            except Exception:
                continue
        known_pids = current_pids
        time.sleep(1.0)

def monitor_network():
    while True:
        try:
            conns = psutil.net_connections(kind='inet')
            for c in conns:
                pid = c.pid
                if pid is None:
                    continue
                if c.raddr and c.status == psutil.CONN_ESTABLISHED:
                    try:
                        proc = psutil.Process(pid)
                        path = get_proc_path(proc)
                        if not path:
                            continue
                    except Exception:
                        continue
                    event = {
                        "type": "net",
                        "pid": pid,
                        "path": path,
                        "remote_ip": c.raddr.ip,
                        "remote_port": c.raddr.port
                    }
                    decision = core_decide_net(event)
                    if decision.get("honeypot_redirect"):
                        honeypot_redirect(event)
                    enqueue_decision(decision)
        except Exception:
            pass
        time.sleep(1.0)

def watcher_loop():
    global WATCHER_STATUS
    WATCHER_STATUS["state"] = "RUNNING"
    enc_log("WATCHER START", "INFO")
    try:
        baseline_scan()
        threading.Thread(target=monitor_processes, daemon=True).start()
        threading.Thread(target=monitor_network, daemon=True).start()
        while True:
            time.sleep(5.0)
    except Exception as e:
        WATCHER_STATUS["state"] = "ERROR"
        WATCHER_STATUS["error"] = str(e)
        enc_log(f"WATCHER ERROR {e}", "ERROR")

# ----------------- SETTINGS / RULES DIALOGS -----------------

class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")

        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; }
            QLabel { color: white; }
            QPlainTextEdit { color: white; background-color: #202020; border: 1px solid #404040; }
            QComboBox { color: white; background-color: #303030; border: 1px solid #505050; }
            QCheckBox { color: white; }
            QSpinBox { color: white; background-color: #202020; border: 1px solid #404040; }
            QPushButton { color: white; background-color: #404040; border: 1px solid #606060; padding: 4px; }
        """)

        layout = QtWidgets.QFormLayout()

        self.cmb_theme = QtWidgets.QComboBox()
        self.cmb_theme.addItems(["dark", "light"])
        self.cmb_theme.setCurrentText(SETTINGS.get("theme", "dark"))

        self.chk_notify = QtWidgets.QCheckBox("Enable block notifications")
        self.chk_notify.setChecked(SETTINGS.get("notify_blocks", True))

        self.spin_gui = QtWidgets.QSpinBox()
        self.spin_gui.setRange(1000, 60000)
        self.spin_gui.setValue(SETTINGS.get("gui_update_interval_ms", 15000))

        layout.addRow("Theme:", self.cmb_theme)
        layout.addRow(self.chk_notify)
        layout.addRow("GUI update interval (ms):", self.spin_gui)

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok |
            QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

        self.setLayout(layout)

    def get_settings(self):
        return {
            "theme": self.cmb_theme.currentText(),
            "auto_quarantine": False,  # Mode C hard-coded
            "notify_blocks": self.chk_notify.isChecked(),
            "gui_update_interval_ms": self.spin_gui.value()
        }

class RulesDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Rules")

        self.setStyleSheet("""
            QDialog { background-color: #1e1e1e; }
            QLabel { color: white; }
            QPlainTextEdit { color: white; background-color: #202020; border: 1px solid #404040; }
            QSpinBox { color: white; background-color: #202020; border: 1px solid #404040; }
            QPushButton { color: white; background-color: #404040; border: 1px solid #606060; padding: 4px; }
        """)

        layout = QtWidgets.QFormLayout()

        self.txt_paths = QtWidgets.QPlainTextEdit()
        self.txt_paths.setPlainText("\n".join(RULES["blocked_paths"]))

        self.txt_ips = QtWidgets.QPlainTextEdit()
        self.txt_ips.setPlainText("\n".join(RULES["blocked_ips"]))

        self.txt_ports = QtWidgets.QPlainTextEdit()
        self.txt_ports.setPlainText("\n".join(str(p) for p in RULES["blocked_ports"]))

        self.spin_honeypot = QtWidgets.QSpinBox()
        self.spin_honeypot.setRange(0, 200)
        self.spin_honeypot.setValue(RULES["max_score_honeypot"])

        self.spin_kill = QtWidgets.QSpinBox()
        self.spin_kill.setRange(0, 200)
        self.spin_kill.setValue(RULES["max_score_recommend_kill"])

        self.spin_quar = QtWidgets.QSpinBox()
        self.spin_quar.setRange(0, 200)
        self.spin_quar.setValue(RULES["max_score_recommend_quar"])

        layout.addRow("Blocked paths:", self.txt_paths)
        layout.addRow("Blocked IPs:", self.txt_ips)
        layout.addRow("Blocked ports:", self.txt_ports)
        layout.addRow("Score threshold (honeypot):", self.spin_honeypot)
        layout.addRow("Score threshold (recommend kill):", self.spin_kill)
        layout.addRow("Score threshold (recommend quarantine):", self.spin_quar)

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok |
            QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

        self.setLayout(layout)

    def get_rules(self):
        paths = [l.strip() for l in self.txt_paths.toPlainText().splitlines() if l.strip()]
        ips   = [l.strip() for l in self.txt_ips.toPlainText().splitlines() if l.strip()]
        ports = []
        for l in self.txt_ports.toPlainText().splitlines():
            l = l.strip()
            if not l:
                continue
            try:
                ports.append(int(l))
            except ValueError:
                continue
        return {
            "blocked_paths": paths,
            "blocked_ips": ips,
            "blocked_ports": ports,
            "blocked_hashes": RULES.get("blocked_hashes", []),
            "suspicious_patterns": RULES.get("suspicious_patterns", []),
            "max_score_honeypot": self.spin_honeypot.value(),
            "max_score_recommend_kill": self.spin_kill.value(),
            "max_score_recommend_quar": self.spin_quar.value()
        }

# ----------------- GUI (Status + Pending Decisions + Integrity Watchdog) -----------------

class StatusGUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Daemon v10 – Mode C Dashboard")
        self.setGeometry(200, 200, 1200, 750)

        self.theme = SETTINGS.get("theme", "dark")
        self.apply_theme()

        main_layout = QtWidgets.QVBoxLayout()

        # Top status bar
        status_layout = QtWidgets.QHBoxLayout()
        self.lbl_core        = QtWidgets.QLabel("Core: STOPPED")
        self.lbl_watcher     = QtWidgets.QLabel("Watcher: STOPPED")
        self.lbl_core_err    = QtWidgets.QLabel("")
        self.lbl_watcher_err = QtWidgets.QLabel("")
        self.lbl_cpu         = QtWidgets.QLabel("CPU: 0%")
        self.lbl_mem         = QtWidgets.QLabel("Memory: 0%")
        self.lbl_watchdog    = QtWidgets.QLabel("GUI Watchdog: ACTIVE")

        for lbl in [self.lbl_core, self.lbl_watcher, self.lbl_core_err,
                    self.lbl_watcher_err, self.lbl_cpu, self.lbl_mem, self.lbl_watchdog]:
            lbl.setStyleSheet("font-size: 13px; color: white;")
            status_layout.addWidget(lbl)

        main_layout.addLayout(status_layout)

        # Controls
        ctrl_layout = QtWidgets.QHBoxLayout()
        self.btn_settings = QtWidgets.QPushButton("Settings")
        self.btn_settings.clicked.connect(self.open_settings)
        self.btn_rules = QtWidgets.QPushButton("Rules")
        self.btn_rules.clicked.connect(self.open_rules)
        self.txt_pid = QtWidgets.QLineEdit()
        self.txt_pid.setPlaceholderText("PID to kill (manual)")
        self.btn_kill = QtWidgets.QPushButton("Kill PID")
        self.btn_kill.clicked.connect(self.kill_pid_from_gui)
        ctrl_layout.addWidget(self.btn_settings)
        ctrl_layout.addWidget(self.btn_rules)
        ctrl_layout.addWidget(self.txt_pid)
        ctrl_layout.addWidget(self.btn_kill)
        main_layout.addLayout(ctrl_layout)

        # Tabs
        self.tabs = QtWidgets.QTabWidget()
        self.tabs.setStyleSheet(
            "QTabWidget::pane { border: 1px solid #404040; } "
            "QTabBar::tab { color: white; background: #303030; padding: 6px; } "
            "QTabBar::tab:selected { background: #505050; }"
        )

        # Overview tab (pending decisions)
        self.tab_overview = QtWidgets.QWidget()
        ov_layout = QtWidgets.QVBoxLayout()
        self.lst_pending = QtWidgets.QTableWidget()
        self.lst_pending.setColumnCount(7)
        self.lst_pending.setHorizontalHeaderLabels(
            ["Type", "PID", "Path/IP", "Score", "Recommended", "Timestamp", "Action"]
        )
        self.lst_pending.horizontalHeader().setStretchLastSection(True)
        self.lst_pending.setStyleSheet(
            "QTableWidget { color: white; background-color: #202020; gridline-color: #404040; } "
            "QHeaderView::section { background-color: #303030; color: white; }"
        )
        ov_layout.addWidget(QtWidgets.QLabel("Pending decisions (manual YES/NO):"))
        ov_layout.addWidget(self.lst_pending)
        self.tab_overview.setLayout(ov_layout)

        # Processes tab
        self.tab_processes = QtWidgets.QWidget()
        proc_layout = QtWidgets.QVBoxLayout()
        self.tbl_procs = QtWidgets.QTableWidget()
        self.tbl_procs.setColumnCount(7)
        self.tbl_procs.setHorizontalHeaderLabels(["PID", "Name", "Path", "CPU%", "Mem%", "Parent", "Start"])
        self.tbl_procs.horizontalHeader().setStretchLastSection(True)
        self.tbl_procs.setStyleSheet(
            "QTableWidget { color: white; background-color: #202020; gridline-color: #404040; } "
            "QHeaderView::section { background-color: #303030; color: white; }"
        )
        proc_layout.addWidget(self.tbl_procs)
        self.tab_processes.setLayout(proc_layout)

        # Network tab
        self.tab_network = QtWidgets.QWidget()
        net_layout = QtWidgets.QVBoxLayout()
        self.tbl_net = QtWidgets.QTableWidget()
        self.tbl_net.setColumnCount(6)
        self.tbl_net.setHorizontalHeaderLabels(["PID", "Process", "Local", "Remote", "Status", "Family"])
        self.tbl_net.horizontalHeader().setStretchLastSection(True)
        self.tbl_net.setStyleSheet(
            "QTableWidget { color: white; background-color: #202020; gridline-color: #404040; } "
            "QHeaderView::section { background-color: #303030; color: white; }"
        )
        net_layout.addWidget(self.tbl_net)
        self.tab_network.setLayout(net_layout)

        # Rules tab (read-only view)
        self.tab_rules_view = QtWidgets.QWidget()
        rv_layout = QtWidgets.QVBoxLayout()
        self.txt_rules_view = QtWidgets.QTextEdit()
        self.txt_rules_view.setReadOnly(True)
        self.txt_rules_view.setStyleSheet("color: white; background-color: #202020;")
        rv_layout.addWidget(QtWidgets.QLabel("Current rules (JSON):"))
        rv_layout.addWidget(self.txt_rules_view)
        self.tab_rules_view.setLayout(rv_layout)

        # Logs tab
        self.tab_logs = QtWidgets.QWidget()
        logs_layout = QtWidgets.QVBoxLayout()
        self.txt_logs = QtWidgets.QTextEdit()
        self.txt_logs.setReadOnly(True)
        self.txt_logs.setStyleSheet("color: white; background-color: #202020;")
        logs_layout.addWidget(QtWidgets.QLabel("Logs (decrypted):"))
        logs_layout.addWidget(self.txt_logs)
        self.tab_logs.setLayout(logs_layout)

        self.tabs.addTab(self.tab_overview, "Pending")
        self.tabs.addTab(self.tab_processes, "Processes")
        self.tabs.addTab(self.tab_network, "Network")
        self.tabs.addTab(self.tab_rules_view, "Rules")
        self.tabs.addTab(self.tab_logs, "Logs")

        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

        # Timers – slowed to 15s for heavy updates
        interval = SETTINGS.get("gui_update_interval_ms", 15000)

        self.timer_status = QtCore.QTimer()
        self.timer_status.timeout.connect(self.update_status)
        self.timer_status.start(1000)  # status can stay fast

        self.timer_logs = QtCore.QTimer()
        self.timer_logs.timeout.connect(self.update_logs)
        self.timer_logs.start(interval)

        self.timer_stats = QtCore.QTimer()
        self.timer_stats.timeout.connect(self.update_stats)
        self.timer_stats.start(1000)

        self.timer_procs = QtCore.QTimer()
        self.timer_procs.timeout.connect(self.update_process_table)
        self.timer_procs.start(interval)

        self.timer_net = QtCore.QTimer()
        self.timer_net.timeout.connect(self.update_network_table)
        self.timer_net.start(interval)

        self.timer_rules_view = QtCore.QTimer()
        self.timer_rules_view.timeout.connect(self.update_rules_view)
        self.timer_rules_view.start(interval)

        self.timer_pending = QtCore.QTimer()
        self.timer_pending.timeout.connect(self.update_pending_table)
        self.timer_pending.start(interval)

        # GUI integrity watchdog
        self.watchdog_timer = QtCore.QTimer()
        self.watchdog_timer.timeout.connect(self.gui_watchdog)
        self.watchdog_timer.start(2000)

    def apply_theme(self):
        palette = QtGui.QPalette()
        palette.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(25, 25, 25))
        palette.setColor(QtGui.QPalette.ColorRole.WindowText, QtGui.QColor(230, 230, 230))
        palette.setColor(QtGui.QPalette.ColorRole.Base, QtGui.QColor(20, 20, 20))
        palette.setColor(QtGui.QPalette.ColorRole.Text, QtGui.QColor(230, 230, 230))
        palette.setColor(QtGui.QPalette.ColorRole.Button, QtGui.QColor(40, 40, 40))
        palette.setColor(QtGui.QPalette.ColorRole.ButtonText, QtGui.QColor(230, 230, 230))
        palette.setColor(QtGui.QPalette.ColorRole.Highlight, QtGui.QColor(0, 120, 215))
        palette.setColor(QtGui.QPalette.ColorRole.HighlightedText, QtGui.QColor(255, 255, 255))
        self.setPalette(palette)

        self.setStyleSheet("""
            QLabel { color: white; }
            QLineEdit { color: white; background-color: #202020; }
            QPushButton { color: white; background-color: #404040; border: 1px solid #606060; padding: 4px; }
            QSplitter::handle { background-color: #303030; }
        """)

    def open_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            new_s = dlg.get_settings()
            SETTINGS.update(new_s)
            save_json(SETTINGS_PATH, SETTINGS)
            self.theme = SETTINGS.get("theme", "dark")
            self.apply_theme()
            interval = SETTINGS.get("gui_update_interval_ms", 15000)
            self.timer_logs.setInterval(interval)
            self.timer_procs.setInterval(interval)
            self.timer_net.setInterval(interval)
            self.timer_rules_view.setInterval(interval)
            self.timer_pending.setInterval(interval)

    def open_rules(self):
        dlg = RulesDialog(self)
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            new_r = dlg.get_rules()
            RULES.update(new_r)
            save_json(RULES_PATH, RULES)

    def kill_pid_from_gui(self):
        pid_text = self.txt_pid.text().strip()
        if not pid_text.isdigit():
            return
        pid = int(pid_text)
        kill_pid(pid)

    def update_status(self):
        self.lbl_core.setText(f"Core: {CORE_STATUS['state']}")
        self.lbl_watcher.setText(f"Watcher: {WATCHER_STATUS['state']}")
        self.lbl_core_err.setText(f"Core error: {CORE_STATUS['error']}")
        self.lbl_watcher_err.setText(f"Watcher error: {WATCHER_STATUS['error']}")

    def update_logs(self):
        logs = tail_decrypted_logs()
        self.txt_logs.clear()
        for line in logs:
            self.txt_logs.append(line)

    def update_stats(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        self.lbl_cpu.setText(f"CPU: {cpu:.1f}%")
        self.lbl_mem.setText(f"Memory: {mem:.1f}%")

    def update_process_table(self):
        procs = []
        for proc in psutil.process_iter(['pid', 'name']):
            try:
                pid    = proc.pid
                name   = proc.info.get("name", "")
                path   = get_proc_path(proc) or ""
                cpu    = proc.cpu_percent(interval=None)
                mem    = proc.memory_percent()
                parent = get_proc_parent(proc)
                start  = get_proc_create_time(proc)
                procs.append((pid, name, path, cpu, mem, parent, start))
            except Exception:
                continue

        self.tbl_procs.setRowCount(len(procs))
        for row, (pid, name, path, cpu, mem, parent, start) in enumerate(procs):
            self.tbl_procs.setItem(row, 0, QtWidgets.QTableWidgetItem(str(pid)))
            self.tbl_procs.setItem(row, 1, QtWidgets.QTableWidgetItem(name))
            self.tbl_procs.setItem(row, 2, QtWidgets.QTableWidgetItem(path))
            self.tbl_procs.setItem(row, 3, QtWidgets.QTableWidgetItem(f"{cpu:.1f}"))
            self.tbl_procs.setItem(row, 4, QtWidgets.QTableWidgetItem(f"{mem:.1f}"))
            self.tbl_procs.setItem(row, 5, QtWidgets.QTableWidgetItem(str(parent)))
            self.tbl_procs.setItem(row, 6, QtWidgets.QTableWidgetItem(start))

    def update_network_table(self):
        conns = []
        try:
            for c in psutil.net_connections(kind='inet'):
                pid = c.pid
                if pid is None:
                    continue
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                except Exception:
                    name = "?"
                laddr  = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
                raddr  = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
                status = c.status
                family = str(c.family)
                conns.append((pid, name, laddr, raddr, status, family))
        except Exception:
            pass

        self.tbl_net.setRowCount(len(conns))
        for row, (pid, name, laddr, raddr, status, family) in enumerate(conns):
            self.tbl_net.setItem(row, 0, QtWidgets.QTableWidgetItem(str(pid)))
            self.tbl_net.setItem(row, 1, QtWidgets.QTableWidgetItem(name))
            self.tbl_net.setItem(row, 2, QtWidgets.QTableWidgetItem(laddr))
            self.tbl_net.setItem(row, 3, QtWidgets.QTableWidgetItem(raddr))
            self.tbl_net.setItem(row, 4, QtWidgets.QTableWidgetItem(status))
            self.tbl_net.setItem(row, 5, QtWidgets.QTableWidgetItem(family))

    def update_rules_view(self):
        self.txt_rules_view.clear()
        self.txt_rules_view.append(json.dumps(RULES, indent=2))

    def update_pending_table(self):
        self.lst_pending.setRowCount(len(PENDING_DECISIONS))
        for row, dec in enumerate(PENDING_DECISIONS):
            dtype = dec.get("type", "")
            pid   = dec.get("pid", "")
            score = dec.get("score", 0)
            rec   = dec.get("recommended_action", "")
            ts    = datetime.fromtimestamp(dec.get("timestamp", time.time())).strftime("%Y-%m-%d %H:%M:%S")

            if dtype == "exec":
                path_ip = dec.get("path", "")
            else:
                path_ip = f"{dec.get('remote_ip', '')}:{dec.get('remote_port', '')}"

            self.lst_pending.setItem(row, 0, QtWidgets.QTableWidgetItem(dtype))
            self.lst_pending.setItem(row, 1, QtWidgets.QTableWidgetItem(str(pid)))
            self.lst_pending.setItem(row, 2, QtWidgets.QTableWidgetItem(path_ip))
            self.lst_pending.setItem(row, 3, QtWidgets.QTableWidgetItem(str(score)))
            self.lst_pending.setItem(row, 4, QtWidgets.QTableWidgetItem(rec))
            self.lst_pending.setItem(row, 5, QtWidgets.QTableWidgetItem(ts))

            # Action cell: buttons
            btn_widget = QtWidgets.QWidget()
            btn_layout = QtWidgets.QHBoxLayout()
            btn_layout.setContentsMargins(0, 0, 0, 0)

            btn_kill = QtWidgets.QPushButton("Kill")
            btn_quar = QtWidgets.QPushButton("Quarantine")
            btn_ignore = QtWidgets.QPushButton("Ignore")

            btn_kill.clicked.connect(lambda _, r=row: self.perform_action(r, "kill"))
            btn_quar.clicked.connect(lambda _, r=row: self.perform_action(r, "quarantine"))
            btn_ignore.clicked.connect(lambda _, r=row: self.perform_action(r, "ignore"))

            btn_layout.addWidget(btn_kill)
            btn_layout.addWidget(btn_quar)
            btn_layout.addWidget(btn_ignore)
            btn_widget.setLayout(btn_layout)

            self.lst_pending.setCellWidget(row, 6, btn_widget)

    def perform_action(self, row, action):
        if row < 0 or row >= len(PENDING_DECISIONS):
            return
        dec = PENDING_DECISIONS[row]
        pid = dec.get("pid")
        path = dec.get("path", "")

        if action == "kill":
            if pid is not None:
                kill_pid(pid)
                enc_log(f"MANUAL_KILL pid={pid} path={path}", "WARN")
        elif action == "quarantine":
            if pid is not None:
                kill_pid(pid)
            if path:
                qpath = quarantine_file(path)
                enc_log(f"MANUAL_QUAR pid={pid} path={path} qpath={qpath}", "WARN")
        elif action == "ignore":
            enc_log(f"MANUAL_IGNORE pid={pid} path={path}", "INFO")

        # remove from pending
        del PENDING_DECISIONS[row]
        persist_pending()
        self.update_pending_table()

    def gui_watchdog(self):
        """
        GUI integrity watchdog: ensure window is visible and not minimized.
        """
        if not self.isVisible():
            self.show()
        if self.isMinimized():
            self.showNormal()
        self.raise_()
        self.activateWindow()
        self.lbl_watchdog.setText("GUI Watchdog: ACTIVE")

    def closeEvent(self, event: QtGui.QCloseEvent):
        """
        Prevent accidental closing – you can only minimize, not close.
        """
        event.ignore()
        self.showMinimized()
        enc_log("GUI_CLOSE_ATTEMPT blocked by watchdog", "WARN")

# ----------------- ENTRY POINT -----------------

def run_gui():
    app = QtWidgets.QApplication(sys.argv)
    gui = StatusGUI()
    gui.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    threading.Thread(target=core_loop, daemon=True).start()
    threading.Thread(target=watcher_loop, daemon=True).start()
    run_gui()
