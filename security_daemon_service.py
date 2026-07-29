import sys
import os
import time
import json
import socket
import threading
import importlib
import subprocess

# ----------------- AUTOLOADER -----------------

REQUIRED_LIBS = ["PyQt6", "cryptography", "psutil"]

def autoload_libraries():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
    globals().update({lib: importlib.import_module(lib) for lib in REQUIRED_LIBS})

autoload_libraries()

from PyQt6 import QtWidgets, QtCore, QtGui
from cryptography.fernet import Fernet
import psutil

# ----------------- GLOBAL PATHS / SETTINGS -----------------

LOG_KEY_PATH = "logkey.bin"
ENC_LOG_PATH = "secure.log.enc"
SETTINGS_PATH = "settings.json"

DEFAULT_SETTINGS = {
    "blocked_paths": [],
    "blocked_ips": [],
    "theme": "dark"
}

CORE_STATUS = {"state": "STOPPED", "error": ""}
WATCHER_STATUS = {"state": "STOPPED", "error": ""}

def load_settings():
    if not os.path.exists(SETTINGS_PATH):
        save_settings(DEFAULT_SETTINGS)
        return DEFAULT_SETTINGS.copy()
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in DEFAULT_SETTINGS.items():
            if k not in data:
                data[k] = v
        return data
    except Exception:
        return DEFAULT_SETTINGS.copy()

def save_settings(s):
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(s, f, indent=2)
    except Exception:
        pass

SETTINGS = load_settings()

# ----------------- LOGGING / CRYPTO -----------------

def load_log_key():
    if not os.path.exists(LOG_KEY_PATH):
        key = Fernet.generate_key()
        with open(LOG_KEY_PATH, "wb") as f:
            f.write(key)
        return key
    return open(LOG_KEY_PATH, "rb").read()

LOG_KEY = load_log_key()
LOG_CIPHER = Fernet(LOG_KEY)

def enc_log(message: str):
    data = f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {message}".encode()
    token = LOG_CIPHER.encrypt(data)
    with open(ENC_LOG_PATH, "ab") as f:
        f.write(token + b"\n")

def tail_decrypted_logs(max_lines=200):
    if not os.path.exists(ENC_LOG_PATH):
        return []
    lines = []
    with open(ENC_LOG_PATH, "rb") as f:
        data = f.readlines()
    for line in data[-max_lines:]:
        line = line.strip()
        if not line:
            continue
        try:
            dec = LOG_CIPHER.decrypt(line).decode(errors="ignore")
            lines.append(dec)
        except Exception:
            continue
    return lines

# ----------------- CORE ENGINE -----------------

def core_handle_exec(event, settings):
    path = event.get("path", "")
    pid = event.get("pid")
    for b in settings["blocked_paths"]:
        if b and b.lower() in path.lower():
            enc_log(f"BLOCK_PROC EXEC path={path} pid={pid}")
            return {"allow": False}
    enc_log(f"ALLOW_PROC EXEC path={path} pid={pid}")
    return {"allow": True}

def core_handle_net(event, settings):
    path = event.get("path", "")
    pid = event.get("pid")
    rip = event.get("remote_ip", "")
    rport = event.get("remote_port")
    for ip in settings["blocked_ips"]:
        if ip and ip == rip:
            enc_log(f"BLOCK_NET ip={rip} port={rport} pid={pid} path={path}")
            return {"allow": False}
    enc_log(f"ALLOW_NET ip={rip} port={rport} pid={pid} path={path}")
    return {"allow": True}

def core_loop():
    global CORE_STATUS
    CORE_STATUS["state"] = "RUNNING"
    enc_log("CORE START")
    settings = load_settings()
    try:
        while True:
            time.sleep(1.0)
            # core is passive; watcher calls handlers directly
    except Exception as e:
        CORE_STATUS["state"] = "ERROR"
        CORE_STATUS["error"] = str(e)
        enc_log(f"CORE ERROR {e}")

# ----------------- WATCHER -----------------

known_pids = set()
baseline_done = False

def kill_pid(pid):
    try:
        psutil.Process(pid).terminate()
        enc_log(f"BLOCK_PROC KILL pid={pid}")
    except Exception:
        pass

def get_proc_path(proc):
    try:
        return proc.exe()
    except Exception:
        return None

def baseline_scan():
    global known_pids, baseline_done
    if baseline_done:
        return
    enc_log("WATCHER BASELINE START")
    settings = load_settings()
    for proc in psutil.process_iter(['pid', 'name']):
        path = get_proc_path(proc)
        if not path:
            continue
        event = {"type": "exec", "pid": proc.pid, "path": path}
        core_handle_exec(event, settings)
        known_pids.add(proc.pid)
    baseline_done = True
    enc_log("WATCHER BASELINE DONE")

def monitor_processes():
    global known_pids
    settings = load_settings()
    while True:
        current_pids = set()
        for proc in psutil.process_iter(['pid', 'name']):
            pid = proc.pid
            current_pids.add(pid)
            if pid not in known_pids:
                path = get_proc_path(proc)
                if not path:
                    continue
                event = {"type": "exec", "pid": pid, "path": path}
                decision = core_handle_exec(event, settings)
                if not decision.get("allow", True):
                    kill_pid(pid)
                else:
                    known_pids.add(pid)
        known_pids = known_pids.intersection(current_pids)
        time.sleep(1.0)

def monitor_network():
    settings = load_settings()
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
                    decision = core_handle_net(event, settings)
                    if not decision.get("allow", True):
                        kill_pid(pid)
        except Exception:
            pass
        time.sleep(1.0)

def watcher_loop():
    global WATCHER_STATUS
    WATCHER_STATUS["state"] = "RUNNING"
    enc_log("WATCHER START")
    try:
        baseline_scan()
        threading.Thread(target=monitor_processes, daemon=True).start()
        threading.Thread(target=monitor_network, daemon=True).start()
        while True:
            time.sleep(5.0)
    except Exception as e:
        WATCHER_STATUS["state"] = "ERROR"
        WATCHER_STATUS["error"] = str(e)
        enc_log(f"WATCHER ERROR {e}")

# ----------------- SETTINGS DIALOG -----------------

class SettingsDialog(QtWidgets.QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Settings")
        layout = QtWidgets.QFormLayout()

        self.txt_paths = QtWidgets.QPlainTextEdit()
        self.txt_paths.setPlainText("\n".join(SETTINGS["blocked_paths"]))

        self.txt_ips = QtWidgets.QPlainTextEdit()
        self.txt_ips.setPlainText("\n".join(SETTINGS["blocked_ips"]))

        self.cmb_theme = QtWidgets.QComboBox()
        self.cmb_theme.addItems(["dark", "light"])
        self.cmb_theme.setCurrentText(SETTINGS.get("theme", "dark"))

        layout.addRow("Blocked paths (one per line):", self.txt_paths)
        layout.addRow("Blocked IPs (one per line):", self.txt_ips)
        layout.addRow("Theme:", self.cmb_theme)

        btns = QtWidgets.QDialogButtonBox(
            QtWidgets.QDialogButtonBox.StandardButton.Ok |
            QtWidgets.QDialogButtonBox.StandardButton.Cancel
        )
        btns.accepted.connect(self.accept)
        btns.rejected.connect(self.reject)
        layout.addRow(btns)

        self.setLayout(layout)

    def get_settings(self):
        paths = [l.strip() for l in self.txt_paths.toPlainText().splitlines() if l.strip()]
        ips = [l.strip() for l in self.txt_ips.toPlainText().splitlines() if l.strip()]
        theme = self.cmb_theme.currentText()
        return {
            "blocked_paths": paths,
            "blocked_ips": ips,
            "theme": theme
        }

# ----------------- GUI -----------------

class StatusGUI(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Security Daemon Dashboard")
        self.setGeometry(200, 200, 900, 600)

        self.theme = SETTINGS.get("theme", "dark")
        self.apply_theme()

        main_layout = QtWidgets.QVBoxLayout()

        self.lbl_core = QtWidgets.QLabel("Core: STOPPED")
        self.lbl_watcher = QtWidgets.QLabel("Watcher: STOPPED")
        self.lbl_core_err = QtWidgets.QLabel("")
        self.lbl_watcher_err = QtWidgets.QLabel("")

        for lbl in [self.lbl_core, self.lbl_watcher, self.lbl_core_err, self.lbl_watcher_err]:
            lbl.setStyleSheet("font-size: 14px; color: white;")
            main_layout.addWidget(lbl)

        self.lbl_cpu = QtWidgets.QLabel("CPU: 0%")
        self.lbl_mem = QtWidgets.QLabel("Memory: 0%")
        self.lbl_cpu.setStyleSheet("font-size: 14px; color: white;")
        self.lbl_mem.setStyleSheet("font-size: 14px; color: white;")
        main_layout.addWidget(self.lbl_cpu)
        main_layout.addWidget(self.lbl_mem)

        ctrl_layout = QtWidgets.QHBoxLayout()
        self.btn_settings = QtWidgets.QPushButton("Settings")
        self.btn_settings.clicked.connect(self.open_settings)
        self.txt_pid = QtWidgets.QLineEdit()
        self.txt_pid.setPlaceholderText("PID to kill")
        self.btn_kill = QtWidgets.QPushButton("Kill PID")
        self.btn_kill.clicked.connect(self.kill_pid_from_gui)
        ctrl_layout.addWidget(self.btn_settings)
        ctrl_layout.addWidget(self.txt_pid)
        ctrl_layout.addWidget(self.btn_kill)
        main_layout.addLayout(ctrl_layout)

        splitter = QtWidgets.QSplitter(QtCore.Qt.Orientation.Horizontal)

        logs_widget = QtWidgets.QWidget()
        logs_layout = QtWidgets.QVBoxLayout()
        logs_label = QtWidgets.QLabel("Logs (decrypted):")
        logs_label.setStyleSheet("color: white;")
        self.txt_logs = QtWidgets.QTextEdit()
        self.txt_logs.setReadOnly(True)
        self.txt_logs.setStyleSheet("color: white; background-color: #202020;")
        logs_layout.addWidget(logs_label)
        logs_layout.addWidget(self.txt_logs)
        logs_widget.setLayout(logs_layout)

        blocks_widget = QtWidgets.QWidget()
        blocks_layout = QtWidgets.QVBoxLayout()
        blocks_label = QtWidgets.QLabel("Blocks (process / network):")
        blocks_label.setStyleSheet("color: white;")
        self.lst_blocks = QtWidgets.QListWidget()
        self.lst_blocks.setStyleSheet("color: white; background-color: #202020;")
        blocks_layout.addWidget(blocks_label)
        blocks_layout.addWidget(self.lst_blocks)
        blocks_widget.setLayout(blocks_layout)

        splitter.addWidget(logs_widget)
        splitter.addWidget(blocks_widget)
        main_layout.addWidget(splitter)

        self.setLayout(main_layout)

        self.timer_status = QtCore.QTimer()
        self.timer_status.timeout.connect(self.update_status)
        self.timer_status.start(1000)

        self.timer_logs = QtCore.QTimer()
        self.timer_logs.timeout.connect(self.update_logs)
        self.timer_logs.start(2000)

        self.timer_stats = QtCore.QTimer()
        self.timer_stats.timeout.connect(self.update_stats)
        self.timer_stats.start(1000)

    def apply_theme(self):
        if self.theme == "dark":
            palette = QtGui.QPalette()
            palette.setColor(QtGui.QPalette.ColorRole.Window, QtGui.QColor(30, 30, 30))
            palette.setColor(QtGui.QPalette.ColorRole.WindowText, QtGui.QColor(220, 220, 220))
            palette.setColor(QtGui.QPalette.ColorRole.Base, QtGui.QColor(20, 20, 20))
            palette.setColor(QtGui.QPalette.ColorRole.Text, QtGui.QColor(220, 220, 220))
            self.setPalette(palette)
        else:
            self.setPalette(QtGui.QPalette())

    def open_settings(self):
        dlg = SettingsDialog(self)
        if dlg.exec() == QtWidgets.QDialog.DialogCode.Accepted:
            new_s = dlg.get_settings()
            SETTINGS.update(new_s)
            save_settings(SETTINGS)
            self.theme = SETTINGS.get("theme", "dark")
            self.apply_theme()

    def kill_pid_from_gui(self):
        pid_text = self.txt_pid.text().strip()
        if not pid_text.isdigit():
            return
        pid = int(pid_text)
        try:
            psutil.Process(pid).terminate()
            enc_log(f"GUI KILL pid={pid}")
        except Exception:
            pass

    def update_status(self):
        self.lbl_core.setText(f"Core: {CORE_STATUS['state']}")
        self.lbl_watcher.setText(f"Watcher: {WATCHER_STATUS['state']}")
        self.lbl_core_err.setText(f"Core error: {CORE_STATUS['error']}")
        self.lbl_watcher_err.setText(f"Watcher error: {WATCHER_STATUS['error']}")

    def update_logs(self):
        logs = tail_decrypted_logs()
        self.txt_logs.clear()
        self.lst_blocks.clear()
        for line in logs:
            self.txt_logs.append(line)
            if "BLOCK_PROC" in line or "BLOCK_NET" in line:
                self.lst_blocks.addItem(line)

    def update_stats(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory().percent
        self.lbl_cpu.setText(f"CPU: {cpu:.1f}%")
        self.lbl_mem.setText(f"Memory: {mem:.1f}%")

def run_gui():
    app = QtWidgets.QApplication(sys.argv)
    gui = StatusGUI()
    gui.show()
    sys.exit(app.exec())

# ----------------- ENTRY POINT -----------------

if __name__ == "__main__":
    # start core + watcher as threads
    threading.Thread(target=core_loop, daemon=True).start()
    threading.Thread(target=watcher_loop, daemon=True).start()
    # start GUI
    run_gui()
