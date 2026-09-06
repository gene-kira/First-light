#!/usr/bin/env python3
"""
Windows Usage Monitor v2
- Auto-elevation to admin
- Monitors what the user actually uses
- Marks unused stuff as "standby" (priority/affinity/suspend)
- Weekly system scan for new programs
- GUI showing:
  - Most used programs
  - Active programs
  - Standby programs
  - Unused drives
  - USB devices
- Settings panel for thresholds and intervals
"""

# ==========================
# AUTO-ELEVATION CHECK
# ==========================
import ctypes
import os
import sys

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
        print(f"[Usage Monitor] Elevation failed: {e}")
        sys.exit()

ensure_admin()

# ==========================
# AUTOLOADER
# ==========================
import importlib
import subprocess

REQUIRED_MODULES = {
    "os": "os",
    "time": "time",
    "threading": "threading",
    "json": "json",
    "logging": "logging",
    "psutil": "psutil",
    "schedule": "schedule",
    "PySide6": "PySide6",
    "win32api": "pywin32",
    "win32con": "pywin32",
    "win32process": "pywin32",
}

BUILTIN_OR_OS = {
    "os",
    "time",
    "threading",
    "json",
    "logging",
}

def _safe_import(module_name):
    try:
        importlib.import_module(module_name)
        print(f"[AUTOLOADER] Loaded: {module_name}")
        return True
    except ImportError:
        print(f"[AUTOLOADER] Missing: {module_name}")
        return False
    except Exception as e:
        print(f"[AUTOLOADER] Error importing {module_name}: {e}")
        return False

def _install_packages(pkgs):
    if not pkgs:
        return True
    try:
        print(f"[AUTOLOADER] Installing: {pkgs}")
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + pkgs)
        return True
    except Exception as e:
        print(f"[AUTOLOADER] Install failed for {pkgs}: {e}")
        return False

def autoload_modules():
    missing = []
    for module_name, pip_name in REQUIRED_MODULES.items():
        if module_name in BUILTIN_OR_OS:
            print(f"[AUTOLOADER] {module_name} is builtin/OS-provided.")
            continue
        if not _safe_import(module_name):
            missing.append(pip_name)

    if missing:
        if not _install_packages(missing):
            print("[AUTOLOADER] FATAL: required modules failed to install.")
            sys.exit(1)

    for module_name in REQUIRED_MODULES.keys():
        if module_name in BUILTIN_OR_OS:
            continue
        _safe_import(module_name)

    print("[AUTOLOADER] Complete.")

autoload_modules()

import time
import threading
import json
import logging
import psutil
import schedule
from PySide6 import QtWidgets, QtCore
import win32api
import win32con
import win32process

# ==========================
# LOGGING + CONFIG
# ==========================
BASE_DIR = os.getcwd()
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "usage_monitor.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

def log_info(msg):
    print(msg)
    logging.info(msg)

CONFIG_PATH = os.path.join(BASE_DIR, "usage_monitor_config.json")

DEFAULT_CONFIG = {
    "scan_interval_sec": 10,
    "weekly_scan_day": "Sunday",
    "weekly_scan_hour": 3,
    "usage_window_minutes": 60,
    "standby_threshold": 5,  # CPU% below which we consider standby candidate
}

def load_config():
    if not os.path.isfile(CONFIG_PATH):
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for k, v in DEFAULT_CONFIG.items():
            if k not in data:
                data[k] = v
        return data
    except Exception as e:
        log_info(f"[CONFIG] Failed to load config, using defaults: {e}")
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        log_info("[CONFIG] usage_monitor_config.json updated.")
    except Exception as e:
        log_info(f"[CONFIG ERROR] {e}")

CONFIG = load_config()

# ==========================
# STANDBY ENGINE
# ==========================
def suspend_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.suspend()
        log_info(f"[STANDBY] Suspended PID {pid}")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Suspend failed for PID {pid}: {e}")
        return False

def resume_process(pid):
    try:
        proc = psutil.Process(pid)
        proc.resume()
        log_info(f"[STANDBY] Resumed PID {pid}")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Resume failed for PID {pid}: {e}")
        return False

def lower_priority(pid):
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
        win32process.SetPriorityClass(handle, win32process.IDLE_PRIORITY_CLASS)
        win32api.CloseHandle(handle)
        log_info(f"[STANDBY] Lowered priority for PID {pid}")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Priority change failed for PID {pid}: {e}")
        return False

def reduce_affinity(pid):
    try:
        proc = psutil.Process(pid)
        proc.cpu_affinity([0])
        log_info(f"[STANDBY] Reduced affinity for PID {pid} to core 0")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Affinity change failed for PID {pid}: {e}")
        return False

def spin_down_drive(drive_letter):
    try:
        path = f"\\\\.\\{drive_letter.replace(':','')}"
        handle = win32api.CreateFile(
            path,
            win32con.GENERIC_WRITE,
            win32con.FILE_SHARE_WRITE,
            None,
            win32con.OPEN_EXISTING,
            0,
            None
        )
        ctypes.windll.kernel32.SetDevicePowerState(handle.handle, False)
        win32api.CloseHandle(handle)
        log_info(f"[STANDBY] Drive {drive_letter} spun down.")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Drive spin-down failed for {drive_letter}: {e}")
        return False

# ==========================
# USAGE TRACKER
# ==========================
class UsageTracker:
    def __init__(self, window_minutes=60):
        self.window_seconds = window_minutes * 60
        self.process_usage = {}  # pid -> {name, last_seen, total_active_sec, last_cpu}
        self.program_usage = {}  # name -> total_active_sec
        self.lock = threading.Lock()

    def update(self):
        now = time.time()
        with self.lock:
            for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
                pid = proc.info["pid"]
                name = proc.info["name"] or "unknown"
                cpu = proc.info["cpu_percent"] or 0.0

                if pid not in self.process_usage:
                    self.process_usage[pid] = {
                        "name": name,
                        "last_seen": now,
                        "total_active_sec": 0.0,
                        "last_cpu": cpu,
                    }
                else:
                    delta = now - self.process_usage[pid]["last_seen"]
                    self.process_usage[pid]["total_active_sec"] += delta
                    self.process_usage[pid]["last_seen"] = now
                    self.process_usage[pid]["last_cpu"] = cpu

                self.program_usage.setdefault(name, 0.0)
                self.program_usage[name] += CONFIG["scan_interval_sec"]

            to_delete = []
            for pid, info in self.process_usage.items():
                if now - info["last_seen"] > self.window_seconds:
                    to_delete.append(pid)
            for pid in to_delete:
                del self.process_usage[pid]

    def get_top_programs(self, limit=10):
        with self.lock:
            items = sorted(
                self.program_usage.items(),
                key=lambda kv: kv[1],
                reverse=True
            )
            return items[:limit]

    def get_active_programs(self):
        with self.lock:
            names = set(info["name"] for info in self.process_usage.values())
            return sorted(names)

    def get_standby_candidates(self):
        with self.lock:
            threshold = CONFIG["standby_threshold"]
            candidates = []
            for pid, info in self.process_usage.items():
                if info["last_cpu"] < threshold:
                    candidates.append((pid, info["name"], info["last_cpu"]))
            return candidates

    def get_standby_programs(self):
        with self.lock:
            active = set(info["name"] for info in self.process_usage.values())
            all_programs = set(self.program_usage.keys())
            standby = all_programs - active
            return sorted(standby)

usage_tracker = UsageTracker(window_minutes=CONFIG["usage_window_minutes"])

# ==========================
# SYSTEM SCAN (DRIVES + USB)
# ==========================
def get_drives():
    drives = []
    for part in psutil.disk_partitions(all=False):
        drives.append(part.device)
    return drives

def get_unused_drives():
    unused = []
    for part in psutil.disk_partitions(all=False):
        try:
            usage = psutil.disk_usage(part.mountpoint)
            if usage.percent < 1.0:
                unused.append(part.device)
        except Exception:
            continue
    return unused

def get_usb_devices():
    usb = []
    for disk in psutil.disk_partitions(all=True):
        if "removable" in disk.opts.lower():
            usb.append(disk.device)
    return usb

def get_unused_usb_devices():
    return get_usb_devices()

# ==========================
# WEEKLY SCAN (PROGRAMS)
# ==========================
PROGRAM_DB_PATH = os.path.join(BASE_DIR, "program_db.json")

def load_program_db():
    if not os.path.isfile(PROGRAM_DB_PATH):
        return {}
    try:
        with open(PROGRAM_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_program_db(db):
    try:
        with open(PROGRAM_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=2)
        log_info("[PROGRAM DB] Updated.")
    except Exception as e:
        log_info(f"[PROGRAM DB ERROR] {e}")

def weekly_scan_programs():
    log_info("[WEEKLY SCAN] Starting weekly program scan.")
    db = load_program_db()
    for proc in psutil.process_iter(["name"]):
        name = proc.info["name"] or "unknown"
        db.setdefault(name, {"first_seen": time.time(), "last_seen": time.time()})
        db[name]["last_seen"] = time.time()
    save_program_db(db)
    log_info("[WEEKLY SCAN] Completed.")

# ==========================
# BACKGROUND THREADS
# ==========================
def usage_loop():
    while True:
        try:
            usage_tracker.update()
        except Exception as e:
            log_info(f"[USAGE LOOP ERROR] {e}")
        time.sleep(CONFIG["scan_interval_sec"])

def schedule_loop():
    schedule.every().week.do(weekly_scan_programs)
    while True:
        try:
            schedule.run_pending()
        except Exception as e:
            log_info(f"[SCHEDULE ERROR] {e}")
        time.sleep(1)

# ==========================
# SETTINGS PANEL
# ==========================
class SettingsPanel(QtWidgets.QDialog):
    def __init__(self, config):
        super().__init__()
        self.setWindowTitle("Settings")
        self.resize(400, 300)
        self.config = config

        layout = QtWidgets.QFormLayout(self)

        self.scan_interval = QtWidgets.QSpinBox()
        self.scan_interval.setRange(1, 3600)
        self.scan_interval.setValue(config["scan_interval_sec"])
        layout.addRow("Scan interval (sec):", self.scan_interval)

        self.usage_window = QtWidgets.QSpinBox()
        self.usage_window.setRange(1, 1440)
        self.usage_window.setValue(config["usage_window_minutes"])
        layout.addRow("Usage window (minutes):", self.usage_window)

        self.standby_threshold = QtWidgets.QSpinBox()
        self.standby_threshold.setRange(1, 100)
        self.standby_threshold.setValue(config.get("standby_threshold", 5))
        layout.addRow("Standby threshold (% CPU):", self.standby_threshold)

        save_btn = QtWidgets.QPushButton("Save")
        save_btn.clicked.connect(self.save_settings)
        layout.addRow(save_btn)

    def save_settings(self):
        self.config["scan_interval_sec"] = self.scan_interval.value()
        self.config["usage_window_minutes"] = self.usage_window.value()
        self.config["standby_threshold"] = self.standby_threshold.value()
        save_config(self.config)
        self.accept()

# ==========================
# GUI
# ==========================
class UsageMonitorWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Usage Monitor v2")
        self.resize(900, 650)

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)

        self.summary_label = QtWidgets.QLabel("System summary")
        layout.addWidget(self.summary_label)

        self.top_programs_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Most used programs (recent window):"))
        layout.addWidget(self.top_programs_list)

        self.active_programs_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Active programs:"))
        layout.addWidget(self.active_programs_list)

        self.standby_programs_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Standby programs (not currently active):"))
        layout.addWidget(self.standby_programs_list)

        self.standby_candidates_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Standby candidates (low CPU):"))
        layout.addWidget(self.standby_candidates_list)

        self.drives_label = QtWidgets.QLabel("Drives / USB status")
        layout.addWidget(self.drives_label)

        btn_layout = QtWidgets.QHBoxLayout()
        self.settings_btn = QtWidgets.QPushButton("Settings")
        self.settings_btn.clicked.connect(self.open_settings)
        btn_layout.addWidget(self.settings_btn)

        self.apply_standby_btn = QtWidgets.QPushButton("Apply Standby to Selected PID")
        self.apply_standby_btn.clicked.connect(self.apply_standby_to_selected)
        btn_layout.addWidget(self.apply_standby_btn)

        layout.addLayout(btn_layout)

        self.setCentralWidget(central)

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.refresh_view)
        self.timer.start(3000)

        self.refresh_view()

    def open_settings(self):
        dlg = SettingsPanel(CONFIG)
        dlg.exec()

    def apply_standby_to_selected(self):
        item = self.standby_candidates_list.currentItem()
        if not item:
            return
        text = item.text()
        try:
            pid_str = text.split(" ")[0]
            pid = int(pid_str)
        except Exception:
            return
        lower_priority(pid)
        reduce_affinity(pid)
        suspend_process(pid)

    def refresh_view(self):
        drives = get_drives()
        unused_drives = get_unused_drives()
        usb = get_usb_devices()
        unused_usb = get_unused_usb_devices()

        summary = []
        summary.append(f"Total drives: {len(drives)}")
        summary.append(f"Unused drives (heuristic): {', '.join(unused_drives) if unused_drives else 'None'}")
        summary.append(f"USB devices: {', '.join(usb) if usb else 'None'}")
        summary.append(f"Unused USB (heuristic): {', '.join(unused_usb) if unused_usb else 'None'}")

        self.summary_label.setText("System summary:\n" + "\n".join(summary))

        self.top_programs_list.clear()
        for name, sec in usage_tracker.get_top_programs(limit=10):
            self.top_programs_list.addItem(f"{name} — {sec:.0f}s active")

        self.active_programs_list.clear()
        for name in usage_tracker.get_active_programs():
            self.active_programs_list.addItem(name)

        self.standby_programs_list.clear()
        for name in usage_tracker.get_standby_programs():
            self.standby_programs_list.addItem(name)

        self.standby_candidates_list.clear()
        for pid, name, cpu in usage_tracker.get_standby_candidates():
            self.standby_candidates_list.addItem(f"{pid} {name} — {cpu:.1f}% CPU")

# ==========================
# MAIN
# ==========================
def main():
    t_usage = threading.Thread(target=usage_loop, daemon=True)
    t_usage.start()

    t_sched = threading.Thread(target=schedule_loop, daemon=True)
    t_sched.start()

    app = QtWidgets.QApplication(sys.argv)
    win = UsageMonitorWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
