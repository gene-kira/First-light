#!/usr/bin/env python3
"""
Windows Usage Monitor v1
- Monitors what the user actually uses
- Marks unused stuff as "standby" (conceptual)
- Weekly system scan for new programs
- GUI showing:
  - Most used programs
  - Currently active programs
  - Standby programs
  - Unused drives
  - Unused USB devices
"""

# ==========================
# AUTOLOADER
# ==========================
import importlib
import subprocess
import sys
import os

REQUIRED_MODULES = {
    "os": "os",
    "time": "time",
    "threading": "threading",
    "json": "json",
    "logging": "logging",
    "psutil": "psutil",
    "schedule": "schedule",
    "PySide6": "PySide6",
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

    # Re-import after installation
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
# USAGE TRACKER
# ==========================
class UsageTracker:
    def __init__(self, window_minutes=60):
        self.window_seconds = window_minutes * 60
        self.process_usage = {}  # pid -> {name, last_seen, total_active_sec}
        self.program_usage = {}  # name -> total_active_sec
        self.lock = threading.Lock()

    def update(self):
        now = time.time()
        with self.lock:
            # mark active processes
            for proc in psutil.process_iter(["pid", "name", "cpu_percent"]):
                pid = proc.info["pid"]
                name = proc.info["name"] or "unknown"
                cpu = proc.info["cpu_percent"]
                if cpu is None:
                    cpu = 0.0

                if pid not in self.process_usage:
                    self.process_usage[pid] = {
                        "name": name,
                        "last_seen": now,
                        "total_active_sec": 0.0,
                    }
                else:
                    # if we see it again, add time since last_seen
                    delta = now - self.process_usage[pid]["last_seen"]
                    self.process_usage[pid]["total_active_sec"] += delta
                    self.process_usage[pid]["last_seen"] = now

                # aggregate by program name
                self.program_usage.setdefault(name, 0.0)
                self.program_usage[name] += CONFIG["scan_interval_sec"]

            # prune old processes (not seen in window)
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

    def get_standby_programs(self):
        with self.lock:
            active = set(info["name"] for info in self.process_usage.values())
            all_programs = set(self.program_usage.keys())
            standby = all_programs - active
            return sorted(standby)

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
            # heuristic: if used < 1% and no recent activity, call it "unused"
            if usage.percent < 1.0:
                unused.append(part.device)
        except Exception:
            continue
    return unused

def get_usb_devices():
    # simple heuristic: drives with 'removable' type
    usb = []
    for disk in psutil.disk_partitions(all=True):
        if "removable" in disk.opts.lower():
            usb.append(disk.device)
    return usb

def get_unused_usb_devices():
    # for now, unused == present but not mounted as active partition
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
    # simple heuristic: record all currently seen process names
    for proc in psutil.process_iter(["name"]):
        name = proc.info["name"] or "unknown"
        db.setdefault(name, {"first_seen": time.time(), "last_seen": time.time()})
        db[name]["last_seen"] = time.time()
    save_program_db(db)
    log_info("[WEEKLY SCAN] Completed.")

# ==========================
# BACKGROUND THREADS
# ==========================
usage_tracker = UsageTracker(window_minutes=CONFIG["usage_window_minutes"])

def usage_loop():
    while True:
        try:
            usage_tracker.update()
        except Exception as e:
            log_info(f"[USAGE LOOP ERROR] {e}")
        time.sleep(CONFIG["scan_interval_sec"])

def schedule_loop():
    # weekly scan
    schedule.every().week.do(weekly_scan_programs)
    while True:
        try:
            schedule.run_pending()
        except Exception as e:
            log_info(f"[SCHEDULE ERROR] {e}")
        time.sleep(1)

# ==========================
# GUI
# ==========================
class UsageMonitorWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Usage Monitor v1")
        self.resize(900, 600)

        central = QtWidgets.QWidget()
        layout = QtWidgets.QVBoxLayout(central)

        # Top: summary labels
        self.summary_label = QtWidgets.QLabel("System summary")
        layout.addWidget(self.summary_label)

        # Top programs
        self.top_programs_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Most used programs (recent window):"))
        layout.addWidget(self.top_programs_list)

        # Active programs
        self.active_programs_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Active programs:"))
        layout.addWidget(self.active_programs_list)

        # Standby programs
        self.standby_programs_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Standby (not currently active):"))
        layout.addWidget(self.standby_programs_list)

        # Drives + USB
        self.drives_label = QtWidgets.QLabel("Drives / USB status")
        layout.addWidget(self.drives_label)

        self.setCentralWidget(central)

        # Timer to refresh GUI
        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.refresh_view)
        self.timer.start(3000)  # every 3 seconds

        self.refresh_view()

    def refresh_view(self):
        # summary
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

        # top programs
        self.top_programs_list.clear()
        for name, sec in usage_tracker.get_top_programs(limit=10):
            self.top_programs_list.addItem(f"{name} — {sec:.0f}s active")

        # active programs
        self.active_programs_list.clear()
        for name in usage_tracker.get_active_programs():
            self.active_programs_list.addItem(name)

        # standby programs
        self.standby_programs_list.clear()
        for name in usage_tracker.get_standby_programs():
            self.standby_programs_list.addItem(name)

# ==========================
# MAIN
# ==========================
def main():
    # start background threads
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
