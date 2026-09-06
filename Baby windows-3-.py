#!/usr/bin/env python3
"""
Windows Usage Monitor Pro
- Auto-elevation to admin
- Monitors CPU/RAM/Disk/GPU usage
- Auto-standby rules (priority/affinity/suspend)
- Whitelist for protected processes
- Weekly program scan + bloat detection
- Cleanup suggestions
- System tray mode
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
    "pystray": "pystray",
    "PIL": "Pillow",
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
import pystray
from PIL import Image, ImageDraw

# ==========================
# LOGGING + CONFIG
# ==========================
BASE_DIR = os.getcwd()
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "usage_monitor_pro.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

def log_info(msg):
    print(msg)
    logging.info(msg)

CONFIG_PATH = os.path.join(BASE_DIR, "usage_monitor_pro_config.json")

DEFAULT_CONFIG = {
    "scan_interval_sec": 10,
    "weekly_scan_day": "Sunday",
    "weekly_scan_hour": 3,
    "usage_window_minutes": 60,
    "standby_threshold_cpu": 5,
    "standby_idle_minutes": 15,
    "auto_standby_enabled": True,
    "whitelist": [
        "System",
        "Registry",
        "smss.exe",
        "csrss.exe",
        "wininit.exe",
        "services.exe",
        "lsass.exe",
        "svchost.exe",
        "explorer.exe",
        "python.exe",
    ],
    "bloat_min_days": 7,
    "bloat_max_active_sec": 300,
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
        log_info("[CONFIG] usage_monitor_pro_config.json updated.")
    except Exception as e:
        log_info(f"[CONFIG ERROR] {e}")

CONFIG = load_config()

# ==========================
# STANDBY ENGINE + WHITELIST
# ==========================
def is_whitelisted(name: str) -> bool:
    wl = CONFIG.get("whitelist", [])
    name_lower = (name or "").lower()
    for w in wl:
        if w.lower() == name_lower:
            return True
    return False

def suspend_process(pid, name):
    if is_whitelisted(name):
        log_info(f"[STANDBY] Skipping suspend for whitelisted {name} (PID {pid})")
        return False
    try:
        proc = psutil.Process(pid)
        proc.suspend()
        log_info(f"[STANDBY] Suspended {name} (PID {pid})")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Suspend failed for {name} (PID {pid}): {e}")
        return False

def resume_process(pid, name):
    try:
        proc = psutil.Process(pid)
        proc.resume()
        log_info(f"[STANDBY] Resumed {name} (PID {pid})")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Resume failed for {name} (PID {pid}): {e}")
        return False

def lower_priority(pid, name):
    if is_whitelisted(name):
        log_info(f"[STANDBY] Skipping priority change for whitelisted {name} (PID {pid})")
        return False
    try:
        handle = win32api.OpenProcess(win32con.PROCESS_ALL_ACCESS, True, pid)
        win32process.SetPriorityClass(handle, win32process.IDLE_PRIORITY_CLASS)
        win32api.CloseHandle(handle)
        log_info(f"[STANDBY] Lowered priority for {name} (PID {pid})")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Priority change failed for {name} (PID {pid}): {e}")
        return False

def reduce_affinity(pid, name):
    if is_whitelisted(name):
        log_info(f"[STANDBY] Skipping affinity change for whitelisted {name} (PID {pid})")
        return False
    try:
        proc = psutil.Process(pid)
        proc.cpu_affinity([0])
        log_info(f"[STANDBY] Reduced affinity for {name} (PID {pid}) to core 0")
        return True
    except Exception as e:
        log_info(f"[STANDBY] Affinity change failed for {name} (PID {pid}): {e}")
        return False

# ==========================
# USAGE TRACKER (CPU/RAM/DISK/GPU-ish)
# ==========================
PROGRAM_DB_PATH = os.path.join(BASE_DIR, "program_db_pro.json")

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

class UsageTracker:
    def __init__(self, window_minutes=60):
        self.window_seconds = window_minutes * 60
        self.process_usage = {}  # pid -> info
        self.program_usage = {}  # name -> total_active_sec
        self.lock = threading.Lock()
        self.program_db = load_program_db()

    def update(self):
        now = time.time()
        with self.lock:
            for proc in psutil.process_iter(["pid", "name", "cpu_percent", "memory_info", "io_counters"]):
                pid = proc.info["pid"]
                name = proc.info["name"] or "unknown"
                cpu = proc.info["cpu_percent"] or 0.0
                mem = proc.info["memory_info"].rss if proc.info["memory_info"] else 0
                io = proc.info["io_counters"].read_bytes + proc.info["io_counters"].write_bytes if proc.info["io_counters"] else 0

                if pid not in self.process_usage:
                    self.process_usage[pid] = {
                        "name": name,
                        "first_seen": now,
                        "last_seen": now,
                        "total_active_sec": 0.0,
                        "last_cpu": cpu,
                        "last_mem": mem,
                        "last_io": io,
                    }
                else:
                    delta = now - self.process_usage[pid]["last_seen"]
                    self.process_usage[pid]["total_active_sec"] += delta
                    self.process_usage[pid]["last_seen"] = now
                    self.process_usage[pid]["last_cpu"] = cpu
                    self.process_usage[pid]["last_mem"] = mem
                    self.process_usage[pid]["last_io"] = io

                self.program_usage.setdefault(name, 0.0)
                self.program_usage[name] += CONFIG["scan_interval_sec"]

                # update program DB
                entry = self.program_db.get(name, {"first_seen": now, "last_seen": now, "total_active_sec": 0.0})
                entry["last_seen"] = now
                entry["total_active_sec"] += CONFIG["scan_interval_sec"]
                self.program_db[name] = entry

            # prune old processes
            to_delete = []
            for pid, info in self.process_usage.items():
                if now - info["last_seen"] > self.window_seconds:
                    to_delete.append(pid)
            for pid in to_delete:
                del self.process_usage[pid]

            save_program_db(self.program_db)

    def get_top_programs(self, limit=10):
        with self.lock:
            items = sorted(self.program_usage.items(), key=lambda kv: kv[1], reverse=True)
            return items[:limit]

    def get_active_programs(self):
        with self.lock:
            names = set(info["name"] for info in self.process_usage.values())
            return sorted(names)

    def get_standby_candidates(self):
        with self.lock:
            threshold = CONFIG["standby_threshold_cpu"]
            idle_minutes = CONFIG["standby_idle_minutes"]
            idle_sec = idle_minutes * 60
            candidates = []
            now = time.time()
            for pid, info in self.process_usage.items():
                idle_time = now - info["last_seen"]
                if info["last_cpu"] < threshold and idle_time > idle_sec:
                    candidates.append((pid, info["name"], info["last_cpu"], idle_time))
            return candidates

    def get_standby_programs(self):
        with self.lock:
            active = set(info["name"] for info in self.process_usage.values())
            all_programs = set(self.program_usage.keys())
            standby = all_programs - active
            return sorted(standby)

    def get_system_summary(self):
        cpu = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")
        # GPU: psutil doesn't do GPU; we just say "GPU monitoring not available (placeholder)"
        return {
            "cpu_percent": cpu,
            "mem_used": mem.used,
            "mem_total": mem.total,
            "mem_percent": mem.percent,
            "disk_used": disk.used,
            "disk_total": disk.total,
            "disk_percent": disk.percent,
            "gpu_info": "GPU monitoring placeholder (extend with vendor-specific tools)",
        }

    def detect_bloat(self):
        # bloat = seen for >= bloat_min_days but total_active_sec <= bloat_max_active_sec
        now = time.time()
        min_days = CONFIG["bloat_min_days"]
        max_active = CONFIG["bloat_max_active_sec"]
        results = []
        for name, entry in self.program_db.items():
            first_seen = entry.get("first_seen", now)
            total_active = entry.get("total_active_sec", 0.0)
            days = (now - first_seen) / 86400.0
            if days >= min_days and total_active <= max_active:
                results.append((name, days, total_active))
        results.sort(key=lambda x: x[1], reverse=True)
        return results

usage_tracker = UsageTracker(window_minutes=CONFIG["usage_window_minutes"])

# ==========================
# WEEKLY SCAN (already handled in tracker via DB)
# ==========================
def weekly_scan_programs():
    log_info("[WEEKLY SCAN] Program DB already updated via tracker; running bloat detection.")
    bloat = usage_tracker.detect_bloat()
    if not bloat:
        log_info("[WEEKLY SCAN] No bloat candidates found.")
    else:
        for name, days, active in bloat:
            log_info(f"[BLOAT] {name}: seen {days:.1f} days, active {active:.0f}s")

# ==========================
# BACKGROUND THREADS + AUTO-STANDBY
# ==========================
def usage_loop():
    while True:
        try:
            usage_tracker.update()
            if CONFIG.get("auto_standby_enabled", True):
                auto_standby_tick()
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

def auto_standby_tick():
    candidates = usage_tracker.get_standby_candidates()
    for pid, name, cpu, idle in candidates:
        # apply gentle standby: lower priority + reduce affinity
        lower_priority(pid, name)
        reduce_affinity(pid, name)
        # optional: suspend if extremely idle
        if idle > CONFIG["standby_idle_minutes"] * 60 * 2:
            suspend_process(pid, name)

# ==========================
# SETTINGS PANEL
# ==========================
class SettingsPanel(QtWidgets.QDialog):
    def __init__(self, config):
        super().__init__()
        self.setWindowTitle("Settings")
        self.resize(420, 320)
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
        self.standby_threshold.setValue(config.get("standby_threshold_cpu", 5))
        layout.addRow("Standby threshold (% CPU):", self.standby_threshold)

        self.standby_idle = QtWidgets.QSpinBox()
        self.standby_idle.setRange(1, 120)
        self.standby_idle.setValue(config.get("standby_idle_minutes", 15))
        layout.addRow("Idle minutes before standby:", self.standby_idle)

        self.auto_standby_chk = QtWidgets.QCheckBox("Enable auto-standby")
        self.auto_standby_chk.setChecked(config.get("auto_standby_enabled", True))
        layout.addRow(self.auto_standby_chk)

        save_btn = QtWidgets.QPushButton("Save")
        save_btn.clicked.connect(self.save_settings)
        layout.addRow(save_btn)

    def save_settings(self):
        self.config["scan_interval_sec"] = self.scan_interval.value()
        self.config["usage_window_minutes"] = self.usage_window.value()
        self.config["standby_threshold_cpu"] = self.standby_threshold.value()
        self.config["standby_idle_minutes"] = self.standby_idle.value()
        self.config["auto_standby_enabled"] = self.auto_standby_chk.isChecked()
        save_config(self.config)
        self.accept()

# ==========================
# SYSTEM TRAY
# ==========================
def create_tray_icon(on_show_callback, on_exit_callback):
    # simple generated icon
    img = Image.new("RGB", (64, 64), color=(30, 30, 30))
    d = ImageDraw.Draw(img)
    d.rectangle([8, 8, 56, 56], outline=(0, 200, 0), width=3)
    d.line([16, 48, 32, 24, 48, 40], fill=(0, 200, 0), width=3)

    menu = pystray.Menu(
        pystray.MenuItem("Show", lambda icon, item: on_show_callback()),
        pystray.MenuItem("Exit", lambda icon, item: on_exit_callback())
    )
    icon = pystray.Icon("UsageMonitorPro", img, "Usage Monitor Pro", menu)
    return icon

# ==========================
# GUI
# ==========================
class UsageMonitorWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Windows Usage Monitor Pro")
        self.resize(950, 700)

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
        layout.addWidget(QtWidgets.QLabel("Standby candidates (low CPU + idle):"))
        layout.addWidget(self.standby_candidates_list)

        self.bloat_list = QtWidgets.QListWidget()
        layout.addWidget(QtWidgets.QLabel("Bloat candidates (rarely used programs):"))
        layout.addWidget(self.bloat_list)

        self.drives_label = QtWidgets.QLabel("Drives / USB status")
        layout.addWidget(self.drives_label)

        btn_layout = QtWidgets.QHBoxLayout()
        self.settings_btn = QtWidgets.QPushButton("Settings")
        self.settings_btn.clicked.connect(self.open_settings)
        btn_layout.addWidget(self.settings_btn)

        self.apply_standby_btn = QtWidgets.QPushButton("Apply Standby to Selected PID")
        self.apply_standby_btn.clicked.connect(self.apply_standby_to_selected)
        btn_layout.addWidget(self.apply_standby_btn)

        self.cleanup_btn = QtWidgets.QPushButton("Show Cleanup Suggestions")
        self.cleanup_btn.clicked.connect(self.show_cleanup_suggestions)
        btn_layout.addWidget(self.cleanup_btn)

        self.to_tray_btn = QtWidgets.QPushButton("Minimize to Tray")
        self.to_tray_btn.clicked.connect(self.minimize_to_tray)
        btn_layout.addWidget(self.to_tray_btn)

        layout.addLayout(btn_layout)

        self.setCentralWidget(central)

        self.timer = QtCore.QTimer()
        self.timer.timeout.connect(self.refresh_view)
        self.timer.start(3000)

        self.tray_icon = None
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
        with usage_tracker.lock:
            info = usage_tracker.process_usage.get(pid)
        if not info:
            return
        name = info["name"]
        lower_priority(pid, name)
        reduce_affinity(pid, name)
        suspend_process(pid, name)

    def show_cleanup_suggestions(self):
        bloat = usage_tracker.detect_bloat()
        msg_lines = []
        if not bloat:
            msg_lines.append("No bloat candidates detected.")
        else:
            for name, days, active in bloat:
                msg_lines.append(f"{name}: seen {days:.1f} days, active {active:.0f}s")
        QtWidgets.QMessageBox.information(self, "Cleanup Suggestions", "\n".join(msg_lines))

    def minimize_to_tray(self):
        self.hide()
        if self.tray_icon is None:
            def on_show():
                self.show()
            def on_exit():
                QtWidgets.QApplication.quit()
            self.tray_icon = create_tray_icon(on_show, on_exit)
            threading.Thread(target=self.tray_icon.run, daemon=True).start()

    def refresh_view(self):
        summary = usage_tracker.get_system_summary()
        summary_lines = [
            f"CPU: {summary['cpu_percent']:.1f}%",
            f"RAM: {summary['mem_used']/1024/1024:.0f} MiB / {summary['mem_total']/1024/1024:.0f} MiB ({summary['mem_percent']:.1f}%)",
            f"Disk: {summary['disk_used']/1024/1024/1024:.1f} GiB / {summary['disk_total']/1024/1024/1024:.1f} GiB ({summary['disk_percent']:.1f}%)",
            f"GPU: {summary['gpu_info']}",
        ]
        self.summary_label.setText("System summary:\n" + "\n".join(summary_lines))

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
        for pid, name, cpu, idle in usage_tracker.get_standby_candidates():
            self.standby_candidates_list.addItem(f"{pid} {name} — {cpu:.1f}% CPU, idle {idle/60:.1f} min")

        self.bloat_list.clear()
        for name, days, active in usage_tracker.detect_bloat():
            self.bloat_list.addItem(f"{name} — {days:.1f} days, {active:.0f}s active")

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
