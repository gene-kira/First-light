#!/usr/bin/env python3
"""
Python Trust Console v7 (Compact Dark, OS-Level Aware)

- Full Trust Python Interpreter (profiles)
- Multi-interpreter trust (multiple Python installs)
- System-wide .py/.pyw associations
- Auto-elevation
- Autoloader
- Registry backup + rollback
- Registry diff viewer
- Trust generator
- Reset to defaults
- Python path selector
- Profile export/import (JSON)
- Integrity monitor with scheduled checks
- Boot-time auto-scan (only if backup + trust initialized)
- Sandbox trust mode (conceptual safe dirs)
- Developer diagnostics (OS-level, Defender/SmartScreen, kernel-flow conceptual)
- Multi-node distributed trust (profile/log sync via shared JSON)
- Persistent logging
- Compact PySide6 UI with readable dark theme
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

if "--watchdog" not in sys.argv:
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
    "ctypes": "ctypes",
    "winreg": "winreg",
    "logging": "logging",
    "PySide6": "PySide6",
}

OPTIONAL_MODULES = {
    "psutil": "psutil",
}

def autoload_modules():
    missing = []
    for module_name, pip_name in {**REQUIRED_MODULES, **OPTIONAL_MODULES}.items():
        try:
            importlib.import_module(module_name)
            print(f"[AUTOLOADER] Loaded: {module_name}")
        except Exception:
            if pip_name in ("os", "time", "threading", "json", "ctypes", "winreg", "logging"):
                print(f"[AUTOLOADER] {module_name} is builtin or OS-provided.")
                continue
            print(f"[AUTOLOADER] Missing: {module_name} — will install {pip_name}")
            missing.append(pip_name)
    if missing:
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)
        for module_name in REQUIRED_MODULES.keys():
            importlib.import_module(module_name)
            print(f"[AUTOLOADER] Loaded: {module_name}")
        for module_name in OPTIONAL_MODULES.keys():
            try:
                importlib.import_module(module_name)
                print(f"[AUTOLOADER] Loaded: {module_name}")
            except Exception as e:
                print(f"[AUTOLOADER] Optional {module_name} failed: {e}")

autoload_modules()

import time
import threading
import json
import winreg
import logging
from PySide6 import QtWidgets, QtCore, QtGui

try:
    import psutil
except Exception:
    psutil = None

# ==========================
# LOGGING
# ==========================
BASE_DIR = os.getcwd()
LOG_DIR = os.path.join(BASE_DIR, "logs")
os.makedirs(LOG_DIR, exist_ok=True)
LOG_PATH = os.path.join(LOG_DIR, "trust_console.log")

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
)

def log_info(msg):
    print(msg)
    logging.info(msg)

def log_warn(msg):
    print(msg)
    logging.warning(msg)

def log_error(msg):
    print(msg)
    logging.error(msg)

# ==========================
# CONFIG (BOOT + NODE + FLAGS)
# ==========================
CONFIG_PATH = os.path.join(BASE_DIR, "trust_config.json")

DEFAULT_CONFIG = {
    "trust_initialized": False,
    "node_id": "NODE_LOCAL",
    "central_hub_path": os.path.join(BASE_DIR, "central_hub_profiles.json"),
    "auto_monitor_interval_sec": 3600,  # 1 hour
    "auto_monitor_enabled": True,
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
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        log_info("[CONFIG] trust_config.json updated.")
    except Exception as e:
        log_error(f"[CONFIG ERROR] {e}")

CONFIG = load_config()

# ==========================
# REGISTRY HELPERS
# ==========================
def set_reg(root, path, name, value, reg_type=winreg.REG_SZ):
    try:
        key = winreg.CreateKey(root, path)
        winreg.SetValueEx(key, name, 0, reg_type, value)
        winreg.CloseKey(key)
        return True, ""
    except Exception as e:
        return False, str(e)

def get_reg(root, path, name=None):
    try:
        key = winreg.OpenKey(root, path)
        if name is None:
            val, _ = winreg.QueryValueEx(key, "")
        else:
            val, _ = winreg.QueryValueEx(key, name)
        winreg.CloseKey(key)
        return True, val
    except FileNotFoundError:
        return True, "NOT SET"
    except Exception as e:
        return False, f"ERROR: {e}"

def delete_key(root, path):
    try:
        winreg.DeleteKey(root, path)
        return True, ""
    except FileNotFoundError:
        return True, ""
    except Exception as e:
        return False, str(e)

# ==========================
# ROLLBACK SYSTEM + DIFF
# ==========================
BACKUP_PATH = os.path.join(BASE_DIR, "trust_backup.json")
DIFF_PATH = os.path.join(BASE_DIR, "trust_diff.json")

REG_KEYS = {
    "AppPaths": (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\python.exe", ""),
    "PY_EXT": (winreg.HKEY_CLASSES_ROOT, r".py", ""),
    "PY_CMD": (winreg.HKEY_CLASSES_ROOT, r"Python.File\\Shell\\Open\\Command", ""),
    "PYW_EXT": (winreg.HKEY_CLASSES_ROOT, r".pyw", ""),
    "PYW_CMD": (winreg.HKEY_CLASSES_ROOT, r"Python.NoConsole\\Shell\\Open\\Command", ""),
}

def snapshot_registry():
    snap = {}
    for key_name, (root, path, value_name) in REG_KEYS.items():
        ok, val = get_reg(root, path, value_name)
        snap[key_name] = val if ok else None
    return snap

def backup_registry(gui_log=None):
    backup = snapshot_registry()
    with open(BACKUP_PATH, "w", encoding="utf-8") as f:
        json.dump(backup, f, indent=2)
    msg = "[BACKUP] Registry snapshot saved."
    log_info(msg)
    if gui_log:
        gui_log(msg)

def compute_diff(old, new):
    diff = {}
    for k in REG_KEYS.keys():
        ov = old.get(k)
        nv = new.get(k)
        if ov != nv:
            diff[k] = {"old": ov, "new": nv}
    return diff

def save_diff(diff, gui_log=None):
    with open(DIFF_PATH, "w", encoding="utf-8") as f:
        json.dump(diff, f, indent=2)
    msg = "[DIFF] Registry diff saved."
    log_info(msg)
    if gui_log:
        gui_log(msg)

def rollback_registry(gui_log=None):
    if not os.path.isfile(BACKUP_PATH):
        msg = "[ROLLBACK] No backup found."
        log_warn(msg)
        if gui_log:
            gui_log(msg)
        return False

    try:
        with open(BACKUP_PATH, "r", encoding="utf-8") as f:
            backup = json.load(f)

        current = snapshot_registry()
        diff = compute_diff(current, backup)
        save_diff(diff, gui_log)

        for key_name, (root, path, value_name) in REG_KEYS.items():
            old_val = backup.get(key_name)
            if old_val is None:
                continue
            ok, err = set_reg(root, path, value_name, old_val)
            if ok:
                msg = f"[ROLLBACK] Restored {key_name}"
                log_info(msg)
            else:
                msg = f"[ROLLBACK FAIL] {key_name}: {err}"
                log_warn(msg)
            if gui_log:
                gui_log(msg)

        msg = "[ROLLBACK] Completed."
        log_info(msg)
        if gui_log:
            gui_log(msg)
        return True

    except Exception as e:
        msg = f"[ROLLBACK ERROR] {e}"
        log_error(msg)
        if gui_log:
            gui_log(msg)
        return False

# ==========================
# TRUST PROFILES + EXPORT/IMPORT + HUB SYNC
# ==========================
PROFILE_BASIC = "Basic"
PROFILE_FULL = "Full"
PROFILE_DEV = "Developer"
PROFILE_AGG = "Aggressive"
PROFILE_SANDBOX = "Sandbox"

TRUST_PROFILES = [PROFILE_BASIC, PROFILE_FULL, PROFILE_DEV, PROFILE_AGG, PROFILE_SANDBOX]

PROFILE_STORE_PATH = os.path.join(BASE_DIR, "trust_profiles.json")

DEFAULT_PROFILE_CONFIG = {
    PROFILE_BASIC: {"app_paths": False, "py": True, "pyw": False, "dev_tools": False, "aggressive": False, "sandbox": False},
    PROFILE_FULL: {"app_paths": True, "py": True, "pyw": True, "dev_tools": False, "aggressive": False, "sandbox": False},
    PROFILE_DEV: {"app_paths": True, "py": True, "pyw": True, "dev_tools": True, "aggressive": False, "sandbox": False},
    PROFILE_AGG: {"app_paths": True, "py": True, "pyw": True, "dev_tools": True, "aggressive": True, "sandbox": False},
    PROFILE_SANDBOX: {"app_paths": True, "py": True, "pyw": False, "dev_tools": False, "aggressive": False, "sandbox": True},
}

def load_profiles():
    if not os.path.isfile(PROFILE_STORE_PATH):
        return DEFAULT_PROFILE_CONFIG.copy()
    try:
        with open(PROFILE_STORE_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        for p in TRUST_PROFILES:
            if p not in data:
                data[p] = DEFAULT_PROFILE_CONFIG[p]
        return data
    except Exception:
        return DEFAULT_PROFILE_CONFIG.copy()

def save_profiles(profiles, gui_log=None):
    try:
        with open(PROFILE_STORE_PATH, "w", encoding="utf-8") as f:
            json.dump(profiles, f, indent=2)
        msg = "[PROFILE] Profiles exported to trust_profiles.json"
        log_info(msg)
        if gui_log:
            gui_log(msg)
    except Exception as e:
        msg = f"[PROFILE ERROR] Export failed: {e}"
        log_error(msg)
        if gui_log:
            gui_log(msg)

def sync_profiles_to_hub(profiles, gui_log=None):
    hub_path = CONFIG.get("central_hub_path")
    try:
        with open(hub_path, "w", encoding="utf-8") as f:
            json.dump({"node_id": CONFIG.get("node_id"), "profiles": profiles}, f, indent=2)
        msg = f"[HUB] Profiles synced to central hub: {hub_path}"
        log_info(msg)
        if gui_log:
            gui_log(msg)
    except Exception as e:
        msg = f"[HUB ERROR] Sync failed: {e}"
        log_error(msg)
        if gui_log:
            gui_log(msg)

def load_profiles_from_hub(gui_log=None):
    hub_path = CONFIG.get("central_hub_path")
    if not os.path.isfile(hub_path):
        msg = "[HUB] No central hub profile file found."
        log_warn(msg)
        if gui_log:
            gui_log(msg)
        return None
    try:
        with open(hub_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        profiles = data.get("profiles", {})
        msg = f"[HUB] Profiles loaded from central hub: {hub_path}"
        log_info(msg)
        if gui_log:
            gui_log(msg)
        return profiles
    except Exception as e:
        msg = f"[HUB ERROR] Load failed: {e}"
        log_error(msg)
        if gui_log:
            gui_log(msg)
        return None

# ==========================
# PYTHON TRUST MODEL
# ==========================
SAFE_SANDBOX_DIRS = [
    os.path.expanduser(r"~\\Documents\\PythonSafe"),
    os.path.expanduser(r"~\\Desktop\\PythonSafe"),
]

def register_app_paths(python_exe, gui_log=None):
    ok, err = set_reg(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\python.exe",
        "",
        python_exe
    )
    if ok:
        msg = f"[TRUST] AppPaths registered: {python_exe}"
        log_info(msg)
    else:
        msg = f"[TRUST FAIL] AppPaths: {err}"
        log_warn(msg)
    if gui_log:
        gui_log(msg)
    return ok

def register_py_association(python_exe, gui_log=None, sandbox=False):
    handler = "Python.File"
    ok1, err1 = set_reg(
        winreg.HKEY_CLASSES_ROOT,
        r".py",
        "",
        handler
    )
    cmd = f'"{python_exe}" "%1" %*'
    # Sandbox is conceptual: user keeps scripts in SAFE_SANDBOX_DIRS
    ok2, err2 = set_reg(
        winreg.HKEY_CLASSES_ROOT,
        r"Python.File\\Shell\\Open\\Command",
        "",
        cmd
    )
    if ok1 and ok2:
        msg = "[TRUST] .py association registered"
        log_info(msg)
    else:
        msg = f"[TRUST FAIL] .py association: {err1 or err2}"
        log_warn(msg)
    if gui_log:
        gui_log(msg)
    return ok1 and ok2

def register_pyw_association(python_exe, gui_log=None):
    ok3, err3 = set_reg(
        winreg.HKEY_CLASSES_ROOT,
        r".pyw",
        "",
        "Python.NoConsole"
    )
    ok4, err4 = set_reg(
        winreg.HKEY_CLASSES_ROOT,
        r"Python.NoConsole\\Shell\\Open\\Command",
        "",
        f'"{python_exe}" "%1" %*'
    )
    if ok3 and ok4:
        msg = "[TRUST] .pyw association registered"
        log_info(msg)
    else:
        msg = f"[TRUST FAIL] .pyw association: {err3 or err4}"
        log_warn(msg)
    if gui_log:
        gui_log(msg)
    return ok3 and ok4

def register_dev_tools(python_exe, gui_log=None):
    venv_path = os.path.join(os.path.dirname(python_exe), "Scripts")
    msg = f"[DEV] Developer trust (pip/venv) assumed at {venv_path}"
    log_info(msg)
    if gui_log:
        gui_log(msg)
    return True

def register_aggressive(python_exe, gui_log=None):
    msg = "[AGG] Aggressive profile: system-wide Python script trust enabled (via associations)."
    log_info(msg)
    if gui_log:
        gui_log(msg)
    return True

def apply_trust_profile(profile_name, python_exe_list, profiles_cfg, gui_log=None):
    cfg = profiles_cfg.get(profile_name, DEFAULT_PROFILE_CONFIG[profile_name])
    ok_all = True
    for python_exe in python_exe_list:
        if cfg.get("app_paths"):
            ok_all &= register_app_paths(python_exe, gui_log)
        if cfg.get("py"):
            ok_all &= register_py_association(python_exe, gui_log, sandbox=cfg.get("sandbox", False))
        if cfg.get("pyw"):
            ok_all &= register_pyw_association(python_exe, gui_log)
        if cfg.get("dev_tools"):
            ok_all &= register_dev_tools(python_exe, gui_log)
        if cfg.get("aggressive"):
            ok_all &= register_aggressive(python_exe, gui_log)

    if ok_all:
        CONFIG["trust_initialized"] = True
        save_config(CONFIG)

    if gui_log:
        if ok_all:
            gui_log(f"[TRUST] Profile '{profile_name}' applied to {len(python_exe_list)} interpreter(s). trust_initialized=True")
        else:
            gui_log(f"[TRUST FAIL] Profile '{profile_name}' encountered errors.")
    return ok_all

# ==========================
# STATUS + TRUST GENERATOR
# ==========================
def check_status():
    status = {}
    ok, val = get_reg(
        winreg.HKEY_LOCAL_MACHINE,
        r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\python.exe"
    )
    status["AppPaths"] = val if ok else f"ERROR: {val}"

    ok2, val2 = get_reg(
        winreg.HKEY_CLASSES_ROOT,
        r".py"
    )
    status[".py"] = val2 if ok2 else f"ERROR: {val2}"

    ok3, val3 = get_reg(
        winreg.HKEY_CLASSES_ROOT,
        r"Python.File\\Shell\\Open\\Command"
    )
    status["Python.File Command"] = val3 if ok3 else f"ERROR: {val3}"

    ok4, val4 = get_reg(
        winreg.HKEY_CLASSES_ROOT,
        r".pyw"
    )
    status[".pyw"] = val4 if ok4 else f"ERROR: {val4}"

    ok5, val5 = get_reg(
        winreg.HKEY_CLASSES_ROOT,
        r"Python.NoConsole\\Shell\\Open\\Command"
    )
    status["Python.NoConsole Command"] = val5 if ok5 else f"ERROR: {val5}"

    return status

def generate_trust_for_missing(python_exe_list, gui_log=None):
    status = check_status()

    def needs_fix(val):
        s = str(val)
        return s.startswith("NOT SET") or s.startswith("ERROR")

    for python_exe in python_exe_list:
        if needs_fix(status.get("AppPaths", "")):
            register_app_paths(python_exe, gui_log)

        if needs_fix(status.get(".py", "")):
            register_py_association(python_exe, gui_log)

        if needs_fix(status.get("Python.File Command", "")):
            register_py_association(python_exe, gui_log)

        if needs_fix(status.get(".pyw", "")):
            register_pyw_association(python_exe, gui_log)

        if needs_fix(status.get("Python.NoConsole Command", "")):
            register_pyw_association(python_exe, gui_log)

    msg = "[GEN] Trust generator finished."
    log_info(msg)
    if gui_log:
        gui_log(msg)
    return True

# ==========================
# RESET TO WINDOWS DEFAULTS (approx)
# ==========================
def reset_to_defaults(gui_log=None):
    delete_key(winreg.HKEY_CLASSES_ROOT, r".py")
    delete_key(winreg.HKEY_CLASSES_ROOT, r"Python.File\\Shell\\Open\\Command")
    delete_key(winreg.HKEY_CLASSES_ROOT, r".pyw")
    delete_key(winreg.HKEY_CLASSES_ROOT, r"Python.NoConsole\\Shell\\Open\\Command")
    msg = "[RESET] .py/.pyw associations cleared (Windows defaults will apply if present)."
    log_info(msg)
    if gui_log:
        gui_log(msg)
    return True

# ==========================
# INTEGRITY MONITOR (scheduled, boot-aware)
# ==========================
class IntegrityMonitor(threading.Thread):
    def __init__(self, gui_log=None, interval=3600, auto_repair=False, python_exe_list=None):
        super().__init__(daemon=True)
        self.gui_log = gui_log
        self.interval = interval
        self.auto_repair = auto_repair
        self.python_exe_list = python_exe_list or [sys.executable]
        self.last_status = None
        self.running = True

    def run(self):
        while self.running:
            try:
                status = check_status()
                if self.last_status is not None and status != self.last_status:
                    msg = "[INTEGRITY] Trust status changed (registry drift detected)."
                    log_warn(msg)
                    if self.gui_log:
                        self.gui_log(msg)
                    if self.auto_repair:
                        msg2 = "[INTEGRITY] Auto-repair enabled — regenerating trust."
                        log_info(msg2)
                        if self.gui_log:
                            self.gui_log(msg2)
                        generate_trust_for_missing(self.python_exe_list, self.gui_log)
                self.last_status = status
            except Exception as e:
                msg = f"[INTEGRITY ERROR] {e}"
                log_error(msg)
                if self.gui_log:
                    self.gui_log(msg)
            time.sleep(self.interval)

    def stop(self):
        self.running = False

def boot_time_auto_scan(gui_log=None):
    if not os.path.isfile(BACKUP_PATH):
        msg = "[BOOT] Auto-scan skipped: no backup present."
        log_warn(msg)
        if gui_log:
            gui_log(msg)
        return
    if not CONFIG.get("trust_initialized", False):
        msg = "[BOOT] Auto-scan skipped: trust not initialized."
        log_warn(msg)
        if gui_log:
            gui_log(msg)
        return

    msg = "[BOOT] Auto-scan starting: backup present and trust_initialized=True."
    log_info(msg)
    if gui_log:
        gui_log(msg)

    current = snapshot_registry()
    with open(BACKUP_PATH, "r", encoding="utf-8") as f:
        backup = json.load(f)
    diff = compute_diff(current, backup)
    if diff:
        save_diff(diff, gui_log)
        msg2 = "[BOOT] Drift detected — running trust generator for repair."
        log_warn(msg2)
        if gui_log:
            gui_log(msg2)
        generate_trust_for_missing([sys.executable], gui_log)
    else:
        msg2 = "[BOOT] No drift detected — trust baseline intact."
        log_info(msg2)
        if gui_log:
            gui_log(msg2)

# ==========================
# PYTHON PATH DISCOVERY
# ==========================
def discover_python_paths():
    paths = [sys.executable]
    common = [
        r"C:\\Python39\\python.exe",
        r"C:\\Python311\\python.exe",
        r"C:\\Program Files\\Python311\\python.exe",
        r"C:\\Program Files\\Python39\\python.exe",
    ]
    for p in common:
        if os.path.isfile(p) and p not in paths:
            paths.append(p)
    return paths

# ==========================
# COMPACT PySide6 GUI (Dark, v7)
# ==========================
from PySide6 import QtWidgets, QtCore, QtGui

class TrustConsoleWindow(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Python Trust Console v7 (Compact Dark, OS-Level Aware)")
        self.resize(1000, 650)

        self.python_paths = discover_python_paths()
        self.selected_python_paths = set(self.python_paths)
        self.current_profile = PROFILE_FULL
        self.integrity_monitor = None
        self.profiles_cfg = load_profiles()

        self._init_ui()
        self.refresh_status()
        self.refresh_profiles_view()
        self.refresh_dev_diag()

        # Boot-time auto-scan (conceptual OS-level trust flow)
        boot_time_auto_scan(self.gui_log)

        # Auto-start monitor if config says so
        if CONFIG.get("auto_monitor_enabled", True):
            self.gui_log("[BOOT] Auto-monitor enabled in config — starting hourly integrity monitor.")
            self.start_monitor_internal(auto=True)

    def _init_ui(self):
        central = QtWidgets.QWidget()
        self.setCentralWidget(central)

        main_layout = QtWidgets.QVBoxLayout(central)

        # Top row: profile + python selector + node info
        top_row = QtWidgets.QHBoxLayout()

        self.profile_combo = QtWidgets.QComboBox()
        self.profile_combo.addItems(TRUST_PROFILES)
        self.profile_combo.setCurrentText(self.current_profile)
        self.profile_combo.currentTextChanged.connect(self.on_profile_changed)

        self.python_list = QtWidgets.QListWidget()
        self.python_list.setSelectionMode(QtWidgets.QAbstractItemView.MultiSelection)
        for p in self.python_paths:
            item = QtWidgets.QListWidgetItem(p)
            item.setSelected(True)
            self.python_list.addItem(item)

        browse_btn = QtWidgets.QPushButton("Add Python")
        browse_btn.clicked.connect(self.on_browse_python)

        self.node_label = QtWidgets.QLabel(f"Node: {CONFIG.get('node_id')}")

        top_row.addWidget(QtWidgets.QLabel("Profile:"))
        top_row.addWidget(self.profile_combo)
        top_row.addSpacing(10)
        top_row.addWidget(QtWidgets.QLabel("Interpreters:"))
        top_row.addWidget(self.python_list)
        top_row.addWidget(browse_btn)
        top_row.addSpacing(10)
        top_row.addWidget(self.node_label)

        main_layout.addLayout(top_row)

        # Button row: actions
        btn_row = QtWidgets.QHBoxLayout()

        apply_btn = QtWidgets.QPushButton("Apply Trust")
        apply_btn.clicked.connect(self.on_apply_trust)

        gen_btn = QtWidgets.QPushButton("Generate Trust")
        gen_btn.clicked.connect(self.on_generate_trust)

        reset_btn = QtWidgets.QPushButton("Reset Defaults")
        reset_btn.clicked.connect(self.on_reset_defaults)

        backup_btn = QtWidgets.QPushButton("Backup")
        backup_btn.clicked.connect(self.on_backup)

        rollback_btn = QtWidgets.QPushButton("Rollback (with Diff)")
        rollback_btn.clicked.connect(self.on_rollback)

        start_mon_btn = QtWidgets.QPushButton("Start Monitor (Hourly)")
        start_mon_btn.clicked.connect(self.on_start_monitor)

        stop_mon_btn = QtWidgets.QPushButton("Stop Monitor")
        stop_mon_btn.clicked.connect(self.on_stop_monitor)

        export_prof_btn = QtWidgets.QPushButton("Export Profiles")
        export_prof_btn.clicked.connect(self.on_export_profiles)

        import_prof_btn = QtWidgets.QPushButton("Reload Profiles")
        import_prof_btn.clicked.connect(self.on_import_profiles)

        sync_hub_btn = QtWidgets.QPushButton("Sync to Hub")
        sync_hub_btn.clicked.connect(self.on_sync_hub)

        load_hub_btn = QtWidgets.QPushButton("Load from Hub")
        load_hub_btn.clicked.connect(self.on_load_hub)

        btn_row.addWidget(apply_btn)
        btn_row.addWidget(gen_btn)
        btn_row.addWidget(reset_btn)
        btn_row.addWidget(backup_btn)
        btn_row.addWidget(rollback_btn)
        btn_row.addWidget(start_mon_btn)
        btn_row.addWidget(stop_mon_btn)
        btn_row.addWidget(export_prof_btn)
        btn_row.addWidget(import_prof_btn)
        btn_row.addWidget(sync_hub_btn)
        btn_row.addWidget(load_hub_btn)

        main_layout.addLayout(btn_row)

        # Splitter: status/log + diagnostics
        splitter = QtWidgets.QSplitter(QtCore.Qt.Vertical)

        upper_split = QtWidgets.QSplitter(QtCore.Qt.Horizontal)

        self.status_view = QtWidgets.QPlainTextEdit()
        self.status_view.setReadOnly(True)
        self.status_view.setFont(QtGui.QFont("Consolas", 9))
        self.status_view.setPlaceholderText("Registry / Trust Status")

        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        self.log_view.setFont(QtGui.QFont("Consolas", 9))
        self.log_view.setPlaceholderText("Activity Log")

        upper_split.addWidget(self.status_view)
        upper_split.addWidget(self.log_view)
        upper_split.setSizes([450, 450])

        self.dev_diag_view = QtWidgets.QPlainTextEdit()
        self.dev_diag_view.setReadOnly(True)
        self.dev_diag_view.setFont(QtGui.QFont("Consolas", 9))
        self.dev_diag_view.setPlaceholderText(
            "Developer Diagnostics:\n"
            "- OS-level trust flow (conceptual)\n"
            "- Defender/SmartScreen interactions (conceptual)\n"
            "- Kernel event bus (conceptual)\n"
            "- Node + hub info\n"
            "- Sandbox dirs\n"
            "- Backup/diff/profile paths\n"
        )

        splitter.addWidget(upper_split)
        splitter.addWidget(self.dev_diag_view)
        splitter.setSizes([380, 270])

        main_layout.addWidget(splitter)

        # Dark theme + styles
        palette = self.palette()
        palette.setColor(QtGui.QPalette.Window, QtGui.QColor(28, 28, 28))
        palette.setColor(QtGui.QPalette.Base, QtGui.QColor(18, 18, 18))
        palette.setColor(QtGui.QPalette.Text, QtGui.QColor(240, 240, 240))
        palette.setColor(QtGui.QPalette.Button, QtGui.QColor(55, 55, 55))
        palette.setColor(QtGui.QPalette.ButtonText, QtGui.QColor(255, 255, 255))
        palette.setColor(QtGui.QPalette.Highlight, QtGui.QColor(70, 70, 70))
        palette.setColor(QtGui.QPalette.HighlightedText, QtGui.QColor(255, 255, 255))
        palette.setColor(QtGui.QPalette.WindowText, QtGui.QColor(230, 230, 230))
        self.setPalette(palette)

        for btn in self.findChildren(QtWidgets.QPushButton):
            btn.setStyleSheet("""
                QPushButton {
                    color: white;
                    background-color: #444444;
                    border: 1px solid #666666;
                    padding: 6px;
                }
                QPushButton:hover {
                    background-color: #555555;
                }
                QPushButton:pressed {
                    background-color: #333333;
                }
            """)

        for combo in self.findChildren(QtWidgets.QComboBox):
            combo.setStyleSheet("""
                QComboBox {
                    color: white;
                    background-color: #444444;
                    padding: 4px;
                }
                QComboBox QAbstractItemView {
                    background-color: #333333;
                    color: white;
                    selection-background-color: #555555;
                }
            """)

        self.python_list.setStyleSheet("""
            QListWidget {
                color: white;
                background-color: #222222;
            }
            QListWidget::item:selected {
                background-color: #555555;
            }
        """)

    # ---------- GUI helpers ----------
    def gui_log(self, msg):
        self.log_view.appendPlainText(msg)
        self.log_view.verticalScrollBar().setValue(
            self.log_view.verticalScrollBar().maximum()
        )

    def set_status(self, status_dict):
        self.status_view.clear()
        for k, v in status_dict.items():
            self.status_view.appendPlainText(f"{k}: {v}")

    def refresh_status(self):
        status = check_status()
        self.set_status(status)
        self.gui_log("[INFO] Status refreshed")

    def refresh_profiles_view(self):
        self.dev_diag_view.appendPlainText("[PROFILES] Current profile configuration:")
        for name, cfg in self.profiles_cfg.items():
            self.dev_diag_view.appendPlainText(f"  {name}: {cfg}")
        self.dev_diag_view.appendPlainText("")

    def refresh_dev_diag(self):
        self.dev_diag_view.appendPlainText("[DIAG] Python interpreters:")
        for p in self.python_paths:
            self.dev_diag_view.appendPlainText(f"  {p}")
        self.dev_diag_view.appendPlainText("")
        self.dev_diag_view.appendPlainText("[DIAG] Sandbox directories (conceptual safe locations):")
        for d in SAFE_SANDBOX_DIRS:
            self.dev_diag_view.appendPlainText(f"  {d}")
        self.dev_diag_view.appendPlainText("")
        self.dev_diag_view.appendPlainText(f"[DIAG] Backup file: {BACKUP_PATH}")
        self.dev_diag_view.appendPlainText(f"[DIAG] Diff file:   {DIFF_PATH}")
        self.dev_diag_view.appendPlainText(f"[DIAG] Profiles file: {PROFILE_STORE_PATH}")
        self.dev_diag_view.appendPlainText(f"[DIAG] Config file:   {CONFIG_PATH}")
        self.dev_diag_view.appendPlainText(f"[DIAG] Central hub file: {CONFIG.get('central_hub_path')}")
        self.dev_diag_view.appendPlainText("")
        self.dev_diag_view.appendPlainText("[DIAG] OS-level trust flow (conceptual):")
        self.dev_diag_view.appendPlainText("  Kernel Event Bus -> Registry Layer -> Trust Engine -> Profiles -> Execution Policy")
        self.dev_diag_view.appendPlainText("  SmartScreen/Defender -> Warning/Block -> Trust Engine Check -> Log/Repair/Rollback")
        self.dev_diag_view.appendPlainText("")
        self.dev_diag_view.appendPlainText("[DIAG] Node + Distributed Trust:")
        self.dev_diag_view.appendPlainText(f"  Node ID: {CONFIG.get('node_id')}")
        self.dev_diag_view.appendPlainText("  Local Trust Engine <-> Central Hub (JSON sync)")
        self.dev_diag_view.appendPlainText("")

    def get_selected_python_list(self):
        selected = []
        for i in range(self.python_list.count()):
            item = self.python_list.item(i)
            if item.isSelected():
                selected.append(item.text())
        if not selected:
            selected = [sys.executable]
        return selected

    # ---------- Events ----------
    def on_profile_changed(self, text):
        self.current_profile = text
        self.gui_log(f"[GUI] Profile changed to {text}")

    def on_browse_python(self):
        dlg = QtWidgets.QFileDialog(self, "Select python.exe")
        dlg.setFileMode(QtWidgets.QFileDialog.ExistingFile)
        dlg.setNameFilter("Python Executable (python.exe)")
        if dlg.exec():
            files = dlg.selectedFiles()
            if files:
                path = files[0]
                if path not in self.python_paths:
                    self.python_paths.append(path)
                    item = QtWidgets.QListWidgetItem(path)
                    item.setSelected(True)
                    self.python_list.addItem(item)
                self.gui_log(f"[GUI] Added interpreter: {path}")
                self.refresh_dev_diag()

    def on_apply_trust(self):
        def worker():
            self.gui_log("[RUN] Backup before trust...")
            backup_registry(self.gui_log)

            py_list = self.get_selected_python_list()
            self.gui_log(f"[RUN] Applying profile '{self.current_profile}' to {len(py_list)} interpreter(s)...")
            ok = apply_trust_profile(self.current_profile, py_list, self.profiles_cfg, self.gui_log)

            if not ok:
                self.gui_log("[FAIL] Trust failed — rolling back...")
                rollback_registry(self.gui_log)

            self.refresh_status()

        threading.Thread(target=worker, daemon=True).start()

    def on_generate_trust(self):
        def worker():
            self.gui_log("[RUN] Trust generator started...")
            py_list = self.get_selected_python_list()
            generate_trust_for_missing(py_list, self.gui_log)
            self.gui_log("[DONE] Trust generator finished.")
            self.refresh_status()

        threading.Thread(target=worker, daemon=True).start()

    def on_reset_defaults(self):
        def worker():
            self.gui_log("[RUN] Resetting to Windows defaults (approx)...")
            reset_to_defaults(self.gui_log)
            self.gui_log("[DONE] Reset completed.")
            self.refresh_status()

        threading.Thread(target=worker, daemon=True).start()

    def on_backup(self):
        def worker():
            self.gui_log("[RUN] Manual backup...")
            backup_registry(self.gui_log)
            self.gui_log("[DONE] Backup completed.")
            self.refresh_status()

        threading.Thread(target=worker, daemon=True).start()

    def on_rollback(self):
        def worker():
            self.gui_log("[RUN] Manual rollback (with diff)...")
            ok = rollback_registry(self.gui_log)
            if ok:
                self.gui_log("[DONE] Rollback successful. Diff saved.")
            else:
                self.gui_log("[WARN] Rollback failed or no backup.")
            self.refresh_status()

        threading.Thread(target=worker, daemon=True).start()

    def start_monitor_internal(self, auto=False):
        if self.integrity_monitor and self.integrity_monitor.running:
            if not auto:
                self.gui_log("[MON] Monitor already running.")
            return
        py_list = self.get_selected_python_list()
        interval = CONFIG.get("auto_monitor_interval_sec", 3600)
        self.gui_log(f"[MON] Starting integrity monitor (interval={interval}s, auto-repair ON)...")
        self.integrity_monitor = IntegrityMonitor(
            gui_log=self.gui_log,
            interval=interval,
            auto_repair=True,
            python_exe_list=py_list,
        )
        self.integrity_monitor.start()

    def on_start_monitor(self):
        self.start_monitor_internal(auto=False)

    def on_stop_monitor(self):
        if self.integrity_monitor:
            self.gui_log("[MON] Stopping integrity monitor...")
            self.integrity_monitor.stop()
            self.integrity_monitor = None
        else:
            self.gui_log("[MON] Monitor not running.")

    def on_export_profiles(self):
        save_profiles(self.profiles_cfg, self.gui_log)
        self.refresh_profiles_view()

    def on_import_profiles(self):
        self.profiles_cfg = load_profiles()
        self.gui_log("[PROFILE] Profiles reloaded from trust_profiles.json")
        self.refresh_profiles_view()

    def on_sync_hub(self):
        sync_profiles_to_hub(self.profiles_cfg, self.gui_log)
        self.refresh_profiles_view()

    def on_load_hub(self):
        hub_profiles = load_profiles_from_hub(self.gui_log)
        if hub_profiles:
            self.profiles_cfg = hub_profiles
            self.gui_log("[HUB] Local profiles replaced with hub profiles.")
            self.refresh_profiles_view()

    def closeEvent(self, event):
        if self.integrity_monitor:
            self.integrity_monitor.stop()
        super().closeEvent(event)

# ==========================
# ENTRY POINT
# ==========================
def main():
    app = QtWidgets.QApplication(sys.argv)
    win = TrustConsoleWindow()
    win.show()
    sys.exit(app.exec())

if __name__ == "__main__":
    main()
