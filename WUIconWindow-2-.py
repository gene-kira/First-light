#!/usr/bin/env python3
# codex_honeypot_gui_v6.py

import os
import sys
import json
import time
import threading
import subprocess
import importlib
import traceback
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List, Optional

BASE_DIR = os.path.join(os.path.expanduser("~"), "CodexHoneypot")
os.makedirs(BASE_DIR, exist_ok=True)

CONFIG_PATH = Path(BASE_DIR) / "codex_honeypot_config.json"
STATE_PATH = Path(BASE_DIR) / "codex_honeypot_state.json"

DEFAULT_CONFIG = {
    "honeypot_mode": "C",
    "window_scope_mode": 2,
    "autoloader_enabled": True,
    "headless": False,
    "win32_hooks_enabled": True,
}

DEFAULT_STATE = {
    "known_window_classes": [
        "Progman", "Shell_TrayWnd", "Chrome_WidgetWin_0",
        "ApplicationFrameWindow", "Windows.UI.Core.CoreWindow"
    ],
    "trapped_windows": [],
    "behavior_log": [],
    "ai_model_state": {}
}

def load_json(path: Path, default: Dict[str, Any]) -> Dict[str, Any]:
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, dict):
                    return data
    except Exception:
        print(f"[WARN] JSON corrupted: {path}. Resetting to default.")
    return default.copy()

def save_json(path: Path, data: Dict[str, Any]):
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[WARN] Failed to save {path}: {e}")

config = load_json(CONFIG_PATH, DEFAULT_CONFIG)
state = load_json(STATE_PATH, DEFAULT_STATE)

# ============================================================
# AUTOLOADER
# ============================================================

class Autoloader:
    def __init__(self):
        self.dependency_map: Dict[str, Dict[str, Any]] = {
            "network": {"modules": ["requests"], "install": True},
            "notify": {"modules": ["win10toast"], "install": True},
            "win32": {"modules": ["ctypes"], "install": False},
            "honeypot": {"modules": ["psutil"], "install": True},
            "ai": {"modules": ["numpy"], "install": False},
        }
        self.loaded_modules: Dict[str, Any] = {}
        self.missing_modules: Dict[str, List[str]] = {}
        self.lock = threading.Lock()
        self.predictive_thread: Optional[threading.Thread] = None
        self.predictive_running = False

    def _soft_import(self, module_name: str) -> Optional[Any]:
        try:
            return importlib.import_module(module_name)
        except ImportError:
            return None

    def _hard_install(self, module_name: str) -> bool:
        try:
            print(f"[Autoloader] Installing {module_name}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", module_name])
            return True
        except Exception as e:
            print(f"[Autoloader] Failed to install {module_name}: {e}")
            return False

    def ensure_group(self, group_name: str):
        group = self.dependency_map.get(group_name, {})
        modules = group.get("modules", [])
        allow_install = group.get("install", False)
        missing = []
        for m in modules:
            mod = self._soft_import(m)
            if mod is None:
                missing.append(m)
                if allow_install and self._hard_install(m):
                    mod = self._soft_import(m)
            if mod is not None:
                with self.lock:
                    self.loaded_modules[m] = mod
        if missing:
            with self.lock:
                self.missing_modules[group_name] = missing

    def start_predictive_daemon(self):
        if self.predictive_running:
            return

        def _daemon():
            self.predictive_running = True
            for g in list(self.dependency_map.keys()):
                self.ensure_group(g)
                time.sleep(0.5)
            self.predictive_running = False

        self.predictive_thread = threading.Thread(target=_daemon, daemon=True)
        self.predictive_thread.start()

    def get_module(self, name: str) -> Optional[Any]:
        return self.loaded_modules.get(name)

AUTOLOADER = Autoloader()
if config.get("autoloader_enabled", True):
    AUTOLOADER.start_predictive_daemon()

# ============================================================
# MODE / SCOPE
# ============================================================

def set_honeypot_mode(mode: str):
    assert mode in ("A", "B", "C")
    config["honeypot_mode"] = mode
    save_json(CONFIG_PATH, config)
    print(f"[Mode] Honeypot mode -> {mode}")

def get_honeypot_mode() -> str:
    return config.get("honeypot_mode", "C")

def set_window_scope_mode(scope: int):
    assert scope in (1, 2, 3)
    config["window_scope_mode"] = scope
    save_json(CONFIG_PATH, config)
    print(f"[Scope] Window scope -> {scope}")

def get_window_scope_mode() -> int:
    return config.get("window_scope_mode", 2)

def is_known_window_class(cls_name: str) -> bool:
    return cls_name in state["known_window_classes"]

def ai_decide_trap(cls_name: str) -> bool:
    if not is_known_window_class(cls_name):
        return True
    return False

def should_trap_window(cls_name: str) -> bool:
    scope = get_window_scope_mode()
    if scope == 1:
        return cls_name == "wuiconwindow"
    if scope == 2:
        return not is_known_window_class(cls_name)
    if scope == 3:
        return ai_decide_trap(cls_name)
    return False

# ============================================================
# AI SCORING PIPELINE (NUMPY STUB)
# ============================================================

def ai_score_window(cls_name: str) -> float:
    np = AUTOLOADER.get_module("numpy")
    base = 0.3
    name = cls_name.lower()
    if "wuico" in name:
        base = 0.85
    elif "unknown" in name:
        base = 0.75
    if np is None:
        return base
    vec = np.array([len(name), base])
    score = float(vec[1] + (vec[0] % 5) * 0.02)
    return max(0.0, min(1.0, score))

# ============================================================
# LOGGING / HONEYPOT
# ============================================================

def log_behavior(pid: int, cls_name: str, action: str):
    entry = {
        "pid": pid,
        "class": cls_name,
        "action": action,
        "timestamp": datetime.now().isoformat()
    }
    state["behavior_log"].append(entry)
    save_json(STATE_PATH, state)

def trap_window_in_honeypot(hwnd: int, cls_name: str, pid: int):
    entry = {
        "hwnd": hwnd,
        "class": cls_name,
        "pid": pid,
        "timestamp": datetime.now().isoformat()
    }
    state["trapped_windows"].append(entry)
    save_json(STATE_PATH, state)

    mode = get_honeypot_mode()
    if mode == "A":
        apply_soft_honeypot(hwnd, cls_name, pid)
    elif mode == "B":
        apply_hard_honeypot(hwnd, cls_name, pid)
    elif mode == "C":
        apply_hybrid_ai_honeypot(hwnd, cls_name, pid)
    else:
        apply_soft_honeypot(hwnd, cls_name, pid)

def apply_soft_honeypot(hwnd, cls_name, pid):
    log_behavior(pid, cls_name, "soft_honeypot")
    print(f"[Soft Honeypot] Trapped {cls_name} (PID {pid}, HWND {hwnd})")

def apply_hard_honeypot(hwnd, cls_name, pid):
    log_behavior(pid, cls_name, "hard_honeypot")
    print(f"[Hard Honeypot] Isolated {cls_name} (PID {pid}, HWND {hwnd})")

def apply_hybrid_ai_honeypot(hwnd, cls_name, pid):
    score = ai_score_window(cls_name)
    if score > 0.7:
        apply_hard_honeypot(hwnd, cls_name, pid)
    else:
        apply_soft_honeypot(hwnd, cls_name, pid)

def auto_nuke_process(pid: int, reason: str):
    log_behavior(pid, "unknown", f"auto_nuke:{reason}")
    print(f"[Auto-Nuke] PID {pid} reason={reason}")
    # Stub: implement real kill/quarantine later

# ============================================================
# REAL PROCESS INSPECTION (psutil)
# ============================================================

def get_process_info(pid: int) -> Dict[str, Any]:
    psutil = AUTOLOADER.get_module("psutil")
    info = {"pid": pid}
    if psutil is None:
        return info
    try:
        p = psutil.Process(pid)
        info.update({
            "name": p.name(),
            "exe": p.exe(),
            "cmdline": p.cmdline(),
            "ppid": p.ppid(),
            "cpu_percent": p.cpu_percent(interval=0.1),
            "memory_info": p.memory_info()._asdict(),
        })
    except Exception as e:
        info["error"] = str(e)
    return info

# ============================================================
# REAL WIN32 HOOKS + ENUMWINDOWS
# ============================================================

WIN32_AVAILABLE = False
user32 = None
ctypes = AUTOLOADER.get_module("ctypes")
if ctypes is not None and os.name == "nt":
    try:
        user32 = ctypes.windll.user32
        WIN32_AVAILABLE = True
    except Exception:
        WIN32_AVAILABLE = False

EVENT_OBJECT_CREATE = 0x8000
WINEVENT_OUTOFCONTEXT = 0x0000

HOOK_THREAD = None

def get_window_class_name(hwnd: int) -> str:
    if not WIN32_AVAILABLE:
        return "UnknownClass"
    buf = ctypes.create_unicode_buffer(256)
    user32.GetClassNameW(hwnd, buf, 256)
    return buf.value

def enum_windows_callback(hwnd, lParam):
    cls = get_window_class_name(hwnd)
    pid = ctypes.c_ulong()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    pid_val = pid.value
    if should_trap_window(cls):
        trap_window_in_honeypot(hwnd, cls, pid_val)
    return True

def enum_all_windows_once():
    if not WIN32_AVAILABLE:
        print("[Win32] EnumWindows not available, using simulation.")
        simulate_window_events()
        return
    EnumWindowsProc = ctypes.WINFUNCTYPE(ctypes.c_bool, ctypes.c_int, ctypes.c_int)
    cb = EnumWindowsProc(enum_windows_callback)
    user32.EnumWindows(cb, 0)

def win_event_proc(hWinEventHook, event, hwnd, idObject, idChild, dwEventThread, dwmsEventTime):
    if event == EVENT_OBJECT_CREATE and hwnd:
        cls = get_window_class_name(hwnd)
        pid = ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pid_val = pid.value
        if should_trap_window(cls):
            trap_window_in_honeypot(hwnd, cls, pid_val)

def start_win32_hooks():
    global HOOK_THREAD
    if not WIN32_AVAILABLE or not config.get("win32_hooks_enabled", True):
        print("[Win32] Hooks disabled or unavailable.")
        return

    def hook_thread():
        WinEventProcType = ctypes.WINFUNCTYPE(
            None, ctypes.c_void_p, ctypes.c_uint, ctypes.c_int,
            ctypes.c_long, ctypes.c_long, ctypes.c_uint, ctypes.c_uint
        )
        proc = WinEventProcType(win_event_proc)
        hook = user32.SetWinEventHook(
            EVENT_OBJECT_CREATE, EVENT_OBJECT_CREATE,
            0, proc, 0, 0, WINEVENT_OUTOFCONTEXT
        )
        if not hook:
            print("[Win32] Failed to set hook, falling back to enum.")
            enum_all_windows_once()
            return
        print("[Win32] SetWinEventHook active.")
        msg = ctypes.wintypes.MSG()
        while True:
            if user32.GetMessageW(ctypes.byref(msg), 0, 0, 0) == 0:
                break
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

    HOOK_THREAD = threading.Thread(target=hook_thread, daemon=True)
    HOOK_THREAD.start()

# ============================================================
# SIMULATION (fallback)
# ============================================================

def simulate_window_events():
    fake_events = [
        (0x001, "wuiconwindow", 1234),
        (0x002, "UnknownClassX", 5678),
        (0x003, "Chrome_WidgetWin_0", 9999),
        (0x004, "RandomUIClass", 2222),
    ]
    print("[Sim] Simulating window events...")
    for hwnd, cls_name, pid in fake_events:
        if should_trap_window(cls_name):
            trap_window_in_honeypot(hwnd, cls_name, pid)
        else:
            print(f"[Monitor] Allowed {cls_name} (PID {pid}, HWND {hwnd})")

# ============================================================
# TKINTER HONEYPOT WINDOW CREATION
# ============================================================

HONEYPOT_WINDOWS: List[int] = []

def create_honeypot_window():
    import tkinter as tk
    win = tk.Toplevel()
    win.title("Honeypot Window")
    win.geometry("400x200")
    label = tk.Label(win, text="This is a decoy honeypot window.", fg="red")
    label.pack(expand=True)
    hwnd = win.winfo_id()
    HONEYPOT_WINDOWS.append(hwnd)
    print(f"[Honeypot] Created decoy window HWND={hwnd}")
    return hwnd

# ============================================================
# CLI
# ============================================================

def cli(args: List[str]):
    import argparse
    parser = argparse.ArgumentParser(description="Codex Honeypot CLI")
    parser.add_argument("--honeypot-mode", choices=["A", "B", "C"])
    parser.add_argument("--window-scope", type=int, choices=[1, 2, 3])
    parser.add_argument("--replay", action="store_true")
    parser.add_argument("--list-trapped", action="store_true")
    parser.add_argument("--headless", action="store_true")
    parser.add_argument("--no-win32-hooks", action="store_true")

    opts = parser.parse_args(args)

    if opts.honeypot_mode:
        set_honeypot_mode(opts.honeypot_mode)
    if opts.window_scope is not None:
        set_window_scope_mode(opts.window_scope)
    if opts.headless:
        config["headless"] = True
        save_json(CONFIG_PATH, config)
    if opts.no_win32_hooks:
        config["win32_hooks_enabled"] = False
        save_json(CONFIG_PATH, config)

    if opts.replay:
        print("=== Behavior Replay ===")
        for entry in state["behavior_log"]:
            print(f"{entry['timestamp']} | PID {entry['pid']} | {entry['class']} | {entry['action']}")
    if opts.list_trapped:
        print("=== Trapped Windows ===")
        for w in state["trapped_windows"]:
            print(f"{w['timestamp']} | HWND {w['hwnd']} | PID {w['pid']} | {w['class']}")

# ============================================================
# GUI
# ============================================================

def start_gui():
    import tkinter as tk
    from tkinter import ttk

    root = tk.Tk()
    root.title("Codex Honeypot v6")

    mode_frame = ttk.LabelFrame(root, text="Honeypot Mode")
    mode_frame.grid(row=0, column=0, padx=5, pady=5, sticky="nsew")
    mode_var = tk.StringVar(value=get_honeypot_mode())
    for text, val in [("Soft (A)", "A"), ("Hard (B)", "B"), ("Hybrid AI (C)", "C")]:
        rb = ttk.Radiobutton(mode_frame, text=text, value=val, variable=mode_var,
                             command=lambda v=mode_var: set_honeypot_mode(v.get()))
        rb.pack(anchor="w")

    scope_frame = ttk.LabelFrame(root, text="Window Scope")
    scope_frame.grid(row=0, column=1, padx=5, pady=5, sticky="nsew")
    scope_var = tk.IntVar(value=get_window_scope_mode())
    for text, val in [("Only wuiconwindow (1)", 1),
                      ("All unknown classes (2)", 2),
                      ("AI hybrid (3)", 3)]:
        rb = ttk.Radiobutton(scope_frame, text=text, value=val, variable=scope_var,
                             command=lambda v=scope_var: set_window_scope_mode(v.get()))
        rb.pack(anchor="w")

    trapped_frame = ttk.LabelFrame(root, text="Trapped Windows")
    trapped_frame.grid(row=1, column=0, padx=5, pady=5, sticky="nsew")
    trapped_list = tk.Listbox(trapped_frame, width=60, height=10)
    trapped_list.pack(fill="both", expand=True)

    log_frame = ttk.LabelFrame(root, text="Behavior Log")
    log_frame.grid(row=1, column=1, padx=5, pady=5, sticky="nsew")
    log_text = tk.Text(log_frame, width=60, height=10)
    log_text.pack(fill="both", expand=True)

    control_frame = ttk.Frame(root)
    control_frame.grid(row=2, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

    def refresh_views():
        trapped_list.delete(0, tk.END)
        for w in state["trapped_windows"]:
            trapped_list.insert(tk.END, f"{w['timestamp']} | {w['class']} | PID {w['pid']} | HWND {w['hwnd']}")
        log_text.delete("1.0", tk.END)
        for e in state["behavior_log"]:
            log_text.insert(tk.END, f"{e['timestamp']} | PID {e['pid']} | {e['class']} | {e['action']}\n")

    def simulate_btn():
        simulate_window_events()
        refresh_views()

    def auto_nuke_selected():
        sel = trapped_list.curselection()
        if not sel:
            return
        idx = sel[0]
        w = state["trapped_windows"][idx]
        auto_nuke_process(w["pid"], "manual_gui")
        refresh_views()

    def create_honeypot_btn():
        create_honeypot_window()

    ttk.Button(control_frame, text="Simulate Events", command=simulate_btn).pack(side="left", padx=5)
    ttk.Button(control_frame, text="Auto-Nuke Selected", command=auto_nuke_selected).pack(side="left", padx=5)
    ttk.Button(control_frame, text="Create Honeypot Window", command=create_honeypot_btn).pack(side="left", padx=5)
    ttk.Button(control_frame, text="Refresh", command=refresh_views).pack(side="left", padx=5)

    refresh_views()
    if WIN32_AVAILABLE and config.get("win32_hooks_enabled", True):
        start_win32_hooks()
    else:
        print("[GUI] Win32 hooks not active; using simulation + manual refresh.")

    root.mainloop()

# ============================================================
# SAFE STARTUP
# ============================================================

def safe_startup():
    try:
        args = sys.argv[1:]
        if args:
            cli(args)
        headless = config.get("headless", False)
        if headless:
            if WIN32_AVAILABLE and config.get("win32_hooks_enabled", True):
                start_win32_hooks()
                time.sleep(2)
                enum_all_windows_once()
            else:
                simulate_window_events()
        else:
            start_gui()
    except SystemExit:
        raise
    except Exception as e:
        print("\n[CRITICAL] Codex Honeypot crashed.")
        print("Reason:", e)
        traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    safe_startup()
