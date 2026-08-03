#!/usr/bin/env python3
# codex_honeypot_gui_v7_s1.py

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
SURICATA_EVE_PATH = Path(BASE_DIR) / "eve.json"  # you can point this to real Suricata eve.json

DEFAULT_CONFIG = {
    "honeypot_mode": "C",
    "window_scope_mode": 2,
    "autoloader_enabled": True,
    "headless": False,
    "win32_hooks_enabled": True,
    "suricata_enabled": True,
    "process_monitor_enabled": True,
}

DEFAULT_STATE = {
    "known_window_classes": [
        "Progman", "Shell_TrayWnd", "Chrome_WidgetWin_0",
        "ApplicationFrameWindow", "Windows.UI.Core.CoreWindow"
    ],
    "trapped_windows": [],
    "behavior_log": [],
    "ai_model_state": {},
    "suricata_events": [],
    "process_events": [],
    "deception_assets": [],
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

def log_behavior(pid: int, cls_name: str, action: str, extra: Optional[Dict[str, Any]] = None):
    entry = {
        "pid": pid,
        "class": cls_name,
        "action": action,
        "timestamp": datetime.now().isoformat(),
        "extra": extra or {},
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
# PROCESS MONITOR (psutil)
# ============================================================

PROCESS_MONITOR_RUNNING = False

def start_process_monitor():
    global PROCESS_MONITOR_RUNNING
    if PROCESS_MONITOR_RUNNING:
        return
    psutil = AUTOLOADER.get_module("psutil")
    if psutil is None:
        print("[ProcessMonitor] psutil not available.")
        return

    def monitor_loop():
        known_pids = set()
        while True:
            try:
                for p in psutil.process_iter(attrs=["pid", "name", "cmdline"]):
                    pid = p.info["pid"]
                    if pid not in known_pids:
                        known_pids.add(pid)
                        evt = {
                            "pid": pid,
                            "name": p.info.get("name"),
                            "cmdline": p.info.get("cmdline"),
                            "timestamp": datetime.now().isoformat(),
                        }
                        state["process_events"].append(evt)
                        log_behavior(pid, "process", "spawn", {"name": evt["name"], "cmdline": evt["cmdline"]})
                save_json(STATE_PATH, state)
                time.sleep(2.0)
            except Exception as e:
                print(f"[ProcessMonitor] Error: {e}")
                time.sleep(2.0)

    PROCESS_MONITOR_RUNNING = True
    t = threading.Thread(target=monitor_loop, daemon=True)
    t.start()
    print("[ProcessMonitor] Started.")

# ============================================================
# SURICATA INGESTION (eve.json)
# ============================================================

SURICATA_RUNNING = False

MITRE_MAP = {
    "ET SCAN": "Reconnaissance",
    "ET TROJAN": "Command and Control",
    "ET POLICY": "Policy Violation",
    "ET EXPLOIT": "Execution",
}

def start_suricata_ingestion():
    global SURICATA_RUNNING
    if SURICATA_RUNNING:
        return
    if not SURICATA_EVE_PATH.exists():
        print(f"[Suricata] eve.json not found at {SURICATA_EVE_PATH}, running stub.")
        return

    def tail_loop():
        try:
            with open(SURICATA_EVE_PATH, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(1.0)
                        continue
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        evt = json.loads(line)
                    except Exception:
                        continue
                    handle_suricata_event(evt)
        except Exception as e:
            print(f"[Suricata] Error: {e}")

    SURICATA_RUNNING = True
    t = threading.Thread(target=tail_loop, daemon=True)
    t.start()
    print("[Suricata] Ingestion started.")

def handle_suricata_event(evt: Dict[str, Any]):
    kind = evt.get("event_type")
    sig = evt.get("alert", {}).get("signature", "") if "alert" in evt else ""
    src_ip = evt.get("src_ip")
    dest_ip = evt.get("dest_ip")
    mitre = None
    for key, val in MITRE_MAP.items():
        if key in sig:
            mitre = val
            break
    record = {
        "event_type": kind,
        "signature": sig,
        "src_ip": src_ip,
        "dest_ip": dest_ip,
        "mitre": mitre,
        "timestamp": datetime.now().isoformat(),
    }
    state["suricata_events"].append(record)
    save_json(STATE_PATH, state)
    log_behavior(0, "suricata", "event", record)
    print(f"[Suricata] {kind} {sig} {src_ip}->{dest_ip} MITRE={mitre}")

# ============================================================
# DECEPTION ENGINE (basic assets)
# ============================================================

def add_deception_asset(kind: str, details: Dict[str, Any]):
    asset = {
        "kind": kind,
        "details": details,
        "timestamp": datetime.now().isoformat(),
    }
    state["deception_assets"].append(asset)
    save_json(STATE_PATH, state)
    print(f"[Deception] Added {kind}: {details}")

def fake_memory_dump(pid: int):
    path = Path(BASE_DIR) / "fake" / "memdumps"
    os.makedirs(path, exist_ok=True)
    fname = path / f"memdump_pid{pid}_{int(time.time())}.txt"
    content = f"FAKE MEMORY DUMP FOR PID {pid}\nRandom bytes: {os.urandom(32).hex()}\n"
    with open(fname, "w", encoding="utf-8") as f:
        f.write(content)
    add_deception_asset("memory_dump", {"pid": pid, "path": str(fname)})

def fake_gpu_info():
    info = {
        "gpus": [
            {"name": "Fake RTX 5090", "vram_gb": 48, "driver": "FAKE-555.55"},
            {"name": "Fake A100", "vram_gb": 80, "driver": "FAKE-600.00"},
        ]
    }
    add_deception_asset("gpu_info", info)

def fake_net_interfaces():
    info = {
        "interfaces": [
            {"name": "eth0", "ip": "10.0.0.10", "mac": "FA:KE:00:00:00:01"},
            {"name": "vpn0", "ip": "172.16.0.5", "mac": "FA:KE:00:00:00:02"},
        ]
    }
    add_deception_asset("net_interfaces", info)

def fake_windows_logs():
    info = {"source": "windows", "events": ["User logon", "Service start", "Group policy applied"]}
    add_deception_asset("windows_logs", info)

def fake_linux_logs():
    info = {"source": "linux", "events": ["sshd accepted", "sudo command", "systemd service restart"]}
    add_deception_asset("linux_logs", info)

def fake_browser_profile():
    info = {"profile": "fake_user", "history": ["https://example.com", "https://bank.example"], "cookies": ["session=FAKE"]}
    add_deception_asset("browser_profile", info)

def fake_crypto_wallet():
    info = {"rpc": "http://127.0.0.1:8545", "addresses": ["0xFAKE...", "0xDEAD..."], "balance": "0.00"}
    add_deception_asset("crypto_wallet", info)

def fake_ad_domain():
    info = {"domain": "FAKECORP.LOCAL", "users": ["alice", "bob", "charlie"], "groups": ["Domain Admins", "HR", "IT"]}
    add_deception_asset("ad_domain", info)

def fake_smb_share():
    info = {"share": "\\\\FAKECORP\\HR", "files": ["payroll.xlsx", "employees.docx"]}
    add_deception_asset("smb_share", info)

def fake_sql_db():
    info = {"dsn": "FAKE-SQL", "tables": ["users", "transactions"], "rows": 1000}
    add_deception_asset("sql_db", info)

def fake_docker():
    info = {"containers": ["web", "db", "redis"], "images": ["fake/web:latest", "fake/db:latest"]}
    add_deception_asset("docker", info)

def fake_k8s():
    info = {"pods": ["api-0", "api-1", "worker-0"], "namespaces": ["default", "prod", "dev"]}
    add_deception_asset("k8s", info)

def fake_cloud_metadata():
    info = {"instance_id": "i-FAKE123456", "iam_role": "FakeRole", "region": "us-fake-1"}
    add_deception_asset("cloud_metadata", info)

# ============================================================
# WIN32 HOOKS + ENUMWINDOWS (same as v6)
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
    parser.add_argument("--no-suricata", action="store_true")
    parser.add_argument("--no-process-monitor", action="store_true")

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
    if opts.no_suricata:
        config["suricata_enabled"] = False
        save_json(CONFIG_PATH, config)
    if opts.no_process_monitor:
        config["process_monitor_enabled"] = False
        save_json(CONFIG_PATH, config)

    if opts.replay:
        print("=== Behavior Replay ===")
        for entry in state["behavior_log"]:
            print(f"{entry['timestamp']} | PID {entry['pid']} | {entry['class']} | {entry['action']} | {entry.get('extra')}")
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
    root.title("Codex Honeypot v7 (S1)")

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

    suricata_frame = ttk.LabelFrame(root, text="Suricata Events")
    suricata_frame.grid(row=2, column=0, padx=5, pady=5, sticky="nsew")
    suricata_list = tk.Listbox(suricata_frame, width=60, height=8)
    suricata_list.pack(fill="both", expand=True)

    process_frame = ttk.LabelFrame(root, text="Process Events")
    process_frame.grid(row=2, column=1, padx=5, pady=5, sticky="nsew")
    process_list = tk.Listbox(process_frame, width=60, height=8)
    process_list.pack(fill="both", expand=True)

    deception_frame = ttk.LabelFrame(root, text="Deception Assets")
    deception_frame.grid(row=3, column=0, columnspan=2, padx=5, pady=5, sticky="nsew")
    deception_list = tk.Listbox(deception_frame, width=120, height=8)
    deception_list.pack(fill="both", expand=True)

    control_frame = ttk.Frame(root)
    control_frame.grid(row=4, column=0, columnspan=2, padx=5, pady=5, sticky="ew")

    def refresh_views():
        trapped_list.delete(0, tk.END)
        for w in state["trapped_windows"]:
            trapped_list.insert(tk.END, f"{w['timestamp']} | {w['class']} | PID {w['pid']} | HWND {w['hwnd']}")
        log_text.delete("1.0", tk.END)
        for e in state["behavior_log"]:
            log_text.insert(tk.END, f"{e['timestamp']} | PID {e['pid']} | {e['class']} | {e['action']} | {e.get('extra')}\n")
        suricata_list.delete(0, tk.END)
        for s in state["suricata_events"]:
            suricata_list.insert(tk.END, f"{s['timestamp']} | {s['event_type']} | {s['signature']} | {s['src_ip']}->{s['dest_ip']} | {s['mitre']}")
        process_list.delete(0, tk.END)
        for p in state["process_events"]:
            process_list.insert(tk.END, f"{p['timestamp']} | PID {p['pid']} | {p['name']} | {p['cmdline']}")
        deception_list.delete(0, tk.END)
        for d in state["deception_assets"]:
            deception_list.insert(tk.END, f"{d['timestamp']} | {d['kind']} | {d['details']}")

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

    def generate_deception_btn():
        fake_gpu_info()
        fake_net_interfaces()
        fake_windows_logs()
        fake_linux_logs()
        fake_browser_profile()
        fake_crypto_wallet()
        fake_ad_domain()
        fake_smb_share()
        fake_sql_db()
        fake_docker()
        fake_k8s()
        fake_cloud_metadata()
        refresh_views()

    ttk.Button(control_frame, text="Simulate Events", command=simulate_btn).pack(side="left", padx=5)
    ttk.Button(control_frame, text="Auto-Nuke Selected", command=auto_nuke_selected).pack(side="left", padx=5)
    ttk.Button(control_frame, text="Generate Deception Assets", command=generate_deception_btn).pack(side="left", padx=5)
    ttk.Button(control_frame, text="Refresh", command=refresh_views).pack(side="left", padx=5)

    refresh_views()

    if WIN32_AVAILABLE and config.get("win32_hooks_enabled", True):
        start_win32_hooks()
    else:
        print("[GUI] Win32 hooks not active; using simulation + manual refresh.")

    if config.get("suricata_enabled", True):
        start_suricata_ingestion()
    if config.get("process_monitor_enabled", True):
        start_process_monitor()

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
            if config.get("suricata_enabled", True):
                start_suricata_ingestion()
            if config.get("process_monitor_enabled", True):
                start_process_monitor()
            while True:
                time.sleep(5)
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
