#!/usr/bin/env python3
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
    "tkinter": "tkinter",
    "watchdog": "watchdog",
    "requests": "requests",
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
import tkinter as tk
from tkinter import ttk, scrolledtext

# Optional GPU
try:
    import torch
    GPU_AVAILABLE = torch.cuda.is_available()
except Exception:
    GPU_AVAILABLE = False

# ==========================
# CONFIG
# ==========================
WATCH_DIRS = [
    os.path.expanduser(r"~\Downloads"),
    os.path.expanduser(r"~\Desktop"),
    os.path.expanduser(r"~\AppData\Local\Steam\steamapps\common"),
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

# ==========================
# AUTONOMY FLAGS
# ==========================
AUTO_FS_WATCH = True
AUTO_KILL = True

# ==========================
# GUI SETUP
# ==========================
root = tk.Tk()
root.title("Steam Malware Guard – Autonomous")
root.geometry("1000x600")
root.configure(bg="#202020")

style = ttk.Style()
style.theme_use("clam")
style.configure("TFrame", background="#202020")
style.configure("TButton", background="#2d2d2d", foreground="#ffffff")
style.configure("TLabel", background="#202020", foreground="#ffffff")

top_frame = ttk.Frame(root)
top_frame.pack(fill=tk.X, padx=10, pady=5)

btn_manual_scan = ttk.Button(top_frame, text="Manual Full Scan")
btn_toggle_fs = ttk.Button(top_frame, text="Toggle FS Watch (ON)")
btn_toggle_kill = ttk.Button(top_frame, text="Toggle Auto-Kill (ON)")
btn_manual_scan.pack(side=tk.LEFT, padx=5)
btn_toggle_fs.pack(side=tk.LEFT, padx=5)
btn_toggle_kill.pack(side=tk.LEFT, padx=5)

log_box = scrolledtext.ScrolledText(root, wrap=tk.WORD, font=("Consolas", 10),
                                    bg="#1e1e1e", fg="#dcdcdc")
log_box.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

def gui_log(msg):
    print(msg)
    log_box.insert(tk.END, msg + "\n")
    log_box.see(tk.END)

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

def quarantine(path):
    try:
        dest = os.path.join(QUARANTINE_DIR, os.path.basename(path))
        os.replace(path, dest)
        return dest
    except Exception as e:
        return f"Quarantine failed: {e}"

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
# ANALYSIS + ACTION
# ==========================
def analyze_file(path):
    if not os.path.isfile(path):
        return
    if not is_pe(path):
        return

    name_flag = suspicious_name(path)
    string_flag = has_suspicious_strings(path)
    ent = file_entropy(path)
    ent_flag = ent > 7.0

    sha = sha256_file(path)
    vt = vt_lookup(sha)

    if name_flag or string_flag or ent_flag:
        gui_log(f"[SUSPICIOUS FILE] {path}")
        gui_log(f"  SHA256={sha}")
        gui_log(f"  entropy={ent:.2f} (flag={ent_flag})")
        gui_log(f"  name_flag={name_flag}, string_flag={string_flag}")
        gui_log(f"  VT={vt}")
        qpath = quarantine(path)
        gui_log(f"  → QUARANTINED: {qpath}")

def kill_suspicious_processes():
    for proc in psutil.process_iter(["pid", "name", "exe", "cmdline"]):
        try:
            name = (proc.info["name"] or "").lower()
            exe = (proc.info["exe"] or "").lower()
            cmd = " ".join(proc.info["cmdline"] or []).lower()
            combined = " ".join([name, exe, cmd])
            if any(token in combined for token in SUSPICIOUS_NAME_TOKENS):
                gui_log(f"[AUTO-KILL] PID={proc.pid} NAME={name}")
                proc.kill()
        except Exception as e:
            gui_log(f"[AUTO-KILL ERROR] {e}")

# ==========================
# REAL-TIME FS WATCHER
# ==========================
class MalwareEventHandler(FileSystemEventHandler):
    def on_created(self, event):
        if not AUTO_FS_WATCH:
            return
        if event.is_directory:
            return
        path = event.src_path
        if not path.lower().endswith((".exe", ".dll")):
            return
        analyze_file(path)

def fs_watch_loop():
    observer = Observer()
    handler = MalwareEventHandler()
    for d in WATCH_DIRS:
        if os.path.isdir(d):
            observer.schedule(handler, d, recursive=True)
    observer.start()
    gui_log("[FS WATCH] Started.")
    try:
        while True:
            time.sleep(1)
    finally:
        observer.stop()
        observer.join()

# ==========================
# STEAM SESSION MONITOR
# ==========================
def steam_session_monitor():
    steam_config = os.path.expanduser(r"~\AppData\Local\Steam\config\loginusers.vdf")
    last_size = None
    while True:
        if os.path.isfile(steam_config):
            size = os.path.getsize(steam_config)
            if last_size is not None and size != last_size:
                gui_log(f"[STEAM SESSION] loginusers.vdf size changed: {last_size} -> {size}")
            last_size = size
        time.sleep(10)

# ==========================
# AUTONOMOUS LOOPS
# ==========================
def auto_kill_loop():
    while True:
        if AUTO_KILL:
            kill_suspicious_processes()
        time.sleep(10)

def manual_full_scan():
    gui_log("[MANUAL SCAN] Starting full scan...")
    for base in WATCH_DIRS:
        if not os.path.isdir(base):
            continue
        for root_dir, dirs, files in os.walk(base):
            for f in files:
                full = os.path.join(root_dir, f)
                if full.lower().endswith((".exe", ".dll")):
                    analyze_file(full)
    gui_log("[MANUAL SCAN] Done.")

# ==========================
# MANUAL OVERRIDE HANDLERS
# ==========================
def on_manual_scan():
    threading.Thread(target=manual_full_scan, daemon=True).start()

def on_toggle_fs():
    global AUTO_FS_WATCH
    AUTO_FS_WATCH = not AUTO_FS_WATCH
    state = "ON" if AUTO_FS_WATCH else "OFF"
    btn_toggle_fs.config(text=f"Toggle FS Watch ({state})")
    gui_log(f"[OVERRIDE] FS Watch set to {state}")

def on_toggle_kill():
    global AUTO_KILL
    AUTO_KILL = not AUTO_KILL
    state = "ON" if AUTO_KILL else "OFF"
    btn_toggle_kill.config(text=f"Toggle Auto-Kill ({state})")
    gui_log(f"[OVERRIDE] Auto-Kill set to {state}")

btn_manual_scan.config(command=on_manual_scan)
btn_toggle_fs.config(command=on_toggle_fs)
btn_toggle_kill.config(command=on_toggle_kill)

# ==========================
# THREAD START
# ==========================
threading.Thread(target=fs_watch_loop, daemon=True).start()
threading.Thread(target=steam_session_monitor, daemon=True).start()
threading.Thread(target=auto_kill_loop, daemon=True).start()

gui_log("[INIT] Steam Malware Guard – Autonomous started.")
root.mainloop()
