#!/usr/bin/env python3
"""
Folder Control Center Ultimate

Windows folder metadata, desktop.ini, backup/restore, sandbox monitoring,
attribute visualization, icon/editor tools, special-folder repair, audit,
Explorer tools, conservative cleanup, template sandbox, behavior firewall,
system-wide icon pack manager, permissions analyzer, registry-based
Explorer tweaks, folder behavior AI predictor, system-wide folder health
score, Explorer crash recovery engine, folder encryption manager, and
full theme pack manager.

Requires: Python 3.10+ on Windows.
Optional: pywin32, watchdog, tkinterdnd2.
An autoloader attempts to install optional packages via pip at startup.
"""

from __future__ import annotations

import os, sys, json, time, shutil, subprocess, traceback
from pathlib import Path
from datetime import datetime
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from tkinter.scrolledtext import ScrolledText

# -------------------------------------------------------------------
# AUTOLOADER FOR OPTIONAL LIBRARIES
# -------------------------------------------------------------------
OPTIONAL_LIBS = [
    ("win32api", "pywin32"),
    ("watchdog.observers", "watchdog"),
    ("tkinterdnd2", "tkinterdnd2"),
]

def autoload_optional_libs():
    import importlib
    for module_name, pip_name in OPTIONAL_LIBS:
        try:
            importlib.import_module(module_name)
        except Exception:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])
            except Exception:
                pass

autoload_optional_libs()

# -------------------------------------------------------------------
# CONDITIONAL IMPORTS AFTER AUTOLOADER
# -------------------------------------------------------------------
try:
    import win32api, win32con
except Exception:
    win32api = win32con = None

try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:
    Observer = None
    class FileSystemEventHandler: pass

try:
    from tkinterdnd2 import TkinterDnD, DND_FILES
except Exception:
    TkinterDnD = None
    DND_FILES = None

try:
    import winreg
except Exception:
    winreg = None

APP_DIR = Path(__file__).resolve().parent
DATA_DIR = APP_DIR / "folder_control_center_data"
BACKUP_DIR = DATA_DIR / "backups"
SANDBOX_DB = DATA_DIR / "sandbox_rules.json"
ICON_PACK_DIR = DATA_DIR / "icon_packs"
THEME_PACK_DIR = DATA_DIR / "theme_packs"
DATA_DIR.mkdir(exist_ok=True)
BACKUP_DIR.mkdir(exist_ok=True)
ICON_PACK_DIR.mkdir(parents=True, exist_ok=True)
THEME_PACK_DIR.mkdir(parents=True, exist_ok=True)

ATTRS = {
    "READONLY": 0x1, "HIDDEN": 0x2, "SYSTEM": 0x4, "DIRECTORY": 0x10,
    "ARCHIVE": 0x20, "NORMAL": 0x80, "TEMPORARY": 0x100,
    "SPARSE_FILE": 0x200, "REPARSE_POINT": 0x400, "COMPRESSED": 0x800,
    "OFFLINE": 0x1000, "NOT_CONTENT_INDEXED": 0x2000, "ENCRYPTED": 0x4000,
}

def log_time(): return datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def load_json(path, default):
    try:
        if path.exists():
            with path.open("r", encoding="utf-8") as f: return json.load(f)
    except Exception:
        pass
    return default

def save_json(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    with tmp.open("w", encoding="utf-8") as f: json.dump(value, f, indent=2)
    tmp.replace(path)

def attrs_raw(path):
    if win32api:
        try: return win32api.GetFileAttributes(str(path))
        except Exception: return None
    return None

def attrs_desc(value):
    if value is None: return {k: False for k in ATTRS} | {"ERROR": True}
    return {k: bool(value & bit) for k, bit in ATTRS.items()}

def set_attrs(path, value):
    if not win32api: return False
    try:
        win32api.SetFileAttributes(str(path), int(value))
        return True
    except Exception:
        return False

def file_hash(path):
    try:
        import hashlib
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for block in iter(lambda: f.read(1024 * 1024), b""):
                h.update(block)
        return h.hexdigest()
    except Exception:
        return None

def desktop_ini(folder): return Path(folder) / "desktop.ini"

def folder_report(folder):
    p = Path(folder)
    result = {"folder": str(p), "exists": p.is_dir(), "attributes": {}, "desktop_ini": {}, "summary": {}}
    if not p.is_dir(): return result
    result["attributes"] = attrs_desc(attrs_raw(p))
    ini = desktop_ini(p)
    result["desktop_ini"] = {
        "exists": ini.is_file(),
        "path": str(ini),
        "attributes": attrs_desc(attrs_raw(ini)) if ini.exists() else {}
    }
    files = dirs = total = 0
    try:
        for root, ds, fs in os.walk(p):
            dirs += len(ds); files += len(fs)
            for name in fs:
                try: total += (Path(root) / name).stat().st_size
                except OSError: pass
    except Exception:
        pass
    result["summary"] = {"files": files, "folders": dirs, "bytes": total}
    return result

def backup_folder_metadata(folder):
    p = Path(folder)
    if not p.is_dir(): raise ValueError("Folder does not exist")
    stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = BACKUP_DIR / f"backup_{p.name or 'root'}_{stamp}"
    target.mkdir(parents=True, exist_ok=False)
    manifest = {"created": log_time(), "folder": str(p), "entries": []}
    for candidate in (p, desktop_ini(p)):
        if candidate.exists():
            entry = {
                "path": str(candidate),
                "kind": "folder" if candidate.is_dir() else "file",
                "attributes": attrs_raw(candidate)
            }
            if candidate.is_file():
                copied = target / "desktop.ini"
                shutil.copy2(candidate, copied)
                entry["backup_file"] = str(copied)
                entry["sha256"] = file_hash(candidate)
            manifest["entries"].append(entry)
    save_json(target / "manifest.json", manifest)
    return target, manifest

def restore_backup(backup):
    b = Path(backup)
    manifest = load_json(b / "manifest.json", None)
    if not manifest: raise ValueError("Invalid backup")
    folder = Path(manifest["folder"])
    folder.mkdir(parents=True, exist_ok=True)
    restored = []
    for entry in manifest.get("entries", []):
        if entry.get("kind") == "file" and entry.get("backup_file"):
            source = Path(entry["backup_file"]); dest = Path(entry["path"])
            if source.exists():
                shutil.copy2(source, dest)
                restored.append(str(dest))
        if entry.get("attributes") is not None:
            set_attrs(entry["path"], entry["attributes"])
    return restored

def cleanup_candidates(root):
    root = Path(root); candidates = []
    if not root.is_dir(): return candidates
    allowed_suffixes = {".tmp", ".bak", ".old"}
    try:
        for p in root.rglob("*"):
            if p.is_file() and (p.suffix.lower() in allowed_suffixes or p.name.lower() in {"thumbs.db"}):
                try: candidates.append({"path": str(p), "size": p.stat().st_size})
                except OSError: pass
    except Exception:
        pass
    return candidates

# --- Special folder + audit + icon/editor + Explorer tools ---

def is_special_folder(folder):
    p = Path(folder)
    if not p.is_dir(): return False, "Not a folder"
    fa = attrs_raw(p)
    if fa is None: return False, "Cannot read folder attributes"
    has_ro = bool(fa & ATTRS["READONLY"])
    ini = desktop_ini(p)
    if not ini.is_file(): return False, "No desktop.ini"
    ia = attrs_raw(ini)
    if ia is None: return False, "Cannot read desktop.ini attributes"
    is_hidden = bool(ia & ATTRS["HIDDEN"])
    is_system = bool(ia & ATTRS["SYSTEM"])
    if has_ro and is_hidden and is_system:
        return True, "READONLY folder + SYSTEM+HIDDEN desktop.ini"
    elif is_hidden and is_system:
        return True, "SYSTEM+HIDDEN desktop.ini"
    return False, "Not special"

def fix_special_folder(folder, delete_ini=False, backup_ini=True):
    p = Path(folder)
    actions = {
        "folder": str(p),
        "changed_folder_attrs": False,
        "changed_ini_attrs": False,
        "ini_deleted": False,
        "ini_backup_path": None,
        "errors": []
    }
    if not p.is_dir():
        actions["errors"].append("Not a folder"); return actions
    fa = attrs_raw(p)
    if fa is not None and (fa & ATTRS["READONLY"]):
        new = fa & ~ATTRS["READONLY"]
        if set_attrs(p, new): actions["changed_folder_attrs"] = True
        else: actions["errors"].append("Failed to clear READONLY")
    ini = desktop_ini(p)
    if ini.is_file():
        ia = attrs_raw(ini)
        if ia is not None:
            new = ia & ~ATTRS["SYSTEM"]
            new &= ~ATTRS["HIDDEN"]
            if set_attrs(ini, new): actions["changed_ini_attrs"] = True
            else: actions["errors"].append("Failed to clear SYSTEM/HIDDEN")
        if delete_ini:
            try:
                if backup_ini:
                    backup_path = ini.with_suffix(ini.suffix + ".bak")
                    if backup_path.exists(): backup_path.unlink()
                    shutil.copy2(ini, backup_path)
                    actions["ini_backup_path"] = str(backup_path)
                ini.unlink()
                actions["ini_deleted"] = True
            except Exception as e:
                actions["errors"].append(f"Failed to delete/backup desktop.ini: {e}")
    else:
        actions["errors"].append("No desktop.ini")
    return actions

def scan_for_special_folders(root):
    root = Path(root); out = []
    if not root.is_dir(): return out
    try:
        for r, ds, fs in os.walk(root):
            for d in ds:
                f = Path(r) / d
                special, reason = is_special_folder(f)
                if special: out.append({"folder": str(f), "reason": reason})
    except Exception:
        pass
    return out

def find_all_desktop_ini(root):
    root = Path(root); out = []
    if not root.is_dir(): return out
    try:
        for p in root.rglob("desktop.ini"):
            out.append({"path": str(p), "attributes": attrs_desc(attrs_raw(p))})
    except Exception:
        pass
    return out

def audit_folders(root):
    root = Path(root); report = []
    if not root.is_dir(): return report
    try:
        for r, ds, fs in os.walk(root):
            for d in ds:
                f = Path(r) / d
                fa = attrs_desc(attrs_raw(f))
                ini = desktop_ini(f)
                has_ini = ini.is_file()
                special, reason = is_special_folder(f)
                report.append({
                    "folder": str(f),
                    "attributes": fa,
                    "has_desktop_ini": has_ini,
                    "special": special,
                    "special_reason": reason,
                })
    except Exception:
        pass
    return report

def set_folder_icon(folder, icon_path):
    actions = {
        "folder": str(folder),
        "icon": str(icon_path),
        "desktop_ini_written": False,
        "folder_readonly_set": False,
        "ini_system_hidden_set": False,
        "errors": []
    }
    f = Path(folder); ico = Path(icon_path)
    if not f.is_dir():
        actions["errors"].append("Not a folder"); return actions
    if not ico.is_file():
        actions["errors"].append("Icon file does not exist"); return actions
    ini = desktop_ini(f)
    try:
        ini.write_text(f"[.ShellClassInfo]\nIconResource={ico},0\n", encoding="utf-8")
        actions["desktop_ini_written"] = True
    except Exception as e:
        actions["errors"].append(f"Failed to write desktop.ini: {e}")
        return actions
    ia = attrs_raw(ini) or 0
    new_ia = ia | ATTRS["SYSTEM"] | ATTRS["HIDDEN"]
    if set_attrs(ini, new_ia): actions["ini_system_hidden_set"] = True
    else: actions["errors"].append("Failed to set SYSTEM+HIDDEN on desktop.ini")
    fa = attrs_raw(f) or ATTRS["DIRECTORY"]
    new_fa = fa | ATTRS["READONLY"]
    if set_attrs(f, new_fa): actions["folder_readonly_set"] = True
    else: actions["errors"].append("Failed to set READONLY on folder")
    return actions

def reset_folder_template(folder):
    actions = {"folder": str(folder), "fixed_special": False, "errors": []}
    try:
        fix = fix_special_folder(folder, delete_ini=True, backup_ini=True)
        actions["fixed_special"] = True
        actions["details"] = fix
    except Exception as e:
        actions["errors"].append(str(e))
    return actions

def refresh_explorer_icons():
    if not win32api: return False
    try:
        SHCNE_ASSOCCHANGED = 0x08000000
        SHCNF_IDLIST = 0x0000
        ctypes = __import__("ctypes")
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
        return True
    except Exception:
        return False

def rebuild_icon_cache_best_effort():
    result = {"notified_shell": False, "suggested_manual_restart": True, "errors": []}
    if not win32api:
        result["errors"].append("pywin32 not available"); return result
    try:
        SHCNE_ASSOCCHANGED = 0x08000000
        SHCNF_IDLIST = 0x0000
        ctypes = __import__("ctypes")
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
        result["notified_shell"] = True
    except Exception as e:
        result["errors"].append(f"SHChangeNotify failed: {e}")
    return result

def restart_explorer():
    result = {"killed_explorer": False, "started_explorer": False, "errors": []}
    try:
        subprocess.call(["taskkill", "/F", "/IM", "explorer.exe"],
                        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        result["killed_explorer"] = True
    except Exception as e:
        result["errors"].append(f"Failed to kill explorer.exe: {e}")
    try:
        subprocess.Popen("explorer.exe")
        result["started_explorer"] = True
    except Exception as e:
        result["errors"].append(f"Failed to start explorer.exe: {e}")
    return result

# --- Sandbox rules / firewall / template sandbox ---

def load_sandbox_rules():
    return load_json(SANDBOX_DB, {"folders": {}})

def save_sandbox_rules(rules):
    save_json(SANDBOX_DB, rules)

def get_folder_rules(folder):
    rules = load_sandbox_rules()
    return rules.get("folders", {}).get(str(Path(folder)), {
        "log_only": True,
        "auto_revert_template": False,
        "block_desktop_ini": False,
        "block_readonly": False,
    })

def set_folder_rules(folder, rule_dict):
    rules = load_sandbox_rules()
    folders = rules.setdefault("folders", {})
    folders[str(Path(folder))] = rule_dict
    save_sandbox_rules(rules)

def enforce_firewall_for_path(app, path):
    p = Path(path)
    folder = p.parent if p.name.lower() == "desktop.ini" else p
    rules = get_folder_rules(folder)
    if p.name.lower() == "desktop.ini":
        if rules.get("block_desktop_ini"):
            try:
                if p.exists():
                    p.unlink()
                    app.safe_log(f"[FIREWALL] Deleted desktop.ini under protected folder: {folder}")
            except Exception as e:
                app.safe_log(f"[FIREWALL] Failed to delete desktop.ini: {e}")
        if rules.get("auto_revert_template"):
            try:
                fix_special_folder(folder, delete_ini=True, backup_ini=True)
                app.safe_log(f"[SANDBOX] Auto-reverted template for {folder}")
            except Exception as e:
                app.safe_log(f"[SANDBOX] Failed to auto-revert template: {e}")
    fa = attrs_raw(folder)
    if fa is not None and rules.get("block_readonly") and (fa & ATTRS["READONLY"]):
        new = fa & ~ATTRS["READONLY"]
        if set_attrs(folder, new):
            app.safe_log(f"[FIREWALL] Cleared READONLY on protected folder: {folder}")

class SandboxHandler(FileSystemEventHandler):
    def __init__(self, app): self.app = app
    def _event(self, event):
        if getattr(event, "is_directory", False): return
        path = str(getattr(event, "src_path", ""))
        if Path(path).name.lower() == "desktop.ini":
            self.app.safe_log(f"[SANDBOX] desktop.ini change observed: {path}")
        enforce_firewall_for_path(self.app, path)
        self.app.after_event(path)
    on_created = _event; on_modified = _event; on_deleted = _event; on_moved = _event

# --- Icon pack manager ---

def load_icon_pack(path):
    return load_json(Path(path), {"rules": []})

def save_icon_pack(path, pack):
    save_json(Path(path), pack)

def apply_icon_pack(root, pack):
    root = Path(root)
    results = []
    if not root.is_dir(): return results
    for rule in pack.get("rules", []):
        pattern = rule.get("pattern")
        icon = rule.get("icon")
        if not pattern or not icon: continue
        for r, ds, fs in os.walk(root):
            for d in ds:
                f = Path(r) / d
                if pattern.lower() in f.name.lower():
                    actions = set_folder_icon(f, icon)
                    results.append({"folder": str(f), "actions": actions})
    return results

# --- Permissions analyzer (using icacls) ---

def analyze_permissions(folder):
    folder = Path(folder)
    if not folder.exists(): return {"folder": str(folder), "error": "Folder does not exist"}
    try:
        proc = subprocess.run(["icacls", str(folder)], capture_output=True, text=True, shell=True)
        out = proc.stdout.splitlines()
        parsed = []
        for line in out:
            line = line.strip()
            if not line or line.startswith(str(folder)): continue
            parsed.append(line)
        return {"folder": str(folder), "raw": out, "parsed": parsed}
    except Exception as e:
        return {"folder": str(folder), "error": str(e)}

# --- Registry-based Explorer tweaks (safe subset) ---

EXPLORER_TWEAKS = [
    {
        "name": "Show hidden files",
        "key": r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "value": "Hidden",
        "type": "DWORD",
        "on": 1,
        "off": 2,
    },
    {
        "name": "Show file extensions",
        "key": r"Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced",
        "value": "HideFileExt",
        "type": "DWORD",
        "on": 0,
        "off": 1,
    },
]

def get_tweak_state(tweak):
    if not winreg: return None
    try:
        root = winreg.HKEY_CURRENT_USER
        key = winreg.OpenKey(root, tweak["key"])
        val, _ = winreg.QueryValueEx(key, tweak["value"])
        winreg.CloseKey(key)
        return val
    except Exception:
        return None

def set_tweak_state(tweak, enable=True):
    if not winreg: return False
    try:
        root = winreg.HKEY_CURRENT_USER
        key = winreg.CreateKey(root, tweak["key"])
        val = tweak["on"] if enable else tweak["off"]
        winreg.SetValueEx(key, tweak["value"], 0, winreg.REG_DWORD, val)
        winreg.CloseKey(key)
        return True
    except Exception:
        return False

# --- Folder Behavior AI Predictor (heuristic) & Health Score ---

def predict_folder_behavior(folder):
    """
    Heuristic "AI" predictor: uses attributes, desktop.ini presence,
    size, and special-folder status to estimate risk and likely behavior.
    """
    report = folder_report(folder)
    attrs = report.get("attributes", {})
    summary = report.get("summary", {})
    ini_info = report.get("desktop_ini", {})
    special, reason = is_special_folder(folder)
    score = 0
    notes = []

    if ini_info.get("exists"):
        score += 20
        notes.append("desktop.ini present")
    if attrs.get("READONLY"):
        score += 15
        notes.append("READONLY set")
    if attrs.get("SYSTEM") or attrs.get("HIDDEN"):
        score += 15
        notes.append("SYSTEM/HIDDEN attributes")
    if special:
        score += 25
        notes.append(f"Special folder: {reason}")
    if summary.get("bytes", 0) > 10 * 1024 * 1024 * 1024:
        score += 10
        notes.append("Large folder (>10GB)")
    if summary.get("files", 0) > 10000:
        score += 10
        notes.append("Many files (>10k)")

    risk_level = "LOW"
    if score >= 60: risk_level = "HIGH"
    elif score >= 30: risk_level = "MEDIUM"

    return {
        "folder": str(folder),
        "score": score,
        "risk": risk_level,
        "notes": notes,
        "special": special,
        "special_reason": reason,
    }

def compute_health_score(root):
    """
    System-wide folder health score: scans folders and aggregates
    issues like special folders, desktop.ini proliferation, and
    attribute anomalies.
    """
    root = Path(root)
    if not root.is_dir():
        return {"root": str(root), "error": "Root is not a folder"}
    total = 0
    specials = 0
    ini_count = 0
    readonly_count = 0
    folders_scanned = 0
    try:
        for r, ds, fs in os.walk(root):
            for d in ds:
                f = Path(r) / d
                folders_scanned += 1
                fa = attrs_desc(attrs_raw(f))
                if fa.get("READONLY"): readonly_count += 1
                special, _ = is_special_folder(f)
                if special: specials += 1
                if desktop_ini(f).is_file(): ini_count += 1
                total += 1
    except Exception:
        pass

    issues = specials + ini_count + readonly_count
    if total == 0:
        health = 100
    else:
        # Simple heuristic: more issues → lower health
        ratio = issues / max(total, 1)
        health = max(0, int(100 - ratio * 100))

    return {
        "root": str(root),
        "folders_scanned": folders_scanned,
        "special_folders": specials,
        "desktop_ini_files": ini_count,
        "readonly_folders": readonly_count,
        "health_score": health,
    }

# --- Explorer Crash Recovery Engine (best-effort) ---

def explorer_crash_recovery():
    """
    Best-effort crash recovery: restart Explorer and refresh icons.
    """
    result = {"restart": None, "icon_refresh": None}
    result["restart"] = restart_explorer()
    result["icon_refresh"] = refresh_explorer_icons()
    return result

# --- Folder Encryption Manager (placeholder using EFS) ---

def encrypt_folder(folder):
    """
    Best-effort encryption using Windows EFS via cipher.exe.
    """
    folder = Path(folder)
    if not folder.exists():
        return {"folder": str(folder), "error": "Folder does not exist"}
    try:
        proc = subprocess.run(["cipher", "/E", str(folder)], capture_output=True, text=True, shell=True)
        return {"folder": str(folder), "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as e:
        return {"folder": str(folder), "error": str(e)}

def decrypt_folder(folder):
    """
    Best-effort decryption using Windows EFS via cipher.exe.
    """
    folder = Path(folder)
    if not folder.exists():
        return {"folder": str(folder), "error": "Folder does not exist"}
    try:
        proc = subprocess.run(["cipher", "/D", str(folder)], capture_output=True, text=True, shell=True)
        return {"folder": str(folder), "stdout": proc.stdout, "stderr": proc.stderr}
    except Exception as e:
        return {"folder": str(folder), "error": str(e)}

# --- Full Theme Pack Manager ---

def load_theme_pack(path):
    return load_json(Path(path), {"icon_pack": {"rules": []}, "explorer_tweaks": {}, "sandbox_rules": {}})

def save_theme_pack(path, pack):
    save_json(Path(path), pack)

def apply_theme_pack(root, pack):
    """
    Apply theme pack: icon pack + explorer tweaks + sandbox rules.
    """
    results = {"icon_pack": None, "tweaks": [], "sandbox": []}
    icon_pack = pack.get("icon_pack", {"rules": []})
    results["icon_pack"] = apply_icon_pack(root, icon_pack)

    tweaks = pack.get("explorer_tweaks", {})
    for tweak in EXPLORER_TWEAKS:
        desired = tweaks.get(tweak["name"])
        if desired is None: continue
        ok = set_tweak_state(tweak, enable=bool(desired))
        results["tweaks"].append({"name": tweak["name"], "enabled": bool(desired), "ok": ok})

    sandbox_rules = pack.get("sandbox_rules", {})
    for folder, rule_dict in sandbox_rules.items():
        try:
            set_folder_rules(folder, rule_dict)
            results["sandbox"].append({"folder": folder, "rules": rule_dict})
        except Exception as e:
            results["sandbox"].append({"folder": folder, "error": str(e)})

    return results

# --- GUI APP ---

class App:
    def __init__(self):
        self.root = (TkinterDnD.Tk() if TkinterDnD else tk.Tk())
        self.root.title("Folder Control Center Ultimate")
        self.root.geometry("1280x860"); self.root.minsize(900, 600)
        self.last_folder = None
        self.observer = None
        self.sandbox_enabled = False
        self.build_style()
        self.build_ui()
        self.load_state()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def build_style(self):
        s = ttk.Style(self.root)
        try: s.theme_use("vista")
        except Exception: pass
        s.configure("Title.TLabel", font=("Segoe UI", 15, "bold"))
        s.configure("Small.TLabel", font=("Segoe UI", 9))

    def build_ui(self):
        top = ttk.Frame(self.root, padding=8); top.pack(fill="x")
        ttk.Label(top, text="Folder Control Center Ultimate", style="Title.TLabel").pack(side="left")
        self.status = ttk.Label(top, text="Ready", style="Small.TLabel"); self.status.pack(side="right")
        self.tabs = ttk.Notebook(self.root); self.tabs.pack(fill="both", expand=True, padx=8, pady=4)

        self.tab_analyze = ttk.Frame(self.tabs)
        self.tab_attr = ttk.Frame(self.tabs)
        self.tab_ini = ttk.Frame(self.tabs)
        self.tab_backup = ttk.Frame(self.tabs)
        self.tab_sandbox = ttk.Frame(self.tabs)
        self.tab_cleanup = ttk.Frame(self.tabs)
        self.tab_mass = ttk.Frame(self.tabs)
        self.tab_explorer = ttk.Frame(self.tabs)
        self.tab_icon = ttk.Frame(self.tabs)
        self.tab_iconpacks = ttk.Frame(self.tabs)
        self.tab_permissions = ttk.Frame(self.tabs)
        self.tab_tweaks = ttk.Frame(self.tabs)
        self.tab_ai = ttk.Frame(self.tabs)
        self.tab_health = ttk.Frame(self.tabs)
        self.tab_recovery = ttk.Frame(self.tabs)
        self.tab_encrypt = ttk.Frame(self.tabs)
        self.tab_theme = ttk.Frame(self.tabs)
        self.tab_logs = ttk.Frame(self.tabs)

        for tab, name in [
            (self.tab_analyze, "Analyze"),
            (self.tab_attr, "Attributes"),
            (self.tab_ini, "Desktop.ini"),
            (self.tab_backup, "Backup/Restore"),
            (self.tab_sandbox, "Sandbox / Firewall"),
            (self.tab_cleanup, "Cleanup"),
            (self.tab_mass, "Mass Tools"),
            (self.tab_explorer, "Explorer Tools"),
            (self.tab_icon, "Icon Editor"),
            (self.tab_iconpacks, "Icon Packs"),
            (self.tab_permissions, "Permissions"),
            (self.tab_tweaks, "Explorer Tweaks"),
            (self.tab_ai, "Behavior Predictor"),
            (self.tab_health, "Health Score"),
            (self.tab_recovery, "Crash Recovery"),
            (self.tab_encrypt, "Encryption"),
            (self.tab_theme, "Theme Packs"),
            (self.tab_logs, "Logs"),
        ]:
            self.tabs.add(tab, text=name)

        self.build_analyze()
        self.build_attributes()
        self.build_ini()
        self.build_backup()
        self.build_sandbox()
        self.build_cleanup()
        self.build_mass()
        self.build_explorer()
        self.build_icon()
        self.build_iconpacks()
        self.build_permissions()
        self.build_tweaks()
        self.build_ai()
        self.build_health()
        self.build_recovery()
        self.build_encrypt()
        self.build_theme()
        self.build_logs()

    def field(self, parent, label):
        f = ttk.Frame(parent); f.pack(fill="x", padx=10, pady=5)
        ttk.Label(f, text=label, width=18).pack(side="left")
        e = ttk.Entry(f); e.pack(side="left", fill="x", expand=True)
        return e

    def browse_into(self, entry, folder=True):
        value = filedialog.askdirectory() if folder else filedialog.askopenfilename()
        if value:
            entry.delete(0, "end")
            entry.insert(0, value)

    def build_analyze(self):
        ttk.Label(self.tab_analyze, text="Analyze folders and inspect metadata", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.analyze_entry = self.field(self.tab_analyze, "Folder")
        b = ttk.Frame(self.tab_analyze); b.pack(fill="x", padx=10)
        ttk.Button(b, text="Browse", command=lambda: self.browse_into(self.analyze_entry)).pack(side="left")
        ttk.Button(b, text="Analyze", command=self.analyze).pack(side="left", padx=5)
        ttk.Button(b, text="Backup Metadata", command=self.backup_current).pack(side="left")
        self.analyze_text = ScrolledText(self.tab_analyze, font=("Consolas", 10))
        self.analyze_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_attributes(self):
        ttk.Label(self.tab_attr, text="Graphical folder attribute map", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.attr_entry = self.field(self.tab_attr, "Folder or file")
        ttk.Button(self.tab_attr, text="Browse Folder", command=lambda: self.browse_into(self.attr_entry)).pack(anchor="w", padx=10)
        self.attr_canvas = tk.Canvas(self.tab_attr, height=300)
        self.attr_canvas.pack(fill="x", padx=10, pady=10)
        ttk.Button(self.tab_attr, text="Visualize Attributes", command=self.visualize).pack(anchor="w", padx=10)

    def build_ini(self):
        ttk.Label(self.tab_ini, text="Desktop.ini editor", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.ini_entry = self.field(self.tab_ini, "desktop.ini")
        b = ttk.Frame(self.tab_ini); b.pack(fill="x", padx=10)
        ttk.Button(b, text="Open Folder", command=self.open_ini_folder).pack(side="left")
        ttk.Button(b, text="Load", command=self.load_ini).pack(side="left", padx=5)
        ttk.Button(b, text="Save", command=self.save_ini).pack(side="left")
        ttk.Button(b, text="Save As", command=self.save_ini_as).pack(side="left", padx=5)
        self.ini_text = ScrolledText(self.tab_ini, font=("Consolas", 10), undo=True)
        self.ini_text.pack(fill="both", expand=True, padx=10, pady=10)
        self.ini_text.tag_configure("section", foreground="#0066aa")
        self.ini_text.tag_configure("comment", foreground="#777777")

    def build_backup(self):
        ttk.Label(self.tab_backup, text="Backup and restore folder metadata", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.back_entry = self.field(self.tab_backup, "Folder")
        ttk.Button(self.tab_backup, text="Browse", command=lambda: self.browse_into(self.back_entry)).pack(anchor="w", padx=10)
        b = ttk.Frame(self.tab_backup); b.pack(fill="x", padx=10, pady=8)
        ttk.Button(b, text="Create Backup", command=self.create_backup).pack(side="left")
        ttk.Button(b, text="Restore Backup", command=self.do_restore).pack(side="left", padx=5)
        ttk.Button(b, text="Open Backup Folder", command=lambda: os.startfile(BACKUP_DIR)).pack(side="left")
        self.back_text = ScrolledText(self.tab_backup, font=("Consolas", 10))
        self.back_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_sandbox(self):
        ttk.Label(self.tab_sandbox, text="Folder behavior sandbox / firewall", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.sandbox_entry = self.field(self.tab_sandbox, "Watch folder")
        b = ttk.Frame(self.tab_sandbox); b.pack(fill="x", padx=10)
        ttk.Button(b, text="Browse", command=lambda: self.browse_into(self.sandbox_entry)).pack(side="left")
        ttk.Button(b, text="Start Monitor", command=self.start_sandbox).pack(side="left", padx=5)
        ttk.Button(b, text="Stop Monitor", command=self.stop_sandbox).pack(side="left")
        ttk.Label(self.tab_sandbox, text="Template sandbox & firewall rules (per folder):", style="Small.TLabel").pack(anchor="w", padx=10, pady=5)
        r = ttk.Frame(self.tab_sandbox); r.pack(fill="x", padx=10, pady=5)
        self.rule_log_only = tk.BooleanVar(value=True)
        self.rule_auto_revert = tk.BooleanVar(value=False)
        self.rule_block_ini = tk.BooleanVar(value=False)
        self.rule_block_ro = tk.BooleanVar(value=False)
        ttk.Checkbutton(r, text="Log only", variable=self.rule_log_only).pack(side="left")
        ttk.Checkbutton(r, text="Auto-revert template", variable=self.rule_auto_revert).pack(side="left", padx=5)
        ttk.Checkbutton(r, text="Block desktop.ini", variable=self.rule_block_ini).pack(side="left", padx=5)
        ttk.Checkbutton(r, text="Block READONLY", variable=self.rule_block_ro).pack(side="left", padx=5)
        ttk.Button(self.tab_sandbox, text="Apply Rules to Folder", command=self.apply_sandbox_rules).pack(anchor="w", padx=10, pady=5)
        ttk.Label(self.tab_sandbox, text="Monitoring is observation-first; firewall rules may auto-revert or block changes.", wraplength=900).pack(anchor="w", padx=10, pady=10)
        self.sandbox_text = ScrolledText(self.tab_sandbox, font=("Consolas", 10))
        self.sandbox_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_cleanup(self):
        ttk.Label(self.tab_cleanup, text="Conservative one-click cleanup", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.clean_entry = self.field(self.tab_cleanup, "Scan folder")
        ttk.Button(self.tab_cleanup, text="Browse", command=lambda: self.browse_into(self.clean_entry)).pack(anchor="w", padx=10)
        b = ttk.Frame(self.tab_cleanup); b.pack(fill="x", padx=10, pady=8)
        ttk.Button(b, text="Scan Candidates", command=self.scan_cleanup).pack(side="left")
        ttk.Button(b, text="Delete Listed Candidates", command=self.delete_cleanup).pack(side="left", padx=5)
        self.clean_text = ScrolledText(self.tab_cleanup, font=("Consolas", 10))
        self.clean_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_mass(self):
        ttk.Label(self.tab_mass, text="Mass special-folder tools and audit", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.mass_root_entry = self.field(self.tab_mass, "Root folder")
        ttk.Button(self.tab_mass, text="Browse", command=lambda: self.browse_into(self.mass_root_entry)).pack(anchor="w", padx=10)
        b = ttk.Frame(self.tab_mass); b.pack(fill="x", padx=10, pady=8)
        ttk.Button(b, text="Scan for Special Folders", command=self.mass_scan_special).pack(side="left")
        ttk.Button(b, text="Fix ALL Special Folders", command=self.mass_fix_special).pack(side="left", padx=5)
        ttk.Button(b, text="Scan for desktop.ini", command=self.mass_scan_ini).pack(side="left", padx=5)
        ttk.Button(b, text="Generate Folder Audit Report", command=self.mass_audit).pack(side="left", padx=5)
        self.mass_text = ScrolledText(self.tab_mass, font=("Consolas", 10))
        self.mass_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_explorer(self):
        ttk.Label(self.tab_explorer, text="Explorer / icon tools", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        b = ttk.Frame(self.tab_explorer); b.pack(fill="x", padx=10, pady=8)
        ttk.Button(b, text="Refresh Explorer Icons", command=self.explorer_refresh).pack(side="left")
        ttk.Button(b, text="Rebuild Icon Cache (Best Effort)", command=self.explorer_rebuild_cache).pack(side="left", padx=5)
        ttk.Button(b, text="Restart Explorer", command=self.explorer_restart).pack(side="left", padx=5)
        self.explorer_text = ScrolledText(self.tab_explorer, font=("Consolas", 10))
        self.explorer_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_icon(self):
        ttk.Label(self.tab_icon, text="Folder icon editor and template reset", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.icon_folder_entry = self.field(self.tab_icon, "Folder")
        ttk.Button(self.tab_icon, text="Browse Folder", command=lambda: self.browse_into(self.icon_folder_entry)).pack(anchor="w", padx=10)
        self.icon_file_entry = self.field(self.tab_icon, "Icon (.ico)")
        ttk.Button(self.tab_icon, text="Browse Icon", command=lambda: self.browse_into(self.icon_file_entry, folder=False)).pack(anchor="w", padx=10)
        b = ttk.Frame(self.tab_icon); b.pack(fill="x", padx=10, pady=8)
        ttk.Button(b, text="Apply Icon to Folder", command=self.icon_apply).pack(side="left")
        ttk.Button(b, text="Reset Folder Template", command=self.icon_reset_template).pack(side="left", padx=5)
        self.icon_text = ScrolledText(self.tab_icon, font=("Consolas", 10))
        self.icon_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_iconpacks(self):
        ttk.Label(self.tab_iconpacks, text="System-wide icon pack manager", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.iconpack_root_entry = self.field(self.tab_iconpacks, "Root folder")
        ttk.Button(self.tab_iconpacks, text="Browse Root", command=lambda: self.browse_into(self.iconpack_root_entry)).pack(anchor="w", padx=10)
        self.iconpack_file_entry = self.field(self.tab_iconpacks, "Icon pack JSON")
        ttk.Button(self.tab_iconpacks, text="Browse Pack", command=lambda: self.browse_into(self.iconpack_file_entry, folder=False)).pack(anchor="w", padx=10)
        b = ttk.Frame(self.tab_iconpacks); b.pack(fill="x", padx=10, pady=8)
        ttk.Button(b, text="Load Pack", command=self.iconpack_load).pack(side="left")
        ttk.Button(b, text="Save Pack", command=self.iconpack_save).pack(side="left", padx=5)
        ttk.Button(b, text="Apply Pack to Root", command=self.iconpack_apply).pack(side="left", padx=5)
        self.iconpack_text = ScrolledText(self.tab_iconpacks, font=("Consolas", 10))
        self.iconpack_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_permissions(self):
        ttk.Label(self.tab_permissions, text="Folder permissions analyzer", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.perm_entry = self.field(self.tab_permissions, "Folder")
        ttk.Button(self.tab_permissions, text="Browse", command=lambda: self.browse_into(self.perm_entry)).pack(anchor="w", padx=10)
        ttk.Button(self.tab_permissions, text="Analyze Permissions", command=self.perm_analyze).pack(anchor="w", padx=10, pady=5)
        self.perm_text = ScrolledText(self.tab_permissions, font=("Consolas", 10))
        self.perm_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_tweaks(self):
        ttk.Label(self.tab_tweaks, text="Registry-based Explorer tweaks", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        if not winreg:
            ttk.Label(self.tab_tweaks, text="winreg unavailable; Explorer tweaks disabled.", style="Small.TLabel").pack(anchor="w", padx=10, pady=5)
            return
        self.tweak_vars = []
        for tweak in EXPLORER_TWEAKS:
            frame = ttk.Frame(self.tab_tweaks); frame.pack(fill="x", padx=10, pady=5)
            var = tk.BooleanVar(value=False)
            state = get_tweak_state(tweak)
            if state is not None:
                var.set(state == tweak["on"])
            ttk.Checkbutton(frame, text=tweak["name"], variable=var).pack(side="left")
            self.tweak_vars.append((tweak, var))
        ttk.Button(self.tab_tweaks, text="Apply Tweaks", command=self.apply_tweaks).pack(anchor="w", padx=10, pady=5)
        ttk.Button(self.tab_tweaks, text="Refresh States", command=self.refresh_tweaks).pack(anchor="w", padx=10, pady=5)
        self.tweaks_text = ScrolledText(self.tab_tweaks, font=("Consolas", 10))
        self.tweaks_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_ai(self):
        ttk.Label(self.tab_ai, text="Folder Behavior AI Predictor (heuristic)", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.ai_entry = self.field(self.tab_ai, "Folder")
        ttk.Button(self.tab_ai, text="Browse", command=lambda: self.browse_into(self.ai_entry)).pack(anchor="w", padx=10)
        ttk.Button(self.tab_ai, text="Predict Behavior", command=self.ai_predict).pack(anchor="w", padx=10, pady=5)
        self.ai_text = ScrolledText(self.tab_ai, font=("Consolas", 10))
        self.ai_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_health(self):
        ttk.Label(self.tab_health, text="System-wide Folder Health Score", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.health_entry = self.field(self.tab_health, "Root folder")
        ttk.Button(self.tab_health, text="Browse", command=lambda: self.browse_into(self.health_entry)).pack(anchor="w", padx=10)
        ttk.Button(self.tab_health, text="Compute Health Score", command=self.health_compute).pack(anchor="w", padx=10, pady=5)
        self.health_text = ScrolledText(self.tab_health, font=("Consolas", 10))
        self.health_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_recovery(self):
        ttk.Label(self.tab_recovery, text="Explorer Crash Recovery Engine", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        ttk.Button(self.tab_recovery, text="Run Crash Recovery", command=self.recovery_run).pack(anchor="w", padx=10, pady=5)
        self.recovery_text = ScrolledText(self.tab_recovery, font=("Consolas", 10))
        self.recovery_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_encrypt(self):
        ttk.Label(self.tab_encrypt, text="Folder Encryption Manager (EFS)", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.encrypt_entry = self.field(self.tab_encrypt, "Folder")
        ttk.Button(self.tab_encrypt, text="Browse", command=lambda: self.browse_into(self.encrypt_entry)).pack(anchor="w", padx=10)
        b = ttk.Frame(self.tab_encrypt); b.pack(fill="x", padx=10, pady=8)
        ttk.Button(b, text="Encrypt Folder", command=self.encrypt_run).pack(side="left")
        ttk.Button(b, text="Decrypt Folder", command=self.decrypt_run).pack(side="left", padx=5)
        self.encrypt_text = ScrolledText(self.tab_encrypt, font=("Consolas", 10))
        self.encrypt_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_theme(self):
        ttk.Label(self.tab_theme, text="Full Theme Pack Manager", style="Title.TLabel").pack(anchor="w", padx=10, pady=10)
        self.theme_root_entry = self.field(self.tab_theme, "Root folder")
        ttk.Button(self.tab_theme, text="Browse Root", command=lambda: self.browse_into(self.theme_root_entry)).pack(anchor="w", padx=10)
        self.theme_file_entry = self.field(self.tab_theme, "Theme pack JSON")
        ttk.Button(self.tab_theme, text="Browse Theme", command=lambda: self.browse_into(self.theme_file_entry, folder=False)).pack(anchor="w", padx=10)
        b = ttk.Frame(self.tab_theme); b.pack(fill="x", padx=10, pady=8)
        ttk.Button(b, text="Load Theme", command=self.theme_load).pack(side="left")
        ttk.Button(b, text="Save Example Theme", command=self.theme_save).pack(side="left", padx=5)
        ttk.Button(b, text="Apply Theme to Root", command=self.theme_apply).pack(side="left", padx=5)
        self.theme_text = ScrolledText(self.tab_theme, font=("Consolas", 10))
        self.theme_text.pack(fill="both", expand=True, padx=10, pady=10)

    def build_logs(self):
        self.log_text = ScrolledText(self.tab_logs, font=("Consolas", 10))
        self.log_text.pack(fill="both", expand=True, padx=10, pady=10)
        ttk.Button(self.tab_logs, text="Clear Logs", command=lambda: self.log_text.delete("1.0", "end")).pack(anchor="w", padx=10, pady=5)

    def safe_log(self, text):
        self.root.after(0, lambda: self._log(text))

    def _log(self, text):
        self.log_text.insert("end", f"[{log_time()}] {text}\n")
        self.log_text.see("end")

    def after_event(self, path):
        self.safe_log(f"Observed change: {path}")

    def choose_folder(self, entry):
        p = entry.get().strip()
        return Path(p) if p else None

    def analyze(self):
        p = self.choose_folder(self.analyze_entry)
        if not p or not p.is_dir():
            messagebox.showerror("Invalid folder", "Choose an existing folder.")
            return
        self.last_folder = str(p)
        data = folder_report(p)
        self.analyze_text.delete("1.0", "end")
        self.analyze_text.insert("end", json.dumps(data, indent=2))
        self.safe_log(f"Analyzed {p}")

    def backup_current(self):
        p = self.choose_folder(self.analyze_entry)
        if not p: return
        try:
            target, _ = backup_folder_metadata(p)
            messagebox.showinfo("Backup created", str(target))
            self.safe_log(f"Backup created: {target}")
        except Exception as e:
            messagebox.showerror("Backup failed", str(e))

    def visualize(self):
        p = Path(self.attr_entry.get().strip())
        value = attrs_raw(p)
        self.attr_canvas.delete("all")
        if value is None:
            messagebox.showerror("Error", "Cannot read Windows attributes. Run on Windows with pywin32 installed.")
            return
        items = list(ATTRS.items()); w = 170; h = 55
        for i, (name, bit) in enumerate(items):
            x = (i % 5) * w + 10; y = (i // 5) * h + 10
            on = bool(value & bit)
            fill = "#69b36d" if on else "#dddddd"
            self.attr_canvas.create_rectangle(x, y, x + 150, y + 38, fill=fill, outline="#444")
            self.attr_canvas.create_text(x + 75, y + 19, text=name, fill="#000")

    def open_ini_folder(self):
        p = filedialog.askdirectory()
        if p:
            self.ini_entry.delete(0, "end")
            self.ini_entry.insert(0, str(Path(p) / "desktop.ini"))
            self.load_ini()

    def highlight_ini(self):
        self.ini_text.tag_remove("section", "1.0", "end")
        self.ini_text.tag_remove("comment", "1.0", "end")
        for i, line in enumerate(self.ini_text.get("1.0", "end").splitlines(), 1):
            s = line.strip()
            tag = "section" if s.startswith("[") and s.endswith("]") else "comment" if s.startswith((";", "#")) else None
            if tag:
                self.ini_text.tag_add(tag, f"{i}.0", f"{i}.end")

    def load_ini(self):
        p = Path(self.ini_entry.get().strip())
        try:
            self.ini_text.delete("1.0", "end")
            self.ini_text.insert("1.0", p.read_text(encoding="utf-8-sig"))
            self.highlight_ini()
            self.safe_log(f"Loaded {p}")
        except Exception as e:
            messagebox.showerror("Load failed", str(e))

    def save_ini(self):
        p = Path(self.ini_entry.get().strip())
        if not p.name.lower() == "desktop.ini":
            messagebox.showerror("Invalid file", "Only desktop.ini is supported here.")
            return
        try:
            p.write_text(self.ini_text.get("1.0", "end-1c"), encoding="utf-8")
            self.highlight_ini()
            self.safe_log(f"Saved {p}")
        except Exception as e:
            messagebox.showerror("Save failed", str(e))

    def save_ini_as(self):
        p = filedialog.asksaveasfilename(defaultextension=".ini", filetypes=[("INI files", "*.ini"), ("All files", "*.*")])
        if p:
            self.ini_entry.delete(0, "end")
            self.ini_entry.insert(0, p)
            self.save_ini()

    def create_backup(self):
        p = self.choose_folder(self.back_entry)
        try:
            target, _ = backup_folder_metadata(p)
            self.back_text.insert("end", f"Created: {target}\n")
        except Exception as e:
            messagebox.showerror("Backup failed", str(e))

    def do_restore(self):
        p = filedialog.askdirectory(initialdir=BACKUP_DIR, title="Select backup directory")
        if not p or not messagebox.askyesno("Confirm restore", "Restore this backup and overwrite its recorded desktop.ini file?"):
            return
        try:
            result = restore_backup(p)
            self.back_text.insert("end", json.dumps(result, indent=2) + "\n")
            self.safe_log(f"Restored backup {p}")
        except Exception as e:
            messagebox.showerror("Restore failed", str(e))

    def start_sandbox(self):
        if Observer is None:
            messagebox.showerror("Missing dependency", "Install watchdog with: python -m pip install watchdog")
            return
        p = self.choose_folder(self.sandbox_entry)
        if not p or not p.is_dir():
            messagebox.showerror("Invalid folder", "Choose an existing folder.")
            return
        self.stop_sandbox()
        self.observer = Observer()
        self.observer.schedule(SandboxHandler(self), str(p), recursive=True)
        self.observer.start()
        self.sandbox_enabled = True
        self.sandbox_text.insert("end", f"Monitoring: {p}\n")
        self.safe_log(f"Sandbox monitor started: {p}")

    def stop_sandbox(self):
        if self.observer:
            try:
                self.observer.stop()
                self.observer.join(timeout=2)
            except Exception:
                pass
            self.observer = None
        self.sandbox_enabled = False

    def apply_sandbox_rules(self):
        p = self.choose_folder(self.sandbox_entry)
        if not p or not p.is_dir():
            messagebox.showerror("Invalid folder", "Choose an existing folder.")
            return
        rules = {
            "log_only": self.rule_log_only.get(),
            "auto_revert_template": self.rule_auto_revert.get(),
            "block_desktop_ini": self.rule_block_ini.get(),
            "block_readonly": self.rule_block_ro.get(),
        }
        set_folder_rules(p, rules)
        self.sandbox_text.insert("end", f"Applied rules to {p}:\n{json.dumps(rules, indent=2)}\n")
        self.safe_log(f"Sandbox rules applied to {p}")

    def scan_cleanup(self):
        p = self.choose_folder(self.clean_entry)
        items = cleanup_candidates(p) if p else []
        self.clean_text.delete("1.0", "end")
        self.clean_text.insert("end", json.dumps(items, indent=2))
        self.safe_log(f"Cleanup scan found {len(items)} candidate(s)")

    def delete_cleanup(self):
        p = self.choose_folder(self.clean_entry)
        items = cleanup_candidates(p) if p else []
        if not items: return
        if not messagebox.askyesno("Confirm cleanup", f"Delete {len(items)} selected temporary/backup candidates under {p}?\nThis cannot be undone."):
            return
        deleted = 0
        for item in items:
            try:
                Path(item["path"]).unlink()
                deleted += 1
            except Exception as e:
                self.safe_log(f"Could not delete {item['path']}: {e}")
        self.safe_log(f"Cleanup deleted {deleted} file(s)")
        self.scan_cleanup()

    def mass_root(self):
        p = self.mass_root_entry.get().strip()
        return Path(p) if p else None

    def mass_scan_special(self):
        root = self.mass_root()
        if not root or not root.is_dir():
            messagebox.showerror("Invalid root", "Choose an existing folder.")
            return
        specials = scan_for_special_folders(root)
        self.mass_text.delete("1.0", "end")
        self.mass_text.insert("end", json.dumps(specials, indent=2))
        self.safe_log(f"Mass scan: {len(specials)} special folder(s) under {root}")

    def mass_fix_special(self):
        root = self.mass_root()
        if not root or not root.is_dir():
            messagebox.showerror("Invalid root", "Choose an existing folder.")
            return
        specials = scan_for_special_folders(root)
        if not specials:
            messagebox.showinfo("No specials", "No special folders found.")
            return
        if not messagebox.askyesno("Confirm mass fix", f"Fix {len(specials)} special folder(s) under {root}?"):
            return
        fixed = []
        for item in specials:
            f = item["folder"]
            actions = fix_special_folder(f, delete_ini=True, backup_ini=True)
            fixed.append({"folder": f, "actions": actions})
        self.mass_text.delete("1.0", "end")
        self.mass_text.insert("end", json.dumps(fixed, indent=2))
        self.safe_log(f"Mass fix applied to {len(fixed)} folder(s)")
        refresh_explorer_icons()

    def mass_scan_ini(self):
        root = self.mass_root()
        if not root or not root.is_dir():
            messagebox.showerror("Invalid root", "Choose an existing folder.")
            return
        results = find_all_desktop_ini(root)
        self.mass_text.delete("1.0", "end")
        self.mass_text.insert("end", json.dumps(results, indent=2))
        self.safe_log(f"Found {len(results)} desktop.ini file(s) under {root}")

    def mass_audit(self):
        root = self.mass_root()
        if not root or not root.is_dir():
            messagebox.showerror("Invalid root", "Choose an existing folder.")
            return
        report = audit_folders(root)
        self.mass_text.delete("1.0", "end")
        self.mass_text.insert("end", json.dumps(report, indent=2))
        self.safe_log(f"Audit report generated for {len(report)} folder(s) under {root}")

    def explorer_refresh(self):
        ok = refresh_explorer_icons()
        self.explorer_text.insert("end", f"Refresh Explorer icons: {'OK' if ok else 'FAILED'}\n")
        self.safe_log("Explorer icon refresh requested")

    def explorer_rebuild_cache(self):
        result = rebuild_icon_cache_best_effort()
        self.explorer_text.insert("end", json.dumps(result, indent=2) + "\n")
        self.safe_log("Icon cache rebuild requested")

    def explorer_restart(self):
        if not messagebox.askyesno("Restart Explorer", "Kill and restart explorer.exe? Open windows may briefly disappear."):
            return
        result = restart_explorer()
        self.explorer_text.insert("end", json.dumps(result, indent=2) + "\n")
        self.safe_log("Explorer restart requested")

    def icon_apply(self):
        folder = self.icon_folder_entry.get().strip()
        icon = self.icon_file_entry.get().strip()
        if not folder or not icon:
            messagebox.showerror("Missing data", "Specify both folder and icon file.")
            return
        actions = set_folder_icon(folder, icon)
        self.icon_text.insert("end", json.dumps(actions, indent=2) + "\n")
        self.safe_log(f"Icon applied to {folder}")
        refresh_explorer_icons()

    def icon_reset_template(self):
        folder = self.icon_folder_entry.get().strip()
        if not folder:
            messagebox.showerror("Missing folder", "Specify a folder to reset.")
            return
        actions = reset_folder_template(folder)
        self.icon_text.insert("end", json.dumps(actions, indent=2) + "\n")
        self.safe_log(f"Template reset for {folder}")
        refresh_explorer_icons()

    def iconpack_load(self):
        path = self.iconpack_file_entry.get().strip()
        if not path:
            messagebox.showerror("Missing pack", "Specify an icon pack JSON file.")
            return
        pack = load_icon_pack(path)
        self.iconpack_text.insert("end", f"Loaded pack from {path}:\n{json.dumps(pack, indent=2)}\n")
        self.safe_log(f"Icon pack loaded from {path}")

    def iconpack_save(self):
        path = self.iconpack_file_entry.get().strip()
        if not path:
            path = filedialog.asksaveasfilename(initialdir=ICON_PACK_DIR, defaultextension=".json",
                                                filetypes=[("JSON files", "*.json")])
            if not path: return
            self.iconpack_file_entry.delete(0, "end")
            self.iconpack_file_entry.insert(0, path)
        pack = {"rules": [
            {"pattern": "Games", "icon": "C:\\icons\\game.ico"},
            {"pattern": "Media", "icon": "C:\\icons\\media.ico"},
        ]}
        save_icon_pack(path, pack)
        self.iconpack_text.insert("end", f"Saved example pack to {path}:\n{json.dumps(pack, indent=2)}\n")
        self.safe_log(f"Icon pack saved to {path}")

    def iconpack_apply(self):
        root = self.iconpack_root_entry.get().strip()
        pack_path = self.iconpack_file_entry.get().strip()
        if not root or not pack_path:
            messagebox.showerror("Missing data", "Specify both root folder and icon pack JSON.")
            return
        pack = load_icon_pack(pack_path)
        results = apply_icon_pack(root, pack)
        self.iconpack_text.insert("end", f"Applied pack to {root}:\n{json.dumps(results, indent=2)}\n")
        self.safe_log(f"Icon pack applied to {root}")
        refresh_explorer_icons()

    def perm_analyze(self):
        folder = self.perm_entry.get().strip()
        if not folder:
            messagebox.showerror("Missing folder", "Specify a folder.")
            return
        result = analyze_permissions(folder)
        self.perm_text.delete("1.0", "end")
        self.perm_text.insert("end", json.dumps(result, indent=2))
        self.safe_log(f"Permissions analyzed for {folder}")

    def apply_tweaks(self):
        if not winreg:
            messagebox.showerror("Unavailable", "winreg not available.")
            return
        for tweak, var in self.tweak_vars:
            ok = set_tweak_state(tweak, enable=var.get())
            self.tweaks_text.insert("end", f"{tweak['name']}: {'OK' if ok else 'FAILED'}\n")
        self.safe_log("Explorer tweaks applied")

    def refresh_tweaks(self):
        if not winreg:
            return
        self.tweaks_text.insert("end", "Refreshing tweak states...\n")
        for tweak, var in self.tweak_vars:
            state = get_tweak_state(tweak)
            if state is not None:
                var.set(state == tweak["on"])
            self.tweaks_text.insert("end", f"{tweak['name']} state: {state}\n")
        self.safe_log("Explorer tweak states refreshed")

    def ai_predict(self):
        folder = self.ai_entry.get().strip()
        if not folder:
            messagebox.showerror("Missing folder", "Specify a folder.")
            return
        result = predict_folder_behavior(folder)
        self.ai_text.delete("1.0", "end")
        self.ai_text.insert("end", json.dumps(result, indent=2))
        self.safe_log(f"Behavior predicted for {folder}")

    def health_compute(self):
        root = self.health_entry.get().strip()
        if not root:
            messagebox.showerror("Missing root", "Specify a root folder.")
            return
        result = compute_health_score(root)
        self.health_text.delete("1.0", "end")
        self.health_text.insert("end", json.dumps(result, indent=2))
        self.safe_log(f"Health score computed for {root}")

    def recovery_run(self):
        result = explorer_crash_recovery()
        self.recovery_text.delete("1.0", "end")
        self.recovery_text.insert("end", json.dumps(result, indent=2))
        self.safe_log("Crash recovery executed")

    def encrypt_run(self):
        folder = self.encrypt_entry.get().strip()
        if not folder:
            messagebox.showerror("Missing folder", "Specify a folder.")
            return
        result = encrypt_folder(folder)
        self.encrypt_text.delete("1.0", "end")
        self.encrypt_text.insert("end", json.dumps(result, indent=2))
        self.safe_log(f"Encryption requested for {folder}")

    def decrypt_run(self):
        folder = self.encrypt_entry.get().strip()
        if not folder:
            messagebox.showerror("Missing folder", "Specify a folder.")
            return
        result = decrypt_folder(folder)
        self.encrypt_text.delete("1.0", "end")
        self.encrypt_text.insert("end", json.dumps(result, indent=2))
        self.safe_log(f"Decryption requested for {folder}")

    def theme_load(self):
        path = self.theme_file_entry.get().strip()
        if not path:
            messagebox.showerror("Missing theme", "Specify a theme pack JSON file.")
            return
        pack = load_theme_pack(path)
        self.theme_text.insert("end", f"Loaded theme from {path}:\n{json.dumps(pack, indent=2)}\n")
        self.safe_log(f"Theme pack loaded from {path}")

    def theme_save(self):
        path = self.theme_file_entry.get().strip()
        if not path:
            path = filedialog.asksaveasfilename(initialdir=THEME_PACK_DIR, defaultextension=".json",
                                                filetypes=[("JSON files", "*.json")])
            if not path: return
            self.theme_file_entry.delete(0, "end")
            self.theme_file_entry.insert(0, path)
        pack = {
            "icon_pack": {
                "rules": [
                    {"pattern": "Games", "icon": "C:\\icons\\game.ico"},
                    {"pattern": "Media", "icon": "C:\\icons\\media.ico"},
                ]
            },
            "explorer_tweaks": {
                "Show hidden files": True,
                "Show file extensions": True,
            },
            "sandbox_rules": {
                "C:\\ProtectedFolder": {
                    "log_only": False,
                    "auto_revert_template": True,
                    "block_desktop_ini": True,
                    "block_readonly": True,
                }
            }
        }
        save_theme_pack(path, pack)
        self.theme_text.insert("end", f"Saved example theme to {path}:\n{json.dumps(pack, indent=2)}\n")
        self.safe_log(f"Theme pack saved to {path}")

    def theme_apply(self):
        root = self.theme_root_entry.get().strip()
        path = self.theme_file_entry.get().strip()
        if not root or not path:
            messagebox.showerror("Missing data", "Specify both root folder and theme pack JSON.")
            return
        pack = load_theme_pack(path)
        results = apply_theme_pack(root, pack)
        self.theme_text.insert("end", f"Applied theme to {root}:\n{json.dumps(results, indent=2)}\n")
        self.safe_log(f"Theme pack applied to {root}")
        refresh_explorer_icons()

    def load_state(self):
        self.safe_log("Application started")
        if win32api is None: self.safe_log("WARNING: pywin32 unavailable; Windows attribute operations are disabled")
        if Observer is None: self.safe_log("INFO: watchdog unavailable; sandbox monitoring is disabled")
        if TkinterDnD is None: self.safe_log("INFO: tkinterdnd2 unavailable; drag-and-drop is disabled")
        if winreg is None: self.safe_log("INFO: winreg unavailable; Explorer tweaks disabled")

    def close(self):
        self.stop_sandbox()
        self.root.destroy()

    def run(self):
        self.root.mainloop()

def main():
    try:
        App().run()
    except Exception:
        traceback.print_exc()
        try:
            messagebox.showerror("Startup error", traceback.format_exc())
        except Exception:
            pass

if __name__ == "__main__":
    main()
