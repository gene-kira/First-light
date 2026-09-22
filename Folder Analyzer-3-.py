#!/usr/bin/env python3
# ================================================================
# Folder Fixer — Special Folder Detector & Auto-Fixer
# Author: Copilot for killer666
# Description:
#   • Drag-and-drop folder input (TkinterDnD)
#   • Detects "special" Windows folders:
#       - READONLY folder
#       - SYSTEM+HIDDEN desktop.ini
#   • Automatically fixes:
#       - Clears READONLY on folder
#       - Clears SYSTEM/HIDDEN on desktop.ini
#       - Optional delete/backup of desktop.ini
#   • Can scan a root (e.g., Desktop) for ALL special folders
#   • Copy-to-Clipboard for full report
# ================================================================

import os
import sys
import hashlib
import time
import json
import traceback
import subprocess

# ------------------------------------------------
# AUTOLOADER FOR REQUIRED LIBRARIES
# ------------------------------------------------
REQUIRED_PIP_LIBS = [
    "tkinterdnd2",
    "pywin32",
]

def autoload_libs():
    import importlib

    for lib in REQUIRED_PIP_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            try:
                print(f"[AUTOLOADER] Installing missing library via pip: {lib}")
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            except Exception as e:
                print(f"[AUTOLOADER] Failed to install {lib}: {e}")

autoload_libs()

# ------------------------------------------------
# CORE IMPORTS (AFTER AUTOLOAD)
# ------------------------------------------------
import ctypes
import win32api
import win32con
from tkinter import filedialog, scrolledtext
from tkinterdnd2 import DND_FILES, TkinterDnD

# ------------------------------------------------
# WINDOWS FILE ATTRIBUTE HELPERS
# ------------------------------------------------
def get_windows_file_attributes(path):
    try:
        attrs = win32api.GetFileAttributes(path)
        return attrs
    except Exception:
        return None

def describe_attributes(attrs):
    if attrs is None:
        return {"error": "Could not read attributes"}
    return {
        "READONLY": bool(attrs & win32con.FILE_ATTRIBUTE_READONLY),
        "HIDDEN": bool(attrs & win32con.FILE_ATTRIBUTE_HIDDEN),
        "SYSTEM": bool(attrs & win32con.FILE_ATTRIBUTE_SYSTEM),
        "DIRECTORY": bool(attrs & win32con.FILE_ATTRIBUTE_DIRECTORY),
        "ARCHIVE": bool(attrs & win32con.FILE_ATTRIBUTE_ARCHIVE),
        "NORMAL": bool(attrs & win32con.FILE_ATTRIBUTE_NORMAL),
        "TEMPORARY": bool(attrs & win32con.FILE_ATTRIBUTE_TEMPORARY),
        "COMPRESSED": bool(attrs & win32con.FILE_ATTRIBUTE_COMPRESSED),
        "OFFLINE": bool(attrs & win32con.FILE_ATTRIBUTE_OFFLINE),
        "NOT_CONTENT_INDEXED": bool(attrs & win32con.FILE_ATTRIBUTE_NOT_CONTENT_INDEXED),
        "ENCRYPTED": bool(attrs & win32con.FILE_ATTRIBUTE_ENCRYPTED),
    }

def set_windows_file_attributes(path, attrs):
    try:
        win32api.SetFileAttributes(path, attrs)
        return True
    except Exception:
        return False

# ------------------------------------------------
# HASHING (OPTIONAL, FOR REPORT)
# ------------------------------------------------
def hash_file(path):
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            while True:
                chunk = f.read(8192)
                if not chunk:
                    break
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

# ------------------------------------------------
# SPECIAL FOLDER DETECTION & FIXING
# ------------------------------------------------
def is_special_folder(folder_path):
    """
    A "special" folder for our purposes:
    - Folder exists
    - Folder has READONLY attribute
    - Contains desktop.ini that is SYSTEM + HIDDEN
    """
    if not os.path.isdir(folder_path):
        return False, "Not a folder"

    folder_attrs = get_windows_file_attributes(folder_path)
    if folder_attrs is None:
        return False, "Could not read folder attributes"

    folder_desc = describe_attributes(folder_attrs)
    has_readonly = folder_desc.get("READONLY", False)

    desktop_ini_path = os.path.join(folder_path, "desktop.ini")
    if not os.path.isfile(desktop_ini_path):
        return False, "No desktop.ini present"

    ini_attrs = get_windows_file_attributes(desktop_ini_path)
    if ini_attrs is None:
        return False, "Could not read desktop.ini attributes"

    ini_desc = describe_attributes(ini_attrs)
    is_hidden = ini_desc.get("HIDDEN", False)
    is_system = ini_desc.get("SYSTEM", False)

    if has_readonly and is_hidden and is_system:
        return True, "READONLY folder + SYSTEM+HIDDEN desktop.ini"
    elif is_hidden and is_system:
        return True, "SYSTEM+HIDDEN desktop.ini (even without READONLY)"
    else:
        return False, "desktop.ini not SYSTEM+HIDDEN or folder not READONLY"

def fix_special_folder(folder_path, delete_ini=False, backup_ini=True):
    """
    Fixes a special folder:
    - Clears READONLY on folder
    - Clears SYSTEM/HIDDEN on desktop.ini
    - Optionally deletes desktop.ini (with backup)
    Returns a dict describing actions taken.
    """
    actions = {
        "folder": folder_path,
        "changed_folder_attrs": False,
        "changed_ini_attrs": False,
        "ini_deleted": False,
        "ini_backup_path": None,
        "errors": [],
    }

    if not os.path.isdir(folder_path):
        actions["errors"].append("Not a folder")
        return actions

    # Folder attributes
    folder_attrs = get_windows_file_attributes(folder_path)
    if folder_attrs is None:
        actions["errors"].append("Could not read folder attributes")
    else:
        # Clear READONLY
        if folder_attrs & win32con.FILE_ATTRIBUTE_READONLY:
            new_attrs = folder_attrs & ~win32con.FILE_ATTRIBUTE_READONLY
            if set_windows_file_attributes(folder_path, new_attrs):
                actions["changed_folder_attrs"] = True
            else:
                actions["errors"].append("Failed to clear READONLY on folder")

    # desktop.ini handling
    desktop_ini_path = os.path.join(folder_path, "desktop.ini")
    if os.path.isfile(desktop_ini_path):
        ini_attrs = get_windows_file_attributes(desktop_ini_path)
        if ini_attrs is None:
            actions["errors"].append("Could not read desktop.ini attributes")
        else:
            # Clear SYSTEM + HIDDEN
            new_ini_attrs = ini_attrs & ~win32con.FILE_ATTRIBUTE_SYSTEM
            new_ini_attrs = new_ini_attrs & ~win32con.FILE_ATTRIBUTE_HIDDEN
            if set_windows_file_attributes(desktop_ini_path, new_ini_attrs):
                actions["changed_ini_attrs"] = True
            else:
                actions["errors"].append("Failed to clear SYSTEM/HIDDEN on desktop.ini")

        # Optional delete with backup
        if delete_ini:
            try:
                if backup_ini:
                    backup_path = desktop_ini_path + ".bak"
                    if os.path.exists(backup_path):
                        os.remove(backup_path)
                    os.rename(desktop_ini_path, backup_path)
                    actions["ini_backup_path"] = backup_path
                else:
                    os.remove(desktop_ini_path)
                actions["ini_deleted"] = True
            except Exception as e:
                actions["errors"].append(f"Failed to delete/backup desktop.ini: {e}")

    else:
        actions["errors"].append("No desktop.ini to fix/delete")

    return actions

def scan_for_special_folders(root_path):
    """
    Walks a root and returns a list of all special folders detected.
    """
    specials = []
    for current_root, dirs, files in os.walk(root_path):
        for d in dirs:
            folder = os.path.join(current_root, d)
            is_special, reason = is_special_folder(folder)
            if is_special:
                specials.append({
                    "folder": folder,
                    "reason": reason,
                })
    return specials

# ------------------------------------------------
# ANALYSIS REPORT (FOR UI)
# ------------------------------------------------
def analyze_folder(folder_path):
    report = {
        "folder": folder_path,
        "exists": os.path.exists(folder_path),
        "created": None,
        "modified": None,
        "attributes": {},
        "contents": [],
        "summary": {},
        "special_status": {},
    }

    if not os.path.exists(folder_path):
        report["special_status"] = {"is_special": False, "reason": "Folder does not exist"}
        return report

    try:
        report["created"] = time.ctime(os.path.getctime(folder_path))
        report["modified"] = time.ctime(os.path.getmtime(folder_path))
    except Exception:
        pass

    folder_attrs = get_windows_file_attributes(folder_path)
    report["attributes"] = describe_attributes(folder_attrs)

    file_count = 0
    folder_count = 0
    total_size = 0

    for root, dirs, files in os.walk(folder_path):
        for d in dirs:
            folder_count += 1
            full = os.path.join(root, d)
            attrs = get_windows_file_attributes(full)
            entry = {
                "type": "folder",
                "path": full,
                "attributes": describe_attributes(attrs),
            }
            report["contents"].append(entry)

        for f in files:
            file_count += 1
            full = os.path.join(root, f)
            try:
                size = os.path.getsize(full)
                total_size += size
            except Exception:
                size = None

            attrs = get_windows_file_attributes(full)
            entry = {
                "type": "file",
                "path": full,
                "size": size,
                "hash": hash_file(full),
                "attributes": describe_attributes(attrs),
            }
            report["contents"].append(entry)

    report["summary"] = {
        "total_files": file_count,
        "total_folders": folder_count,
        "total_size_bytes": total_size,
    }

    is_special, reason = is_special_folder(folder_path)
    report["special_status"] = {
        "is_special": is_special,
        "reason": reason,
    }

    return report

# ------------------------------------------------
# GUI — DRAG & DROP + AUTO-FIX
# ------------------------------------------------
class FolderFixerGUI:
    def __init__(self):
        self.root = TkinterDnD.Tk()
        self.root.title("Folder Fixer — Special Folder Detector & Auto-Fixer")
        self.root.geometry("1100x800")

        import tkinter as tk

        self.label = tk.Label(
            self.root,
            text="Drag & Drop a Folder Here\n(or use Select Folder button)\nDrop = Analyze + Auto-Fix",
            font=("Arial", 14)
        )
        self.label.pack(pady=10)

        self.drop_area = tk.Label(
            self.root,
            text="DROP FOLDER HERE",
            bg="#222",
            fg="white",
            font=("Consolas", 18),
            width=40,
            height=5,
            relief="ridge",
            bd=3
        )
        self.drop_area.pack(pady=10)

        self.drop_area.drop_target_register(DND_FILES)
        self.drop_area.dnd_bind("<<Drop>>", self.on_drop)

        self.output = scrolledtext.ScrolledText(self.root, width=130, height=30, font=("Consolas", 10))
        self.output.pack(pady=10)

        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)

        self.select_btn = tk.Button(btn_frame, text="Select Folder Manually (Analyze + Fix)", command=self.select_folder)
        self.select_btn.pack(side="left", padx=5)

        self.scan_btn = tk.Button(btn_frame, text="Scan Root for Special Folders", command=self.scan_root)
        self.scan_btn.pack(side="left", padx=5)

        self.copy_btn = tk.Button(btn_frame, text="Copy Output", command=self.copy_output)
        self.copy_btn.pack(side="left", padx=5)

        self.clear_btn = tk.Button(btn_frame, text="Clear Output", command=self.clear_output)
        self.clear_btn.pack(side="left", padx=5)

    # ------------- GUI HELPERS -------------
    def clear_output(self):
        self.output.delete("1.0", "end")

    def copy_output(self):
        text = self.output.get("1.0", "end")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def log(self, text):
        self.output.insert("end", text + "\n")
        self.output.see("end")

    def normalize_dropped_path(self, raw):
        path = raw.strip()
        if path.startswith("{") and path.endswith("}"):
            path = path[1:-1]
        if path.startswith('"') and path.endswith('"'):
            path = path[1:-1]
        return path

    # ------------- ACTIONS -------------
    def on_drop(self, event):
        raw = event.data
        folder = self.normalize_dropped_path(raw)
        if os.path.isdir(folder):
            self.analyze_and_fix(folder)
        else:
            self.log(f"[ERROR] Dropped item is not a folder: {folder}")

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.analyze_and_fix(folder)

    def analyze_and_fix(self, folder):
        self.clear_output()
        self.log(f"[INFO] Analyzing folder: {folder}")
        try:
            report = analyze_folder(folder)
            self.log("[REPORT]")
            self.log(json.dumps(report, indent=4))

            if report["special_status"]["is_special"]:
                self.log(f"[INFO] Folder is special: {report['special_status']['reason']}")
                self.log("[INFO] Applying auto-fix: clear READONLY, clear SYSTEM/HIDDEN on desktop.ini, backup desktop.ini.bak")
                actions = fix_special_folder(folder, delete_ini=True, backup_ini=True)
                self.log("[FIX ACTIONS]")
                self.log(json.dumps(actions, indent=4))
            else:
                self.log(f"[INFO] Folder is NOT special: {report['special_status']['reason']}")
        except Exception:
            self.log("[ERROR] Exception during analyze_and_fix:")
            self.log(traceback.format_exc())

    def scan_root(self):
        from tkinter import simpledialog
        root_path = simpledialog.askstring("Scan Root", "Enter root folder to scan (e.g., C:/Users/tbarr/Desktop):")
        if not root_path:
            return
        if not os.path.isdir(root_path):
            self.log(f"[ERROR] Not a folder: {root_path}")
            return

        self.clear_output()
        self.log(f"[INFO] Scanning for special folders under: {root_path}")
        try:
            specials = scan_for_special_folders(root_path)
            self.log("[SPECIAL FOLDERS FOUND]")
            self.log(json.dumps(specials, indent=4))
        except Exception:
            self.log("[ERROR] Exception during scan_root:")
            self.log(traceback.format_exc())

    def run(self):
        self.root.mainloop()

# ------------------------------------------------
# MAIN ENTRY
# ------------------------------------------------
def main():
    gui = FolderFixerGUI()
    gui.run()

if __name__ == "__main__":
    main()
