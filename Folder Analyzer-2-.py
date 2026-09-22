#!/usr/bin/env python3
# ================================================================
# Folder Analyzer — Full File (All Upgrades Applied)
# Author: Copilot for killer666
# Description:
#   • Auto-installs needed libs (tkinterdnd2 + pywin32)
#   • True drag-and-drop folder input (TkinterDnD)
#   • Deep folder metadata inspection (Windows attributes)
#   • Recursive content + hashes + anomaly detection
#   • JSON report viewer
#   • Copy-to-Clipboard button
# ================================================================

import os
import sys
import hashlib
import time
import json
import traceback

# ------------------------------------------------
# AUTOLOADER FOR REQUIRED LIBRARIES
# ------------------------------------------------
REQUIRED_PIP_LIBS = [
    "tkinterdnd2",
    "pywin32",
]

def autoload_libs():
    import subprocess
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
# WINDOWS FILE ATTRIBUTE INSPECTION
# ------------------------------------------------
def get_windows_file_attributes(path):
    try:
        attrs = win32api.GetFileAttributes(path)
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
    except Exception as e:
        return {"error": str(e)}

# ------------------------------------------------
# HASHING
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
# FOLDER ANALYSIS CORE
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
        "anomalies": [],
    }

    if not os.path.exists(folder_path):
        report["anomalies"].append("Folder does not exist.")
        return report

    # Timestamps
    try:
        report["created"] = time.ctime(os.path.getctime(folder_path))
        report["modified"] = time.ctime(os.path.getmtime(folder_path))
    except Exception:
        report["anomalies"].append("Could not read timestamps.")

    # Windows attributes
    report["attributes"] = get_windows_file_attributes(folder_path)

    # Contents
    file_count = 0
    folder_count = 0
    total_size = 0

    for root, dirs, files in os.walk(folder_path):
        for d in dirs:
            folder_count += 1
            full = os.path.join(root, d)
            entry = {
                "type": "folder",
                "path": full,
                "attributes": get_windows_file_attributes(full),
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

            entry = {
                "type": "file",
                "path": full,
                "size": size,
                "hash": hash_file(full),
                "attributes": get_windows_file_attributes(full),
            }
            report["contents"].append(entry)

    # Summary
    report["summary"] = {
        "total_files": file_count,
        "total_folders": folder_count,
        "total_size_bytes": total_size,
    }

    # Anomaly detection on root folder
    attrs = report["attributes"]
    if attrs.get("SYSTEM"):
        report["anomalies"].append("Folder is marked SYSTEM — unusual for normal desktop folders.")
    if attrs.get("HIDDEN"):
        report["anomalies"].append("Folder is HIDDEN — may affect icon rendering or visibility.")
    if attrs.get("ENCRYPTED"):
        report["anomalies"].append("Folder is ENCRYPTED — metadata and access may behave differently.")
    if attrs.get("NOT_CONTENT_INDEXED"):
        report["anomalies"].append("Folder is NOT_CONTENT_INDEXED — search/indexing may be disabled.")
    if attrs.get("TEMPORARY"):
        report["anomalies"].append("Folder is TEMPORARY — may be treated specially by the system.")

    return report

# ------------------------------------------------
# GUI — DRAG & DROP FOLDER ANALYZER
# ------------------------------------------------
class FolderAnalyzerGUI:
    def __init__(self):
        self.root = TkinterDnD.Tk()
        self.root.title("Folder Analyzer — Drag & Drop")
        self.root.geometry("1000x750")

        import tkinter as tk

        self.label = tk.Label(
            self.root,
            text="Drag & Drop a Folder Here\n(or use Select Folder button)",
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

        # Enable DND
        self.drop_area.drop_target_register(DND_FILES)
        self.drop_area.dnd_bind("<<Drop>>", self.on_drop)

        # Output area
        self.output = scrolledtext.ScrolledText(self.root, width=120, height=30, font=("Consolas", 10))
        self.output.pack(pady=10)

        # Buttons
        btn_frame = tk.Frame(self.root)
        btn_frame.pack(pady=5)

        self.select_btn = tk.Button(btn_frame, text="Select Folder Manually", command=self.select_folder)
        self.select_btn.pack(side="left", padx=5)

        self.copy_btn = tk.Button(btn_frame, text="Copy Output", command=self.copy_output)
        self.copy_btn.pack(side="left", padx=5)

        self.clear_btn = tk.Button(btn_frame, text="Clear Output", command=self.clear_output)
        self.clear_btn.pack(side="left", padx=5)

    # ------------- GUI HANDLERS -------------
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

    def on_drop(self, event):
        raw = event.data
        folder = self.normalize_dropped_path(raw)
        if os.path.isdir(folder):
            self.run_analysis(folder)
        else:
            self.log(f"[ERROR] Dropped item is not a folder: {folder}")

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.run_analysis(folder)

    def run_analysis(self, folder):
        self.clear_output()
        self.log(f"[INFO] Analyzing folder: {folder}")
        try:
            report = analyze_folder(folder)
            self.log(json.dumps(report, indent=4))
        except Exception:
            self.log("[ERROR] Exception during analysis:")
            self.log(traceback.format_exc())

    def run(self):
        self.root.mainloop()

# ------------------------------------------------
# MAIN ENTRY
# ------------------------------------------------
def main():
    gui = FolderAnalyzerGUI()
    gui.run()

if __name__ == "__main__":
    main()
