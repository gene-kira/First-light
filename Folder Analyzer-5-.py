#!/usr/bin/env python3
# ================================================================
# Folder Control Center — Tabbed Special Folder Detector & Repair
# Author: Copilot for killer666
# Mode: Ask Before Fixing (Option B)
#
# Features:
#   • Classic horizontal tabs (ttk.Notebook)
#   • Tab 1: Analyze & Fix (drag-and-drop, select, fix, protect)
#   • Tab 2: Mass Tools (scan/fix special folders, scan desktop.ini)
#   • Tab 3: Explorer Tools (refresh icons, best-effort icon cache)
#   • Tab 4: Protection (protected folders list, re-fix, remove)
#   • Tab 5: Logs (full output, copy, clear)
#   • Detects "special" Windows folders (READONLY + SYSTEM+HIDDEN desktop.ini)
#   • Asks before fixing folders
#   • Uses SHChangeNotify to refresh Explorer icons
#   • Lightweight protection tracking via JSON
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

import tkinter as tk
from tkinter import filedialog, scrolledtext, simpledialog, messagebox
from tkinter import ttk

from tkinterdnd2 import DND_FILES, TkinterDnD

# ------------------------------------------------
# WINDOWS FILE ATTRIBUTE HELPERS
# ------------------------------------------------
def get_windows_file_attributes_raw(path):
    try:
        return win32api.GetFileAttributes(path)
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
# HASHING (FOR REPORT)
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
    if not os.path.isdir(folder_path):
        return False, "Not a folder"

    folder_attrs = get_windows_file_attributes_raw(folder_path)
    if folder_attrs is None:
        return False, "Could not read folder attributes"

    folder_desc = describe_attributes(folder_attrs)
    has_readonly = folder_desc.get("READONLY", False)

    desktop_ini_path = os.path.join(folder_path, "desktop.ini")
    if not os.path.isfile(desktop_ini_path):
        return False, "No desktop.ini present"

    ini_attrs = get_windows_file_attributes_raw(desktop_ini_path)
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

    folder_attrs = get_windows_file_attributes_raw(folder_path)
    if folder_attrs is None:
        actions["errors"].append("Could not read folder attributes")
    else:
        if folder_attrs & win32con.FILE_ATTRIBUTE_READONLY:
            new_attrs = folder_attrs & ~win32con.FILE_ATTRIBUTE_READONLY
            if set_windows_file_attributes(folder_path, new_attrs):
                actions["changed_folder_attrs"] = True
            else:
                actions["errors"].append("Failed to clear READONLY on folder")

    desktop_ini_path = os.path.join(folder_path, "desktop.ini")
    if os.path.isfile(desktop_ini_path):
        ini_attrs = get_windows_file_attributes_raw(desktop_ini_path)
        if ini_attrs is None:
            actions["errors"].append("Could not read desktop.ini attributes")
        else:
            new_ini_attrs = ini_attrs & ~win32con.FILE_ATTRIBUTE_SYSTEM
            new_ini_attrs = new_ini_attrs & ~win32con.FILE_ATTRIBUTE_HIDDEN
            if set_windows_file_attributes(desktop_ini_path, new_ini_attrs):
                actions["changed_ini_attrs"] = True
            else:
                actions["errors"].append("Failed to clear SYSTEM/HIDDEN on desktop.ini")

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

def find_all_desktop_ini(root_path):
    results = []
    for current_root, dirs, files in os.walk(root_path):
        for f in files:
            if f.lower() == "desktop.ini":
                full = os.path.join(current_root, f)
                attrs = get_windows_file_attributes_raw(full)
                results.append({
                    "path": full,
                    "attributes": describe_attributes(attrs),
                })
    return results

# ------------------------------------------------
# EXPLORER REFRESH & ICON CACHE
# ------------------------------------------------
def refresh_explorer_icons():
    try:
        SHCNE_ASSOCCHANGED = 0x08000000
        SHCNF_IDLIST = 0x0000
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
        return True
    except Exception:
        return False

def rebuild_icon_cache_best_effort():
    result = {
        "notified_shell": False,
        "suggested_manual_restart": True,
        "errors": [],
    }
    try:
        SHCNE_ASSOCCHANGED = 0x08000000
        SHCNF_IDLIST = 0x0000
        ctypes.windll.shell32.SHChangeNotify(SHCNE_ASSOCCHANGED, SHCNF_IDLIST, None, None)
        result["notified_shell"] = True
    except Exception as e:
        result["errors"].append(f"SHChangeNotify failed: {e}")
    return result

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

    folder_attrs = get_windows_file_attributes_raw(folder_path)
    report["attributes"] = describe_attributes(folder_attrs)

    file_count = 0
    folder_count = 0
    total_size = 0

    for root, dirs, files in os.walk(folder_path):
        for d in dirs:
            folder_count += 1
            full = os.path.join(root, d)
            attrs = get_windows_file_attributes_raw(full)
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

            attrs = get_windows_file_attributes_raw(full)
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
# PROTECTION TRACKING (LIGHTWEIGHT)
# ------------------------------------------------
PROTECTION_DB_PATH = os.path.join(os.path.dirname(__file__), "folder_protection.json")

def load_protection_db():
    if not os.path.isfile(PROTECTION_DB_PATH):
        return {"protected_folders": []}
    try:
        with open(PROTECTION_DB_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {"protected_folders": []}

def save_protection_db(db):
    try:
        with open(PROTECTION_DB_PATH, "w", encoding="utf-8") as f:
            json.dump(db, f, indent=4)
    except Exception:
        pass

def add_protected_folder(path):
    db = load_protection_db()
    if path not in db.get("protected_folders", []):
        db["protected_folders"].append(path)
        save_protection_db(db)

def remove_protected_folder(path):
    db = load_protection_db()
    if path in db.get("protected_folders", []):
        db["protected_folders"].remove(path)
        save_protection_db(db)

def get_protected_folders():
    db = load_protection_db()
    return db.get("protected_folders", [])

# ------------------------------------------------
# GUI — TABBED CONTROL CENTER
# ------------------------------------------------
class FolderControlCenterGUI:
    def __init__(self):
        self.root = TkinterDnD.Tk()
        self.root.title("Folder Control Center — Tabbed Special Folder Detector & Repair")
        self.root.geometry("1100x800")

        self.last_analyzed_folder = None

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        # Tabs
        self.tab_analyze = ttk.Frame(self.notebook)
        self.tab_mass = ttk.Frame(self.notebook)
        self.tab_explorer = ttk.Frame(self.notebook)
        self.tab_protection = ttk.Frame(self.notebook)
        self.tab_logs = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_analyze, text="Analyze & Fix")
        self.notebook.add(self.tab_mass, text="Mass Tools")
        self.notebook.add(self.tab_explorer, text="Explorer Tools")
        self.notebook.add(self.tab_protection, text="Protection")
        self.notebook.add(self.tab_logs, text="Logs")

        # Logs tab (global output)
        self.logs_text = scrolledtext.ScrolledText(self.tab_logs, width=130, height=35, font=("Consolas", 10))
        self.logs_text.pack(pady=10, padx=10)

        logs_btn_frame = tk.Frame(self.tab_logs)
        logs_btn_frame.pack(pady=5)

        self.copy_btn = tk.Button(logs_btn_frame, text="Copy Output", command=self.copy_output)
        self.copy_btn.pack(side="left", padx=5)

        self.clear_btn = tk.Button(logs_btn_frame, text="Clear Output", command=self.clear_output)
        self.clear_btn.pack(side="left", padx=5)

        # Analyze & Fix tab
        self.build_analyze_tab()

        # Mass Tools tab
        self.build_mass_tab()

        # Explorer Tools tab
        self.build_explorer_tab()

        # Protection tab
        self.build_protection_tab()

        self.refresh_protection_list()

    # ------------------------------------------------
    # TAB BUILDERS
    # ------------------------------------------------
    def build_analyze_tab(self):
        label = tk.Label(
            self.tab_analyze,
            text="Drag & Drop a Folder Here (Analyze & Ask Before Fixing)\nOr use Select Folder",
            font=("Arial", 12)
        )
        label.pack(pady=10)

        self.drop_area = tk.Label(
            self.tab_analyze,
            text="DROP FOLDER HERE",
            bg="#222",
            fg="white",
            font=("Consolas", 16),
            width=40,
            height=4,
            relief="ridge",
            bd=3
        )
        self.drop_area.pack(pady=10)

        self.drop_area.drop_target_register(DND_FILES)
        self.drop_area.dnd_bind("<<Drop>>", self.on_drop)

        btn_frame = tk.Frame(self.tab_analyze)
        btn_frame.pack(pady=5)

        self.select_btn = tk.Button(btn_frame, text="Select Folder (Analyze)", command=self.select_folder)
        self.select_btn.pack(side="left", padx=5)

        self.fix_btn = tk.Button(btn_frame, text="Fix Last Analyzed Folder", command=self.fix_last_folder)
        self.fix_btn.pack(side="left", padx=5)

        self.protect_btn = tk.Button(btn_frame, text="Protect Last Analyzed Folder", command=self.protect_last_folder)
        self.protect_btn.pack(side="left", padx=5)

        self.analyze_status = tk.Label(self.tab_analyze, text="No folder analyzed yet.", font=("Consolas", 10), fg="#555")
        self.analyze_status.pack(pady=10)

    def build_mass_tab(self):
        frame = tk.Frame(self.tab_mass)
        frame.pack(pady=20)

        self.scan_special_btn = tk.Button(frame, text="Scan Root for Special Folders", command=self.scan_root_for_specials)
        self.scan_special_btn.pack(pady=5, fill="x")

        self.fix_all_special_btn = tk.Button(frame, text="Fix ALL Special Folders Under Root", command=self.fix_all_specials_under_root)
        self.fix_all_special_btn.pack(pady=5, fill="x")

        self.scan_ini_btn = tk.Button(frame, text="Scan Root for desktop.ini Files", command=self.scan_root_for_ini)
        self.scan_ini_btn.pack(pady=5, fill="x")

    def build_explorer_tab(self):
        frame = tk.Frame(self.tab_explorer)
        frame.pack(pady=20)

        self.refresh_icons_btn = tk.Button(frame, text="Refresh Explorer Icons", command=self.refresh_icons)
        self.refresh_icons_btn.pack(pady=5, fill="x")

        self.rebuild_cache_btn = tk.Button(frame, text="Rebuild Icon Cache (Best Effort)", command=self.rebuild_icon_cache)
        self.rebuild_cache_btn.pack(pady=5, fill="x")

    def build_protection_tab(self):
        top_frame = tk.Frame(self.tab_protection)
        top_frame.pack(pady=10, fill="x")

        label = tk.Label(top_frame, text="Protected Folders", font=("Arial", 12))
        label.pack(side="left", padx=10)

        list_frame = tk.Frame(self.tab_protection)
        list_frame.pack(pady=10, fill="both", expand=True)

        self.protection_listbox = tk.Listbox(list_frame, font=("Consolas", 10))
        self.protection_listbox.pack(side="left", fill="both", expand=True, padx=10)

        scrollbar = tk.Scrollbar(list_frame, orient="vertical", command=self.protection_listbox.yview)
        scrollbar.pack(side="right", fill="y")
        self.protection_listbox.config(yscrollcommand=scrollbar.set)

        btn_frame = tk.Frame(self.tab_protection)
        btn_frame.pack(pady=10)

        self.refix_protected_btn = tk.Button(btn_frame, text="Re-Fix All Protected Folders", command=self.refix_protected_folders)
        self.refix_protected_btn.pack(side="left", padx=5)

        self.remove_protected_btn = tk.Button(btn_frame, text="Remove Selected From Protection", command=self.remove_selected_protection)
        self.remove_protected_btn.pack(side="left", padx=5)

    # ------------------------------------------------
    # LOGGING
    # ------------------------------------------------
    def clear_output(self):
        self.logs_text.delete("1.0", "end")

    def copy_output(self):
        text = self.logs_text.get("1.0", "end")
        self.root.clipboard_clear()
        self.root.clipboard_append(text)

    def log(self, text):
        self.logs_text.insert("end", text + "\n")
        self.logs_text.see("end")

    # ------------------------------------------------
    # ANALYZE TAB ACTIONS
    # ------------------------------------------------
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
            self.analyze_folder_action(folder, ask_fix=True)
        else:
            self.log(f"[ERROR] Dropped item is not a folder: {folder}")
            self.analyze_status.config(text="Dropped item is not a folder.")

    def select_folder(self):
        folder = filedialog.askdirectory()
        if folder:
            self.analyze_folder_action(folder, ask_fix=True)

    def analyze_folder_action(self, folder, ask_fix=False):
        self.last_analyzed_folder = folder
        self.analyze_status.config(text=f"Last analyzed: {folder}")
        self.log(f"[INFO] Analyzing folder: {folder}")
        try:
            report = analyze_folder(folder)
            self.log("[REPORT]")
            self.log(json.dumps(report, indent=4))

            if report["special_status"]["is_special"]:
                self.log(f"[INFO] Folder is special: {report['special_status']['reason']}")
                if ask_fix:
                    answer = messagebox.askyesno(
                        "Fix Folder?",
                        f"This folder appears special:\n\n{report['special_status']['reason']}\n\nDo you want to fix it now?"
                    )
                    if answer:
                        self.apply_fix(folder)
                    else:
                        self.log("[INFO] User chose not to fix this folder.")
            else:
                self.log(f"[INFO] Folder is NOT special: {report['special_status']['reason']}")
        except Exception:
            self.log("[ERROR] Exception during analyze_folder_action:")
            self.log(traceback.format_exc())

    def apply_fix(self, folder):
        self.log("[INFO] Applying fix: clear READONLY, clear SYSTEM/HIDDEN on desktop.ini, backup desktop.ini.bak")
        actions = fix_special_folder(folder, delete_ini=True, backup_ini=True)
        self.log("[FIX ACTIONS]")
        self.log(json.dumps(actions, indent=4))

        self.log("[INFO] Requesting Explorer icon refresh...")
        if refresh_explorer_icons():
            self.log("[INFO] Explorer icons refresh requested successfully.")
        else:
            self.log("[WARN] Explorer icon refresh request failed.")

    def fix_last_folder(self):
        if not self.last_analyzed_folder:
            messagebox.showinfo("No Folder", "No folder has been analyzed yet.")
            return
        answer = messagebox.askyesno(
            "Fix Last Folder?",
            f"Do you want to fix the last analyzed folder?\n\n{self.last_analyzed_folder}"
        )
        if answer:
            self.apply_fix(self.last_analyzed_folder)

    def protect_last_folder(self):
        if not self.last_analyzed_folder:
            messagebox.showinfo("No Folder", "No folder has been analyzed yet.")
            return
        answer = messagebox.askyesno(
            "Protect Folder",
            f"Mark this folder as protected?\n\n{self.last_analyzed_folder}\n\nThis will track it and make it easy to re-fix."
        )
        if answer:
            add_protected_folder(self.last_analyzed_folder)
            self.log(f"[INFO] Folder marked as protected: {self.last_analyzed_folder}")
            self.refresh_protection_list()

    # ------------------------------------------------
    # MASS TOOLS TAB ACTIONS
    # ------------------------------------------------
    def scan_root_for_specials(self):
        root_path = simpledialog.askstring("Scan Root", "Enter root folder to scan for special folders (e.g., C:/Users/tbarr/Desktop):")
        if not root_path:
            return
        if not os.path.isdir(root_path):
            self.log(f"[ERROR] Not a folder: {root_path}")
            return

        self.log(f"[INFO] Scanning for special folders under: {root_path}")
        try:
            specials = scan_for_special_folders(root_path)
            self.log("[SPECIAL FOLDERS FOUND]")
            self.log(json.dumps(specials, indent=4))
        except Exception:
            self.log("[ERROR] Exception during scan_root_for_specials:")
            self.log(traceback.format_exc())

    def fix_all_specials_under_root(self):
        root_path = simpledialog.askstring("Fix ALL Special Folders", "Enter root folder to scan and fix (e.g., C:/Users/tbarr/Desktop):")
        if not root_path:
            return
        if not os.path.isdir(root_path):
            self.log(f"[ERROR] Not a folder: {root_path}")
            return

        answer = messagebox.askyesno(
            "Confirm Mass Fix",
            f"This will scan and fix ALL special folders under:\n\n{root_path}\n\nProceed?"
        )
        if not answer:
            self.log("[INFO] User cancelled mass fix.")
            return

        self.log(f"[INFO] Scanning and fixing special folders under: {root_path}")
        try:
            specials = scan_for_special_folders(root_path)
            self.log("[SPECIAL FOLDERS BEFORE FIX]")
            self.log(json.dumps(specials, indent=4))

            fixed = []
            for item in specials:
                folder = item["folder"]
                self.log(f"[INFO] Fixing: {folder}")
                actions = fix_special_folder(folder, delete_ini=True, backup_ini=True)
                fixed.append({
                    "folder": folder,
                    "actions": actions,
                })

            self.log("[FIXED SPECIAL FOLDERS]")
            self.log(json.dumps(fixed, indent=4))

            self.log("[INFO] Requesting Explorer icon refresh after mass fix...")
            if refresh_explorer_icons():
                self.log("[INFO] Explorer icons refresh requested successfully.")
            else:
                self.log("[WARN] Explorer icon refresh request failed.")
        except Exception:
            self.log("[ERROR] Exception during fix_all_specials_under_root:")
            self.log(traceback.format_exc())

    def scan_root_for_ini(self):
        root_path = simpledialog.askstring("Scan Root for desktop.ini", "Enter root folder to scan for desktop.ini (e.g., C:/):")
        if not root_path:
            return
        if not os.path.isdir(root_path):
            self.log(f"[ERROR] Not a folder: {root_path}")
            return

        self.log(f"[INFO] Scanning for desktop.ini under: {root_path}")
        try:
            results = find_all_desktop_ini(root_path)
            self.log("[DESKTOP.INI FILES FOUND]")
            self.log(json.dumps(results, indent=4))
        except Exception:
            self.log("[ERROR] Exception during scan_root_for_ini:")
            self.log(traceback.format_exc())

    # ------------------------------------------------
    # EXPLORER TOOLS TAB ACTIONS
    # ------------------------------------------------
    def refresh_icons(self):
        self.log("[INFO] Requesting Explorer icon refresh...")
        if refresh_explorer_icons():
            self.log("[INFO] Explorer icons refresh requested successfully.")
        else:
            self.log("[WARN] Explorer icon refresh request failed.")

    def rebuild_icon_cache(self):
        self.log("[INFO] Attempting best-effort icon cache rebuild...")
        result = rebuild_icon_cache_best_effort()
        self.log("[ICON CACHE REBUILD RESULT]")
        self.log(json.dumps(result, indent=4))
        self.log("[INFO] You may still need to restart Explorer or log off/log on for full effect.")

    # ------------------------------------------------
    # PROTECTION TAB ACTIONS
    # ------------------------------------------------
    def refresh_protection_list(self):
        self.protection_listbox.delete(0, "end")
        for folder in get_protected_folders():
            self.protection_listbox.insert("end", folder)

    def refix_protected_folders(self):
        protected = get_protected_folders()
        if not protected:
            messagebox.showinfo("No Protected Folders", "There are no protected folders.")
            return
        answer = messagebox.askyesno(
            "Re-Fix Protected Folders",
            "This will re-fix all protected folders.\nProceed?"
        )
        if not answer:
            return

        self.log("[INFO] Re-fixing all protected folders...")
        for folder in protected:
            self.log(f"[INFO] Re-fixing: {folder}")
            actions = fix_special_folder(folder, delete_ini=True, backup_ini=True)
            self.log(json.dumps(actions, indent=4))
        self.log("[INFO] Requesting Explorer icon refresh after re-fix...")
        if refresh_explorer_icons():
            self.log("[INFO] Explorer icons refresh requested successfully.")
        else:
            self.log("[WARN] Explorer icon refresh request failed.")

    def remove_selected_protection(self):
        selection = self.protection_listbox.curselection()
        if not selection:
            messagebox.showinfo("No Selection", "Select a folder to remove from protection.")
            return
        index = selection[0]
        folder = self.protection_listbox.get(index)
        answer = messagebox.askyesno(
            "Remove Protection",
            f"Remove this folder from protection?\n\n{folder}"
        )
        if not answer:
            return
        remove_protected_folder(folder)
        self.log(f"[INFO] Removed from protection: {folder}")
        self.refresh_protection_list()

    # ------------------------------------------------
    # MAIN LOOP
    # ------------------------------------------------
    def run(self):
        self.root.mainloop()

# ------------------------------------------------
# MAIN ENTRY
# ------------------------------------------------
def main():
    gui = FolderControlCenterGUI()
    gui.run()

if __name__ == "__main__":
    main()
