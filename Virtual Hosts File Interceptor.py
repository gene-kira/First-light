#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Full Hosts Manager
- Real Hosts (authority, ad-blockers)
- System Virtual (system-generated entries)
- Two GUI tabs: Real Hosts | System Virtual
- File watchers for both files
"""

import os
import sys
import threading
import time
import tkinter as tk
from tkinter import ttk, messagebox

# ---------------- CONFIG ----------------

HOSTS_REAL_PATH = r"C:\Windows\System32\drivers\etc\hosts"
HOSTS_VIRTUAL_PATH = r"C:\ProgramData\HostsManager\system_virtual_hosts.txt"

WATCH_INTERVAL_SECONDS = 1.0

LOG_ENABLED = True


# ---------------- LOGGING ----------------

def log(msg):
    if LOG_ENABLED:
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{ts}] {msg}")


# ---------------- DATA STRUCTURES ----------------

class HostsEntry:
    def __init__(self, ip, hosts):
        self.ip = ip
        self.hosts = hosts  # list of hostnames

    def to_line(self):
        return f"{self.ip} " + " ".join(self.hosts)

    @staticmethod
    def from_line(line):
        line = line.strip()
        if not line or line.startswith("#"):
            return None
        parts = line.split()
        if len(parts) < 2:
            return None
        ip = parts[0]
        hosts = parts[1:]
        return HostsEntry(ip, hosts)


class HostsFileModel:
    def __init__(self, path):
        self.path = path
        self.entries = []
        self.last_mtime = None

    def load(self):
        self.entries = []
        if not os.path.exists(self.path):
            log(f"File not found, creating empty: {self.path}")
            try:
                os.makedirs(os.path.dirname(self.path), exist_ok=True)
                with open(self.path, "a", encoding="utf-8", errors="ignore"):
                    pass
            except Exception as e:
                log(f"Error creating file {self.path}: {e}")
                return

        try:
            with open(self.path, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    entry = HostsEntry.from_line(line)
                    if entry:
                        self.entries.append(entry)
            self.last_mtime = os.path.getmtime(self.path)
            log(f"Loaded {len(self.entries)} entries from {self.path}")
        except Exception as e:
            log(f"Error reading {self.path}: {e}")

    def save(self):
        try:
            lines = [e.to_line() for e in self.entries]
            data = "\n".join(lines) + ("\n" if lines else "")
            with open(self.path, "w", encoding="utf-8", errors="ignore") as f:
                f.write(data)
            self.last_mtime = os.path.getmtime(self.path)
            log(f"Saved {len(self.entries)} entries to {self.path}")
        except Exception as e:
            log(f"Error writing {self.path}: {e}")

    def has_changed_on_disk(self):
        if not os.path.exists(self.path):
            return False
        try:
            mtime = os.path.getmtime(self.path)
            if self.last_mtime is None:
                self.last_mtime = mtime
                return False
            return mtime != self.last_mtime
        except Exception:
            return False


# ---------------- MODELS ----------------

real_hosts_model = HostsFileModel(HOSTS_REAL_PATH)
system_virtual_model = HostsFileModel(HOSTS_VIRTUAL_PATH)


# ---------------- GUI ----------------

class HostsManagerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Hosts Manager - Real Hosts | System Virtual")

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        # Real Hosts tab
        self.real_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.real_frame, text="Real Hosts (Ad-blockers)")

        # System Virtual tab
        self.system_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.system_frame, text="System Virtual (System Entries)")

        # Real Hosts UI
        self.real_tree = ttk.Treeview(
            self.real_frame,
            columns=("ip", "hosts"),
            show="headings",
            selectmode="browse"
        )
        self.real_tree.heading("ip", text="IP")
        self.real_tree.heading("hosts", text="Hostnames")
        self.real_tree.column("ip", width=120, anchor=tk.W)
        self.real_tree.column("hosts", width=400, anchor=tk.W)
        self.real_tree.pack(fill=tk.BOTH, expand=True, side=tk.TOP)

        self.real_controls = ttk.Frame(self.real_frame)
        self.real_controls.pack(fill=tk.X, side=tk.BOTTOM)

        ttk.Label(self.real_controls, text="IP:").pack(side=tk.LEFT, padx=2)
        self.real_ip_entry = ttk.Entry(self.real_controls, width=15)
        self.real_ip_entry.pack(side=tk.LEFT, padx=2)

        ttk.Label(self.real_controls, text="Hosts (space-separated):").pack(side=tk.LEFT, padx=2)
        self.real_hosts_entry = ttk.Entry(self.real_controls, width=40)
        self.real_hosts_entry.pack(side=tk.LEFT, padx=2)

        self.real_add_btn = ttk.Button(self.real_controls, text="Add", command=self.on_real_add)
        self.real_add_btn.pack(side=tk.LEFT, padx=2)

        self.real_remove_btn = ttk.Button(self.real_controls, text="Remove Selected", command=self.on_real_remove)
        self.real_remove_btn.pack(side=tk.LEFT, padx=2)

        # System Virtual UI
        self.system_tree = ttk.Treeview(
            self.system_frame,
            columns=("ip", "hosts"),
            show="headings",
            selectmode="browse"
        )
        self.system_tree.heading("ip", text="IP")
        self.system_tree.heading("hosts", text="Hostnames")
        self.system_tree.column("ip", width=120, anchor=tk.W)
        self.system_tree.column("hosts", width=400, anchor=tk.W)
        self.system_tree.pack(fill=tk.BOTH, expand=True, side=tk.TOP)

        self.system_controls = ttk.Frame(self.system_frame)
        self.system_controls.pack(fill=tk.X, side=tk.BOTTOM)

        ttk.Label(self.system_controls, text="IP:").pack(side=tk.LEFT, padx=2)
        self.system_ip_entry = ttk.Entry(self.system_controls, width=15)
        self.system_ip_entry.pack(side=tk.LEFT, padx=2)

        ttk.Label(self.system_controls, text="Hosts (space-separated):").pack(side=tk.LEFT, padx=2)
        self.system_hosts_entry = ttk.Entry(self.system_controls, width=40)
        self.system_hosts_entry.pack(side=tk.LEFT, padx=2)

        self.system_add_btn = ttk.Button(self.system_controls, text="Add", command=self.on_system_add)
        self.system_add_btn.pack(side=tk.LEFT, padx=2)

        self.system_remove_btn = ttk.Button(self.system_controls, text="Remove Selected", command=self.on_system_remove)
        self.system_remove_btn.pack(side=tk.LEFT, padx=2)

        # Initial population
        self.refresh_real_tab()
        self.refresh_system_tab()

    # ---------- Real Hosts Handlers ----------

    def refresh_real_tab(self):
        self.real_tree.delete(*self.real_tree.get_children())
        for idx, entry in enumerate(real_hosts_model.entries):
            self.real_tree.insert("", tk.END, iid=str(idx), values=(entry.ip, " ".join(entry.hosts)))

    def on_real_add(self):
        ip = self.real_ip_entry.get().strip()
        hosts_str = self.real_hosts_entry.get().strip()
        if not ip or not hosts_str:
            messagebox.showwarning("Input Error", "IP and Hosts are required.")
            return
        hosts = hosts_str.split()
        entry = HostsEntry(ip, hosts)
        real_hosts_model.entries.append(entry)
        real_hosts_model.save()
        self.refresh_real_tab()
        self.real_ip_entry.delete(0, tk.END)
        self.real_hosts_entry.delete(0, tk.END)

    def on_real_remove(self):
        sel = self.real_tree.selection()
        if not sel:
            messagebox.showwarning("Selection Error", "No entry selected.")
            return
        idx = int(sel[0])
        if 0 <= idx < len(real_hosts_model.entries):
            del real_hosts_model.entries[idx]
            real_hosts_model.save()
            self.refresh_real_tab()

    # ---------- System Virtual Handlers ----------

    def refresh_system_tab(self):
        self.system_tree.delete(*self.system_tree.get_children())
        for idx, entry in enumerate(system_virtual_model.entries):
            self.system_tree.insert("", tk.END, iid=str(idx), values=(entry.ip, " ".join(entry.hosts)))

    def on_system_add(self):
        ip = self.system_ip_entry.get().strip()
        hosts_str = self.system_hosts_entry.get().strip()
        if not ip or not hosts_str:
            messagebox.showwarning("Input Error", "IP and Hosts are required.")
            return
        hosts = hosts_str.split()
        entry = HostsEntry(ip, hosts)
        system_virtual_model.entries.append(entry)
        system_virtual_model.save()
        self.refresh_system_tab()
        self.system_ip_entry.delete(0, tk.END)
        self.system_hosts_entry.delete(0, tk.END)

    def on_system_remove(self):
        sel = self.system_tree.selection()
        if not sel:
            messagebox.showwarning("Selection Error", "No entry selected.")
            return
        idx = int(sel[0])
        if 0 <= idx < len(system_virtual_model.entries):
            del system_virtual_model.entries[idx]
            system_virtual_model.save()
            self.refresh_system_tab()


# ---------------- WATCHERS ----------------

class HostsWatcher(threading.Thread):
    def __init__(self, gui: HostsManagerGUI):
        super().__init__(daemon=True)
        self.gui = gui
        self.running = True

    def run(self):
        while self.running:
            time.sleep(WATCH_INTERVAL_SECONDS)
            # Real hosts file watcher
            if real_hosts_model.has_changed_on_disk():
                log("Real hosts file changed on disk; reloading (authority).")
                real_hosts_model.load()
                self._safe_gui_call(self.gui.refresh_real_tab)

            # System virtual file watcher
            if system_virtual_model.has_changed_on_disk():
                log("System virtual file changed on disk; reloading.")
                system_virtual_model.load()
                self._safe_gui_call(self.gui.refresh_system_tab)

    def _safe_gui_call(self, func):
        try:
            self.gui.root.after(0, func)
        except Exception as e:
            log(f"Error scheduling GUI update: {e}")

    def stop(self):
        self.running = False


# ---------------- MAIN ----------------

def main():
    log("Starting Hosts Manager...")

    # Load both models
    real_hosts_model.load()
    system_virtual_model.load()

    root = tk.Tk()
    gui = HostsManagerGUI(root)

    watcher = HostsWatcher(gui)
    watcher.start()

    def on_close():
        watcher.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

    log("Hosts Manager exited.")


if __name__ == "__main__":
    main()
