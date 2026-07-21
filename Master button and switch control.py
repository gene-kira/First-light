#!/usr/bin/env python
# Codex Win11 Control Console — single-file, auto-adjusting, crash-safe

import sys
import os
import platform
import subprocess
import threading
import time
import random
import math

# ---------------------------
# Basic environment checks
# ---------------------------

if platform.system().lower() != "windows":
    print("This build is Windows-only. Detected:", platform.system())
    sys.exit(1)

REQUIRED_MODULES = ["tkinter", "psutil", "winreg", "hashlib", "datetime"]

def ensure_dependencies():
    import importlib
    missing = []
    for m in REQUIRED_MODULES:
        try:
            importlib.import_module(m)
        except ImportError:
            missing.append(m)
    if missing:
        print("Missing Python modules:", ", ".join(missing))
        print("Install them with:")
        print("    pip install psutil")
        sys.exit(1)

ensure_dependencies()

import tkinter as tk
from tkinter import ttk, messagebox
import psutil
import winreg
import hashlib
from datetime import datetime

SNAPSHOT_ROOT = "Snapshots"
DEFAULT_REG_PATH = r"HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy"

# ---------------------------
# Safe helpers
# ---------------------------

def safe_call(cmd, text=True):
    try:
        return subprocess.check_output(cmd, text=text)
    except Exception:
        return ""

def hash_state(data):
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()

def ensure_snapshot_root():
    os.makedirs(SNAPSHOT_ROOT, exist_ok=True)

# ---------------------------
# Firewall / registry state
# ---------------------------

def get_firewall_state():
    return safe_call(["netsh", "advfirewall", "show", "allprofiles"])

def get_profiles_state():
    return get_firewall_state()

def read_registry_key(path):
    try:
        hive, subkey = path.split("\\", 1)
        hive_map = {
            "HKLM": winreg.HKEY_LOCAL_MACHINE,
            "HKCU": winreg.HKEY_CURRENT_USER
        }
        key = winreg.OpenKey(hive_map[hive], subkey)
        values = []
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
                values.append((name, value))
                i += 1
            except OSError:
                break
        return values
    except Exception:
        return []

def get_settings_state():
    vals = read_registry_key(DEFAULT_REG_PATH)
    return "\n".join(f"{n}={v}" for n, v in vals)

# ---------------------------
# Snapshots
# ---------------------------

def list_snapshots():
    ensure_snapshot_root()
    return sorted(
        [os.path.join(SNAPSHOT_ROOT, d) for d in os.listdir(SNAPSHOT_ROOT)
         if os.path.isdir(os.path.join(SNAPSHOT_ROOT, d))],
        reverse=True
    )

def create_snapshot():
    ensure_snapshot_root()
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    folder = os.path.join(SNAPSHOT_ROOT, timestamp)
    os.makedirs(folder, exist_ok=True)

    # firewall rules
    try:
        subprocess.call(["netsh", "advfirewall", "export", os.path.join(folder, "firewall_rules.wfw")])
    except Exception:
        pass

    # firewall profiles
    try:
        with open(os.path.join(folder, "firewall_profiles.txt"), "w", encoding="utf-8") as f:
            f.write(get_firewall_state())
    except Exception:
        pass

    # registry policy
    try:
        subprocess.call([
            "reg", "export",
            DEFAULT_REG_PATH,
            os.path.join(folder, "firewall_policy.reg"), "/y"
        ])
    except Exception:
        pass

    return folder

def restore_snapshot(folder):
    rules = os.path.join(folder, "firewall_rules.wfw")
    policy = os.path.join(folder, "firewall_policy.reg")
    if os.path.isfile(rules):
        try:
            subprocess.call(["netsh", "advfirewall", "import", rules])
        except Exception:
            pass
    if os.path.isfile(policy):
        try:
            subprocess.call(["reg", "import", policy])
        except Exception:
            pass

# ---------------------------
# Animated overlays / swarm
# ---------------------------

class OverlayCanvas:
    def __init__(self, canvas):
        self.canvas = canvas
        self.width = int(canvas["width"])
        self.height = int(canvas["height"])
        self.objects = []
        self._init_objects()
        self.running = True
        self.animate()

    def _init_objects(self):
        for _ in range(20):
            x = random.randint(0, self.width)
            y = random.randint(0, self.height)
            r = random.randint(2, 6)
            dx = random.uniform(-1.5, 1.5)
            dy = random.uniform(-1.5, 1.5)
            oid = self.canvas.create_oval(x-r, y-r, x+r, y+r, outline="#00ffcc")
            self.objects.append({"id": oid, "x": x, "y": y, "dx": dx, "dy": dy, "r": r})

    def animate(self):
        if not self.running:
            return
        for obj in self.objects:
            obj["x"] += obj["dx"]
            obj["y"] += obj["dy"]
            if obj["x"] < 0 or obj["x"] > self.width:
                obj["dx"] *= -1
            if obj["y"] < 0 or obj["y"] > self.height:
                obj["dy"] *= -1
            r = obj["r"]
            self.canvas.coords(obj["id"], obj["x"]-r, obj["y"]-r, obj["x"]+r, obj["y"]+r)
        self.canvas.after(50, self.animate)

class SwarmCanvas:
    def __init__(self, canvas, node_count=12):
        self.canvas = canvas
        self.width = int(canvas["width"])
        self.height = int(canvas["height"])
        self.nodes = []
        self.lines = []
        self.node_count = node_count
        self._init_nodes()
        self.running = True
        self.animate()

    def _init_nodes(self):
        center_x = self.width // 2
        center_y = self.height // 2
        radius = min(self.width, self.height) // 3
        for i in range(self.node_count):
            angle = 2 * math.pi * i / self.node_count
            x = center_x + radius * math.cos(angle)
            y = center_y + radius * math.sin(angle)
            oid = self.canvas.create_oval(x-6, y-6, x+6, y+6, fill="#ff0066")
            self.nodes.append({"id": oid, "x": x, "y": y, "angle": angle})
        for i in range(self.node_count):
            j = (i + 1) % self.node_count
            l = self.canvas.create_line(
                self.nodes[i]["x"], self.nodes[i]["y"],
                self.nodes[j]["x"], self.nodes[j]["y"],
                fill="#4444ff"
            )
            self.lines.append(l)

    def animate(self):
        if not self.running:
            return
        center_x = self.width // 2
        center_y = self.height // 2
        radius = min(self.width, self.height) // 3
        for idx, node in enumerate(self.nodes):
            node["angle"] += 0.01
            x = center_x + radius * math.cos(node["angle"])
            y = center_y + radius * math.sin(node["angle"])
            node["x"], node["y"] = x, y
            self.canvas.coords(node["id"], x-6, y-6, x+6, y+6)
        for i, line in enumerate(self.lines):
            j = (i + 1) % self.node_count
            self.canvas.coords(
                line,
                self.nodes[i]["x"], self.nodes[i]["y"],
                self.nodes[j]["x"], self.nodes[j]["y"]
            )
        self.canvas.after(60, self.animate)

# ---------------------------
# Settings editor (registry + firewall)
# ---------------------------

class SettingsEditorPanel:
    def __init__(self, parent, log_fn):
        self.parent = parent
        self.log = log_fn

        frame = ttk.LabelFrame(parent, text="System Settings Editor (Win11)")
        frame.pack(fill="both", expand=True, padx=5, pady=5)

        top = ttk.Frame(frame)
        top.pack(fill="x", pady=2)

        ttk.Label(top, text="Registry Path (HKLM\\... or HKCU\\...)").pack(side="left", padx=5)
        self.reg_path_var = tk.StringVar(value=DEFAULT_REG_PATH)
        self.reg_entry = ttk.Entry(top, textvariable=self.reg_path_var, width=70)
        self.reg_entry.pack(side="left", padx=5)
        ttk.Button(top, text="Load", command=self.load_registry).pack(side="left", padx=5)

        mid = ttk.Frame(frame)
        mid.pack(fill="both", expand=True, pady=2)

        self.reg_list = ttk.Treeview(mid, columns=("name", "value"), show="headings", height=8)
        self.reg_list.heading("name", text="Name")
        self.reg_list.heading("value", text="Value")
        self.reg_list.column("name", width=150)
        self.reg_list.column("value", width=300)
        self.reg_list.pack(side="left", fill="both", expand=True, padx=5, pady=5)

        reg_btns = ttk.Frame(mid)
        reg_btns.pack(side="left", fill="y", padx=5)

        ttk.Button(reg_btns, text="Add/Edit", command=self.edit_registry_value).pack(fill="x", pady=2)
        ttk.Button(reg_btns, text="Delete", command=self.delete_registry_value).pack(fill="x", pady=2)

        fw_frame = ttk.LabelFrame(frame, text="Firewall Rule Editor")
        fw_frame.pack(fill="x", pady=5)

        ttk.Label(fw_frame, text="Rule Name").grid(row=0, column=0, padx=5, pady=2, sticky="w")
        ttk.Label(fw_frame, text="Direction (in/out)").grid(row=0, column=1, padx=5, pady=2, sticky="w")
        ttk.Label(fw_frame, text="Action (allow/block)").grid(row=0, column=2, padx=5, pady=2, sticky="w")
        ttk.Label(fw_frame, text="Protocol").grid(row=0, column=3, padx=5, pady=2, sticky="w")
        ttk.Label(fw_frame, text="Local Port").grid(row=0, column=4, padx=5, pady=2, sticky="w")

        self.fw_name = tk.StringVar()
        self.fw_dir = tk.StringVar(value="in")
        self.fw_action = tk.StringVar(value="allow")
        self.fw_proto = tk.StringVar(value="TCP")
        self.fw_port = tk.StringVar(value="any")

        ttk.Entry(fw_frame, textvariable=self.fw_name, width=15).grid(row=1, column=0, padx=5, pady=2)
        ttk.Entry(fw_frame, textvariable=self.fw_dir, width=8).grid(row=1, column=1, padx=5, pady=2)
        ttk.Entry(fw_frame, textvariable=self.fw_action, width=8).grid(row=1, column=2, padx=5, pady=2)
        ttk.Entry(fw_frame, textvariable=self.fw_proto, width=8).grid(row=1, column=3, padx=5, pady=2)
        ttk.Entry(fw_frame, textvariable=self.fw_port, width=8).grid(row=1, column=4, padx=5, pady=2)

        ttk.Button(fw_frame, text="Add Rule", command=self.add_rule).grid(row=1, column=5, padx=5, pady=2)
        ttk.Button(fw_frame, text="Delete Rule", command=self.delete_rule).grid(row=1, column=6, padx=5, pady=2)

    def load_registry(self):
        path = self.reg_path_var.get().strip()
        self.reg_list.delete(*self.reg_list.get_children())
        values = read_registry_key(path)
        for name, value in values:
            self.reg_list.insert("", "end", values=(name, str(value)))
        self.log(f"Loaded registry key: {path}")

    def edit_registry_value(self):
        path = self.reg_path_var.get().strip()
        sel = self.reg_list.selection()
        if sel:
            name = self.reg_list.item(sel[0], "values")[0]
            value = self.reg_list.item(sel[0], "values")[1]
        else:
            name = ""
            value = ""

        edit_win = tk.Toplevel(self.parent)
        edit_win.title("Edit Registry Value")

        ttk.Label(edit_win, text="Name").pack(padx=5, pady=2)
        name_var = tk.StringVar(value=name)
        ttk.Entry(edit_win, textvariable=name_var, width=40).pack(padx=5, pady=2)

        ttk.Label(edit_win, text="Value").pack(padx=5, pady=2)
        value_var = tk.StringVar(value=value)
        ttk.Entry(edit_win, textvariable=value_var, width=40).pack(padx=5, pady=2)

        def apply():
            n = name_var.get().strip()
            v = value_var.get()
            if not n:
                messagebox.showerror("Error", "Name cannot be empty.")
                return
            try:
                hive, subkey = path.split("\\", 1)
                hive_map = {
                    "HKLM": winreg.HKEY_LOCAL_MACHINE,
                    "HKCU": winreg.HKEY_CURRENT_USER
                }
                key = winreg.CreateKey(hive_map[hive], subkey)
                winreg.SetValueEx(key, n, 0, winreg.REG_SZ, v)
                self.log(f"Registry value set: {path}\\{n} = {v}")
                self.load_registry()
                edit_win.destroy()
            except Exception:
                messagebox.showerror("Error", "Failed to write registry value.")

        ttk.Button(edit_win, text="Apply", command=apply).pack(padx=5, pady=5)

    def delete_registry_value(self):
        path = self.reg_path_var.get().strip()
        sel = self.reg_list.selection()
        if not sel:
            messagebox.showinfo("Delete", "No value selected.")
            return
        name = self.reg_list.item(sel[0], "values")[0]
        try:
            hive, subkey = path.split("\\", 1)
            hive_map = {
                "HKLM": winreg.HKEY_LOCAL_MACHINE,
                "HKCU": winreg.HKEY_CURRENT_USER
            }
            key = winreg.OpenKey(hive_map[hive], subkey, 0, winreg.KEY_SET_VALUE)
            winreg.DeleteValue(key, name)
            self.log(f"Registry value deleted: {path}\\{name}")
            self.load_registry()
        except Exception:
            messagebox.showerror("Error", "Failed to delete registry value.")

    def add_rule(self):
        name = self.fw_name.get().strip()
        direction = self.fw_dir.get().strip()
        action = self.fw_action.get().strip()
        proto = self.fw_proto.get().strip()
        port = self.fw_port.get().strip()
        if not name:
            messagebox.showerror("Error", "Rule name required.")
            return
        try:
            cmd = [
                "netsh", "advfirewall", "firewall", "add", "rule",
                f"name={name}",
                f"dir={direction}",
                f"action={action}",
                f"protocol={proto}",
                f"localport={port}",
            ]
            subprocess.call(cmd)
            self.log(f"Firewall rule added: {name} ({direction}, {action}, {proto}, {port})")
        except Exception:
            messagebox.showerror("Error", "Failed to add firewall rule.")

    def delete_rule(self):
        name = self.fw_name.get().strip()
        if not name:
            messagebox.showerror("Error", "Rule name required.")
            return
        try:
            subprocess.call(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={name}"])
            self.log(f"Firewall rule deleted: {name}")
        except Exception:
            messagebox.showerror("Error", "Failed to delete firewall rule.")

# ---------------------------
# GUI Watchdog (simplified, no crash)
# ---------------------------

class GUIWatchdog:
    def __init__(self, app, log_fn):
        self.app = app
        self.log = log_fn
        self.manifest = {}
        self.running = True
        self._build_manifest()
        self._start()

    def _build_manifest(self):
        self._register("override_button", self.app.override_button)
        self._register("status_fw", self.app.status_fw)
        self._register("status_profiles", self.app.status_profiles)
        self._register("status_reg", self.app.status_reg)
        self._register("alert_box", self.app.alert_box)
        self._register("snapshot_combo", self.app.snapshot_combo)
        self._register("threat_tree", self.app.threat_tree)
        self._register("editor_reg_list", self.app.editor_panel.reg_list)

    def _register(self, name, widget):
        self.manifest[name] = {"widget": widget}

    def _start(self):
        t = threading.Thread(target=self._loop, daemon=True)
        t.start()

    def _loop(self):
        while self.running:
            self._check_widgets()
            time.sleep(1)

    def _check_widgets(self):
        for name, info in self.manifest.items():
            w = info["widget"]
            try:
                exists = bool(w.winfo_exists())
                visible = bool(w.winfo_ismapped())
                if not exists or not visible:
                    self._handle_violation(name, w, exists, visible)
            except Exception:
                self._handle_violation(name, w, False, False)

    def _handle_violation(self, name, widget, exists, visible):
        self.log(f"⚠ GUI integrity issue: {name} (exists={exists}, visible={visible})")
        snap = create_snapshot()
        self.log(f"✔ Snapshot created due to GUI issue: {snap}")
        try:
            widget.pack()
        except Exception:
            pass
        try:
            widget.configure(foreground="red")
        except Exception:
            pass

# ---------------------------
# Main GUI
# ---------------------------

class CodexSettingsGuard:
    def __init__(self, root):
        self.root = root
        self.root.title("Codex Win11 Control Console")
        self.root.geometry("1400x850")

        self.auto_block_enabled = True

        self._build_ui()
        self._start_monitoring()
        self._start_threat_matrix_refresh()

        self.watchdog = GUIWatchdog(self, self.log_alert)

    def _build_ui(self):
        main = ttk.Frame(self.root)
        main.pack(fill="both", expand=True)

        top_frame = ttk.Frame(main)
        top_frame.pack(fill="x", pady=5)

        title = ttk.Label(
            top_frame,
            text="Codex Control Console — Windows 11 (Auto-adjust, crash-safe)",
            font=("Arial", 18)
        )
        title.pack(side="left", padx=10)

        self.override_button = ttk.Button(
            top_frame,
            text="Manual Override: ENABLED",
            command=self.toggle_override
        )
        self.override_button.pack(side="right", padx=10)

        status_frame = ttk.Frame(main)
        status_frame.pack(fill="x", pady=5)

        self.status_fw = ttk.Label(status_frame, text="Firewall: NORMAL", foreground="green")
        self.status_fw.pack(side="left", padx=10)

        self.status_profiles = ttk.Label(status_frame, text="Profiles: NORMAL", foreground="green")
        self.status_profiles.pack(side="left", padx=10)

        self.status_reg = ttk.Label(status_frame, text="Settings Store: NORMAL", foreground="green")
        self.status_reg.pack(side="left", padx=10)

        snapshot_frame = ttk.Frame(main)
        snapshot_frame.pack(fill="x", pady=5)

        self.snapshot_var = tk.StringVar()
        self.snapshot_combo = ttk.Combobox(snapshot_frame, textvariable=self.snapshot_var, width=60)
        self.snapshot_combo.pack(side="left", padx=10)
        self.refresh_snapshots()

        restore_btn = ttk.Button(snapshot_frame, text="Restore Selected Snapshot", command=self.restore_selected_snapshot)
        restore_btn.pack(side="left", padx=10)

        center_frame = ttk.Frame(main)
        center_frame.pack(fill="both", expand=True, pady=5)

        left_frame = ttk.Frame(center_frame)
        left_frame.pack(side="left", fill="both", expand=True)

        right_frame = ttk.Frame(center_frame)
        right_frame.pack(side="right", fill="both", expand=True)

        self.alert_box = tk.Text(left_frame, height=20, width=80, bg="#1e1e1e", fg="#00ff00")
        self.alert_box.pack(fill="both", expand=True, padx=5, pady=5)
        self.log_alert("Codex Win11 Control Console started.")

        self.editor_panel = SettingsEditorPanel(left_frame, self.log_alert)

        threat_label = ttk.Label(right_frame, text="Threat Matrix", font=("Arial", 12))
        threat_label.pack(pady=2)

        self.threat_tree = ttk.Treeview(right_frame, columns=("pid", "name", "cpu", "conns"), show="headings", height=15)
        self.threat_tree.heading("pid", text="PID")
        self.threat_tree.heading("name", text="Name")
        self.threat_tree.heading("cpu", text="CPU%")
        self.threat_tree.heading("conns", text="Connections")
        self.threat_tree.column("pid", width=60)
        self.threat_tree.column("name", width=160)
        self.threat_tree.column("cpu", width=60)
        self.threat_tree.column("conns", width=90)
        self.threat_tree.pack(fill="both", expand=True, padx=5, pady=5)

        overlay_label = ttk.Label(right_frame, text="Codex Overlay / Swarm", font=("Arial", 12))
        overlay_label.pack(pady=2)

        overlay_canvas = tk.Canvas(right_frame, width=350, height=120, bg="#000000", highlightthickness=0)
        overlay_canvas.pack(padx=5, pady=2)
        self.overlay = OverlayCanvas(overlay_canvas)

        swarm_canvas = tk.Canvas(right_frame, width=350, height=160, bg="#050515", highlightthickness=0)
        swarm_canvas.pack(padx=5, pady=2)
        self.swarm = SwarmCanvas(swarm_canvas, node_count=10)

    def toggle_override(self):
        self.auto_block_enabled = not self.auto_block_enabled
        if self.auto_block_enabled:
            self.override_button.config(text="Manual Override: ENABLED")
            self.log_alert("Auto-block re-enabled.")
        else:
            self.override_button.config(text="Manual Override: DISABLED")
            self.log_alert("Manual override active — changes allowed.")

    def log_alert(self, message):
        timestamp = time.strftime("[%H:%M:%S] ")
        self.alert_box.insert(tk.END, timestamp + message + "\n")
        self.alert_box.see(tk.END)

    def refresh_snapshots(self):
        snaps = list_snapshots()
        self.snapshot_combo["values"] = snaps
        if snaps:
            self.snapshot_combo.current(0)

    def restore_selected_snapshot(self):
        folder = self.snapshot_var.get()
        if not folder:
            messagebox.showinfo("Restore Snapshot", "No snapshot selected.")
            return
        self.log_alert(f"Restoring snapshot: {folder}")
        restore_snapshot(folder)
        self.log_alert("Snapshot restore completed.")

    def _start_monitoring(self):
        t = threading.Thread(target=self._monitor_loop, daemon=True)
        t.start()

    def _monitor_loop(self):
        last_fw_hash = ""
        last_profile_hash = ""
        last_settings_hash = ""
        while True:
            fw_state = get_firewall_state()
            profiles_state = get_profiles_state()
            settings_state = get_settings_state()

            fw_hash = hash_state(fw_state)
            prof_hash = hash_state(profiles_state)
            set_hash = hash_state(settings_state)

            if last_fw_hash and fw_hash != last_fw_hash:
                self._handle_change("Firewall")
            if last_profile_hash and prof_hash != last_profile_hash:
                self._handle_change("Profiles")
            if last_settings_hash and set_hash != last_settings_hash:
                self._handle_change("Settings Store")

            last_fw_hash = fw_hash
            last_profile_hash = prof_hash
            last_settings_hash = set_hash

            time.sleep(2)

    def _handle_change(self, setting_name):
        self.log_alert(f"⚠ Change detected: {setting_name}")
        self._set_status(setting_name, changed=True)
        # For now: log only, no auto-kill to avoid surprise crashes
        self.log_alert(f"[Info] Auto-block not killing processes yet for {setting_name}.")

    def _set_status(self, setting_name, changed):
        color = "red" if changed else "green"
        text_suffix = "CHANGED" if changed else "NORMAL"
        if setting_name == "Firewall":
            self.status_fw.config(text=f"Firewall: {text_suffix}", foreground=color)
        elif setting_name == "Profiles":
            self.status_profiles.config(text=f"Profiles: {text_suffix}", foreground=color)
        elif setting_name == "Settings Store":
            self.status_reg.config(text=f"Settings Store: {text_suffix}", foreground=color)

    def _start_threat_matrix_refresh(self):
        t = threading.Thread(target=self._threat_loop, daemon=True)
        t.start()

    def _threat_loop(self):
        while True:
            self._refresh_threat_matrix()
            time.sleep(5)

    def _refresh_threat_matrix(self):
        for row in self.threat_tree.get_children():
            self.threat_tree.delete(row)
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            try:
                conns = proc.connections()
                self.threat_tree.insert(
                    "",
                    "end",
                    values=(proc.info['pid'], proc.info['name'], proc.info['cpu_percent'], len(conns))
                )
            except Exception:
                continue

# ---------------------------
# Entry point
# ---------------------------

if __name__ == "__main__":
    root = tk.Tk()
    app = CodexSettingsGuard(root)
    root.mainloop()
