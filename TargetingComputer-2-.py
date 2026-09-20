#!/usr/bin/env python3
# ============================================================
# TargetingComputer_Advanced.py
# Fully unified file with:
# - Autoloader
# - GUI (Tkinter)
# - Threat list + AI control + manual override
# - Animated targeting reticle
# - Sound effects
# - Network scanner (safe local port scan)
# - Plugin API
# - Swarm-sync nodes (DominionDeck-style)
# - VRAM-accelerated threat scoring (simulated GPU path)
# - Full cyber-command dashboard
# ============================================================

import importlib
import subprocess
import sys

# ------------------------------------------------------------
# AUTOLOADER: Ensures all required libraries are installed
# ------------------------------------------------------------
REQUIRED_LIBS = [
    "tkinter",
    "numpy",   # used for scoring; will fallback if missing
]

def autoload():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            try:
                print(f"[AUTOLOADER] Installing missing library: {lib}")
                subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            except Exception as e:
                print(f"[AUTOLOADER] Failed to install {lib}: {e}")

autoload()

# ------------------------------------------------------------
# IMPORTS
# ------------------------------------------------------------
import tkinter as tk
from tkinter import ttk
import random
import time
import threading
import socket
import os
import math

try:
    import numpy as np
except ImportError:
    np = None

try:
    import winsound
except ImportError:
    winsound = None

# ------------------------------------------------------------
# Threat + Engine
# ------------------------------------------------------------
class Threat:
    def __init__(self, name, level, port=None):
        self.name = name
        self.level = level
        self.port = port
        self.status = "ACTIVE"
        self.score = 0.0

    def __repr__(self):
        return f"{self.name} (Level {self.level}, Score {self.score:.2f}) - {self.status}"

class ThreatEngine:
    def __init__(self, log_callback, scoring_callback):
        self.log = log_callback
        self.score_cb = scoring_callback
        self.threats = []
        self.ai_enabled = True

    def add_threat(self, name, level, port=None):
        t = Threat(name, level, port)
        self.threats.append(t)
        self.log(f"[ENGINE] Threat added: {t}")
        self.update_scores()

    def remove_threat(self, threat):
        threat.status = "NEUTRALIZED"
        self.log(f"[ENGINE] Threat neutralized: {threat}")

    def update_scores(self):
        if not self.threats:
            return
        self.score_cb(self.threats)

    def ai_cycle(self):
        while True:
            time.sleep(2)
            if self.ai_enabled and self.threats:
                active = [t for t in self.threats if t.status == "ACTIVE"]
                if active:
                    target = max(active, key=lambda x: x.score)
                    self.log(f"[AI] Auto-targeting: {target.name} (Score {target.score:.2f})")
                    self.remove_threat(target)

# ------------------------------------------------------------
# Swarm Sync Nodes (DominionDeck-style)
# ------------------------------------------------------------
class SwarmNode:
    def __init__(self, node_id):
        self.node_id = node_id
        self.status = "ONLINE"
        self.load = random.uniform(0.1, 0.9)

    def __repr__(self):
        return f"Node-{self.node_id} [{self.status}] Load={self.load:.2f}"

class SwarmManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.nodes = [SwarmNode(i) for i in range(1, 6)]

    def sync_cycle(self):
        while True:
            time.sleep(3)
            for n in self.nodes:
                n.load = max(0.0, min(1.0, n.load + random.uniform(-0.1, 0.1)))
            self.log("[SWARM] Sync tick: " + ", ".join(f"{n.node_id}:{n.load:.2f}" for n in self.nodes))

# ------------------------------------------------------------
# Plugin API
# ------------------------------------------------------------
class PluginManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.plugins = []
        self.plugin_dir = os.path.join(os.path.dirname(__file__), "plugins")
        if not os.path.isdir(self.plugin_dir):
            try:
                os.makedirs(self.plugin_dir, exist_ok=True)
            except Exception:
                pass

    def load_plugins(self):
        self.plugins.clear()
        if not os.path.isdir(self.plugin_dir):
            self.log("[PLUGIN] Plugin directory missing.")
            return
        for fname in os.listdir(self.plugin_dir):
            if fname.endswith(".py"):
                path = os.path.join(self.plugin_dir, fname)
                mod_name = f"plugin_{fname[:-3]}"
                spec = importlib.util.spec_from_file_location(mod_name, path)
                if spec and spec.loader:
                    try:
                        mod = importlib.util.module_from_spec(spec)
                        spec.loader.exec_module(mod)
                        self.plugins.append(mod)
                        self.log(f"[PLUGIN] Loaded: {fname}")
                    except Exception as e:
                        self.log(f"[PLUGIN] Failed to load {fname}: {e}")

    def run_plugins(self, context):
        for p in self.plugins:
            try:
                if hasattr(p, "run"):
                    p.run(context)
                    self.log(f"[PLUGIN] Executed plugin: {p.__name__}")
            except Exception as e:
                self.log(f"[PLUGIN] Error in {p.__name__}: {e}")

# ------------------------------------------------------------
# VRAM-Accelerated Threat Scoring (simulated)
# ------------------------------------------------------------
def vram_accelerated_scoring(threats):
    # Simulated GPU scoring using numpy if available
    levels = [t.level for t in threats]
    ports = [t.port if t.port is not None else 0 for t in threats]
    base = np.array(levels, dtype=float) if np is not None else [float(l) for l in levels]
    port_weight = np.array(ports, dtype=float) if np is not None else [float(p) for p in ports]

    if np is not None:
        scores = base * 1.5 + (port_weight > 0) * 2.0 + np.random.rand(len(threats)) * 0.5
    else:
        scores = []
        for b, pw in zip(base, port_weight):
            s = b * 1.5 + (1 if pw > 0 else 0) * 2.0 + random.random() * 0.5
            scores.append(s)

    for t, s in zip(threats, scores):
        t.score = float(s)

# ------------------------------------------------------------
# Network Scanner (safe local ports)
# ------------------------------------------------------------
def scan_ports(host="127.0.0.1", ports=None, timeout=0.2):
    if ports is None:
        ports = [22, 35, 80, 443, 8080]
    open_ports = []
    for p in ports:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        try:
            if s.connect_ex((host, p)) == 0:
                open_ports.append(p)
        except Exception:
            pass
        finally:
            s.close()
    return open_ports

# ------------------------------------------------------------
# Sound Effects
# ------------------------------------------------------------
def play_beep():
    if winsound:
        winsound.Beep(1000, 150)
    else:
        print("[SOUND] Beep (winsound not available)")

def play_target_lock():
    if winsound:
        winsound.Beep(1500, 200)
        winsound.Beep(1800, 200)
    else:
        print("[SOUND] Target lock (winsound not available)")

def play_neutralize():
    if winsound:
        winsound.Beep(800, 200)
        winsound.Beep(600, 200)
    else:
        print("[SOUND] Neutralize (winsound not available)")

# ------------------------------------------------------------
# GUI
# ------------------------------------------------------------
class TargetingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Targeting Computer — Cyber Command Dashboard")
        self.root.geometry("1200x700")

        # LOG WINDOW
        self.log_box = tk.Text(root, height=8, bg="#111", fg="#0f0")
        self.log_box.pack(fill="x")

        # ENGINE + SCORING
        self.engine = ThreatEngine(self.write_log, vram_accelerated_scoring)

        # SWARM + PLUGINS
        self.swarm = SwarmManager(self.write_log)
        self.plugins = PluginManager(self.write_log)

        # DASHBOARD FRAMES
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(fill="both", expand=True)

        self.left_frame = tk.Frame(self.main_frame)
        self.left_frame.pack(side="left", fill="both", expand=True)

        self.right_frame = tk.Frame(self.main_frame)
        self.right_frame.pack(side="right", fill="both", expand=True)

        # Build panels
        self.build_threat_panel(self.left_frame)
        self.build_targeting_panel(self.left_frame)
        self.build_network_panel(self.right_frame)
        self.build_swarm_panel(self.right_frame)
        self.build_plugin_panel(self.right_frame)
        self.build_reticle_panel(self.left_frame)

        # Threads
        threading.Thread(target=self.engine.ai_cycle, daemon=True).start()
        threading.Thread(target=self.swarm.sync_cycle, daemon=True).start()

        # Initial plugin load
        self.plugins.load_plugins()

        # Reticle animation
        self.reticle_running = True
        self.animate_reticle()

    # --------------------------------------------------------
    # LOGGING
    # --------------------------------------------------------
    def write_log(self, msg):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    # --------------------------------------------------------
    # THREAT PANEL
    # --------------------------------------------------------
    def build_threat_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Threats")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.threat_list = tk.Listbox(frame, height=12)
        self.threat_list.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(side="right", fill="y")

        tk.Button(btn_frame, text="Add Rogue AI",
                  command=lambda: self.add_threat("Rogue AI", 5)).pack(fill="x")
        tk.Button(btn_frame, text="Add Hacker",
                  command=lambda: self.add_threat("Hacker", 3)).pack(fill="x")
        tk.Button(btn_frame, text="Add Hacker on Port 35",
                  command=lambda: self.add_threat("Hacker on Port 35", 4, 35)).pack(fill="x")
        tk.Button(btn_frame, text="Add Rogue Shell Script",
                  command=lambda: self.add_threat("Rogue Shell Script", 2)).pack(fill="x")
        tk.Button(btn_frame, text="Refresh Threats",
                  command=self.refresh_threat_list).pack(fill="x")

    def add_threat(self, name, level, port=None):
        self.engine.add_threat(name, level, port)
        play_beep()
        self.refresh_threat_list()

    def refresh_threat_list(self):
        self.threat_list.delete(0, "end")
        for t in self.engine.threats:
            self.threat_list.insert(
                "end",
                f"{t.name} — L{t.level} — Score {t.score:.2f} — {t.status}"
            )

    # --------------------------------------------------------
    # TARGETING PANEL
    # --------------------------------------------------------
    def build_targeting_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Targeting Computer")
        frame.pack(fill="x", padx=10, pady=10)

        self.ai_var = tk.BooleanVar(value=True)
        tk.Checkbutton(frame, text="AI-Controlled Mode",
                       variable=self.ai_var,
                       command=self.toggle_ai).pack(anchor="w")

        tk.Button(frame, text="Manual Target Neutralize",
                  command=self.manual_target).pack(fill="x")

        tk.Button(frame, text="Recompute Threat Scores (VRAM)",
                  command=self.recompute_scores).pack(fill="x")

    def toggle_ai(self):
        self.engine.ai_enabled = self.ai_var.get()
        mode = "ENABLED" if self.engine.ai_enabled else "DISABLED"
        self.write_log(f"[SYSTEM] AI mode {mode}")
        play_beep()

    def manual_target(self):
        idx = self.threat_list.curselection()
        if not idx:
            self.write_log("[MANUAL] No threat selected.")
            return

        threat = self.engine.threats[idx[0]]
        if threat.status != "ACTIVE":
            self.write_log("[MANUAL] Threat already neutralized.")
            return

        self.write_log(f"[MANUAL] Neutralizing: {threat.name}")
        play_target_lock()
        self.engine.remove_threat(threat)
        play_neutralize()
        self.refresh_threat_list()

    def recompute_scores(self):
        self.write_log("[SCORING] Recomputing threat scores (VRAM simulated)...")
        self.engine.update_scores()
        self.refresh_threat_list()

    # --------------------------------------------------------
    # NETWORK PANEL
    # --------------------------------------------------------
    def build_network_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Network Scanner")
        frame.pack(fill="x", padx=10, pady=10)

        self.scan_result_box = tk.Listbox(frame, height=6)
        self.scan_result_box.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(side="right", fill="y")

        tk.Button(btn_frame, text="Scan Local Ports",
                  command=self.run_scan).pack(fill="x")

    def run_scan(self):
        self.write_log("[NET] Scanning local ports...")
        ports = scan_ports()
        self.scan_result_box.delete(0, "end")
        if ports:
            for p in ports:
                self.scan_result_box.insert("end", f"Port {p} OPEN")
            self.write_log("[NET] Open ports: " + ", ".join(str(p) for p in ports))
        else:
            self.scan_result_box.insert("end", "No known ports open.")
            self.write_log("[NET] No known ports open.")

    # --------------------------------------------------------
    # SWARM PANEL
    # --------------------------------------------------------
    def build_swarm_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Swarm Sync Nodes")
        frame.pack(fill="x", padx=10, pady=10)

        self.swarm_box = tk.Listbox(frame, height=6)
        self.swarm_box.pack(fill="both", expand=True)

        tk.Button(frame, text="Refresh Swarm Status",
                  command=self.refresh_swarm).pack(fill="x")

    def refresh_swarm(self):
        self.swarm_box.delete(0, "end")
        for n in self.swarm.nodes:
            self.swarm_box.insert("end", f"Node-{n.node_id} — Load {n.load:.2f} — {n.status}")

    # --------------------------------------------------------
    # PLUGIN PANEL
    # --------------------------------------------------------
    def build_plugin_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Plugin API")
        frame.pack(fill="x", padx=10, pady=10)

        self.plugin_box = tk.Listbox(frame, height=6)
        self.plugin_box.pack(fill="both", expand=True)

        tk.Button(frame, text="Reload Plugins",
                  command=self.reload_plugins).pack(fill="x")
        tk.Button(frame, text="Run Plugins (Context: Threats)",
                  command=self.run_plugins).pack(fill="x")

    def reload_plugins(self):
        self.plugins.load_plugins()
        self.plugin_box.delete(0, "end")
        if self.plugins.plugins:
            for p in self.plugins.plugins:
                self.plugin_box.insert("end", p.__name__)
        else:
            self.plugin_box.insert("end", "No plugins loaded.")

    def run_plugins(self):
        context = {
            "threats": self.engine.threats,
            "swarm_nodes": self.swarm.nodes,
        }
        self.plugins.run_plugins(context)
        self.refresh_threat_list()
        self.refresh_swarm()

    # --------------------------------------------------------
    # RETICLE PANEL (Animated Targeting Reticle)
    # --------------------------------------------------------
    def build_reticle_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Targeting Reticle")
        frame.pack(fill="x", padx=10, pady=10)

        self.reticle_canvas = tk.Canvas(frame, width=300, height=300, bg="#000")
        self.reticle_canvas.pack()

        self.reticle_angle = 0.0
        self.reticle_radius = 100

    def animate_reticle(self):
        if not self.reticle_running:
            return

        self.reticle_canvas.delete("all")

        cx, cy = 150, 150
        r = self.reticle_radius

        # Outer circle
        self.reticle_canvas.create_oval(cx - r, cy - r, cx + r, cy + r,
                                        outline="#0f0", width=2)

        # Crosshair lines
        self.reticle_canvas.create_line(cx - r, cy, cx + r, cy, fill="#0f0")
        self.reticle_canvas.create_line(cx, cy - r, cx, cy + r, fill="#0f0")

        # Rotating segments
        angle = self.reticle_angle
        for offset in [0, math.pi / 2, math.pi, 3 * math.pi / 2]:
            a = angle + offset
            x1 = cx + r * 0.6 * math.cos(a)
            y1 = cy + r * 0.6 * math.sin(a)
            x2 = cx + r * 0.9 * math.cos(a)
            y2 = cy + r * 0.9 * math.sin(a)
            self.reticle_canvas.create_line(x1, y1, x2, y2, fill="#0f0", width=3)

        self.reticle_angle += 0.1
        self.root.after(50, self.animate_reticle)

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    gui = TargetingGUI(root)
    root.mainloop()
