#!/usr/bin/env python3
# ============================================================
# TargetingComputer_DominionDeck_Probes.py
# Cyber-Command Dashboard with:
# - Autoloader
# - GUI (Tkinter)
# - Threat list + AI control + manual override
# - Animated targeting reticle
# - Sound effects
# - Network scanner (safe local ports)
# - Plugin API with basic sandboxing
# - Swarm-sync nodes (DominionDeck-style, threaded)
# - VRAM-accelerated threat scoring (GPU-backed if available)
# - Real-time threat heatmap (matplotlib, optional)
# - Process + file probe simulation (Star Trek-style probes)
# - DominionDeck integration hooks (stubbed)
# ============================================================

import importlib
import subprocess
import sys

# ------------------------------------------------------------
# AUTOLOADER
# ------------------------------------------------------------
REQUIRED_LIBS = [
    "tkinter",
    "numpy",
    "matplotlib",
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
    import matplotlib
    matplotlib.use("Agg")
    from matplotlib.figure import Figure
    from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
except Exception:
    Figure = None
    FigureCanvasTkAgg = None

try:
    import winsound
except ImportError:
    winsound = None

# Optional GPU backends
try:
    import cupy as cp
except ImportError:
    cp = None

try:
    import torch
except ImportError:
    torch = None

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
        return f"{self.name} (L{self.level}, S{self.score:.2f}) - {self.status}"

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
# Plugin API (basic sandbox)
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
                        # basic sandbox: only keep plugins with 'run' attribute
                        if hasattr(mod, "run"):
                            self.plugins.append(mod)
                            self.log(f"[PLUGIN] Loaded: {fname}")
                        else:
                            self.log(f"[PLUGIN] Skipped (no run()): {fname}")
                    except Exception as e:
                        self.log(f"[PLUGIN] Failed to load {fname}: {e}")

    def run_plugins(self, context):
        for p in self.plugins:
            try:
                p.run(context)
                self.log(f"[PLUGIN] Executed plugin: {p.__name__}")
            except Exception as e:
                self.log(f"[PLUGIN] Error in {p.__name__}: {e}")

# ------------------------------------------------------------
# VRAM-Accelerated Threat Scoring (GPU-backed if available)
# ------------------------------------------------------------
def vram_accelerated_scoring(threats):
    levels = [t.level for t in threats]
    ports = [t.port if t.port is not None else 0 for t in threats]

    backend = "CPU"
    if cp is not None:
        backend = "CuPy"
        base = cp.array(levels, dtype=cp.float32)
        port_weight = cp.array(ports, dtype=cp.float32)
        scores = base * 1.7 + (port_weight > 0) * 2.3 + cp.random.rand(len(threats)) * 0.7
        scores = cp.asnumpy(scores)
    elif torch is not None:
        backend = "Torch"
        base = torch.tensor(levels, dtype=torch.float32)
        port_weight = torch.tensor(ports, dtype=torch.float32)
        scores = base * 1.7 + (port_weight > 0) * 2.3 + torch.rand(len(threats)) * 0.7
        scores = scores.detach().cpu().numpy()
    elif np is not None:
        backend = "NumPy"
        base = np.array(levels, dtype=float)
        port_weight = np.array(ports, dtype=float)
        scores = base * 1.7 + (port_weight > 0) * 2.3 + np.random.rand(len(threats)) * 0.7
    else:
        backend = "PurePython"
        scores = []
        for l, p in zip(levels, ports):
            s = l * 1.7 + (1 if p > 0 else 0) * 2.3 + random.random() * 0.7
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

def play_target_lock():
    if winsound:
        winsound.Beep(1500, 200)
        winsound.Beep(1800, 200)

def play_neutralize():
    if winsound:
        winsound.Beep(800, 200)
        winsound.Beep(600, 200)

# ------------------------------------------------------------
# Star Trek-style Probes
# ------------------------------------------------------------
class Probe:
    def __init__(self, probe_id):
        self.probe_id = probe_id
        self.status = "IDLE"
        self.sector = "N/A"
        self.reading = 0.0

    def __repr__(self):
        return f"Probe-{self.probe_id} [{self.status}] Sector={self.sector} Reading={self.reading:.2f}"

class ProbeManager:
    def __init__(self, log_callback):
        self.log = log_callback
        self.probes = [Probe(i) for i in range(1, 4)]
        self.running = True

    def cycle(self):
        sectors = ["Alpha", "Beta", "Gamma", "Delta", "Omega"]
        while self.running:
            time.sleep(2)
            for p in self.probes:
                if p.status == "LAUNCHED":
                    p.sector = random.choice(sectors)
                    p.reading = random.uniform(0.0, 1.0)
            self.log("[PROBE] Telemetry tick: " + ", ".join(
                f"{p.probe_id}:{p.sector}:{p.reading:.2f}" for p in self.probes if p.status == "LAUNCHED"
            ))

    def launch_probe(self, probe):
        probe.status = "LAUNCHED"
        self.log(f"[PROBE] Launched Probe-{probe.probe_id}")

    def recall_probe(self, probe):
        probe.status = "IDLE"
        probe.sector = "N/A"
        probe.reading = 0.0
        self.log(f"[PROBE] Recalled Probe-{probe.probe_id}")

# ------------------------------------------------------------
# DominionDeck Integration Hooks (stub)
# ------------------------------------------------------------
class DominionDeckHooks:
    def __init__(self, log_callback):
        self.log = log_callback

    def push_threat_matrix(self, threats):
        self.log(f"[DOMINIONDECK] Pushed threat matrix ({len(threats)} entries).")

    def pull_purge_rules(self):
        self.log("[DOMINIONDECK] Pulled purge rules (stub).")

# ------------------------------------------------------------
# GUI
# ------------------------------------------------------------
class TargetingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Targeting Computer — DominionDeck Cyber Command with Probes")
        self.root.geometry("1400x800")

        # LOG WINDOW
        self.log_box = tk.Text(root, height=8, bg="#111", fg="#0f0")
        self.log_box.pack(fill="x")

        # ENGINE + SCORING
        self.engine = ThreatEngine(self.write_log, vram_accelerated_scoring)

        # SWARM + PLUGINS + PROBES + DOMINIONDECK
        self.swarm = SwarmManager(self.write_log)
        self.plugins = PluginManager(self.write_log)
        self.probes = ProbeManager(self.write_log)
        self.dd_hooks = DominionDeckHooks(self.write_log)

        # MAIN LAYOUT
        self.main_frame = tk.Frame(root)
        self.main_frame.pack(fill="both", expand=True)

        self.left_frame = tk.Frame(self.main_frame)
        self.left_frame.pack(side="left", fill="both", expand=True)

        self.right_frame = tk.Frame(self.main_frame)
        self.right_frame.pack(side="right", fill="both", expand=True)

        # Panels
        self.build_threat_panel(self.left_frame)
        self.build_targeting_panel(self.left_frame)
        self.build_reticle_panel(self.left_frame)

        self.build_network_panel(self.right_frame)
        self.build_swarm_panel(self.right_frame)
        self.build_plugin_panel(self.right_frame)
        self.build_probe_panel(self.right_frame)
        self.build_heatmap_panel(self.right_frame)

        # Threads
        threading.Thread(target=self.engine.ai_cycle, daemon=True).start()
        threading.Thread(target=self.swarm.sync_cycle, daemon=True).start()
        threading.Thread(target=self.probes.cycle, daemon=True).start()

        # Initial plugin load
        self.plugins.load_plugins()

        # Reticle animation
        self.reticle_running = True
        self.reticle_angle = 0.0
        self.reticle_radius = 100
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
        tk.Button(btn_frame, text="Push Threat Matrix to DominionDeck",
                  command=self.push_dd_matrix).pack(fill="x")

    def add_threat(self, name, level, port=None):
        self.engine.add_threat(name, level, port)
        play_beep()
        self.refresh_threat_list()
        self.update_heatmap()

    def refresh_threat_list(self):
        self.threat_list.delete(0, "end")
        for t in self.engine.threats:
            self.threat_list.insert(
                "end",
                f"{t.name} — L{t.level} — S{t.score:.2f} — {t.status}"
            )

    def push_dd_matrix(self):
        self.dd_hooks.push_threat_matrix(self.engine.threats)

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

        tk.Button(frame, text="Pull Purge Rules (DominionDeck)",
                  command=self.pull_dd_rules).pack(fill="x")

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
        self.update_heatmap()

    def recompute_scores(self):
        self.write_log("[SCORING] Recomputing threat scores (VRAM backend)...")
        self.engine.update_scores()
        self.refresh_threat_list()
        self.update_heatmap()

    def pull_dd_rules(self):
        self.dd_hooks.pull_purge_rules()

    # --------------------------------------------------------
    # RETICLE PANEL (Animated Targeting Reticle)
    # --------------------------------------------------------
    def build_reticle_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Targeting Reticle")
        frame.pack(fill="x", padx=10, pady=10)

        self.reticle_canvas = tk.Canvas(frame, width=300, height=300, bg="#000")
        self.reticle_canvas.pack()

    def animate_reticle(self):
        if not self.reticle_running:
            return

        self.reticle_canvas.delete("all")

        cx, cy = 150, 150
        r = self.reticle_radius

        self.reticle_canvas.create_oval(cx - r, cy - r, cx + r, cy + r,
                                        outline="#0f0", width=2)
        self.reticle_canvas.create_line(cx - r, cy, cx + r, cy, fill="#0f0")
        self.reticle_canvas.create_line(cx, cy - r, cx, cy + r, fill="#0f0")

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
        tk.Button(frame, text="Run Plugins (Threat + Swarm Context)",
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
        self.update_heatmap()

    # --------------------------------------------------------
    # PROBE PANEL (Star Trek-style)
    # --------------------------------------------------------
    def build_probe_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Probes (Star Trek-style)")
        frame.pack(fill="x", padx=10, pady=10)

        self.probe_box = tk.Listbox(frame, height=6)
        self.probe_box.pack(side="left", fill="both", expand=True)

        btn_frame = tk.Frame(frame)
        btn_frame.pack(side="right", fill="y")

        tk.Button(btn_frame, text="Refresh Probes",
                  command=self.refresh_probes).pack(fill="x")
        tk.Button(btn_frame, text="Launch Selected Probe",
                  command=self.launch_selected_probe).pack(fill="x")
        tk.Button(btn_frame, text="Recall Selected Probe",
                  command=self.recall_selected_probe).pack(fill="x")

    def refresh_probes(self):
        self.probe_box.delete(0, "end")
        for p in self.probes.probes:
            self.probe_box.insert("end", f"Probe-{p.probe_id} — {p.status} — {p.sector} — {p.reading:.2f}")

    def get_selected_probe(self):
        idx = self.probe_box.curselection()
        if not idx:
            return None
        return self.probes.probes[idx[0]]

    def launch_selected_probe(self):
        probe = self.get_selected_probe()
        if not probe:
            self.write_log("[PROBE] No probe selected.")
            return
        self.probes.launch_probe(probe)
        self.refresh_probes()

    def recall_selected_probe(self):
        probe = self.get_selected_probe()
        if not probe:
            self.write_log("[PROBE] No probe selected.")
            return
        self.probes.recall_probe(probe)
        self.refresh_probes()

    # --------------------------------------------------------
    # HEATMAP PANEL (Threat Heatmap)
    # --------------------------------------------------------
    def build_heatmap_panel(self, parent):
        frame = ttk.LabelFrame(parent, text="Threat Heatmap")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.heatmap_frame = frame
        self.heatmap_canvas = None
        self.heatmap_fig = None

        if Figure is not None and FigureCanvasTkAgg is not None:
            self.heatmap_fig = Figure(figsize=(4, 3), dpi=100)
            self.heatmap_ax = self.heatmap_fig.add_subplot(111)
            self.heatmap_canvas = FigureCanvasTkAgg(self.heatmap_fig, master=self.heatmap_frame)
            self.heatmap_canvas.get_tk_widget().pack(fill="both", expand=True)
            self.update_heatmap()
        else:
            lbl = tk.Label(frame, text="Matplotlib not available — heatmap disabled.", fg="red")
            lbl.pack(fill="both", expand=True)

    def update_heatmap(self):
        if not self.heatmap_fig or not self.engine.threats:
            return
        scores = [t.score for t in self.engine.threats]
        levels = [t.level for t in self.engine.threats]
        data = np.zeros((10, 10)) if np is not None else [[0 for _ in range(10)] for _ in range(10)]
        for i, (s, l) in enumerate(zip(scores, levels)):
            x = i % 10
            y = min(9, l)
            if np is not None:
                data[y, x] = s
            else:
                data[y][x] = s
        self.heatmap_ax.clear()
        self.heatmap_ax.set_title("Threat Heatmap")
        if np is not None:
            im = self.heatmap_ax.imshow(data, cmap="inferno", interpolation="nearest")
        else:
            im = self.heatmap_ax.imshow(data, cmap="inferno", interpolation="nearest")
        self.heatmap_fig.colorbar(im, ax=self.heatmap_ax, fraction=0.046, pad=0.04)
        self.heatmap_canvas.draw()

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    gui = TargetingGUI(root)
    root.mainloop()
