#!/usr/bin/env python3
# ============================================================
# TargetingComputer.py
# Fully unified file with autoloader, GUI, AI-control system,
# manual override, threat list, targeting panel, and event log.
# ============================================================

import importlib
import subprocess
import sys

# ------------------------------------------------------------
# AUTOLOADER: Ensures all required libraries are installed
# ------------------------------------------------------------
REQUIRED_LIBS = [
    "tkinter",
]

def autoload():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            print(f"[AUTOLOADER] Installing missing library: {lib}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])

autoload()

# ------------------------------------------------------------
# GUI + SYSTEM IMPORTS
# ------------------------------------------------------------
import tkinter as tk
from tkinter import ttk
import random
import time
import threading

# ------------------------------------------------------------
# Threat Simulation Engine
# ------------------------------------------------------------
class Threat:
    def __init__(self, name, level, port=None):
        self.name = name
        self.level = level
        self.port = port
        self.status = "ACTIVE"

    def __repr__(self):
        return f"{self.name} (Level {self.level}) - {self.status}"

class ThreatEngine:
    def __init__(self, log_callback):
        self.log = log_callback
        self.threats = []
        self.ai_enabled = True

    def add_threat(self, name, level, port=None):
        t = Threat(name, level, port)
        self.threats.append(t)
        self.log(f"[ENGINE] Threat added: {t}")

    def remove_threat(self, threat):
        threat.status = "NEUTRALIZED"
        self.log(f"[ENGINE] Threat neutralized: {threat}")

    def ai_cycle(self):
        """AI automatically selects and neutralizes threats."""
        while True:
            time.sleep(2)
            if self.ai_enabled and self.threats:
                active = [t for t in self.threats if t.status == "ACTIVE"]
                if active:
                    target = random.choice(active)
                    self.log(f"[AI] Auto-targeting: {target.name}")
                    self.remove_threat(target)

# ------------------------------------------------------------
# GUI System
# ------------------------------------------------------------
class TargetingGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Targeting Computer — AI Control System")
        self.root.geometry("900x600")

        # LOG WINDOW
        self.log_box = tk.Text(root, height=10, bg="#111", fg="#0f0")
        self.log_box.pack(fill="x")

        # ENGINE
        self.engine = ThreatEngine(self.write_log)

        # MAIN PANELS
        self.build_threat_panel()
        self.build_targeting_panel()

        # AI THREAD
        threading.Thread(target=self.engine.ai_cycle, daemon=True).start()

    # --------------------------------------------------------
    # LOGGING
    # --------------------------------------------------------
    def write_log(self, msg):
        self.log_box.insert("end", msg + "\n")
        self.log_box.see("end")

    # --------------------------------------------------------
    # THREAT PANEL
    # --------------------------------------------------------
    def build_threat_panel(self):
        frame = ttk.LabelFrame(self.root, text="Threats")
        frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.threat_list = tk.Listbox(frame, height=10)
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

    def add_threat(self, name, level, port=None):
        self.engine.add_threat(name, level, port)
        self.refresh_threat_list()

    def refresh_threat_list(self):
        self.threat_list.delete(0, "end")
        for t in self.engine.threats:
            self.threat_list.insert("end", f"{t.name} — Level {t.level} — {t.status}")

    # --------------------------------------------------------
    # TARGETING PANEL
    # --------------------------------------------------------
    def build_targeting_panel(self):
        frame = ttk.LabelFrame(self.root, text="Targeting Computer")
        frame.pack(fill="x", padx=10, pady=10)

        # AI MODE TOGGLE
        self.ai_var = tk.BooleanVar(value=True)
        tk.Checkbutton(frame, text="AI-Controlled Mode",
                       variable=self.ai_var,
                       command=self.toggle_ai).pack(anchor="w")

        # MANUAL OVERRIDE BUTTON
        tk.Button(frame, text="Manual Target Neutralize",
                  command=self.manual_target).pack(fill="x")

    def toggle_ai(self):
        self.engine.ai_enabled = self.ai_var.get()
        mode = "ENABLED" if self.engine.ai_enabled else "DISABLED"
        self.write_log(f"[SYSTEM] AI mode {mode}")

    def manual_target(self):
        """Manual override: user selects threat from list."""
        idx = self.threat_list.curselection()
        if not idx:
            self.write_log("[MANUAL] No threat selected.")
            return

        threat = self.engine.threats[idx[0]]
        if threat.status != "ACTIVE":
            self.write_log("[MANUAL] Threat already neutralized.")
            return

        self.write_log(f"[MANUAL] Neutralizing: {threat.name}")
        self.engine.remove_threat(threat)
        self.refresh_threat_list()

# ------------------------------------------------------------
# MAIN EXECUTION
# ------------------------------------------------------------
if __name__ == "__main__":
    root = tk.Tk()
    gui = TargetingGUI(root)
    root.mainloop()
