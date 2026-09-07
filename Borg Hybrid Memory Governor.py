#!/usr/bin/env python3
# Borg Hybrid Memory Governor v1.0
# Python, Windows-focused, monolithic file as requested.

import os
import sys
import time
import json
import math
import threading
import queue
import traceback
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional

import tkinter as tk
from tkinter import ttk, messagebox

# Optional dependencies (telemetry + UI automation)
try:
    import psutil
except ImportError:
    psutil = None

try:
    import uiautomation as auto  # dd uiautomation hook
except ImportError:
    auto = None

try:
    import winreg
except ImportError:
    winreg = None


# -----------------------------
# Data classes and core models
# -----------------------------

@dataclass
class TelemetrySnapshot:
    timestamp: float
    ram_used: float
    ram_total: float
    pagefile_used: float
    pagefile_total: float
    cpu_percent: float
    disk_read_bytes: float
    disk_write_bytes: float
    hard_faults_estimate: float
    processes: int
    profile_name: str = "unknown"


@dataclass
class Profile:
    name: str
    description: str
    mode: str  # "auto", "manual", "hybrid"
    registry_tweaks: Dict[str, Any] = field(default_factory=dict)
    constraints: Dict[str, Any] = field(default_factory=dict)


@dataclass
class RollbackEntry:
    timestamp: float
    description: str
    registry_state: Dict[str, Any]


# -----------------------------
# Registry Manager (safe wrapper)
# -----------------------------

class RegistryManager:
    BASE_MM = r"SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management"
    BASE_MM_PREFETCH = BASE_MM + r"\PrefetchParameters"

    def __init__(self):
        self.enabled = winreg is not None

    def _open_key(self, root, path, access=winreg.KEY_READ):
        if not self.enabled:
            return None
        try:
            return winreg.OpenKey(root, path, 0, access)
        except OSError:
            return None

    def read_value(self, path: str, name: str) -> Optional[Any]:
        if not self.enabled:
            return None
        try:
            root = winreg.HKEY_LOCAL_MACHINE
            key = self._open_key(root, path, winreg.KEY_READ)
            if key is None:
                return None
            val, _ = winreg.QueryValueEx(key, name)
            winreg.CloseKey(key)
            return val
        except OSError:
            return None

    def write_value(self, path: str, name: str, value: Any, vtype=None) -> bool:
        if not self.enabled:
            return False
        try:
            root = winreg.HKEY_LOCAL_MACHINE
            key = self._open_key(root, path, winreg.KEY_SET_VALUE)
            if key is None:
                key = winreg.CreateKey(root, path)
            if vtype is None:
                if isinstance(value, int):
                    vtype = winreg.REG_DWORD
                elif isinstance(value, str):
                    vtype = winreg.REG_SZ
                else:
                    vtype = winreg.REG_BINARY
            winreg.SetValueEx(key, name, 0, vtype, value)
            winreg.CloseKey(key)
            return True
        except OSError:
            return False

    def snapshot_mm(self) -> Dict[str, Any]:
        """Snapshot key values for rollback."""
        if not self.enabled:
            return {}
        keys = [
            "ClearPageFileAtShutdown",
            "DisablePagingExecutive",
            "LargeSystemCache",
            "NonPagedPoolQuota",
            "NonPagedPoolSize",
            "PagedPoolQuota",
            "PagedPoolSize",
            "SecondLevelDataCache",
            "SessionPoolSize",
            "SessionViewSize",
            "SystemPages",
            "PhysicalAddressExtension",
            "ThirdLevelDataCache",
            "iopagelocklimit",
        ]
        state = {}
        for k in keys:
            state[k] = self.read_value(self.BASE_MM, k)
        # Prefetch
        for k in ["EnableSuperfetch", "EnablePrefetcher"]:
            state[k] = self.read_value(self.BASE_MM_PREFETCH, k)
        return state

    def apply_tweaks(self, tweaks: Dict[str, Any]) -> bool:
        ok = True
        for name, val in tweaks.items():
            if name in ["EnableSuperfetch", "EnablePrefetcher"]:
                path = self.BASE_MM_PREFETCH
            else:
                path = self.BASE_MM
            if not self.write_value(path, name, val):
                ok = False
        return ok


# -----------------------------
# Telemetry System
# -----------------------------

class TelemetrySystem:
    def __init__(self):
        self.running = False
        self.thread = None
        self.snapshots: List[TelemetrySnapshot] = []
        self.lock = threading.Lock()
        self.event_queue = queue.Queue()

    def start(self, interval: float = 2.0):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, args=(interval,), daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _loop(self, interval: float):
        while self.running:
            try:
                snap = self._collect_snapshot()
                with self.lock:
                    self.snapshots.append(snap)
                self.event_queue.put(snap)
            except Exception:
                traceback.print_exc()
            time.sleep(interval)

    def _collect_snapshot(self) -> TelemetrySnapshot:
        ts = time.time()
        if psutil is None:
            # Fallback dummy snapshot
            return TelemetrySnapshot(
                timestamp=ts,
                ram_used=0,
                ram_total=0,
                pagefile_used=0,
                pagefile_total=0,
                cpu_percent=0,
                disk_read_bytes=0,
                disk_write_bytes=0,
                hard_faults_estimate=0,
                processes=0,
            )

        vm = psutil.virtual_memory()
        swap = psutil.swap_memory()
        cpu = psutil.cpu_percent(interval=None)
        disk_io = psutil.disk_io_counters()
        procs = len(psutil.pids())

        # Hard faults estimate: we approximate via swap in/out + paging activity.
        hard_faults_estimate = (swap.sin + swap.sout) / max(1, (time.time() - ts))

        return TelemetrySnapshot(
            timestamp=ts,
            ram_used=vm.used,
            ram_total=vm.total,
            pagefile_used=swap.used,
            pagefile_total=swap.total,
            cpu_percent=cpu,
            disk_read_bytes=disk_io.read_bytes,
            disk_write_bytes=disk_io.write_bytes,
            hard_faults_estimate=hard_faults_estimate,
            processes=procs,
        )

    def get_recent(self, n: int = 50) -> List[TelemetrySnapshot]:
        with self.lock:
            return self.snapshots[-n:]


# -----------------------------
# Profile System
# -----------------------------

class ProfileSystem:
    def __init__(self, registry: RegistryManager):
        self.registry = registry
        self.profiles: Dict[str, Profile] = {}
        self.current_profile: Optional[Profile] = None
        self._init_default_profiles()

    def _init_default_profiles(self):
        # Basic presets; you can tune these further.
        self.profiles["Safe"] = Profile(
            name="Safe",
            description="Near-default Windows behavior, minimal risk.",
            mode="manual",
            registry_tweaks={
                "DisablePagingExecutive": 0,
                "LargeSystemCache": 0,
                "EnableSuperfetch": 3,
                "EnablePrefetcher": 3,
            },
            constraints={"max_risk": 0.2},
        )
        self.profiles["Gaming"] = Profile(
            name="Gaming",
            description="Low-latency, keep kernel in RAM, aggressive prefetch.",
            mode="auto",
            registry_tweaks={
                "DisablePagingExecutive": 1,
                "LargeSystemCache": 0,
                "EnableSuperfetch": 3,
                "EnablePrefetcher": 3,
            },
            constraints={"max_hard_faults": 1000},
        )
        self.profiles["Workstation"] = Profile(
            name="Workstation",
            description="Balanced for heavy apps, VMs, and multitasking.",
            mode="hybrid",
            registry_tweaks={
                "DisablePagingExecutive": 1,
                "LargeSystemCache": 0,
                "EnableSuperfetch": 2,
                "EnablePrefetcher": 3,
            },
            constraints={"max_commit_ratio": 0.9},
        )

    def set_profile(self, name: str) -> bool:
        prof = self.profiles.get(name)
        if not prof:
            return False
        self.current_profile = prof
        return True

    def apply_current_profile(self) -> bool:
        if not self.current_profile:
            return False
        return self.registry.apply_tweaks(self.current_profile.registry_tweaks)

    def export_profiles(self, path: str):
        data = {name: vars(p) for name, p in self.profiles.items()}
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    def import_profiles(self, path: str):
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        self.profiles.clear()
        for name, pd in data.items():
            self.profiles[name] = Profile(**pd)


# -----------------------------
# Rollback System
# -----------------------------

class RollbackSystem:
    def __init__(self, registry: RegistryManager):
        self.registry = registry
        self.history: List[RollbackEntry] = []

    def snapshot(self, description: str = "Snapshot"):
        state = self.registry.snapshot_mm()
        entry = RollbackEntry(
            timestamp=time.time(),
            description=description,
            registry_state=state,
        )
        self.history.append(entry)

    def rollback_last(self) -> bool:
        if not self.history:
            return False
        entry = self.history[-1]
        return self.registry.apply_tweaks(entry.registry_state)


# -----------------------------
# Borg Hybrid Engine
# -----------------------------

class BorgHybridEngine:
    """
    Adaptive engine:
    - Uses telemetry to infer workload and missing details.
    - Applies Bernoulli-style probabilistic reasoning for best-guess tuning.
    - "Water data physics engine": treats resource flows like fluid dynamics.
    - More resilient, predictive, and self-correcting.
    """

    def __init__(self, telemetry: TelemetrySystem, profiles: ProfileSystem, registry: RegistryManager, rollback: RollbackSystem):
        self.telemetry = telemetry
        self.profiles = profiles
        self.registry = registry
        self.rollback = rollback
        self.running = False
        self.thread = None

    def start(self, interval: float = 5.0):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, args=(interval,), daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def _loop(self, interval: float):
        while self.running:
            try:
                self._analyze_and_tune()
            except Exception:
                traceback.print_exc()
            time.sleep(interval)

    def _analyze_and_tune(self):
        snaps = self.telemetry.get_recent(30)
        if not snaps:
            return

        # Aggregate metrics
        avg_cpu = sum(s.cpu_percent for s in snaps) / len(snaps)
        avg_ram_ratio = sum(s.ram_used / max(1, s.ram_total) for s in snaps) / len(snaps)
        avg_pf_ratio = sum(
            (s.pagefile_used / max(1, s.pagefile_total)) if s.pagefile_total > 0 else 0
            for s in snaps
        ) / len(snaps)
        avg_hf = sum(s.hard_faults_estimate for s in snaps) / len(snaps)

        # Bernoulli-style predictive reasoning:
        # We treat "bad events" (high hard faults, high commit ratio) as Bernoulli trials.
        # p_bad approximates probability of memory stress.
        p_hf = min(1.0, avg_hf / 5000.0)
        p_ram = min(1.0, avg_ram_ratio)
        p_pf = min(1.0, avg_pf_ratio)
        p_bad = 1 - (1 - p_hf) * (1 - p_ram) * (1 - p_pf)

        # "Water data physics engine": think of RAM + pagefile as reservoirs.
        # If RAM reservoir is near full and pagefile reservoir is underused, we might
        # allow more paging; if both are stressed, we tighten.
        # This is metaphorical but we encode it as heuristic rules.

        # Decide profile based on flows:
        if avg_cpu > 60 and p_bad < 0.4:
            target_profile = "Gaming"
        elif p_bad > 0.7:
            target_profile = "Safe"
        else:
            target_profile = "Workstation"

        # Missing details inference:
        # If we lack swap_total or telemetry is partial, we bias toward Safe.
        if any(s.pagefile_total == 0 for s in snaps):
            target_profile = "Safe"

        # Apply profile if changed
        current = self.profiles.current_profile.name if self.profiles.current_profile else None
        if current != target_profile:
            self.rollback.snapshot(description=f"Before switching to {target_profile}")
            self.profiles.set_profile(target_profile)
            self.profiles.apply_current_profile()

    def best_guess_state(self) -> Dict[str, Any]:
        """Expose current best-guess about system stress and recommended profile."""
        snaps = self.telemetry.get_recent(30)
        if not snaps:
            return {"status": "no_telemetry"}

        avg_cpu = sum(s.cpu_percent for s in snaps) / len(snaps)
        avg_ram_ratio = sum(s.ram_used / max(1, s.ram_total) for s in snaps) / len(snaps)
        avg_pf_ratio = sum(
            (s.pagefile_used / max(1, s.pagefile_total)) if s.pagefile_total > 0 else 0
            for s in snaps
        ) / len(snaps)
        avg_hf = sum(s.hard_faults_estimate for s in snaps) / len(snaps)

        p_hf = min(1.0, avg_hf / 5000.0)
        p_ram = min(1.0, avg_ram_ratio)
        p_pf = min(1.0, avg_pf_ratio)
        p_bad = 1 - (1 - p_hf) * (1 - p_ram) * (1 - p_pf)

        return {
            "avg_cpu": avg_cpu,
            "avg_ram_ratio": avg_ram_ratio,
            "avg_pf_ratio": avg_pf_ratio,
            "avg_hf": avg_hf,
            "p_bad": p_bad,
            "recommended_profile": self.profiles.current_profile.name if self.profiles.current_profile else None,
        }


# -----------------------------
# GUI (Tkinter)
# -----------------------------

class BorgGUI(tk.Tk):
    def __init__(self, telemetry: TelemetrySystem, profiles: ProfileSystem, rollback: RollbackSystem, borg: BorgHybridEngine):
        super().__init__()
        self.telemetry = telemetry
        self.profiles = profiles
        self.rollback = rollback
        self.borg = borg

        self.title("Borg Hybrid Memory Governor")
        self.geometry("900x600")

        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self._build_ui()
        self._update_loop()

    def _build_ui(self):
        notebook = ttk.Notebook(self)
        notebook.pack(fill=tk.BOTH, expand=True)

        # Dashboard
        self.frame_dashboard = ttk.Frame(notebook)
        notebook.add(self.frame_dashboard, text="Dashboard")

        # Profiles
        self.frame_profiles = ttk.Frame(notebook)
        notebook.add(self.frame_profiles, text="Profiles")

        # Advanced
        self.frame_advanced = ttk.Frame(notebook)
        notebook.add(self.frame_advanced, text="Advanced")

        # Dashboard widgets
        self.lbl_cpu = ttk.Label(self.frame_dashboard, text="CPU: -- %")
        self.lbl_cpu.pack(anchor="w", padx=10, pady=5)

        self.lbl_ram = ttk.Label(self.frame_dashboard, text="RAM: -- / --")
        self.lbl_ram.pack(anchor="w", padx=10, pady=5)

        self.lbl_pf = ttk.Label(self.frame_dashboard, text="Pagefile: -- / --")
        self.lbl_pf.pack(anchor="w", padx=10, pady=5)

        self.lbl_hf = ttk.Label(self.frame_dashboard, text="Hard faults (est): --")
        self.lbl_hf.pack(anchor="w", padx=10, pady=5)

        self.lbl_profile = ttk.Label(self.frame_dashboard, text="Current profile: --")
        self.lbl_profile.pack(anchor="w", padx=10, pady=5)

        self.lbl_pbad = ttk.Label(self.frame_dashboard, text="Stress probability (Bernoulli): --")
        self.lbl_pbad.pack(anchor="w", padx=10, pady=5)

        # Profiles tab
        ttk.Label(self.frame_profiles, text="Available Profiles:").pack(anchor="w", padx=10, pady=5)
        self.lst_profiles = tk.Listbox(self.frame_profiles, height=6)
        self.lst_profiles.pack(fill=tk.X, padx=10, pady=5)
        for name in self.profiles.profiles.keys():
            self.lst_profiles.insert(tk.END, name)

        btn_set_profile = ttk.Button(self.frame_profiles, text="Apply Selected Profile", command=self._apply_selected_profile)
        btn_set_profile.pack(padx=10, pady=5)

        btn_snapshot = ttk.Button(self.frame_profiles, text="Snapshot (Rollback Point)", command=self._snapshot)
        btn_snapshot.pack(padx=10, pady=5)

        btn_rollback = ttk.Button(self.frame_profiles, text="Rollback Last", command=self._rollback_last)
        btn_rollback.pack(padx=10, pady=5)

        # Advanced tab
        ttk.Label(self.frame_advanced, text="Mode Control:").pack(anchor="w", padx=10, pady=5)
        self.mode_var = tk.StringVar(value="auto")
        ttk.Radiobutton(self.frame_advanced, text="Auto (Borg)", variable=self.mode_var, value="auto", command=self._mode_changed).pack(anchor="w", padx=20)
        ttk.Radiobutton(self.frame_advanced, text="Manual", variable=self.mode_var, value="manual", command=self._mode_changed).pack(anchor="w", padx=20)
        ttk.Radiobutton(self.frame_advanced, text="Hybrid", variable=self.mode_var, value="hybrid", command=self._mode_changed).pack(anchor="w", padx=20)

        ttk.Label(self.frame_advanced, text="Export / Import Profiles:").pack(anchor="w", padx=10, pady=10)
        btn_export = ttk.Button(self.frame_advanced, text="Export Profiles (profiles.json)", command=self._export_profiles)
        btn_export.pack(anchor="w", padx=20, pady=2)
        btn_import = ttk.Button(self.frame_advanced, text="Import Profiles (profiles.json)", command=self._import_profiles)
        btn_import.pack(anchor="w", padx=20, pady=2)

        ttk.Label(self.frame_advanced, text="UI Automation Status:").pack(anchor="w", padx=10, pady=10)
        self.lbl_uia = ttk.Label(self.frame_advanced, text="uiautomation: available" if auto else "uiautomation: NOT available")
        self.lbl_uia.pack(anchor="w", padx=20, pady=2)

    def _apply_selected_profile(self):
        sel = self.lst_profiles.curselection()
        if not sel:
            messagebox.showwarning("No selection", "Select a profile first.")
            return
        name = self.lst_profiles.get(sel[0])
        if self.profiles.set_profile(name):
            self.rollback.snapshot(description=f"Manual switch to {name}")
            self.profiles.apply_current_profile()
            messagebox.showinfo("Profile applied", f"Profile '{name}' applied.")
        else:
            messagebox.showerror("Error", f"Failed to set profile '{name}'.")

    def _snapshot(self):
        self.rollback.snapshot(description="Manual snapshot")
        messagebox.showinfo("Snapshot", "Snapshot created for rollback.")

    def _rollback_last(self):
        if self.rollback.rollback_last():
            messagebox.showinfo("Rollback", "Rolled back to last snapshot.")
        else:
            messagebox.showwarning("Rollback", "No rollback history available.")

    def _mode_changed(self):
        mode = self.mode_var.get()
        if mode == "auto":
            self.borg.start()
        elif mode == "manual":
            self.borg.stop()
        elif mode == "hybrid":
            # Hybrid: Borg runs but you can override via profiles.
            self.borg.start()

    def _export_profiles(self):
        try:
            self.profiles.export_profiles("profiles.json")
            messagebox.showinfo("Export", "Profiles exported to profiles.json.")
        except Exception as e:
            messagebox.showerror("Export error", str(e))

    def _import_profiles(self):
        try:
            self.profiles.import_profiles("profiles.json")
            self.lst_profiles.delete(0, tk.END)
            for name in self.profiles.profiles.keys():
                self.lst_profiles.insert(tk.END, name)
            messagebox.showinfo("Import", "Profiles imported from profiles.json.")
        except Exception as e:
            messagebox.showerror("Import error", str(e))

    def _update_loop(self):
        # Update dashboard from telemetry + borg best guess
        state = self.borg.best_guess_state()
        snaps = self.telemetry.get_recent(1)
        if snaps:
            s = snaps[-1]
            self.lbl_cpu.config(text=f"CPU: {s.cpu_percent:.1f} %")
            self.lbl_ram.config(text=f"RAM: {self._fmt_bytes(s.ram_used)} / {self._fmt_bytes(s.ram_total)}")
            self.lbl_pf.config(text=f"Pagefile: {self._fmt_bytes(s.pagefile_used)} / {self._fmt_bytes(s.pagefile_total)}")
            self.lbl_hf.config(text=f"Hard faults (est): {s.hard_faults_estimate:.2f}")
        else:
            self.lbl_cpu.config(text="CPU: -- %")
            self.lbl_ram.config(text="RAM: -- / --")
            self.lbl_pf.config(text="Pagefile: -- / --")
            self.lbl_hf.config(text="Hard faults (est): --")

        if self.profiles.current_profile:
            self.lbl_profile.config(text=f"Current profile: {self.profiles.current_profile.name}")
        else:
            self.lbl_profile.config(text="Current profile: --")

        if state.get("status") != "no_telemetry":
            self.lbl_pbad.config(text=f"Stress probability (Bernoulli): {state['p_bad']:.2f}")
        else:
            self.lbl_pbad.config(text="Stress probability (Bernoulli): --")

        self.after(1000, self._update_loop)

    @staticmethod
    def _fmt_bytes(b: float) -> str:
        if b <= 0:
            return "0 B"
        units = ["B", "KB", "MB", "GB", "TB"]
        i = int(math.floor(math.log(b, 1024)))
        val = b / (1024 ** i)
        return f"{val:.1f} {units[i]}"


# -----------------------------
# Main entry
# -----------------------------

def main():
    registry = RegistryManager()
    telemetry = TelemetrySystem()
    telemetry.start(interval=2.0)

    profiles = ProfileSystem(registry)
    rollback = RollbackSystem(registry)
    borg = BorgHybridEngine(telemetry, profiles, registry, rollback)

    # Default: start in hybrid mode
    profiles.set_profile("Workstation")
    profiles.apply_current_profile()
    borg.start(interval=5.0)

    app = BorgGUI(telemetry, profiles, rollback, borg)
    app.mainloop()

    borg.stop()
    telemetry.stop()


if __name__ == "__main__":
    main()
