#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Codex Sentinel Ritual Shell — Enhanced Edition
Windows-focused dashboard for system/process monitoring, safe Explorer tweaks,
profiles, configuration backups, and audit logging.

Important:
- "CPU/GPU/IO envelopes" are application profiles, not direct hardware overclocking.
- This app does not disable Windows telemetry or enforce Group Policy.
- Registry changes are limited to explicitly listed per-user Explorer values.
- Admin elevation is optional and never triggered automatically at startup.
"""

from __future__ import annotations

import ctypes
import json
import logging
import os
import platform
import shutil
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import winreg  # Windows only
except ImportError:
    winreg = None

try:
    import psutil  # Optional: richer process/system telemetry
except ImportError:
    psutil = None


APP_NAME = "CodexSentinelRitualShell"
APP_TITLE = "Codex Sentinel — System Command Center"
CONFIG_DIR = Path(os.environ.get("APPDATA", str(Path.home()))) / APP_NAME
CONFIG_PATH = CONFIG_DIR / "config.json"
LOG_PATH = CONFIG_DIR / "sentinel.log"
BACKUP_DIR = CONFIG_DIR / "backups"
REFRESH_MS = 2000
PROCESS_LIMIT = 250

DEFAULT_CONFIG: dict[str, Any] = {
    "profile": "Sentinel",
    "secure_mode": True,
    "persona_locked": False,
    "watchdog_enabled": True,
    "auto_refresh": True,
    "refresh_ms": REFRESH_MS,
    "cpu_envelope": "Balanced",
    "gpu_envelope": "Sentinel (monitor only)",
    "io_envelope": "Normal",
    "theme": "Dark",
    "registry_backup_before_change": True,
    "last_registry_backup": "",
}


def is_windows() -> bool:
    return os.name == "nt" and winreg is not None


def is_admin() -> bool:
    if not is_windows():
        return False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def windows_version_text() -> str:
    try:
        return f"{platform.system()} {platform.release()} ({platform.version()})"
    except Exception:
        return platform.platform()


def safe_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


class SentinelApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("880x650")
        self.root.minsize(760, 560)

        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        logging.basicConfig(
            filename=str(LOG_PATH),
            level=logging.INFO,
            format="%(asctime)s %(levelname)s %(message)s",
            encoding="utf-8",
        )

        self.config = dict(DEFAULT_CONFIG)
        self._load_config()
        self.running = True
        self.monitoring = bool(self.config.get("watchdog_enabled", True))
        self.last_snapshot = "Not yet collected"
        self.snapshot_count = 0
        self.cpu_history: list[float] = []
        self.mem_history: list[float] = []
        self.process_rows: list[tuple] = []
        self._last_cpu = None

        # Non-blocking telemetry: background worker + pending metrics
        self._metrics_lock = threading.Lock()
        self._metrics_thread: Optional[threading.Thread] = None
        self._pending_metrics: Optional[dict[str, Any]] = None

        self.status_var = tk.StringVar(value="Starting monitor…")
        self.system_var = tk.StringVar(value="Collecting system information…")
        self.cpu_var = tk.StringVar(value="CPU: —")
        self.mem_var = tk.StringVar(value="Memory: —")
        self.disk_var = tk.StringVar(value="Disk: —")
        self.profile_var = tk.StringVar(value=self.config.get("profile", "Sentinel"))
        self.auto_refresh_var = tk.BooleanVar(value=bool(self.config.get("auto_refresh", True)))
        self.secure_var = tk.BooleanVar(value=bool(self.config.get("secure_mode", True)))
        self.watchdog_var = tk.BooleanVar(value=self.monitoring)

        self._build_ui()
        self._apply_theme()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.root.after(200, self.refresh_all)

    # ---------- Configuration and audit ----------
    def _load_config(self) -> None:
        if not CONFIG_PATH.exists():
            self._save_config()
            return
        try:
            loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                self.config.update(loaded)
        except Exception as exc:
            logging.exception("Config load failed")
            try:
                bad_path = CONFIG_PATH.with_suffix(".corrupt.json")
                shutil.copy2(CONFIG_PATH, bad_path)
            except Exception:
                pass
            messagebox.showwarning(
                "Configuration recovery",
                f"Could not read the saved configuration. Defaults will be used.\n\n{exc}",
            )

    def _save_config(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        temp = CONFIG_PATH.with_suffix(".tmp")
        temp.write_text(json.dumps(self.config, indent=2), encoding="utf-8")
        temp.replace(CONFIG_PATH)
        logging.info("Configuration saved")

    def audit(self, message: str) -> None:
        logging.info(message)
        if hasattr(self, "event_log"):
            stamp = datetime.now().strftime("%H:%M:%S")
            self.event_log.insert("end", f"[{stamp}] {message}\n")
            self.event_log.see("end")

    # ---------- UI ----------
    def _build_ui(self) -> None:
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass

        header = ttk.Frame(self.root, padding=(12, 10))
        header.pack(fill="x")
        ttk.Label(header, text="🧿 Codex Sentinel", font=("Segoe UI", 17, "bold")).pack(side="left")
        ttk.Label(header, text="Monitor • Profiles • Safe Registry Tools", font=("Segoe UI", 9)).pack(
            side="left", padx=14, pady=(5, 0)
        )
        ttk.Button(header, text="Save Config", command=self.save_config_clicked).pack(side="right")

        summary = ttk.Frame(self.root, padding=(12, 0, 12, 8))
        summary.pack(fill="x")
        ttk.Label(summary, textvariable=self.cpu_var, width=22).pack(side="left")
        ttk.Label(summary, textvariable=self.mem_var, width=22).pack(side="left")
        ttk.Label(summary, textvariable=self.disk_var, width=24).pack(side="left")
        ttk.Label(summary, textvariable=self.status_var).pack(side="right")

        self.tabs = ttk.Notebook(self.root)
        self.tabs.pack(fill="both", expand=True, padx=12, pady=6)

        self.dashboard_tab = ttk.Frame(self.tabs, padding=12)
        self.process_tab = ttk.Frame(self.tabs, padding=12)
        self.profile_tab = ttk.Frame(self.tabs, padding=12)
        self.registry_tab = ttk.Frame(self.tabs, padding=12)
        self.security_tab = ttk.Frame(self.tabs, padding=12)
        self.logs_tab = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.dashboard_tab, text="Dashboard")
        self.tabs.add(self.process_tab, text="Processes")
        self.tabs.add(self.profile_tab, text="Profiles")
        self.tabs.add(self.registry_tab, text="Registry Tools")
        self.tabs.add(self.security_tab, text="Safety & Controls")
        self.tabs.add(self.logs_tab, text="Event Log")

        self._build_dashboard()
        self._build_processes()
        self._build_profiles()
        self._build_registry()
        self._build_security()
        self._build_logs()

        footer = ttk.Frame(self.root, padding=(12, 3, 12, 9))
        footer.pack(fill="x")
        ttk.Label(
            footer,
            text="Hardware profiles are guidance only; no voltage, clock, or firmware changes are made.",
            foreground="#777777",
        ).pack(side="left")
        ttk.Button(footer, text="Open Config Folder", command=self.open_config_folder).pack(side="right")

    def _build_dashboard(self) -> None:
        ttk.Label(self.dashboard_tab, text="Live System Overview", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(self.dashboard_tab, textvariable=self.system_var, justify="left").pack(anchor="w", pady=(8, 12))

        controls = ttk.LabelFrame(self.dashboard_tab, text="Monitoring", padding=10)
        controls.pack(fill="x", pady=5)
        ttk.Checkbutton(
            controls, text="Automatic refresh", variable=self.auto_refresh_var, command=self.on_auto_refresh
        ).grid(row=0, column=0, sticky="w", padx=4, pady=4)
        ttk.Checkbutton(
            controls, text="Watchdog snapshots", variable=self.watchdog_var, command=self.on_watchdog
        ).grid(row=0, column=1, sticky="w", padx=12, pady=4)
        ttk.Button(controls, text="Refresh now", command=self.refresh_all).grid(row=0, column=2, padx=8)
        ttk.Button(controls, text="Open Windows Settings", command=self.open_windows_settings).grid(
            row=0, column=3, padx=8
        )

        stats = ttk.LabelFrame(self.dashboard_tab, text="Recent utilization samples", padding=10)
        stats.pack(fill="both", expand=True, pady=8)
        self.history_text = tk.Text(stats, height=9, wrap="none", state="disabled", font=("Consolas", 10))
        self.history_text.pack(fill="both", expand=True)

    def _build_processes(self) -> None:
        top = ttk.Frame(self.process_tab)
        top.pack(fill="x")
        ttk.Label(top, text="Running Processes", font=("Segoe UI", 13, "bold")).pack(side="left")
        ttk.Button(top, text="Refresh", command=self.refresh_processes).pack(side="right")
        ttk.Label(
            self.process_tab,
            text="Read-only process list. The app does not terminate processes automatically.",
        ).pack(anchor="w", pady=6)
        columns = ("pid", "name", "cpu", "memory", "status")
        self.process_tree = ttk.Treeview(self.process_tab, columns=columns, show="headings", height=18)
        for col, title, width in [
            ("pid", "PID", 80), ("name", "Process", 260), ("cpu", "CPU %", 90),
            ("memory", "Memory MB", 110), ("status", "Status", 150)
        ]:
            self.process_tree.heading(col, text=title)
            self.process_tree.column(col, width=width, anchor="w")
        ybar = ttk.Scrollbar(self.process_tab, orient="vertical", command=self.process_tree.yview)
        self.process_tree.configure(yscrollcommand=ybar.set)
        self.process_tree.pack(side="left", fill="both", expand=True)
        ybar.pack(side="right", fill="y")

    def _build_profiles(self) -> None:
        ttk.Label(self.profile_tab, text="Profiles & Tuning Envelopes", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(
            self.profile_tab,
            text=("Choose a monitoring/behavior preset. These presets do not overclock or undervolt hardware.\n"
                  "Actual GPU controls require vendor-specific APIs and supported hardware."),
            justify="left",
        ).pack(anchor="w", pady=7)

        row = ttk.Frame(self.profile_tab)
        row.pack(fill="x", pady=8)
        ttk.Label(row, text="Current profile:").pack(side="left")
        self.profile_combo = ttk.Combobox(
            row, textvariable=self.profile_var,
            values=("Sentinel", "Ritual", "Silent", "Diagnostics", "Gaming", "Power Saver"),
            state="readonly", width=20,
        )
        self.profile_combo.pack(side="left", padx=8)
        ttk.Button(row, text="Apply Profile", command=self.apply_selected_profile).pack(side="left", padx=8)

        self.profile_details = tk.Text(self.profile_tab, height=12, wrap="word", state="disabled")
        self.profile_details.pack(fill="both", expand=True, pady=8)
        self._show_profile_details(self.profile_var.get())

        ttk.Label(self.profile_tab, text="Refresh interval (milliseconds):").pack(anchor="w", pady=(8, 2))
        self.interval_var = tk.IntVar(value=safe_int(self.config.get("refresh_ms"), REFRESH_MS))
        ttk.Scale(
            self.profile_tab, from_=1000, to=10000, variable=self.interval_var,
            orient="horizontal", command=self._interval_changed,
        ).pack(fill="x")

    def _build_registry(self) -> None:
        ttk.Label(self.registry_tab, text="Per-user Explorer Settings", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(
            self.registry_tab,
            text=("Only the two listed HKCU values are handled here. A backup is created before changes "
                  "when enabled. Values may be absent on some Windows builds."),
            wraplength=760, justify="left",
        ).pack(anchor="w", pady=6)

        self.registry_tree = ttk.Treeview(
            self.registry_tab, columns=("name", "value", "type"), show="headings", height=8
        )
        for col, title, width in [("name", "Value name", 260), ("value", "Current value", 180), ("type", "Type", 120)]:
            self.registry_tree.heading(col, text=title)
            self.registry_tree.column(col, width=width, anchor="w")
        self.registry_tree.pack(fill="x", pady=6)

        btns = ttk.Frame(self.registry_tab)
        btns.pack(fill="x", pady=5)
        ttk.Button(btns, text="Read Current Values", command=self.refresh_registry).pack(side="left", padx=3)
        ttk.Button(btns, text="Enable Snap Assist Flyout", command=self.enable_snap_assist).pack(side="left", padx=3)
        ttk.Button(btns, text="Create Registry Backup", command=self.backup_registry).pack(side="left", padx=3)
        ttk.Button(btns, text="Restore Latest Backup", command=self.restore_registry).pack(side="left", padx=3)
        ttk.Label(
            self.registry_tab,
            text=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer",
        ).pack(anchor="w", pady=8)
        self.refresh_registry()

    def _build_security(self) -> None:
        ttk.Label(self.security_tab, text="Safety & Runtime Controls", font=("Segoe UI", 13, "bold")).pack(anchor="w")
        ttk.Label(self.security_tab, text=f"Operating system: {windows_version_text()}").pack(anchor="w", pady=4)
        ttk.Label(self.security_tab, text=f"Administrator privileges: {'Yes' if is_admin() else 'No'}").pack(anchor="w", pady=4)
        ttk.Label(self.security_tab, text=f"psutil telemetry: {'Available' if psutil else 'Not installed (basic mode)'}").pack(anchor="w", pady=4)
        ttk.Checkbutton(
            self.security_tab, text="Secure-mode UI flag (does not change Windows security policy)",
            variable=self.secure_var, command=self.on_secure_mode,
        ).pack(anchor="w", pady=8)
        ttk.Button(self.security_tab, text="Request Administrator Restart…", command=self.request_elevation).pack(anchor="w", pady=4)
        ttk.Button(self.security_tab, text="Export Diagnostics", command=self.export_diagnostics).pack(anchor="w", pady=4)
        ttk.Button(self.security_tab, text="Reset Preferences to Defaults", command=self.reset_preferences).pack(anchor="w", pady=4)
        ttk.Label(
            self.security_tab,
            text=("No automatic elevation, no automatic process termination, no telemetry suppression, "
                  "and no Group Policy edits. Registry changes require a button click."),
            wraplength=760, justify="left",
        ).pack(anchor="w", pady=12)

    def _build_logs(self) -> None:
        top = ttk.Frame(self.logs_tab)
        top.pack(fill="x")
        ttk.Label(top, text="Activity & Audit Log", font=("Segoe UI", 13, "bold")).pack(side="left")
        ttk.Button(top, text="Open Log File", command=self.open_log).pack(side="right")
        self.event_log = tk.Text(self.logs_tab, wrap="word", height=20, state="normal", font=("Consolas", 9))
        self.event_log.pack(fill="both", expand=True, pady=8)
        self.event_log.insert("end", "Sentinel started. Actions and errors are written to the log file.\n")

    # ---------- Theme ----------
    def _apply_theme(self) -> None:
        dark = self.config.get("theme", "Dark") == "Dark"
        if dark:
            bg, fg, field = "#1e1e1e", "#ffffff", "#252526"
            accent_sel = "#3a3f4b"
        else:
            bg, fg, field = "#f5f5f5", "#202020", "#ffffff"
            accent_sel = "#c0c8d0"
        try:
            self.root.configure(bg=bg)
            style = ttk.Style()
            style.configure(".", background=bg, foreground=fg, fieldbackground=field)
            style.configure("TFrame", background=bg)
            style.configure("TLabel", background=bg, foreground=fg)
            style.configure("TLabelframe", background=bg, foreground=fg)
            style.configure("TLabelframe.Label", background=bg, foreground=fg)
            style.configure("TNotebook", background=bg)
            style.configure("TNotebook.Tab", padding=(10, 5))
            style.configure(
                "Treeview",
                background=field,
                foreground=fg,
                fieldbackground=field,
            )
            style.map(
                "Treeview",
                background=[("selected", accent_sel)],
                foreground=[("selected", fg)],
            )

            for widget in (
                getattr(self, "history_text", None),
                getattr(self, "profile_details", None),
                getattr(self, "event_log", None),
            ):
                if isinstance(widget, tk.Text):
                    widget.configure(bg=field, fg=fg, insertbackground=fg)
        except tk.TclError:
            pass

    # ---------- Monitoring ----------
    def _system_metrics(self) -> dict[str, Any]:
        result: dict[str, Any] = {"cpu": None, "memory": None, "disk": None, "processes": []}
        if psutil:
            try:
                result["cpu"] = psutil.cpu_percent(interval=None)
                result["memory"] = psutil.virtual_memory().percent
                if is_windows():
                    drive = os.environ.get("SystemDrive", "C:")
                    result["disk"] = psutil.disk_usage(drive + "\\").percent
                else:
                    result["disk"] = psutil.disk_usage("/").percent
                procs = []
                for proc in psutil.process_iter(["pid", "name", "memory_info", "status", "cpu_percent"]):
                    try:
                        info = proc.info
                        mem = info.get("memory_info")
                        procs.append((
                            int(info.get("pid") or 0),
                            str(info.get("name") or "Unknown"),
                            float(info.get("cpu_percent") or 0.0),
                            (mem.rss / (1024 * 1024)) if mem else 0.0,
                            str(info.get("status") or "unknown"),
                        ))
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                result["processes"] = sorted(procs, key=lambda row: row[2], reverse=True)[:PROCESS_LIMIT]
            except Exception:
                logging.exception("System telemetry collection failed")
        return result

    def _collect_metrics_worker(self) -> None:
        metrics = self._system_metrics()
        with self._metrics_lock:
            self._pending_metrics = metrics
            self._metrics_thread = None

    def _apply_metrics(self, metrics: dict[str, Any]) -> None:
        cpu, mem, disk = metrics["cpu"], metrics["memory"], metrics["disk"]
        self.cpu_var.set(f"CPU: {cpu:.1f}%" if cpu is not None else "CPU: unavailable")
        self.mem_var.set(f"Memory: {mem:.1f}%" if mem is not None else "Memory: unavailable")
        self.disk_var.set(f"Disk: {disk:.1f}%" if disk is not None else "Disk: unavailable")
        self.system_var.set(
            f"OS: {windows_version_text()}\n"
            f"Python: {platform.python_version()}   |   Admin: {'Yes' if is_admin() else 'No'}\n"
            f"Profile: {self.config.get('profile')}   |   Monitor: {'Running' if self.monitoring else 'Paused'}\n"
            f"Last snapshot: {self.last_snapshot}   |   Snapshots: {self.snapshot_count}\n"
            f"Config: {CONFIG_PATH}"
        )
        if self.monitoring:
            self.snapshot_count += 1
            self.last_snapshot = datetime.now().strftime("%H:%M:%S")
            if cpu is not None:
                self.cpu_history.append(float(cpu))
                self.cpu_history = self.cpu_history[-30:]
            if mem is not None:
                self.mem_history.append(float(mem))
                self.mem_history = self.mem_history[-30:]
            self._render_history()
        self._render_processes(metrics["processes"])
        self.status_var.set("Monitoring" if self.monitoring else "Paused")
        if is_windows():
            self.refresh_registry()

    def refresh_all(self) -> None:
        if not self.running:
            return
        try:
            # Start background metrics collection if not already running
            with self._metrics_lock:
                if self._metrics_thread is None:
                    self._metrics_thread = threading.Thread(
                        target=self._collect_metrics_worker, daemon=True
                    )
                    self._metrics_thread.start()
                pending = self._pending_metrics
                self._pending_metrics = None

            # Apply metrics from last completed worker run
            if pending is not None:
                self._apply_metrics(pending)
        except Exception as exc:
            logging.exception("Refresh failed")
            self.status_var.set(f"Refresh error: {exc}")

        if self.auto_refresh_var.get():
            interval = max(1000, min(10000, safe_int(self.config.get("refresh_ms"), REFRESH_MS)))
            self.root.after(interval, self.refresh_all)

    def _render_history(self) -> None:
        if not hasattr(self, "history_text"):
            return
        lines = ["Sample  CPU %   Memory %", "------  -----   ---------"]
        count = max(len(self.cpu_history), len(self.mem_history))
        for i in range(count):
            cpu = self.cpu_history[i] if i < len(self.cpu_history) else 0.0
            mem = self.mem_history[i] if i < len(self.mem_history) else 0.0
            lines.append(f"{i + 1:>6}  {cpu:>5.1f}   {mem:>8.1f}")
        self.history_text.configure(state="normal")
        self.history_text.delete("1.0", "end")
        self.history_text.insert("end", "\n".join(lines))
        self.history_text.configure(state="disabled")

    def _render_processes(self, rows: list[tuple]) -> None:
        if not hasattr(self, "process_tree"):
            return
        self.process_tree.delete(*self.process_tree.get_children())
        for row in rows:
            self.process_tree.insert("", "end", values=(
                row[0], row[1][:60], f"{row[2]:.1f}", f"{row[3]:.1f}", row[4]
            ))

    def refresh_processes(self) -> None:
        metrics = self._system_metrics()
        self._render_processes(metrics["processes"])
        self.audit("Process list refreshed")

    # ---------- Profiles ----------
    def _profile_values(self, name: str) -> tuple[str, str, str, str]:
        profiles = {
            "Sentinel": ("Balanced", "Sentinel (monitor only)", "Normal", "Balanced monitoring; safety-focused defaults."),
            "Ritual": ("Responsive (app preset)", "Sentinel (monitor only)", "Normal", "Responsive UI preset; no CPU/GPU clocks are changed."),
            "Silent": ("Low-impact (app preset)", "Cool (monitor only)", "Gentle", "Lower refresh activity when you prefer a quieter dashboard."),
            "Diagnostics": ("Diagnostics", "Diagnostics (monitor only)", "Trace", "Detailed monitoring and audit logging."),
            "Gaming": ("Avoid background work", "Monitor only", "Normal", "Keeps this dashboard lightweight; does not tune a game or GPU."),
            "Power Saver": ("Low-impact (app preset)", "Monitor only", "Gentle", "Lightweight monitoring; Windows power mode remains unchanged."),
        }
        return profiles.get(name, profiles["Sentinel"])

    def _show_profile_details(self, name: str) -> None:
        if not hasattr(self, "profile_details"):
            return
        cpu, gpu, io, desc = self._profile_values(name)
        content = (
            f"Profile: {name}\n\n{desc}\n\n"
            f"CPU envelope: {cpu}\nGPU envelope: {gpu}\nI/O envelope: {io}\n\n"
            "These are app-side labels and monitoring preferences, not direct hardware controls."
        )
        self.profile_details.configure(state="normal")
        self.profile_details.delete("1.0", "end")
        self.profile_details.insert("end", content)
        self.profile_details.configure(state="disabled")

    def apply_selected_profile(self) -> None:
        name = self.profile_var.get()
        cpu, gpu, io, _ = self._profile_values(name)
        self.config.update({"profile": name, "cpu_envelope": cpu, "gpu_envelope": gpu, "io_envelope": io})
        if name == "Silent":
            self.config["refresh_ms"] = 5000
            self.interval_var.set(5000)
        elif name == "Diagnostics":
            self.config["refresh_ms"] = 1500
            self.interval_var.set(1500)
        elif name == "Gaming":
            self.config["refresh_ms"] = 4000
            self.interval_var.set(4000)
        self._show_profile_details(name)
        self._save_config()
        self.audit(f"Profile applied: {name}")
        self.status_var.set(f"Profile: {name}")

    def _interval_changed(self, _value: str) -> None:
        self.config["refresh_ms"] = max(1000, min(10000, safe_int(self.interval_var.get(), REFRESH_MS)))

    # ---------- Registry backup / restore ----------
    @property
    def explorer_key_path(self) -> str:
        return r"Software\Microsoft\Windows\CurrentVersion\Explorer"

    def _registry_items(self) -> list[dict[str, Any]]:
        if not is_windows():
            return []
        result = []
        for name in ("EnableSnapAssistFlyout", "ShowRecent"):
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.explorer_key_path, 0, winreg.KEY_READ) as key:
                    value, value_type = winreg.QueryValueEx(key, name)
                result.append({"name": name, "exists": True, "value": value, "type": value_type})
            except FileNotFoundError:
                result.append({"name": name, "exists": False, "value": None, "type": None})
            except OSError:
                result.append({"name": name, "exists": False, "value": None, "type": None})
        return result

    def refresh_registry(self) -> None:
        if not hasattr(self, "registry_tree"):
            return
        self.registry_tree.delete(*self.registry_tree.get_children())
        if not is_windows():
            self.registry_tree.insert("", "end", values=("Windows-only", "Registry unavailable", "N/A"))
            return
        for item in self._registry_items():
            value = item["value"] if item["exists"] else "Not set"
            type_name = {
                winreg.REG_DWORD: "REG_DWORD",
                winreg.REG_SZ: "REG_SZ",
            }.get(item["type"], str(item["type"]) if item["type"] else "—")
            self.registry_tree.insert("", "end", values=(item["name"], value, type_name))

    def backup_registry(self) -> Optional[Path]:
        if not is_windows():
            messagebox.showwarning("Windows only", "Registry backup is available only on Windows.")
            return None
        payload = {
            "created": datetime.now().isoformat(timespec="seconds"),
            "root": "HKEY_CURRENT_USER",
            "path": self.explorer_key_path,
            "values": self._registry_items(),
        }
        path = BACKUP_DIR / f"registry_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        try:
            path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
            self.config["last_registry_backup"] = str(path)
            self._save_config()
            self.audit(f"Registry backup created: {path}")
            messagebox.showinfo("Backup created", f"Registry values backed up to:\n{path}")
            return path
        except Exception as exc:
            logging.exception("Registry backup failed")
            messagebox.showerror("Backup failed", str(exc))
            return None

    def _latest_backup(self) -> Optional[Path]:
        configured = self.config.get("last_registry_backup")
        if configured and Path(configured).exists():
            return Path(configured)
        backups = sorted(BACKUP_DIR.glob("registry_backup_*.json"), reverse=True)
        return backups[0] if backups else None

    def enable_snap_assist(self) -> None:
        if not is_windows():
            messagebox.showwarning("Windows only", "This setting is available only on Windows.")
            return
        if not messagebox.askyesno(
            "Confirm Registry Change",
            "Set HKCU Explorer\\EnableSnapAssistFlyout to DWORD 1?\n\nA backup will be created first.",
        ):
            return
        if self.config.get("registry_backup_before_change", True):
            if self.backup_registry() is None:
                return
        try:
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, self.explorer_key_path, 0, winreg.KEY_SET_VALUE
            ) as key:
                winreg.SetValueEx(key, "EnableSnapAssistFlyout", 0, winreg.REG_DWORD, 1)
            self.audit("Set EnableSnapAssistFlyout=1")
            self.refresh_registry()
            messagebox.showinfo(
                "Registry updated",
                "The per-user value was set. Windows may require Explorer sign-out/restart to reflect some changes.",
            )
        except Exception as exc:
            logging.exception("Registry update failed")
            messagebox.showerror("Registry update failed", str(exc))

    def restore_registry(self) -> None:
        if not is_windows():
            messagebox.showwarning("Windows only", "Registry restore is available only on Windows.")
            return
        backup = self._latest_backup()
        if not backup:
            messagebox.showwarning("No backup", "No Sentinel registry backup was found.")
            return
        if not messagebox.askyesno(
            "Confirm Restore",
            f"Restore the two tracked values from:\n{backup}\n\nThis may overwrite current values.",
        ):
            return
        try:
            data = json.loads(backup.read_text(encoding="utf-8"))
            if data.get("path") != self.explorer_key_path:
                raise ValueError("Backup registry path did not match the expected Explorer key.")
            with winreg.CreateKeyEx(
                winreg.HKEY_CURRENT_USER, self.explorer_key_path, 0, winreg.KEY_SET_VALUE
            ) as key:
                for item in data.get("values", []):
                    name = item.get("name")
                    if name not in ("EnableSnapAssistFlyout", "ShowRecent"):
                        continue
                    if item.get("exists"):
                        value_type = item.get("type")
                        value = item.get("value")
                        if value_type in (
                            winreg.REG_DWORD,
                            winreg.REG_SZ,
                            winreg.REG_QWORD,
                            winreg.REG_BINARY,
                        ):
                            winreg.SetValueEx(key, name, 0, value_type, value)
                    else:
                        try:
                            winreg.DeleteValue(key, name)
                        except OSError:
                            pass
            self.audit(f"Registry restored from backup: {backup}")
            self.refresh_registry()
            messagebox.showinfo("Registry restored", "Tracked Explorer values were restored from the latest backup.")
        except Exception as exc:
            logging.exception("Registry restore failed")
            messagebox.showerror("Registry restore failed", str(exc))

    # ---------- Safety & controls ----------
    def open_config_folder(self) -> None:
        try:
            if not CONFIG_DIR.exists():
                CONFIG_DIR.mkdir(parents=True, exist_ok=True)
            if is_windows():
                os.startfile(str(CONFIG_DIR))
            else:
                subprocess.Popen(["xdg-open", str(CONFIG_DIR)])
            self.audit("Config folder opened")
        except Exception as exc:
            logging.exception("Open config folder failed")
            messagebox.showerror("Open folder failed", str(exc))

    def open_log(self) -> None:
        try:
            if not LOG_PATH.exists():
                LOG_PATH.touch()
            if is_windows():
                os.startfile(str(LOG_PATH))
            else:
                subprocess.Popen(["xdg-open", str(LOG_PATH)])
            self.audit("Log file opened")
        except Exception as exc:
            logging.exception("Open log failed")
            messagebox.showerror("Open log failed", str(exc))

    def export_diagnostics(self) -> None:
        try:
            payload = {
                "timestamp": datetime.now().isoformat(timespec="seconds"),
                "os": windows_version_text(),
                "python": platform.python_version(),
                "admin": is_admin(),
                "config_path": str(CONFIG_PATH),
                "log_path": str(LOG_PATH),
                "profile": self.config.get("profile"),
                "refresh_ms": self.config.get("refresh_ms"),
                "secure_mode": self.config.get("secure_mode"),
                "watchdog_enabled": self.config.get("watchdog_enabled"),
                "auto_refresh": self.config.get("auto_refresh"),
            }
            dest = filedialog.asksaveasfilename(
                title="Export Diagnostics",
                defaultextension=".json",
                filetypes=[("JSON files", "*.json"), ("All files", "*.*")],
                initialfile=f"sentinel_diagnostics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            )
            if not dest:
                return
            Path(dest).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            self.audit(f"Diagnostics exported to {dest}")
            messagebox.showinfo("Diagnostics exported", f"Diagnostics written to:\n{dest}")
        except Exception as exc:
            logging.exception("Diagnostics export failed")
            messagebox.showerror("Diagnostics export failed", str(exc))

    def request_elevation(self) -> None:
        if not is_windows():
            messagebox.showwarning("Windows only", "Elevation restart is available only on Windows.")
            return
        if not messagebox.askyesno(
            "Restart as Administrator",
            "Restart Codex Sentinel with administrator privileges?\n\n"
            "This does not change Windows security policy; it only elevates this app.",
        ):
            return
        try:
            params = " ".join(f'"{arg}"' for arg in sys.argv)
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                params,
                None,
                1,
            )
            self.audit("Elevation restart requested")
            self.running = False
            self.root.destroy()
        except Exception as exc:
            logging.exception("Elevation restart failed")
            messagebox.showerror("Elevation failed", str(exc))

    def reset_preferences(self) -> None:
        if not messagebox.askyesno(
            "Reset Preferences",
            "Reset Sentinel preferences to factory defaults?\n\nThis does not touch Windows settings.",
        ):
            return
        try:
            self.config = dict(DEFAULT_CONFIG)
            self._save_config()
            self.profile_var.set(self.config["profile"])
            self.auto_refresh_var.set(self.config["auto_refresh"])
            self.secure_var.set(self.config["secure_mode"])
            self.watchdog_var.set(self.config["watchdog_enabled"])
            self.interval_var.set(self.config["refresh_ms"])
            self._show_profile_details(self.config["profile"])
            self._apply_theme()
            self.audit("Preferences reset to defaults")
            messagebox.showinfo("Preferences reset", "Sentinel preferences were reset to defaults.")
        except Exception as exc:
            logging.exception("Reset preferences failed")
            messagebox.showerror("Reset failed", str(exc))

    def on_secure_mode(self) -> None:
        self.config["secure_mode"] = bool(self.secure_var.get())
        self._save_config()
        self.audit(f"Secure-mode flag set to {self.config['secure_mode']}")

    def on_auto_refresh(self) -> None:
        self.config["auto_refresh"] = bool(self.auto_refresh_var.get())
        self._save_config()
        self.audit(f"Auto-refresh set to {self.config['auto_refresh']}")
        if self.auto_refresh_var.get():
            self.root.after(
                max(1000, min(10000, safe_int(self.config.get("refresh_ms"), REFRESH_MS))),
                self.refresh_all,
            )

    def on_watchdog(self) -> None:
        self.monitoring = bool(self.watchdog_var.get())
        self.config["watchdog_enabled"] = self.monitoring
        self._save_config()
        self.audit(f"Watchdog monitoring set to {self.monitoring}")
        self.status_var.set("Monitoring" if self.monitoring else "Paused")

    def open_windows_settings(self) -> None:
        if not is_windows():
            messagebox.showwarning("Windows only", "Windows Settings shortcut is available only on Windows.")
            return
        try:
            subprocess.Popen(["start", "ms-settings:"], shell=True)
            self.audit("Windows Settings opened")
        except Exception as exc:
            logging.exception("Open Windows Settings failed")
            messagebox.showerror("Open Settings failed", str(exc))

    def save_config_clicked(self) -> None:
        try:
            self._save_config()
            self.audit("Configuration saved via button")
            self.status_var.set("Configuration saved")
        except Exception as exc:
            logging.exception("Manual save config failed")
            messagebox.showerror("Save failed", str(exc))

    def on_close(self) -> None:
        self.running = False
        try:
            self._save_config()
        except Exception:
            pass
        self.audit("Sentinel closed")
        self.root.destroy()


def main() -> None:
    root = tk.Tk()
    app = SentinelApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
