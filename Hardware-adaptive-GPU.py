"""
Universal GPU Control Center for Windows
----------------------------------------
Hardware-adaptive GPU monitor/control GUI.

Supported detection:
  - NVIDIA: nvidia-smi (when installed)
  - AMD: WMI/PowerShell display adapter detection
  - Intel: WMI/PowerShell display adapter detection

Important:
  This program intentionally does NOT perform arbitrary GPU register/VBIOS
  writes or undocumented VRAM timing/strap writes. Those operations are
  hardware/firmware-specific and can permanently damage hardware or prevent
  booting. The Timing page reports whether such controls are exposed, and
  supported clock/power controls are delegated to vendor tools where safely
  available.

Requirements:
  Python 3.10+
  tkinter (normally included with Windows Python)

Optional:
  NVIDIA driver + nvidia-smi
  PowerShell (included with Windows)

Run:
  python universal_gpu_control_center.py
"""

from __future__ import annotations

import csv
import json
import os
import platform
import shutil
import subprocess
import threading
import time
import tkinter as tk
from dataclasses import dataclass, asdict, field
from pathlib import Path
from tkinter import filedialog, messagebox, ttk


APP_NAME = "Universal GPU Control Center"
PROFILE_DIR = Path.home() / "GPUControlCenter"
PROFILE_DIR.mkdir(parents=True, exist_ok=True)


@dataclass
class GPU:
    index: int
    name: str
    vendor: str
    driver: str = "Unknown"
    memory_mb: int = 0
    device_id: str = ""
    pnp_id: str = ""
    temperature_c: float | None = None
    utilization_pct: float | None = None
    memory_used_mb: float | None = None
    memory_total_mb: float | None = None
    core_clock_mhz: float | None = None
    memory_clock_mhz: float | None = None
    power_w: float | None = None
    power_limit_w: float | None = None
    fan_pct: float | None = None
    controls: dict = field(default_factory=dict)


def run_cmd(args, timeout=4):
    try:
        p = subprocess.run(
            args,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        return p.returncode, p.stdout.strip(), p.stderr.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return -1, "", ""


def powershell(script, timeout=6):
    exe = shutil.which("powershell") or shutil.which("pwsh")
    if not exe:
        return ""
    rc, out, _ = run_cmd(
        [exe, "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script],
        timeout,
    )
    return out if rc == 0 else ""


def detect_windows_adapters():
    # WMI/CIM gives broad cross-vendor identification without vendor SDKs.
    script = r"""
$ErrorActionPreference='SilentlyContinue'
Get-CimInstance Win32_VideoController |
Select-Object Name,PNPDeviceID,AdapterCompatibility,DriverVersion,
AdapterRAM,VideoProcessor |
ConvertTo-Json -Compress
"""
    raw = powershell(script)
    if not raw:
        return []
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []
    if isinstance(data, dict):
        data = [data]
    return data


def detect_nvidia():
    exe = shutil.which("nvidia-smi")
    if not exe:
        # Common installation path fallback.
        candidates = [
            r"C:\Windows\System32\nvidia-smi.exe",
            r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe",
        ]
        exe = next((x for x in candidates if os.path.exists(x)), None)
    if not exe:
        return []

    query = (
        "index,name,driver_version,memory.total,memory.used,"
        "temperature.gpu,utilization.gpu,clocks.gr,clocks.mem,"
        "power.draw,power.limit,fan.speed,pci.device"
    )
    rc, out, _ = run_cmd(
        [exe, f"--query-gpu={query}", "--format=csv,noheader,nounits"], timeout=6
    )
    if rc != 0:
        return []

    result = []
    for row in csv.reader(out.splitlines()):
        if len(row) < 13:
            continue
        try:
            def num(i):
                try:
                    return float(row[i].strip())
                except Exception:
                    return None

            result.append(
                GPU(
                    index=int(row[0].strip()),
                    name=row[1].strip(),
                    vendor="NVIDIA",
                    driver=row[2].strip(),
                    memory_mb=int(num(3) or 0),
                    memory_total_mb=num(3),
                    memory_used_mb=num(4),
                    temperature_c=num(5),
                    utilization_pct=num(6),
                    core_clock_mhz=num(7),
                    memory_clock_mhz=num(8),
                    power_w=num(9),
                    power_limit_w=num(10),
                    fan_pct=num(11),
                    device_id=row[12].strip(),
                    controls={
                        "telemetry": True,
                        "power_limit": True,
                        "core_clock_offset": False,
                        "memory_clock_offset": False,
                        "fan_control": False,
                        "voltage": False,
                        "memory_timings": False,
                        "vbios_write": False,
                    },
                )
            )
        except Exception:
            continue
    return result


def classify_vendor(name, compatibility=""):
    text = f"{name} {compatibility}".lower()
    if "nvidia" in text:
        return "NVIDIA"
    if "amd" in text or "advanced micro devices" in text or "radeon" in text:
        return "AMD"
    if "intel" in text:
        return "Intel"
    return "Other"


def detect_gpus():
    # Prefer nvidia-smi for NVIDIA telemetry.
    gpus = detect_nvidia()
    seen = {g.name.lower() for g in gpus}

    adapters = detect_windows_adapters()
    next_index = max([g.index for g in gpus], default=-1) + 1

    for a in adapters:
        name = str(a.get("Name") or "Unknown GPU")
        vendor = classify_vendor(name, str(a.get("AdapterCompatibility") or ""))

        if name.lower() in seen:
            continue

        ram = a.get("AdapterRAM") or 0
        try:
            ram_mb = int(ram) // (1024 * 1024)
        except Exception:
            ram_mb = 0

        g = GPU(
            index=next_index,
            name=name,
            vendor=vendor,
            driver=str(a.get("DriverVersion") or "Unknown"),
            memory_mb=ram_mb,
            device_id=str(a.get("PNPDeviceID") or ""),
            pnp_id=str(a.get("PNPDeviceID") or ""),
            controls={
                "telemetry": True,
                "power_limit": False,
                "core_clock_offset": False,
                "memory_clock_offset": False,
                "fan_control": False,
                "voltage": False,
                "memory_timings": False,
                "vbios_write": False,
            },
        )
        gpus.append(g)
        next_index += 1

    return gpus


class VendorBackend:
    """Safe capability/telemetry abstraction.

    Backends deliberately expose only operations that can be implemented
    through supported vendor interfaces. Unsupported controls are rejected.
    """

    def __init__(self, gpu: GPU):
        self.gpu = gpu

    def set_power_limit(self, watts: float):
        raise NotImplementedError("No safe generic power-limit interface.")

    def set_clock_offset(self, core: int, memory: int):
        raise NotImplementedError("No safe generic clock-offset interface.")

    def set_fan(self, percent: int):
        raise NotImplementedError("No safe generic fan interface.")

    def refresh(self):
        return self.gpu


class NvidiaBackend(VendorBackend):
    def __init__(self, gpu):
        super().__init__(gpu)
        self.exe = shutil.which("nvidia-smi") or (
            r"C:\Program Files\NVIDIA Corporation\NVSMI\nvidia-smi.exe"
        )

    def set_power_limit(self, watts: float):
        if not os.path.exists(self.exe) and not shutil.which(self.exe):
            raise RuntimeError("nvidia-smi was not found.")
        if watts <= 0:
            raise ValueError("Power limit must be positive.")
        rc, out, err = run_cmd(
            [self.exe, "-i", str(self.gpu.index), "-pl", str(int(watts))], timeout=5
        )
        if rc != 0:
            raise RuntimeError(err or out or "nvidia-smi rejected the power limit.")
        return out or "Power limit applied."

    def refresh(self):
        latest = detect_nvidia()
        for g in latest:
            if g.index == self.gpu.index:
                self.gpu = g
                break
        return self.gpu


class GenericBackend(VendorBackend):
    pass


def backend_for(gpu):
    return NvidiaBackend(gpu) if gpu.vendor == "NVIDIA" else GenericBackend(gpu)


class App(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1180x760")
        self.minsize(960, 620)

        self.gpus = []
        self.selected_gpu: GPU | None = None
        self.backend: VendorBackend | None = None
        self.monitoring = False
        self.monitor_thread = None
        self.profile_vars = {}

        self._build_ui()
        self.after(100, self.detect)

    def _build_ui(self):
        top = ttk.Frame(self, padding=10)
        top.pack(fill="x")

        ttk.Label(top, text=APP_NAME, font=("Segoe UI", 18, "bold")).pack(
            side="left"
        )

        ttk.Button(top, text="Detect GPUs", command=self.detect).pack(side="right")
        ttk.Button(top, text="Export Report", command=self.export_report).pack(
            side="right", padx=6
        )

        self.gpu_combo = ttk.Combobox(top, state="readonly", width=42)
        self.gpu_combo.pack(side="right", padx=10)
        self.gpu_combo.bind("<<ComboboxSelected>>", self.select_gpu)

        self.status = tk.StringVar(value="Detecting hardware...")
        ttk.Label(self, textvariable=self.status, padding=(10, 0)).pack(fill="x")

        self.notebook = ttk.Notebook(self)
        self.notebook.pack(fill="both", expand=True, padx=10, pady=10)

        self.info_tab = ttk.Frame(self.notebook, padding=15)
        self.monitor_tab = ttk.Frame(self.notebook, padding=15)
        self.control_tab = ttk.Frame(self.notebook, padding=15)
        self.timing_tab = ttk.Frame(self.notebook, padding=15)
        self.profile_tab = ttk.Frame(self.notebook, padding=15)
        self.log_tab = ttk.Frame(self.notebook, padding=15)

        for tab, title in [
            (self.info_tab, "GPU Information"),
            (self.monitor_tab, "Live Monitor"),
            (self.control_tab, "Controls"),
            (self.timing_tab, "Memory / Timings"),
            (self.profile_tab, "Profiles"),
            (self.log_tab, "Diagnostics"),
        ]:
            self.notebook.add(tab, text=title)

        self._build_info()
        self._build_monitor()
        self._build_controls()
        self._build_timings()
        self._build_profiles()
        self._build_log()

    def _build_info(self):
        self.info = ttk.Treeview(
            self.info_tab, columns=("value",), show="tree headings", height=18
        )
        self.info.heading("#0", text="Property")
        self.info.heading("value", text="Value")
        self.info.column("#0", width=270)
        self.info.column("value", width=650)
        self.info.pack(fill="both", expand=True)

    def _build_monitor(self):
        self.monitor_text = tk.Text(
            self.monitor_tab, wrap="word", state="disabled", font=("Consolas", 11)
        )
        self.monitor_text.pack(fill="both", expand=True)

        bar = ttk.Frame(self.monitor_tab)
        bar.pack(fill="x", pady=(10, 0))
        self.monitor_button = ttk.Button(
            bar, text="Start Monitoring", command=self.toggle_monitor
        )
        self.monitor_button.pack(side="left")

    def _build_controls(self):
        frame = ttk.Frame(self.control_tab)
        frame.pack(fill="x")

        self.control_status = tk.StringVar(
            value="Select a GPU to see supported controls."
        )
        ttk.Label(
            frame, textvariable=self.control_status, wraplength=900
        ).pack(anchor="w", pady=(0, 15))

        power = ttk.LabelFrame(frame, text="Power Limit", padding=12)
        power.pack(fill="x", pady=6)

        self.power_var = tk.StringVar()
        ttk.Label(power, text="Watts:").pack(side="left")
        ttk.Entry(power, textvariable=self.power_var, width=12).pack(
            side="left", padx=8
        )
        self.power_button = ttk.Button(
            power, text="Apply", command=self.apply_power
        )
        self.power_button.pack(side="left")

        clock = ttk.LabelFrame(frame, text="Clock Offsets", padding=12)
        clock.pack(fill="x", pady=6)

        self.core_var = tk.StringVar(value="0")
        self.mem_var = tk.StringVar(value="0")

        ttk.Label(clock, text="Core offset (MHz):").pack(side="left")
        ttk.Entry(clock, textvariable=self.core_var, width=10).pack(
            side="left", padx=6
        )
        ttk.Label(clock, text="Memory offset (MHz):").pack(side="left")
        ttk.Entry(clock, textvariable=self.mem_var, width=10).pack(
            side="left", padx=6
        )

        self.clock_button = ttk.Button(
            clock, text="Apply", command=self.apply_clocks
        )
        self.clock_button.pack(side="left", padx=8)

        fan = ttk.LabelFrame(frame, text="Fan", padding=12)
        fan.pack(fill="x", pady=6)

        self.fan_var = tk.StringVar(value="Auto")
        ttk.Label(fan, text="Mode:").pack(side="left")
        self.fan_combo = ttk.Combobox(
            fan,
            textvariable=self.fan_var,
            values=["Auto", "25", "50", "75", "100"],
            state="readonly",
            width=10,
        )
        self.fan_combo.pack(side="left", padx=8)

        self.fan_button = ttk.Button(
            fan, text="Apply", command=self.apply_fan
        )
        self.fan_button.pack(side="left")

        ttk.Label(
            frame,
            text=(
                "Unsupported controls are intentionally disabled. "
                "This application does not perform arbitrary register or "
                "VBIOS writes."
            ),
            wraplength=900,
        ).pack(anchor="w", pady=20)

    def _build_timings(self):
        ttk.Label(
            self.timing_tab,
            text="Memory Timing Capability",
            font=("Segoe UI", 14, "bold"),
        ).pack(anchor="w")

        self.timing_tree = ttk.Treeview(
            self.timing_tab, columns=("value", "status"), show="headings"
        )
        self.timing_tree.heading("value", text="Value")
        self.timing_tree.heading("status", text="Status")
        self.timing_tree.pack(fill="both", expand=True, pady=10)

        ttk.Label(
            self.timing_tab,
            text=(
                "VRAM timing/strap editing is not a universal GPU setting. "
                "It depends on the GPU generation, firmware and vendor tools. "
                "The program therefore reports availability instead of writing "
                "undocumented registers."
            ),
            wraplength=950,
        ).pack(anchor="w")

    def _build_profiles(self):
        top = ttk.Frame(self.profile_tab)
        top.pack(fill="x")

        ttk.Button(top, text="Save Profile", command=self.save_profile).pack(
            side="left"
        )
        ttk.Button(top, text="Load Profile", command=self.load_profile).pack(
            side="left", padx=6
        )
        ttk.Button(top, text="Reset Fields", command=self.reset_fields).pack(
            side="left"
        )

        self.profile_text = tk.Text(
            self.profile_tab, height=18, font=("Consolas", 10)
        )
        self.profile_text.pack(fill="both", expand=True, pady=12)

    def _build_log(self):
        self.log_text = tk.Text(
            self.log_tab, wrap="word", state="disabled", font=("Consolas", 10)
        )
        self.log_text.pack(fill="both", expand=True)

    def log(self, message):
        stamp = time.strftime("%H:%M:%S")
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{stamp}] {message}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def detect(self):
        self.status.set("Detecting GPUs...")
        self.log("Starting hardware detection.")

        def worker():
            gpus = detect_gpus()
            self.after(0, lambda: self._finish_detection(gpus))

        threading.Thread(target=worker, daemon=True).start()

    def _finish_detection(self, gpus):
        self.gpus = gpus
        self.gpu_combo["values"] = [
            f"GPU {g.index}: {g.vendor} — {g.name}" for g in gpus
        ]

        if gpus:
            self.gpu_combo.current(0)
            self.select_gpu()
            self.status.set(f"Detected {len(gpus)} GPU(s).")
            self.log(f"Detected {len(gpus)} GPU(s).")
        else:
            self.status.set("No GPU could be identified.")
            self.log("No GPU detected through available Windows interfaces.")
            self.clear_ui()

    def select_gpu(self, event=None):
        if not self.gpus:
            return
        idx = self.gpu_combo.current()
        if idx < 0:
            return

        self.selected_gpu = self.gpus[idx]
        self.backend = backend_for(self.selected_gpu)

        self.update_info()
        self.update_controls()
        self.update_timings()
        self.log(
            f"Selected GPU {self.selected_gpu.index}: "
            f"{self.selected_gpu.vendor} {self.selected_gpu.name}"
        )

    def clear_ui(self):
        for tree in (self.info, self.timing_tree):
            for item in tree.get_children():
                tree.delete(item)

    def update_info(self):
        for item in self.info.get_children():
            self.info.delete(item)

        g = self.selected_gpu
        if not g:
            return

        values = [
            ("Name", g.name),
            ("Vendor", g.vendor),
            ("Driver", g.driver),
            ("VRAM", f"{g.memory_mb:,} MB" if g.memory_mb else "Unknown"),
            ("Device ID", g.device_id or "Unknown"),
            ("Temperature", self.fmt(g.temperature_c, " °C")),
            ("GPU Utilization", self.fmt(g.utilization_pct, " %")),
            ("VRAM Used", self.fmt(g.memory_used_mb, " MB")),
            ("Core Clock", self.fmt(g.core_clock_mhz, " MHz")),
            ("Memory Clock", self.fmt(g.memory_clock_mhz, " MHz")),
            ("Power", self.fmt(g.power_w, " W")),
            ("Power Limit", self.fmt(g.power_limit_w, " W")),
            ("Fan", self.fmt(g.fan_pct, " %")),
        ]

        for k, v in values:
            self.info.insert("", "end", text=k, values=(v,))

    @staticmethod
    def fmt(value, suffix=""):
        return "Unknown" if value is None else f"{value:g}{suffix}"

    def update_controls(self):
        g = self.selected_gpu
        if not g:
            return

        controls = g.controls
        self.power_button.configure(
            state="normal" if controls.get("power_limit") else "disabled"
        )
        self.clock_button.configure(
            state="normal"
            if controls.get("core_clock_offset") or controls.get("memory_clock_offset")
            else "disabled"
        )
        self.fan_button.configure(
            state="normal" if controls.get("fan_control") else "disabled"
        )

        supported = [
            name.replace("_", " ").title()
            for name, value in controls.items()
            if value
        ]
        self.control_status.set(
            f"{g.vendor} / {g.name}\n"
            f"Supported interfaces: {', '.join(supported) or 'telemetry only'}"
        )

    def update_timings(self):
        for item in self.timing_tree.get_children():
            self.timing_tree.delete(item)

        g = self.selected_gpu
        if not g:
            return

        entries = [
            ("Memory clock", self.fmt(g.memory_clock_mhz, " MHz"), "Read-only telemetry"),
            ("Memory timing control", "", "Not exposed by generic Windows interface"),
            ("Timing/strap registers", "", "Not supported by this safe generic backend"),
            ("VBIOS timing modification", "", "Disabled"),
        ]

        if g.controls.get("memory_timings"):
            entries[1] = (
                "Memory timing control",
                "Vendor interface available",
                "Supported backend",
            )

        for a, b, c in entries:
            self.timing_tree.insert("", "end", values=(f"{a}: {b}", c))

    def apply_power(self):
        if not self.backend or not self.selected_gpu:
            return
        try:
            value = float(self.power_var.get())
            result = self.backend.set_power_limit(value)
            self.log(result)
            self.status.set("Power-limit request completed.")
        except Exception as e:
            self.log(f"Power-limit change rejected: {e}")
            messagebox.showwarning("Unsupported / rejected", str(e))

    def apply_clocks(self):
        messagebox.showinfo(
            "Vendor-specific control",
            "Clock-offset control is not exposed by the generic backend. "
            "A vendor-specific backend must be implemented for this GPU."
        )
        self.log("Clock-offset request not applied.")

    def apply_fan(self):
        messagebox.showinfo(
            "Vendor-specific control",
            "Fan control is not exposed by the generic backend for this GPU."
        )
        self.log("Fan-control request not applied.")

    def toggle_monitor(self):
        if self.monitoring:
            self.monitoring = False
            self.monitor_button.configure(text="Start Monitoring")
            self.log("Monitoring stopped.")
        else:
            if not self.selected_gpu:
                return
            self.monitoring = True
            self.monitor_button.configure(text="Stop Monitoring")
            self.log("Monitoring started.")
            self.after(100, self.monitor_tick)

    def monitor_tick(self):
        if not self.monitoring or not self.backend:
            return

        def worker():
            try:
                g = self.backend.refresh()
                self.after(0, lambda: self.update_live(g))
            except Exception as e:
                self.after(0, lambda: self.log(f"Monitor error: {e}"))

        threading.Thread(target=worker, daemon=True).start()
        self.after(1000, self.monitor_tick)

    def update_live(self, g):
        self.selected_gpu = g
        self.update_info()

        lines = [
            f"GPU: {g.name}",
            f"Vendor: {g.vendor}",
            "",
            f"Temperature : {self.fmt(g.temperature_c, ' °C')}",
            f"GPU Load    : {self.fmt(g.utilization_pct, ' %')}",
            f"VRAM Used   : {self.fmt(g.memory_used_mb, ' MB')}",
            f"VRAM Total  : {self.fmt(g.memory_total_mb, ' MB')}",
            f"Core Clock  : {self.fmt(g.core_clock_mhz, ' MHz')}",
            f"Memory Clock: {self.fmt(g.memory_clock_mhz, ' MHz')}",
            f"Power       : {self.fmt(g.power_w, ' W')}",
            f"Power Limit : {self.fmt(g.power_limit_w, ' W')}",
            f"Fan         : {self.fmt(g.fan_pct, ' %')}",
            "",
            "Safety state: arbitrary register/VBIOS writes disabled.",
        ]

        self.monitor_text.configure(state="normal")
        self.monitor_text.delete("1.0", "end")
        self.monitor_text.insert("end", "\n".join(lines))
        self.monitor_text.configure(state="disabled")

    def reset_fields(self):
        self.power_var.set("")
        self.core_var.set("0")
        self.mem_var.set("0")
        self.fan_var.set("Auto")
        self.log("Control fields reset.")

    def profile_data(self):
        g = self.selected_gpu
        return {
            "application": APP_NAME,
            "version": 1,
            "created": time.strftime("%Y-%m-%d %H:%M:%S"),
            "gpu": asdict(g) if g else None,
            "requested_settings": {
                "power_w": self.power_var.get(),
                "core_offset_mhz": self.core_var.get(),
                "memory_offset_mhz": self.mem_var.get(),
                "fan": self.fan_var.get(),
            },
        }

    def save_profile(self):
        if not self.selected_gpu:
            messagebox.showwarning("No GPU", "Detect and select a GPU first.")
            return

        path = filedialog.asksaveasfilename(
            initialdir=str(PROFILE_DIR),
            defaultextension=".json",
            filetypes=[("GPU profile", "*.json")],
        )
        if not path:
            return

        try:
            data = self.profile_data()
            Path(path).write_text(json.dumps(data, indent=2), encoding="utf-8")
            self.profile_text.delete("1.0", "end")
            self.profile_text.insert("end", json.dumps(data, indent=2))
            self.log(f"Profile saved: {path}")
        except Exception as e:
            messagebox.showerror("Profile error", str(e))

    def load_profile(self):
        path = filedialog.askopenfilename(
            initialdir=str(PROFILE_DIR),
            filetypes=[("GPU profile", "*.json")],
        )
        if not path:
            return

        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            settings = data.get("requested_settings", {})
            self.power_var.set(settings.get("power_w", ""))
            self.core_var.set(settings.get("core_offset_mhz", "0"))
            self.mem_var.set(settings.get("memory_offset_mhz", "0"))
            self.fan_var.set(settings.get("fan", "Auto"))

            self.profile_text.delete("1.0", "end")
            self.profile_text.insert("end", json.dumps(data, indent=2))
            self.log(f"Profile loaded: {path}")
        except Exception as e:
            messagebox.showerror("Profile error", str(e))

    def export_report(self):
        if not self.selected_gpu:
            messagebox.showwarning("No GPU", "Detect and select a GPU first.")
            return

        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[("Text report", "*.txt")],
        )
        if not path:
            return

        g = self.selected_gpu
        lines = [
            APP_NAME,
            "=" * 70,
            f"GPU: {g.name}",
            f"Vendor: {g.vendor}",
            f"Driver: {g.driver}",
            f"VRAM: {g.memory_mb} MB",
            f"Device ID: {g.device_id}",
            "",
            "Telemetry:",
            f"Temperature: {self.fmt(g.temperature_c, ' °C')}",
            f"Utilization: {self.fmt(g.utilization_pct, ' %')}",
            f"Core clock: {self.fmt(g.core_clock_mhz, ' MHz')}",
            f"Memory clock: {self.fmt(g.memory_clock_mhz, ' MHz')}",
            f"Power: {self.fmt(g.power_w, ' W')}",
            f"Power limit: {self.fmt(g.power_limit_w, ' W')}",
            f"Fan: {self.fmt(g.fan_pct, ' %')}",
            "",
            "Capabilities:",
        ]
        lines.extend(f"  {k}: {v}" for k, v in g.controls.items())
        lines += [
            "",
            "Safety:",
            "Arbitrary GPU register/VBIOS writes are disabled.",
            "Only controls backed by a supported vendor interface should be enabled.",
        ]

        Path(path).write_text("\n".join(lines), encoding="utf-8")
        self.log(f"Report exported: {path}")
        messagebox.showinfo("Export complete", f"Report saved to:\n{path}")


if __name__ == "__main__":
    if platform.system() != "Windows":
        print("Warning: this application is designed for Windows.")
    app = App()
    app.mainloop()
