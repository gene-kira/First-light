#!/usr/bin/env python3
# DominionDeck Full Stack - Auto-elevate, Auto-install, Security + GPU + Tor + GUI
# Windows 10/11

import ctypes
import subprocess
import sys
import os
import traceback
import json
import time
import threading
import socket
import winreg
from datetime import datetime

# ============================================================
#  AUTO-ELEVATION
# ============================================================

def ensure_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{a}"' for a in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                f'"{script}" {params}', None, 1
            )
            sys.exit(0)
    except Exception as e:
        print(f"[DominionDeck] Elevation failed: {e}")
        sys.exit(1)

ensure_admin()

# ============================================================
#  AUTO-INSTALL REQUIRED LIBS
# ============================================================

REQUIRED_LIBS = ["wmi", "pywin32", "stem"]

def install_package(pkg):
    print(f"[AUTOLOADER] Installing: {pkg}")
    try:
        subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
        print(f"[AUTOLOADER] Installed: {pkg}")
        return True
    except Exception as e:
        print(f"[AUTOLOADER] FAILED to install {pkg}: {e}")
        return False

def ensure_packages():
    import importlib
    for pkg in REQUIRED_LIBS:
        try:
            importlib.import_module(pkg)
            print(f"[AUTOLOADER] OK: {pkg}")
        except ImportError:
            install_package(pkg)

ensure_packages()

# ============================================================
#  IMPORTS AFTER INSTALL
# ============================================================

try:
    import wmi
except ImportError:
    wmi = None

try:
    from stem import Signal
    from stem.control import Controller
except ImportError:
    Controller = None
    Signal = None

import tkinter as tk
from tkinter import ttk, messagebox

# ============================================================
#  GLOBALS / LOGGING
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
LOG_CORE_ISOLATION_PATH = os.path.join(BASE_DIR, "core_isolation_log.jsonl")
SNAPSHOT_BACKUP_PATH = os.path.join(BASE_DIR, "security_snapshot_backup.json")
SNAPSHOT_BACKUP_HVCI_PATH = os.path.join(BASE_DIR, "security_snapshot_backup_hvci.json")

def now_utc_iso():
    return datetime.utcnow().isoformat() + "Z"

def emit_event(event_type: str, payload: dict):
    entry = {
        "timestamp": now_utc_iso(),
        "event_type": event_type,
        "payload": payload,
    }
    try:
        events_path = os.path.join(BASE_DIR, "dominiondeck_events_log.jsonl")
        with open(events_path, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass

def log_core_isolation_change(reg_state, runtime_state):
    entry = {
        "timestamp": now_utc_iso(),
        "registry_enabled": reg_state,
        "runtime_hvci": runtime_state
    }
    try:
        with open(LOG_CORE_ISOLATION_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    emit_event("core_isolation_change", entry)

# ============================================================
#  DEVICE GUARD / HVCI
# ============================================================

def get_device_guard_status():
    if wmi is None:
        return None
    c = wmi.WMI(namespace="root\\Microsoft\\Windows\\DeviceGuard")
    try:
        dg_list = c.Win32_DeviceGuard()
        if not dg_list:
            return None
        dg = dg_list[0]
        services_configured = getattr(dg, "SecurityServicesConfigured", None)
        services_running = getattr(dg, "SecurityServicesRunning", None)
        vbs_status = getattr(dg, "VirtualizationBasedSecurityStatus", None)

        hvci_enabled = False
        if services_running and 1 in services_running:
            hvci_enabled = True

        return {
            "SecurityServicesConfigured": services_configured,
            "SecurityServicesRunning": services_running,
            "VirtualizationBasedSecurityStatus": vbs_status,
            "HVCIEnabled": hvci_enabled
        }
    except Exception as e:
        return {"error": str(e)}

def get_hvci_registry_state():
    key_path = r"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
    try:
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            value, _ = winreg.QueryValueEx(key, "Enabled")
            return int(value)
    except FileNotFoundError:
        return 0
    except Exception:
        return 0

def is_hvci_enabled():
    dg = get_device_guard_status()
    if isinstance(dg, dict):
        return bool(dg.get("HVCIEnabled", False))
    return False

def get_hvci_runtime_state():
    if wmi is None:
        return None
    try:
        c = wmi.WMI(namespace="root\\Microsoft\\Windows\\DeviceGuard")
        dg_list = c.Win32_DeviceGuard()
        if not dg_list:
            return None
        dg = dg_list[0]
        services_running = getattr(dg, "SecurityServicesRunning", None)
        if services_running and 1 in services_running:
            return True
        return False
    except Exception:
        return None

class CoreIsolationWatchdog(threading.Thread):
    def __init__(self, ui_callback, interval=5.0):
        super().__init__(daemon=True)
        self.ui_callback = ui_callback
        self.interval = interval
        self._stop = threading.Event()
        self._last = None

    def run(self):
        while not self._stop.is_set():
            reg_state = get_hvci_registry_state()
            runtime_state = get_hvci_runtime_state()
            current = (reg_state, runtime_state)
            if self._last is None:
                self._last = current
            else:
                if current != self._last:
                    self._last = current
                    log_core_isolation_change(reg_state, runtime_state)
                    self.ui_callback(reg_state, runtime_state)
            time.sleep(self.interval)

    def stop(self):
        self._stop.set()

# ============================================================
#  SECURE BOOT / TPM / BITLOCKER
# ============================================================

def get_secure_boot_status():
    try:
        key_path = r"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            value, _ = winreg.QueryValueEx(key, "UEFISecureBootEnabled")
            return {"Enabled": bool(value)}
    except FileNotFoundError:
        return {"Enabled": False}
    except Exception as e:
        return {"error": str(e)}

def get_tpm_status():
    if wmi is None:
        return {"Present": False, "Ready": False, "ManufacturerId": None, "ManufacturerVersion": None}
    try:
        c = wmi.WMI(namespace="root\\CIMV2\\Security\\MicrosoftTpm")
        tpm_list = c.Win32_Tpm()
        if not tpm_list:
            return {"Present": False, "Ready": False, "ManufacturerId": None, "ManufacturerVersion": None}
        tpm = tpm_list[0]
        present = getattr(tpm, "IsEnabled_InitialValue", False)
        ready = getattr(tpm, "IsActivated_InitialValue", False) and getattr(tpm, "IsOwned_InitialValue", False)
        manu_id = getattr(tpm, "ManufacturerId", None)
        manu_ver = getattr(tpm, "ManufacturerVersion", None)
        return {
            "Present": bool(present),
            "Ready": bool(ready),
            "ManufacturerId": manu_id,
            "ManufacturerVersion": manu_ver
        }
    except Exception as e:
        return {"error": str(e), "Present": False, "Ready": False}

def get_bitlocker_volumes():
    volumes = []
    try:
        result = subprocess.run(
            ["manage-bde", "-status"],
            capture_output=True,
            text=True,
            shell=False
        )
        output = result.stdout.splitlines()
        current_volume = None
        for line in output:
            line = line.strip()
            if not line:
                continue
            if line.startswith("Volume"):
                current_volume = {"Volume": line.split(":", 1)[-1].strip()}
                volumes.append(current_volume)
            elif current_volume is not None:
                if line.startswith("Conversion Status:"):
                    current_volume["ConversionStatus"] = line.split(":", 1)[-1].strip()
                elif line.startswith("Protection Status:"):
                    current_volume["ProtectionStatus"] = line.split(":", 1)[-1].strip()
                elif line.startswith("Lock Status:"):
                    current_volume["LockStatus"] = line.split(":", 1)[-1].strip()
    except Exception as e:
        return [{"error": str(e)}]
    return volumes

def get_bitlocker_status_global():
    try:
        key_path = r"SYSTEM\\CurrentControlSet\\Control\\BitLocker"
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, key_path) as key:
            value, _ = winreg.QueryValueEx(key, "EnableBDE")
            return {"ProtectionStatus": value}
    except FileNotFoundError:
        return {"ProtectionStatus": "Unknown"}
    except Exception as e:
        return {"error": str(e)}

# ============================================================
#  DRIVER SCAN / READINESS
# ============================================================

def get_driver_blockers():
    if wmi is None:
        return []
    c = wmi.WMI()
    suspects = []
    try:
        for d in c.Win32_PnPSignedDriver():
            provider = getattr(d, "DriverProviderName", "") or ""
            if not provider:
                continue
            if any(p in provider for p in ["Microsoft", "Intel", "AMD", "NVIDIA", "Qualcomm", "Realtek"]):
                continue
            suspects.append({
                "DeviceName": getattr(d, "DeviceName", ""),
                "DriverVersion": getattr(d, "DriverVersion", ""),
                "DriverProviderName": provider,
                "InfName": getattr(d, "InfName", ""),
                "DeviceID": getattr(d, "DeviceID", "")
            })
    except Exception as e:
        return [{"error": str(e)}]
    return suspects

def get_security_snapshot():
    snapshot = {
        "timestamp": now_utc_iso(),
        "DeviceGuard": get_device_guard_status(),
        "SecureBoot": get_secure_boot_status(),
        "BitLockerGlobal": get_bitlocker_status_global(),
        "BitLockerVolumes": get_bitlocker_volumes(),
        "TPM": get_tpm_status(),
        "DriverBlocks": get_driver_blockers(),
        "HVCIRegistry": get_hvci_registry_state(),
        "HVCIRuntime": get_hvci_runtime_state(),
    }
    return snapshot

def save_snapshot(path: str):
    try:
        snap = get_security_snapshot()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2)
        emit_event("snapshot_saved", {"path": path})
        return True, None
    except Exception as e:
        return False, str(e)

def save_snapshot_backup_default():
    return save_snapshot(SNAPSHOT_BACKUP_PATH)

def save_snapshot_backup_hvci():
    return save_snapshot(SNAPSHOT_BACKUP_HVCI_PATH)

def get_security_readiness_score():
    snap = get_security_snapshot()
    score = 0
    details = []

    hvci = is_hvci_enabled()
    if hvci:
        score += 30
        details.append("HVCI enabled (+30)")
    else:
        details.append("HVCI disabled (+0)")

    sb = snap.get("SecureBoot", {})
    if sb.get("Enabled", False):
        score += 20
        details.append("Secure Boot enabled (+20)")
    else:
        details.append("Secure Boot disabled (+0)")

    tpm = snap.get("TPM", {})
    if tpm.get("Present", False):
        score += 20
        details.append("TPM present (+20)")
    else:
        details.append("TPM not present (+0)")

    if tpm.get("Ready", False):
        score += 10
        details.append("TPM ready (+10)")
    else:
        details.append("TPM not ready (+0)")

    blg = snap.get("BitLockerGlobal", {})
    ps = blg.get("ProtectionStatus", "Unknown")
    if isinstance(ps, int) and ps != 0:
        score += 10
        details.append("BitLocker globally enabled (+10)")
    elif isinstance(ps, str) and "on" in ps.lower():
        score += 10
        details.append("BitLocker globally enabled (+10)")
    else:
        details.append("BitLocker not clearly enabled (+0)")

    drivers = snap.get("DriverBlocks", [])
    if drivers and not any("error" in d for d in drivers):
        details.append("Non-Microsoft/OEM drivers detected (+0)")
    else:
        score += 10
        details.append("No driver blockers or WMI error (+10)")

    return score, details

# ============================================================
#  SECURITY SENTINEL + GPU GOVERNOR
# ============================================================

class SecuritySentinelClient:
    def get_snapshot(self):
        return get_security_snapshot()
    def get_readiness(self):
        return get_security_readiness_score()
    def hvci_on(self):
        return is_hvci_enabled()

class GPUGovernor:
    def __init__(self, sentinel: SecuritySentinelClient):
        self.sentinel = sentinel
        self._wmi = wmi.WMI() if wmi is not None else None
    def get_gpu_adapters(self):
        adapters = []
        if self._wmi is None:
            return adapters
        try:
            for gpu in self._wmi.Win32_VideoController():
                name = getattr(gpu, "Name", "")
                vram = getattr(gpu, "AdapterRAM", None)
                adapters.append({"Name": name, "VRAMBytes": vram})
        except Exception:
            pass
        return adapters
    def get_vram_summary(self):
        adapters = self.get_gpu_adapters()
        lines = []
        for a in adapters:
            name = a.get("Name", "")
            vram = a.get("VRAMBytes", None)
            if vram is not None:
                gb = vram / (1024 ** 3)
                lines.append(f"{name}: {gb:.2f} GB VRAM")
            else:
                lines.append(f"{name}: VRAM unknown")
        if not lines:
            lines.append("No GPU adapters detected (WMI).")
        return "\n".join(lines)
    def get_security_readiness(self):
        return self.sentinel.get_readiness()

# ============================================================
#  SIMPLE TORNET-STYLE TOR CONTROLLER
# ============================================================

class SimpleTorController:
    def __init__(self, host="127.0.0.1", port=9051, interval_sec=3):
        self.host = host
        self.port = port
        self.interval_sec = interval_sec
        self.running = False
        self.thread = None
        self.stop_event = threading.Event()

    def _check_port(self):
        try:
            with socket.create_connection((self.host, self.port), timeout=1.0):
                return True
        except OSError:
            return False

    def rotate_once(self):
        if Controller is None or Signal is None:
            emit_event("tor_rotation_error", {"error": "stem not available"})
            return False
        try:
            with Controller.from_port(address=self.host, port=self.port) as c:
                c.authenticate()
                c.signal(Signal.NEWNYM)
            emit_event("tor_rotated", {"interval_sec": self.interval_sec})
            return True
        except Exception as e:
            emit_event("tor_rotation_error", {"error": str(e)})
            return False

    def _loop(self):
        while not self.stop_event.is_set():
            time.sleep(self.interval_sec)
            if self.stop_event.is_set():
                break
            self.rotate_once()

    def start(self):
        if self.running:
            return
        if not self._check_port():
            print(f"[TOR] Control port {self.host}:{self.port} not reachable")
            return
        self.stop_event.clear()
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        if not self.running:
            return
        self.stop_event.set()
        if self.thread and self.thread.is_alive():
            self.thread.join(timeout=5.0)
        self.running = False

# ============================================================
#  GUI
# ============================================================

class DominionDeckGUI:
    def __init__(self, root, sentinel: SecuritySentinelClient, gpu_gov: GPUGovernor, tor: SimpleTorController):
        self.root = root
        self.sentinel = sentinel
        self.gpu_gov = gpu_gov
        self.tor = tor

        self.root.title("DominionDeck Command Center")
        self.root.geometry("1100x720")
        self.apply_dark_mode()
        self.build_layout()
        self.refresh_all()

    def apply_dark_mode(self):
        self.root.configure(bg="#1e1e1e")
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TFrame", background="#1e1e1e")
        style.configure("TLabel", background="#1e1e1e", foreground="#ffffff")
        style.configure("TButton", background="#2d2d2d", foreground="#ffffff")
        style.configure("TNotebook", background="#1e1e1e")
        style.configure("TNotebook.Tab", background="#2d2d2d", foreground="#ffffff")

    def build_layout(self):
        main_frame = ttk.Frame(self.root)
        main_frame.pack(fill="both", expand=True, padx=10, pady=10)

        notebook = ttk.Notebook(main_frame)
        notebook.pack(fill="both", expand=True)

        self.tab_security = ttk.Frame(notebook)
        self.tab_gpu = ttk.Frame(notebook)
        self.tab_tor = ttk.Frame(notebook)

        notebook.add(self.tab_security, text="Security")
        notebook.add(self.tab_gpu, text="GPU")
        notebook.add(self.tab_tor, text="Tor")

        # Security tab
        self.security_text = tk.Text(self.tab_security, bg="#1e1e1e", fg="#ffffff", insertbackground="#ffffff")
        self.security_text.pack(fill="both", expand=True)

        btn_frame = ttk.Frame(self.tab_security)
        btn_frame.pack(fill="x", pady=5)
        ttk.Button(btn_frame, text="Snapshot Backup", command=self.do_snapshot_backup).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Snapshot Backup (HVCI)", command=self.do_snapshot_backup_hvci).pack(side="left", padx=5)
        ttk.Button(btn_frame, text="Show Readiness", command=self.show_readiness).pack(side="left", padx=5)

        # GPU tab
        self.gpu_text = tk.Text(self.tab_gpu, bg="#1e1e1e", fg="#ffffff", insertbackground="#ffffff")
        self.gpu_text.pack(fill="both", expand=True)

        # Tor tab
        tor_frame = ttk.Frame(self.tab_tor)
        tor_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.tor_status_label = ttk.Label(tor_frame, text="Tor Status: Unknown")
        self.tor_status_label.pack(anchor="w", pady=5)

        interval_frame = ttk.Frame(tor_frame)
        interval_frame.pack(fill="x", pady=5)
        ttk.Label(interval_frame, text="Rotation Interval (seconds):").pack(side="left")
        self.tor_interval_var = tk.IntVar(value=self.tor.interval_sec)
        tk.Entry(interval_frame, textvariable=self.tor_interval_var).pack(side="left", padx=5)
        ttk.Button(interval_frame, text="Apply Interval", command=self.apply_tor_interval).pack(side="left", padx=5)

        ttk.Button(tor_frame, text="Rotate Now", command=self.rotate_tor_now).pack(anchor="w", pady=5)

        self.tor_log_text = tk.Text(tor_frame, bg="#1e1e1e", fg="#ffffff", insertbackground="#ffffff", height=15)
        self.tor_log_text.pack(fill="both", expand=True, pady=5)

    def refresh_all(self):
        self.refresh_security()
        self.refresh_gpu()
        self.refresh_tor_status()

    def refresh_security(self):
        snap = self.sentinel.get_snapshot()
        self.security_text.delete("1.0", "end")
        self.security_text.insert("end", json.dumps(snap, indent=2))

    def refresh_gpu(self):
        vram_summary = self.gpu_gov.get_vram_summary()
        score, details = self.gpu_gov.get_security_readiness()
        self.gpu_text.delete("1.0", "end")
        self.gpu_text.insert("end", "=== GPU VRAM ===\n")
        self.gpu_text.insert("end", vram_summary + "\n\n")
        self.gpu_text.insert("end", "=== Security Readiness ===\n")
        self.gpu_text.insert("end", f"Score: {score}\n")
        for d in details:
            self.gpu_text.insert("end", f"- {d}\n")

    def refresh_tor_status(self):
        self.tor_status_label.config(text=f"Tor Status: interval={self.tor.interval_sec}s")

    def do_snapshot_backup(self):
        ok, err = save_snapshot_backup_default()
        if ok:
            messagebox.showinfo("Snapshot", f"Snapshot saved to {SNAPSHOT_BACKUP_PATH}")
        else:
            messagebox.showerror("Snapshot Error", str(err))

    def do_snapshot_backup_hvci(self):
        ok, err = save_snapshot_backup_hvci()
        if ok:
            messagebox.showinfo("Snapshot", f"HVCI snapshot saved to {SNAPSHOT_BACKUP_HVCI_PATH}")
        else:
            messagebox.showerror("Snapshot Error", str(err))

    def show_readiness(self):
        score, details = get_security_readiness_score()
        msg = f"Security Readiness Score: {score}\n\n" + "\n".join(details)
        messagebox.showinfo("Security Readiness", msg)

    def apply_tor_interval(self):
        try:
            sec = int(self.tor_interval_var.get())
            self.tor.interval_sec = sec
            self.refresh_tor_status()
            self.tor_log_text.insert("end", f"[{now_utc_iso()}] Interval set to {sec} seconds\n")
        except ValueError:
            messagebox.showerror("Interval Error", "Invalid interval value.")

    def rotate_tor_now(self):
        ok = self.tor.rotate_once()
        if ok:
            self.tor_log_text.insert("end", f"[{now_utc_iso()}] Manual rotation success\n")
        else:
            self.tor_log_text.insert("end", f"[{now_utc_iso()}] Manual rotation FAILED\n")

# ============================================================
#  MAIN
# ============================================================

def main():
    sentinel = SecuritySentinelClient()
    gpu_gov = GPUGovernor(sentinel)
    tor = SimpleTorController(interval_sec=3)
    tor.start()

    root = tk.Tk()
    gui = DominionDeckGUI(root, sentinel, gpu_gov, tor)

    watchdog = CoreIsolationWatchdog(
        ui_callback=lambda r, s: emit_event("hvci_watchdog", {"reg": r, "runtime": s}),
        interval=5.0
    )
    watchdog.start()

    def on_close():
        watchdog.stop()
        tor.stop()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("[DominionDeck] Fatal error:")
        print(traceback.format_exc())
