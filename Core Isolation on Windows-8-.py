# === AUTO-ELEVATION CHECK ===
import ctypes
import os
import sys

def ensure_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{script}" {params}',
                None,
                1
            )
            sys.exit()
    except Exception as e:
        print(f"[Security Sentinel] Elevation failed: {e}")
        sys.exit()

ensure_admin()

import json
import subprocess
import threading
import time
import winreg
import tkinter as tk
from tkinter import messagebox, ttk
from datetime import datetime

try:
    import wmi
except ImportError:
    wmi = None


# ---------- Global paths / modes ----------

BASE_DIR = os.path.dirname(os.path.abspath(sys.argv[0]))
LOG_CORE_ISOLATION_PATH = os.path.join(BASE_DIR, "core_isolation_log.jsonl")
LOG_DRIVER_REMEDIATION_PATH = os.path.join(BASE_DIR, "driver_remediation_log.jsonl")
SNAPSHOT_BACKUP_PATH = os.path.join(BASE_DIR, "security_snapshot_backup.json")
SNAPSHOT_BACKUP_HVCI_PATH = os.path.join(BASE_DIR, "security_snapshot_backup_hvci.json")
SNAPSHOT_RESTORE_PATH = os.path.join(BASE_DIR, "security_snapshot_restore.json")

AUTO_REPAIR_MODE_DEFAULT = False
AUTO_REPAIR_REQUIRE_MANUAL_OVERRIDE = True

SAFE_REMEDIATION_DEFAULT = True


# ---------- Event bus / logging ----------

def now_utc_iso():
    return datetime.utcnow().isoformat() + "Z"


def emit_event(event_type: str, payload: dict):
    entry = {
        "timestamp": now_utc_iso(),
        "event_type": event_type,
        "payload": payload,
    }
    # For now, just log to a generic events file
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


def log_driver_remediation(action: str, device_info: dict, result: str, error: str = None):
    entry = {
        "timestamp": now_utc_iso(),
        "action": action,
        "device": device_info,
        "result": result,
        "error": error,
    }
    try:
        with open(LOG_DRIVER_REMEDIATION_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
    emit_event("driver_remediation", entry)


# ---------- Plugin API skeleton ----------

class DominionPlugin:
    def on_snapshot(self, snapshot: dict):
        pass

    def on_event(self, event_type: str, payload: dict):
        pass


class PluginManager:
    def __init__(self):
        self._plugins = []

    def register(self, plugin: DominionPlugin):
        self._plugins.append(plugin)

    def broadcast_snapshot(self, snapshot: dict):
        for p in self._plugins:
            try:
                p.on_snapshot(snapshot)
            except Exception:
                continue

    def broadcast_event(self, event_type: str, payload: dict):
        for p in self._plugins:
            try:
                p.on_event(event_type, payload)
            except Exception:
                continue


PLUGIN_MANAGER = PluginManager()


# ---------- Swarm sync hooks (stubs) ----------

def send_snapshot_to_swarm(snapshot: dict):
    # Stub: in future, push to remote swarm nodes / command center
    emit_event("swarm_snapshot_send", {"snapshot_summary": "size=" + str(len(json.dumps(snapshot)))})


def receive_swarm_policies():
    # Stub: in future, pull policies from swarm
    # For now, return empty policy set
    return {
        "driver_blocklist": [],
        "hvci_required": False,
    }


# ---------- Admin check ----------

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False


# ---------- Device Guard / Core Isolation ----------

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


def set_memory_integrity(enable: bool):
    key_path = r"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
    try:
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        value = 1 if enable else 0
        winreg.SetValueEx(key, "Enabled", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        emit_event("hvci_set", {"target": enable})
        return True, None
    except PermissionError:
        return False, "Permission denied (run as Administrator)."
    except Exception as e:
        return False, str(e)


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


# ---------- Secure Boot ----------

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


# ---------- TPM Status ----------

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


# ---------- BitLocker per-volume ----------

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


# ---------- Driver scan ----------

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

            # Skip major OEM / Microsoft
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


def score_driver_risk(driver: dict) -> int:
    """
    Simple heuristic risk score:
    - Unknown provider / empty version => higher risk
    - Weird provider names => moderate risk
    """
    provider = (driver.get("DriverProviderName") or "").lower()
    version = (driver.get("DriverVersion") or "").strip()

    score = 0

    if not provider:
        score += 40
    elif any(x in provider for x in ["unknown", "generic", "virtual", "filter"]):
        score += 30
    else:
        score += 10

    if not version:
        score += 30
    else:
        score += 10

    return score


# ---------- Driver auto-remediation (heuristic) ----------

def attempt_disable_device(device_id: str, device_info: dict):
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            f"Disable-PnpDevice -InstanceId '{device_id}' -Confirm:$false"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            log_driver_remediation("disable", device_info, "success", None)
            return True, None
        else:
            err = result.stderr.strip() or "Unknown error disabling device."
            log_driver_remediation("disable", device_info, "failure", err)
            return False, err
    except Exception as e:
        log_driver_remediation("disable", device_info, "exception", str(e))
        return False, str(e)


def attempt_enable_device(device_id: str, device_info: dict):
    try:
        cmd = [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy", "Bypass",
            "-Command",
            f"Enable-PnpDevice -InstanceId '{device_id}' -Confirm:$false"
        ]
        result = subprocess.run(cmd, capture_output=True, text=True)
        if result.returncode == 0:
            log_driver_remediation("enable_restore", device_info, "success", None)
            return True, None
        else:
            err = result.stderr.strip() or "Unknown error enabling device."
            log_driver_remediation("enable_restore", device_info, "failure", err)
            return False, err
    except Exception as e:
        log_driver_remediation("enable_restore", device_info, "exception", str(e))
        return False, str(e)


# ---------- Snapshot + restore ----------

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
    PLUGIN_MANAGER.broadcast_snapshot(snapshot)
    return snapshot


def print_json_snapshot():
    snap = get_security_snapshot()
    print(json.dumps(snap, indent=2))


def save_snapshot(path: str):
    try:
        snap = get_security_snapshot()
        with open(path, "w", encoding="utf-8") as f:
            json.dump(snap, f, indent=2)
        emit_event("snapshot_saved", {"path": path})
        return True, None
    except Exception as e:
        return False, str(e)


def load_snapshot(path: str):
    try:
        with open(path, "r", encoding="utf-8") as f:
            snap = json.load(f)
        return snap, None
    except Exception as e:
        return None, str(e)


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


# ---------- GPU Governor / SecuritySentinelClient ----------

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
                adapters.append({
                    "Name": name,
                    "VRAMBytes": vram,
                })
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
        score, details = self.sentinel.get_readiness()
        return score, details


# ---------- GUI (Dark Mode DominionDeck Command Center) ----------

class SecurityGovernorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("DominionDeck Command Center - Security & GPU")
        self.root.geometry("980x680")

        self.apply_dark_mode()

        self.sentinel = SecuritySentinelClient()
        self.gpu_governor = GPUGovernor(self.sentinel)

        self.main_frame = tk.Frame(root, bg="#1e1e1e")
        self.main_frame.pack(fill="both", expand=True)

        self.label_status = tk.Label(
            self.main_frame,
            text="",
            anchor="w",
            justify="left",
            bg="#1e1e1e",
            fg="#ffffff",
            font=("Consolas", 10)
        )
        self.label_status.pack(padx=10, pady=10, fill="x")

        # Top control bar
        self.button_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.button_frame.pack(padx=10, pady=5, fill="x")

        self.button_toggle = tk.Button(
            self.button_frame,
            text="...",
            command=self.toggle_hvci,
            bg="#2d2d30",
            fg="#ffffff",
            activebackground="#3e3e40",
            activeforeground="#ffffff"
        )
        self.button_toggle.pack(side="left", padx=5)

        self.button_remediate = tk.Button(
            self.button_frame,
            text="Driver Auto-Remediation (Aggressive)",
            command=self.remediate_drivers_aggressive,
            bg="#2d2d30",
            fg="#ffffff",
            activebackground="#3e3e40",
            activeforeground="#ffffff"
        )
        self.button_remediate.pack(side="left", padx=5)

        self.button_remediate_safe = tk.Button(
            self.button_frame,
            text="Driver Safe Remediation (Heuristic)",
            command=self.remediate_drivers_safe,
            bg="#2d2d30",
            fg="#ffffff",
            activebackground="#3e3e40",
            activeforeground="#ffffff"
        )
        self.button_remediate_safe.pack(side="left", padx=5)

        self.button_refresh = tk.Button(
            self.button_frame,
            text="Refresh Snapshot",
            command=self.refresh_state,
            bg="#2d2d30",
            fg="#ffffff",
            activebackground="#3e3e40",
            activeforeground="#ffffff"
        )
        self.button_refresh.pack(side="left", padx=5)

        self.button_score = tk.Button(
            self.button_frame,
            text="Show Security Readiness Score",
            command=self.show_readiness_score,
            bg="#2d2d30",
            fg="#ffffff",
            activebackground="#3e3e40",
            activeforeground="#ffffff"
        )
        self.button_score.pack(side="left", padx=5)

        self.button_save_snapshot = tk.Button(
            self.button_frame,
            text="Save Snapshot Backup",
            command=self.save_snapshot_backup_gui,
            bg="#2d2d30",
            fg="#ffffff",
            activebackground="#3e3e40",
            activeforeground="#ffffff"
        )
        self.button_save_snapshot.pack(side="left", padx=5)

        self.button_restore_snapshot = tk.Button(
            self.button_frame,
            text="Restore Snapshot (HVCI + Drivers)",
            command=self.restore_snapshot_gui,
            bg="#2d2d30",
            fg="#ffffff",
            activebackground="#3e3e40",
            activeforeground="#ffffff"
        )
        self.button_restore_snapshot.pack(side="left", padx=5)

        # Manual override + auto-repair mode controls
        self.override_frame = tk.Frame(self.main_frame, bg="#1e1e1e")
        self.override_frame.pack(padx=10, pady=5, fill="x")

        self.manual_override_var = tk.BooleanVar(value=False)
        self.auto_repair_var = tk.BooleanVar(value=AUTO_REPAIR_MODE_DEFAULT)
        self.safe_remediation_var = tk.BooleanVar(value=SAFE_REMEDIATION_DEFAULT)

        self.chk_manual_override = tk.Checkbutton(
            self.override_frame,
            text="Manual Override for Auto-Repair (required before disabling drivers)",
            variable=self.manual_override_var,
            bg="#1e1e1e",
            fg="#ffffff",
            selectcolor="#1e1e1e",
            activebackground="#1e1e1e",
            activeforeground="#ffffff"
        )
        self.chk_manual_override.pack(side="left", padx=5)

        self.chk_auto_repair = tk.Checkbutton(
            self.override_frame,
            text="Enable Auto-Repair Mode (Aggressive)",
            variable=self.auto_repair_var,
            bg="#1e1e1e",
            fg="#ffffff",
            selectcolor="#1e1e1e",
            activebackground="#1e1e1e",
            activeforeground="#ffffff"
        )
        self.chk_auto_repair.pack(side="left", padx=5)

        self.chk_safe_remediation = tk.Checkbutton(
            self.override_frame,
            text="Prefer Safe Remediation (Heuristic)",
            variable=self.safe_remediation_var,
            bg="#1e1e1e",
            fg="#ffffff",
            selectcolor="#1e1e1e",
            activebackground="#1e1e1e",
            activeforeground="#ffffff"
        )
        self.chk_safe_remediation.pack(side="left", padx=5)

        # Notebook
        self.notebook = ttk.Notebook(self.main_frame)
        self.notebook.pack(padx=10, pady=10, fill="both", expand=True)

        # Security - Drivers
        self.frame_drivers = tk.Frame(self.notebook, bg="#1e1e1e")
        self.text_drivers = tk.Text(
            self.frame_drivers,
            height=10,
            bg="#252526",
            fg="#ffffff",
            insertbackground="#ffffff",
            font=("Consolas", 9)
        )
        self.text_drivers.pack(padx=5, pady=5, fill="both", expand=True)
        self.notebook.add(self.frame_drivers, text="Security - Drivers")

        # Security - TPM
        self.frame_tpm = tk.Frame(self.notebook, bg="#1e1e1e")
        self.text_tpm = tk.Text(
            self.frame_tpm,
            height=6,
            bg="#252526",
            fg="#ffffff",
            insertbackground="#ffffff",
            font=("Consolas", 9)
        )
        self.text_tpm.pack(padx=5, pady=5, fill="both", expand=True)
        self.notebook.add(self.frame_tpm, text="Security - TPM")

        # Security - BitLocker
        self.frame_bitlocker = tk.Frame(self.notebook, bg="#1e1e1e")
        self.text_bitlocker = tk.Text(
            self.frame_bitlocker,
            height=8,
            bg="#252526",
            fg="#ffffff",
            insertbackground="#ffffff",
            font=("Consolas", 9)
        )
        self.text_bitlocker.pack(padx=5, pady=5, fill="both", expand=True)
        self.notebook.add(self.frame_bitlocker, text="Security - BitLocker")

        # GPU panel
        self.frame_gpu = tk.Frame(self.notebook, bg="#1e1e1e")
        self.text_gpu = tk.Text(
            self.frame_gpu,
            height=10,
            bg="#252526",
            fg="#ffffff",
            insertbackground="#ffffff",
            font=("Consolas", 9)
        )
        self.text_gpu.pack(padx=5, pady=5, fill="both", expand=True)
        self.notebook.add(self.frame_gpu, text="GPU - Telemetry & Readiness")

        # Swarm / events panel
        self.frame_swarm = tk.Frame(self.notebook, bg="#1e1e1e")
        self.text_swarm = tk.Text(
            self.frame_swarm,
            height=10,
            bg="#252526",
            fg="#ffffff",
            insertbackground="#ffffff",
            font=("Consolas", 9)
        )
        self.text_swarm.pack(padx=5, pady=5, fill="both", expand=True)
        self.notebook.add(self.frame_swarm, text="Swarm & Events")

        self.hvci_current = False

        self.watchdog = CoreIsolationWatchdog(self.on_core_isolation_change, interval=5.0)
        self.watchdog.start()

        self.refresh_state()

    def apply_dark_mode(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("TNotebook", background="#1e1e1e", foreground="#ffffff")
        style.configure("TNotebook.Tab", background="#2d2d30", foreground="#ffffff")
        style.map("TNotebook.Tab", background=[("selected", "#3e3e40")])

    def on_core_isolation_change(self, reg_state, runtime_state):
        def notify():
            msg = (
                "Core Isolation / Memory Integrity state changed!\n\n"
                f"Registry Enabled: {reg_state}\n"
                f"Runtime HVCI: {runtime_state}\n\n"
                "If you did not change this, treat it as suspicious.\n"
                f"Logged to: {LOG_CORE_ISOLATION_PATH}"
            )
            messagebox.showwarning("Core Isolation Change Detected", msg)
            self.refresh_state()
        self.root.after(0, notify)

    def refresh_state(self):
        snap = get_security_snapshot()
        dg = snap.get("DeviceGuard", {})
        hvci_enabled = False
        if isinstance(dg, dict):
            hvci_enabled = dg.get("HVCIEnabled", False)

        self.hvci_current = hvci_enabled

        status_lines = []

        status_lines.append(f"Memory Integrity (HVCI): {'ON' if hvci_enabled else 'OFF'}")
        status_lines.append(f"HVCI Registry Enabled: {snap.get('HVCIRegistry', 0)}")
        status_lines.append(f"HVCI Runtime: {snap.get('HVCIRuntime', None)}")

        sb = snap.get("SecureBoot", {})
        status_lines.append(f"Secure Boot: {sb.get('Enabled', False)}")

        blg = snap.get("BitLockerGlobal", {})
        status_lines.append(f"BitLocker Global ProtectionStatus: {blg.get('ProtectionStatus', 'Unknown')}")

        tpm = snap.get("TPM", {})
        if "error" in tpm:
            status_lines.append(f"TPM: ERROR: {tpm['error']}")
        else:
            status_lines.append(f"TPM Present: {tpm.get('Present', False)}")
            status_lines.append(f"TPM Ready: {tpm.get('Ready', False)}")
            status_lines.append(f"TPM ManufacturerId: {tpm.get('ManufacturerId', None)}")
            status_lines.append(f"TPM ManufacturerVersion: {tpm.get('ManufacturerVersion', None)}")

        score, details = get_security_readiness_score()
        status_lines.append(f"Security Readiness Score: {score}/100")

        self.label_status.config(text="\n".join(status_lines))

        if hvci_enabled:
            self.button_toggle.config(text="Turn OFF Memory Integrity")
        else:
            self.button_toggle.config(text="Turn ON Memory Integrity")

        # Drivers panel
        self.text_drivers.delete("1.0", tk.END)
        self.text_drivers.insert(tk.END, "Potential non-Microsoft/OEM drivers (with heuristic risk scores):\n\n")
        for d in snap.get("DriverBlocks", []):
            if "error" in d:
                self.text_drivers.insert(tk.END, f"ERROR: {d['error']}\n")
                continue
            risk = score_driver_risk(d)
            line = (
                f"[Risk {risk:3d}] "
                f"{d.get('DeviceName','')} | "
                f"{d.get('DriverProviderName','')} | "
                f"{d.get('DriverVersion','')} | "
                f"{d.get('InfName','')} | "
                f"{d.get('DeviceID','')}\n"
            )
            self.text_drivers.insert(tk.END, line)

        # TPM panel
        self.text_tpm.delete("1.0", tk.END)
        if "error" in tpm:
            self.text_tpm.insert(tk.END, f"TPM ERROR: {tpm['error']}\n")
        else:
            self.text_tpm.insert(tk.END, "TPM Status:\n\n")
            self.text_tpm.insert(tk.END, f"Present: {tpm.get('Present', False)}\n")
            self.text_tpm.insert(tk.END, f"Ready: {tpm.get('Ready', False)}\n")
            self.text_tpm.insert(tk.END, f"ManufacturerId: {tpm.get('ManufacturerId', None)}\n")
            self.text_tpm.insert(tk.END, f"ManufacturerVersion: {tpm.get('ManufacturerVersion', None)}\n")

        # BitLocker panel
        self.text_bitlocker.delete("1.0", tk.END)
        self.text_bitlocker.insert(tk.END, "BitLocker Volumes:\n\n")
        for v in snap.get("BitLockerVolumes", []):
            if "error" in v:
                self.text_bitlocker.insert(tk.END, f"ERROR: {v['error']}\n")
                continue
            self.text_bitlocker.insert(tk.END, f"Volume: {v.get('Volume','')}\n")
            self.text_bitlocker.insert(tk.END, f"  ProtectionStatus: {v.get('ProtectionStatus','')}\n")
            self.text_bitlocker.insert(tk.END, f"  ConversionStatus: {v.get('ConversionStatus','')}\n")
            self.text_bitlocker.insert(tk.END, f"  LockStatus: {v.get('LockStatus','')}\n\n")

        # GPU panel: VRAM telemetry + security readiness
        self.text_gpu.delete("1.0", tk.END)
        self.text_gpu.insert(tk.END, "GPU Adapters / VRAM:\n\n")
        self.text_gpu.insert(tk.END, self.gpu_governor.get_vram_summary())
        self.text_gpu.insert(tk.END, "\n\nSecurity Readiness (for GPU tuning):\n\n")
        self.text_gpu.insert(tk.END, f"Score: {score}/100\n\n")
        for d in details:
            self.text_gpu.insert(tk.END, f"- {d}\n")

        # Swarm / events panel (simple view)
        self.text_swarm.delete("1.0", tk.END)
        self.text_swarm.insert(tk.END, "Swarm Policies (stub):\n\n")
        policies = receive_swarm_policies()
        self.text_swarm.insert(tk.END, json.dumps(policies, indent=2))
        self.text_swarm.insert(tk.END, "\n\nSnapshots can be sent to swarm via hooks.\n")

    def toggle_hvci(self):
        target = not self.hvci_current
        msg = (
            f"Set Memory Integrity to {'ON' if target else 'OFF'} and require reboot?\n\n"
            "A backup snapshot will be saved before changing the registry."
        )
        if messagebox.askyesno("Confirm", msg):
            ok_backup, err_backup = save_snapshot_backup_hvci()
            if not ok_backup:
                messagebox.showwarning(
                    "Snapshot Backup Failed",
                    f"Failed to save HVCI backup snapshot: {err_backup}\nProceeding anyway."
                )

            ok, err = set_memory_integrity(target)
            if not ok:
                messagebox.showerror("Error", f"Failed to set Memory Integrity: {err}")
            else:
                messagebox.showinfo(
                    "Info",
                    "Memory Integrity registry updated.\nReboot required.\n"
                    f"Backup snapshot saved to: {SNAPSHOT_BACKUP_HVCI_PATH}"
                )
                self.refresh_state()

    def _check_manual_override_and_mode(self, aggressive: bool):
        if AUTO_REPAIR_REQUIRE_MANUAL_OVERRIDE and not self.manual_override_var.get():
            messagebox.showwarning(
                "Manual Override Required",
                "Manual Override for Auto-Repair is not enabled.\n\n"
                "Enable the checkbox before attempting driver remediation."
            )
            return False

        if aggressive:
            if not self.auto_repair_var.get():
                messagebox.showinfo(
                    "Auto-Repair Mode Disabled",
                    "Aggressive Auto-Repair Mode is currently disabled.\n\n"
                    "Enable it if you want full driver disabling."
                )
                return False
        else:
            if not self.safe_remediation_var.get():
                messagebox.showinfo(
                    "Safe Remediation Disabled",
                    "Safe remediation mode is currently disabled.\n\n"
                    "Enable it if you want heuristic driver disabling."
                )
                return False

        return True

    def _backup_before_remediation(self, label: str):
        ok_backup, err_backup = save_snapshot(SNAPSHOT_BACKUP_PATH)
        if not ok_backup:
            if not messagebox.askyesno(
                "Snapshot Backup Failed",
                f"Failed to save security snapshot backup before {label}.\n\n"
                f"Error: {err_backup}\n\nProceed anyway?"
            ):
                return False
        else:
            messagebox.showinfo(
                "Snapshot Backup",
                f"Security snapshot backup saved to:\n{SNAPSHOT_BACKUP_PATH}\n\n"
                f"Proceeding with {label}."
            )
        return True

    def remediate_drivers_aggressive(self):
        if not self._check_manual_override_and_mode(aggressive=True):
            return

        if not self._backup_before_remediation("aggressive driver auto-remediation"):
            return

        snap = get_security_snapshot()
        drivers = snap.get("DriverBlocks", [])
        if not drivers:
            messagebox.showinfo("Info", "No non-Microsoft/OEM drivers detected.")
            return

        if not messagebox.askyesno(
            "Driver Auto-Remediation (Aggressive)",
            "Attempt to disable ALL listed non-Microsoft/OEM devices via PowerShell?\n"
            "This is aggressive and may affect device functionality.\n\n"
            "A backup snapshot has been saved."
        ):
            return

        results = []
        for d in drivers:
            if "error" in d:
                continue
            device_id = d.get("DeviceID", "")
            if not device_id:
                continue
            ok, err = attempt_disable_device(device_id, d)
            if ok:
                results.append(f"OK: Disabled {d.get('DeviceName','')} ({device_id})")
            else:
                results.append(f"FAIL: {d.get('DeviceName','')} ({device_id}) -> {err}")

        if not results:
            messagebox.showinfo("Driver Auto-Remediation", "No devices could be processed.")
        else:
            messagebox.showinfo("Driver Auto-Remediation (Aggressive)", "\n".join(results))
            self.refresh_state()

    def remediate_drivers_safe(self):
        if not self._check_manual_override_and_mode(aggressive=False):
            return

        if not self._backup_before_remediation("safe driver remediation"):
            return

        snap = get_security_snapshot()
        drivers = snap.get("DriverBlocks", [])
        if not drivers:
            messagebox.showinfo("Info", "No non-Microsoft/OEM drivers detected.")
            return

        # Filter drivers by heuristic risk score
        high_risk = [d for d in drivers if "error" not in d and score_driver_risk(d) >= 40]
        if not high_risk:
            if not messagebox.askyesno(
                "Safe Remediation",
                "No high-risk drivers detected by heuristic.\n\n"
                "Do you still want to process all non-Microsoft/OEM drivers?"
            ):
                return
            high_risk = [d for d in drivers if "error" not in d]

        preview_lines = []
        for d in high_risk:
            preview_lines.append(
                f"{d.get('DeviceName','')} | {d.get('DriverProviderName','')} | "
                f"{d.get('DriverVersion','')} | {d.get('DeviceID','')}"
            )

        if not messagebox.askyesno(
            "Safe Driver Remediation",
            "Heuristic-selected drivers (high risk) will be disabled:\n\n"
            + "\n".join(preview_lines[:20]) +
            ("\n\n(Showing first 20 entries only...)" if len(preview_lines) > 20 else "") +
            "\n\nProceed?"
        ):
            return

        results = []
        for d in high_risk:
            device_id = d.get("DeviceID", "")
            if not device_id:
                continue
            ok, err = attempt_disable_device(device_id, d)
            if ok:
                results.append(f"OK: Disabled {d.get('DeviceName','')} ({device_id})")
            else:
                results.append(f"FAIL: {d.get('DeviceName','')} ({device_id}) -> {err}")

        if not results:
            messagebox.showinfo("Safe Driver Remediation", "No devices could be processed.")
        else:
            messagebox.showinfo("Safe Driver Remediation", "\n".join(results))
            self.refresh_state()

    def save_snapshot_backup_gui(self):
        ok, err = save_snapshot_backup_default()
        if not ok:
            messagebox.showerror("Snapshot Backup Failed", f"Failed to save snapshot: {err}")
        else:
            messagebox.showinfo(
                "Snapshot Backup",
                f"Security snapshot backup saved to:\n{SNAPSHOT_BACKUP_PATH}"
            )

    def restore_snapshot_gui(self):
        snap, err = load_snapshot(SNAPSHOT_BACKUP_PATH)
        if snap is None:
            messagebox.showerror(
                "Restore Failed",
                f"Failed to load snapshot from {SNAPSHOT_BACKUP_PATH}:\n{err}"
            )
            return

        if not messagebox.askyesno(
            "Restore Snapshot",
            "Attempt to restore HVCI registry state and re-enable previously disabled drivers\n"
            "based on the backup snapshot?\n\n"
            "This is best-effort and may not fully revert all changes.\n\nProceed?"
        ):
            return

        # Restore HVCI registry state
        hvci_reg = snap.get("HVCIRegistry", None)
        if hvci_reg is not None:
            target = bool(hvci_reg)
            ok, err_set = set_memory_integrity(target)
            if not ok:
                messagebox.showwarning(
                    "HVCI Restore Failed",
                    f"Failed to restore HVCI registry state: {err_set}"
                )
            else:
                messagebox.showinfo(
                    "HVCI Restore",
                    f"HVCI registry state restored to: {hvci_reg} (ON={bool(hvci_reg)})"
                )

        # Attempt to re-enable drivers that appear in snapshot and may have been disabled
        drivers = snap.get("DriverBlocks", [])
        results = []
        for d in drivers:
            if "error" in d:
                continue
            device_id = d.get("DeviceID", "")
            if not device_id:
                continue
            ok, err_en = attempt_enable_device(device_id, d)
            if ok:
                results.append(f"OK: Enabled {d.get('DeviceName','')} ({device_id})")
            else:
                results.append(f"FAIL: {d.get('DeviceName','')} ({device_id}) -> {err_en}")

        if results:
            messagebox.showinfo("Driver Restore", "\n".join(results))
        else:
            messagebox.showinfo("Driver Restore", "No drivers could be processed for restore.")

        self.refresh_state()

    def show_readiness_score(self):
        score, details = get_security_readiness_score()
        msg = f"Security Readiness Score: {score}/100\n\n" + "\n".join(details)
        messagebox.showinfo("Security Readiness", msg)

    def shutdown(self):
        if self.watchdog:
            self.watchdog.stop()


def main():
    # CLI override: --json for snapshot
    if len(sys.argv) > 1:
        if sys.argv[1] == "--json":
            print_json_snapshot()
            return

    root = tk.Tk()
    app = SecurityGovernorGUI(root)

    def on_close():
        app.shutdown()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()


if __name__ == "__main__":
    main()
