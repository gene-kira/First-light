# === AUTO-ELEVATION CHECK ===
import ctypes
import os
import sys

def ensure_admin():
    try:
        # If not running as admin, relaunch with elevation
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
        print(f"[Codex Sentinel] Elevation failed: {e}")
        sys.exit()

ensure_admin()

import json
import sys
import ctypes
import winreg
import tkinter as tk
from tkinter import messagebox

try:
    import wmi
except ImportError:
    wmi = None


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


# ---------- BitLocker ----------

def get_bitlocker_status():
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

            if any(p in provider for p in ["Microsoft", "Intel", "AMD", "NVIDIA"]):
                continue

            suspects.append({
                "DeviceName": getattr(d, "DeviceName", ""),
                "DriverVersion": getattr(d, "DriverVersion", ""),
                "DriverProviderName": provider,
                "InfName": getattr(d, "InfName", "")
            })
    except Exception as e:
        return [{"error": str(e)}]

    return suspects


# ---------- Memory Integrity toggle ----------

def set_memory_integrity(enable: bool):
    key_path = r"SYSTEM\\CurrentControlSet\\Control\\DeviceGuard\\Scenarios\\HypervisorEnforcedCodeIntegrity"
    try:
        key = winreg.CreateKey(winreg.HKEY_LOCAL_MACHINE, key_path)
        value = 1 if enable else 0
        winreg.SetValueEx(key, "Enabled", 0, winreg.REG_DWORD, value)
        winreg.CloseKey(key)
        return True, None
    except PermissionError:
        return False, "Permission denied (run as Administrator)."
    except Exception as e:
        return False, str(e)


# ---------- Snapshot ----------

def get_security_snapshot():
    snapshot = {
        "DeviceGuard": get_device_guard_status(),
        "SecureBoot": get_secure_boot_status(),
        "BitLocker": get_bitlocker_status(),
        "DriverBlocks": get_driver_blockers()
    }
    return snapshot


def print_json_snapshot():
    snap = get_security_snapshot()
    print(json.dumps(snap, indent=2))


# ---------- GUI ----------

class SecurityGovernorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Governor")
        self.root.geometry("480x320")

        self.label_status = tk.Label(root, text="", anchor="w", justify="left")
        self.label_status.pack(padx=10, pady=10, fill="x")

        self.button_toggle = tk.Button(root, text="...", command=self.toggle_hvci)
        self.button_toggle.pack(padx=10, pady=10)

        self.label_warning = tk.Label(
            root,
            text="Changing Memory Integrity requires a reboot\nand may be blocked by incompatible drivers.",
            anchor="w",
            justify="left"
        )
        self.label_warning.pack(padx=10, pady=10, fill="x")

        self.text_drivers = tk.Text(root, height=8)
        self.text_drivers.pack(padx=10, pady=10, fill="both", expand=True)

        self.hvci_current = False
        self.refresh_state()

    def refresh_state(self):
        snap = get_security_snapshot()
        dg = snap.get("DeviceGuard", {})
        hvci_enabled = False
        if isinstance(dg, dict):
            hvci_enabled = dg.get("HVCIEnabled", False)

        self.hvci_current = hvci_enabled

        status_lines = []
        status_lines.append(f"Memory Integrity (HVCI): {'ON' if hvci_enabled else 'OFF'}")

        sb = snap.get("SecureBoot", {})
        status_lines.append(f"Secure Boot: {sb.get('Enabled', False)}")

        bl = snap.get("BitLocker", {})
        status_lines.append(f"BitLocker ProtectionStatus: {bl.get('ProtectionStatus', 'Unknown')}")

        self.label_status.config(text="\n".join(status_lines))

        if hvci_enabled:
            self.button_toggle.config(text="Turn OFF Memory Integrity")
        else:
            self.button_toggle.config(text="Turn ON Memory Integrity")

        self.text_drivers.delete("1.0", tk.END)
        self.text_drivers.insert(tk.END, "Potential non-Microsoft/OEM drivers:\n\n")
        for d in snap.get("DriverBlocks", []):
            if "error" in d:
                self.text_drivers.insert(tk.END, f"ERROR: {d['error']}\n")
                continue
            line = f"{d.get('DeviceName','')} | {d.get('DriverProviderName','')} | {d.get('DriverVersion','')} | {d.get('InfName','')}\n"
            self.text_drivers.insert(tk.END, line)

    def toggle_hvci(self):
        target = not self.hvci_current
        msg = f"Set Memory Integrity to {'ON' if target else 'OFF'} and require reboot?"
        if messagebox.askyesno("Confirm", msg):
            ok, err = set_memory_integrity(target)
            if not ok:
                messagebox.showerror("Error", f"Failed to set Memory Integrity: {err}")
            else:
                messagebox.showinfo("Info", "Memory Integrity registry updated.\nReboot required.")
                self.refresh_state()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--json":
        print_json_snapshot()
        return

    root = tk.Tk()
    app = SecurityGovernorGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
