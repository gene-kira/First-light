import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import time
import ctypes
import os
import sys

# ================== CONFIG ==================
CHECK_INTERVAL = 5          # seconds between AI checks
LOGFILE = "mouse_ai_watchdog.log"

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001

ctypes.windll.kernel32.SetThreadExecutionState(
    ES_CONTINUOUS | ES_SYSTEM_REQUIRED
)

# ================== LOGGING ==================
def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line)


# ================== SYSTEM HELPERS ==================
def run_ps(command):
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True
        )
        return result.stdout.strip(), result.stderr.strip()
    except Exception as e:
        return "", str(e)


def get_mouse_status():
    cmd = "Get-PnpDevice -Class Mouse | Select-Object Status, FriendlyName"
    out, err = run_ps(cmd)
    if err:
        log(f"[ERROR] Get-PnpDevice: {err}")
    return out


def get_usb_selective_suspend():
    cmd = r"""
    $scheme = powercfg /getactivescheme
    $guid = ($scheme -split '\s+')[3]
    powercfg /q $guid SUB_USB USBSELECTIVE SUSPEND
    """
    out, err = run_ps(cmd)
    if err:
        log(f"[ERROR] USB selective suspend query: {err}")
        return "Unknown"
    if "Enabled" in out:
        return "Enabled"
    if "Disabled" in out:
        return "Disabled"
    return "Unknown"


def set_usb_selective_suspend(disable=True):
    cmd = r"""
    $scheme = powercfg /getactivescheme
    $guid = ($scheme -split '\s+')[3]
    """
    if disable:
        cmd += r"""
        powercfg /setacvalueindex $guid SUB_USB USBSELECTIVE 0
        powercfg /setdcvalueindex $guid SUB_USB USBSELECTIVE 0
        powercfg /S $guid
        """
    else:
        cmd += r"""
        powercfg /setacvalueindex $guid SUB_USB USBSELECTIVE 1
        powercfg /setdcvalueindex $guid SUB_USB USBSELECTIVE 1
        powercfg /S $guid
        """
    out, err = run_ps(cmd)
    if err:
        log(f"[ERROR] Set USB selective suspend: {err}")
    else:
        log(f"[OK] USB selective suspend set to {'Disabled' if disable else 'Enabled'}")


def restart_hid_driver():
    log("[AI] Attempting HID driver restart...")
    try:
        subprocess.run(
            ["devcon", "restart", "hidclass"],
            capture_output=True,
            text=True
        )
        log("[AI] HID driver restart command issued.")
    except Exception as e:
        log(f"[ERROR] HID driver restart failed: {e}")


# ================== AI WATCHDOG ==================
class MouseAIWatchdog(threading.Thread):
    def __init__(self, ui_update_callback):
        super().__init__(daemon=True)
        self.running = False
        self.ui_update_callback = ui_update_callback

    def run(self):
        self.running = True
        log("=== Mouse AI Watchdog Started ===")
        while self.running:
            status_text = get_mouse_status().lower()
            if "ok" in status_text:
                log("[AI] Mouse status OK.")
                self.ui_update_callback("OK", status_text)
            else:
                log("[AI] Mouse status NOT OK — triggering repair.")
                self.ui_update_callback("ISSUE", status_text)
                # AI logic: escalate based on pattern
                restart_hid_driver()
            time.sleep(CHECK_INTERVAL)

    def stop(self):
        self.running = False
        log("=== Mouse AI Watchdog Stopped ===")


# ================== GUI ==================
class MouseAIApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Mouse Power & AI Watchdog")
        self.root.geometry("700x400")
        self.root.resizable(False, False)

        self.watchdog = None

        self.create_widgets()
        self.refresh_status()

    def create_widgets(self):
        # Status frame
        status_frame = ttk.LabelFrame(self.root, text="Mouse Status & Power")
        status_frame.pack(fill="x", padx=10, pady=10)

        self.mouse_status_label = ttk.Label(status_frame, text="Mouse Status: Unknown", font=("Segoe UI", 10, "bold"))
        self.mouse_status_label.pack(anchor="w", padx=10, pady=5)

        self.mouse_detail_text = tk.Text(status_frame, height=5, width=80)
        self.mouse_detail_text.pack(padx=10, pady=5)
        self.mouse_detail_text.configure(state="disabled")

        self.usb_power_label = ttk.Label(status_frame, text="USB Selective Suspend: Unknown", font=("Segoe UI", 10))
        self.usb_power_label.pack(anchor="w", padx=10, pady=5)

        # Controls frame
        control_frame = ttk.LabelFrame(self.root, text="Power & AI Controls")
        control_frame.pack(fill="x", padx=10, pady=10)

        self.btn_disable_usb = ttk.Button(control_frame, text="Disable USB Selective Suspend", command=self.disable_usb_suspend)
        self.btn_disable_usb.grid(row=0, column=0, padx=5, pady=5, sticky="w")

        self.btn_enable_usb = ttk.Button(control_frame, text="Enable USB Selective Suspend", command=self.enable_usb_suspend)
        self.btn_enable_usb.grid(row=0, column=1, padx=5, pady=5, sticky="w")

        self.btn_manual_restart = ttk.Button(control_frame, text="Manual HID Driver Restart", command=self.manual_restart)
        self.btn_manual_restart.grid(row=1, column=0, padx=5, pady=5, sticky="w")

        self.ai_status_label = ttk.Label(control_frame, text="AI Watchdog: Stopped", font=("Segoe UI", 10, "bold"))
        self.ai_status_label.grid(row=2, column=0, padx=5, pady=10, sticky="w")

        self.btn_start_ai = ttk.Button(control_frame, text="Start AI Watchdog", command=self.start_ai)
        self.btn_start_ai.grid(row=2, column=1, padx=5, pady=5, sticky="w")

        self.btn_stop_ai = ttk.Button(control_frame, text="Stop AI Watchdog", command=self.stop_ai)
        self.btn_stop_ai.grid(row=2, column=2, padx=5, pady=5, sticky="w")

        # Log frame
        log_frame = ttk.LabelFrame(self.root, text="Log & Info")
        log_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.log_text = tk.Text(log_frame, height=8, width=80)
        self.log_text.pack(padx=10, pady=5)
        self.log_text.configure(state="disabled")

        self.btn_open_log = ttk.Button(log_frame, text="Open Log File", command=self.open_log)
        self.btn_open_log.pack(anchor="e", padx=10, pady=5)

    def refresh_status(self):
        # Mouse status
        status_raw = get_mouse_status()
        status_lower = status_raw.lower()
        if "ok" in status_lower:
            self.mouse_status_label.config(text="Mouse Status: OK", foreground="green")
        else:
            self.mouse_status_label.config(text="Mouse Status: ISSUE", foreground="red")

        self.mouse_detail_text.configure(state="normal")
        self.mouse_detail_text.delete("1.0", tk.END)
        self.mouse_detail_text.insert(tk.END, status_raw or "No mouse devices found.")
        self.mouse_detail_text.configure(state="disabled")

        # USB selective suspend
        usb_state = get_usb_selective_suspend()
        self.usb_power_label.config(text=f"USB Selective Suspend: {usb_state}")

        # Schedule next refresh
        self.root.after(5000, self.refresh_status)

    def disable_usb_suspend(self):
        set_usb_selective_suspend(disable=True)
        messagebox.showinfo("USB Power", "USB selective suspend disabled.\nThis helps keep mouse power stable.")
        self.refresh_status()

    def enable_usb_suspend(self):
        set_usb_selective_suspend(disable=False)
        messagebox.showinfo("USB Power", "USB selective suspend enabled.\nWindows may power down USB ports to save energy.")
        self.refresh_status()

    def manual_restart(self):
        if messagebox.askyesno("Confirm", "Restart HID driver now?\nMouse may briefly disconnect."):
            restart_hid_driver()
            messagebox.showinfo("HID Driver", "HID driver restart command issued.")

    def start_ai(self):
        if self.watchdog and self.watchdog.running:
            messagebox.showinfo("AI Watchdog", "AI Watchdog is already running.")
            return
        self.watchdog = MouseAIWatchdog(self.update_ai_view)
        self.watchdog.start()
        self.ai_status_label.config(text="AI Watchdog: Running", foreground="green")
        log("[UI] AI Watchdog started.")

    def stop_ai(self):
        if self.watchdog:
            self.watchdog.stop()
            self.watchdog = None
            self.ai_status_label.config(text="AI Watchdog: Stopped", foreground="red")
            log("[UI] AI Watchdog stopped.")

    def update_ai_view(self, state, detail):
        # Called from watchdog thread; use after() to update safely
        def _update():
            if state == "OK":
                self.mouse_status_label.config(text="Mouse Status: OK (AI)", foreground="green")
            else:
                self.mouse_status_label.config(text="Mouse Status: ISSUE (AI)", foreground="red")

            self.mouse_detail_text.configure(state="normal")
            self.mouse_detail_text.delete("1.0", tk.END)
            self.mouse_detail_text.insert(tk.END, detail)
            self.mouse_detail_text.configure(state="disabled")

            self.append_log_view(detail)

        self.root.after(0, _update)

    def append_log_view(self, text):
        self.log_text.configure(state="normal")
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)
        self.log_text.configure(state="disabled")

    def open_log(self):
        if not os.path.exists(LOGFILE):
            messagebox.showinfo("Log", "No log file yet.")
            return
        try:
            os.startfile(LOGFILE)
        except Exception as e:
            messagebox.showerror("Log", f"Could not open log file:\n{e}")


def main():
    root = tk.Tk()
    app = MouseAIApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
