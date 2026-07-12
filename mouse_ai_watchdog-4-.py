import tkinter as tk
from tkinter import ttk, messagebox
import subprocess
import threading
import time
import ctypes
import os

# ================== CONFIG ==================
CHECK_INTERVAL = 5
LOGFILE = "hid_audio_ai_governor.log"

ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001

ctypes.windll.kernel32.SetThreadExecutionState(
    ES_CONTINUOUS | ES_SYSTEM_REQUIRED
)

USB_SUSPEND_STATE = "Unknown"

# ================== LOGGING ==================
def log(msg):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    with open(LOGFILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")
    print(line)

# ================== POWERSHELL RUNNER ==================
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

# ================== HID STATUS (MOUSE / KEYBOARD) ==================
def get_mouse_status():
    cmd = "Get-PnpDevice -Class Mouse | Select-Object Status, FriendlyName, InstanceId"
    out, err = run_ps(cmd)
    if err:
        log(f"[ERROR] Get-PnpDevice Mouse: {err}")
    return out

def get_keyboard_status():
    cmd = "Get-PnpDevice -Class Keyboard | Select-Object Status, FriendlyName, InstanceId"
    out, err = run_ps(cmd)
    if err:
        log(f"[ERROR] Get-PnpDevice Keyboard: {err}")
    return out

# ================== USB MICROPHONE STATUS ==================
def get_mic_status():
    """
    USB microphone status via AudioEndpoint / SoundDevice.
    """
    cmd = r"""
    $ep = Get-PnpDevice -Class AudioEndpoint -ErrorAction SilentlyContinue |
          Select-Object Status, FriendlyName, InstanceId
    if (-not $ep) {
        $ep = Get-WmiObject Win32_SoundDevice -ErrorAction SilentlyContinue |
              Select-Object Status, Name, DeviceID
    }
    $ep | Format-Table -AutoSize
    """
    out, err = run_ps(cmd)
    if err:
        log(f"[ERROR] USB Mic status query: {err}")
    return out

def restart_mic_driver():
    """
    Try to restart audio/media class for USB mic.
    """
    log("[AI] Attempting USB microphone driver restart...")
    try:
        # Generic media/audio class restart
        subprocess.run(
            ["devcon", "restart", "=media"],
            capture_output=True,
            text=True
        )
        log("[AI] Media/audio driver restart command issued.")
    except Exception as e:
        log(f"[ERROR] USB microphone driver restart failed: {e}")

# ================== USB SELECTIVE SUSPEND (STATE-TRACKING ONLY) ==================
def get_usb_selective_suspend():
    return USB_SUSPEND_STATE

def set_usb_selective_suspend(disable=True):
    global USB_SUSPEND_STATE

    out, err = run_ps("(powercfg /getactivescheme)")
    if err or not out:
        log(f"[ERROR] Active scheme query: {err}")
        return
    try:
        guid = out.split()[3]
    except Exception:
        log("[ERROR] Could not parse active power scheme GUID")
        return

    if disable:
        cmds = [
            f"powercfg /setacvalueindex {guid} SUB_USB USBSELECTIVE 0",
            f"powercfg /setdcvalueindex {guid} SUB_USB USBSELECTIVE 0",
            f"powercfg /S {guid}"
        ]
        USB_SUSPEND_STATE = "Disabled"
    else:
        cmds = [
            f"powercfg /setacvalueindex {guid} SUB_USB USBSELECTIVE 1",
            f"powercfg /setdcvalueindex {guid} SUB_USB USBSELECTIVE 1",
            f"powercfg /S {guid}"
        ]
        USB_SUSPEND_STATE = "Enabled"

    for cmd in cmds:
        out, err = run_ps(cmd)
        if err:
            log(f"[ERROR] {cmd}: {err}")

    log(f"[OK] USB selective suspend set to {USB_SUSPEND_STATE}")

# ================== HID DRIVER RESTART ==================
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

# ================== USB CONTROLLER / PRIORITY ==================
def get_usb_controller_priority_map():
    out, err = run_ps("""
        Get-WmiObject Win32_USBControllerDevice |
        ForEach-Object {
            $dev = $_.Dependent
            $ctrl = $_.Antecedent
            [PSCustomObject]@{
                Controller = $ctrl
                Device = $dev
            }
        } | Format-Table -AutoSize
    """)
    if err:
        log(f"[ERROR] USB controller map: {err}")
    return out

def get_hid_devices():
    out, err = run_ps("""
        $m = Get-PnpDevice -Class Mouse | Select-Object FriendlyName, InstanceId
        $k = Get-PnpDevice -Class Keyboard | Select-Object FriendlyName, InstanceId
        $m + $k | Format-Table -AutoSize
    """)
    if err:
        log(f"[ERROR] HID devices query: {err}")
    return out

def analyze_hid_priority():
    hid = get_hid_devices()
    ctrlmap = get_usb_controller_priority_map()
    report = "=== HID PRIORITY ANALYSIS ===\n"

    for line in hid.splitlines():
        if not line.strip():
            continue
        if "FriendlyName" in line or "InstanceId" in line:
            continue
        dev = line.strip()
        if "Hub" in ctrlmap:
            report += f"[LOW] {dev} may be on a USB hub (lower priority)\n"
        else:
            report += f"[HIGH] {dev} appears on a root controller (higher priority)\n"

    return report

def enforce_hid_priority():
    report = analyze_hid_priority()
    log(report)
    if "[LOW]" in report:
        log("[AI] HID devices detected on possible low-priority hub — recommend moving mouse/keyboard to rear motherboard ports.")
    else:
        log("[AI] HID devices appear on higher-priority controllers.")
    return report

# ================== METRICS / BUS LOAD / INTERRUPTS ==================
def get_usb_bus_load():
    out, err = run_ps("""
        Get-WmiObject Win32_USBHub |
        Select-Object Name, Status, DeviceID |
        Format-Table -AutoSize
    """)
    if err:
        log(f"[ERROR] USB bus load query: {err}")
    return "=== USB BUS HUBS ===\n" + (out or "No hubs found.")

def get_interrupt_latency():
    out, err = run_ps("""
        Get-Counter '\\Processor(_Total)\\Interrupts/sec' |
        Select-Object -ExpandProperty CounterSamples |
        Select-Object CookedValue
    """)
    if err:
        log(f"[ERROR] Interrupt latency query: {err}")
        return "Interrupts/sec: Unknown"
    lines = out.splitlines()
    val = "Unknown"
    for line in lines:
        line = line.strip()
        if line and (line[0].isdigit() or line[0] == '-'):
            val = line
            break
    return f"Interrupts/sec (approx HID latency proxy): {val}"

def smooth_metric(value_list, new_value, window=5):
    value_list.append(new_value)
    if len(value_list) > window:
        value_list.pop(0)
    try:
        nums = []
        for v in value_list:
            if isinstance(v, (int, float)):
                nums.append(float(v))
            else:
                s = str(v)
                if s.replace('.', '', 1).replace('-', '', 1).isdigit():
                    nums.append(float(s))
        if nums:
            return sum(nums) / len(nums)
    except Exception:
        pass
    return new_value

# ================== GAME DETECTION ==================
def is_game_running():
    """
    Simple game detection: look for common game processes.
    You can extend this list.
    """
    game_names = [
        "steam", "epicgameslauncher", "battle.net",
        "cs2", "valorant", "fortnite", "warzone",
        "eldenring", "gtav", "rdr2"
    ]
    ps_cmd = "Get-Process | Select-Object -ExpandProperty ProcessName"
    out, err = run_ps(ps_cmd)
    if err:
        log(f"[ERROR] Game detection query: {err}")
        return False
    names = [n.lower() for n in out.splitlines() if n.strip()]
    return any(g in names for g in game_names)

# ================== AI WATCHDOG ==================
class HIDAudioAIWatchdog(threading.Thread):
    def __init__(self, ui_update_callback):
        super().__init__(daemon=True)
        self.running = False
        self.ui_update_callback = ui_update_callback
        self.latency_history = []

    def run(self):
        self.running = True
        log("=== HID + USB Mic AI Watchdog Started ===")
        while self.running:
            mouse_status = get_mouse_status().lower()
            keyboard_status = get_keyboard_status().lower()
            mic_status = get_mic_status().lower()

            hid_ok = "ok" in mouse_status and "ok" in keyboard_status
            mic_ok = "ok" in mic_status or "working properly" in mic_status

            if hid_ok and mic_ok:
                log("[AI] HID + Mic status OK.")
                self.ui_update_callback("OK", mouse_status + "\n" + keyboard_status + "\n" + mic_status)
            else:
                log("[AI] HID/Mic status NOT OK — triggering repair.")
                self.ui_update_callback("ISSUE", mouse_status + "\n" + keyboard_status + "\n" + mic_status)
                restart_hid_driver()
                restart_mic_driver()

            priority_report = enforce_hid_priority()
            self.ui_update_callback("PRIORITY", priority_report)

            latency_text = get_interrupt_latency()
            try:
                val_str = latency_text.split(":")[-1].strip()
                if val_str.replace('.', '', 1).replace('-', '', 1).isdigit():
                    val = float(val_str)
                else:
                    val = 0.0
            except Exception:
                val = 0.0
            smoothed = smooth_metric(self.latency_history, val)
            metrics_text = latency_text + f"\nSmoothed (AI HID smoothing proxy): {smoothed:.2f}"
            bus_text = get_usb_bus_load()

            game_mode = is_game_running()
            gm_text = f"Game mode: {'ACTIVE' if game_mode else 'inactive'}"
            self.ui_update_callback("METRICS", gm_text + "\n\n" + metrics_text + "\n\n" + bus_text)

            time.sleep(CHECK_INTERVAL if not game_mode else max(2, CHECK_INTERVAL - 2))

    def stop(self):
        self.running = False
        log("=== HID + USB Mic AI Watchdog Stopped ===")

# ================== GUI ==================
class HIDAudioAIApp:
    def __init__(self, root):
        self.root = root
        self.root.title("📡 HID + USB Mic Power AI Governor")
        self.root.geometry("1000x650")
        self.root.resizable(False, False)

        self.watchdog = None

        self.create_widgets()
        self.refresh_status()

    def create_widgets(self):
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=5, pady=5)

        self.tab_status = ttk.Frame(self.notebook)
        self.tab_power = ttk.Frame(self.notebook)
        self.tab_priority = ttk.Frame(self.notebook)
        self.tab_metrics = ttk.Frame(self.notebook)
        self.tab_mic = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_status, text="📡 HID Status")
        self.notebook.add(self.tab_mic, text="🎤 Mic Status")
        self.notebook.add(self.tab_power, text="💾 Power")
        self.notebook.add(self.tab_priority, text="⚙ Priority")
        self.notebook.add(self.tab_metrics, text="🔥 Metrics")

        status_frame = ttk.LabelFrame(self.tab_status, text="Mouse & Keyboard Status")
        status_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.mouse_status_label = ttk.Label(status_frame, text="Mouse Status: Unknown", font=("Segoe UI", 10, "bold"))
        self.mouse_status_label.pack(anchor="w", padx=10, pady=5)

        self.keyboard_status_label = ttk.Label(status_frame, text="Keyboard Status: Unknown", font=("Segoe UI", 10, "bold"))
        self.keyboard_status_label.pack(anchor="w", padx=10, pady=5)

        self.hid_detail_text = tk.Text(status_frame, height=12, width=110)
        self.hid_detail_text.pack(padx=10, pady=5)
        self.hid_detail_text.configure(state="disabled")

        mic_frame = ttk.LabelFrame(self.tab_mic, text="USB Microphone Status")
        mic_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.mic_status_label = ttk.Label(mic_frame, text="Mic Status: Unknown", font=("Segoe UI", 10, "bold"))
        self.mic_status_label.pack(anchor="w", padx=10, pady=5)

        self.mic_detail_text = tk.Text(mic_frame, height=12, width=110)
        self.mic_detail_text.pack(padx=10, pady=5)
        self.mic_detail_text.configure(state="disabled")

        self.btn_restart_mic = ttk.Button(mic_frame, text="Restart Mic Driver", command=self.manual_restart_mic)
        self.btn_restart_mic.pack(anchor="w", padx=10, pady=5)

        power_frame = ttk.LabelFrame(self.tab_power, text="USB Power & HID/Mic Control")
        power_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.usb_power_label = ttk.Label(power_frame, text="USB Selective Suspend: Unknown", font=("Segoe UI", 10))
        self.usb_power_label.pack(anchor="w", padx=10, pady=5)

        self.btn_disable_usb = ttk.Button(power_frame, text="Disable USB Selective Suspend", command=self.disable_usb_suspend)
        self.btn_disable_usb.pack(anchor="w", padx=10, pady=5)

        self.btn_enable_usb = ttk.Button(power_frame, text="Enable USB Selective Suspend", command=self.enable_usb_suspend)
        self.btn_enable_usb.pack(anchor="w", padx=10, pady=5)

        self.btn_manual_restart_hid = ttk.Button(power_frame, text="Manual HID Driver Restart", command=self.manual_restart_hid)
        self.btn_manual_restart_hid.pack(anchor="w", padx=10, pady=5)

        self.ai_status_label = ttk.Label(power_frame, text="AI Watchdog: Stopped", font=("Segoe UI", 10, "bold"))
        self.ai_status_label.pack(anchor="w", padx=10, pady=10)

        self.btn_start_ai = ttk.Button(power_frame, text="Start AI Watchdog", command=self.start_ai)
        self.btn_start_ai.pack(anchor="w", padx=10, pady=5)

        self.btn_stop_ai = ttk.Button(power_frame, text="Stop AI Watchdog", command=self.stop_ai)
        self.btn_stop_ai.pack(anchor="w", padx=10, pady=5)

        priority_frame = ttk.LabelFrame(self.tab_priority, text="USB HID Priority Analysis")
        priority_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.priority_text = tk.Text(priority_frame, height=20, width=110)
        self.priority_text.pack(padx=10, pady=5)
        self.priority_text.configure(state="disabled")

        self.btn_refresh_priority = ttk.Button(priority_frame, text="Refresh HID Priority Analysis", command=self.refresh_priority)
        self.btn_refresh_priority.pack(anchor="e", padx=10, pady=5)

        metrics_frame = ttk.LabelFrame(self.tab_metrics, text="Bus Load, Interrupts & Game Mode")
        metrics_frame.pack(fill="both", expand=True, padx=10, pady=10)

        self.metrics_text = tk.Text(metrics_frame, height=20, width=110)
        self.metrics_text.pack(padx=10, pady=5)
        self.metrics_text.configure(state="disabled")

        self.btn_refresh_metrics = ttk.Button(metrics_frame, text="Refresh Metrics", command=self.refresh_metrics)
        self.btn_refresh_metrics.pack(anchor="e", padx=10, pady=5)

        self.btn_open_log = ttk.Button(self.root, text="Open Log File", command=self.open_log)
        self.btn_open_log.pack(anchor="e", padx=10, pady=5)

    def refresh_status(self):
        mouse_raw = get_mouse_status()
        keyboard_raw = get_keyboard_status()
        mic_raw = get_mic_status()

        mouse_lower = mouse_raw.lower()
        keyboard_lower = keyboard_raw.lower()
        mic_lower = mic_raw.lower()

        if "ok" in mouse_lower:
            self.mouse_status_label.config(text="Mouse Status: OK", foreground="green")
        else:
            self.mouse_status_label.config(text="Mouse Status: ISSUE", foreground="red")

        if "ok" in keyboard_lower:
            self.keyboard_status_label.config(text="Keyboard Status: OK", foreground="green")
        else:
            self.keyboard_status_label.config(text="Keyboard Status: ISSUE", foreground="red")

        if "ok" in mic_lower or "working properly" in mic_lower:
            self.mic_status_label.config(text="Mic Status: OK", foreground="green")
        else:
            self.mic_status_label.config(text="Mic Status: ISSUE", foreground="red")

        self.hid_detail_text.configure(state="normal")
        self.hid_detail_text.delete("1.0", tk.END)
        self.hid_detail_text.insert(tk.END, "=== Mouse ===\n" + (mouse_raw or "No mouse devices found.") + "\n\n")
        self.hid_detail_text.insert(tk.END, "=== Keyboard ===\n" + (keyboard_raw or "No keyboard devices found.") + "\n")
        self.hid_detail_text.configure(state="disabled")

        self.mic_detail_text.configure(state="normal")
        self.mic_detail_text.delete("1.0", tk.END)
        self.mic_detail_text.insert(tk.END, mic_raw or "No audio endpoints / USB mic found.")
        self.mic_detail_text.configure(state="disabled")

        usb_state = get_usb_selective_suspend()
        self.usb_power_label.config(text=f"USB Selective Suspend: {usb_state}")

        self.root.after(5000, self.refresh_status)

    def disable_usb_suspend(self):
        set_usb_selective_suspend(disable=True)
        messagebox.showinfo("USB Power", "USB selective suspend disabled.\nMouse, keyboard and USB mic will stay at full power more reliably.")
        self.refresh_status()

    def enable_usb_suspend(self):
        set_usb_selective_suspend(disable=False)
        messagebox.showinfo("USB Power", "USB selective suspend enabled.\nWindows may power down USB ports to save energy.")
        self.refresh_status()

    def manual_restart_hid(self):
        if messagebox.askyesno("Confirm", "Restart HID driver now?\nMouse and keyboard may briefly disconnect."):
            restart_hid_driver()
            messagebox.showinfo("HID Driver", "HID driver restart command issued.")

    def manual_restart_mic(self):
        if messagebox.askyesno("Confirm", "Restart USB microphone driver now?\nAudio may briefly cut out."):
            restart_mic_driver()
            messagebox.showinfo("Mic Driver", "USB microphone driver restart command issued.")

    def start_ai(self):
        if self.watchdog and self.watchdog.running:
            messagebox.showinfo("AI Watchdog", "AI Watchdog is already running.")
            return
        self.watchdog = HIDAudioAIWatchdog(self.update_ai_view)
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
        def _update():
            if state == "OK":
                self.mouse_status_label.config(text="Mouse Status: OK (AI)", foreground="green")
                self.keyboard_status_label.config(text="Keyboard Status: OK (AI)", foreground="green")
                self.mic_status_label.config(text="Mic Status: OK (AI)", foreground="green")
            elif state == "ISSUE":
                self.mouse_status_label.config(text="Mouse Status: ISSUE (AI)", foreground="red")
                self.keyboard_status_label.config(text="Keyboard Status: ISSUE (AI)", foreground="red")
                self.mic_status_label.config(text="Mic Status: ISSUE (AI)", foreground="red")
            elif state == "PRIORITY":
                self.priority_text.configure(state="normal")
                self.priority_text.delete("1.0", tk.END)
                self.priority_text.insert(tk.END, detail)
                self.priority_text.configure(state="disabled")
            elif state == "METRICS":
                self.metrics_text.configure(state="normal")
                self.metrics_text.delete("1.0", tk.END)
                self.metrics_text.insert(tk.END, detail)
                self.metrics_text.configure(state="disabled")

        self.root.after(0, _update)

    def refresh_priority(self):
        report = enforce_hid_priority()
        self.priority_text.configure(state="normal")
        self.priority_text.delete("1.0", tk.END)
        self.priority_text.insert(tk.END, report)
        self.priority_text.configure(state="disabled")

    def refresh_metrics(self):
        gm = "ACTIVE" if is_game_running() else "inactive"
        latency_text = get_interrupt_latency()
        bus_text = get_usb_bus_load()
        self.metrics_text.configure(state="normal")
        self.metrics_text.delete("1.0", tk.END)
        self.metrics_text.insert(tk.END, f"Game mode: {gm}\n\n" + latency_text + "\n\n" + bus_text)
        self.metrics_text.configure(state="disabled")

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
    app = HIDAudioAIApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()
