import tkinter as tk
from tkinter import messagebox
import os, sys, platform, ctypes, winreg
import threading
import time

# ============================================================
# 🧿 GLOBAL STATE / FLAGS
# ============================================================
SECURE_MODE = False
PERSONA_LOCKED = False
SWARM_SYNC_ENABLED = True
SYMBOLIC_REGISTRY_ENABLED = True
THREAT_PANEL_OVERRIDES_ENABLED = True
TELEMETRY_SUPPRESSION_ENABLED = True
GROUP_POLICY_ENFORCEMENT_ENABLED = True

# Hardware tuning envelopes (symbolic)
CPU_ENVELOPE = "Balanced"
GPU_ENVELOPE = "Sentinel"
IO_ENVELOPE = "Normal"

safe_mode = True  # set in main


# ============================================================
# 🧿 AUTO‑ELEVATION RITUAL
# ============================================================
def elevate():
    if "--elevated" not in sys.argv:
        try:
            params = " ".join([f'"{arg}"' for arg in sys.argv] + ["--elevated"])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            sys.exit()
        except Exception as e:
            messagebox.showerror("Elevation Error", str(e))
            sys.exit()


# ============================================================
# 🧿 COMPATIBILITY CHECKS
# ============================================================
def is_windows_compatible():
    try:
        ver = sys.getwindowsversion()
        return ver.major >= 10
    except Exception:
        return False


def has_registry_access():
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            r"Software\Microsoft\Windows\CurrentVersion\Explorer",
            0,
            winreg.KEY_SET_VALUE,
        ):
            return True
    except Exception:
        return False


def is_admin():
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


# ============================================================
# 🧿 MODE DETECTION
# ============================================================
def detect_safe_mode():
    return not (is_windows_compatible() and has_registry_access() and is_admin())


# ============================================================
# 🧿 SCHEDULER QoS DETECTION (SYMBOLIC)
# ============================================================
def get_scheduler_qos():
    """
    Symbolic Scheduler QoS based on current process priority class.
    No external deps, uses Win32 GetPriorityClass.
    """
    try:
        kernel32 = ctypes.windll.kernel32
        GetCurrentProcess = kernel32.GetCurrentProcess
        GetPriorityClass = kernel32.GetPriorityClass

        h_proc = GetCurrentProcess()
        prio = GetPriorityClass(h_proc)

        # Priority class constants (Win32)
        PRIORITY_MAP = {
            0x20: "Normal",
            0x40: "Idle",
            0x80: "High",
            0x100: "Realtime",
            0x4000: "Below Normal",
            0x8000: "Above Normal",
        }

        qos = PRIORITY_MAP.get(prio, "Unknown")
        # Symbolic QoS tiering
        if qos in ("Realtime", "High"):
            return "QoS: Critical / High"
        elif qos in ("Above Normal", "Normal"):
            return "QoS: Standard"
        elif qos in ("Below Normal", "Idle"):
            return "QoS: Background"
        else:
            return "QoS: Unknown"
    except Exception:
        return "QoS: Undetected"


# ============================================================
# 🧿 CODEX SENTINEL STACK (SYMBOLIC IMPLEMENTATION)
# ============================================================
class CodexSentinel:
    def __init__(self):
        self.watchdog_thread = None
        self.watchdog_running = False
        self.snapshot_counter = 0
        self.last_snapshot_time = None

    def start_watchdog(self):
        if self.watchdog_running:
            return
        self.watchdog_running = True
        self.watchdog_thread = threading.Thread(
            target=self._watchdog_loop, daemon=True
        )
        self.watchdog_thread.start()

    def stop_watchdog(self):
        self.watchdog_running = False

    def _watchdog_loop(self):
        while self.watchdog_running:
            self.snapshot_processes()
            time.sleep(5)

    def snapshot_processes(self):
        # Symbolic snapshot only – no real process scraping
        self.snapshot_counter += 1
        self.last_snapshot_time = time.strftime("%H:%M:%S")

    def apply_group_policy_enforcement(self):
        # Symbolic only: no real Group Policy changes
        pass

    def apply_telemetry_suppression(self):
        # Symbolic only: no real telemetry changes
        pass

    def persona_locked(self):
        return PERSONA_LOCKED

    def secure_mode_active(self):
        return SECURE_MODE


sentinel = CodexSentinel()


# ============================================================
# 🧿 HARDWARE TUNING ENVELOPES (SYMBOLIC)
# ============================================================
def set_hardware_envelope(mode):
    """
    Symbolic hardware tuning envelopes:
    - 'Ritual'  : more aggressive / sentinel‑style
    - 'Balanced': default
    - 'Silent'  : conservative
    """
    global CPU_ENVELOPE, GPU_ENVELOPE, IO_ENVELOPE

    if mode == "Ritual":
        CPU_ENVELOPE = "Ritual / High‑Response"
        GPU_ENVELOPE = "Ritual / Sentinel"
        IO_ENVELOPE = "Priority / Fast Path"
    elif mode == "Silent":
        CPU_ENVELOPE = "Silent / Low‑Impact"
        GPU_ENVELOPE = "Silent / Cool"
        IO_ENVELOPE = "Background / Gentle"
    else:
        CPU_ENVELOPE = "Balanced"
        GPU_ENVELOPE = "Sentinel"
        IO_ENVELOPE = "Normal"

    feedback(f"Hardware tuning envelope set to: {mode}", success=True)


# ============================================================
# 🧿 REGISTRY / CONFIG VISIBILITY
# ============================================================
def get_registry_value(root, path, name):
    try:
        with winreg.OpenKey(root, path, 0, winreg.KEY_READ) as key:
            value, _ = winreg.QueryValueEx(key, name)
            return value
    except Exception:
        return None


def show_registry_config():
    explorer_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
    snap_assist = get_registry_value(
        winreg.HKEY_CURRENT_USER, explorer_path, "EnableSnapAssistFlyout"
    )

    lines = [
        "🧿 Registry / Config Visibility",
        "",
        f"Explorer key: HKCU\\{explorer_path}",
        f"EnableSnapAssistFlyout: {snap_assist if snap_assist is not None else 'Not set'}",
        "",
        "Symbolic Config Envelopes:",
        f"CPU Envelope: {CPU_ENVELOPE}",
        f"GPU Envelope: {GPU_ENVELOPE}",
        f"IO Envelope: {IO_ENVELOPE}",
        "",
        get_scheduler_qos(),
    ]
    messagebox.showinfo("Registry / Config Visibility", "\n".join(lines))


# ============================================================
# 🧿 RITUAL FUNCTIONS
# ============================================================
def enable_god_mode():
    if SECURE_MODE and PERSONA_LOCKED:
        feedback("Secure Mode + Persona Lock: God Mode ritual blocked.", success=False)
        return

    try:
        path = os.path.expanduser(
            "~/Desktop/GodMode.{ED7BA470-8E54-465E-825C-99712043E01C}"
        )
        os.makedirs(path, exist_ok=True)
        feedback("God Mode activated.", success=True)
    except Exception as e:
        feedback(f"God Mode error:\n{e}", success=False)


def enable_hidden_feature():
    if SECURE_MODE and not SYMBOLIC_REGISTRY_ENABLED:
        feedback("Secure Mode: symbolic registry disabled, hidden feature blocked.", success=False)
        return

    try:
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Explorer"
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, "EnableSnapAssistFlyout", 0, winreg.REG_DWORD, 1)
        feedback("Hidden feature enabled.", success=True)
    except Exception as e:
        feedback(f"Registry error:\n{e}", success=False)


def show_all_settings():
    try:
        os.system("start ms-settings:")
        feedback("Windows Settings opened (All Settings).", success=True)
    except Exception as e:
        feedback(f"Show All Settings error:\n{e}", success=False)


# ============================================================
# 🧿 FEEDBACK RITUAL
# ============================================================
def feedback(message, success=True):
    if safe_mode:
        title = "Success" if success else "Error"
    else:
        title = "🧿 Ritual Complete" if success else "⚠️ Ritual Failed"

    if success:
        messagebox.showinfo(title, message)
    else:
        messagebox.showerror(title, message)


# ============================================================
# 🧿 PERSONA / SENTINEL PANELS
# ============================================================
def show_persona_status():
    status_lines = [
        f"{'🧿 ' if not safe_mode else ''}OS: {platform.system()} {platform.release()}",
        f"{'🧿 ' if not safe_mode else ''}Version: {platform.version()}",
        f"{'🧿 ' if not safe_mode else ''}Admin Privileges: {'Yes' if is_admin() else 'No'}",
        f"{'🧿 ' if not safe_mode else ''}Registry Access: {'Yes' if has_registry_access() else 'No'}",
        f"{'🧿 ' if not safe_mode else ''}Windows 10+ Compatible: {'Yes' if is_windows_compatible() else 'No'}",
        f"{'🧿 ' if not safe_mode else ''}Mode: {'Safe Mode' if safe_mode else 'Symbolic Mode'}",
        "",
        f"Secure Mode: {'Enabled' if SECURE_MODE else 'Disabled'}",
        f"Persona Lock: {'Engaged' if PERSONA_LOCKED else 'Released'}",
        f"Swarm Sync: {'Active' if SWARM_SYNC_ENABLED else 'Idle'}",
        f"Symbolic Registry: {'Enabled' if SYMBOLIC_REGISTRY_ENABLED else 'Disabled'}",
        f"Threat Panel Overrides: {'Enabled' if THREAT_PANEL_OVERRIDES_ENABLED else 'Disabled'}",
        f"Telemetry Suppression: {'Enabled' if TELEMETRY_SUPPRESSION_ENABLED else 'Disabled'}",
        f"Group Policy Enforcement: {'Enabled' if GROUP_POLICY_ENFORCEMENT_ENABLED else 'Disabled'}",
        "",
        f"CPU Envelope: {CPU_ENVELOPE}",
        f"GPU Envelope: {GPU_ENVELOPE}",
        f"IO Envelope: {IO_ENVELOPE}",
        get_scheduler_qos(),
        "",
        f"Watchdog: {'Running' if sentinel.watchdog_running else 'Stopped'}",
        f"Snapshots: {sentinel.snapshot_counter}",
        f"Last Snapshot: {sentinel.last_snapshot_time or 'N/A'}",
    ]
    messagebox.showinfo("Persona Status Panel", "\n".join(status_lines))


def show_threat_panel():
    lines = [
        "🧿 Codex Sentinel Threat Panel",
        "",
        f"Secure Mode: {'ON' if SECURE_MODE else 'OFF'}",
        f"Persona Lock: {'LOCKED' if PERSONA_LOCKED else 'UNLOCKED'}",
        f"Overrides: {'ACTIVE' if THREAT_PANEL_OVERRIDES_ENABLED else 'INACTIVE'}",
        "",
        "Threat Surface (symbolic):",
        "- Ritual Shell: monitored",
        "- Registry rituals: guarded",
        "- God Mode gateway: watched",
        "",
        f"Daemonized Watchdog: {'RUNNING' if sentinel.watchdog_running else 'STOPPED'}",
        f"Snapshots taken: {sentinel.snapshot_counter}",
        f"Last snapshot: {sentinel.last_snapshot_time or 'N/A'}",
        "",
        get_scheduler_qos(),
    ]
    messagebox.showinfo("Codex Sentinel Threat Panel", "\n".join(lines))


# ============================================================
# 🧿 SECURE MODE / PERSONA LOCK TOGGLES
# ============================================================
def toggle_secure_mode():
    global SECURE_MODE
    SECURE_MODE = not SECURE_MODE

    if SECURE_MODE:
        sentinel.apply_group_policy_enforcement()
        sentinel.apply_telemetry_suppression()
        sentinel.start_watchdog()
        msg = "Secure Mode enabled.\nCodex Sentinel watchdog and symbolic enforcement are now active."
    else:
        sentinel.stop_watchdog()
        msg = "Secure Mode disabled.\nCodex Sentinel watchdog paused; rituals run in symbolic mode."

    feedback(msg, success=True)


def toggle_persona_lock():
    global PERSONA_LOCKED
    PERSONA_LOCKED = not PERSONA_LOCKED
    state = "engaged" if PERSONA_LOCKED else "released"
    feedback(f"Persona Lock {state}.", success=True)


# ============================================================
# 🧿 ANIMATED OVERLAYS + RITUAL GLYPH TRANSITIONS
# ============================================================
def start_glyph_animation(canvas):
    glyphs = ["🧿", "⚡", "✶", "☼", "✦", "⟁"]
    text_id = canvas.create_text(
        240, 40, text="🧿", font=("Segoe UI Symbol", 26, "bold"), fill="#4B8DF8"
    )

    def animate(index=0):
        canvas.itemconfig(text_id, text=glyphs[index % len(glyphs)])
        canvas.after(260, animate, (index + 1))

    animate()


# ============================================================
# 🧿 GUI LAUNCHER
# ============================================================
def launch_gui():
    root = tk.Tk()
    root.title("🧿 Ritual Shell: God Mode + Codex Sentinel")
    root.geometry("520x420")
    root.resizable(False, False)

    # Top glyph canvas (animated overlay)
    canvas = tk.Canvas(root, width=520, height=80, bg="#101010", highlightthickness=0)
    canvas.pack(fill="x")
    start_glyph_animation(canvas)

    tk.Label(
        root,
        text="Activate Rituals" if safe_mode else "🧿 Activate Rituals",
        font=("Segoe UI", 12, "bold"),
    ).pack(pady=6)

    # Core rituals
    tk.Button(root, text="Enable God Mode", command=enable_god_mode, width=36).pack(pady=3)
    tk.Button(root, text="Enable Hidden Feature", command=enable_hidden_feature, width=36).pack(pady=3)
    tk.Button(root, text="Show All Settings", command=show_all_settings, width=36).pack(pady=3)

    # Persona / Sentinel
    tk.Button(root, text="Show Persona Status", command=show_persona_status, width=36).pack(pady=3)
    tk.Button(root, text="Show Threat Panel", command=show_threat_panel, width=36).pack(pady=3)
    tk.Button(root, text="Registry / Config Visibility", command=show_registry_config, width=36).pack(pady=3)

    # Secure / Persona toggles
    tk.Button(root, text="Toggle Secure Mode", command=toggle_secure_mode, width=36).pack(pady=3)
    tk.Button(root, text="Toggle Persona Lock", command=toggle_persona_lock, width=36).pack(pady=3)

    # Hardware envelopes
    tk.Button(root, text="Envelope: Balanced", command=lambda: set_hardware_envelope("Balanced"), width=18).pack(side="left", padx=10, pady=10)
    tk.Button(root, text="Envelope: Ritual", command=lambda: set_hardware_envelope("Ritual"), width=18).pack(side="left", padx=10, pady=10)
    tk.Button(root, text="Envelope: Silent", command=lambda: set_hardware_envelope("Silent"), width=18).pack(side="left", padx=10, pady=10)

    tk.Label(
        root,
        text=(
            "Plain feedback enabled."
            if safe_mode
            else "Symbolic feedback, Codex Sentinel, QoS, and tuning envelopes guide your path."
        ),
        font=("Segoe UI", 9, "italic"),
    ).pack(pady=8)

    root.mainloop()


# ============================================================
# 🧿 ENTRY POINT
# ============================================================
if __name__ == "__main__":
    if "--elevated" not in sys.argv:
        elevate()

    safe_mode = detect_safe_mode()
    sentinel.start_watchdog()
    launch_gui()
