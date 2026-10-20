import tkinter as tk
from tkinter import messagebox
import os, sys, platform, ctypes, winreg, json
import threading
import time
from pathlib import Path

# ============================================================
# 🧿 CONFIG / CONTEXT
# ============================================================
APP_NAME = "CodexSentinelRitualShell"
CONFIG_DIR = Path(os.path.expanduser("~")) / "AppData" / "Roaming" / APP_NAME
CONFIG_PATH = CONFIG_DIR / "config.json"


class CodexContext:
    def __init__(self):
        # Core flags
        self.secure_mode = False
        self.persona_locked = False
        self.swarm_sync_enabled = True
        self.symbolic_registry_enabled = True
        self.threat_panel_overrides_enabled = True
        self.telemetry_suppression_enabled = True
        self.group_policy_enforcement_enabled = True

        # Hardware envelopes
        self.cpu_envelope = "Balanced"
        self.gpu_envelope = "Sentinel"
        self.io_envelope = "Normal"

        # Profile
        self.profile = "Sentinel"

        # Environment
        self.safe_mode = True

        # Sentinel stack
        self.sentinel = CodexSentinel()

    def to_dict(self):
        return {
            "secure_mode": self.secure_mode,
            "persona_locked": self.persona_locked,
            "swarm_sync_enabled": self.swarm_sync_enabled,
            "symbolic_registry_enabled": self.symbolic_registry_enabled,
            "threat_panel_overrides_enabled": self.threat_panel_overrides_enabled,
            "telemetry_suppression_enabled": self.telemetry_suppression_enabled,
            "group_policy_enforcement_enabled": self.group_policy_enforcement_enabled,
            "cpu_envelope": self.cpu_envelope,
            "gpu_envelope": self.gpu_envelope,
            "io_envelope": self.io_envelope,
            "profile": self.profile,
        }

    def load_from_dict(self, data):
        self.secure_mode = data.get("secure_mode", self.secure_mode)
        self.persona_locked = data.get("persona_locked", self.persona_locked)
        self.swarm_sync_enabled = data.get("swarm_sync_enabled", self.swarm_sync_enabled)
        self.symbolic_registry_enabled = data.get("symbolic_registry_enabled", self.symbolic_registry_enabled)
        self.threat_panel_overrides_enabled = data.get("threat_panel_overrides_enabled", self.threat_panel_overrides_enabled)
        self.telemetry_suppression_enabled = data.get("telemetry_suppression_enabled", self.telemetry_suppression_enabled)
        self.group_policy_enforcement_enabled = data.get("group_policy_enforcement_enabled", self.group_policy_enforcement_enabled)
        self.cpu_envelope = data.get("cpu_envelope", self.cpu_envelope)
        self.gpu_envelope = data.get("gpu_envelope", self.gpu_envelope)
        self.io_envelope = data.get("io_envelope", self.io_envelope)
        self.profile = data.get("profile", self.profile)


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


ctx = CodexContext()


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
# 🧿 COMPATIBILITY / ENVIRONMENT
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


def detect_safe_mode():
    return not (is_windows_compatible() and has_registry_access() and is_admin())


# ============================================================
# 🧿 SCHEDULER QoS DETECTION (SYMBOLIC)
# ============================================================
def get_scheduler_qos():
    try:
        kernel32 = ctypes.windll.kernel32
        GetCurrentProcess = kernel32.GetCurrentProcess
        GetPriorityClass = kernel32.GetPriorityClass

        h_proc = GetCurrentProcess()
        prio = GetPriorityClass(h_proc)

        PRIORITY_MAP = {
            0x20: "Normal",
            0x40: "Idle",
            0x80: "High",
            0x100: "Realtime",
            0x4000: "Below Normal",
            0x8000: "Above Normal",
        }

        qos = PRIORITY_MAP.get(prio, "Unknown")
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
# 🧿 CONFIG PERSISTENCE
# ============================================================
def load_config():
    try:
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            ctx.load_from_dict(data)
    except Exception:
        # Ignore config errors, run with defaults
        pass


def save_config():
    try:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(ctx.to_dict(), f, indent=2)
    except Exception:
        # Silent failure; ritual shell continues
        pass


# ============================================================
# 🧿 HARDWARE TUNING ENVELOPES (SYMBOLIC)
# ============================================================
def apply_profile(profile_name):
    profile_name = profile_name.capitalize()
    ctx.profile = profile_name

    if profile_name == "Ritual":
        ctx.cpu_envelope = "Ritual / High‑Response"
        ctx.gpu_envelope = "Ritual / Sentinel"
        ctx.io_envelope = "Priority / Fast Path"
        ctx.secure_mode = True
        ctx.persona_locked = False
    elif profile_name == "Silent":
        ctx.cpu_envelope = "Silent / Low‑Impact"
        ctx.gpu_envelope = "Silent / Cool"
        ctx.io_envelope = "Background / Gentle"
        ctx.secure_mode = False
        ctx.persona_locked = False
    elif profile_name == "Diagnostics":
        ctx.cpu_envelope = "Diagnostics / Verbose"
        ctx.gpu_envelope = "Diagnostics / Neutral"
        ctx.io_envelope = "Diagnostics / Trace"
        ctx.secure_mode = False
        ctx.persona_locked = False
    else:  # Sentinel
        ctx.cpu_envelope = "Balanced"
        ctx.gpu_envelope = "Sentinel"
        ctx.io_envelope = "Normal"
        ctx.secure_mode = True
        ctx.persona_locked = False

    save_config()
    feedback(f"Profile set to: {profile_name}", success=True)


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
    show_recent = get_registry_value(
        winreg.HKEY_CURRENT_USER, explorer_path, "ShowRecent"
    )

    lines = [
        "🧿 Registry / Config Visibility",
        "",
        f"Explorer key: HKCU\\{explorer_path}",
        f"EnableSnapAssistFlyout: {snap_assist if snap_assist is not None else 'Not set'}",
        f"ShowRecent: {show_recent if show_recent is not None else 'Not set'}",
        "",
        "Symbolic Config Envelopes:",
        f"CPU Envelope: {ctx.cpu_envelope}",
        f"GPU Envelope: {ctx.gpu_envelope}",
        f"IO Envelope: {ctx.io_envelope}",
        "",
        get_scheduler_qos(),
    ]
    messagebox.showinfo("Registry / Config Visibility", "\n".join(lines))


# ============================================================
# 🧿 RITUAL FUNCTIONS
# ============================================================
def enable_god_mode():
    if ctx.secure_mode and ctx.persona_locked:
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
    if ctx.secure_mode and not ctx.symbolic_registry_enabled:
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
    if ctx.safe_mode:
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
        f"{'🧿 ' if not ctx.safe_mode else ''}OS: {platform.system()} {platform.release()}",
        f"{'🧿 ' if not ctx.safe_mode else ''}Version: {platform.version()}",
        f"{'🧿 ' if not ctx.safe_mode else ''}Admin Privileges: {'Yes' if is_admin() else 'No'}",
        f"{'🧿 ' if not ctx.safe_mode else ''}Registry Access: {'Yes' if has_registry_access() else 'No'}",
        f"{'🧿 ' if not ctx.safe_mode else ''}Windows 10+ Compatible: {'Yes' if is_windows_compatible() else 'No'}",
        f"{'🧿 ' if not ctx.safe_mode else ''}Mode: {'Safe Mode' if ctx.safe_mode else 'Symbolic Mode'}",
        "",
        f"Profile: {ctx.profile}",
        f"Secure Mode: {'Enabled' if ctx.secure_mode else 'Disabled'}",
        f"Persona Lock: {'Engaged' if ctx.persona_locked else 'Released'}",
        f"Swarm Sync: {'Active' if ctx.swarm_sync_enabled else 'Idle'}",
        f"Symbolic Registry: {'Enabled' if ctx.symbolic_registry_enabled else 'Disabled'}",
        f"Threat Panel Overrides: {'Enabled' if ctx.threat_panel_overrides_enabled else 'Disabled'}",
        f"Telemetry Suppression: {'Enabled' if ctx.telemetry_suppression_enabled else 'Disabled'}",
        f"Group Policy Enforcement: {'Enabled' if ctx.group_policy_enforcement_enabled else 'Disabled'}",
        "",
        f"CPU Envelope: {ctx.cpu_envelope}",
        f"GPU Envelope: {ctx.gpu_envelope}",
        f"IO Envelope: {ctx.io_envelope}",
        get_scheduler_qos(),
        "",
        f"Watchdog: {'Running' if ctx.sentinel.watchdog_running else 'Stopped'}",
        f"Snapshots: {ctx.sentinel.snapshot_counter}",
        f"Last Snapshot: {ctx.sentinel.last_snapshot_time or 'N/A'}",
    ]
    messagebox.showinfo("Persona Status Panel", "\n".join(status_lines))


def show_threat_panel():
    lines = [
        "🧿 Codex Sentinel Threat Panel",
        "",
        f"Profile: {ctx.profile}",
        f"Secure Mode: {'ON' if ctx.secure_mode else 'OFF'}",
        f"Persona Lock: {'LOCKED' if ctx.persona_locked else 'UNLOCKED'}",
        f"Overrides: {'ACTIVE' if ctx.threat_panel_overrides_enabled else 'INACTIVE'}",
        "",
        "Threat Surface (symbolic):",
        "- Ritual Shell: monitored",
        "- Registry rituals: guarded",
        "- God Mode gateway: watched",
        "",
        f"Daemonized Watchdog: {'RUNNING' if ctx.sentinel.watchdog_running else 'STOPPED'}",
        f"Snapshots taken: {ctx.sentinel.snapshot_counter}",
        f"Last snapshot: {ctx.sentinel.last_snapshot_time or 'N/A'}",
        "",
        get_scheduler_qos(),
    ]
    messagebox.showinfo("Codex Sentinel Threat Panel", "\n".join(lines))


# ============================================================
# 🧿 SECURE MODE / PERSONA LOCK TOGGLES
# ============================================================
def toggle_secure_mode():
    ctx.secure_mode = not ctx.secure_mode

    if ctx.secure_mode:
        ctx.sentinel.apply_group_policy_enforcement()
        ctx.sentinel.apply_telemetry_suppression()
        ctx.sentinel.start_watchdog()
        msg = "Secure Mode enabled.\nCodex Sentinel watchdog and symbolic enforcement are now active."
    else:
        ctx.sentinel.stop_watchdog()
        msg = "Secure Mode disabled.\nCodex Sentinel watchdog paused; rituals run in symbolic mode."

    save_config()
    feedback(msg, success=True)


def toggle_persona_lock():
    ctx.persona_locked = not ctx.persona_locked
    state = "engaged" if ctx.persona_locked else "released"
    save_config()
    feedback(f"Persona Lock {state}.", success=True)


# ============================================================
# 🧿 ANIMATED OVERLAYS + RITUAL GLYPH TRANSITIONS
# ============================================================
def start_glyph_animation(canvas):
    glyphs = ["🧿", "⚡", "✶", "☼", "✦", "⟁"]
    text_id = canvas.create_text(
        260, 40, text="🧿", font=("Segoe UI Symbol", 26, "bold"), fill="#4B8DF8"
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
    root.geometry("560x460")
    root.resizable(False, False)

    # Top glyph canvas (animated overlay)
    canvas = tk.Canvas(root, width=560, height=80, bg="#101010", highlightthickness=0)
    canvas.pack(fill="x")
    start_glyph_animation(canvas)

    tk.Label(
        root,
        text="🧿 Activate Rituals" if not ctx.safe_mode else "Activate Rituals",
        font=("Segoe UI", 12, "bold"),
    ).pack(pady=6)

    # Frame layout
    frame_top = tk.Frame(root)
    frame_top.pack(pady=4)

    frame_mid = tk.Frame(root)
    frame_mid.pack(pady=4)

    frame_bottom = tk.Frame(root)
    frame_bottom.pack(pady=4)

    # Core rituals
    tk.Label(frame_top, text="Rituals", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, columnspan=2, pady=2)
    tk.Button(frame_top, text="Enable God Mode", command=enable_god_mode, width=24).grid(row=1, column=0, padx=4, pady=2)
    tk.Button(frame_top, text="Enable Hidden Feature", command=enable_hidden_feature, width=24).grid(row=1, column=1, padx=4, pady=2)
    tk.Button(frame_top, text="Show All Settings", command=show_all_settings, width=24).grid(row=2, column=0, padx=4, pady=2)
    tk.Button(frame_top, text="Registry / Config Visibility", command=show_registry_config, width=24).grid(row=2, column=1, padx=4, pady=2)

    # Persona / Sentinel
    tk.Label(frame_mid, text="Sentinel / Persona", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, columnspan=2, pady=2)
    tk.Button(frame_mid, text="Show Persona Status", command=show_persona_status, width=24).grid(row=1, column=0, padx=4, pady=2)
    tk.Button(frame_mid, text="Show Threat Panel", command=show_threat_panel, width=24).grid(row=1, column=1, padx=4, pady=2)
    tk.Button(frame_mid, text="Toggle Secure Mode", command=toggle_secure_mode, width=24).grid(row=2, column=0, padx=4, pady=2)
    tk.Button(frame_mid, text="Toggle Persona Lock", command=toggle_persona_lock, width=24).grid(row=2, column=1, padx=4, pady=2)

    # Profiles / envelopes
    tk.Label(frame_bottom, text="Profiles / Envelopes", font=("Segoe UI", 10, "bold")).grid(row=0, column=0, columnspan=4, pady=2)
    tk.Button(frame_bottom, text="Sentinel", command=lambda: apply_profile("Sentinel"), width=12).grid(row=1, column=0, padx=4, pady=2)
    tk.Button(frame_bottom, text="Ritual", command=lambda: apply_profile("Ritual"), width=12).grid(row=1, column=1, padx=4, pady=2)
    tk.Button(frame_bottom, text="Silent", command=lambda: apply_profile("Silent"), width=12).grid(row=1, column=2, padx=4, pady=2)
    tk.Button(frame_bottom, text="Diagnostics", command=lambda: apply_profile("Diagnostics"), width=12).grid(row=1, column=3, padx=4, pady=2)

    tk.Label(
        root,
        text=(
            "Plain feedback enabled."
            if ctx.safe_mode
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

    load_config()
    ctx.safe_mode = detect_safe_mode()
    ctx.sentinel.start_watchdog()
    launch_gui()
