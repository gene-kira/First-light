import sys
import subprocess
import importlib
import os
import time
import threading
import json
import socket
import hashlib
from datetime import datetime

# -----------------------------
# Auto-loader for dependencies
# -----------------------------
REQUIRED_LIBS = ["psutil", "comtypes", "pycaw", "requests", "pefile", "pywin32"]

def ensure_libs():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            print(f"[+] Installing missing library: {lib}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
    globals()["psutil"] = importlib.import_module("psutil")
    globals()["comtypes"] = importlib.import_module("comtypes")
    globals()["pycaw"] = importlib.import_module("pycaw")
    globals()["requests"] = importlib.import_module("requests")
    globals()["pefile"] = importlib.import_module("pefile")
    globals()["pythoncom"] = importlib.import_module("pythoncom")

ensure_libs()

import psutil
from ctypes import POINTER, cast
from comtypes import CLSCTX_ALL
from pycaw.pycaw import AudioUtilities, ISimpleAudioVolume
import requests
import pefile
import pythoncom

import tkinter as tk
from tkinter import ttk, messagebox

# -----------------------------
# Config / constants
# -----------------------------
LOG_FILE = "security_bridge.log"
STATE_FILE = "security_state.json"
RULES_FILE = "rules.json"

REMOTE_TOOL_KEYWORDS = [
    "anydesk", "teamviewer", "rustdesk", "parsec",
    "chrome remote desktop", "chromeremotedesktop",
    "splashtop", "ultravnc", "tightvnc", "realvnc",
    "mstsc", "rdp", "screenconnect", "logmein",
    "gotomypc"
]

SUSPICIOUS_PORTS = [
    3389,
    5938,
    7070,
    47984,
]

MITRE_MAP = {
    "REMOTE_TOOL": ["T1105", "T1071"],
    "AUDIO_ACTIVE": ["T1129"],
    "SUSP_PORT": ["T1071"],
    "EXTERNAL_IP": ["T1041"],
    "REPEATED_HIT": ["T1027"],
    "FILE_SUSP": ["T1059", "T1055"],
}

DEFAULT_AUTO_BLOCK_THRESHOLD = 70

HONEYPOT_PORTS = [55222, 3390]

# default allowlist / audio whitelist / trusted gaming zone
DEFAULT_ALLOW_NAMES = [
    "steam.exe",
    "steamwebhelper.exe",
    "Spotify.exe",
    "SpotifyWidgetProvider.exe",
    "chrome.exe",
    "msedge.exe",
    "discord.exe",
]

DEFAULT_AUDIO_WHITELIST = [
    "Spotify.exe",
    "SpotifyWidgetProvider.exe",
    "chrome.exe",
    "msedge.exe",
    "discord.exe",
]

DEFAULT_TRUSTED_GAMING = [
    "steam.exe",
    "steamwebhelper.exe",
]

# cooldown for logging (seconds)
MEDIUM_LOG_COOLDOWN = 60
LOW_LOG_COOLDOWN = 120

# -----------------------------
# Logging / state
# -----------------------------
def log_event(level, message):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] [{level}] {message}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

def load_state():
    if not os.path.exists(STATE_FILE):
        return {}
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_state(state):
    try:
        with open(STATE_FILE, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass

def load_rules():
    if not os.path.exists(RULES_FILE):
        rules = {
            "block_names": REMOTE_TOOL_KEYWORDS,
            "block_ports": SUSPICIOUS_PORTS,
            "auto_block_threshold": DEFAULT_AUTO_BLOCK_THRESHOLD,
            "allow_names": DEFAULT_ALLOW_NAMES,
            "audio_whitelist": DEFAULT_AUDIO_WHITELIST,
            "trusted_gaming": DEFAULT_TRUSTED_GAMING,
        }
        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(rules, f, indent=2)
        except Exception:
            pass
        return rules
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {
            "block_names": REMOTE_TOOL_KEYWORDS,
            "block_ports": SUSPICIOUS_PORTS,
            "auto_block_threshold": DEFAULT_AUTO_BLOCK_THRESHOLD,
            "allow_names": DEFAULT_ALLOW_NAMES,
            "audio_whitelist": DEFAULT_AUDIO_WHITELIST,
            "trusted_gaming": DEFAULT_TRUSTED_GAMING,
        }

STATE = load_state()
RULES = load_rules()

def increment_detection_count(proc_key):
    global STATE
    if "detections" not in STATE:
        STATE["detections"] = {}
    if proc_key not in STATE["detections"]:
        STATE["detections"][proc_key] = 0
    STATE["detections"][proc_key] += 1
    save_state(STATE)
    return STATE["detections"][proc_key]

def get_dynamic_threshold():
    global STATE, RULES
    base = RULES.get("auto_block_threshold", DEFAULT_AUTO_BLOCK_THRESHOLD)
    detections = STATE.get("detections", {})
    high_hits = sum(1 for _, v in detections.items() if v > 5)
    adjust = min(high_hits * 2, 10)
    return max(50, base - adjust)

def should_log(proc_key, risk_level):
    global STATE
    now = time.time()
    if "log_cooldown" not in STATE:
        STATE["log_cooldown"] = {}
    cooldowns = STATE["log_cooldown"]
    last = cooldowns.get(proc_key, 0)

    if risk_level == "High":
        cooldowns[proc_key] = now
        save_state(STATE)
        return True
    elif risk_level == "Medium":
        if now - last >= MEDIUM_LOG_COOLDOWN:
            cooldowns[proc_key] = now
            save_state(STATE)
            return True
        return False
    else:
        if now - last >= LOW_LOG_COOLDOWN:
            cooldowns[proc_key] = now
            save_state(STATE)
            return True
        return False

# -----------------------------
# Data structures
# -----------------------------
class ProcessSecurityInfo:
    def __init__(self, pid, name, volume, muted, connections,
                 risk_level, risk_reason, score, mitre_tags,
                 parent_pid, exe_path, cmdline, create_time,
                 file_hash, file_suspicious):
        self.pid = pid
        self.name = name
        self.volume = volume
        self.muted = muted
        self.connections = connections
        self.risk_level = risk_level
        self.risk_reason = risk_reason
        self.score = score
        self.mitre_tags = mitre_tags
        self.parent_pid = parent_pid
        self.exe_path = exe_path
        self.cmdline = cmdline
        self.create_time = create_time
        self.file_hash = file_hash
        self.file_suspicious = file_suspicious

# -----------------------------
# Core analysis functions
# -----------------------------
def get_audio_sessions():
    pythoncom.CoInitialize()
    sessions = AudioUtilities.GetAllSessions()
    result = []
    for session in sessions:
        try:
            volume = session._ctl.QueryInterface(ISimpleAudioVolume)
            vol_level = volume.GetMasterVolume()
            muted = volume.GetMute()
            pid = session.Process.pid if session.Process else None
            process_name = "System (no process)" if not session.Process else session.Process.name()
            result.append((pid, process_name, vol_level, muted))
        except Exception:
            continue
    return result

def is_external_ip(ip):
    if not ip:
        return False
    private_prefixes = ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.",
                        "172.20.", "172.21.", "172.22.", "172.23.", "172.24.",
                        "172.25.", "172.26.", "172.27.", "172.28.", "172.29.",
                        "172.30.", "172.31.")
    return not ip.startswith(private_prefixes)

def get_process_connections(pid):
    connections_info = []
    try:
        proc = psutil.Process(pid)
        conns = proc.connections(kind="inet")
        for c in conns:
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            external = False
            if c.raddr and is_external_ip(c.raddr.ip):
                external = True
            connections_info.append((laddr, raddr, c.status, external))
    except Exception:
        pass
    return connections_info

def get_process_metadata(pid):
    parent_pid = None
    exe_path = ""
    cmdline = ""
    create_time = None
    try:
        proc = psutil.Process(pid)
        parent = proc.parent()
        parent_pid = parent.pid if parent else None
        exe_path = proc.exe()
        cmdline = " ".join(proc.cmdline())
        create_time = datetime.fromtimestamp(proc.create_time()).strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        pass
    return parent_pid, exe_path, cmdline, create_time

def hash_file(path):
    if not path or not os.path.exists(path):
        return None
    try:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(8192), b""):
                h.update(chunk)
        return h.hexdigest()
    except Exception:
        return None

def analyze_pe_file(path):
    if not path or not os.path.exists(path):
        return False
    try:
        pe = pefile.PE(path, fast_load=True)
        pe.parse_data_directories()
        suspicious = False
        imports = [entry.dll.decode(errors="ignore").lower()
                   for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])]
        bad_imports = ["ws2_32.dll", "wininet.dll", "advapi32.dll"]
        if any(b in imports for b in bad_imports):
            suspicious = True
        for section in pe.sections:
            if section.get_entropy() > 7.5:
                suspicious = True
                break
        return suspicious
    except Exception:
        return False

def map_mitre_tags(remote_keyword_hit, has_audio, suspicious_port_hit,
                   external_ip_hit, repeated_hit, file_suspicious):
    tags = set()
    if remote_keyword_hit:
        tags.update(MITRE_MAP["REMOTE_TOOL"])
    if has_audio:
        tags.update(MITRE_MAP["AUDIO_ACTIVE"])
    if suspicious_port_hit:
        tags.update(MITRE_MAP["SUSP_PORT"])
    if external_ip_hit:
        tags.update(MITRE_MAP["EXTERNAL_IP"])
    if repeated_hit:
        tags.update(MITRE_MAP["REPEATED_HIT"])
    if file_suspicious:
        tags.update(MITRE_MAP["FILE_SUSP"])
    return sorted(tags)

def compute_threat_score(remote_keyword_hit, has_audio, suspicious_port_hit,
                         external_ip_hit, repeated_hit, has_network,
                         file_suspicious, name_lower):
    score = 0
    if has_audio:
        score += 20
    if remote_keyword_hit:
        score += 40
    if suspicious_port_hit:
        score += 30
    if external_ip_hit:
        score += 20
    if has_network:
        score += 10
    if repeated_hit:
        score += 10
    if file_suspicious:
        score += 20

    # dampen score for trusted gaming
    trusted_gaming = [n.lower() for n in RULES.get("trusted_gaming", DEFAULT_TRUSTED_GAMING)]
    if any(tg in name_lower for tg in trusted_gaming):
        score = max(0, score - 20)

    # dampen score for audio whitelist
    audio_whitelist = [n.lower() for n in RULES.get("audio_whitelist", DEFAULT_AUDIO_WHITELIST)]
    if any(aw in name_lower for aw in audio_whitelist):
        score = max(0, score - 20)

    return min(score, 100)

def is_allowlisted(name_lower):
    allow = [n.lower() for n in RULES.get("allow_names", DEFAULT_ALLOW_NAMES)]
    return any(a == name_lower for a in allow)

def assess_risk(name, pid, volume, muted, connections, file_suspicious):
    name_lower = (name or "").lower()
    has_audio = (volume is not None and volume > 0.01 and not muted)
    has_network = any(raddr for (_, raddr, _, _) in connections)
    remote_keyword_hit = any(k in name_lower for k in RULES.get("block_names", REMOTE_TOOL_KEYWORDS))
    suspicious_port_hit = any(
        (raddr and any(str(p) == raddr.split(":")[-1] for p in RULES.get("block_ports", SUSPICIOUS_PORTS)))
        for (_, raddr, _, _) in connections
    )
    external_ip_hit = any(ext for (_, _, _, ext) in connections)

    proc_key = f"{name_lower}:{pid}"
    detection_count = increment_detection_count(proc_key)
    repeated_hit = detection_count > 3

    mitre_tags = map_mitre_tags(remote_keyword_hit, has_audio,
                                suspicious_port_hit, external_ip_hit,
                                repeated_hit, file_suspicious)
    score = compute_threat_score(remote_keyword_hit, has_audio,
                                 suspicious_port_hit, external_ip_hit,
                                 repeated_hit, has_network, file_suspicious,
                                 name_lower)

    risk_level = "Low"
    reasons = []

    if remote_keyword_hit:
        reasons.append("Process name matches known remote-control tool.")
    if suspicious_port_hit:
        reasons.append("Process uses suspicious remote-control port.")
    if has_audio:
        reasons.append("Process is actively playing audio.")
    if has_network:
        reasons.append("Process has active network connections.")
    if external_ip_hit:
        reasons.append("Process connects to external IPs.")
    if repeated_hit:
        reasons.append("Process repeatedly flagged in prior sessions.")
    if file_suspicious:
        reasons.append("Executable shows suspicious PE characteristics.")

    if is_allowlisted(name_lower):
        risk_level = "Low"
        score = 0
        reasons.append("Process is allowlisted.")
    else:
        if score >= 80:
            risk_level = "High"
        elif score >= 50:
            risk_level = "Medium"
        else:
            risk_level = "Low"

    if should_log(proc_key, risk_level) and risk_level != "Low":
        log_event(
            risk_level,
            f"PID {pid} ({name}) score={score}, MITRE={mitre_tags}, reasons={'; '.join(reasons)}"
        )

    return risk_level, "; ".join(reasons) if reasons else "No obvious risk indicators.", score, mitre_tags

def auto_block_if_needed(info: ProcessSecurityInfo):
    if info.pid is None:
        return
    name_lower = (info.name or "").lower()
    if is_allowlisted(name_lower):
        return
    threshold = get_dynamic_threshold()
    if info.score < threshold:
        return
    try:
        proc = psutil.Process(info.pid)
        log_event("AUTO-BLOCK", f"Auto-killing PID {info.pid} ({info.name}) score={info.score}, threshold={threshold}")
        proc.terminate()
        gone, alive = psutil.wait_procs([proc], timeout=3)
        for p in alive:
            p.kill()
    except Exception as e:
        log_event("ERROR", f"Auto-block failed for PID {info.pid}: {e}")

def build_security_snapshot():
    snapshot = []
    audio_sessions = get_audio_sessions()

    for pid, name, volume, muted in audio_sessions:
        if pid is None:
            connections = []
            parent_pid = None
            exe_path = ""
            cmdline = ""
            create_time = None
            file_hash = None
            file_suspicious = False
            risk_level, risk_reason, score, mitre_tags = assess_risk(
                name, pid, volume, muted, connections, file_suspicious
            )
            info = ProcessSecurityInfo(
                pid, name, volume, muted, connections,
                risk_level, risk_reason, score, mitre_tags,
                parent_pid, exe_path, cmdline, create_time,
                file_hash, file_suspicious
            )
            snapshot.append(info)
            continue

        connections = get_process_connections(pid)
        parent_pid, exe_path, cmdline, create_time = get_process_metadata(pid)
        file_hash = hash_file(exe_path)
        file_suspicious = analyze_pe_file(exe_path)
        risk_level, risk_reason, score, mitre_tags = assess_risk(
            name, pid, volume, muted, connections, file_suspicious
        )
        info = ProcessSecurityInfo(
            pid, name, volume, muted, connections,
            risk_level, risk_reason, score, mitre_tags,
            parent_pid, exe_path, cmdline, create_time,
            file_hash, file_suspicious
        )
        auto_block_if_needed(info)
        snapshot.append(info)

    return snapshot

# -----------------------------
# Honeypot listener
# -----------------------------
def honeypot_worker(port):
    pythoncom.CoInitialize()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("0.0.0.0", port))
        sock.listen(5)
        log_event("HONEYPOT", f"Listening on fake service port {port}")
        while True:
            conn, addr = sock.accept()
            log_event("HONEYPOT", f"Connection from {addr[0]}:{addr[1]} to port {port}")
            try:
                conn.sendall(b"Fake service.\r\n")
            except Exception:
                pass
            conn.close()
    except Exception as e:
        log_event("ERROR", f"Honeypot failed on port {port}: {e}")

def start_honeypot():
    for p in HONEYPOT_PORTS:
        t = threading.Thread(target=honeypot_worker, args=(p,), daemon=True)
        t.start()

# -----------------------------
# GUI
# -----------------------------
class SecurityBridgeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Bridge - Audio, Network, File, Honeypot, Auto-Block (v3)")
        self.root.geometry("1300x650")

        self.auto_refresh = tk.BooleanVar(value=True)
        self.refresh_interval = 5

        self._build_ui()
        self._start_auto_refresh()

    def _build_ui(self):
        control_frame = ttk.Frame(self.root)
        control_frame.pack(fill=tk.X, padx=10, pady=5)

        ttk.Label(
            control_frame,
            text="Security Bridge v3 - Tuned (Allowlist + Cooldown + Trusted Gaming + Audio Whitelist)",
            font=("Segoe UI", 12, "bold")
        ).pack(side=tk.LEFT)

        ttk.Checkbutton(
            control_frame,
            text="Auto refresh",
            variable=self.auto_refresh
        ).pack(side=tk.LEFT, padx=10)

        ttk.Button(
            control_frame,
            text="Refresh now",
            command=self.refresh_snapshot
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            control_frame,
            text="Kill selected process",
            command=self.kill_selected_process
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            control_frame,
            text="View connections",
            command=self.view_selected_connections
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            control_frame,
            text="View metadata",
            command=self.view_selected_metadata
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            control_frame,
            text="View file analysis",
            command=self.view_selected_file
        ).pack(side=tk.LEFT, padx=5)

        columns = ("pid", "process", "volume", "muted",
                   "risk", "score", "mitre", "reason")
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings")
        self.tree.heading("pid", text="PID")
        self.tree.heading("process", text="Process")
        self.tree.heading("volume", text="Volume")
        self.tree.heading("muted", text="Muted")
        self.tree.heading("risk", text="Risk")
        self.tree.heading("score", text="Score")
        self.tree.heading("mitre", text="MITRE")
        self.tree.heading("reason", text="Reason")

        self.tree.column("pid", width=70, anchor=tk.CENTER)
        self.tree.column("process", width=220, anchor=tk.W)
        self.tree.column("volume", width=70, anchor=tk.CENTER)
        self.tree.column("muted", width=70, anchor=tk.CENTER)
        self.tree.column("risk", width=80, anchor=tk.CENTER)
        self.tree.column("score", width=70, anchor=tk.CENTER)
        self.tree.column("mitre", width=180, anchor=tk.W)
        self.tree.column("reason", width=500, anchor=tk.W)

        self.tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=10, pady=3)

    def _start_auto_refresh(self):
        def loop():
            pythoncom.CoInitialize()
            while True:
                if self.auto_refresh.get():
                    self.refresh_snapshot()
                time.sleep(self.refresh_interval)
        t = threading.Thread(target=loop, daemon=True)
        t.start()

    def refresh_snapshot(self):
        try:
            snapshot = build_security_snapshot()
        except Exception as e:
            self.status_var.set(f"Error building snapshot: {e}")
            log_event("ERROR", f"Snapshot error: {e}")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        for info in snapshot:
            vol_str = f"{int(info.volume * 100)}%" if info.volume is not None else "N/A"
            muted_str = "Yes" if info.muted else "No"
            pid_str = info.pid if info.pid is not None else "-"
            mitre_str = ",".join(info.mitre_tags) if info.mitre_tags else ""
            self.tree.insert(
                "",
                tk.END,
                values=(
                    pid_str,
                    info.name,
                    vol_str,
                    muted_str,
                    info.risk_level,
                    info.score,
                    mitre_str,
                    info.risk_reason
                )
            )

        self.status_var.set(f"Snapshot updated: {len(snapshot)} audio sessions")

    def _get_selected_pid_and_name(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("No selection", "Select a row first.")
            return None, None
        item = self.tree.item(selected[0])
        pid_str = item["values"][0]
        process_name = item["values"][1]
        if pid_str == "-" or pid_str is None:
            return None, process_name
        try:
            pid = int(pid_str)
        except ValueError:
            return None, process_name
        return pid, process_name

    def kill_selected_process(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot kill", "Selected session is not tied to a user process.")
            return
        answer = messagebox.askyesno(
            "Confirm kill",
            f"Kill process {process_name} (PID {pid})?\n\nThis will forcibly stop its audio and any running activity."
        )
        if not answer:
            return
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            gone, alive = psutil.wait_procs([proc], timeout=3)
            for p in alive:
                p.kill()
            self.status_var.set(f"Killed process {process_name} (PID {pid})")
            log_event("INFO", f"Killed process {process_name} (PID {pid}) via GUI.")
            self.refresh_snapshot()
        except psutil.NoSuchProcess:
            self.status_var.set(f"Process {pid} no longer exists.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to kill process {pid}: {e}")
            self.status_var.set(f"Error killing process {pid}: {e}")
            log_event("ERROR", f"Kill error for PID {pid}: {e}")

    def view_selected_connections(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showinfo("No process", "Selected session has no PID or is a system audio session.")
            return
        connections = get_process_connections(pid)
        if not connections:
            messagebox.showinfo("No connections", f"No active network connections for PID {pid} ({process_name}).")
            return
        lines = []
        for laddr, raddr, status, external in connections:
            ext_flag = "EXTERNAL" if external else "LOCAL"
            lines.append(f"{laddr} -> {raddr} [{status}] ({ext_flag})")
        msg = "\n".join(lines)
        messagebox.showinfo(
            "Network connections",
            f"PID {pid} ({process_name}) connections:\n\n{msg}"
        )

    def view_selected_metadata(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showinfo("No process", "Selected session has no PID or is a system audio session.")
            return
        parent_pid, exe_path, cmdline, create_time = get_process_metadata(pid)
        msg = (
            f"Process: {process_name}\n"
            f"PID: {pid}\n"
            f"Parent PID: {parent_pid}\n"
            f"Executable: {exe_path}\n"
            f"Cmdline: {cmdline}\n"
            f"Created: {create_time}\n"
        )
        messagebox.showinfo("Process metadata", msg)

    def view_selected_file(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showinfo("No process", "Selected session has no PID or is a system audio session.")
            return
        parent_pid, exe_path, cmdline, create_time = get_process_metadata(pid)
        file_hash = hash_file(exe_path)
        file_suspicious = analyze_pe_file(exe_path)
        msg = (
            f"Process: {process_name}\n"
            f"PID: {pid}\n"
            f"Executable: {exe_path}\n"
            f"SHA256: {file_hash}\n"
            f"Suspicious PE: {file_suspicious}\n"
        )
        messagebox.showinfo("File analysis", msg)


def main():
    log_event("INFO", "Security Bridge (Full Upgrade v3) started.")
    start_honeypot()
    root = tk.Tk()
    app = SecurityBridgeGUI(root)
    root.mainloop()
    log_event("INFO", "Security Bridge closed.")


if __name__ == "__main__":
    main()
