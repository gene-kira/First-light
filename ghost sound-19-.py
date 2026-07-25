import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import json
import threading
import time
from datetime import datetime

# External / system-specific imports (stubs if not available)
try:
    import pythoncom
    from pycaw.pycaw import AudioUtilities, ISimpleAudioVolume
except ImportError:
    pythoncom = None
    AudioUtilities = None
    ISimpleAudioVolume = None

# === GLOBAL STATE / CONFIG ===
STATE = {
    "timeline": [],
    "audio_spikes": [],
    "clusters": [],
    "event_stream": [],
    "proc_history": {},
    "safe_to_ignore": [],
    "audio_lockdown_active": False,
}

RULES_FILE = "security_bridge_rules.json"
REPORT_FILE_JSON = "security_bridge_report.json"
REPORT_FILE_TXT = "security_bridge_report.txt"
INCIDENT_ZIP = "security_bridge_incident.zip"
INCIDENT_SESSION_FILE = "security_bridge_incident_session.json"
LOCKDOWN_ZIP = "security_bridge_lockdown.zip"

DEFAULT_ALLOW_NAMES = [
    "system",
    "audiodg.exe",
    "svchost.exe",
]

# FULL GAME IMMUNITY + Steam/Epic/Teams protection
DEFAULT_AUDIO_WHITELIST = [
    "steam.exe",
    "steamservice.exe",
    "epicgameslauncher.exe",
    "epicwebhelper.exe",
    "fortniteclient-win64-shipping.exe",
    "valorant.exe",
    "riotclientservices.exe",
    "league of legends.exe",
    "overwatch.exe",
    "battle.net.exe",
    "cs2.exe",
    "csgo.exe",
    "eldenring.exe",
    "minecraft.exe",
    "robloxplayerbeta.exe",
    "robloxplayer.exe",
    "gta5.exe",
    "rdr2.exe",
    "halo",
    "doom",
    "apex",
    "warzone",
    "pubg",
    "rocketleague.exe",
    "teams.exe",
    "ms-teams",
]

GAME_KEYWORDS = [
    "steam",
    "epic",
    "epicgames",
    "epicgameslauncher",
    "riot",
    "valorant",
    "league of legends",
    "lol",
    "battle.net",
    "bnet",
    "overwatch",
    "cs2",
    "csgo",
    "gta",
    "rdr2",
    "minecraft",
    "roblox",
    "warzone",
    "pubg",
    "apex",
    "rocketleague",
]

TEAMS_KEYWORDS = [
    "teams",
    "ms-teams",
    "msteams",
]

REMOTE_TOOL_KEYWORDS = [
    "anydesk",
    "teamviewer",
    "rustdesk",
    "radmin",
    "remote",
    "vnc",
]

SUSPICIOUS_PORTS = [22, 80, 443, 3389, 5900]
DEFAULT_AUTO_BLOCK_THRESHOLD = 60

RULES = {
    "allow_names": DEFAULT_ALLOW_NAMES,
    "block_names": REMOTE_TOOL_KEYWORDS,
    "block_ports": SUSPICIOUS_PORTS,
    "auto_block_threshold": DEFAULT_AUTO_BLOCK_THRESHOLD,
    "audio_whitelist": DEFAULT_AUDIO_WHITELIST,
    "mode": "NORMAL",
    "profile": "DEFAULT",
}

MITRE_VIEWS = {
    "ALL": [],
    "Code Injection": ["T1055"],
    "Ingress Tool Transfer": ["T1105"],
    "Exfiltration": ["T1041"],
    "Execution": ["T1129"],
    "C2": ["T1071"],
    "Obfuscation": ["T1027"],
}

# === UTILITY FUNCTIONS ===

def log_event(level, msg):
    ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ev = {"ts": ts, "level": level, "msg": msg}
    STATE.setdefault("event_stream", []).append(ev)

def emit_event(ev):
    STATE.setdefault("event_stream", []).append(ev)

def save_state(state):
    try:
        with open("security_bridge_state.json", "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2)
    except Exception:
        pass

def load_rules():
    global RULES
    try:
        with open(RULES_FILE, "r", encoding="utf-8") as f:
            RULES = json.load(f)
    except Exception:
        pass

def is_allowlisted(name_lower):
    for n in RULES.get("allow_names", DEFAULT_ALLOW_NAMES):
        if n.lower() == name_lower:
            return True
    return False

def is_game_process(name_lower):
    if any(w in name_lower for w in GAME_KEYWORDS):
        return True
    return False

def is_teams_process(name_lower):
    if any(w in name_lower for w in TEAMS_KEYWORDS):
        return True
    return False

def is_protected_process(name_lower):
    # FULL GAME IMMUNITY + Steam/Epic + Teams protection
    if is_game_process(name_lower):
        return True
    if is_teams_process(name_lower):
        return True
    if any(w in name_lower for w in [n.lower() for n in RULES.get("audio_whitelist", DEFAULT_AUDIO_WHITELIST)]):
        return True
    return False

def update_trust_score(proc_key, verdict):
    # Lightweight trust score adjustment stub
    hist = STATE.setdefault("trust_scores", {})
    cur = hist.get(proc_key, 0)
    if verdict == "benign":
        cur += 10
    elif verdict == "hostile":
        cur -= 20
    hist[proc_key] = cur
    save_state(STATE)

# === ENGINE STUBS (to be wired to your real engine) ===

def build_security_snapshot(gui_confirm_callback=None):
    """
    Stub: return list of info objects with attributes used in GUI.
    In your real system, this will query audio sessions, processes, RSE, MITRE, etc.
    """
    class Info:
        def __init__(self):
            self.pid = None
            self.name = "System"
            self.volume = 0.0
            self.muted = False
            self.risk_level = "Low"
            self.score = 0
            self.threat_class = "unknown"
            self.persona = "unknown"
            self.remote_index = 0
            self.rse_verdict = "None"
            self.rse_score = 0
            self.mitre_tags = []
            self.risk_reason = ""
            self.audio_profile = {
                "level": "low",
                "voice_like": False,
                "music_like": False,
                "game_like": False,
            }
            self.connections = []
    # Return empty snapshot for stub
    return []

def kill_process(pid):
    # Stub: implement actual process kill
    log_event("ACTION", f"Kill process PID={pid}")

def sandbox_process(pid):
    # Stub: suspend/quarantine process and return inspection info
    info = {
        "parent_pid": 0,
        "exe_path": f"C:\\fake\\path\\proc_{pid}.exe",
        "cmdline": f"proc_{pid}.exe",
        "create_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "file_hash": "FAKEHASH",
        "file_suspicious": False,
        "mem_suspicious": False,
    }
    log_event("ACTION", f"Sandbox process PID={pid}")
    return info

def resume_process(pid):
    # Stub: resume suspended process
    log_event("ACTION", f"Resume process PID={pid}")

def generate_report(snapshot):
    try:
        with open(REPORT_FILE_JSON, "w", encoding="utf-8") as f:
            json.dump([vars(s) for s in snapshot], f, indent=2)
        with open(REPORT_FILE_TXT, "w", encoding="utf-8") as f:
            f.write("Threat report\n")
    except Exception:
        pass

def create_incident_pack(snapshot):
    # Stub: write incident pack ZIP
    log_event("ACTION", "Incident pack created")

def freeze_incident_session(snapshot):
    try:
        with open(INCIDENT_SESSION_FILE, "w", encoding="utf-8") as f:
            json.dump([vars(s) for s in snapshot], f, indent=2)
    except Exception:
        pass

def run_lockdown_full_kill():
    """
    Deep scan + kill intruders.
    Respect FULL GAME IMMUNITY + Teams protection.
    """
    snapshot = build_security_snapshot()
    candidates = []
    killed = []
    for info in snapshot:
        name_lower = (info.name or "").lower()
        if is_protected_process(name_lower):
            continue
        intruder_score = max(info.score, info.remote_index)
        if intruder_score >= 60 or info.risk_level == "High":
            candidates.append({
                "pid": info.pid,
                "name": info.name,
                "intruder_score": intruder_score,
                "remote_index": info.remote_index,
                "verdict": info.rse_verdict,
                "risk": info.risk_level,
                "class": info.threat_class,
                "persona": info.persona,
            })
            if info.pid is not None:
                kill_process(info.pid)
                killed.append(info.pid)
    freeze_incident_session(snapshot)
    create_incident_pack(snapshot)
    return snapshot, candidates, killed

def audio_lockdown_trace():
    """
    Trace from speaker back to loud non-allowlisted audio source.
    Respect FULL GAME IMMUNITY + Teams protection.
    """
    # Stub: no real audio trace, return None
    return None, []

def confirm_audio_intruder(chain, user_confirm):
    """
    Respect user choice and FULL GAME IMMUNITY.
    """
    name_lower = (chain.get("name") or "").lower()
    if is_protected_process(name_lower):
        # Never kill protected processes
        return "protected"
    if user_confirm:
        pid = chain.get("pid")
        if pid is not None:
            kill_process(pid)
        return "killed"
    else:
        return "protected"

def reset_system_state():
    STATE["timeline"] = []
    STATE["audio_spikes"] = []
    STATE["clusters"] = []
    STATE["event_stream"] = []
    STATE["proc_history"] = {}
    STATE["safe_to_ignore"] = []
    STATE["audio_lockdown_active"] = False
    save_state(STATE)

def start_honeypot():
    # Stub: start honeypot
    log_event("INFO", "Honeypot started")

# === GUI CLASS ===

class SecurityBridgeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Bridge — Codex Control Console")
        load_rules()

        self.auto_refresh = tk.BooleanVar(value=False)
        self.refresh_interval = 10
        self.mode_var = tk.StringVar(value=RULES.get("mode", "NORMAL"))
        self.profile_var = tk.StringVar(value=RULES.get("profile", "DEFAULT"))
        self.mitre_filter_var = tk.StringVar(value="ALL")
        self.mitre_view_var = tk.StringVar(value="ALL")

        style = ttk.Style()
        style.configure("LockdownFull.TButton", foreground="red")
        style.configure("Reset.TButton", foreground="blue")
        style.configure("AudioLockdownGreen.TButton", foreground="green")
        style.configure("AudioLockdownRed.TButton", foreground="red")

        # === TOP BAR (3 ROWS, CODEX LAYOUT) ===
        top_bar = ttk.Frame(self.root)
        top_bar.pack(fill=tk.X, padx=10, pady=5)

        # ROW 1 — Lockdown / Reset / Audio Lockdown
        row1 = ttk.Frame(top_bar)
        row1.pack(fill=tk.X, pady=(4, 2))

        ttk.Button(
            row1,
            text="LOCKDOWN MODE — FULL KILL",
            command=self.lockdown_full_kill_gui,
            style="LockdownFull.TButton",
        ).pack(side=tk.LEFT, padx=5)

        ttk.Button(
            row1,
            text="RESET SYSTEM — RETURN TO NORMAL MODE",
            command=self.reset_system_gui,
            style="Reset.TButton",
        ).pack(side=tk.LEFT, padx=5)

        self.audio_lockdown_button = ttk.Button(
            row1,
            text="AUDIO LOCKDOWN — READY",
            command=self.audio_lockdown_gui,
            style="AudioLockdownGreen.TButton",
        )
        self.audio_lockdown_button.pack(side=tk.LEFT, padx=5)

        # ROW 2 — Core controls
        row2 = ttk.Frame(top_bar)
        row2.pack(fill=tk.X, pady=(2, 2))

        ttk.Button(row2, text="Refresh snapshot", command=self.refresh_snapshot).pack(side=tk.LEFT, padx=5)
        ttk.Checkbutton(row2, text="Auto refresh", variable=self.auto_refresh).pack(side=tk.LEFT, padx=5)
        ttk.Button(row2, text="Generate report", command=self.generate_report_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(row2, text="Incident pack", command=self.incident_pack_gui).pack(side=tk.LEFT, padx=5)
        ttk.Button(row2, text="Freeze session", command=self.freeze_session_gui).pack(side=tk.LEFT, padx=5)

        # ROW 3 — Security actions
        row3 = ttk.Frame(top_bar)
        row3.pack(fill=tk.X, pady=(2, 4))

        ttk.Button(row3, text="Kill all high-risk", command=self.kill_all_high_risk).pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="Suspend remote-index > 60", command=self.suspend_remote_high).pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="Mute suspicious audio", command=self.mute_suspicious_audio).pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="Silence non-media audio", command=self.silence_non_media_audio).pack(side=tk.LEFT, padx=5)
        ttk.Button(row3, text="Snapshot + pack", command=self.snapshot_and_pack).pack(side=tk.LEFT, padx=5)

        # === NOTEBOOK TABS ===
        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)

        # Processes tab
        self.proc_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.proc_frame, text="Processes")

        columns = (
            "pid",
            "process",
            "volume",
            "muted",
            "risk",
            "score",
            "class",
            "persona",
            "remote_index",
            "rse",
            "mitre",
            "reason",
        )
        self.tree = ttk.Treeview(self.proc_frame, columns=columns, show="headings")
        for col, text, width in [
            ("pid", "PID", 70),
            ("process", "Process", 220),
            ("volume", "Volume", 70),
            ("muted", "Muted", 70),
            ("risk", "Risk", 80),
            ("score", "Score", 70),
            ("class", "Class", 120),
            ("persona", "Persona", 160),
            ("remote_index", "RemoteIdx", 90),
            ("rse", "RSE", 160),
            ("mitre", "MITRE", 200),
            ("reason", "Reason", 500),
        ]:
            self.tree.heading(col, text=text)
            self.tree.column(
                col,
                width=width,
                anchor=tk.CENTER
                if col in ("pid", "volume", "muted", "risk", "score", "remote_index")
                else tk.W,
            )
        self.tree.pack(fill=tk.BOTH, expand=True)
        self.tree.bind("<<TreeviewSelect>>", self.on_process_select)

        # Timeline tab
        self.timeline_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.timeline_frame, text="Threat Timeline")
        self.timeline_text = scrolledtext.ScrolledText(self.timeline_frame, wrap=tk.WORD, height=20)
        self.timeline_text.pack(fill=tk.BOTH, expand=True)

        # Remote-control tab
        self.remote_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.remote_frame, text="Remote-Control / RSE")
        self.remote_text = scrolledtext.ScrolledText(self.remote_frame, wrap=tk.WORD, height=20)
        self.remote_text.pack(fill=tk.BOTH, expand=True)

        # Audio focus tab
        self.audio_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.audio_frame, text="Suspicious Audio Focus")
        self.audio_text = scrolledtext.ScrolledText(self.audio_frame, wrap=tk.WORD, height=20)
        self.audio_text.pack(fill=tk.BOTH, expand=True)

        # Audio Intruder Trace tab
        self.audio_trace_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.audio_trace_frame, text="Audio Intruder Trace")
        self.audio_trace_text = scrolledtext.ScrolledText(self.audio_trace_frame, wrap=tk.WORD, height=20)
        self.audio_trace_text.pack(fill=tk.BOTH, expand=True)

        # Rule editor tab
        self.rules_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.rules_frame, text="Rule Editor")
        self._build_rule_editor(self.rules_frame)

        # Per-process history tab
        self.history_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.history_frame, text="Process History")
        self.history_text = scrolledtext.ScrolledText(self.history_frame, wrap=tk.WORD, height=20)
        self.history_text.pack(fill=tk.BOTH, expand=True)

        # Clusters tab
        self.cluster_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.cluster_frame, text="Correlation Clusters")
        self.cluster_text = scrolledtext.ScrolledText(self.cluster_frame, wrap=tk.WORD, height=20)
        self.cluster_text.pack(fill=tk.BOTH, expand=True)

        # Event stream tab
        self.event_frame = ttk.Frame(self.notebook)
        self.notebook.add(self.event_frame, text="JSON Event Stream")
        self.event_text = scrolledtext.ScrolledText(self.event_frame, wrap=tk.WORD, height=20)
        self.event_text.pack(fill=tk.BOTH, expand=True)

        # MITRE filter bar
        mitre_bar = ttk.Frame(self.timeline_frame)
        mitre_bar.pack(fill=tk.X, padx=5, pady=5)
        ttk.Label(mitre_bar, text="MITRE tag filter:").pack(side=tk.LEFT)
        mitre_combo = ttk.Combobox(
            mitre_bar,
            textvariable=self.mitre_filter_var,
            values=["ALL", "T1055", "T1105", "T1041", "T1129", "T1071", "T1027"],
            width=10,
        )
        mitre_combo.pack(side=tk.LEFT, padx=5)
        mitre_combo.bind("<<ComboboxSelected>>", self.on_mitre_filter_change)

        ttk.Label(mitre_bar, text="MITRE view:").pack(side=tk.LEFT, padx=(20, 2))
        mitre_view_combo = ttk.Combobox(
            mitre_bar,
            textvariable=self.mitre_view_var,
            values=list(MITRE_VIEWS.keys()),
            width=20,
        )
        mitre_view_combo.pack(side=tk.LEFT, padx=5)
        mitre_view_combo.bind("<<ComboboxSelected>>", self.on_mitre_view_change)

        self.status_var = tk.StringVar(value="Ready")
        status_bar = ttk.Label(self.root, textvariable=self.status_var, anchor=tk.W)
        status_bar.pack(fill=tk.X, padx=10, pady=3)

        self._start_auto_refresh()
        self.refresh_snapshot()

    # === Rule editor ===
    def _build_rule_editor(self, frame):
        pad = 5
        ttk.Label(frame, text="Allowlist (one name per line):").pack(anchor=tk.W, padx=pad, pady=(pad, 0))
        self.allow_text = scrolledtext.ScrolledText(frame, height=6)
        self.allow_text.pack(fill=tk.X, padx=pad, pady=(0, pad))

        ttk.Label(frame, text="Block (remote tool) keywords (one per line):").pack(anchor=tk.W, padx=pad, pady=(pad, 0))
        self.block_text = scrolledtext.ScrolledText(frame, height=6)
        self.block_text.pack(fill=tk.X, padx=pad, pady=(0, pad))

        ttk.Label(frame, text="Suspicious ports (comma-separated):").pack(anchor=tk.W, padx=pad, pady=(pad, 0))
        self.ports_entry = ttk.Entry(frame)
        self.ports_entry.pack(fill=tk.X, padx=pad, pady=(0, pad))

        ttk.Label(frame, text="Base auto-block threshold (profile baseline):").pack(anchor=tk.W, padx=pad, pady=(pad, 0))
        self.threshold_entry = ttk.Entry(frame)
        self.threshold_entry.pack(fill=tk.X, padx=pad, pady=(0, pad))

        ttk.Button(frame, text="Load rules", command=self.load_rules_into_editor).pack(side=tk.LEFT, padx=pad, pady=pad)
        ttk.Button(frame, text="Save rules", command=self.save_rules_from_editor).pack(side=tk.LEFT, padx=pad, pady=pad)

        self.load_rules_into_editor()

    def load_rules_into_editor(self):
        self.allow_text.delete("1.0", tk.END)
        self.block_text.delete("1.0", tk.END)
        self.ports_entry.delete(0, tk.END)
        self.threshold_entry.delete(0, tk.END)

        for n in RULES.get("allow_names", DEFAULT_ALLOW_NAMES):
            self.allow_text.insert(tk.END, n + "\n")
        for k in RULES.get("block_names", REMOTE_TOOL_KEYWORDS):
            self.block_text.insert(tk.END, k + "\n")
        self.ports_entry.insert(0, ",".join(str(p) for p in RULES.get("block_ports", SUSPICIOUS_PORTS)))
        self.threshold_entry.insert(0, str(RULES.get("auto_block_threshold", DEFAULT_AUTO_BLOCK_THRESHOLD)))

    def save_rules_from_editor(self):
        allow_lines = [l.strip() for l in self.allow_text.get("1.0", tk.END).splitlines() if l.strip()]
        block_lines = [l.strip() for l in self.block_text.get("1.0", tk.END).splitlines() if l.strip()]
        ports_str = self.ports_entry.get().strip()
        threshold_str = self.threshold_entry.get().strip()

        try:
            ports = [int(p.strip()) for p in ports_str.split(",") if p.strip()]
            threshold = int(threshold_str)
        except ValueError:
            messagebox.showerror("Error", "Ports must be integers, threshold must be integer.")
            return

        RULES["allow_names"] = allow_lines
        RULES["block_names"] = block_lines
        RULES["block_ports"] = ports
        RULES["auto_block_threshold"] = threshold

        try:
            with open(RULES_FILE, "w", encoding="utf-8") as f:
                json.dump(RULES, f, indent=2)
        except Exception:
            pass

        self.status_var.set("Rules saved.")
        messagebox.showinfo("Rules", "Rules updated and saved.")

    # === Auto refresh ===
    def _start_auto_refresh(self):
        def loop():
            if pythoncom:
                pythoncom.CoInitialize()
            while True:
                if self.auto_refresh.get():
                    self.refresh_snapshot()
                time.sleep(self.refresh_interval)

        t = threading.Thread(target=loop, daemon=True)
        t.start()

    # === GUI confirm autoblock ===
    def gui_confirm_autoblock(self, info, sandbox_info):
        if sandbox_info is None:
            return "kill"
        msg = (
            f"Auto-block candidate:\n\n"
            f"PID: {info.pid}\n"
            f"Name: {info.name}\n"
            f"Score: {info.score}\n"
            f"Risk: {info.risk_level}\n"
            f"Class: {info.threat_class}\n"
            f"Persona: {info.persona}\n"
            f"Remote index: {info.remote_index}\n"
            f"RSE: {info.rse_verdict} ({info.rse_score}%)\n"
            f"Executable: {sandbox_info['exe_path']}\n"
            f"SHA256: {sandbox_info['file_hash']}\n"
            f"File suspicious: {sandbox_info['file_suspicious']}\n"
            f"Memory suspicious: {sandbox_info['mem_suspicious']}\n\n"
            f"Kill this process?"
        )
        answer = messagebox.askyesnocancel("Auto-block decision", msg)
        if answer is None:
            return "resume"
        return "kill" if answer else "resume"

    # === Snapshot + panels ===
    def refresh_snapshot(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
            self.last_snapshot = snapshot
        except Exception as e:
            self.status_var.set(f"Error building snapshot: {e}")
            log_event("ERROR", f"Snapshot error: {e}")
            return

        for item in self.tree.get_children():
            self.tree.delete(item)

        mitre_filter = self.mitre_filter_var.get()
        mitre_view = self.mitre_view_var.get()
        view_tags = MITRE_VIEWS.get(mitre_view, [])

        for info in snapshot:
            if mitre_filter != "ALL" and mitre_filter not in info.mitre_tags:
                continue
            if view_tags:
                if not any(t in info.mitre_tags for t in view_tags):
                    continue
            vol_str = f"{int(info.volume * 100)}%" if info.volume is not None else "N/A"
            muted_str = "Yes" if info.muted else "No"
            pid_str = info.pid if info.pid is not None else "-"
            mitre_str = ",".join(info.mitre_tags) if info.mitre_tags else ""
            rse_str = f"{info.rse_verdict} ({info.rse_score}%)" if info.rse_verdict != "None" else ""
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
                    info.threat_class,
                    info.persona,
                    info.remote_index,
                    rse_str,
                    mitre_str,
                    info.risk_reason,
                ),
            )

        self.update_timeline()
        self.update_remote_panel(snapshot)
        self.update_audio_focus(snapshot)
        self.update_audio_trace_panel(None)
        self.update_clusters()
        self.update_event_stream()

        self.status_var.set(f"Snapshot updated: {len(snapshot)} audio sessions")

    def update_timeline(self):
        self.timeline_text.delete("1.0", tk.END)
        timeline = STATE.get("timeline", [])
        mitre_view = self.mitre_view_var.get()
        view_tags = MITRE_VIEWS.get(mitre_view, [])

        self.timeline_text.insert(tk.END, f"MITRE view: {mitre_view} (tags={view_tags})\n\n")

        for entry in timeline[-400:]:
            persona = entry.get("persona", "unknown")
            remote_index = entry.get("remote_index", 0)
            score = entry.get("score", 0)
            risk = entry.get("risk", "Low")
            cls = entry.get("class", "unknown")
            rse_verdict = entry.get("rse_verdict", "None")
            rse_score = entry.get("rse_score", 0)
            line = (
                f"{entry.get('ts', '?')} PID {entry.get('pid', '?')} {entry.get('name', '?')} "
                f"score={score} risk={risk} class={cls} persona={persona} "
                f"remote_index={remote_index} RSE={rse_verdict}({rse_score}%)\n"
            )
            self.timeline_text.insert(tk.END, line)

        self.timeline_text.insert(tk.END, "\nAudio spikes (last 50):\n")
        for spike in STATE.get("audio_spikes", [])[-50:]:
            self.timeline_text.insert(
                tk.END,
                f"{spike['ts']} PID {spike['pid']} {spike['name']} audio {spike['old_level']} -> {spike['new_level']}\n",
            )

    def update_remote_panel(self, snapshot):
        self.remote_text.delete("1.0", tk.END)
        mitre_view = self.mitre_view_var.get()
        view_tags = MITRE_VIEWS.get(mitre_view, [])

        self.remote_text.insert(tk.END, f"Remote-control / RSE view ({mitre_view}):\n\n")

        for info in snapshot:
            name_lower = (info.name or "").lower()
            if is_protected_process(name_lower):
                continue
            if info.remote_index >= 40 or any(k in name_lower for k in REMOTE_TOOL_KEYWORDS):
                if view_tags and not any(t in info.mitre_tags for t in view_tags):
                    continue
                self.remote_text.insert(
                    tk.END,
                    f"REMOTE SUSPECT: PID {info.pid} {info.name} score={info.score} "
                    f"risk={info.risk_level} class={info.threat_class} persona={info.persona} "
                    f"remote_index={info.remote_index} RSE={info.rse_verdict}({info.rse_score}%) MITRE={info.mitre_tags}\n",
                )
                for laddr, raddr, status, external, rep in info.connections:
                    self.remote_text.insert(
                        tk.END,
                        f"  {laddr} -> {raddr} [{status}] external={external} rep={rep}\n",
                    )

    def update_audio_focus(self, snapshot):
        self.audio_text.delete("1.0", tk.END)
        self.audio_text.insert(tk.END, "Suspicious audio focus:\n\n")
        for info in snapshot:
            name_lower = (info.name or "").lower()
            if is_protected_process(name_lower):
                continue
            if info.audio_profile["level"] in ("medium", "high") and not is_allowlisted(name_lower):
                self.audio_text.insert(
                    tk.END,
                    f"AUDIO: PID {info.pid} {info.name} level={info.audio_profile['level']} "
                    f"voice={info.audio_profile['voice_like']} music={info.audio_profile['music_like']} "
                    f"game={info.audio_profile['game_like']} score={info.score} risk={info.risk_level} "
                    f"class={info.threat_class} persona={info.persona} remote_index={info.remote_index} "
                    f"RSE={info.rse_verdict}({info.rse_score}%)\n",
                )

    def update_audio_trace_panel(self, chain):
        self.audio_trace_text.delete("1.0", tk.END)
        if chain is None:
            self.audio_trace_text.insert(tk.END, "Audio Intruder Trace: no active trace.\n")
            return
        self.audio_trace_text.insert(tk.END, "Audio Intruder Trace:\n\n")
        self.audio_trace_text.insert(
            tk.END,
            f"Speaker → Audio Session → PID {chain['pid']} ({chain['name']})\n",
        )
        self.audio_trace_text.insert(
            tk.END,
            f"Volume: {int(chain['volume'] * 100)}% level={chain['audio_profile']['level']} "
            f"muted={chain['muted']}\n",
        )
        self.audio_trace_text.insert(
            tk.END,
            f"Parent PID: {chain['parent_pid']} exe={chain['exe_path']}\n",
        )
        self.audio_trace_text.insert(
            tk.END,
            f"Cmdline: {chain['cmdline']}\nCreated: {chain['create_time']}\n",
        )
        self.audio_trace_text.insert(
            tk.END,
            f"File hash: {chain['file_hash']}\nFile suspicious: {chain['file_suspicious']} "
            f"Mem suspicious: {chain['mem_suspicious']}\n",
        )
        self.audio_trace_text.insert(
            tk.END,
            f"Score: {chain['score']} risk={chain['risk_level']} class={chain['threat_class']} "
            f"persona={chain['persona']} remote_index={chain['remote_index']} "
            f"RSE={chain['rse_verdict']}({chain['rse_score']}%) MITRE={chain['mitre_tags']}\n\n",
        )
        self.audio_trace_text.insert(tk.END, "Connections:\n")
        for laddr, raddr, status, external, rep in chain["connections"]:
            self.audio_trace_text.insert(
                tk.END,
                f"  {laddr} -> {raddr} [{status}] external={external} rep={rep}\n",
            )

    def update_clusters(self):
        self.cluster_text.delete("1.0", tk.END)
        clusters = STATE.get("clusters", [])
        if not clusters:
            self.cluster_text.insert(tk.END, "No clusters recorded.\n")
            return
        self.cluster_text.insert(tk.END, "Correlation clusters (lightweight):\n\n")
        for c in clusters:
            self.cluster_text.insert(
                tk.END,
                f"PID {c.get('pid')} {c.get('name')} parent={c.get('parent_pid')} "
                f"remote_index={c.get('remote_index')} persona={c.get('persona')} "
                f"RSE={c.get('rse_verdict')}({c.get('rse_score')}) "
                f"external_ips={c.get('external_ips')}\n",
            )
        self.cluster_text.insert(tk.END, "\nCluster actions:\n")
        self.cluster_text.insert(tk.END, "Use 'Mark cluster benign' or 'Mark cluster hostile' from process selection.\n")

    def update_event_stream(self):
        self.event_text.delete("1.0", tk.END)
        events = STATE.get("event_stream", [])
        for ev in events[-400:]:
            self.event_text.insert(tk.END, json.dumps(ev) + "\n")

    # === Process selection helpers ===
    def on_process_select(self, event=None):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            return
        name_lower = (process_name or "").lower()
        proc_key = f"{name_lower}:{pid}"
        hist = STATE.get("proc_history", {}).get(proc_key, [])
        self.history_text.delete("1.0", tk.END)
        self.history_text.insert(tk.END, f"History for {process_name} (PID {pid}):\n\n")
        for h in hist[-200:]:
            self.history_text.insert(
                tk.END,
                f"{h.get('ts', '?')} score={h.get('score', 0)} risk={h.get('risk', 'Low')} "
                f"class={h.get('class', 'unknown')} persona={h.get('persona', 'unknown')} "
                f"remote_index={h.get('remote_index', 0)} "
                f"audio={h.get('audio', False)} net={h.get('network', False)} "
                f"RSE={h.get('rse_verdict', 'None')}({h.get('rse_score', 0)}%)\n",
            )

    def _get_selected_pid_and_name(self):
        selected = self.tree.selection()
        if not selected:
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

    # === Actions (respect FULL GAME IMMUNITY + Teams) ===
    def kill_selected_process(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot kill", "Selected session is not tied to a user process.")
            return
        name_lower = (process_name or "").lower()
        if is_protected_process(name_lower):
            messagebox.showinfo(
                "Protected process",
                f"{process_name} (PID {pid}) is protected by FULL GAME IMMUNITY / Teams patch and will not be killed.",
            )
            return
        answer = messagebox.askyesno(
            "Confirm kill",
            f"Kill process {process_name} (PID {pid})?\n\nThis will forcibly stop its audio and any running activity.",
        )
        if not answer:
            return
        kill_process(pid)
        self.status_var.set(f"Killed process {process_name} (PID {pid})")
        self.refresh_snapshot()

    def kill_all_high_risk(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
        except Exception as e:
            messagebox.showerror("Error", f"Snapshot error: {e}")
            return
        count = 0
        for info in snapshot:
            name_lower = (info.name or "").lower()
            if is_protected_process(name_lower):
                continue
            if info.risk_level == "High" and info.pid is not None and not is_allowlisted(name_lower):
                kill_process(info.pid)
                count += 1
        messagebox.showinfo("Kill all high-risk", f"Killed {count} high-risk processes.")
        self.status_var.set(f"Killed {count} high-risk processes.")
        self.refresh_snapshot()

    def suspend_remote_high(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
        except Exception as e:
            messagebox.showerror("Error", f"Snapshot error: {e}")
            return
        count = 0
        for info in snapshot:
            name_lower = (info.name or "").lower()
            if is_protected_process(name_lower):
                continue
            if info.remote_index >= 60 and info.pid is not None and not is_allowlisted(name_lower):
                sandbox_process(info.pid)
                count += 1
        messagebox.showinfo("Suspend remote-index > 60", f"Suspended {count} processes.")
        self.status_var.set(f"Suspended {count} remote-suspect processes.")
        self.refresh_snapshot()

    def mute_suspicious_audio(self):
        if pythoncom:
            pythoncom.CoInitialize()
        if not AudioUtilities:
            messagebox.showerror("Error", "AudioUtilities not available.")
            return
        sessions = AudioUtilities.GetAllSessions()
        count = 0
        for session in sessions:
            try:
                volume = session._ctl.QueryInterface(ISimpleAudioVolume)
                pid = session.Process.pid if session.Process else None
                name = session.Process.name() if session.Process else "System"
                name_lower = (name or "").lower()
                if pid is None:
                    continue
                if is_protected_process(name_lower):
                    continue
                if is_allowlisted(name_lower):
                    continue
                vol_level = volume.GetMasterVolume()
                if vol_level > 0.2:
                    volume.SetMasterVolume(0.0, None)
                    count += 1
                    emit_event(
                        {
                            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "audio_mute",
                            "pid": pid,
                            "name": name,
                            "prev_volume": vol_level,
                        }
                    )
            except Exception:
                continue
        messagebox.showinfo("Mute suspicious audio", f"Muted {count} loud non-allowlisted audio sessions.")
        self.status_var.set(f"Muted {count} suspicious audio sessions.")
        self.refresh_snapshot()

    def silence_non_media_audio(self):
        if pythoncom:
            pythoncom.CoInitialize()
        if not AudioUtilities:
            messagebox.showerror("Error", "AudioUtilities not available.")
            return
        sessions = AudioUtilities.GetAllSessions()
        count = 0
        media_whitelist = [n.lower() for n in RULES.get("audio_whitelist", DEFAULT_AUDIO_WHITELIST)]
        for session in sessions:
            try:
                volume = session._ctl.QueryInterface(ISimpleAudioVolume)
                pid = session.Process.pid if session.Process else None
                name = session.Process.name() if session.Process else "System"
                name_lower = (name or "").lower()
                if pid is None:
                    continue
                if any(w in name_lower for w in media_whitelist):
                    continue
                if is_protected_process(name_lower):
                    continue
                vol_level = volume.GetMasterVolume()
                if vol_level > 0.05:
                    volume.SetMasterVolume(0.0, None)
                    count += 1
                    emit_event(
                        {
                            "ts": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                            "type": "audio_mute_non_media",
                            "pid": pid,
                            "name": name,
                            "prev_volume": vol_level,
                        }
                    )
            except Exception:
                continue
        messagebox.showinfo("Silence non-media audio", f"Muted {count} non-media audio sessions.")
        self.status_var.set(f"Silenced {count} non-media audio sessions.")
        self.refresh_snapshot()

    def snapshot_and_pack(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
            freeze_incident_session(snapshot)
            create_incident_pack(snapshot)
            messagebox.showinfo(
                "Snapshot + pack",
                f"Snapshot, incident session, and pack created ({INCIDENT_ZIP}).",
            )
            self.status_var.set("Snapshot + pack completed.")
        except Exception as e:
            messagebox.showerror("Error", f"Snapshot + pack error: {e}")
            self.status_var.set(f"Snapshot + pack error: {e}")

    def sandbox_selected(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot sandbox", "Selected session is not tied to a user process.")
            return
        name_lower = (process_name or "").lower()
        if is_protected_process(name_lower):
            messagebox.showinfo(
                "Protected process",
                f"{process_name} (PID {pid}) is protected by FULL GAME IMMUNITY / Teams patch and will not be sandboxed.",
            )
            return
        info = sandbox_process(pid)
        if not info:
            messagebox.showerror("Sandbox failed", "Could not sandbox process.")
            return
        msg = (
            f"Sandboxed PID {pid} ({process_name})\n"
            f"Parent PID: {info['parent_pid']}\n"
            f"Executable: {info['exe_path']}\n"
            f"Cmdline: {info['cmdline']}\n"
            f"Created: {info['create_time']}\n"
            f"SHA256: {info['file_hash']}\n"
            f"File suspicious: {info['file_suspicious']}\n"
            f"Memory suspicious: {info['mem_suspicious']}\n"
        )
        messagebox.showinfo("Sandbox inspection", msg)
        self.status_var.set(f"Sandboxed PID {pid} ({process_name})")

    def resume_selected(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot resume", "Selected session is not tied to a user process.")
            return
        resume_process(pid)
        self.status_var.set(f"Resumed PID {pid} ({process_name})")
        self.refresh_snapshot()

    def generate_report_gui(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
            generate_report(snapshot)
            messagebox.showinfo(
                "Report",
                f"Threat report written to {REPORT_FILE_JSON} and {REPORT_FILE_TXT}",
            )
            self.status_var.set("Report generated.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate report: {e}")
            self.status_var.set(f"Report error: {e}")

    def incident_pack_gui(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
            create_incident_pack(snapshot)
            messagebox.showinfo("Incident pack", f"Incident pack written to {INCIDENT_ZIP}")
            self.status_var.set("Incident pack created.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to create incident pack: {e}")
            self.status_var.set(f"Incident pack error: {e}")

    def freeze_session_gui(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
            freeze_incident_session(snapshot)
            messagebox.showinfo(
                "Incident session",
                f"Incident session frozen to {INCIDENT_SESSION_FILE}",
            )
            self.status_var.set("Incident session frozen.")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to freeze incident session: {e}")
            self.status_var.set(f"Incident session error: {e}")

    def mark_safe_selected(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot mark", "Selected session is not tied to a user process.")
            return
        name_lower = (process_name or "").lower()
        proc_key = f"{name_lower}:{pid}"
        safe_set = STATE.get("safe_to_ignore", [])
        if proc_key not in safe_set:
            safe_set.append(proc_key)
            STATE["safe_to_ignore"] = safe_set
            save_state(STATE)
        messagebox.showinfo("Noise filter", f"Marked {process_name} (PID {pid}) as safe-to-ignore.")
        self.status_var.set(f"Marked {process_name} as safe-to-ignore.")
        self.refresh_snapshot()

    def mark_cluster_benign(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot mark cluster", "Select a process first.")
            return
        clusters = STATE.get("clusters", [])
        affected = 0
        for c in clusters:
            if c.get("pid") == pid:
                parent_pid = c.get("parent_pid")
                ext_ips = set(c.get("external_ips", []))
                for c2 in clusters:
                    if c2.get("parent_pid") == parent_pid or ext_ips.intersection(
                        set(c2.get("external_ips", []))
                    ):
                        ck = f"{(c2.get('name') or '').lower()}:{c2.get('pid')}"
                        update_trust_score(ck, "benign")
                        affected += 1
        messagebox.showinfo("Cluster benign", f"Marked {affected} cluster members as benign (trust raised).")
        self.status_var.set(f"Cluster benign: {affected} members.")
        self.refresh_snapshot()

    def mark_cluster_hostile(self):
        pid, process_name = self._get_selected_pid_and_name()
        if pid is None:
            messagebox.showwarning("Cannot mark cluster", "Select a process first.")
            return
        clusters = STATE.get("clusters", [])
        affected = 0
        for c in clusters:
            if c.get("pid") == pid:
                parent_pid = c.get("parent_pid")
                ext_ips = set(c.get("external_ips", []))
                for c2 in clusters:
                    if c2.get("parent_pid") == parent_pid or ext_ips.intersection(
                        set(c2.get("external_ips", []))
                    ):
                        ck = f"{(c2.get('name') or '').lower()}:{c2.get('pid')}"
                        update_trust_score(ck, "hostile")
                        affected += 1
        messagebox.showinfo("Cluster hostile", f"Marked {affected} cluster members as hostile (trust lowered).")
        self.status_var.set(f"Cluster hostile: {affected} members.")
        self.refresh_snapshot()

    def quarantine_remote_tools(self):
        try:
            snapshot = build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
        except Exception as e:
            messagebox.showerror("Error", f"Snapshot error: {e}")
            return
        count = 0
        for info in snapshot:
            if info.pid is None:
                continue
            name_lower = (info.name or "").lower()
            if is_protected_process(name_lower):
                continue
            if info.remote_index >= 40 and ("T1105" in info.mitre_tags or "T1071" in info.mitre_tags):
                sandbox_process(info.pid)
                count += 1
        messagebox.showinfo("Quarantine remote tools", f"Suspended {count} remote-control suspects.")
        self.status_var.set(f"Quarantined {count} remote-control suspects.")
        self.refresh_snapshot()

    def audio_lockdown_gui(self):
        STATE["audio_lockdown_active"] = True
        save_state(STATE)
        self.audio_lockdown_button.configure(
            text="AUDIO LOCKDOWN — SCANNING AUDIO SOURCE…",
            style="AudioLockdownRed.TButton",
        )
        self.status_var.set("AUDIO LOCKDOWN running (speaker trace)...")
        self.root.update_idletasks()

        try:
            chain, sessions = audio_lockdown_trace()
        except Exception as e:
            messagebox.showerror("AUDIO LOCKDOWN ERROR", f"Audio trace failed: {e}")
            self.status_var.set(f"Audio lockdown error: {e}")
            return

        if chain is None:
            messagebox.showinfo("AUDIO LOCKDOWN", "No loud non-allowlisted audio source found.")
            self.status_var.set("Audio lockdown: no intruder found.")
            self.update_audio_trace_panel(None)
            return

        self.update_audio_trace_panel(chain)

        msg = (
            f"Audio intruder candidate:\n\n"
            f"PID: {chain['pid']}\n"
            f"Name: {chain['name']}\n"
            f"Volume: {int(chain['volume'] * 100)}% level={chain['audio_profile']['level']} muted={chain['muted']}\n"
            f"Parent PID: {chain['parent_pid']}\n"
            f"Executable: {chain['exe_path']}\n"
            f"Cmdline: {chain['cmdline']}\n"
            f"Created: {chain['create_time']}\n"
            f"File suspicious: {chain['file_suspicious']} Mem suspicious: {chain['mem_suspicious']}\n"
            f"Score: {chain['score']} risk={chain['risk_level']} class={chain['threat_class']} persona={chain['persona']}\n"
            f"Remote index: {chain['remote_index']} RSE={chain['rse_verdict']}({chain['rse_score']}%)\n"
            f"MITRE: {chain['mitre_tags']}\n\n"
            f"Is this the intruder causing the sound?\n"
        )
        answer = messagebox.askyesno("AUDIO LOCKDOWN — CONFIRM INTRUDER", msg)

        result = confirm_audio_intruder(chain, user_confirm=answer)

        if result == "protected":
            self.status_var.set("Audio lockdown: user denied kill or process protected.")
            messagebox.showinfo(
                "AUDIO LOCKDOWN",
                "Process is protected or you said NO.\n\n"
                "Auto-block disabled, repeated-hit disabled, trust reset.\n"
                "It will NOT keep coming back.",
            )
        elif result == "killed":
            self.status_var.set("Audio lockdown: intruder confirmed and killed.")
            messagebox.showinfo(
                "AUDIO LOCKDOWN",
                "Intruder confirmed and killed.\n\n"
                "System will perform one more scan.\n"
                "If the sound stops, this intruder will NOT be hunted again.",
            )
            try:
                build_security_snapshot(gui_confirm_callback=self.gui_confirm_autoblock)
            except Exception:
                pass
        else:
            self.status_var.set("Audio lockdown: kill failed or error.")

        self.audio_lockdown_button.configure(
            text="AUDIO LOCKDOWN — ACTIVE (WAITING FOR RESET)",
            style="AudioLockdownRed.TButton",
        )

        self.refresh_snapshot()

    def lockdown_full_kill_gui(self):
        answer = messagebox.askyesno(
            "LOCKDOWN MODE — FULL KILL",
            "You are about to run LOCKDOWN MODE (Full Kill).\n\n"
            "This will:\n"
            "- Deep scan for intruder candidates\n"
            "- Kill all high-suspicion processes (intruder_score >= 60 or remote_index >= 60 or High risk)\n"
            "- Freeze evidence and create a lockdown pack\n\n"
            "Proceed?",
        )
        if not answer:
            return

        self.status_var.set("LOCKDOWN MODE running (Full Kill)...")
        self.root.update_idletasks()

        try:
            snapshot, candidates, killed = run_lockdown_full_kill()
        except Exception as e:
            messagebox.showerror("LOCKDOWN ERROR", f"Lockdown failed: {e}")
            self.status_var.set(f"Lockdown error: {e}")
            return

        msg = (
            f"LOCKDOWN MODE completed.\n\n"
            f"Intruder candidates: {len(candidates)}\n"
            f"Processes killed: {len(killed)}\n"
            f"Lockdown pack: {LOCKDOWN_ZIP}\n\n"
            f"Top candidates:\n"
        )
        for c in candidates[:10]:
            msg += (
                f"- PID {c['pid']} {c['name']} intruder_score={c['intruder_score']} "
                f"remote_index={c['remote_index']} verdict={c['verdict']} "
                f"risk={c['risk']} class={c['class']} persona={c['persona']}\n"
            )

        messagebox.showinfo("LOCKDOWN MODE — RESULT", msg)
        self.status_var.set(f"LOCKDOWN completed. Killed {len(killed)} processes. Pack: {LOCKDOWN_ZIP}")
        self.refresh_snapshot()

    def reset_system_gui(self):
        answer = messagebox.askyesno(
            "RESET SYSTEM — RETURN TO NORMAL MODE",
            "You are about to reset Security Bridge internal state.\n\n"
            "This will:\n"
            "- Clear volatile incident state (timeline, audio spikes, event stream, history, clusters)\n"
            "- Reset detection counters and trust scores\n"
            "- Reset AUDIO LOCKDOWN state (button returns green)\n"
            "- Keep all lockdown evidence files (JSON + ZIP)\n\n"
            "Windows will NOT reboot.\n\n"
            "Proceed?",
        )
        if not answer:
            return

        self.status_var.set("Reset Mode running...")
        self.root.update_idletasks()

        try:
            reset_system_state()
        except Exception as e:
            messagebox.showerror("RESET ERROR", f"Reset failed: {e}")
            self.status_var.set(f"Reset error: {e}")
            return

        self.audio_lockdown_button.configure(
            text="AUDIO LOCKDOWN — READY",
            style="AudioLockdownGreen.TButton",
        )

        messagebox.showinfo(
            "RESET COMPLETE",
            "System Reset Complete — Monitoring Normal.\n\n"
            "All lockdown evidence has been preserved.\n",
        )
        self.status_var.set("System Reset Complete — Monitoring Normal.")
        self.refresh_snapshot()

    def on_mitre_filter_change(self, event=None):
        self.update_timeline()

    def on_mitre_view_change(self, event=None):
        self.update_timeline()
        self.update_remote_panel(self.last_snapshot if hasattr(self, "last_snapshot") else [])


# === MAIN ENTRYPOINT ===

def main():
    log_event("INFO", "Security Bridge (Codex Control Console Full Upgrade) started.")
    start_honeypot()
    root = tk.Tk()
    app = SecurityBridgeGUI(root)

    # Right-click context menu (keep advanced actions here)
    menu = tk.Menu(root, tearoff=0)
    menu.add_command(label="Kill selected process", command=app.kill_selected_process)
    menu.add_command(label="Sandbox selected", command=app.sandbox_selected)
    menu.add_command(label="Resume selected", command=app.resume_selected)
    menu.add_separator()
    menu.add_command(label="Mark selected safe-to-ignore", command=app.mark_safe_selected)
    menu.add_separator()
    menu.add_command(label="Mark cluster benign", command=app.mark_cluster_benign)
    menu.add_command(label="Mark cluster hostile", command=app.mark_cluster_hostile)

    def show_menu(event):
        try:
            app.tree.selection_set(app.tree.identify_row(event.y))
            menu.tk_popup(event.x_root, event.y_root)
        finally:
            menu.grab_release()

    app.tree.bind("<Button-3>", show_menu)

    root.mainloop()
    log_event("INFO", "Security Bridge closed.")


if __name__ == "__main__":
    main()
