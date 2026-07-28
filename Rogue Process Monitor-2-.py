import time
import datetime
import psutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# ============================================================
# Rogue Process Monitor v13.0 (SAFE, NON-DESTRUCTIVE)
# - Behavior engine
# - Reputation scoring
# - Threat meter
# - Timeline visualization
# - Parent/child process tree (cycle-proof)
# - Snapshot panel
# - Rogue report generator
# - Optimized refresh rates (Performance Mode)
# ============================================================

LOG_FILE = "rogue_monitor_v13_0_log.txt"

# -------------------------
# Logging
# -------------------------

def log(msg):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# -------------------------
# Blacklist / config
# -------------------------

DEFAULT_BLACKLIST = [
    "google chrome for testing.exe",
    "chrome.exe",
    "chrome_sandbox.exe",
    "chrome_child.exe",
    "chrome_renderer.exe",
    "chrome_gpu.exe",
    "pdpro7 hook.exe",
    "audiohook.dll",
    "overlayinjector.exe",
    "virtualaudio.exe",
    "debug_audio_hook.exe",
]

SUSPICIOUS_PATH_KEYWORDS = [
    "\\temp\\",
    "\\tmp\\",
    "\\appdata\\local\\temp\\",
    "\\appdata\\roaming\\",
    "\\downloads\\",
]

SUSPICIOUS_PARENT_KEYWORDS = [
    "steamwebhelper.exe",
    "chrome.exe",
    "google chrome for testing.exe",
    "pdpro7 hook.exe",
]

blacklist_lock = threading.Lock()
blacklist = DEFAULT_BLACKLIST.copy()

def get_blacklist():
    with blacklist_lock:
        return list(blacklist)

def add_to_blacklist(name):
    name = name.strip()
    if not name:
        return
    with blacklist_lock:
        if name not in blacklist:
            blacklist.append(name)
    log(f"Added to blacklist: {name}")

def remove_from_blacklist(name):
    name = name.strip()
    if not name:
        return
    with blacklist_lock:
        if name in blacklist:
            blacklist.remove(name)
    log(f"Removed from blacklist: {name}")

def is_rogue_name(name: str) -> bool:
    if not name:
        return False
    lname = name.lower()
    with blacklist_lock:
        for entry in blacklist:
            if entry.lower() in lname:
                return True
    return False

# -------------------------
# History / timeline
# -------------------------

history_lock = threading.Lock()
history_events = []  # list of dicts: {ts, name, pid, path, reason, score}

def record_rogue_event(name, pid, path, reason, score):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event = {
        "ts": ts,
        "name": name,
        "pid": pid,
        "path": path,
        "reason": reason,
        "score": score,
    }
    with history_lock:
        history_events.append(event)
        if len(history_events) > 1000:
            history_events.pop(0)
    log(f"DETECTED ROGUE: {name} (PID={pid}) path={path} reason={reason} score={score}")

# -------------------------
# Notification (SAFE)
# -------------------------

def notify_user_popup(name, pid, path, reason, score):
    def _show():
        root = tk.Tk()
        root.withdraw()
        messagebox.showwarning(
            "Rogue Process Detected",
            f"Process: {name}\nPID: {pid}\nPath: {path}\nReason: {reason}\nScore: {score}\n\n"
            "This process matches your rogue criteria.\n"
            "No destructive action was taken automatically."
        )
        root.destroy()
    t = threading.Thread(target=_show, daemon=True)
    t.start()

# -------------------------
# Behavior engine / scoring (SAFE)
# -------------------------

def estimate_signature_status(proc: psutil.Process):
    try:
        exe = proc.exe()
    except Exception:
        exe = ""
    exe_lower = exe.lower()

    if "\\windows\\" in exe_lower:
        return "trusted"
    if "\\program files" in exe_lower:
        return "likely trusted"
    if any(k in exe_lower for k in SUSPICIOUS_PATH_KEYWORDS):
        return "unknown"
    return "unknown"

def compute_reputation_score(proc: psutil.Process):
    score = 0
    reasons = []

    try:
        name = proc.name() or ""
        exe = proc.exe() or ""
        exe_lower = exe.lower()
    except Exception:
        name = ""
        exe = ""
        exe_lower = ""

    if is_rogue_name(name):
        score += 40
        reasons.append("Name matched blacklist")

    for kw in SUSPICIOUS_PATH_KEYWORDS:
        if kw in exe_lower:
            score += 20
            reasons.append(f"Suspicious path keyword: {kw}")
            break

    try:
        parent = proc.parent()
        if parent:
            pname = parent.name() or ""
            plower = pname.lower()
            for kw in SUSPICIOUS_PARENT_KEYWORDS:
                if kw in plower:
                    score += 15
                    reasons.append(f"Suspicious parent: {pname}")
                    break
    except Exception:
        pass

    try:
        cpu = proc.cpu_percent(interval=0.0)
        mem = proc.memory_info().rss
        if cpu > 20.0:
            score += 10
            reasons.append(f"High CPU usage: {cpu:.1f}%")
        if mem > 200 * 1024 * 1024:
            score += 5
            reasons.append(f"High memory usage: {mem // (1024 * 1024)}MB")
    except Exception:
        pass

    sig = estimate_signature_status(proc)
    if sig == "unknown":
        score += 10
        reasons.append("Unknown signature / non-system path")
    elif sig == "trusted":
        score -= 10
        reasons.append("Trusted system binary")

    if score < 0:
        score = 0
    if score > 100:
        score = 100

    return score, reasons

# -------------------------
# Threat meter state
# -------------------------

threat_lock = threading.Lock()
current_threat_level = 0  # 0-100

def update_threat_level_from_events():
    global current_threat_level
    with history_lock:
        recent = history_events[-50:]
    if not recent:
        with threat_lock:
            current_threat_level = 0
        return
    avg_score = sum(e["score"] for e in recent) / len(recent)
    with threat_lock:
        current_threat_level = int(avg_score)

def get_threat_level():
    with threat_lock:
        return current_threat_level

# -------------------------
# Monitor thread (SAFE)
# -------------------------

class RogueMonitorThread:
    def __init__(self, gui_ref):
        self.gui_ref = gui_ref
        self.running = True
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        log("Rogue monitor thread v13.0 started (SAFE, non-destructive)")
        while self.running:
            try:
                self.scan_once()
                update_threat_level_from_events()
            except Exception as e:
                log(f"Error in monitor loop: {e}")
            time.sleep(2.0)

    def scan_once(self):
        for proc in psutil.process_iter(["name", "pid", "exe"]):
            try:
                name = proc.info["name"]
                pid = proc.info["pid"]
                path = proc.info.get("exe", "") or ""
                if not name:
                    continue

                score, reasons = compute_reputation_score(proc)
                if score >= 50 or is_rogue_name(name):
                    reason_text = "; ".join(reasons) if reasons else "Suspicious behavior"
                    record_rogue_event(name, pid, path, reason_text, score)
                    if self.gui_ref:
                        self.gui_ref.enqueue_alert(name, pid, path, reason_text, score)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

# -------------------------
# GUI
# -------------------------

class RogueMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Rogue Process Monitor v13.0 (SAFE)")
        self.root.geometry("1100x750")

        self.alert_queue_lock = threading.Lock()
        self.alert_queue = []

        self._build_ui()
        self._start_refresh_threads()

        self.monitor_thread = RogueMonitorThread(self)

    # ---- UI build ----

    def _build_ui(self):
        main = ttk.Notebook(self.root)
        main.pack(fill=tk.BOTH, expand=True)

        self.tab_overview = ttk.Frame(main, padding=10)
        self.tab_blacklist = ttk.Frame(main, padding=10)
        self.tab_history = ttk.Frame(main, padding=10)
        self.tab_live = ttk.Frame(main, padding=10)
        self.tab_tree = ttk.Frame(main, padding=10)
        self.tab_snapshot = ttk.Frame(main, padding=10)
        self.tab_report = ttk.Frame(main, padding=10)

        main.add(self.tab_overview, text="Overview")
        main.add(self.tab_blacklist, text="Blacklist")
        main.add(self.tab_history, text="History / Timeline")
        main.add(self.tab_live, text="Live Processes")
        main.add(self.tab_tree, text="Process Tree")
        main.add(self.tab_snapshot, text="Snapshot")
        main.add(self.tab_report, text="Rogue Report")

        self._build_overview_tab()
        self._build_blacklist_tab()
        self._build_history_tab()
        self._build_live_tab()
        self._build_tree_tab()
        self._build_snapshot_tab()
        self._build_report_tab()

    def _build_overview_tab(self):
        frame = self.tab_overview

        title = ttk.Label(frame, text="Rogue Process Monitor v13.0 (SAFE, Non-Destructive)", font=("Segoe UI", 14, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Monitors processes, scores behavior, and highlights suspicious activity.\n"
                "It does NOT kill, block, or modify anything automatically. Diagnostic only."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.status_label = ttk.Label(frame, text="Status: starting...", foreground="#00aa00")
        self.status_label.grid(row=2, column=0, columnspan=3, sticky="w", pady=(5, 10))

        meter_label = ttk.Label(frame, text="Threat Meter (0-100):")
        meter_label.grid(row=3, column=0, sticky="w", pady=(5, 0))

        self.meter_canvas = tk.Canvas(frame, width=600, height=30, bg="#000000",
                                      highlightthickness=1, highlightbackground="#333333")
        self.meter_canvas.grid(row=4, column=0, columnspan=3, sticky="w", pady=(5, 10))

        alert_label = ttk.Label(frame, text="Recent Alerts:")
        alert_label.grid(row=5, column=0, sticky="w", pady=(5, 0))

        self.alert_box = tk.Text(frame, height=10, width=120, state="disabled", bg="#101010", fg="#ffcc00")
        self.alert_box.grid(row=6, column=0, columnspan=3, sticky="we", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=1)

    def _build_blacklist_tab(self):
        frame = self.tab_blacklist

        title = ttk.Label(frame, text="Rogue Process Blacklist", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Names containing any of these entries will be treated as rogue.\n"
                "The monitor will log and alert when they are detected, but will not kill them automatically."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.blacklist_listbox = tk.Listbox(frame, height=18, width=60, bg="#101010", fg="#00ffcc")
        self.blacklist_listbox.grid(row=2, column=0, columnspan=2, sticky="nswe", pady=(5, 10))

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.blacklist_listbox.yview)
        scrollbar.grid(row=2, column=2, sticky="ns")
        self.blacklist_listbox.config(yscrollcommand=scrollbar.set)

        self._refresh_blacklist_listbox()

        add_label = ttk.Label(frame, text="Add entry:")
        add_label.grid(row=3, column=0, sticky="w", pady=(5, 0))

        self.add_entry = ttk.Entry(frame, width=40)
        self.add_entry.grid(row=3, column=1, sticky="w", pady=(5, 0))

        add_btn = ttk.Button(frame, text="Add to blacklist", command=self._add_blacklist_entry)
        add_btn.grid(row=3, column=2, sticky="w", padx=(5, 0))

        remove_btn = ttk.Button(frame, text="Remove selected", command=self._remove_selected_blacklist_entry)
        remove_btn.grid(row=4, column=0, sticky="w", pady=(10, 0))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=1)
        frame.grid_columnconfigure(2, weight=0)

    def _build_history_tab(self):
        frame = self.tab_history

        title = ttk.Label(frame, text="Detection History / Timeline", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows all rogue process detections recorded by the monitor.\n"
                "Use this to understand when and how often certain processes appear."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.history_box = tk.Text(frame, height=25, width=120, state="disabled", bg="#101010", fg="#00ffcc")
        self.history_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_live_tab(self):
        frame = self.tab_live

        title = ttk.Label(frame, text="Live Process View", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows currently running processes, their reputation scores, and whether they match your blacklist.\n"
                "No actions are taken automatically; this is for visibility only."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        columns = ("pid", "name", "path", "score", "rogue")
        self.live_tree = ttk.Treeview(frame, columns=columns, show="headings", height=25)
        self.live_tree.heading("pid", text="PID")
        self.live_tree.heading("name", text="Name")
        self.live_tree.heading("path", text="Path")
        self.live_tree.heading("score", text="Score")
        self.live_tree.heading("rogue", text="Rogue?")

        self.live_tree.column("pid", width=80, anchor="w")
        self.live_tree.column("name", width=200, anchor="w")
        self.live_tree.column("path", width=500, anchor="w")
        self.live_tree.column("score", width=80, anchor="center")
        self.live_tree.column("rogue", width=80, anchor="center")

        self.live_tree.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.live_tree.yview)
        scrollbar.grid(row=2, column=1, sticky="ns")
        self.live_tree.config(yscrollcommand=scrollbar.set)

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_tree_tab(self):
        frame = self.tab_tree

        title = ttk.Label(frame, text="Parent/Child Process Tree", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows a simplified process tree, highlighting suspicious parents and children.\n"
                "Cycle-proof and safe."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.tree_box = tk.Text(frame, height=25, width=120, state="disabled", bg="#101010", fg="#00ffcc")
        self.tree_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

    def _build_snapshot_tab(self):
        frame = self.tab_snapshot

        title = ttk.Label(frame, text="Process Snapshot", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Select a PID and capture a snapshot of its CPU, memory, threads, and basic info.\n"
                "Diagnostic view only."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        pid_label = ttk.Label(frame, text="PID:")
        pid_label.grid(row=2, column=0, sticky="w", pady=(5, 0))

        self.snapshot_pid_entry = ttk.Entry(frame, width=15)
        self.snapshot_pid_entry.grid(row=2, column=1, sticky="w", pady=(5, 0))

        snap_btn = ttk.Button(frame, text="Capture Snapshot", command=self._capture_snapshot)
        snap_btn.grid(row=2, column=2, sticky="w", padx=(5, 0))

        self.snapshot_box = tk.Text(frame, height=25, width=120, state="disabled", bg="#101010", fg="#00ffcc")
        self.snapshot_box.grid(row=3, column=0, columnspan=3, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_columnconfigure(1, weight=0)
        frame.grid_columnconfigure(2, weight=0)
        frame.grid_rowconfigure(3, weight=1)

    def _build_report_tab(self):
        frame = self.tab_report

        title = ttk.Label(frame, text="Rogue Process Report", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Generate a summary of recent rogue detections, including top offenders and average scores.\n"
                "Helps understand long-term patterns."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        report_btn = ttk.Button(frame, text="Generate Report", command=self._generate_report)
        report_btn.grid(row=2, column=0, sticky="w", pady=(5, 10))

        self.report_box = tk.Text(frame, height=25, width=120, state="disabled", bg="#101010", fg="#00ffcc")
        self.report_box.grid(row=3, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(3, weight=1)

    # ---- Blacklist tab actions ----

    def _refresh_blacklist_listbox(self):
        self.blacklist_listbox.delete(0, tk.END)
        for entry in get_blacklist():
            self.blacklist_listbox.insert(tk.END, entry)

    def _add_blacklist_entry(self):
        text = self.add_entry.get().strip()
        if not text:
            return
        add_to_blacklist(text)
        self.add_entry.delete(0, tk.END)
        self._refresh_blacklist_listbox()
        self._update_status(f"Added '{text}' to blacklist")

    def _remove_selected_blacklist_entry(self):
        selection = self.blacklist_listbox.curselection()
        if not selection:
            return
        index = selection[0]
        entry = self.blacklist_listbox.get(index)
        remove_from_blacklist(entry)
        self._refresh_blacklist_listbox()
        self._update_status(f"Removed '{entry}' from blacklist")

    # ---- Alert queue ----

    def enqueue_alert(self, name, pid, path, reason, score):
        with self.alert_queue_lock:
            self.alert_queue.append((name, pid, path, reason, score))

    def _process_alert_queue(self):
        alerts = []
        with self.alert_queue_lock:
            if self.alert_queue:
                alerts = list(self.alert_queue)
                self.alert_queue.clear()

        if not alerts:
            return

        for (name, pid, path, reason, score) in alerts:
            self._append_alert_text(name, pid, path, reason, score)
            notify_user_popup(name, pid, path, reason, score)

    def _append_alert_text(self, name, pid, path, reason, score):
        line = f"[ALERT] {name} (PID={pid}) path={path} reason={reason} score={score}\n"
        self.alert_box.config(state="normal")
        self.alert_box.insert(tk.END, line)
        self.alert_box.see(tk.END)
        self.alert_box.config(state="disabled")

    # ---- History refresh ----

    def _refresh_history_box(self):
        with history_lock:
            events = list(history_events)

        lines = []
        for e in events:
            lines.append(
                f"[{e['ts']}] {e['name']} (PID={e['pid']}) path={e['path']} reason={e['reason']} score={e['score']}"
            )
        text = "\n".join(lines)

        self.history_box.config(state="normal")
        self.history_box.delete("1.0", tk.END)
        self.history_box.insert(tk.END, text)
        self.history_box.config(state="disabled")

    # ---- Live process view ----

    def _refresh_live_processes(self):
        self.live_tree.delete(*self.live_tree.get_children())

        for proc in psutil.process_iter(["name", "pid", "exe"]):
            try:
                name = proc.info["name"]
                pid = proc.info["pid"]
                path = proc.info.get("exe", "") or ""
                if not name:
                    continue

                score, _ = compute_reputation_score(proc)
                rogue = "YES" if (score >= 50 or is_rogue_name(name)) else "NO"
                values = (pid, name, path, score, rogue)
                item_id = self.live_tree.insert("", tk.END, values=values)
                if rogue == "YES":
                    self.live_tree.item(item_id, tags=("rogue",))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self.live_tree.tag_configure("rogue", background="#330000", foreground="#ff6666")

    # ---- Process tree (cycle-proof) ----

    def _refresh_process_tree(self):
        self.tree_box.config(state="normal")
        self.tree_box.delete("1.0", tk.END)

        procs = {}
        children_map = {}

        for proc in psutil.process_iter(["pid", "name", "ppid"]):
            try:
                pid = proc.info["pid"]
                name = proc.info["name"] or ""
                ppid = proc.info["ppid"]
                procs[pid] = (name, ppid)
                children_map.setdefault(ppid, []).append(pid)
            except Exception:
                continue

        visited = set()

        def render_node(pid, indent=""):
            if pid in visited:
                self.tree_box.insert(tk.END, f"{indent}{pid} (cycle detected)\n")
                return
            visited.add(pid)

            if pid not in procs:
                return

            name, ppid = procs[pid]
            try:
                score, _ = compute_reputation_score(psutil.Process(pid))
            except Exception:
                score = 0

            rogue_flag = " [ROGUE]" if (score >= 50 or is_rogue_name(name)) else ""
            self.tree_box.insert(tk.END, f"{indent}{name} (PID={pid}, score={score}){rogue_flag}\n")

            for child_pid in children_map.get(pid, []):
                render_node(child_pid, indent + "    ")

        roots = [pid for pid, (name, ppid) in procs.items() if ppid == 0]

        for root_pid in roots:
            render_node(root_pid)

        self.tree_box.config(state="disabled")

    # ---- Snapshot ----

    def _capture_snapshot(self):
        text_pid = self.snapshot_pid_entry.get().strip()
        if not text_pid.isdigit():
            messagebox.showerror("Invalid PID", "Please enter a numeric PID.")
            return
        pid = int(text_pid)
        try:
            proc = psutil.Process(pid)
        except psutil.NoSuchProcess:
            messagebox.showerror("Process not found", f"No process with PID {pid}.")
            return
        except psutil.AccessDenied:
            messagebox.showerror("Access denied", f"Access denied to PID {pid}.")
            return

        try:
            name = proc.name() or ""
            exe = proc.exe() or ""
            cpu = proc.cpu_percent(interval=0.1)
            mem = proc.memory_info().rss
            threads = proc.num_threads()
            handles = getattr(proc, "num_handles", lambda: 0)()
            score, reasons = compute_reputation_score(proc)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to capture snapshot: {e}")
            return

        lines = [
            f"Snapshot for PID {pid}",
            f"Name: {name}",
            f"Path: {exe}",
            f"CPU: {cpu:.1f}%",
            f"Memory: {mem // (1024 * 1024)} MB",
            f"Threads: {threads}",
            f"Handles: {handles}",
            f"Reputation score: {score}",
            f"Reasons: {', '.join(reasons) if reasons else 'None'}",
        ]

        self.snapshot_box.config(state="normal")
        self.snapshot_box.delete("1.0", tk.END)
        self.snapshot_box.insert(tk.END, "\n".join(lines))
        self.snapshot_box.config(state="disabled")

    # ---- Report ----

    def _generate_report(self):
        with history_lock:
            events = list(history_events)

        if not events:
            text = "No rogue events recorded yet."
        else:
            total = len(events)
            avg_score = sum(e["score"] for e in events) / total
            freq = {}
            for e in events:
                freq[e["name"]] = freq.get(e["name"], 0) + 1
            top = sorted(freq.items(), key=lambda x: x[1], reverse=True)[:10]

            lines = [
                f"Rogue Process Report",
                f"Total events: {total}",
                f"Average score: {avg_score:.1f}",
                "",
                "Top offenders:",
            ]
            for name, count in top:
                lines.append(f"  {name}: {count} detections")

            lines.append("")
            lines.append("Recent events:")
            for e in events[-20:]:
                lines.append(
                    f"[{e['ts']}] {e['name']} (PID={e['pid']}) score={e['score']} reason={e['reason']}"
                )

            text = "\n".join(lines)

        self.report_box.config(state="normal")
        self.report_box.delete("1.0", tk.END)
        self.report_box.insert(tk.END, text)
        self.report_box.config(state="disabled")

    # ---- Threat meter ----

    def _refresh_threat_meter(self):
        level = get_threat_level()
        self.meter_canvas.delete("all")
        w = self.meter_canvas.winfo_width()
        h = self.meter_canvas.winfo_height()
        bar_width = int((level / 100) * w)

        if level < 30:
            color = "#00ff00"
        elif level < 60:
            color = "#ffff00"
        else:
            color = "#ff0000"

        self.meter_canvas.create_rectangle(0, 0, bar_width, h, fill=color, outline="")
        self.meter_canvas.create_text(
            w // 2,
            h // 2,
            text=f"Threat Level: {level}",
            fill="#ffffff",
            font=("Consolas", 11),
        )

    # ---- Status ----

    def _update_status(self, text):
        self.status_label.config(text=f"Status: {text}", foreground="#00aa00")

    # ---- Background refresh threads (Performance Mode) ----

    def _start_refresh_threads(self):
        threading.Thread(target=self._status_loop, daemon=True).start()
        threading.Thread(target=self._history_loop, daemon=True).start()
        threading.Thread(target=self._live_loop, daemon=True).start()
        threading.Thread(target=self._alert_loop, daemon=True).start()
        threading.Thread(target=self._tree_loop, daemon=True).start()
        threading.Thread(target=self._meter_loop, daemon=True).start()

    def _status_loop(self):
        while True:
            try:
                count = len(get_blacklist())
                self.root.after(0, lambda: self._update_status(f"monitoring | blacklist entries={count}"))
            except Exception:
                pass
            time.sleep(5.0)

    def _history_loop(self):
        while True:
            try:
                self.root.after(0, self._refresh_history_box)
            except Exception:
                pass
            time.sleep(15.0)

    def _live_loop(self):
        while True:
            try:
                self.root.after(0, self._refresh_live_processes)
            except Exception:
                pass
            time.sleep(10.0)

    def _alert_loop(self):
        while True:
            try:
                self.root.after(0, self._process_alert_queue)
            except Exception:
                pass
            time.sleep(1.0)

    def _tree_loop(self):
        while True:
            try:
                self.root.after(0, self._refresh_process_tree)
            except Exception:
                pass
            time.sleep(30.0)

    def _meter_loop(self):
        while True:
            try:
                self.root.after(0, self._refresh_threat_meter)
            except Exception:
                pass
            time.sleep(2.0)

# -------------------------
# Main
# -------------------------

def main():
    log("Rogue Process Monitor v13.0 (SAFE) starting")
    root = tk.Tk()
    gui = RogueMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
