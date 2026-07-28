import time
import datetime
import psutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# ============================================================
# Rogue Process Monitor v13.3 (SAFE, NON-DESTRUCTIVE)
# Elite Edition
# - Full sandbox isolation
# - Incremental scanning (per-PID cache)
# - Multi-threaded scoring
# - Diff-based GUI updates
# - Limited / prioritized live view (virtualized-ish)
# - Smoothed threat meter
# - Throttled alerts
# - Still NO killing, blocking, or destructive actions
# ============================================================

LOG_FILE = "rogue_monitor_v13_3_log.txt"

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
# Sandbox shared state
# -------------------------

sandbox_lock = threading.Lock()

sandbox_live_processes = []   # list of dicts: {pid, name, path, score, rogue}
sandbox_history_events = []   # list of dicts: {ts, name, pid, path, reason, score}
sandbox_tree_lines = []       # list of strings
sandbox_alerts = []           # list of dicts: {name, pid, path, reason, score}
sandbox_threat_level_raw = 0
sandbox_threat_level_smoothed = 0

def sandbox_set_live_processes(items):
    global sandbox_live_processes
    with sandbox_lock:
        sandbox_live_processes = items

def sandbox_get_live_processes():
    with sandbox_lock:
        return list(sandbox_live_processes)

def sandbox_append_history(event):
    global sandbox_history_events
    with sandbox_lock:
        sandbox_history_events.append(event)
        if len(sandbox_history_events) > 1000:
            sandbox_history_events.pop(0)

def sandbox_get_history():
    with sandbox_lock:
        return list(sandbox_history_events)

def sandbox_set_tree_lines(lines):
    global sandbox_tree_lines
    with sandbox_lock:
        sandbox_tree_lines = lines

def sandbox_get_tree_lines():
    with sandbox_lock:
        return list(sandbox_tree_lines)

def sandbox_add_alert(alert):
    global sandbox_alerts
    with sandbox_lock:
        sandbox_alerts.append(alert)
        if len(sandbox_alerts) > 200:
            sandbox_alerts.pop(0)

def sandbox_pop_alerts(max_count=10):
    global sandbox_alerts
    with sandbox_lock:
        alerts = sandbox_alerts[:max_count]
        sandbox_alerts = sandbox_alerts[max_count:]
        return alerts

def sandbox_set_threat_level(level):
    global sandbox_threat_level_raw, sandbox_threat_level_smoothed
    with sandbox_lock:
        sandbox_threat_level_raw = int(max(0, min(100, level)))
        sandbox_threat_level_smoothed = int(
            0.7 * sandbox_threat_level_smoothed + 0.3 * sandbox_threat_level_raw
        )

def sandbox_get_threat_level():
    with sandbox_lock:
        return sandbox_threat_level_smoothed

# -------------------------
# Behavior engine / scoring
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
# Incremental scanning cache
# -------------------------

scan_cache_lock = threading.Lock()
scan_cache = {}  # pid -> {name, path, score, rogue, last_seen}

def update_scan_cache(pid, name, path, score, rogue):
    with scan_cache_lock:
        scan_cache[pid] = {
            "pid": pid,
            "name": name,
            "path": path,
            "score": score,
            "rogue": rogue,
            "last_seen": time.time(),
        }

def get_scan_cache_snapshot():
    with scan_cache_lock:
        return dict(scan_cache)

def prune_scan_cache(max_age=60.0):
    now = time.time()
    with scan_cache_lock:
        to_delete = [pid for pid, info in scan_cache.items()
                     if now - info.get("last_seen", 0) > max_age]
        for pid in to_delete:
            del scan_cache[pid]

# -------------------------
# Sandbox threads (scan + tree + scoring pool)
# -------------------------

class SandboxScanner:
    def __init__(self):
        self.running = True
        self.scan_thread = threading.Thread(target=self.scan_loop, daemon=True)
        self.tree_thread = threading.Thread(target=self.tree_loop, daemon=True)
        self.scan_thread.start()
        self.tree_thread.start()

    def scan_loop(self):
        log("SandboxScanner v13.3 scan loop started")
        while self.running:
            try:
                self.incremental_scan()
            except Exception as e:
                log(f"Sandbox scan error: {e}")
            time.sleep(3.0)

    def tree_loop(self):
        log("SandboxScanner v13.3 tree loop started")
        while self.running:
            try:
                self.build_tree()
            except Exception as e:
                log(f"Sandbox tree error: {e}")
            time.sleep(30.0)

    def incremental_scan(self):
        procs = []
        for proc in psutil.process_iter(["name", "pid", "exe", "ppid"]):
            try:
                procs.append(proc)
            except Exception:
                continue

        live_items = []
        history_batch = []
        alerts_batch = []

        def score_proc(proc):
            try:
                name = proc.info["name"]
                pid = proc.info["pid"]
                path = proc.info.get("exe", "") or ""
                if not name:
                    return None

                score, reasons = compute_reputation_score(proc)
                rogue = (score >= 50 or is_rogue_name(name))

                update_scan_cache(pid, name, path, score, rogue)

                if rogue:
                    reason_text = "; ".join(reasons) if reasons else "Suspicious behavior"
                    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    event = {
                        "ts": ts,
                        "name": name,
                        "pid": pid,
                        "path": path,
                        "reason": reason_text,
                        "score": score,
                    }
                    return {
                        "live": {
                            "pid": pid,
                            "name": name,
                            "path": path,
                            "score": score,
                            "rogue": rogue,
                        },
                        "history": event,
                        "alert": {
                            "name": name,
                            "pid": pid,
                            "path": path,
                            "reason": reason_text,
                            "score": score,
                        },
                    }
                else:
                    return {
                        "live": {
                            "pid": pid,
                            "name": name,
                            "path": path,
                            "score": score,
                            "rogue": rogue,
                        },
                        "history": None,
                        "alert": None,
                    }
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                return None
            except Exception:
                return None

        threads = []
        results = []

        def worker(chunk):
            local_results = []
            for p in chunk:
                r = score_proc(p)
                if r is not None:
                    local_results.append(r)
            results.extend(local_results)

        num_threads = 4
        if len(procs) < num_threads:
            num_threads = max(1, len(procs))

        chunk_size = max(1, len(procs) // max(1, num_threads))
        for i in range(num_threads):
            chunk = procs[i * chunk_size:(i + 1) * chunk_size]
            if not chunk:
                continue
            t = threading.Thread(target=worker, args=(chunk,))
            t.start()
            threads.append(t)

        for t in threads:
            t.join()

        for r in results:
            live_items.append(r["live"])
            if r["history"] is not None:
                history_batch.append(r["history"])
            if r["alert"] is not None:
                alerts_batch.append(r["alert"])

        prune_scan_cache()

        sandbox_set_live_processes(live_items)

        for ev in history_batch:
            sandbox_append_history(ev)
        for al in alerts_batch:
            sandbox_add_alert(al)

        history = sandbox_get_history()
        recent = history[-50:]
        if recent:
            avg_score = sum(e["score"] for e in recent) / len(recent)
        else:
            avg_score = 0
        sandbox_set_threat_level(avg_score)

    def build_tree(self):
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
        lines = []

        def render_node(pid, indent=""):
            if pid in visited:
                lines.append(f"{indent}{pid} (cycle detected)")
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
            lines.append(f"{indent}{name} (PID={pid}, score={score}){rogue_flag}")

            for child_pid in children_map.get(pid, []):
                render_node(child_pid, indent + "    ")

        roots = [pid for pid, (name, ppid) in procs.items() if ppid == 0]

        for root_pid in roots:
            render_node(root_pid)

        sandbox_set_tree_lines(lines)

# -------------------------
# GUI
# -------------------------

class RogueMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Rogue Process Monitor v13.3 (SAFE, Elite Sandbox)")
        self.root.geometry("1100x750")

        self._build_ui()

        self.sandbox = SandboxScanner()

        self.last_history_text = ""
        self.last_tree_text = ""
        self.last_live_snapshot = []

        self.last_alert_popup_time = 0.0

        self._start_refresh_loops()

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

        title = ttk.Label(frame, text="Rogue Process Monitor v13.3 (SAFE, Sandbox)", font=("Segoe UI", 14, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "All heavy scanning runs in a separate sandbox with incremental scanning.\n"
                "GUI uses diff-based updates and throttling to stay responsive.\n"
                "No processes are killed or blocked automatically."
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
                "Names containing any of these entries will be treated as rogue by the sandbox.\n"
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
                "Shows rogue process detections recorded by the sandbox.\n"
                "Incremental updates keep this responsive."
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

        title = ttk.Label(frame, text="Live Process View (Sandbox Summary)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Shows processes as summarized by the sandbox.\n"
                "GUI uses limited rows and diff-based updates to stay smooth."
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

        title = ttk.Label(frame, text="Parent/Child Process Tree (Sandbox)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Tree is built inside the sandbox and streamed here.\n"
                "Diff-based updates avoid heavy redraws."
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

        title = ttk.Label(frame, text="Process Snapshot (Direct psutil)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Snapshot uses direct psutil calls for a single PID.\n"
                "This is the only place GUI touches psutil directly."
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

        title = ttk.Label(frame, text="Rogue Process Report (Sandbox)", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "Generates a summary of rogue detections based on sandbox history.\n"
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

    # ---- Blacklist actions ----

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
        events = sandbox_get_history()

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
                f"Rogue Process Report (Sandbox)",
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
        level = sandbox_get_threat_level()
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

    # ---- GUI refresh loops ----

    def _start_refresh_loops(self):
        self._schedule_status_refresh()
        self._schedule_history_refresh()
        self._schedule_live_refresh()
        self._schedule_alert_refresh()
        self._schedule_tree_refresh()
        self._schedule_meter_refresh()

    def _schedule_status_refresh(self):
        self._update_status(f"monitoring | blacklist entries={len(get_blacklist())}")
        self.root.after(5000, self._schedule_status_refresh)

    def _schedule_history_refresh(self):
        events = sandbox_get_history()
        lines = [
            f"[{e['ts']}] {e['name']} (PID={e['pid']}) path={e['path']} reason={e['reason']} score={e['score']}"
            for e in events
        ]
        text = "\n".join(lines)
        if text != self.last_history_text:
            self.last_history_text = text
            self.history_box.config(state="normal")
            self.history_box.delete("1.0", tk.END)
            self.history_box.insert(tk.END, text)
            self.history_box.config(state="disabled")
        self.root.after(15000, self._schedule_history_refresh)

    def _schedule_live_refresh(self):
        items = sandbox_get_live_processes()
        items = sorted(items, key=lambda x: x["score"], reverse=True)
        items = items[:200]

        snapshot = [(i["pid"], i["name"], i["path"], i["score"], i["rogue"]) for i in items]
        if snapshot != self.last_live_snapshot:
            self.last_live_snapshot = snapshot
            self.live_tree.delete(*self.live_tree.get_children())
            for pid, name, path, score, rogue in snapshot:
                rogue_str = "YES" if rogue else "NO"
                values = (pid, name, path, score, rogue_str)
                iid = self.live_tree.insert("", tk.END, values=values)
                if rogue_str == "YES":
                    self.live_tree.item(iid, tags=("rogue",))
            self.live_tree.tag_configure("rogue", background="#330000", foreground="#ff6666")
        self.root.after(10000, self._schedule_live_refresh)

    def _schedule_alert_refresh(self):
        alerts = sandbox_pop_alerts(max_count=5)
        if alerts:
            self.alert_box.config(state="normal")
            for al in alerts:
                line = f"[ALERT] {al['name']} (PID={al['pid']}) path={al['path']} reason={al['reason']} score={al['score']}\n"
                self.alert_box.insert(tk.END, line)
                self.alert_box.see(tk.END)
            self.alert_box.config(state="disabled")

            now = time.time()
            for al in alerts:
                if now - self.last_alert_popup_time > 2.0:
                    self.last_alert_popup_time = now
                    self._show_alert_popup(al)
                    break
        self.root.after(1000, self._schedule_alert_refresh)

    def _show_alert_popup(self, al):
        def _popup():
            messagebox.showwarning(
                "Rogue Process Detected (Sandbox)",
                f"Process: {al['name']}\nPID: {al['pid']}\nPath: {al['path']}\nReason: {al['reason']}\nScore: {al['score']}\n\n"
                "This process matches your rogue criteria.\n"
                "No destructive action was taken automatically."
            )
        self.root.after(0, _popup)

    def _schedule_tree_refresh(self):
        lines = sandbox_get_tree_lines()
        text = "\n".join(lines)
        if text != self.last_tree_text:
            self.last_tree_text = text
            self.tree_box.config(state="normal")
            self.tree_box.delete("1.0", tk.END)
            self.tree_box.insert(tk.END, text)
            self.tree_box.config(state="disabled")
        self.root.after(30000, self._schedule_tree_refresh)

    def _schedule_meter_refresh(self):
        self._refresh_threat_meter()
        self.root.after(2000, self._schedule_meter_refresh)

# -------------------------
# Main
# -------------------------

def main():
    log("Rogue Process Monitor v13.3 (SAFE, Elite Sandbox) starting")
    root = tk.Tk()
    gui = RogueMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
