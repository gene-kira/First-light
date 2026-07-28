import time
import datetime
import psutil
import threading
import tkinter as tk
from tkinter import ttk, messagebox

# ============================================================
# v12.8 Rogue Process Monitor – FULL GUI FILE (SAFE, NON-DESTRUCTIVE)
# ============================================================

LOG_FILE = "rogue_monitor_log.txt"

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
# Rogue blacklist (initial)
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

blacklist_lock = threading.Lock()
blacklist = DEFAULT_BLACKLIST.copy()

def get_blacklist():
    with blacklist_lock:
        return list(blacklist)

def set_blacklist(new_list):
    with blacklist_lock:
        blacklist.clear()
        blacklist.extend(new_list)
    log(f"Blacklist updated: {blacklist}")

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

def is_rogue_process(name: str) -> bool:
    if not name:
        return False
    lname = name.lower()
    with blacklist_lock:
        for entry in blacklist:
            if entry.lower() in lname:
                return True
    return False

# -------------------------
# Rogue detection + history
# -------------------------

history_lock = threading.Lock()
history_events = []  # list of dicts: {ts, name, pid, path, reason}

def record_rogue_event(name, pid, path, reason):
    ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    event = {
        "ts": ts,
        "name": name,
        "pid": pid,
        "path": path,
        "reason": reason,
    }
    with history_lock:
        history_events.append(event)
        if len(history_events) > 500:
            history_events.pop(0)
    log(f"DETECTED ROGUE: {name} (PID={pid}) path={path} reason={reason}")

# -------------------------
# Notification (GUI-safe)
# -------------------------

def notify_user_popup(name, pid, path, reason):
    def _show():
        root = tk.Tk()
        root.withdraw()
        messagebox.showwarning(
            "Rogue Process Detected",
            f"Process: {name}\nPID: {pid}\nPath: {path}\nReason: {reason}\n\n"
            "This process matches your rogue blacklist.\n"
            "No destructive action was taken automatically."
        )
        root.destroy()
    t = threading.Thread(target=_show, daemon=True)
    t.start()

# -------------------------
# Monitor thread (SAFE – NO KILL)
# -------------------------

class RogueMonitorThread:
    def __init__(self, gui_ref):
        self.gui_ref = gui_ref
        self.running = True
        self.thread = threading.Thread(target=self.loop, daemon=True)
        self.thread.start()

    def loop(self):
        log("Rogue monitor thread started (SAFE, non-destructive)")
        while self.running:
            try:
                self.scan_once()
            except Exception as e:
                log(f"Error in monitor loop: {e}")
            time.sleep(2.0)

    def scan_once(self):
        current_blacklist = get_blacklist()
        for proc in psutil.process_iter(["name", "pid", "exe"]):
            try:
                name = proc.info["name"]
                pid = proc.info["pid"]
                path = proc.info.get("exe", "") or ""
                if not name:
                    continue

                if is_rogue_process(name):
                    reason = "Name matched blacklist entry"
                    record_rogue_event(name, pid, path, reason)
                    if self.gui_ref:
                        self.gui_ref.enqueue_alert(name, pid, path, reason)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

# -------------------------
# GUI
# -------------------------

class RogueMonitorGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Rogue Process Monitor v12.8 (SAFE)")
        self.root.geometry("900x700")

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

        main.add(self.tab_overview, text="Overview")
        main.add(self.tab_blacklist, text="Blacklist")
        main.add(self.tab_history, text="History")
        main.add(self.tab_live, text="Live Processes")

        self._build_overview_tab()
        self._build_blacklist_tab()
        self._build_history_tab()
        self._build_live_tab()

    def _build_overview_tab(self):
        frame = self.tab_overview

        title = ttk.Label(frame, text="Rogue Process Monitor v12.8 (SAFE, Non-Destructive)", font=("Segoe UI", 14, "bold"))
        title.grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "This tool watches for processes that match your rogue blacklist.\n"
                "It logs detections and shows alerts, but does NOT kill or block anything automatically.\n"
                "Use this to understand what is running and decide manually what to remove or block."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.status_label = ttk.Label(frame, text="Status: starting...", foreground="#00aa00")
        self.status_label.grid(row=2, column=0, columnspan=3, sticky="w", pady=(5, 10))

        alert_label = ttk.Label(frame, text="Recent Alerts:")
        alert_label.grid(row=3, column=0, sticky="w", pady=(5, 0))

        self.alert_box = tk.Text(frame, height=10, width=100, state="disabled", bg="#101010", fg="#ffcc00")
        self.alert_box.grid(row=4, column=0, columnspan=3, sticky="we", pady=(5, 10))

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
                "Processes whose names contain any of these entries will be treated as rogue.\n"
                "This monitor will log and alert when they are detected, but will not kill them automatically."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, columnspan=3, sticky="w", pady=(0, 10))

        self.blacklist_listbox = tk.Listbox(frame, height=15, width=60, bg="#101010", fg="#00ffcc")
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

        title = ttk.Label(frame, text="Detection History", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "This shows all rogue process detections recorded by the monitor.\n"
                "Use this to understand when and how often certain processes appear."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        self.history_box = tk.Text(frame, height=25, width=100, state="disabled", bg="#101010", fg="#00ffcc")
        self.history_box.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        frame.grid_columnconfigure(0, weight=1)

    def _build_live_tab(self):
        frame = self.tab_live

        title = ttk.Label(frame, text="Live Process View", font=("Segoe UI", 12, "bold"))
        title.grid(row=0, column=0, sticky="w", pady=(0, 10))

        desc = ttk.Label(
            frame,
            text=(
                "This shows currently running processes and highlights those that match your blacklist.\n"
                "No actions are taken automatically; this is for visibility only."
            ),
            justify="left"
        )
        desc.grid(row=1, column=0, sticky="w", pady=(0, 10))

        columns = ("pid", "name", "path", "rogue")
        self.live_tree = ttk.Treeview(frame, columns=columns, show="headings", height=25)
        self.live_tree.heading("pid", text="PID")
        self.live_tree.heading("name", text="Name")
        self.live_tree.heading("path", text="Path")
        self.live_tree.heading("rogue", text="Rogue?")

        self.live_tree.column("pid", width=80, anchor="w")
        self.live_tree.column("name", width=200, anchor="w")
        self.live_tree.column("path", width=400, anchor="w")
        self.live_tree.column("rogue", width=80, anchor="center")

        self.live_tree.grid(row=2, column=0, sticky="nswe", pady=(5, 10))

        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=self.live_tree.yview)
        scrollbar.grid(row=2, column=1, sticky="ns")
        self.live_tree.config(yscrollcommand=scrollbar.set)

        frame.grid_columnconfigure(0, weight=1)
        frame.grid_rowconfigure(2, weight=1)

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

    def enqueue_alert(self, name, pid, path, reason):
        with self.alert_queue_lock:
            self.alert_queue.append((name, pid, path, reason))

    def _process_alert_queue(self):
        alerts = []
        with self.alert_queue_lock:
            if self.alert_queue:
                alerts = list(self.alert_queue)
                self.alert_queue.clear()

        if not alerts:
            return

        for (name, pid, path, reason) in alerts:
            self._append_alert_text(name, pid, path, reason)
            notify_user_popup(name, pid, path, reason)

    def _append_alert_text(self, name, pid, path, reason):
        line = f"[ALERT] {name} (PID={pid}) path={path} reason={reason}\n"
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
                f"[{e['ts']}] {e['name']} (PID={e['pid']}) path={e['path']} reason={e['reason']}"
            )
        text = "\n".join(lines)

        self.history_box.config(state="normal")
        self.history_box.delete("1.0", tk.END)
        self.history_box.insert(tk.END, text)
        self.history_box.config(state="disabled")

    # ---- Live process view ----

    def _refresh_live_processes(self):
        self.live_tree.delete(*self.live_tree.get_children())
        current_blacklist = get_blacklist()

        for proc in psutil.process_iter(["name", "pid", "exe"]):
            try:
                name = proc.info["name"]
                pid = proc.info["pid"]
                path = proc.info.get("exe", "") or ""
                if not name:
                    continue

                rogue = "YES" if is_rogue_process(name) else "NO"
                values = (pid, name, path, rogue)
                item_id = self.live_tree.insert("", tk.END, values=values)
                if rogue == "YES":
                    self.live_tree.item(item_id, tags=("rogue",))
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

        self.live_tree.tag_configure("rogue", background="#330000", foreground="#ff6666")

    # ---- Status ----

    def _update_status(self, text):
        self.status_label.config(text=f"Status: {text}", foreground="#00aa00")

    # ---- Background refresh threads ----

    def _start_refresh_threads(self):
        t1 = threading.Thread(target=self._status_loop, daemon=True)
        t1.start()

        t2 = threading.Thread(target=self._history_loop, daemon=True)
        t2.start()

        t3 = threading.Thread(target=self._live_loop, daemon=True)
        t3.start()

        t4 = threading.Thread(target=self._alert_loop, daemon=True)
        t4.start()

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
            time.sleep(5.0)

    def _live_loop(self):
        while True:
            try:
                self.root.after(0, self._refresh_live_processes)
            except Exception:
                pass
            time.sleep(5.0)

    def _alert_loop(self):
        while True:
            try:
                self.root.after(0, self._process_alert_queue)
            except Exception:
                pass
            time.sleep(1.0)

# -------------------------
# Main
# -------------------------

def main():
    log("Rogue Process Monitor v12.8 (SAFE) starting")
    root = tk.Tk()
    gui = RogueMonitorGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
