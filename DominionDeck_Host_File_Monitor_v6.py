#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""DominionDeck Host File Monitor v6 - resilient Windows hosts-file monitor.

Uses only Python's standard library for the GUI and monitoring. watchdog and
psutil are optional; polling continues if either is missing. Run as Administrator
only if you want to import/restore the protected Windows hosts file.
"""
import os
import sys
import time
import csv
import shutil
import threading
import datetime as dt
import subprocess
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

HOST_FILE = os.path.join(os.environ.get("WINDIR", r"C:\Windows"), "System32", "drivers", "etc", "hosts")
LOG_FILE = os.path.join(os.path.expanduser("~"), "DominionDeck_hosts_trend.csv")
POLL_SECONDS = 1.0
MAX_EVENTS = 5

# Optional modules: failure to install or import them never prevents startup.
try:
    import psutil
except Exception:
    psutil = None
try:
    from watchdog.observers import Observer
    from watchdog.events import FileSystemEventHandler
except Exception:
    Observer = None
    FileSystemEventHandler = object


def file_state(path):
    try:
        st = os.stat(path)
        return {"exists": True, "size": st.st_size,
                "mtime": dt.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds")}
    except OSError:
        return {"exists": False, "size": 0, "mtime": None}


def find_open_processes(path):
    """Best-effort list of processes with the file open; not proof of writing."""
    if psutil is None:
        return []
    target = os.path.normcase(os.path.abspath(path))
    found = []
    try:
        for proc in psutil.process_iter(["pid", "name", "exe"]):
            try:
                for opened in proc.open_files():
                    if os.path.normcase(os.path.abspath(opened.path)) == target:
                        found.append({"pid": proc.info.get("pid"), "name": proc.info.get("name") or "?",
                                      "exe": proc.info.get("exe") or "?"})
                        break
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess, OSError):
                continue
            except Exception:
                continue
    except Exception:
        pass
    return found


def ensure_log():
    try:
        if not os.path.exists(LOG_FILE):
            with open(LOG_FILE, "w", newline="", encoding="utf-8") as f:
                csv.writer(f).writerow(["timestamp", "event", "size", "delta", "exists", "mtime"])
    except OSError:
        pass


def log_event(event):
    ensure_log()
    try:
        with open(LOG_FILE, "a", newline="", encoding="utf-8") as f:
            csv.writer(f).writerow([event["timestamp"], event["event"], event["size"],
                                    event["delta"], event["exists"], event["mtime"] or ""])
    except OSError:
        pass


def read_recent_log(days=30):
    cutoff = dt.datetime.now() - dt.timedelta(days=days)
    out = []
    try:
        with open(LOG_FILE, newline="", encoding="utf-8") as f:
            for row in csv.DictReader(f):
                try:
                    stamp = dt.datetime.fromisoformat(row["timestamp"])
                    if stamp >= cutoff:
                        out.append({"timestamp": stamp, "event": row.get("event", "CHANGE"),
                                    "size": int(row.get("size", 0)), "delta": int(row.get("delta", 0)),
                                    "exists": row.get("exists", "True") == "True", "mtime": row.get("mtime") or None})
                except (ValueError, KeyError, TypeError):
                    continue
    except (OSError, UnicodeError):
        pass
    return out


def human_size(value):
    if value < 1024: return f"{value} B"
    if value < 1024 * 1024: return f"{value / 1024:.1f} KB"
    return f"{value / (1024 * 1024):.2f} MB"


class HostMonitor:
    def __init__(self, gui):
        self.gui = gui
        self.stop_event = threading.Event()
        self.last = file_state(HOST_FILE)
        self.observer = None
        self.watchdog_active = False
        if Observer is not None:
            try:
                handler_cls = type("Handler", (FileSystemEventHandler,), {
                    "on_any_event": self._watchdog_event
                })
                self.observer = Observer()
                self.observer.schedule(handler_cls(), os.path.dirname(HOST_FILE), recursive=False)
                self.observer.start()
                self.watchdog_active = True
            except Exception:
                self.observer = None
        self.thread = threading.Thread(target=self._poll, name="HostsFileMonitor", daemon=True)
        self.thread.start()

    def _watchdog_event(self, event):
        if getattr(event, "is_directory", False): return
        src = os.path.normcase(os.path.abspath(getattr(event, "src_path", "")))
        dst = os.path.normcase(os.path.abspath(getattr(event, "dest_path", ""))) if getattr(event, "dest_path", None) else ""
        target = os.path.normcase(os.path.abspath(HOST_FILE))
        if src == target or dst == target:
            self._check("FILE SYSTEM EVENT")

    def _poll(self):
        while not self.stop_event.wait(POLL_SECONDS):
            self._check("POLL DETECTED CHANGE")

    def _check(self, label):
        current = file_state(HOST_FILE)
        # Watchdog can issue several events for one write; compare actual state and debounce.
        if current == self.last:
            return
        previous = self.last
        self.last = current
        if not previous["exists"] and current["exists"]: kind = "CREATED"
        elif previous["exists"] and not current["exists"]: kind = "DELETED / MISSING"
        elif current["size"] > previous["size"]: kind = "GROWTH"
        elif current["size"] < previous["size"]: kind = "SHRINK"
        elif current["mtime"] != previous["mtime"]: kind = "MODIFIED"
        else: kind = label
        event = {"timestamp": dt.datetime.now().isoformat(timespec="seconds"), "event": kind,
                 "size": current["size"], "delta": current["size"] - previous["size"],
                 "exists": current["exists"], "mtime": current["mtime"],
                 "processes": find_open_processes(HOST_FILE)}
        log_event(event)
        self.gui.post_event(event)

    def close(self):
        self.stop_event.set()
        if self.observer is not None:
            try: self.observer.stop(); self.observer.join(timeout=2)
            except Exception: pass


class DominionDeckGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DominionDeck Host File Monitor v6")
        self.root.geometry("920x620")
        self.root.minsize(760, 500)
        self.root.configure(bg="#171a21")
        self.events = []
        self._closing = False
        self._build_ui()
        self.monitor = HostMonitor(self)
        self._refresh_stats()
        self.root.protocol("WM_DELETE_WINDOW", self.close)

    def _build_ui(self):
        style = ttk.Style()
        try: style.theme_use("clam")
        except tk.TclError: pass
        style.configure("TFrame", background="#171a21")
        style.configure("TLabel", background="#171a21", foreground="#d9e2f2", font=("Segoe UI", 9))
        style.configure("Title.TLabel", background="#171a21", foreground="#62f5dc", font=("Segoe UI", 15, "bold"))
        style.configure("TButton", padding=6)
        style.configure("TNotebook", background="#171a21", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(12, 7))
        outer = ttk.Frame(self.root, padding=12); outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="DOMINIONDECK · HOST FILE MONITOR", style="Title.TLabel").pack(anchor="w")
        ttk.Label(outer, text=f"Target: {HOST_FILE}").pack(anchor="w", pady=(4, 8))
        stats = ttk.Frame(outer); stats.pack(fill="x", pady=(0, 8))
        self.status_label = ttk.Label(stats, text="Status: starting…"); self.status_label.pack(side="left", padx=(0, 18))
        self.size_label = ttk.Label(stats, text="Size: —"); self.size_label.pack(side="left", padx=(0, 18))
        self.mtime_label = ttk.Label(stats, text="Last write: —"); self.mtime_label.pack(side="left")
        buttons = ttk.Frame(outer); buttons.pack(fill="x", pady=(0, 8))
        ttk.Button(buttons, text="Export / Backup", command=self.export_hosts).pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="Import / Restore…", command=self.import_hosts).pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="Open Log Folder", command=self.open_log_folder).pack(side="left", padx=(0, 6))
        ttk.Button(buttons, text="Refresh", command=self._refresh_stats).pack(side="left")
        self.tabs = ttk.Notebook(outer); self.tabs.pack(fill="both", expand=True)
        event_tab = ttk.Frame(self.tabs, padding=8); trend_tab = ttk.Frame(self.tabs, padding=8); info_tab = ttk.Frame(self.tabs, padding=8)
        self.tabs.add(event_tab, text="Events"); self.tabs.add(trend_tab, text="Trends"); self.tabs.add(info_tab, text="Diagnostics")
        ttk.Label(event_tab, text="Recent changes (newest first)", style="Title.TLabel").pack(anchor="w", pady=(0, 6))
        self.event_text = tk.Text(event_tab, bg="#0e1117", fg="#c8fff4", insertbackground="white", font=("Consolas", 9),
                                  wrap="word", relief="flat", padx=8, pady=8)
        scroll = ttk.Scrollbar(event_tab, orient="vertical", command=self.event_text.yview)
        self.event_text.configure(yscrollcommand=scroll.set); self.event_text.pack(side="left", fill="both", expand=True); scroll.pack(side="right", fill="y")
        ttk.Label(trend_tab, text="File-size history · last 30 days", style="Title.TLabel").pack(anchor="w")
        self.trend_summary = ttk.Label(trend_tab, text="Collecting change history…"); self.trend_summary.pack(anchor="w", pady=6)
        self.graph = tk.Canvas(trend_tab, bg="#0e1117", highlightthickness=0, height=260)
        self.graph.pack(fill="both", expand=True, pady=6); self.graph.bind("<Configure>", lambda _e: self._draw_graph())
        ttk.Label(trend_tab, text=f"Persistent log: {LOG_FILE}", wraplength=820).pack(anchor="w")
        self.diag_text = tk.Text(info_tab, bg="#0e1117", fg="#d9e2f2", font=("Consolas", 9), wrap="word", relief="flat", padx=8, pady=8)
        self.diag_text.pack(fill="both", expand=True)
        self.diag_text.insert("end", "Monitoring uses file metadata polling every second; watchdog is an optional event accelerator.\n"
            "The process list is best-effort: Windows may deny access, and a process with the file open is not necessarily writing it.\n\n"
            f"Python: {sys.version.split()[0]}\nHosts file exists: {os.path.exists(HOST_FILE)}\n"
            f"watchdog event watcher: {'available' if Observer is not None else 'not installed (polling fallback active)'}\n"
            f"psutil process inspection: {'available' if psutil is not None else 'not installed (process list unavailable)'}\n"
            f"Log file: {LOG_FILE}\n\nImport/Restore may require running this program as Administrator. Export does not.")
        self.diag_text.configure(state="disabled")

    def post_event(self, event):
        try: self.root.after(0, lambda e=event: self._apply_event(e))
        except tk.TclError: pass

    def _apply_event(self, event):
        self.events.insert(0, event); self.events = self.events[:MAX_EVENTS]
        stamp = event["timestamp"].replace("T", " ")
        text = f"[{stamp}] {event['event']} | size {human_size(event['size'])} | Δ {event['delta']:+,} bytes | exists={event['exists']}\n"
        if event.get("processes"):
            text += "  Processes with file open (best effort):\n"
            for proc in event["processes"][:10]: text += f"    PID {proc['pid']} · {proc['name']} · {proc['exe']}\n"
        else: text += "  Open-file process: none detected / access unavailable\n"
        text += "\n"
        self.event_text.configure(state="normal"); self.event_text.insert("1.0", text); self.event_text.configure(state="disabled")
        self._refresh_stats(); self._draw_graph()

    def _refresh_stats(self):
        state = file_state(HOST_FILE)
        self.status_label.configure(text="Status: monitoring · file present" if state["exists"] else "Status: WARNING · hosts file missing")
        self.size_label.configure(text=f"Size: {human_size(state['size'])}")
        self.mtime_label.configure(text=f"Last write: {state['mtime'] or 'unknown'}")
        self._draw_graph()

    def _draw_graph(self):
        if not hasattr(self, "graph"): return
        c = self.graph; c.delete("all")
        w = max(c.winfo_width(), 300); h = max(c.winfo_height(), 180)
        entries = read_recent_log(30)
        if not entries:
            c.create_text(w/2, h/2, text="No changes recorded in the last 30 days", fill="#c8fff4", font=("Segoe UI", 11))
            self.trend_summary.configure(text="30-day trend: waiting for file changes; baseline monitoring is active.")
            return
        sizes = [e["size"] for e in entries]; lo, hi = min(sizes), max(sizes)
        pad_l, pad_r, pad_t, pad_b = 55, 18, 18, 34
        c.create_line(pad_l, pad_t, pad_l, h-pad_b, fill="#64748b"); c.create_line(pad_l, h-pad_b, w-pad_r, h-pad_b, fill="#64748b")
        if len(entries) == 1 or hi == lo:
            y = (pad_t + h-pad_b)/2
            c.create_line(pad_l, y, w-pad_r, y, fill="#62f5dc", width=2)
        else:
            pts=[]
            for i, val in enumerate(sizes):
                x=pad_l + i*(w-pad_l-pad_r)/max(1,len(sizes)-1)
                y=(h-pad_b) - (val-lo)/(hi-lo)*(h-pad_t-pad_b)
                pts.extend((x,y))
            if len(pts) >= 4: c.create_line(*pts, fill="#62f5dc", width=2, smooth=False)
        c.create_text(8, pad_t, anchor="nw", text=human_size(hi), fill="#d9e2f2")
        c.create_text(8, h-pad_b, anchor="sw", text=human_size(lo), fill="#d9e2f2")
        delta=sizes[-1]-sizes[0]
        direction="↑" if delta>0 else "↓" if delta<0 else "→"
        self.trend_summary.configure(text=f"{len(entries)} logged events · size trend {direction} {delta:+,} bytes · range {human_size(lo)}–{human_size(hi)}")

    def export_hosts(self):
        if not os.path.isfile(HOST_FILE):
            messagebox.showerror("Export failed", f"Hosts file not found:\n{HOST_FILE}"); return
        dest=filedialog.asksaveasfilename(title="Export / Back up hosts file", defaultextension=".txt",
                                          initialfile="hosts-backup.txt", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not dest: return
        try:
            shutil.copy2(HOST_FILE, dest)
            messagebox.showinfo("Export complete", f"Hosts file backed up to:\n{dest}")
        except OSError as exc: messagebox.showerror("Export failed", str(exc))

    def import_hosts(self):
        src=filedialog.askopenfilename(title="Choose hosts backup to restore", filetypes=[("Text files", "*.txt;hosts"), ("All files", "*.*")])
        if not src: return
        if not os.path.isfile(src): messagebox.showerror("Restore failed", "The selected file does not exist."); return
        if os.path.normcase(os.path.abspath(src)) == os.path.normcase(os.path.abspath(HOST_FILE)):
            messagebox.showwarning("Restore skipped", "The selected file is already the active hosts file."); return
        if not messagebox.askyesno("Confirm restore", "This replaces the Windows hosts file. A backup of the current file will be created if possible. Continue?"):
            return
        backup = HOST_FILE + ".dominiondeck-backup-" + dt.datetime.now().strftime("%Y%m%d-%H%M%S")
        try:
            if os.path.exists(HOST_FILE): shutil.copy2(HOST_FILE, backup)
            shutil.copy2(src, HOST_FILE)
            self.monitor._check("RESTORE")
            messagebox.showinfo("Restore complete", f"Hosts file restored.\nPrevious-file backup (if created):\n{backup}")
        except PermissionError:
            messagebox.showerror("Permission denied", "Windows denied access to the hosts file. Close the program, then reopen it with Run as administrator and retry.")
        except OSError as exc: messagebox.showerror("Restore failed", f"Could not restore hosts file:\n{exc}")

    def open_log_folder(self):
        folder=os.path.dirname(LOG_FILE)
        try:
            if os.name == "nt": os.startfile(folder)
            elif sys.platform == "darwin": subprocess.Popen(["open", folder])
            else: subprocess.Popen(["xdg-open", folder])
        except Exception as exc: messagebox.showerror("Cannot open folder", str(exc))

    def close(self):
        if self._closing: return
        self._closing=True
        try: self.monitor.close()
        except Exception: pass
        self.root.destroy()

    def run(self): self.root.mainloop()


if __name__ == "__main__":
    try:
        DominionDeckGUI().run()
    except Exception as exc:
        try: messagebox.showerror("DominionDeck startup error", f"The monitor could not start:\n{exc}")
        except Exception: print(f"DominionDeck startup error: {exc}", file=sys.stderr)
        raise
