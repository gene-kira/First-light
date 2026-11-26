import ctypes
from datetime import datetime
import hashlib
import importlib
import json
import queue
import ipaddress
from pathlib import Path
import socket
import subprocess
import sys
import threading
import tkinter as tk
from tkinter import messagebox, simpledialog, ttk

try:
    import winsound
except ImportError:
    winsound = None


def autoload_dependencies(packages: list[tuple[str, str]]) -> dict[str, bool]:
    """
    Autoload required third-party packages at startup using pip if not already importable.
    Returns a map of {import_name: available}.
    """
    status: dict[str, bool] = {}
    for import_name, pip_name in packages:
        try:
            importlib.import_module(import_name)
            status[import_name] = True
        except ImportError:
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", pip_name],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                importlib.import_module(import_name)
                status[import_name] = True
            except Exception:
                status[import_name] = False
    return status


DEP_STATUS = autoload_dependencies([("psutil", "psutil")])
if DEP_STATUS.get("psutil"):
    import psutil  # type: ignore
else:
    psutil = None  # type: ignore


MEMORY_FILE = Path(__file__).with_name("big_brother_memory.json")
GUARD_LOG_FILE = Path(__file__).with_name("big_brother_guard_log.json")
GUI_REFRESH_MS = 15000  # 15 seconds between GUI redraws so moving/using the GUI stays smooth
IDLE_AWAY_SECONDS = 300
SUSPICIOUS_PORTS = {22, 23, 3389, 5900, 5985, 5986}
SHELL_OR_SCRIPT_PARENTS = {
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
    "wscript.exe",
    "cscript.exe",
    "mshta.exe",
}

DEFAULT_WEIGHTS = {
    "outside_ip_db": 1.0,
    "away_state": 1.0,
    "off_hour": 0.85,
    "risky_origin_or_port": 1.1,
    "cross_drive": 1.0,
    "counterfeit_ip": 1.8,
}


def beep_beep_alert() -> None:
    def _play() -> None:
        try:
            if winsound is not None:
                winsound.Beep(1150, 140)
                winsound.Beep(1450, 180)
            else:
                print("\a", end="", flush=True)
        except Exception:
            pass

    threading.Thread(target=_play, daemon=True).start()


def get_idle_seconds() -> float:
    try:
        class LASTINPUTINFO(ctypes.Structure):
            _fields_ = [("cbSize", ctypes.c_uint), ("dwTime", ctypes.c_uint)]

        lii = LASTINPUTINFO()
        lii.cbSize = ctypes.sizeof(LASTINPUTINFO)
        if ctypes.windll.user32.GetLastInputInfo(ctypes.byref(lii)):
            tick_count = ctypes.windll.kernel32.GetTickCount()
            elapsed_ms = (tick_count - lii.dwTime) & 0xFFFFFFFF
            return elapsed_ms / 1000.0
    except Exception:
        pass
    return 0.0


def get_drive_letter(path_str: str) -> str:
    if len(path_str) >= 2 and path_str[1] == ":":
        return path_str[:2].upper()
    return "N/A"


def file_sha256(exe_path: str) -> str:
    if not exe_path:
        return ""
    p = Path(exe_path)
    if not p.exists() or not p.is_file():
        return ""
    try:
        h = hashlib.sha256()
        with p.open("rb") as f:
            while chunk := f.read(65536):
                h.update(chunk)
        return h.hexdigest()
    except OSError:
        return ""


def format_lineage(proc: object, max_depth: int = 4) -> tuple[str, str]:
    chain: list[str] = []
    immediate_parent = "unknown"
    depth = 0
    try:
        curr = proc.parent()  # type: ignore[attr-defined]
    except Exception:
        curr = None

    while curr is not None and depth < max_depth:
        try:
            pname = curr.name() or f"pid:{curr.pid}"  # type: ignore[attr-defined]
            chain.append(f"{pname}({curr.pid})")  # type: ignore[attr-defined]
            if depth == 0:
                immediate_parent = pname.lower()
            curr = curr.parent()  # type: ignore[attr-defined]
        except Exception:
            chain.append("<?parent>")
            break
        depth += 1

    return (" -> ".join(reversed(chain)) if chain else "root/orphan"), immediate_parent


def inspect_origin_health(exe_path: str) -> tuple[str, bool, str]:
    if not exe_path:
        return "No exe path visible", True, "Origin hidden (check parent/session)"
    p = Path(exe_path)
    if not p.exists():
        return "Binary missing on disk", True, "Possible self-cleanup or crashed/collapsed path"
    try:
        st = p.stat()
        age_hours = (datetime.now().timestamp() - st.st_mtime) / 3600.0
        if age_hours < 24:
            return f"Modified/created {age_hours:.1f}h ago", True, "Fresh binary—verify installer/entry source"
        return f"Intact ({age_hours/24:.1f}d old)", False, "Established binary on disk"
    except OSError:
        return "Stat check restricted", False, "Restricted stat check"


def resolve_domain_ips(domain: str) -> set[str]:
    ips: set[str] = set()
    clean = domain.strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
    if not clean:
        return ips
    try:
        infos = socket.getaddrinfo(clean, None)
        for info in infos:
            addr = info[4][0]
            if addr:
                ips.add(addr)
    except OSError:
        pass
    return ips


class BigBrotherNextGenApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("BIG BROTHER NEXT-GEN — Reasoning, Predictive Weights, IP DB & Guard Log")
        self.root.geometry("1440x820")

        self.memory = self.load_memory()
        self.guard_log: list[dict] = self.load_guard_log()
        self.session_start = datetime.now().isoformat(timespec="seconds")
        self.memory["session_history"].append({"event": "LOGIN_OR_START", "time": self.session_start})
        self.memory["session_history"] = self.memory["session_history"][-100:]
        self.save_memory()

        self.runtime_strikes: dict[str, int] = {}
        self.risk_history: dict[str, list[float]] = {}
        self.guard_posts: dict[str, dict] = {}
        self.row_keys: dict[str, str] = {}
        self.reasoning_by_key: dict[str, str] = {}
        self._pending_alerts: list[tuple[str, bool]] = []
        self._last_saved_tick = 0
        self._last_beep_key = ""
        self._scan_queue = queue.Queue(maxsize=1)
        self._scan_requested = threading.Event()
        self._stop_worker = threading.Event()
        self._hash_cache: dict[str, tuple[int, int, str]] = {}

        self._build_ui()
        self.refresh_guard_log_box()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self._worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="BigBrotherScanner")
        self._worker_thread.start()
        self._scan_requested.set()
        self.poll()

    def load_memory(self) -> dict:
        if MEMORY_FILE.exists():
            try:
                raw = json.loads(MEMORY_FILE.read_text(encoding="utf-8"))
                known_db = set(raw.get("known_ip_database", []))
                for ip_set in raw.get("seen_ips", {}).values():
                    known_db.update(ip_set)
                for ip_set in raw.get("watched_domains", {}).values():
                    known_db.update(ip_set)
                weights = dict(DEFAULT_WEIGHTS)
                weights.update(raw.get("learning_weights", {}))
                return {
                    "known_ip_database": known_db,
                    "trusted_pairs": set(raw.get("trusted_pairs", [])),
                    "seen_ips": {k: set(v) for k, v in raw.get("seen_ips", {}).items()},
                    "seen_drives": {k: set(v) for k, v in raw.get("seen_drives", {}).items()},
                    "user_approved_exes": set(raw.get("user_approved_exes", [])),
                    "active_hours": set(raw.get("active_hours", [])),
                    "session_history": list(raw.get("session_history", [])),
                    "watched_domains": {k: set(v) for k, v in raw.get("watched_domains", {}).items()},
                    "learning_weights": weights,
                }
            except Exception:
                pass
        return {
            "known_ip_database": set(),
            "trusted_pairs": set(),
            "seen_ips": {},
            "seen_drives": {},
            "user_approved_exes": set(),
            "active_hours": set(),
            "session_history": [],
            "watched_domains": {"yahoo.com": set()},
            "learning_weights": dict(DEFAULT_WEIGHTS),
        }

    def load_guard_log(self) -> list[dict]:
        if GUARD_LOG_FILE.exists():
            try:
                data = json.loads(GUARD_LOG_FILE.read_text(encoding="utf-8"))
                if isinstance(data, list):
                    return data[-300:]
            except Exception:
                pass
        return []

    def save_guard_log(self) -> None:
        self._atomic_json_write(GUARD_LOG_FILE, self.guard_log[-300:])

    def append_guard_log(self, status: str, target: str, detail: str) -> None:
        entry = {
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "status": status,
            "target": target,
            "detail": detail,
        }
        if self.guard_log and (
            self.guard_log[-1]["status"] == status and self.guard_log[-1]["target"] == target
        ):
            return
        self.guard_log.append(entry)
        self.guard_log = self.guard_log[-300:]
        self.save_guard_log()

    def save_memory(self) -> None:
        payload = {
            "last_updated": datetime.now().isoformat(timespec="seconds"),
            "known_ip_database": sorted(self.memory["known_ip_database"]),
            "trusted_pairs": sorted(self.memory["trusted_pairs"]),
            "seen_ips": {k: sorted(v) for k, v in self.memory["seen_ips"].items()},
            "seen_drives": {k: sorted(v) for k, v in self.memory["seen_drives"].items()},
            "user_approved_exes": sorted(self.memory["user_approved_exes"]),
            "active_hours": sorted(self.memory["active_hours"]),
            "session_history": self.memory["session_history"][-100:],
            "watched_domains": {k: sorted(v) for k, v in self.memory["watched_domains"].items()},
            "learning_weights": {k: round(float(v), 3) for k, v in self.memory["learning_weights"].items()},
        }
        self._atomic_json_write(MEMORY_FILE, payload)

    @staticmethod
    def _atomic_json_write(path: Path, payload: object) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        tmp.replace(path)

    def cached_file_sha256(self, exe_path: str) -> str:
        if not exe_path:
            return ""
        try:
            p = Path(exe_path)
            st = p.stat()
            key = str(p).lower()
            stamp = (st.st_mtime_ns, st.st_size)
            old = self._hash_cache.get(key)
            if old and old[:2] == stamp:
                return old[2]
            digest = file_sha256(exe_path)
            self._hash_cache[key] = (stamp[0], stamp[1], digest)
            if len(self._hash_cache) > 500:
                self._hash_cache.pop(next(iter(self._hash_cache)))
            return digest
        except OSError:
            return ""

    def _worker_loop(self) -> None:
        while not self._stop_worker.is_set():
            self._scan_requested.wait(timeout=GUI_REFRESH_MS / 1000)
            self._scan_requested.clear()
            if self._stop_worker.is_set():
                break
            try:
                result = self._scan_once()
            except Exception as exc:
                result = {"error": f"{type(exc).__name__}: {exc}"}
            try:
                self._scan_queue.put_nowait(result)
            except queue.Full:
                try:
                    self._scan_queue.get_nowait()
                    self._scan_queue.put_nowait(result)
                except queue.Empty:
                    pass

    def _scan_once(self) -> dict:
        now = datetime.now()
        hour_str = f"{now.hour:02d}:00"
        idle_sec = get_idle_seconds()
        away = idle_sec >= IDLE_AWAY_SECONDS
        hours = self.memory["active_hours"]
        unusual = bool(not away and len(hours) >= 4 and hour_str not in hours)
        if not away:
            hours.add(hour_str)

        proc_meta = {}
        connections = []
        if psutil is not None:
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    info = proc.info
                    exe = info.get("exe") or ""
                    proc_meta[info["pid"]] = (
                        info.get("name") or "unknown", exe, self.inspect_proc_drives(proc, exe),
                        *format_lineage(proc), *inspect_origin_health(exe)
                    )
                except Exception:
                    continue
            try:
                connections = psutil.net_connections(kind="inet")
            except Exception:
                connections = []

        rows = []
        if psutil is not None:
            for conn in connections:
                if (conn.status != psutil.CONN_ESTABLISHED or not conn.raddr or not conn.pid):
                    continue
                meta = proc_meta.get(conn.pid, ("unknown", "", set(), "unknown", "unknown", "No metadata", True, "Origin hidden"))
                name, exe, drives, lineage, parent, origin, fresh, wall = meta
                ip, port = conn.raddr.ip, conn.raddr.port
                key, db, prediction, strikes, guard, summary = self.score_event(
                    name, exe, lineage, parent, origin, fresh, wall, ip, port,
                    drives, idle_sec, hour_str, unusual
                )
                if strikes > 0 or guard == "STANDING GUARD" or key in self.memory["trusted_pairs"]:
                    rows.append((strikes, conn.pid, name, ip, db, port,
                                 ", ".join(sorted(drives)) or "N/A", prediction, guard, summary, key))
        rows.sort(key=lambda r: (r[8] == "STANDING GUARD", r[0], r[2]), reverse=True)
        return {"rows": rows[:140], "now": now, "idle": idle_sec, "away": away,
                "hours": len(hours), "db": len(self.memory["known_ip_database"]),
                "guards": len(self.guard_posts),
                "weight": self.memory["learning_weights"].get("outside_ip_db", 1.0)}

    def request_scan(self) -> None:
        self._scan_requested.set()

    def on_close(self) -> None:
        self._stop_worker.set()
        self._scan_requested.set()
        self.memory["session_history"].append(
            {"event": "LOGOUT_OR_EXIT", "time": datetime.now().isoformat(timespec="seconds")}
        )
        try:
            self.save_memory()
            self.save_guard_log()
        except OSError as exc:
            messagebox.showerror("Save Error", str(exc), parent=self.root)
        self.root.destroy()
    def _build_ui(self) -> None:
        top = ttk.Frame(self.root, padding=(10, 8))
        top.pack(fill=tk.X)

        self.status_var = tk.StringVar(value="Initializing...")
        ttk.Label(top, textvariable=self.status_var, font=("Segoe UI", 10, "bold")).pack(side=tk.LEFT)

        self.habit_var = tk.StringVar(value="Weights & Memory: Ready")
        ttk.Label(top, textvariable=self.habit_var, font=("Segoe UI", 9, "bold")).pack(side=tk.RIGHT)

        controls = ttk.Frame(self.root, padding=(10, 0, 10, 8))
        controls.pack(fill=tk.X)

        ttk.Button(controls, text="Trust & Learn (+Weight)", command=self.trust_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(controls, text="Post Guard Watch", command=self.post_guard_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(controls, text="Patch & Lift Guard", command=self.patch_and_lift_guard).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(controls, text="Strike +1 (Reinforce)", command=self.flag_selected).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Label(controls, text="Verify Site:").pack(side=tk.LEFT, padx=(14, 4))
        self.domain_entry = ttk.Entry(controls, width=18)
        self.domain_entry.insert(0, "yahoo.com")
        self.domain_entry.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(controls, text="Learn & Check Site", command=self.learn_and_check_site).pack(side=tk.LEFT)

        ttk.Button(controls, text="Save Memory & Log", command=self.save_all_now).pack(side=tk.RIGHT)

        columns = (
            "pid",
            "process",
            "remote_ip",
            "db_status",
            "port",
            "drives",
            "pred_risk",
            "strikes",
            "guard",
            "summary_and_origin",
        )
        self.tree = ttk.Treeview(self.root, columns=columns, show="headings", height=12)
        col_specs = [
            ("pid", 55),
            ("process", 150),
            ("remote_ip", 120),
            ("db_status", 120),
            ("port", 58),
            ("drives", 85),
            ("pred_risk", 85),
            ("strikes", 65),
            ("guard", 120),
            ("summary_and_origin", 575),
        ]
        for col, width in col_specs:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=width, anchor=tk.W)
        self.tree.bind("<<TreeviewSelect>>", self.on_row_selected)
        self.tree.pack(fill=tk.BOTH, expand=True, padx=10)

        cot_frame = ttk.LabelFrame(self.root, text="Big Brother Evidence & Predictive Assessment", padding=6)
        cot_frame.pack(fill=tk.X, padx=10, pady=(6, 4))
        self.cot_var = tk.StringVar(value="Select a row above to inspect evidence summary, contributing signals, weights, and trend forecast.")
        ttk.Label(cot_frame, textvariable=self.cot_var, font=("Consolas", 9), wraplength=1390, justify=tk.LEFT).pack(
            anchor=tk.W
        )

        lower = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        lower.pack(fill=tk.BOTH, expand=False, padx=10, pady=(2, 10))

        guard_frame = ttk.LabelFrame(lower, text="Active Guard Posts & Patch Log (Always Tracked)", padding=6)
        self.guard_log_box = tk.Listbox(guard_frame, height=7, font=("Consolas", 9))
        self.guard_log_box.pack(fill=tk.BOTH, expand=True)
        lower.add(guard_frame, weight=1)

        alert_frame = ttk.LabelFrame(lower, text="Big Brother Live Alert & Counterfeit Feed", padding=6)
        self.alert_list = tk.Listbox(alert_frame, height=7, font=("Consolas", 9))
        self.alert_list.pack(fill=tk.BOTH, expand=True)
        lower.add(alert_frame, weight=1)

    def save_all_now(self) -> None:
        self.save_memory()
        self.save_guard_log()

    def on_row_selected(self, _event: object = None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        key = self.row_keys.get(sel[0])
        if key and key in self.reasoning_by_key:
            self.cot_var.set(self.reasoning_by_key[key])

    def queue_alert(self, message: str, counterfeit_beep: bool = False) -> None:
        self._pending_alerts.append((message, counterfeit_beep))

    def flush_alerts_to_gui(self) -> None:
        if not self._pending_alerts:
            return
        for message, counterfeit_beep in self._pending_alerts:
            if not self.alert_list.size() or self.alert_list.get(0) != message:
                self.alert_list.insert(0, message)
                if self.alert_list.size() > 160:
                    self.alert_list.delete(160, tk.END)
                if counterfeit_beep and self._last_beep_key != message:
                    self._last_beep_key = message
                    beep_beep_alert()
        self._pending_alerts.clear()

    def refresh_guard_log_box(self) -> None:
        self.guard_log_box.delete(0, tk.END)
        for gkey, info in self.guard_posts.items():
            hits = info.get("hits", 0)
            self.guard_log_box.insert(
                tk.END, f"[ACTIVE GUARD | hits={hits}] {gkey} | origin: {info.get('lineage', 'unknown')}"
            )
        for entry in reversed(self.guard_log[-30:]):
            self.guard_log_box.insert(
                tk.END,
                f"[{entry['time']}] {entry['status']} -> {entry['target']} ({entry['detail']})",
            )

    def learn_and_check_site(self) -> None:
        raw_dom = self.domain_entry.get().strip().lower().removeprefix("https://").removeprefix("http://").split("/")[0]
        if not raw_dom:
            return
        self.status_var.set(f"Resolving {raw_dom} in background...")
        def job():
            resolved = resolve_domain_ips(raw_dom)
            if not resolved:
                msg = f"[SITE CHECK] Could not resolve {raw_dom} right now."
            else:
                known = self.memory["watched_domains"].setdefault(raw_dom, set())
                new_ips = resolved - known
                known.update(resolved)
                self.memory["known_ip_database"].update(resolved)
                try:
                    self.save_memory()
                    msg = f"[IP DB UPDATED] {raw_dom} added {len(new_ips)} new IP(s) (total DB size: {len(self.memory['known_ip_database'])})"
                except OSError as exc:
                    msg = f"[SITE CHECK] Save failed: {exc}"
            try:
                self.root.after(0, lambda: (self.queue_alert(msg), self.flush_alerts_to_gui()))
            except tk.TclError:
                pass
        threading.Thread(target=job, daemon=True, name="DomainResolver").start()
    def inspect_proc_drives(self, proc: object, exe_path: str) -> set[str]:
        drives: set[str] = set()
        d_exe = get_drive_letter(exe_path)
        if d_exe != "N/A":
            drives.add(d_exe)
        try:
            d_cwd = get_drive_letter(proc.cwd())  # type: ignore[attr-defined]
            if d_cwd != "N/A":
                drives.add(d_cwd)
        except Exception:
            pass
        try:
            for f in proc.open_files()[:25]:  # type: ignore[attr-defined]
                d_f = get_drive_letter(f.path)
                if d_f != "N/A":
                    drives.add(d_f)
        except Exception:
            pass
        return drives

    def check_ip_against_database(self, remote_ip: str) -> tuple[str, bool]:
        try:
            addr = ipaddress.ip_address(remote_ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return "PRIVATE/LOCAL IP", True
        except ValueError:
            pass
        if remote_ip in self.memory["known_ip_database"]:
            return "IN IP DB", False
        return "OUTSIDE IP DB", True

    def predict_risk(self, pair_key: str, weighted_score: float) -> tuple[str, str]:
        hist = self.risk_history.setdefault(pair_key, [])
        raw_pct = max(0.0, min(100.0, (weighted_score / 3.2) * 100.0))
        hist.append(raw_pct)
        self.risk_history[pair_key] = hist[-8:]

        if len(hist) >= 2:
            delta = hist[-1] - hist[-2]
            projected = max(0.0, min(100.0, hist[-1] + (delta * 0.65)))
            if delta >= 10.0:
                trend = "Rising"
            elif delta <= -10.0:
                trend = "Cooling"
            else:
                trend = "Steady"
        else:
            projected = raw_pct
            trend = "Initial"

        return f"{int(round(projected))}% ({trend})", trend

    def adjust_weights_from_feedback(self, increase: bool) -> None:
        w = self.memory["learning_weights"]
        factor = 1.08 if increase else 0.94
        for k in list(w.keys()):
            val = float(w[k]) * factor
            w[k] = round(max(0.35, min(2.5, val)), 3)

    def score_event(
        self,
        proc_name: str,
        exe_path: str,
        lineage: str,
        parent_name: str,
        origin_note: str,
        is_fresh_or_risky: bool,
        wall_hint: str,
        remote_ip: str,
        port: int,
        drives: set[str],
        idle_sec: float,
        hour_str: str,
        unusual_hour: bool,
    ) -> tuple[str, str, str, int, str, str]:
        proc_key = f"{proc_name.lower()}|{exe_path.lower()}"
        pair_key = f"{proc_key}->{remote_ip}:{port}"
        exe_guard_key = exe_path.lower() or proc_key
        weights = self.memory["learning_weights"]

        db_status, is_outside_db = self.check_ip_against_database(remote_ip)
        known_ips = self.memory["seen_ips"].setdefault(proc_key, set())
        known_drives = self.memory["seen_drives"].setdefault(proc_key, set())

        current_hash = self.cached_file_sha256(exe_path)
        if exe_guard_key in self.guard_posts:
            old_hash = self.guard_posts[exe_guard_key].get("hash", "")
            if old_hash and current_hash and old_hash != current_hash:
                self.guard_posts[exe_guard_key]["hash"] = current_hash
                self.append_guard_log(
                    "BINARY CHANGED",
                    exe_guard_key,
                    "File hash changed on disk—verify if patch was applied",
                )

        guard_status = "STANDING GUARD" if exe_guard_key in self.guard_posts else "Watching"
        if exe_guard_key in self.guard_posts:
            self.guard_posts[exe_guard_key]["hits"] = self.guard_posts[exe_guard_key].get("hits", 0) + 1
            self.guard_posts[exe_guard_key]["lineage"] = lineage

        lower_exe = exe_path.lower()
        is_standard_dir = (
            "\\program files\\" in lower_exe
            or "\\program files (x86)\\" in lower_exe
            or proc_key in self.memory["user_approved_exes"]
        )
        is_temp_or_download = any(
            tag in lower_exe for tag in ("\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\")
        )

        weighted_points = 0.0
        counterfeit_hit = False
        step1_parts = [f"exe={proc_name}", f"origin={origin_note} ({wall_hint})", f"lineage={lineage}"]
        step2_parts = [
            f"state={'AWAY' if idle_sec >= IDLE_AWAY_SECONDS else 'ACTIVE'} ({int(idle_sec)}s)",
            f"hour={hour_str}",
        ]
        step3_parts = [f"ip={remote_ip}:{port}", f"db={db_status}"]

        if pair_key in self.memory["trusted_pairs"] and exe_guard_key not in self.guard_posts:
            self.memory["known_ip_database"].add(remote_ip)
            known_ips.add(remote_ip)
            known_drives.update(drives)
            strikes = self.runtime_strikes.get(pair_key, 0)
            pred_label, _ = self.predict_risk(pair_key, 0.0)
            cot = (
                f"Assessment [{proc_name} -> {remote_ip}:{port}]: "
                f"1.Origin: Trusted pair/app | "
                f"2.Context: {step2_parts[0]}, {step2_parts[1]} | "
                f"3.Destination: Approved in IP DB | "
                f"4.Verdict: Low risk, remembered baseline."
            )
            return pair_key, "IN IP DB", pred_label, strikes, "Trusted", f"Remembered | {cot}"

        if is_fresh_or_risky or port in SUSPICIOUS_PORTS or is_temp_or_download or parent_name in SHELL_OR_SCRIPT_PARENTS:
            w_val = float(weights["risky_origin_or_port"])
            weighted_points += w_val
            step1_parts.append(f"+{w_val:.2f} risky origin/port/parent")

        if idle_sec >= IDLE_AWAY_SECONDS:
            w_val = float(weights["away_state"])
            weighted_points += w_val
            step2_parts.append(f"+{w_val:.2f} away")

        if unusual_hour:
            w_val = float(weights["off_hour"])
            weighted_points += w_val
            step2_parts.append(f"+{w_val:.2f} off-habit hour")

        new_drives = drives - known_drives
        if new_drives and known_drives:
            w_val = float(weights["cross_drive"])
            weighted_points += w_val
            step2_parts.append(f"+{w_val:.2f} cross-drive ({','.join(sorted(new_drives))})")
        known_drives.update(drives)

        if db_status == "PRIVATE/LOCAL IP":
            step3_parts.append("private/local destination; not suspicious by itself")
        elif is_outside_db:
            w_val = float(weights["outside_ip_db"])
            weighted_points += w_val
            step3_parts.append(f"+{w_val:.2f} outside IP DB")
        else:
            step3_parts.append("0.00 in IP DB")

        if remote_ip not in known_ips:
            if is_standard_dir and idle_sec < IDLE_AWAY_SECONDS and len(known_ips) < 6 and not counterfeit_hit:
                known_ips.add(remote_ip)
                self.memory["known_ip_database"].add(remote_ip)
                db_status = "IN IP DB (LEARNED)"
                step3_parts.append("auto-learned into DB")

        pred_label, trend = self.predict_risk(pair_key, weighted_points)
        computed_strikes = min(3, int(round(weighted_points)))
        prev_strikes = self.runtime_strikes.get(pair_key, 0)
        strikes = min(3, max(prev_strikes, computed_strikes))
        self.runtime_strikes[pair_key] = strikes

        verdict = (
            "COUNTERFEIT/BREACH ALERT"
            if counterfeit_hit or strikes == 3
            else ("GUARD WATCH" if strikes >= 2 else ("WATCHING TREND" if trend == "Rising" else "NORMAL/OBSERVED"))
        )
        cot = (
            f"Assessment [{proc_name} -> {remote_ip}:{port}]: "
            f"1.Origin: {'; '.join(step1_parts)} | "
            f"2.Context: {'; '.join(step2_parts)} | "
            f"3.Destination: {'; '.join(step3_parts)} | "
            f"4.Forecast & Verdict: weighted={weighted_points:.2f}, pred={pred_label}, verdict={verdict}."
        )
        self.reasoning_by_key[pair_key] = cot

        if (strikes >= 2 or (trend == "Rising" and weighted_points >= 2.0)) and exe_guard_key not in self.guard_posts:
            self.guard_posts[exe_guard_key] = {
                "hits": 1,
                "lineage": lineage,
                "pair_key": pair_key,
                "hash": current_hash,
            }
            guard_status = "STANDING GUARD"
            self.append_guard_log(
                "GUARD POST OPENED",
                exe_guard_key,
                f"{proc_name} -> {remote_ip}:{port} [{db_status}, pred={pred_label}] | {wall_hint}",
            )
            prefix = "BEEP BEEP — COUNTERFEIT / OUTSIDE DB" if counterfeit_hit else "GUARD POST OPENED"
            self.queue_alert(
                f"[{prefix} @ {hour_str}] {proc_name} -> {remote_ip}:{port} ({db_status}, {pred_label}) | Origin: {lineage}",
                counterfeit_beep=(counterfeit_hit or strikes == 3),
            )
        elif strikes >= 2:
            self.queue_alert(
                f"[{strikes} STRIKES | {pred_label} @ {hour_str}] {proc_name} -> {remote_ip}:{port} ({db_status}) | {wall_hint}",
                counterfeit_beep=counterfeit_hit,
            )

        summary = f"{verdict} | {wall_hint} || Lineage: {lineage}"
        return pair_key, db_status, pred_label, strikes, guard_status, summary

    def get_selected_key(self) -> str | None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("No Selection", "Select a row in the table first.")
            return None
        return self.row_keys.get(sel[0])

    def trust_selected(self) -> None:
        key = self.get_selected_key()
        if not key:
            return
        proc_key, endpoint = key.split("->", 1)
        ip = endpoint.split(":", 1)[0]
        self.memory["trusted_pairs"].add(key)
        self.memory["user_approved_exes"].add(proc_key)
        self.memory["seen_ips"].setdefault(proc_key, set()).add(ip)
        self.memory["known_ip_database"].add(ip)
        self.adjust_weights_from_feedback(increase=False)
        self.runtime_strikes[key] = 0
        self.save_memory()
        self.queue_alert(f"[LEARNED & WEIGHTS TUNED DOWN] {ip} added to IP DB ({key})")
        self.request_scan()

    def post_guard_selected(self) -> None:
        key = self.get_selected_key()
        if not key:
            return
        proc_key, _ = key.split("->", 1)
        exe_path = proc_key.split("|", 1)[1] if "|" in proc_key else proc_key
        gkey = exe_path or proc_key
        self.guard_posts.setdefault(
            gkey, {"hits": 0, "lineage": "manual guard post", "pair_key": key, "hash": self.cached_file_sha256(exe_path)}
        )
        self.append_guard_log("GUARD POST OPENED", gkey, f"Manual guard watch started for {key}")
        self.queue_alert(f"[MANUAL GUARD POST] Standing watch on {gkey} until patched.")
        self.request_scan()

    def patch_and_lift_guard(self) -> None:
        key = self.get_selected_key()
        if not key:
            return
        proc_key, _ = key.split("->", 1)
        exe_path = proc_key.split("|", 1)[1] if "|" in proc_key else proc_key
        gkey = exe_path or proc_key

        patch_ref = simpledialog.askstring(
            "Patch Confirmation",
            "Optional patch / advisory note (e.g., CVE/patch version):",
            initialvalue="Patch applied",
            parent=self.root,
        )
        if patch_ref is None:
            return
        patch_note = patch_ref.strip() or "Patch applied"

        removed = self.guard_posts.pop(gkey, None)
        self.runtime_strikes[key] = 0
        self.risk_history.pop(key, None)
        self.append_guard_log("PATCHED — NO LONGER GUARDING", gkey, patch_note)
        if removed is not None:
            self.queue_alert(f"[PATCHED — NO LONGER GUARDING] {gkey} | {patch_note}")
        else:
            self.queue_alert(f"[GUARD CLEARED] PATCHED — NO LONGER GUARDING for {key}")
        self.request_scan()

    def flag_selected(self) -> None:
        key = self.get_selected_key()
        if not key:
            return
        self.runtime_strikes[key] = min(3, self.runtime_strikes.get(key, 0) + 1)
        self.adjust_weights_from_feedback(increase=True)
        self.save_memory()
        self.queue_alert(f"[STRIKE -> {self.runtime_strikes[key]} | WEIGHTS REINFORCED] {key}")
        self.request_scan()

    def poll(self, reschedule: bool = True) -> None:
        """Non-blocking Tk event pump. Process enumeration and socket inspection happen in a worker."""
        latest = None
        try:
            while True:
                latest = self._scan_queue.get_nowait()
        except queue.Empty:
            pass
        if latest:
            if "error" in latest:
                self.status_var.set(f"Scanner warning: {latest['error']}")
            else:
                now = latest["now"]
                idle = latest["idle"]
                self.status_var.set(
                    f"BIG BROTHER | {now.strftime('%H:%M:%S')} | {'AWAY' if latest['away'] else 'ACTIVE'} "
                    f"({int(idle)}s) | IP DB: {latest['db']} | Guards: {latest['guards']} | Background scan"
                )
                self.habit_var.set(
                    f"Habit Hours: {latest['hours']}/24 | IP-DB Weight: {latest['weight']:.2f} | "
                    f"Autoload psutil: {'OK' if psutil else 'FALLBACK'}"
                )
                selected_key = self.row_keys.get(self.tree.selection()[0]) if self.tree.selection() else None
                for item in self.tree.get_children():
                    self.tree.delete(item)
                self.row_keys.clear()
                for strikes, pid, name, ip, db, port, drives, pred, guard, summary, key in latest["rows"]:
                    item = self.tree.insert("", tk.END, values=(pid, name, ip, db, port, drives, pred, strikes, guard, summary))
                    self.row_keys[item] = key
                    if selected_key == key:
                        self.tree.selection_set(item)
                self.flush_alerts_to_gui()
                self.refresh_guard_log_box()
                self._last_saved_tick += 1
                if self._last_saved_tick >= 4:
                    self._last_saved_tick = 0
                    try:
                        self.save_memory()
                        self.save_guard_log()
                    except OSError as exc:
                        self.status_var.set(f"Save warning: {exc}")
        if reschedule and not self._stop_worker.is_set():
            self.root.after(250, self.poll)

if __name__ == "__main__":
    root = tk.Tk()
    BigBrotherNextGenApp(root)
    root.mainloop()