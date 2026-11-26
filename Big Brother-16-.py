import ctypes
from datetime import datetime
import hashlib
import math
import os
import shutil
import importlib
import ipaddress
import json
from pathlib import Path
import queue
import re
import socket
import subprocess
import sys
import threading
import time
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
FORENSICS_DIR = Path(__file__).with_name("big_brother_forensics")

GUI_REFRESH_MS = 8000  # Faster background scan cadence; GUI remains event-driven.
AUTO_CONTAIN_CONFIRM_SCANS = 3
AUTO_CONTAIN_COOLDOWN_SECONDS = 900
MAX_RISK_HISTORY = 24
MAX_FEEDBACK_EVENTS = 500
CRITICAL_PROCESS_NAMES = {
    "system", "system idle process", "registry", "smss.exe", "csrss.exe",
    "wininit.exe", "winlogon.exe", "services.exe", "lsass.exe", "svchost.exe",
    "explorer.exe", "dwm.exe", "fontdrvhost.exe", "taskhostw.exe",
}
SAFE_AUTO_CONTAIN_DENYLIST = CRITICAL_PROCESS_NAMES | BROWSER_PROCESS_NAMES if "BROWSER_PROCESS_NAMES" in globals() else CRITICAL_PROCESS_NAMES
IDLE_AWAY_SECONDS = 300
PORT_SCAN_WINDOW_SECONDS = 180
PORT_SCAN_MULTI_PORT_THRESHOLD = 3
POST_SITE_WATCH_SECONDS = 300

CONFIDENCE_RANK = {"Low": 1, "Medium": 2, "High": 3}

SUSPICIOUS_PORTS = {22, 23, 3389, 5900, 5985, 5986}
EXFIL_SENSITIVE_PORTS = {21, 445, 1433, 3306, 5432, 6379, 8080, 8443, 9001}
BROWSER_PROCESS_NAMES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "iexplore.exe",
}
SAFE_AUTO_CONTAIN_DENYLIST = CRITICAL_PROCESS_NAMES | BROWSER_PROCESS_NAMES

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
    "port_scan_sweep": 1.65,
    "post_site_anomaly": 1.35,
    "kill_chain_sequence": 1.5,
}


def beep_beep_alert(high_priority: bool = False, muted: bool = False) -> None:
    if muted:
        return

    def _play() -> None:
        try:
            if winsound is not None:
                if high_priority:
                    winsound.Beep(1450, 140)
                    winsound.Beep(1750, 140)
                    winsound.Beep(1450, 200)
                else:
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


def extract_binary_indicators(exe_path: str, max_bytes: int = 2_000_000) -> dict:
    """
    Safe static inspection: header magic, size, printable strings,
    and suspicious network/system/info-gathering tokens without executing or modifying the binary.
    """
    info = {
        "exists": False,
        "size_bytes": 0,
        "header": "unknown",
        "matched_tokens": [],
        "sample_strings": [],
    }
    if not exe_path:
        return info
    p = Path(exe_path)
    if not p.exists() or not p.is_file():
        return info
    info["exists"] = True
    try:
        st = p.stat()
        info["size_bytes"] = st.st_size
        with p.open("rb") as f:
            data = f.read(max_bytes)
        if data.startswith(b"MZ"):
            info["header"] = "PE/MZ Windows Executable"
        elif data.startswith(b"\x7fELF"):
            info["header"] = "ELF Binary"
        else:
            info["header"] = f"Raw/Other ({data[:4].hex()})"

        ascii_strings = re.findall(rb"[ -~]{5,64}", data)
        decoded = [s.decode("ascii", errors="ignore") for s in ascii_strings]
        interesting_patterns = [
            r"http[s]?://",
            r"socket|connect|WSAStartup|InternetOpen|WinHttp",
            r"GetComputerName|GetUserName|RegOpenKey|whoami|ipconfig|systeminfo",
            r"password|credential|token|cookie|wallet|ssh|keylog",
            r"VirtualAlloc|WriteProcessMemory|CreateRemoteThread|cmd\.exe|powershell",
        ]
        matched: list[str] = []
        for pat in interesting_patterns:
            hits = [s for s in decoded if re.search(pat, s, flags=re.IGNORECASE)]
            if hits:
                matched.append(f"{pat} ({len(hits)}x, e.g. {hits[0][:40]})")
        info["matched_tokens"] = matched[:15]
        info["sample_strings"] = decoded[:20]
    except OSError as exc:
        info["header"] = f"Read error: {exc}"
    return info


def format_lineage(proc: object, max_depth: int = 5) -> tuple[str, str]:
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


def inspect_origin_health(exe_path: str) -> tuple[str, bool, str, bool]:
    """
    Returns (origin_status, is_fresh_or_risky, wall_hint, is_unknown_origin).
    """
    if not exe_path:
        return "No exe path visible", True, "Origin hidden (unknown origin—investigate!)", True
    p = Path(exe_path)
    if not p.exists():
        return "Binary missing on disk", True, "Missing binary on disk—high alert", True
    lower_path = str(p).lower()
    in_known_system_or_app = any(
        prefix in lower_path
        for prefix in ("\\windows\\", "\\program files\\", "\\program files (x86)\\")
    )
    try:
        st = p.stat()
        age_hours = max(0.0, (datetime.now().timestamp() - st.st_mtime) / 3600.0)
        if age_hours < 24:
            return (
                f"Modified/created {age_hours:.1f}h ago",
                True,
                "Fresh binary—verify installer/entry source",
                not in_known_system_or_app,
            )
        unknown_origin = not in_known_system_or_app and any(
            tag in lower_path for tag in ("\\temp\\", "\\appdata\\", "\\downloads\\", "\\users\\public\\")
        )
        hint = "Unknown/user-space origin" if unknown_origin else "Established binary on disk"
        return f"Intact ({age_hours/24:.1f}d old)", unknown_origin, hint, unknown_origin
    except OSError:
        return "Stat check restricted", True, "Restricted stat check", True


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
        self.root.title("BIG BROTHER NEXT-GEN — Scan Sweep, Forensics, Predictive Weights & Regret Policy")
        self.root.geometry("1360x820")
        self.root.minsize(980, 620)

        self._lock = threading.RLock()
        self.memory = self.load_memory()
        self.guard_log: list[dict] = self.load_guard_log()
        self.session_start = datetime.now().isoformat(timespec="seconds")
        with self._lock:
            self.memory["session_history"].append({"event": "LOGIN_OR_START", "time": self.session_start})
            self.memory["session_history"] = self.memory["session_history"][-100:]
            self.save_memory()

        self.runtime_strikes: dict[str, int] = {}
        self.risk_history: dict[str, list[float]] = {}
        self.guard_posts: dict[str, dict] = {}
        self.row_keys: dict[str, str] = {}
        self.row_pids: dict[str, int] = {}
        self.reasoning_by_key: dict[str, str] = {}
        self.signals_by_key: dict[str, list[str]] = {}
        self.ip_port_observations: dict[str, list[tuple[float, int, str]]] = {}
        self.known_procs_seen: set[str] = set()
        self.last_site_check_ts: float = 0.0
        self.last_site_checked_domain: str = ""
        self.auto_contain_enabled: bool = False
        self.session_logged_out_or_locked: bool = False
        self.muted: bool = False
        self.guards_paused: bool = False
        self.min_action_confidence: str = "Low"

        self._pending_alerts: list[tuple[str, bool, bool]] = []
        self._last_saved_tick = 0
        self._last_beep_key = ""
        self._scan_queue = queue.Queue(maxsize=1)
        self._scan_requested = threading.Event()
        self._stop_worker = threading.Event()
        self._hash_cache: dict[str, tuple[int, int, str]] = {}
        self._contain_confirmations: dict[int, int] = {}
        self._contain_last_action: dict[int, float] = {}
        self._scan_generation = 0
        self._last_worker_error = ""
        self._scan_started_at = 0.0

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
                    "hour_counts": {k: int(v) for k, v in raw.get("hour_counts", {}).items()},
                    "process_baselines": dict(raw.get("process_baselines", {})),
                    "session_history": list(raw.get("session_history", [])),
                    "watched_domains": {k: set(v) for k, v in raw.get("watched_domains", {}).items()},
                    "learning_weights": weights,
                    "scan_history": list(raw.get("scan_history", []))[-100:],
                    "feedback_events": list(raw.get("feedback_events", []))[-MAX_FEEDBACK_EVENTS:],
                    "model_metrics": dict(raw.get("model_metrics", {})),
                    "schema_version": 3,
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
            "hour_counts": {},
            "process_baselines": {},
            "session_history": [],
            "watched_domains": {"yahoo.com": set()},
            "learning_weights": dict(DEFAULT_WEIGHTS),
            "scan_history": [],
            "feedback_events": [],
            "model_metrics": {},
            "schema_version": 3,
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
        with self._lock:
            self._atomic_json_write(GUARD_LOG_FILE, self.guard_log[-300:])

    def append_guard_log(self, status: str, target: str, detail: str) -> None:
        with self._lock:
            entry = {
                "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                "status": status,
                "target": target,
                "detail": detail,
            }
            if self.guard_log and (
                self.guard_log[-1]["status"] == status
                and self.guard_log[-1]["target"] == target
                and self.guard_log[-1]["detail"] == detail
            ):
                return
            self.guard_log.append(entry)
            self.guard_log = self.guard_log[-300:]
            self.save_guard_log()

    def save_memory(self) -> None:
        with self._lock:
            payload = {
                "last_updated": datetime.now().isoformat(timespec="seconds"),
                "known_ip_database": sorted(self.memory["known_ip_database"]),
                "trusted_pairs": sorted(self.memory["trusted_pairs"]),
                "seen_ips": {k: sorted(v) for k, v in self.memory["seen_ips"].items()},
                "seen_drives": {k: sorted(v) for k, v in self.memory["seen_drives"].items()},
                "user_approved_exes": sorted(self.memory["user_approved_exes"]),
                "active_hours": sorted(self.memory["active_hours"]),
                "hour_counts": dict(self.memory.get("hour_counts", {})),
                "process_baselines": dict(list(self.memory.get("process_baselines", {}).items())[-250:]),
                "session_history": self.memory["session_history"][-100:],
                "watched_domains": {k: sorted(v) for k, v in self.memory["watched_domains"].items()},
                "learning_weights": {k: round(float(v), 3) for k, v in self.memory["learning_weights"].items()},
                 "scan_history": self.memory.get("scan_history", [])[-100:],
                "feedback_events": self.memory.get("feedback_events", [])[-MAX_FEEDBACK_EVENTS:],
                "model_metrics": dict(self.memory.get("model_metrics", {})),
                "schema_version": 3,
            }
            self._atomic_json_write(MEMORY_FILE, payload)

    @staticmethod
    def _atomic_json_write(path: Path, payload: object) -> None:
        tmp = path.with_suffix(path.suffix + ".tmp")
        serialized = json.dumps(payload, indent=2, ensure_ascii=False)
        tmp.write_text(serialized, encoding="utf-8")
        # Keep one recoverable previous version before replacing persistent state.
        if path.exists():
            backup = path.with_suffix(path.suffix + ".bak")
            try:
                shutil.copy2(path, backup)
            except OSError:
                pass
        tmp.replace(path)

    def cached_file_sha256(self, exe_path: str) -> str:
        if not exe_path:
            return ""
        try:
            p = Path(exe_path)
            st = p.stat()
            key = str(p).lower()
            stamp = (st.st_mtime_ns, st.st_size)
            with self._lock:
                old = self._hash_cache.get(key)
                if old and old[:2] == stamp:
                    return old[2]
            digest = file_sha256(exe_path)
            with self._lock:
                self._hash_cache[key] = (stamp[0], stamp[1], digest)
                if len(self._hash_cache) > 500:
                    self._hash_cache.pop(next(iter(self._hash_cache)))
            return digest
        except OSError:
            return ""

    def _record_port_scan_sweep(
        self, remote_ip: str, port: int, proc_name: str, idle_or_away: bool, hour_str: str
    ) -> tuple[bool, list[int], int]:
        """
        Tracks distinct ports observed for a remote_ip within PORT_SCAN_WINDOW_SECONDS.
        Returns (is_multi_port_scan, distinct_ports_list, total_hits_in_window).
        """
        now_ts = time.time()
        with self._lock:
            obs = self.ip_port_observations.setdefault(remote_ip, [])
            obs.append((now_ts, port, proc_name))
            obs = [item for item in obs if (now_ts - item[0]) <= PORT_SCAN_WINDOW_SECONDS]
            self.ip_port_observations[remote_ip] = obs

            distinct_ports = sorted({p for _, p, _ in obs})
            hits = len(obs)
            is_sweep = len(distinct_ports) >= PORT_SCAN_MULTI_PORT_THRESHOLD
            if is_sweep:
                record = {
                    "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                    "ip": remote_ip,
                    "ports": distinct_ports,
                    "hits": hits,
                    "idle_or_away": idle_or_away,
                    "hour": hour_str,
                }
                hist = self.memory.setdefault("scan_history", [])
                if not hist or hist[-1].get("ip") != remote_ip or hist[-1].get("ports") != distinct_ports:
                    hist.append(record)
                    self.memory["scan_history"] = hist[-100:]
            return is_sweep, distinct_ports, hits

    def _evaluate_temporal_coherence(
        self,
        pair_key: str,
        is_unknown_origin: bool,
        is_outside_db: bool,
        is_sweep: bool,
        idle_or_away: bool,
        post_site_window_active: bool,
    ) -> tuple[str, float]:
        """
        Evaluates cross-signal temporal coherence across observations to distinguish
        converging multi-signal anomalies from isolated single-tick noise.
        Returns (coherence_label, coherence_factor).
        """
        with self._lock:
            hist = self.risk_history.get(pair_key, [])
        active_signals = sum(
            [
                1 if is_unknown_origin else 0,
                1 if is_outside_db else 0,
                1 if is_sweep else 0,
                1 if idle_or_away else 0,
                1 if post_site_window_active else 0,
            ]
        )
        persistent_steps = sum(1 for v in hist[-4:] if v >= 35.0)
        if active_signals >= 3 and persistent_steps >= 1:
            return "Convergent Multi-Signal", 1.15
        if active_signals <= 1 and persistent_steps == 0:
            return "Isolated / Self-Healing Drift", 0.90
        return "Partial Temporal Alignment", 1.0

    def _detect_kill_chain_sequence(
        self,
        lineage: str,
        parent_name: str,
        is_unknown_origin: bool,
        is_temp_or_download: bool,
        is_outside_db: bool,
        post_site_window_active: bool,
    ) -> tuple[bool, str]:
        """
        Checks multi-stage execution-to-network chains (e.g., browser/script host ->
        user-space/temp/download binary -> external network destination).
        """
        lower_lineage = lineage.lower()
        has_script_or_browser = (
            parent_name in SHELL_OR_SCRIPT_PARENTS
            or any(b in lower_lineage for b in BROWSER_PROCESS_NAMES)
            or any(s in lower_lineage for s in SHELL_OR_SCRIPT_PARENTS)
        )
        if has_script_or_browser and (is_unknown_origin or is_temp_or_download) and (is_outside_db or post_site_window_active):
            return True, "Shell/Browser->UserBinary->External/PostSite"
        if is_unknown_origin and is_temp_or_download and is_outside_db:
            return True, "Temp/DownloadBinary->ExternalNet"
        return False, "None"

    def _update_and_check_process_baseline(self, proc_key: str, current_conns_for_proc: int, port: int) -> tuple[bool, str]:
        """
        Tracks per-process baseline connection fan-out and common ports.
        Returns (is_fanout_spike, baseline_note).
        """
        with self._lock:
            baselines = self.memory.setdefault("process_baselines", {})
            entry = baselines.get(proc_key) or {"max_conns": 1, "ports": [], "samples": 0}
            prev_max = int(entry.get("max_conns", 1))
            samples = int(entry.get("samples", 0))
            ports_list = list(entry.get("ports", []))

            spike = bool(samples >= 3 and current_conns_for_proc > max(3, prev_max * 2))
            entry["max_conns"] = max(prev_max, current_conns_for_proc)
            entry["samples"] = samples + 1
            if port not in ports_list and len(ports_list) < 25:
                ports_list.append(port)
            entry["ports"] = ports_list
            baselines[proc_key] = entry
            return spike, f"baseline_max={entry['max_conns']}, seen_ports={len(ports_list)}"

    def _evaluate_decision_policy(
        self,
        strikes: int,
        proj_pct: float,
        weighted_points: float,
        is_unknown_origin: bool,
        is_outside_db: bool,
        is_sweep: bool,
        counterfeit_hit: bool,
        kill_chain_hit: bool,
        idle_or_away: bool,
        is_trusted_pair: bool,
        coherence_label: str,
    ) -> tuple[str, str, str]:
        """
        Weighs evidence vs. ambiguity to pick a concrete action and confidence level:
        - CONFIDENCE: High / Medium / Low based on signal convergence & history
        - ACTION: CONTAIN_OR_STOP, OPEN_GUARD, INVESTIGATE_ORIGIN, OBSERVE, or TRUST_CANDIDATE
        """
        if is_trusted_pair and not is_sweep and not counterfeit_hit and strikes == 0:
            return "High", "TRUST_CANDIDATE", "Matches approved baseline with no active anomaly."

        evidence_count = sum(
            [
                1 if counterfeit_hit else 0,
                1 if is_sweep else 0,
                1 if kill_chain_hit else 0,
                1 if is_unknown_origin else 0,
                1 if is_outside_db else 0,
                1 if (idle_or_away and (is_sweep or is_unknown_origin)) else 0,
            ]
        )

        if evidence_count >= 4 or (evidence_count >= 3 and proj_pct >= 65.0):
            confidence = "High"
        elif evidence_count >= 2 or proj_pct >= 35.0:
            confidence = "Medium"
        else:
            confidence = "Low"

        if counterfeit_hit or strikes >= 3 or (idle_or_away and is_sweep and evidence_count >= 3):
            action = "CONTAIN_OR_STOP"
            rationale = "Multiple high-severity indicators converge; stop process or contain immediately if unverified."
        elif is_sweep or kill_chain_hit or strikes >= 2 or weighted_points >= 1.8:
            action = "OPEN_GUARD"
            rationale = "Active scan, sequence, or escalating score warrants continuous guard watch and inspection."
        elif is_unknown_origin:
            action = "INVESTIGATE_ORIGIN"
            rationale = "Binary origin is unfamiliar or user-scoped; inspect path, lineage, and strings before trusting."
        else:
            action = "OBSERVE"
            rationale = f"{coherence_label}; keep observing before changing guard state."

        return confidence, action, rationale

    def _estimate_action_regret(
        self,
        proc_name: str,
        rec_action: str,
        is_unknown_origin: bool,
        is_sweep: bool,
        counterfeit_hit: bool,
        kill_chain_hit: bool,
        idle_or_away: bool,
    ) -> str:
        """
        Estimates asymmetric regret: cost of false-positive disruption vs. cost of delayed containment.
        """
        is_browser = proc_name.lower() in BROWSER_PROCESS_NAMES
        if rec_action == "CONTAIN_OR_STOP":
            fp_cost = "High (browser/active app disruption)" if is_browser else ("Low" if is_unknown_origin else "Moderate")
            fn_cost = "High (uncontained sweep/exfil/counterfeit)"
            reversibility = "Reversible restart; inspect report first"
        elif rec_action == "OPEN_GUARD":
            fp_cost = "Low (non-blocking watch)"
            fn_cost = (
                "Elevated if sweep or kill-chain escalates"
                if (is_sweep or kill_chain_hit or idle_or_away)
                else "Moderate"
            )
            reversibility = "Fully reversible (Patch & Lift Guard)"
        else:
            fp_cost = "Minimal"
            fn_cost = "Moderate if unknown origin persists" if is_unknown_origin else "Low"
            reversibility = "Fully reversible"
        return f"FP_cost={fp_cost}, FN_cost={fn_cost} ({reversibility})"

    def record_feedback(self, key: str, outcome: str, note: str = "") -> None:
        """Persist an operator-labelled outcome and make small, bounded weight updates."""
        with self._lock:
            active = list(self.signals_by_key.get(key, []))
            event = {
                "time": datetime.now().isoformat(timespec="seconds"),
                "key": key,
                "outcome": outcome,
                "signals": active,
                "note": note[:240],
            }
            events = self.memory.setdefault("feedback_events", [])
            events.append(event)
            self.memory["feedback_events"] = events[-MAX_FEEDBACK_EVENTS:]
            metrics = self.memory.setdefault("model_metrics", {})
            metrics[outcome] = int(metrics.get(outcome, 0)) + 1
            # False-positive feedback lowers implicated weights gently; confirmed-threat
            # feedback raises them. Bounds and decay prevent runaway self-reinforcement.
            if outcome == "false_positive":
                self.adjust_weights_from_feedback(False, active or None)
            elif outcome == "confirmed_threat":
                self.adjust_weights_from_feedback(True, active or None)
            self.save_memory()

    def get_learning_summary(self) -> str:
        with self._lock:
            weights = self.memory.get("learning_weights", {})
            metrics = self.memory.get("model_metrics", {})
            events = self.memory.get("feedback_events", [])
            return (
                f"Feedback samples: {len(events)} | Confirmed threats: {metrics.get('confirmed_threat', 0)} | "
                f"False positives: {metrics.get('false_positive', 0)} | "
                f"Top weights: {', '.join(f'{k}={float(v):.2f}' for k, v in sorted(weights.items(), key=lambda x: float(x[1]), reverse=True)[:4])}"
            )

    def decay_weights_toward_default(self) -> None:
        """
        Gently nudges weights toward DEFAULT_WEIGHTS during periodic maintenance so weights
        stay responsive without locking onto old anomalies indefinitely.
        """
        with self._lock:
            w = self.memory["learning_weights"]
            for k, default_v in DEFAULT_WEIGHTS.items():
                curr_v = float(w.get(k, default_v))
                nudged = curr_v + (float(default_v) - curr_v) * 0.03
                w[k] = round(max(0.35, min(2.8, nudged)), 3)

    def check_ip_against_database(self, remote_ip: str) -> tuple[str, bool]:
        try:
            addr = ipaddress.ip_address(remote_ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                return "PRIVATE/LOCAL IP", False
        except ValueError:
            pass
        with self._lock:
            if remote_ip in self.memory["known_ip_database"]:
                return "IN IP DB", False
        return "OUTSIDE IP DB", True

    def predict_risk(self, pair_key: str, weighted_score: float, multiplier: float = 1.0) -> tuple[str, str, str, float]:
        """
        Computes projected risk %, trend label, second-order trajectory, and raw projected float.
        """
        with self._lock:
            hist = self.risk_history.setdefault(pair_key, [])
            effective_score = weighted_score * multiplier
            raw_pct = max(0.0, min(100.0, (effective_score / 3.2) * 100.0))
            hist.append(raw_pct)
            self.risk_history[pair_key] = hist[-MAX_RISK_HISTORY:]

            if len(hist) >= 2:
                recent = hist[-min(6, len(hist)):]
                deltas = [recent[i] - recent[i - 1] for i in range(1, len(recent))]
                # Dampen one-tick spikes; recent evidence matters more than old samples.
                ewma_delta = 0.0
                for d in deltas:
                    ewma_delta = 0.55 * d + 0.45 * ewma_delta
                delta = hist[-1] - hist[-2]
                projected = max(0.0, min(100.0, hist[-1] + max(-18.0, min(18.0, ewma_delta * 1.35))))
                if ewma_delta >= 5.0:
                    trend = "Rising"
                elif ewma_delta <= -5.0:
                    trend = "Cooling"
                else:
                    trend = "Steady"
            else:
                delta = 0.0
                ewma_delta = 0.0
                projected = raw_pct
                trend = "Initial"

            if len(hist) >= 3:
                prev_delta = hist[-2] - hist[-3]
                accel = delta - prev_delta
                if ewma_delta >= 7.0 and accel >= 5.0 and projected >= 50.0:
                    trajectory = "Escalating Surge"
                elif ewma_delta <= -5.0:
                    trajectory = "Decelerating"
                elif len(hist) >= 6 and max(hist[-5:]) - min(hist[-5:]) < 4.0:
                    trajectory = "Stable Baseline"
                else:
                    trajectory = "Linear Drift"
            else:
                trajectory = "Baseline Sampling"

            return f"{int(round(projected))}% ({trend})", trend, trajectory, projected

    def adjust_weights_from_feedback(self, increase: bool, focus_keys: list[str] | None = None) -> None:
        with self._lock:
            w = self.memory["learning_weights"]
            factor = 1.10 if increase else 0.94
            targets = focus_keys if focus_keys else list(w.keys())
            for k in targets:
                if k in w:
                    val = float(w[k]) * factor
                    w[k] = round(max(0.35, min(2.8, val)), 3)

    def score_event(
        self,
        proc_name: str,
        exe_path: str,
        lineage: str,
        parent_name: str,
        origin_note: str,
        is_fresh_or_risky: bool,
        wall_hint: str,
        is_unknown_origin: bool,
        remote_ip: str,
        port: int,
        drives: set[str],
        idle_sec: float,
        hour_str: str,
        unusual_hour: bool,
        rare_hour_ratio: float,
        proc_conn_count: int,
        post_site_window_active: bool,
        browser_active: bool,
    ) -> tuple[str, str, str, int, str, str, int, float]:
        proc_key = f"{proc_name.lower()}|{exe_path.lower()}"
        pair_key = f"{proc_key}->{remote_ip}:{port}"
        exe_guard_key = exe_path.lower() or proc_key
        idle_or_away = idle_sec >= IDLE_AWAY_SECONDS or self.session_logged_out_or_locked

        with self._lock:
            weights = dict(self.memory["learning_weights"])
            db_status, is_outside_db = self.check_ip_against_database(remote_ip)
            known_ips = self.memory["seen_ips"].setdefault(proc_key, set())
            known_drives = self.memory["seen_drives"].setdefault(proc_key, set())
            is_trusted_pair = pair_key in self.memory["trusted_pairs"]
            has_guard = exe_guard_key in self.guard_posts
            is_approved_exe = proc_key in self.memory["user_approved_exes"]
            watched_ips = (
                set().union(*self.memory["watched_domains"].values()) if self.memory["watched_domains"] else set()
            )
            guards_paused_now = self.guards_paused
            min_conf_rank = CONFIDENCE_RANK.get(self.min_action_confidence, 1)

            current_hash = self.cached_file_sha256(exe_path)
            if has_guard:
                old_hash = self.guard_posts[exe_guard_key].get("hash", "")
                if old_hash and current_hash and old_hash != current_hash:
                    self.guard_posts[exe_guard_key]["hash"] = current_hash
                    self.append_guard_log(
                        "BINARY CHANGED",
                        exe_guard_key,
                        "File hash changed on disk—verify if patch was applied",
                    )

            guard_status = (
                "GUARD PAUSED"
                if (has_guard and guards_paused_now)
                else ("STANDING GUARD" if has_guard else "Watching")
            )
            if has_guard:
                self.guard_posts[exe_guard_key]["hits"] = self.guard_posts[exe_guard_key].get("hits", 0) + 1
                self.guard_posts[exe_guard_key]["lineage"] = lineage
                self.guard_posts[exe_guard_key]["last_remote"] = f"{remote_ip}:{port}"

            is_new_proc = proc_key not in self.known_procs_seen
            self.known_procs_seen.add(proc_key)

            lower_exe = exe_path.lower()
            is_standard_dir = (
                "\\program files\\" in lower_exe
                or "\\program files (x86)\\" in lower_exe
                or is_approved_exe
            )
            is_temp_or_download = any(
                tag in lower_exe for tag in ("\\temp\\", "\\appdata\\local\\temp\\", "\\downloads\\")
            )

            is_sweep, sweep_ports, sweep_hits = self._record_port_scan_sweep(
                remote_ip, port, proc_name, idle_or_away, hour_str
            )
            coherence_label, coherence_factor = self._evaluate_temporal_coherence(
                pair_key,
                is_unknown_origin,
                is_outside_db,
                is_sweep,
                idle_or_away,
                post_site_window_active,
            )
            kill_chain_hit, chain_label = self._detect_kill_chain_sequence(
                lineage,
                parent_name,
                is_unknown_origin,
                is_temp_or_download,
                is_outside_db,
                post_site_window_active,
            )
            fanout_spike, baseline_note = self._update_and_check_process_baseline(proc_key, proc_conn_count, port)

            high_alert_multiplier = (
                1.35 if (idle_or_away and (is_sweep or is_unknown_origin)) else (1.15 if idle_or_away else 1.0)
            ) * coherence_factor

            counterfeit_hit = bool(
                (is_unknown_origin and is_outside_db and (port in EXFIL_SENSITIVE_PORTS or is_sweep))
                or (
                    self.last_site_checked_domain
                    and remote_ip not in watched_ips
                    and is_unknown_origin
                    and post_site_window_active
                )
            )

            weighted_points = 0.0
            active_weight_keys: list[str] = []
            step1_parts = [
                f"exe={proc_name}",
                f"origin={origin_note} ({wall_hint})",
                f"unknown_origin={is_unknown_origin}",
                f"lineage={lineage}",
                f"base=({baseline_note})",
            ]
            step2_parts = [
                f"state={'AWAY/LOCKED' if idle_or_away else 'ACTIVE'} ({int(idle_sec)}s)",
                f"hour={hour_str} (rarity={rare_hour_ratio:.0%})",
            ]
            step3_parts = [f"ip={remote_ip}:{port}", f"db={db_status}"]

            if is_trusted_pair and not has_guard and not is_sweep and not counterfeit_hit:
                self.memory["known_ip_database"].add(remote_ip)
                known_ips.add(remote_ip)
                known_drives.update(drives)
                strikes = self.runtime_strikes.get(pair_key, 0)
                pred_label, _, trajectory, proj_pct = self.predict_risk(pair_key, 0.0, 1.0)
                conf, rec_action, rationale = self._evaluate_decision_policy(
                    strikes=strikes,
                    proj_pct=proj_pct,
                    weighted_points=0.0,
                    is_unknown_origin=is_unknown_origin,
                    is_outside_db=is_outside_db,
                    is_sweep=False,
                    counterfeit_hit=False,
                    kill_chain_hit=False,
                    idle_or_away=idle_or_away,
                    is_trusted_pair=True,
                    coherence_label=coherence_label,
                )
                regret_str = self._estimate_action_regret(
                    proc_name, rec_action, is_unknown_origin, False, False, False, idle_or_away
                )
                cot = (
                    f"Chain-of-Thought [{proc_name} -> {remote_ip}:{port}]: "
                    f"1.Origin: Trusted pair/app ({baseline_note}) | "
                    f"2.Context: {step2_parts[0]}, {step2_parts[1]} | "
                    f"3.Destination: Approved in IP DB | "
                    f"4.Coherence & Trajectory: {coherence_label} / {trajectory} | "
                    f"5.Decision [{conf} conf -> {rec_action}]: {rationale} | "
                    f"6.Regret: {regret_str} | "
                    f"7.Verdict: Low risk, remembered baseline."
                )
                self.reasoning_by_key[pair_key] = cot
                self.signals_by_key[pair_key] = []
                return pair_key, "IN IP DB", pred_label, strikes, "Trusted", f"Remembered | {cot}", 0, proj_pct

            if (
                is_fresh_or_risky
                or is_unknown_origin
                or port in SUSPICIOUS_PORTS
                or is_temp_or_download
                or parent_name in SHELL_OR_SCRIPT_PARENTS
                or fanout_spike
            ):
                w_val = (
                    float(weights["risky_origin_or_port"])
                    * (1.25 if is_unknown_origin else 1.0)
                    * (1.15 if fanout_spike else 1.0)
                )
                weighted_points += w_val
                active_weight_keys.append("risky_origin_or_port")
                step1_parts.append(f"+{w_val:.2f} risky/unknown origin/port/parent/fanout")

            if kill_chain_hit:
                w_val = float(weights["kill_chain_sequence"])
                weighted_points += w_val
                active_weight_keys.append("kill_chain_sequence")
                step1_parts.append(f"+{w_val:.2f} KILL-CHAIN SEQUENCE ({chain_label})")

            if idle_or_away:
                w_val = float(weights["away_state"]) * (1.3 if is_sweep else 1.0)
                weighted_points += w_val
                active_weight_keys.append("away_state")
                step2_parts.append(f"+{w_val:.2f} {'away/locked HIGH ALERT' if is_sweep else 'away/idle'}")

            if unusual_hour:
                w_val = float(weights["off_hour"]) * (1.0 + 0.35 * rare_hour_ratio)
                weighted_points += w_val
                active_weight_keys.append("off_hour")
                step2_parts.append(f"+{w_val:.2f} off-habit hour")

            if is_sweep:
                w_val = float(weights["port_scan_sweep"]) * (1.25 if idle_or_away else 1.0)
                weighted_points += w_val
                active_weight_keys.append("port_scan_sweep")
                step3_parts.append(
                    f"+{w_val:.2f} MULTI-PORT SCAN SWEEP ({len(sweep_ports)} ports: {sweep_ports[:6]}, {sweep_hits} hits)"
                )

            if post_site_window_active and (is_new_proc or is_unknown_origin or browser_active):
                w_val = float(weights["post_site_anomaly"])
                weighted_points += w_val
                active_weight_keys.append("post_site_anomaly")
                step2_parts.append(
                    f"+{w_val:.2f} post-site anomaly (site={self.last_site_checked_domain}, new_proc={is_new_proc})"
                )

            new_drives = drives - known_drives
            if new_drives and known_drives:
                w_val = float(weights["cross_drive"])
                weighted_points += w_val
                active_weight_keys.append("cross_drive")
                step2_parts.append(f"+{w_val:.2f} cross-drive ({','.join(sorted(new_drives))})")
            known_drives.update(drives)

            if db_status == "PRIVATE/LOCAL IP":
                step3_parts.append("0.00 private/local destination")
            elif is_outside_db:
                w_val = float(weights["outside_ip_db"])
                weighted_points += w_val
                active_weight_keys.append("outside_ip_db")
                step3_parts.append(f"+{w_val:.2f} outside IP DB")
            else:
                step3_parts.append("0.00 in IP DB")

            if counterfeit_hit:
                w_val = float(weights["counterfeit_ip"])
                weighted_points += w_val
                active_weight_keys.append("counterfeit_ip")
                step3_parts.append(f"+{w_val:.2f} COUNTERFEIT/EXFIL-RISK SIGNAL")

            if remote_ip not in known_ips and not is_sweep and not counterfeit_hit:
                if is_standard_dir and not idle_or_away and len(known_ips) < 12:
                    known_ips.add(remote_ip)
                    self.memory["known_ip_database"].add(remote_ip)
                    db_status = "IN IP DB (LEARNED)"
                    step3_parts.append("auto-learned into DB")

            pred_label, trend, trajectory, proj_pct = self.predict_risk(pair_key, weighted_points, high_alert_multiplier)
            top_weight = max((float(weights.get(k, 0.0)) for k in active_weight_keys), default=0.0)
            cf_score = max(0.0, weighted_points - top_weight)
            cf_pct = int(round(max(0.0, min(100.0, ((cf_score * high_alert_multiplier) / 3.2) * 100.0))))
            counterfactual_str = (
                f"dropping top signal (~{top_weight:.2f}) lowers risk from ~{int(round(proj_pct))}% to ~{cf_pct}%"
            )

            surge_bump = 1 if (trajectory == "Escalating Surge" and weighted_points >= 1.8) else 0
            computed_strikes = min(
                3,
                int(round(weighted_points * (1.15 if idle_or_away and is_sweep else 1.0))) + surge_bump,
            )
            prev_strikes = self.runtime_strikes.get(pair_key, 0)
            strikes = min(3, max(prev_strikes, computed_strikes))
            self.runtime_strikes[pair_key] = strikes

            conf, rec_action, rationale = self._evaluate_decision_policy(
                strikes=strikes,
                proj_pct=proj_pct,
                weighted_points=weighted_points,
                is_unknown_origin=is_unknown_origin,
                is_outside_db=is_outside_db,
                is_sweep=is_sweep,
                counterfeit_hit=counterfeit_hit,
                kill_chain_hit=kill_chain_hit,
                idle_or_away=idle_or_away,
                is_trusted_pair=is_trusted_pair,
                coherence_label=coherence_label,
            )
            regret_str = self._estimate_action_regret(
                proc_name, rec_action, is_unknown_origin, is_sweep, counterfeit_hit, kill_chain_hit, idle_or_away
            )
            meets_conf_threshold = CONFIDENCE_RANK.get(conf, 1) >= min_conf_rank

            verdict = (
                "HIGH-ALERT SCAN / EXFIL / COUNTERFEIT"
                if counterfeit_hit or (is_sweep and idle_or_away) or strikes == 3
                else (
                    "KILL-CHAIN / UNKNOWN-ORIGIN ALERT"
                    if kill_chain_hit and is_unknown_origin
                    else (
                        "MULTI-PORT SCAN DETECTED"
                        if is_sweep
                        else (
                            "POST-SITE / UNKNOWN-ORIGIN ALERT"
                            if post_site_window_active and is_unknown_origin
                            else (
                                "GUARD WATCH"
                                if strikes >= 2
                                else ("WATCHING TREND" if trend == "Rising" else "NORMAL/OBSERVED")
                            )
                        )
                    )
                )
            )
            cot = (
                f"Chain-of-Thought [{proc_name} -> {remote_ip}:{port}]: "
                f"1.Origin: {'; '.join(step1_parts)} | "
                f"2.Context: {'; '.join(step2_parts)} | "
                f"3.Destination: {'; '.join(step3_parts)} | "
                f"4.Coherence & Trajectory: {coherence_label} / {trajectory} | "
                f"5.Counterfactual: {counterfactual_str} | "
                f"6.Decision [{conf} conf -> {rec_action}]: {rationale} | "
                f"7.Regret: {regret_str} | "
                f"8.Forecast & Verdict: weighted={weighted_points:.2f} (x{high_alert_multiplier:.2f}), "
                f"pred={pred_label}, verdict={verdict}."
            )
            self.reasoning_by_key[pair_key] = cot
            self.signals_by_key[pair_key] = active_weight_keys

            should_open_guard = (
                not guards_paused_now
                and meets_conf_threshold
                and (
                    strikes >= 2
                    or is_sweep
                    or counterfeit_hit
                    or kill_chain_hit
                    or rec_action in ("OPEN_GUARD", "CONTAIN_OR_STOP")
                    or trajectory == "Escalating Surge"
                    or (trend == "Rising" and weighted_points >= 2.0)
                )
            )
            if should_open_guard and not has_guard:
                self.guard_posts[exe_guard_key] = {
                    "hits": 1,
                    "lineage": lineage,
                    "pair_key": pair_key,
                    "hash": current_hash,
                    "last_remote": f"{remote_ip}:{port}",
                }
                guard_status = "STANDING GUARD"
                self.append_guard_log(
                    "GUARD POST OPENED",
                    exe_guard_key,
                    f"{proc_name} -> {remote_ip}:{port} [{db_status}, action={rec_action}, pred={pred_label}, verdict={verdict}] | {wall_hint}",
                )
                prefix = (
                    "HIGH-ALERT SCAN/COUNTERFEIT"
                    if (counterfeit_hit or (is_sweep and idle_or_away) or strikes == 3)
                    else "GUARD POST OPENED"
                )
                self._pending_alerts.append(
                    (
                        f"[{prefix} @ {hour_str}] {proc_name} -> {remote_ip}:{port} ({db_status}, {pred_label}, {rec_action}) | {verdict} | Origin: {lineage}",
                        bool(counterfeit_hit or is_sweep or strikes == 3),
                        bool(idle_or_away and (is_sweep or is_unknown_origin)),
                    )
                )
            elif (strikes >= 2 or is_sweep or kill_chain_hit) and meets_conf_threshold:
                self._pending_alerts.append(
                    (
                        f"[{strikes} STRIKES | {pred_label} @ {hour_str}] {proc_name} -> {remote_ip}:{port} ({db_status}, {rec_action}) | {verdict}",
                        bool(counterfeit_hit or is_sweep or kill_chain_hit),
                        bool(idle_or_away and is_sweep),
                    )
                )

            auto_contained = False
            if (
                self.auto_contain_enabled
                and meets_conf_threshold
                and is_unknown_origin
                and not is_approved_exe
                and not is_trusted_pair
                and (
                    rec_action == "CONTAIN_OR_STOP"
                    or strikes >= 3
                    or counterfeit_hit
                    or (idle_or_away and is_sweep)
                    or (kill_chain_hit and strikes >= 2)
                )
            ):
                auto_contained = True

            summary = f"[{rec_action}/{conf}] {verdict} | {trajectory} | {wall_hint} || Lineage: {lineage}"
            return pair_key, db_status, pred_label, strikes, guard_status, summary, (1 if auto_contained else 0), proj_pct

    def _worker_loop(self) -> None:
        while not self._stop_worker.is_set():
            self._scan_requested.wait(timeout=GUI_REFRESH_MS / 1000)
            self._scan_requested.clear()
            if self._stop_worker.is_set():
                break
            try:
                result = self._scan_once()
                result["scan_duration_ms"] = round((time.time() - self._scan_started_at) * 1000, 1)
                self._last_worker_error = ""
            except Exception as exc:
                error_text = f"{type(exc).__name__}: {exc}"
                result = {"error": error_text}
                self._last_worker_error = error_text
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
        with self._lock:
            away = idle_sec >= IDLE_AWAY_SECONDS or self.session_logged_out_or_locked
            hours = self.memory["active_hours"]
            hour_counts = self.memory.setdefault("hour_counts", {})
            unusual = bool(not away and len(hours) >= 4 and hour_str not in hours)
            if not away:
                hours.add(hour_str)
                hour_counts[hour_str] = int(hour_counts.get(hour_str, 0)) + 1
            total_hour_obs = max(1, sum(int(v) for v in hour_counts.values()))
            this_hour_obs = int(hour_counts.get(hour_str, 0))
            rare_hour_ratio = max(0.0, min(1.0, 1.0 - (this_hour_obs / total_hour_obs)))
            post_site_active = (time.time() - self.last_site_check_ts) <= POST_SITE_WATCH_SECONDS and bool(
                self.last_site_checked_domain
            )

        proc_meta: dict[int, tuple] = {}
        connections = []
        browser_active = False
        if psutil is not None:
            for proc in psutil.process_iter(["pid", "name", "exe"]):
                try:
                    info = proc.info
                    pname = info.get("name") or "unknown"
                    if pname.lower() in BROWSER_PROCESS_NAMES:
                        browser_active = True
                    exe = info.get("exe") or ""
                    lineage, parent = format_lineage(proc)
                    origin, risky, wall, unk_origin = inspect_origin_health(exe)
                    proc_meta[info["pid"]] = (
                        pname,
                        exe,
                        self.inspect_proc_drives(proc, exe),
                        lineage,
                        parent,
                        origin,
                        risky,
                        wall,
                        unk_origin,
                    )
                except Exception:
                    continue
            try:
                connections = psutil.net_connections(kind="inet")
            except Exception:
                connections = []

        established_conns = []
        proc_conn_counts: dict[str, int] = {}
        if psutil is not None:
            scan_visible_states = {
                psutil.CONN_ESTABLISHED,
                getattr(psutil, "CONN_SYN_RECV", "SYN_RECV"),
            }
            for conn in connections:
                # Include inbound half-open TCP sessions as well as established sessions.
                # This improves visibility into connection sweeps; some Windows builds do
                # not expose a PID for SYN_RECV, so unknown ownership is still recorded.
                if conn.status not in scan_visible_states or not conn.raddr:
                    continue
                meta = proc_meta.get(
                    conn.pid,
                    ("unknown", "", set(), "unknown", "unknown", "No metadata", True, "Origin hidden", True),
                )
                name, exe = meta[0], meta[1]
                pkey = f"{name.lower()}|{exe.lower()}"
                proc_conn_counts[pkey] = proc_conn_counts.get(pkey, 0) + 1
                established_conns.append((conn, meta, pkey))

        rows = []
        auto_contain_candidates: list[tuple[int, str, str]] = []
        self._scan_generation += 1
        self._scan_started_at = time.time()
        observed_candidate_pids: set[int] = set()
        unknown_origin_hits = 0
        high_risk_rows = 0
        max_proj_pct = 0.0

        for conn, meta, pkey in established_conns:
            name, exe, drives, lineage, parent, origin, fresh, wall, unk_origin = meta
            if unk_origin:
                unknown_origin_hits += 1
            ip, port = conn.raddr.ip, conn.raddr.port
            key, db, prediction, strikes, guard, summary, auto_flag, proj_pct = self.score_event(
                name,
                exe,
                lineage,
                parent,
                origin,
                fresh,
                wall,
                unk_origin,
                ip,
                port,
                drives,
                idle_sec,
                hour_str,
                unusual,
                rare_hour_ratio,
                proc_conn_counts.get(pkey, 1),
                post_site_active,
                browser_active,
            )
            max_proj_pct = max(max_proj_pct, proj_pct)
            if strikes >= 2 or proj_pct >= 60.0:
                high_risk_rows += 1
            if auto_flag and conn.pid:
                pname_lower = name.lower()
                if pname_lower not in SAFE_AUTO_CONTAIN_DENYLIST:
                    candidate_pid = int(conn.pid)
                    if candidate_pid not in observed_candidate_pids:
                        observed_candidate_pids.add(candidate_pid)
                        confirmations = self._contain_confirmations.get(candidate_pid, 0) + 1
                        self._contain_confirmations[candidate_pid] = confirmations
                        last_action = self._contain_last_action.get(candidate_pid, 0.0)
                        if confirmations >= AUTO_CONTAIN_CONFIRM_SCANS and (time.time() - last_action) >= AUTO_CONTAIN_COOLDOWN_SECONDS:
                            auto_contain_candidates.append((candidate_pid, name, key))
            
            if strikes > 0 or guard in ("STANDING GUARD", "GUARD PAUSED") or key in self.memory["trusted_pairs"]:
                rows.append(
                    (
                        strikes,
                        conn.pid,
                        name,
                        ip,
                        db,
                        port,
                        ", ".join(sorted(drives)) or "N/A",
                        prediction,
                        guard,
                        summary,
                        key,
                    )
                )

        if auto_contain_candidates:
            deduped = {}
            for candidate in auto_contain_candidates:
                deduped.setdefault(candidate[0], candidate)
            auto_contain_candidates = list(deduped.values())

        for stale_pid in list(self._contain_confirmations):
            if stale_pid not in observed_candidate_pids:
                self._contain_confirmations[stale_pid] = max(0, self._contain_confirmations[stale_pid] - 1)
                if self._contain_confirmations[stale_pid] == 0:
                    self._contain_confirmations.pop(stale_pid, None)

        if unknown_origin_hits == 0 and high_risk_rows == 0:
            self.decay_weights_toward_default()

        if unknown_origin_hits >= 5 or high_risk_rows >= 3 or max_proj_pct >= 75.0:
            posture = "ELEVATED"
        elif unknown_origin_hits > 0 or high_risk_rows > 0 or max_proj_pct >= 40.0:
            posture = "GUARDED"
        else:
            posture = "CALM"

        rows.sort(key=lambda r: (r[8] == "STANDING GUARD", r[0], r[2]), reverse=True)
        with self._lock:
            db_count = len(self.memory["known_ip_database"])
            guard_count = len(self.guard_posts)
            weight_val = self.memory["learning_weights"].get("outside_ip_db", 1.0)
            scan_weight = self.memory["learning_weights"].get("port_scan_sweep", 1.65)
            hours_count = len(self.memory["active_hours"])

        return {
            "rows": rows[:160],
            "now": now,
            "idle": idle_sec,
            "away": away,
            "hours": hours_count,
            "db": db_count,
            "guards": guard_count,
            "weight": weight_val,
            "scan_weight": scan_weight,
            "unknown_hits": unknown_origin_hits,
            "auto_contain_candidates": auto_contain_candidates,
            "posture": posture,
            "peak_risk_pct": int(round(max_proj_pct)),
        }

    def request_scan(self) -> None:
        self._scan_requested.set()

    def on_close(self) -> None:
        self._stop_worker.set()
        self._scan_requested.set()
        with self._lock:
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

        tab_strip = ttk.Notebook(self.root, padding=(10, 0, 10, 6))
        tab_strip.pack(fill=tk.X)

        tab_process = ttk.Frame(tab_strip, padding=(6, 6))
        tab_policy = ttk.Frame(tab_strip, padding=(6, 6))
        tab_storage = ttk.Frame(tab_strip, padding=(6, 6))

        tab_strip.add(tab_process, text="Process & Guard")
        tab_strip.add(tab_policy, text="Policy, Mode & Site")
        tab_strip.add(tab_storage, text="Weights & Storage")

        # Tab 1: Row-targeted process & guard controls
        ttk.Button(tab_process, text="Trust & Learn (-Weight)", command=self.trust_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(tab_process, text="Post Guard Watch", command=self.post_guard_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(tab_process, text="Patch & Lift Guard", command=self.patch_and_lift_guard).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(tab_process, text="Strike +1 (Reinforce)", command=self.flag_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(tab_process, text="Inspect & Examine", command=self.inspect_selected_process).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(tab_process, text="Stop Process", command=self.stop_selected_process).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(tab_process, text="Scan Now", command=self.request_scan).pack(side=tk.LEFT)

        # Tab 2: Policy thresholds, alert/guard modes, and site verification
        ttk.Label(tab_policy, text="Min Conf:").pack(side=tk.LEFT, padx=(0, 4))
        self.conf_combo = ttk.Combobox(tab_policy, values=["Low", "Medium", "High"], state="readonly", width=8)
        self.conf_combo.set("Low")
        self.conf_combo.bind("<<ComboboxSelected>>", self.on_confidence_threshold_changed)
        self.conf_combo.pack(side=tk.LEFT, padx=(0, 10))

        self.mute_btn = ttk.Button(tab_policy, text="Mute Beeps", command=self.toggle_mute)
        self.mute_btn.pack(side=tk.LEFT, padx=(0, 6))

        self.pause_guards_btn = ttk.Button(tab_policy, text="Pause Guards", command=self.toggle_pause_guards)
        self.pause_guards_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.away_mode_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            tab_policy,
            text="Logged-Out / High-Alert Mode",
            variable=self.away_mode_var,
            command=self.toggle_logged_out_mode,
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.auto_contain_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            tab_policy,
            text="Auto-Contain (3 scans; excludes critical/browser apps)",
            variable=self.auto_contain_var,
            command=self.toggle_auto_contain,
        ).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(tab_policy, text="Verify Site:").pack(side=tk.LEFT, padx=(0, 4))
        self.domain_entry = ttk.Entry(tab_policy, width=18)
        self.domain_entry.insert(0, "yahoo.com")
        self.domain_entry.pack(side=tk.LEFT, padx=(0, 4))
        ttk.Button(tab_policy, text="Learn & Check Site", command=self.learn_and_check_site).pack(side=tk.LEFT)

        # Tab 3: Weight tuning, exports, and persistence
        ttk.Button(tab_storage, text="Weights", command=self.inspect_or_reset_weights).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(tab_storage, text="Export Snapshot", command=self.export_reasoning_snapshot).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(tab_storage, text="Save Memory & Log", command=self.save_all_now).pack(side=tk.LEFT)

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
        tree_frame = ttk.Frame(self.root)
        tree_frame.pack(fill=tk.BOTH, expand=True, padx=10)
        self.tree = ttk.Treeview(tree_frame, columns=columns, show="headings", height=10)
        tree_scroll_y = ttk.Scrollbar(tree_frame, orient=tk.VERTICAL, command=self.tree.yview)
        tree_scroll_x = ttk.Scrollbar(tree_frame, orient=tk.HORIZONTAL, command=self.tree.xview)
        self.tree.configure(yscrollcommand=tree_scroll_y.set, xscrollcommand=tree_scroll_x.set)
        col_specs = [
            ("pid", 58),
            ("process", 155),
            ("remote_ip", 125),
            ("db_status", 130),
            ("port", 60),
            ("drives", 85),
            ("pred_risk", 95),
            ("strikes", 65),
            ("guard", 125),
            ("summary_and_origin", 680),
        ]
        for col, width in col_specs:
            self.tree.heading(col, text=col.upper())
            self.tree.column(col, width=width, anchor=tk.W)
        self.tree.bind("<<TreeviewSelect>>", self.on_row_selected)
        self.tree.grid(row=0, column=0, sticky="nsew")
        tree_scroll_y.grid(row=0, column=1, sticky="ns")
        tree_scroll_x.grid(row=1, column=0, sticky="ew")
        tree_frame.rowconfigure(0, weight=1)
        tree_frame.columnconfigure(0, weight=1)

        cot_frame = ttk.LabelFrame(
            self.root,
            text="Evidence Trace, Decision Rationale, Counterfactual & Risk Forecast",
            padding=6,
        )
        cot_frame.pack(fill=tk.X, padx=10, pady=(6, 4))
        self.cot_var = tk.StringVar(
            value="Select a row above to inspect evidence signals, decision rationale, regret analysis, learned weights, and trend forecast."
        )
        ttk.Label(cot_frame, textvariable=self.cot_var, font=("Consolas", 9), wraplength=1530, justify=tk.LEFT).pack(
            anchor=tk.W
        )

        lower = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        lower.pack(fill=tk.BOTH, expand=False, padx=10, pady=(2, 10))

        guard_frame = ttk.LabelFrame(lower, text="Active Guard Posts, Scan Sweeps & Patch Log", padding=6)
        self.guard_log_box = tk.Listbox(guard_frame, height=8, font=("Consolas", 9))
        self.guard_log_box.pack(fill=tk.BOTH, expand=True)
        lower.add(guard_frame, weight=1)

        alert_frame = ttk.LabelFrame(lower, text="Big Brother High-Alert, Scan & Counterfeit Feed", padding=6)
        self.alert_list = tk.Listbox(alert_frame, height=8, font=("Consolas", 9))
        self.alert_list.pack(fill=tk.BOTH, expand=True)
        lower.add(alert_frame, weight=1)

    def inspect_or_reset_weights(self) -> None:
        with self._lock:
            lines = [f"{k}: {float(v):.3f} (default {DEFAULT_WEIGHTS.get(k, 1.0):.2f})" for k, v in self.memory["learning_weights"].items()]
        reset = messagebox.askyesno(
            "Learning Weights",
            "Current Learning Weights:\n\n"
            + "\n".join(lines)
            + "\n\nReset all weights back to DEFAULT_WEIGHTS?",
            parent=self.root,
        )
        if reset:
            with self._lock:
                self.memory["learning_weights"] = dict(DEFAULT_WEIGHTS)
                self.save_memory()
            self.queue_alert("[WEIGHTS RESET] Restored DEFAULT_WEIGHTS.", counterfeit_beep=False)
            self.flush_alerts_to_gui()
            self.request_scan()

    def on_confidence_threshold_changed(self, _event: object = None) -> None:
        chosen = self.conf_combo.get().strip()
        if chosen in CONFIDENCE_RANK:
            with self._lock:
                self.min_action_confidence = chosen
            self.queue_alert(f"[POLICY] Minimum action confidence threshold set to {chosen}.", counterfeit_beep=False)
            self.flush_alerts_to_gui()
            self.request_scan()

    def export_reasoning_snapshot(self) -> None:
        FORENSICS_DIR.mkdir(exist_ok=True)
        out_path = FORENSICS_DIR / f"snapshot_{int(time.time())}.json"
        with self._lock:
            snapshot = {
                "exported_at": datetime.now().isoformat(timespec="seconds"),
                "min_action_confidence": self.min_action_confidence,
                "learning_weights": dict(self.memory.get("learning_weights", {})),
                "active_guards": dict(self.guard_posts),
                "recent_scans": list(self.memory.get("scan_history", [])[-25:]),
                "reasoning_traces": dict(list(self.reasoning_by_key.items())[-100:]),
                "feedback_events": list(self.memory.get("feedback_events", [])[-100:]),
                "model_metrics": dict(self.memory.get("model_metrics", {})),
                "containment_policy": {
                    "confirmation_scans": AUTO_CONTAIN_CONFIRM_SCANS,
                    "cooldown_seconds": AUTO_CONTAIN_COOLDOWN_SECONDS,
                    "protected_processes": sorted(SAFE_AUTO_CONTAIN_DENYLIST),
                },
            }
        try:
            self._atomic_json_write(out_path, snapshot)
            self.queue_alert(f"[SNAPSHOT EXPORTED] Saved {out_path.name}", counterfeit_beep=False)
            self.flush_alerts_to_gui()
            messagebox.showinfo("Snapshot Exported", f"Saved snapshot to:\n{out_path}", parent=self.root)
        except OSError as exc:
            messagebox.showerror("Export Failed", str(exc), parent=self.root)

    def toggle_mute(self) -> None:
        with self._lock:
            self.muted = not self.muted
            is_muted = self.muted
        self.mute_btn.config(text="Unmute Beeps" if is_muted else "Mute Beeps")
        self.queue_alert(f"[AUDIO] Alert beep sound {'MUTED' if is_muted else 'UNMUTED'}.", counterfeit_beep=False)
        self.flush_alerts_to_gui()

    def toggle_pause_guards(self) -> None:
        with self._lock:
            self.guards_paused = not self.guards_paused
            paused = self.guards_paused
        self.pause_guards_btn.config(text="Resume Guards" if paused else "Pause Guards")
        self.queue_alert(f"[GUARDS] Auto-guard escalation {'PAUSED' if paused else 'ACTIVE'}.", counterfeit_beep=False)
        self.flush_alerts_to_gui()
        self.request_scan()

    def toggle_logged_out_mode(self) -> None:
        with self._lock:
            self.session_logged_out_or_locked = bool(self.away_mode_var.get())
            state_label = "LOGGED_OUT_HIGH_ALERT" if self.session_logged_out_or_locked else "ACTIVE_SESSION"
            self.memory["session_history"].append(
                {"event": state_label, "time": datetime.now().isoformat(timespec="seconds")}
            )
            self.save_memory()
        self.queue_alert(
            f"[MODE CHANGE] Logged-Out / High-Alert mode {'ENABLED' if self.session_logged_out_or_locked else 'DISABLED'}.",
            counterfeit_beep=self.session_logged_out_or_locked,
            high_priority=self.session_logged_out_or_locked,
        )
        self.flush_alerts_to_gui()
        self.request_scan()

    def toggle_auto_contain(self) -> None:
        with self._lock:
            self.auto_contain_enabled = bool(self.auto_contain_var.get())
        self.queue_alert(
            f"[AUTO-CONTAIN] Automated containment for high-severity unknown scan/exfil {'ENABLED' if self.auto_contain_enabled else 'DISABLED'}.",
            counterfeit_beep=False,
            high_priority=False,
        )
        self.flush_alerts_to_gui()

    def save_all_now(self) -> None:
        self.save_memory()
        self.save_guard_log()

    def on_row_selected(self, _event: object = None) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        with self._lock:
            key = self.row_keys.get(sel[0])
            cot = self.reasoning_by_key.get(key) if key else None
        if cot:
            self.cot_var.set(cot)

    def queue_alert(self, message: str, counterfeit_beep: bool = False, high_priority: bool = False) -> None:
        with self._lock:
            self._pending_alerts.append((message, counterfeit_beep, high_priority))

    def flush_alerts_to_gui(self) -> None:
        with self._lock:
            pending = list(self._pending_alerts)
            self._pending_alerts.clear()
            muted = self.muted
        if not pending:
            return
        for message, counterfeit_beep, high_priority in pending:
            if not self.alert_list.size() or self.alert_list.get(0) != message:
                self.alert_list.insert(0, message)
                if self.alert_list.size() > 200:
                    self.alert_list.delete(200, tk.END)
                if (counterfeit_beep or high_priority) and self._last_beep_key != message:
                    self._last_beep_key = message
                    beep_beep_alert(high_priority=high_priority, muted=muted)

    def refresh_guard_log_box(self) -> None:
        with self._lock:
            guards_snapshot = list(self.guard_posts.items())
            log_snapshot = list(self.guard_log[-30:])
            scans_snapshot = list(self.memory.get("scan_history", [])[-10:])
        self.guard_log_box.delete(0, tk.END)
        for gkey, info in guards_snapshot:
            hits = info.get("hits", 0)
            remote = info.get("last_remote", "n/a")
            self.guard_log_box.insert(
                tk.END, f"[ACTIVE GUARD | hits={hits} | last={remote}] {gkey} | origin: {info.get('lineage', 'unknown')}"
            )
        for sc in reversed(scans_snapshot):
            self.guard_log_box.insert(
                tk.END,
                f"[SCAN SWEEP @ {sc.get('time')}] IP={sc.get('ip')} ports={sc.get('ports')} (away={sc.get('idle_or_away')})",
            )
        for entry in reversed(log_snapshot):
            self.guard_log_box.insert(
                tk.END,
                f"[{entry['time']}] {entry['status']} -> {entry['target']} ({entry['detail']})",
            )

    def learn_and_check_site(self) -> None:
        raw_dom = (
            self.domain_entry.get()
            .strip()
            .lower()
            .removeprefix("https://")
            .removeprefix("http://")
            .split("/")[0]
        )
        if not raw_dom:
            return
        with self._lock:
            self.last_site_check_ts = time.time()
            self.last_site_checked_domain = raw_dom
        self.status_var.set(f"Resolving {raw_dom} & watching for post-visit anomalies...")

        def job() -> None:
            resolved = resolve_domain_ips(raw_dom)
            if not resolved:
                msg = f"[SITE CHECK] Could not resolve {raw_dom} right now (post-visit watch active for {POST_SITE_WATCH_SECONDS}s)."
            else:
                with self._lock:
                    known = self.memory["watched_domains"].setdefault(raw_dom, set())
                    new_ips = resolved - known
                    known.update(resolved)
                    self.memory["known_ip_database"].update(resolved)
                    try:
                        self.save_memory()
                        msg = (
                            f"[IP DB & POST-SITE WATCH] {raw_dom} added {len(new_ips)} new IP(s) "
                            f"(DB={len(self.memory['known_ip_database'])}); watching for strange process behavior."
                        )
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

    def get_selected_item_info(self) -> tuple[str | None, int | None]:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("No Selection", "Select a row in the table first.", parent=self.root)
            return None, None
        item_id = sel[0]
        with self._lock:
            return self.row_keys.get(item_id), self.row_pids.get(item_id)

    def trust_selected(self) -> None:
        key, _ = self.get_selected_item_info()
        if not key:
            return
        proc_key, endpoint = key.split("->", 1)
        ip = endpoint.rsplit(":", 1)[0]
        with self._lock:
            active_signals = list(self.signals_by_key.get(key, []))
            self.memory["trusted_pairs"].add(key)
            self.memory["user_approved_exes"].add(proc_key)
            self.memory["seen_ips"].setdefault(proc_key, set()).add(ip)
            self.memory["known_ip_database"].add(ip)
            self.runtime_strikes[key] = 0
            self.record_feedback(key, "false_positive", "Operator trusted this process/destination pair.")
        self.queue_alert(f"[LEARNED & WEIGHTS TUNED DOWN] {ip} added to IP DB ({key})")
        self.request_scan()

    def post_guard_selected(self) -> None:
        key, _ = self.get_selected_item_info()
        if not key:
            return
        proc_key, endpoint = key.split("->", 1)
        exe_path = proc_key.split("|", 1)[1] if "|" in proc_key else proc_key
        gkey = exe_path or proc_key
        with self._lock:
            self.guard_posts.setdefault(
                gkey,
                {
                    "hits": 0,
                    "lineage": "manual guard post",
                    "pair_key": key,
                    "hash": self.cached_file_sha256(exe_path),
                    "last_remote": endpoint,
                },
            )
            self.append_guard_log("GUARD POST OPENED", gkey, f"Manual guard watch started for {key}")
        self.queue_alert(f"[MANUAL GUARD POST] Standing watch on {gkey} until patched.")
        self.request_scan()

    def patch_and_lift_guard(self) -> None:
        key, _ = self.get_selected_item_info()
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

        with self._lock:
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
        key, _ = self.get_selected_item_info()
        if not key:
            return
        with self._lock:
            active_signals = list(self.signals_by_key.get(key, []))
            new_strikes = min(3, self.runtime_strikes.get(key, 0) + 1)
            self.runtime_strikes[key] = new_strikes
            targets = active_signals or ["port_scan_sweep", "outside_ip_db", "counterfeit_ip", "kill_chain_sequence"]
            self.signals_by_key[key] = targets
            self.record_feedback(key, "confirmed_threat", "Operator manually reinforced this alert.")
        self.queue_alert(f"[STRIKE -> {new_strikes} | WEIGHTS REINFORCED] {key}", counterfeit_beep=(new_strikes == 3))
        self.request_scan()

    def inspect_selected_process(self) -> None:
        """
        Deep examination of a selected process: lineage, open files, active network destinations,
        SHA-256, static header/string indicators, and saved forensics report.
        """
        key, pid = self.get_selected_item_info()
        if not key:
            return
        proc_key, endpoint = key.split("->", 1)
        proc_name, exe_path = (proc_key.split("|", 1) + [""])[:2]
        lineage_str = "unknown"
        cwd_str = "n/a"
        cmdline_str = "n/a"
        open_files_list: list[str] = []
        conns_list: list[str] = []

        if psutil is not None and pid is not None:
            try:
                proc = psutil.Process(pid)
                lineage_str, _ = format_lineage(proc)
                exe_path = exe_path or (proc.exe() or "")
                try:
                    cwd_str = proc.cwd()
                except Exception:
                    pass
                try:
                    cmdline_str = " ".join(proc.cmdline())[:300]
                except Exception:
                    pass
                try:
                    open_files_list = [f.path for f in proc.open_files()[:20]]
                except Exception:
                    pass
                try:
                    for c in proc.net_connections(kind="inet")[:20]:
                        r_addr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else "listening/none"
                        conns_list.append(f"{c.status} -> {r_addr}")
                except Exception:
                    pass
            except Exception as exc:
                lineage_str = f"Process lookup note: {exc}"

        sha256_val = self.cached_file_sha256(exe_path)
        static_info = extract_binary_indicators(exe_path)
        FORENSICS_DIR.mkdir(exist_ok=True)
        report_path = FORENSICS_DIR / f"inspect_{pid or 0}_{int(time.time())}.json"
        report_payload = {
            "inspected_at": datetime.now().isoformat(timespec="seconds"),
            "key": key,
            "pid": pid,
            "process_name": proc_name,
            "exe_path": exe_path,
            "sha256": sha256_val,
            "lineage": lineage_str,
            "cwd": cwd_str,
            "cmdline": cmdline_str,
            "active_connections": conns_list,
            "open_files": open_files_list,
            "static_indicators": static_info,
        }
        try:
            self._atomic_json_write(report_path, report_payload)
        except OSError:
            pass

        summary_text = (
            f"PID: {pid} | Process: {proc_name}\n"
            f"Path: {exe_path or 'HIDDEN / UNKNOWN'}\n"
            f"SHA-256: {sha256_val[:24] + '...' if sha256_val else 'N/A'}\n"
            f"Lineage: {lineage_str}\n"
            f"CWD: {cwd_str}\n"
            f"Connections ({len(conns_list)}): {', '.join(conns_list[:6]) or 'none'}\n"
            f"Open Files ({len(open_files_list)}): {', '.join(open_files_list[:5]) or 'none'}\n"
            f"Header: {static_info['header']} | Tokens: {', '.join(static_info['matched_tokens'][:3]) or 'none'}\n"
            f"Report saved: {report_path.name}"
        )
        with self._lock:
            self.reasoning_by_key[key] = f"INSPECTION [{proc_name} @ {endpoint}]: {summary_text.replace(chr(10), ' | ')}"
        self.cot_var.set(self.reasoning_by_key[key])
        self.append_guard_log(
            "DEEP INSPECTED", exe_path or proc_key, f"PID={pid}, conns={len(conns_list)}, sha256={sha256_val[:12]}"
        )
        messagebox.showinfo("Process Examination & Forensics", summary_text, parent=self.root)

    def stop_selected_process(self) -> None:
        key, pid = self.get_selected_item_info()
        if not key:
            return
        if psutil is None or pid is None:
            messagebox.showwarning("Unavailable", "psutil or valid PID is unavailable.", parent=self.root)
            return
        confirm = messagebox.askyesno(
            "Confirm Stop Process",
            f"Terminate process PID {pid} ({key})?\nOnly stop processes you have verified should not be running.",
            parent=self.root,
        )
        if not confirm:
            return
        try:
            proc = psutil.Process(pid)
            proc.terminate()
            try:
                proc.wait(timeout=3)
            except Exception:
                proc.kill()
            with self._lock:
                self.append_guard_log("PROCESS STOPPED", key, f"Terminated PID {pid} by operator request")
            self.queue_alert(f"[STOPPED PROCESS] Terminated PID {pid} for {key}", counterfeit_beep=True, high_priority=True)
            self.flush_alerts_to_gui()
            self.request_scan()
        except Exception as exc:
            messagebox.showerror("Stop Failed", f"Could not terminate PID {pid}: {exc}", parent=self.root)

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
                mode_tag = "HIGH-ALERT AWAY/LOCKED" if latest["away"] else "ACTIVE"
                with self._lock:
                    mute_tag = "MUTED" if self.muted else "AUDIO ON"
                    guard_mode_tag = "GUARDS PAUSED" if self.guards_paused else "GUARDS ACTIVE"
                self.status_var.set(
                    f"BIG BROTHER [{latest['posture']} / peak {latest['peak_risk_pct']}%] | "
                    f"{now.strftime('%H:%M:%S')} | {mode_tag} ({int(idle)}s) | {mute_tag} | {guard_mode_tag} | "
                    f"Unknown-Origin Conns: {latest['unknown_hits']} | IP DB: {latest['db']} | Guards: {latest['guards']} | "
                    f"Scan: {latest.get('scan_duration_ms', 0):.0f}ms"
                )
                self.habit_var.set(
                    f"Habit Hours: {latest['hours']}/24 | IP-DB Wt: {latest['weight']:.2f} | "
                    f"Scan Wt: {latest['scan_weight']:.2f} | psutil: {'OK' if psutil else 'FALLBACK'} | "
                    f"{self.get_learning_summary()}"
                )
                with self._lock:
                    selected_key = self.row_keys.get(self.tree.selection()[0]) if self.tree.selection() else None
                    for item in self.tree.get_children():
                        self.tree.delete(item)
                    self.row_keys.clear()
                    self.row_pids.clear()
                    for strikes, pid, name, ip, db, port, drives, pred, guard, summary, key in latest["rows"]:
                        item = self.tree.insert(
                            "", tk.END, values=(pid, name, ip, db, port, drives, pred, strikes, guard, summary)
                        )
                        self.row_keys[item] = key
                        self.row_pids[item] = pid
                        if selected_key == key:
                            self.tree.selection_set(item)

                for cand_pid, cand_name, cand_key in latest.get("auto_contain_candidates", []):
                    if psutil is not None:
                        try:
                            p_obj = psutil.Process(cand_pid)
                            # PID reuse guard: verify the process still has the expected name
                            # and is not a protected Windows/browser process before acting.
                            current_name = (p_obj.name() or "").lower()
                            if current_name != cand_name.lower() or current_name in SAFE_AUTO_CONTAIN_DENYLIST:
                                self._contain_confirmations.pop(cand_pid, None)
                                continue
                            p_obj.terminate()
                            self._contain_last_action[cand_pid] = time.time()
                            self._contain_confirmations.pop(cand_pid, None)
                            self.append_guard_log(
                                "AUTO-CONTAINED",
                                cand_key,
                                f"Terminated verified {cand_name} (PID {cand_pid}) after {AUTO_CONTAIN_CONFIRM_SCANS} consecutive scan confirmations",
                            )
                            self.queue_alert(
                                f"[AUTO-CONTAINED] Stopped verified {cand_name} (PID {cand_pid}) -> {cand_key}",
                                counterfeit_beep=True,
                                high_priority=True,
                            )
                        except Exception as exc:
                            self.append_guard_log("AUTO-CONTAIN FAILED", cand_key, f"PID={cand_pid}: {exc}")

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