import argparse
from collections import defaultdict, deque
from datetime import datetime, timezone
import ipaddress
import json
import os
from pathlib import Path
import signal
import subprocess
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from urllib.error import URLError
from urllib.request import Request, urlopen
import psutil

PROTECTED_NAMES = {
    "system",
    "system idle process",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "dwm.exe",
    "systemd",
    "init",
    "sshd",
    "python",
    "python3",
    "pythonw.exe",
    "bash",
    "zsh",
    "cmd.exe",
    "powershell.exe",
    "pwsh.exe",
}

COMMON_HIGH_SOCKET_NAMES = {
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "code.exe",
    "node.exe",
    "steam.exe",
    "spotify.exe",
}


class GeoIPTracer:
    """Caches and looks up world location, ISP, and ASN for remote IP addresses."""

    def __init__(self, cache_path: Path | None = None):
        self.cache_path = cache_path
        self.lock = threading.Lock()
        self.cache: dict[str, dict] = {}
        self._last_req_ts = 0.0
        self._backoff_until = 0.0
        self._load_cache()

    def _load_cache(self):
        if not self.cache_path or not self.cache_path.exists():
            return
        try:
            raw = json.loads(self.cache_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.cache = {str(k): v for k, v in raw.items() if isinstance(v, dict)}
        except (OSError, ValueError, TypeError):
            self.cache = {}

    def _save_cache(self):
        if not self.cache_path:
            return
        try:
            tmp = self.cache_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.cache, indent=2, sort_keys=True), encoding="utf-8")
            tmp.replace(self.cache_path)
        except OSError:
            pass

    @staticmethod
    def _classify_special_ip(ip_str: str) -> dict | None:
        cleaned = ip_str.strip("[]").split("%")[0]
        try:
            addr = ipaddress.ip_address(cleaned)
        except ValueError:
            return {"ip": ip_str, "country": "InvalidIP", "city": "", "region": "", "isp": "", "org": "", "as": "", "label": "Invalid-IP"}
        if addr.is_loopback:
            return {"ip": ip_str, "country": "Localhost", "city": "Loopback", "region": "", "isp": "Local", "org": "Loopback", "as": "", "label": "Localhost"}
        if addr.is_private:
            return {"ip": ip_str, "country": "LAN/Private", "city": "Private-Net", "region": "", "isp": "Private", "org": "RFC1918/ULA", "as": "", "label": "LAN/Private"}
        if addr.is_link_local:
            return {"ip": ip_str, "country": "Link-Local", "city": "Local-Link", "region": "", "isp": "Link-Local", "org": "", "as": "", "label": "Link-Local"}
        if addr.is_multicast:
            return {"ip": ip_str, "country": "Multicast", "city": "", "region": "", "isp": "", "org": "", "as": "", "label": "Multicast"}
        if addr.is_unspecified:
            return {"ip": ip_str, "country": "Unspecified", "city": "0.0.0.0/::", "region": "", "isp": "", "org": "", "as": "", "label": "Any-Addr"}
        return None

    def get_cached(self, ip_str: str) -> dict | None:
        special = self._classify_special_ip(ip_str)
        if special:
            return special
        with self.lock:
            return dict(self.cache[ip_str]) if ip_str in self.cache else None

    def lookup(self, ip_str: str, allow_network: bool = True) -> dict:
        special = self._classify_special_ip(ip_str)
        if special:
            return special

        with self.lock:
            if ip_str in self.cache:
                return dict(self.cache[ip_str])
            if not allow_network:
                return {
                    "ip": ip_str,
                    "country": "Unresolved",
                    "city": "",
                    "region": "",
                    "isp": "",
                    "org": "",
                    "as": "",
                    "label": f"Public:{ip_str}",
                }
            now = time.time()
            if now < self._backoff_until:
                return {
                    "ip": ip_str,
                    "country": "RateLimited",
                    "city": "",
                    "region": "",
                    "isp": "",
                    "org": "",
                    "as": "",
                    "label": f"RateLimit:{ip_str}",
                }
            elapsed = now - self._last_req_ts
            if elapsed < 1.35:
                time.sleep(1.35 - elapsed)
            self._last_req_ts = time.time()

        cleaned = ip_str.strip("[]").split("%")[0]
        url = f"http://ip-api.com/json/{cleaned}?fields=status,message,country,countryCode,regionName,city,isp,org,as,query"
        try:
            req = Request(url, headers={"User-Agent": "AgenticDefenderTracer/1.0"})
            with urlopen(req, timeout=4.0) as resp:
                data = json.loads(resp.read().decode("utf-8", errors="replace"))
            if data.get("status") == "success":
                country = data.get("country") or "Unknown"
                code = data.get("countryCode") or ""
                city = data.get("city") or ""
                region = data.get("regionName") or ""
                isp = data.get("isp") or ""
                org = data.get("org") or ""
                asn = data.get("as") or ""
                loc_part = f"{city}, {country}" if city and city != country else country
                if code and code not in loc_part:
                    loc_part = f"{loc_part} ({code})"
                record = {
                    "ip": ip_str,
                    "country": country,
                    "country_code": code,
                    "region": region,
                    "city": city,
                    "isp": isp,
                    "org": org,
                    "as": asn,
                    "label": loc_part,
                }
            else:
                record = {
                    "ip": ip_str,
                    "country": "LookupFail",
                    "city": "",
                    "region": "",
                    "isp": "",
                    "org": "",
                    "as": "",
                    "label": f"LookupFail:{ip_str}",
                }
        except (URLError, TimeoutError, OSError, ValueError) as exc:
            msg = str(exc)
            if "429" in msg:
                with self.lock:
                    self._backoff_until = time.time() + 60.0
            record = {
                "ip": ip_str,
                "country": "Offline/Err",
                "city": "",
                "region": "",
                "isp": "",
                "org": "",
                "as": "",
                "label": f"NetErr:{ip_str}",
            }

        with self.lock:
            self.cache[ip_str] = record
            self._save_cache()
        return dict(record)


class PredictiveForecaster:
    """Computes socket velocity, acceleration, damped projection, and ETA via trend analysis."""

    def __init__(self, horizon_sec: float = 10.0, damping: float = 0.85):
        self.horizon_sec = max(1.0, float(horizon_sec))
        self.damping = max(0.1, min(1.0, float(damping)))

    def forecast(self, samples: deque[tuple[float, int]]) -> dict[str, float]:
        """samples: deque of (epoch_seconds, socket_count)."""
        if len(samples) < 2:
            latest = float(samples[-1][1]) if samples else 0.0
            return {
                "slope_per_sec": 0.0,
                "accel_per_sec2": 0.0,
                "projected_sockets": round(latest, 1),
                "eta_25_sec": -1.0,
                "confidence": 0.2 if samples else 0.0,
                "trend_boost": 0.0,
            }

        pts = list(samples)
        t0 = pts[0][0]
        xs = [p[0] - t0 for p in pts]
        ys = [float(p[1]) for p in pts]

        n = len(xs)
        mean_x = sum(xs) / n
        mean_y = sum(ys) / n
        denom = sum((x - mean_x) ** 2 for x in xs)

        if denom <= 1e-6:
            slope = 0.0
        else:
            slope = sum((xs[i] - mean_x) * (ys[i] - mean_y) for i in range(n)) / denom

        accel = 0.0
        if n >= 4:
            mid = n // 2
            dt1 = max(1e-3, xs[mid] - xs[0])
            dt2 = max(1e-3, xs[-1] - xs[mid])
            s1 = (ys[mid] - ys[0]) / dt1
            s2 = (ys[-1] - ys[mid]) / dt2
            dt_mid = max(0.5, ((xs[mid] + xs[-1]) * 0.5) - ((xs[0] + xs[mid]) * 0.5))
            accel = (s2 - s1) / dt_mid

        latest_y = ys[-1]
        effective_slope = slope * self.damping + (accel * self.horizon_sec * 0.25)
        projected = max(0.0, latest_y + effective_slope * self.horizon_sec)

        eta_25 = -1.0
        if latest_y >= 25.0:
            eta_25 = 0.0
        elif slope > 1e-4:
            eta_25 = round((25.0 - latest_y) / slope, 1)

        confidence = round(min(0.99, 0.35 + (n / 20.0) * 0.55 + (0.09 if denom > 0.2 else 0.0)), 2)
        accel_boost = max(0.0, accel) * 1.25
        trend_boost = round(
            max(0.0, slope) * 2.0
            + accel_boost
            + (1.0 if projected >= 25.0 else 0.0),
            2,
        )

        return {
            "slope_per_sec": round(slope, 3),
            "accel_per_sec2": round(accel, 3),
            "projected_sockets": round(projected, 1),
            "eta_25_sec": eta_25,
            "confidence": confidence,
            "trend_boost": trend_boost,
        }


class AdaptiveWeightStore:
    """Maintains per-process learned weights with bounded reinforcement, gentle decay, and history."""

    def __init__(self, weights_path: Path):
        self.weights_path = weights_path
        self.weights: dict[str, float] = {}
        self.stats: dict[str, dict[str, int | float]] = {}
        self.load()

    def load(self):
        if not self.weights_path.exists():
            self.weights = {}
            self.stats = {}
            return
        try:
            raw = json.loads(self.weights_path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                if "weights" in raw and isinstance(raw["weights"], dict):
                    self.weights = {str(k).lower(): float(v) for k, v in raw["weights"].items()}
                    if isinstance(raw.get("stats"), dict):
                        self.stats = raw["stats"]
                else:
                    self.weights = {str(k).lower(): float(v) for k, v in raw.items()}
        except (OSError, ValueError, TypeError):
            self.weights = {}
            self.stats = {}

    def save(self):
        tmp = self.weights_path.with_suffix(".tmp")
        payload = {"weights": self.weights, "stats": self.stats}
        try:
            self.weights_path.parent.mkdir(parents=True, exist_ok=True)
            tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            tmp.replace(self.weights_path)
        except OSError:
            # A read-only profile directory must not stop live monitoring.
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass

    def _ensure_stat(self, key: str) -> dict[str, int | float]:
        if key not in self.stats or not isinstance(self.stats[key], dict):
            self.stats[key] = {"adjustments": 0, "alerts": 0, "containments": 0}
        return self.stats[key]

    def get_weight(self, proc_name: str) -> float:
        return round(self.weights.get(proc_name.lower(), 1.0), 3)

    def get_stat_summary(self, proc_name: str) -> dict[str, int | float]:
        st = self._ensure_stat(proc_name.lower())
        return {
            "weight": self.get_weight(proc_name),
            "adjustments": int(st.get("adjustments", 0)),
            "alerts": int(st.get("alerts", 0)),
            "containments": int(st.get("containments", 0)),
        }

    def adjust_weight(self, proc_name: str, delta: float, event_kind: str = "adjust"):
        key = proc_name.lower()
        current = self.weights.get(key, 1.0)
        updated = max(0.5, min(2.5, round(current + delta, 3)))
        self.weights[key] = updated
        st = self._ensure_stat(key)
        st["adjustments"] = int(st.get("adjustments", 0)) + 1
        if event_kind == "alert":
            st["alerts"] = int(st.get("alerts", 0)) + 1
        elif event_kind == "containment":
            st["containments"] = int(st.get("containments", 0)) + 1
        self.save()

    def decay_toward_baseline(self, step: float = 0.02):
        changed = False
        for key, val in list(self.weights.items()):
            if abs(val - 1.0) <= step:
                if val != 1.0:
                    self.weights[key] = 1.0
                    changed = True
            elif val > 1.0:
                self.weights[key] = round(max(1.0, val - step), 3)
                changed = True
            else:
                self.weights[key] = round(min(1.0, val + step), 3)
                changed = True
        if changed:
            self.save()

    def reset(self):
        self.weights = {}
        self.stats = {}
        self.save()


class BehavioralMemory:
    """Learns per-process behavioral baselines with bounded EMA statistics.

    The current observation is scored against the previous baseline before it is
    incorporated, reducing the chance that a sudden spike immediately teaches
    itself to look normal. The model is intentionally transparent and local.
    """

    FEATURES = ("sockets", "delta", "spread", "slope", "accel")

    def __init__(self, path: Path, alpha: float = 0.12):
        self.path = path
        self.alpha = max(0.02, min(0.5, float(alpha)))
        self.lock = threading.Lock()
        self.records: dict[str, dict] = {}
        self._load()

    @staticmethod
    def _key(name: str, exe: str | None) -> str:
        return f"{(name or 'unknown').lower()}|{(exe or '').lower()}"

    def _load(self):
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                self.records = {str(k): v for k, v in raw.items() if isinstance(v, dict)}
        except (OSError, ValueError, TypeError):
            self.records = {}

    def _save(self):
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp = self.path.with_suffix(".tmp")
            tmp.write_text(json.dumps(self.records, indent=2, sort_keys=True), encoding="utf-8")
            tmp.replace(self.path)
        except OSError:
            pass

    def observe(self, name: str, exe: str | None, features: dict[str, float]) -> dict:
        key = self._key(name, exe)
        with self.lock:
            rec = self.records.setdefault(key, {"n": 0, "mean": {}, "var": {}, "updated": None})
            n = int(rec.get("n", 0))
            deviations = []
            if n >= 8:
                for feature in self.FEATURES:
                    value = float(features.get(feature, 0.0))
                    mean = float(rec.get("mean", {}).get(feature, 0.0))
                    variance = max(float(rec.get("var", {}).get(feature, 0.0)), 1.0)
                    z = abs(value - mean) / (variance ** 0.5)
                    # Cap each feature contribution to prevent one noisy metric dominating.
                    deviations.append(min(4.0, z))
            anomaly = round(sum(deviations) / len(deviations), 2) if deviations else 0.0
            means = rec.setdefault("mean", {})
            variances = rec.setdefault("var", {})
            for feature in self.FEATURES:
                value = float(features.get(feature, 0.0))
                if n == 0:
                    means[feature] = value
                    variances[feature] = 1.0
                else:
                    old_mean = float(means.get(feature, value))
                    old_var = max(float(variances.get(feature, 1.0)), 0.25)
                    diff = value - old_mean
                    new_mean = old_mean + self.alpha * diff
                    # EMA variance update around the previous mean.
                    new_var = (1.0 - self.alpha) * (old_var + self.alpha * diff * diff)
                    means[feature] = round(new_mean, 4)
                    variances[feature] = round(max(0.25, new_var), 4)
            rec["n"] = n + 1
            rec["updated"] = datetime.now(timezone.utc).isoformat()
            self._save()
            return {"samples": n + 1, "deviation": anomaly, "ready": n >= 8}


class DefenderEngine:
    """Runs 24/7 in a background thread (or headless) with predictive, causal, geo, reboot-persistent & adaptive reasoning."""

    def __init__(
        self,
        work_dir: Path,
        mode: str = "auto",
        interval: float = 2.0,
        threshold: float = 8.0,
        auto_action: str = "suspend",
        horizon_sec: float = 10.0,
        grace_sec: float = 60.0,
        auto_remediate: bool = False,
        auto_rerun: bool = True,
        cli_overrides: set[str] | None = None,
    ):
        self.work_dir = work_dir
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.canary_dir = self.work_dir / "canary_tripwires"
        self.log_path = self.work_dir / "defender_events.jsonl"
        self.snapshots_path = self.work_dir / "forensic_snapshots.jsonl"
        self.state_path = self.work_dir / "session_state.json"
        self.weights_store = AdaptiveWeightStore(self.work_dir / "learned_weights.json")
        self.behavior_memory = BehavioralMemory(self.work_dir / "behavior_memory.json")
        self.risk_streaks: dict[int, int] = defaultdict(int)
        self.geo_tracer = GeoIPTracer(self.work_dir / "geoip_cache.json")
        self.forecaster = PredictiveForecaster(horizon_sec=horizon_sec)

        self.mode = mode  # "auto" or "manual"
        self.interval = max(0.5, interval)
        self.threshold = threshold
        self.auto_action = auto_action  # "suspend" or "terminate"
        self.grace_sec = max(5.0, float(grace_sec))
        self.auto_remediate = bool(auto_remediate)
        self.auto_rerun = bool(auto_rerun)

        self.stop_event = threading.Event()
        self.lock = threading.Lock()
        self.self_pid = os.getpid()
        self.parent_pid = os.getppid()

        self.pid_history: dict[int, deque[float]] = defaultdict(lambda: deque(maxlen=30))
        self.socket_series: dict[int, deque[tuple[float, int]]] = defaultdict(lambda: deque(maxlen=20))
        self.prev_sockets: dict[int, int] = {}
        self.last_acted: dict[int, float] = {}
        self.canary_states: dict[Path, tuple[float, float]] = {}
        self.alerted_canaries: set[tuple[str, float]] = set()
        self.recent_canary_events: deque[tuple[float, str, str]] = deque(maxlen=50)
        self.suspended_ledger: dict[int, dict] = {}
        self.allowed_processes: set[str] = set()
        self.rerun_targets: dict[str, dict] = {}
        self._rerun_attempted: set[str] = set()
        self.latest_rows: list[dict] = []
        self.latest_sockets_by_pid: dict[int, list[dict]] = {}
        self.latest_reasoning: dict[int, list[str]] = {}
        self.latest_counterfactuals: dict[int, dict] = {}
        self._cycle_count = 0

        self._load_persistent_state(cli_overrides or set())
        self.ensure_canaries()
        self.save_persistent_state()

    def _load_persistent_state(self, cli_overrides: set[str]):
        if not self.state_path.exists():
            return
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, TypeError):
            return
        if not isinstance(raw, dict):
            return

        settings = raw.get("settings", {})
        if isinstance(settings, dict):
            if "mode" not in cli_overrides and settings.get("mode") in ("auto", "manual"):
                self.mode = settings["mode"]
            if "interval" not in cli_overrides and isinstance(settings.get("interval"), (int, float)):
                self.interval = max(0.5, float(settings["interval"]))
            if "threshold" not in cli_overrides and isinstance(settings.get("threshold"), (int, float)):
                self.threshold = float(settings["threshold"])
            if "auto_action" not in cli_overrides and settings.get("auto_action") in ("suspend", "terminate"):
                self.auto_action = settings["auto_action"]
            if "horizon_sec" not in cli_overrides and isinstance(settings.get("horizon_sec"), (int, float)):
                self.forecaster.horizon_sec = max(1.0, float(settings["horizon_sec"]))
            if "grace_sec" not in cli_overrides and isinstance(settings.get("grace_sec"), (int, float)):
                self.grace_sec = max(5.0, float(settings["grace_sec"]))
            if "auto_remediate" not in cli_overrides and isinstance(settings.get("auto_remediate"), bool):
                self.auto_remediate = settings["auto_remediate"]
            if "auto_rerun" not in cli_overrides and isinstance(settings.get("auto_rerun"), bool):
                self.auto_rerun = settings["auto_rerun"]

        allowed = raw.get("allowed_processes", [])
        if isinstance(allowed, list):
            self.allowed_processes = {str(x).lower() for x in allowed if x}

        targets = raw.get("rerun_targets", {})
        if isinstance(targets, dict):
            for k, v in targets.items():
                if isinstance(v, dict):
                    self.rerun_targets[str(k).lower()] = dict(v)

    def save_persistent_state(self):
        with self.lock:
            payload = {
                "updated_at": datetime.now(timezone.utc).isoformat(),
                "settings": {
                    "mode": self.mode,
                    "interval": self.interval,
                    "threshold": self.threshold,
                    "auto_action": self.auto_action,
                    "horizon_sec": self.forecaster.horizon_sec,
                    "grace_sec": self.grace_sec,
                    "auto_remediate": self.auto_remediate,
                    "auto_rerun": self.auto_rerun,
                },
                "allowed_processes": sorted(self.allowed_processes),
                "rerun_targets": self.rerun_targets,
            }
        try:
            tmp = self.state_path.with_suffix(".tmp")
            tmp.write_text(json.dumps(payload, indent=2, sort_keys=True), encoding="utf-8")
            tmp.replace(self.state_path)
        except OSError:
            pass

    def allow_and_track_process(self, pid: int, name: str, register_rerun: bool = True) -> dict:
        key = name.lower()
        exe_path = None
        cmdline = []
        if pid >= 0:
            try:
                proc = psutil.Process(pid)
                try:
                    exe_path = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                try:
                    cmdline = proc.cmdline()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            except psutil.NoSuchProcess:
                pass

        with self.lock:
            self.allowed_processes.add(key)
            self.suspended_ledger.pop(pid, None)
            self.weights_store.adjust_weight(name, -0.15, event_kind="allow_selection")
            if register_rerun:
                existing = self.rerun_targets.get(key, {})
                self.rerun_targets[key] = {
                    "name": name,
                    "exe": exe_path or existing.get("exe"),
                    "cmdline": cmdline or existing.get("cmdline") or [],
                    "enabled": True,
                    "selected_at": datetime.now(timezone.utc).isoformat(),
                }
        self.save_persistent_state()
        self.log_event(
            "INFO",
            "PERSIST_ALLOW_RUN",
            f"Saved '{name}' (PID {pid}) as ALLOWED (non-blocked) & rerun-eligible across reboots.",
            meta={"pid": pid, "process": name, "exe": exe_path, "rerun": register_rerun},
        )
        return self.rerun_targets.get(key, {"name": name, "exe": exe_path, "cmdline": cmdline})

    def remove_saved_selection(self, proc_name: str):
        key = proc_name.lower()
        with self.lock:
            self.allowed_processes.discard(key)
            self.rerun_targets.pop(key, None)
        self.save_persistent_state()
        self.log_event("INFO", "PERSIST_REMOVE", f"Removed saved allow/rerun selection for '{proc_name}'.")

    def _is_process_running_by_name(self, proc_name: str) -> bool:
        target = proc_name.lower()
        for proc in psutil.process_iter(["name"]):
            try:
                if (proc.info.get("name") or "").lower() == target:
                    return True
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        return False

    def rerun_saved_selections(self, force: bool = False) -> list[str]:
        """Automatically reruns user-selected processes that were marked to run and are not currently active."""
        with self.lock:
            if not self.auto_rerun and not force:
                return []
            candidates = list(self.rerun_targets.items())

        launched: list[str] = []
        for key, item in candidates:
            if not item.get("enabled", True):
                continue
            if not force and key in self._rerun_attempted:
                continue
            self._rerun_attempted.add(key)

            pname = str(item.get("name") or key)
            if pname.lower() in PROTECTED_NAMES:
                continue
            if self._is_process_running_by_name(pname):
                continue

            exe = item.get("exe")
            cmdline = item.get("cmdline") if isinstance(item.get("cmdline"), list) else []
            cmd_to_run: list[str] | None = None
            if exe and Path(str(exe)).is_file():
                # Avoid re-invoking Python scripts blindly unless explicit safe exe path exists
                if len(cmdline) > 1 and Path(str(cmdline[0])).name.lower() == Path(str(exe)).name.lower():
                    cmd_to_run = [str(x) for x in cmdline]
                else:
                    cmd_to_run = [str(exe)]

            if not cmd_to_run:
                continue

            try:
                subprocess.Popen(
                    cmd_to_run,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    start_new_session=True,
                )
                launched.append(pname)
                self.log_event(
                    "INFO",
                    "AUTO_RERUN",
                    f"Automatically restarted user-selected process '{pname}' ({' '.join(cmd_to_run)}).",
                    meta={"process": pname, "cmd": cmd_to_run},
                )
            except (OSError, ValueError) as exc:
                self.log_event("WARN", "AUTO_RERUN_FAIL", f"Could not rerun '{pname}': {exc}")

        return launched

    def record_feedback(self, pid: int, label: str) -> tuple[bool, str]:
        """Record explicit operator feedback; detector alerts alone never train weights."""
        if label not in ("benign", "suspicious"):
            return False, "Unsupported feedback label."
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            exe = None
            try:
                exe = proc.exe()
            except (psutil.AccessDenied, psutil.NoSuchProcess, psutil.ZombieProcess):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied) as exc:
            return False, str(exc)
        delta = -0.08 if label == "benign" else 0.08
        self.weights_store.adjust_weight(name, delta, event_kind=f"feedback_{label}")
        self.log_event("INFO", "OPERATOR_FEEDBACK", f"Operator marked PID {pid} ({name}) as {label}; learned weight adjusted by {delta:+.2f}.", meta={"pid": pid, "process": name, "exe": exe, "label": label, "delta": delta})
        return True, f"Recorded {label} feedback for {name}."

    def ensure_canaries(self):
        self.canary_dir.mkdir(parents=True, exist_ok=True)
        decoys = {
            "decoy_api_keys.env": "FAKE_API_KEY=canary-decoy-do-not-use\nFAKE_CLOUD_TOKEN=canary-tripwire\n",
            "canary_credentials.json": '{\n  "type": "canary_decoy",\n  "note": "Tripwire file"\n}\n',
        }
        with self.lock:
            self.canary_states.clear()
            self.alerted_canaries.clear()
            for name, body in decoys.items():
                p = self.canary_dir / name
                if not p.exists():
                    p.write_text(body, encoding="utf-8")
                st = p.stat()
                self.canary_states[p] = (st.st_mtime, st.st_atime)

    def set_mode(self, new_mode: str):
        if new_mode not in ("auto", "manual"):
            return
        with self.lock:
            self.mode = new_mode
        self.save_persistent_state()
        self.log_event("INFO", "MODE_CHANGE", f"Mode switched to '{new_mode}' (saved for reboot).")

    def get_mode(self) -> str:
        with self.lock:
            return self.mode

    def set_auto_action(self, action: str):
        if action not in ("suspend", "terminate"):
            return
        with self.lock:
            self.auto_action = action
        self.save_persistent_state()
        self.log_event("INFO", "ACTION_POLICY", f"Autonomous containment action set to '{action}' (saved for reboot).")

    def set_auto_remediate(self, enabled: bool):
        with self.lock:
            self.auto_remediate = bool(enabled)
        self.save_persistent_state()
        self.log_event("INFO", "REMEDIATION_POLICY", f"Auto-remediation set to {bool(enabled)} (saved for reboot).")

    def set_auto_rerun(self, enabled: bool):
        with self.lock:
            self.auto_rerun = bool(enabled)
        self.save_persistent_state()
        self.log_event("INFO", "RERUN_POLICY", f"Auto-rerun of saved selections set to {bool(enabled)} (saved for reboot).")

    def set_threshold(self, thresh: float):
        with self.lock:
            self.threshold = float(thresh)
        self.save_persistent_state()
        self.log_event("INFO", "THRESHOLD_CHANGE", f"Burst threshold set to {self.threshold} (saved for reboot).")

    def set_horizon(self, horizon_sec: float):
        h = max(1.0, float(horizon_sec))
        with self.lock:
            self.forecaster.horizon_sec = h
        self.save_persistent_state()
        self.log_event("INFO", "HORIZON_CHANGE", f"Forecast horizon set to {h:.1f}s (saved for reboot).")

    def _record_canary_trigger(self, kind: str, detail: str, now: float | None = None):
        ts = now if now is not None else time.time()
        with self.lock:
            self.recent_canary_events.append((ts, kind, detail))

    def _recent_canary_count(self, now: float, window_sec: float = 45.0) -> tuple[int, str]:
        with self.lock:
            recent = [(k, d) for (t, k, d) in self.recent_canary_events if now - t <= window_sec]
        if not recent:
            return 0, "none"
        summary = ", ".join(f"{k}:{d}" for k, d in recent[-3:])
        return len(recent), summary

    def log_event(
        self,
        severity: str,
        category: str,
        message: str,
        meta: dict | None = None,
        reasoning_steps: list[str] | None = None,
    ):
        with self.lock:
            mode_now = self.mode
        event = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "severity": severity,
            "category": category,
            "mode": mode_now,
            "message": message,
            "reasoning_steps": reasoning_steps or [],
            "meta": meta or {},
        }
        line = json.dumps(event)
        with self.lock:
            with self.log_path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")
        print(f"[{event['timestamp']}] [{severity}] [{mode_now}] {message}", flush=True)

    def capture_forensic_snapshot(self, pid: int, name: str, reason: str, endpoints: list[str]) -> dict:
        info = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "pid": pid,
            "process": name,
            "reason": reason,
            "endpoints": endpoints[:25],
            "exe": None,
            "cmdline": None,
            "ppid": None,
            "parent_name": None,
            "username": None,
            "cwd": None,
        }
        try:
            proc = psutil.Process(pid)
            info["ppid"] = proc.ppid()
            try:
                info["parent_name"] = psutil.Process(info["ppid"]).name() if info["ppid"] else None
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                pass
            try:
                info["username"] = proc.username()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            try:
                info["cwd"] = proc.cwd()
            except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                pass
            try:
                info["exe"] = proc.exe()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
            try:
                info["cmdline"] = proc.cmdline()
            except (psutil.AccessDenied, psutil.ZombieProcess):
                pass
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            pass

        with self.lock:
            with self.snapshots_path.open("a", encoding="utf-8") as f:
                f.write(json.dumps(info) + "\n")
        return info

    def snoop_pid(self, pid: int, resolve_geo: bool = True) -> dict:
        """Detailed snooping & network/world-origin trace for a given PID."""
        report = {
            "pid": pid,
            "name": "<restricted>" if pid < 0 else "unknown",
            "status": "unknown",
            "username": "restricted/unknown",
            "ppid": None,
            "parent_name": None,
            "exe": "restricted/unknown",
            "cmdline": [],
            "cwd": "restricted/unknown",
            "create_time": None,
            "num_threads": None,
            "memory_mb": None,
            "open_files": [],
            "sockets": [],
            "origins": [],
        }

        if pid >= 0:
            try:
                proc = psutil.Process(pid)
                try:
                    report["name"] = proc.name()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    report["name"] = "<restricted>"
                try:
                    report["status"] = str(proc.status())
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    report["status"] = "restricted"
                try:
                    report["username"] = proc.username()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    report["username"] = "<restricted>"
                try:
                    ppid = proc.ppid()
                    report["ppid"] = ppid
                    try:
                        report["parent_name"] = psutil.Process(ppid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        report["parent_name"] = "<restricted>"
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                try:
                    report["exe"] = proc.exe()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    report["exe"] = "<restricted (run as Admin/root for path)>"
                try:
                    report["cmdline"] = proc.cmdline()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    report["cmdline"] = ["<restricted>"]
                try:
                    report["cwd"] = proc.cwd()
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    report["cwd"] = "<restricted>"
                try:
                    report["create_time"] = datetime.fromtimestamp(proc.create_time(), tz=timezone.utc).isoformat()
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                try:
                    report["num_threads"] = proc.num_threads()
                    report["memory_mb"] = round(proc.memory_info().rss / (1024 * 1024), 1)
                except (psutil.AccessDenied, psutil.ZombieProcess):
                    pass
                try:
                    report["open_files"] = [f.path for f in proc.open_files()[:15]]
                except (psutil.AccessDenied, psutil.ZombieProcess, OSError):
                    report["open_files"] = ["<restricted>"]
            except psutil.NoSuchProcess:
                report["name"] = "<exited>"
                report["status"] = "dead"

        with self.lock:
            sock_entries = list(self.latest_sockets_by_pid.get(pid, []))

        unique_remote_ips: list[str] = []
        seen_ips: set[str] = set()
        for s in sock_entries:
            rip = s.get("remote_ip")
            if rip and rip not in seen_ips:
                seen_ips.add(rip)
                unique_remote_ips.append(rip)

        origins = []
        for rip in unique_remote_ips[:20]:
            geo = self.geo_tracer.lookup(rip, allow_network=resolve_geo)
            origins.append(geo)

        report["sockets"] = sock_entries
        report["origins"] = origins
        return report

    def trace_all_remote_ips(self, max_ips: int = 25) -> list[dict]:
        """Resolves world location/ISP/ASN for active remote IPs across tracked processes."""
        with self.lock:
            sock_map = dict(self.latest_sockets_by_pid)
        ips: list[str] = []
        seen: set[str] = set()
        for entries in sock_map.values():
            for e in entries:
                rip = e.get("remote_ip")
                if rip and rip not in seen:
                    seen.add(rip)
                    ips.append(rip)
                    if len(ips) >= max_ips:
                        break
            if len(ips) >= max_ips:
                break
        results = []
        for ip in ips:
            results.append(self.geo_tracer.lookup(ip, allow_network=True))
        return results

    def _is_user_allowed(self, name: str) -> bool:
        with self.lock:
            return name.lower() in self.allowed_processes

    def _is_protected(self, pid: int, name: str) -> bool:
        if self._is_user_allowed(name):
            return True
        if pid < 0 or pid in (0, 4, self.self_pid, self.parent_pid) or name.lower() in PROTECTED_NAMES:
            return True
        try:
            if psutil.Process(pid).ppid() in (self.self_pid, self.parent_pid):
                return True
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            return True
        return False

    def _evaluate_counterfactual(
        self,
        pid: int,
        name: str,
        count: int,
        delta: int,
        spread: int,
        forecast: dict[str, float],
        weight: float,
        final_score: float,
        threshold: float,
        protected: bool,
        canary_hits: int,
    ) -> dict:
        low_name = name.lower()
        benign_prior = 0.55 if low_name in COMMON_HIGH_SOCKET_NAMES else 0.15
        if self._is_user_allowed(name):
            benign_prior = 0.85
        if spread <= 2 and count >= 12 and forecast["slope_per_sec"] <= 0.2:
            benign_prior = min(0.85, benign_prior + 0.25)
        if canary_hits > 0 and spread >= 3 and not self._is_user_allowed(name):
            benign_prior = max(0.05, benign_prior - 0.35)

        act_now_fp_risk = round(min(0.95, max(0.05, benign_prior * (1.2 if weight < 1.1 else 0.85))), 2)
        defer_missed_burst_risk = round(
            min(
                0.98,
                max(
                    0.05,
                    (0.35 if forecast["projected_sockets"] >= 20 else 0.1)
                    + (0.35 if canary_hits > 0 else 0.0)
                    + (0.2 if forecast["accel_per_sec2"] > 0.2 else 0.0),
                ),
            ),
            2,
        )

        if protected:
            recommended_path = "USER_ALLOWED_OR_PROTECTED" if self._is_user_allowed(name) else "PROTECT_AND_OBSERVE"
        elif final_score >= threshold and act_now_fp_risk <= 0.55:
            recommended_path = "CONTAIN_WITH_SNAPSHOT"
        elif final_score >= threshold:
            recommended_path = "SNAPSHOT_AND_VERIFY_FIRST"
        elif defer_missed_burst_risk >= 0.65:
            recommended_path = "PRE_STAGE_WATCH"
        else:
            recommended_path = "CONTINUE_PASSIVE"

        return {
            "benign_prior": round(benign_prior, 2),
            "fp_risk_if_act_now": act_now_fp_risk,
            "miss_risk_if_defer": defer_missed_burst_risk,
            "recommended_path": recommended_path,
        }

    def _build_reasoning_chain(
        self,
        pid: int,
        name: str,
        count: int,
        delta: int,
        spread: int,
        forecast: dict[str, float],
        weight: float,
        final_score: float,
        threshold: float,
        mode: str,
        protected: bool,
        action: str,
        canary_hits: int,
        canary_summary: str,
        cf: dict,
        origins_summary: str = "",
    ) -> list[str]:
        eta_str = (
            "already >=25 sockets"
            if forecast["eta_25_sec"] == 0.0
            else (f"~{forecast['eta_25_sec']}s" if forecast["eta_25_sec"] > 0 else "not approaching 25")
        )
        causal_note = (
            f"Correlated with {canary_hits} recent canary tripwire event(s) ({canary_summary})."
            if canary_hits > 0
            else "No recent canary tripwire correlation in active window."
        )
        origin_note = f" Observed remote origins: {origins_summary}." if origins_summary else ""
        user_allowed = self._is_user_allowed(name)

        steps = [
            f"1. Observation: PID {pid} ({name}) holds {count} active sockets (delta {delta:+d}) across {spread} distinct remote endpoints.{origin_note}",
            (
                f"2. Predictive Trajectory: Velocity is {forecast['slope_per_sec']:+.3f} sockets/sec "
                f"(accel {forecast['accel_per_sec2']:+.3f}/s²); {self.forecaster.horizon_sec:.0f}s damped projection is "
                f"{forecast['projected_sockets']} sockets (ETA 25: {eta_str}, conf {forecast['confidence']:.0%}, boost +{forecast['trend_boost']})."
            ),
            (
                f"3. Causal & Counterfactual Check: {causal_note} "
                f"If we act now, estimated false-positive risk is {cf['fp_risk_if_act_now']:.0%}; "
                f"if we defer, risk of missing an escalating burst is {cf['miss_risk_if_defer']:.0%} (path: {cf['recommended_path']})."
            ),
            (
                f"4. Adaptive Weighting: Learned weight for '{name}' is {weight:.3f}x, "
                f"yielding effective anomaly score {final_score} vs threshold {threshold}."
            ),
        ]
        if final_score < threshold:
            steps.append("5. Decision: Below threshold; continue passive 24/7 observation without containment.")
        elif user_allowed:
            steps.append("5. Decision: Threshold exceeded, but user saved '{0}' as ALLOWED; do not block or suspend.".format(name))
        elif protected:
            steps.append("5. Decision: Threshold exceeded, but process is protected; skip automatic suspension/termination to preserve OS stability.")
        elif mode != "auto":
            steps.append("5. Decision: Threshold exceeded in MANUAL mode; log alert and await explicit human selection.")
        else:
            steps.append(
                f"5. Decision: Threshold exceeded in AUTO mode on non-protected process; "
                f"capture forensic snapshot and execute '{action}' (FP risk {cf['fp_risk_if_act_now']:.0%})."
            )
        return steps

    def resume_or_remediate_pid(self, pid: int, source: str = "manual") -> tuple[bool, str]:
        try:
            proc = psutil.Process(pid)
            name = proc.name()
            proc.resume()
            with self.lock:
                self.suspended_ledger.pop(pid, None)
                self.allowed_processes.add(name.lower())
                self.weights_store.adjust_weight(name, -0.10, event_kind="remediate")
            self.save_persistent_state()
            self.log_event("INFO", "REMEDIATE_RESUME", f"Resumed PID {pid} ({name}) via {source} and persisted as allowed.")
            return True, f"Resumed PID {pid} ({name})."
        except (psutil.NoSuchProcess, psutil.AccessDenied, NotImplementedError) as exc:
            with self.lock:
                self.suspended_ledger.pop(pid, None)
            return False, str(exc)

    def _check_auto_remediation(self, now: float):
        with self.lock:
            if not self.auto_remediate:
                return
            due_pids = [
                pid for pid, rec in self.suspended_ledger.items()
                if rec.get("action") == "suspend" and (now - rec.get("ts", now)) >= self.grace_sec
            ]
        for pid in due_pids:
            with self.lock:
                current_map = {r["pid"]: r for r in self.latest_rows}
            row = current_map.get(pid)
            if not row or row["score"] < self.threshold * 0.6:
                self.resume_or_remediate_pid(pid, source="auto_remediate_grace")

    def _maybe_auto_contain(self, pid: int, name: str, score: float, endpoints: list[str], reasoning: list[str]):
        with self.lock:
            mode = self.mode
            thresh = self.threshold
            action = self.auto_action
        if mode != "auto" or score < thresh:
            if score < thresh:
                self.risk_streaks[pid] = 0
            return
        self.risk_streaks[pid] = self.risk_streaks.get(pid, 0) + 1
        canary_count, canary_detail = self._recent_canary_count(time.time(), window_sec=45.0)
        if self.risk_streaks[pid] < 3 and canary_count == 0:
            return
        if self._is_user_allowed(name):
            self.log_event(
                "INFO",
                "ALLOWED_SKIP",
                f"Skipped blocking user-allowed PID {pid} ({name}) score={score}.",
                meta={"pid": pid, "process": name, "score": score},
                reasoning_steps=reasoning,
            )
            return
        if self._is_protected(pid, name):
            self.log_event(
                "WARN",
                "PROTECTED_SKIP",
                f"Skipped protected PID {pid} ({name}) score={score}.",
                meta={"pid": pid, "process": name, "score": score},
                reasoning_steps=reasoning,
            )
            return

        now = time.time()
        if now - self.last_acted.get(pid, 0.0) < 60.0:
            return

        snap = self.capture_forensic_snapshot(pid, name, f"auto_{action}_score_{score}", endpoints)
        try:
            proc = psutil.Process(pid)
            if action == "terminate":
                proc.terminate()
                verb = "terminated"
            else:
                proc.suspend()
                verb = "suspended"
            self.last_acted[pid] = now
            with self.lock:
                # Containment is recorded as an outcome, not treated as proof that
                # the process was malicious. Only explicit operator feedback trains weights.
                stat = self.weights_store._ensure_stat(name.lower())
                stat["containments"] = int(stat.get("containments", 0)) + 1
                self.weights_store.save()
                if verb == "suspended":
                    self.suspended_ledger[pid] = {
                        "pid": pid,
                        "process": name,
                        "ts": now,
                        "action": "suspend",
                        "score": score,
                        "snapshot": snap,
                    }
            self.log_event(
                "ALERT",
                "AUTO_CONTAIN",
                f"Autonomously {verb} PID {pid} ({name}) score={score} after corroboration.",
                meta={"pid": pid, "process": name, "score": score, "action": verb},
                reasoning_steps=reasoning,
            )
        except (psutil.NoSuchProcess, psutil.AccessDenied, NotImplementedError) as exc:
            self.log_event("WARN", "AUTO_FAIL", f"Could not {action} PID {pid} ({name}): {exc}")

    def scan_canaries(self):
        now = time.time()
        with self.lock:
            items = list(self.canary_states.items())
        for path, (prev_mtime, prev_atime) in items:
            if not path.exists():
                self._record_canary_trigger("DELETED", path.name, now)
                self.log_event(
                    "ALERT",
                    "CANARY_DELETED",
                    f"Canary deleted: {path}",
                    reasoning_steps=[
                        f"1. Observation: Tripwire canary '{path.name}' disappeared between scan cycles.",
                        "2. Assessment: File removal or rename on a decoy secret indicates potential reconnaissance or tampering.",
                        "3. Decision: Log high-priority tripwire alert, correlate with active socket bursts, and recreate decoy canary automatically.",
                    ],
                )
                self.ensure_canaries()
                return
            try:
                st = path.stat()
            except OSError:
                continue
            if st.st_mtime != prev_mtime:
                ev_key = (f"MOD:{path.name}", st.st_mtime)
                if ev_key not in self.alerted_canaries:
                    self.alerted_canaries.add(ev_key)
                    self._record_canary_trigger("MODIFIED", path.name, now)
                    self.log_event(
                        "ALERT",
                        "CANARY_MODIFIED",
                        f"Canary modified: {path}",
                        reasoning_steps=[
                            f"1. Observation: Modification timestamp changed on decoy file '{path.name}'.",
                            "2. Assessment: Decoy credentials have no legitimate reason to be edited.",
                            "3. Decision: Raise tripwire alert and boost causal correlation for processes opening sockets.",
                        ],
                    )
            elif st.st_atime != prev_atime:
                ev_key = (f"ACC:{path.name}", st.st_atime)
                if ev_key not in self.alerted_canaries:
                    self.alerted_canaries.add(ev_key)
                    self._record_canary_trigger("ACCESSED", path.name, now)
                    self.log_event(
                        "ALERT",
                        "CANARY_ACCESSED",
                        f"Canary accessed: {path}",
                        reasoning_steps=[
                            f"1. Observation: Access timestamp changed on decoy file '{path.name}'.",
                            "2. Assessment: Automated credential or secret hunters often read .env or JSON key files.",
                            "3. Decision: Raise tripwire alert so defenders can correlate active processes.",
                        ],
                    )
            with self.lock:
                self.canary_states[path] = (st.st_mtime, st.st_atime)

    def _collect_connections(self) -> list:
        conns = []
        seen_keys = set()
        try:
            raw_conns = psutil.net_connections(kind="inet")
            for c in raw_conns:
                key = (
                    c.pid,
                    c.laddr.ip if c.laddr else None,
                    c.laddr.port if c.laddr else None,
                    c.raddr.ip if c.raddr else None,
                    c.raddr.port if c.raddr else None,
                    str(c.status),
                )
                if key not in seen_keys:
                    seen_keys.add(key)
                    conns.append(c)
        except (psutil.AccessDenied, PermissionError):
            for proc in psutil.process_iter(["pid", "name"]):
                try:
                    for c in proc.net_connections(kind="inet"):
                        if c.pid is None:
                            c = type("ConnProxy", (), {
                                "pid": proc.pid,
                                "laddr": c.laddr,
                                "raddr": c.raddr,
                                "status": c.status,
                            })()
                        key = (
                            c.pid,
                            c.laddr.ip if c.laddr else None,
                            c.laddr.port if c.laddr else None,
                            c.raddr.ip if c.raddr else None,
                            c.raddr.port if c.raddr else None,
                            str(c.status),
                        )
                        if key not in seen_keys:
                            seen_keys.add(key)
                            conns.append(c)
                except (psutil.NoSuchProcess, psutil.AccessDenied):
                    continue
        return conns

    def scan_sockets(self):
        now = time.time()
        grouped: dict[int, list[str]] = defaultdict(list)
        detailed_socks: dict[int, list[dict]] = defaultdict(list)
        remotes: dict[int, set[str]] = defaultdict(set)
        remote_ips_by_pid: dict[int, list[str]] = defaultdict(list)

        conns = self._collect_connections()
        if not conns and not self.latest_rows:
            return

        for c in conns:
            bucket_pid = int(c.pid) if c.pid is not None else -1
            l_str = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "n/a"
            if c.raddr:
                rip = c.raddr.ip
                ep = f"{rip}:{c.raddr.port}"
                remotes[bucket_pid].add(ep)
                remote_ips_by_pid[bucket_pid].append(rip)
                grouped[bucket_pid].append(f"{ep} ({c.status})")
                detailed_socks[bucket_pid].append(
                    {
                        "local": l_str,
                        "remote": ep,
                        "remote_ip": rip,
                        "remote_port": c.raddr.port,
                        "status": str(c.status),
                    }
                )
            elif c.laddr:
                grouped[bucket_pid].append(f"LOCAL:{c.laddr.port} ({c.status})")
                detailed_socks[bucket_pid].append(
                    {
                        "local": l_str,
                        "remote": "-",
                        "remote_ip": None,
                        "remote_port": None,
                        "status": str(c.status),
                    }
                )

        with self.lock:
            thresh = self.threshold
            mode = self.mode
            action = self.auto_action
            self._cycle_count += 1
            if self._cycle_count % 30 == 0:
                self.weights_store.decay_toward_baseline(0.02)

        canary_hits, canary_summary = self._recent_canary_count(now, window_sec=45.0)
        rows = []
        reasoning_map: dict[int, list[str]] = {}
        cf_map: dict[int, dict] = {}

        for pid, sockets in grouped.items():
            count = len(sockets)
            prev = self.prev_sockets.get(pid, count)
            delta = count - prev
            self.prev_sockets[pid] = count

            hist = self.pid_history[pid]
            if delta > 0 or count >= 10:
                hist.append(now)

            series = self.socket_series[pid]
            series.append((now, count))
            forecast = self.forecaster.forecast(series)

            recent = sum(1 for t in hist if now - t <= 10.0)
            spread = len(remotes[pid])
            causal_boost = min(3.0, canary_hits * 1.25) if (canary_hits > 0 and (delta > 0 or spread >= 2)) else 0.0
            raw_score = (
                (max(0, delta) * 1.5)
                + (recent * 1.2)
                + (min(spread, 25) * 0.25)
                + (1.5 if count >= 20 else 0.0)
                + forecast["trend_boost"]
                + causal_boost
            )

            if pid < 0:
                name = "<unowned-kernel/restricted>"
                status = "restricted"
            else:
                try:
                    proc = psutil.Process(pid)
                    try:
                        name = proc.name()
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        name = "<restricted>"
                    try:
                        status = str(proc.status())
                    except (psutil.AccessDenied, psutil.ZombieProcess):
                        status = "restricted"
                except psutil.NoSuchProcess:
                    name = "unknown"
                    status = "unknown"

            origin_labels: list[str] = []
            seen_loc: set[str] = set()
            for rip in remote_ips_by_pid.get(pid, [])[:10]:
                cached = self.geo_tracer.get_cached(rip)
                lbl = cached["label"] if cached else f"Public:{rip}"
                if lbl not in seen_loc:
                    seen_loc.add(lbl)
                    origin_labels.append(lbl)
            origins_str = " | ".join(origin_labels[:3]) + (f" (+{len(origin_labels) - 3})" if len(origin_labels) > 3 else "")

            exe_path = None
            if pid >= 0:
                try:
                    exe_path = psutil.Process(pid).exe()
                except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                    pass
            behavior = self.behavior_memory.observe(name, exe_path, {
                "sockets": float(count), "delta": float(delta), "spread": float(spread),
                "slope": float(forecast["slope_per_sec"]), "accel": float(forecast["accel_per_sec2"]),
            })
            behavior_boost = min(3.5, max(0.0, behavior["deviation"] - 1.5) * 0.8) if behavior["ready"] else 0.0
            raw_score += behavior_boost

            with self.lock:
                weight = self.weights_store.get_weight(name)

            score = round(raw_score * weight, 1)
            protected = self._is_protected(pid, name)
            cf = self._evaluate_counterfactual(
                pid=pid,
                name=name,
                count=count,
                delta=delta,
                spread=spread,
                forecast=forecast,
                weight=weight,
                final_score=score,
                threshold=thresh,
                protected=protected,
                canary_hits=canary_hits,
            )
            cf_map[pid] = cf

            reasoning = self._build_reasoning_chain(
                pid=pid,
                name=name,
                count=count,
                delta=delta,
                spread=spread,
                forecast=forecast,
                weight=weight,
                final_score=score,
                threshold=thresh,
                mode=mode,
                protected=protected,
                action=action,
                canary_hits=canary_hits,
                canary_summary=canary_summary,
                cf=cf,
                origins_summary=origins_str,
            )
            reasoning_map[pid] = reasoning

            if self._is_user_allowed(name):
                flag = "ALLOWED/PERSIST"
            elif score >= thresh:
                flag = "BURST ALERT"
            elif forecast["projected_sockets"] >= max(20.0, count * 1.5) and forecast["slope_per_sec"] > 0.4:
                flag = "RISING TREND"
            elif canary_hits > 0 and spread >= 2:
                flag = "CANARY LINKED"
            elif count >= 12:
                flag = "ELEVATED"
            else:
                flag = "Normal"

            sample = ", ".join(sockets[:2]) + (f" (+{len(sockets) - 2})" if len(sockets) > 2 else "")
            rows.append(
                {
                    "score": score,
                    "pid": pid,
                    "name": name,
                    "status": status,
                    "count": count,
                    "delta_str": f"{delta:+d}",
                    "spread": spread,
                    "projected": forecast["projected_sockets"],
                    "weight": weight,
                    "deviation": behavior["deviation"],
                    "baseline_samples": behavior["samples"],
                    "flag": flag,
                    "origins": origins_str or "-",
                    "sample": sample,
                }
            )

            if score >= thresh:
                self.log_event(
                    "ALERT",
                    "BURST_DETECTED",
                    f"PID {pid} ({name}) score={score} (w={weight:.2f}x, proj={forecast['projected_sockets']}) sockets={count} origins=[{origins_str}]",
                    meta={
                        "pid": pid,
                        "process": name,
                        "score": score,
                        "weight": weight,
                        "forecast": forecast,
                        "counterfactual": cf,
                        "origins": origins_str,
                    },
                    reasoning_steps=reasoning,
                )
                self._maybe_auto_contain(pid, name, score, sockets, reasoning)

        active_pids = {r["pid"] for r in rows}
        for tracked_pid in list(self.risk_streaks):
            if tracked_pid not in active_pids:
                self.risk_streaks.pop(tracked_pid, None)
        rows.sort(key=lambda r: (r["score"], r["projected"], r["count"]), reverse=True)
        with self.lock:
            self.latest_rows = rows
            self.latest_sockets_by_pid = dict(detailed_socks)
            self.latest_reasoning = reasoning_map
            self.latest_counterfactuals = cf_map

        self._check_auto_remediation(now)

    def run_loop(self):
        self.log_event("INFO", "START", f"24/7 background loop started in '{self.mode}' mode (state={self.state_path}).")
        self.rerun_saved_selections(force=False)
        while not self.stop_event.is_set():
            t0 = time.time()
            try:
                self.scan_canaries()
                self.scan_sockets()
            except Exception as exc:
                self.log_event("ERROR", "MONITOR_CYCLE_RECOVERED", f"Monitoring cycle failed but loop will continue: {type(exc).__name__}: {exc}")
            elapsed = time.time() - t0
            self.stop_event.wait(max(0.1, self.interval - elapsed))
        self.save_persistent_state()
        self.log_event("INFO", "STOP", "24/7 background loop stopped and state saved.")


class DefenderAppGUI:
    """GUI with top Menu Bar for snooping/tracing, reboot persistence, manual selection, reasoning, weights, and containment."""

    def __init__(self, root: tk.Tk, engine: DefenderEngine):
        self.root = root
        self.engine = engine
        self.root.title("Agentic Defender v2 — Predictive Behavioral Intelligence")
        self.root.geometry("1280x760")
        self._log_pos = 0
        self._snoop_win: tk.Toplevel | None = None
        self._snoop_text: tk.Text | None = None

        self._build_menubar()
        self._build_ui()
        self.refresh_ui()
        self._poll()

    def _build_menubar(self):
        menubar = tk.Menu(self.root)

        mode_menu = tk.Menu(menubar, tearoff=False)
        mode_menu.add_command(label="Switch to 24/7 Autonomous (Auto)", command=lambda: self._switch_mode("auto"))
        mode_menu.add_command(label="Switch to Manual / Observe Only", command=lambda: self._switch_mode("manual"))
        mode_menu.add_separator()
        mode_menu.add_command(label="Auto Action: Suspend Process", command=lambda: self._set_auto_action("suspend"))
        mode_menu.add_command(label="Auto Action: Terminate Process", command=lambda: self._set_auto_action("terminate"))
        mode_menu.add_command(label="Toggle Auto-Remediation (Grace Resume)", command=self._toggle_auto_remediate)
        mode_menu.add_command(label="Toggle Auto-Rerun Saved Selections on Startup", command=self._toggle_auto_rerun)
        mode_menu.add_command(label="Set Burst Threshold...", command=self._prompt_threshold)
        mode_menu.add_command(label="Set Forecast Horizon (sec)...", command=self._prompt_horizon)
        menubar.add_cascade(label="Mode & Policy", menu=mode_menu)

        manual_menu = tk.Menu(menubar, tearoff=False)
        manual_menu.add_command(label="Allow & Auto-Rerun Selected Process (Persist Reboot)", command=self._allow_and_persist_selected)
        manual_menu.add_command(label="Remove Saved Allow/Rerun for Selected Process", command=self._remove_selected_persistence)
        manual_menu.add_command(label="Run Saved Selections Now", command=self._rerun_now)
        manual_menu.add_command(label="View Saved Reboot State & Selections", command=self._show_saved_state)
        manual_menu.add_separator()
        manual_menu.add_command(label="Manual Action: Suspend Selected PID", command=lambda: self._manual_pid("suspend"))
        manual_menu.add_command(label="Manual Action: Resume Selected PID", command=lambda: self._manual_pid("resume"))
        manual_menu.add_command(label="Manual Action: Terminate Selected PID", command=lambda: self._manual_pid("terminate"))
        manual_menu.add_separator()
        manual_menu.add_command(label="Manual Action: Snapshot Selected PID", command=self._manual_snapshot)
        manual_menu.add_command(label="Manual Action: Show Reasoning for Selected PID", command=self._show_selected_reasoning)
        manual_menu.add_command(label="Manual Action: Show Counterfactual & Ledger", command=self._show_counterfactual_summary)
        manual_menu.add_command(label="Manual Action: Reset Canary Tripwires", command=self._reset_canaries)
        manual_menu.add_command(label="Manual Action: Run Immediate Scan", command=self._manual_scan)
        menubar.add_cascade(label="Manual Selection", menu=manual_menu)

        snoop_menu = tk.Menu(menubar, tearoff=False)
        snoop_menu.add_command(label="Open Snoop & World-Origin Tracer (Selected PID)", command=lambda: self._open_snoop_window(resolve_geo=True))
        snoop_menu.add_command(label="Quick Trace Selected PID (Exe, Cmdline, Sockets & Geo)", command=self._quick_trace_selected)
        snoop_menu.add_command(label="Trace All Active Remote IPs (World Location / ISP / ASN)", command=self._trace_all_ips)
        snoop_menu.add_command(label="Lookup Custom IP / Host...", command=self._prompt_custom_ip)
        menubar.add_cascade(label="Snooping & Tracing", menu=snoop_menu)

        learning_menu = tk.Menu(menubar, tearoff=False)
        learning_menu.add_command(label="Reinforce Weight (+0.15) for Selected Process", command=lambda: self._adjust_selected_weight(+0.15))
        learning_menu.add_command(label="Lower Weight (-0.15) for Selected Process", command=lambda: self._adjust_selected_weight(-0.15))
        learning_menu.add_separator()
        learning_menu.add_command(label="Feedback: Selected Process Is Benign", command=lambda: self._feedback_selected("benign"))
        learning_menu.add_command(label="Feedback: Selected Process Is Suspicious", command=lambda: self._feedback_selected("suspicious"))
        learning_menu.add_command(label="Reset All Learned Weights", command=self._reset_weights)
        learning_menu.add_command(label="Export Event Log...", command=self._export_log)
        menubar.add_cascade(label="Reasoning & Weights", menu=learning_menu)

        self.root.config(menu=menubar)

    def _build_ui(self):
        status_bar = ttk.Frame(self.root, padding=(10, 8))
        status_bar.pack(fill=tk.X)

        self.mode_label = ttk.Label(status_bar, text="")
        self.mode_label.pack(side=tk.LEFT)

        ttk.Label(
            status_bar,
            text="Selections & settings auto-save for reboot • Use 'Manual Selection' to Allow/Rerun or 'Snooping & Tracing'",
        ).pack(side=tk.RIGHT)

        table_frame = ttk.LabelFrame(self.root, text="Predictive Socket, Forecast, World Origins & Adaptive Weight Monitor", padding=8)
        table_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 6))

        cols = ("pid", "process", "state", "sockets", "delta", "remotes", "proj_10s", "baseline_z", "weight", "score", "flag", "origins", "sample")
        self.tree = ttk.Treeview(table_frame, columns=cols, show="headings", height=11)
        widths = {
            "pid": 60,
            "process": 165,
            "state": 80,
            "sockets": 65,
            "delta": 55,
            "remotes": 65,
            "proj_10s": 70,
            "baseline_z": 78,
            "weight": 65,
            "score": 65,
            "flag": 120,
            "origins": 210,
            "sample": 220,
        }
        for c in cols:
            self.tree.heading(c, text=c.upper())
            self.tree.column(c, width=widths[c], anchor=tk.CENTER if c not in ("sample", "origins", "process") else tk.W)
        self.tree.bind("<<TreeviewSelect>>", lambda _e: self._on_selection_changed())
        self.tree.pack(fill=tk.BOTH, expand=True)

        lower_pane = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        lower_pane.pack(fill=tk.BOTH, expand=False, padx=10, pady=(0, 10))

        reason_frame = ttk.LabelFrame(lower_pane, text="Auditable Decision Trace (Selected Process)", padding=8)
        self.reason_text = tk.Text(reason_frame, height=10, width=52, state=tk.DISABLED, wrap=tk.WORD)
        self.reason_text.pack(fill=tk.BOTH, expand=True)
        lower_pane.add(reason_frame, weight=1)

        log_frame = ttk.LabelFrame(lower_pane, text="Continuous 24/7 Event Log", padding=8)
        self.log_text = tk.Text(log_frame, height=10, width=64, state=tk.DISABLED, wrap=tk.WORD)
        self.log_text.pack(fill=tk.BOTH, expand=True)
        lower_pane.add(log_frame, weight=2)

    def _allow_and_persist_selected(self):
        info = self._get_selected_row_info()
        if not info:
            messagebox.showwarning("No Selection", "Select a process row first.")
            return
        pid, name = info
        rec = self.engine.allow_and_track_process(pid, name, register_rerun=True)
        messagebox.showinfo(
            "Saved for Reboot",
            f"'{name}' is now ALLOWED (won't be blocked) and saved for rerun if needed.\nSaved exe: {rec.get('exe') or 'name-only'}",
        )
        self.refresh_ui()

    def _remove_selected_persistence(self):
        info = self._get_selected_row_info()
        if not info:
            messagebox.showwarning("No Selection", "Select a process row first.")
            return
        _, name = info
        self.engine.remove_saved_selection(name)
        messagebox.showinfo("Removed", f"Removed saved allow/rerun state for '{name}'.")
        self.refresh_ui()

    def _rerun_now(self):
        started = self.engine.rerun_saved_selections(force=True)
        messagebox.showinfo("Rerun Complete", f"Started {len(started)} saved process(es): {', '.join(started) if started else 'none needed'}.")

    def _show_saved_state(self):
        with self.engine.lock:
            allowed = sorted(self.engine.allowed_processes)
            targets = dict(self.engine.rerun_targets)
            st = {
                "mode": self.engine.mode,
                "auto_action": self.engine.auto_action,
                "auto_remediate": self.engine.auto_remediate,
                "auto_rerun": self.engine.auto_rerun,
                "threshold": self.engine.threshold,
                "horizon_sec": self.engine.forecaster.horizon_sec,
            }
        lines = [
            f"State File: {self.engine.state_path}",
            f"Settings: {json.dumps(st)}",
            f"Allowed (Non-Blocked) Processes ({len(allowed)}): {', '.join(allowed) if allowed else 'none'}",
            f"Rerun Targets ({len(targets)}):",
        ]
        for k, v in targets.items():
            lines.append(f"  - {v.get('name', k)}: exe={v.get('exe') or 'n/a'} enabled={v.get('enabled', True)}")
        messagebox.showinfo("Persistent Reboot State", "\n".join(lines))

    def _format_snoop_report(self, rep: dict) -> str:
        lines = [
            f"=== SNOOP & TRACE REPORT: PID {rep['pid']} ({rep['name']}) ===",
            f"Status: {rep['status']} | User: {rep['username']} | Parent: {rep['parent_name']} (PPID {rep['ppid']})",
            f"Executable: {rep['exe']}",
            f"Working Dir: {rep['cwd']}",
            f"Cmdline: {' '.join(rep['cmdline']) if isinstance(rep['cmdline'], list) and rep['cmdline'] else rep['cmdline']}",
            f"Started (UTC): {rep['create_time']} | Threads: {rep['num_threads']} | RSS: {rep['memory_mb']} MB",
            "",
            f"--- World Origins / Remote Endpoints ({len(rep['origins'])}) ---",
        ]
        if not rep["origins"]:
            lines.append("  No remote IP addresses resolved/present for this PID.")
        else:
            for g in rep["origins"]:
                extra = " | ".join(x for x in [g.get("org"), g.get("as"), g.get("isp")] if x)
                lines.append(f"  {g['ip']} -> {g['label']}" + (f" [{extra}]" if extra else ""))

        lines.append("")
        lines.append(f"--- Active Sockets ({len(rep['sockets'])}) ---")
        for s in rep["sockets"][:30]:
            lines.append(f"  {s['local']}  ==>  {s['remote']}  ({s['status']})")
        if len(rep["sockets"]) > 30:
            lines.append(f"  ... (+{len(rep['sockets']) - 30} more sockets)")

        lines.append("")
        lines.append("--- Open Files (sample) ---")
        for of in rep["open_files"][:10]:
            lines.append(f"  {of}")
        return "\n".join(lines)

    def _open_snoop_window(self, resolve_geo: bool = True):
        info = self._get_selected_row_info()
        if not info:
            messagebox.showwarning("No Selection", "Select a process row first to snoop and trace.")
            return
        pid, _ = info
        if self._snoop_win is None or not self._snoop_win.winfo_exists():
            win = tk.Toplevel(self.root)
            win.title("Snoop & World-Origin Tracer")
            win.geometry("820x560")
            btn_bar = ttk.Frame(win, padding=(8, 6))
            btn_bar.pack(fill=tk.X)
            ttk.Button(btn_bar, text="Refresh + Geo-Trace Selected", command=lambda: self._refresh_snoop_window(True)).pack(side=tk.LEFT, padx=(0, 6))
            ttk.Button(btn_bar, text="Fast Refresh (Cache Only)", command=lambda: self._refresh_snoop_window(False)).pack(side=tk.LEFT)

            txt = tk.Text(win, wrap=tk.WORD, font=("Consolas", 9))
            txt.pack(fill=tk.BOTH, expand=True, padx=8, pady=(0, 8))
            self._snoop_win = win
            self._snoop_text = txt
        else:
            self._snoop_win.lift()

        self._refresh_snoop_window(resolve_geo=resolve_geo)

    def _refresh_snoop_window(self, resolve_geo: bool = True):
        if self._snoop_win is None or not self._snoop_win.winfo_exists() or self._snoop_text is None:
            return
        info = self._get_selected_row_info()
        if not info:
            return
        pid, _ = info
        rep = self.engine.snoop_pid(pid, resolve_geo=resolve_geo)
        formatted = self._format_snoop_report(rep)
        self._snoop_text.configure(state=tk.NORMAL)
        self._snoop_text.delete("1.0", tk.END)
        self._snoop_text.insert(tk.END, formatted)
        self._snoop_text.configure(state=tk.DISABLED)

    def _on_selection_changed(self):
        self._update_reasoning_pane()
        if self._snoop_win is not None and self._snoop_win.winfo_exists():
            self._refresh_snoop_window(resolve_geo=False)

    def _quick_trace_selected(self):
        info = self._get_selected_row_info()
        if not info:
            messagebox.showwarning("No Selection", "Select a process row first.")
            return
        pid, _ = info
        rep = self.engine.snoop_pid(pid, resolve_geo=True)
        messagebox.showinfo(f"Trace — PID {pid} ({rep['name']})", self._format_snoop_report(rep)[:2500])

    def _trace_all_ips(self):
        results = self.engine.trace_all_remote_ips(max_ips=25)
        if not results:
            messagebox.showinfo("World Origin Trace", "No active remote IP addresses found right now.")
            return
        lines = []
        for g in results:
            lines.append(f"{g['ip']} -> {g['label']} | {g.get('org') or g.get('isp') or ''} {g.get('as') or ''}".strip())
        messagebox.showinfo("Active Remote IP World Origins", "\n".join(lines))

    def _prompt_custom_ip(self):
        ip_val = simpledialog.askstring("IP / World Origin Lookup", "Enter an IPv4 or IPv6 address to trace:")
        if ip_val:
            g = self.engine.geo_tracer.lookup(ip_val.strip(), allow_network=True)
            messagebox.showinfo(
                f"Origin Trace: {g['ip']}",
                f"Location: {g['label']}\nRegion: {g.get('region') or '-'}\nISP: {g.get('isp') or '-'}\nOrg: {g.get('org') or '-'}\nAS: {g.get('as') or '-'}",
            )

    def _switch_mode(self, mode: str):
        self.engine.set_mode(mode)
        self.refresh_ui()

    def _set_auto_action(self, action: str):
        self.engine.set_auto_action(action)
        self.refresh_ui()

    def _toggle_auto_remediate(self):
        with self.engine.lock:
            nxt = not self.engine.auto_remediate
        self.engine.set_auto_remediate(nxt)
        self.refresh_ui()

    def _toggle_auto_rerun(self):
        with self.engine.lock:
            nxt = not self.engine.auto_rerun
        self.engine.set_auto_rerun(nxt)
        self.refresh_ui()

    def _prompt_threshold(self):
        val = simpledialog.askfloat(
            "Burst Threshold",
            "Enter new burst score threshold:",
            initialvalue=self.engine.threshold,
            minvalue=1.0,
        )
        if val is not None:
            self.engine.set_threshold(float(val))
            self.refresh_ui()

    def _prompt_horizon(self):
        val = simpledialog.askfloat(
            "Forecast Horizon",
            "Enter prediction horizon in seconds:",
            initialvalue=self.engine.forecaster.horizon_sec,
            minvalue=1.0,
            maxvalue=120.0,
        )
        if val is not None:
            self.engine.set_horizon(float(val))
            self.refresh_ui()

    def _reset_canaries(self):
        self.engine.ensure_canaries()
        self.engine.log_event("INFO", "MANUAL_CANARY_RESET", "Manually reset canary tripwire files.")
        messagebox.showinfo("Canaries Reset", "Canary tripwire files have been refreshed.")

    def _manual_scan(self):
        self.engine.set_mode("manual")
        self.engine.scan_canaries()
        self.engine.scan_sockets()
        self.refresh_ui()

    def _get_selected_row_info(self) -> tuple[int, str] | None:
        sel = self.tree.selection()
        if not sel:
            return None
        vals = self.tree.item(sel[0], "values")
        return int(vals[0]), str(vals[1])

    def _update_reasoning_pane(self):
        info = self._get_selected_row_info()
        with self.engine.lock:
            steps = list(self.engine.latest_reasoning.get(info[0], [])) if info else []
            cf = dict(self.engine.latest_counterfactuals.get(info[0], {})) if info else {}
            stats = self.engine.weights_store.get_stat_summary(info[1]) if info else {}

        self.reason_text.configure(state=tk.NORMAL)
        self.reason_text.delete("1.0", tk.END)
        if not info:
            self.reason_text.insert(tk.END, "Select a process row above to view the evidence, risk factors, and decision summary.")
        elif not steps:
            self.reason_text.insert(tk.END, f"No reasoning steps recorded yet for PID {info[0]} ({info[1]}).")
        else:
            body = "\n\n".join(steps)
            if cf:
                body += (
                    f"\n\n[Counterfactual & Weight Stats] FP-Now={cf.get('fp_risk_if_act_now', 0):.0%}, "
                    f"Miss-Defer={cf.get('miss_risk_if_defer', 0):.0%}, "
                    f"Alerts={stats.get('alerts', 0)}, Containments={stats.get('containments', 0)}"
                )
            self.reason_text.insert(tk.END, body)
        self.reason_text.configure(state=tk.DISABLED)

    def _show_selected_reasoning(self):
        info = self._get_selected_row_info()
        if not info:
            messagebox.showwarning("No Selection", "Select a process row first.")
            return
        self._update_reasoning_pane()
        with self.engine.lock:
            steps = list(self.engine.latest_reasoning.get(info[0], []))
        messagebox.showinfo(f"Reasoning Trace — PID {info[0]} ({info[1]})", "\n\n".join(steps) if steps else "No trace available.")

    def _show_counterfactual_summary(self):
        info = self._get_selected_row_info()
        with self.engine.lock:
            cf = dict(self.engine.latest_counterfactuals.get(info[0], {})) if info else {}
            ledger = list(self.engine.suspended_ledger.values())

        lines = []
        if info and cf:
            lines.append(
                f"Selected PID {info[0]} ({info[1]}): "
                f"benign_prior={cf.get('benign_prior')}, fp_if_act_now={cf.get('fp_risk_if_act_now')}, "
                f"miss_if_defer={cf.get('miss_risk_if_defer')}, path={cf.get('recommended_path')}"
            )
        lines.append(f"Tracked Suspended PIDs ({len(ledger)}):")
        for item in ledger[:10]:
            lines.append(f"  - PID {item['pid']} ({item['process']}) score={item['score']}")
        messagebox.showinfo("Counterfactual & Containment Ledger", "\n".join(lines) if lines else "No data yet.")

    def _manual_snapshot(self):
        info = self._get_selected_row_info()
        if not info:
            messagebox.showwarning("No Selection", "Select a process row first.")
            return
        pid, name = info
        snap = self.engine.capture_forensic_snapshot(pid, name, "manual_snapshot", [])
        self.engine.log_event("INFO", "MANUAL_SNAPSHOT", f"Captured forensic snapshot for PID {pid} ({name}).", meta=snap)
        messagebox.showinfo("Snapshot Saved", f"Saved snapshot to {self.engine.snapshots_path}")

    def _feedback_selected(self, label: str):
        info = self._get_selected_row_info()
        if not info:
            messagebox.showwarning("No Selection", "Select a process row first.")
            return
        ok, message = self.engine.record_feedback(info[0], label)
        if ok:
            messagebox.showinfo("Feedback Saved", message)
        else:
            messagebox.showwarning("Feedback Not Saved", message)
        self.refresh_ui()

    def _adjust_selected_weight(self, delta: float):
        info = self._get_selected_row_info()
        if not info:
            messagebox.showwarning("No Selection", "Select a process row first.")
            return
        _, name = info
        with self.engine.lock:
            self.engine.weights_store.adjust_weight(name, delta, event_kind="manual_tune")
            new_w = self.engine.weights_store.get_weight(name)
        self.engine.log_event("INFO", "WEIGHT_ADJUST", f"Adjusted weight for '{name}' by {delta:+.2f} -> {new_w:.3f}x.")
        self.refresh_ui()

    def _reset_weights(self):
        with self.engine.lock:
            self.engine.weights_store.reset()
        self.engine.log_event("INFO", "WEIGHT_RESET", "Reset all learned process weights to 1.000x.")
        self.refresh_ui()

    def _export_log(self):
        if not self.engine.log_path.exists():
            messagebox.showinfo("Export Log", "No log file exists yet.")
            return
        dest = filedialog.asksaveasfilename(
            defaultextension=".jsonl",
            filetypes=[("JSON Lines", "*.jsonl"), ("Text", "*.txt"), ("All files", "*.*")],
            initialfile="defender_events_export.jsonl",
        )
        if dest:
            Path(dest).write_text(self.engine.log_path.read_text(encoding="utf-8"), encoding="utf-8")
            messagebox.showinfo("Exported", f"Exported events to {dest}")

    def _manual_pid(self, action: str):
        self.engine.set_mode("manual")
        info = self._get_selected_row_info()
        if not info:
            messagebox.showwarning("No PID Selected", "Select a process row first, then use 'Manual Selection'.")
            return
        pid, name = info
        if not messagebox.askyesno("Confirm Manual Action", f"{action.upper()} PID {pid} ({name})? (Mode set to 'manual')"):
            return
        if action in ("suspend", "terminate"):
            snap = self.engine.capture_forensic_snapshot(pid, name, f"manual_{action}", [])
        try:
            getattr(psutil.Process(pid), action)()
            if action in ("suspend", "terminate"):
                with self.engine.lock:
                    self.engine.weights_store.adjust_weight(name, +0.25, event_kind="containment")
                    if action == "suspend":
                        self.engine.suspended_ledger[pid] = {
                            "pid": pid,
                            "process": name,
                            "ts": time.time(),
                            "action": "suspend",
                            "score": 0.0,
                            "snapshot": snap,
                        }
            elif action == "resume":
                self.engine.allow_and_track_process(pid, name, register_rerun=True)
            self.engine.log_event("ALERT", "MANUAL_ACTION", f"Manually {action}d PID {pid} ({name}).")
            self.refresh_ui()
        except (psutil.NoSuchProcess, psutil.AccessDenied, NotImplementedError) as exc:
            messagebox.showerror("Action Failed", str(exc))

    def refresh_ui(self):
        with self.engine.lock:
            mode = self.engine.mode
            thresh = self.engine.threshold
            auto_act = self.engine.auto_action
            auto_rem = self.engine.auto_remediate
            auto_rerun = self.engine.auto_rerun
            horizon = self.engine.forecaster.horizon_sec
            rows = list(self.engine.latest_rows)

        self.mode_label.config(
            text=(
                f"24/7 Loop: RUNNING | Mode: {mode.upper()} | Auto-Action: {auto_act.upper()} | "
                f"Auto-Remediate: {'ON' if auto_rem else 'OFF'} | Auto-Rerun: {'ON' if auto_rerun else 'OFF'} | "
                f"Horizon: {horizon:.0f}s | Threshold: {thresh}"
            )
        )

        selected = self._get_selected_row_info()
        selected_pid = selected[0] if selected else None

        self.tree.delete(*self.tree.get_children())
        for r in rows[:50]:
            iid = self.tree.insert(
                "",
                tk.END,
                values=(
                    r["pid"],
                    r["name"],
                    r["status"],
                    r["count"],
                    r["delta_str"],
                    r["spread"],
                    r["projected"],
                    f"{r.get('deviation', 0.0):.2f} ({r.get('baseline_samples', 0)} samples)",
                    f"{r['weight']:.2f}x",
                    r["score"],
                    r["flag"],
                    r["origins"],
                    r["sample"],
                ),
            )
            if selected_pid is not None and r["pid"] == selected_pid:
                self.tree.selection_set(iid)

        self._update_reasoning_pane()

        if self.engine.log_path.exists():
            with self.engine.log_path.open("r", encoding="utf-8") as f:
                f.seek(self._log_pos)
                new_lines = f.readlines()
                self._log_pos = f.tell()
            if new_lines:
                self.log_text.configure(state=tk.NORMAL)
                for line in new_lines:
                    try:
                        ev = json.loads(line)
                        self.log_text.insert(
                            tk.END,
                            f"[{ev['timestamp']}] [{ev['severity']}] ({ev['mode']}) {ev['message']}\n",
                        )
                    except ValueError:
                        self.log_text.insert(tk.END, line)
                self.log_text.see(tk.END)
                self.log_text.configure(state=tk.DISABLED)

    def _poll(self):
        if not self.engine.stop_event.is_set():
            self.refresh_ui()
            self.root.after(2000, self._poll)


def run_cli_manual_prompt(engine: DefenderEngine):
    """Manual selection menu when running in --headless mode."""
    while not engine.stop_event.is_set():
        cmd = input("\nManual selection [m=menu, q=quit]: ").strip().lower()
        if cmd == "q":
            engine.stop_event.set()
            break
        if cmd == "m":
            print("1) Switch to 24/7 AUTO mode")
            print("2) Switch to MANUAL mode")
            print("3) Reset canary tripwires")
            print("4) Suspend a PID (with forensic snapshot)")
            print("5) Resume a PID (and persist as allowed/rerun)")
            print("6) Terminate a PID (with forensic snapshot)")
            print("7) View reasoning trace for a PID")
            print("8) Reset learned weights")
            print("9) View counterfactual & suspended PID ledger")
            print("10) Snoop & World-Origin trace for a PID")
            print("11) Allow & Persist a PID to run/not be blocked across reboots")
            print("12) Rerun saved selections now & view state")
            choice = input("Select option: ").strip()
            if choice == "1":
                engine.set_mode("auto")
            elif choice == "2":
                engine.set_mode("manual")
            elif choice == "3":
                engine.ensure_canaries()
                engine.log_event("INFO", "MANUAL_CANARY_RESET", "Canaries reset via CLI.")
            elif choice in ("4", "5", "6"):
                engine.set_mode("manual")
                pid_str = input("Enter target PID: ").strip()
                if pid_str.isdigit():
                    pid = int(pid_str)
                    verb = "suspend" if choice == "4" else ("resume" if choice == "5" else "terminate")
                    try:
                        proc = psutil.Process(pid)
                        pname = proc.name()
                        if verb in ("suspend", "terminate"):
                            engine.capture_forensic_snapshot(pid, pname, f"cli_manual_{verb}", [])
                        getattr(proc, verb)()
                        if verb == "resume":
                            engine.allow_and_track_process(pid, pname, register_rerun=True)
                        engine.log_event("ALERT", "MANUAL_ACTION", f"Manually {verb}d PID {pid} ({pname}).")
                    except Exception as exc:
                        print(f"Error: {exc}")
            elif choice == "7":
                pid_str = input("Enter PID to inspect reasoning: ").strip()
                if pid_str.isdigit():
                    with engine.lock:
                        steps = list(engine.latest_reasoning.get(int(pid_str), []))
                    print("\n".join(steps) if steps else "No decision trace for that PID.")
            elif choice == "8":
                with engine.lock:
                    engine.weights_store.reset()
                print("Learned weights reset to 1.0x.")
            elif choice == "9":
                with engine.lock:
                    ledger = list(engine.suspended_ledger.values())
                    cfs = dict(engine.latest_counterfactuals)
                print(f"Suspended PIDs: {len(ledger)}")
                for item in ledger:
                    print(f"  PID {item['pid']} ({item['process']}) score={item['score']}")
                for pid, cf in list(cfs.items())[:8]:
                    print(f"  PID {pid} CF: {cf}")
            elif choice == "10":
                pid_str = input("Enter PID (or -1 for unowned/restricted): ").strip()
                try:
                    pid = int(pid_str)
                    rep = engine.snoop_pid(pid, resolve_geo=True)
                    print(json.dumps(rep, indent=2))
                except ValueError:
                    print("Invalid PID.")
            elif choice == "11":
                pid_str = input("Enter PID to allow & save for reboot: ").strip()
                if pid_str.isdigit():
                    pid = int(pid_str)
                    try:
                        pname = psutil.Process(pid).name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pname = input("Enter process name: ").strip()
                    if pname:
                        rec = engine.allow_and_track_process(pid, pname, register_rerun=True)
                        print("Saved:", rec)
            elif choice == "12":
                started = engine.rerun_saved_selections(force=True)
                print("Started:", started)
                print("Allowed:", sorted(engine.allowed_processes))
                print("Rerun targets:", engine.rerun_targets)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--dir", type=Path, default=Path.home() / ".agentic_defender")
    parser.add_argument("--mode", choices=["auto", "manual"], default="auto")
    parser.add_argument("--interval", type=float, default=2.0)
    parser.add_argument("--threshold", type=float, default=8.0)
    parser.add_argument("--auto-action", choices=["suspend", "terminate"], default="suspend")
    parser.add_argument("--horizon", type=float, default=10.0, help="Forecast horizon in seconds")
    parser.add_argument("--grace-sec", type=float, default=60.0, help="Observation grace window before auto-remediation")
    parser.add_argument("--auto-remediate", action="store_true", help="Automatically resume suspended PIDs if burst subsides after grace window")
    parser.add_argument("--no-auto-rerun", action="store_true", help="Do not automatically relaunch saved user selections on startup")
    parser.add_argument("--headless", action="store_true", help="Run without GUI window, keeping 24/7 loop + manual CLI menu")
    args = parser.parse_args()

    cli_overrides: set[str] = set()
    import sys
    for idx, tok in enumerate(sys.argv[1:]):
        if tok.startswith("--"):
            flag = tok.split("=", 1)[0].lstrip("-").replace("-", "_")
            if flag == "horizon":
                flag = "horizon_sec"
            if flag == "no_auto_rerun":
                flag = "auto_rerun"
            cli_overrides.add(flag)

    engine = DefenderEngine(
        args.dir,
        mode=args.mode,
        interval=args.interval,
        threshold=args.threshold,
        auto_action=args.auto_action,
        horizon_sec=args.horizon,
        grace_sec=args.grace_sec,
        auto_remediate=args.auto_remediate,
        auto_rerun=not args.no_auto_rerun,
        cli_overrides=cli_overrides,
    )
    worker_thread = threading.Thread(target=engine.run_loop, name="Defender24x7Thread", daemon=True)
    worker_thread.start()

    def _handle_sig(*_a):
        engine.stop_event.set()

    signal.signal(signal.SIGINT, _handle_sig)
    signal.signal(signal.SIGTERM, _handle_sig)

    if args.headless:
        try:
            run_cli_manual_prompt(engine)
        finally:
            engine.stop_event.set()
            worker_thread.join(timeout=3.0)
        return

    root = tk.Tk()
    app = DefenderAppGUI(root, engine)

    def _on_close():
        engine.stop_event.set()
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", _on_close)
    root.mainloop()
    worker_thread.join(timeout=3.0)


if __name__ == "__main__":
    main()