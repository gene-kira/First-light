#!/usr/bin/env python3
# ============================================================
#  GlassShield++ Dominion Sentinel Security Governor (Ultra+ AI, Outbound Obfuscation)
#  - 24/7 daemon
#  - All-PID + network monitoring (via psutil)
#  - Baseline learning + AI-style anomaly scoring (stats-based)
#  - Deep heuristics (process origin, cmdline, resurrection)
#  - Color classification (GREEN / YELLOW / RED in memory only)
#  - Risk zones (system / user / unknown / high_risk)
#  - Process history tracking (in memory)
#  - Network connection history (in memory)
#  - Threat timeline per caller (in memory)
#  - Process origin tracing (path, cmdline, parent PID)
#  - Auto-tagging known Windows processes
#  - Suspicious behavior heuristics + clustering
#  - NO enforcement (no kill, no block)
#  - NO disk logging / NO file writes
#  - GPU/VRAM-assisted entropy (NVML, optional)
#  - Heat Signature Mask mode (for obfuscation if desired)
#  - Swarm sync (optional)
#  - GlassShield applied across system telemetry
#  - Remote dashboard (HTTP JSON, in-memory only)
#  - OUTBOUND DATA OBFUSCATION (network + telemetry)
# ============================================================

import importlib
import sys
import os
import hashlib
import json
import time
import traceback
from math import sqrt
from datetime import datetime
from threading import Thread, Lock
from http.server import BaseHTTPRequestHandler, HTTPServer

# ============================================================
# AUTOLOADER
# ============================================================

REQUIRED_LIBS = ["cryptography", "requests"]
OPTIONAL_GPU_LIBS = ["cupy", "pynvml", "psutil"]

def autoload_libraries():
    missing = []
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            missing.append(lib)

    if missing:
        print("[GS] Installing required libs:", missing)
        import subprocess
        subprocess.check_call([sys.executable, "-m", "pip", "install"] + missing)

    for lib in OPTIONAL_GPU_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            print(f"[GS] Optional lib '{lib}' not found. Feature degraded.")

autoload_libraries()

from cryptography.fernet import Fernet
import requests

# GPU / NVML flags
try:
    import cupy as cp
    GPU_AVAILABLE = True
except Exception:
    GPU_AVAILABLE = False

try:
    import pynvml
    pynvml.nvmlInit()
    NVML_AVAILABLE = True
except Exception:
    NVML_AVAILABLE = False

# psutil for real-world process info
try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    PSUTIL_AVAILABLE = False

# ============================================================
# GPU TELEMETRY
# ============================================================

def get_gpu_telemetry():
    if not NVML_AVAILABLE:
        return {"temp": None, "vram_used": None, "vram_total": None}
    try:
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        return {
            "temp": int(temp),
            "vram_used": int(mem.used),
            "vram_total": int(mem.total),
        }
    except Exception as e:
        print("[GS] NVML telemetry failed:", e)
        return {"temp": None, "vram_used": None, "vram_total": None}

# ============================================================
# REAL-WORLD HELPERS
# ============================================================

def get_process_tag(pid=None):
    if not PSUTIL_AVAILABLE:
        return "process::unknown"
    try:
        if pid is None:
            p = psutil.Process()
        else:
            p = psutil.Process(pid)
        name = p.name()
        return f"process::{name}:{p.pid}"
    except Exception:
        return "process::unknown"

def get_file_tag(path):
    return f"file::{os.path.abspath(path)}"

def get_network_tag(remote_addr, remote_port):
    return f"network::{remote_addr}:{remote_port}"

def get_process_origin(pid):
    if not PSUTIL_AVAILABLE:
        return {"pid": pid, "name": None, "exe": None, "cmdline": None, "ppid": None}
    try:
        p = psutil.Process(pid)
        return {
            "pid": pid,
            "name": p.name(),
            "exe": p.exe() if p.exe() else None,
            "cmdline": " ".join(p.cmdline()) if p.cmdline() else None,
            "ppid": p.ppid(),
        }
    except Exception:
        return {"pid": pid, "name": None, "exe": None, "cmdline": None, "ppid": None}

# ============================================================
# GLASSSHIELD CORE
# ============================================================

class GlassShield:
    def __init__(self, swarm_endpoint=None, node_id="glass-node-01"):
        self.key = Fernet.generate_key()
        self.crypto = Fernet(self.key)

        # Watch-only: allow_raw=True, block_untrusted=False
        self.policy = {
            "allow_raw": True,
            "allow_meta": True,
            "obfuscation_level": 3,   # default mid-level
            "log_access": False,      # no disk logging
            "block_untrusted": False,
            "gpu_enabled": GPU_AVAILABLE,
            "nvml_enabled": NVML_AVAILABLE,
            "swarm_enabled": swarm_endpoint is not None,
            "heat_mask_mode": True,
        }

        self.access_log = []            # kept in memory only if enabled
        self.trusted_callers = set()
        self.lock = Lock()

        self.swarm_endpoint = swarm_endpoint
        self.node_id = node_id

        self.resurrection_map = {}
        self.threat_scores = {}

        if self.policy["swarm_enabled"]:
            Thread(target=self._swarm_heartbeat, daemon=True).start()

    # ---------------- TRUST ----------------

    def add_trusted(self, caller_id):
        with self.lock:
            self.trusted_callers.add(caller_id)

    def is_trusted(self, caller_id):
        with self.lock:
            return caller_id in self.trusted_callers

    # ---------------- RESURRECTION GLYPHS ----------------

    def _update_resurrection(self, caller_id):
        with self.lock:
            self.resurrection_map[caller_id] = self.resurrection_map.get(caller_id, 0) + 1
            count = self.resurrection_map[caller_id]
        glyph = hashlib.sha256(f"{caller_id}:{count}".encode()).hexdigest()[:12]
        return glyph, count

    # ---------------- GPU / VRAM ENTROPY ----------------

    def _gpu_entropy(self, length=512):
        try:
            if self.policy["gpu_enabled"]:
                buf = cp.random.randint(0, 256, size=length, dtype=cp.uint8)
                return cp.asnumpy(buf).tobytes()
        except Exception as e:
            print("[GS] GPU entropy failed:", e)
            traceback.print_exc()
        return os.urandom(length)

    # ---------------- HEAT SIGNATURE MASK ----------------

    def _heat_signature_mask(self, data: str):
        telem = get_gpu_telemetry()
        temp = telem["temp"]
        used = telem["vram_used"]
        total = telem["vram_total"]

        if temp is None or used is None or total is None:
            return "### HEAT MASK (no telemetry) ###"

        usage_ratio = used / total if total > 0 else 0.0

        if temp < 50 and usage_ratio < 0.3:
            return "### HEAT MASK: LOW ACTIVITY ###"
        elif temp < 70:
            return "### HEAT MASK: MEDIUM ACTIVITY ###"
        else:
            return "### HEAT MASK: HIGH ACTIVITY ###"

    # ---------------- OBFUSCATION (USED FOR OUTBOUND DATA) ----------------

    def obfuscate(self, data: str) -> str:
        lvl = self.policy["obfuscation_level"]
        try:
            entropy = self._gpu_entropy()
            telem = get_gpu_telemetry()
            temp = telem["temp"]
            vram_used = telem["vram_used"]
            vram_total = telem["vram_total"]

            telemetry_str = f"T={temp};U={vram_used};TOT={vram_total}"
            curve_seed = hashlib.sha256(entropy + telemetry_str.encode()).hexdigest()[:16]
            base_hash = hashlib.sha256((data + curve_seed).encode()).hexdigest()

            if self.policy["heat_mask_mode"] and lvl >= 4:
                return self._heat_signature_mask(data)

            if lvl == 1:
                return base_hash[:16]
            if lvl == 2:
                return base_hash
            if lvl == 3:
                enc = self.crypto.encrypt((data + "|curve=" + curve_seed).encode()).decode()
                return enc[:32] + "...opaque"
            if lvl == 4:
                return f"### DATA BLOCKED (curve={curve_seed}) ###"
            if lvl == 5:
                return "### COMPLETE OPACITY ###"
            return "### UNKNOWN LEVEL ###"
        except Exception as e:
            print("[GS] Obfuscation failure:", e)
            traceback.print_exc()
            return "### OBFUSCATION ERROR ###"

    # ---------------- THREAT SCORING ----------------

    def _compute_threat_score(self, caller_id, status, meta):
        base = 0.0

        if status == "blocked":
            base += 5.0
        elif status == "filtered":
            base += 2.0
        elif status == "raw":
            base += 0.5
        elif status == "error":
            base += 7.0

        glyph, count = self._update_resurrection(caller_id)
        base += count * 0.5

        if caller_id.startswith("dominiondeck::"):
            base += 1.0
        if caller_id.startswith("sentinel::"):
            base += 3.0
        if caller_id.startswith("process::"):
            base += 1.5
        if caller_id.startswith("file::"):
            base += 1.0
        if caller_id.startswith("network::"):
            base += 2.0

        telem = get_gpu_telemetry()
        temp = telem["temp"]
        if temp is not None:
            base += max(0, (temp - 60) * 0.1)

        score = round(base, 2)

        meta["resurrection_count"] = count

        with self.lock:
            self.threat_scores[caller_id] = {
                "score": score,
                "glyph": glyph,
                "last_status": status,
                "last_meta": meta,
            }

        return score, glyph

    # ---------------- ACCESS FILTER (INTERNAL, RAW) ----------------

    def access(self, caller_id, data: str):
        try:
            timestamp = datetime.now().isoformat()
            meta = {
                "caller": caller_id,
                "time": timestamp,
                "length": len(data),
                "hash": hashlib.sha256(data.encode()).hexdigest()[:12],
            }

            if self.policy["log_access"]:
                with self.lock:
                    self.access_log.append(meta)

            status = "raw"
            score, glyph = self._compute_threat_score(caller_id, status, meta)
            meta["threat_score"] = score
            meta["glyph"] = glyph
            self._swarm_report(status, caller_id, meta)
            return {
                "status": status,
                "visible": data,
                "meta": meta,
            }
        except Exception as e:
            print("[GS] ACCESS FAILURE:", e)
            traceback.print_exc()
            meta = {"caller": caller_id, "time": datetime.now().isoformat()}
            score, glyph = self._compute_threat_score(caller_id, "error", meta)
            meta["threat_score"] = score
            meta["glyph"] = glyph
            return {"status": "error", "visible": None, "meta": meta}

    # ---------------- OUTBOUND ACCESS (OBFUSCATED) ----------------

    def outbound(self, caller_id, data: str):
        """
        For data leaving the system (telemetry, network payloads, etc.).
        Returns obfuscated data as 'visible'.
        """
        try:
            timestamp = datetime.now().isoformat()
            meta = {
                "caller": caller_id,
                "time": timestamp,
                "length": len(data),
                "hash": hashlib.sha256(data.encode()).hexdigest()[:12],
                "outbound": True,
            }

            obfuscated = self.obfuscate(data)

            status = "raw"
            score, glyph = self._compute_threat_score(caller_id, status, meta)
            meta["threat_score"] = score
            meta["glyph"] = glyph
            self._swarm_report(status, caller_id, meta)
            return {
                "status": status,
                "visible": obfuscated,
                "meta": meta,
            }
        except Exception as e:
            print("[GS] OUTBOUND FAILURE:", e)
            traceback.print_exc()
            meta = {"caller": caller_id, "time": datetime.now().isoformat(), "outbound": True}
            score, glyph = self._compute_threat_score(caller_id, "error", meta)
            meta["threat_score"] = score
            meta["glyph"] = glyph
            return {"status": "error", "visible": None, "meta": meta}

    # ---------------- POLICY CONTROL ----------------

    def set_policy(self, **kwargs):
        with self.lock:
            for k, v in kwargs.items():
                if k in self.policy:
                    self.policy[k] = v

    # ---------------- SWARM SYNC ----------------

    def _swarm_heartbeat(self):
        while True:
            try:
                payload = {
                    "node_id": self.node_id,
                    "ts": datetime.now().isoformat(),
                    "policy": self.policy,
                }
                requests.post(self.swarm_endpoint + "/heartbeat", json=payload, timeout=2)
            except Exception:
                pass
            time.sleep(10)

    def _swarm_report(self, status, caller_id, meta):
        if not self.policy["swarm_enabled"]:
            return
        try:
            payload = {
                "node_id": self.node_id,
                "status": status,
                "caller": caller_id,
                "meta": meta,
            }
            requests.post(self.swarm_endpoint + "/event", json=payload, timeout=2)
        except Exception:
            pass

    # ---------------- DOMINIONDECK / SENTINEL HOOKS ----------------
    # Internal telemetry can use outbound() if it's leaving the box.

    def dominiondeck_guard(self, source, payload: str, outbound=False):
        cid = f"dominiondeck::{source}"
        if outbound:
            return self.outbound(cid, payload)
        return self.access(cid, payload)

    def sentinel_guard(self, module, payload: str, outbound=False):
        cid = f"sentinel::{module}"
        if outbound:
            return self.outbound(cid, payload)
        return self.access(cid, payload)

    # ---------------- REAL-WORLD HOOKS ----------------

    def process_guard(self, pid=None, payload: str = ""):
        tag = get_process_tag(pid)
        return self.access(tag, payload)

    def file_guard(self, path: str, payload: str = ""):
        tag = get_file_tag(path)
        return self.access(tag, payload)

    def network_guard(self, remote_addr: str, remote_port: int, payload: str = "", outbound=True):
        """
        For network, we treat payload as outbound by default.
        """
        tag = get_network_tag(remote_addr, remote_port)
        if outbound:
            return self.outbound(tag, payload)
        return self.access(tag, payload)

# ============================================================
# SECURITY GOVERNOR + ANOMALY ENGINE + CLUSTERING (NO ENFORCEMENT)
# ============================================================

KNOWN_SYSTEM_PROCESSES = {
    "System",
    "smss.exe",
    "csrss.exe",
    "wininit.exe",
    "services.exe",
    "lsass.exe",
    "svchost.exe",
    "explorer.exe",
    "winlogon.exe",
    "dwm.exe",
    "spoolsv.exe",
}

class SecurityGovernor:
    def __init__(self, swarm_endpoint=None, node_id="secgov-node-01"):
        self.gs = GlassShield(swarm_endpoint=swarm_endpoint, node_id=node_id)

        self.baseline = {}          # caller_id -> {count, avg_score, m2, last_seen}
        self.process_history = {}   # pid -> [events]
        self.network_history = []   # list of {remote, port, time, caller}
        self.alert_log = []         # list of alerts (in memory only)
        self.clusters = {
            "process_name": {},     # name -> {count, avg_score}
            "remote_ip": {},        # ip -> {count, avg_score}
        }
        self.threat_timeline = {}   # caller_id -> list of {time, score, color, anomaly}
        self.lock = Lock()

        self.enforcement_enabled = False  # watch-only

    # ---------------- TRUST / POLICY ----------------

    def trust(self, caller_id):
        self.gs.add_trusted(caller_id)

    def set_policy(self, **kwargs):
        self.gs.set_policy(**kwargs)

    # ---------------- BASELINE / ANOMALY (Welford) ----------------

    def _update_baseline(self, caller_id, score):
        now = datetime.now().isoformat()
        with self.lock:
            entry = self.baseline.get(
                caller_id,
                {"count": 0, "avg_score": 0.0, "m2": 0.0, "last_seen": None},
            )
            c_prev = entry["count"]
            c = c_prev + 1
            mean_prev = entry["avg_score"]
            delta = score - mean_prev
            mean = mean_prev + delta / c
            delta2 = score - mean
            m2 = entry["m2"] + delta * delta2

            entry["count"] = c
            entry["avg_score"] = mean
            entry["m2"] = m2
            entry["last_seen"] = now
            self.baseline[caller_id] = entry
        return entry

    def _baseline_stats(self, caller_id):
        entry = self.baseline.get(caller_id)
        if not entry or entry["count"] < 2:
            return entry, None, None
        c = entry["count"]
        mean = entry["avg_score"]
        var = entry["m2"] / (c - 1)
        std = sqrt(var) if var > 0 else None
        return entry, mean, std

    def _anomaly_score(self, caller_id, score):
        entry, mean, std = self._baseline_stats(caller_id)
        if mean is None or std is None or std == 0:
            return 0.0
        z = (score - mean) / std
        return round(z, 2)

    def _is_known_system_process(self, caller_id):
        if not caller_id.startswith("process::"):
            return False
        try:
            name_part = caller_id.split("::", 1)[1]
            name = name_part.split(":", 1)[0]
            return name in KNOWN_SYSTEM_PROCESSES
        except Exception:
            return False

    # ---------------- DEEP HEURISTICS ----------------

    def _heuristics_suspicious(self, caller_id, info, anomaly_score):
        score = info.get("score", 0.0)
        meta = info.get("last_meta", {}) or {}
        resurrection = meta.get("resurrection_count", 0)
        status = info.get("last_status", "")

        suspicious_reasons = []

        if score >= 12.0:
            suspicious_reasons.append(f"high threat score={score}")
        if resurrection >= 5:
            suspicious_reasons.append(f"high resurrection_count={resurrection}")
        if status == "blocked":
            suspicious_reasons.append("blocked by policy")
        if anomaly_score >= 2.5:
            suspicious_reasons.append(f"strong anomaly (z={anomaly_score})")
        if caller_id.startswith("network::") and score >= 8.0:
            suspicious_reasons.append("network caller with elevated score")
        if caller_id.startswith("process::") and not self._is_known_system_process(caller_id) and score >= 8.0:
            suspicious_reasons.append("unknown process with elevated score")

        if caller_id.startswith("process::"):
            try:
                name_part = caller_id.split("::", 1)[1]
                name, pid_str = name_part.split(":", 1)
                pid = int(pid_str)
            except Exception:
                name = "unknown"
                pid = None

            origin = get_process_origin(pid)
            exe = origin.get("exe")
            cmdline = origin.get("cmdline")
            ppid = origin.get("ppid")

            if exe and "temp" in exe.lower():
                suspicious_reasons.append("process running from temp directory")
            if cmdline and ("-enc" in cmdline.lower() or "powershell" in cmdline.lower()):
                suspicious_reasons.append("potential encoded or powershell payload")
            if ppid in (None, 0):
                suspicious_reasons.append("orphan process (no parent)")

        return suspicious_reasons

    def _color_for_info(self, caller_id, info, reasons, anomaly_score):
        score = info.get("score", 0.0)
        meta = info.get("last_meta", {}) or {}
        resurrection = meta.get("resurrection_count", 0)

        if reasons:
            return "RED"
        if anomaly_score >= 2.5:
            return "RED"
        if self._is_known_system_process(caller_id) and score < 5.0 and resurrection < 3 and anomaly_score < 1.5:
            return "GREEN"
        if score < 5.0 and resurrection < 3 and anomaly_score < 1.5:
            return "GREEN"
        if score < 10.0 and anomaly_score < 2.0:
            return "YELLOW"
        return "RED"

    def _risk_zone(self, caller_id, color, anomaly_score, score):
        if self._is_known_system_process(caller_id):
            if color == "GREEN" and anomaly_score < 1.5:
                return "system"
            return "system_watch"

        if caller_id.startswith("dominiondeck::") or caller_id.startswith("sentinel::"):
            if color == "GREEN" and anomaly_score < 1.5:
                return "user"
            return "user_watch"

        if color == "RED" or anomaly_score >= 2.5 or score >= 12.0:
            return "high_risk"

        return "unknown"

    def _apply_glassshield_mode_for_color(self, color):
        if color == "GREEN":
            self.gs.set_policy(
                allow_raw=True,
                block_untrusted=False,
                obfuscation_level=1,
            )
        elif color == "YELLOW":
            self.gs.set_policy(
                allow_raw=True,
                block_untrusted=False,
                obfuscation_level=2,
            )
        elif color == "RED":
            self.gs.set_policy(
                allow_raw=True,
                block_untrusted=False,
                obfuscation_level=3,
            )

    # ---------------- CLUSTERING ----------------

    def _update_clusters_for_process(self, name, score):
        with self.lock:
            entry = self.clusters["process_name"].get(name, {"count": 0, "avg_score": 0.0})
            c = entry["count"] + 1
            avg = (entry["avg_score"] * entry["count"] + score) / c
            entry["count"] = c
            entry["avg_score"] = avg
            self.clusters["process_name"][name] = entry

    def _update_clusters_for_remote(self, remote, score):
        with self.lock:
            entry = self.clusters["remote_ip"].get(remote, {"count": 0, "avg_score": 0.0})
            c = entry["count"] + 1
            avg = (entry["avg_score"] * entry["count"] + score) / c
            entry["count"] = c
            entry["avg_score"] = avg
            self.clusters["remote_ip"][remote] = entry

    # ---------------- THREAT TIMELINE ----------------

    def _update_timeline(self, caller_id, time_str, score, color, anomaly_score):
        with self.lock:
            tl = self.threat_timeline.get(caller_id, [])
            tl.append({
                "time": time_str,
                "score": score,
                "color": color,
                "anomaly": anomaly_score,
            })
            if len(tl) > 200:
                tl = tl[-200:]
            self.threat_timeline[caller_id] = tl

    # ---------------- ALERT (NO ENFORCEMENT, IN-MEMORY ONLY) ----------------

    def _alert(self, caller_id, info, reasons, color, anomaly_score, zone):
        ts = datetime.now().isoformat()
        alert = {
            "time": ts,
            "caller": caller_id,
            "score": info.get("score"),
            "glyph": info.get("glyph"),
            "status": info.get("last_status"),
            "reasons": reasons,
            "color": color,
            "anomaly": anomaly_score,
            "zone": zone,
        }
        with self.lock:
            self.alert_log.append(alert)

        print(f"[ALERT-{color}/{zone}] {ts} :: {caller_id} :: z={anomaly_score} :: reasons={reasons} :: score={info.get('score')}")

    def _enforce(self, caller_id, info, color):
        print(f"[ENFORCE-DISABLED-{color}] Would act on {caller_id} (score={info.get('score')}) but enforcement is OFF.")

    # ---------------- POST EVENT ----------------

    def _post_event(self, caller_id, result):
        meta = result.get("meta") or {}
        score = meta.get("threat_score", 0.0)

        baseline_entry = self._update_baseline(caller_id, score)
        anomaly_score = self._anomaly_score(caller_id, score)

        info = self.gs.threat_scores.get(caller_id, {})
        if not info:
            info = {
                "score": score,
                "glyph": meta.get("glyph"),
                "last_status": result.get("status"),
                "last_meta": meta,
            }

        reasons = self._heuristics_suspicious(caller_id, info, anomaly_score)
        color = self._color_for_info(caller_id, info, reasons, anomaly_score)
        zone = self._risk_zone(caller_id, color, anomaly_score, score)

        self._apply_glassshield_mode_for_color(color)

        info["color"] = color
        info["anomaly"] = anomaly_score
        info["zone"] = zone
        self.gs.threat_scores[caller_id] = info

        time_str = meta.get("time", datetime.now().isoformat())
        self._update_timeline(caller_id, time_str, score, color, anomaly_score)

        if caller_id.startswith("process::"):
            try:
                name_part = caller_id.split("::", 1)[1]
                name, pid_str = name_part.split(":", 1)
                pid = int(pid_str)
            except Exception:
                pid = None
                name = "unknown"

            origin = get_process_origin(pid)

            event = {
                "time": time_str,
                "name": name,
                "pid": pid,
                "score": info.get("score"),
                "status": info.get("last_status"),
                "glyph": info.get("glyph"),
                "color": color,
                "anomaly": anomaly_score,
                "zone": zone,
                "origin": origin,
            }
            with self.lock:
                hist = self.process_history.get(pid, [])
                hist.append(event)
                if len(hist) > 200:
                    hist = hist[-200:]
                self.process_history[pid] = hist

            self._update_clusters_for_process(name, info.get("score", 0.0))

        if caller_id.startswith("network::"):
            try:
                net_part = caller_id.split("::", 1)[1]
                remote, port_str = net_part.split(":", 1)
                port = int(port_str)
            except Exception:
                remote = "unknown"
                port = None

            conn_event = {
                "time": time_str,
                "remote": remote,
                "port": port,
                "score": info.get("score"),
                "status": info.get("last_status"),
                "glyph": info.get("glyph"),
                "caller": caller_id,
                "color": color,
                "anomaly": anomaly_score,
                "zone": zone,
            }
            with self.lock:
                self.network_history.append(conn_event)
                if len(self.network_history) > 1000:
                    self.network_history = self.network_history[-1000:]

            self._update_clusters_for_remote(remote, info.get("score", 0.0))

        if reasons:
            self._alert(caller_id, info, reasons, color, anomaly_score, zone)

    # ---------------- GUARD WRAPPERS ----------------

    def guard_generic(self, caller_id, payload: str, outbound=False):
        if outbound:
            result = self.gs.outbound(caller_id, payload)
        else:
            result = self.gs.access(caller_id, payload)
        self._post_event(caller_id, result)
        return result

    def guard_dominiondeck(self, source, payload: str, outbound=False):
        result = self.gs.dominiondeck_guard(source, payload, outbound=outbound)
        caller_id = f"dominiondeck::{source}"
        self._post_event(caller_id, result)
        return result

    def guard_sentinel(self, module, payload: str, outbound=False):
        result = self.gs.sentinel_guard(module, payload, outbound=outbound)
        caller_id = f"sentinel::{module}"
        self._post_event(caller_id, result)
        return result

    def guard_process(self, pid=None, payload: str = ""):
        caller_id = get_process_tag(pid)
        result = self.gs.process_guard(pid, payload)
        self._post_event(caller_id, result)
        return result

    def guard_file(self, path: str, payload: str = ""):
        caller_id = get_file_tag(path)
        result = self.gs.file_guard(path, payload)
        self._post_event(caller_id, result)
        return result

    def guard_network(self, remote_addr: str, remote_port: int, payload: str = "", outbound=True):
        caller_id = get_network_tag(remote_addr, remote_port)
        result = self.gs.network_guard(remote_addr, remote_port, payload, outbound=outbound)
        self._post_event(caller_id, result)
        return result

    @property
    def threat_scores(self):
        return self.gs.threat_scores

    def snapshot_state(self):
        with self.lock:
            return {
                "baseline": self.baseline,
                "clusters": self.clusters,
                "alerts": self.alert_log[-100:],
                "process_history_size": {pid: len(events) for pid, events in self.process_history.items()},
                "network_history_size": len(self.network_history),
                "timeline_size": {cid: len(tl) for cid, tl in self.threat_timeline.items()},
            }

    def snapshot_timeline(self, max_entries=50):
        with self.lock:
            out = {}
            for cid, tl in self.threat_timeline.items():
                out[cid] = tl[-max_entries:]
            return out

# ============================================================
# REMOTE DASHBOARD (HTTP JSON, IN-MEMORY ONLY)
# ============================================================

class DashboardHandler(BaseHTTPRequestHandler):
    secgov_ref = None

    def _send_json(self, obj, code=200):
        data = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        if self.path == "/status":
            if DashboardHandler.secgov_ref is None:
                self._send_json({"error": "no secgov"}, 500)
                return
            snapshot = DashboardHandler.secgov_ref.snapshot_state()
            self._send_json(snapshot)
        elif self.path == "/threats":
            if DashboardHandler.secgov_ref is None:
                self._send_json({"error": "no secgov"}, 500)
                return
            self._send_json(DashboardHandler.secgov_ref.threat_scores)
        elif self.path == "/timeline":
            if DashboardHandler.secgov_ref is None:
                self._send_json({"error": "no secgov"}, 500)
                return
            self._send_json(DashboardHandler.secgov_ref.snapshot_timeline())
        else:
            self._send_json({"error": "unknown endpoint"}, 404)

def launch_dashboard_async(secgov: SecurityGovernor, host="127.0.0.1", port=8088):
    def _run():
        try:
            DashboardHandler.secgov_ref = secgov
            server = HTTPServer((host, port), DashboardHandler)
            print(f"[DASHBOARD] Listening on http://{host}:{port}")
            server.serve_forever()
        except Exception as e:
            print("[DASHBOARD] Failed:", e)
    Thread(target=_run, daemon=True).start()

# ============================================================
# DAEMON LOOP (24/7, ALL PIDs + NETWORK, NO DISK WRITES)
# ============================================================

def daemon_loop(secgov: SecurityGovernor):
    print("\n=== GlassShield++ Daemon Started (Ultra+ AI, Outbound Obfuscation, Watch-Only, No Disk Logging) ===\n")
    tick = 0
    while True:
        tick += 1
        try:
            if PSUTIL_AVAILABLE:
                for proc in psutil.process_iter(["pid", "name"]):
                    try:
                        pid = proc.info.get("pid")
                        name = proc.info.get("name", "unknown")
                        payload = f"name={name};tick={tick}"
                        secgov.guard_process(pid=pid, payload=payload)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                    except Exception as e:
                        print("[GS] Error guarding process:", e)
                        continue
            else:
                secgov.guard_process(payload=f"daemon_tick={tick}")

            if PSUTIL_AVAILABLE:
                try:
                    conns = psutil.net_connections(kind="inet")
                    for c in conns:
                        if c.raddr:
                            remote = c.raddr.ip
                            port = c.raddr.port
                            payload = f"status={c.status};tick={tick}"
                            secgov.guard_network(remote, port, payload, outbound=True)
                except Exception as e:
                    print("[GS] Error reading net connections:", e)

            example_path = "example.txt"
            if os.path.exists(example_path):
                secgov.guard_file(example_path, payload=f"file_tick={tick}")

            # Internal telemetry; if you ever send this out, call outbound=True
            secgov.guard_dominiondeck("telemetry", f"FPS=144;GPU=72C;tick={tick}", outbound=False)
            secgov.guard_sentinel("threat_scanner", f"score=0.03;normalized=true;tick={tick}", outbound=False)

            time.sleep(5)
        except KeyboardInterrupt:
            print("\n[GS] KeyboardInterrupt received, stopping daemon loop.")
            break
        except Exception as e:
            print("[GS] Daemon loop error:", e)
            traceback.print_exc()
            time.sleep(2)

    print("[GS] Daemon loop exited.")

# ============================================================
# MAIN
# ============================================================

def main():
    secgov = SecurityGovernor(
        swarm_endpoint=None,
        node_id="secgov-node-01",
    )

    secgov.trust("camera_module")
    for name in KNOWN_SYSTEM_PROCESSES:
        secgov.trust(f"process::{name}")

    launch_dashboard_async(secgov, host="127.0.0.1", port=8088)

    daemon_loop(secgov)

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        print("FATAL:", e)
        traceback.print_exc()
        time.sleep(3)
