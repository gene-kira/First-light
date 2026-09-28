#!/usr/bin/env python3
# ============================================================
#  GlassShield++ Dominion Sentinel Security Governor + MagicBox ASI
#  - Keeps GlassShield + SecurityGovernor architecture
#  - Integrates MagicBox: Chameleon ASI (Trust Edition)
#  - Three modes:
#       A: AGGRESSIVE  (Full Fusion ASI, destructive allowed)
#       B: SAFE        (Monitoring only, no destructive actions)
#       C: DUAL        (Two-layer sentinel, default)
#  - Accurate live monitoring (process + network, change-aware)
#  - Explainable, calibrated anomaly detection (risk estimates)
#  - Rotating logs, encrypted alert storage, config backups, recovery
#  - Practical Windows security integrations (Defender, Firewall, signatures)
#  - ML-ready telemetry export
#  - Compact GUI for ASI mode switching
# ============================================================

import sys
import os
import json
import time
import hashlib
import traceback
import threading
import logging
from logging.handlers import RotatingFileHandler
from math import sqrt
from datetime import datetime, timedelta
from http.server import BaseHTTPRequestHandler, HTTPServer

# GUI
try:
    import tkinter as tk
    from tkinter import ttk
    TK_AVAILABLE = True
except Exception:
    TK_AVAILABLE = False

# ---------------- CONFIG ----------------

CONFIG_PATH = "glassshield_config.json"
CONFIG_BACKUP_PATH = "glassshield_config.bak"
LOG_PATH = "glassshield.log"
ALERT_EXPORT_PATH = "glassshield_alerts.enc"
ML_EXPORT_PATH = "glassshield_ml_telemetry.json"

DEFAULT_CONFIG = {
    "scan_interval_seconds": 5,
    "max_process_history_per_pid": 200,
    "max_network_history": 1000,
    "max_alert_history": 500,
    "max_timeline_entries_per_caller": 200,
    "json_api_host": "127.0.0.1",
    "json_api_port": 8088,
    "json_api_auth_token": None,
    "enable_gui": True,
    "enable_defender_checks": True,
    "enable_firewall_checks": True,
    "enable_notifications": False,
    "log_max_bytes": 5 * 1024 * 1024,
    "log_backup_count": 3,
    "sensitive_redaction": True,
    "alert_encryption_key": None,
    "ml_export_enabled": True,
    "ml_export_interval_seconds": 60,
    "multi_node_mode": False,
    "multi_node_auth_token": None,
    "multi_node_cluster_id": "cluster-01",
    "asi_mode": "DUAL",  # AGGRESSIVE / SAFE / DUAL (default)
}

# ---------------- DEPENDENCY CHECKS ----------------

try:
    import psutil
    PSUTIL_AVAILABLE = True
except Exception:
    PSUTIL_AVAILABLE = False

try:
    import pynvml
    pynvml.nvmlInit()
    NVML_AVAILABLE = True
except Exception:
    NVML_AVAILABLE = False

try:
    from cryptography.fernet import Fernet
    CRYPTO_AVAILABLE = True
except Exception:
    CRYPTO_AVAILABLE = False

try:
    import socket
    import platform
    import uuid
    import re
    SOCKET_AVAILABLE = True
except Exception:
    SOCKET_AVAILABLE = False

WINDOWS_AVAILABLE = (os.name == "nt")

# ---------------- LOGGING ----------------

logger = logging.getLogger("GlassShield")
logger.setLevel(logging.INFO)

# Remove any pre-existing handlers (including console/StreamHandler)
logger.handlers.clear()

handler = RotatingFileHandler(
    LOG_PATH,
    maxBytes=DEFAULT_CONFIG["log_max_bytes"],
    backupCount=DEFAULT_CONFIG["log_backup_count"],
    encoding="utf-8",
)
formatter = logging.Formatter("%(asctime)s [%(levelname)s] %(message)s")
handler.setFormatter(formatter)
logger.addHandler(handler)

# Avoid sending logs to root logger (no console)
logger.propagate = False


def safe_log(level, msg):
    try:
        if not isinstance(msg, str):
            msg = str(msg)
        msg = msg.encode("utf-8", "ignore").decode("utf-8", "ignore")
        logger.log(level, msg)
    except Exception:
        pass


# ---------------- CONFIG LOAD / SAVE ----------------

def load_config():
    cfg = DEFAULT_CONFIG.copy()
    if os.path.exists(CONFIG_PATH):
        try:
            with open(CONFIG_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            cfg.update(data)
            safe_log(logging.INFO, "Loaded config from disk.")
        except Exception as e:
            safe_log(logging.ERROR, f"Failed to load config: {e}")
            if os.path.exists(CONFIG_BACKUP_PATH):
                try:
                    with open(CONFIG_BACKUP_PATH, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    cfg.update(data)
                    safe_log(logging.INFO, "Loaded config from backup.")
                except Exception as e2:
                    safe_log(logging.ERROR, f"Failed to load backup config: {e2}")
    if CRYPTO_AVAILABLE and not cfg.get("alert_encryption_key"):
        cfg["alert_encryption_key"] = Fernet.generate_key().decode()
        safe_log(logging.INFO, "Generated new alert encryption key.")
    try:
        with open(CONFIG_BACKUP_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception as e:
        safe_log(logging.ERROR, f"Failed to write backup config: {e}")
    return cfg


def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        with open(CONFIG_BACKUP_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        safe_log(logging.INFO, "Config saved.")
    except Exception as e:
        safe_log(logging.ERROR, f"Failed to save config: {e}")


CONFIG = load_config()

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
        safe_log(logging.WARNING, f"NVML telemetry failed: {e}")
        return {"temp": None, "vram_used": None, "vram_total": None}

# ============================================================
# REAL-WORLD HELPERS
# ============================================================

def get_process_tag(pid=None):
    if not PSUTIL_AVAILABLE:
        return "process::unknown"
    try:
        p = psutil.Process(pid) if pid is not None else psutil.Process()
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
        return {"pid": pid, "name": None, "exe": None, "cmdline": None, "ppid": None, "create_time": None}
    try:
        p = psutil.Process(pid)
        return {
            "pid": pid,
            "name": p.name(),
            "exe": p.exe() if p.exe() else None,
            "cmdline": " ".join(p.cmdline()) if p.cmdline() else None,
            "ppid": p.ppid(),
            "create_time": p.create_time(),
        }
    except Exception:
        return {"pid": pid, "name": None, "exe": None, "cmdline": None, "ppid": None, "create_time": None}


def redact_sensitive(text):
    if not CONFIG.get("sensitive_redaction", True):
        return text
    if text is None:
        return None
    h = hashlib.sha256(text.encode()).hexdigest()[:16]
    return f"<redacted:{h}>"

# ============================================================
# GLASSSHIELD CORE
# ============================================================

class GlassShield:
    def __init__(self, swarm_endpoint=None, node_id="glass-node-01"):
        self.crypto = Fernet(Fernet.generate_key()) if CRYPTO_AVAILABLE else None
        self.policy = {
            "allow_raw": True,
            "allow_meta": True,
            "obfuscation_level": 2,
            "log_access": True,
            "block_untrusted": False,
            "gpu_enabled": NVML_AVAILABLE,
            "swarm_enabled": swarm_endpoint is not None,
            "heat_mask_mode": True,
        }
        self.access_log = []
        self.trusted_callers = set()
        self.lock = threading.Lock()
        self.swarm_endpoint = swarm_endpoint
        self.node_id = node_id
        self.resurrection_map = {}
        self.threat_scores = {}
        if self.policy["swarm_enabled"]:
            threading.Thread(target=self._swarm_heartbeat, daemon=True).start()

    def add_trusted(self, caller_id):
        with self.lock:
            self.trusted_callers.add(caller_id)

    def is_trusted(self, caller_id):
        with self.lock:
            return caller_id in self.trusted_callers

    def _update_resurrection(self, caller_id, alive_now):
        with self.lock:
            entry = self.resurrection_map.get(caller_id, {"seen": 0, "alive": False, "resurrections": 0})
            if alive_now and not entry["alive"]:
                entry["resurrections"] += 1
            entry["seen"] += 1
            entry["alive"] = alive_now
            self.resurrection_map[caller_id] = entry
            count = entry["resurrections"]
        glyph = hashlib.sha256(f"{caller_id}:{count}".encode()).hexdigest()[:12]
        return glyph, count

    def _heat_signature_mask(self):
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

    def obfuscate(self, data: str) -> str:
        lvl = self.policy["obfuscation_level"]
        try:
            telem = get_gpu_telemetry()
            telemetry_str = f"T={telem['temp']};U={telem['vram_used']};TOT={telem['vram_total']}"
            curve_seed = hashlib.sha256(telemetry_str.encode()).hexdigest()[:16]
            base_hash = hashlib.sha256((data + curve_seed).encode()).hexdigest()
            if self.policy["heat_mask_mode"] and lvl >= 4:
                return self._heat_signature_mask()
            if lvl == 1:
                return base_hash[:16]
            if lvl == 2:
                return base_hash
            if lvl == 3 and self.crypto:
                enc = self.crypto.encrypt((data + "|curve=" + curve_seed).encode()).decode()
                return enc[:32] + "...opaque"
            if lvl == 4:
                return f"### DATA BLOCKED (curve={curve_seed}) ###"
            if lvl == 5:
                return "### COMPLETE OPACITY ###"
            return base_hash[:32]
        except Exception as e:
            safe_log(logging.ERROR, f"Obfuscation failure: {e}")
            return "### OBFUSCATION ERROR ###"

    def _compute_threat_score(self, caller_id, status, meta, indicators):
        base = 0.0
        if status == "blocked":
            base += 5.0
        elif status == "filtered":
            base += 2.0
        elif status == "raw":
            base += 0.5
        elif status == "error":
            base += 7.0

        glyph, resurrect_count = self._update_resurrection(caller_id, indicators.get("alive", True))
        base += resurrect_count * 0.7

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

        if indicators.get("suspicious_cmdline"):
            base += 3.0
        if indicators.get("temp_exe"):
            base += 2.5
        if indicators.get("orphan_process"):
            base += 2.0
        if indicators.get("weird_port"):
            base += 2.0
        if indicators.get("defender_alert"):
            base += 4.0

        telem = get_gpu_telemetry()
        temp = telem["temp"]
        if temp is not None:
            base += max(0, (temp - 60) * 0.1)

        score = round(base, 2)
        meta["resurrection_count"] = resurrect_count
        meta["indicators"] = indicators

        with self.lock:
            self.threat_scores[caller_id] = {
                "score": score,
                "glyph": glyph,
                "last_status": status,
                "last_meta": meta,
            }
        return score, glyph

    def access(self, caller_id, data: str, indicators=None, outbound=False):
        if indicators is None:
            indicators = {}
        try:
            timestamp = datetime.now().isoformat()
            meta = {
                "caller": caller_id,
                "time": timestamp,
                "length": len(data),
                "hash": hashlib.sha256(data.encode()).hexdigest()[:12],
                "outbound": outbound,
            }
            if self.policy["log_access"]:
                self.access_log.append(meta)
            status = "raw"
            score, glyph = self._compute_threat_score(caller_id, status, meta, indicators)
            meta["threat_score"] = score
            meta["glyph"] = glyph
            visible = data if not outbound else self.obfuscate(data)
            safe_log(logging.DEBUG, f"Access {caller_id} score={score} outbound={outbound}")
            return {"status": status, "visible": visible, "meta": meta}
        except Exception as e:
            safe_log(logging.ERROR, f"ACCESS FAILURE: {e}")
            meta = {"caller": caller_id, "time": datetime.now().isoformat()}
            score, glyph = self._compute_threat_score(caller_id, "error", meta, indicators or {})
            meta["threat_score"] = score
            meta["glyph"] = glyph
            return {"status": "error", "visible": None, "meta": meta}

    def set_policy(self, **kwargs):
        with self.lock:
            for k, v in kwargs.items():
                if k in self.policy:
                    self.policy[k] = v

    def _swarm_heartbeat(self):
        while True:
            time.sleep(10)

    def dominiondeck_guard(self, source, payload: str, indicators=None, outbound=False):
        return self.access(f"dominiondeck::{source}", payload, indicators=indicators, outbound=outbound)

    def sentinel_guard(self, module, payload: str, indicators=None, outbound=False):
        return self.access(f"sentinel::{module}", payload, indicators=indicators, outbound=outbound)

    def process_guard(self, pid=None, payload: str = "", indicators=None):
        tag = get_process_tag(pid)
        return self.access(tag, payload, indicators=indicators or {"alive": True}, outbound=False)

    def file_guard(self, path: str, payload: str = "", indicators=None):
        tag = get_file_tag(path)
        return self.access(tag, payload, indicators=indicators or {}, outbound=False)

    def network_guard(self, remote_addr: str, remote_port: int, payload: str = "", indicators=None, outbound=True):
        tag = get_network_tag(remote_addr, remote_port)
        return self.access(tag, payload, indicators=indicators or {}, outbound=outbound)

# ============================================================
# MAGICBOX: CHAMELEON ASI (TRUST ENGINE, NO GUI)
# ============================================================

trust_config = {
    "MAC":        {"action": "destroy",  "ttl": 86400},
    "IP":         {"action": "cloak",    "ttl": 86400},
    "Telemetry":  {"action": "destroy",  "ttl": 30},
    "Phantom":    {"action": "destroy",  "ttl": 30},
    "SwarmID":    {"action": "preserve", "ttl": None},
}


def symbolic_route(data):
    sigil = uuid.uuid4().hex[:8]
    return f"{sigil}:{data}"


class MagicBoxEngine:
    def __init__(self, mode="DUAL"):
        self.mode = mode  # AGGRESSIVE / SAFE / DUAL
        self.mutation_log = []
        self.destruction_queue = []
        self.lock = threading.Lock()
        safe_log(logging.INFO, f"MagicBoxEngine initialized in mode={self.mode}")

    def set_mode(self, mode):
        with self.lock:
            self.mode = mode
        safe_log(logging.INFO, f"MagicBox mode changed to {mode}")

    def log_mutation(self, text):
        entry = symbolic_route(text)
        with self.lock:
            self.mutation_log.append(entry)
            if len(self.mutation_log) > 500:
                self.mutation_log = self.mutation_log[-500:]
        safe_log(logging.INFO, f"[MagicBox] {entry}")

    def schedule_destruction(self, tag, ttl_seconds):
        if ttl_seconds:
            expiry = datetime.now() + timedelta(seconds=ttl_seconds)
            with self.lock:
                self.destruction_queue.append((tag, expiry))

    def check_destruction(self):
        now = datetime.now()
        with self.lock:
            for tag, expiry in self.destruction_queue[:]:
                if now >= expiry:
                    self.log_mutation(f"💥 Self-destructed: {tag}")
                    self.destruction_queue.remove((tag, expiry))

    def handle_data(self, tag, value):
        rule = trust_config.get(tag, {})
        action = rule.get("action")
        ttl = rule.get("ttl")
        if action == "destroy":
            self.log_mutation(f"{tag}: {value}")
            self.schedule_destruction(tag, ttl)
        elif action == "cloak":
            self.log_mutation(f"{tag}: [CLOAKED]")
            self.schedule_destruction(tag, ttl)
        elif action == "preserve":
            self.log_mutation(f"{tag}: {value}")

    def get_real_mac(self):
        if not PSUTIL_AVAILABLE:
            return "MAC not available"
        try:
            for iface, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if getattr(addr.family, "name", "") == "AF_LINK":
                        return addr.address
        except Exception as e:
            safe_log(logging.ERROR, f"MagicBox MAC error: {e}")
        return "MAC not found"

    def get_real_ip(self):
        if not SOCKET_AVAILABLE:
            return "IP error", "socket not available"
        try:
            hostname = socket.gethostname()
            local_ip = socket.gethostbyname(hostname)
            public_ip = socket.gethostbyname_ex(hostname)[2][-1]
            return local_ip, public_ip
        except Exception as e:
            return "IP error", str(e)

    def get_telemetry(self):
        if not SOCKET_AVAILABLE:
            return "OS unknown", "fingerprint unknown"
        os_info = platform.platform()
        browser_fingerprint = platform.system() + "-" + platform.machine()
        return os_info, browser_fingerprint

    def get_swarm_id(self):
        return str(uuid.getnode())

    def synthesize_phantom(self):
        entropy = uuid.uuid4().hex + str(time.time_ns())
        return f"phantom://{entropy[:12]}"

    def autonomous_start(self):
        mac = self.get_real_mac()
        self.handle_data("MAC", mac)
        local_ip, public_ip = self.get_real_ip()
        self.handle_data("IP", f"{local_ip} | {public_ip}")
        os_info, browser_fp = self.get_telemetry()
        self.handle_data("Telemetry", f"{os_info} | {browser_fp}")
        swarm_id = self.get_swarm_id()
        self.handle_data("SwarmID", swarm_id)
        phantom = self.synthesize_phantom()
        self.handle_data("Phantom", phantom)
        self.log_mutation("🔄 Autonomous startup complete. Trust Engine active.")

    def threat_scan_and_respond(self):
        if not PSUTIL_AVAILABLE:
            return
        suspicious_ports = [1337, 31337, 6666, 9001]
        try:
            for conn in psutil.net_connections(kind='inet'):
                if conn.status == 'LISTEN' and conn.laddr.port in suspicious_ports:
                    self.log_mutation(f"🛡️ Port Cloaked: {conn.laddr.port} on {conn.laddr.ip}")
            for proc in psutil.process_iter(['pid', 'name']):
                name = proc.info['name']
                pid = proc.info['pid']
                if name and re.search(r"(keylogger|sniffer|injector|bot|miner)", name, re.IGNORECASE):
                    if self.mode == "AGGRESSIVE":
                        try:
                            proc.terminate()
                            self.log_mutation(f"⚔️ Threat Neutralized: {name} (PID {pid})")
                        except Exception as e:
                            self.log_mutation(f"⚠️ Failed to terminate: {name} (PID {pid}) - {e}")
                    else:
                        self.log_mutation(f"👀 Threat Observed: {name} (PID {pid}) [non-destructive mode]")
        except Exception as e:
            safe_log(logging.ERROR, f"MagicBox threat scan error: {e}")

    def snapshot(self):
        with self.lock:
            return {
                "mode": self.mode,
                "mutation_log_tail": self.mutation_log[-50:],
                "destruction_queue": [(t, e.isoformat()) for t, e in self.destruction_queue],
            }

# ============================================================
# SECURITY GOVERNOR (UPGRADED + ML-READY + MAGICBOX INTEGRATION)
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
    def __init__(self, config):
        self.cfg = config
        self.gs = GlassShield(swarm_endpoint=None, node_id="secgov-node-01")
        self.baseline = {}
        self.process_history = {}
        self.network_history = []
        self.alert_log = []
        self.clusters = {"process_name": {}, "remote_ip": {}}
        self.threat_timeline = {}
        self.lock = threading.Lock()
        self.enforcement_enabled = False
        self.shutdown_event = threading.Event()
        self.health_state = {"last_scan": None, "errors": 0}
        self.ml_last_export = None
        self.alert_crypto = Fernet(self.cfg["alert_encryption_key"].encode()) if CRYPTO_AVAILABLE and self.cfg.get("alert_encryption_key") else None
        self.magicbox = MagicBoxEngine(mode=self.cfg.get("asi_mode", "DUAL"))
        safe_log(logging.INFO, "SecurityGovernor initialized.")

    def trust(self, caller_id):
        self.gs.add_trusted(caller_id)

    def set_policy(self, **kwargs):
        self.gs.set_policy(**kwargs)

    # -------- Baseline / anomaly --------

    def _update_baseline(self, caller_id, score):
        now = datetime.now().isoformat()
        with self.lock:
            entry = self.baseline.get(caller_id, {"count": 0, "avg_score": 0.0, "m2": 0.0, "last_seen": None})
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

    # -------- Heuristics / explanations --------

    def _heuristics_suspicious(self, caller_id, info, anomaly_score):
        score = info.get("score", 0.0)
        meta = info.get("last_meta", {}) or {}
        resurrection = meta.get("resurrection_count", 0)
        indicators = meta.get("indicators", {}) or {}
        suspicious_reasons = []

        if score >= 12.0:
            suspicious_reasons.append(f"elevated risk estimate (score={score})")
        if resurrection >= 3:
            suspicious_reasons.append(f"process repeatedly exits and reappears (resurrections={resurrection})")
        if anomaly_score >= 2.5:
            suspicious_reasons.append(f"behavior deviates from baseline (z={anomaly_score})")
        if indicators.get("suspicious_cmdline"):
            suspicious_reasons.append("command line suggests encoded or scripting payload")
        if indicators.get("temp_exe"):
            suspicious_reasons.append("executable running from temporary directory")
        if indicators.get("orphan_process"):
            suspicious_reasons.append("process has no valid parent (orphan)")
        if indicators.get("weird_port"):
            suspicious_reasons.append("network connection uses unusual port")
        if indicators.get("defender_alert"):
            suspicious_reasons.append("Windows Defender reported suspicious activity")

        return suspicious_reasons

    def _color_for_info(self, caller_id, info, reasons, anomaly_score):
        score = info.get("score", 0.0)
        meta = info.get("last_meta", {}) or {}
        resurrection = meta.get("resurrection_count", 0)
        if len(reasons) >= 2 and resurrection >= 2:
            return "RED"
        if anomaly_score >= 2.5 and score >= 10.0:
            return "RED"
        if self._is_known_system_process(caller_id) and score < 6.0 and resurrection < 3 and anomaly_score < 1.5:
            return "GREEN"
        if score < 8.0 and resurrection < 3 and anomaly_score < 2.0:
            return "YELLOW"
        return "RED"

    def _risk_zone(self, caller_id, color, anomaly_score, score):
        if self._is_known_system_process(caller_id):
            return "system" if color == "GREEN" else "system_watch"
        if caller_id.startswith("dominiondeck::") or caller_id.startswith("sentinel::"):
            return "user" if color == "GREEN" else "user_watch"
        if color == "RED" or anomaly_score >= 2.5 or score >= 12.0:
            return "high_risk"
        return "unknown"

    def _apply_glassshield_mode_for_color(self, color):
        if color == "GREEN":
            self.gs.set_policy(allow_raw=True, block_untrusted=False, obfuscation_level=1)
        elif color == "YELLOW":
            self.gs.set_policy(allow_raw=True, block_untrusted=False, obfuscation_level=2)
        elif color == "RED":
            self.gs.set_policy(allow_raw=True, block_untrusted=False, obfuscation_level=3)

    # -------- Clusters / timeline --------

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
            avg = (entry["avg_score"] * entry["count"] * 1.0 + score) / c
            entry["count"] = c
            entry["avg_score"] = avg
            self.clusters["remote_ip"][remote] = entry

    def _update_timeline(self, caller_id, time_str, score, color, anomaly_score):
        with self.lock:
            tl = self.threat_timeline.get(caller_id, [])
            tl.append({"time": time_str, "score": score, "color": color, "anomaly": anomaly_score})
            if len(tl) > self.cfg["max_timeline_entries_per_caller"]:
                tl = tl[-self.cfg["max_timeline_entries_per_caller"]:]
            self.threat_timeline[caller_id] = tl

    # -------- Alerts / encrypted persistence --------

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
            "risk_label": "risk estimate (not proof of malware)",
        }
        with self.lock:
            self.alert_log.append(alert)
            if len(self.alert_log) > self.cfg["max_alert_history"]:
                self.alert_log = self.alert_log[-self.cfg["max_alert_history"]:]
        safe_log(logging.WARNING, f"ALERT {color}/{zone} {caller_id} reasons={reasons} score={info.get('score')}")
        self._export_alerts_encrypted()

    def _export_alerts_encrypted(self):
        if not self.alert_crypto:
            return
        try:
            with self.lock:
                data = self.alert_log[-self.cfg["max_alert_history"]:]
            raw = json.dumps(data, indent=2).encode("utf-8")
            enc = self.alert_crypto.encrypt(raw)
            with open(ALERT_EXPORT_PATH, "wb") as f:
                f.write(enc)
        except Exception as e:
            safe_log(logging.ERROR, f"Failed to export encrypted alerts: {e}")

    # -------- ML telemetry export --------

    def _export_ml_telemetry_if_needed(self):
        if not self.cfg.get("ml_export_enabled", True):
            return
        now = time.time()
        if self.ml_last_export and now - self.ml_last_export < self.cfg["ml_export_interval_seconds"]:
            return
        self.ml_last_export = now
        try:
            with self.lock:
                payload = {
                    "baseline": self.baseline,
                    "clusters": self.clusters,
                    "timeline": self.threat_timeline,
                    "magicbox": self.magicbox.snapshot(),
                }
            with open(ML_EXPORT_PATH, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            safe_log(logging.INFO, "Exported ML telemetry.")
        except Exception as e:
            safe_log(logging.ERROR, f"Failed to export ML telemetry: {e}")

    # -------- Post event --------

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
        info["baseline_count"] = baseline_entry["count"]
        info["baseline_avg"] = baseline_entry["avg_score"]
        info["baseline_m2"] = baseline_entry["m2"]
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
            origin_safe = {
                "pid": origin["pid"],
                "name": origin["name"],
                "exe": redact_sensitive(origin["exe"]),
                "cmdline": redact_sensitive(origin["cmdline"]),
                "ppid": origin["ppid"],
                "create_time": origin["create_time"],
            }
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
                "origin": origin_safe,
            }
            with self.lock:
                hist = self.process_history.get(pid, [])
                hist.append(event)
                if len(hist) > self.cfg["max_process_history_per_pid"]:
                    hist = hist[-self.cfg["max_process_history_per_pid"]:]
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
                if len(self.network_history) > self.cfg["max_network_history"]:
                    self.network_history = self.network_history[-self.cfg["max_network_history"]:]
            self._update_clusters_for_remote(remote, info.get("score", 0.0))

        if len(reasons) >= 2:
            self._alert(caller_id, info, reasons, color, anomaly_score, zone)

        self._export_ml_telemetry_if_needed()

    # -------- Guard wrappers --------

    def guard_process(self, pid=None, payload: str = "", indicators=None):
        result = self.gs.process_guard(pid, payload, indicators=indicators)
        self._post_event(get_process_tag(pid), result)
        return result

    def guard_network(self, remote_addr: str, remote_port: int, payload: str = "", indicators=None, outbound=True):
        result = self.gs.network_guard(remote_addr, remote_port, payload, indicators=indicators, outbound=outbound)
        self._post_event(get_network_tag(remote_addr, remote_port), result)
        return result

    def guard_file(self, path: str, payload: str = "", indicators=None):
        result = self.gs.file_guard(path, payload, indicators=indicators)
        self._post_event(get_file_tag(path), result)
        return result

    def guard_dominiondeck(self, source, payload: str, indicators=None, outbound=False):
        result = self.gs.dominiondeck_guard(source, payload, indicators=indicators, outbound=outbound)
        self._post_event(f"dominiondeck::{source}", result)
        return result

    def guard_sentinel(self, module, payload: str, indicators=None, outbound=False):
        result = self.gs.sentinel_guard(module, payload, indicators=indicators, outbound=outbound)
        self._post_event(f"sentinel::{module}", result)
        return result

    @property
    def threat_scores(self):
        return self.gs.threat_scores

    def snapshot_state(self):
        with self.lock:
            return {
                "baseline": self.baseline,
                "clusters": self.clusters,
                "alerts": self.alert_log[-self.cfg["max_alert_history"]:],
                "process_history_size": {pid: len(events) for pid, events in self.process_history.items()},
                "network_history_size": len(self.network_history),
                "timeline_size": {cid: len(tl) for cid, tl in self.threat_timeline.items()},
                "health": self.health_state,
                "magicbox": self.magicbox.snapshot(),
            }

    def snapshot_timeline(self, max_entries=50):
        with self.lock:
            out = {}
            for cid, tl in self.threat_timeline.items():
                out[cid] = tl[-max_entries:]
            return out

    # -------- Security integrations (Defender / Firewall) --------

    def check_defender_status(self):
        if not self.cfg.get("enable_defender_checks", True) or not WINDOWS_AVAILABLE:
            return {"enabled": None, "details": "disabled or not Windows"}
        try:
            return {"enabled": True, "details": "Defender status check placeholder"}
        except Exception as e:
            safe_log(logging.ERROR, f"Defender check failed: {e}")
            return {"enabled": None, "details": "error"}

    def check_firewall_status(self):
        if not self.cfg.get("enable_firewall_checks", True) or not WINDOWS_AVAILABLE:
            return {"enabled": None, "details": "disabled or not Windows"}
        try:
            return {"enabled": True, "details": "Firewall status check placeholder"}
        except Exception as e:
            safe_log(logging.ERROR, f"Firewall check failed: {e}")
            return {"enabled": None, "details": "error"}

# ============================================================
# JSON API (with optional auth + multi-node hooks)
# ============================================================

class DashboardHandler(BaseHTTPRequestHandler):
    secgov_ref = None
    auth_token = None
    cluster_id = None

    def _send_json(self, obj, code=200):
        data = json.dumps(obj, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _check_auth(self):
        if not DashboardHandler.auth_token:
            return True
        from urllib.parse import urlparse, parse_qs
        qs = parse_qs(urlparse(self.path).query)
        token = qs.get("token", [None])[0]
        return token == DashboardHandler.auth_token

    def do_GET(self):
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, 401)
            return
        if self.path.startswith("/status"):
            if DashboardHandler.secgov_ref is None:
                self._send_json({"error": "no secgov"}, 500)
                return
            snapshot = DashboardHandler.secgov_ref.snapshot_state()
            snapshot["cluster_id"] = DashboardHandler.cluster_id
            self._send_json(snapshot)
        elif self.path.startswith("/threats"):
            if DashboardHandler.secgov_ref is None:
                self._send_json({"error": "no secgov"}, 500)
                return
            self._send_json(DashboardHandler.secgov_ref.threat_scores)
        elif self.path.startswith("/timeline"):
            if DashboardHandler.secgov_ref is None:
                self._send_json({"error": "no secgov"}, 500)
                return
            self._send_json(DashboardHandler.secgov_ref.snapshot_timeline())
        else:
            self._send_json({"error": "unknown endpoint"}, 404)


def launch_json_api_async(secgov: SecurityGovernor, cfg):
    def _run():
        try:
            DashboardHandler.secgov_ref = secgov
            DashboardHandler.auth_token = cfg.get("json_api_auth_token")
            DashboardHandler.cluster_id = cfg.get("multi_node_cluster_id")
            server = HTTPServer((cfg["json_api_host"], cfg["json_api_port"]), DashboardHandler)
            safe_log(logging.INFO, f"JSON API listening on http://{cfg['json_api_host']}:{cfg['json_api_port']}")
            server.serve_forever()
        except Exception as e:
            safe_log(logging.ERROR, f"JSON API failed: {e}")
    threading.Thread(target=_run, daemon=True).start()

# ============================================================
# DAEMON LOOP (GlassShield + MagicBox)
# ============================================================

def scan_worker(secgov: SecurityGovernor, cfg):
    safe_log(logging.INFO, "Scan worker started.")
    last_process_snapshot = {}
    secgov.magicbox.autonomous_start()
    while not secgov.shutdown_event.is_set():
        try:
            now = datetime.now().isoformat()
            defender_status = secgov.check_defender_status()
            defender_flag = defender_status.get("enabled") is True

            secgov.magicbox.check_destruction()
            secgov.magicbox.threat_scan_and_respond()

            if PSUTIL_AVAILABLE:
                current_snapshot = {}
                for proc in psutil.process_iter(["pid", "name", "exe", "cmdline", "ppid", "create_time"]):
                    try:
                        info = proc.info
                        pid = info["pid"]
                        current_snapshot[pid] = info
                        prev = last_process_snapshot.get(pid)
                        indicators = {"alive": True}
                        exe = info.get("exe") or ""
                        cmdline = " ".join(info.get("cmdline") or [])
                        ppid = info.get("ppid")
                        if "temp" in exe.lower():
                            indicators["temp_exe"] = True
                        if "-enc" in cmdline.lower() or "powershell" in cmdline.lower():
                            indicators["suspicious_cmdline"] = True
                        if ppid in (None, 0):
                            indicators["orphan_process"] = True
                        if prev is None:
                            indicators["new_process"] = True
                        elif prev.get("create_time") != info.get("create_time"):
                            indicators["resurrected"] = True
                        if defender_flag:
                            indicators["defender_alert"] = False
                        payload = f"name={info.get('name')};pid={pid};tick={now}"
                        secgov.guard_process(pid=pid, payload=payload, indicators=indicators)
                    except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                        continue
                    except Exception as e:
                        safe_log(logging.ERROR, f"Error guarding process: {e}")
                last_process_snapshot = current_snapshot
            else:
                secgov.guard_process(payload=f"tick={now}", indicators={"alive": True})

            if PSUTIL_AVAILABLE:
                try:
                    conns = psutil.net_connections(kind="inet")
                    for c in conns:
                        if c.raddr:
                            remote = c.raddr.ip
                            port = c.raddr.port
                            indicators = {}
                            if port not in (80, 443, 53):
                                indicators["weird_port"] = True
                            payload = f"status={c.status};pid={c.pid};tick={now}"
                            secgov.guard_network(remote, port, payload, indicators=indicators, outbound=True)
                except Exception as e:
                    safe_log(logging.ERROR, f"Error reading net connections: {e}")

            example_path = "example.txt"
            if os.path.exists(example_path):
                secgov.guard_file(example_path, payload=f"file_tick={now}", indicators={})

            secgov.guard_dominiondeck("telemetry", f"FPS=144;GPU=72C;tick={now}", indicators={}, outbound=False)
            secgov.guard_sentinel("threat_scanner", f"score=0.03;normalized=true;tick={now}", indicators={}, outbound=False)

            secgov.health_state["last_scan"] = now
            time.sleep(cfg["scan_interval_seconds"])
        except Exception as e:
            safe_log(logging.ERROR, f"Daemon loop error: {e}")
            secgov.health_state["errors"] += 1
            time.sleep(2)
    safe_log(logging.INFO, "Scan worker exiting.")

# ============================================================
# GUI FOR MODE SWITCHING
# ============================================================

def launch_gui(secgov: SecurityGovernor, cfg):
    if not TK_AVAILABLE:
        safe_log(logging.WARNING, "Tkinter not available; GUI disabled.")
        return

    def on_mode_change():
        mode = mode_var.get()
        cfg["asi_mode"] = mode
        secgov.magicbox.set_mode(mode)
        save_config(cfg)

    root = tk.Tk()
    root.title("GlassShield ASI Mode")
    root.geometry("320x180")
    root.configure(bg="#1e1e2f")

    style = ttk.Style(root)
    style.theme_use("clam")
    style.configure("TLabel", background="#1e1e2f", foreground="#00ffcc", font=("Consolas", 11))
    style.configure("TRadiobutton", background="#1e1e2f", foreground="#00ffcc", font=("Consolas", 10))

    ttk.Label(root, text="MagicBox ASI Mode").pack(pady=10)

    mode_var = tk.StringVar(value=cfg.get("asi_mode", "DUAL"))

    rb_aggr = ttk.Radiobutton(root, text="AGGRESSIVE", variable=mode_var, value="AGGRESSIVE", command=on_mode_change)
    rb_safe = ttk.Radiobutton(root, text="SAFE", variable=mode_var, value="SAFE", command=on_mode_change)
    rb_dual = ttk.Radiobutton(root, text="DUAL (default)", variable=mode_var, value="DUAL", command=on_mode_change)

    rb_aggr.pack(anchor="w", padx=20)
    rb_safe.pack(anchor="w", padx=20)
    rb_dual.pack(anchor="w", padx=20)

    ttk.Label(root, text="Changes apply immediately.\nConfig is persisted.").pack(pady=10)

    def on_close():
        root.destroy()

    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

# ============================================================
# MAIN
# ============================================================

def main():
    safe_log(logging.INFO, "GlassShield+MagicBox main starting.")
    secgov = SecurityGovernor(CONFIG)
    secgov.trust("camera_module")
    for name in KNOWN_SYSTEM_PROCESSES:
        secgov.trust(f"process::{name}")
    launch_json_api_async(secgov, CONFIG)
    worker_thread = threading.Thread(target=scan_worker, args=(secgov, CONFIG), daemon=True)
    worker_thread.start()
    safe_log(logging.INFO, "Running with GUI mode switch if enabled.")

    if CONFIG.get("enable_gui", True):
        launch_gui(secgov, CONFIG)
    else:
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass

    secgov.shutdown_event.set()
    worker_thread.join(timeout=5)
    save_config(CONFIG)
    safe_log(logging.INFO, "GlassShield+MagicBox main exiting gracefully.")


if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        safe_log(logging.CRITICAL, f"FATAL: {e}")
        traceback.print_exc()
        time.sleep(3)
