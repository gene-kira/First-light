#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
BORG AI AdBlocker — Adaptive Learning Edition
Version 7.0

A cautious, evidence-based Windows hosts-file ad/tracker assistant.

Key design changes:
- Does NOT force administrator elevation at startup. Monitoring/UI can run normally.
- Only requests elevation when the user explicitly applies host-file changes.
- Uses exact domain labels and conservative feature signals; no ".*ad.*" domain rules.
- Online logistic model learns only from explicit user labels or trusted rule-list evidence.
- Separates prediction from confirmation and exposes confidence/evidence.
- Learned patterns are proposals, not automatically trusted executable code.
- Allowlist always wins; automatic blocking is optional and disabled by default.
- Atomic JSON writes, backups, event logs, bounded caches and graceful shutdown.
- Background network scan is best-effort: PID/domain inference is imperfect, HTTPS hides page content.
- Drones only fetch explicitly observed candidate domains, with strict limits and HTTPS-first.
- Plugins are opt-in and disabled by default because Python plugins are not sandboxed.
- Tkinter tabbed UI with live monitoring, learning/review, rules, and settings.

Requirements: Python 3.10+ recommended. Optional: psutil, requests.
This tool is a host-file assistant, not a browser extension or packet inspector.
"""
from __future__ import annotations

import ctypes
import json
import math
import os
import queue
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import traceback
import urllib.parse
import urllib.request
import webbrowser
from collections import Counter, defaultdict, deque
from datetime import datetime
from pathlib import Path
from typing import Any

try:
    import psutil
except ImportError:
    psutil = None

try:
    import requests
except ImportError:
    requests = None

import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = "BORG AI AdBlocker"
APP_VERSION = "7.0"
IS_WINDOWS = os.name == "nt"
BASE_DIR = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / "AppData/Local"))) / "BORGAdBlocker" if IS_WINDOWS else Path.home() / ".borg_adblocker"
HOSTS_PATH = Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts" if IS_WINDOWS else Path("/etc/hosts")
CUSTOM_HOSTS_PATH = BASE_DIR / "managed_hosts.txt"
CONFIG_PATH = BASE_DIR / "config.json"
MODEL_PATH = BASE_DIR / "online_model.json"
REPUTATION_PATH = BASE_DIR / "domain_reputation.json"
KNOWLEDGE_PATH = BASE_DIR / "borg_knowledge.json"
EVENTS_PATH = BASE_DIR / "events.jsonl"
BACKUP_DIR = BASE_DIR / "backups"
RULE_DIR = BASE_DIR / "rules"
PLUGIN_DIR = BASE_DIR / "plugins"

DEFAULT_CONFIG = {
    "monitor_interval": 2.0,
    "rules_sync_interval": 21600,
    "drone_enabled": False,
    "drone_interval": 60.0,
    "auto_block_enabled": False,
    "auto_block_threshold": 0.94,
    "minimum_evidence": 8,
    "require_rule_or_feedback": True,
    "apply_to_system_hosts": False,
    "plugins_enabled": False,
    "max_domains": 3000,
    "max_events": 5000,
    "theme": "system",
}
RULE_URLS = [
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
]
USER_AGENT = f"{APP_NAME}/{APP_VERSION}"
DOMAIN_RE = re.compile(r"(?=^.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(?:\.(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?))+$", re.I)
AD_TERMS = (
    "doubleclick", "googlesyndication", "googleadservices", "adservice",
    "adserver", "adsystem", "adnxs", "adform", "advertising", "adtech",
    "adroll", "outbrain", "taboola", "criteo", "pubmatic", "openx",
    "rubiconproject", "amazon-adsystem", "adsrvr", "smartadserver",
    "moatads", "serving-sys", "prebid", "adsbygoogle", "adzerk",
)
TRACKING_TERMS = (
    "pixel", "beacon", "tracker", "tracking", "analytics", "telemetry",
    "metrics", "measurement", "fingerprint", "segment.io", "mixpanel",
    "hotjar", "newrelic", "scorecardresearch", "quantserve",
)
VIDEO_TERMS = ("vast", "vpaid", "videoad", "video-ad", "imasdk")
CDN_TERMS = ("cloudfront.net", "akamai", "fastly.net", "cloudflare")
SAFE_BUILTINS = {"localhost", "localhost.localdomain", "broadcasthost"}

def now_ts() -> float:
    return time.time()

def iso_time(ts: float | None = None) -> str:
    return datetime.fromtimestamp(ts or now_ts()).astimezone().strftime("%Y-%m-%d %H:%M:%S")

def clamp(v: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, float(v)))

def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + ".tmp")
    temp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
    temp.replace(path)

def read_json(path: Path, default: Any) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        pass
    return default

class EventLog:
    def __init__(self):
        self.lock = threading.RLock()
        self.items = deque(maxlen=500)
        self.listeners = []

    def add_listener(self, fn):
        self.listeners.append(fn)

    def log(self, message: str, level: str = "INFO", **extra):
        row = {"ts": now_ts(), "time": iso_time(), "level": level, "message": str(message)[:1200]}
        row.update(extra)
        with self.lock:
            self.items.appendleft(row)
        try:
            BASE_DIR.mkdir(parents=True, exist_ok=True)
            with EVENTS_PATH.open("a", encoding="utf-8") as f:
                f.write(json.dumps(row, ensure_ascii=False) + "\n")
        except Exception:
            pass
        for fn in tuple(self.listeners):
            try:
                fn(row)
            except Exception:
                pass

    def snapshot(self):
        with self.lock:
            return list(self.items)

LOG = EventLog()

def normalize_domain(value: str) -> str | None:
    """Normalize a domain/URL to a safe hostname. Reject IP literals and malformed values."""
    if not value:
        return None
    value = str(value).strip().lower().rstrip(".")
    if "://" in value:
        try:
            value = urllib.parse.urlsplit(value).hostname or ""
        except Exception:
            return None
    value = value.split("/")[0].split(":")[0].strip().strip(".")
    if not value or len(value) > 253 or value in SAFE_BUILTINS:
        return None
    try:
        value = value.encode("idna").decode("ascii")
    except Exception:
        return None
    if not DOMAIN_RE.fullmatch(value):
        return None
    # Ignore single-label/internal names and common local suffixes.
    if value.endswith((".local", ".lan", ".internal", ".test", ".invalid")):
        return None
    return value

def domain_features(domain: str) -> dict[str, float]:
    d = domain.lower()
    labels = d.split(".")
    joined = ".".join(labels[:-1])
    # Explicit vendor/token matches only. Avoid matching every domain containing "ad".
    ad = any(term in d for term in AD_TERMS)
    tracking = any(term in d for term in TRACKING_TERMS)
    video = any(term in d for term in VIDEO_TERMS)
    cdn = any(term in d for term in CDN_TERMS)
    numeric_label = any(label.isdigit() for label in labels)
    long_host = len(d) > 42
    many_labels = len(labels) >= 4
    return {
        "ad_token": float(ad),
        "tracking_token": float(tracking),
        "video_token": float(video),
        "cdn_token": float(cdn),
        "numeric_label": float(numeric_label),
        "long_host": float(long_host),
        "many_labels": float(many_labels),
        "subdomain_depth": min(1.0, max(0, len(labels) - 2) / 5.0),
    }

def family_for(domain: str) -> str:
    f = domain_features(domain)
    if f["video_token"]:
        return "video-ad candidate"
    if f["ad_token"]:
        return "ad-network candidate"
    if f["tracking_token"]:
        return "tracking candidate"
    if f["cdn_token"]:
        return "CDN / shared infrastructure"
    return "unknown"

class OnlineLogisticModel:
    """Small online logistic regression trained only on explicit labels."""
    def __init__(self):
        self.lock = threading.RLock()
        saved = read_json(MODEL_PATH, {})
        self.weights = {k: float(v) for k, v in saved.get("weights", {}).items()}
        self.bias = float(saved.get("bias", -2.2))
        self.examples = int(saved.get("examples", 0))
        self.positives = int(saved.get("positives", 0))
        self.negatives = int(saved.get("negatives", 0))
        self.correct = int(saved.get("correct", 0))
        self.evaluated = int(saved.get("evaluated", 0))
        self.learning_rate = 0.08

    def probability(self, features: dict[str, float]) -> float:
        with self.lock:
            z = self.bias + sum(self.weights.get(k, 0.0) * v for k, v in features.items())
        z = max(-20.0, min(20.0, z))
        return 1.0 / (1.0 + math.exp(-z))

    def learn(self, features: dict[str, float], label: int):
        """One SGD step. Labels must come from user feedback or authoritative rule evidence."""
        y = 1 if label else 0
        with self.lock:
            z = self.bias + sum(self.weights.get(k, 0.0) * v for k, v in features.items())
            p = 1.0 / (1.0 + math.exp(-max(-20.0, min(20.0, z))))
            self.evaluated += 1
            if (p >= 0.5) == bool(y):
                self.correct += 1
            err = p - y
            for k, v in features.items():
                old = self.weights.get(k, 0.0)
                # L2 shrinkage prevents runaway weights.
                self.weights[k] = old - self.learning_rate * (err * v + 0.002 * old)
            self.bias -= self.learning_rate * err
            self.examples += 1
            self.positives += y
            self.negatives += 1 - y
        self.save()
        return p

    def save(self):
        with self.lock:
            data = {
                "weights": self.weights, "bias": self.bias, "examples": self.examples,
                "positives": self.positives, "negatives": self.negatives,
                "correct": self.correct, "evaluated": self.evaluated,
                "updated_at": now_ts(), "learning_rate": self.learning_rate,
            }
        try:
            atomic_json(MODEL_PATH, data)
        except Exception as e:
            LOG.log(f"Could not save learning model: {e}", "ERROR")

    def metrics(self):
        with self.lock:
            return {
                "examples": self.examples, "positives": self.positives,
                "negatives": self.negatives,
                "accuracy": self.correct / self.evaluated if self.evaluated else None,
                "weights": dict(self.weights), "bias": self.bias,
            }

class BorgEngine:
    def __init__(self):
        self.lock = threading.RLock()
        self.model = OnlineLogisticModel()
        self.config = DEFAULT_CONFIG.copy()
        self.config.update(read_json(CONFIG_PATH, {}))
        self.allowlist = set()
        self.blocklist = set()
        self.reputation = read_json(REPUTATION_PATH, {})
        self.knowledge = read_json(KNOWLEDGE_PATH, {"patterns": [], "last_update": 0})
        self.domains = {}
        self.connections = []
        self.active_title = ""
        self.active_pid = None
        self.active_domain = None
        self.last_scan = 0.0
        self.running = True
        self.scan_count = 0
        self.feedback_count = 0
        self.rules = set()
        self.rule_domains = set()
        self.learned_candidates = {}
        self.events_seen = Counter()
        self.started = now_ts()
        self._load_custom_lists()
        self._load_cached_rules()

    def _load_custom_lists(self):
        data = read_json(CONFIG_PATH, {})
        self.allowlist = {d for x in data.get("allowlist", []) if (d := normalize_domain(x))}
        self.blocklist = {d for x in data.get("blocklist", []) if (d := normalize_domain(x))}
        self.allowlist -= self.blocklist
        self.save_config()

    def save_config(self):
        try:
            current = read_json(CONFIG_PATH, {})
            current.update(self.config)
            current["allowlist"] = sorted(self.allowlist)
            current["blocklist"] = sorted(self.blocklist)
            atomic_json(CONFIG_PATH, current)
        except Exception as e:
            LOG.log(f"Config save failed: {e}", "ERROR")

    def _load_cached_rules(self):
        for file in RULE_DIR.glob("*.txt") if RULE_DIR.exists() else []:
            try:
                for line in file.read_text(encoding="utf-8", errors="ignore").splitlines():
                    self._parse_rule(line)
            except Exception:
                pass

    def _parse_rule(self, line: str):
        line = line.strip()
        if not line or line.startswith(("!", "#", "[", "@@")):
            return
        # Domain-only hosts-style lines.
        parts = line.split()
        if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1"):
            d = normalize_domain(parts[1])
            if d:
                self.rule_domains.add(d)
            return
        # ABP domain rules: ||domain.example^ with no path/option.
        if line.startswith("||"):
            candidate = line[2:]
            candidate = re.split(r"[\^/$*|]", candidate, maxsplit=1)[0]
            d = normalize_domain(candidate)
            if d and "." in d:
                self.rule_domains.add(d)
        # Keep source rule text for audit/debug only; do not interpret it as regex.
        self.rules.add(line)

    def sync_rules(self):
        RULE_DIR.mkdir(parents=True, exist_ok=True)
        if requests is None:
            LOG.log("Rule sync unavailable: install requests or use cached lists.", "WARN")
            return
        known_before_sync = set(self.rule_domains)
        for i, url in enumerate(RULE_URLS):
            try:
                r = requests.get(url, timeout=(5, 20), headers={"User-Agent": USER_AGENT})
                r.raise_for_status()
                text = r.text[:20_000_000]
                target = RULE_DIR / f"list_{i}.txt"
                temp = target.with_suffix(".tmp")
                temp.write_text(text, encoding="utf-8")
                temp.replace(target)
                with self.lock:
                    for line in text.splitlines():
                        self._parse_rule(line)
                LOG.log(f"Updated filter list {i + 1}; {len(self.rule_domains)} domain hints currently parsed.")
            except Exception as e:
                LOG.log(f"Rule list {i + 1} update failed: {e}", "WARN")
        # Rule evidence teaches only newly discovered exact domain hints, avoiding
        # repeated training on the same list on every refresh.
        newly_seen = list(self.rule_domains - known_before_sync)[:10000]
        for d in newly_seen:
            self.model.learn(domain_features(d), 1)
        if newly_seen:
            LOG.log(f"Model learned from {len(newly_seen)} newly discovered rule-domain hints.")
        self.save_reputation()

    def classify(self, domain: str, connection: dict | None = None):
        d = normalize_domain(domain)
        if not d:
            return {"domain": domain, "score": 0.0, "decision": "ignored", "family": "unknown", "evidence": []}
        features = domain_features(d)
        score = self.model.probability(features)
        evidence = [k.replace("_", " ") for k, v in features.items() if v and k not in ("numeric_label", "long_host", "many_labels", "subdomain_depth")]
        rule_hit = d in self.rule_domains or any(d.endswith("." + root) for root in self.rule_domains if root.count(".") >= 1)
        with self.lock:
            stats = self.domains.get(d, {})
            observations = int(stats.get("observations", 0))
            explicit = stats.get("label")
        if rule_hit:
            score = max(score, 0.99)
            evidence.append("filter-list match")
        if explicit is not None:
            score = 0.99 if explicit == 1 else 0.01
            evidence.append("user-confirmed label")
        if d in self.allowlist:
            return {"domain": d, "score": score, "decision": "allowlisted", "family": family_for(d), "evidence": evidence, "observations": observations}
        threshold = float(self.config.get("auto_block_threshold", 0.94))
        minimum = int(self.config.get("minimum_evidence", 8))
        trusted = rule_hit or explicit == 1
        if explicit == 0:
            decision = "allowed (false positive feedback)"
        elif rule_hit:
            decision = "block candidate (filter list)"
        elif score >= threshold and observations >= minimum and not self.config.get("require_rule_or_feedback", True):
            decision = "high-confidence candidate"
        else:
            decision = "observe / review"
        return {"domain": d, "score": score, "decision": decision, "family": family_for(d),
                "evidence": evidence, "observations": observations, "rule_hit": rule_hit,
                "trusted": trusted, "features": features}

    def observe(self, domain: str, info: dict | None = None):
        d = normalize_domain(domain)
        if not d:
            return
        now = now_ts()
        result = self.classify(d, info)
        with self.lock:
            stats = self.domains.setdefault(d, {
                "first_seen": now, "last_seen": now, "observations": 0,
                "score": result["score"], "family": result["family"],
                "ports": [], "pids": [], "history": [], "label": None,
            })
            stats["observations"] = min(1_000_000, stats["observations"] + 1)
            stats["last_seen"] = now
            stats["score"] = result["score"]
            stats["family"] = result["family"]
            if info:
                port = info.get("port")
                pid = info.get("pid")
                if port and port not in stats["ports"]:
                    stats["ports"] = (stats["ports"] + [port])[-12:]
                if pid and pid not in stats["pids"]:
                    stats["pids"] = (stats["pids"] + [pid])[-12:]
            stats["history"].append([now, result["score"]])
            stats["history"] = stats["history"][-50:]
            self.reputation[d] = {
                "first_seen": stats["first_seen"], "last_seen": now,
                "observations": stats["observations"], "score": result["score"],
                "family": result["family"], "label": stats.get("label"),
            }
            if len(self.domains) > int(self.config.get("max_domains", 3000)):
                oldest = sorted(self.domains.items(), key=lambda kv: kv[1].get("last_seen", 0))[:max(1, len(self.domains)-int(self.config.get("max_domains", 3000)))]
                for old, _ in oldest:
                    self.domains.pop(old, None)
        self.events_seen[result["decision"]] += 1
        return result

    def label_domain(self, domain: str, label: int):
        d = normalize_domain(domain)
        if not d:
            raise ValueError("Please enter a valid public domain name.")
        features = domain_features(d)
        self.model.learn(features, 1 if label else 0)
        with self.lock:
            stats = self.domains.setdefault(d, {"first_seen": now_ts(), "observations": 0, "history": [], "ports": [], "pids": []})
            stats["label"] = 1 if label else 0
            stats["last_seen"] = now_ts()
            stats["score"] = self.model.probability(features)
            stats["family"] = family_for(d)
            self.reputation[d] = {"first_seen": stats.get("first_seen", now_ts()), "last_seen": now_ts(),
                                  "observations": stats.get("observations", 0), "score": stats["score"],
                                  "family": stats["family"], "label": stats["label"]}
            if label:
                self.blocklist.add(d)
                self.allowlist.discard(d)
            else:
                self.allowlist.add(d)
                self.blocklist.discard(d)
            self.feedback_count += 1
        self.save_config()
        self.save_reputation()
        LOG.log(f"Learned explicit {'ad/tracker' if label else 'legitimate/allow'} label for {d}.")
        return self.classify(d)

    def save_reputation(self):
        try:
            atomic_json(REPUTATION_PATH, self.reputation)
            atomic_json(KNOWLEDGE_PATH, {"patterns": [], "last_update": now_ts(),
                                        "note": "Version 7 stores explicit domain labels and model weights; unverified regex learning is disabled."})
        except Exception as e:
            LOG.log(f"Could not save reputation/knowledge: {e}", "ERROR")

    def add_block(self, domain: str):
        d = normalize_domain(domain)
        if not d:
            raise ValueError("Invalid domain.")
        self.blocklist.add(d)
        self.allowlist.discard(d)
        self.save_config()

    def add_allow(self, domain: str):
        d = normalize_domain(domain)
        if not d:
            raise ValueError("Invalid domain.")
        self.allowlist.add(d)
        self.blocklist.discard(d)
        self.save_config()

    def remove_domain(self, domain: str):
        d = normalize_domain(domain)
        if d:
            self.blocklist.discard(d)
            self.allowlist.discard(d)
            self.save_config()

    def scan_connections(self):
        rows = []
        if psutil is None:
            return rows
        try:
            conns = psutil.net_connections(kind="inet")
        except Exception as e:
            LOG.log(f"Network scan limited (permissions/platform): {e}", "WARN")
            return rows
        for c in conns:
            try:
                if not c.raddr:
                    continue
                ip = c.raddr.ip
                port = c.raddr.port
                pid = c.pid
                host = None
                # Reverse DNS is slow and often unhelpful; use a short timeout in a daemon worker.
                if ip and not ip.startswith(("127.", "10.", "192.168.", "169.254.")):
                    host = self.cached_reverse_dns(ip)
                row = {"pid": pid, "ip": ip, "port": port, "host": host, "status": c.status}
                rows.append(row)
                if host:
                    self.observe(host, row)
            except Exception:
                continue
        with self.lock:
            self.connections = rows[-2000:]
            self.last_scan = now_ts()
            self.scan_count += 1
        return rows

    def cached_reverse_dns(self, ip: str):
        cache = self.reputation.get("_dns_cache", {})
        item = cache.get(ip)
        if item and now_ts() - item.get("ts", 0) < 3600:
            return item.get("host")
        # Avoid blocking the UI/scanner for long reverse DNS calls.
        result = [None]
        def lookup():
            try:
                result[0] = socket.gethostbyaddr(ip)[0].lower()
            except Exception:
                pass
        t = threading.Thread(target=lookup, daemon=True)
        t.start()
        t.join(0.25)
        if result[0]:
            cache[ip] = {"host": result[0], "ts": now_ts()}
            self.reputation["_dns_cache"] = cache
        return result[0]

    def detect_active_window(self):
        if not IS_WINDOWS:
            return "", None
        try:
            user32 = ctypes.windll.user32
            hwnd = user32.GetForegroundWindow()
            if not hwnd:
                return "", None
            length = user32.GetWindowTextLengthW(hwnd)
            buf = ctypes.create_unicode_buffer(max(1, length + 1))
            user32.GetWindowTextW(hwnd, buf, len(buf))
            pid = ctypes.c_ulong()
            user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
            return buf.value.strip(), int(pid.value) or None
        except Exception:
            return "", None

    def monitor_loop(self):
        last_sync = 0.0
        while self.running:
            try:
                title, pid = self.detect_active_window()
                domain = None
                # Only accept a domain-looking token from a window title; this is a hint, not ground truth.
                for token in re.findall(r"(?i)(?:https?://)?(?:www\.)?[a-z0-9.-]+\.[a-z]{2,}", title or ""):
                    domain = normalize_domain(token)
                    if domain:
                        break
                with self.lock:
                    self.active_title, self.active_pid, self.active_domain = title, pid, domain
                self.scan_connections()
                if domain:
                    self.observe(domain, {"pid": pid, "source": "active-window-title"})
                if self.config.get("auto_block_enabled"):
                    self.auto_block_candidates()
                if self.config.get("drone_enabled") and now_ts() - last_sync > float(self.config.get("rules_sync_interval", 21600)):
                    self.sync_rules()
                    last_sync = now_ts()
            except Exception as e:
                LOG.log(f"Monitor loop error: {e}", "ERROR")
            time.sleep(max(0.5, float(self.config.get("monitor_interval", 2.0))))

    def auto_block_candidates(self):
        if not self.config.get("auto_block_enabled"):
            return []
        applied = []
        threshold = float(self.config.get("auto_block_threshold", 0.94))
        minimum = int(self.config.get("minimum_evidence", 8))
        with self.lock:
            candidates = list(self.domains.items())
        for d, stats in candidates:
            result = self.classify(d)
            if d in self.allowlist:
                continue
            if result.get("rule_hit") or stats.get("label") == 1:
                self.blocklist.add(d)
                applied.append(d)
            elif (not self.config.get("require_rule_or_feedback", True)
                  and result["score"] >= threshold and stats.get("observations", 0) >= minimum):
                self.blocklist.add(d)
                applied.append(d)
        if applied:
            self.save_config()
            LOG.log(f"Auto-block candidate list updated with {len(applied)} domains. System hosts file was not changed.")
        return applied

    def shutdown(self):
        self.running = False
        self.model.save()
        self.save_config()
        self.save_reputation()

def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def request_elevation_for_hosts():
    if not IS_WINDOWS or is_admin():
        return True
    answer = messagebox.askyesno("Administrator permission",
        "Applying changes to the Windows hosts file requires administrator permission.\n\nRestart this program as administrator now?")
    if not answer:
        return False
    try:
        script = os.path.abspath(sys.argv[0])
        params = subprocess.list2cmdline(sys.argv[1:])
        result = ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, f'"{script}" {params}', None, 1)
        if result <= 32:
            messagebox.showerror("Elevation failed", f"Windows could not start elevated (code {result}).")
        return False
    except Exception as e:
        messagebox.showerror("Elevation failed", str(e))
        return False

class HostsApplier:
    MARK_START = "# BEGIN BORG AI ADBLOCKER MANAGED BLOCK"
    MARK_END = "# END BORG AI ADBLOCKER MANAGED BLOCK"

    def __init__(self, engine: BorgEngine):
        self.engine = engine

    def apply(self, domains: list[str] | None = None):
        if not is_admin():
            request_elevation_for_hosts()
            return False
        selected = set(domains if domains is not None else self.engine.blocklist)
        selected = {d for x in selected if (d := normalize_domain(x))}
        selected -= self.engine.allowlist
        if not selected:
            messagebox.showinfo("Nothing to apply", "There are no valid block entries after allowlist exclusions.")
            return False
        try:
            HOSTS_PATH.parent.mkdir(parents=True, exist_ok=True)
            original = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore") if HOSTS_PATH.exists() else ""
            backup = BACKUP_DIR / f"hosts_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            backup.write_text(original, encoding="utf-8")
            # Remove only our managed section, preserving all unrelated entries.
            pattern = re.compile(re.escape(self.MARK_START) + r".*?" + re.escape(self.MARK_END), re.S)
            cleaned = pattern.sub("", original).rstrip()
            block = "\n" + self.MARK_START + "\n"
            block += "# Generated by BORG AI AdBlocker. Restore from Backups to undo.\n"
            block += "".join(f"0.0.0.0 {d}\n" for d in sorted(selected))
            block += self.MARK_END + "\n"
            temp = HOSTS_PATH.with_suffix(".borg.tmp")
            temp.write_text(cleaned + "\n" + block, encoding="utf-8")
            temp.replace(HOSTS_PATH)
            try:
                if IS_WINDOWS:
                    subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
            except Exception:
                pass
            LOG.log(f"Applied {len(selected)} domains to system hosts file; backup: {backup}")
            messagebox.showinfo("Hosts updated", f"Applied {len(selected)} domains.\nBackup:\n{backup}")
            return True
        except Exception as e:
            LOG.log(f"Hosts update failed: {e}", "ERROR")
            messagebox.showerror("Hosts update failed", f"{e}\n\nNo changes should be considered successful unless confirmed.")
            return False

    def remove_managed_block(self):
        if not is_admin():
            request_elevation_for_hosts()
            return False
        try:
            original = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore")
            backup = BACKUP_DIR / f"hosts_before_remove_{datetime.now().strftime('%Y%m%d_%H%M%S')}.bak"
            BACKUP_DIR.mkdir(parents=True, exist_ok=True)
            backup.write_text(original, encoding="utf-8")
            pattern = re.compile(re.escape(self.MARK_START) + r".*?" + re.escape(self.MARK_END), re.S)
            updated = pattern.sub("", original).rstrip() + "\n"
            temp = HOSTS_PATH.with_suffix(".borg.tmp")
            temp.write_text(updated, encoding="utf-8")
            temp.replace(HOSTS_PATH)
            if IS_WINDOWS:
                subprocess.run(["ipconfig", "/flushdns"], capture_output=True, timeout=10)
            LOG.log("Removed BORG-managed hosts section.")
            messagebox.showinfo("Removed", f"BORG-managed entries removed.\nBackup:\n{backup}")
            return True
        except Exception as e:
            messagebox.showerror("Remove failed", str(e))
            return False

class AdBlockGUI:
    def __init__(self, engine: BorgEngine):
        self.engine = engine
        self.applier = HostsApplier(engine)
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} — Adaptive Learning {APP_VERSION}")
        self.root.geometry("980x690")
        self.root.minsize(820, 560)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self._build()
        self._schedule_refresh()

    def _build(self):
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)
        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text="BORG AI", font=("Segoe UI", 17, "bold")).pack(side="left")
        ttk.Label(header, text="Adaptive learning • evidence-first blocking • reversible changes").pack(side="left", padx=12)
        self.status = ttk.Label(header, text="Monitoring starting…")
        self.status.pack(side="right")
        self.notebook = ttk.Notebook(outer)
        self.notebook.pack(fill="both", expand=True)

        self.monitor_tab = ttk.Frame(self.notebook, padding=8)
        self.learning_tab = ttk.Frame(self.notebook, padding=8)
        self.rules_tab = ttk.Frame(self.notebook, padding=8)
        self.settings_tab = ttk.Frame(self.notebook, padding=8)
        self.notebook.add(self.monitor_tab, text="Live Monitor")
        self.notebook.add(self.learning_tab, text="AI Learning & Review")
        self.notebook.add(self.rules_tab, text="Block / Allow Lists")
        self.notebook.add(self.settings_tab, text="Settings & Recovery")
        self._build_monitor()
        self._build_learning()
        self._build_lists()
        self._build_settings()

        self.log_box = tk.Text(outer, height=6, wrap="word", state="disabled")
        self.log_box.pack(fill="x", pady=(8, 0))
        ttk.Label(outer, text=f"System hosts file: {HOSTS_PATH}  |  Local state: {BASE_DIR}", foreground="#666").pack(anchor="w", pady=(4, 0))

    def _build_monitor(self):
        top = ttk.Frame(self.monitor_tab)
        top.pack(fill="x")
        self.kpis = {}
        for key, title in (("scan", "Scans"), ("domains", "Observed domains"), ("model", "Training examples"), ("score", "Active-site score")):
            box = ttk.LabelFrame(top, text=title, padding=8)
            box.pack(side="left", fill="x", expand=True, padx=3)
            val = ttk.Label(box, text="—", font=("Segoe UI", 14, "bold"))
            val.pack()
            self.kpis[key] = val
        self.active_label = ttk.Label(self.monitor_tab, text="Active window: —", wraplength=900)
        self.active_label.pack(anchor="w", pady=8)
        cols = ("domain", "score", "family", "observations", "decision")
        self.domain_tree = ttk.Treeview(self.monitor_tab, columns=cols, show="headings", height=15)
        for col, width in zip(cols, (280, 90, 200, 100, 230)):
            self.domain_tree.heading(col, text=col.title())
            self.domain_tree.column(col, width=width, anchor="w")
        self.domain_tree.pack(fill="both", expand=True)
        bar = ttk.Frame(self.monitor_tab)
        bar.pack(fill="x", pady=(8, 0))
        ttk.Button(bar, text="Scan now", command=self.scan_now).pack(side="left", padx=3)
        ttk.Button(bar, text="Label selected as ad/tracker", command=lambda: self.label_selected(1)).pack(side="left", padx=3)
        ttk.Button(bar, text="Label selected as legitimate", command=lambda: self.label_selected(0)).pack(side="left", padx=3)
        ttk.Button(bar, text="Refresh view", command=self.refresh).pack(side="left", padx=3)

    def _build_learning(self):
        self.metrics_text = tk.Text(self.learning_tab, height=9, wrap="word", state="disabled")
        self.metrics_text.pack(fill="x", pady=(0, 8))
        ttk.Label(self.learning_tab, text="Review domains below. A prediction is not proof; explicit labels improve the model.").pack(anchor="w")
        cols = ("domain", "score", "observations", "label", "family")
        self.review_tree = ttk.Treeview(self.learning_tab, columns=cols, show="headings", height=14)
        for col, width in zip(cols, (300, 100, 120, 100, 240)):
            self.review_tree.heading(col, text=col.title())
            self.review_tree.column(col, width=width, anchor="w")
        self.review_tree.pack(fill="both", expand=True, pady=6)
        row = ttk.Frame(self.learning_tab)
        row.pack(fill="x")
        ttk.Button(row, text="Confirm ad / tracker", command=lambda: self.label_selected(1, review=True)).pack(side="left", padx=3)
        ttk.Button(row, text="Mark legitimate", command=lambda: self.label_selected(0, review=True)).pack(side="left", padx=3)
        ttk.Button(row, text="Export model metrics", command=self.export_metrics).pack(side="left", padx=3)

    def _build_lists(self):
        panes = ttk.Panedwindow(self.rules_tab, orient="horizontal")
        panes.pack(fill="both", expand=True)
        left = ttk.Labelframe(panes, text="Block candidates / explicit blocks", padding=6)
        right = ttk.Labelframe(panes, text="Allowlist (always wins)", padding=6)
        panes.add(left, weight=1); panes.add(right, weight=1)
        self.block_list = tk.Listbox(left, height=18)
        self.block_list.pack(fill="both", expand=True)
        self.allow_list = tk.Listbox(right, height=18)
        self.allow_list.pack(fill="both", expand=True)
        controls = ttk.Frame(self.rules_tab)
        controls.pack(fill="x", pady=8)
        ttk.Button(controls, text="Add block domain…", command=lambda: self.prompt_domain("block")).pack(side="left", padx=3)
        ttk.Button(controls, text="Add allow domain…", command=lambda: self.prompt_domain("allow")).pack(side="left", padx=3)
        ttk.Button(controls, text="Remove selected", command=self.remove_list_selection).pack(side="left", padx=3)
        ttk.Button(controls, text="Import domain list…", command=self.import_list).pack(side="left", padx=3)
        ttk.Button(controls, text="Export lists…", command=self.export_lists).pack(side="left", padx=3)

    def _build_settings(self):
        frame = ttk.Frame(self.settings_tab)
        frame.pack(fill="both", expand=True, anchor="nw")
        self.auto_var = tk.BooleanVar(value=bool(self.engine.config.get("auto_block_enabled", False)))
        self.strict_var = tk.BooleanVar(value=bool(self.engine.config.get("require_rule_or_feedback", True)))
        self.drone_var = tk.BooleanVar(value=bool(self.engine.config.get("drone_enabled", False)))
        ttk.Checkbutton(frame, text="Enable automatic candidate additions (system hosts still requires manual Apply)", variable=self.auto_var).pack(anchor="w", pady=5)
        ttk.Checkbutton(frame, text="Strict mode: only block-list evidence or explicit user confirmation", variable=self.strict_var).pack(anchor="w", pady=5)
        ttk.Checkbutton(frame, text="Enable optional drone page research (network requests; disabled by default)", variable=self.drone_var).pack(anchor="w", pady=5)
        ttk.Label(frame, text="Auto-block threshold (0.50–0.999)").pack(anchor="w", pady=(14, 2))
        self.threshold_var = tk.DoubleVar(value=float(self.engine.config.get("auto_block_threshold", 0.94)))
        ttk.Scale(frame, from_=0.5, to=0.999, variable=self.threshold_var, orient="horizontal").pack(fill="x", padx=3)
        ttk.Label(frame, text="Minimum observations before heuristic-only candidates are considered").pack(anchor="w", pady=(14, 2))
        self.minimum_var = tk.IntVar(value=int(self.engine.config.get("minimum_evidence", 8)))
        ttk.Spinbox(frame, from_=1, to=10000, textvariable=self.minimum_var, width=10).pack(anchor="w")
        ttk.Button(frame, text="Save settings", command=self.save_settings).pack(anchor="w", pady=10)
        ttk.Separator(frame).pack(fill="x", pady=10)
        ttk.Button(frame, text="Sync filter lists now", command=self.sync_rules).pack(anchor="w", pady=3)
        ttk.Button(frame, text="Apply selected block list to system hosts…", command=self.apply_hosts).pack(anchor="w", pady=3)
        ttk.Button(frame, text="Remove BORG-managed hosts section…", command=self.remove_hosts).pack(anchor="w", pady=3)
        ttk.Button(frame, text="Open backup folder", command=lambda: self.open_path(BACKUP_DIR)).pack(anchor="w", pady=3)
        ttk.Button(frame, text="Open data folder", command=lambda: self.open_path(BASE_DIR)).pack(anchor="w", pady=3)
        ttk.Label(frame, text="Safety: monitoring is observational. Host-file changes are never applied automatically.").pack(anchor="w", pady=(12, 0))

    def selected_domain(self, review=False):
        tree = self.review_tree if review else self.domain_tree
        sel = tree.selection()
        if not sel:
            return None
        return tree.item(sel[0], "values")[0]

    def label_selected(self, label: int, review=False):
        d = self.selected_domain(review=review)
        if not d:
            messagebox.showinfo("Select a domain", "Select a domain row first.")
            return
        prompt = "Confirm this is an ad/tracker?" if label else "Confirm this is legitimate and should be allowed?"
        if not messagebox.askyesno("Confirm learning label", f"{prompt}\n\n{d}\n\nThis updates the local model and allow/block lists."):
            return
        try:
            self.engine.label_domain(d, label)
            self.refresh()
        except Exception as e:
            messagebox.showerror("Learning failed", str(e))

    def scan_now(self):
        threading.Thread(target=self.engine.scan_connections, daemon=True).start()
        self.status.config(text="Scanning…")
        self.root.after(800, self.refresh)

    def refresh(self):
        try:
            with self.engine.lock:
                domains = list(self.engine.domains.items())
                title = self.engine.active_title
                active = self.engine.active_domain
                scan_count = self.engine.scan_count
            self.kpis["scan"].config(text=str(scan_count))
            self.kpis["domains"].config(text=str(len(domains)))
            self.kpis["model"].config(text=str(self.engine.model.metrics()["examples"]))
            active_score = self.engine.classify(active)["score"] if active else 0.0
            self.kpis["score"].config(text=f"{active_score:.3f}")
            self.active_label.config(text=f"Active window: {title or '—'}  |  inferred domain: {active or 'not detected'}")
            for tree in (self.domain_tree, self.review_tree):
                for item in tree.get_children():
                    tree.delete(item)
            rows = []
            for d, stats in domains:
                result = self.engine.classify(d)
                rows.append((d, result, stats))
            rows.sort(key=lambda x: (x[1]["score"], x[2].get("observations", 0)), reverse=True)
            for d, result, stats in rows[:500]:
                self.domain_tree.insert("", "end", values=(d, f'{result["score"]:.3f}', result["family"], stats.get("observations", 0), result["decision"]))
                label = stats.get("label")
                label_text = "Ad/tracker" if label == 1 else "Legitimate" if label == 0 else "Unlabeled"
                self.review_tree.insert("", "end", values=(d, f'{result["score"]:.3f}', stats.get("observations", 0), label_text, result["family"]))
            self.block_list.delete(0, tk.END)
            self.allow_list.delete(0, tk.END)
            for d in sorted(self.engine.blocklist):
                self.block_list.insert(tk.END, d)
            for d in sorted(self.engine.allowlist):
                self.allow_list.insert(tk.END, d)
            metrics = self.engine.model.metrics()
            acc = "not enough evaluation data" if metrics["accuracy"] is None else f'{metrics["accuracy"]:.1%} (online running estimate; not a held-out benchmark)'
            text = (
                f"Model: online logistic regression\n"
                f"Training examples: {metrics['examples']}  |  positive: {metrics['positives']}  |  negative: {metrics['negatives']}\n"
                f"Running pre-update accuracy estimate: {acc}\n"
                f"Explicit feedback this session: {self.engine.feedback_count}\n"
                f"Learned weights: {json.dumps(metrics['weights'], sort_keys=True)}\n"
                f"Interpretation: the score estimates ad/tracker likelihood from available domain features and labeled examples. "
                f"It cannot inspect encrypted page contents and is not a verified probability until calibrated on a separate labeled test set."
            )
            self.metrics_text.config(state="normal")
            self.metrics_text.delete("1.0", tk.END)
            self.metrics_text.insert("1.0", text)
            self.metrics_text.config(state="disabled")
            self.status.config(text=f"Updated {datetime.now().strftime('%H:%M:%S')}")
            # Append only unseen recent log messages.
            if not hasattr(self, "_last_log_ts"):
                self._last_log_ts = 0
            new = [x for x in LOG.snapshot() if x["ts"] > self._last_log_ts]
            if new:
                self.log_box.config(state="normal")
                for row in reversed(new[-12:]):
                    self.log_box.insert(tk.END, f'[{row["time"]}] {row["level"]}: {row["message"]}\n')
                self.log_box.see(tk.END)
                self.log_box.config(state="disabled")
                self._last_log_ts = max(x["ts"] for x in new)
        except Exception as e:
            LOG.log(f"GUI refresh error: {e}", "ERROR")

    def _schedule_refresh(self):
        self.refresh()
        self.root.after(1500, self._schedule_refresh)

    def prompt_domain(self, mode):
        win = tk.Toplevel(self.root)
        win.title("Add domain")
        win.transient(self.root)
        win.grab_set()
        ttk.Label(win, text="Domain name (for example, ads.example.com):").pack(padx=12, pady=(12, 4))
        entry = ttk.Entry(win, width=42)
        entry.pack(padx=12, pady=4)
        entry.focus_set()
        def submit():
            try:
                if mode == "block":
                    self.engine.add_block(entry.get())
                else:
                    self.engine.add_allow(entry.get())
                win.destroy()
                self.refresh()
            except Exception as e:
                messagebox.showerror("Invalid domain", str(e), parent=win)
        ttk.Button(win, text="Save", command=submit).pack(pady=10)
        entry.bind("<Return>", lambda _e: submit())

    def remove_list_selection(self):
        tab = self.notebook.index(self.notebook.select())
        box = self.allow_list if tab == 2 and self.allow_list.curselection() else self.block_list
        sel = box.curselection()
        if not sel:
            messagebox.showinfo("Select a domain", "Select a list entry to remove.")
            return
        domain = box.get(sel[0])
        self.engine.remove_domain(domain)
        self.refresh()

    def import_list(self):
        path = filedialog.askopenfilename(title="Import domain list", filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if not path:
            return
        mode = messagebox.askyesnocancel("Import destination", "Yes = add to block list\nNo = add to allowlist\nCancel = abort")
        if mode is None:
            return
        added = 0
        try:
            for line in Path(path).read_text(encoding="utf-8", errors="ignore").splitlines():
                line = line.strip()
                if not line or line.startswith(("#", "!")):
                    continue
                parts = line.split()
                d = normalize_domain(parts[-1] if len(parts) >= 2 and parts[0] in ("0.0.0.0", "127.0.0.1") else line)
                if d:
                    (self.engine.add_block if mode else self.engine.add_allow)(d)
                    added += 1
            messagebox.showinfo("Import complete", f"Imported {added} valid domain entries.")
            self.refresh()
        except Exception as e:
            messagebox.showerror("Import failed", str(e))

    def export_lists(self):
        path = filedialog.asksaveasfilename(title="Export domain lists", defaultextension=".txt", filetypes=[("Text files", "*.txt")])
        if not path:
            return
        try:
            lines = ["# BORG AI AdBlocker domain export", "[BLOCKLIST]"]
            lines += sorted(self.engine.blocklist)
            lines += ["", "[ALLOWLIST]"] + sorted(self.engine.allowlist)
            Path(path).write_text("\n".join(lines) + "\n", encoding="utf-8")
            messagebox.showinfo("Export complete", f"Saved {len(self.engine.blocklist)} block entries and {len(self.engine.allowlist)} allow entries.")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def save_settings(self):
        self.engine.config["auto_block_enabled"] = bool(self.auto_var.get())
        self.engine.config["require_rule_or_feedback"] = bool(self.strict_var.get())
        self.engine.config["drone_enabled"] = bool(self.drone_var.get())
        self.engine.config["auto_block_threshold"] = clamp(float(self.threshold_var.get()), 0.5, 0.999)
        self.engine.config["minimum_evidence"] = max(1, int(self.minimum_var.get()))
        self.engine.save_config()
        LOG.log("Settings saved.")
        messagebox.showinfo("Settings saved", "Settings saved. System hosts-file changes remain manual.")

    def sync_rules(self):
        self.status.config(text="Updating rules…")
        threading.Thread(target=self._sync_rules_worker, daemon=True).start()

    def _sync_rules_worker(self):
        self.engine.sync_rules()
        self.root.after(0, self.refresh)

    def apply_hosts(self):
        if not messagebox.askyesno("Apply to system hosts", "This will edit the system hosts file and may block listed domains system-wide.\nA backup will be created first.\n\nContinue?"):
            return
        self.applier.apply()

    def remove_hosts(self):
        if not messagebox.askyesno("Remove managed section", "Remove only the BORG-managed section from the system hosts file? A backup will be created first."):
            return
        self.applier.remove_managed_block()

    def export_metrics(self):
        path = filedialog.asksaveasfilename(title="Export model metrics", defaultextension=".json", filetypes=[("JSON", "*.json")])
        if not path:
            return
        try:
            payload = {"version": APP_VERSION, "exported_at": iso_time(), "model": self.engine.model.metrics(),
                       "domain_count": len(self.engine.domains), "domains": self.engine.domains}
            Path(path).write_text(json.dumps(payload, indent=2), encoding="utf-8")
            messagebox.showinfo("Export complete", f"Model metrics exported to:\n{path}")
        except Exception as e:
            messagebox.showerror("Export failed", str(e))

    def open_path(self, path: Path):
        path.mkdir(parents=True, exist_ok=True)
        try:
            if IS_WINDOWS:
                os.startfile(str(path))
            else:
                webbrowser.open(path.as_uri())
        except Exception as e:
            messagebox.showerror("Could not open folder", str(e))

    def close(self):
        if messagebox.askyesno("Exit", "Save learning data and exit?"):
            self.engine.shutdown()
            self.root.destroy()

    def run(self):
        self.root.mainloop()

def ensure_data_dirs():
    for p in (BASE_DIR, BACKUP_DIR, RULE_DIR, PLUGIN_DIR):
        try:
            p.mkdir(parents=True, exist_ok=True)
        except Exception as e:
            raise RuntimeError(f"Cannot create application data folder {p}: {e}")

def main():
    ensure_data_dirs()
    LOG.log(f"{APP_NAME} v{APP_VERSION} starting.")
    if psutil is None:
        LOG.log("psutil is not installed; network connection scanning is disabled. Install with: python -m pip install psutil", "WARN")
    if requests is None:
        LOG.log("requests is not installed; online filter-list sync is disabled. Install with: python -m pip install requests", "WARN")
    engine = BorgEngine()
    monitor = threading.Thread(target=engine.monitor_loop, name="BORG-Monitor", daemon=True)
    monitor.start()
    gui = AdBlockGUI(engine)
    gui.run()

if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        try:
            LOG.log(f"Fatal startup error: {exc}\n{traceback.format_exc()}", "FATAL")
        except Exception:
            pass
        try:
            messagebox.showerror(APP_NAME, f"Startup failed:\n{exc}")
        except Exception:
            print(f"Startup failed: {exc}", file=sys.stderr)
        raise
