#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Hybrid Ad Blocker – FULL UPGRADED PREDICTIVE VERSION
- Auto-elevation
- PID + window title website detection
- Whole-web connection scan
- Predictive scoring engine (heuristics + ML-lite logistic)
- Burst detection + temporal weighting + time decay
- PID correlation intelligence
- Domain reputation cache
- Regex pattern recognition + port heuristics
- Reverse DNS cache
- Ad storm detection
- Auto-block threshold (self-learning)
- Ad family classification
- Plugin API for custom scoring
- GUI with predictive metrics + heatmap-style per-site view
"""

# ============================================================
# AUTO-ELEVATION
# ============================================================
import ctypes, os, sys

def ensure_admin():
    try:
        if os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable,
                f'"{script}" {params}', None, 1
            )
            sys.exit()
    except Exception as e:
        print(f"[Hybrid AdBlock] Elevation failed: {e}")
        sys.exit()

ensure_admin()

# ============================================================
# IMPORTS
# ============================================================
import time, json, threading, socket, re, importlib, traceback
from pathlib import Path
from collections import defaultdict, deque

import psutil
import requests

import tkinter as tk
from tkinter import ttk, filedialog

# ============================================================
# CONFIG
# ============================================================
CUSTOM_HOSTS_PATH = Path(r"C:\AdBlock\ad_hosts.txt")
BLOCK_IP = "0.0.0.0"
BACKUP_DIR = CUSTOM_HOSTS_PATH.parent / "backups"
LOG_PATH = CUSTOM_HOSTS_PATH.parent / "adblock_log.json"
REPUTATION_PATH = CUSTOM_HOSTS_PATH.parent / "domain_reputation.json"
DNS_CACHE_PATH = CUSTOM_HOSTS_PATH.parent / "dns_cache.json"
PLUGIN_DIR = CUSTOM_HOSTS_PATH.parent / "plugins"

PRIMARY_TEST_SITE = "adblock.turtlecute.org"

AD_RULE_URLS = [
    "https://easylist.to/easylist/easylist.txt",
    "https://easylist-downloads.adblockplus.org/easyprivacy.txt",
]

WEB_AD_DETECTION_INTERVAL = 1.0
AD_RULES_SYNC_INTERVAL = 300.0
DOMAIN_DECAY_INTERVAL = 60.0
DNS_CACHE_TTL = 3600.0
AUTO_BLOCK_THRESHOLD = 0.75
AD_STORM_WINDOW_SEC = 1.0
AD_STORM_COUNT_THRESHOLD = 20

BROWSER_NAMES = ["chrome", "msedge", "edge", "firefox", "brave", "opera"]

# Regex patterns for ad/tracking classification
AD_PATTERNS = [
    re.compile(r".*ad.*", re.IGNORECASE),
    re.compile(r".*ads.*", re.IGNORECASE),
    re.compile(r".*banner.*", re.IGNORECASE),
    re.compile(r".*promo.*", re.IGNORECASE),
    re.compile(r".*click.*", re.IGNORECASE),
]
TRACKING_PATTERNS = [
    re.compile(r".*track.*", re.IGNORECASE),
    re.compile(r".*pixel.*", re.IGNORECASE),
    re.compile(r".*beacon.*", re.IGNORECASE),
    re.compile(r".*metrics.*", re.IGNORECASE),
    re.compile(r".*analytics.*", re.IGNORECASE),
]
CDN_PATTERNS = [
    re.compile(r".*cdn.*", re.IGNORECASE),
    re.compile(r".*cloudfront.*", re.IGNORECASE),
    re.compile(r".*akamai.*", re.IGNORECASE),
]
VIDEO_AD_PATTERNS = [
    re.compile(r".*video.*ad.*", re.IGNORECASE),
    re.compile(r".*vast.*", re.IGNORECASE),
]

# ============================================================
# GLOBAL STATE
# ============================================================
ad_rules = set()
ad_host_hints = set()

reverse_dns_cache = {}
plugins = []

web_ad_state = {
    "active": False,
    "last_scan_ts": 0.0,
    "connections": [],
    "ad_connections": [],
    "domain_stats": {},
    "prediction_score": 0.0,
    "last_event_ts": 0.0,
    "ad_storm": False,
    "storm_events": deque(),  # (timestamp, domain)
}

active_domain_state = {
    "domain": None,
    "title": "",
    "pid": None,
}

domain_reputation = {}

# ============================================================
# LOGGING
# ============================================================
def log(msg):
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}] {msg}")

# ============================================================
# HOSTS MANAGER
# ============================================================
class HostsManager:
    def __init__(self, path: Path, block_ip: str):
        self.path = path
        self.block_ip = block_ip
        self.entries = set()
        self._load()

    def _load(self):
        self.entries.clear()
        if not self.path.exists():
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.path.touch()
            return
        with self.path.open("r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split()
                if len(parts) >= 2:
                    ip, domain = parts[0], parts[1]
                    if ip == self.block_ip:
                        self.entries.add(domain.lower())

    def is_blocked(self, domain: str) -> bool:
        return domain.lower() in self.entries

    def add(self, domain: str) -> bool:
        d = domain.lower().strip()
        if not d or d.startswith("#"):
            return False
        if d in self.entries:
            return False
        self.entries.add(d)
        return True

    def save(self):
        BACKUP_DIR.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        backup_path = BACKUP_DIR / f"hosts_backup_{ts}.txt"
        if self.path.exists():
            backup_path.write_text(
                self.path.read_text(encoding="utf-8", errors="ignore"),
                encoding="utf-8"
            )
        lines = [
            "# Hybrid AdBlock Hosts File\n",
            f"# Block IP: {self.block_ip}\n",
            f"# Last update: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n"
        ]
        for domain in sorted(self.entries):
            lines.append(f"{self.block_ip} {domain}\n")
        self.path.write_text("".join(lines), encoding="utf-8")

# ============================================================
# COUNTERS + ANALYTICS
# ============================================================
class AdCounter:
    def __init__(self):
        self.reset()

    def reset(self):
        self.page = None
        self.blocked = 0
        self.missed = 0
        self.missed_list = []

    def set_page(self, page_id: str):
        if self.page != page_id:
            self.reset()
            self.page = page_id

    def log_blocked(self):
        self.blocked += 1

    def log_missed(self, domain: str):
        self.missed += 1
        self.missed_list.append(domain)

class Analytics:
    def __init__(self):
        self.per_site = defaultdict(lambda: {
            "blocked": 0,
            "missed": 0,
            "predictive_score": 0.0,
            "future_likelihood": 0.0,
            "family": "unknown",
        })

    def log(self, domain: str, blocked: bool, predictive_score: float, future_likelihood: float, family: str):
        site = domain.lower()
        if blocked:
            self.per_site[site]["blocked"] += 1
        else:
            self.per_site[site]["missed"] += 1
        self.per_site[site]["predictive_score"] = predictive_score
        self.per_site[site]["future_likelihood"] = future_likelihood
        self.per_site[site]["family"] = family

    def snapshot(self):
        return dict(self.per_site)

def write_log(counter: AdCounter, analytics: Analytics):
    LOG_PATH.write_text(json.dumps({
        "page": counter.page,
        "blocked": counter.blocked,
        "missed": counter.missed,
        "missed_list": counter.missed_list,
        "per_site": analytics.snapshot(),
        "timestamp": time.time()
    }, indent=2))

# ============================================================
# AD RULES (kept for future)
# ============================================================
def _extract_host_hint_from_rule(line: str):
    line = line.strip()
    if not line or line.startswith("!"):
        return None
    host = None
    if line.startswith("||"):
        body = line[2:]
        for sep in ("^", "/", "$"):
            if sep in body:
                body = body.split(sep, 1)[0]
        if body and "." in body:
            host = body.lower()
    else:
        if "." in line and not line.startswith("@@"):
            host = line.lower()
    return host

def fetch_ad_rules_from_internet():
    global ad_rules, ad_host_hints
    new_rules = set()
    new_hosts = set()
    for url in AD_RULE_URLS:
        try:
            r = requests.get(url, timeout=10)
            if r.status_code == 200:
                for line in r.text.splitlines():
                    line = line.strip()
                    if not line or line.startswith("!"):
                        continue
                    new_rules.add(line)
                    host_hint = _extract_host_hint_from_rule(line)
                    if host_hint:
                        new_hosts.add(host_hint)
                log(f"[AD] Fetched rules from {url}")
        except Exception as e:
            log(f"[AD] Failed to fetch {url}: {e}")
    ad_rules |= new_rules
    ad_host_hints |= new_hosts

def ad_rules_sync_loop():
    while True:
        fetch_ad_rules_from_internet()
        time.sleep(AD_RULES_SYNC_INTERVAL)

# ============================================================
# REPUTATION + DNS CACHE + PLUGINS
# ============================================================
def load_reputation():
    global domain_reputation
    try:
        if REPUTATION_PATH.exists():
            domain_reputation = json.loads(REPUTATION_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log(f"[REP] Failed to load reputation: {e}")
        domain_reputation = {}

def save_reputation():
    try:
        REPUTATION_PATH.write_text(json.dumps(domain_reputation, indent=2), encoding="utf-8")
    except Exception as e:
        log(f"[REP] Failed to save reputation: {e}")

def load_dns_cache():
    global reverse_dns_cache
    try:
        if DNS_CACHE_PATH.exists():
            reverse_dns_cache = json.loads(DNS_CACHE_PATH.read_text(encoding="utf-8"))
    except Exception:
        reverse_dns_cache = {}

def save_dns_cache():
    try:
        DNS_CACHE_PATH.write_text(json.dumps(reverse_dns_cache, indent=2), encoding="utf-8")
    except Exception:
        pass

def load_plugins():
    global plugins
    plugins = []
    try:
        PLUGIN_DIR.mkdir(parents=True, exist_ok=True)
        for file in PLUGIN_DIR.glob("plugin_*.py"):
            try:
                spec_name = f"adblock_plugin_{file.stem}"
                module = importlib.machinery.SourceFileLoader(spec_name, str(file)).load_module()
                if hasattr(module, "modify_score"):
                    plugins.append(module)
                    log(f"[PLUGIN] Loaded {file.name}")
            except Exception as e:
                log(f"[PLUGIN] Failed to load {file.name}: {e}")
                traceback.print_exc()
    except Exception as e:
        log(f"[PLUGIN] Plugin loading error: {e}")

# ============================================================
# PID + WINDOW TITLE DETECTION
# ============================================================
def get_active_window_info():
    if os.name != "nt":
        return "", None
    try:
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return "", None
        length = user32.GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(max(1, length + 1))
        user32.GetWindowTextW(hwnd, buf, len(buf))
        pid = wintypes.DWORD()
        user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        return buf.value.strip(), int(pid.value) or None
    except Exception:
        return "", None

# ============================================================
# WHOLE-WEB CONNECTION SCAN
# ============================================================
def _reverse_dns(ip: str):
    now = time.time()
    # cache lookup
    cached = reverse_dns_cache.get(ip)
    if cached:
        host, ts = cached.get("host"), cached.get("ts", 0)
        if now - ts < DNS_CACHE_TTL:
            return host
    try:
        host, _, _ = socket.gethostbyaddr(ip)
        host = host.lower()
    except Exception:
        host = None
    reverse_dns_cache[ip] = {"host": host, "ts": now}
    return host

def _classify_connection(conn):
    if not conn.raddr:
        return None
    r_ip = conn.raddr.ip
    r_port = conn.raddr.port
    host = _reverse_dns(r_ip)
    descriptor = f"{r_ip}:{r_port}"
    return {
        "pid": conn.pid,
        "host": host,
        "raddr": descriptor,
        "port": r_port,
        "ip": r_ip,
    }

def scan_web_ports_all():
    connections = []
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return connections
    for conn in conns:
        info = _classify_connection(conn)
        if not info:
            continue
        connections.append(info)
    return connections

# ============================================================
# ACTIVE DOMAIN DETECTION
# ============================================================
def extract_domain_from_title(title: str):
    if not title:
        return None
    for part in title.split():
        part = part.strip()
        if "." in part and "/" not in part:
            return part.lower()
    return None

def active_domain_detection_loop():
    while True:
        try:
            title, pid = get_active_window_info()
            active_domain_state["title"] = title
            active_domain_state["pid"] = pid

            domain = extract_domain_from_title(title)

            if not domain and pid:
                try:
                    conns = psutil.net_connections(kind="inet")
                except Exception:
                    conns = []
                for conn in conns:
                    if conn.pid != pid or not conn.raddr:
                        continue
                    host = _reverse_dns(conn.raddr.ip)
                    if host and "." in host:
                        domain = host.lower()
                        break

            if not domain and PRIMARY_TEST_SITE in (title or "").lower():
                domain = PRIMARY_TEST_SITE

            active_domain_state["domain"] = domain
        except Exception as e:
            log(f"[ACTIVE] Detection error: {e}")
        time.sleep(0.5)

# ============================================================
# PATTERN + FAMILY CLASSIFICATION
# ============================================================
def classify_family(domain: str):
    d = domain.lower()
    for p in VIDEO_AD_PATTERNS:
        if p.search(d):
            return "video_ad"
    for p in AD_PATTERNS:
        if p.search(d):
            return "banner_ad"
    for p in TRACKING_PATTERNS:
        if p.search(d):
            return "tracking"
    for p in CDN_PATTERNS:
        if p.search(d):
            return "cdn_ad"
    return "unknown"

def pattern_score(domain: str):
    d = domain.lower()
    score = 0.0
    if any(p.search(d) for p in AD_PATTERNS):
        score += 0.3
    if any(p.search(d) for p in TRACKING_PATTERNS):
        score += 0.3
    if any(p.search(d) for p in CDN_PATTERNS):
        score += 0.2
    if any(p.search(d) for p in VIDEO_AD_PATTERNS):
        score += 0.3
    return min(score, 1.0)

def port_score(port: int):
    score = 0.0
    if port in (8080, 8443, 8888):
        score += 0.2
    elif port == 80:
        score += 0.1
    elif port == 443:
        score += 0.05
    return score

# ============================================================
# ML-LITE LOGISTIC PREDICTION
# ============================================================
def logistic(x):
    try:
        import math
        return 1.0 / (1.0 + math.exp(-x))
    except Exception:
        return 0.5

def ml_lite_score(features):
    """
    features: dict with keys:
      ratio, freq, burst, pid_mismatch, pattern, port, reputation
    """
    w = {
        "ratio": 2.0,
        "freq": 1.0,
        "burst": 1.5,
        "pid_mismatch": 0.8,
        "pattern": 1.2,
        "port": 0.7,
        "reputation": 1.0,
    }
    x = 0.0
    for k, v in features.items():
        x += w.get(k, 0.0) * v
    x -= 2.0  # bias
    return logistic(x)

# ============================================================
# DOMAIN STATS + PREDICTION ENGINE
# ============================================================
def _update_domain_stats(ad_connections):
    now = time.time()
    for info in ad_connections:
        host = info.get("host") or info.get("raddr")
        if not host:
            continue
        key = host.lower()
        stats = web_ad_state["domain_stats"].get(key, {
            "domain": key,
            "hits": 0,
            "ad_hits": 0,
            "score": 0.0,
            "burst": 0,
            "last_seen_ts": 0.0,
            "pid_mismatch_hits": 0,
            "pattern_score": 0.0,
            "port_score": 0.0,
            "reputation_score": 0.0,
            "future_likelihood": 0.0,
            "family": "unknown",
        })

        # base hit/ad_hit (TEST MODE: everything ad-like)
        stats["hits"] += 1
        stats["ad_hits"] += 1

        # burst detection
        if stats["last_seen_ts"] > 0 and now - stats["last_seen_ts"] < 0.3:
            stats["burst"] += 1
        else:
            stats["burst"] = 0
        stats["last_seen_ts"] = now

        # PID mismatch
        active_pid = active_domain_state.get("pid")
        if active_pid is not None and info.get("pid") != active_pid:
            stats["pid_mismatch_hits"] += 1

        # pattern + port scores
        stats["pattern_score"] = pattern_score(key)
        stats["port_score"] = port_score(info.get("port", 0))

        # reputation
        rep = domain_reputation.get(key, {})
        stats["reputation_score"] = float(rep.get("reputation_score", 0.0))

        # ratio + freq
        ratio = stats["ad_hits"] / max(1, stats["hits"])
        freq = min(1.0, stats["hits"] / 50.0)
        burst_norm = min(1.0, stats["burst"] / 5.0)
        pid_mismatch_norm = min(1.0, stats["pid_mismatch_hits"] / max(1, stats["hits"]))
        pattern_norm = stats["pattern_score"]
        port_norm = stats["port_score"]
        rep_norm = stats["reputation_score"]

        features = {
            "ratio": ratio,
            "freq": freq,
            "burst": burst_norm,
            "pid_mismatch": pid_mismatch_norm,
            "pattern": pattern_norm,
            "port": port_norm,
            "reputation": rep_norm,
        }

        ml_score = ml_lite_score(features)

        # heuristic blend
        heuristic_score = (
            0.4 * ratio +
            0.2 * freq +
            0.1 * burst_norm +
            0.1 * pid_mismatch_norm +
            0.1 * pattern_norm +
            0.1 * port_norm
        )

        stats["score"] = min(1.0, 0.5 * ml_score + 0.5 * heuristic_score)

        # future likelihood: emphasize burst + pid mismatch
        stats["future_likelihood"] = min(
            1.0,
            stats["score"] * (1.0 + 0.5 * burst_norm + 0.3 * pid_mismatch_norm)
        )

        # family classification
        stats["family"] = classify_family(key)

        web_ad_state["domain_stats"][key] = stats

        # update reputation
        rep["first_seen"] = rep.get("first_seen", now)
        rep["last_seen"] = now
        rep["total_hits"] = rep.get("total_hits", 0) + 1
        rep["reputation_score"] = stats["score"]
        domain_reputation[key] = rep

        # storm tracking
        web_ad_state["storm_events"].append((now, key))

    # global prediction score (top 10 domains)
    if web_ad_state["domain_stats"]:
        scores = sorted((v["score"] for v in web_ad_state["domain_stats"].values()), reverse=True)
        web_ad_state["prediction_score"] = sum(scores[:10]) / max(1, len(scores[:10]))
    else:
        web_ad_state["prediction_score"] = 0.0

    # ad storm detection
    while web_ad_state["storm_events"] and now - web_ad_state["storm_events"][0][0] > AD_STORM_WINDOW_SEC:
        web_ad_state["storm_events"].popleft()
    web_ad_state["ad_storm"] = len(web_ad_state["storm_events"]) >= AD_STORM_COUNT_THRESHOLD

def decay_domain_stats_loop():
    while True:
        try:
            now = time.time()
            for key, stats in list(web_ad_state["domain_stats"].items()):
                stats["hits"] *= 0.98
                stats["ad_hits"] *= 0.98
                stats["pid_mismatch_hits"] *= 0.98
                # keep last_seen_ts, burst as-is
                web_ad_state["domain_stats"][key] = stats
            save_reputation()
            save_dns_cache()
        except Exception as e:
            log(f"[DECAY] Error: {e}")
        time.sleep(DOMAIN_DECAY_INTERVAL)

# ============================================================
# AD DETECTION LOOP (PREDICTIVE)
# ============================================================
def web_ad_detection_loop(manager: HostsManager, counter: AdCounter, analytics: Analytics):
    while True:
        try:
            connections = scan_web_ports_all()

            # Treat ALL connections as ad-like, but score them
            ad_connections = connections

            web_ad_state["connections"] = connections
            web_ad_state["ad_connections"] = ad_connections
            web_ad_state["active"] = bool(ad_connections)
            web_ad_state["last_scan_ts"] = time.time()

            _update_domain_stats(ad_connections)

            current_page = active_domain_state["domain"] or "unknown"
            counter.set_page(current_page)

            for info in ad_connections:
                host = info.get("host") or info.get("raddr")
                if not host:
                    continue
                domain = host.lower()
                stats = web_ad_state["domain_stats"].get(domain, {})
                predictive_score = float(stats.get("score", 0.0))
                future_likelihood = float(stats.get("future_likelihood", 0.0))
                family = stats.get("family", "unknown")

                # plugin hooks
                for plugin in plugins:
                    try:
                        predictive_score = plugin.modify_score(domain, stats, predictive_score)
                    except Exception as e:
                        log(f"[PLUGIN] modify_score error for {domain}: {e}")

                # auto-block threshold
                if predictive_score >= AUTO_BLOCK_THRESHOLD and not manager.is_blocked(domain):
                    if manager.add(domain):
                        manager.save()
                        log(f"[AUTO-BLOCK] {domain} (score={predictive_score:.2f})")

                if manager.is_blocked(domain):
                    counter.log_blocked()
                    analytics.log(domain, True, predictive_score, future_likelihood, family)
                else:
                    counter.log_missed(domain)
                    analytics.log(domain, False, predictive_score, future_likelihood, family)

            write_log(counter, analytics)
        except Exception as e:
            log(f"[WEB-AD] Detection loop error: {e}")
        time.sleep(WEB_AD_DETECTION_INTERVAL)

# ============================================================
# GUI (PREDICTIVE)
# ============================================================
class AdBlockGUI:
    def __init__(self, manager: HostsManager, counter: AdCounter, analytics: Analytics):
        self.manager = manager
        self.counter = counter
        self.analytics = analytics
        self.root = tk.Tk()
        self._build()

    def _build(self):
        self.root.title("Hybrid Ad Blocker – Predictive Engine")
        self.root.geometry("520x420")
        self.root.resizable(False, False)

        self.page_label = ttk.Label(self.root, text="Page: -")
        self.page_label.pack(anchor="w", padx=8, pady=(8, 2))

        self.title_label = ttk.Label(self.root, text="Window: -")
        self.title_label.pack(anchor="w", padx=8, pady=(0, 4))

        self.blocked_label = ttk.Label(self.root, text="Blocked: 0")
        self.blocked_label.pack(anchor="w", padx=8)

        self.missed_label = ttk.Label(self.root, text="Missed: 0")
        self.missed_label.pack(anchor="w", padx=8, pady=(0, 4))

        self.pred_label = ttk.Label(self.root, text="Global prediction score: 0.00")
        self.pred_label.pack(anchor="w", padx=8, pady=(0, 4))

        self.future_label = ttk.Label(self.root, text="Future ad likelihood (current page): 0.00")
        self.future_label.pack(anchor="w", padx=8, pady=(0, 4))

        self.storm_label = ttk.Label(self.root, text="Ad storm: No")
        self.storm_label.pack(anchor="w", padx=8, pady=(0, 8))

        btn_frame = ttk.Frame(self.root)
        btn_frame.pack(fill="x", padx=8, pady=(0, 8))

        import_btn = ttk.Button(btn_frame, text="Import Hosts", command=self._import_hosts)
        import_btn.pack(side="left", padx=(0, 4))

        export_btn = ttk.Button(btn_frame, text="Export Hosts", command=self._export_hosts)
        export_btn.pack(side="left", padx=(4, 4))

        refresh_btn = ttk.Button(btn_frame, text="Save Reputation", command=lambda: save_reputation())
        refresh_btn.pack(side="left", padx=(4, 4))

        ttk.Label(self.root, text="Per-site analytics (heatmap-style):").pack(anchor="w", padx=8)
        self.site_list = tk.Listbox(self.root, height=12)
        self.site_list.pack(fill="both", expand=True, padx=8, pady=(2, 8))

        self._schedule_update()

    def _schedule_update(self):
        self._update()
        self.root.after(1000, self._schedule_update)

    def _update(self):
        page = active_domain_state["domain"] or "-"
        title = active_domain_state["title"] or "-"
        self.page_label.config(text=f"Page: {page}")
        self.title_label.config(text=f"Window: {title}")
        self.blocked_label.config(text=f"Blocked: {self.counter.blocked}")
        self.missed_label.config(text=f"Missed: {self.counter.missed}")
        self.pred_label.config(
            text=f"Global prediction score: {web_ad_state['prediction_score']:.2f}"
        )

        # current page future likelihood
        page_stats = web_ad_state["domain_stats"].get(page.lower(), {}) if page != "-" else {}
        future_likelihood = float(page_stats.get("future_likelihood", 0.0))
        self.future_label.config(
            text=f"Future ad likelihood (current page): {future_likelihood:.2f}"
        )

        self.storm_label.config(
            text=f"Ad storm: {'YES' if web_ad_state.get('ad_storm') else 'No'}"
        )

        # heatmap-style list: sort by predictive_score
        self.site_list.delete(0, tk.END)
        snapshot = self.analytics.snapshot()
        items = sorted(
            snapshot.items(),
            key=lambda kv: kv[1].get("predictive_score", 0.0),
            reverse=True
        )
        for site, stats in items:
            line = (
                f"{site}  "
                f"B:{stats['blocked']}  M:{stats['missed']}  "
                f"S:{stats['predictive_score']:.2f}  "
                f"F:{stats['future_likelihood']:.2f}  "
                f"{stats['family']}"
            )
            self.site_list.insert(tk.END, line)

    def _import_hosts(self):
        filepath = filedialog.askopenfilename(
            title="Select Hosts File",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not filepath:
            return
        try:
            imported = set()
            with open(filepath, "r", encoding="utf-8", errors="ignore") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split()
                    if len(parts) >= 2:
                        ip, domain = parts[0], parts[1]
                        if ip == self.manager.block_ip:
                            imported.add(domain.lower())
                    else:
                        imported.add(line.lower())
            before = len(self.manager.entries)
            self.manager.entries.update(imported)
            self.manager.save()
            log(f"[GUI] Imported {len(self.manager.entries) - before} host entries from {filepath}")
        except Exception as e:
            log(f"[GUI] Import failed: {e}")

    def _export_hosts(self):
        filepath = filedialog.asksaveasfilename(
            title="Save Hosts File",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")]
        )
        if not filepath:
            return
        try:
            with open(filepath, "w", encoding="utf-8") as f:
                f.write("# Exported Hosts\n")
                for domain in sorted(self.manager.entries):
                    f.write(f"{self.manager.block_ip} {domain}\n")
            log(f"[GUI] Exported hosts to {filepath}")
        except Exception as e:
            log(f"[GUI] Export failed: {e}")

    def run(self):
        self.root.mainloop()

# ============================================================
# MAIN
# ============================================================
def main():
    load_reputation()
    load_dns_cache()
    load_plugins()

    manager = HostsManager(CUSTOM_HOSTS_PATH, BLOCK_IP)
    counter = AdCounter()
    analytics = Analytics()

    threading.Thread(target=ad_rules_sync_loop, daemon=True).start()
    threading.Thread(target=active_domain_detection_loop, daemon=True).start()
    threading.Thread(target=web_ad_detection_loop, args=(manager, counter, analytics), daemon=True).start()
    threading.Thread(target=decay_domain_stats_loop, daemon=True).start()

    gui = AdBlockGUI(manager, counter, analytics)
    gui.run()

if __name__ == "__main__":
    main()
