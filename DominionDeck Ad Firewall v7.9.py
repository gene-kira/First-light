#!/usr/bin/env python3
"""
DominionDeck v10.8 – System-Wide Predictive Ad Firewall (Borg + Malvertising Shield, Stable Startup)
Hosts-Based • Auto-Elevation • Redirect/Dummy Load • Ad Disassembly Lab • Auto-Lab API
Borg Collective Sync • Malvertising Behavior Heuristics (Script/WASM/Fingerprint)

- Auto-elevates to Administrator on Windows.
- System-wide ad blocking via hosts file.
- Predictive domain scoring (learns suspicious hosts).
- Profiles: STRICT / BALANCED / RELAXED.
- Manual add/remove domains.
- Import/export dynamic blocklist.
- Periodic auto-apply to hosts file.
- Redirect mode: 0.0.0.0 (block) or 127.0.0.1/custom (dummy load).

- Ad Disassembly Lab:
    • GUI: paste ad URLs / snippets / HTML, extract host-like tokens, learn them.
    • Auto-Lab API: external modules can feed captured text on-the-fly.

- Borg Collective Sync:
    • Each machine can share its dynamic ad domains to a shared “collective” file.
    • All nodes periodically pull from that shared file and merge into their firewall.
    • Simple file-based sync: point all machines at the same network path.

- Malvertising Shield (behavioral heuristics):
    • External modules can feed script/WASM/fingerprint metadata.
    • Heuristic scoring for exploit-like behavior (entropy, WASM, fingerprinting, network fan-out).
    • High-risk signals auto-promote domains into dynamic blocklist.
"""

from __future__ import annotations

# === AUTO-ELEVATION CHECK (same pattern as earlier working builds) ===
import ctypes
import os
import sys

def ensure_admin():
    try:
        if not ctypes.windll.shell32.IsUserAnAdmin():
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{script}" {params}',
                None,
                1
            )
            sys.exit()
    except Exception as e:
        print(f"[DominionDeck] Elevation failed: {e}")
        sys.exit()

ensure_admin()

import logging
import time
import threading
import json
import socket
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Set, Dict, List

APP_NAME = "DominionDeck System-Wide Predictive Ad Firewall"
APP_VERSION = "10.9"
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "dominiondeck_v10_8.log"

HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")

DEFAULT_SINKHOLE_IP = "0.0.0.0"
BLOCKLIST_EXPORT = BASE_DIR / "dominiondeck_dynamic_blocklist.txt"

# Borg Collective config – edit these to match your environment
BORG_ENABLED = True
BORG_SHARE_PATH = Path(os.environ.get("DOMINIONDECK_BORG_SHARE", r"\\MOTHERBOARD\DominionDeck\borg_collective_blocklist.txt"))
BORG_SYNC_INTERVAL_SECONDS = 120

# Local API: port 0 asks the operating system to assign an available TCP port.
# Bound to loopback by default so it is not exposed to other computers.
API_ENABLED = True
API_HOST = os.environ.get("DOMINIONDECK_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("DOMINIONDECK_API_PORT", "0"))
API_MAX_BODY_BYTES = 1_000_000


# ============================================================
# Firewall Config + Predictive Engine
# ============================================================

@dataclass
class FirewallConfig:
    static_block: Set[str] = field(default_factory=lambda: {
        "pagead2.googlesyndication.com",
        "googleads.g.doubleclick.net",
        "doubleclick.net",
        "googletagmanager.com",
        "googletagservices.com",
        "google-analytics.com",
        "gstaticadssl.com",
        "ads.tiktok.com",
        "analytics.tiktok.com",
        "businessapi.tiktok.com",
        "logbyteoverseas.com",
        "connect.facebook.net",
        "static.xx.fbcdn.net",
        "ads-api.twitter.com",
        "ads.pinterest.com",
        "ads.linkedin.com",
        "adservice.google.com",
        "adroll.com",
        "criteo.com",
        "taboola.com",
        "outbrain.com",
        "pubmatic.com",
        "openx.net",
        "rubiconproject.com",
        "magnite.com",
        "indexexchange.com",
        "unityads.unity3d.com",
        "ironSource.com",
        "freshmarketer.com",
        "claritybt.freshmarketer.com",
        "fttracks.freshmarketer.com",
        "sentry-cdn.com",
        "app.getsentry.com",
        "getsentry.com",
        "datamissindiaexami.com",
        "datamissrussiaexami.com",
        "exami.com",
        "huawei.com",
        "ads.huawei.com",
        "analytics.huawei.com",
        "books.analytics.events.apple.com",
        "analytics.apple.com",
        "metrics.apple.com",
        "samsung.com",
        "analytics.api.samsung.com",
        "thcn.com",
        "securepubads.g.doubleclick.net",
        "s.youtube.com",
        "pagead.google.com",
        "ads.youtube.com",
    })
    wildcards: Set[str] = field(default_factory=lambda: {
        ".doubleclick.net",
        ".googlesyndication.com",
        ".google-analytics.com",
        ".googletagmanager.com",
        ".freshmarketer.com",
        ".sentry-cdn.com",
        ".getsentry.com",
        ".tiktok.com",
        ".facebook.com",
        ".fbcdn.net",
        ".twitter.com",
        ".pinterest.com",
        ".linkedin.com",
        ".adroll.com",
        ".criteo.com",
        ".taboola.com",
        ".outbrain.com",
        ".pubmatic.com",
        ".openx.net",
        ".rubiconproject.com",
        ".magnite.com",
        ".indexexchange.com",
        ".unity3d.com",
        ".ironsource.com",
        ".huawei.com",
        ".apple.com",
        ".samsung.com",
        ".exami.com",
    })
    heuristic_keywords: Set[str] = field(default_factory=lambda: {
        "ads", "adserver", "adservice", "adclick",
        "impression", "tracking", "telemetry", "pixel",
        "retargeting", "remarketing", "sponsor",
        "buy now", "limited offer", "sale", "promo",
        "discount", "affiliate",
    })
    heuristic_threshold_strict: int = 3
    heuristic_threshold_balanced: int = 4
    heuristic_threshold_relaxed: int = 5
    profile: str = "STRICT"  # STRICT / BALANCED / RELAXED


class DomainFirewall:
    def __init__(self, cfg: FirewallConfig):
        self.cfg = cfg
        self.dynamic_block: Set[str] = set()
        self.domain_scores: Dict[str, int] = {}
        self.lock = threading.Lock()

    def _current_threshold(self) -> int:
        if self.cfg.profile == "STRICT":
            return self.cfg.heuristic_threshold_strict
        if self.cfg.profile == "BALANCED":
            return self.cfg.heuristic_threshold_balanced
        return self.cfg.heuristic_threshold_relaxed

    def _score_domain(self, host: str, context: str = "") -> int:
        host = (host or "").lower().strip()
        text = f"{host} {context}".lower()
        score = 0

        if any(k in host for k in ["ad", "ads", "track", "analytics", "telemetry"]):
            score += 2

        for kw in self.cfg.heuristic_keywords:
            if kw in text:
                score += 1

        existing = self.domain_scores.get(host, 0)
        score += existing

        return min(score, 20)

    def learn_domain(self, host: str, context: str = "", manual: bool = False):
        host = (host or "").lower().strip()
        if not host:
            return

        with self.lock:
            base_score = self._score_domain(host, context)
            if manual:
                base_score += 3

            self.domain_scores[host] = base_score

            threshold = self._current_threshold()
            if base_score >= threshold:
                if host not in self.dynamic_block and host not in self.cfg.static_block:
                    self.dynamic_block.add(host)

    def remove_domain(self, host: str):
        host = (host or "").lower().strip()
        with self.lock:
            self.dynamic_block.discard(host)

    def all_blocked_domains(self) -> List[str]:
        with self.lock:
            domains = set(self.cfg.static_block)
            domains.update(self.dynamic_block)
            for suffix in self.cfg.wildcards:
                base = suffix.lstrip(".")
                domains.add(base)
            return sorted(domains)

    def snapshot(self) -> Dict[str, Set[str]]:
        with self.lock:
            return {
                "static": set(self.cfg.static_block),
                "dynamic": set(self.dynamic_block),
            }

    def top_suspicious(self, limit: int = 20) -> List[str]:
        with self.lock:
            items = sorted(self.domain_scores.items(), key=lambda kv: kv[1], reverse=True)
            return [f"{host} (score={score})" for host, score in items[:limit]]

    def export_dynamic(self, path: Path):
        with self.lock:
            lines = sorted(self.dynamic_block)
        try:
            path.write_text("\n".join(lines), encoding="utf-8")
        except Exception:
            pass

    def import_dynamic(self, path: Path):
        if not path.exists():
            return
        try:
            content = path.read_text(encoding="utf-8").splitlines()
        except Exception:
            return
        with self.lock:
            for line in content:
                host = line.strip().lower()
                if host:
                    self.dynamic_block.add(host)
                    self.domain_scores[host] = max(
                        self.domain_scores.get(host, 0),
                        self._current_threshold() + 1,
                    )


# ============================================================
# Hosts File Manager (with redirect/dummy mode)
# ============================================================

class HostsManager:
    def __init__(self, firewall: DomainFirewall, log_callback, sinkhole_ip_getter):
        self.firewall = firewall
        self.log_callback = log_callback
        self.sinkhole_ip_getter = sinkhole_ip_getter
        self.lock = threading.Lock()

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}"
        logging.info(msg)
        self.log_callback(line)

    def apply_blocklist(self):
        with self.lock:
            domains = self.firewall.all_blocked_domains()
            if not domains:
                self.log("No domains to block yet.")
                return

            sink_ip = self.sinkhole_ip_getter().strip() or DEFAULT_SINKHOLE_IP

            try:
                if not HOSTS_PATH.exists():
                    self.log(f"Hosts file not found at {HOSTS_PATH}.")
                    return

                original = HOSTS_PATH.read_text(encoding="utf-8", errors="ignore").splitlines()

                filtered = []
                in_section = False
                for line in original:
                    if line.strip().startswith("# DominionDeck BEGIN"):
                        in_section = True
                        continue
                    if line.strip().startswith("# DominionDeck END"):
                        in_section = False
                        continue
                    if not in_section:
                        filtered.append(line)

                section = ["", "# DominionDeck BEGIN – System-Wide Predictive Ad Firewall"]
                section.append(f"# Mode: sinkhole/redirect IP = {sink_ip}")
                for d in domains:
                    section.append(f"{sink_ip} {d}")
                section.append("# DominionDeck END – System-Wide Predictive Ad Firewall")
                section.append("")

                new_content = "\n".join(filtered + section)
                HOSTS_PATH.write_text(new_content, encoding="utf-8")
                self.log(f"Applied blocklist to hosts file with {len(domains)} domains (IP={sink_ip}).")
            except PermissionError:
                self.log("PermissionError: hosts file write failed even after elevation.")
            except Exception as exc:
                self.log(f"Error updating hosts file: {exc}")


# ============================================================
# Ad Disassembly Lab helpers (GUI + Auto-Lab API)
# ============================================================

def extract_host_candidates(text: str) -> List[str]:
    """
    Very simple host-like token extractor:
    - Splits on whitespace and punctuation.
    - Keeps tokens that look like domains (contain a dot, no spaces).
    """
    import re
    tokens = re.split(r"[\s\"'<>()=;:,]+", text)
    hosts = []
    for t in tokens:
        t = t.strip()
        if "." in t and " " not in t and len(t) > 3:
            t = t.replace("https://", "").replace("http://", "").replace("www.", "")
            t = t.split("/")[0].split("?")[0]
            if t and "." in t:
                hosts.append(t.lower())
    return sorted(set(hosts))


# ============================================================
# Malvertising Shield – behavioral heuristics
# ============================================================

@dataclass
class ScriptBehavior:
    domain: str
    has_wasm: bool = False
    high_entropy: bool = False
    uses_fingerprint_apis: bool = False
    network_fan_out: int = 0
    suspicious_eval: bool = False
    suspicious_obfuscation: bool = False
    gpu_accel_usage: bool = False


class MalvertisingShield:
    """
    Lightweight heuristic engine:
    External modules can feed ScriptBehavior objects.
    High-risk scores promote domains into dynamic blocklist.
    """

    def __init__(self, firewall: DomainFirewall, log_callback):
        self.firewall = firewall
        self.log_callback = log_callback

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [SHIELD] {msg}"
        logging.info(line)
        self.log_callback(line)

    def score_behavior(self, b: ScriptBehavior) -> int:
        score = 0
        if b.has_wasm:
            score += 3
        if b.high_entropy:
            score += 2
        if b.uses_fingerprint_apis:
            score += 2
        if b.network_fan_out >= 10:
            score += 2
        elif b.network_fan_out >= 5:
            score += 1
        if b.suspicious_eval:
            score += 2
        if b.suspicious_obfuscation:
            score += 2
        if b.gpu_accel_usage:
            score += 1
        return score

    def feed_behavior(self, b: ScriptBehavior):
        """
        External modules call this when they observe ad script behavior.
        If score is high, we treat the domain as malvertising and learn it.
        """
        domain = (b.domain or "").strip().lower()
        if not domain:
            return
        score = self.score_behavior(b)
        if score >= 4:
            self.log(f"High-risk malvertising behavior detected for {domain} (score={score}). Promoting to firewall.")
            self.firewall.learn_domain(domain, context="malvertising_shield", manual=True)
        else:
            self.log(f"Observed behavior for {domain} (score={score}) – below promotion threshold.")


# ============================================================
# Borg Collective Sync Engine
# ============================================================

class BorgSync:
    """
    Simple file-based Borg collective:
    - Each node writes its dynamic domains to a shared file.
    - Each node reads from that shared file and merges into its firewall.
    """

    def __init__(self, firewall: DomainFirewall, log_callback):
        self.firewall = firewall
        self.log_callback = log_callback
        self.lock = threading.Lock()

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [BORG] {msg}"
        logging.info(line)
        self.log_callback(line)

    def push_to_collective(self):
        if not BORG_ENABLED:
            return
        try:
            with self.firewall.lock:
                local_domains = sorted(self.firewall.dynamic_block)
            if not local_domains:
                return

            existing: Set[str] = set()
            try:
                if BORG_SHARE_PATH.exists():
                    content = BORG_SHARE_PATH.read_text(encoding="utf-8").splitlines()
                    existing = {line.strip().lower() for line in content if line.strip()}
            except OSError as exc:
                self.log(f"Network share unavailable ({BORG_SHARE_PATH}): {exc}. Check computer name, share name, permissions, and network connectivity.")
                return
            except Exception as exc:
                self.log(f"Could not read collective file: {exc}")
                return

            merged = sorted(existing.union(local_domains))
            BORG_SHARE_PATH.parent.mkdir(parents=True, exist_ok=True)
            BORG_SHARE_PATH.write_text("\n".join(merged), encoding="utf-8")
            self.log(f"Pushed {len(local_domains)} local dynamic domains to collective (merged={len(merged)}).")
        except Exception as exc:
            self.log(f"Push error: {exc}")

    def pull_from_collective(self):
        if not BORG_ENABLED:
            return
        try:
            if not BORG_SHARE_PATH.exists():
                self.log(f"Collective share not found or unavailable: {BORG_SHARE_PATH} (Windows error 53 commonly means the network path was not found).")
                return
            content = BORG_SHARE_PATH.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            self.log(f"Pull failed for collective path {BORG_SHARE_PATH}: {exc}. Check that the host/share exists and is reachable.")
            return
        except Exception as exc:
            self.log(f"Pull read error: {exc}")
            return

        new_hosts = 0
        for line in content:
            host = line.strip().lower()
            if not host:
                continue
            with self.firewall.lock:
                if host not in self.firewall.dynamic_block and host not in self.firewall.cfg.static_block:
                    self.firewall.dynamic_block.add(host)
                    self.firewall.domain_scores[host] = max(
                        self.firewall.domain_scores.get(host, 0),
                        self.firewall._current_threshold() + 1,
                    )
                    new_hosts += 1
        if new_hosts:
            self.log(f"Pulled {new_hosts} new domains from collective into local firewall.")



# ============================================================
# Local Auto-Lab HTTP API
# ============================================================

class LocalLabAPI:
    """Small localhost-only API. The server binds port 0 when auto-selecting,
    so the OS chooses a port that is available at bind time."""

    def __init__(self, firewall: DomainFirewall, log_callback, host=API_HOST, port=API_PORT):
        self.firewall = firewall
        self.log_callback = log_callback
        self.host = host
        self.requested_port = port
        self.server = None
        self.thread = None
        self.port = None

    def start(self):
        firewall = self.firewall
        log_callback = self.log_callback

        class Handler(BaseHTTPRequestHandler):
            def _reply(self, status, payload):
                data = json.dumps(payload).encode("utf-8")
                self.send_response(status)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(data)))
                self.send_header("Cache-Control", "no-store")
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path.rstrip("/") == "/health":
                    self._reply(200, {"status": "ok", "service": "DominionDeck Auto-Lab API"})
                else:
                    self._reply(404, {"error": "Not found", "endpoints": ["GET /health", "POST /domains"]})

            def do_POST(self):
                if self.path.rstrip("/") != "/domains":
                    self._reply(404, {"error": "Use POST /domains"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 1 or length > API_MAX_BODY_BYTES:
                        self._reply(413, {"error": f"Body must be between 1 and {API_MAX_BODY_BYTES} bytes"})
                        return
                    payload = json.loads(self.rfile.read(length).decode("utf-8"))
                    if not isinstance(payload, dict):
                        self._reply(400, {"error": "Expected a JSON object"})
                        return
                    supplied = payload.get("domain", "")
                    text = payload.get("text", "")
                    hosts = set()
                    if isinstance(supplied, str) and supplied.strip():
                        hosts.add(supplied.strip().lower())
                    if isinstance(text, str) and text.strip():
                        hosts.update(extract_host_candidates(text))
                    valid_hosts = sorted(h for h in hosts if h and len(h) <= 253 and " " not in h and "." in h)
                    if not valid_hosts:
                        self._reply(400, {"error": "Provide a domain or text containing domain-like hosts"})
                        return
                    learned = []
                    for host in valid_hosts:
                        firewall.learn_domain(host, context="local_api", manual=True)
                        learned.append(host)
                    log_callback(f"[API] Learned {len(learned)} host candidate(s) from localhost client.")
                    self._reply(200, {"accepted": len(learned), "domains": learned})
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    self._reply(400, {"error": f"Invalid request: {exc}"})
                except Exception as exc:
                    log_callback(f"[API] Request error: {exc}")
                    self._reply(500, {"error": "Internal server error"})

            def log_message(self, fmt, *args):
                logging.info("[API] " + fmt, *args)

        try:
            # Binding port 0 and keeping the socket open avoids the usual
            # find-a-port-then-bind race condition.
            self.server = ThreadingHTTPServer((self.host, self.requested_port), Handler)
            self.server.daemon_threads = True
            self.port = self.server.server_address[1]
            self.thread = threading.Thread(target=self.server.serve_forever, name="DominionDeck-API", daemon=True)
            self.thread.start()
            self.log_callback(f"[API] Listening on http://{self.host}:{self.port} (GET /health, POST /domains).")
            return self.port
        except OSError as exc:
            self.log_callback(f"[API] Could not start on {self.host}:{self.requested_port}: {exc}")
            self.server = None
            return None

    def stop(self):
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
            self.server = None


# ============================================================
# GUI + Controller
# ============================================================

class DominionDeckGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("980x780")
        self.root.minsize(820, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.status_var = tk.StringVar(value="Initializing…")
        self.profile_var = tk.StringVar(value="STRICT")
        self.sinkhole_ip_var = tk.StringVar(value=DEFAULT_SINKHOLE_IP)

        self._build_ui()

        cfg = FirewallConfig()
        self.firewall = DomainFirewall(cfg)
        self.hosts_manager = HostsManager(
            self.firewall,
            self._append_log,
            sinkhole_ip_getter=lambda: self.sinkhole_ip_var.get(),
        )

        self.borg_sync = BorgSync(self.firewall, self._append_log)
        self.shield = MalvertisingShield(self.firewall, self._append_log)

        self._seed_learning()
        self.firewall.import_dynamic(BLOCKLIST_EXPORT)

        self._append_log("DominionDeck v10.9 initialized.")
        self._append_log("System-wide predictive ad firewall using hosts file.")
        self._append_log("No browser is opened; protection applies to all browsers.")
        self._append_log("Auto-elevation attempted at startup.")
        self._append_log(f"Profile: {self.firewall.cfg.profile}")
        self._append_log(f"Sinkhole/redirect IP: {self.sinkhole_ip_var.get()}")
        self._append_log(f"Borg share path: {BORG_SHARE_PATH}")
        self._append_log("Local API uses an OS-assigned free port by default (API_PORT=0).")
        if BORG_ENABLED:
            self._append_log(f"[BORG] Collective sync enabled at: {BORG_SHARE_PATH}")
        else:
            self._append_log("[BORG] Collective sync disabled.")
        self._append_log("[SHIELD] Malvertising behavior heuristics active (script/WASM/fingerprint/network).")

        self.root.after(800, self._auto_apply)
        self._schedule_periodic_apply()
        self._schedule_suspicious_refresh()
        self._schedule_borg_sync()

        self.auto_lab_buffer: List[str] = []
        self.api = None
        if API_ENABLED:
            self.api = LocalLabAPI(self.firewall, self._append_log)
            self.api.start()
        self._schedule_auto_lab()

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=14)
        outer.pack(fill="both", expand=True)

        ttk.Label(outer, text=APP_NAME, font=("Segoe UI", 18, "bold")).pack(anchor="w")
        ttk.Label(
            outer,
            text="System-wide predictive ad firewall using hosts file. Local Auto-Lab API auto-selects an available TCP port; Borg sync reports unreachable network shares.",
            wraplength=940,
        ).pack(anchor="w", pady=(3, 10))

        status_frame = ttk.LabelFrame(outer, text="Status", padding=10)
        status_frame.pack(fill="x", pady=(0, 10))
        ttk.Label(status_frame, text="Firewall:").grid(row=0, column=0, sticky="w")
        ttk.Label(status_frame, textvariable=self.status_var, font=("Segoe UI", 10, "bold")).grid(row=0, column=1, sticky="w", padx=8)

        options_frame = ttk.LabelFrame(outer, text="Options & Controls", padding=10)
        options_frame.pack(fill="x", pady=(0, 10))

        ttk.Label(options_frame, text="Profile:").grid(row=0, column=0, sticky="w")
        profile_combo = ttk.Combobox(
            options_frame,
            textvariable=self.profile_var,
            values=["STRICT", "BALANCED", "RELAXED"],
            state="readonly",
            width=10,
        )
        profile_combo.grid(row=0, column=1, sticky="w", padx=6)
        profile_combo.bind("<<ComboboxSelected>>", self._on_profile_change)

        ttk.Label(options_frame, text="Sinkhole / Redirect IP:").grid(row=0, column=2, sticky="w")
        ttk.Entry(options_frame, textvariable=self.sinkhole_ip_var, width=14).grid(row=0, column=3, sticky="w", padx=6)
        ttk.Label(
            options_frame,
            text="(0.0.0.0 = block, 127.0.0.1/custom = dummy load)",
        ).grid(row=1, column=2, columnspan=2, sticky="w", pady=(2, 0))

        ttk.Label(options_frame, text="Manual domain:").grid(row=2, column=0, sticky="w", pady=(6, 0))
        self.manual_domain_var = tk.StringVar()
        ttk.Entry(options_frame, textvariable=self.manual_domain_var, width=32).grid(row=2, column=1, sticky="w", padx=6, pady=(6, 0))

        ttk.Button(options_frame, text="Add & Learn", command=self._manual_add).grid(row=2, column=2, sticky="w", padx=6, pady=(6, 0))
        ttk.Button(options_frame, text="Remove from Dynamic", command=self._manual_remove).grid(row=2, column=3, sticky="w", padx=6, pady=(6, 0))

        ttk.Button(options_frame, text="Export Dynamic Blocklist", command=self._export_blocklist).grid(row=3, column=0, sticky="w", pady=(8, 0))
        # FIXED: use the correct method name (_import_blocklist) so GUI startup doesn’t crash
        ttk.Button(options_frame, text="Import Dynamic Blocklist", command=self._import_blocklist).grid(row=3, column=1, sticky="w", padx=6, pady=(8, 0))

        log_frame = ttk.LabelFrame(outer, text="Live Activity Log", padding=8)
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(log_frame, height=14, wrap="word", state="disabled", font=("Consolas", 9))
        scrollbar = ttk.Scrollbar(log_frame, orient="vertical", command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        suspicious_frame = ttk.LabelFrame(outer, text="Top Suspicious Domains (Predictive View)", padding=8)
        suspicious_frame.pack(fill="x", expand=False, pady=(8, 0))
        self.suspicious_list = tk.Text(suspicious_frame, height=6, wrap="none", state="disabled", font=("Consolas", 9))
        self.suspicious_list.pack(fill="both", expand=True)

        lab_frame = ttk.LabelFrame(outer, text="Ad Disassembly Lab – Paste Ad URLs / HTML / Snippets", padding=8)
        lab_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.lab_text = tk.Text(lab_frame, height=8, wrap="word", font=("Consolas", 9))
        self.lab_text.pack(fill="both", expand=True)
        lab_buttons = ttk.Frame(lab_frame)
        lab_buttons.pack(fill="x", pady=(6, 0))
        ttk.Button(lab_buttons, text="Analyze & Learn Hosts", command=self._lab_analyze).pack(side="left")
        ttk.Label(
            lab_buttons,
            text="(Extracts host-like tokens from pasted content and feeds them into the predictive firewall.)",
        ).pack(side="left", padx=8)

        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(8, 0))
        ttk.Button(footer, text="Apply Blocklist Now", command=self._manual_apply).pack(side="left")
        ttk.Button(footer, text="Show Firewall Snapshot", command=self.show_firewall_snapshot).pack(side="left", padx=8)
        ttk.Label(
            footer,
            text="System-wide • Hosts-based • Predictive • Profiles • Redirect/Dummy Load • Ad Disassembly Lab • Auto-Lab • Borg Collective • Malvertising Shield • Auto-elevation",
        ).pack(side="right")

    def _append_log(self, line: str):
        # Tk widgets must only be updated from the GUI thread.
        if threading.current_thread() is not threading.main_thread():
            try:
                self.root.after(0, self._append_log, line)
            except tk.TclError:
                pass
            return
        try:
            self.log_text.configure(state="normal")
            self.log_text.insert("end", line + "\n")
            self.log_text.see("end")
            self.log_text.configure(state="disabled")
        except tk.TclError:
            pass

    def _set_status(self, status: str):
        self.status_var.set(status)

    def _seed_learning(self):
        seeds = [
            "ads.google.com",
            "adservice.google.com",
            "telemetry.microsoft.com",
            "events.reddit.com",
            "ads.youtube.com",
            "s.youtube.com",
            "pagead.google.com",
            "track.example-ads.net",
        ]
        for host in seeds:
            self.firewall.learn_domain(host, context="seed", manual=False)

    def _auto_apply(self):
        self._set_status("Applying blocklist to hosts file…")
        self.hosts_manager.apply_blocklist()
        self._set_status("Active – system-wide predictive ad blocking in effect.")

    def _manual_apply(self):
        self._set_status("Manual apply requested…")
        self.hosts_manager.apply_blocklist()
        self._set_status("Active – system-wide predictive ad blocking in effect.")

    def _schedule_periodic_apply(self):
        def periodic():
            while True:
                time.sleep(300)
                try:
                    self.hosts_manager.apply_blocklist()
                except Exception:
                    pass

        t = threading.Thread(target=periodic, daemon=True)
        t.start()

    def _schedule_suspicious_refresh(self):
        def refresh():
            self._refresh_suspicious_view()
            self.root.after(5000, refresh)
        self.root.after(2000, refresh)

    def _refresh_suspicious_view(self):
        items = self.firewall.top_suspicious(limit=20)
        self.suspicious_list.configure(state="normal")
        self.suspicious_list.delete("1.0", "end")
        if not items:
            self.suspicious_list.insert("end", "No suspicious domains tracked yet.\n")
        else:
            for line in items:
                self.suspicious_list.insert("end", line + "\n")
        self.suspicious_list.configure(state="disabled")

    def _on_profile_change(self, event=None):
        profile = self.profile_var.get().strip().upper()
        if profile not in ("STRICT", "BALANCED", "RELAXED"):
            profile = "STRICT"
            self.profile_var.set(profile)
        self.firewall.cfg.profile = profile
        self._append_log(f"Profile changed to: {profile}")
        self._set_status(f"Profile: {profile} – heuristic threshold adjusted.")

    def _manual_add(self):
        host = self.manual_domain_var.get().strip()
        if not host:
            return
        self.firewall.learn_domain(host, context="manual", manual=True)
        self._append_log(f"Manually added & learned domain: {host}")
        self._set_status("Manual domain learned; will be included if score exceeds threshold.")

    def _manual_remove(self):
        host = self.manual_domain_var.get().strip()
        if not host:
            return
        self.firewall.remove_domain(host)
        self._append_log(f"Manually removed domain from dynamic blocklist: {host}")
        self._set_status("Manual domain removed from dynamic blocklist.")

    def _export_blocklist(self):
        self.firewall.export_dynamic(BLOCKLIST_EXPORT)
        self._append_log(f"Exported dynamic blocklist to: {BLOCKLIST_EXPORT}")
        self._set_status("Dynamic blocklist exported.")

    def _import_blocklist(self):
        self.firewall.import_dynamic(BLOCKLIST_EXPORT)
        self._append_log(f"Imported dynamic blocklist from: {BLOCKLIST_EXPORT}")
        self._set_status("Dynamic blocklist imported.")

    def _lab_analyze(self):
        text = self.lab_text.get("1.0", "end")
        hosts = extract_host_candidates(text)
        if not hosts:
            self._append_log("Ad Lab: no host-like tokens found.")
            self._set_status("Ad Lab: no hosts found.")
            return
        for h in hosts:
            self.firewall.learn_domain(h, context="ad_lab", manual=True)
        self._append_log(f"Ad Lab: learned {len(hosts)} host candidates from pasted content.")
        self._set_status(f"Ad Lab: {len(hosts)} hosts learned; will be enforced on next apply.")

    # === Auto-Lab API ===
    def auto_lab_feed(self, text: str):
        """
        External modules can call this to feed captured ad-related text.
        The GUI schedules periodic processing of this buffer.
        """
        if not text:
            return
        self.auto_lab_buffer.append(text)

    def _schedule_auto_lab(self):
        def process():
            if self.auto_lab_buffer:
                batch = self.auto_lab_buffer[:]
                self.auto_lab_buffer.clear()
                combined = "\n".join(batch)
                hosts = extract_host_candidates(combined)
                if hosts:
                    for h in hosts:
                        self.firewall.learn_domain(h, context="auto_lab", manual=True)
                    self._append_log(f"Auto-Lab: learned {len(hosts)} host candidates from auto feed.")
            self.root.after(4000, process)
        self.root.after(4000, process)

    # === Borg Collective periodic sync ===
    def _schedule_borg_sync(self):
        if not BORG_ENABLED:
            return

        def sync_loop():
            while True:
                time.sleep(BORG_SYNC_INTERVAL_SECONDS)
                try:
                    self.borg_sync.push_to_collective()
                    self.borg_sync.pull_from_collective()
                except Exception:
                    pass

        t = threading.Thread(target=sync_loop, daemon=True)
        t.start()

    def show_firewall_snapshot(self):
        snap = self.firewall.snapshot()
        static_count = len(snap["static"])
        dynamic_count = len(snap["dynamic"])
        msg_lines = [
            f"Static blocked domains: {static_count}",
            f"Dynamic harvested domains: {dynamic_count}",
        ]
        preview_dynamic = sorted(list(snap["dynamic"]))[:20]
        if preview_dynamic:
            msg_lines.append("")
            msg_lines.append("Sample dynamic domains:")
            msg_lines.extend(f"  - {d}" for d in preview_dynamic)
        messagebox.showinfo("Firewall Snapshot", "\n".join(msg_lines))

    def on_close(self):
        try:
            self.firewall.export_dynamic(BLOCKLIST_EXPORT)
        except Exception:
            pass
        try:
            if self.api:
                self.api.stop()
        except Exception:
            pass
        self.root.destroy()


# ============================================================
# Main
# ============================================================

def main():
    logging.basicConfig(
        filename=str(LOG_FILE),
        level=logging.INFO,
        format="%(asctime)s %(levelname)s %(message)s",
        encoding="utf-8",
    )
    root = tk.Tk()
    try:
        style = ttk.Style()
        if "vista" in style.theme_names():
            style.theme_use("vista")
    except Exception:
        pass
    gui = DominionDeckGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
