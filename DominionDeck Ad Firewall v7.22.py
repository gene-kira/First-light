#!/usr/bin/env python3
"""
DominionDeck v17.2 – Predictive Sentinel + Drive Guardian + Anomaly Engine + YouTube Integration

- System-wide hosts-based firewall (Windows hosts file)
- Auto-elevation
- Predictive domain scoring (heuristics + ML-style classifier)
- Proactive optional auto-apply for newly learned blocklist changes
- Merge-safe optional hosts-backup synchronization with safety snapshots
- Malvertising Shield (script/WASM/fingerprint behavior)
- Mapper Bot – Web terrain scanner (general + ad-heavy sites)
- Threat Intel Swarm – Known bad hosts/IPs
- Global News Sentinel – Worldwide security & AI feeds
- Universal Scanner Engine – Threats + news + ads + corporate targets
- Borg Collective Sync – Shared dynamic blocklist
- Local Auto-Lab API – POST /domains + /youtube for local tools
- Telemetry Engine – SQLite + optional Redis + ZeroMQ
- Drive Guardian – Monitors disk I/O + external access patterns
- Anomaly Engine – Learns baseline and flags unusual activity
- YouTube Detection Integration – network + PID + window-title feed into Auto-Lab
- Extra Detection Engines – process/connection scanners feeding firewall
- GUI Dashboard – Profiles, logs, telemetry, lab, snapshot, drive/anomaly panel
- User-selectable blocklist backup path for export/import (DominionDeck Ad Firewall v7.11-style)
"""

from __future__ import annotations

import ctypes
import os
import sys
import logging
import time
import threading
import json
import asyncio
import sqlite3
import ipaddress
import re
from urllib.parse import urlsplit
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tkinter as tk
from tkinter import ttk, messagebox
from pathlib import Path
from datetime import datetime
from dataclasses import dataclass, field
from typing import Set, Dict, List, Optional, Tuple

try:
    import redis
except ImportError:
    redis = None

try:
    import zmq
except ImportError:
    zmq = None

try:
    import requests
except ImportError:
    requests = None

try:
    import feedparser
except ImportError:
    feedparser = None

try:
    import psutil
except ImportError:
    psutil = None

APP_NAME = "DominionDeck Universal Sentinel"
APP_VERSION = "17.2"
BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "dominiondeck_v17_2.log"

HOSTS_PATH = Path(r"C:\Windows\System32\drivers\etc\hosts")
DEFAULT_SINKHOLE_IP = "0.0.0.0"

# Default fallback blocklist path; GUI lets user pick and persist a custom backup file
BLOCKLIST_EXPORT_DEFAULT = BASE_DIR / "dominiondeck_dynamic_blocklist.txt"

BORG_ENABLED = True
_BORG_ENV_PATH = os.environ.get("DOMINIONDECK_BORG_SHARE", "").strip()
BORG_SHARE_PATH = Path(_BORG_ENV_PATH) if _BORG_ENV_PATH else None
BORG_SYNC_INTERVAL_SECONDS = 120
APP_CONFIG_FILE = BASE_DIR / "dominiondeck_config.json"
BORG_FILENAME = "borg_collective_blocklist.txt"


def borg_share_file():
    """Return a usable collective file path, or None without touching an unset share."""
    if BORG_SHARE_PATH is None:
        return None
    try:
        configured = Path(BORG_SHARE_PATH)
        if configured.suffix.lower() == ".txt":
            parent = configured.parent
            if not parent.exists() or not parent.is_dir():
                return None
            return configured
        if not configured.exists() or not configured.is_dir():
            return None
        return configured / BORG_FILENAME
    except (OSError, ValueError, TypeError):
        return None


API_ENABLED = True
API_HOST = os.environ.get("DOMINIONDECK_API_HOST", "127.0.0.1")
API_PORT = int(os.environ.get("DOMINIONDECK_API_PORT", "0"))
API_MAX_BODY_BYTES = 1_000_000

TELEMETRY_DB = BASE_DIR / "dominiondeck_telemetry.sqlite"
REDIS_URL = os.environ.get("DOMINIONDECK_REDIS_URL", "redis://localhost:6379/0")
ZMQ_ENDPOINT = os.environ.get("DOMINIONDECK_ZMQ_ENDPOINT", "tcp://127.0.0.1:5557")

MAPPER_ENABLED = True
MAPPER_INTERVAL_SECONDS = 300
MAPPER_SEEDS = [
    "https://www.reddit.com",
    "https://www.youtube.com",
    "https://www.cnn.com",
    "https://www.nytimes.com",
    "https://www.twitch.tv",
    "https://www.facebook.com",
    "https://www.twitter.com",
    "https://www.tiktok.com",
    "https://www.amazon.com",
    "https://www.ebay.com",
    "https://www.aliexpress.com",
    "https://www.taboola.com",
    "https://www.outbrain.com",
    "https://www.criteo.com",
    "https://www.adroll.com",
    "https://www.pubmatic.com",
    "https://www.openx.com",
]

THREAT_INTEL_ENABLED = True
THREAT_INTEL_INTERVAL_SECONDS = 600
THREAT_INTEL_FEEDS = [
    "https://www.spamhaus.org/drop/drop.lasso",
    "https://www.spamhaus.org/drop/edrop.lasso",
    "https://feodotracker.abuse.ch/downloads/ipblocklist.csv",
    "https://feodotracker.abuse.ch/downloads/domainblocklist.csv",
]

NEWS_SENTINEL_ENABLED = True
NEWS_SENTINEL_INTERVAL_SECONDS = 900
NEWS_SENTINEL_FEEDS = [
    "https://feeds.feedburner.com/TheHackersNews",
    "https://www.bleepingcomputer.com/feed/",
    "https://krebsonsecurity.com/feed/",
    "https://www.cisa.gov/news.xml",
    "https://www.europol.europa.eu/rss.xml",
    "https://www.ncsc.gov.uk/feeds/advisories.xml",
    "https://www.cert.europa.eu/rss/advisories.xml",
    "https://www.jpcert.or.jp/rss/jpcert.rdf",
    "https://www.cert.gov.au/rss",
    "https://www.cert-in.org.in/en/rssadvisory.jsp",
    "https://www.csirt.gob.cl/feed/",
    "https://www.cert.br/rss/alertas.xml",
    "https://www.africacert.org/feed/",
    "https://www.gov.il/en/departments/Units/cert-israel?skip=0&limit=20&format=rss",
    "https://msrc-blog.microsoft.com/feed/",
    "https://security.googleblog.com/feeds/posts/default",
    "https://aws.amazon.com/security/feed/",
    "https://openai.com/blog/rss.xml",
]

UNIVERSAL_SCANNER_ENABLED = True
UNIVERSAL_SCANNER_INTERVAL_SECONDS = 900
UNIVERSAL_SCANNER_TARGETS = [
    "https://www.google.com/ads",
    "https://ads.google.com",
    "https://business.facebook.com",
    "https://ads.tiktok.com",
    "https://ads.twitter.com",
    "https://ads.linkedin.com",
    "https://ads.pinterest.com",
    "https://ads.snapchat.com",
    "https://www.microsoft.com/en-us/advertising",
    "https://www.google.com/intl/en/ads",
    "https://www.amazon.com/advertising",
    "https://www.apple.com/newsroom/",
    "https://www.samsung.com/global/galaxy/",
    "https://www.adobe.com/marketing.html",
    "https://www.salesforce.com/products/marketing-cloud/overview/",
    "https://www.oracle.com/marketingcloud/",
]

DRIVE_GUARDIAN_ENABLED = True
DRIVE_GUARDIAN_INTERVAL_SECONDS = 3
DRIVE_GUARDIAN_BASELINE_WINDOW = 60
DRIVE_GUARDIAN_SPIKE_FACTOR = 3.0

ANOMALY_ENGINE_ENABLED = True
ANOMALY_BASELINE_WINDOW = 120
ANOMALY_SPIKE_FACTOR = 2.5

# Extra detection engines toggles
PROCESS_SCANNER_ENABLED = True
PROCESS_SCANNER_INTERVAL_SECONDS = 20

YOUTUBE_INTEGRATION_ENABLED = True


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


def normalize_domain(value: str) -> Optional[str]:
    """Normalize and validate a DNS hostname; reject URLs, paths, IPs, and junk."""
    if not isinstance(value, str):
        return None
    raw = value.strip().strip('"\'<>[](){};,')
    if not raw or len(raw) > 2048:
        return None
    candidate = raw
    if "://" in candidate:
        try:
            candidate = urlsplit(candidate).hostname or ""
        except ValueError:
            return None
    else:
        candidate = candidate.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if candidate.count(":") == 1:
            candidate = candidate.rsplit(":", 1)[0]
    candidate = candidate.strip().rstrip(".").lower()
    if candidate.startswith("*."):
        candidate = candidate[2:]
    if not candidate or len(candidate) > 253 or "." not in candidate:
        return None
    try:
        ipaddress.ip_address(candidate.strip("[]"))
        return None
    except ValueError:
        pass
    labels = candidate.split(".")
    if len(labels) < 2 or any(not label or len(label) > 63 for label in labels):
        return None
    if any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]*[a-z0-9])?", label) for label in labels):
        return None
    if not re.fullmatch(r"[a-z][a-z0-9-]*|xn--[a-z0-9-]+", labels[-1]):
        return None
    return candidate


def extract_host_candidates(text: str) -> List[str]:
    """Extract validated DNS hostnames from URLs, HTML snippets, and plain text."""
    if not isinstance(text, str) or not text:
        return []
    pattern = re.compile(
        r"(?i)(?:https?://)?(?:[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\.)+[a-z][a-z0-9-]{1,62}(?::\d{1,5})?(?:/[^\s\"'<>]*)?"
    )
    hosts = set()
    for match in pattern.finditer(text[:2_000_000]):
        host = normalize_domain(match.group(0))
        if host and not host.startswith("www."):
            hosts.add(host)
        elif host:
            hosts.add(host[4:])
    return sorted(hosts)


class DomainMLClassifier:
    def __init__(self):
        self.weights = {
            "has_ads": 2.5,
            "has_track": 2.0,
            "has_analytics": 2.0,
            "has_telemetry": 1.5,
            "has_marketing_kw": 1.5,
            "length": 0.01,
            "dots": 0.5,
        }
        self.bias = 0.0

    def _features(self, host: str, context: str) -> Dict[str, float]:
        h = host.lower()
        text = (host + " " + context).lower()
        marketing_kws = [
            "ads", "adserver", "adservice", "adclick",
            "impression", "tracking", "telemetry", "pixel",
            "retargeting", "remarketing", "sponsor",
            "buy now", "limited offer", "sale", "promo",
            "discount", "affiliate",
        ]
        return {
            "has_ads": 1.0 if "ads" in h or "ad." in h or ".ad" in h else 0.0,
            "has_track": 1.0 if "track" in h else 0.0,
            "has_analytics": 1.0 if "analytic" in h else 0.0,
            "has_telemetry": 1.0 if "telemetry" in h else 0.0,
            "has_marketing_kw": 1.0 if any(kw in text for kw in marketing_kws) else 0.0,
            "length": float(len(h)),
            "dots": float(h.count(".")),
        }

    def predict_score(self, host: str, context: str = "") -> float:
        feats = self._features(host, context)
        score = self.bias
        for k, v in feats.items():
            score += self.weights.get(k, 0.0) * v
        score = max(0.0, min(10.0, score / 5.0))
        return score


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
    })
    heuristic_keywords: Set[str] = field(default_factory=lambda: {
        "ads", "adserver", "adservice", "adclick",
        "impression", "tracking", "telemetry", "pixel",
        "retargeting", "remarketing", "sponsor",
        "buy now", "limited offer", "sale", "promo",
        "discount", "affiliate",
        "malware", "phishing", "ransomware", "exploit",
        "botnet", "breach", "hack", "hacker",
    })
    heuristic_threshold_strict: int = 3
    heuristic_threshold_balanced: int = 4
    heuristic_threshold_relaxed: int = 5
    profile: str = "STRICT"


class DomainFirewall:
    def __init__(self, cfg: FirewallConfig, ml_classifier: Optional[DomainMLClassifier] = None):
        self.cfg = cfg
        self.dynamic_block: Set[str] = set()
        self.domain_scores: Dict[str, int] = {}
        self.domain_evidence: Dict[str, List[str]] = {}
        self.lock = threading.RLock()
        self.ml = ml_classifier or DomainMLClassifier()

    def _current_threshold(self) -> int:
        if self.cfg.profile == "STRICT":
            return self.cfg.heuristic_threshold_strict
        if self.cfg.profile == "BALANCED":
            return self.cfg.heuristic_threshold_balanced
        return self.cfg.heuristic_threshold_relaxed

    def _score_domain(self, host: str, context: str = "") -> int:
        host = normalize_domain(host) or ""
        if not host:
            return 0
        labels = set(host.split("."))
        evidence: List[str] = []
        score = 0
        ad_labels = {"ad", "ads", "adserver", "adservice", "adtrack", "adtracking", "adclick", "adnetwork", "adtech"}
        tracking_labels = {"track", "tracker", "tracking", "pixel", "beacon", "telemetry", "analytics", "metric", "metrics"}
        marketing_labels = {"sponsor", "sponsored", "retarget", "retargeting", "remarketing", "affiliate", "impression"}
        if labels & ad_labels:
            score += 3
            evidence.append("advertising-related hostname label")
        if labels & tracking_labels:
            score += 2
            evidence.append("tracking/analytics hostname label")
        if labels & marketing_labels:
            score += 2
            evidence.append("marketing/affiliate hostname label")
        if any(token in labels for token in ("malware", "phishing", "botnet", "ransomware", "exploit")):
            score += 4
            evidence.append("threat-related hostname label")
        ml_score = self.ml.predict_score(host, "")
        if ml_score >= 1.0 and len(host) >= 24:
            score += 1
            evidence.append("long/complex hostname heuristic")
        score = min(score, 10)
        self.domain_evidence[host] = evidence or ["weak/no explicit hostname signals"]
        return score

    def learn_domain(self, host: str, context: str = "", manual: bool = False):
        normalized = normalize_domain(host)
        if not normalized:
            return False
        with self.lock:
            base_score = self._score_domain(normalized, context)
            if manual:
                base_score = max(base_score, 10)
                self.domain_evidence[normalized] = ["manually added by user"]
            self.domain_scores[normalized] = base_score
            threshold = self._current_threshold()
            if base_score >= threshold:
                if normalized not in self.dynamic_block and normalized not in self.cfg.static_block:
                    self.dynamic_block.add(normalized)
            return True

    def remove_domain(self, host: str):
        host = normalize_domain(host) or ""
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
            return [
                f"{host} (risk={score}/10; evidence={', '.join(self.domain_evidence.get(host, []))})"
                for host, score in items[:limit]
            ]

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
                host = normalize_domain(line)
                if host:
                    self.dynamic_block.add(host)
                    self.domain_scores[host] = max(
                        self.domain_scores.get(host, 0),
                        self._current_threshold() + 1,
                    )
                    self.domain_evidence[host] = ["imported from trusted local blocklist"]


class HostsManager:
    def __init__(self, firewall: DomainFirewall, log_callback, sinkhole_ip_getter, telemetry):
        self.firewall = firewall
        self.log_callback = log_callback
        self.sinkhole_ip_getter = sinkhole_ip_getter
        self.lock = threading.Lock()
        self.telemetry = telemetry

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] {msg}"
        logging.info(msg)
        self.log_callback(line)
        self.telemetry.enqueue_event("log", {"message": msg})

    def apply_blocklist(self):
        with self.lock:
            domains = [d for raw in self.firewall.all_blocked_domains() if (d := normalize_domain(raw))]
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
                section = ["", "# DominionDeck BEGIN – Universal Sentinel"]
                section.append(f"# Mode: sinkhole/redirect IP = {sink_ip}")
                for d in domains:
                    section.append(f"{sink_ip} {d}")
                section.append("# DominionDeck END – Universal Sentinel")
                section.append("")
                new_content = "\n".join(filtered + section)
                old_content = "\n".join(original)
                if new_content == old_content:
                    self.log("Hosts file already matches the current rules; no write needed.")
                    return
                backup_path = HOSTS_PATH.with_name("hosts.dominiondeck.backup")
                try:
                    if not backup_path.exists():
                        backup_path.write_text(old_content, encoding="utf-8")
                except OSError as backup_exc:
                    self.log(
                        f"Could not create first-run hosts backup: {backup_exc}; continuing with requested apply."
                    )
                HOSTS_PATH.write_text(new_content, encoding="utf-8")
                self.log(
                    f"Applied blocklist to hosts file with {len(domains)} validated domains (IP={sink_ip}); backup: {backup_path}."
                )
                self.telemetry.enqueue_event(
                    "hosts_apply",
                    {
                        "count": len(domains),
                        "sink_ip": sink_ip,
                        "timestamp": datetime.now().isoformat(),
                    },
                )
            except PermissionError:
                self.log("PermissionError: hosts file write failed even after elevation.")
            except Exception as exc:
                self.log(f"Error updating hosts file: {exc}")


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
    def __init__(self, firewall: DomainFirewall, log_callback, telemetry):
        self.firewall = firewall
        self.log_callback = log_callback
        self.telemetry = telemetry

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [SHIELD] {msg}"
        logging.info(line)
        self.log_callback(line)
        self.telemetry.enqueue_event("shield_log", {"message": msg})

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
        domain = (b.domain or "").strip().lower()
        if not domain:
            return
        score = self.score_behavior(b)
        self.telemetry.enqueue_event(
            "shield_behavior",
            {
                "domain": domain,
                "score": score,
                "has_wasm": b.has_wasm,
                "high_entropy": b.high_entropy,
                "fingerprint": b.uses_fingerprint_apis,
                "network_fan_out": b.network_fan_out,
            },
        )
        if score >= 4:
            self.log(
                f"High-risk malvertising behavior detected for {domain} (score={score}). Promoting to firewall."
            )
            self.firewall.learn_domain(domain, context="malvertising_shield", manual=True)
        else:
            self.log(f"Observed behavior for {domain} (score={score}) – below promotion threshold.")


class BorgSync:
    def __init__(self, firewall: DomainFirewall, log_callback, telemetry):
        self.firewall = firewall
        self.log_callback = log_callback
        self.lock = threading.Lock()
        self.telemetry = telemetry

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [BORG] {msg}"
        logging.info(line)
        self.log_callback(line)
        self.telemetry.enqueue_event("borg_log", {"message": msg})

    def push_to_collective(self):
        if not BORG_ENABLED:
            return
        share_file = borg_share_file()
        if share_file is None:
            return
        try:
            with self.firewall.lock:
                local_domains = sorted(self.firewall.dynamic_block)
            if not local_domains:
                return
            existing: Set[str] = set()
            try:
                if share_file.exists():
                    content = share_file.read_text(encoding="utf-8").splitlines()
                    existing = {line.strip().lower() for line in content if line.strip()}
            except OSError as exc:
                self.log(f"Network share unavailable ({share_file}): {exc}.")
                return
            except Exception as exc:
                self.log(f"Could not read collective file: {exc}")
                return
            merged = sorted(existing.union(local_domains))
            if not share_file.parent.exists():
                return
            share_file.write_text("\n".join(merged), encoding="utf-8")
            self.log(
                f"Pushed {len(local_domains)} local dynamic domains to collective (merged={len(merged)})."
            )
            self.telemetry.enqueue_event(
                "borg_push",
                {
                    "local_count": len(local_domains),
                    "merged_count": len(merged),
                },
            )
        except Exception as exc:
            self.log(f"Push error: {exc}")

    def pull_from_collective(self):
        if not BORG_ENABLED:
            return
        share_file = borg_share_file()
        if share_file is None:
            return
        try:
            if not share_file.exists():
                return
            content = share_file.read_text(encoding="utf-8").splitlines()
        except OSError as exc:
            self.log(f"Pull failed for collective path {share_file}: {exc}.")
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
            self.telemetry.enqueue_event("borg_pull", {"new_hosts": new_hosts})


class TelemetryEngine:
    def __init__(self):
        self.queue: asyncio.Queue = asyncio.Queue()
        self.loop = None
        self.thread = None
        self.redis_client = None
        self.zmq_ctx = None
        self.zmq_socket = None
        self._init_storage()

    def _init_storage(self):
        conn = sqlite3.connect(str(TELEMETRY_DB))
        try:
            cur = conn.cursor()
            cur.execute(
                """
                CREATE TABLE IF NOT EXISTS events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ts TEXT NOT NULL,
                    type TEXT NOT NULL,
                    payload TEXT NOT NULL
                )
            """
            )
            conn.commit()
        finally:
            conn.close()
        if redis is not None:
            try:
                self.redis_client = redis.Redis.from_url(REDIS_URL)
                self.redis_client.ping()
            except Exception:
                self.redis_client = None
        if zmq is not None:
            try:
                self.zmq_ctx = zmq.Context.instance()
                self.zmq_socket = self.zmq_ctx.socket(zmq.PUB)
                self.zmq_socket.bind(ZMQ_ENDPOINT)
            except Exception:
                self.zmq_ctx = None
                self.zmq_socket = None

    def enqueue_event(self, event_type: str, payload: Dict):
        try:
            data = {
                "ts": datetime.now().isoformat(),
                "type": event_type,
                "payload": payload,
            }
            if self.loop and self.loop.is_running():
                asyncio.run_coroutine_threadsafe(self.queue.put(data), self.loop)
        except Exception:
            pass

    async def _process_events(self):
        while True:
            data = await self.queue.get()
            try:
                self._store_sqlite(data)
                self._store_redis(data)
                self._publish_zmq(data)
            except Exception:
                pass

    def _store_sqlite(self, data: Dict):
        conn = sqlite3.connect(str(TELEMETRY_DB))
        try:
            cur = conn.cursor()
            cur.execute(
                "INSERT INTO events (ts, type, payload) VALUES (?, ?, ?)",
                (data["ts"], data["type"], json.dumps(data["payload"])),
            )
            conn.commit()
        finally:
            conn.close()

    def _store_redis(self, data: Dict):
        if not self.redis_client:
            return
        key = f"dominiondeck:event:{data['type']}"
        try:
            self.redis_client.lpush(key, json.dumps(data))
            self.redis_client.ltrim(key, 0, 999)
        except Exception:
            pass

    def _publish_zmq(self, data: Dict):
        if not self.zmq_socket:
            return
        try:
            self.zmq_socket.send_json(data)
        except Exception:
            pass

    def start(self):
        def runner():
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.create_task(self._process_events())
            self.loop.run_forever()

        self.thread = threading.Thread(
            target=runner, name="DominionDeck-Telemetry", daemon=True
        )
        self.thread.start()


class MapperBot:
    def __init__(self, firewall: DomainFirewall, telemetry: TelemetryEngine, log_callback):
        self.firewall = firewall
        self.telemetry = telemetry
        self.log_callback = log_callback
        self.enabled = MAPPER_ENABLED
        self.thread = None

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [MAPPER] {msg}"
        logging.info(line)
        self.log_callback(line)
        self.telemetry.enqueue_event("mapper_log", {"message": msg})

    def _fetch_page(self, url: str) -> str:
        if requests is None:
            return ""
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            return ""
        return ""

    def _scan_once(self):
        if not self.enabled or requests is None:
            return
        total_hosts = 0
        for url in MAPPER_SEEDS:
            html = self._fetch_page(url)
            if not html:
                continue
            hosts = extract_host_candidates(html)
            if not hosts:
                continue
            for h in hosts:
                self.firewall.learn_domain(h, context="mapper_bot", manual=False)
            total_hosts += len(hosts)
        if total_hosts:
            self.log(
                f"Mapper Bot scanned {len(MAPPER_SEEDS)} seed URLs and learned {total_hosts} host candidates."
            )
            self.telemetry.enqueue_event(
                "mapper_scan",
                {
                    "seed_count": len(MAPPER_SEEDS),
                    "hosts_learned": total_hosts,
                },
            )

    def start(self):
        if not self.enabled:
            self.log("Mapper Bot disabled.")
            return

        def loop():
            while True:
                try:
                    self._scan_once()
                except Exception:
                    pass
                time.sleep(MAPPER_INTERVAL_SECONDS)

        self.thread = threading.Thread(
            target=loop, name="DominionDeck-MapperBot", daemon=True
        )
        self.thread.start()
        self.log("Mapper Bot started.")


class ThreatIntelSwarm:
    def __init__(self, firewall: DomainFirewall, telemetry: TelemetryEngine, log_callback):
        self.firewall = firewall
        self.telemetry = telemetry
        self.log_callback = log_callback
        self.enabled = THREAT_INTEL_ENABLED
        self.thread = None

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [THREAT] {msg}"
        logging.info(line)
        self.log_callback(line)
        self.telemetry.enqueue_event("threat_log", {"message": msg})

    def _fetch_feed_text(self, url: str) -> str:
        if requests is None:
            return ""
        try:
            resp = requests.get(url, timeout=10)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            return ""
        return ""

    def _scan_once(self):
        if not self.enabled or requests is None:
            return
        total_hosts = 0
        for url in THREAT_INTEL_FEEDS:
            text = self._fetch_feed_text(url)
            if not text:
                continue
            hosts = extract_host_candidates(text)
            if not hosts:
                continue
            for h in hosts:
                self.firewall.learn_domain(h, context="threat_intel", manual=True)
            total_hosts += len(hosts)
        if total_hosts:
            self.log(
                f"Threat Intel Swarm ingested {len(THREAT_INTEL_FEEDS)} feeds and learned {total_hosts} host candidates."
            )
            self.telemetry.enqueue_event(
                "threat_intel_scan",
                {
                    "feed_count": len(THREAT_INTEL_FEEDS),
                    "hosts_learned": total_hosts,
                },
            )

    def start(self):
        if not self.enabled:
            self.log("Threat Intel Swarm disabled.")
            return

        def loop():
            while True:
                try:
                    self._scan_once()
                except Exception:
                    pass
                time.sleep(THREAT_INTEL_INTERVAL_SECONDS)

        self.thread = threading.Thread(
            target=loop, name="DominionDeck-ThreatIntel", daemon=True
        )
        self.thread.start()
        self.log("Threat Intel Swarm started.")


class NewsSentinel:
    def __init__(self, firewall: DomainFirewall, telemetry: TelemetryEngine, log_callback):
        self.firewall = firewall
        self.telemetry = telemetry
        self.log_callback = log_callback
        self.enabled = NEWS_SENTINEL_ENABLED
        self.thread = None

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [NEWS] {msg}"
        logging.info(line)
        self.log_callback(line)
        self.telemetry.enqueue_event("news_log", {"message": msg})

    def _parse_feed(self, url: str) -> List[str]:
        hosts: List[str] = []
        if feedparser is None:
            return hosts
        try:
            feed = feedparser.parse(url)
            for entry in feed.entries:
                text = (entry.get("title", "") or "") + " " + (entry.get("summary", "") or "")
                hosts.extend(extract_host_candidates(text))
        except Exception:
            return hosts
        return sorted(set(hosts))

    def _scan_once(self):
        if not self.enabled or feedparser is None:
            return
        total_hosts = 0
        for url in NEWS_SENTINEL_FEEDS:
            hosts = self._parse_feed(url)
            if not hosts:
                continue
            for h in hosts:
                self.firewall.learn_domain(h, context="news_sentinel", manual=False)
            total_hosts += len(hosts)
        if total_hosts:
            self.log(
                f"News Sentinel scanned {len(NEWS_SENTINEL_FEEDS)} global news feeds and learned {total_hosts} host candidates."
            )
            self.telemetry.enqueue_event(
                "news_sentinel_scan",
                {
                    "feed_count": len(NEWS_SENTINEL_FEEDS),
                    "hosts_learned": total_hosts,
                },
            )

    def start(self):
        if not self.enabled:
            self.log("News Sentinel disabled.")
            return

        def loop():
            while True:
                try:
                    self._scan_once()
                except Exception:
                    pass
                time.sleep(NEWS_SENTINEL_INTERVAL_SECONDS)

        self.thread = threading.Thread(
            target=loop, name="DominionDeck-NewsSentinel", daemon=True
        )
        self.thread.start()
        self.log("Global News Sentinel started.")


class UniversalScanner:
    def __init__(self, firewall: DomainFirewall, telemetry: TelemetryEngine, log_callback):
        self.firewall = firewall
        self.telemetry = telemetry
        self.log_callback = log_callback
        self.enabled = UNIVERSAL_SCANNER_ENABLED
        self.thread = None

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [UNIVERSAL] {msg}"
        logging.info(line)
        self.log_callback(line)
        self.telemetry.enqueue_event("universal_log", {"message": msg})

    def _fetch_page(self, url: str) -> str:
        if requests is None:
            return ""
        try:
            resp = requests.get(url, timeout=12)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            return ""
        return ""

    def _scan_once(self):
        if not self.enabled or requests is None:
            return
        total_hosts = 0
        for url in UNIVERSAL_SCANNER_TARGETS:
            html = self._fetch_page(url)
            if not html:
                continue
            hosts = extract_host_candidates(html)
            if not hosts:
                continue
            for h in hosts:
                self.firewall.learn_domain(h, context="universal_scanner", manual=False)
            total_hosts += len(hosts)
        if total_hosts:
            self.log(
                f"Universal Scanner scanned {len(UNIVERSAL_SCANNER_TARGETS)} targets and learned {total_hosts} host candidates."
            )
            self.telemetry.enqueue_event(
                "universal_scan",
                {
                    "target_count": len(UNIVERSAL_SCANNER_TARGETS),
                    "hosts_learned": total_hosts,
                },
            )

    def start(self):
        if not self.enabled:
            self.log("Universal Scanner disabled.")
            return

        def loop():
            while True:
                try:
                    self._scan_once()
                except Exception:
                    pass
                time.sleep(UNIVERSAL_SCANNER_INTERVAL_SECONDS)

        self.thread = threading.Thread(
            target=loop, name="DominionDeck-UniversalScanner", daemon=True
        )
        self.thread.start()
        self.log("Universal Scanner Engine started.")


class YouTubeDetectionEngine:
    """
    Integration point for external YouTube detectors:
    - Strong detection using network + PID + window title
    - External tool calls POST /youtube on LocalLabAPI
    - This engine just logs and feeds domains into Auto-Lab / firewall
    """

    def __init__(self, firewall: DomainFirewall, telemetry: TelemetryEngine, log_callback, auto_lab_feed):
        self.firewall = firewall
        self.telemetry = telemetry
        self.log_callback = log_callback
        self.auto_lab_feed = auto_lab_feed
        self.enabled = YOUTUBE_INTEGRATION_ENABLED

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [YOUTUBE] {msg}"
        logging.info(line)
        self.log_callback(line)
        self.telemetry.enqueue_event("youtube_log", {"message": msg})

    def feed_activity(self, window_title: str, process_name: str, urls: List[str]):
        """
        External detector calls this with:
        - window_title: e.g. 'YouTube - Chrome'
        - process_name: browser or app
        - urls: list of observed video/ad URLs
        """
        if not self.enabled:
            return
        combined = " ".join(urls)
        self.auto_lab_feed(combined)
        hosts = extract_host_candidates(combined)
        learned = 0
        for h in hosts:
            self.firewall.learn_domain(h, context="youtube_detector", manual=True)
            learned += 1
        self.log(
            f"YouTube activity from {process_name} / '{window_title}' – learned {learned} host candidates."
        )
        self.telemetry.enqueue_event(
            "youtube_activity",
            {
                "window_title": window_title,
                "process_name": process_name,
                "urls_count": len(urls),
                "hosts_learned": learned,
            },
        )


class ProcessScannerEngine:
    """
    Lightweight process/connection scanner:
    - Uses psutil to inspect connections
    - Extracts remote hostnames/IPs
    - Feeds domains into firewall with 'process_scanner' context
    """

    def __init__(self, firewall: DomainFirewall, telemetry: TelemetryEngine, log_callback):
        self.firewall = firewall
        self.telemetry = telemetry
        self.log_callback = log_callback
        self.enabled = PROCESS_SCANNER_ENABLED and psutil is not None
        self.thread = None

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [PROC] {msg}"
        logging.info(line)
        self.log_callback(line)
        self.telemetry.enqueue_event("process_scanner_log", {"message": msg})

    def _scan_once(self):
        if not self.enabled or psutil is None:
            return
        learned = 0
        try:
            for proc in psutil.process_iter(attrs=["pid", "name"]):
                pid = proc.info.get("pid")
                name = proc.info.get("name") or ""
                if not pid:
                    continue
                try:
                    conns = proc.connections(kind="inet")
                except Exception:
                    continue
                for c in conns:
                    raddr = c.raddr
                    if not raddr:
                        continue
                    host = raddr.ip
                    if not host:
                        continue
                    # IPs are ignored by normalize_domain; still feed telemetry
                    nd = normalize_domain(host)
                    if nd:
                        self.firewall.learn_domain(nd, context="process_scanner", manual=False)
                        learned += 1
            if learned:
                self.log(f"Process Scanner learned {learned} host candidates from active connections.")
                self.telemetry.enqueue_event(
                    "process_scanner_scan",
                    {
                        "hosts_learned": learned,
                    },
                )
        except Exception:
            pass

    def start(self):
        if not self.enabled:
            self.log("Process Scanner disabled (psutil missing or feature disabled).")
            return

        def loop():
            while True:
                try:
                    self._scan_once()
                except Exception:
                    pass
                time.sleep(PROCESS_SCANNER_INTERVAL_SECONDS)

        self.thread = threading.Thread(
            target=loop, name="DominionDeck-ProcessScanner", daemon=True
        )
        self.thread.start()
        self.log("Process Scanner Engine started.")


class LocalLabAPI:
    def __init__(self, firewall: DomainFirewall, log_callback, telemetry, youtube_engine: Optional[YouTubeDetectionEngine], host=API_HOST, port=API_PORT):
        self.firewall = firewall
        self.log_callback = log_callback
        self.host = host
        self.requested_port = port
        self.server = None
        self.thread = None
        self.port = None
        self.telemetry = telemetry
        self.youtube_engine = youtube_engine

    def start(self):
        firewall = self.firewall
        log_callback = self.log_callback
        telemetry = self.telemetry
        youtube_engine = self.youtube_engine

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
                    self._reply(
                        404,
                        {
                            "error": "Not found",
                            "endpoints": ["GET /health", "POST /domains", "POST /youtube"],
                        },
                    )

            def _handle_domains(self, payload: Dict):
                supplied = payload.get("domain", "")
                text = payload.get("text", "")
                hosts = set()
                if isinstance(supplied, str) and supplied.strip():
                    normalized = normalize_domain(supplied)
                    if normalized:
                        hosts.add(normalized)
                if isinstance(text, str) and text.strip():
                    hosts.update(extract_host_candidates(text))
                valid_hosts = sorted(h for item in hosts if (h := normalize_domain(item)))
                if not valid_hosts:
                    self._reply(
                        400,
                        {"error": "Provide a domain or text containing domain-like hosts"},
                    )
                    return
                learned = []
                for host in valid_hosts:
                    firewall.learn_domain(host, context="local_api", manual=True)
                    learned.append(host)
                log_callback(f"[API] Learned {len(learned)} host candidate(s) from localhost client.")
                telemetry.enqueue_event(
                    "api_learn",
                    {
                        "count": len(learned),
                        "domains": learned,
                    },
                )
                self._reply(200, {"accepted": len(learned), "domains": learned})

            def _handle_youtube(self, payload: Dict):
                """
                Expected JSON:
                {
                    "window_title": "...",
                    "process_name": "...",
                    "urls": ["https://www.youtube.com/watch?v=...", ...]
                }
                """
                if youtube_engine is None:
                    self._reply(501, {"error": "YouTube integration not available"})
                    return
                window_title = str(payload.get("window_title", "") or "")
                process_name = str(payload.get("process_name", "") or "")
                urls = payload.get("urls", [])
                if not isinstance(urls, list):
                    self._reply(400, {"error": "urls must be a list of strings"})
                    return
                urls = [str(u) for u in urls if isinstance(u, str) and u.strip()]
                if not urls:
                    self._reply(400, {"error": "Provide at least one URL"})
                    return
                youtube_engine.feed_activity(window_title, process_name, urls)
                self._reply(
                    200,
                    {
                        "status": "accepted",
                        "urls_count": len(urls),
                    },
                )

            def do_POST(self):
                path = self.path.rstrip("/")
                if path not in ("/domains", "/youtube"):
                    self._reply(404, {"error": "Use POST /domains or POST /youtube"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 1 or length > API_MAX_BODY_BYTES:
                        self._reply(
                            413,
                            {
                                "error": f"Body must be between 1 and {API_MAX_BODY_BYTES} bytes",
                            },
                        )
                        return
                    payload = json.loads(self.rfile.read(length).decode("utf-8"))
                    if not isinstance(payload, dict):
                        self._reply(400, {"error": "Expected a JSON object"})
                        return
                    if path == "/domains":
                        self._handle_domains(payload)
                    else:
                        self._handle_youtube(payload)
                except (ValueError, UnicodeDecodeError, json.JSONDecodeError) as exc:
                    self._reply(400, {"error": f"Invalid request: {exc}"})
                except Exception as exc:
                    log_callback(f"[API] Request error: {exc}")
                    telemetry.enqueue_event("api_error", {"error": str(exc)})
                    self._reply(500, {"error": "Internal server error"})

            def log_message(self, fmt, *args):
                logging.info("[API] " + fmt, *args)

        try:
            self.server = ThreadingHTTPServer((self.host, self.requested_port), Handler)
            self.server.daemon_threads = True
            self.port = self.server.server_address[1]
            self.thread = threading.Thread(
                target=self.server.serve_forever, name="DominionDeck-API", daemon=True
            )
            self.thread.start()
            self.log_callback(
                f"[API] Listening on http://{self.host}:{self.port} (GET /health, POST /domains, POST /youtube)."
            )
            self.telemetry.enqueue_event(
                "api_start",
                {
                    "host": self.host,
                    "port": self.port,
                },
            )
            return self.port
        except OSError as exc:
            self.log_callback(
                f"[API] Could not start on {self.host}:{self.requested_port}: {exc}"
            )
            self.telemetry.enqueue_event("api_start_error", {"error": str(exc)})
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


class DriveGuardian:
    """
    Monitors disk I/O and flags suspicious spikes that might feel like
    “external scanning” of drives (e.g., lights constantly active).
    Uses psutil if available; otherwise, stays dormant.
    """

    def __init__(self, telemetry: TelemetryEngine, log_callback):
        self.telemetry = telemetry
        self.log_callback = log_callback
        self.enabled = DRIVE_GUARDIAN_ENABLED and psutil is not None
        self.thread = None
        self.baseline: List[float] = []
        self.last_sample_ts = None
        self._last_io_total = None
        self._last_alert_ts = 0.0

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [DRIVE] {msg}"
        logging.info(line)
        self.log_callback(line)
        self.telemetry.enqueue_event("drive_log", {"message": msg})

    def _sample_io(self) -> float:
        if psutil is None:
            return 0.0
        try:
            io = psutil.disk_io_counters()
            total = float(io.read_bytes + io.write_bytes)
            previous = self._last_io_total
            self._last_io_total = total
            return 0.0 if previous is None else max(0.0, total - previous)
        except Exception:
            return 0.0

    def _update_baseline(self, value: float):
        self.baseline.append(value)
        now = time.time()
        if self.last_sample_ts is None:
            self.last_sample_ts = now
        window = DRIVE_GUARDIAN_BASELINE_WINDOW
        if len(self.baseline) > window:
            self.baseline = self.baseline[-window:]

    def _baseline_stats(self) -> Tuple[float, float]:
        if not self.baseline:
            return 0.0, 0.0
        avg = sum(self.baseline) / len(self.baseline)
        var = sum((x - avg) ** 2 for x in self.baseline) / max(1, len(self.baseline))
        std = var ** 0.5
        return avg, std

    def _loop(self):
        while True:
            try:
                val = self._sample_io()
                avg, std = self._baseline_stats()
                enough_history = len(self.baseline) >= 10
                threshold = max(avg * DRIVE_GUARDIAN_SPIKE_FACTOR, avg + 3.0 * std, 1_000_000.0)
                now = time.time()
                if enough_history and val > threshold and now - self._last_alert_ts >= 30:
                    self._last_alert_ts = now
                    ratio = val / max(threshold, 1.0)
                    self.log(
                        f"Drive I/O surge: {val:.0f} bytes/sample vs learned threshold {threshold:.0f} (x{ratio:.1f}); investigate if unexpected."
                    )
                    self.telemetry.enqueue_event(
                        "drive_spike",
                        {
                            "current_bytes_per_sample": val,
                            "baseline_avg": avg,
                            "baseline_std": std,
                            "threshold": threshold,
                            "severity_score": min(100, int(50 + 10 * ratio)),
                        },
                    )
                self._update_baseline(val)
                time.sleep(DRIVE_GUARDIAN_INTERVAL_SECONDS)
            except Exception:
                time.sleep(DRIVE_GUARDIAN_INTERVAL_SECONDS)

    def start(self):
        if not self.enabled:
            self.log("Drive Guardian disabled (psutil missing or feature disabled).")
            return
        self.thread = threading.Thread(
            target=self._loop, name="DominionDeck-DriveGuardian", daemon=True
        )
        self.thread.start()
        self.log("Drive Guardian started (monitoring disk I/O for suspicious spikes).")


class AnomalyEngine:
    """
    Predictive anomaly detector:
    Learns baseline of system metrics (CPU, disk I/O) and flags unusual spikes.
    """

    def __init__(self, telemetry: TelemetryEngine, log_callback):
        self.telemetry = telemetry
        self.log_callback = log_callback
        self.enabled = ANOMALY_ENGINE_ENABLED and psutil is not None
        self.thread = None
        self.cpu_baseline: List[float] = []
        self.io_baseline: List[float] = []
        self._last_io_total = None
        self._last_cpu_alert_ts = 0.0
        self._last_io_alert_ts = 0.0

    def log(self, msg: str):
        ts = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        line = f"[{ts}] [ANOMALY] {msg}"
        logging.info(line)
        self.log_callback(line)
        self.telemetry.enqueue_event("anomaly_log", {"message": msg})

    def _sample_metrics(self) -> Tuple[float, float]:
        if psutil is None:
            return 0.0, 0.0
        try:
            cpu = float(psutil.cpu_percent(interval=0.2))
        except Exception:
            cpu = 0.0
        try:
            io = psutil.disk_io_counters()
            total = float(io.read_bytes + io.write_bytes)
            previous = self._last_io_total
            self._last_io_total = total
            io_val = 0.0 if previous is None else max(0.0, total - previous)
        except Exception:
            io_val = 0.0
        return cpu, io_val

    def _update_baseline(self, cpu: float, io: float):
        self.cpu_baseline.append(cpu)
        self.io_baseline.append(io)
        window = ANOMALY_BASELINE_WINDOW
        if len(self.cpu_baseline) > window:
            self.cpu_baseline = self.cpu_baseline[-window:]
        if len(self.io_baseline) > window:
            self.io_baseline = self.io_baseline[-window:]

    def _stats(self, data: List[float]) -> Tuple[float, float]:
        if not data:
            return 0.0, 0.0
        avg = sum(data) / len(data)
        var = sum((x - avg) ** 2 for x in data) / max(1, len(data))
        std = var ** 0.5
        return avg, std

    def _loop(self):
        while True:
            try:
                cpu, io_val = self._sample_metrics()
                cpu_avg, cpu_std = self._stats(self.cpu_baseline)
                io_avg, io_std = self._stats(self.io_baseline)
                now = time.time()
                if len(self.cpu_baseline) >= 10:
                    cpu_threshold = max(cpu_avg * ANOMALY_SPIKE_FACTOR, cpu_avg + 3.0 * cpu_std, 25.0)
                    if cpu > cpu_threshold and now - self._last_cpu_alert_ts >= 30:
                        self._last_cpu_alert_ts = now
                        severity = min(100, int(40 + (cpu - cpu_threshold) * 2))
                        self.log(
                            f"CPU surge: {cpu:.1f}% vs learned threshold {cpu_threshold:.1f}% (severity {severity}/100)."
                        )
                        self.telemetry.enqueue_event(
                            "anomaly_cpu_spike",
                            {
                                "current": cpu,
                                "baseline_avg": cpu_avg,
                                "baseline_std": cpu_std,
                                "threshold": cpu_threshold,
                                "severity_score": severity,
                            },
                        )
                if len(self.io_baseline) >= 10:
                    io_threshold = max(io_avg * ANOMALY_SPIKE_FACTOR, io_avg + 3.0 * io_std, 1_000_000.0)
                    if io_val > io_threshold and now - self._last_io_alert_ts >= 30:
                        self._last_io_alert_ts = now
                        ratio = io_val / max(io_threshold, 1.0)
                        severity = min(100, int(50 + 10 * ratio))
                        self.log(
                            f"Disk I/O surge: {io_val:.0f} bytes/sample vs threshold {io_threshold:.0f} (severity {severity}/100)."
                        )
                        self.telemetry.enqueue_event(
                            "anomaly_io_spike",
                            {
                                "current_bytes_per_sample": io_val,
                                "baseline_avg": io_avg,
                                "baseline_std": io_std,
                                "threshold": io_threshold,
                                "severity_score": severity,
                            },
                        )
                self._update_baseline(cpu, io_val)
                time.sleep(3)
            except Exception:
                time.sleep(3)

    def start(self):
        if not self.enabled:
            self.log("Anomaly Engine disabled (psutil missing or feature disabled).")
            return
        self.thread = threading.Thread(
            target=self._loop, name="DominionDeck-AnomalyEngine", daemon=True
        )
        self.thread.start()
        self.log("Anomaly Engine started (learning baseline and flagging unusual spikes).")


class DominionDeckGUI:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("780x560")
        self.root.minsize(600, 420)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        self.status_var = tk.StringVar(value="Initializing…")
        self.profile_var = tk.StringVar(value="STRICT")
        self.sinkhole_ip_var = tk.StringVar(value=DEFAULT_SINKHOLE_IP)
        self.network_share_var = tk.StringVar(value=str(BORG_SHARE_PATH or ""))
        self.network_share_status_var = tk.StringVar(
            value="No network share selected — Borg sync is idle."
        )
        self.blocklist_path_var = tk.StringVar(value=str(BLOCKLIST_EXPORT_DEFAULT))
        self.auto_hosts_backup_sync_var = tk.BooleanVar(value=False)
        self.auto_apply_learned_var = tk.BooleanVar(value=False)
        self._last_applied_domain_digest = ""
        self._last_auto_hosts_backup_hash = ""
        self._auto_hosts_sync_busy = False

        self.telemetry = TelemetryEngine()
        self.telemetry.start()

        self._build_ui()

        cfg = FirewallConfig()
        self.firewall = DomainFirewall(cfg, ml_classifier=DomainMLClassifier())
        self.hosts_manager = HostsManager(
            self.firewall,
            self._append_log,
            sinkhole_ip_getter=lambda: self.sinkhole_ip_var.get(),
            telemetry=self.telemetry,
        )

        self.borg_sync = BorgSync(self.firewall, self._append_log, telemetry=self.telemetry)
        self.shield = MalvertisingShield(self.firewall, self._append_log, telemetry=self.telemetry)
        self.mapper_bot = MapperBot(self.firewall, self.telemetry, self._append_log)
        self.threat_intel = ThreatIntelSwarm(self.firewall, self.telemetry, self._append_log)
        self.news_sentinel = NewsSentinel(self.firewall, self.telemetry, self._append_log)
        self.universal_scanner = UniversalScanner(self.firewall, self.telemetry, self._append_log)

        self.drive_guardian = DriveGuardian(self.telemetry, self._append_log)
        self.anomaly_engine = AnomalyEngine(self.telemetry, self._append_log)

        # YouTube + extra detection engines
        self.auto_lab_buffer: List[str] = []
        self.youtube_engine = YouTubeDetectionEngine(
            self.firewall, self.telemetry, self._append_log, auto_lab_feed=self.auto_lab_feed
        )
        self.process_scanner = ProcessScannerEngine(
            self.firewall, self.telemetry, self._append_log
        )

        self._load_app_config()
        self._seed_learning()
        self.firewall.import_dynamic(self._current_blocklist_path())

        self._append_log("DominionDeck v17.1 initialized.")
        self._append_log("System-wide predictive ad firewall using hosts file.")
        self._append_log("Auto-elevation attempted at startup.")
        self._append_log(f"Profile: {self.firewall.cfg.profile}")
        self._append_log(f"Sinkhole/redirect IP: {self.sinkhole_ip_var.get()}")
        self._append_log(
            f"Borg share path: {BORG_SHARE_PATH}"
            if BORG_SHARE_PATH
            else "Borg share path: not selected (sync idle; no network path will be accessed)."
        )
        self._append_log("[SHIELD] Malvertising behavior heuristics active.")
        self._append_log(
            "[Risk Engine] Stable domain scoring enabled; evidence shown in Threat Review. Scores do not accumulate across repeated scans."
        )
        self._append_log(
            "[Telemetry] SQLite active; optional Redis/ZeroMQ availability is reported by startup checks."
        )
        self._append_log("[Mapper] Web terrain Mapper Bot enabled.")
        self._append_log("[Threat] Threat Intel Swarm enabled (known bad hosts/IPs).")
        self._append_log("[News] Global News Sentinel enabled (worldwide security/AI news watcher).")
        self._append_log(
            "[Universal] Universal Scanner Engine enabled (threats + news + ads + corporate)."
        )
        self._append_log("[Drive] Drive Guardian enabled (disk I/O spike monitoring).")
        self._append_log("[Anomaly] Anomaly Engine enabled (baseline learning + spike detection).")
        self._append_log(
            "[YouTube] Integration ready – external detector can POST /youtube to Auto-Lab API."
        )
        self._append_log(
            "[Process] Process Scanner Engine enabled (psutil-based connection harvesting)."
        )
        self._append_log(
            f"[Blocklist] Export/import path: {self._current_blocklist_path()} (user-selectable backup)."
        )

        self.root.after(800, self._auto_apply)
        self._schedule_periodic_apply()
        self._schedule_auto_hosts_backup_sync()
        self._schedule_auto_apply_learned()
        self._schedule_suspicious_refresh()
        self._schedule_borg_sync()
        self._schedule_telemetry_refresh()
        self._schedule_auto_lab()

        self.api = None
        if API_ENABLED:
            self.api = LocalLabAPI(
                self.firewall,
                self._append_log,
                telemetry=self.telemetry,
                youtube_engine=self.youtube_engine,
            )
            self.api.start()

        self.mapper_bot.start()
        self.threat_intel.start()
        self.news_sentinel.start()
        self.universal_scanner.start()
        self.drive_guardian.start()
        self.anomaly_engine.start()
        self.process_scanner.start()

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=6)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 4))
        ttk.Label(
            header, text=APP_NAME, font=("Segoe UI", 12, "bold")
        ).pack(side="left", anchor="w")
        ttk.Label(
            header,
            text="Universal Sentinel • Firewall • Borg • Telemetry • YouTube",
            font=("Segoe UI", 8),
        ).pack(side="right", anchor="e")

        status_frame = ttk.Frame(outer, padding=(6, 4))
        status_frame.pack(fill="x", pady=(0, 5))
        ttk.Label(status_frame, text="Status:").pack(side="left")
        ttk.Label(
            status_frame, textvariable=self.status_var, font=("Segoe UI", 9, "bold")
        ).pack(side="left", padx=(5, 0), fill="x", expand=True)

        notebook = ttk.Notebook(outer)
        notebook.pack(fill="both", expand=True)

        # Network share tab
        network_tab = ttk.Frame(notebook, padding=8)
        notebook.add(network_tab, text="Network Share")
        share_frame = ttk.LabelFrame(
            network_tab, text="Shared Borg Collective Folder", padding=8
        )
        share_frame.pack(fill="x", anchor="n")
        ttk.Label(
            share_frame,
            text="Select the same existing shared folder on each PC. No share is touched until selected.",
            wraplength=560,
        ).grid(row=0, column=0, columnspan=3, sticky="w", pady=(0, 7))
        ttk.Label(share_frame, text="Folder / blocklist:").grid(row=1, column=0, sticky="w")
        ttk.Entry(share_frame, textvariable=self.network_share_var).grid(
            row=1, column=1, sticky="ew", padx=6
        )
        ttk.Button(
            share_frame, text="Browse…", command=self._browse_network_share
        ).grid(row=1, column=2)
        ttk.Button(
            share_frame, text="Save / Connect", command=self._save_network_share
        ).grid(row=2, column=1, sticky="w", padx=6, pady=(8, 0))
        ttk.Button(
            share_frame, text="Disconnect", command=self._disconnect_network_share
        ).grid(row=2, column=2, sticky="e", pady=(8, 0))
        share_frame.columnconfigure(1, weight=1)
        ttk.Label(
            network_tab, textvariable=self.network_share_status_var, wraplength=580
        ).pack(fill="x", anchor="w", pady=(10, 0))
        ttk.Label(
            network_tab,
            text=r"Tip: UNC paths (\\SERVER\Share) are usually more reliable than mapped drive letters across different accounts. Every PC needs read/write permission.",
            wraplength=580,
        ).pack(fill="x", anchor="w", pady=(8, 0))

        # Firewall controls tab
        controls_tab = ttk.Frame(notebook, padding=8)
        notebook.add(controls_tab, text="Firewall Controls")
        options_frame = ttk.LabelFrame(
            controls_tab, text="Protection Profile & Manual Rules", padding=8
        )
        options_frame.pack(fill="x", anchor="n")
        ttk.Label(options_frame, text="Profile:").grid(row=0, column=0, sticky="w")
        profile_combo = ttk.Combobox(
            options_frame,
            textvariable=self.profile_var,
            values=["STRICT", "BALANCED", "RELAXED"],
            state="readonly",
            width=11,
        )
        profile_combo.grid(row=0, column=1, sticky="w", padx=6)
        profile_combo.bind("<<ComboboxSelected>>", self._on_profile_change)
        ttk.Label(options_frame, text="Sinkhole / Redirect IP:").grid(
            row=1, column=0, sticky="w", pady=(7, 0)
        )
        ttk.Entry(options_frame, textvariable=self.sinkhole_ip_var, width=18).grid(
            row=1, column=1, sticky="w", padx=6, pady=(7, 0)
        )
        ttk.Label(
            options_frame,
            text="0.0.0.0 blocks; 127.0.0.1 or a custom IP redirects.",
            wraplength=280,
        ).grid(row=1, column=2, sticky="w", padx=5, pady=(7, 0))
        ttk.Label(options_frame, text="Manual domain:").grid(
            row=2, column=0, sticky="w", pady=(9, 0)
        )
        self.manual_domain_var = tk.StringVar()
        ttk.Entry(options_frame, textvariable=self.manual_domain_var).grid(
            row=2, column=1, sticky="ew", padx=6, pady=(9, 0)
        )
        ttk.Button(
            options_frame, text="Add & Learn", command=self._manual_add
        ).grid(row=2, column=2, sticky="ew", padx=3, pady=(9, 0))
        ttk.Button(
            options_frame, text="Remove Dynamic", command=self._manual_remove
        ).grid(row=3, column=2, sticky="ew", padx=3, pady=(5, 0))
        options_frame.columnconfigure(1, weight=1)

        # Blocklist path controls (DominionDeck Ad Firewall v7.11-style backup selection)
        blocklist_frame = ttk.LabelFrame(
            controls_tab, text="Blocklist Backup Location (Export / Import)", padding=8
        )
        blocklist_frame.pack(fill="x", anchor="n", pady=(8, 4))
        ttk.Label(blocklist_frame, text="Backup file path:").grid(row=0, column=0, sticky="w")
        ttk.Entry(blocklist_frame, textvariable=self.blocklist_path_var).grid(
            row=0, column=1, sticky="ew", padx=6
        )
        ttk.Button(
            blocklist_frame, text="Browse…", command=self._browse_blocklist_path
        ).grid(row=0, column=2, sticky="w")
        ttk.Label(
            blocklist_frame,
            text="Choose where DominionDeck Ad Firewall v7.11-style backup file lives (e.g., shared drive).",
            wraplength=420,
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(6, 0))
        blocklist_frame.columnconfigure(1, weight=1)

        file_buttons = ttk.Frame(controls_tab)
        file_buttons.pack(fill="x", pady=8)
        ttk.Button(
            file_buttons, text="Export Blocklist", command=self._export_blocklist
        ).pack(side="left")
        ttk.Button(
            file_buttons, text="Import Blocklist", command=self._import_blocklist
        ).pack(side="left", padx=5)
        ttk.Button(file_buttons, text="Apply Now", command=self._manual_apply).pack(
            side="left"
        )
        ttk.Button(
            file_buttons, text="Firewall Snapshot", command=self.show_firewall_snapshot
        ).pack(side="left", padx=5)
        # Separate controls for the hosts backup. Never overwrite the original
        # hosts.dominiondeck.backup when exporting a plain domain blocklist.
        hosts_backup_frame = ttk.LabelFrame(
            controls_tab, text="Hosts Backup Blocklist (hosts.dominiondeck.backup)", padding=8
        )
        hosts_backup_frame.pack(fill="x", anchor="n", pady=(2, 5))
        ttk.Label(
            hosts_backup_frame,
            text="Export the active dynamic domains to a separate .txt file, or import domains from a hosts backup / blocklist file.",
            wraplength=580,
        ).pack(anchor="w")
        hosts_backup_buttons = ttk.Frame(hosts_backup_frame)
        hosts_backup_buttons.pack(fill="x", pady=(6, 0))
        ttk.Button(
            hosts_backup_buttons,
            text="Export Blocklist Copy…",
            command=self._export_hosts_backup_blocklist,
        ).pack(side="left")
        ttk.Button(
            hosts_backup_buttons,
            text="Import from Hosts Backup…",
            command=self._import_hosts_backup_blocklist,
        ).pack(side="left", padx=5)
        ttk.Button(
            hosts_backup_buttons,
            text="Restore System Hosts from Backup…",
            command=self._restore_system_hosts_from_backup,
        ).pack(side="left", padx=5)
        ttk.Checkbutton(
            hosts_backup_frame,
            text="Automatically apply new learned blocks (proactive mode)",
            variable=self.auto_apply_learned_var,
            command=self._toggle_auto_apply_learned,
        ).pack(anchor="w", pady=(7, 0))
        ttk.Label(
            hosts_backup_frame,
            text="When enabled, new domains that pass the selected STRICT / BALANCED / RELAXED scoring profile are applied to the managed DominionDeck section within about 10 seconds. Manual and imported rules are included. Review the Activity Log and Threat Review for evidence.",
            wraplength=580,
        ).pack(anchor="w", pady=(3, 0))
        ttk.Checkbutton(
            hosts_backup_frame,
            text="Auto-sync backup changes into Windows hosts (preserve other entries)",
            variable=self.auto_hosts_backup_sync_var,
            command=self._toggle_auto_hosts_backup_sync,
        ).pack(anchor="w", pady=(7, 0))
        ttk.Label(
            hosts_backup_frame,
            text="When checked, DominionDeck checks the backup every 10 seconds. If it changes, the app merges its non-DominionDeck host mappings with existing non-managed entries, saves a timestamped safety copy, then reapplies the current blocklist. It does not blindly replace the whole hosts file.",
            wraplength=580,
        ).pack(anchor="w", pady=(3, 0))
        ttk.Label(
            controls_tab,
            text="System-wide hosts-file changes may require administrator privileges. The original hosts backup is preserved.",
            wraplength=580,
        ).pack(anchor="w", pady=(5, 0))

        # Activity log tab
        activity_tab = ttk.Frame(notebook, padding=6)
        notebook.add(activity_tab, text="Activity Log")
        log_frame = ttk.LabelFrame(activity_tab, text="Live Activity", padding=5)
        log_frame.pack(fill="both", expand=True)
        self.log_text = tk.Text(
            log_frame,
            height=10,
            wrap="word",
            state="disabled",
            font=("Consolas", 8),
        )
        scrollbar = ttk.Scrollbar(
            log_frame, orient="vertical", command=self.log_text.yview
        )
        self.log_text.configure(yscrollcommand=scrollbar.set)
        self.log_text.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Threat review tab
        suspicious_tab = ttk.Frame(notebook, padding=6)
        notebook.add(suspicious_tab, text="Threat Review")
        suspicious_frame = ttk.LabelFrame(
            suspicious_tab,
            text="Top Suspicious Domains • Stable Heuristic Risk + Evidence",
            padding=5,
        )
        suspicious_frame.pack(fill="both", expand=True)
        self.suspicious_list = tk.Text(
            suspicious_frame,
            height=12,
            wrap="none",
            state="disabled",
            font=("Consolas", 8),
        )
        suspicious_scroll = ttk.Scrollbar(
            suspicious_frame, orient="vertical", command=self.suspicious_list.yview
        )
        self.suspicious_list.configure(yscrollcommand=suspicious_scroll.set)
        self.suspicious_list.pack(side="left", fill="both", expand=True)
        suspicious_scroll.pack(side="right", fill="y")

        # Ad Analysis Lab tab
        lab_tab = ttk.Frame(notebook, padding=6)
        notebook.add(lab_tab, text="Ad Analysis Lab")
        lab_frame = ttk.LabelFrame(
            lab_tab, text="Paste Ad URLs, HTML, or Snippets", padding=6
        )
        lab_frame.pack(fill="both", expand=True)
        self.lab_text = tk.Text(
            lab_frame,
            height=10,
            wrap="word",
            font=("Consolas", 8),
        )
        lab_scroll = ttk.Scrollbar(
            lab_frame, orient="vertical", command=self.lab_text.yview
        )
        self.lab_text.configure(yscrollcommand=lab_scroll.set)
        self.lab_text.pack(side="left", fill="both", expand=True)
        lab_scroll.pack(side="right", fill="y")
        lab_buttons = ttk.Frame(lab_tab)
        lab_buttons.pack(fill="x", pady=(6, 0))
        ttk.Button(
            lab_buttons, text="Analyze & Learn Hosts", command=self._lab_analyze
        ).pack(side="left")
        ttk.Label(
            lab_buttons,
            text="Extracts host-like tokens; review learned hosts before applying.",
            wraplength=340,
        ).pack(side="left", padx=8)

        # Telemetry summary tab
        telemetry_tab = ttk.Frame(notebook, padding=6)
        notebook.add(telemetry_tab, text="Telemetry Summary")
        self.telemetry_hosts_applied_var = tk.StringVar(value="0")
        self.telemetry_dynamic_count_var = tk.StringVar(value="0")
        self.telemetry_last_apply_var = tk.StringVar(value="N/A")
        self.telemetry_borg_push_var = tk.StringVar(value="0")
        self.telemetry_borg_pull_var = tk.StringVar(value="0")
        self.telemetry_mapper_scans_var = tk.StringVar(value="0")
        self.telemetry_threat_scans_var = tk.StringVar(value="0")
        self.telemetry_news_scans_var = tk.StringVar(value="0")
        self.telemetry_universal_scans_var = tk.StringVar(value="0")
        self.telemetry_process_scans_var = tk.StringVar(value="0")
        self.telemetry_youtube_events_var = tk.StringVar(value="0")
        summary = ttk.LabelFrame(telemetry_tab, text="Runtime Counters", padding=8)
        summary.pack(fill="x", anchor="n")
        summary_items = [
            ("Hosts apply events", self.telemetry_hosts_applied_var),
            ("Dynamic domains", self.telemetry_dynamic_count_var),
            ("Last apply", self.telemetry_last_apply_var),
            ("Borg pushes", self.telemetry_borg_push_var),
            ("Borg pulls", self.telemetry_borg_pull_var),
            ("Mapper scans", self.telemetry_mapper_scans_var),
            ("Threat intel scans", self.telemetry_threat_scans_var),
            ("News sentinel scans", self.telemetry_news_scans_var),
            ("Universal scanner scans", self.telemetry_universal_scans_var),
            ("Process scanner scans", self.telemetry_process_scans_var),
            ("YouTube events", self.telemetry_youtube_events_var),
        ]
        for i, (label, variable) in enumerate(summary_items):
            r, c = divmod(i, 2)
            ttk.Label(summary, text=label + ":").grid(
                row=r, column=c * 2, sticky="w", padx=(0, 5), pady=3
            )
            ttk.Label(
                summary,
                textvariable=variable,
                font=("Segoe UI", 9, "bold"),
            ).grid(row=r, column=c * 2 + 1, sticky="w", padx=(0, 12), pady=3)
        summary.columnconfigure(1, weight=1)
        summary.columnconfigure(3, weight=1)

        # System events tab
        events_tab = ttk.Frame(notebook, padding=6)
        notebook.add(events_tab, text="System Events")
        drive_anomaly_frame = ttk.LabelFrame(
            events_tab, text="Drive Guardian & Anomaly Events", padding=5
        )
        drive_anomaly_frame.pack(fill="both", expand=True)
        self.telemetry_events_text = tk.Text(
            drive_anomaly_frame,
            height=12,
            wrap="none",
            state="disabled",
            font=("Consolas", 8),
        )
        telemetry_scroll = ttk.Scrollbar(
            drive_anomaly_frame, orient="vertical", command=self.telemetry_events_text.yview
        )
        self.telemetry_events_text.configure(yscrollcommand=telemetry_scroll.set)
        self.telemetry_events_text.pack(side="left", fill="both", expand=True)
        telemetry_scroll.pack(side="right", fill="y")

    def _current_blocklist_path(self) -> Path:
        raw = self.blocklist_path_var.get().strip()
        if not raw:
            return BLOCKLIST_EXPORT_DEFAULT
        try:
            return Path(raw)
        except Exception:
            return BLOCKLIST_EXPORT_DEFAULT

    def _load_app_config(self):
        global BORG_SHARE_PATH
        try:
            if APP_CONFIG_FILE.exists():
                data = json.loads(APP_CONFIG_FILE.read_text(encoding="utf-8"))
                saved_share = str(data.get("network_share", "")).strip()
                if saved_share:
                    BORG_SHARE_PATH = Path(saved_share)
                    self.network_share_var.set(saved_share)
                    self.network_share_status_var.set(
                        "Saved share configured. It will be checked only when Borg sync runs."
                    )
                saved_profile = str(data.get("profile", "STRICT")).strip().upper()
                if saved_profile in ("STRICT", "BALANCED", "RELAXED"):
                    self.profile_var.set(saved_profile)
                saved_ip = str(
                    data.get("sinkhole_ip", DEFAULT_SINKHOLE_IP)
                ).strip()
                try:
                    ipaddress.ip_address(saved_ip)
                    self.sinkhole_ip_var.set(saved_ip)
                except ValueError:
                    self.sinkhole_ip_var.set(DEFAULT_SINKHOLE_IP)
                saved_blocklist = str(
                    data.get("blocklist_path", str(BLOCKLIST_EXPORT_DEFAULT))
                ).strip()
                if saved_blocklist:
                    self.blocklist_path_var.set(saved_blocklist)
                self.auto_hosts_backup_sync_var.set(
                    bool(data.get("auto_hosts_backup_sync", False))
                )
                self.auto_apply_learned_var.set(
                    bool(data.get("auto_apply_learned", False))
                )
                self._last_applied_domain_digest = str(data.get("last_applied_domain_digest", ""))
                self._last_auto_hosts_backup_hash = str(
                    data.get("last_auto_hosts_backup_hash", "")
                )
        except Exception:
            pass

    def _write_app_config(self):
        try:
            APP_CONFIG_FILE.write_text(
                json.dumps(
                    {
                        "network_share": str(BORG_SHARE_PATH or ""),
                        "profile": self.profile_var.get().strip().upper(),
                        "sinkhole_ip": self.sinkhole_ip_var.get().strip(),
                        "blocklist_path": self.blocklist_path_var.get().strip(),
                        "auto_hosts_backup_sync": bool(self.auto_hosts_backup_sync_var.get()),
                        "auto_apply_learned": bool(self.auto_apply_learned_var.get()),
                        "last_applied_domain_digest": self._last_applied_domain_digest,
                        "last_auto_hosts_backup_hash": self._last_auto_hosts_backup_hash,
                    },
                    indent=2,
                ),
                encoding="utf-8",
            )
        except OSError as exc:
            self._append_log(f"[CONFIG] Could not save settings: {exc}")

    def _browse_network_share(self):
        from tkinter import filedialog
        chosen = filedialog.askdirectory(
            title="Choose an existing shared network folder",
            mustexist=True,
        )
        if chosen:
            self.network_share_var.set(chosen)

    def _save_network_share(self):
        global BORG_SHARE_PATH
        raw = self.network_share_var.get().strip().strip('"')
        if not raw:
            self._disconnect_network_share()
            return
        candidate = Path(raw)
        try:
            if not candidate.exists():
                messagebox.showwarning(
                    "Network share unavailable",
                    "That folder/file is not currently reachable. Check the network path and permissions, "
                    "then try again. The previous setting has been kept.",
                )
                self.network_share_status_var.set("Not connected: selected path is not reachable.")
                return
            if not candidate.is_dir() and not (
                candidate.is_file() and candidate.suffix.lower() == ".txt"
            ):
                messagebox.showwarning(
                    "Invalid share",
                    "Choose an existing folder or an existing .txt blocklist file.",
                )
                return
        except OSError as exc:
            messagebox.showwarning(
                "Network share unavailable", f"Could not access that path: {exc}"
            )
            self.network_share_status_var.set("Not connected: path access failed.")
            return
        BORG_SHARE_PATH = candidate
        self._write_app_config()
        share_file = borg_share_file()
        self.network_share_status_var.set(
            f"Configured: {candidate}\nCollective file: {share_file}\n"
            "Borg will sync only while this location is reachable."
        )
        self._append_log(f"[BORG] Network collective configured: {candidate}")
        self.telemetry.enqueue_event(
            "borg_share_configured", {"path": str(candidate)}
        )

    def _disconnect_network_share(self):
        global BORG_SHARE_PATH
        BORG_SHARE_PATH = None
        self.network_share_var.set("")
        self._write_app_config()
        self.network_share_status_var.set(
            "Disconnected — Borg sync is idle. No network path will be accessed."
        )
        self._append_log(
            "[BORG] Network share disconnected; collective sync disabled until selected."
        )

    def _browse_blocklist_path(self):
        from tkinter import filedialog
        chosen = filedialog.asksaveasfilename(
            title="Choose DominionDeck Ad Firewall backup file",
            defaultextension=".txt",
            filetypes=[("Text files", "*.txt"), ("All files", "*.*")],
        )
        if chosen:
            self.blocklist_path_var.set(chosen)
            self._write_app_config()
            self._append_log(
                f"[BLOCKLIST] Backup path set to: {chosen} (used for export/import)."
            )

    def _append_log(self, line: str):
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
        try:
            ipaddress.ip_address(self.sinkhole_ip_var.get().strip())
        except ValueError:
            self._set_status(
                "Invalid sinkhole IP — correct it in Firewall Controls before applying."
            )
            self._append_log(
                "[FIREWALL] Startup apply skipped: invalid sinkhole/redirect IP."
            )
            return
        self._set_status("Applying blocklist to hosts file…")
        self.hosts_manager.apply_blocklist()
        self._set_status("Active – system-wide predictive blocking in effect.")

    def _manual_apply(self):
        raw_ip = self.sinkhole_ip_var.get().strip()
        try:
            ipaddress.ip_address(raw_ip)
        except ValueError:
            messagebox.showwarning(
                "Invalid redirect IP",
                "Enter a valid IPv4 or IPv6 address, such as 0.0.0.0 or 127.0.0.1.",
            )
            return
        self._set_status("Manual apply requested…")
        self.hosts_manager.apply_blocklist()
        self._set_status("Active – system-wide predictive blocking in effect.")

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
        self._write_app_config()
        self._append_log(f"Profile changed to: {profile}")
        self._set_status(f"Profile: {profile} – heuristic + ML threshold adjusted.")

    def _manual_add(self):
        raw_host = self.manual_domain_var.get().strip()
        host = normalize_domain(raw_host)
        if not host:
            messagebox.showwarning(
                "Invalid domain",
                "Enter a valid DNS hostname, such as ads.example.com. URLs, IP addresses, and paths are not accepted here.",
            )
            return
        self.firewall.learn_domain(host, context="manual", manual=True)
        self._append_log(f"Manually added & learned domain: {host}")
        self._set_status("Manual domain learned; will be included if score exceeds threshold.")

    def _manual_remove(self):
        host = normalize_domain(self.manual_domain_var.get().strip())
        if not host:
            messagebox.showwarning(
                "Invalid domain", "Enter a valid DNS hostname to remove."
            )
            return
        self.firewall.remove_domain(host)
        self._append_log(
            f"Manually removed domain from dynamic blocklist: {host}"
        )
        self._set_status("Manual domain removed from dynamic blocklist.")

    def _export_blocklist(self):
        path = self._current_blocklist_path()
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.firewall.export_dynamic(path)
            if not path.exists():
                raise OSError("export file was not created")
            self._append_log(f"Exported dynamic blocklist to: {path}")
            self._set_status(f"Dynamic blocklist exported ({path.name}).")
        except Exception as exc:
            self._append_log(f"[BLOCKLIST] Export failed: {exc}")
            messagebox.showerror("Blocklist export failed", str(exc))

    def _import_blocklist(self):
        path = self._current_blocklist_path()
        try:
            if not path.is_file():
                messagebox.showwarning("Blocklist not found", f"File does not exist:\n{path}")
                return
            before = len(self.firewall.snapshot()["dynamic"])
            self.firewall.import_dynamic(path)
            added = len(self.firewall.snapshot()["dynamic"]) - before
            self._append_log(f"Imported dynamic blocklist from: {path} ({max(0, added)} new domains)")
            self._set_status(f"Dynamic blocklist imported ({max(0, added)} new domains).")
        except Exception as exc:
            self._append_log(f"[BLOCKLIST] Import failed: {exc}")
            messagebox.showerror("Blocklist import failed", str(exc))

    def _export_hosts_backup_blocklist(self):
        """Export active dynamic domains beside the hosts backup, without touching the backup."""
        from tkinter import filedialog
        default_path = HOSTS_PATH.with_name("hosts.dominiondeck.blocklist.txt")
        chosen = filedialog.asksaveasfilename(
            title="Export DominionDeck blocklist copy",
            initialdir=str(default_path.parent),
            initialfile=default_path.name,
            defaultextension=".txt",
            filetypes=[("Text blocklists", "*.txt"), ("All files", "*.*")],
        )
        if not chosen:
            return
        path = Path(chosen)
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            self.firewall.export_dynamic(path)
            if not path.is_file():
                raise OSError("export file was not created")
            count = len([line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()])
            self._append_log(f"[BLOCKLIST] Exported {count} dynamic domains to {path}; hosts backup left unchanged.")
            self._set_status(f"Exported {count} domains to {path.name}.")
            messagebox.showinfo("Blocklist exported", f"Exported {count} domains to:\n{path}\n\nThe original hosts.dominiondeck.backup was not changed.")
        except Exception as exc:
            self._append_log(f"[BLOCKLIST] Backup-copy export failed: {exc}")
            messagebox.showerror("Blocklist export failed", str(exc))

    def _import_hosts_backup_blocklist(self):
        """Import domains from a hosts-format backup or a plain one-domain-per-line list."""
        from tkinter import filedialog
        default_path = HOSTS_PATH.with_name("hosts.dominiondeck.backup")
        chosen = filedialog.askopenfilename(
            title="Import domains from hosts.dominiondeck.backup or a blocklist",
            initialdir=str(default_path.parent),
            initialfile=default_path.name,
            filetypes=[("Hosts / text blocklists", "*.backup *.txt *.hosts *.*"), ("All files", "*.*")],
        )
        if not chosen:
            return
        path = Path(chosen)
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            candidates = set()
            skipped_local = {"localhost", "localhost.localdomain", "broadcasthost", "ip6-localhost", "ip6-loopback"}
            for raw in lines:
                line = raw.strip()
                if not line or line.startswith(("#", ";")):
                    continue
                # Accept either hosts-file records (IP followed by hostnames) or
                # plain blocklist entries. Strip inline comments first.
                line = line.split("#", 1)[0].strip()
                if not line:
                    continue
                fields = line.split()
                if len(fields) >= 2:
                    try:
                        ipaddress.ip_address(fields[0])
                        fields = fields[1:]
                    except ValueError:
                        pass
                for token in fields:
                    host = normalize_domain(token)
                    if host and host not in skipped_local and "." in host:
                        candidates.add(host)
            if not candidates:
                messagebox.showwarning("No domains found", f"No valid domain entries were found in:\n{path}")
                return
            before = len(self.firewall.snapshot()["dynamic"])
            for host in sorted(candidates):
                self.firewall.learn_domain(host, context=f"imported from {path.name}", manual=True)
            after = len(self.firewall.snapshot()["dynamic"])
            added = max(0, after - before)
            self._append_log(f"[BLOCKLIST] Imported {len(candidates)} valid domains from {path} ({added} new dynamic entries).")
            self._set_status(f"Imported {len(candidates)} domains from {path.name}.")
            messagebox.showinfo(
                "Blocklist imported",
                f"Read {len(candidates)} valid domain(s) from:\n{path}\n\nNew dynamic entries: {added}.\n\nUse Apply Now to apply the current firewall rules to the Windows hosts file.",
            )
        except Exception as exc:
            self._append_log(f"[BLOCKLIST] Hosts-backup import failed: {exc}")
            messagebox.showerror("Blocklist import failed", str(exc))

    def _toggle_auto_hosts_backup_sync(self):
        """Persist the checkbox and immediately check the backup when enabled."""
        enabled = bool(self.auto_hosts_backup_sync_var.get())
        self._write_app_config()
        if enabled:
            self._append_log(
                "[HOSTS AUTO-SYNC] Enabled: checking hosts.dominiondeck.backup every 10 seconds; "
                "the system hosts file will update only when backup contents change."
            )
            self._auto_sync_hosts_backup_once()
        else:
            self._append_log("[HOSTS AUTO-SYNC] Disabled by user.")
        self._set_status(
            "Hosts backup auto-sync enabled." if enabled else "Hosts backup auto-sync disabled."
        )

    def _schedule_auto_hosts_backup_sync(self):
        """Poll via Tk's event loop; no extra worker thread touches the GUI."""
        def tick():
            try:
                if self.auto_hosts_backup_sync_var.get():
                    self._auto_sync_hosts_backup_once()
            except Exception as exc:
                self._append_log(f"[HOSTS AUTO-SYNC] Check failed: {exc}")
            finally:
                try:
                    self.root.after(10000, tick)
                except tk.TclError:
                    pass
        self.root.after(10000, tick)

    def _auto_sync_hosts_backup_once(self):
        """Merge changed backup baseline with current unmanaged entries, then reapply rules.

        Never blindly replace the entire hosts file: preserve unrelated entries and the
        current DominionDeck dynamic/static blocklist. A timestamped safety copy is made
        before any write, and the source digest is remembered only after verification.
        """
        if self._auto_hosts_sync_busy:
            return
        backup_path = HOSTS_PATH.with_name("hosts.dominiondeck.backup")
        if not backup_path.is_file() or not HOSTS_PATH.is_file():
            return
        self._auto_hosts_sync_busy = True
        try:
            import hashlib
            backup_bytes = backup_path.read_bytes()
            if not backup_bytes.strip():
                self._append_log("[HOSTS AUTO-SYNC] Backup is empty; ignored.")
                return
            backup_text = backup_bytes.decode("utf-8-sig", errors="replace")
            backup_lines = backup_text.splitlines()
            meaningful = [line.strip() for line in backup_lines if line.strip()]
            if not any(line.startswith("#") or len(line.split()) >= 2 for line in meaningful):
                self._append_log("[HOSTS AUTO-SYNC] Backup format not recognized; ignored.")
                return
            digest = hashlib.sha256(backup_bytes).hexdigest()
            if digest == self._last_auto_hosts_backup_hash:
                return

            current_bytes = HOSTS_PATH.read_bytes()
            current_text = current_bytes.decode("utf-8-sig", errors="replace")

            def unmanaged_lines(text):
                result = []
                in_managed = False
                for line in text.splitlines():
                    stripped = line.strip()
                    if stripped.startswith("# DominionDeck BEGIN"):
                        in_managed = True
                        continue
                    if stripped.startswith("# DominionDeck END"):
                        in_managed = False
                        continue
                    if not in_managed:
                        result.append(line)
                return result

            # Preserve order, comments, and all unrelated mappings from both files.
            merged = []
            seen = set()
            for line in unmanaged_lines(backup_text) + unmanaged_lines(current_text):
                key = line.strip().casefold()
                if key not in seen:
                    seen.add(key)
                    merged.append(line)
            merged_text = "\n".join(merged).rstrip() + "\n"
            if merged_text.encode("utf-8") == current_bytes and digest == self._last_auto_hosts_backup_hash:
                return

            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safety_path = HOSTS_PATH.with_name(f"hosts.before_auto_sync_{stamp}.backup")
            suffix = 1
            while safety_path.exists():
                safety_path = HOSTS_PATH.with_name(f"hosts.before_auto_sync_{stamp}_{suffix}.backup")
                suffix += 1
            safety_path.write_bytes(current_bytes)
            with HOSTS_PATH.open("w", encoding="utf-8", newline="\n") as hosts_file:
                hosts_file.write(merged_text)
            # Reapply the current rules to the dedicated managed section.
            self.hosts_manager.apply_blocklist()
            verified_text = HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
            if "# DominionDeck BEGIN" not in verified_text or "# DominionDeck END" not in verified_text:
                raise OSError("hosts update verification failed; managed block markers are missing")
            self._last_auto_hosts_backup_hash = digest
            self._write_app_config()
            self._append_log(
                f"[HOSTS AUTO-SYNC] Merged changed backup {backup_path}; preserved unrelated mappings, "
                f"reapplied current blocklist; safety copy: {safety_path}."
            )
            self._set_status("Hosts backup changes merged; DominionDeck rules reapplied.")
        except PermissionError:
            self._append_log("[HOSTS AUTO-SYNC] Permission denied. Run as administrator; will retry.")
        except Exception as exc:
            self._append_log(f"[HOSTS AUTO-SYNC] Update failed (will retry): {exc}")
        finally:
            self._auto_hosts_sync_busy = False

    def _toggle_auto_apply_learned(self):
        enabled = bool(self.auto_apply_learned_var.get())
        self._write_app_config()
        if enabled:
            self._append_log(
                "[PROACTIVE] Auto-apply enabled. Newly learned domains that pass the selected profile "
                "will be applied to the managed hosts section on the next check."
            )
            self._auto_apply_learned_once()
        else:
            self._append_log("[PROACTIVE] Auto-apply disabled; learned domains require manual Apply Now.")
        self._set_status("Proactive auto-apply enabled." if enabled else "Proactive auto-apply disabled.")

    def _schedule_auto_apply_learned(self):
        """Use Tk's event loop for periodic digest checks; no GUI access from worker threads."""
        def tick():
            try:
                if self.auto_apply_learned_var.get():
                    self._auto_apply_learned_once()
            except Exception as exc:
                self._append_log(f"[PROACTIVE] Check failed: {exc}")
            finally:
                try:
                    self.root.after(10000, tick)
                except tk.TclError:
                    pass
        self.root.after(10000, tick)

    def _auto_apply_learned_once(self):
        """Apply only when the effective domain set changes; avoid repetitive writes."""
        if not hasattr(self, "hosts_manager"):
            return
        try:
            import hashlib
            domains = self.firewall.all_blocked_domains()
            digest = hashlib.sha256("\n".join(domains).encode("utf-8")).hexdigest()
            if digest == self._last_applied_domain_digest:
                return
            try:
                ipaddress.ip_address(self.sinkhole_ip_var.get().strip())
            except ValueError:
                self._append_log("[PROACTIVE] Invalid sinkhole IP; automatic apply skipped until corrected.")
                return
            self.hosts_manager.apply_blocklist()
            verified_text = HOSTS_PATH.read_text(encoding="utf-8", errors="replace")
            if "# DominionDeck BEGIN" not in verified_text or "# DominionDeck END" not in verified_text:
                raise OSError("hosts apply could not be verified; will retry on the next check")
            self._last_applied_domain_digest = digest
            self._write_app_config()
            self._append_log(f"[PROACTIVE] Applied updated effective blocklist ({len(domains)} domains).")
        except Exception as exc:
            self._append_log(f"[PROACTIVE] Auto-apply failed; will retry: {exc}")

    def _restore_system_hosts_from_backup(self):
        """Restore the Windows hosts file from hosts.dominiondeck.backup.

        A timestamped copy of the current hosts file is created first. This is a
        deliberate restore action and therefore always requires user confirmation.
        """
        backup_path = HOSTS_PATH.with_name("hosts.dominiondeck.backup")
        if not backup_path.is_file():
            messagebox.showwarning(
                "Hosts backup not found",
                f"Could not find the DominionDeck hosts backup:\n{backup_path}\n\n"
                "No changes were made.",
            )
            return
        try:
            backup_bytes = backup_path.read_bytes()
            if not backup_bytes.strip():
                messagebox.showwarning(
                    "Backup is empty",
                    f"The backup file is empty:\n{backup_path}\n\nNo changes were made.",
                )
                return
            # Basic sanity check: a hosts file should contain readable text and
            # at least one hostname/IP mapping or a comment. Preserve bytes exactly.
            decoded = backup_bytes.decode("utf-8-sig", errors="replace")
            meaningful = [line.strip() for line in decoded.splitlines() if line.strip()]
            has_hosts_record = any(
                line.startswith("#") or len(line.split()) >= 2
                for line in meaningful
            )
            if not has_hosts_record:
                messagebox.showwarning(
                    "Backup format not recognized",
                    "The selected backup does not look like a Windows hosts file.\n\n"
                    "No changes were made.",
                )
                return
            if not HOSTS_PATH.is_file():
                messagebox.showerror(
                    "System hosts file not found",
                    f"Could not find the Windows hosts file:\n{HOSTS_PATH}",
                )
                return
            confirmed = messagebox.askyesno(
                "Restore Windows hosts file?",
                "This will replace the current Windows hosts file with the contents of:\n\n"
                f"{backup_path}\n\n"
                "A timestamped safety copy of the current hosts file will be created first.\n\n"
                "Any DominionDeck blocking entries not present in the backup will be removed.\n\n"
                "Continue?",
                icon="warning",
            )
            if not confirmed:
                self._append_log("[HOSTS] Backup restore cancelled by user; no changes made.")
                return

            current_bytes = HOSTS_PATH.read_bytes()
            stamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safety_path = HOSTS_PATH.with_name(f"hosts.before_restore_{stamp}.backup")
            # Never overwrite an existing safety snapshot if called twice in one second.
            suffix = 1
            while safety_path.exists():
                safety_path = HOSTS_PATH.with_name(f"hosts.before_restore_{stamp}_{suffix}.backup")
                suffix += 1
            safety_path.write_bytes(current_bytes)
            HOSTS_PATH.write_bytes(backup_bytes)
            self._append_log(
                f"[HOSTS] Restored Windows hosts file from {backup_path}; "
                f"pre-restore safety copy: {safety_path}."
            )
            self._set_status("Windows hosts file restored from DominionDeck backup.")
            messagebox.showinfo(
                "Hosts file restored",
                f"Windows hosts file restored successfully from:\n{backup_path}\n\n"
                f"Safety copy of the previous hosts file:\n{safety_path}\n\n"
                "If Windows reports access denied, restart DominionDeck with administrator "
                "privileges and try again.",
            )
        except PermissionError:
            self._append_log("[HOSTS] Restore failed: permission denied writing the Windows hosts file.")
            messagebox.showerror(
                "Administrator permission required",
                "Windows denied access to the hosts file. Run DominionDeck as administrator, "
                "then try the restore again. No successful restore was reported.",
            )
        except Exception as exc:
            self._append_log(f"[HOSTS] Restore failed: {exc}")
            messagebox.showerror("Hosts restore failed", str(exc))

    def _lab_analyze(self):
        text = self.lab_text.get("1.0", "end")
        hosts = extract_host_candidates(text)
        if not hosts:
            self._append_log("Ad Lab: no host-like tokens found.")
            self._set_status("Ad Lab: no hosts found.")
            return
        for h in hosts:
            self.firewall.learn_domain(h, context="ad_lab", manual=True)
        self._append_log(
            f"Ad Lab: learned {len(hosts)} host candidates from pasted content."
        )
        self._set_status(
            f"Ad Lab: {len(hosts)} hosts learned; will be enforced on next apply."
        )

    def auto_lab_feed(self, text: str):
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
                    self._append_log(
                        f"Auto-Lab: learned {len(hosts)} host candidates from auto feed."
                    )
            self.root.after(4000, process)

        self.root.after(4000, process)

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

    def _schedule_telemetry_refresh(self):
        def refresh():
            conn = None
            try:
                conn = sqlite3.connect(str(TELEMETRY_DB))
                cur = conn.cursor()
                cur.execute("SELECT COUNT(*) FROM events WHERE type='hosts_apply'")
                hosts_apply_count = cur.fetchone()[0]
                self.telemetry_hosts_applied_var.set(str(hosts_apply_count))

                snap = self.firewall.snapshot()
                self.telemetry_dynamic_count_var.set(str(len(snap["dynamic"])))

                cur.execute(
                    "SELECT ts, payload FROM events WHERE type='hosts_apply' ORDER BY id DESC LIMIT 1"
                )
                row = cur.fetchone()
                if row:
                    self.telemetry_last_apply_var.set(row[0])
                else:
                    self.telemetry_last_apply_var.set("N/A")

                cur.execute("SELECT COUNT(*) FROM events WHERE type='borg_push'")
                borg_push_count = cur.fetchone()[0]
                self.telemetry_borg_push_var.set(str(borg_push_count))

                cur.execute("SELECT COUNT(*) FROM events WHERE type='borg_pull'")
                borg_pull_count = cur.fetchone()[0]
                self.telemetry_borg_pull_var.set(str(borg_pull_count))

                cur.execute("SELECT COUNT(*) FROM events WHERE type='mapper_scan'")
                mapper_scans = cur.fetchone()[0]
                self.telemetry_mapper_scans_var.set(str(mapper_scans))

                cur.execute("SELECT COUNT(*) FROM events WHERE type='threat_intel_scan'")
                threat_scans = cur.fetchone()[0]
                self.telemetry_threat_scans_var.set(str(threat_scans))

                cur.execute("SELECT COUNT(*) FROM events WHERE type='news_sentinel_scan'")
                news_scans = cur.fetchone()[0]
                self.telemetry_news_scans_var.set(str(news_scans))

                cur.execute("SELECT COUNT(*) FROM events WHERE type='universal_scan'")
                universal_scans = cur.fetchone()[0]
                self.telemetry_universal_scans_var.set(str(universal_scans))

                cur.execute("SELECT COUNT(*) FROM events WHERE type='process_scanner_scan'")
                process_scans = cur.fetchone()[0]
                self.telemetry_process_scans_var.set(str(process_scans))

                cur.execute("SELECT COUNT(*) FROM events WHERE type='youtube_activity'")
                youtube_events = cur.fetchone()[0]
                self.telemetry_youtube_events_var.set(str(youtube_events))

                cur.execute(
                    """
                    SELECT ts, type, payload
                    FROM events
                    WHERE type IN (
                        'drive_spike',
                        'anomaly_cpu_spike',
                        'anomaly_io_spike',
                        'drive_log',
                        'anomaly_log'
                    )
                    ORDER BY id DESC LIMIT 80
                """
                )
                rows = cur.fetchall()
                self.telemetry_events_text.configure(state="normal")
                self.telemetry_events_text.delete("1.0", "end")
                for ts, etype, payload in rows:
                    self.telemetry_events_text.insert(
                        "end", f"{ts} [{etype}] {payload}\n"
                    )
                self.telemetry_events_text.configure(state="disabled")
            except Exception:
                pass
            finally:
                if conn:
                    try:
                        conn.close()
                    except Exception:
                        pass
            self.root.after(7000, refresh)

        self.root.after(3000, refresh)

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
            self._write_app_config()
        except Exception:
            pass
        try:
            self.firewall.export_dynamic(self._current_blocklist_path())
        except Exception:
            pass
        try:
            if self.api:
                self.api.stop()
        except Exception:
            pass
        self.root.destroy()


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
    DominionDeckGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()
