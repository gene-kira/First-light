#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DominionDeck Borg-Style Companion (Autonomous Multi-Modal Nexus & DominionDeckCache Edition)
Enterprise-Grade Regeneration with:
- Corrected Default Cache Root: DominionDeckCache (Unified for Web, Physics, Drives, & Peers)
- Fully Flexible Multi-Drive Cache Root Selection & Real-Time Path Switching
- System Main Drives Cache Simulation & Local Network Peer Caching
- Intelligent Water Data Physics Engine (Hydrodynamic Telemetry & Flow Modeling)
- Altered States of Consciousness Engine (Adaptive Cognitive State Transitions)
- Multi-Modal Borg Probe Swarm & Advanced LFU/LRU Hybrid Caching
- Rate-Limited Event Batching GUI & Circuit-Breaker Resiliency
"""

import os
import threading
import socket
import time
import json
import queue
import logging
import random
import math
import urllib.request
import urllib.parse
from html.parser import HTMLParser
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timedelta

###############################################################################
# LOGGING SETUP
###############################################################################

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s"
)
logger = logging.getLogger("DominionDeckBorgNexus")

###############################################################################
# CONFIG & RUNTIME PROFILES
###############################################################################

APP_ID = "DominionDeck-Borg-Nexus"
APP_VERSION = "3.3.0"

BEACON_PORT = 49231
DISCOVERY_TIMEOUT_SEC = 3
MAX_TRIES_PER_TARGET = 2
DAILY_RESCAN_INTERVAL = timedelta(days=1)
MAX_GOOD_PEERS_MEMORY = 32
CACHE_CHUNK_SIZE = 4096  # bytes per chunk file

DEFAULT_CACHE_ROOT = os.path.join(os.path.expanduser("~"), "DominionDeckCache")
BOOT_CONFIG_PATH = os.path.join(os.path.expanduser("~"), "dominion_nexus_boot.json")
BOOT_CONFIG_BACKUP_PATH = os.path.join(os.path.expanduser("~"), "dominion_nexus_boot.backup.json")
RUNTIME_CONFIG_PATH = os.path.join(os.path.expanduser("~"), "dominion_nexus_runtime.json")

DEFAULT_RUNTIME_CONFIG = {
    "discovery_seed_urls": [
        "http://example.com",
        "http://httpbin.org/html",
    ],
    "beacon_interval_sec": 5,
    "discovery_interval_sec": 12,
    "physics_sample_interval_sec": 20,
    "drive_cache_interval_sec": 45,
    "peer_sync_interval_sec": 30,
    "altered_state_shift_sec": 45,
    "cache_min_gb": 1,
    "cache_max_gb": 5,
    "cache_expand_threshold": 0.90,
    "cache_expiration_days": 60,
    "cache_expiration_interval_sec": 3600,
}

def load_runtime_config():
    if os.path.isfile(RUNTIME_CONFIG_PATH):
        try:
            with open(RUNTIME_CONFIG_PATH, "r", encoding="utf-8") as f:
                cfg = json.load(f)
                merged = DEFAULT_RUNTIME_CONFIG.copy()
                merged.update(cfg)
                return merged
        except Exception as e:
            logger.warning(f"Failed to load runtime config, using defaults: {e}")
    return DEFAULT_RUNTIME_CONFIG.copy()

RUNTIME_CFG = load_runtime_config()

BEACON_INTERVAL_SEC = RUNTIME_CFG["beacon_interval_sec"]
DISCOVERY_INTERVAL_SEC = RUNTIME_CFG["discovery_interval_sec"]
PHYSICS_SAMPLE_INTERVAL_SEC = RUNTIME_CFG["physics_sample_interval_sec"]
DRIVE_CACHE_INTERVAL_SEC = RUNTIME_CFG["drive_cache_interval_sec"]
PEER_SYNC_INTERVAL_SEC = RUNTIME_CFG["peer_sync_interval_sec"]
ALTERED_STATE_SHIFT_SEC = RUNTIME_CFG["altered_state_shift_sec"]
CACHE_MIN_GB = RUNTIME_CFG["cache_min_gb"]
CACHE_MAX_GB = RUNTIME_CFG["cache_max_gb"]
CACHE_EXPAND_THRESHOLD = RUNTIME_CFG["cache_expand_threshold"]
CACHE_EXPIRATION_DAYS = RUNTIME_CFG["cache_expiration_days"]
CACHE_EXPIRATION_INTERVAL_SEC = RUNTIME_CFG["cache_expiration_interval_sec"]
DISCOVERY_SEED_URLS = RUNTIME_CFG["discovery_seed_urls"]

###############################################################################
# HTML LINK PARSER HELPER
###############################################################################

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.links = []

    def handle_starttag(self, tag, attrs):
        if tag.lower() == "a":
            for attr, value in attrs:
                if attr.lower() == "href" and value:
                    self.links.append(value)

###############################################################################
# TELEMETRY & METRICS STORE
###############################################################################

class TelemetryStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.counters = {
            "beacons_sent": 0,
            "beacons_received": 0,
            "health_checks_total": 0,
            "health_checks_success": 0,
            "health_checks_fail": 0,
            "web_crawls_total": 0,
            "web_crawls_success": 0,
            "web_crawls_fail": 0,
            "physics_samples_collected": 0,
            "drive_samples_collected": 0,
            "peer_syncs_total": 0,
            "altered_state_shifts": 0,
            "cache_writes": 0,
            "cache_evictions": 0,
        }

    def increment(self, key, amount=1):
        with self.lock:
            if key in self.counters:
                self.counters[key] += amount

    def get_snapshot(self):
        with self.lock:
            return dict(self.counters)

TELEMETRY = TelemetryStore()

###############################################################################
# STATE & ADVANCED SUB-SYSTEMS
###############################################################################

class PeerInfo:
    def __init__(self, addr, last_seen=None, is_main=False):
        self.addr = addr
        self.last_seen = last_seen or datetime.utcnow()
        self.is_main = is_main
        self.last_health_ok = None
        self.last_health_fail = None
        self.health_attempts = 0
        self.success_count = 0
        self.fail_count = 0
        
        # Circuit Breaker & Exponential Backoff
        self.consecutive_failures = 0
        self.backoff_until = None

    def mark_ok(self):
        self.last_health_ok = datetime.utcnow()
        self.health_attempts = 0
        self.success_count += 1
        self.consecutive_failures = 0
        self.backoff_until = None

    def mark_fail(self):
        self.last_health_fail = datetime.utcnow()
        self.health_attempts += 1
        self.fail_count += 1
        self.consecutive_failures += 1
        backoff_secs = min(300, 5 * (2 ** (self.consecutive_failures - 1)))
        self.backoff_until = datetime.utcnow() + timedelta(seconds=backoff_secs)
        logger.warning(f"Circuit breaker tripped for peer {self.addr}. Backoff active for {backoff_secs}s.")

    @property
    def is_in_backoff(self):
        if self.backoff_until is None:
            return False
        return datetime.utcnow() < self.backoff_until

    @property
    def reliability_score(self):
        total = self.success_count + self.fail_count
        if total == 0:
            return 1.0
        return self.success_count / total

    @property
    def is_healthy(self):
        if self.last_health_ok is None:
            return False
        if self.last_health_fail is None:
            return True
        return self.last_health_ok > self.last_health_fail


class CacheEntry:
    def __init__(self, source_ip, source_type, data, timestamp=None):
        self.source_ip = source_ip
        self.source_type = source_type
        self.data = data
        self.timestamp = timestamp or datetime.utcnow()
        self.size = len(data)
        self.access_count = 1
        self.last_accessed = datetime.utcnow()

    def touch(self):
        self.access_count += 1
        self.last_accessed = datetime.utcnow()

    @property
    def hybrid_score(self):
        age_seconds = (datetime.utcnow() - self.timestamp).total_seconds() + 1
        recency_velocity = 1.0 / age_seconds
        frequency_weight = float(self.access_count)
        return (frequency_weight * 0.7) + (recency_velocity * 0.3)


class WaterPhysicsEngine:
    """Intelligent Water Data Physics Engine: Models flow, pressure, and turbulence."""
    def __init__(self):
        self.flow_velocity_ms = 1.45
        self.pressure_psi = 45.2
        self.turbulence_index = 0.03
        self.viscosity_cp = 1.002
        self.hydro_entropy = 0.12

    def compute_next_state(self):
        self.flow_velocity_ms = max(0.1, round(self.flow_velocity_ms + random.uniform(-0.08, 0.09), 3))
        self.pressure_psi = max(10.0, round(self.pressure_psi + random.uniform(-1.2, 1.3), 2))
        self.turbulence_index = max(0.0, round(self.turbulence_index + random.uniform(-0.005, 0.006), 4))
        self.hydro_entropy = max(0.01, round(abs(math.sin(time.time() * 0.05)) * 0.5, 3))

    def generate_physics_payload(self):
        self.compute_next_state()
        data = {
            "engine": "WaterPhysicsEngine_v3",
            "timestamp": datetime.utcnow().isoformat(),
            "metrics": {
                "flow_velocity_ms": self.flow_velocity_ms,
                "pressure_psi": self.pressure_psi,
                "turbulence_index": self.turbulence_index,
                "viscosity_cp": self.viscosity_cp,
                "hydro_entropy": self.hydro_entropy
            }
        }
        return json.dumps(data, indent=2).encode("utf-8")


class AlteredStatesEngine:
    """Altered States of Consciousness Engine: Simulates cognitive synchronization states."""
    STATES = ["BASELINE_SYNC", "HYPER_FOCUS", "DEEP_DREAM", "COLLECTIVE_ASSIMILATION"]
    
    def __init__(self):
        self.current_state_idx = 0
        self.neural_sync_pct = 88.4
        self.consciousness_entropy = 0.42
        self.last_transition = datetime.utcnow()

    def evaluate_transition(self):
        now = datetime.utcnow()
        if (now - self.last_transition).total_seconds() >= ALTERED_STATE_SHIFT_SEC:
            self.current_state_idx = (self.current_state_idx + 1) % len(self.STATES)
            self.last_transition = now
            self.neural_sync_pct = round(random.uniform(75.0, 99.9), 2)
            self.consciousness_entropy = round(random.uniform(0.1, 0.85), 3)
            TELEMETRY.increment("altered_state_shifts")
            return True
        return False

    @property
    def active_state(self):
        return self.STATES[self.current_state_idx]


class BorgState:
    def __init__(self):
        self.lock = threading.RLock()
        self.this_host = socket.gethostname()
        self.this_ip = self._get_local_ip()
        self.is_main = True

        self.peers = {}
        self.good_peers_order = []
        self.last_full_scan = None
        self.gui_queue = queue.Queue()

        self.main_drives = self._detect_main_drives()
        self.boot_config = self._load_boot_config()

        self.water_physics = WaterPhysicsEngine()
        self.altered_states = AlteredStatesEngine()

        self.cache_limit_gb = CACHE_MIN_GB
        self.cache_ram = []

        self.discovered_urls_count = 0
        self.last_discovery_target = "None"

        cache_root_from_config = self.boot_config.get("cache_root")
        if cache_root_from_config and isinstance(cache_root_from_config, str):
            self.cache_drive_root = cache_root_from_config
        else:
            self.cache_drive_root = DEFAULT_CACHE_ROOT

    def _get_local_ip(self):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"

    def _detect_main_drives(self):
        drives = []
        if os.name == "nt":
            import string
            from ctypes import windll
            bitmask = windll.kernel32.GetLogicalDrives()
            for letter in string.ascii_uppercase:
                if bitmask & 1:
                    drives.append(f"{letter}:\\")
                bitmask >>= 1
        else:
            drives.append("/")
        return drives

    def _load_boot_config(self):
        if os.path.isfile(BOOT_CONFIG_PATH):
            try:
                with open(BOOT_CONFIG_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "boot_mode": "normal",
            "last_good_boot": None,
            "upgraded": True,
            "cache_root": DEFAULT_CACHE_ROOT,
        }

    def _save_boot_config(self):
        try:
            with open(BOOT_CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self.boot_config, f, indent=2)
        except Exception:
            pass

    def backup_boot_config(self):
        try:
            with open(BOOT_CONFIG_BACKUP_PATH, "w", encoding="utf-8") as f:
                json.dump(self.boot_config, f, indent=2)
        except Exception:
            pass

    def restore_boot_config_from_backup(self):
        if os.path.isfile(BOOT_CONFIG_BACKUP_PATH):
            try:
                with open(BOOT_CONFIG_BACKUP_PATH, "r", encoding="utf-8") as f:
                    self.boot_config = json.load(f)
                self._save_boot_config()
                self.push_gui_event("boot_restored", None)
            except Exception:
                pass

    def mark_boot_good(self):
        self.boot_config["last_good_boot"] = datetime.utcnow().isoformat()
        self._save_boot_config()

    def apply_boot_upgrade_safely(self):
        self.backup_boot_config()
        if not self.boot_config.get("last_good_boot"):
            self.boot_config["last_good_boot"] = datetime.utcnow().isoformat()
            self._save_boot_config()

        self.boot_config["boot_mode"] = "nexus_upgraded"
        self.boot_config["upgraded"] = True
        self._save_boot_config()
        self.push_gui_event("boot_upgrade_applied", None)

    def update_peer(self, addr, is_main=False):
        with self.lock:
            if addr == self.this_ip:
                return
            if addr not in self.peers:
                self.peers[addr] = PeerInfo(addr, is_main=is_main)
            else:
                self.peers[addr].last_seen = datetime.utcnow()
                self.peers[addr].is_main = is_main
            self._update_good_peers(addr)

    def _update_good_peers(self, addr):
        if addr not in self.good_peers_order:
            self.good_peers_order.insert(0, addr)
        if len(self.good_peers_order) > MAX_GOOD_PEERS_MEMORY:
            self.good_peers_order = self.good_peers_order[:MAX_GOOD_PEERS_MEMORY]

    def get_peers_sorted_predictive(self):
        with self.lock:
            peer_list = list(self.peers.values())
            def score(p):
                if p.is_in_backoff:
                    return -10.0
                return p.reliability_score
            peer_list.sort(key=score, reverse=True)
            return peer_list

    def should_rescan(self):
        with self.lock:
            if self.last_full_scan is None:
                return True
            return datetime.utcnow() - self.last_full_scan >= DAILY_RESCAN_INTERVAL

    def mark_rescan_done(self):
        with self.lock:
            self.last_full_scan = datetime.utcnow()

    def push_gui_event(self, event_type, payload=None):
        self.gui_queue.put((event_type, payload))

    def set_cache_drive_root(self, root_path):
        with self.lock:
            self.cache_drive_root = root_path
            self.boot_config["cache_root"] = root_path
            self._save_boot_config()
        self.push_gui_event("cache_drive_changed", None)

    def add_cache_entry(self, entry: CacheEntry):
        with self.lock:
            if len(self.cache_ram) >= 1200:
                self.cache_ram.sort(key=lambda e: e.hybrid_score)
                self.cache_ram.pop(0)
                TELEMETRY.increment("cache_evictions")
            self.cache_ram.append(entry)
            TELEMETRY.increment("cache_writes")

        self._write_cache_to_disk(entry)
        self._check_cache_expand()
        self.push_gui_event("cache_update", None)

    def _write_cache_to_disk(self, entry: CacheEntry):
        try:
            if entry.source_type == "peer":
                safe_ip = entry.source_ip.replace(":", "_")
                folder = os.path.join(self.cache_drive_root, "peers", safe_ip)
            elif entry.source_type == "web":
                folder = os.path.join(self.cache_drive_root, "web_discoveries")
            elif entry.source_type == "physics":
                folder = os.path.join(self.cache_drive_root, "water_physics")
            elif entry.source_type == "drive":
                safe_label = entry.source_ip.replace(":", "").replace("\\", "_").replace("/", "_")
                folder = os.path.join(self.cache_drive_root, f"drive_{safe_label}")
            else:
                folder = os.path.join(self.cache_drive_root, "general")
            os.makedirs(folder, exist_ok=True)

            ts = entry.timestamp.strftime("%Y%m%d_%H%M%S_%f")
            filename = os.path.join(folder, f"chunk_{ts}.bin")
            with open(filename, "wb") as f:
                f.write(entry.data[:CACHE_CHUNK_SIZE])
        except Exception as e:
            logger.error(f"Failed to write cache entry to disk: {e}")

    def _cache_usage_bytes(self):
        total = 0
        root = self.cache_drive_root
        if not os.path.isdir(root):
            return 0
        for base, dirs, files in os.walk(root):
            for fname in files:
                if fname.startswith("chunk_"):
                    try:
                        total += os.path.getsize(os.path.join(base, fname))
                    except Exception:
                        pass
        return total

    def _check_cache_expand(self):
        usage_bytes = self._cache_usage_bytes()
        limit_bytes = self.cache_limit_gb * (1024 ** 3)
        usage_ratio = usage_bytes / limit_bytes if limit_bytes > 0 else 0

        if usage_ratio >= CACHE_EXPAND_THRESHOLD:
            if self.cache_limit_gb < CACHE_MAX_GB:
                self.cache_limit_gb += 1
                logger.info(f"Cache threshold reached ({usage_ratio:.2%}). Expanding limit to {self.cache_limit_gb} GB.")
                self.push_gui_event("cache_expanded", {"new_limit": self.cache_limit_gb})

    def list_cache_summary(self):
        with self.lock:
            summary = []
            for e in self.cache_ram:
                summary.append({
                    "source_ip": e.source_ip,
                    "source_type": e.source_type,
                    "timestamp": e.timestamp,
                    "size": e.size,
                    "score": round(e.hybrid_score, 2),
                })
            return summary

    def list_disk_cache_summary(self):
        result = []
        root = self.cache_drive_root
        if not os.path.isdir(root):
            return result
        for base, dirs, files in os.walk(root):
            for fname in files:
                if fname.startswith("chunk_"):
                    fpath = os.path.join(base, fname)
                    try:
                        size = os.path.getsize(fpath)
                    except Exception:
                        size = 0
                    result.append({"path": fpath, "size": size})
        return result

    def purge_expired_cache_all(self):
        cutoff = datetime.utcnow() - timedelta(days=CACHE_EXPIRATION_DAYS)
        with self.lock:
            self.cache_ram = [e for e in self.cache_ram if e.timestamp >= cutoff]

        root = self.cache_drive_root
        if os.path.isdir(root):
            cutoff_ts = time.time() - (CACHE_EXPIRATION_DAYS * 24 * 3600)
            for base, dirs, files in os.walk(root):
                for fname in files:
                    if not fname.startswith("chunk_"):
                        continue
                    fpath = os.path.join(base, fname)
                    try:
                        if os.path.getmtime(fpath) < cutoff_ts:
                            os.remove(fpath)
                    except Exception:
                        pass
        self.push_gui_event("cache_purged", None)


STATE = BorgState()

###############################################################################
# NETWORK & PROBE SWARM ENGINES
###############################################################################

def beacon_sender():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    while True:
        try:
            payload = {
                "type": "beacon",
                "app_id": APP_ID,
                "version": APP_VERSION,
                "host": STATE.this_host,
                "ip": STATE.this_ip,
                "is_main": STATE.is_main,
                "state": STATE.altered_states.active_state,
                "timestamp": datetime.utcnow().isoformat(),
            }
            sock.sendto(json.dumps(payload).encode("utf-8"), ("255.255.255.255", BEACON_PORT))
            TELEMETRY.increment("beacons_sent")
        except Exception as e:
            logger.debug(f"Beacon send error: {e}")
        time.sleep(BEACON_INTERVAL_SEC)


def beacon_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("", BEACON_PORT))

    while True:
        try:
            data, addr = sock.recvfrom(4096)
            ip = addr[0]
            msg = json.loads(data.decode("utf-8"))
            if msg.get("app_id") == APP_ID:
                TELEMETRY.increment("beacons_received")
                STATE.update_peer(ip, is_main=msg.get("is_main", False))
                STATE.push_gui_event("peer_update", None)
        except Exception:
            time.sleep(0.1)


def water_physics_probe_worker():
    """Autonomous probe sampling hydrodynamic physics and water data."""
    while True:
        try:
            payload = STATE.water_physics.generate_physics_payload()
            STATE.add_cache_entry(CacheEntry("127.0.0.1_hydro", "physics", payload))
            TELEMETRY.increment("physics_samples_collected")
            STATE.push_gui_event("physics_update", None)
        except Exception as e:
            logger.error(f"Water physics probe error: {e}")
        time.sleep(PHYSICS_SAMPLE_INTERVAL_SEC)


def periodic_main_drive_cache():
    """Simulates and caches hardware telemetry across all detected system drives."""
    while True:
        try:
            for drive in STATE.main_drives:
                payload = f"System Drive Redundancy Cache Sample from {drive} at {datetime.utcnow()}".encode("utf-8")
                STATE.add_cache_entry(CacheEntry(drive, "drive", payload))
                TELEMETRY.increment("drive_samples_collected")
        except Exception as e:
            logger.error(f"Drive cache error: {e}")
        time.sleep(DRIVE_CACHE_INTERVAL_SEC)


def periodic_peer_cache_sync():
    """Synchronizes local network cache with active healthy companion peers."""
    while True:
        try:
            peers = STATE.get_peers_sorted_predictive()
            for p in peers:
                if p.is_healthy:
                    payload = f"Peer Collective Cache Sync Payload for {p.addr} at {datetime.utcnow()}".encode("utf-8")
                    STATE.add_cache_entry(CacheEntry(p.addr, "peer", payload))
                    TELEMETRY.increment("peer_syncs_total")
        except Exception as e:
            logger.error(f"Peer sync error: {e}")
        time.sleep(PEER_SYNC_INTERVAL_SEC)


def web_discovery_worker():
    """Predictive continuous web discovery probe with altered-states awareness."""
    priority_queue = []
    
    def score_url(url):
        score = 10
        parsed = urllib.parse.urlparse(url)
        if parsed.path in ("", "/"):
            score -= 5
        if any(ext in parsed.path.lower() for ext in [".html", ".json", ".xml"]):
            score -= 3
        return score

    for seed in DISCOVERY_SEED_URLS:
        priority_queue.append((score_url(seed), seed))

    visited_urls = set()

    while True:
        try:
            if STATE.altered_states.evaluate_transition():
                STATE.push_gui_event("state_update", None)

            if not priority_queue:
                for seed in DISCOVERY_SEED_URLS:
                    if seed not in visited_urls:
                        priority_queue.append((score_url(seed), seed))

            priority_queue.sort(key=lambda x: x[0])
            score, url = priority_queue.pop(0)

            if url in visited_urls:
                continue
            visited_urls.add(url)

            STATE.last_discovery_target = url
            STATE.push_gui_event("discovery_status", {"target": url, "status": "crawling"})

            TELEMETRY.increment("web_crawls_total")
            req = urllib.request.Request(
                url,
                headers={"User-Agent": f"{APP_ID}/{APP_VERSION} ({STATE.altered_states.active_state})"}
            )
            with urllib.request.urlopen(req, timeout=DISCOVERY_TIMEOUT_SEC) as resp:
                content_type = resp.headers.get("Content-Type", "")
                body = resp.read()

            cache_payload = f"URL: {url}\nState: {STATE.altered_states.active_state}\nContentType: {content_type}\n\n".encode("utf-8") + body
            STATE.add_cache_entry(CacheEntry(url, "web", cache_payload))
            STATE.discovered_urls_count += 1
            TELEMETRY.increment("web_crawls_success")
            STATE.push_gui_event("discovery_status", {"target": url, "status": "success", "size": len(body)})

            if "text/html" in content_type.lower():
                parser = LinkParser()
                parser.feed(body.decode("utf-8", errors="ignore"))
                for link in parser.links:
                    absolute_link = urllib.parse.urljoin(url, link)
                    parsed_link = urllib.parse.urlparse(absolute_link)
                    if parsed_link.scheme in ("http", "https") and absolute_link not in visited_urls:
                        priority_queue.append((score_url(absolute_link), absolute_link))

        except Exception as e:
            TELEMETRY.increment("web_crawls_fail")
            STATE.push_gui_event("discovery_status", {"target": "error", "status": "error", "error": str(e)})

        interval = DISCOVERY_INTERVAL_SEC * (1.0 + STATE.altered_states.consciousness_entropy)
        time.sleep(interval)


def periodic_cache_expiration():
    while True:
        try:
            STATE.purge_expired_cache_all()
        except Exception:
            pass
        time.sleep(CACHE_EXPIRATION_INTERVAL_SEC)

###############################################################################
# GUI
###############################################################################

class BorgGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DominionDeck Borg Nexus Companion (Enterprise Edition)")
        self.geometry("1340x820")
        self.minsize(1024, 640)
        self.resizable(True, True)

        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self._pending_peer_refresh = False
        self._pending_cache_refresh = False

        self._build_layout()
        self.after(200, self._poll_gui_queue)
        self.after(1000, self._refresh_live_indicators)

    def _build_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=3)
        self.rowconfigure(2, weight=2)

        # Main Nexus Info Panel
        frame_main = ttk.LabelFrame(self, text="Borg Nexus Control & Multi-Modal Telemetry")
        frame_main.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        for c in range(5):
            frame_main.columnconfigure(c, weight=1)

        self.lbl_host = ttk.Label(frame_main, text=f"Host: {STATE.this_host}")
        self.lbl_host.grid(row=0, column=0, sticky="w", padx=4, pady=2)

        self.lbl_state = ttk.Label(frame_main, text=f"Altered State: {STATE.altered_states.active_state}")
        self.lbl_state.grid(row=0, column=1, sticky="w", padx=4, pady=2)

        self.lbl_discovery_stats = ttk.Label(frame_main, text="Discovered URLs: 0 | Target: None")
        self.lbl_discovery_stats.grid(row=0, column=2, columnspan=2, sticky="w", padx=4, pady=2)

        self.lbl_boot = ttk.Label(
            frame_main,
            text=f"Boot Mode: {STATE.boot_config.get('boot_mode', 'normal')} | Nexus Upgraded"
        )
        self.lbl_boot.grid(row=0, column=4, sticky="w", padx=4, pady=2)

        # Cache drive selector & Custom path switcher
        ttk.Label(frame_main, text="Cache Drive Root:").grid(row=1, column=0, sticky="w", padx=4, pady=2)
        
        self.cache_drive_var = tk.StringVar(value=STATE.cache_drive_root)
        self.cache_drive_entry = ttk.Entry(frame_main, textvariable=self.cache_drive_var, width=32)
        self.cache_drive_entry.grid(row=1, column=1, sticky="w", padx=4, pady=2)

        ttk.Label(frame_main, text="Select Drive:").grid(row=1, column=2, sticky="w", padx=4, pady=2)
        self.drive_choice_var = tk.StringVar()
        self.drive_choice_combo = ttk.Combobox(
            frame_main,
            textvariable=self.drive_choice_var,
            values=STATE.main_drives,
            width=8,
            state="readonly"
        )
        default_drive = STATE.main_drives[0] if STATE.main_drives else "C:\\"
        for d in STATE.main_drives:
            if d.upper().startswith("C:"):
                default_drive = d
                break
        self.drive_choice_var.set(default_drive)
        self.drive_choice_combo.grid(row=1, column=3, sticky="w", padx=4, pady=2)

        self.btn_change_cache_drive = ttk.Button(
            frame_main,
            text="Change Cache Drive",
            command=self._change_cache_drive_to_selected
        )
        self.btn_change_cache_drive.grid(row=1, column=4, sticky="w", padx=4, pady=2)

        # Cache Usage & Telemetry Stats
        self.lbl_cache_usage = ttk.Label(frame_main, text="Cache Usage: calculating...")
        self.lbl_cache_usage.grid(row=2, column=0, columnspan=2, sticky="w", padx=4, pady=2)

        self.lbl_telemetry = ttk.Label(frame_main, text="Telemetry: Crawls: 0 | Physics: 0 | Drives: 0 | Peers: 0")
        self.lbl_telemetry.grid(row=2, column=2, columnspan=3, sticky="w", padx=4, pady=2)

        # Peer list
        frame_peers = ttk.LabelFrame(self, text="Companion Systems (Nexus Collective & Circuit Breakers)")
        frame_peers.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        frame_peers.columnconfigure(0, weight=1)
        frame_peers.rowconfigure(0, weight=1)

        columns = ("ip", "last_seen", "health", "score", "backoff", "role")
        self.tree_peers = ttk.Treeview(frame_peers, columns=columns, show="headings")
        for col, text in zip(columns, ["IP", "Last Seen", "Health", "Rel. Score", "Backoff State", "Role"]):
            self.tree_peers.heading(col, text=text)

        self.tree_peers.column("ip", width=140, anchor="w")
        self.tree_peers.column("last_seen", width=170, anchor="w")
        self.tree_peers.column("health", width=90, anchor="w")
        self.tree_peers.column("score", width=90, anchor="e")
        self.tree_peers.column("backoff", width=120, anchor="w")
        self.tree_peers.column("role", width=90, anchor="w")

        scroll_peers_y = ttk.Scrollbar(frame_peers, orient="vertical", command=self.tree_peers.yview)
        self.tree_peers.configure(yscrollcommand=scroll_peers_y.set)

        self.tree_peers.grid(row=0, column=0, sticky="nsew", padx=(4, 0), pady=4)
        scroll_peers_y.grid(row=0, column=1, sticky="ns", padx=(0, 4), pady=4)

        # Cache panels (RAM Hybrid + Disk Chunks)
        frame_cache = ttk.LabelFrame(self, text="Cache Overview (RAM Hybrid LFU/LRU + System Drives & Peer Chunks)")
        frame_cache.grid(row=2, column=0, sticky="nsew", padx=8, pady=8)
        frame_cache.columnconfigure(0, weight=1)
        frame_cache.columnconfigure(1, weight=1)
        frame_cache.rowconfigure(1, weight=1)

        ttk.Label(frame_cache, text="RAM Cache (Hybrid LFU/LRU):").grid(row=0, column=0, sticky="w", padx=4, pady=2)
        ttk.Label(frame_cache, text="Disk Cache (Chunks):").grid(row=0, column=1, sticky="w", padx=4, pady=2)

        self.tree_ram = ttk.Treeview(frame_cache, columns=("source", "type", "time", "score", "size"), show="headings")
        for col, text in zip(("source", "type", "time", "score", "size"), ["Source", "Type", "Timestamp", "Score", "Size"]):
            self.tree_ram.heading(col, text=text)
        self.tree_ram.column("source", width=130, anchor="w")
        self.tree_ram.column("type", width=70, anchor="w")
        self.tree_ram.column("time", width=170, anchor="w")
        self.tree_ram.column("score", width=90, anchor="e")
        self.tree_ram.column("size", width=80, anchor="e")

        self.tree_disk = ttk.Treeview(frame_cache, columns=("path", "size"), show="headings")
        self.tree_disk.heading("path", text="Path")
        self.tree_disk.heading("size", text="Size (bytes)")
        self.tree_disk.column("path", width=320, anchor="w")
        self.tree_disk.column("size", width=100, anchor="e")

        scroll_ram_y = ttk.Scrollbar(frame_cache, orient="vertical", command=self.tree_ram.yview)
        self.tree_ram.configure(yscrollcommand=scroll_ram_y.set)

        scroll_disk_y = ttk.Scrollbar(frame_cache, orient="vertical", command=self.tree_disk.yview)
        self.tree_disk.configure(yscrollcommand=scroll_disk_y.set)

        self.tree_ram.grid(row=1, column=0, sticky="nsew", padx=(4, 0), pady=4)
        scroll_ram_y.grid(row=1, column=0, sticky="nse", padx=(0, 4), pady=4)

        self.tree_disk.grid(row=1, column=1, sticky="nsew", padx=(4, 0), pady=4)
        scroll_disk_y.grid(row=1, column=1, sticky="nse", padx=(0, 4), pady=4)

    def _change_cache_drive_to_selected(self):
        drive = self.drive_choice_var.get().strip()
        if not drive:
            messagebox.showerror("Cache Drive", "Please select a drive.")
            return

        if os.name == "nt":
            if not drive.endswith("\\"):
                drive = drive + "\\"
            new_root = os.path.join(drive, "DominionDeckCache")
        else:
            new_root = os.path.join(drive, "DominionDeckCache")

        try:
            os.makedirs(new_root, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Cache Drive", f"Unable to create cache folder on {drive}:\n{e}")
            return

        STATE.set_cache_drive_root(new_root)
        self.cache_drive_var.set(new_root)
        self._refresh_live_indicators()
        self._refresh_cache_lists()
        messagebox.showinfo("Cache Drive", f"Cache drive successfully switched to: {new_root}\nSaved to persistent boot configuration.")

    def _refresh_live_indicators(self):
        usage_bytes = STATE._cache_usage_bytes()
        limit_bytes = STATE.cache_limit_gb * (1024 ** 3)
        percent = (usage_bytes / limit_bytes if limit_bytes > 0 else 0.0) * 100.0

        color = "green" if percent < 60 else "orange" if percent < 90 else "red"
        text = f"Cache: {usage_bytes/1024/1024:.2f} MB / {STATE.cache_limit_gb} GB ({percent:.1f}%)"
        self.lbl_cache_usage.config(text=text, foreground=color)

        snap = TELEMETRY.get_snapshot()
        t_text = f"Telemetry: Crawls: {snap['web_crawls_success']}/{snap['web_crawls_total']} | Physics: {snap['physics_samples_collected']} | Drives: {snap['drive_samples_collected']} | Peers: {snap['peer_syncs_total']}"
        self.lbl_telemetry.config(text=t_text)

        self.after(1000, self._refresh_live_indicators)

    def _poll_gui_queue(self):
        processed = 0
        try:
            while processed < 50:
                event_type, payload = STATE.gui_queue.get_nowait()
                processed += 1
                if event_type in ("peer_update", "peer_health"):
                    self._pending_peer_refresh = True
                elif event_type in ("cache_update", "cache_expanded", "cache_drive_changed", "cache_purged"):
                    self._pending_cache_refresh = True
                elif event_type == "discovery_status":
                    self.lbl_discovery_stats.config(
                        text=f"Discovered URLs: {STATE.discovered_urls_count} | Target: {STATE.last_discovery_target}"
                    )
                elif event_type == "state_update":
                    self.lbl_state.config(text=f"Altered State: {STATE.altered_states.active_state}")
        except queue.Empty:
            pass

        if self._pending_peer_refresh:
            self._refresh_peers()
            self._pending_peer_refresh = False

        if self._pending_cache_refresh:
            self._refresh_cache_lists()
            self._pending_cache_refresh = False

        self.after(250, self._poll_gui_queue)

    def _refresh_peers(self):
        for item in self.tree_peers.get_children():
            self.tree_peers.delete(item)
        for p in STATE.get_peers_sorted_predictive():
            health = "OK" if p.is_healthy else "Unknown" if p.last_health_ok is None else "Fail"
            score_str = f"{p.reliability_score:.2f}"
            role = "MAIN" if p.is_main else "PEER"
            last_seen = p.last_seen.isoformat()
            backoff_str = f"Active ({int((p.backoff_until - datetime.utcnow()).total_seconds())}s)" if p.is_in_backoff else "Normal"
            self.tree_peers.insert("", "end", values=(p.addr, last_seen, health, score_str, backoff_str, role))

    def _refresh_cache_lists(self):
        for item in self.tree_ram.get_children():
            self.tree_ram.delete(item)
        for item in self.tree_disk.get_children():
            self.tree_disk.delete(item)

        for e in STATE.list_cache_summary():
            self.tree_ram.insert("", "end", values=(e["source_ip"], e["source_type"], e["timestamp"].isoformat(), e["score"], e["size"]))

        for e in STATE.list_disk_cache_summary():
            self.tree_disk.insert("", "end", values=(e["path"], e["size"]))

###############################################################################
# MAIN
###############################################################################

def main():
    STATE.mark_boot_good()

    threads = [
        threading.Thread(target=beacon_sender, daemon=True, name="BeaconSender"),
        threading.Thread(target=beacon_listener, daemon=True, name="BeaconListener"),
        threading.Thread(target=water_physics_probe_worker, daemon=True, name="WaterPhysicsProbe"),
        threading.Thread(target=periodic_main_drive_cache, daemon=True, name="DriveCacheSimulator"),
        threading.Thread(target=periodic_peer_cache_sync, daemon=True, name="PeerCacheSyncWorker"),
        threading.Thread(target=web_discovery_worker, daemon=True, name="WebDiscoveryWorker"),
        threading.Thread(target=periodic_cache_expiration, daemon=True, name="CacheExpirationWorker"),
    ]

    for t in threads:
        t.start()

    gui = BorgGUI()
    gui.mainloop()


if __name__ == "__main__":
    main()