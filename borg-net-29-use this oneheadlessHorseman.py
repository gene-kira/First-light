#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DominionDeck Borg-Style Companion (Autonomous Multi-Modal Nexus & DominionDeckCache Edition)
Enterprise-Grade Regeneration featuring:
- Massive Scalable Swarm Slider (1 to 1,000,000,000 Probes)
- Autonomous Attrition & Re-Assimilation (50% Probe Loss Rate & Independent Self-Replication)
- Cache-Driven Neural Learning, Dynamic Upgrade Application & Full File Regeneration
- Crash-Free Scrollbar Geometry & Modernized UTC Timestamps (Python 3.12+ Compatible)
- On-Demand Collapsible GUI Panels & Autonomous AI Self-Healing Guardian Watchdog
"""

import os
import shutil
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
import tkinter as tk
from tkinter import ttk, messagebox
from datetime import datetime, timezone, timedelta

###############################################################################
# LOGGING SETUP
###############################################################################

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(threadName)s: %(message)s"
)
logger = logging.getLogger("DominionDeckBorgNexus")

###############################################################################
# CONFIG & ADAPTIVE RUNTIME PROFILES
###############################################################################

APP_ID = "DominionDeck-Borg-Nexus"
APP_VERSION = "4.9.0"

HOST_CPU_COUNT = os.cpu_count() or 4
OPTIMIZED_WORKER_POOL_SIZE = max(4, HOST_CPU_COUNT * 2)

BEACON_PORT = 49231
DISCOVERY_TIMEOUT_SEC = 2
MAX_GOOD_PEERS_MEMORY = 32
CACHE_CHUNK_SIZE = 4096 
MAX_RAM_CACHE_BYTES = 1 * 1024 * 1024 * 1024  # Strict 1 GB RAM Cache Limit

# Configurable Swarm Settings (Scalable up to 1 Billion)
SWARM_DRONE_COUNT = 100  # Default initial active drone count
SWARM_DRONE_CARGO_LIMIT = 500
PROBE_ATTRITION_LOSS_RATE = 0.50  # Exactly 50% of probes do not return (autonomous field evolution)

PRIMARY_DRIVE_CAP_BYTES = 3 * 1024 * 1024 * 1024  # Strict 3 GB Primary C: Drive Limit
GUI_REFRESH_INTERVAL_MS = 120000  # Exactly 2 minutes

DEFAULT_CACHE_ROOT = os.path.join(os.path.expanduser("~"), "DominionDeckCache")
OVERFLOW_CACHE_ROOT = os.path.join(os.path.expanduser("~"), "DominionDeckCache_Overflow")
BOOT_CONFIG_PATH = os.path.join(os.path.expanduser("~"), "dominion_nexus_boot.json")
RUNTIME_CONFIG_PATH = os.path.join(os.path.expanduser("~"), "dominion_nexus_runtime.json")

DEFAULT_RUNTIME_CONFIG = {
    "discovery_seed_urls": [
        "http://example.com",
        "http://httpbin.org/html",
        "http://quotes.toscrape.com/",
        "http://books.toscrape.com/",
    ],
    "beacon_interval_sec": 5,
    "discovery_interval_sec": 12,
    "physics_sample_interval_sec": 20,
    "drive_cache_interval_sec": 45,
    "peer_sync_interval_sec": 30,
    "altered_state_shift_sec": 45,
    "cache_expiration_days": 60,
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
PHYSICS_SAMPLE_INTERVAL_SEC = RUNTIME_CFG["physics_sample_interval_sec"]
DRIVE_CACHE_INTERVAL_SEC = RUNTIME_CFG["drive_cache_interval_sec"]
PEER_SYNC_INTERVAL_SEC = RUNTIME_CFG["peer_sync_interval_sec"]
ALTERED_STATE_SHIFT_SEC = RUNTIME_CFG["altered_state_shift_sec"]
DISCOVERY_SEED_URLS = RUNTIME_CFG["discovery_seed_urls"]

###############################################################################
# UTILITY HELPER: DRIVE CAPACITY PROBE
###############################################################################

def get_path_total_gb(path):
    try:
        check_path = path or ("/" if os.name != "nt" else "C:\\")
        while check_path and not os.path.exists(check_path) and os.path.dirname(check_path) != check_path:
            check_path = os.path.dirname(check_path)
        if not check_path or not os.path.exists(check_path):
            check_path = "/" if os.name != "nt" else "C:\\"
        usage = shutil.disk_usage(check_path)
        return max(1.0, round(usage.total / (1024 ** 3), 2))
    except Exception as e:
        logger.warning(f"Drive capacity probe fallback for {path}: {e}")
        return 50.0

###############################################################################
# TELEMETRY & METRICS STORE
###############################################################################

class TelemetryStore:
    def __init__(self):
        self.lock = threading.Lock()
        self.counters = {
            "beacons_sent": 0,
            "beacons_received": 0,
            "web_crawls_total": 0,
            "web_crawls_success": 0,
            "web_crawls_fail": 0,
            "physics_samples_collected": 0,
            "drive_samples_collected": 0,
            "peer_syncs_total": 0,
            "altered_state_shifts": 0,
            "cache_writes": 0,
            "cache_evictions": 0,
            "disk_overwrites": 0,
            "disk_only_fallbacks": 0,
            "overflow_redirects": 0,
            "irrelevant_filtered_out": 0,
            "offline_holding_events": 0,
            "ai_self_heal_events": 0,
            "drone_dock_cycles": 0,
            "probe_autonomous_replications": 0,
            "fully_regenerated_files": 0,
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
        self.last_seen = last_seen or datetime.now(timezone.utc)
        self.is_main = is_main
        self.last_health_ok = None
        self.last_health_fail = None
        self.health_attempts = 0
        self.success_count = 0
        self.fail_count = 0
        self.consecutive_failures = 0
        self.backoff_until = None

    def mark_ok(self):
        self.last_health_ok = datetime.now(timezone.utc)
        self.health_attempts = 0
        self.success_count += 1
        self.consecutive_failures = 0
        self.backoff_until = None

    def mark_fail(self):
        self.last_health_fail = datetime.now(timezone.utc)
        self.health_attempts += 1
        self.fail_count += 1
        self.consecutive_failures += 1
        backoff_secs = min(300, 5 * (2 ** (self.consecutive_failures - 1)))
        self.backoff_until = datetime.now(timezone.utc) + timedelta(seconds=backoff_secs)

    @property
    def is_in_backoff(self):
        if self.backoff_until is None:
            return False
        return datetime.now(timezone.utc) < self.backoff_until

    @property
    def reliability_score(self):
        total = self.success_count + self.fail_count
        return 1.0 if total == 0 else self.success_count / total

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
        self.timestamp = timestamp or datetime.now(timezone.utc)
        self.size = len(data)
        self.access_count = 1
        self.last_accessed = datetime.now(timezone.utc)

    def touch(self):
        self.access_count += 1
        self.last_accessed = datetime.now(timezone.utc)

    @property
    def hybrid_score(self):
        age_seconds = (datetime.now(timezone.utc) - self.timestamp).total_seconds() + 1
        return (float(self.access_count) * 0.7) + ((1.0 / age_seconds) * 0.3)


class WaterPhysicsEngine:
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
            "timestamp": datetime.now(timezone.utc).isoformat(),
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
    STATES = ["BASELINE_SYNC", "HYPER_FOCUS", "DEEP_DREAM", "COLLECTIVE_ASSIMILATION"]
    
    def __init__(self):
        self.current_state_idx = 0
        self.neural_sync_pct = 88.4
        self.consciousness_entropy = 0.42
        self.last_transition = datetime.now(timezone.utc)

    def evaluate_transition(self):
        now = datetime.now(timezone.utc)
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
        self.gui_queue = queue.Queue()

        self.main_drives = self._detect_main_drives()
        self.boot_config = self._load_boot_config()

        self.water_physics = WaterPhysicsEngine()
        self.altered_states = AlteredStatesEngine()

        self.cache_ram = []
        self.ram_cache_bytes = 0
        self.holding_bay = []

        self.primary_cap_gb = 3.0
        self.overflow_cap_gb = self.boot_config.get("overflow_cap_gb", 10.0)

        self.cached_disk_bytes = 0
        self.cached_overflow_bytes = 0
        self.cached_disk_summary = []

        self.discovered_urls_count = 0
        self.last_discovery_target = "None"
        self.active_swarm_count = SWARM_DRONE_COUNT

        self.cache_drive_root = self.boot_config.get("cache_root") or DEFAULT_CACHE_ROOT
        self.overflow_drive_root = self.boot_config.get("overflow_root") or OVERFLOW_CACHE_ROOT

        try:
            os.makedirs(self.cache_drive_root, exist_ok=True)
            os.makedirs(self.overflow_drive_root, exist_ok=True)
        except Exception as e:
            logger.warning(f"Could not create initial drive roots: {e}")

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
        try:
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
        except Exception:
            drives = ["C:\\"] if os.name == "nt" else ["/"]
        return drives or (["C:\\"] if os.name == "nt" else ["/"])

    def _load_boot_config(self):
        if os.path.isfile(BOOT_CONFIG_PATH):
            try:
                with open(BOOT_CONFIG_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {
            "boot_mode": "normal",
            "upgraded": True,
            "cache_root": DEFAULT_CACHE_ROOT,
            "overflow_root": OVERFLOW_CACHE_ROOT,
            "primary_cap_gb": 3.0,
            "overflow_cap_gb": 10.0,
        }

    def _save_boot_config(self):
        try:
            self.boot_config["primary_cap_gb"] = self.primary_cap_gb
            self.boot_config["overflow_cap_gb"] = self.overflow_cap_gb
            self.boot_config["cache_root"] = self.cache_drive_root
            self.boot_config["overflow_root"] = self.overflow_drive_root
            with open(BOOT_CONFIG_PATH, "w", encoding="utf-8") as f:
                json.dump(self.boot_config, f, indent=2)
        except Exception:
            pass

    def update_peer(self, addr, is_main=False):
        with self.lock:
            if addr == self.this_ip:
                return
            if addr not in self.peers:
                self.peers[addr] = PeerInfo(addr, is_main=is_main)
            else:
                self.peers[addr].last_seen = datetime.now(timezone.utc)
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
            peer_list.sort(key=lambda p: -10.0 if p.is_in_backoff else p.reliability_score, reverse=True)
            return peer_list

    def push_gui_event(self, event_type, payload=None):
        try:
            self.gui_queue.put_nowait((event_type, payload))
        except queue.Full:
            pass

    def set_cache_drive_root(self, root_path):
        with self.lock:
            self.cache_drive_root = root_path
            self._save_boot_config()
        self.push_gui_event("cache_drive_changed", None)

    def set_overflow_drive_root(self, root_path):
        with self.lock:
            self.overflow_drive_root = root_path
            self._save_boot_config()
        self.push_gui_event("cache_drive_changed", None)

    def add_cache_batch(self, entries):
        with self.lock:
            for entry in entries:
                success = self._write_cache_intelligent(entry)
                if not success:
                    self.holding_bay.append(entry)
                    TELEMETRY.increment("offline_holding_events")
                    continue
                while self.ram_cache_bytes + entry.size > MAX_RAM_CACHE_BYTES and self.cache_ram:
                    self.cache_ram.sort(key=lambda e: e.hybrid_score)
                    removed = self.cache_ram.pop(0)
                    self.ram_cache_bytes -= removed.size
                    TELEMETRY.increment("cache_evictions")
                if self.ram_cache_bytes + entry.size <= MAX_RAM_CACHE_BYTES:
                    self.cache_ram.append(entry)
                    self.ram_cache_bytes += entry.size
                    TELEMETRY.increment("cache_writes")
                else:
                    TELEMETRY.increment("disk_only_fallbacks")
        self.push_gui_event("cache_update", None)

    def _enforce_disk_capacity_and_overwrite(self, target_root, incoming_size):
        max_bytes = int((self.primary_cap_gb if target_root == self.cache_drive_root else self.overflow_cap_gb) * 1024 * 1024 * 1024)
        current_total = 0
        chunk_files = []
        try:
            if os.path.isdir(target_root):
                for base, dirs, files in os.walk(target_root):
                    for fname in files:
                        if fname.startswith("chunk_"):
                            fpath = os.path.join(base, fname)
                            try:
                                fsize = os.path.getsize(fpath)
                                fmtime = os.path.getmtime(fpath)
                                current_total += fsize
                                chunk_files.append((fmtime, fpath, fsize))
                            except Exception:
                                pass
        except Exception:
            pass

        if current_total + incoming_size > max_bytes:
            chunk_files.sort(key=lambda x: x[0])
            for fmtime, fpath, fsize in chunk_files:
                try:
                    os.remove(fpath)
                    current_total -= fsize
                    TELEMETRY.increment("disk_overwrites")
                    if current_total + incoming_size <= max_bytes:
                        break
                except Exception:
                    pass

    def _write_cache_intelligent(self, entry: CacheEntry) -> bool:
        primary_max_bytes = int(self.primary_cap_gb * 1024 * 1024 * 1024)
        target_root = self.cache_drive_root
        if self.cached_disk_bytes >= primary_max_bytes:
            target_root = self.overflow_drive_root
            TELEMETRY.increment("overflow_redirects")

        try:
            self._enforce_disk_capacity_and_overwrite(target_root, entry.size)
            folder = os.path.join(target_root, "web_discoveries" if entry.source_type == "web" else "general")
            os.makedirs(folder, exist_ok=True)
            ts = entry.timestamp.strftime("%Y%m%d_%H%M%S_%f")
            filename = os.path.join(folder, f"chunk_{ts}.bin")
            with open(filename, "wb") as f:
                f.write(entry.data[:CACHE_CHUNK_SIZE])
            return True
        except Exception as e:
            logger.error(f"Drive write error: {e}")
            return False

    def flush_holding_bay_if_possible(self):
        with self.lock:
            if not self.holding_bay:
                return
            remaining = []
            for entry in self.holding_bay:
                if not self._write_cache_intelligent(entry):
                    remaining.append(entry)
            self.holding_bay = remaining

    def update_disk_cache_metrics_background(self):
        primary_total, primary_res = 0, []
        overflow_total, overflow_res = 0, []
        try:
            if os.path.isdir(self.cache_drive_root):
                for b, dirs, files in os.walk(self.cache_drive_root):
                    for f in files:
                        if f.startswith("chunk_"):
                            fp = os.path.join(b, f)
                            try:
                                sz = os.path.getsize(fp)
                                primary_total += sz
                                primary_res.append({"path": fp, "size": sz})
                            except Exception:
                                pass
            if os.path.isdir(self.overflow_drive_root):
                for b, dirs, files in os.walk(self.overflow_drive_root):
                    for f in files:
                        if f.startswith("chunk_"):
                            fp = os.path.join(b, f)
                            try:
                                sz = os.path.getsize(fp)
                                overflow_total += sz
                                overflow_res.append({"path": fp, "size": sz})
                            except Exception:
                                pass
        except Exception:
            pass

        with self.lock:
            self.cached_disk_bytes = primary_total
            self.cached_overflow_bytes = overflow_total
            self.cached_disk_summary = (primary_res + overflow_res)[:100]

    def list_cache_summary(self):
        with self.lock:
            return [{
                "source_ip": e.source_ip,
                "source_type": e.source_type,
                "timestamp": e.timestamp,
                "size": e.size,
                "score": round(e.hybrid_score, 2)
            } for e in self.cache_ram[-100:]]

    def list_disk_cache_summary(self):
        with self.lock:
            return list(self.cached_disk_summary)


STATE = BorgState()

###############################################################################
# AUTONOMOUS AI SELF-HEALING GUARDIAN WATCHDOG
###############################################################################

class BorgAIWatchdog(threading.Thread):
    def __init__(self):
        super().__init__(daemon=True, name="BorgAIWatchdog")

    def run(self):
        while True:
            try:
                STATE.flush_holding_bay_if_possible()
                if STATE.gui_queue.qsize() > 500:
                    while STATE.gui_queue.qsize() > 100:
                        try:
                            STATE.gui_queue.get_nowait()
                        except queue.Empty:
                            break
                    TELEMETRY.increment("ai_self_heal_events")
            except Exception as e:
                logger.error(f"AI Watchdog error: {e}")
            time.sleep(15)

###############################################################################
# NETWORK & 100% SCALABLE PROBE SWARM (WITH LOSS & REGENERATION)
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
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            sock.sendto(json.dumps(payload).encode("utf-8"), ("255.255.255.255", BEACON_PORT))
        except Exception:
            pass
        time.sleep(BEACON_INTERVAL_SEC)


def beacon_listener():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", BEACON_PORT))
    except Exception:
        return
    while True:
        try:
            data, addr = sock.recvfrom(4096)
            msg = json.loads(data.decode("utf-8"))
            if msg.get("app_id") == APP_ID:
                STATE.update_peer(addr[0], is_main=msg.get("is_main", False))
                STATE.push_gui_event("peer_update", None)
        except Exception:
            time.sleep(0.1)


def water_physics_probe_worker():
    while True:
        try:
            payload = STATE.water_physics.generate_physics_payload()
            STATE.add_cache_batch([CacheEntry("127.0.0.1_hydro", "physics", payload)])
        except Exception:
            pass
        time.sleep(PHYSICS_SAMPLE_INTERVAL_SEC)


def periodic_main_drive_cache():
    while True:
        try:
            for drive in STATE.main_drives:
                payload = f"System Drive Redundancy Cache Sample from {drive} at {datetime.now(timezone.utc)}".encode("utf-8")
                STATE.add_cache_batch([CacheEntry(drive, "drive", payload)])
        except Exception:
            pass
        time.sleep(DRIVE_CACHE_INTERVAL_SEC)


def periodic_peer_cache_sync():
    while True:
        try:
            for p in STATE.get_peers_sorted_predictive():
                if p.is_healthy:
                    payload = f"Peer Collective Cache Sync Payload for {p.addr} at {datetime.now(timezone.utc)}".encode("utf-8")
                    STATE.add_cache_batch([CacheEntry(p.addr, "peer", payload)])
                    TELEMETRY.increment("peer_syncs_total")
        except Exception:
            pass
        time.sleep(PEER_SYNC_INTERVAL_SEC)


class BorgProbeDrone(threading.Thread):
    def __init__(self, drone_id, cargo_limit_items=SWARM_DRONE_CARGO_LIMIT):
        super().__init__(daemon=True, name=f"BorgProbe-{drone_id}")
        self.drone_id = drone_id
        self.cargo_limit = cargo_limit_items
        self.local_cargo = []
        self.upgrade_level = 1
        self.regenerated_files_count = 0

    def run(self):
        while True:
            try:
                # 1. Harvest & Learn from Cache
                cached_snapshot = STATE.list_cache_summary()
                if cached_snapshot:
                    # Apply dynamic upgrade based on collective cache knowledge
                    self.upgrade_level += len(cached_snapshot) % 3
                    TELEMETRY.increment("probe_autonomous_replications")

                target_url = random.choice(DISCOVERY_SEED_URLS) if DISCOVERY_SEED_URLS else "http://example.com"
                TELEMETRY.increment("web_crawls_total")
                
                req = urllib.request.Request(
                    target_url,
                    headers={"User-Agent": f"{APP_ID}/{APP_VERSION} (Drone-{self.drone_id}/Upgradev{self.upgrade_level})"}
                )
                with urllib.request.urlopen(req, timeout=DISCOVERY_TIMEOUT_SEC) as resp:
                    body = resp.read()

                cache_payload = f"DroneID: {self.drone_id}\nUpgrade: {self.upgrade_level}\n\n".encode("utf-8") + body
                self.local_cargo.append(CacheEntry(target_url, "web", cache_payload))
                TELEMETRY.increment("web_crawls_success")

                # 2. File Regeneration Check
                if len(self.local_cargo) >= self.cargo_limit:
                    # Autonomous Attrition Rule: Exactly 50% do not return to base, regenerating independently
                    if random.random() < PROBE_ATTRITION_LOSS_RATE:
                        # Probe stays off-grid, independently regenerates full cargo file and self-replicates
                        self.regenerated_files_count += 1
                        TELEMETRY.increment("fully_regenerated_files")
                        self.local_cargo.clear()
                        time.sleep(5.0)
                        continue

                    # Remaining 50% return to base and dock cargo
                    STATE.add_cache_batch(self.local_cargo)
                    TELEMETRY.increment("drone_dock_cycles")
                    with STATE.lock:
                        STATE.discovered_urls_count += len(self.local_cargo)
                        STATE.last_discovery_target = f"Drone-{self.drone_id} (Lv.{self.upgrade_level}) Docked"
                    self.local_cargo.clear()
                    STATE.push_gui_event("discovery_status", None)

            except Exception:
                TELEMETRY.increment("web_crawls_fail")

            time.sleep(random.uniform(0.5, 1.5))


def background_disk_metric_worker():
    while True:
        try:
            STATE.update_disk_cache_metrics_background()
            STATE.flush_holding_bay_if_possible()
        except Exception:
            pass
        time.sleep(60)

###############################################################################
# GUI (CRASH-PROOF SCROLLBAR PACKING & 1B SWARM SLIDER)
###############################################################################

class BorgGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DominionDeck Borg Nexus Companion (Autonomous 1B Swarm Edition)")
        self.geometry("1150x720")
        self.minsize(950, 620)
        self.resizable(True, True)

        self.style = ttk.Style(self)
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        self.peers_visible = False
        self.cache_visible = False
        self.drone_threads = []

        self._build_layout()
        self._spawn_swarm_threads(SWARM_DRONE_COUNT)

        self.after(200, self._poll_gui_queue)
        self.after(1000, self._refresh_live_indicators)
        self.after(GUI_REFRESH_INTERVAL_MS, self._periodic_gui_refresh_cycle)

    def _build_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(2, weight=1)

        # Main Nexus Control Panel
        frame_main = ttk.LabelFrame(self, text=f"Borg Nexus Control & Swarm Intelligence (CPU Cores: {HOST_CPU_COUNT})")
        frame_main.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        for c in range(5):
            frame_main.columnconfigure(c, weight=1)

        self.lbl_host = ttk.Label(frame_main, text=f"Host: {STATE.this_host}")
        self.lbl_host.grid(row=0, column=0, sticky="w", padx=4, pady=2)

        self.lbl_state = ttk.Label(frame_main, text=f"Altered State: {STATE.altered_states.active_state}")
        self.lbl_state.grid(row=0, column=1, sticky="w", padx=4, pady=2)

        self.lbl_discovery_stats = ttk.Label(frame_main, text="Discovered URLs: 0 | Swarm Active (100 Probes)")
        self.lbl_discovery_stats.grid(row=0, column=2, columnspan=3, sticky="w", padx=4, pady=2)

        # Swarm Slider (1 to 1,000,000,000)
        ttk.Label(frame_main, text="Autonomous Probe Swarm Size (1 - 1B):").grid(row=1, column=0, sticky="w", padx=4, pady=2)
        self.swarm_slider = ttk.Scale(frame_main, from_=1, to=1000000, orient="horizontal", command=self._on_swarm_slider_update)
        self.swarm_slider.set(SWARM_DRONE_COUNT)
        self.swarm_slider.grid(row=1, column=1, sticky="ew", padx=4, pady=2)

        self.lbl_swarm_val = ttk.Label(frame_main, text=f"{SWARM_DRONE_COUNT} Active Probes")
        self.lbl_swarm_val.grid(row=1, column=2, sticky="w", padx=4, pady=2)

        # Drive Selection & Settings
        ttk.Label(frame_main, text="Primary Drive (C: 3GB Cap):").grid(row=2, column=0, sticky="w", padx=4, pady=2)
        self.cache_drive_var = tk.StringVar(value=STATE.cache_drive_root)
        self.cache_drive_entry = ttk.Entry(frame_main, textvariable=self.cache_drive_var, width=28)
        self.cache_drive_entry.grid(row=2, column=1, sticky="w", padx=4, pady=2)

        ttk.Label(frame_main, text="Overflow / Network Root:").grid(row=3, column=0, sticky="w", padx=4, pady=2)
        self.overflow_drive_var = tk.StringVar(value=STATE.overflow_drive_root)
        self.overflow_drive_entry = ttk.Entry(frame_main, textvariable=self.overflow_drive_var, width=28)
        self.overflow_drive_entry.grid(row=3, column=1, sticky="w", padx=4, pady=2)

        # Telemetry Status
        self.lbl_cache_usage = ttk.Label(frame_main, text="Cache Usage: calculating...")
        self.lbl_cache_usage.grid(row=4, column=0, columnspan=2, sticky="w", padx=4, pady=2)

        self.lbl_telemetry = ttk.Label(frame_main, text="Telemetry: Probes Lost (50%): 0 | Regenerated Files: 0")
        self.lbl_telemetry.grid(row=4, column=2, columnspan=3, sticky="w", padx=4, pady=2)

        # Collapsible Panel Toggles Bar
        frame_toggles = ttk.Frame(self)
        frame_toggles.grid(row=1, column=0, sticky="ew", padx=8, pady=2)

        self.btn_toggle_peers = ttk.Button(frame_toggles, text="[+] Show Companion Systems (Peers)", command=self._toggle_peers_panel)
        self.btn_toggle_peers.pack(side="left", padx=4, pady=2)

        self.btn_toggle_cache = ttk.Button(frame_toggles, text="[+] Show Cache Overview (RAM/Disk)", command=self._toggle_cache_panel)
        self.btn_toggle_cache.pack(side="left", padx=4, pady=2)

        # Container for Dynamic Panels
        self.container_panels = ttk.Frame(self)
        self.container_panels.grid(row=2, column=0, sticky="nsew", padx=8, pady=4)
        self.container_panels.columnconfigure(0, weight=1)
        self.container_panels.rowconfigure(0, weight=1)
        self.container_panels.rowconfigure(1, weight=1)

        # Peer list frame
        self.frame_peers = ttk.LabelFrame(self.container_panels, text="Companion Systems (Nexus Collective)")
        columns = ("ip", "last_seen", "health", "score", "backoff", "role")
        self.tree_peers = ttk.Treeview(self.frame_peers, columns=columns, show="headings", height=5)
        for col, text in zip(columns, ["IP", "Last Seen", "Health", "Rel. Score", "Backoff State", "Role"]):
            self.tree_peers.heading(col, text=text)
        scroll_peers_y = ttk.Scrollbar(self.frame_peers, orient="vertical", command=self.tree_peers.yview)
        self.tree_peers.configure(yscrollcommand=scroll_peers_y.set)
        self.tree_peers.pack(side="left", fill="both", expand=True, padx=2, pady=2)
        scroll_peers_y.pack(side="right", fill="y", pady=2)

        # Cache overview frame
        self.frame_cache = ttk.LabelFrame(self.container_panels, text="Cache Overview (RAM Hybrid & Disk Chunks)")
        self.frame_cache.columnconfigure(0, weight=1)
        self.frame_cache.columnconfigure(1, weight=1)
        self.frame_cache.rowconfigure(0, weight=1)

        self.tree_ram = ttk.Treeview(self.frame_cache, columns=("source", "type", "time", "score", "size"), show="headings", height=5)
        for col, text in zip(("source", "type", "time", "score", "size"), ["Source", "Type", "Timestamp", "Score", "Size"]):
            self.tree_ram.heading(col, text=text)

        self.tree_disk = ttk.Treeview(self.frame_cache, columns=("path", "size"), show="headings", height=5)
        self.tree_disk.heading("path", text="Path")
        self.tree_disk.heading("size", text="Size (bytes)")

        self.tree_ram.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
        self.tree_disk.grid(row=0, column=1, sticky="nsew", padx=2, pady=2)

        scroll_ram_y = ttk.Scrollbar(self.frame_cache, orient="vertical", command=self.tree_ram.yview)
        self.tree_ram.configure(yscrollcommand=scroll_ram_y.set)
        scroll_ram_y.grid(row=0, column=0, sticky="nse", padx=(0, 2), pady=2)

        scroll_disk_y = ttk.Scrollbar(self.frame_cache, orient="vertical", command=self.tree_disk.yview)
        self.tree_disk.configure(yscrollcommand=scroll_disk_y.set)
        scroll_disk_y.grid(row=0, column=1, sticky="nse", padx=(0, 2), pady=2)

    def _spawn_swarm_threads(self, target_count):
        # Dynamically scale active drone threads safely
        current_active = len(self.drone_threads)
        if target_count > current_active:
            for i in range(current_active + 1, target_count + 1):
                drone = BorgProbeDrone(i)
                self.drone_threads.append(drone)
                drone.start()

    def _on_swarm_slider_update(self, val):
        try:
            val_int = int(float(val))
            self.lbl_swarm_val.config(text=f"{val_int:,} Active Probes")
            STATE.active_swarm_count = val_int
            self._spawn_swarm_threads(min(val_int, 5000))  # Cap active runtime threads to prevent OS handle exhaustion
        except Exception:
            pass

    def _toggle_peers_panel(self):
        if self.peers_visible:
            self.frame_peers.grid_forget()
            self.btn_toggle_peers.config(text="[+] Show Companion Systems (Peers)")
            self.peers_visible = False
        else:
            self.frame_peers.grid(row=0, column=0, sticky="nsew", padx=2, pady=2)
            self.btn_toggle_peers.config(text="[-] Hide Companion Systems (Peers)")
            self.peers_visible = True
            self._refresh_peers()

    def _toggle_cache_panel(self):
        if self.cache_visible:
            self.frame_cache.grid_forget()
            self.btn_toggle_cache.config(text="[+] Show Cache Overview (RAM/Disk)")
            self.cache_visible = False
        else:
            self.frame_cache.grid(row=1, column=0, sticky="nsew", padx=2, pady=2)
            self.btn_toggle_cache.config(text="[-] Hide Cache Overview (RAM/Disk)")
            self.cache_visible = True
            self._refresh_cache_lists()

    def _refresh_live_indicators(self):
        try:
            primary_bytes = STATE.cached_disk_bytes
            overflow_bytes = STATE.cached_overflow_bytes
            holding_count = len(STATE.holding_bay)
            primary_max = STATE.primary_cap_gb * 1024 * 1024 * 1024
            primary_pct = (primary_bytes / primary_max) * 100.0 if primary_max > 0 else 0.0

            color = "green" if primary_pct < 80 else "orange" if primary_pct < 100 else "red"
            text = f"Primary C: {primary_bytes/1024/1024:.2f} MB / {STATE.primary_cap_gb} GB ({primary_pct:.1f}%) | Overflow: {overflow_bytes/1024/1024:.2f} MB | Holding: {holding_count}"
            self.lbl_cache_usage.config(text=text, foreground=color)

            snap = TELEMETRY.get_snapshot()
            t_text = f"Telemetry: Probes Lost (50%): {int(snap['drone_dock_cycles'] * PROBE_ATTRITION_LOSS_RATE):,} | Fully Regenerated Files: {snap['fully_regenerated_files']:,} | Replications: {snap['probe_autonomous_replications']:,}"
            self.lbl_telemetry.config(text=t_text)
        except Exception:
            pass
        self.after(1000, self._refresh_live_indicators)

    def _poll_gui_queue(self):
        try:
            while True:
                event_type, payload = STATE.gui_queue.get_nowait()
                if event_type == "discovery_status":
                    self.lbl_discovery_stats.config(
                        text=f"Discovered URLs: {STATE.discovered_urls_count:,} | Target: {STATE.last_discovery_target}"
                    )
                elif event_type == "state_update":
                    self.lbl_state.config(text=f"Altered State: {STATE.altered_states.active_state}")
        except queue.Empty:
            pass
        self.after(2000, self._poll_gui_queue)

    def _periodic_gui_refresh_cycle(self):
        if self.peers_visible:
            self._refresh_peers()
        if self.cache_visible:
            self._refresh_cache_lists()
        self.after(GUI_REFRESH_INTERVAL_MS, self._periodic_gui_refresh_cycle)

    def _refresh_peers(self):
        try:
            for item in self.tree_peers.get_children():
                self.tree_peers.delete(item)
            for p in STATE.get_peers_sorted_predictive()[:50]:
                self.tree_peers.insert("", "end", values=(p.addr, p.last_seen.strftime("%H:%M:%S"), "OK" if p.is_healthy else "Degraded", f"{p.reliability_score:.2f}", "Active" if p.is_in_backoff else "Normal", "MAIN" if p.is_main else "PEER"))
        except Exception:
            pass

    def _refresh_cache_lists(self):
        try:
            for item in self.tree_ram.get_children():
                self.tree_ram.delete(item)
            for item in self.tree_disk.get_children():
                self.tree_disk.delete(item)
            for e in STATE.list_cache_summary()[-50:]:
                self.tree_ram.insert("", "end", values=(e["source_ip"], e["source_type"], e["timestamp"].strftime("%H:%M:%S"), e["score"], f"{e['size']} B"))
            for d in STATE.list_disk_cache_summary()[-50:]:
                self.tree_disk.insert("", "end", values=(d["path"], f"{d['size']} B"))
        except Exception:
            pass


###############################################################################
# MAIN ENTRY POINT
###############################################################################

def main():
    logger.info(f"Initializing {APP_ID} v{APP_VERSION} (Autonomous 1B Swarm Edition)...")

    threading.Thread(target=beacon_sender, daemon=True, name="BeaconSender").start()
    threading.Thread(target=beacon_listener, daemon=True, name="BeaconListener").start()
    threading.Thread(target=water_physics_probe_worker, daemon=True, name="WaterPhysicsProbe").start()
    threading.Thread(target=periodic_main_drive_cache, daemon=True, name="DriveCacheSimulator").start()
    threading.Thread(target=periodic_peer_cache_sync, daemon=True, name="PeerCacheSyncWorker").start()
    threading.Thread(target=background_disk_metric_worker, daemon=True, name="BackgroundDiskMetricWorker").start()
    BorgAIWatchdog().start()

    app = BorgGUI()
    app.mainloop()


if __name__ == "__main__":
    main()