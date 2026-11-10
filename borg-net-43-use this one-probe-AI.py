#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DominionDeck Universal AI Probe Nexus v10.1.1
A local-first, policy-aware web cache and AI retrieval gateway featuring Persistent Memory &
Session State Recovery across reboots, OS Startup Auto-Boot Registration, Active Window PID
& Browser Recognition, Autonomous Self-Tuning Learning Weights, AI Query Augmentation,
FTS5 Full-Text Search, and Allowed Domains Management.
"""

from __future__ import annotations

import sys
import importlib

REQUIRED_MODULES = [
    "hashlib", "html", "json", "logging", "os", "queue", "re", "shutil",
    "socket", "sqlite3", "threading", "time", "urllib.error", "urllib.parse",
    "urllib.robotparser", "urllib.request", "uuid", "collections", "dataclasses",
    "datetime", "http.server", "html.parser", "pathlib", "typing", "tkinter",
    "hmac", "ipaddress", "ctypes"
]

def autoload_libraries() -> None:
    missing = []
    for mod_name in REQUIRED_MODULES:
        try:
            importlib.import_module(mod_name)
        except ImportError:
            missing.append(mod_name)
    if missing:
        print(f"[!] Warning: Some modules could not be imported: {missing}", file=sys.stderr)

autoload_libraries()

import hashlib
import copy
import html
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import queue
import re
import shutil
import socket
import sqlite3
import threading
import time
import tempfile
import urllib.error
import urllib.parse
import urllib.robotparser
import urllib.request
import uuid
import hmac
import ipaddress
import ctypes
from ctypes import wintypes
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = "DominionDeck Universal AI Probe Nexus"
APP_VERSION = "10.1.1"
HOME = Path.home()
CONFIG_PATH = HOME / "dominion_nexus_config.json"
DEFAULT_ROOT = HOME / "DominionDeckCache"
LOG_PATH = HOME / "dominion_nexus.log"
USER_AGENT = "DominionDeckProbe/10.1 (+local-first intelligence mesh; respects robots.txt)"
MAX_URL_LENGTH = 2048

DEFAULT_CONFIG = {
    "cache_root": str(DEFAULT_ROOT),
    "overflow_root": "",
    "primary_cap_gb": 3.0,
    "overflow_cap_gb": 0.0,
    "ram_index_limit": 5000,
    "max_pages": 1000,
    "max_depth": 2,
    "workers": 4,
    "request_timeout": 12,
    "max_page_mb": 3,
    "per_host_delay": 2.0,
    "refresh_after_hours": 72,
    "expire_unused_days": 60,
    "crawl_enabled": False,
    "auto_adder_enabled": True,
    "scan_browser_history": True,
    "auto_start_workers_for_manual_queue": True,
    "api_enabled": True,
    "api_host": "127.0.0.1",
    "api_port": 8765,
    "api_token": "",
    "seed_urls": [
        "https://example.com/",
        "https://www.iana.org/domains/reserved"
    ],
    "allowed_domains": [],
    "respect_robots": True,
    "max_links_per_page": 100,
    "log_level": "INFO",
    "cluster_enabled": False,
    "cluster_id": "DOMINIONDECK-LOCAL-CLUSTER",
    "cluster_node_id": "",
    "cluster_secret": "",
    "cluster_peers": [],
    "cluster_sync_interval": 60,
    "cluster_share_discoveries": True,
    "cluster_share_cache_metadata": True,
    "cluster_share_metrics": True,
    "cluster_share_learning": True,
    "cluster_auto_accept_discoveries": False,
    "cluster_max_events_per_sync": 100
}

def load_config() -> dict:
    cfg = copy.deepcopy(DEFAULT_CONFIG)
    try:
        if CONFIG_PATH.exists():
            loaded = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
            if isinstance(loaded, dict):
                cfg.update(loaded)
    except Exception:
        pass
    return cfg

CONFIG = load_config()

def save_config() -> None:
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(CONFIG, indent=2), encoding="utf-8")
    tmp.replace(CONFIG_PATH)

def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()

def safe_int(value: Any, default: int, low: int, high: int) -> int:
    try:
        return max(low, min(high, int(value)))
    except (TypeError, ValueError):
        return default

def safe_float(value: Any, default: float, low: float, high: float) -> float:
    try:
        return max(low, min(high, float(value)))
    except (TypeError, ValueError):
        return default

def normalize_url(raw: str, base: str | None = None) -> str | None:
    try:
        url = urllib.parse.urljoin(base or "", raw.strip())
        p = urllib.parse.urlsplit(url)
        if p.scheme.lower() not in ("http", "https") or not p.hostname:
            return None
        if p.username or p.password or len(url) > MAX_URL_LENGTH:
            return None
        host = p.hostname.lower().rstrip(".")
        try:
            ip = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80),
                                    type=socket.SOCK_STREAM)[0][4][0]
            addr = ipaddress.ip_address(ip)
            if not addr.is_global:
                return None
        except (socket.gaierror, ValueError, OSError):
            if host in ("localhost",) or host.endswith((".local", ".internal")):
                return None
        path = p.path or "/"
        clean = urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), path,
                                         p.query, ""))
        return clean
    except Exception:
        return None

def domain_of(url: str) -> str:
    return (urllib.parse.urlsplit(url).hostname or "").lower()

def get_active_window_browser_info() -> dict:
    if os.name != 'nt':
        return {"browser": None, "pid": 0, "title": ""}
    try:
        hwnd = ctypes.windll.user32.GetForegroundWindow()
        if not hwnd:
            return {"browser": None, "pid": 0, "title": ""}

        pid = wintypes.DWORD()
        ctypes.windll.user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        active_pid = pid.value

        length = ctypes.windll.user32.GetWindowTextLengthW(hwnd)
        buff = ctypes.create_unicode_buffer(length + 1)
        ctypes.windll.user32.GetWindowTextW(hwnd, buff, length + 1)
        window_title = buff.value

        browser_name = None
        try:
            import psutil
            for proc in psutil.process_iter(['pid', 'name']):
                if proc.info['pid'] == active_pid:
                    p_name = proc.info['name'].lower()
                    if "chrome" in p_name:
                        browser_name = "Google Chrome"
                    elif "msedge" in p_name:
                        browser_name = "Microsoft Edge"
                    elif "firefox" in p_name:
                        browser_name = "Mozilla Firefox"
                    elif "brave" in p_name:
                        browser_name = "Brave"
                    break
        except ImportError:
            t_low = window_title.lower()
            if "chrome" in t_low:
                browser_name = "Google Chrome"
            elif "edge" in t_low:
                browser_name = "Microsoft Edge"
            elif "firefox" in t_low:
                browser_name = "Mozilla Firefox"

        return {
            "browser": browser_name,
            "pid": active_pid,
            "title": window_title
        }
    except Exception:
        return {"browser": None, "pid": 0, "title": ""}

def register_os_startup() -> bool:
    if os.name != 'nt':
        return False
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        script_path = os.path.abspath(sys.argv[0])
        python_exe = sys.executable
        command = f'"{python_exe}" "{script_path}"'
        
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "DominionNexusAI", 0, winreg.REG_SZ, command)
        return True
    except Exception:
        return False

def unregister_os_startup() -> bool:
    if os.name != 'nt':
        return False
    try:
        import winreg
        key_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.DeleteValue(key, "DominionNexusAI")
        return True
    except Exception:
        return False

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.text_parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() in ("script", "style", "noscript", "svg", "nav", "footer"):
            self._skip += 1
        if tag.lower() == "a" and attrs.get("href") and len(self.links) < 2000:
            self.links.append(attrs["href"])

    def handle_endtag(self, tag):
        if tag.lower() in ("script", "style", "noscript", "svg", "nav", "footer") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            s = re.sub(r"\s+", " ", data).strip()
            if s:
                self.text_parts.append(s)

@dataclass(order=True)
class CrawlTask:
    priority_weight: float
    timestamp: float
    url: str = field(compare=False)
    depth: int = field(default=0, compare=False)
    reason: str = field(default="seed", compare=False)

class Nexus:
    def __init__(self):
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.tasks: queue.PriorityQueue[CrawlTask] = queue.PriorityQueue(maxsize=10000)
        self.events: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=2000)
        self.seen: set[str] = set()
        self.host_last_request: dict[str, float] = {}
        self.robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}
        self.workers: list[threading.Thread] = []
        self.active_tasks: dict[str, CrawlTask] = {}
        self._shutdown_lock = threading.Lock()
        self._stopped = False
        self.server: ThreadingHTTPServer | None = None
        self.server_thread: threading.Thread | None = None
        self.root = Path(str(CONFIG.get("cache_root") or DEFAULT_ROOT)).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        self.content_dir = self.root / "objects"
        self.content_dir.mkdir(exist_ok=True)
        self.db_path = self.root / "nexus_v8.sqlite3"
        self._init_db()
        if not str(CONFIG.get("cluster_node_id", "")).strip():
            CONFIG["cluster_node_id"] = str(uuid.uuid4())
            save_config()
        if not str(CONFIG.get("cluster_secret", "")).strip():
            import secrets
            CONFIG["cluster_secret"] = secrets.token_urlsafe(32)
            save_config()
        self.cluster_stop_event = threading.Event()
        self.cluster_thread = None

        self.stats = self._load_persistent_stats()
        self.last_message = "Ready (Memory Restored)"
        self._load_seen()
        self._load_queue_state()
        
        self.auto_adder_thread = threading.Thread(target=self._auto_adder_loop, daemon=True)
        self.auto_adder_thread.start()
        if CONFIG.get("cluster_enabled", False):
            self.cluster_thread = threading.Thread(target=self._cluster_sync_loop, daemon=True,
                                                   name="NexusClusterSync")
            self.cluster_thread.start()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=20)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA busy_timeout=20000")
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA synchronous=NORMAL")
        return conn

    def _init_db(self):
        with self._connect() as db:
            db.executescript("""
            CREATE TABLE IF NOT EXISTS pages(
                id INTEGER PRIMARY KEY,
                url TEXT UNIQUE NOT NULL,
                domain TEXT NOT NULL,
                title TEXT DEFAULT '',
                content TEXT NOT NULL,
                object_path TEXT NOT NULL,
                sha256 TEXT NOT NULL,
                content_type TEXT DEFAULT '',
                status INTEGER DEFAULT 200,
                fetched_at TEXT NOT NULL,
                last_access TEXT NOT NULL,
                access_count INTEGER DEFAULT 0,
                depth INTEGER DEFAULT 0,
                etag TEXT DEFAULT '',
                last_modified TEXT DEFAULT '',
                next_refresh TEXT DEFAULT '',
                change_velocity REAL DEFAULT 1.0,
                learning_weight REAL DEFAULT 1.0
            );
            CREATE INDEX IF NOT EXISTS idx_pages_domain ON pages(domain);
            CREATE INDEX IF NOT EXISTS idx_pages_hash ON pages(sha256);
            CREATE INDEX IF NOT EXISTS idx_pages_access ON pages(last_access);
            
            CREATE TABLE IF NOT EXISTS app_state(
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS domain_stats(
                domain TEXT PRIMARY KEY,
                success_count INTEGER DEFAULT 0,
                error_count INTEGER DEFAULT 0,
                avg_latency_ms REAL DEFAULT 0.0,
                reputation_weight REAL DEFAULT 1.0,
                last_updated TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS change_history(
                id INTEGER PRIMARY KEY,
                url TEXT NOT NULL,
                old_sha256 TEXT,
                new_sha256 TEXT,
                changed_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS crawl_queue(
                url TEXT PRIMARY KEY, depth INTEGER NOT NULL, reason TEXT,
                priority_weight REAL DEFAULT 1.0, queued_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS crawl_history(
                id INTEGER PRIMARY KEY, url TEXT, outcome TEXT, detail TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auto_inbox(
                id INTEGER PRIMARY KEY, url TEXT UNIQUE NOT NULL, source TEXT, added_at TEXT NOT NULL
            );
            """)
            db.executescript("""
            CREATE TABLE IF NOT EXISTS cluster_outbox(
                event_id TEXT PRIMARY KEY, event_type TEXT NOT NULL,
                payload TEXT NOT NULL, created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cluster_inbox(
                event_id TEXT PRIMARY KEY, node_id TEXT NOT NULL,
                received_at TEXT NOT NULL, event_type TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS pending_discoveries(
                id INTEGER PRIMARY KEY, event_id TEXT UNIQUE NOT NULL,
                source_node TEXT NOT NULL, url TEXT NOT NULL,
                title TEXT DEFAULT '', discovered_at TEXT NOT NULL,
                status TEXT DEFAULT 'pending'
            );
            CREATE TABLE IF NOT EXISTS shared_cache_meta(
                url TEXT PRIMARY KEY, source_node TEXT NOT NULL,
                title TEXT DEFAULT '', sha256 TEXT DEFAULT '',
                fetched_at TEXT NOT NULL, received_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cluster_nodes(
                node_id TEXT PRIMARY KEY, last_seen TEXT NOT NULL,
                metrics_json TEXT DEFAULT '{}'
            );
            CREATE TABLE IF NOT EXISTS shared_domain_learning(
                domain TEXT PRIMARY KEY, success_count INTEGER DEFAULT 0,
                error_count INTEGER DEFAULT 0, avg_latency_ms REAL DEFAULT 0,
                reputation_weight REAL DEFAULT 1.0,
                source_node TEXT NOT NULL, updated_at TEXT NOT NULL
            );
            """)
            self.fts_available = False
            try:
                db.executescript("""
                CREATE VIRTUAL TABLE IF NOT EXISTS pages_fts USING fts5(
                    url, title, content, domain, content='pages', content_rowid='id'
                );
                CREATE TRIGGER IF NOT EXISTS pages_ai AFTER INSERT ON pages BEGIN
                    INSERT INTO pages_fts(rowid,url,title,content,domain)
                    VALUES(new.id,new.url,new.title,new.content,new.domain);
                END;
                CREATE TRIGGER IF NOT EXISTS pages_ad AFTER DELETE ON pages BEGIN
                    INSERT INTO pages_fts(pages_fts,rowid,url,title,content,domain)
                    VALUES('delete',old.id,old.url,old.title,old.content,old.domain);
                END;
                CREATE TRIGGER IF NOT EXISTS pages_au AFTER UPDATE ON pages BEGIN
                    INSERT INTO pages_fts(pages_fts,rowid,url,title,content,domain)
                    VALUES('delete',old.id,old.url,old.title,old.content,old.domain);
                    INSERT INTO pages_fts(rowid,url,title,content,domain)
                    VALUES(new.id,new.url,new.title,new.content,new.domain);
                END;
                """)
                db.execute("INSERT INTO pages_fts(pages_fts) VALUES('rebuild')")
                self.fts_available = True
            except sqlite3.OperationalError as exc:
                logging.warning("FTS5 unavailable; using LIKE search fallback: %s", exc)
                self.fts_available = False

    def _load_persistent_stats(self) -> dict:
        defaults = {"fetched": 0, "errors": 0, "bytes": 0, "deduplicated": 0,
                    "blocked": 0, "expired": 0, "api_requests": 0, "auto_added": 0,
                    "predictive_refreshes": 0, "augmentations": 0}
        try:
            with self._connect() as db:
                rows = db.execute("SELECT key, value FROM app_state").fetchall()
                for r in rows:
                    k, v = r["key"], r["value"]
                    if k in defaults:
                        try:
                            defaults[k] = int(v)
                        except ValueError:
                            pass
        except Exception:
            pass
        return defaults

    def save_persistent_state(self):
        try:
            with self._connect() as db:
                for k, v in self.stats.items():
                    db.execute("INSERT INTO app_state(key, value, updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at",
                               (k, str(v), utc_now()))
        except Exception:
            pass

    def _load_seen(self):
        with self._connect() as db:
            self.seen = {r[0] for r in db.execute("SELECT url FROM pages")}

    def _load_queue_state(self):
        with self._connect() as db:
            rows = db.execute("SELECT url,depth,reason,priority_weight FROM crawl_queue ORDER BY queued_at").fetchall()
        for r in rows:
            try:
                self.seen.add(r["url"])
                weight = float(r["priority_weight"] or 1.0)
                task = CrawlTask(priority_weight=-weight, timestamp=time.time(), url=r["url"], depth=r["depth"], reason=r["reason"] or "resume")
                self.tasks.put_nowait(task)
            except queue.Full:
                break

    def emit(self, kind: str, message: str):
        self.last_message = message
        try:
            self.events.put_nowait((kind, message))
        except queue.Full:
            try:
                self.events.get_nowait()
                self.events.put_nowait((kind, message))
            except queue.Empty:
                pass

    def get_domain_weight(self, domain: str) -> float:
        with self._connect() as db:
            row = db.execute("SELECT reputation_weight FROM domain_stats WHERE domain=?", (domain,)).fetchone()
            return row["reputation_weight"] if row else 1.0

    def update_domain_reputation(self, domain: str, success: bool, latency_ms: float):
        with self._connect() as db:
            row = db.execute("SELECT success_count, error_count, avg_latency_ms, reputation_weight FROM domain_stats WHERE domain=?", (domain,)).fetchone()
            if not row:
                s_cnt = 1 if success else 0
                e_cnt = 0 if success else 1
                weight = 1.2 if success else 0.7
                db.execute("INSERT INTO domain_stats(domain,success_count,error_count,avg_latency_ms,reputation_weight,last_updated) VALUES(?,?,?,?,?,?)",
                           (domain, s_cnt, e_cnt, latency_ms, weight, utc_now()))
            else:
                s_cnt = row["success_count"] + (1 if success else 0)
                e_cnt = row["error_count"] + (0 if success else 1)
                total = s_cnt + e_cnt
                avg_lat = ((row["avg_latency_ms"] * (total - 1)) + latency_ms) / total
                success_ratio = s_cnt / max(1, total)
                weight = max(0.2, min(3.0, success_ratio * (2.0 / (1.0 + (avg_lat / 1000.0)))))
                db.execute("UPDATE domain_stats SET success_count=?, error_count=?, avg_latency_ms=?, reputation_weight=?, last_updated=? WHERE domain=?",
                           (s_cnt, e_cnt, avg_lat, weight, utc_now(), domain))

    def queue_url(self, raw: str, depth: int = 0, reason: str = "manual",
                  force: bool = False) -> bool:
        url = normalize_url(raw)
        if not url:
            return False
        raw_allowed = CONFIG.get("allowed_domains", [])
        if not isinstance(raw_allowed, list):
            raw_allowed = []
        allowed = [str(d).lower().strip() for d in raw_allowed
                   if isinstance(d, str) and d.strip()]
        host = domain_of(url)
        if allowed and not any(host == d or host.endswith("." + d) for d in allowed):
            return False
        depth = safe_int(depth, 0, 0, 20)
        dom_weight = self.get_domain_weight(host)
        with self.lock:
            if not force and url in self.seen:
                return False
            try:
                with self._connect() as db:
                    if db.execute("SELECT 1 FROM crawl_queue WHERE url=?", (url,)).fetchone():
                        return False
                    db.execute("INSERT INTO crawl_queue(url,depth,reason,priority_weight,queued_at) VALUES(?,?,?,?,?)",
                               (url, depth, reason, dom_weight, utc_now()))
                task = CrawlTask(priority_weight=-dom_weight, timestamp=time.time(), url=url, depth=depth, reason=reason)
                self.tasks.put_nowait(task)
                self.seen.add(url)
            except (queue.Full, sqlite3.Error) as exc:
                try:
                    with self._connect() as db:
                        db.execute("DELETE FROM crawl_queue WHERE url=?", (url,))
                except Exception:
                    pass
                logging.warning("Unable to queue %s: %s", url, exc)
                if not force:
                    self.seen.discard(url)
                return False
        self.emit("queue", f"Queued [{reason}] ({dom_weight:.2f}w) {url}")
        return True

    def _remove_queued_url(self, url: str) -> None:
        try:
            with self._connect() as db:
                db.execute("DELETE FROM crawl_queue WHERE url=?", (url,))
                cached = db.execute("SELECT 1 FROM pages WHERE url=?", (url,)).fetchone()
        except sqlite3.Error:
            logging.exception("Could not clear queue record for %s", url)
            return
        if not cached:
            with self.lock:
                self.seen.discard(url)

    def seed(self):
        for url in CONFIG.get("seed_urls", []):
            self.queue_url(url, 0, "seed")

    def register_external_url(self, raw_url: str, source: str = "auto-scanner") -> bool:
        url = normalize_url(raw_url)
        if not url:
            return False
        with self._connect() as db:
            exists = db.execute("SELECT 1 FROM auto_inbox WHERE url=?", (url,)).fetchone()
            if not exists:
                db.execute("INSERT OR IGNORE INTO auto_inbox(url, source, added_at) VALUES(?,?,?)",
                           (url, source, utc_now()))
                self.stats["auto_added"] += 1
                self.save_persistent_state()
        if CONFIG.get("cluster_share_discoveries", True):
            self._cluster_publish("discovery", {"url": url, "source": str(source)[:80],
                                                 "title": "", "discovered_at": utc_now()})
        added = self.queue_url(url, depth=0, reason=f"auto:{source}")
        if added:
            self.emit("auto", f"Auto-added URL from {source}: {url}")
        return added

    def scan_browser_history_and_pid(self):
        win_info = get_active_window_browser_info()
        if win_info["browser"]:
            title = win_info["title"]
            self.emit("monitor", f"Active [{win_info['browser']} | PID:{win_info['pid']}] -> {title[:60]}")

        history_paths = []
        home = Path.home()
        if os.name == 'nt':
            local_app = Path(os.environ.get('LOCALAPPDATA', ''))
            app_data = Path(os.environ.get('APPDATA', ''))
            history_paths.extend([
                local_app / "Google" / "Chrome" / "User Data" / "Default" / "History",
                local_app / "Microsoft" / "Edge" / "User Data" / "Default" / "History",
                app_data / "Mozilla" / "Firefox" / "Profiles"
            ])
        elif sys.platform == "darwin":
            history_paths.extend([
                home / "Library" / "Application Support" / "Google" / "Chrome" / "Default" / "History",
                home / "Library" / "Application Support" / "Microsoft" / "Edge" / "Default" / "History",
                home / "Library" / "Application Support" / "Firefox" / "Profiles"
            ])
        else:
            history_paths.extend([
                home / ".config" / "google-chrome" / "Default" / "History",
                home / ".config" / "microsoft-edge" / "Default" / "History",
                home / ".mozilla" / "firefox"
            ])

        for path in history_paths:
            if not path.exists():
                continue
            try:
                if "firefox" in str(path).lower():
                    profiles = list(path.glob("*.default*")) + list(path.glob("*.default-release*"))
                    for prof in profiles:
                        places = prof / "places.sqlite"
                        if places.exists():
                            temp_hist = self.root / f"temp_ff_{uuid.uuid4()}.sqlite"
                            shutil.copy2(places, temp_hist)
                            conn = sqlite3.connect(temp_hist)
                            cursor = conn.cursor()
                            cursor.execute("SELECT url FROM moz_places ORDER BY last_visit_date DESC LIMIT 15")
                            for (raw_url,) in cursor.fetchall():
                                self._evaluate_history_url(raw_url, "firefox-history")
                            conn.close()
                            temp_hist.unlink(missing_ok=True)
                else:
                    temp_hist = self.root / f"temp_chrom_{uuid.uuid4()}.sqlite"
                    shutil.copy2(path, temp_hist)
                    conn = sqlite3.connect(temp_hist)
                    cursor = conn.cursor()
                    cursor.execute("SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 20")
                    for (raw_url,) in cursor.fetchall():
                        self._evaluate_history_url(raw_url, "browser-history")
                    conn.close()
                    temp_hist.unlink(missing_ok=True)
            except Exception:
                pass

    def _evaluate_history_url(self, raw_url: str, source: str):
        parsed_domain = domain_of(raw_url)
        if parsed_domain and not parsed_domain.startswith(("chrome", "edge", "about", "localhost", "127.0.0.1", "internal", "file")):
            self.register_external_url(raw_url, source=source)

    def _auto_adder_loop(self):
        while not self.stop_event.wait(15.0):
            if not CONFIG.get("auto_adder_enabled", True):
                continue
            try:
                if CONFIG.get("scan_browser_history", True):
                    self.scan_browser_history_and_pid()
                inbox_file = self.root / "auto_url_inbox.txt"
                if inbox_file.exists():
                    lines = inbox_file.read_text(encoding="utf-8", errors="ignore").splitlines()
                    for line in lines:
                        clean = line.strip()
                        if clean and not clean.startswith("#"):
                            self.register_external_url(clean, source="watchfile")
                    inbox_file.write_text("# Drop new URLs here to auto-probe\n", encoding="utf-8")
            except Exception:
                pass

    def _robots_allowed(self, url: str) -> bool:
        if not CONFIG.get("respect_robots", True):
            return True
        p = urllib.parse.urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"
        with self.lock:
            parser = self.robots.get(origin, "__NOT_CACHED__")
        if parser == "__NOT_CACHED__":
            parser = urllib.robotparser.RobotFileParser()
            robots_url = origin + "/robots.txt"
            parser.set_url(robots_url)
            timeout = safe_int(CONFIG.get("request_timeout"), 12, 3, 60)
            try:
                request = urllib.request.Request(robots_url, headers={"User-Agent": USER_AGENT})
                with urllib.request.urlopen(request, timeout=timeout) as response:
                    raw = response.read(512 * 1024 + 1)
                if len(raw) > 512 * 1024:
                    raise ValueError("robots.txt exceeds 512 KiB safety limit")
                parser.parse(raw.decode("utf-8", errors="replace").splitlines())
            except urllib.error.HTTPError as exc:
                if exc.code in (404, 410):
                    parser.parse([])
                elif exc.code in (401, 403):
                    parser.parse(["User-agent: *", "Disallow: /"])
                else:
                    parser = None
            except Exception as exc:
                logging.debug("robots.txt unavailable for %s: %s", origin, exc)
                parser = None
            if parser is not None:
                with self.lock:
                    self.robots[origin] = parser
        if parser is None:
            return False
        try:
            return bool(parser.can_fetch(USER_AGENT, url))
        except Exception:
            logging.exception("robots policy check failed for %s", url)
            return False

    def _throttle(self, host: str):
        dom_weight = self.get_domain_weight(host)
        base_delay = safe_float(CONFIG.get("per_host_delay"), 2.0, 0.25, 60.0)
        delay = max(0.25, base_delay / max(0.3, dom_weight))
        now = time.monotonic()
        with self.lock:
            last = self.host_last_request.get(host, 0.0)
            next_allowed = max(now, last + delay)
            self.host_last_request[host] = next_allowed
        wait = next_allowed - now
        if wait > 0:
            self.stop_event.wait(wait)

    def fetch_url(self, url: str, depth: int = 0) -> dict:
        start_time = time.time()
        host = domain_of(url)
        if not self._robots_allowed(url):
            self.stats["blocked"] += 1
            self.update_domain_reputation(host, success=False, latency_ms=0.0)
            self.save_persistent_state()
            self._history(url, "blocked", "robots.txt disallowed or unavailable")
            self._remove_queued_url(url)
            return {"ok": False, "error": "robots.txt disallowed or unavailable"}
        
        self._throttle(host)
        timeout = safe_int(CONFIG.get("request_timeout"), 12, 3, 60)
        max_bytes = safe_int(CONFIG.get("max_page_mb"), 3, 1, 20) * 1024 * 1024
        headers = {"User-Agent": USER_AGENT, "Accept": "text/html,text/plain,application/xhtml+xml"}
        old = self.get_metadata(url)
        if old:
            if old.get("etag"):
                headers["If-None-Match"] = old["etag"]
            if old.get("last_modified"):
                headers["If-Modified-Since"] = old["last_modified"]
        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                status = response.status
                ctype = response.headers.get("Content-Type", "")
                if not any(x in ctype.lower() for x in ("text/html", "text/plain", "application/xhtml")):
                    raise ValueError(f"Unsupported content type: {ctype}")
                length = response.headers.get("Content-Length")
                if length and int(length) > max_bytes:
                    raise ValueError("Page exceeds configured size limit")
                raw = response.read(max_bytes + 1)
                if len(raw) > max_bytes:
                    raise ValueError("Page exceeds configured size limit")
                charset = response.headers.get_content_charset() or "utf-8"
                text = raw.decode(charset, errors="replace")
                final_url = normalize_url(response.geturl())
                if not final_url:
                    raise ValueError("Redirect destination failed URL safety validation")
                allowed_domains = CONFIG.get("allowed_domains", [])
                if allowed_domains:
                    redirected_host = domain_of(final_url)
                    permitted = isinstance(allowed_domains, list) and any(
                        isinstance(d, str) and d.strip() and (
                            redirected_host == d.lower().strip()
                            or redirected_host.endswith("." + d.lower().strip())
                        ) for d in allowed_domains
                    )
                    if not permitted:
                        raise ValueError("Redirect destination is outside the allowed-domain list")
                if not self._robots_allowed(final_url):
                    raise ValueError("Redirect destination disallowed by robots.txt")
                etag = response.headers.get("ETag", "")
                modified = response.headers.get("Last-Modified", "")
                
                latency_ms = (time.time() - start_time) * 1000.0
                self.update_domain_reputation(host, success=True, latency_ms=latency_ms)

                self._store_page(final_url, text, ctype, status, depth, etag, modified)
                self.stats["bytes"] += len(raw)
                self.stats["fetched"] += 1
                self.save_persistent_state()
                self._history(url, "fetched", f"{status}, {len(raw)} bytes")
                self.emit("fetch", f"Fetched {final_url} ({len(raw):,} bytes)")
                links = []
                if "html" in ctype.lower():
                    parser = LinkParser()
                    parser.feed(text)
                    links = parser.links[:safe_int(CONFIG.get("max_links_per_page"), 100, 1, 500)]
                    for link in links:
                        candidate = normalize_url(link, final_url)
                        if not candidate or domain_of(candidate) != domain_of(final_url):
                            continue
                        self.queue_url(candidate, depth + 1, "discovered")
                return {"ok": True, "url": final_url, "bytes": len(raw), "links_found": len(links)}
        except urllib.error.HTTPError as e:
            latency_ms = (time.time() - start_time) * 1000.0
            self.update_domain_reputation(host, success=False, latency_ms=latency_ms)
            self.save_persistent_state()
            if e.code == 304 and old:
                with self._connect() as db:
                    db.execute("UPDATE pages SET fetched_at=?, next_refresh=? WHERE url=?",
                               (utc_now(), self._next_refresh(old.get("change_velocity", 1.0)), url))
                self._remove_queued_url(url)
                return {"ok": True, "url": url, "not_modified": True}
            self.stats["errors"] += 1
            self.save_persistent_state()
            self._history(url, "http_error", str(e))
            self._remove_queued_url(url)
            return {"ok": False, "error": f"HTTP {e.code}"}
        except Exception as e:
            latency_ms = (time.time() - start_time) * 1000.0
            self.update_domain_reputation(host, success=False, latency_ms=latency_ms)
            self.stats["errors"] += 1
            self.save_persistent_state()
            self._history(url, "error", str(e)[:500])
            self.emit("error", f"{url}: {e}")
            self._remove_queued_url(url)
            return {"ok": False, "error": str(e)}

    def _next_refresh(self, change_velocity: float = 1.0) -> str:
        base_hours = safe_int(CONFIG.get("refresh_after_hours"), 72, 1, 8760)
        adjusted_hours = max(1.0, base_hours / max(0.2, change_velocity))
        return (datetime.now(timezone.utc) + timedelta(hours=adjusted_hours)).isoformat()

    def _store_page(self, url: str, content: str, ctype: str, status: int,
                    depth: int, etag: str, modified: str):
        raw = content.encode("utf-8", errors="replace")
        digest = hashlib.sha256(raw).hexdigest()
        obj = self.content_dir / digest[:2] / (digest + ".txt")
        obj.parent.mkdir(parents=True, exist_ok=True)
        if not obj.exists():
            tmp = obj.with_suffix(".tmp")
            tmp.write_bytes(raw)
            tmp.replace(obj)
        title = ""
        m = re.search(r"<title[^>]*>(.*?)</title>", content, re.I | re.S)
        if m:
            title = html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).strip()[:300]
        
        host = domain_of(url)
        dom_weight = self.get_domain_weight(host)

        with self._connect() as db:
            existing = db.execute("SELECT sha256, change_velocity FROM pages WHERE url=?", (url,)).fetchone()
            velocity = 1.0
            if existing:
                if existing["sha256"] == digest:
                    self.stats["deduplicated"] += 1
                    velocity = max(0.2, existing["change_velocity"] * 0.9)
                else:
                    velocity = min(5.0, existing["change_velocity"] * 1.5)
                    db.execute("INSERT INTO change_history(url,old_sha256,new_sha256,changed_at) VALUES(?,?,?,?)",
                               (url, existing["sha256"], digest, utc_now()))

            db.execute("""INSERT INTO pages(url,domain,title,content,object_path,sha256,content_type,
                        status,fetched_at,last_access,depth,etag,last_modified,next_refresh,change_velocity,learning_weight)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(url) DO UPDATE SET domain=excluded.domain,title=excluded.title,
                        content=excluded.content,object_path=excluded.object_path,sha256=excluded.sha256,
                        content_type=excluded.content_type,status=excluded.status,fetched_at=excluded.fetched_at,
                        depth=excluded.depth,etag=excluded.etag,last_modified=excluded.last_modified,
                        next_refresh=excluded.next_refresh,change_velocity=excluded.change_velocity,learning_weight=excluded.learning_weight""",
                       (url, host, title, content, str(obj), digest, ctype, status,
                        utc_now(), utc_now(), depth, etag, modified, self._next_refresh(velocity), velocity, dom_weight))
            db.execute("DELETE FROM crawl_queue WHERE url=?", (url,))
        self.enforce_storage_limits()
        if CONFIG.get("cluster_share_cache_metadata", True):
            self._cluster_publish("cache_meta", {
                "url": url, "title": title, "sha256": digest, "fetched_at": utc_now()
            })

    def _history(self, url: str, outcome: str, detail: str):
        with self._connect() as db:
            db.execute("INSERT INTO crawl_history(url,outcome,detail,created_at) VALUES(?,?,?,?)",
                       (url, outcome, detail[:1000], utc_now()))

    def get_metadata(self, url: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT url,etag,last_modified,sha256,fetched_at,last_access,access_count,change_velocity,learning_weight FROM pages WHERE url=?",
                             (url,)).fetchone()
        return dict(row) if row else None

    def search(self, query: str, limit: int = 20) -> list[dict]:
        clean_q = query.strip()
        if not clean_q:
            return []
        limit = safe_int(limit, 20, 1, 100)
        with self._connect() as db:
            try:
                rows = db.execute("""
                    SELECT p.url, p.title, p.domain, p.fetched_at, p.last_access, p.access_count,
                           p.learning_weight, length(p.content) AS chars
                    FROM pages_fts f
                    JOIN pages p ON f.rowid = p.id
                    WHERE pages_fts MATCH ?
                    ORDER BY (rank * (1.0 / p.learning_weight)) LIMIT ?
                """, (clean_q, limit)).fetchall()
                if rows:
                    return [dict(r) for r in rows]
            except Exception:
                pass
            
            terms = [t for t in re.findall(r"[\w-]{2,}", clean_q.lower())[:8]]
            if not terms:
                return []
            where = " AND ".join(["(lower(title) LIKE ? OR lower(content) LIKE ?)"] * len(terms))
            params = []
            for term in terms:
                params.extend([f"%{term}%", f"%{term}%"])
            params.append(limit)
            rows = db.execute(f"""SELECT url,title,domain,fetched_at,last_access,access_count,
                learning_weight, length(content) AS chars FROM pages WHERE {where}
                ORDER BY learning_weight DESC, access_count DESC, fetched_at DESC LIMIT ?""", params).fetchall()
            return [dict(r) for r in rows]

    def augment_query(self, query: str, limit: int = 5) -> dict:
        self.stats["augmentations"] += 1
        self.save_persistent_state()
        results = self.search(query, limit=limit)
        augmented_context = []
        sources = []
        for r in results:
            cached = self.fetch_cached(r["url"])
            if cached and cached.get("content"):
                snippet = re.sub(r"\s+", " ", cached["content"])[:500]
                augmented_context.append(f"Source [{r['domain']}] - {r['title']}:\n{snippet}\n")
                sources.append(r["url"])
        
        return {
            "query": query,
            "augmented_prompt_context": "\n---\n".join(augmented_context),
            "sources": sources,
            "matched_count": len(sources)
        }

    def fetch_cached(self, url: str) -> dict | None:
        normalized = normalize_url(url)
        if not normalized:
            return None
        with self._connect() as db:
            row = db.execute("SELECT * FROM pages WHERE url=?", (normalized,)).fetchone()
            if not row:
                return None
            db.execute("UPDATE pages SET last_access=?,access_count=access_count+1 WHERE url=?",
                       (utc_now(), normalized))
        result = dict(row)
        result["content"] = row["content"]
        return result

    def freshness(self, url: str) -> dict:
        item = self.get_metadata(normalize_url(url) or "")
        if not item:
            return {"cached": False, "url": url, "stale": True}
        fetched = datetime.fromisoformat(item["fetched_at"])
        age_hours = (datetime.now(timezone.utc) - fetched).total_seconds() / 3600
        threshold = safe_int(CONFIG.get("refresh_after_hours"), 72, 1, 8760)
        return {"cached": True, "url": item["url"], "age_hours": round(age_hours, 2),
                "stale": age_hours >= (threshold / max(0.2, item.get("change_velocity", 1.0))),
                "sha256": item["sha256"], "change_velocity": item.get("change_velocity", 1.0),
                "learning_weight": item.get("learning_weight", 1.0),
                "last_access": item["last_access"], "access_count": item["access_count"]}

    def request_refresh(self, url: str) -> bool:
        return self.queue_url(url, 0, "AI refresh request", force=True)

    def predictive_refresh(self, limit: int = 10) -> int:
        now = datetime.now(timezone.utc)
        threshold = safe_int(CONFIG.get("refresh_after_hours"), 72, 1, 8760)
        with self._connect() as db:
            rows = db.execute("SELECT url,fetched_at,last_access,access_count,change_velocity,learning_weight FROM pages").fetchall()
        scored = []
        for r in rows:
            try:
                age = (now - datetime.fromisoformat(r["fetched_at"])).total_seconds() / 3600
                vel = r["change_velocity"] or 1.0
                l_weight = r["learning_weight"] or 1.0
                effective_thresh = threshold / max(0.2, vel)
                if age < effective_thresh * 0.7:
                    continue
                used = (now - datetime.fromisoformat(r["last_access"])).total_seconds() / 86400
                score = min(age / effective_thresh, 25) * (1 + min(r["access_count"], 100) / 20) * vel * l_weight / (1 + used / 30)
                scored.append((score, r["url"]))
            except Exception:
                continue
        added = 0
        for _, url in sorted(scored, reverse=True)[:safe_int(limit, 10, 1, 100)]:
            if self.queue_url(url, 0, "predictive refresh", force=True):
                added += 1
                self.stats["predictive_refreshes"] += 1
        self.save_persistent_state()
        return added

    def cleanup_expired(self) -> int:
        days = safe_int(CONFIG.get("expire_unused_days"), 60, 1, 3650)
        cutoff = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
        removed = 0
        with self._connect() as db:
            rows = db.execute("SELECT url,object_path FROM pages WHERE last_access < ?", (cutoff,)).fetchall()
            for row in rows:
                db.execute("DELETE FROM pages WHERE url=?", (row["url"],))
                removed += 1
            refs = {r[0] for r in db.execute("SELECT DISTINCT object_path FROM pages")}
        for row in rows:
            path = row["object_path"]
            if path not in refs:
                try:
                    Path(path).unlink(missing_ok=True)
                except OSError:
                    pass
        self.stats["expired"] += removed
        self.save_persistent_state()
        if removed:
            self.emit("cleanup", f"Expired {removed} unused cache entries")
        return removed

    def _dir_size(self, path: Path) -> int:
        total = 0
        try:
            for root, _, files in os.walk(path):
                for name in files:
                    try:
                        total += (Path(root) / name).stat().st_size
                    except OSError:
                        pass
        except OSError:
            pass
        return total

    def enforce_storage_limits(self):
        cap = int(safe_float(CONFIG.get("primary_cap_gb"), 3, 0.1, 10000) * 1024**3)
        if not self.root.exists():
            return
        size = self._dir_size(self.root)
        if size <= cap:
            return
        with self._connect() as db:
            rows = db.execute("SELECT url,object_path FROM pages ORDER BY last_access ASC").fetchall()
            for row in rows:
                if size <= cap * 0.95:
                    break
                db.execute("DELETE FROM pages WHERE url=?", (row["url"],))
                count = db.execute("SELECT count(*) FROM pages WHERE object_path=?",
                                   (row["object_path"],)).fetchone()[0]
                if not count:
                    try:
                        n = Path(row["object_path"]).stat().st_size
                        Path(row["object_path"]).unlink(missing_ok=True)
                        size -= n
                    except OSError:
                        pass

    def export_rag_dataset(self, limit: int = 500) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("SELECT url, title, domain, content, fetched_at, learning_weight FROM pages ORDER BY learning_weight DESC, access_count DESC LIMIT ?", (safe_int(limit, 500, 1, 5000),)).fetchall()
        return [dict(r) for r in rows]

    def status(self) -> dict:
        with self._connect() as db:
            count = db.execute("SELECT count(*) FROM pages").fetchone()[0]
            queued = db.execute("SELECT count(*) FROM crawl_queue").fetchone()[0]
            domains = db.execute("SELECT count(DISTINCT domain) FROM pages").fetchone()[0]
        return {
            "app": APP_NAME, "version": APP_VERSION, "pages": count, "queued": queued,
            "domains": domains, "workers": len(self.workers),
            "queue_memory": self.tasks.qsize(), "cache_bytes": self._dir_size(self.root),
            "cache_root": str(self.root), "stats": self.stats.copy(),
            "api": f"http://{CONFIG['api_host']}:{CONFIG['api_port']}/api/v1"
        }

    def worker(self, number: int):
        while not self.stop_event.is_set():
            if number > safe_int(CONFIG.get("workers"), 4, 1, 32):
                return
            if not CONFIG.get("crawl_enabled", False):
                self.stop_event.wait(0.5)
                continue
            try:
                task = self.tasks.get(timeout=1)
            except queue.Empty:
                continue
            try:
                with self.lock:
                    self.active_tasks[task.url] = task
                if task.depth > safe_int(CONFIG.get("max_depth"), 2, 0, 10):
                    self._remove_queued_url(task.url)
                    continue
                self.fetch_url(task.url, task.depth)
            except Exception:
                logging.exception("Worker %s failed", number)
                self._remove_queued_url(task.url)
            finally:
                with self.lock:
                    self.active_tasks.pop(task.url, None)
                self.tasks.task_done()

    def start_workers(self):
        self.workers = [t for t in self.workers if t.is_alive()]
        count = safe_int(CONFIG.get("workers"), 4, 1, 32)
        active_numbers = set()
        for thread in self.workers:
            match = re.fullmatch(r"Probe-(\d+)", thread.name)
            if match:
                active_numbers.add(int(match.group(1)))
        for number in range(1, count + 1):
            if number not in active_numbers:
                thread = threading.Thread(
                    target=self.worker, args=(number,),
                    name=f"Probe-{number}", daemon=True
                )
                thread.start()
                self.workers.append(thread)

    def maintenance_loop(self):
        while not self.stop_event.wait(300):
            try:
                self.cleanup_expired()
                self.predictive_refresh(10)
                self.enforce_storage_limits()
                self.save_persistent_state()
            except Exception:
                logging.exception("Maintenance cycle failed")

    def start_api(self):
        if not CONFIG.get("api_enabled", True):
            return
        nexus = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "DominionDeckNexus/8.0"
            def log_message(self, fmt, *args):
                logging.info("API %s - %s", self.client_address[0], fmt % args)

            def _auth(self):
                token = str(CONFIG.get("api_token", "")).strip()
                if not token:
                    return True
                supplied = self.headers.get("Authorization", "")
                return hmac.compare_digest(supplied, "Bearer " + token)

            def _send(self, code: int, obj: dict):
                body = json.dumps(obj, ensure_ascii=False).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                self.send_response(204)
                self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Authorization,Content-Type")
                self.end_headers()

            def do_GET(self):
                nexus.stats["api_requests"] += 1
                nexus.save_persistent_state()
                if not self._auth():
                    return self._send(401, {"error": "Unauthorized"})
                parsed = urllib.parse.urlsplit(self.path)
                q = urllib.parse.parse_qs(parsed.query)
                if parsed.path == "/api/v1/status":
                    return self._send(200, nexus.status())
                if parsed.path == "/api/v1/search":
                    return self._send(200, {"results": nexus.search(q.get("q", [""])[0],
                                                                   safe_int(q.get("limit", [20])[0], 20, 1, 100))})
                if parsed.path == "/api/v1/fetch":
                    item = nexus.fetch_cached(q.get("url", [""])[0])
                    return self._send(200, item or {"error": "Not cached"})
                if parsed.path == "/api/v1/freshness":
                    return self._send(200, nexus.freshness(q.get("url", [""])[0]))
                if parsed.path == "/api/v1/augment":
                    return self._send(200, nexus.augment_query(q.get("q", [""])[0], safe_int(q.get("limit", [5])[0], 5, 1, 20)))
                if parsed.path == "/api/v1/export":
                    return self._send(200, {"dataset": nexus.export_rag_dataset(safe_int(q.get("limit", [100])[0], 100, 1, 1000))})
                return self._send(404, {"error": "Not found"})

            def do_POST(self):
                nexus.stats["api_requests"] += 1
                nexus.save_persistent_state()
                if self.path == "/cluster/v1/sync":
                    try:
                        length = int(self.headers.get("Content-Length", "0"))
                        if length < 2 or length > 1024 * 1024:
                            return self._send(413, {"error": "Invalid cluster payload size"})
                        raw_body = self.rfile.read(length)
                        timestamp = self.headers.get("X-Dominion-Timestamp", "")
                        node_id = self.headers.get("X-Dominion-Node", "")
                        signature = self.headers.get("X-Dominion-Signature", "")
                        if not nexus._cluster_verify(raw_body, timestamp, node_id, signature):
                            return self._send(401, {"error": "Cluster authentication failed"})
                        payload = json.loads(raw_body.decode("utf-8"))
                        if payload.get("cluster_id") != str(CONFIG.get("cluster_id")):
                            return self._send(403, {"error": "Cluster ID mismatch"})
                        accepted = nexus._cluster_apply_events(node_id, payload.get("events", []))
                        return self._send(200, {"ok": True, "accepted": accepted,
                                                "node_id": CONFIG.get("cluster_node_id")})
                    except Exception as exc:
                        logging.warning("Cluster sync rejected: %s", exc)
                        return self._send(400, {"error": "Invalid cluster sync request"})
                if not self._auth():
                    return self._send(401, {"error": "Unauthorized"})
                if self.path not in ("/api/v1/probe", "/api/v1/auto-add", "/api/v1/predictive-refresh", "/api/v1/augment"):
                    return self._send(404, {"error": "Not found"})
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 2 or length > 16384:
                        return self._send(413, {"error": "Invalid request size"})
                    payload = json.loads(self.rfile.read(length).decode("utf-8"))
                except Exception:
                    return self._send(400, {"error": "Invalid JSON"})
                
                if self.path == "/api/v1/probe":
                    url = payload.get("url", "")
                    if not url:
                        return self._send(400, {"error": "Missing URL"})
                    added = nexus.queue_url(url, 0, "API probe")
                    return self._send(202, {"ok": added, "queued": added, "url": url})
                
                if self.path == "/api/v1/auto-add":
                    url = payload.get("url", "")
                    source = payload.get("source", "api")
                    if not url:
                        return self._send(400, {"error": "Missing URL"})
                    added = nexus.register_external_url(url, source=source)
                    return self._send(201, {"ok": added, "auto_added": added, "url": url})

                if self.path == "/api/v1/augment":
                    q = payload.get("q", "")
                    limit = safe_int(payload.get("limit", 5), 5, 1, 20)
                    if not q:
                        return self._send(400, {"error": "Missing query 'q'"})
                    return self._send(200, nexus.augment_query(q, limit))

                if self.path == "/api/v1/predictive-refresh":
                    count = nexus.predictive_refresh(safe_int(payload.get("limit", 10), 10, 1, 50))
                    return self._send(200, {"ok": True, "refreshed_queued": count})

        api_host = str(CONFIG.get("api_host", "127.0.0.1")).strip() or "127.0.0.1"
        token = str(CONFIG.get("api_token", "")).strip()
        try:
            addr = ipaddress.ip_address(api_host)
            if not addr.is_loopback and not token:
                self.emit("api", "API disabled: non-loopback binding requires an API token")
                logging.error("Refusing unauthenticated non-loopback API binding")
                return
        except ValueError:
            if api_host not in ("localhost",) and not token:
                self.emit("api", "API disabled: remote hostname binding requires an API token")
                return
        try:
            self.server = ThreadingHTTPServer((api_host, safe_int(CONFIG.get("api_port"), 8765, 1024, 65535)), Handler)
            self.server.daemon_threads = True
            self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="NexusAPI")
            self.server_thread.start()
            self.emit("api", f"API running on http://{api_host}:{CONFIG['api_port']}/api/v1")
        except OSError as exc:
            self.server = None
            self.server_thread = None
            logging.exception("API server could not start")
            self.emit("error", f"API unavailable (port/host issue): {exc}")

    def cluster_status(self) -> dict:
        with self._connect() as db:
            pending = db.execute("SELECT COUNT(*) FROM pending_discoveries WHERE status='pending'").fetchone()[0]
            nodes = db.execute("SELECT node_id,last_seen,metrics_json FROM cluster_nodes ORDER BY last_seen DESC LIMIT 100").fetchall()
            outbox = db.execute("SELECT COUNT(*) FROM cluster_outbox").fetchone()[0]
        return {
            "enabled": bool(CONFIG.get("cluster_enabled", False)),
            "cluster_id": str(CONFIG.get("cluster_id", "")),
            "node_id": str(CONFIG.get("cluster_node_id", "")),
            "peer_count": len(CONFIG.get("cluster_peers", []) or []),
            "pending_discoveries": int(pending),
            "outbox_events": int(outbox),
            "nodes": [{"node_id": r["node_id"], "last_seen": r["last_seen"],
                       "metrics": json.loads(r["metrics_json"] or "{}")} for r in nodes]
        }

    def _cluster_publish(self, event_type: str, payload: dict) -> None:
        if not CONFIG.get("cluster_enabled", False):
            return
        allowed = {"discovery", "cache_meta", "metrics", "learning"}
        if event_type not in allowed:
            return
        try:
            event_id = str(uuid.uuid4())
            with self._connect() as db:
                db.execute("INSERT OR IGNORE INTO cluster_outbox(event_id,event_type,payload,created_at) VALUES(?,?,?,?)",
                           (event_id, event_type, json.dumps(payload, separators=(",", ":")), utc_now()))
                db.execute("""DELETE FROM cluster_outbox WHERE event_id IN
                            (SELECT event_id FROM cluster_outbox ORDER BY created_at DESC LIMIT -1 OFFSET 5000)""")
        except Exception:
            logging.exception("Unable to publish cluster event")

    @staticmethod
    def _cluster_peer_url(peer: str) -> str | None:
        try:
            p = urllib.parse.urlsplit(str(peer).strip())
            if p.scheme not in ("http", "https") or not p.hostname or p.username or p.password:
                return None
            if p.scheme == "http":
                host = p.hostname.lower()
                if host not in ("localhost",) and not host.endswith(".local"):
                    try:
                        ip = ipaddress.ip_address(host)
                        if not (ip.is_private or ip.is_loopback or ip.is_link_local):
                            return None
                    except ValueError:
                        return None
            return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path.rstrip("/"), "", ""))
        except Exception:
            return None

    def _cluster_sign(self, body: bytes, timestamp: str, node_id: str) -> str:
        secret = str(CONFIG.get("cluster_secret", "")).encode("utf-8")
        message = timestamp.encode("ascii") + b"\n" + node_id.encode("utf-8") + b"\n" + body
        return hmac.new(secret, message, hashlib.sha256).hexdigest()

    def _cluster_verify(self, body: bytes, timestamp: str, node_id: str, signature: str) -> bool:
        if not CONFIG.get("cluster_enabled", False) or not CONFIG.get("cluster_secret"):
            return False
        try:
            ts = int(timestamp)
            if abs(time.time() - ts) > 300 or not node_id or node_id == CONFIG.get("cluster_node_id"):
                return False
            expected = self._cluster_sign(body, timestamp, node_id)
            return hmac.compare_digest(expected, str(signature))
        except Exception:
            return False

    def _cluster_apply_events(self, source_node: str, events: list) -> int:
        if not isinstance(events, list) or len(events) > 500:
            raise ValueError("Invalid event batch")
        accepted = 0
        now = utc_now()
        for event in events:
            if not isinstance(event, dict):
                continue
            event_id = str(event.get("event_id", ""))[:80]
            event_type = str(event.get("type", ""))
            payload = event.get("payload", {})
            if not event_id or event_type not in {"discovery", "cache_meta", "metrics", "learning"} or not isinstance(payload, dict):
                continue
            if event_type in ("discovery", "cache_meta"):
                url = normalize_url(str(payload.get("url", "")))
                if not url:
                    continue
                payload["url"] = url
            with self._connect() as db:
                cur = db.execute("INSERT OR IGNORE INTO cluster_inbox(event_id,node_id,received_at,event_type) VALUES(?,?,?,?)",
                                 (event_id, source_node[:128], now, event_type))
                if cur.rowcount == 0:
                    continue
                if event_type == "discovery":
                    db.execute("""INSERT OR IGNORE INTO pending_discoveries
                                  (event_id,source_node,url,title,discovered_at,status)
                                  VALUES(?,?,?,?,?,'pending')""",
                               (event_id, source_node[:128], payload["url"],
                                str(payload.get("title", ""))[:300], str(payload.get("discovered_at", now))[:64]))
                elif event_type == "cache_meta":
                    db.execute("""INSERT INTO shared_cache_meta(url,source_node,title,sha256,fetched_at,received_at)
                                  VALUES(?,?,?,?,?,?) ON CONFLICT(url) DO UPDATE SET
                                  source_node=excluded.source_node,title=excluded.title,
                                  sha256=excluded.sha256,fetched_at=excluded.fetched_at,
                                  received_at=excluded.received_at""",
                               (payload["url"], source_node[:128], str(payload.get("title", ""))[:300],
                                str(payload.get("sha256", ""))[:64], str(payload.get("fetched_at", now))[:64], now))
                elif event_type == "metrics":
                    db.execute("""INSERT INTO cluster_nodes(node_id,last_seen,metrics_json) VALUES(?,?,?)
                                  ON CONFLICT(node_id) DO UPDATE SET last_seen=excluded.last_seen,
                                  metrics_json=excluded.metrics_json""",
                               (source_node[:128], now, json.dumps(payload)[:4000]))
                elif event_type == "learning":
                    domain = str(payload.get("domain", "")).lower().strip()[:253]
                    if domain and re.fullmatch(r"[a-z0-9.-]+", domain):
                        db.execute("""INSERT INTO shared_domain_learning
                                     (domain,success_count,error_count,avg_latency_ms,reputation_weight,source_node,updated_at)
                                     VALUES(?,?,?,?,?,?,?) ON CONFLICT(domain) DO UPDATE SET
                                     success_count=excluded.success_count,error_count=excluded.error_count,
                                     avg_latency_ms=excluded.avg_latency_ms,
                                     reputation_weight=excluded.reputation_weight,
                                     source_node=excluded.source_node,updated_at=excluded.updated_at""",
                                   (domain, safe_int(payload.get("success_count"), 0, 0, 10**9),
                                    safe_int(payload.get("error_count"), 0, 0, 10**9),
                                    safe_float(payload.get("avg_latency_ms"), 0, 0, 1e9),
                                    safe_float(payload.get("reputation_weight"), 1, 0.2, 3),
                                    source_node[:128], now))
            accepted += 1

        if CONFIG.get("cluster_auto_accept_discoveries", False):
            with self._connect() as db:
                rows = db.execute("SELECT id,url FROM pending_discoveries WHERE status='pending' LIMIT 50").fetchall()
            for row in rows:
                if self.queue_url(row["url"], 0, "cluster-auto-approved"):
                    with self._connect() as db:
                        db.execute("UPDATE pending_discoveries SET status='accepted' WHERE id=?", (row["id"],))
        return accepted

    def cluster_pending(self) -> list[dict]:
        with self._connect() as db:
            rows = db.execute("""SELECT id,source_node,url,title,discovered_at
                                 FROM pending_discoveries WHERE status='pending'
                                 ORDER BY id DESC LIMIT 500""").fetchall()
        return [dict(r) for r in rows]

    def cluster_approve_discovery(self, row_id: int) -> bool:
        with self._connect() as db:
            row = db.execute("SELECT url FROM pending_discoveries WHERE id=? AND status='pending'",
                             (int(row_id),)).fetchone()
        if not row:
            return False
        added = self.queue_url(row["url"], 0, "cluster-approved")
        with self._connect() as db:
            db.execute("UPDATE pending_discoveries SET status=? WHERE id=?",
                       ("accepted" if added else "rejected", int(row_id)))
        return added

    def _cluster_metrics_payload(self) -> dict:
        st = self.status()
        usage = shutil.disk_usage(self.root)
        return {"pages": int(st.get("pages", 0)), "queued": int(st.get("queued", 0)),
                "cache_bytes": int(st.get("cache_bytes", 0)),
                "fetched": int(self.stats.get("fetched", 0)),
                "errors": int(self.stats.get("errors", 0)),
                "free_disk_bytes": int(usage.free), "reported_at": utc_now()}

    def _cluster_build_events(self) -> list:
        events = []
        with self._connect() as db:
            rows = db.execute("SELECT event_id,event_type,payload FROM cluster_outbox ORDER BY created_at DESC LIMIT ?",
                              (safe_int(CONFIG.get("cluster_max_events_per_sync"), 100, 1, 500),)).fetchall()
        for r in reversed(rows):
            try:
                events.append({"event_id": r["event_id"], "type": r["event_type"],
                               "payload": json.loads(r["payload"])})
            except Exception:
                continue
        return events

    def cluster_sync_once(self) -> dict:
        if not CONFIG.get("cluster_enabled", False):
            return {"ok": False, "error": "Cluster mesh is disabled"}
        self._cluster_publish("metrics", self._cluster_metrics_payload())
        if CONFIG.get("cluster_share_learning", True):
            with self._connect() as db:
                rows = db.execute("SELECT domain,success_count,error_count,avg_latency_ms,reputation_weight FROM domain_stats ORDER BY last_updated DESC LIMIT 20").fetchall()
            for r in rows:
                self._cluster_publish("learning", dict(r))
        peers = CONFIG.get("cluster_peers", [])
        if not isinstance(peers, list):
            peers = []
        results = []
        events = self._cluster_build_events()
        body = json.dumps({"cluster_id": CONFIG.get("cluster_id"),
                           "node_id": CONFIG.get("cluster_node_id"),
                           "events": events}, separators=(",", ":")).encode("utf-8")
        timestamp = str(int(time.time()))
        signature = self._cluster_sign(body, timestamp, str(CONFIG.get("cluster_node_id")))
        for raw_peer in peers[:100]:
            peer = self._cluster_peer_url(raw_peer)
            if not peer:
                results.append({"peer": str(raw_peer)[:120], "ok": False, "error": "Peer URL rejected"})
                continue
            req = urllib.request.Request(peer + "/cluster/v1/sync", data=body, method="POST",
                headers={"Content-Type": "application/json", "Content-Length": str(len(body)),
                         "X-Dominion-Timestamp": timestamp,
                         "X-Dominion-Node": str(CONFIG.get("cluster_node_id")),
                         "X-Dominion-Signature": signature})
            try:
                with urllib.request.urlopen(req, timeout=8) as response:
                    data = json.loads(response.read(65536).decode("utf-8"))
                    results.append({"peer": peer, "ok": response.status == 200,
                                    "accepted": data.get("accepted", 0)})
            except Exception as exc:
                results.append({"peer": peer, "ok": False, "error": str(exc)[:180]})
        self.emit("cluster", f"Mesh sync completed: {sum(1 for r in results if r['ok'])}/{len(results)} peers reachable")
        return {"ok": True, "results": results, "events_sent": len(events)}

    def _cluster_sync_loop(self):
        while not self.cluster_stop_event.wait(safe_int(CONFIG.get("cluster_sync_interval"), 60, 15, 3600)):
            try:
                self.cluster_sync_once()
            except Exception:
                logging.exception("Cluster synchronization cycle failed")

    def stop(self):
        with self._shutdown_lock:
            if self._stopped:
                return
            self._stopped = True
        self.stop_event.set()
        self.cluster_stop_event.set()
        if self.cluster_thread and self.cluster_thread.is_alive():
            self.cluster_thread.join(timeout=2.0)
        for thread in list(self.workers):
            if thread.is_alive():
                thread.join(timeout=2.0)
        if self.auto_adder_thread.is_alive():
            self.auto_adder_thread.join(timeout=1.0)
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                logging.exception("API server shutdown encountered an error")

        pending = {}
        with self.lock:
            pending.update(self.active_tasks)
        while True:
            try:
                task = self.tasks.get_nowait()
                pending[task.url] = task
                self.tasks.task_done()
            except queue.Empty:
                break
        try:
            with self._connect() as db:
                db.execute("DELETE FROM crawl_queue")
                for task in pending.values():
                    db.execute(
                        """INSERT OR REPLACE INTO crawl_queue
                           (url,depth,reason,priority_weight,queued_at)
                           VALUES(?,?,?,?,?)""",
                        (task.url, task.depth, task.reason, abs(task.priority_weight), utc_now())
                    )
            self.save_persistent_state()
        except Exception:
            logging.exception("Could not persist queue during shutdown")

class Dashboard:
    def __init__(self, root: tk.Tk, nexus: Nexus):
        self.root = root
        self.nexus = nexus
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1050x720")
        self.root.minsize(800, 560)
        self._setup_styles()
        self._build_ui()
        self._last_heavy_refresh = 0.0
        self._poll_events()
        self._poll_stats()

    def _setup_styles(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure(".", font=("Segoe UI", 10))
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"), foreground="#1e293b")
        style.configure("Heading.TLabel", font=("Segoe UI", 11, "bold"), foreground="#334155")
        style.configure("Stat.TLabel", font=("Segoe UI", 20, "bold"), foreground="#0f172a")

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=12)
        main.pack(fill=tk.BOTH, expand=True)

        hdr = ttk.Frame(main)
        hdr.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(hdr, text=APP_NAME, style="Title.TLabel").pack(side=tk.LEFT)
        
        btn_frame = ttk.Frame(hdr)
        btn_frame.pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Add Seed / URL", command=self.prompt_add_url).pack(side=tk.LEFT, padx=4)
        ttk.Button(btn_frame, text="Export RAG JSON", command=self.export_dataset_gui).pack(side=tk.LEFT, padx=4)

        stats_frame = ttk.LabelFrame(main, text="Nexus Persistent Memory & Active Metrics", padding=10)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        stats_frame.columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        self.lbl_pages = self._make_stat(stats_frame, "Cached Pages", "0", 0)
        self.lbl_queued = self._make_stat(stats_frame, "Queue Backlog", "0", 1)
        self.lbl_fetched = self._make_stat(stats_frame, "Fetched Total", "0", 2)
        self.lbl_bytes = self._make_stat(stats_frame, "Storage Size", "0 MB", 3)
        self.lbl_aug = self._make_stat(stats_frame, "RAG Augmentations", "0", 4)
        self.lbl_errors = self._make_stat(stats_frame, "Errors / Blocked", "0 / 0", 5)

        self.nb = ttk.Notebook(main)
        self.nb.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.tab_live = ttk.Frame(self.nb, padding=8)
        self.tab_search = ttk.Frame(self.nb, padding=8)
        self.tab_learning = ttk.Frame(self.nb, padding=8)
        self.tab_history = ttk.Frame(self.nb, padding=8)
        self.tab_settings = ttk.Frame(self.nb, padding=8)
        self.tab_cluster = ttk.Frame(self.nb, padding=8)
        
        self.nb.add(self.tab_live, text="Live Activity & Browser Tracker")
        self.nb.add(self.tab_search, text="FTS5 Search & RAG Augment")
        self.nb.add(self.tab_learning, text="Learning Weights & Domain Reputation")
        self.nb.add(self.tab_history, text="Auto-URL Inbox & History")
        self.nb.add(self.tab_settings, text="Settings & Startup Persistence")
        self.nb.add(self.tab_cluster, text="Multi-PC Intelligence Mesh")

        self._build_live_tab()
        self._build_search_tab()
        self._build_learning_tab()
        self._build_history_tab()
        self._build_settings_tab()
        self._build_cluster_tab()

        sb = ttk.Frame(main)
        sb.pack(fill=tk.X)
        self.lbl_status = ttk.Label(sb, text="Ready", foreground="#475569")
        self.lbl_status.pack(side=tk.LEFT)

    def _build_cluster_tab(self):
        frame = self.tab_cluster
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(4, weight=1)
        intro = ttk.LabelFrame(frame, text="Local-first multi-PC intelligence mesh", padding=8)
        intro.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        ttk.Label(intro, text=("Share URL discoveries, cache fingerprints/freshness, aggregate node metrics, "
                               "and domain-learning signals with explicitly trusted peers. Page bodies, "
                               "browser history, passwords, and remote commands are never shared."),
                  wraplength=900).pack(anchor="w")
        self.cluster_enabled_var = tk.BooleanVar(value=bool(CONFIG.get("cluster_enabled", False)))
        self.cluster_auto_var = tk.BooleanVar(value=bool(CONFIG.get("cluster_auto_accept_discoveries", False)))
        self.cluster_id_var = tk.StringVar(value=str(CONFIG.get("cluster_id", "")))
        self.cluster_secret_var = tk.StringVar(value=str(CONFIG.get("cluster_secret", "")))
        self.cluster_interval_var = tk.StringVar(value=str(CONFIG.get("cluster_sync_interval", 60)))
        ttk.Checkbutton(intro, text="Enable multi-PC mesh (opt-in)", variable=self.cluster_enabled_var).pack(anchor="w")
        ttk.Checkbutton(intro, text="Auto-accept validated incoming discoveries (normally leave off)",
                        variable=self.cluster_auto_var).pack(anchor="w")
        row = ttk.Frame(intro); row.pack(fill="x", pady=3)
        ttk.Label(row, text="Cluster ID").pack(side="left")
        ttk.Entry(row, textvariable=self.cluster_id_var, width=32).pack(side="left", padx=5)
        ttk.Label(row, text="Sync seconds").pack(side="left", padx=(12, 0))
        ttk.Entry(row, textvariable=self.cluster_interval_var, width=8).pack(side="left", padx=5)
        secret_row = ttk.Frame(intro); secret_row.pack(fill="x", pady=3)
        ttk.Label(secret_row, text="Shared secret").pack(side="left")
        ttk.Entry(secret_row, textvariable=self.cluster_secret_var, width=58, show="•").pack(side="left", padx=5)
        ttk.Button(secret_row, text="Generate", command=self.cluster_generate_secret).pack(side="left", padx=3)
        ttk.Label(intro, text="Use the same strong secret and cluster ID on every trusted node. Store it securely.",
                  foreground="#8a4b08").pack(anchor="w")
        peerbox = ttk.LabelFrame(frame, text="Trusted peer API base URLs (one per line)", padding=8)
        peerbox.grid(row=1, column=0, sticky="ew", pady=(0, 8))
        self.cluster_peers_text = tk.Text(peerbox, height=3, wrap="none")
        self.cluster_peers_text.pack(fill="x")
        self.cluster_peers_text.insert("1.0", "\n".join(CONFIG.get("cluster_peers", []) or []))
        btns = ttk.Frame(frame); btns.grid(row=2, column=0, sticky="ew", pady=4)
        ttk.Button(btns, text="Save Mesh Settings", command=self.cluster_save_ui).pack(side="left", padx=3)
        ttk.Button(btns, text="Sync Now", command=self.cluster_sync_ui).pack(side="left", padx=3)
        ttk.Button(btns, text="Refresh", command=self.cluster_refresh_ui).pack(side="left", padx=3)
        ttk.Label(frame, text=("LAN setup: in Settings set API Host to 0.0.0.0 and configure a strong API token. "
                               "Use a trusted LAN or VPN; do not port-forward this endpoint. "
                               "Plain HTTP peers are accepted only for private/loopback addresses; use HTTPS otherwise."),
                  wraplength=900, foreground="#8a4b08").grid(row=3, column=0, sticky="w", pady=4)
        panes = ttk.Panedwindow(frame, orient=tk.HORIZONTAL)
        panes.grid(row=4, column=0, sticky="nsew")
        left = ttk.LabelFrame(panes, text="Incoming discoveries — approve before queueing", padding=6)
        right = ttk.LabelFrame(panes, text="Known nodes / aggregate performance", padding=6)
        panes.add(left, weight=1); panes.add(right, weight=1)
        self.cluster_pending_tree = ttk.Treeview(left, columns=("node", "url", "date"), show="headings", height=8)
        for col, width in (("node", 100), ("url", 300), ("date", 130)):
            self.cluster_pending_tree.heading(col, text=col.title())
            self.cluster_pending_tree.column(col, width=width, stretch=True)
        self.cluster_pending_tree.pack(fill="both", expand=True)
        ttk.Button(left, text="Approve Selected", command=self.cluster_approve_ui).pack(anchor="e", pady=4)
        self.cluster_nodes_tree = ttk.Treeview(right, columns=("node", "seen", "pages", "queued", "free"), show="headings", height=8)
        for col, width in (("node", 120), ("seen", 140), ("pages", 70), ("queued", 70), ("free", 100)):
            self.cluster_nodes_tree.heading(col, text=col.title())
            self.cluster_nodes_tree.column(col, width=width, stretch=True)
        self.cluster_nodes_tree.pack(fill="both", expand=True)
        self.cluster_refresh_ui()

    def cluster_generate_secret(self):
        import secrets
        self.cluster_secret_var.set(secrets.token_urlsafe(36))

    def cluster_save_ui(self):
        secret = self.cluster_secret_var.get().strip()
        cluster_id = self.cluster_id_var.get().strip()
        if not cluster_id or len(cluster_id) > 128 or not secret or len(secret) < 24:
            messagebox.showerror("Mesh settings", "Set a cluster ID and a shared secret of at least 24 characters.")
            return False
        peers = [line.strip().rstrip("/") for line in self.cluster_peers_text.get("1.0", "end").splitlines()
                 if line.strip()]
        if len(peers) > 100 or any(self.nexus._cluster_peer_url(p) is None for p in peers):
            messagebox.showerror("Mesh settings", "A peer URL is invalid. Use HTTPS or a private LAN IP with HTTP.")
            return False
        CONFIG["cluster_enabled"] = bool(self.cluster_enabled_var.get())
        CONFIG["cluster_auto_accept_discoveries"] = bool(self.cluster_auto_var.get())
        CONFIG["cluster_id"] = cluster_id
        CONFIG["cluster_secret"] = secret
        CONFIG["cluster_sync_interval"] = safe_int(self.cluster_interval_var.get(), 60, 15, 3600)
        CONFIG["cluster_peers"] = peers
        save_config()
        messagebox.showinfo("Mesh settings", "Settings saved. Restart the application to apply enable/disable changes.")
        return True

    def cluster_sync_ui(self):
        if not self.cluster_save_ui():
            return
        threading.Thread(target=self.nexus.cluster_sync_once, daemon=True, name="ManualClusterSync").start()

    def cluster_refresh_ui(self):
        if not hasattr(self, "cluster_pending_tree"):
            return
        for tree in (self.cluster_pending_tree, self.cluster_nodes_tree):
            for item in tree.get_children():
                tree.delete(item)
        for item in self.nexus.cluster_pending():
            self.cluster_pending_tree.insert("", "end", iid=str(item["id"]),
                values=(item["source_node"][:12], item["url"], item["discovered_at"][:19]))
        st = self.nexus.cluster_status()
        for node in st["nodes"]:
            m = node["metrics"]
            free_gb = float(m.get("free_disk_bytes", 0)) / (1024 ** 3)
            self.cluster_nodes_tree.insert("", "end",
                values=(node["node_id"][:12], node["last_seen"][:19],
                        m.get("pages", 0), m.get("queued", 0), f"{free_gb:.1f} GB"))

    def cluster_approve_ui(self):
        sel = self.cluster_pending_tree.selection()
        if not sel:
            messagebox.showinfo("Mesh", "Select an incoming discovery first.")
            return
        ok = self.nexus.cluster_approve_discovery(int(sel[0]))
        self.cluster_refresh_ui()
        messagebox.showinfo("Mesh", "Discovery approved and queued." if ok else
                                    "Discovery was rejected by local URL/domain policy or was already queued.")

    def _make_stat(self, parent, title, val, col):
        f = ttk.Frame(parent)
        f.grid(row=0, column=col, sticky="nsew", padx=4)
        ttk.Label(f, text=title, font=("Segoe UI", 9), foreground="#64748b").pack(anchor="w")
        lbl = ttk.Label(f, text=val, style="Stat.TLabel")
        lbl.pack(anchor="w")
        return lbl

    def _build_live_tab(self):
        frame = self.tab_live
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        ctrl = ttk.Frame(frame)
        ctrl.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        
        self.btn_crawl = ttk.Button(ctrl, text="Start Crawler Workers", command=self.toggle_crawl)
        self.btn_crawl.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(ctrl, text="Trigger Predictive Refresh", command=lambda: self.nexus.predictive_refresh(10)).pack(side=tk.LEFT, padx=4)
        ttk.Button(ctrl, text="Run Expiry Cleanup", command=lambda: self.nexus.cleanup_expired()).pack(side=tk.LEFT, padx=4)

        log_frame = ttk.Frame(frame)
        log_frame.grid(row=1, column=0, sticky="nsew")
        log_frame.columnconfigure(0, weight=1)
        log_frame.rowconfigure(0, weight=1)

        self.txt_log = tk.Text(log_frame, wrap=tk.WORD, font=("Consolas", 9), background="#0f172a", foreground="#f8fafc")
        sb_log = ttk.Scrollbar(log_frame, orient=tk.VERTICAL, command=self.txt_log.yview)
        self.txt_log.configure(yscrollcommand=sb_log.set)
        self.txt_log.grid(row=0, column=0, sticky="nsew")
        sb_log.grid(row=0, column=1, sticky="ns")

    def _build_search_tab(self):
        frame = self.tab_search
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        top = ttk.Frame(frame)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        top.columnconfigure(0, weight=1)

        self.ent_search = ttk.Entry(top, font=("Segoe UI", 11))
        self.ent_search.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.ent_search.bind("<Return>", lambda e: self.do_search())
        ttk.Button(top, text="FTS5 Search", command=self.do_search).grid(row=0, column=1, padx=2)
        ttk.Button(top, text="Augment Context", command=self.do_augment).grid(row=0, column=2, padx=2)

        results_frame = ttk.Frame(frame)
        results_frame.grid(row=1, column=0, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        cols = ("url", "title", "domain", "weight", "fetched", "accesses")
        self.tree_search = ttk.Treeview(results_frame, columns=cols, show="headings", selectmode="browse")
        for col in cols:
            self.tree_search.heading(col, text=col.capitalize())
        
        sb_search = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree_search.yview)
        self.tree_search.configure(yscrollcommand=sb_search.set)
        self.tree_search.grid(row=0, column=0, sticky="nsew")
        sb_search.grid(row=0, column=1, sticky="ns")
        self.tree_search.bind("<Double-1>", self.inspect_cached_page)

    def _build_learning_tab(self):
        frame = self.tab_learning
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(1, weight=1)

        top = ttk.Frame(frame)
        top.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        ttk.Label(top, text="Autonomous Domain Reputation & Learning Weights", style="Heading.TLabel").pack(side=tk.LEFT)
        ttk.Button(top, text="Refresh Learning Weights", command=self.refresh_learning_data).pack(side=tk.RIGHT)

        cols = ("domain", "successes", "errors", "avg_latency_ms", "reputation_weight", "last_updated")
        self.tree_learning = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        for col in cols:
            self.tree_learning.heading(col, text=col.replace("_", " ").capitalize())
        
        sb_ln = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree_learning.yview)
        self.tree_learning.configure(yscrollcommand=sb_ln.set)
        self.tree_learning.grid(row=1, column=0, sticky="nsew")
        sb_ln.grid(row=1, column=1, sticky="ns")
        self.refresh_learning_data()

    def refresh_learning_data(self):
        for item in self.tree_learning.get_children():
            self.tree_learning.delete(item)
        with self.nexus._connect() as db:
            rows = db.execute("SELECT domain, success_count, error_count, avg_latency_ms, reputation_weight, last_updated FROM domain_stats ORDER BY reputation_weight DESC").fetchall()
            for r in rows:
                self.tree_learning.insert("", tk.END, values=(
                    r["domain"], r["success_count"], r["error_count"], f"{r['avg_latency_ms']:.1f}ms", f"{r['reputation_weight']:.2f}", r["last_updated"][:19]
                ))

    def _build_history_tab(self):
        frame = self.tab_history
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        cols = ("url", "source", "added_at")
        self.tree_history = ttk.Treeview(frame, columns=cols, show="headings", selectmode="browse")
        for col in cols:
            self.tree_history.heading(col, text=col.replace("_", " ").capitalize())
        
        sb_hist = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=self.tree_history.yview)
        self.tree_history.configure(yscrollcommand=sb_hist.set)
        self.tree_history.grid(row=0, column=0, sticky="nsew")
        sb_hist.grid(row=0, column=1, sticky="ns")
        self.refresh_history_tab()

    def _build_settings_tab(self):
        frame = self.tab_settings
        frame.columnconfigure(0, weight=1)
        frame.rowconfigure(0, weight=1)

        canvas = tk.Canvas(frame, highlightthickness=0)
        scrollbar = ttk.Scrollbar(frame, orient="vertical", command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas, padding=10)

        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)

        canvas.grid(row=0, column=0, sticky="nsew")
        scrollbar.grid(row=0, column=1, sticky="ns")

        self.settings_vars = {}
        general_lf = ttk.LabelFrame(scrollable_frame, text="General & Network Configuration", padding=10)
        general_lf.pack(fill=tk.X, expand=True, pady=(0, 10))
        general_lf.columnconfigure(1, weight=1)

        fields = [
            ("workers", "Worker Threads", int),
            ("max_depth", "Max Crawl Depth", int),
            ("request_timeout", "Request Timeout (s)", int),
            ("per_host_delay", "Per-Host Delay (s)", float),
            ("primary_cap_gb", "Primary Storage Cap (GB)", float),
            ("refresh_after_hours", "Refresh Interval (Hours)", int)
        ]

        for idx, (key, label, cast_func) in enumerate(fields):
            ttk.Label(general_lf, text=label).grid(row=idx, column=0, sticky="w", pady=4, padx=4)
            var = tk.StringVar(value=str(CONFIG.get(key, "")))
            self.settings_vars[key] = (var, cast_func)
            ent = ttk.Entry(general_lf, textvariable=var, width=15)
            ent.grid(row=idx, column=1, sticky="w", pady=4, padx=4)

        boot_lf = ttk.LabelFrame(scrollable_frame, text="OS Startup Persistence (Auto-Boot)", padding=10)
        boot_lf.pack(fill=tk.X, expand=True, pady=(0, 10))
        
        ttk.Label(boot_lf, text="Register Nexus to start automatically when your computer boots up:").pack(anchor="w", pady=(0, 6))
        boot_btn_frame = ttk.Frame(boot_lf)
        boot_btn_frame.pack(anchor="w")
        ttk.Button(boot_btn_frame, text="Enable OS Startup", command=self.enable_startup).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(boot_btn_frame, text="Disable OS Startup", command=self.disable_startup).pack(side=tk.LEFT)

        domains_lf = ttk.LabelFrame(scrollable_frame, text="Allowed Domains Management", padding=10)
        domains_lf.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        domains_lf.columnconfigure(0, weight=1)
        domains_lf.rowconfigure(1, weight=1)

        dom_top = ttk.Frame(domains_lf)
        dom_top.grid(row=0, column=0, sticky="ew", pady=(0, 6))
        dom_top.columnconfigure(0, weight=1)

        self.ent_new_domain = ttk.Entry(dom_top, font=("Segoe UI", 10))
        self.ent_new_domain.grid(row=0, column=0, sticky="ew", padx=(0, 6))
        self.ent_new_domain.bind("<Return>", lambda e: self.add_allowed_domain())
        ttk.Button(dom_top, text="Add Domain", command=self.add_allowed_domain).grid(row=0, column=1, padx=2)
        ttk.Button(dom_top, text="Remove Selected", command=self.remove_allowed_domain).grid(row=0, column=2, padx=2)

        dom_list_frame = ttk.Frame(domains_lf)
        dom_list_frame.grid(row=1, column=0, sticky="nsew")
        dom_list_frame.columnconfigure(0, weight=1)
        dom_list_frame.rowconfigure(0, weight=1)

        self.listbox_domains = tk.Listbox(dom_list_frame, font=("Consolas", 10), selectmode=tk.SINGLE, height=6)
        sb_dom = ttk.Scrollbar(dom_list_frame, orient=tk.VERTICAL, command=self.listbox_domains.yview)
        self.listbox_domains.configure(yscrollcommand=sb_dom.set)
        self.listbox_domains.grid(row=0, column=0, sticky="nsew")
        sb_dom.grid(row=0, column=1, sticky="ns")
        self.populate_allowed_domains_list()

        btn_save = ttk.Button(scrollable_frame, text="Save Settings & Apply", command=self.save_settings)
        btn_save.pack(anchor="e", pady=10)

    def enable_startup(self):
        if register_os_startup():
            messagebox.showinfo("Startup Enabled", "Nexus has been successfully registered to start automatically on system boot.")
            self.nexus.emit("settings", "Enabled OS startup persistence.")
        else:
            messagebox.showerror("Error", "Failed to register OS startup. Administrator privileges or Windows OS required.")

    def disable_startup(self):
        if unregister_os_startup():
            messagebox.showinfo("Startup Disabled", "Nexus has been removed from OS startup entries.")
            self.nexus.emit("settings", "Disabled OS startup persistence.")
        else:
            messagebox.showerror("Error", "Failed to remove OS startup entry.")

    def populate_allowed_domains_list(self):
        self.listbox_domains.delete(0, tk.END)
        domains = CONFIG.get("allowed_domains", [])
        for d in sorted(domains):
            self.listbox_domains.insert(tk.END, d)

    def add_allowed_domain(self):
        raw = self.ent_new_domain.get().strip().lower()
        if not raw:
            return
        if "://" in raw:
            raw = domain_of(raw)
        raw = raw.strip("/")
        if not raw:
            messagebox.showerror("Invalid Domain", "Please enter a valid domain name (e.g. example.com).")
            return
        
        domains = CONFIG.get("allowed_domains", [])
        if raw not in domains:
            domains.append(raw)
            CONFIG["allowed_domains"] = sorted(domains)
            save_config()
            self.populate_allowed_domains_list()
            self.ent_new_domain.delete(0, tk.END)
            self.nexus.emit("settings", f"Added allowed domain: {raw}")
        else:
            messagebox.showinfo("Already Exists", f"Domain '{raw}' is already in the allowed list.")

    def remove_allowed_domain(self):
        selection = self.listbox_domains.curselection()
        if not selection:
            messagebox.showwarning("Select Domain", "Please select a domain from the list to remove.")
            return
        idx = selection[0]
        domain_to_remove = self.listbox_domains.get(idx)
        domains = CONFIG.get("allowed_domains", [])
        if domain_to_remove in domains:
            domains.remove(domain_to_remove)
            CONFIG["allowed_domains"] = domains
            save_config()
            self.populate_allowed_domains_list()
            self.nexus.emit("settings", f"Removed allowed domain: {domain_to_remove}")

    def save_settings(self):
        try:
            for key, (var, cast_func) in self.settings_vars.items():
                val_str = var.get().strip()
                value = cast_func(val_str)
                if key == "workers": value = max(1, min(32, value))
                elif key == "max_depth": value = max(0, min(10, value))
                elif key == "request_timeout": value = max(3, min(60, value))
                elif key == "per_host_delay": value = max(0.25, min(60.0, value))
                elif key == "primary_cap_gb": value = max(0.1, min(10000.0, value))
                elif key == "refresh_after_hours": value = max(1, min(8760, value))
                CONFIG[key] = value
            save_config()
            if CONFIG.get("crawl_enabled", False):
                self.nexus.start_workers()
            messagebox.showinfo("Settings Saved", "Configuration parameters have been successfully saved and applied.")
            self.nexus.emit("settings", "Updated global settings parameters.")
        except Exception as e:
            messagebox.showerror("Validation Error", f"Invalid value provided: {e}")

    def toggle_crawl(self):
        current = CONFIG.get("crawl_enabled", False)
        new_val = not current
        CONFIG["crawl_enabled"] = new_val
        save_config()
        if new_val:
            self.btn_crawl.configure(text="Stop Crawler Workers")
            self.nexus.start_workers()
            self.nexus.seed()
            self.nexus.emit("crawl", "Started autonomous crawler workers")
        else:
            self.btn_crawl.configure(text="Start Crawler Workers")
            self.nexus.emit("crawl", "Paused crawler workers")

    def prompt_add_url(self):
        top = tk.Toplevel(self.root)
        top.title("Add Seed / URL")
        top.geometry("420x150")
        top.resizable(False, False)
        
        ttk.Label(top, text="Enter Target URL:", style="Heading.TLabel").pack(anchor="w", padx=15, pady=(15, 5))
        ent = ttk.Entry(top, font=("Segoe UI", 10), width=50)
        ent.pack(padx=15, pady=5)
        ent.focus()

        def submit():
            raw = ent.get().strip()
            if raw:
                success = self.nexus.queue_url(raw, 0, "manual-ui")
                if success:
                    if CONFIG.get("auto_start_workers_for_manual_queue", True):
                        CONFIG["crawl_enabled"] = True
                        save_config()
                        self.nexus.start_workers()
                        if hasattr(self, "btn_crawl"):
                            self.btn_crawl.configure(text="Stop Crawler Workers")
                    self.nexus.emit("ui", f"Manually queued URL: {raw}")
                    top.destroy()
                else:
                    messagebox.showerror("Error", "Could not queue URL. Check format, allowed domains filter, or duplicates.")

        ttk.Button(top, text="Queue & Probe", command=submit).pack(anchor="e", padx=15, pady=10)
        ent.bind("<Return>", lambda e: submit())

    def export_dataset_gui(self):
        file_path = filedialog.asksaveasfilename(defaultextension=".json", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if file_path:
            try:
                data = self.nexus.export_rag_dataset(500)
                Path(file_path).write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
                messagebox.showinfo("Export Success", f"Successfully exported {len(data)} cache entries for RAG ingestion.")
            except Exception as e:
                messagebox.showerror("Export Error", str(e))

    def do_search(self):
        query = self.ent_search.get().strip()
        for item in self.tree_search.get_children():
            self.tree_search.delete(item)
        if not query:
            return
        results = self.nexus.search(query, 50)
        for r in results:
            self.tree_search.insert("", tk.END, values=(
                r["url"], r["title"], r["domain"], f"{r['learning_weight']:.2f}", r["fetched_at"][:19], r["access_count"]
            ))

    def do_augment(self):
        query = self.ent_search.get().strip()
        if not query:
            messagebox.showwarning("Empty Query", "Please enter a search query to augment context.")
            return
        aug = self.nexus.augment_query(query, limit=5)
        
        win = tk.Toplevel(self.root)
        win.title(f"RAG Augmented Context: {query}")
        win.geometry("800x600")
        
        txt = tk.Text(win, wrap=tk.WORD, font=("Consolas", 9), background="#ffffff", foreground="#0f172a")
        sb = ttk.Scrollbar(win, orient=tk.VERTICAL, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        
        header_info = f"Query: {aug['query']}\nMatched Sources Count: {aug['matched_count']}\nSources: {', '.join(aug['sources'])}\n" + "-"*80 + "\n\n"
        txt.insert(tk.END, header_info + aug["augmented_prompt_context"])
        txt.configure(state=tk.DISABLED)
        
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def inspect_cached_page(self, event):
        selected = self.tree_search.selection()
        if not selected:
            return
        vals = self.tree_search.item(selected[0], "values")
        if not vals:
            return
        url = vals[0]
        cached = self.nexus.fetch_cached(url)
        if not cached:
            return

        win = tk.Toplevel(self.root)
        win.title(f"Cache Inspector: {url}")
        win.geometry("800x600")
        
        txt = tk.Text(win, wrap=tk.WORD, font=("Consolas", 9), background="#ffffff", foreground="#0f172a")
        sb = ttk.Scrollbar(win, orient=tk.VERTICAL, command=txt.yview)
        txt.configure(yscrollcommand=sb.set)
        
        header_info = f"URL: {cached['url']}\nTitle: {cached['title']}\nDomain: {cached['domain']}\nFetched At: {cached['fetched_at']}\nContent-Type: {cached['content_type']}\nSHA-256: {cached['sha256']}\nLearning Weight: {cached.get('learning_weight', 1.0):.2f}\n" + "-"*80 + "\n\n"
        txt.insert(tk.END, header_info + cached["content"])
        txt.configure(state=tk.DISABLED)
        
        txt.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sb.pack(side=tk.RIGHT, fill=tk.Y)

    def refresh_history_tab(self):
        for item in self.tree_history.get_children():
            self.tree_history.delete(item)
        with self.nexus._connect() as db:
            rows = db.execute("SELECT url, source, added_at FROM auto_inbox ORDER BY id DESC LIMIT 100").fetchall()
            for r in rows:
                self.tree_history.insert("", tk.END, values=(r["url"], r["source"], r["added_at"][:19]))

    def _poll_events(self):
        try:
            while True:
                kind, msg = self.nexus.events.get_nowait()
                timestamp = datetime.now().strftime("%H:%M:%S")
                line = f"[{timestamp}] [{kind.upper()}] {msg}\n"
                self.txt_log.insert(tk.END, line)
                self.txt_log.see(tk.END)
        except queue.Empty:
            pass
        self.root.after(200, self._poll_events)

    def _poll_stats(self):
        try:
            st = self.nexus.status()
            self.lbl_pages.configure(text=f"{st['pages']:,}")
            self.lbl_queued.configure(text=f"{st['queued']:,}")
            self.lbl_fetched.configure(text=f"{st['stats']['fetched']:,}")
            mb = st['cache_bytes'] / (1024 * 1024)
            self.lbl_bytes.configure(text=f"{mb:.1f} MB")
            self.lbl_aug.configure(text=f"{st['stats']['augmentations']:,}")
            self.lbl_errors.configure(text=f"{st['stats']['errors']} / {st['stats']['blocked']}")
            self.lbl_status.configure(text=f"Status: {self.nexus.last_message} | API: {st['api']}")
            if time.monotonic() - self._last_heavy_refresh >= 10.0:
                self.refresh_history_tab()
                self.refresh_learning_data()
                self.cluster_refresh_ui()
                self._last_heavy_refresh = time.monotonic()
        except Exception:
            pass
        self.root.after(1000, self._poll_stats)

def main():
    try:
        file_handler = RotatingFileHandler(
            LOG_PATH, maxBytes=5 * 1024 * 1024, backupCount=3, encoding="utf-8"
        )
        handlers = [file_handler, logging.StreamHandler(sys.stdout)]
    except OSError:
        handlers = [logging.StreamHandler(sys.stdout)]
    logging.basicConfig(
        level=getattr(logging, str(CONFIG.get("log_level", "INFO")).upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        handlers=handlers
    )

    nexus = None
    try:
        nexus = Nexus()
        nexus.start_api()
        if CONFIG.get("crawl_enabled", False):
            nexus.start_workers()
            nexus.seed()

        maint_thread = threading.Thread(
            target=nexus.maintenance_loop, daemon=True, name="Maintenance"
        )
        maint_thread.start()

        root = tk.Tk()
        Dashboard(root, nexus)
        root.protocol("WM_DELETE_WINDOW", root.destroy)
        root.mainloop()
    except KeyboardInterrupt:
        logging.info("Shutdown requested from keyboard")
    except Exception:
        logging.exception("DominionDeck failed during startup or runtime")
        raise
    finally:
        if nexus is not None:
            nexus.stop()

def run_self_test() -> int:
    global CONFIG
    original_config = CONFIG
    with tempfile.TemporaryDirectory(prefix="dominion_nexus_test_") as temp_dir:
        test_config = copy.deepcopy(DEFAULT_CONFIG)
        test_config.update({
            "cache_root": temp_dir,
            "cluster_enabled": False,
            "auto_adder_enabled": False,
            "scan_browser_history": False,
            "respect_robots": False,
            "crawl_enabled": False
        })
        CONFIG = test_config
        nexus = None
        try:
            nexus = Nexus()
            test_url = "https://example.com/self-test"
            nexus._store_page(
                test_url,
                "<html><title>Self Test</title><body>dominion nexus test content</body></html>",
                "text/html; charset=utf-8", 200, 0, "", ""
            )
            assert nexus.fetch_cached(test_url), "cache retrieval failed"
            assert nexus.search("dominion nexus"), "search returned no result"
            assert nexus.export_rag_dataset(10), "RAG export returned no data"
            assert nexus.freshness(test_url).get("cached") is True, "freshness check failed"
            print("[SELF-TEST] PASS: database, cache, search, retrieval, freshness, export")
            return 0
        except Exception:
            logging.exception("[SELF-TEST] FAILED")
            return 1
        finally:
            if nexus is not None:
                nexus.stop()
            CONFIG = original_config


if __name__ == "__main__":
    if "--self-test" in sys.argv:
        raise SystemExit(run_self_test())
    main()