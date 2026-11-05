#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DominionDeck Universal AI Probe Nexus v5.3
A local-first, policy-aware web cache and AI retrieval gateway with Auto-URL Discovery,
automated browser history ingestion, and a built-in Allowed Domains Management Panel.

Features
--------
- Bounded autonomous crawler with recursive same-domain link discovery.
- Automated Auto-URL Adder pipeline scanning active feeds, watch files, and live browser history.
- robots.txt checks, per-host rate limiting, size/time limits and safe URL filtering.
- SQLite metadata/index, SHA-256 deduplication, content-addressed cache files.
- Search/fetch/probe/freshness/status API for AI clients and local tools.
- Optional bearer-token authentication for the API.
- Predictive refresh scoring based on age, use frequency and past change signals.
- 60-day unused-entry expiry, LRU eviction and configurable storage ceilings.
- Worker supervision, graceful shutdown, rotating logs, and Tkinter dashboard with Allowed Domains manager.
- Standard library only. Python 3.10+ recommended.
"""

from __future__ import annotations

# --- Standard Library Autoloader & Guard Check ---
import sys
import importlib

REQUIRED_MODULES = [
    "hashlib", "html", "json", "logging", "os", "queue", "re", "shutil",
    "socket", "sqlite3", "threading", "time", "urllib.error", "urllib.parse",
    "urllib.robotparser", "urllib.request", "uuid", "collections", "dataclasses",
    "datetime", "http.server", "html.parser", "pathlib", "typing", "tkinter",
    "hmac", "ipaddress"
]

def autoload_libraries() -> None:
    """Ensures all required standard modules are loaded and available."""
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
import urllib.error
import urllib.parse
import urllib.robotparser
import urllib.request
import uuid
import hmac
import ipaddress
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone, timedelta
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

APP_NAME = "DominionDeck Universal AI Probe Nexus"
APP_VERSION = "5.3.0"
HOME = Path.home()
CONFIG_PATH = HOME / "dominion_nexus_config.json"
DEFAULT_ROOT = HOME / "DominionDeckCache"
LOG_PATH = HOME / "dominion_nexus.log"
USER_AGENT = "DominionDeckProbe/5.3 (+local cache; respects robots.txt)"
MAX_URL_LENGTH = 2048
DEFAULT_CONFIG = {
    "cache_root": str(DEFAULT_ROOT),
    "overflow_root": "",
    "primary_cap_gb": 3.0,
    "overflow_cap_gb": 0.0,
    "ram_index_limit": 5000,
    "max_pages": 500,
    "max_depth": 2,
    "workers": 4,
    "request_timeout": 12,
    "max_page_mb": 2,
    "per_host_delay": 2.0,
    "refresh_after_hours": 72,
    "expire_unused_days": 60,
    "crawl_enabled": False,
    "auto_adder_enabled": True,
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
    "log_level": "INFO"
}

def load_config() -> dict:
    cfg = DEFAULT_CONFIG.copy()
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

class LinkParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.text_parts: list[str] = []
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag.lower() in ("script", "style", "noscript", "svg"):
            self._skip += 1
        if tag.lower() == "a" and attrs.get("href") and len(self.links) < 2000:
            self.links.append(attrs["href"])

    def handle_endtag(self, tag):
        if tag.lower() in ("script", "style", "noscript", "svg") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            s = re.sub(r"\s+", " ", data).strip()
            if s:
                self.text_parts.append(s)

@dataclass
class CrawlTask:
    url: str
    depth: int = 0
    reason: str = "seed"

class Nexus:
    def __init__(self):
        self.lock = threading.RLock()
        self.stop_event = threading.Event()
        self.tasks: queue.Queue[CrawlTask] = queue.Queue(maxsize=10000)
        self.events: queue.Queue[tuple[str, str]] = queue.Queue(maxsize=2000)
        self.seen: set[str] = set()
        self.host_last_request: dict[str, float] = {}
        self.robots: dict[str, urllib.robotparser.RobotFileParser | None] = {}
        self.workers: list[threading.Thread] = []
        self.server: ThreadingHTTPServer | None = None
        self.server_thread: threading.Thread | None = None
        self.root = Path(CONFIG["cache_root"]).expanduser()
        self.root.mkdir(parents=True, exist_ok=True)
        self.content_dir = self.root / "objects"
        self.content_dir.mkdir(exist_ok=True)
        self.db_path = self.root / "nexus.sqlite3"
        self._init_db()
        self.stats = {"fetched": 0, "errors": 0, "bytes": 0, "deduplicated": 0,
                      "blocked": 0, "expired": 0, "api_requests": 0, "auto_added": 0}
        self.last_message = "Ready"
        self._load_seen()
        self._load_queue_state()
        
        # Start background auto-adder feed watch daemon
        self.auto_adder_thread = threading.Thread(target=self._auto_adder_loop, daemon=True)
        self.auto_adder_thread.start()

    def _connect(self):
        conn = sqlite3.connect(self.db_path, timeout=20)
        conn.row_factory = sqlite3.Row
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
                next_refresh TEXT DEFAULT ''
            );
            CREATE INDEX IF NOT EXISTS idx_pages_domain ON pages(domain);
            CREATE INDEX IF NOT EXISTS idx_pages_hash ON pages(sha256);
            CREATE INDEX IF NOT EXISTS idx_pages_access ON pages(last_access);
            CREATE TABLE IF NOT EXISTS crawl_queue(
                url TEXT PRIMARY KEY, depth INTEGER NOT NULL, reason TEXT,
                queued_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS crawl_history(
                id INTEGER PRIMARY KEY, url TEXT, outcome TEXT, detail TEXT,
                created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS auto_inbox(
                id INTEGER PRIMARY KEY, url TEXT UNIQUE NOT NULL, source TEXT, added_at TEXT NOT NULL
            );
            """)

    def _load_seen(self):
        with self._connect() as db:
            self.seen = {r[0] for r in db.execute("SELECT url FROM pages")}

    def _load_queue_state(self):
        with self._connect() as db:
            rows = db.execute("SELECT url,depth,reason FROM crawl_queue ORDER BY queued_at").fetchall()
        for r in rows:
            try:
                self.tasks.put_nowait(CrawlTask(r["url"], r["depth"], r["reason"] or "resume"))
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

    def queue_url(self, raw: str, depth: int = 0, reason: str = "manual") -> bool:
        url = normalize_url(raw)
        if not url:
            return False
        allowed = [d.lower().strip() for d in CONFIG.get("allowed_domains", []) if d.strip()]
        host = domain_of(url)
        if allowed and not any(host == d or host.endswith("." + d) for d in allowed):
            return False
        with self.lock:
            if url in self.seen:
                return False
            self.seen.add(url)
        try:
            self.tasks.put_nowait(CrawlTask(url, depth, reason))
            with self._connect() as db:
                db.execute("INSERT OR IGNORE INTO crawl_queue(url,depth,reason,queued_at) VALUES(?,?,?,?)",
                           (url, depth, reason, utc_now()))
            self.emit("queue", f"Queued [{reason}] {url}")
            return True
        except queue.Full:
            with self.lock:
                self.seen.discard(url)
            return False

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
        added = self.queue_url(url, depth=0, reason=f"auto:{source}")
        if added:
            self.emit("auto", f"Auto-added URL from {source}: {url}")
        return added

    def scan_browser_history(self):
        """Automatically scans local Chrome/Edge history database for recent URLs."""
        try:
            if os.name == 'nt':
                history_path = Path(os.environ.get('LOCALAPPDATA', '')) / "Google" / "Chrome" / "User Data" / "Default" / "History"
            else:
                history_path = Path.home() / ".config" / "google-chrome" / "Default" / "History"

            if not history_path.exists():
                return

            temp_history = self.root / "temp_history.sqlite"
            shutil.copy2(history_path, temp_history)

            conn = sqlite3.connect(temp_history)
            cursor = conn.cursor()
            cursor.execute("SELECT url FROM urls ORDER BY last_visit_time DESC LIMIT 30")
            rows = cursor.fetchall()
            conn.close()
            temp_history.unlink(missing_ok=True)

            for (raw_url,) in rows:
                parsed_domain = domain_of(raw_url)
                if parsed_domain and not parsed_domain.startswith(("chrome", "edge", "about", "localhost", "127.0.0.1", "internal")):
                    self.register_external_url(raw_url, source="browser-history")
        except Exception:
            pass

    def _auto_adder_loop(self):
        """Background discovery check loop for tracking browser history and watch files."""
        while not self.stop_event.wait(15.0):
            if not CONFIG.get("auto_adder_enabled", True):
                continue
            try:
                self.scan_browser_history()
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
            if origin not in self.robots:
                parser = urllib.robotparser.RobotFileParser()
                parser.set_url(origin + "/robots.txt")
                try:
                    parser.read()
                    self.robots[origin] = parser
                except Exception:
                    self.robots[origin] = None
            parser = self.robots[origin]
        if parser is None:
            return False
        return parser.can_fetch(USER_AGENT, url)

    def _throttle(self, host: str):
        delay = safe_float(CONFIG.get("per_host_delay"), 2.0, 0.25, 60.0)
        with self.lock:
            last = self.host_last_request.get(host, 0.0)
            wait = delay - (time.monotonic() - last)
            if wait > 0:
                self.stop_event.wait(wait)
            self.host_last_request[host] = time.monotonic()

    def fetch_url(self, url: str, depth: int = 0) -> dict:
        if not self._robots_allowed(url):
            self.stats["blocked"] += 1
            self._history(url, "blocked", "robots.txt disallowed or unavailable")
            return {"ok": False, "error": "robots.txt disallowed or unavailable"}
        host = domain_of(url)
        self._throttle(host)
        timeout = safe_int(CONFIG.get("request_timeout"), 12, 3, 60)
        max_bytes = safe_int(CONFIG.get("max_page_mb"), 2, 1, 20) * 1024 * 1024
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
                final_url = normalize_url(response.geturl()) or url
                etag = response.headers.get("ETag", "")
                modified = response.headers.get("Last-Modified", "")
                self._store_page(final_url, text, ctype, status, depth, etag, modified)
                self.stats["bytes"] += len(raw)
                self.stats["fetched"] += 1
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
            if e.code == 304 and old:
                with self._connect() as db:
                    db.execute("UPDATE pages SET fetched_at=?, next_refresh=? WHERE url=?",
                               (utc_now(), self._next_refresh(), url))
                return {"ok": True, "url": url, "not_modified": True}
            self.stats["errors"] += 1
            self._history(url, "http_error", str(e))
            return {"ok": False, "error": f"HTTP {e.code}"}
        except Exception as e:
            self.stats["errors"] += 1
            self._history(url, "error", str(e)[:500])
            self.emit("error", f"{url}: {e}")
            return {"ok": False, "error": str(e)}

    def _next_refresh(self) -> str:
        hours = safe_int(CONFIG.get("refresh_after_hours"), 72, 1, 8760)
        return (datetime.now(timezone.utc) + timedelta(hours=hours)).isoformat()

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
        with self._connect() as db:
            existing = db.execute("SELECT sha256 FROM pages WHERE url=?", (url,)).fetchone()
            if existing and existing["sha256"] == digest:
                self.stats["deduplicated"] += 1
            db.execute("""INSERT INTO pages(url,domain,title,content,object_path,sha256,content_type,
                        status,fetched_at,last_access,depth,etag,last_modified,next_refresh)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)
                        ON CONFLICT(url) DO UPDATE SET domain=excluded.domain,title=excluded.title,
                        content=excluded.content,object_path=excluded.object_path,sha256=excluded.sha256,
                        content_type=excluded.content_type,status=excluded.status,fetched_at=excluded.fetched_at,
                        depth=excluded.depth,etag=excluded.etag,last_modified=excluded.last_modified,
                        next_refresh=excluded.next_refresh""",
                       (url, domain_of(url), title, content, str(obj), digest, ctype, status,
                        utc_now(), utc_now(), depth, etag, modified, self._next_refresh()))
            db.execute("DELETE FROM crawl_queue WHERE url=?", (url,))
        self.enforce_storage_limits()

    def _history(self, url: str, outcome: str, detail: str):
        with self._connect() as db:
            db.execute("INSERT INTO crawl_history(url,outcome,detail,created_at) VALUES(?,?,?,?)",
                       (url, outcome, detail[:1000], utc_now()))

    def get_metadata(self, url: str) -> dict | None:
        with self._connect() as db:
            row = db.execute("SELECT url,etag,last_modified,sha256,fetched_at,last_access,access_count FROM pages WHERE url=?",
                             (url,)).fetchone()
        return dict(row) if row else None

    def search(self, query: str, limit: int = 20) -> list[dict]:
        terms = [t for t in re.findall(r"[\w-]{2,}", query.lower())[:12]]
        if not terms:
            return []
        where = " AND ".join(["(lower(title) LIKE ? OR lower(content) LIKE ?)"] * len(terms))
        params = []
        for term in terms:
            params.extend([f"%{term}%", f"%{term}%"])
        params.append(safe_int(limit, 20, 1, 100))
        with self._connect() as db:
            rows = db.execute(f"""SELECT url,title,domain,fetched_at,last_access,access_count,
                length(content) AS chars FROM pages WHERE {where}
                ORDER BY access_count DESC, fetched_at DESC LIMIT ?""", params).fetchall()
        return [dict(r) for r in rows]

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
        result.pop("content", None)
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
                "stale": age_hours >= threshold, "sha256": item["sha256"],
                "last_access": item["last_access"], "access_count": item["access_count"]}

    def request_refresh(self, url: str) -> bool:
        return self.queue_url(url, 0, "AI refresh request")

    def predictive_refresh(self, limit: int = 10) -> int:
        now = datetime.now(timezone.utc)
        threshold = safe_int(CONFIG.get("refresh_after_hours"), 72, 1, 8760)
        with self._connect() as db:
            rows = db.execute("SELECT url,fetched_at,last_access,access_count FROM pages").fetchall()
        scored = []
        for r in rows:
            try:
                age = (now - datetime.fromisoformat(r["fetched_at"])).total_seconds() / 3600
                if age < threshold:
                    continue
                used = (now - datetime.fromisoformat(r["last_access"])).total_seconds() / 86400
                score = min(age / threshold, 20) * (1 + min(r["access_count"], 100) / 25) / (1 + used / 30)
                scored.append((score, r["url"]))
            except Exception:
                continue
        added = 0
        for _, url in sorted(scored, reverse=True)[:safe_int(limit, 10, 1, 100)]:
            added += int(self.queue_url(url, 0, "predictive refresh"))
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
            refs = {r[0] for r in db.execute("SELECT DISTINCT object_path FROM pages")}
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

    def status(self) -> dict:
        with self._connect() as db:
            count = db.execute("SELECT count(*) FROM pages").fetchone()[0]
            queued = db.execute("SELECT count(*) FROM crawl_queue").fetchone()[0]
            domains = db.execute("SELECT count(DISTINCT domain) FROM pages").fetchone()[0]
        return {"app": APP_NAME, "version": APP_VERSION, "pages": count, "queued": queued,
                "domains": domains, "workers": len(self.workers),
                "queue_memory": self.tasks.qsize(), "cache_bytes": self._dir_size(self.root),
                "cache_root": str(self.root), "stats": self.stats.copy(),
                "api": f"http://{CONFIG['api_host']}:{CONFIG['api_port']}/api/v1"}

    def worker(self, number: int):
        while not self.stop_event.is_set():
            try:
                task = self.tasks.get(timeout=1)
            except queue.Empty:
                continue
            try:
                if task.depth > safe_int(CONFIG.get("max_depth"), 2, 0, 10):
                    continue
                self.fetch_url(task.url, task.depth)
            except Exception:
                logging.exception("Worker %s failed", number)
            finally:
                self.tasks.task_done()

    def start_workers(self):
        count = safe_int(CONFIG.get("workers"), 4, 1, 32)
        for i in range(count):
            t = threading.Thread(target=self.worker, args=(i + 1,),
                                   name=f"Probe-{i+1}", daemon=True)
            t.start()
            self.workers.append(t)

    def maintenance_loop(self):
        while not self.stop_event.wait(300):
            try:
                self.cleanup_expired()
                self.predictive_refresh(5)
                self.enforce_storage_limits()
            except Exception:
                logging.exception("Maintenance cycle failed")

    def start_api(self):
        if not CONFIG.get("api_enabled", True):
            return
        nexus = self

        class Handler(BaseHTTPRequestHandler):
            server_version = "DominionDeckNexus/5"
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
                self.send_header("Access-Control-Allow-Origin", "null")
                self.end_headers()
                self.wfile.write(body)

            def do_OPTIONS(self):
                self.send_response(204)
                self.send_header("Access-Control-Allow-Methods", "GET,POST,OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Authorization,Content-Type")
                self.end_headers()

            def do_GET(self):
                nexus.stats["api_requests"] += 1
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
                return self._send(404, {"error": "Not found"})

            def do_POST(self):
                nexus.stats["api_requests"] += 1
                if not self._auth():
                    return self._send(401, {"error": "Unauthorized"})
                if self.path not in ("/api/v1/probe", "/api/v1/auto-add"):
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

        self.server = ThreadingHTTPServer((CONFIG["api_host"], safe_int(CONFIG["api_port"], 8765, 1024, 65535)), Handler)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True, name="NexusAPI")
        self.server_thread.start()
        self.emit("api", f"API running on http://{CONFIG['api_host']}:{CONFIG['api_port']}/api/v1")

    def stop(self):
        self.stop_event.set()
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass
        with self._connect() as db:
            db.execute("DELETE FROM crawl_queue")
            while True:
                try:
                    task = self.tasks.get_nowait()
                    db.execute("INSERT OR IGNORE INTO crawl_queue(url,depth,reason,queued_at) VALUES(?,?,?,?)",
                               (task.url, task.depth, task.reason, utc_now()))
                except queue.Empty:
                    break

class Dashboard:
    def __init__(self, root: tk.Tk, nexus: Nexus):
        self.root = root
        self.nexus = nexus
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1100x750")
        self.root.minsize(900, 600)
        self._setup_styles()
        self._build_ui()
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

        # Header
        hdr = ttk.Frame(main)
        hdr.pack(fill=tk.X, pady=(0, 10))
        ttk.Label(hdr, text=APP_NAME, style="Title.TLabel").pack(side=tk.LEFT)
        
        btn_frame = ttk.Frame(hdr)
        btn_frame.pack(side=tk.RIGHT)
        ttk.Button(btn_frame, text="Add Seed / URL", command=self.prompt_add_url).pack(side=tk.LEFT, padx=4)

        # Stats Bar
        stats_frame = ttk.LabelFrame(main, text="Nexus Live Metrics", padding=10)
        stats_frame.pack(fill=tk.X, pady=(0, 10))
        stats_frame.columnconfigure((0, 1, 2, 3, 4, 5), weight=1)

        self.lbl_pages = self._make_stat(stats_frame, "Cached Pages", "0", 0)
        self.lbl_queued = self._make_stat(stats_frame, "Queue Backlog", "0", 1)
        self.lbl_fetched = self._make_stat(stats_frame, "Fetched Total", "0", 2)
        self.lbl_bytes = self._make_stat(stats_frame, "Storage Size", "0 MB", 3)
        self.lbl_auto = self._make_stat(stats_frame, "Auto-Injected", "0", 4)
        self.lbl_errors = self._make_stat(stats_frame, "Errors / Blocked", "0 / 0", 5)

        # Notebook / Tabs
        self.nb = ttk.Notebook(main)
        self.nb.pack(fill=tk.BOTH, expand=True, pady=(0, 10))

        self.tab_live = ttk.Frame(self.nb, padding=8)
        self.tab_search = ttk.Frame(self.nb, padding=8)
        self.tab_history = ttk.Frame(self.nb, padding=8)
        self.tab_settings = ttk.Frame(self.nb, padding=8)
        
        self.nb.add(self.tab_live, text="Live Activity Stream")
        self.nb.add(self.tab_search, text="Cache Explorer & Search")
        self.nb.add(self.tab_history, text="Auto-URL Inbox & History")
        self.nb.add(self.tab_settings, text="Settings & Allowed Domains")

        self._build_live_tab()
        self._build_search_tab()
        self._build_history_tab()
        self._build_settings_tab()

        # Statusbar
        sb = ttk.Frame(main)
        sb.pack(fill=tk.X)
        self.lbl_status = ttk.Label(sb, text="Ready", foreground="#475569")
        self.lbl_status.pack(side=tk.LEFT)

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
        ttk.Button(top, text="Search Cache", command=self.do_search).grid(row=0, column=1)

        results_frame = ttk.Frame(frame)
        results_frame.grid(row=1, column=0, sticky="nsew")
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(0, weight=1)

        cols = ("url", "title", "domain", "fetched", "accesses")
        self.tree_search = ttk.Treeview(results_frame, columns=cols, show="headings", selectmode="browse")
        for col in cols:
            self.tree_search.heading(col, text=col.capitalize())
        
        sb_search = ttk.Scrollbar(results_frame, orient=tk.VERTICAL, command=self.tree_search.yview)
        self.tree_search.configure(yscrollcommand=sb_search.set)
        self.tree_search.grid(row=0, column=0, sticky="nsew")
        sb_search.grid(row=0, column=1, sticky="ns")
        self.tree_search.bind("<Double-1>", self.inspect_cached_page)

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

        # Config fields inputs
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

        # --- Allowed Domains Management Panel ---
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

        # Save configuration button
        btn_save = ttk.Button(scrollable_frame, text="Save Settings & Apply", command=self.save_settings)
        btn_save.pack(anchor="e", pady=10)

    def populate_allowed_domains_list(self):
        self.listbox_domains.delete(0, tk.END)
        domains = CONFIG.get("allowed_domains", [])
        for d in sorted(domains):
            self.listbox_domains.insert(tk.END, d)

    def add_allowed_domain(self):
        raw = self.ent_new_domain.get().strip().lower()
        if not raw:
            return
        # strip protocol or paths if user pasted a full url
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
                CONFIG[key] = cast_func(val_str)
            save_config()
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
            if not self.nexus.workers:
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
                    self.nexus.emit("ui", f"Manually queued URL: {raw}")
                    top.destroy()
                else:
                    messagebox.showerror("Error", "Could not queue URL. Check format, allowed domains filter, or duplicates.")

        ttk.Button(top, text="Queue & Probe", command=submit).pack(anchor="e", padx=15, pady=10)
        ent.bind("<Return>", lambda e: submit())

    def do_search(self):
        query = self.ent_search.get().strip()
        for item in self.tree_search.get_children():
            self.tree_search.delete(item)
        if not query:
            return
        results = self.nexus.search(query, 50)
        for r in results:
            self.tree_search.insert("", tk.END, values=(
                r["url"], r["title"], r["domain"], r["fetched_at"][:19], r["access_count"]
            ))

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
        
        header_info = f"URL: {cached['url']}\nTitle: {cached['title']}\nDomain: {cached['domain']}\nFetched At: {cached['fetched_at']}\nContent-Type: {cached['content_type']}\nSHA-256: {cached['sha256']}\n" + "-"*80 + "\n\n"
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
            self.lbl_auto.configure(text=f"{st['stats']['auto_added']:,}")
            self.lbl_errors.configure(text=f"{st['stats']['errors']} / {st['stats']['blocked']}")
            self.lbl_status.configure(text=f"Status: {self.nexus.last_message} | API: {st['api']}")
            self.refresh_history_tab()
        except Exception:
            pass
        self.root.after(1000, self._poll_stats)

def main():
    logging.basicConfig(level=getattr(logging, CONFIG.get("log_level", "INFO"), logging.INFO),
                        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
                        handlers=[RotatingFileHandler(LOG_PATH, maxBytes=5*1024*1024, backupCount=3),
                                  logging.StreamHandler(sys.stdout)])
    
    nexus = Nexus()
    nexus.start_api()
    
    if CONFIG.get("crawl_enabled", False):
        nexus.start_workers()
        nexus.seed()
    
    maint_thread = threading.Thread(target=nexus.maintenance_loop, daemon=True, name="Maintenance")
    maint_thread.start()

    root = tk.Tk()
    app = Dashboard(root, nexus)
    
    def on_close():
        nexus.stop()
        root.destroy()
        sys.exit(0)
        
    root.protocol("WM_DELETE_WINDOW", on_close)
    root.mainloop()

if __name__ == "__main__":
    main()