#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DominionDeck Universal AI Probe Nexus v5.1
A local-first, policy-aware web cache and AI retrieval gateway.

Features
--------
* Bounded autonomous crawler with recursive same-domain and optional cross-domain link discovery.
* Optional Chrome/Edge URL auto-adder extension for top-level pages you visit.
* robots.txt checks, per-host rate limiting, size/time limits and safe URL filtering.
* SQLite metadata/index, SHA-256 deduplication, content-addressed cache files.
* Search/fetch/probe/freshness/status API for AI clients and local tools.
* Optional bearer-token authentication for the API.
* Predictive refresh scoring based on age, use frequency and past change signals.
* 60-day unused-entry expiry, LRU eviction and configurable storage ceilings.
* Worker supervision, graceful shutdown, rotating logs and Tkinter dashboard.
* No browser-cookie access, private-network crawling, paywall bypass or credential scraping.

Standard library only. Python 3.10+ recommended.
"""

from __future__ import annotations

import hashlib
import html
import json
import logging
from logging.handlers import RotatingFileHandler
import os
import queue
import re
import shutil
import secrets
import socket
import sqlite3
import threading
import time
import urllib.error
import urllib.parse
import urllib.robotparser
import urllib.request
import uuid
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
APP_VERSION = "5.1.0"
HOME = Path.home()
CONFIG_PATH = HOME / "dominion_nexus_config.json"
DEFAULT_ROOT = HOME / "DominionDeckCache"
LOG_PATH = HOME / "dominion_nexus.log"
USER_AGENT = "DominionDeckProbe/5.0 (+local cache; respects robots.txt)"
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
    "auto_browser_capture": True,
    "cross_domain_discovery": False,
    "max_discovery_queue": 5000,
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
        # Never fetch local, loopback, link-local or private IP literals.
        try:
            ip = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80),
                                    type=socket.SOCK_STREAM)[0][4][0]
            import ipaddress
            addr = ipaddress.ip_address(ip)
            if not addr.is_global:
                return None
        except (socket.gaierror, ValueError, OSError):
            # DNS resolution may be transient; hostname policy still applies.
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
                      "blocked": 0, "expired": 0, "api_requests": 0,
                      "browser_visits": 0, "browser_rejected": 0}
        self.last_message = "Ready"
        self._load_seen()
        self._load_queue_state()

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
            """)

    def _load_seen(self):
        # `seen` tracks pending/in-flight URLs, not every cached URL. This allows
        # stale cached pages to be deliberately refreshed later.
        with self._connect() as db:
            self.seen = {r[0] for r in db.execute("SELECT url FROM crawl_queue")}

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
            queue_limit = safe_int(CONFIG.get("max_discovery_queue"), 5000, 100, 50000)
            if self.tasks.qsize() >= queue_limit:
                return False
            self.seen.add(url)
        try:
            self.tasks.put_nowait(CrawlTask(url, depth, reason))
            with self._connect() as db:
                db.execute("INSERT OR IGNORE INTO crawl_queue(url,depth,reason,queued_at) VALUES(?,?,?,?)",
                           (url, depth, reason, utc_now()))
            self.emit("queue", f"Queued {url}")
            return True
        except queue.Full:
            with self.lock:
                self.seen.discard(url)
            return False

    def seed(self):
        for url in CONFIG.get("seed_urls", []):
            self.queue_url(url, 0, "seed")

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
                    # Fail closed on an unavailable robots policy.
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
                        if not candidate:
                            continue
                        same_domain = domain_of(candidate) == domain_of(final_url)
                        if not same_domain and not CONFIG.get("cross_domain_discovery", False):
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
        normalized = normalize_url(url)
        if not normalized:
            return False
        with self.lock:
            self.seen.discard(normalized)
        return self.queue_url(normalized, 0, "AI refresh request")

    def record_browser_visit(self, raw_url: str) -> dict:
        """Record a URL reported by the optional browser extension; never receives page data."""
        url = normalize_url(raw_url)
        if not url:
            self.stats["browser_rejected"] += 1
            return {"accepted": False, "reason": "URL rejected by safety checks"}
        self.stats["browser_visits"] += 1
        allowed = [d.lower().strip() for d in CONFIG.get("allowed_domains", []) if d.strip()]
        host = domain_of(url)
        if allowed and not any(host == d or host.endswith("." + d) for d in allowed):
            self.stats["browser_rejected"] += 1
            return {"accepted": False, "reason": "Outside allowed-domain list"}
        with self._connect() as db:
            row = db.execute("SELECT fetched_at FROM pages WHERE url=?", (url,)).fetchone()
            if row:
                db.execute("UPDATE pages SET last_access=?,access_count=access_count+1 WHERE url=?",
                           (utc_now(), url))
        if row:
            freshness = self.freshness(url)
            if freshness.get("stale"):
                queued = self.request_refresh(url)
                return {"accepted": True, "cached": True, "refresh_queued": queued, "url": url}
            return {"accepted": True, "cached": True, "refresh_queued": False, "url": url}
        queued = self.queue_url(url, 0, "browser visit")
        return {"accepted": queued, "cached": False, "refresh_queued": queued,
                "url": url, "reason": "Queued" if queued else "Already queued or queue full"}

    def create_browser_extension(self, destination: str) -> Path:
        """Generate a Chromium Manifest V3 extension that forwards visited URLs only."""
        target = Path(destination).expanduser().resolve()
        target.mkdir(parents=True, exist_ok=True)
        token = str(CONFIG.get("api_token", "")).strip()
        if not token:
            token = secrets.token_urlsafe(32)
            CONFIG["api_token"] = token
            save_config()
        port = safe_int(CONFIG.get("api_port"), 8765, 1024, 65535)
        manifest = {
            "manifest_version": 3,
            "name": "DominionDeck Nexus URL Auto-Adder",
            "version": "1.0.0",
            "description": "Sends visited page URLs to your local DominionDeck Nexus. Does not read page contents, cookies, or passwords.",
            "permissions": ["webNavigation"],
            "host_permissions": ["<all_urls>", f"http://127.0.0.1:{port}/*", f"http://localhost:{port}/*"],
            "background": {"service_worker": "service_worker.js"}
        }
        worker = f"""const NEXUS_ENDPOINT = "http://127.0.0.1:{port}/api/v1/visited";
const NEXUS_TOKEN = {json.dumps(token)};

function eligible(url) {{
  try {{
    const u = new URL(url);
    if (!["http:", "https:"].includes(u.protocol)) return false;
    if (u.username || u.password) return false;
    const h = u.hostname.toLowerCase();
    if (h === "localhost" || h.endsWith(".local") || h.endsWith(".internal")) return false;
    // Remove common credential-bearing query parameters before forwarding URLs.
    const sensitive = /^(token|access_token|refresh_token|auth|authorization|code|password|passwd|session|sessionid|api_key|apikey|secret|jwt|sig|signature)$/i;
    for (const key of [...u.searchParams.keys()]) {{
      if (sensitive.test(key)) u.searchParams.delete(key);
    }}
    u.hash = "";
    return u.toString();
  }} catch (_) {{ return false; }}
}}

// Capture committed top-level navigations only. No DOM, cookies, credentials,
// form fields, or page text are read or transmitted.
chrome.webNavigation.onCommitted.addListener((details) => {{
  if (details.frameId !== 0) return;
  const safeUrl = eligible(details.url);
  if (!safeUrl) return;
  fetch(NEXUS_ENDPOINT, {{
    method: "POST",
    headers: {{ "Content-Type": "application/json", "Authorization": "Bearer " + NEXUS_TOKEN }},
    body: JSON.stringify({{ url: safeUrl, source: "browser" }})
  }}).catch(() => {{ /* Nexus may be closed; do not interrupt browsing. */ }});
}});
"""
        (target / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        (target / "service_worker.js").write_text(worker, encoding="utf-8")
        readme = f"""DominionDeck Nexus URL Auto-Adder (Chrome / Edge)

INSTALL
1. Keep DominionDeck Universal AI Probe Nexus running.
2. Open chrome://extensions (Chrome) or edge://extensions (Edge).
3. Turn on Developer mode.
4. Choose Load unpacked and select this folder:
   {target}
5. Visit a normal public HTTP/HTTPS website. Its URL will be sent to the local Nexus queue.

PRIVACY
This extension sends only the top-level page URL. It does not read page contents,
cookies, passwords, form entries, or browsing history databases. It removes URL fragments
and common credential-like query parameters before forwarding. You can disable or
remove it at any time from the browser extensions page.

The extension communicates with 127.0.0.1:{port}. Keep the Nexus API bound to
127.0.0.1 unless you intentionally configure a secured remote deployment.
If the API port changes, regenerate this extension.
"""
        (target / "README.txt").write_text(readme, encoding="utf-8")
        return target

    def predictive_refresh(self, limit: int = 10) -> int:
        """Prioritize pages likely to be useful and overdue; heuristic, not an AI claim."""
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
            # Remove object files no longer referenced by any URL.
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
                # Delete only when no other URL points at this content object.
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
                "browser_capture": bool(CONFIG.get("auto_browser_capture", True)),
                "cross_domain_discovery": bool(CONFIG.get("cross_domain_discovery", False)),
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
                with self.lock:
                    self.seen.discard(task.url)
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
                import hmac
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
                    return self._send(200 if item else 404, item or {"error": "Not cached"})
                if parsed.path == "/api/v1/freshness":
                    return self._send(200, nexus.freshness(q.get("url", [""])[0]))
                return self._send(404, {"error": "Not found"})

            def do_POST(self):
                nexus.stats["api_requests"] += 1
                if not self._auth():
                    return self._send(401, {"error": "Unauthorized"})
                if self.path not in ("/api/v1/probe", "/api/v1/visited"):
                    return self._send(404, {"error": "Not found"})
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                    if length < 2 or length > 16384:
                        return self._send(413, {"error": "Invalid request size"})
                    data = json.loads(self.rfile.read(length))
                    url = data.get("url", "")
                    if self.path == "/api/v1/visited":
                        if not CONFIG.get("auto_browser_capture", True):
                            return self._send(403, {"accepted": False, "error": "Browser capture is paused"})
                        result = nexus.record_browser_visit(url)
                        return self._send(202 if result.get("accepted") else 400, result)
                    added = nexus.request_refresh(url)
                    return self._send(202 if added else 200,
                                      {"accepted": added, "url": normalize_url(url),
                                       "message": "Queued" if added else "Already queued or rejected"})
                except Exception as e:
                    return self._send(400, {"error": str(e)})

        host = str(CONFIG.get("api_host", "127.0.0.1"))
        port = safe_int(CONFIG.get("api_port"), 8765, 1024, 65535)
        try:
            self.server = ThreadingHTTPServer((host, port), Handler)
            self.server.daemon_threads = True
            self.server_thread = threading.Thread(target=self.server.serve_forever,
                                                  name="NexusAPI", daemon=True)
            self.server_thread.start()
            self.emit("api", f"API listening on http://{host}:{port}")
        except OSError as e:
            self.emit("error", f"API could not start: {e}")

    def shutdown(self):
        self.stop_event.set()
        if self.server:
            try:
                self.server.shutdown()
                self.server.server_close()
            except Exception:
                pass

NEXUS = Nexus()

class NexusGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1050x700")
        self.minsize(820, 560)
        self.protocol("WM_DELETE_WINDOW", self.on_close)
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        self._build()
        self.after(400, self.poll_events)
        self.after(1500, self.refresh_status)

    def _build(self):
        top = ttk.Frame(self, padding=8)
        top.pack(fill="x")
        ttk.Label(top, text="DOMINIONDECK • UNIVERSAL AI PROBE NEXUS",
                  font=("Segoe UI", 13, "bold")).pack(side="left")
        self.status_label = ttk.Label(top, text="Initializing…")
        self.status_label.pack(side="right")

        self.tabs = ttk.Notebook(self)
        self.tabs.pack(fill="both", expand=True, padx=8, pady=6)
        self.dashboard = ttk.Frame(self.tabs, padding=10)
        self.crawler = ttk.Frame(self.tabs, padding=10)
        self.cache_tab = ttk.Frame(self.tabs, padding=10)
        self.api_tab = ttk.Frame(self.tabs, padding=10)
        self.discovery_tab = ttk.Frame(self.tabs, padding=10)
        self.settings = ttk.Frame(self.tabs, padding=10)
        for frame, title in [(self.dashboard, "Dashboard"), (self.crawler, "Probe Control"),
                             (self.cache_tab, "Cache Search"), (self.api_tab, "AI Gateway"),
                             (self.discovery_tab, "Auto URL Discovery"), (self.settings, "Settings")]:
            self.tabs.add(frame, text=title)
        self._dashboard_tab()
        self._crawler_tab()
        self._cache_tab()
        self._api_tab()
        self._discovery_tab()
        self._settings_tab()

        bottom = ttk.Frame(self, padding=(8, 2))
        bottom.pack(fill="x")
        ttk.Label(bottom, text=f"Local-first • robots.txt aware • 60-day unused-cache cleanup • v{APP_VERSION}").pack(side="left")
        ttk.Button(bottom, text="Open Cache Folder", command=self.open_cache).pack(side="right")

    def _dashboard_tab(self):
        self.dashboard.columnconfigure((0, 1, 2), weight=1)
        self.metrics = {}
        for i, (key, label) in enumerate([
            ("pages", "Cached pages"), ("queued", "Queued probes"), ("domains", "Domains"),
            ("cache_bytes", "Cache bytes"), ("fetched", "Fetched"), ("errors", "Errors"),
            ("blocked", "Robots blocked"), ("expired", "Expired entries"), ("api_requests", "AI API calls"),
            ("browser_visits", "Browser URLs seen"), ("browser_rejected", "Browser URLs rejected")
        ]):
            box = ttk.LabelFrame(self.dashboard, text=label, padding=12)
            box.grid(row=i // 3, column=i % 3, sticky="nsew", padx=5, pady=5)
            value = ttk.Label(box, text="—", font=("Segoe UI", 15, "bold"))
            value.pack()
            self.metrics[key] = value
        self.log_view = tk.Text(self.dashboard, height=9, wrap="word", state="disabled")
        self.log_view.grid(row=4, column=0, columnspan=3, sticky="nsew", padx=5, pady=8)
        self.dashboard.rowconfigure(4, weight=1)

    def _crawler_tab(self):
        self.crawler.columnconfigure(0, weight=1)
        ttk.Label(self.crawler, text="Add a public HTTP/HTTPS URL to the autonomous probe queue:").grid(row=0, column=0, sticky="w")
        self.url_var = tk.StringVar()
        row = ttk.Frame(self.crawler)
        row.grid(row=1, column=0, sticky="ew", pady=6)
        row.columnconfigure(0, weight=1)
        ttk.Entry(row, textvariable=self.url_var).grid(row=0, column=0, sticky="ew")
        ttk.Button(row, text="Queue URL", command=self.add_url).grid(row=0, column=1, padx=5)
        actions = ttk.Frame(self.crawler)
        actions.grid(row=2, column=0, sticky="w", pady=5)
        ttk.Button(actions, text="Load Seed URLs", command=NEXUS.seed).pack(side="left", padx=3)
        ttk.Button(actions, text="Predictive Refresh", command=self.predict_refresh).pack(side="left", padx=3)
        ttk.Button(actions, text="Run Cleanup Now", command=self.cleanup).pack(side="left", padx=3)
        ttk.Label(self.crawler, text="Activity").grid(row=3, column=0, sticky="w", pady=(12, 2))
        self.activity = tk.Listbox(self.crawler, height=18)
        self.activity.grid(row=4, column=0, sticky="nsew")
        scroll = ttk.Scrollbar(self.crawler, orient="vertical", command=self.activity.yview)
        scroll.grid(row=4, column=1, sticky="ns")
        self.activity.configure(yscrollcommand=scroll.set)
        self.crawler.rowconfigure(4, weight=1)

    def _cache_tab(self):
        self.cache_tab.columnconfigure(0, weight=1)
        self.cache_tab.rowconfigure(2, weight=1)
        ttk.Label(self.cache_tab, text="Search locally cached pages (titles and extracted source text):").grid(row=0, column=0, sticky="w")
        row = ttk.Frame(self.cache_tab)
        row.grid(row=1, column=0, sticky="ew", pady=5)
        self.search_var = tk.StringVar()
        ttk.Entry(row, textvariable=self.search_var).pack(side="left", fill="x", expand=True)
        ttk.Button(row, text="Search", command=self.search_cache).pack(side="left", padx=5)
        cols = ("title", "url", "domain", "fetched_at", "access_count")
        self.results = ttk.Treeview(self.cache_tab, columns=cols, show="headings")
        for c, label, width in zip(cols, ["Title", "URL", "Domain", "Fetched", "Uses"],
                                    [180, 390, 130, 160, 60]):
            self.results.heading(c, text=label)
            self.results.column(c, width=width, anchor="w")
        self.results.grid(row=2, column=0, sticky="nsew")
        sy = ttk.Scrollbar(self.cache_tab, orient="vertical", command=self.results.yview)
        sy.grid(row=2, column=1, sticky="ns")
        self.results.configure(yscrollcommand=sy.set)
        ttk.Button(self.cache_tab, text="Open Selected Cached Text", command=self.open_selected).grid(row=3, column=0, sticky="w", pady=5)

    def _api_tab(self):
        ttk.Label(self.api_tab, text="AI-compatible local REST gateway", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        ttk.Label(self.api_tab, text=f"Base URL: http://{CONFIG['api_host']}:{CONFIG['api_port']}/api/v1").pack(anchor="w", pady=4)
        self.api_text = tk.Text(self.api_tab, height=20, wrap="word")
        self.api_text.pack(fill="both", expand=True, pady=6)
        self.api_text.insert("1.0", """GET  /status
GET  /search?q=your+terms&limit=20
GET  /fetch?url=https%3A%2F%2Fexample.com%2F
GET  /freshness?url=https%3A%2F%2Fexample.com%2F
POST /probe   JSON body: {"url":"https://example.com/"}
POST /visited JSON body: {"url":"https://example.com/", "source":"browser"}

If an API token is configured, send:
Authorization: Bearer YOUR_TOKEN

Example Python:
import requests
base = "http://127.0.0.1:8765/api/v1"
r = requests.get(base + "/search", params={"q": "example"})
print(r.json())

The API exposes only this application's cache and probe queue. Each AI
client must be configured to call this REST API or an adapter/tool wrapper.
It does not automatically connect to every AI provider.
""")
        self.api_text.configure(state="disabled")

    def _discovery_tab(self):
        self.discovery_tab.columnconfigure(0, weight=1)
        ttk.Label(self.discovery_tab, text="AUTOMATIC URL DISCOVERY", font=("Segoe UI", 12, "bold")).grid(row=0, column=0, sticky="w")
        ttk.Label(self.discovery_tab, text=(
            "Capture top-level URLs as you browse with a small Chrome/Edge extension. "
            "The extension sends URLs only; it never reads page text, cookies, passwords, or form fields."
        ), wraplength=850).grid(row=1, column=0, sticky="w", pady=8)
        self.browser_capture_var = tk.BooleanVar(value=bool(CONFIG.get("auto_browser_capture", True)))
        ttk.Checkbutton(self.discovery_tab, text="Accept URLs from my browser extension", 
                        variable=self.browser_capture_var).grid(row=2, column=0, sticky="w", pady=5)
        self.cross_domain_var = tk.BooleanVar(value=bool(CONFIG.get("cross_domain_discovery", False)))
        ttk.Checkbutton(self.discovery_tab, text="Allow web scans to follow links to other domains (can greatly expand the crawl)",
                        variable=self.cross_domain_var).grid(row=3, column=0, sticky="w", pady=5)
        ttk.Button(self.discovery_tab, text="Generate Chrome / Edge Extension", command=self.generate_extension).grid(row=4, column=0, sticky="w", pady=10)
        ttk.Label(self.discovery_tab, text="Setup instructions", font=("Segoe UI", 10, "bold")).grid(row=5, column=0, sticky="w")
        instructions = (
            "1. Generate the extension into a new folder.\n"
            "2. Open chrome://extensions or edge://extensions.\n"
            "3. Enable Developer mode, choose Load unpacked, and select that folder.\n"
            "4. Keep this Nexus app running; browser visits will be added to the probe queue.\n\n"
            "Web scanning discovers links from pages the probes are allowed to fetch. By default it stays on the same domain. "
            "Cross-domain discovery is optional. robots.txt, URL safety checks, page-size limits, and per-domain delays remain active."
        )
        ttk.Label(self.discovery_tab, text=instructions, justify="left", wraplength=850).grid(row=6, column=0, sticky="nw", pady=6)
        ttk.Button(self.discovery_tab, text="Save Discovery Settings", command=self.save_discovery_settings).grid(row=7, column=0, sticky="w", pady=8)

    def save_discovery_settings(self):
        CONFIG["auto_browser_capture"] = bool(self.browser_capture_var.get())
        CONFIG["cross_domain_discovery"] = bool(self.cross_domain_var.get())
        save_config()
        messagebox.showinfo("URL Discovery", "Discovery settings saved.")

    def generate_extension(self):
        folder = filedialog.askdirectory(title="Choose or create the browser extension folder")
        if not folder:
            return
        try:
            target = NEXUS.create_browser_extension(folder)
            messagebox.showinfo("Extension Created", f"Chrome / Edge extension files created in:\n{target}\n\nNext: open your browser extensions page, enable Developer mode, and choose Load unpacked.")
        except Exception as e:
            messagebox.showerror("Extension Error", str(e))

    def _settings_tab(self):
        self.settings.columnconfigure(1, weight=1)
        self.root_var = tk.StringVar(value=str(CONFIG["cache_root"]))
        self.cap_var = tk.StringVar(value=str(CONFIG["primary_cap_gb"]))
        self.workers_var = tk.StringVar(value=str(CONFIG["workers"]))
        self.delay_var = tk.StringVar(value=str(CONFIG["per_host_delay"]))
        self.depth_var = tk.StringVar(value=str(CONFIG["max_depth"]))
        self.expire_var = tk.StringVar(value=str(CONFIG["expire_unused_days"]))
        self.refresh_var = tk.StringVar(value=str(CONFIG["refresh_after_hours"]))
        self.api_host_var = tk.StringVar(value=str(CONFIG["api_host"]))
        self.api_port_var = tk.StringVar(value=str(CONFIG["api_port"]))
        self.token_var = tk.StringVar(value=str(CONFIG["api_token"]))
        self.robots_var = tk.BooleanVar(value=bool(CONFIG["respect_robots"]))
        self.crawl_var = tk.BooleanVar(value=bool(CONFIG["crawl_enabled"]))
        fields = [
            ("Cache root", self.root_var), ("Primary cache cap (GB)", self.cap_var),
            ("Probe workers (1–32; applies next launch)", self.workers_var),
            ("Per-domain delay seconds", self.delay_var), ("Recursive depth", self.depth_var),
            ("Unused expiry days", self.expire_var), ("Refresh age hours", self.refresh_var),
            ("API bind host (restart required)", self.api_host_var),
            ("API port (restart required)", self.api_port_var), ("API bearer token", self.token_var)
        ]
        for i, (label, var) in enumerate(fields):
            ttk.Label(self.settings, text=label).grid(row=i, column=0, sticky="w", padx=4, pady=5)
            ttk.Entry(self.settings, textvariable=var, show="*" if "token" in label.lower() else "").grid(row=i, column=1, sticky="ew", padx=4, pady=5)
        ttk.Checkbutton(self.settings, text="Respect robots.txt (recommended)", variable=self.robots_var).grid(row=10, column=0, columnspan=2, sticky="w", pady=5)
        ttk.Checkbutton(self.settings, text="Enable autonomous crawling on startup", variable=self.crawl_var).grid(row=11, column=0, columnspan=2, sticky="w", pady=5)
        ttk.Button(self.settings, text="Browse Cache Folder", command=self.choose_root).grid(row=12, column=0, sticky="w", pady=8)
        ttk.Button(self.settings, text="Save Settings", command=self.save_settings).grid(row=12, column=1, sticky="e", pady=8)
        ttk.Label(self.settings, text="API host/port changes take effect after restarting the application.").grid(row=13, column=0, columnspan=2, sticky="w")

    def choose_root(self):
        folder = filedialog.askdirectory()
        if folder:
            self.root_var.set(folder)

    def save_settings(self):
        try:
            CONFIG.update({
                "cache_root": self.root_var.get().strip(),
                "primary_cap_gb": safe_float(self.cap_var.get(), 3, 0.1, 10000),
                "workers": safe_int(self.workers_var.get(), 4, 1, 32),
                "per_host_delay": safe_float(self.delay_var.get(), 2, 0.25, 60),
                "max_depth": safe_int(self.depth_var.get(), 2, 0, 10),
                "expire_unused_days": safe_int(self.expire_var.get(), 60, 1, 3650),
                "refresh_after_hours": safe_int(self.refresh_var.get(), 72, 1, 8760),
                "api_host": self.api_host_var.get().strip() or "127.0.0.1",
                "api_port": safe_int(self.api_port_var.get(), 8765, 1024, 65535),
                "api_token": self.token_var.get().strip(),
                "respect_robots": self.robots_var.get(),
                "crawl_enabled": self.crawl_var.get()
            })
            save_config()
            messagebox.showinfo("Settings", "Settings saved. Worker/API startup settings may require an application restart.")
        except Exception as e:
            messagebox.showerror("Settings", str(e))

    def add_url(self):
        url = self.url_var.get().strip()
        if NEXUS.queue_url(url, 0, "GUI"):
            self.url_var.set("")
        else:
            messagebox.showwarning("Probe", "URL rejected, already queued/cached, outside allowed domains, or queue full.")

    def predict_refresh(self):
        count = NEXUS.predictive_refresh(50)
        messagebox.showinfo("Predictive Refresh", f"Queued {count} overdue/high-use cache entries.")

    def cleanup(self):
        count = NEXUS.cleanup_expired()
        messagebox.showinfo("Cache Cleanup", f"Removed {count} unused entries older than {CONFIG['expire_unused_days']} days.")

    def search_cache(self):
        for item in self.results.get_children():
            self.results.delete(item)
        for row in NEXUS.search(self.search_var.get(), 100):
            self.results.insert("", "end", values=(row["title"], row["url"], row["domain"],
                                                   row["fetched_at"], row["access_count"]))

    def open_selected(self):
        selected = self.results.selection()
        if not selected:
            return
        url = self.results.item(selected[0], "values")[1]
        item = NEXUS.fetch_cached(url)
        if not item:
            return
        win = tk.Toplevel(self)
        win.title(item.get("title") or url)
        win.geometry("850x600")
        text = tk.Text(win, wrap="word")
        text.pack(fill="both", expand=True)
        text.insert("1.0", item["content"])
        text.configure(state="disabled")

    def open_cache(self):
        try:
            os.startfile(str(NEXUS.root))
        except Exception:
            messagebox.showinfo("Cache Folder", str(NEXUS.root))

    def poll_events(self):
        for _ in range(100):
            try:
                kind, msg = NEXUS.events.get_nowait()
            except queue.Empty:
                break
            self.activity.insert(0, f"[{kind}] {msg}")
            if self.activity.size() > 500:
                self.activity.delete(500, tk.END)
            self.log_view.configure(state="normal")
            self.log_view.insert("end", f"[{kind}] {msg}\n")
            self.log_view.see("end")
            self.log_view.configure(state="disabled")
        self.after(500, self.poll_events)

    def refresh_status(self):
        try:
            s = NEXUS.status()
            st = s["stats"]
            for key in ("pages", "queued", "domains", "cache_bytes"):
                value = s[key]
                if key == "cache_bytes":
                    value = f"{value / 1024 / 1024:.1f} MB"
                self.metrics[key].configure(text=value)
            for key in ("fetched", "errors", "blocked", "expired", "api_requests",
                        "browser_visits", "browser_rejected"):
                self.metrics[key].configure(text=st.get(key, 0))
            self.status_label.configure(text=f"Workers {s['workers']} • Queue {s['queue_memory']} • {NEXUS.last_message[:65]}")
        except Exception:
            logging.exception("GUI status refresh failed")
        self.after(2000, self.refresh_status)

    def on_close(self):
        if messagebox.askyesno("Exit", "Stop probes and close DominionDeck Nexus?"):
            NEXUS.shutdown()
            self.destroy()

def configure_logging():
    level = getattr(logging, str(CONFIG.get("log_level", "INFO")).upper(), logging.INFO)
    root = logging.getLogger()
    root.setLevel(level)
    handler = RotatingFileHandler(LOG_PATH, maxBytes=2_000_000, backupCount=4, encoding="utf-8")
    handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(threadName)s: %(message)s"))
    root.addHandler(handler)
    root.addHandler(logging.StreamHandler())

def main():
    configure_logging()
    logging.info("Starting %s v%s", APP_NAME, APP_VERSION)
    NEXUS.start_workers()
    threading.Thread(target=NEXUS.maintenance_loop, name="Maintenance", daemon=True).start()
    NEXUS.start_api()
    NEXUS.cleanup_expired()
    if CONFIG.get("crawl_enabled"):
        NEXUS.seed()
    else:
        NEXUS.emit("system", "Autonomous crawling is paused; add URLs or load seeds to begin.")
    try:
        app = NexusGUI()
        app.mainloop()
    except Exception:
        logging.exception("GUI startup/runtime failure")
        NEXUS.shutdown()
        raise
    finally:
        NEXUS.shutdown()

if __name__ == "__main__":
    main()
