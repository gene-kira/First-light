#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DominionDeck Cache Manager v3.0
Local cache inventory + respectful public-web cache harvester.

The web collector is a bounded downloader for publicly accessible resources:
- Starts from URLs supplied by the user.
- Stays on the seed host(s) by default.
- Checks robots.txt and obeys crawl-delay when available.
- Uses a descriptive User-Agent, rate limiting, page/depth/file/total-byte limits.
- Does not log in, bypass paywalls, evade access controls, or fetch private browser caches.
- Skips Cache-Control: no-store/private and non-cacheable/unsupported content.
- Stores downloaded resources in a separate WebCache directory with a SQLite index.
- Lets the user search, inspect metadata, open, and export collected cache entries.

Existing local cleanup remains review-first. Automatic deletion is OFF by default.
Python 3.10+ recommended. Standard library only; optional send2trash for Recycle Bin.
"""

from __future__ import annotations

import csv
import fnmatch
import hashlib
import html
import json
import logging
import mimetypes
import os
import queue
import re
import sqlite3
import threading
import time
import tkinter as tk
import urllib.error
import urllib.parse
import urllib.robotparser
import urllib.request
from dataclasses import dataclass
from datetime import datetime
from html.parser import HTMLParser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

APP_NAME = "DominionDeck Cache Manager"
APP_VERSION = "3.0"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "dominiondeck_cache_settings.json"
LOG_FILE = BASE_DIR / "DominionDeckCacheCleaner.log"
REPORT_DIR = BASE_DIR / "cache_reports"
WEB_CACHE_DIR = BASE_DIR / "WebCache"
WEB_DB = WEB_CACHE_DIR / "web_cache.sqlite3"
USER_AGENT = "DominionDeckCacheCollector/3.0 (+respectful public-resource caching)"
DEFAULT_CONFIG = {
    "cache_folder": "",
    "cache_expiration_days": 60,
    "scan_interval_hours": 24,
    "auto_scan": True,
    "auto_cleanup": False,
    "use_recycle_bin": True,
    "cleanup_empty_directories": True,
    "excluded_patterns": ["*.lock", "*.db-wal", "*.db-shm"],
    "max_scan_files": 250000,
    "web_max_pages": 100,
    "web_max_depth": 2,
    "web_delay": 1.0,
    "web_max_file_mb": 5,
    "web_max_total_mb": 250,
}
logging.basicConfig(filename=str(LOG_FILE), level=logging.INFO,
                    format="%(asctime)s | %(levelname)s | %(message)s",
                    encoding="utf-8")


def load_config() -> dict:
    try:
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
            result = DEFAULT_CONFIG.copy()
            if isinstance(loaded, dict):
                result.update(loaded)
            return result
    except Exception:
        logging.exception("Configuration load failed; defaults used.")
    return DEFAULT_CONFIG.copy()


def save_config(config: dict) -> None:
    temp = CONFIG_FILE.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
        f.flush()
        os.fsync(f.fileno())
    os.replace(temp, CONFIG_FILE)


def format_size(size: int | float) -> str:
    amount = float(max(0, size))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if amount < 1024 or unit == "TB":
            return f"{amount:,.2f} {unit}"
        amount /= 1024
    return f"{amount:,.2f} TB"


def format_age(seconds: float) -> str:
    days = max(0, int(seconds // 86400))
    return f"{days} day(s)" if days else "Less than 1 day"


def validate_cache_folder(value: str) -> Path:
    if not value.strip():
        raise ValueError("Choose a cache folder first.")
    folder = Path(value).expanduser().resolve(strict=True)
    if not folder.is_dir():
        raise ValueError("The selected path is not a directory.")
    if folder == Path(folder.anchor):
        raise ValueError("A drive/filesystem root cannot be selected.")
    return folder


@dataclass
class CacheRecord:
    path: str
    size: int
    modified: float
    accessed: float
    age_seconds: float
    reason: str


class CacheScanner:
    @staticmethod
    def scan(folder_text: str, expiration_days: int, excluded_patterns: list[str],
             max_files: int, cancel_event: threading.Event) -> dict:
        root = validate_cache_folder(folder_text)
        now, cutoff = time.time(), expiration_days * 86400
        patterns = [p.strip().lower() for p in excluded_patterns if p.strip()]
        records, total_files, total_size, skipped, errors = [], 0, 0, 0, []
        for current, dirs, files in os.walk(root, topdown=True, followlinks=False):
            if cancel_event.is_set():
                break
            kept = []
            for dirname in dirs:
                p = os.path.join(current, dirname)
                if os.path.islink(p):
                    skipped += 1
                else:
                    kept.append(dirname)
            dirs[:] = kept
            for filename in files:
                if cancel_event.is_set():
                    break
                full = os.path.join(current, filename)
                try:
                    if os.path.islink(full) or any(fnmatch.fnmatch(filename.lower(), p) for p in patterns):
                        skipped += 1
                        continue
                    st = os.stat(full, follow_symlinks=False)
                    if not os.path.isfile(full):
                        skipped += 1
                        continue
                    accessed = st.st_atime if st.st_atime > 0 else st.st_mtime
                    age = max(0.0, now - accessed)
                    total_files += 1
                    total_size += st.st_size
                    if age >= cutoff:
                        records.append(CacheRecord(full, st.st_size, st.st_mtime, accessed,
                                                   age, f"No recorded access for {int(age // 86400)} days"))
                    if total_files >= max_files:
                        errors.append(f"Scan limit reached ({max_files:,}); inventory may be incomplete.")
                        return {"records": records, "total_files": total_files, "total_size": total_size,
                                "skipped": skipped, "errors": errors, "cancelled": False,
                                "root": str(root), "scan_time": now}
                except OSError as exc:
                    skipped += 1
                    if len(errors) < 40:
                        errors.append(f"{full}: {exc}")
        return {"records": records, "total_files": total_files, "total_size": total_size,
                "skipped": skipped, "errors": errors, "cancelled": cancel_event.is_set(),
                "root": str(root), "scan_time": now}


class LinkParser(HTMLParser):
    """Extract navigational and static-resource URLs from HTML without executing it."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links = []
    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        for key in ("href", "src", "poster"):
            value = attrs.get(key)
            if value:
                self.links.append(value.strip())
        srcset = attrs.get("srcset", "")
        for part in srcset.split(","):
            candidate = part.strip().split(" ")[0] if part.strip() else ""
            if candidate:
                self.links.append(candidate)


class WebCacheStore:
    def __init__(self):
        WEB_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self._init_db()

    def connect(self):
        db = sqlite3.connect(str(WEB_DB), timeout=20)
        db.execute("PRAGMA journal_mode=WAL")
        return db

    def _init_db(self):
        with self.connect() as db:
            db.execute("""CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE NOT NULL, final_url TEXT, file_path TEXT NOT NULL,
                filename TEXT NOT NULL, content_type TEXT, size INTEGER NOT NULL,
                sha256 TEXT NOT NULL, fetched REAL NOT NULL, status INTEGER,
                etag TEXT, last_modified TEXT, source_host TEXT
            )""")
            db.execute("CREATE INDEX IF NOT EXISTS idx_entries_host ON entries(source_host)")

    def add(self, url, final_url, path, filename, content_type, size, digest, status, headers):
        with self.connect() as db:
            db.execute("""INSERT INTO entries
                (url,final_url,file_path,filename,content_type,size,sha256,fetched,status,etag,last_modified,source_host)
                VALUES (?,?,?,?,?,?,?,?,?,?,?,?)
                ON CONFLICT(url) DO UPDATE SET final_url=excluded.final_url,
                file_path=excluded.file_path,filename=excluded.filename,content_type=excluded.content_type,
                size=excluded.size,sha256=excluded.sha256,fetched=excluded.fetched,status=excluded.status,
                etag=excluded.etag,last_modified=excluded.last_modified""",
                (url, final_url, str(path), filename, content_type, size, digest, time.time(), status,
                 headers.get("ETag", ""), headers.get("Last-Modified", ""),
                 urllib.parse.urlsplit(url).netloc.lower()))

    def rows(self, search=""):
        with self.connect() as db:
            db.row_factory = sqlite3.Row
            if search:
                q = f"%{search.lower()}%"
                return db.execute("""SELECT * FROM entries WHERE lower(url) LIKE ?
                    OR lower(filename) LIKE ? OR lower(content_type) LIKE ? ORDER BY fetched DESC""",
                    (q, q, q)).fetchall()
            return db.execute("SELECT * FROM entries ORDER BY fetched DESC").fetchall()

    def stats(self):
        with self.connect() as db:
            row = db.execute("SELECT COUNT(*), COALESCE(SUM(size),0) FROM entries").fetchone()
            hosts = db.execute("SELECT COUNT(DISTINCT source_host) FROM entries").fetchone()[0]
        return int(row[0]), int(row[1]), int(hosts)

    def remove_missing(self):
        removed = 0
        with self.connect() as db:
            rows = db.execute("SELECT id,file_path FROM entries").fetchall()
            for row_id, path in rows:
                if not Path(path).is_file():
                    db.execute("DELETE FROM entries WHERE id=?", (row_id,))
                    removed += 1
        return removed


class WebCacheHarvester:
    # Only public, browser-like resources useful as a local cache are retained.
    ALLOWED_TYPES = (
        "text/html", "text/css", "text/plain", "text/javascript",
        "application/javascript", "application/json", "application/xml",
        "image/", "font/", "application/font", "application/woff",
        "application/vnd.ms-fontobject"
    )
    SKIP_EXTENSIONS = {".zip", ".exe", ".msi", ".iso", ".dmg", ".7z", ".rar",
                       ".pdf", ".mp4", ".mkv", ".mp3", ".avi", ".mov"}

    def __init__(self, store: WebCacheStore, events: queue.Queue,
                 cancel: threading.Event, settings: dict):
        self.store, self.events, self.cancel, self.settings = store, events, cancel, settings
        self.robots = {}
        self.last_request = {}
        self.seen = set()
        self.total_bytes = 0
        self.saved = 0
        self.skipped = 0
        self.errors = 0

    @staticmethod
    def normalize(url):
        p = urllib.parse.urlsplit(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            return None
        if p.username or p.password:
            return None
        path = p.path or "/"
        return urllib.parse.urlunsplit((p.scheme.lower(), p.netloc.lower(), path, p.query, ""))

    def allowed(self, url, allowed_hosts):
        p = urllib.parse.urlsplit(url)
        return p.scheme in ("http", "https") and p.hostname and p.hostname.lower() in allowed_hosts

    def robot_allowed(self, url):
        p = urllib.parse.urlsplit(url)
        origin = f"{p.scheme}://{p.netloc}"
        if origin not in self.robots:
            parser = urllib.robotparser.RobotFileParser()
            parser.set_url(origin + "/robots.txt")
            try:
                parser.read()
            except Exception:
                # If robots.txt cannot be retrieved, fail closed for this host.
                self.robots[origin] = (None, 1.0)
                return False
            delay = parser.crawl_delay(USER_AGENT) or parser.crawl_delay("*") or 0
            self.robots[origin] = (parser, max(0.0, float(delay)))
        parser, _delay = self.robots[origin]
        return bool(parser and parser.can_fetch(USER_AGENT, url))

    def pace(self, url):
        host = urllib.parse.urlsplit(url).netloc.lower()
        configured = float(self.settings["delay"])
        robots_delay = 0.0
        origin = f"{urllib.parse.urlsplit(url).scheme}://{host}"
        if origin in self.robots:
            robots_delay = self.robots[origin][1]
        wait = max(configured, robots_delay) - (time.monotonic() - self.last_request.get(host, 0))
        if wait > 0 and self.cancel.wait(wait):
            return False
        self.last_request[host] = time.monotonic()
        return not self.cancel.is_set()

    def fetch(self, url):
        if not self.robot_allowed(url) or not self.pace(url):
            self.skipped += 1
            return None
        req = urllib.request.Request(url, headers={
            "User-Agent": USER_AGENT,
            "Accept": "text/html,text/css,application/javascript,application/json,image/*,font/*,*/*;q=0.2",
            "Accept-Encoding": "identity",
        })
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                status = getattr(response, "status", 200)
                headers = response.headers
                final_url = self.normalize(response.geturl())
                if not final_url:
                    self.skipped += 1
                    return None
                cache_control = headers.get("Cache-Control", "").lower()
                if "no-store" in cache_control or "private" in cache_control:
                    self.skipped += 1
                    return None
                content_type = headers.get_content_type().lower()
                if not any(content_type.startswith(t) for t in self.ALLOWED_TYPES):
                    self.skipped += 1
                    return None
                length = headers.get("Content-Length")
                max_file = int(self.settings["max_file_mb"]) * 1024 * 1024
                if length and int(length) > max_file:
                    self.skipped += 1
                    return None
                data = response.read(max_file + 1)
                if len(data) > max_file:
                    self.skipped += 1
                    return None
                return final_url, status, headers, content_type, data
        except (urllib.error.URLError, TimeoutError, OSError, ValueError) as exc:
            self.errors += 1
            self.events.put(("log", f"Web fetch skipped: {url} ({exc})"))
            return None

    @staticmethod
    def extension(url, content_type):
        suffix = Path(urllib.parse.urlsplit(url).path).suffix.lower()
        if suffix and len(suffix) <= 8 and re.fullmatch(r"\.[a-z0-9]+", suffix):
            return suffix
        guessed = mimetypes.guess_extension(content_type.split(";")[0].strip()) or ".bin"
        return ".js" if content_type in ("text/javascript", "application/javascript") else guessed

    def save_resource(self, url, result):
        final_url, status, headers, content_type, data = result
        digest = hashlib.sha256(data).hexdigest()
        ext = self.extension(final_url, content_type)
        filename = digest[:24] + ext
        host_dir = hashlib.sha1(urllib.parse.urlsplit(url).netloc.encode()).hexdigest()[:12]
        destination_dir = WEB_CACHE_DIR / host_dir
        destination_dir.mkdir(parents=True, exist_ok=True)
        destination = destination_dir / filename
        if not destination.exists():
            temp = destination.with_suffix(destination.suffix + ".tmp")
            with temp.open("wb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(temp, destination)
        self.store.add(url, final_url, destination, filename, content_type,
                       len(data), digest, status, headers)
        self.total_bytes += len(data)
        self.saved += 1
        self.events.put(("web_item", url, str(destination), len(data), content_type))
        return data, content_type

    def run(self, seeds):
        max_pages = int(self.settings["max_pages"])
        max_depth = int(self.settings["max_depth"])
        max_total = int(self.settings["max_total_mb"]) * 1024 * 1024
        queue_items = []
        allowed_hosts = set()
        for seed in seeds:
            normalized = self.normalize(seed)
            if normalized:
                allowed_hosts.add(urllib.parse.urlsplit(normalized).hostname.lower())
                queue_items.append((normalized, 0))
        # Each seed host is an explicit allowlist entry; links never leave those hosts.
        queued = {u for u, _ in queue_items}
        visited_pages = 0
        while queue_items and not self.cancel.is_set():
            if visited_pages >= max_pages or self.total_bytes >= max_total:
                break
            url, depth = queue_items.pop(0)
            if url in self.seen:
                continue
            self.seen.add(url)
            p = urllib.parse.urlsplit(url)
            if Path(p.path).suffix.lower() in self.SKIP_EXTENSIONS:
                self.skipped += 1
                continue
            result = self.fetch(url)
            if not result:
                continue
            final_url, status, headers, content_type, data = result
            self.save_resource(url, result)
            visited_pages += 1
            self.events.put(("web_progress", visited_pages, max_pages, self.saved,
                             self.total_bytes, self.skipped, self.errors))
            if content_type == "text/html" and depth < max_depth:
                try:
                    parser = LinkParser()
                    parser.feed(data.decode(headers.get_content_charset() or "utf-8", errors="replace"))
                    for raw in parser.links:
                        if raw.startswith(("mailto:", "javascript:", "data:", "tel:")):
                            continue
                        candidate = self.normalize(urllib.parse.urljoin(final_url, raw))
                        if not candidate or not self.allowed(candidate, allowed_hosts):
                            continue
                        if candidate not in queued and candidate not in self.seen:
                            queued.add(candidate)
                            queue_items.append((candidate, depth + 1))
                except Exception as exc:
                    self.events.put(("log", f"HTML link parse warning: {exc}"))
        return {"saved": self.saved, "bytes": self.total_bytes, "skipped": self.skipped,
                "errors": self.errors, "cancelled": self.cancel.is_set(),
                "visited": visited_pages}


class DominionDeckGUI:
    def __init__(self):
        self.config = load_config()
        self.root = tk.Tk()
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1120x760")
        self.root.minsize(850, 600)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self.events = queue.Queue()
        self.cancel_event = threading.Event()
        self.worker_active = False
        self.closing = False
        self.paused = False
        self.scan_result = None
        self.records_by_id = {}
        self.web_rows = {}
        self.scheduler_id = self.poll_id = None
        self.store = WebCacheStore()

        self.folder_var = tk.StringVar(value=self.config.get("cache_folder", ""))
        self.days_var = tk.StringVar(value=str(self.config.get("cache_expiration_days", 60)))
        self.interval_var = tk.StringVar(value=str(self.config.get("scan_interval_hours", 24)))
        self.auto_scan_var = tk.BooleanVar(value=bool(self.config.get("auto_scan", True)))
        self.auto_cleanup_var = tk.BooleanVar(value=bool(self.config.get("auto_cleanup", False)))
        self.recycle_var = tk.BooleanVar(value=bool(self.config.get("use_recycle_bin", True)))
        self.empty_dirs_var = tk.BooleanVar(value=bool(self.config.get("cleanup_empty_directories", True)))
        self.excluded_var = tk.StringVar(value=", ".join(self.config.get("excluded_patterns", [])))
        self.seed_var = tk.StringVar()
        self.web_pages_var = tk.StringVar(value=str(self.config.get("web_max_pages", 100)))
        self.web_depth_var = tk.StringVar(value=str(self.config.get("web_max_depth", 2)))
        self.web_delay_var = tk.StringVar(value=str(self.config.get("web_delay", 1.0)))
        self.web_file_var = tk.StringVar(value=str(self.config.get("web_max_file_mb", 5)))
        self.web_total_var = tk.StringVar(value=str(self.config.get("web_max_total_mb", 250)))
        self.web_search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready")
        self.summary_var = tk.StringVar(value="Choose a local cache folder, then scan.")
        self.web_summary_var = tk.StringVar(value="No web collection run yet.")
        self.configure_style()
        self.build_gui()
        self.load_log_tail()
        self.refresh_web_cache()
        self.poll_id = self.root.after(150, self.poll_events)
        self.root.after(500, self.startup)

    def configure_style(self):
        style = ttk.Style(self.root)
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("Title.TLabel", font=("Segoe UI", 16, "bold"))
        style.configure("Metric.TLabel", font=("Segoe UI", 14, "bold"))
        style.configure("Treeview", rowheight=24, font=("Segoe UI", 9))
        style.configure("Treeview.Heading", font=("Segoe UI", 9, "bold"))

    def build_gui(self):
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)
        header = ttk.Frame(outer)
        header.pack(fill="x", pady=(0, 8))
        ttk.Label(header, text=APP_NAME, style="Title.TLabel").pack(side="left")
        ttk.Label(header, text=f"v{APP_VERSION} | Local + Web Cache Intelligence").pack(side="right")
        folder = ttk.Frame(outer)
        folder.pack(fill="x", pady=(0, 7))
        ttk.Label(folder, text="Local cache folder:").pack(side="left")
        ttk.Entry(folder, textvariable=self.folder_var).pack(side="left", fill="x", expand=True, padx=7)
        ttk.Button(folder, text="Browse…", command=self.select_folder).pack(side="left")
        ttk.Button(folder, text="Open Folder", command=self.open_folder).pack(side="left", padx=(5, 0))
        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=(0, 7))
        self.scan_button = ttk.Button(actions, text="Scan Local", command=self.run_scan)
        self.scan_button.pack(side="left")
        self.preview_button = ttk.Button(actions, text="Preview Cleanup", command=self.preview_cleanup)
        self.preview_button.pack(side="left", padx=5)
        self.delete_button = ttk.Button(actions, text="Delete Eligible", command=self.manual_cleanup)
        self.delete_button.pack(side="left")
        ttk.Button(actions, text="Export Local CSV", command=self.export_csv).pack(side="left", padx=5)
        self.pause_button = ttk.Button(actions, text="Pause Scheduler", command=self.toggle_pause)
        self.pause_button.pack(side="right")
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True)
        self.dashboard_tab = ttk.Frame(self.tabs, padding=10)
        self.review_tab = ttk.Frame(self.tabs, padding=8)
        self.web_tab = ttk.Frame(self.tabs, padding=10)
        self.settings_tab = ttk.Frame(self.tabs, padding=10)
        self.logs_tab = ttk.Frame(self.tabs, padding=8)
        for tab, label in [(self.dashboard_tab, "Dashboard"), (self.review_tab, "Local Cleanup"),
                           (self.web_tab, "Web Cache Probe"), (self.settings_tab, "Settings"),
                           (self.logs_tab, "Activity & Logs")]:
            self.tabs.add(tab, text=label)
        self.build_dashboard()
        self.build_review()
        self.build_web_tab()
        self.build_settings()
        self.build_logs()
        footer = ttk.Frame(outer)
        footer.pack(fill="x", pady=(7, 0))
        ttk.Label(footer, textvariable=self.status_var).pack(side="left")
        ttk.Label(footer, text="Automatic local deletion: OFF by default").pack(side="right")

    def build_dashboard(self):
        cards = ttk.Frame(self.dashboard_tab)
        cards.pack(fill="x")
        self.metrics = {k: tk.StringVar(value="—") for k in ("files", "size", "eligible", "reclaim")}
        for i, (caption, key) in enumerate([("FILES SCANNED", "files"), ("LOCAL CACHE SIZE", "size"),
                                            ("ELIGIBLE FILES", "eligible"), ("POTENTIAL RECOVERY", "reclaim")]):
            card = ttk.LabelFrame(cards, text=caption, padding=10)
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 5, 0))
            cards.columnconfigure(i, weight=1)
            ttk.Label(card, textvariable=self.metrics[key], style="Metric.TLabel").pack(anchor="w")
        ttk.Label(self.dashboard_tab, text="Local storage intelligence",
                  font=("Segoe UI", 10, "bold")).pack(anchor="w", pady=(20, 5))
        ttk.Label(self.dashboard_tab, textvariable=self.summary_var, justify="left",
                  wraplength=950).pack(anchor="w")
        ttk.Separator(self.dashboard_tab).pack(fill="x", pady=14)
        webcard = ttk.LabelFrame(self.dashboard_tab, text="Collected public-web cache", padding=12)
        webcard.pack(fill="x")
        self.dashboard_web_var = tk.StringVar(value="")
        ttk.Label(webcard, textvariable=self.dashboard_web_var, style="Metric.TLabel").pack(anchor="w")
        ttk.Button(webcard, text="Open Web Cache Probe", command=lambda: self.tabs.select(self.web_tab)).pack(anchor="w", pady=(8, 0))
        ttk.Label(self.dashboard_tab, text=(
            "Local eligibility uses recorded last-access time, which Windows may delay or disable. "
            "Review candidates before deleting. Symbolic links and excluded patterns are skipped."
        ), wraplength=950, justify="left").pack(anchor="w", pady=16)

    def build_review(self):
        top = ttk.Frame(self.review_tab)
        top.pack(fill="x", pady=(0, 6))
        ttk.Label(top, text="Files meeting the local retention rule").pack(side="left")
        ttk.Button(top, text="Select All", command=self.select_all).pack(side="right")
        ttk.Button(top, text="Select None", command=self.select_none).pack(side="right", padx=5)
        columns = ("age", "size", "modified", "path")
        self.tree = ttk.Treeview(self.review_tab, columns=columns, show="tree headings", selectmode="extended")
        for col, label, width in [("#0", "File", 180), ("age", "Recorded unused age", 140),
                                  ("size", "Size", 100), ("modified", "Modified", 145), ("path", "Full path", 450)]:
            self.tree.heading(col, text=label)
            self.tree.column(col, width=width, anchor="w" if col in ("#0", "path") else "center")
        y = ttk.Scrollbar(self.review_tab, orient="vertical", command=self.tree.yview)
        x = ttk.Scrollbar(self.review_tab, orient="horizontal", command=self.tree.xview)
        self.tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        self.tree.pack(side="top", fill="both", expand=True)
        y.pack(side="right", fill="y")
        x.pack(side="bottom", fill="x")
        self.tree.bind("<<TreeviewSelect>>", self.selection_changed)
        self.review_hint = ttk.Label(self.review_tab, text="Run a scan to populate this review.")
        self.review_hint.pack(anchor="w", pady=6)

    def build_web_tab(self):
        intro = ttk.LabelFrame(self.web_tab, text="Bumblebee / probe collection", padding=9)
        intro.pack(fill="x")
        ttk.Label(intro, text="Start URL(s) — one per line. Public pages only; collection stays on each seed host.",
                  wraplength=950).pack(anchor="w")
        self.seed_text = tk.Text(intro, height=3, wrap="word")
        self.seed_text.pack(fill="x", pady=5)
        controls = ttk.Frame(intro)
        controls.pack(fill="x")
        ttk.Label(controls, text="Max pages").pack(side="left")
        ttk.Entry(controls, textvariable=self.web_pages_var, width=6).pack(side="left", padx=(4, 12))
        ttk.Label(controls, text="Depth").pack(side="left")
        ttk.Entry(controls, textvariable=self.web_depth_var, width=4).pack(side="left", padx=(4, 12))
        ttk.Label(controls, text="Delay (sec)").pack(side="left")
        ttk.Entry(controls, textvariable=self.web_delay_var, width=6).pack(side="left", padx=(4, 12))
        ttk.Label(controls, text="Max file MB").pack(side="left")
        ttk.Entry(controls, textvariable=self.web_file_var, width=5).pack(side="left", padx=(4, 12))
        ttk.Label(controls, text="Total MB").pack(side="left")
        ttk.Entry(controls, textvariable=self.web_total_var, width=6).pack(side="left", padx=4)
        buttons = ttk.Frame(intro)
        buttons.pack(fill="x", pady=(8, 0))
        self.web_start_button = ttk.Button(buttons, text="Start Web Probe", command=self.start_web_probe)
        self.web_start_button.pack(side="left")
        self.web_stop_button = ttk.Button(buttons, text="Stop Probe", command=self.stop_web_probe, state="disabled")
        self.web_stop_button.pack(side="left", padx=5)
        ttk.Button(buttons, text="Refresh Cache", command=self.refresh_web_cache).pack(side="left")
        ttk.Button(buttons, text="Open WebCache Folder", command=self.open_web_cache).pack(side="left", padx=5)
        self.web_progress = ttk.Progressbar(self.web_tab, mode="determinate", maximum=100)
        self.web_progress.pack(fill="x", pady=(9, 3))
        ttk.Label(self.web_tab, textvariable=self.web_summary_var, wraplength=950).pack(anchor="w", pady=(0, 7))
        summary = ttk.Frame(self.web_tab)
        summary.pack(fill="x", pady=(0, 6))
        self.web_count_var = tk.StringVar(value="0 resources")
        self.web_size_var = tk.StringVar(value="0 B")
        self.web_hosts_var = tk.StringVar(value="0 hosts")
        for var in (self.web_count_var, self.web_size_var, self.web_hosts_var):
            ttk.Label(summary, textvariable=var, style="Metric.TLabel").pack(side="left", padx=(0, 22))
        searchrow = ttk.Frame(self.web_tab)
        searchrow.pack(fill="x", pady=(0, 5))
        ttk.Label(searchrow, text="Search collected cache:").pack(side="left")
        entry = ttk.Entry(searchrow, textvariable=self.web_search_var)
        entry.pack(side="left", fill="x", expand=True, padx=6)
        entry.bind("<Return>", lambda _e: self.refresh_web_cache())
        ttk.Button(searchrow, text="Search", command=self.refresh_web_cache).pack(side="left")
        cols = ("type", "size", "fetched", "url", "file")
        self.web_tree = ttk.Treeview(self.web_tab, columns=cols, show="headings", selectmode="browse")
        for col, label, width in [("type", "Content type", 140), ("size", "Size", 90),
                                  ("fetched", "Collected", 145), ("url", "Original URL", 430),
                                  ("file", "Local cache file", 220)]:
            self.web_tree.heading(col, text=label)
            self.web_tree.column(col, width=width, anchor="w" if col in ("url", "file", "type") else "center")
        wy = ttk.Scrollbar(self.web_tab, orient="vertical", command=self.web_tree.yview)
        wx = ttk.Scrollbar(self.web_tab, orient="horizontal", command=self.web_tree.xview)
        self.web_tree.configure(yscrollcommand=wy.set, xscrollcommand=wx.set)
        self.web_tree.pack(fill="both", expand=True, side="top")
        wy.pack(side="right", fill="y")
        wx.pack(side="bottom", fill="x")
        bottom = ttk.Frame(self.web_tab)
        bottom.pack(fill="x", pady=(6, 0))
        ttk.Button(bottom, text="Open Selected File", command=self.open_selected_web_file).pack(side="left")
        ttk.Button(bottom, text="Open Selected URL", command=self.open_selected_web_url).pack(side="left", padx=5)
        ttk.Button(bottom, text="Export Cache Index CSV", command=self.export_web_csv).pack(side="left")
        ttk.Label(bottom, text="Files are stored locally; this does not change the live website.").pack(side="right")

    def build_settings(self):
        form = ttk.Frame(self.settings_tab)
        form.pack(fill="x", anchor="nw")
        fields = [("Retention period (days)", self.days_var, 0),
                  ("Scheduled scan interval (hours)", self.interval_var, 1)]
        for label, var, row in fields:
            ttk.Label(form, text=label + ":").grid(row=row, column=0, sticky="w", pady=6)
            ttk.Entry(form, textvariable=var, width=12).grid(row=row, column=1, sticky="w", padx=10)
        checks = [
            ("Enable automatic scheduled local scans", self.auto_scan_var),
            ("Automatically clean eligible local files (not recommended)", self.auto_cleanup_var),
            ("Use Recycle Bin (requires optional send2trash)", self.recycle_var),
            ("Remove empty local subdirectories after cleanup", self.empty_dirs_var)]
        for i, (label, var) in enumerate(checks, start=2):
            ttk.Checkbutton(form, text=label, variable=var).grid(row=i, column=0, columnspan=2, sticky="w", pady=4)
        ttk.Label(form, text="Excluded local filename patterns:").grid(row=6, column=0, sticky="w", pady=8)
        ttk.Entry(form, textvariable=self.excluded_var, width=65).grid(row=6, column=1, sticky="ew", padx=10)
        form.columnconfigure(1, weight=1)
        ttk.Label(self.settings_tab, text=(
            "Web collector safeguards: respects robots.txt, stays on seed hostnames, rate-limits requests, "
            "and enforces page/depth/file/total-size limits. It skips no-store/private responses and "
            "does not bypass logins, paywalls, CAPTCHAs, or access controls. Only collect content you "
            "are allowed to download. The WebCache folder is separate from local cleanup."
        ), foreground="#8a5a20", wraplength=950, justify="left").pack(anchor="w", pady=18)
        ttk.Button(self.settings_tab, text="Save Settings", command=self.save_settings).pack(anchor="w")

    def build_logs(self):
        bar = ttk.Frame(self.logs_tab)
        bar.pack(fill="x", pady=(0, 5))
        ttk.Button(bar, text="Clear View", command=self.clear_log_view).pack(side="right")
        self.log_box = tk.Text(self.logs_tab, height=20, wrap="word", font=("Consolas", 9), state="disabled")
        scroll = ttk.Scrollbar(self.logs_tab, command=self.log_box.yview)
        self.log_box.configure(yscrollcommand=scroll.set)
        self.log_box.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")

    def append_log(self, line):
        self.log_box.configure(state="normal")
        self.log_box.insert("end", line + "\n")
        self.log_box.see("end")
        self.log_box.configure(state="disabled")

    def log(self, message, level="info"):
        getattr(logging, level if level in ("info", "warning", "error") else "info")(message)
        line = f"[{datetime.now():%Y-%m-%d %H:%M:%S}] {message}"
        if threading.current_thread() is threading.main_thread():
            self.append_log(line)
        else:
            self.events.put(("log", line))

    def load_log_tail(self):
        try:
            if LOG_FILE.exists():
                lines = LOG_FILE.read_text(encoding="utf-8", errors="replace").splitlines()[-150:]
                self.log_box.configure(state="normal")
                self.log_box.insert("end", "\n".join(lines) + "\n")
                self.log_box.see("end")
                self.log_box.configure(state="disabled")
        except OSError:
            pass

    def clear_log_view(self):
        self.log_box.configure(state="normal")
        self.log_box.delete("1.0", "end")
        self.log_box.configure(state="disabled")

    def startup(self):
        if not self.closing and self.folder_var.get().strip() and self.auto_scan_var.get():
            self.run_scan()

    def select_folder(self):
        folder = filedialog.askdirectory(title="Select a dedicated local cache folder")
        if folder:
            self.folder_var.set(folder)
            if self.save_settings(silent=True):
                self.run_scan()

    def open_folder(self):
        try:
            self.open_path(validate_cache_folder(self.folder_var.get()))
        except Exception as exc:
            messagebox.showerror(APP_NAME, str(exc))

    @staticmethod
    def open_path(path):
        path = str(path)
        if os.name == "nt":
            os.startfile(path)
        elif os.name == "posix":
            import subprocess
            subprocess.Popen(["xdg-open", path])

    def open_web_cache(self):
        WEB_CACHE_DIR.mkdir(parents=True, exist_ok=True)
        self.open_path(WEB_CACHE_DIR)

    def save_settings(self, silent=False):
        try:
            days, hours = int(self.days_var.get()), int(self.interval_var.get())
            if not 1 <= days <= 3650:
                raise ValueError("Retention must be between 1 and 3650 days.")
            if not 1 <= hours <= 720:
                raise ValueError("Scan interval must be between 1 and 720 hours.")
            folder = self.folder_var.get().strip()
            if folder:
                validate_cache_folder(folder)
            self.config.update({
                "cache_folder": folder, "cache_expiration_days": days, "scan_interval_hours": hours,
                "auto_scan": self.auto_scan_var.get(), "auto_cleanup": self.auto_cleanup_var.get(),
                "use_recycle_bin": self.recycle_var.get(), "cleanup_empty_directories": self.empty_dirs_var.get(),
                "excluded_patterns": [x.strip() for x in self.excluded_var.get().split(",") if x.strip()],
                "web_max_pages": int(self.web_pages_var.get()), "web_max_depth": int(self.web_depth_var.get()),
                "web_delay": float(self.web_delay_var.get()), "web_max_file_mb": int(self.web_file_var.get()),
                "web_max_total_mb": int(self.web_total_var.get())})
            if not 1 <= self.config["web_max_pages"] <= 5000:
                raise ValueError("Web page limit must be 1–5000.")
            if not 0 <= self.config["web_max_depth"] <= 10:
                raise ValueError("Web depth must be 0–10.")
            if not 0.2 <= self.config["web_delay"] <= 60:
                raise ValueError("Web delay must be 0.2–60 seconds.")
            if not 1 <= self.config["web_max_file_mb"] <= 100:
                raise ValueError("Maximum file size must be 1–100 MB.")
            if not 1 <= self.config["web_max_total_mb"] <= 5000:
                raise ValueError("Total web cache limit must be 1–5000 MB.")
            save_config(self.config)
            self.schedule_next()
            if not silent:
                self.log("Settings saved.")
                self.status_var.set("Settings saved.")
            return True
        except Exception as exc:
            messagebox.showerror("Invalid settings", str(exc))
            return False

    def set_busy(self, busy):
        self.worker_active = busy
        state = "disabled" if busy else "normal"
        self.scan_button.configure(state=state)
        self.preview_button.configure(state=state)
        self.delete_button.configure(state=state)
        self.web_start_button.configure(state=state)
        self.web_stop_button.configure(state="normal" if busy and getattr(self, "web_running", False) else "disabled")

    def start_worker(self, label, target, *args):
        if self.worker_active:
            self.status_var.set("Another operation is already running.")
            return False
        self.set_busy(True)
        self.cancel_event.clear()
        self.status_var.set(label)
        def worker():
            try:
                result = target(*args)
                self.events.put(("result", label, result))
            except Exception as exc:
                logging.exception("%s failed", label)
                self.events.put(("error", label, str(exc)))
            finally:
                self.events.put(("finished", label))
        threading.Thread(target=worker, daemon=True, name="DominionDeckWorker").start()
        return True

    def run_scan(self):
        if not self.folder_var.get().strip():
            messagebox.showinfo(APP_NAME, "Choose a local cache folder first.")
            return False
        if not self.save_settings(silent=True):
            return False
        self.log("Starting local cache inventory scan.")
        return self.start_worker("Scanning local cache", CacheScanner.scan, self.folder_var.get(),
                                int(self.days_var.get()), self.config.get("excluded_patterns", []),
                                int(self.config.get("max_scan_files", 250000)), self.cancel_event)

    def start_web_probe(self):
        raw = self.seed_text.get("1.0", "end").splitlines()
        seeds = [line.strip() for line in raw if line.strip()]
        if not seeds:
            messagebox.showinfo(APP_NAME, "Enter at least one public http:// or https:// seed URL.")
            return
        if not self.save_settings(silent=True):
            return
        normalized = [WebCacheHarvester.normalize(s) for s in seeds]
        if any(x is None for x in normalized):
            messagebox.showerror(APP_NAME, "Every seed must be a valid http:// or https:// URL without embedded credentials.")
            return
        self.web_running = True
        self.web_progress.configure(value=0, maximum=self.config["web_max_pages"])
        self.web_summary_var.set("Probe running. Hosts, robots.txt rules and configured limits are being respected.")
        self.log(f"Starting public web cache probe for {len(normalized)} seed URL(s).")
        self.tabs.select(self.web_tab)
        self.start_worker("Collecting public web cache", self.run_harvest, normalized, self.config.copy())

    def run_harvest(self, seeds, config):
        settings = {"max_pages": config["web_max_pages"], "max_depth": config["web_max_depth"],
                    "delay": config["web_delay"], "max_file_mb": config["web_max_file_mb"],
                    "max_total_mb": config["web_max_total_mb"]}
        return WebCacheHarvester(self.store, self.events, self.cancel_event, settings).run(seeds)

    def stop_web_probe(self):
        self.cancel_event.set()
        self.status_var.set("Stopping web probe after the current request…")
        self.log("Web probe stop requested.")

    def refresh_web_cache(self):
        try:
            self.store.remove_missing()
            rows = self.store.rows(self.web_search_var.get().strip())
            for item in self.web_tree.get_children():
                self.web_tree.delete(item)
            self.web_rows.clear()
            for row in rows:
                iid = str(row["id"])
                self.web_rows[iid] = dict(row)
                self.web_tree.insert("", "end", iid=iid, values=(
                    row["content_type"] or "unknown", format_size(row["size"]),
                    datetime.fromtimestamp(row["fetched"]).strftime("%Y-%m-%d %H:%M"),
                    row["url"], row["file_path"]))
            count, size, hosts = self.store.stats()
            self.web_count_var.set(f"{count:,} resources")
            self.web_size_var.set(format_size(size))
            self.web_hosts_var.set(f"{hosts:,} hosts")
            line = f"Collected cache: {count:,} resources | {format_size(size)} | {hosts:,} host(s)"
            self.dashboard_web_var.set(line)
            self.web_summary_var.set(line + f" | Storage: {WEB_CACHE_DIR}")
        except Exception as exc:
            self.log(f"Could not refresh web cache index: {exc}", "error")

    def selected_web_row(self):
        selected = self.web_tree.selection()
        return self.web_rows.get(selected[0]) if selected else None

    def open_selected_web_file(self):
        row = self.selected_web_row()
        if not row:
            messagebox.showinfo(APP_NAME, "Select a collected resource first.")
            return
        path = Path(row["file_path"]).resolve()
        if not path.is_file() or WEB_CACHE_DIR.resolve() not in path.parents:
            messagebox.showerror(APP_NAME, "The selected cache file is missing or outside WebCache.")
            return
        self.open_path(path)

    def open_selected_web_url(self):
        row = self.selected_web_row()
        if not row:
            messagebox.showinfo(APP_NAME, "Select a collected resource first.")
            return
        import webbrowser
        webbrowser.open(row["url"])

    def export_web_csv(self):
        rows = self.store.rows(self.web_search_var.get().strip())
        if not rows:
            messagebox.showinfo(APP_NAME, "No matching web cache entries to export.")
            return
        dest = filedialog.asksaveasfilename(defaultextension=".csv",
            initialfile=f"web_cache_index_{datetime.now():%Y%m%d_%H%M%S}.csv",
            filetypes=[("CSV files", "*.csv")])
        if not dest:
            return
        with open(dest, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["URL", "Local File", "Content Type", "Size Bytes", "SHA256", "Fetched"])
            for r in rows:
                writer.writerow([r["url"], r["file_path"], r["content_type"], r["size"],
                                 r["sha256"], datetime.fromtimestamp(r["fetched"]).isoformat()])
        self.log(f"Web cache index exported: {dest}")

    def preview_cleanup(self):
        if self.scan_result is None:
            self.run_scan()
            self.status_var.set("Local scan started; review will populate when it finishes.")
            return
        self.tabs.select(self.review_tab)
        self.status_var.set("Review candidates; select files before deleting.")

    def populate_scan(self, result):
        self.scan_result = result
        for item in self.tree.get_children():
            self.tree.delete(item)
        self.records_by_id.clear()
        for index, record in enumerate(result["records"]):
            iid = f"candidate_{index}"
            self.records_by_id[iid] = record
            self.tree.insert("", "end", iid=iid, text=os.path.basename(record.path), values=(
                format_age(record.age_seconds), format_size(record.size),
                datetime.fromtimestamp(record.modified).strftime("%Y-%m-%d %H:%M"), record.path))
        eligible = result["records"]
        reclaim = sum(x.size for x in eligible)
        self.metrics["files"].set(f"{result['total_files']:,}")
        self.metrics["size"].set(format_size(result["total_size"]))
        self.metrics["eligible"].set(f"{len(eligible):,}")
        self.metrics["reclaim"].set(format_size(reclaim))
        self.summary_var.set(
            f"Last scan: {datetime.fromtimestamp(result['scan_time']):%Y-%m-%d %H:%M:%S}\n"
            f"Potential recovery: {format_size(reclaim)} across {len(eligible):,} eligible files.\n"
            f"Skipped: {result['skipped']:,}. Retention threshold: {self.days_var.get()} days.\n"
            "Timestamp-based estimate only; it does not prove a file is unused.")
        self.review_hint.configure(text=f"{len(eligible):,} eligible | {format_size(reclaim)} potential recovery")
        self.log(f"Local scan complete: {result['total_files']} files; {len(eligible)} eligible.")
        for warning in result["errors"][:10]:
            self.log("Local scan warning: " + warning, "warning")
        self.status_var.set("Local scan cancelled." if result["cancelled"] else "Local scan complete.")
        self.tabs.select(self.dashboard_tab)

    def selection_changed(self, _event=None):
        selected = self.tree.selection()
        amount = sum(self.records_by_id[x].size for x in selected if x in self.records_by_id)
        self.review_hint.configure(text=f"{len(selected):,} selected | {format_size(amount)} selected size")

    def select_all(self):
        self.tree.selection_set(self.tree.get_children())
        self.selection_changed()

    def select_none(self):
        self.tree.selection_remove(self.tree.selection())
        self.selection_changed()

    def manual_cleanup(self):
        if not self.scan_result:
            messagebox.showinfo(APP_NAME, "Run a local scan before cleanup.")
            return
        selected = list(self.tree.selection())
        candidates = ([self.records_by_id[x] for x in selected if x in self.records_by_id]
                      if selected else list(self.scan_result["records"]))
        if not candidates:
            messagebox.showinfo(APP_NAME, "No eligible local files were found.")
            return
        amount = sum(x.size for x in candidates)
        mode = "Recycle Bin" if self.recycle_var.get() else "permanent deletion"
        if not messagebox.askyesno("Confirm local cleanup",
            f"Proceed with {mode}?\n\nFiles: {len(candidates):,}\nSize: {format_size(amount)}\n\n"
            "This affects only the selected local cache folder, never WebCache.", icon="warning"):
            return
        root = str(validate_cache_folder(self.folder_var.get()))
        self.start_worker("Cleaning local cache", self.delete_records, root, candidates,
                          self.recycle_var.get(), self.empty_dirs_var.get(), int(self.days_var.get()))

    @staticmethod
    def delete_records(root_text, records, use_recycle_bin, remove_empty_dirs, retention_days):
        root = Path(root_text).resolve(strict=True)
        send_to_trash = None
        if use_recycle_bin:
            try:
                from send2trash import send2trash as send_to_trash
            except ImportError:
                raise RuntimeError("Recycle Bin mode requires send2trash. Install: py -m pip install send2trash. No files deleted.")
        deleted, processed_size, failures = 0, 0, []
        now, cutoff = time.time(), retention_days * 86400
        for record in records:
            try:
                candidate = Path(record.path)
                parent = candidate.parent.resolve(strict=True)
                if os.path.commonpath([str(root), str(parent)]) != str(root):
                    raise ValueError("Path is outside selected cache directory.")
                if candidate.is_symlink() or not candidate.is_file():
                    raise ValueError("Not a regular file.")
                st = candidate.stat(follow_symlinks=False)
                access = st.st_atime if st.st_atime > 0 else st.st_mtime
                if now - access < cutoff:
                    raise ValueError("File no longer meets retention threshold.")
                send_to_trash(str(candidate)) if send_to_trash else candidate.unlink()
                deleted += 1
                processed_size += st.st_size
            except Exception as exc:
                failures.append(f"{record.path}: {exc}")
        if remove_empty_dirs:
            for current, dirs, _ in os.walk(root, topdown=False, followlinks=False):
                for dirname in dirs:
                    d = Path(current) / dirname
                    try:
                        if not d.is_symlink() and not any(d.iterdir()):
                            d.rmdir()
                    except OSError:
                        pass
        return {"deleted": deleted, "processed_size": processed_size, "failures": failures}

    def export_csv(self):
        if not self.scan_result:
            messagebox.showinfo(APP_NAME, "Run a local scan before exporting.")
            return
        REPORT_DIR.mkdir(parents=True, exist_ok=True)
        dest = filedialog.asksaveasfilename(defaultextension=".csv",
            initialdir=str(REPORT_DIR), initialfile=f"local_cache_{datetime.now():%Y%m%d_%H%M%S}.csv",
            filetypes=[("CSV files", "*.csv")])
        if not dest:
            return
        with open(dest, "w", newline="", encoding="utf-8-sig") as f:
            writer = csv.writer(f)
            writer.writerow(["Path", "Size Bytes", "Access Time", "Modified Time", "Unused Days", "Reason"])
            for r in self.scan_result["records"]:
                writer.writerow([r.path, r.size, datetime.fromtimestamp(r.accessed).isoformat(),
                                 datetime.fromtimestamp(r.modified).isoformat(),
                                 round(r.age_seconds / 86400, 2), r.reason])
        self.log(f"Local cache report exported: {dest}")

    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_button.configure(text="Resume Scheduler" if self.paused else "Pause Scheduler")
        self.status_var.set("Scheduler paused." if self.paused else "Scheduler resumed.")
        if self.paused and self.scheduler_id:
            self.root.after_cancel(self.scheduler_id)
            self.scheduler_id = None
        elif not self.paused:
            self.schedule_next()

    def schedule_next(self):
        if self.scheduler_id:
            try:
                self.root.after_cancel(self.scheduler_id)
            except tk.TclError:
                pass
            self.scheduler_id = None
        if self.closing or self.paused or not self.auto_scan_var.get():
            return
        try:
            delay = max(1, int(self.interval_var.get())) * 3600 * 1000
        except ValueError:
            delay = 24 * 3600 * 1000
        self.scheduler_id = self.root.after(delay, self.scheduled_scan)

    def scheduled_scan(self):
        self.scheduler_id = None
        if self.closing or self.paused:
            return
        if not self.run_scan():
            self.schedule_next()

    def poll_events(self):
        if self.closing:
            return
        try:
            while True:
                event = self.events.get_nowait()
                kind = event[0]
                if kind == "log":
                    self.append_log(event[1])
                elif kind == "web_item":
                    pass
                elif kind == "web_progress":
                    done, maximum, saved, size, skipped, errors = event[1:]
                    self.web_progress.configure(value=min(done, maximum))
                    self.web_summary_var.set(
                        f"Probe progress: {done}/{maximum} pages | saved {saved} resources | "
                        f"{format_size(size)} | skipped {skipped} | errors {errors}")
                elif kind == "result":
                    label, result = event[1], event[2]
                    if label == "Scanning local cache":
                        self.populate_scan(result)
                        if self.auto_cleanup_var.get() and not result["cancelled"] and result["records"]:
                            self.root.after(100, self.automatic_cleanup)
                    elif label == "Cleaning local cache":
                        self.log(f"Local cleanup: {result['deleted']} files, {format_size(result['processed_size'])}.")
                        for failure in result["failures"][:25]:
                            self.log("Cleanup warning: " + failure, "warning")
                        self.status_var.set(f"Cleanup complete: {result['deleted']} deleted; {len(result['failures'])} issue(s).")
                        self.scan_result = None
                        self.root.after(250, self.run_scan)
                    elif label == "Collecting public web cache":
                        self.web_running = False
                        self.refresh_web_cache()
                        self.web_summary_var.set(
                            f"Probe finished: {result['saved']} resources saved | {format_size(result['bytes'])} | "
                            f"{result['skipped']} skipped | {result['errors']} errors"
                            + (" | cancelled" if result["cancelled"] else ""))
                        self.log(self.web_summary_var.get())
                        self.status_var.set("Web probe finished.")
                elif kind == "error":
                    self.web_running = False
                    self.log(f"{event[1]} failed: {event[2]}", "error")
                    self.status_var.set(f"{event[1]} failed.")
                    messagebox.showerror(event[1], event[2])
                elif kind == "finished":
                    self.set_busy(False)
                    if event[1] == "Collecting public web cache":
                        self.web_running = False
                        self.refresh_web_cache()
                    if event[1] == "Scanning local cache":
                        self.schedule_next()
        except queue.Empty:
            pass
        self.poll_id = self.root.after(150, self.poll_events)

    def automatic_cleanup(self):
        if self.closing or self.worker_active or not self.scan_result:
            return
        records = list(self.scan_result["records"])
        if records:
            self.start_worker("Cleaning local cache", self.delete_records,
                str(validate_cache_folder(self.folder_var.get())), records,
                self.recycle_var.get(), self.empty_dirs_var.get(), int(self.days_var.get()))

    def close(self):
        if self.worker_active and not messagebox.askyesno(APP_NAME, "An operation is running. Stop it and close?"):
            return
        self.closing = True
        self.cancel_event.set()
        for callback in (self.scheduler_id, self.poll_id):
            if callback:
                try:
                    self.root.after_cancel(callback)
                except tk.TclError:
                    pass
        try:
            self.save_config_on_close()
        except Exception:
            logging.exception("Could not save settings at shutdown.")
        self.root.destroy()

    def save_config_on_close(self):
        self.config.update({
            "cache_folder": self.folder_var.get(), "cache_expiration_days": int(self.days_var.get()),
            "scan_interval_hours": int(self.interval_var.get()), "auto_scan": self.auto_scan_var.get(),
            "auto_cleanup": self.auto_cleanup_var.get(), "use_recycle_bin": self.recycle_var.get(),
            "cleanup_empty_directories": self.empty_dirs_var.get(),
            "excluded_patterns": [p.strip() for p in self.excluded_var.get().split(",") if p.strip()]})
        save_config(self.config)

    def start(self):
        self.root.mainloop()


def main():
    try:
        DominionDeckGUI().start()
    except Exception:
        logging.exception("Fatal application error.")
        raise


if __name__ == "__main__":
    main()
