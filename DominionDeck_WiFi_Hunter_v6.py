"""
DominionDeck WiFi Hunter v2.2 (Upgraded & Diagnostic Edition)
Next-Level Predictive Wi-Fi Discovery Radar & Threat Analyzer
Supported OS: Windows, macOS, Linux.
"""

from __future__ import annotations

import sys

# --- Dependency & Environment Autoloader ---
def check_dependencies():
    """Verify Python version and required standard libraries before launch."""
    if sys.version_info < (3, 8):
        print("Error: DominionDeck WiFi Hunter requires Python 3.8 or higher.", file=sys.stderr)
        sys.exit(1)
    
    try:
        import tkinter as tk
        from tkinter import ttk, messagebox, filedialog
    except ImportError:
        print("CRITICAL: 'tkinter' is missing from your Python installation.", file=sys.stderr)
        print("On Linux/Debian systems, install it via: sudo apt install python3-tk", file=sys.stderr)
        sys.exit(1)

check_dependencies()

import csv
import json
import math
import os
import platform
import queue
import re
import shutil
import sqlite3
import subprocess
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

APP_NAME = "DominionDeck WiFi Hunter"
APP_VERSION = "2.2"

APP_DIR = Path.home() / "DominionDeck" / "WiFiHunter"
APP_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = APP_DIR / "wifi_hunter_config.json"
DATABASE_FILE = APP_DIR / "wifi_hunter_history.db"

DEFAULTS = {
    "target_ssid": "main",
    "target_bssid": "47:d9:g7:b1:06:64",
    "scan_interval": 3,
    "tx_power": -40,
    "path_loss": 2.5,
    "alert_threshold": -75,
    "history_limit": 300,
    "sound_alerts": False,
    "auto_start": False,
}


def normalize_bssid(value: str) -> str:
    value = (value or "").strip().lower().replace("-", ":")
    compact = re.sub(r"[^0-9a-f]", "", value)
    if len(compact) == 12:
        return ":".join(compact[i:i + 2] for i in range(0, 12, 2))
    return value


def valid_bssid(value: str) -> bool:
    return bool(re.fullmatch(r"(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", normalize_bssid(value)))


def signal_percent_to_rssi(percent: int) -> int:
    return int(round((max(0, min(100, percent)) / 2.0) - 100))


def estimate_distances(rssi: float, tx_power: float, path_loss: float) -> tuple[float | None, float | None]:
    if rssi is None or rssi >= 0 or path_loss <= 0:
        return None, None
    meters = 10 ** ((tx_power - rssi) / (10.0 * path_loss))
    if not math.isfinite(meters):
        return None, None
    meters = max(0.0, min(meters, 30480.0))
    feet = meters * 3.28084
    return round(feet, 1), round(meters, 1)


def get_frequency_band(channel_str: str, radio_str: str = "") -> str:
    try:
        chan = int(re.sub(r"\D", "", str(channel_str)))
        if 1 <= chan <= 14:
            return "2.4 GHz"
        elif 36 <= chan <= 177:
            return "5 GHz"
        elif chan > 177:
            return "6 GHz"
    except ValueError:
        pass

    radio_lower = (radio_str or "").lower()
    if "6ghz" in radio_lower or "ax (6" in radio_lower:
        return "6 GHz"
    if "802.11b" in radio_lower or "802.11g" in radio_lower or "2.4" in radio_lower:
        return "2.4 GHz"
    if "802.11a" in radio_lower or "802.11ac" in radio_lower or "5" in radio_lower:
        return "5 GHz"
    return "Unknown"


def calculate_velocity_vector(history: deque) -> str:
    """Predictive linear trend analysis over RSSI sample history."""
    if len(history) < 4:
        return "Calibrating..."
    
    n = len(history)
    x_vals = list(range(n))
    y_vals = list(history)
    
    mean_x = sum(x_vals) / n
    mean_y = sum(y_vals) / n
    
    num = sum((x_vals[i] - mean_x) * (y_vals[i] - mean_y) for i in range(n))
    den = sum((x_vals[i] - mean_x) ** 2 for i in range(n))
    
    if den == 0:
        return "Stable ➡️"
        
    slope = num / den
    
    if slope > 1.2:
        return "Approaching Fast 🚀"
    elif slope > 0.4:
        return "Closing In 📈"
    elif slope < -1.2:
        return "Retreating Fast 💨"
    elif slope < -0.4:
        return "Drifting Away 📉"
    else:
        return "Stationary ➡️"


def load_config() -> dict:
    config = DEFAULTS.copy()
    try:
        if CONFIG_FILE.exists():
            with CONFIG_FILE.open("r", encoding="utf-8") as f:
                loaded = json.load(f)
            if isinstance(loaded, dict):
                config.update({k: v for k, v in loaded.items() if k in DEFAULTS})
    except Exception:
        pass
    return config


def save_config(config: dict) -> None:
    APP_DIR.mkdir(parents=True, exist_ok=True)
    temp = CONFIG_FILE.with_suffix(".tmp")
    with temp.open("w", encoding="utf-8") as f:
        json.dump(config, f, indent=2)
    temp.replace(CONFIG_FILE)


class WiFiScanner:
    """Read nearby AP information using native OS tools; no active probing."""

    def __init__(self):
        self.system = platform.system()

    @staticmethod
    def _run(command: list[str], timeout: int = 12) -> str:
        completed = subprocess.run(
            command,
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0) if os.name == "nt" else 0,
        )
        if completed.returncode != 0 and not completed.stdout:
            detail = (completed.stderr or "").strip()
            raise RuntimeError(detail or f"Command returned {completed.returncode}")
        return completed.stdout or ""

    def scan(self) -> tuple[list[dict], str]:
        if self.system == "Windows":
            return self._scan_windows()
        if self.system == "Darwin":
            return self._scan_macos()
        if self.system == "Linux":
            return self._scan_linux()
        raise RuntimeError(f"Unsupported operating system: {self.system}")

    def _scan_windows(self):
        output = self._run(["netsh", "wlan", "show", "networks", "mode=bssid"])
        records = []
        current_ssid = ""
        current = None

        for raw in output.splitlines():
            line = raw.strip()
            ssid_match = re.match(r"(?:SSID|Red)\s+\d+\s*:\s*(.*)$", line, re.I)
            if ssid_match:
                current_ssid = ssid_match.group(1).strip()
                current = None
                continue

            bssid_match = re.match(r"(?:BSSID)\s+\d+\s*:\s*([0-9a-f:-]{17})", line, re.I)
            if bssid_match:
                current = {
                    "ssid": current_ssid,
                    "bssid": normalize_bssid(bssid_match.group(1)),
                    "signal_percent": None,
                    "rssi": None,
                    "channel": "",
                    "radio": "",
                    "security": "",
                }
                records.append(current)
                continue

            if current is None:
                continue

            signal_match = re.match(r"(?:Signal|Señal)\s*:\s*(\d+)\s*%", line, re.I)
            if signal_match:
                current["signal_percent"] = int(signal_match.group(1))
                current["rssi"] = signal_percent_to_rssi(current["signal_percent"])
            channel_match = re.match(r"(?:Channel|Canal)\s*:\s*(\d+)", line, re.I)
            if channel_match:
                current["channel"] = channel_match.group(1)
            radio_match = re.match(r"(?:Radio type|Tipo de radio)\s*:\s*(.*)", line, re.I)
            if radio_match:
                current["radio"] = radio_match.group(1).strip()
            auth_match = re.match(r"(?:Authentication|Autenticación)\s*:\s*(.*)", line, re.I)
            if auth_match:
                current["security"] = auth_match.group(1).strip()

        return records, "Windows netsh"

    def _scan_macos(self):
        airport = (
            "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/"
            "Resources/airport"
        )
        if not Path(airport).exists():
            raise RuntimeError("macOS airport scan utility is unavailable on this system.")
        output = self._run([airport, "-s"])
        records = []
        for line in output.splitlines()[1:]:
            match = re.search(
                r"(?P<bssid>(?:[0-9a-f]{2}:){5}[0-9a-f]{2})\s+"
                r"(?P<rssi>-\d+)\s+(?P<channel>\S+)",
                line, re.I
            )
            if not match:
                continue
            prefix = line[:match.start()].strip()
            ssid = prefix
            rssi = int(match.group("rssi"))
            records.append({
                "ssid": ssid,
                "bssid": normalize_bssid(match.group("bssid")),
                "signal_percent": None,
                "rssi": rssi,
                "channel": match.group("channel"),
                "radio": "",
                "security": "",
            })
        return records, "macOS airport"

    def _scan_linux(self):
        if not shutil.which("nmcli"):
            raise RuntimeError("nmcli was not found. Install NetworkManager/nmcli.")
        output = self._run([
            "nmcli", "--terse", "--escape", "yes",
            "--fields", "BSSID,SSID,SIGNAL,CHAN,SECURITY",
            "device", "wifi", "list", "--rescan", "yes"
        ])
        records = []
        for line in output.splitlines():
            fields = []
            buf = ""
            escaped = False
            for char in line:
                if escaped:
                    buf += char
                    escaped = False
                elif char == "\\":
                    escaped = True
                elif char == ":" and len(fields) < 4:
                    fields.append(buf)
                    buf = ""
                else:
                    buf += char
            fields.append(buf)
            if len(fields) < 5:
                continue
            bssid, ssid, signal, channel, security = fields[:5]
            if not valid_bssid(bssid):
                continue
            try:
                quality = int(signal)
            except ValueError:
                quality = None
            records.append({
                "ssid": ssid,
                "bssid": normalize_bssid(bssid),
                "signal_percent": quality,
                "rssi": signal_percent_to_rssi(quality) if quality is not None else None,
                "channel": channel,
                "radio": "",
                "security": security,
            })
        return records, "Linux nmcli"


class WiFiTrackerApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME} v{APP_VERSION}")
        self.root.geometry("1200x780")
        self.root.minsize(900, 640)
        self.root.configure(bg="#171b22")

        self.config = load_config()
        self.events = queue.Queue()
        self.stop_event = threading.Event()
        self.worker = None
        self.scanner = WiFiScanner()
        self.samples = deque(maxlen=30)
        
        self.discovered_ap_cache = {}
        self.last_target_rssi = None
        self.last_scan_time = None
        self.scan_count = 0
        self.db_lock = threading.Lock()
        
        self._init_db()
        self._build_style()
        self._build_ui()
        self._load_settings_into_ui()
        self._refresh_history()
        
        self.root.after(150, self._process_events)
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

        if self.config.get("auto_start"):
            self.root.after(500, self.start_tracking)

    def _init_db(self):
        with sqlite3.connect(DATABASE_FILE) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS measurements (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ssid TEXT,
                    bssid TEXT,
                    rssi REAL,
                    signal_percent INTEGER,
                    estimated_feet REAL,
                    channel TEXT,
                    source TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS radar_sweeps (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    ssid TEXT,
                    bssid TEXT,
                    rssi REAL,
                    channel TEXT,
                    band TEXT,
                    security TEXT,
                    flag TEXT
                )
            """)
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scan_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp TEXT NOT NULL,
                    event_type TEXT NOT NULL,
                    message TEXT NOT NULL
                )
            """)

    def _db_measurement(self, ap, distance_ft, source):
        try:
            with self.db_lock, sqlite3.connect(DATABASE_FILE) as conn:
                conn.execute(
                    """INSERT INTO measurements
                    (timestamp, ssid, bssid, rssi, signal_percent, estimated_feet, channel, source)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                    (
                        datetime.now().isoformat(timespec="seconds"),
                        ap.get("ssid", ""), ap.get("bssid", ""), ap.get("rssi"),
                        ap.get("signal_percent"), distance_ft, ap.get("channel", ""), source
                    )
                )
        except Exception as exc:
            self.events.put(("log", f"Database write error: {exc}"))

    def _db_radar_sweep(self, sweep_records):
        try:
            ts = datetime.now().isoformat(timespec="seconds")
            with self.db_lock, sqlite3.connect(DATABASE_FILE) as conn:
                for r in sweep_records:
                    conn.execute(
                        """INSERT INTO radar_sweeps (timestamp, ssid, bssid, rssi, channel, band, security, flag)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                        (ts, r["ssid"], r["bssid"], r["rssi"], r["channel"], r["band"], r["security"], r["flag"])
                    )
        except Exception:
            pass

    def _db_event(self, event_type, message):
        try:
            with self.db_lock, sqlite3.connect(DATABASE_FILE) as conn:
                conn.execute(
                    "INSERT INTO scan_events(timestamp, event_type, message) VALUES (?, ?, ?)",
                    (datetime.now().isoformat(timespec="seconds"), event_type, message)
                )
        except Exception:
            pass

    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background="#171b22", borderwidth=0)
        style.configure(
            "TNotebook.Tab", background="#293241", foreground="#e8edf2",
            padding=(14, 8), font=("Segoe UI", 9, "bold")
        )
        style.map("TNotebook.Tab", background=[("selected", "#087f8c")])
        style.configure(
            "Treeview", background="#202733", foreground="#e8edf2",
            fieldbackground="#202733", rowheight=26, borderwidth=0
        )
        style.configure(
            "Treeview.Heading", background="#303b4b", foreground="#ffffff",
            font=("Segoe UI", 9, "bold")
        )
        style.configure(
            "Horizontal.TProgressbar", troughcolor="#303b4b",
            background="#00c9a7", bordercolor="#303b4b"
        )

    def _build_ui(self):
        header = tk.Frame(self.root, bg="#11161d", padx=16, pady=12)
        header.pack(fill="x")
        tk.Label(
            header, text="DOMINIONDECK  /  WIFI HUNTER v2.2",
            font=("Segoe UI", 15, "bold"), fg="#ffffff", bg="#11161d"
        ).pack(side="left")
        tk.Label(
            header, text="Predictive Radar & Threat Intelligence",
            font=("Segoe UI", 9), fg="#00c9a7", bg="#11161d"
        ).pack(side="right")

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=12, pady=12)

        self.live_tab = tk.Frame(self.notebook, bg="#171b22")
        self.scanner_tab = tk.Frame(self.notebook, bg="#171b22")
        self.history_tab = tk.Frame(self.notebook, bg="#171b22")
        self.settings_tab = tk.Frame(self.notebook, bg="#171b22")
        
        self.notebook.add(self.live_tab, text="Live Target & Vector")
        self.notebook.add(self.scanner_tab, text="AP Discovery Radar & Threats")
        self.notebook.add(self.history_tab, text="History & Audits")
        self.notebook.add(self.settings_tab, text="Target & Settings")

        self._build_live_tab()
        self._build_scanner_tab()
        self._build_history_tab()
        self._build_settings_tab()

        footer = tk.Frame(self.root, bg="#11161d", padx=12, pady=7)
        footer.pack(fill="x")
        self.footer_status = tk.Label(
            footer, text="Ready • Predictive Vector Engine Active",
            bg="#11161d", fg="#aab7c4", font=("Segoe UI", 9), anchor="w"
        )
        self.footer_status.pack(fill="x")

    def _build_live_tab(self):
        tab = self.live_tab
        target_box = tk.Frame(tab, bg="#202733", padx=14, pady=10)
        target_box.pack(fill="x", padx=10, pady=(10, 7))
        tk.Label(
            target_box, text="CURRENT TARGET", bg="#202733", fg="#00c9a7",
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w")
        self.target_summary = tk.Label(
            target_box, text="", bg="#202733", fg="#ffffff",
            font=("Consolas", 10), justify="left", anchor="w"
        )
        self.target_summary.pack(fill="x", pady=(4, 0))

        metrics = tk.Frame(tab, bg="#171b22")
        metrics.pack(fill="x", padx=10, pady=5)
        self.rssi_value = self._metric(metrics, "RSSI", "-- dBm", 0)
        self.distance_value = self._metric(metrics, "ESTIMATED DISTANCE", "-- ft / -- m", 1)
        self.vector_value = self._metric(metrics, "PREDICTIVE VECTOR", "Waiting...", 2)

        meter_box = tk.Frame(tab, bg="#202733", padx=14, pady=12)
        meter_box.pack(fill="x", padx=10, pady=7)
        tk.Label(
            meter_box, text="SIGNAL STRENGTH", bg="#202733", fg="#dce5ee",
            font=("Segoe UI", 9, "bold")
        ).pack(anchor="w")
        self.signal_bar = ttk.Progressbar(
            meter_box, orient="horizontal", mode="determinate", maximum=100
        )
        self.signal_bar.pack(fill="x", pady=8)
        self.signal_note = tk.Label(
            meter_box,
            text="Predictive vector analyzes RSSI acceleration to determine closing or retreating movement.",
            bg="#202733", fg="#aab7c4", font=("Segoe UI", 8), anchor="w"
        )
        self.signal_note.pack(anchor="w")

        status_box = tk.Frame(tab, bg="#202733", padx=14, pady=12)
        status_box.pack(fill="both", expand=True, padx=10, pady=7)
        self.live_status = tk.Label(
            status_box, text="Scanning paused", bg="#202733", fg="#ffb454",
            font=("Segoe UI", 12, "bold"), anchor="w"
        )
        self.live_status.pack(fill="x")
        self.detail_label = tk.Label(
            status_box, text="Start monitoring to engage predictive targeting.",
            bg="#202733", fg="#dce5ee", font=("Segoe UI", 9),
            justify="left", anchor="nw"
        )
        self.detail_label.pack(fill="both", expand=True, pady=8)

        controls = tk.Frame(tab, bg="#171b22")
        controls.pack(fill="x", padx=10, pady=(2, 10))
        self.start_btn = tk.Button(
            controls, text="▶  Start Monitoring", command=self.start_tracking,
            bg="#087f5b", fg="white", activebackground="#099268",
            relief="flat", padx=16, pady=9, font=("Segoe UI", 9, "bold")
        )
        self.start_btn.pack(side="left", padx=(0, 8))
        self.stop_btn = tk.Button(
            controls, text="■  Stop", command=self.stop_tracking,
            bg="#9b2c2c", fg="white", activebackground="#c53030",
            relief="flat", padx=16, pady=9, font=("Segoe UI", 9, "bold"),
            state="disabled"
        )
        self.stop_btn.pack(side="left")
        tk.Button(
            controls, text="Open Target Settings", command=lambda: self.notebook.select(self.settings_tab),
            bg="#344256", fg="white", relief="flat", padx=12, pady=9
        ).pack(side="right")

    def _metric(self, parent, heading, value, column):
        box = tk.Frame(parent, bg="#202733", padx=12, pady=12)
        box.grid(row=0, column=column, sticky="nsew", padx=4)
        parent.grid_columnconfigure(column, weight=1)
        tk.Label(
            box, text=heading, bg="#202733", fg="#9fb0c0",
            font=("Segoe UI", 8, "bold")
        ).pack(anchor="w")
        label = tk.Label(
            box, text=value, bg="#202733", fg="#ffffff",
            font=("Segoe UI", 15, "bold")
        )
        label.pack(anchor="w", pady=(4, 0))
        return label

    def _build_scanner_tab(self):
        tab = self.scanner_tab
        top = tk.Frame(tab, bg="#171b22")
        top.pack(fill="x", padx=10, pady=10)
        
        self.scan_summary = tk.Label(
            top, text="No scan performed yet. Radar active.", bg="#171b22", fg="#cbd5e0",
            font=("Segoe UI", 9), anchor="w"
        )
        self.scan_summary.pack(side="left", fill="x", expand=True)

        # Filter Options
        tk.Label(top, text="Filter Band:", bg="#171b22", fg="#aab7c4", font=("Segoe UI", 9)).pack(side="left", padx=(10, 4))
        self.band_filter_var = tk.StringVar(value="All")
        band_cb = ttk.Combobox(top, textvariable=self.band_filter_var, values=["All", "2.4 GHz", "5 GHz", "6 GHz"], width=10, state="readonly")
        band_cb.pack(side="left", padx=4)
        band_cb.bind("<<ComboboxSelected>>", lambda e: self._apply_filters())

        tk.Button(
            top, text="Scan Now", command=self.scan_once,
            bg="#087f8c", fg="white", relief="flat", padx=14, pady=6
        ).pack(side="right", padx=(8, 0))

        columns = ("ap", "rssi", "dist", "vector", "band", "chan", "sec", "seen", "threat")
        self.ap_tree = ttk.Treeview(tab, columns=columns, show="headings", height=18)
        
        headings = {
            "ap": "SSID / BSSID",
            "rssi": "RSSI",
            "dist": "Distance",
            "vector": "Predictive Vector",
            "band": "Band",
            "chan": "Channel",
            "sec": "Security",
            "seen": "First / Last Seen",
            "threat": "Threat / Status"
        }
        widths = {
            "ap": 190,
            "rssi": 75,
            "dist": 90,
            "vector": 135,
            "band": 75,
            "chan": 65,
            "sec": 110,
            "seen": 130,
            "threat": 110
        }
        for col in columns:
            self.ap_tree.heading(col, text=headings[col])
            self.ap_tree.column(col, width=widths[col], anchor="center")
        self.ap_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        self.ap_tree.tag_configure("target", background="#174d49")
        self.ap_tree.tag_configure("rogue", background="#6b2d2d")
        self.ap_tree.tag_configure("duplicate", background="#5b4424")
        self.ap_tree.tag_configure("normal", background="#202733")

    def _build_history_tab(self):
        tab = self.history_tab
        top = tk.Frame(tab, bg="#171b22")
        top.pack(fill="x", padx=10, pady=10)
        tk.Label(
            top, text="Stored target measurements & radar audit logs", bg="#171b22",
            fg="#e8edf2", font=("Segoe UI", 10, "bold")
        ).pack(side="left")
        tk.Button(
            top, text="Refresh", command=self._refresh_history,
            bg="#344256", fg="white", relief="flat", padx=12, pady=6
        ).pack(side="right", padx=4)
        tk.Button(
            top, text="Export CSV", command=self.export_csv,
            bg="#087f8c", fg="white", relief="flat", padx=12, pady=6
        ).pack(side="right", padx=4)

        cols = ("time", "ssid", "bssid", "rssi", "signal", "feet", "channel")
        self.history_tree = ttk.Treeview(tab, columns=cols, show="headings", height=18)
        labels = ("Time", "SSID", "BSSID", "RSSI", "Signal", "Est. feet", "Channel")
        widths = (145, 130, 150, 65, 70, 85, 70)
        for col, label, width in zip(cols, labels, widths):
            self.history_tree.heading(col, text=label)
            self.history_tree.column(col, width=width, anchor="center")
        self.history_tree.pack(fill="both", expand=True, padx=10, pady=(0, 10))

    def _build_settings_tab(self):
        tab = self.settings_tab
        outer = tk.Frame(tab, bg="#171b22")
        outer.pack(fill="both", expand=True, padx=12, pady=12)

        target = tk.LabelFrame(
            outer, text=" Target access point ", bg="#202733", fg="#00c9a7",
            font=("Segoe UI", 10, "bold"), padx=12, pady=10
        )
        target.pack(fill="x", pady=(0, 10))
        self.ssid_var = tk.StringVar()
        self.bssid_var = tk.StringVar()
        self._setting_row(target, "Target SSID", self.ssid_var, 0)
        self._setting_row(target, "Target BSSID / MAC", self.bssid_var, 1)
        tk.Button(
            target, text="Save Target", command=self.save_target,
            bg="#087f5b", fg="white", relief="flat", padx=16, pady=8
        ).grid(row=2, column=1, sticky="w", pady=(8, 0))
        tk.Label(
            target, text="BSSID is the specific access-point radio MAC address.",
            bg="#202733", fg="#aab7c4", font=("Segoe UI", 8)
        ).grid(row=3, column=1, sticky="w", pady=(6, 0))

        tuning = tk.LabelFrame(
            outer, text=" Monitoring & calibration ", bg="#202733", fg="#00c9a7",
            font=("Segoe UI", 10, "bold"), padx=12, pady=10
        )
        tuning.pack(fill="x", pady=(0, 10))
        self.interval_var = tk.StringVar()
        self.tx_var = tk.StringVar()
        self.path_var = tk.StringVar()
        self.threshold_var = tk.StringVar()
        self._setting_row(tuning, "Scan interval (seconds)", self.interval_var, 0)
        self._setting_row(tuning, "Reference TX power (dBm)", self.tx_var, 1)
        self._setting_row(tuning, "Path-loss exponent", self.path_var, 2)
        self._setting_row(tuning, "Weak-signal alert threshold (dBm)", self.threshold_var, 3)

        self.sound_var = tk.BooleanVar()
        self.auto_var = tk.BooleanVar()
        tk.Checkbutton(
            tuning, text="Enable sound alerts", variable=self.sound_var,
            bg="#202733", fg="#e8edf2", selectcolor="#303b4b",
            activebackground="#202733", activeforeground="#ffffff"
        ).grid(row=4, column=1, sticky="w", pady=2)
        tk.Checkbutton(
            tuning, text="Start monitoring automatically next launch",
            variable=self.auto_var, bg="#202733", fg="#e8edf2",
            selectcolor="#303b4b", activebackground="#202733",
            activeforeground="#ffffff"
        ).grid(row=5, column=1, sticky="w", pady=2)

        actions = tk.Frame(outer, bg="#171b22")
        actions.pack(fill="x")
        tk.Button(
            actions, text="Save All Settings", command=self.save_all_settings,
            bg="#087f8c", fg="white", relief="flat", padx=16, pady=9
        ).pack(side="left")
        tk.Button(
            actions, text="Restore Defaults", command=self.restore_defaults,
            bg="#344256", fg="white", relief="flat", padx=16, pady=9
        ).pack(side="left", padx=8)

        note = (
            f"Settings file: {CONFIG_FILE}\nHistory database: {DATABASE_FILE}\n"
            "Predictive intelligence engines analyze RSSI acceleration derivatives across sweep samples."
        )
        tk.Label(
            outer, text=note, bg="#171b22", fg="#9fb0c0",
            font=("Segoe UI", 8), justify="left", anchor="w"
        ).pack(fill="x", pady=(12, 0))

    def _setting_row(self, parent, label, variable, row):
        tk.Label(
            parent, text=label, bg=parent.cget("bg"), fg="#e8edf2",
            font=("Segoe UI", 9), width=32, anchor="w"
        ).grid(row=row, column=0, sticky="w", padx=(0, 10), pady=5)
        entry = tk.Entry(
            parent, textvariable=variable, width=34,
            bg="#111820", fg="#ffffff", insertbackground="#ffffff",
            relief="flat", font=("Segoe UI", 9)
        )
        entry.grid(row=row, column=1, sticky="w", pady=5, ipady=5)

    def _load_settings_into_ui(self):
        self.ssid_var.set(self.config.get("target_ssid", ""))
        self.bssid_var.set(self.config.get("target_bssid", ""))
        self.interval_var.set(str(self.config.get("scan_interval", 3)))
        self.tx_var.set(str(self.config.get("tx_power", -40)))
        self.path_var.set(str(self.config.get("path_loss", 2.5)))
        self.threshold_var.set(str(self.config.get("alert_threshold", -75)))
        self.sound_var.set(bool(self.config.get("sound_alerts", False)))
        self.auto_var.set(bool(self.config.get("auto_start", False)))
        self._update_target_summary()

    def _read_numeric_settings(self):
        try:
            interval = int(self.interval_var.get())
            tx = float(self.tx_var.get())
            path = float(self.path_var.get())
            threshold = float(self.threshold_var.get())
        except ValueError:
            raise ValueError("Monitoring settings must contain valid numbers.")
        if not 1 <= interval <= 300:
            raise ValueError("Scan interval must be between 1 and 300 seconds.")
        if not -100 <= tx <= 0:
            raise ValueError("Reference TX power must be between -100 and 0 dBm.")
        if not 1.0 <= path <= 6.0:
            raise ValueError("Path-loss exponent must be between 1.0 and 6.0.")
        if not -100 <= threshold <= 0:
            raise ValueError("Alert threshold must be between -100 and 0 dBm.")
        return interval, tx, path, threshold

    def save_target(self):
        ssid = self.ssid_var.get().strip()
        bssid = normalize_bssid(self.bssid_var.get())
        if not ssid and not bssid:
            messagebox.showerror("Target required", "Enter an SSID, a BSSID, or both.")
            return
        if bssid and not valid_bssid(bssid):
            messagebox.showerror("Invalid BSSID", "Enter a valid MAC/BSSID such as 46:d9:e7:b1:01:64.")
            return
        self.config["target_ssid"] = ssid
        self.config["target_bssid"] = bssid
        self.bssid_var.set(bssid)
        try:
            save_config(self.config)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        self.samples.clear()
        self._update_target_summary()
        self.footer_status.config(text="Target saved.")
        self._db_event("target", f"Target changed: SSID={ssid!r}, BSSID={bssid!r}")
        messagebox.showinfo("Target saved", "The target SSID/BSSID has been updated.")

    def save_all_settings(self):
        try:
            interval, tx, path, threshold = self._read_numeric_settings()
        except ValueError as exc:
            messagebox.showerror("Invalid settings", str(exc))
            return
        ssid = self.ssid_var.get().strip()
        bssid = normalize_bssid(self.bssid_var.get())
        if not ssid and not bssid:
            messagebox.showerror("Target required", "Enter an SSID, a BSSID, or both.")
            return
        if bssid and not valid_bssid(bssid):
            messagebox.showerror("Invalid BSSID", "Enter a valid BSSID.")
            return

        self.config.update({
            "target_ssid": ssid, "target_bssid": bssid,
            "scan_interval": interval, "tx_power": tx, "path_loss": path,
            "alert_threshold": threshold, "sound_alerts": self.sound_var.get(),
            "auto_start": self.auto_var.get()
        })
        try:
            save_config(self.config)
        except Exception as exc:
            messagebox.showerror("Save failed", str(exc))
            return
        self.bssid_var.set(bssid)
        self._update_target_summary()
        self.footer_status.config(text="All settings saved.")
        messagebox.showinfo("Settings saved", "Your target and monitoring settings were saved.")

    def restore_defaults(self):
        if not messagebox.askyesno("Restore defaults", "Restore all settings to defaults?"):
            return
        self.config = DEFAULTS.copy()
        self._load_settings_into_ui()
        save_config(self.config)
        self.footer_status.config(text="Default settings restored.")

    def _update_target_summary(self):
        ssid = self.config.get("target_ssid") or "(not set)"
        bssid = self.config.get("target_bssid") or "(not set)"
        if hasattr(self, "target_summary"):
            self.target_summary.config(text=f"SSID:  {ssid}\nBSSID: {bssid}")

    def _target_matches(self, ap):
        target_bssid = normalize_bssid(self.config.get("target_bssid", ""))
        target_ssid = (self.config.get("target_ssid") or "").strip().casefold()
        ap_bssid = normalize_bssid(ap.get("bssid", ""))
        ap_ssid = (ap.get("ssid") or "").strip().casefold()
        if target_bssid:
            return ap_bssid == target_bssid
        return bool(target_ssid and ap_ssid == target_ssid)

    def _find_target(self, aps):
        matches = [ap for ap in aps if self._target_matches(ap)]
        if matches:
            return max(matches, key=lambda x: x.get("rssi") if x.get("rssi") is not None else -999)
        return None

    def start_tracking(self):
        if self.worker and self.worker.is_alive():
            return
        if not self.config.get("target_ssid") and not self.config.get("target_bssid"):
            messagebox.showwarning("Target not configured", "Set a target SSID or BSSID first.")
            self.notebook.select(self.settings_tab)
            return
        self.stop_event.clear()
        self.worker = threading.Thread(target=self._scan_loop, daemon=True)
        self.worker.start()
        self.start_btn.config(state="disabled")
        self.stop_btn.config(state="normal")
        self.live_status.config(text="Starting predictive radar…", fg="#00c9a7")
        self.footer_status.config(text="Predictive monitoring active.")

    def stop_tracking(self):
        self.stop_event.set()
        self.start_btn.config(state="normal")
        self.stop_btn.config(state="disabled")
        self.live_status.config(text="Scanning paused", fg="#ffb454")
        self.footer_status.config(text="Monitoring stopped.")

    def _scan_loop(self):
        while not self.stop_event.is_set():
            started = time.time()
            try:
                aps, source = self.scanner.scan()
                target = self._find_target(aps)
                self.events.put(("scan", aps, target, source))
            except Exception as exc:
                self.events.put(("error", str(exc)))

            elapsed = time.time() - started
            interval = float(self.config.get("scan_interval", 3))
            sleep_time = max(0.5, interval - elapsed)
            time.sleep(sleep_time)

    def scan_once(self):
        try:
            aps, source = self.scanner.scan()
            target = self._find_target(aps)
            self._handle_scan_result(aps, target, source)
            messagebox.showinfo("Scan Complete", f"Radar analyzed {len(aps)} access point(s) via {source}.")
        except Exception as exc:
            messagebox.showerror("Scan Failed", str(exc))

    def _process_events(self):
        try:
            while True:
                item = self.events.get_nowait()
                msg_type = item[0]
                if msg_type == "scan":
                    _, aps, target, source = item
                    self._handle_scan_result(aps, target, source)
                elif msg_type == "error":
                    _, err_msg = item
                    self.live_status.config(text="Scan Error", fg="#ff6b6b")
                    self.detail_label.config(text=err_msg)
                elif msg_type == "log":
                    _, log_msg = item
                    self.footer_status.config(text=log_msg)
        except queue.Empty:
            pass
        finally:
            self.root.after(150, self._process_events)

    def _apply_filters(self):
        if hasattr(self, "last_aps_raw") and hasattr(self, "last_source_raw"):
            self._handle_scan_result(self.last_aps_raw, self._find_target(self.last_aps_raw), self.last_source_raw, is_filter_refresh=True)

    def _handle_scan_result(self, aps, target, source, is_filter_refresh=False):
        if not is_filter_refresh:
            self.last_aps_raw = aps
            self.last_source_raw = source
            self.scan_count += 1
            self.last_scan_time = datetime.now()

        now_str = self.last_scan_time.strftime("%H:%M:%S") if self.last_scan_time else datetime.now().strftime("%H:%M:%S")

        for row in self.ap_tree.get_children():
            self.ap_tree.delete(row)

        target_bssid = normalize_bssid(self.config.get("target_bssid", ""))
        target_ssid = (self.config.get("target_ssid") or "").strip().casefold()

        ssid_counts = {}
        for ap in aps:
            s = (ap.get("ssid") or "").strip()
            if s:
                ssid_counts[s] = ssid_counts.get(s, 0) + 1

        selected_band_filter = self.band_filter_var.get() if hasattr(self, "band_filter_var") else "All"
        sweep_db_records = []

        for ap in aps:
            ssid = ap.get("ssid", "")
            bssid = ap.get("bssid", "")
            rssi = ap.get("rssi")
            signal_pct = ap.get("signal_percent")
            channel = ap.get("channel", "")
            security = ap.get("security", "")
            radio = ap.get("radio", "")

            band_str = get_frequency_band(channel, radio)
            if selected_band_filter != "All" and band_str != selected_band_filter:
                continue

            if bssid not in self.discovered_ap_cache:
                self.discovered_ap_cache[bssid] = {
                    "ssid": ssid,
                    "first_seen": now_str,
                    "last_seen": now_str,
                    "rssi_history": deque(maxlen=10),
                    "channel": channel,
                    "security": security,
                    "radio": radio
                }
            
            entry = self.discovered_ap_cache[bssid]
            entry["last_seen"] = now_str
            if ssid and not entry["ssid"]:
                entry["ssid"] = ssid
            if channel:
                entry["channel"] = channel
            if security:
                entry["security"] = security

            if rssi is not None:
                entry["rssi_history"].append(rssi)

            vector_str = calculate_velocity_vector(entry["rssi_history"])

            tx_power = float(self.config.get("tx_power", -40))
            path_loss = float(self.config.get("path_loss", 2.5))
            dist_ft, dist_m = estimate_distances(rssi, tx_power, path_loss)
            dist_str = f"{dist_ft} ft / {dist_m} m" if dist_ft is not None else "-- ft / -- m"

            rssi_str = f"{rssi} dBm" if rssi is not None else "--"
            if signal_pct is not None:
                rssi_str += f" ({signal_pct}%)"

            is_target = False
            if target_bssid:
                is_target = (normalize_bssid(bssid) == target_bssid)
            elif target_ssid:
                is_target = (ssid.strip().casefold() == target_ssid)

            sec_lower = security.lower()
            is_open = ("open" in sec_lower or not security or security == "--")
            is_duplicate = (ssid and ssid_counts.get(ssid, 0) > 1)

            if is_target:
                threat_label = "Target Verified"
                tag = "target"
            elif is_duplicate and is_open:
                threat_label = "⚠️ Rogue / Evil Twin?"
                tag = "rogue"
            elif is_duplicate:
                threat_label = "Duplicate SSID"
                tag = "duplicate"
            elif is_open:
                threat_label = "Open / Unsecured"
                tag = "duplicate"
            else:
                threat_label = "Secure / Normal"
                tag = "normal"

            seen_str = f"{entry['first_seen']} / {entry['last_seen']}"
            ap_display = f"{ssid or '(Hidden)'} [{bssid}]"

            sweep_db_records.append({
                "ssid": ssid, "bssid": bssid, "rssi": rssi,
                "channel": channel, "band": band_str, "security": security, "flag": threat_label
            })

            self.ap_tree.insert(
                "", "end",
                values=(
                    ap_display, rssi_str, dist_str, vector_str,
                    band_str, channel or "--", security or "Open", seen_str, threat_label
                ),
                tags=(tag,)
            )

        if not is_filter_refresh:
            self._db_radar_sweep(sweep_db_records)

        warning_suffix = ""
        if len(aps) == 0:
            warning_suffix = " ⚠️ [Zero APs detected: Check Wi-Fi state or OS locale]"

        self.scan_summary.config(
            text=f"Last sweep: {now_str} • Detected {len(aps)} AP(s) via {source} (Band: {selected_band_filter}){warning_suffix}"
        )

        if target:
            rssi = target.get("rssi")
            signal_pct = target.get("signal_percent") or 0
            tx_power = float(self.config.get("tx_power", -40))
            path_loss = float(self.config.get("path_loss", 2.5))

            dist_ft, dist_m = estimate_distances(rssi, tx_power, path_loss) if rssi is not None else (None, None)

            if rssi is not None:
                self.samples.append(rssi)
                smoothed_rssi = sum(self.samples) / len(self.samples)
            else:
                smoothed_rssi = None

            target_bssid_str = normalize_bssid(target.get("bssid", ""))
            target_entry = self.discovered_ap_cache.get(target_bssid_str)
            target_vector = calculate_velocity_vector(target_entry["rssi_history"]) if target_entry else "Analyzing..."

            self.rssi_value.config(text=f"{rssi} dBm" if rssi is not None else "-- dBm")
            self.distance_value.config(text=f"{dist_ft} ft / {dist_m} m" if dist_ft is not None else "-- ft / -- m")
            self.vector_value.config(text=target_vector)
            self.signal_bar["value"] = max(0, min(100, signal_pct))

            self.live_status.config(text="Target Locked & Tracked", fg="#00c9a7")
            band = get_frequency_band(target.get("channel"), target.get("radio"))
            detail_txt = (
                f"SSID: {target.get('ssid')}\nBSSID: {target.get('bssid')}\n"
                f"Channel: {target.get('channel')} ({band}) | Security: {target.get('security')}\n"
            )
            if smoothed_rssi is not None:
                detail_txt += f"Smoothed RSSI: {smoothed_rssi:.1f} dBm | Movement Vector: {target_vector}"
            else:
                detail_txt += "Smoothed RSSI: --"
            self.detail_label.config(text=detail_txt)

            self._db_measurement(target, dist_ft, source)
        else:
            self.live_status.config(text="Target Not Visible", fg="#ffb454")
            self.detail_label.config(text="Radar sweep active, but configured target BSSID/SSID is out of range. (Check if laptop Wi-Fi is enabled)")

        if not is_filter_refresh:
            self._refresh_history()

    def _refresh_history(self):
        for row in self.history_tree.get_children():
            self.history_tree.delete(row)
        try:
            with self.db_lock, sqlite3.connect(DATABASE_FILE) as conn:
                cursor = conn.execute(
                    "SELECT timestamp, ssid, bssid, rssi, signal_percent, estimated_feet, channel "
                    "FROM measurements ORDER BY id DESC LIMIT 300"
                )
                for row in cursor.fetchall():
                    ts, ssid, bssid, rssi, sig, feet, chan = row
                    self.history_tree.insert(
                        "", "end",
                        values=(
                            ts, ssid, bssid,
                            f"{rssi} dBm" if rssi is not None else "--",
                            f"{sig} %" if sig is not None else "--",
                            f"{feet:.1f}" if feet is not None else "--",
                            chan
                        )
                    )
        except Exception:
            pass

    def export_csv(self):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("CSV Files", "*.csv"), ("All Files", "*.*")],
            title="Export Measurement History & Radar Sweeps"
        )
        if not file_path:
            return
        try:
            with self.db_lock, sqlite3.connect(DATABASE_FILE) as conn:
                cursor = conn.execute(
                    "SELECT timestamp, ssid, bssid, rssi, signal_percent, estimated_feet, channel, source "
                    "FROM measurements ORDER BY id ASC"
                )
                rows = cursor.fetchall()
            with open(file_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.writer(f)
                writer.writerow(["Timestamp", "SSID", "BSSID", "RSSI", "SignalPercent", "EstimatedFeet", "Channel", "Source"])
                writer.writerows(rows)
            messagebox.showinfo("Export Successful", f"Exported {len(rows)} target history records to {file_path}")
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    def on_close(self):
        self.stop_event.set()
        if self.worker and self.worker.is_alive():
            self.worker.join(timeout=1.0)
        self.root.destroy()


def main():
    root = tk.Tk()
    app = WiFiTrackerApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()