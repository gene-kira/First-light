#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DominionDeck Borg-Style Companion
Full regeneration with:
- Bootloader restore-then-upgrade flow
- Dual-write cache (RAM + disk)
- Auto-expanding cache (1–5 GB, 90% threshold)
- Cache drive selection + usage indicator
- Folder-per-peer / per-drive chunked cache
- Predictive peer ordering + health checks
- GUI status panel
- Persistent cache drive selection across reboot
"""

import os
import threading
import socket
import time
import json
import queue
import tkinter as tk
from tkinter import ttk, messagebox

from datetime import datetime, timedelta

###############################################################################
# CONFIG
###############################################################################

APP_ID = "DominionDeck-Borg-Companion"
APP_VERSION = "2.1.0"

BEACON_PORT = 49231
BEACON_INTERVAL_SEC = 5
DISCOVERY_TIMEOUT_SEC = 3
MAX_TRIES_PER_TARGET = 2
DAILY_RESCAN_INTERVAL = timedelta(days=1)
MAX_GOOD_PEERS_MEMORY = 32

CACHE_CHUNK_SIZE = 4096  # bytes per chunk file
CACHE_MIN_GB = 1
CACHE_MAX_GB = 5
CACHE_EXPAND_THRESHOLD = 0.90  # 90%

DEFAULT_CACHE_ROOT = os.path.join(os.path.expanduser("~"), "DominionDeckCache")

BOOT_CONFIG_PATH = os.path.join(os.path.expanduser("~"), "dominion_boot_config.json")
BOOT_CONFIG_BACKUP_PATH = os.path.join(os.path.expanduser("~"), "dominion_boot_config.backup.json")

###############################################################################
# STATE
###############################################################################

class PeerInfo:
    def __init__(self, addr, last_seen=None, is_main=False):
        self.addr = addr
        self.last_seen = last_seen or datetime.utcnow()
        self.is_main = is_main
        self.last_health_ok = None
        self.last_health_fail = None
        self.health_attempts = 0

    def mark_ok(self):
        self.last_health_ok = datetime.utcnow()
        self.health_attempts = 0

    def mark_fail(self):
        self.last_health_fail = datetime.utcnow()
        self.health_attempts += 1

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

        # Drives
        self.main_drives = self._detect_main_drives()

        # Bootloader state (also used to persist cache root)
        self.boot_config = self._load_boot_config()

        # Cache system
        self.cache_limit_gb = CACHE_MIN_GB  # starts at 1 GB
        self.cache_ram = []

        # Cache root: default C-drive-based path, but override from boot_config if present
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
        # default boot config
        return {
            "boot_mode": "normal",
            "last_good_boot": None,
            "upgraded": False,
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
        """
        Safe bootloader upgrade:
        1. Backup current config
        2. Restore to known-good baseline if needed
        3. Apply upgrade flags
        """
        self.backup_boot_config()

        # If last_good_boot is missing, treat current as baseline
        if not self.boot_config.get("last_good_boot"):
            self.boot_config["last_good_boot"] = datetime.utcnow().isoformat()
            self._save_boot_config()

        # Simulate restoring bootloader to known-good state
        self.boot_config["boot_mode"] = "normal"
        self.boot_config["upgraded"] = False
        self._save_boot_config()
        self.push_gui_event("boot_restore_phase", None)

        # Now apply upgrade flags
        self.boot_config["boot_mode"] = "upgraded"
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

    def mark_peer_ok(self, addr):
        with self.lock:
            if addr in self.peers:
                self.peers[addr].mark_ok()
                self._update_good_peers(addr)

    def mark_peer_fail(self, addr):
        with self.lock:
            if addr in self.peers:
                self.peers[addr].mark_fail()

    def get_peers_sorted_predictive(self):
        with self.lock:
            good = [self.peers[a] for a in self.good_peers_order if a in self.peers]
            others = [p for a, p in self.peers.items() if a not in self.good_peers_order]
            good.sort(key=lambda p: p.last_seen, reverse=True)
            others.sort(key=lambda p: p.last_seen, reverse=True)
            return good + others

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
            # persist in boot_config so it survives reboot
            self.boot_config["cache_root"] = root_path
            self._save_boot_config()
        self.push_gui_event("cache_drive_changed", None)

    def add_cache_entry(self, entry: CacheEntry):
        with self.lock:
            self.cache_ram.append(entry)
        self._write_cache_to_disk(entry)
        self._check_cache_expand()
        self.push_gui_event("cache_update", None)

    def _peer_folder(self, ip):
        safe_ip = ip.replace(":", "_")
        return os.path.join(self.cache_drive_root, safe_ip)

    def _drive_folder(self, drive_label):
        safe_label = drive_label.replace(":", "").replace("\\", "_").replace("/", "_")
        return os.path.join(self.cache_drive_root, f"drive_{safe_label}")

    def _ensure_folder(self, path):
        os.makedirs(path, exist_ok=True)

    def _write_cache_to_disk(self, entry: CacheEntry):
        try:
            if entry.source_type == "peer":
                folder = self._peer_folder(entry.source_ip)
            else:
                folder = self._drive_folder(entry.source_ip)
            self._ensure_folder(folder)

            ts = entry.timestamp.strftime("%Y%m%d_%H%M%S_%f")
            filename = os.path.join(folder, f"chunk_{ts}.bin")
            with open(filename, "wb") as f:
                f.write(entry.data[:CACHE_CHUNK_SIZE])
        except Exception:
            pass

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
                    result.append({
                        "path": fpath,
                        "size": size,
                    })
        return result


STATE = BorgState()

###############################################################################
# NETWORK / BEACON ENGINE
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
                "timestamp": datetime.utcnow().isoformat(),
            }
            sock.sendto(json.dumps(payload).encode("utf-8"), ("255.255.255.255", BEACON_PORT))
        except Exception:
            pass
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
            if msg.get("type") == "beacon" and msg.get("app_id") == APP_ID:
                STATE.update_peer(ip, is_main=msg.get("is_main", False))
                STATE.push_gui_event("peer_update", None)

                reply = {
                    "type": "reply",
                    "app_id": APP_ID,
                    "version": APP_VERSION,
                    "host": STATE.this_host,
                    "ip": STATE.this_ip,
                    "is_main": STATE.is_main,
                    "timestamp": datetime.utcnow().isoformat(),
                }
                sock.sendto(json.dumps(reply).encode("utf-8"), addr)
            elif msg.get("type") == "reply" and msg.get("app_id") == APP_ID:
                STATE.update_peer(ip, is_main=msg.get("is_main", False))
                STATE.push_gui_event("peer_update", None)
        except Exception:
            time.sleep(0.1)


def health_check_peer(peer: PeerInfo):
    if peer.health_attempts >= MAX_TRIES_PER_TARGET:
        return
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(DISCOVERY_TIMEOUT_SEC)
        s.connect((peer.addr, 80))
        s.close()
        STATE.mark_peer_ok(peer.addr)
        STATE.push_gui_event("peer_health", {"addr": peer.addr, "status": "ok"})
        data = f"Health OK from {peer.addr} at {datetime.utcnow()}".encode("utf-8")
        STATE.add_cache_entry(CacheEntry(peer.addr, "peer", data))
    except Exception:
        STATE.mark_peer_fail(peer.addr)
        STATE.push_gui_event("peer_health", {"addr": peer.addr, "status": "fail"})


def periodic_health_manager():
    while True:
        try:
            peers = STATE.get_peers_sorted_predictive()
            if STATE.should_rescan():
                STATE.mark_rescan_done()
                for p in peers:
                    health_check_peer(p)
            else:
                for p in peers:
                    if p.last_health_fail and (datetime.utcnow() - p.last_health_fail) > timedelta(minutes=10):
                        health_check_peer(p)
        except Exception:
            pass
        time.sleep(10)

###############################################################################
# MAIN DRIVE CACHE SIMULATION
###############################################################################

def periodic_main_drive_cache():
    while True:
        try:
            for drive in STATE.main_drives:
                data = f"Cache sample from main drive {drive} at {datetime.utcnow()}".encode("utf-8")
                STATE.add_cache_entry(CacheEntry(drive, "drive", data))
        except Exception:
            pass
        time.sleep(60)

###############################################################################
# GUI
###############################################################################

class BorgGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("DominionDeck Borg Companion")
        self.geometry("1200x650")
        self.minsize(900, 500)
        self.resizable(True, True)

        self.style = ttk.Style(self)
        self.style.theme_use("clam")

        self._build_layout()
        self.after(200, self._poll_gui_queue)
        self.after(1000, self._refresh_cache_usage)

    def _build_layout(self):
        self.columnconfigure(0, weight=1)
        self.rowconfigure(1, weight=3)
        self.rowconfigure(2, weight=2)

        # Main system info
        frame_main = ttk.LabelFrame(self, text="Main System")
        frame_main.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        for c in range(5):
            frame_main.columnconfigure(c, weight=1)

        self.lbl_host = ttk.Label(frame_main, text=f"Host: {STATE.this_host}")
        self.lbl_host.grid(row=0, column=0, sticky="w", padx=4, pady=2)

        self.lbl_ip = ttk.Label(frame_main, text=f"IP: {STATE.this_ip}")
        self.lbl_ip.grid(row=0, column=1, sticky="w", padx=4, pady=2)

        self.lbl_role = ttk.Label(frame_main, text="Role: MAIN (not scanned as target)")
        self.lbl_role.grid(row=0, column=2, sticky="w", padx=4, pady=2)

        # Bootloader status
        self.lbl_boot = ttk.Label(
            frame_main,
            text=f"Boot Mode: {STATE.boot_config.get('boot_mode', 'unknown')} | Upgraded: {STATE.boot_config.get('upgraded', False)}"
        )
        self.lbl_boot.grid(row=0, column=3, sticky="w", padx=4, pady=2)

        # Cache drive selector (GUI button + dropdown + entry)
        ttk.Label(frame_main, text="Cache Drive Root:").grid(row=1, column=0, sticky="w", padx=4, pady=2)

        # Entry showing full path
        self.cache_drive_var = tk.StringVar(value=STATE.cache_drive_root)
        self.cache_drive_entry = ttk.Entry(frame_main, textvariable=self.cache_drive_var, width=40)
        self.cache_drive_entry.grid(row=1, column=1, sticky="w", padx=4, pady=2)

        # Combobox listing drives (C:, D:, etc.)
        ttk.Label(frame_main, text="Select Drive:").grid(row=1, column=2, sticky="w", padx=4, pady=2)
        self.drive_choice_var = tk.StringVar()
        self.drive_choice_combo = ttk.Combobox(
            frame_main,
            textvariable=self.drive_choice_var,
            values=STATE.main_drives,
            width=10,
            state="readonly"
        )
        # default to C: if present, else first drive
        default_drive = None
        for d in STATE.main_drives:
            if d.upper().startswith("C:"):
                default_drive = d
                break
        if default_drive is None and STATE.main_drives:
            default_drive = STATE.main_drives[0]
        if default_drive:
            self.drive_choice_var.set(default_drive)
        self.drive_choice_combo.grid(row=1, column=3, sticky="w", padx=4, pady=2)

        # Button: CHANGE CACHE DRIVE (this is what you asked for)
        self.btn_change_cache_drive = ttk.Button(
            frame_main,
            text="Change Cache Drive",
            command=self._change_cache_drive_to_selected
        )
        self.btn_change_cache_drive.grid(row=1, column=4, sticky="w", padx=4, pady=2)

        # Cache usage indicator
        self.lbl_cache_usage = ttk.Label(frame_main, text="Cache Usage: calculating...")
        self.lbl_cache_usage.grid(row=2, column=0, columnspan=2, sticky="w", padx=4, pady=2)

        # Bootloader control
        self.btn_boot_fix = ttk.Button(
            frame_main,
            text="Restore Bootloader + Apply Upgrade",
            command=self._fix_bootloader_and_upgrade
        )
        self.btn_boot_fix.grid(row=2, column=2, sticky="w", padx=4, pady=4)

        # Peer list
        frame_peers = ttk.LabelFrame(self, text="Companion Systems (Collective)")
        frame_peers.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        frame_peers.columnconfigure(0, weight=1)
        frame_peers.rowconfigure(0, weight=1)

        columns = ("ip", "last_seen", "health", "role")
        self.tree_peers = ttk.Treeview(frame_peers, columns=columns, show="headings")
        for col, text in zip(columns, ["IP", "Last Seen", "Health", "Role"]):
            self.tree_peers.heading(col, text=text)

        self.tree_peers.column("ip", width=160, anchor="w")
        self.tree_peers.column("last_seen", width=200, anchor="w")
        self.tree_peers.column("health", width=120, anchor="w")
        self.tree_peers.column("role", width=120, anchor="w")

        scroll_peers_y = ttk.Scrollbar(frame_peers, orient="vertical", command=self.tree_peers.yview)
        self.tree_peers.configure(yscrollcommand=scroll_peers_y.set)

        self.tree_peers.grid(row=0, column=0, sticky="nsew", padx=(4, 0), pady=4)
        scroll_peers_y.grid(row=0, column=1, sticky="ns", padx=(0, 4), pady=4)

        # Cache panels
        frame_cache = ttk.LabelFrame(self, text="Cache Overview (RAM + Disk)")
        frame_cache.grid(row=2, column=0, sticky="nsew", padx=8, pady=8)
        frame_cache.columnconfigure(0, weight=1)
        frame_cache.columnconfigure(1, weight=1)
        frame_cache.rowconfigure(1, weight=1)

        ttk.Label(frame_cache, text="RAM Cache (live):").grid(row=0, column=0, sticky="w", padx=4, pady=2)
        ttk.Label(frame_cache, text="Disk Cache (chunks):").grid(row=0, column=1, sticky="w", padx=4, pady=2)

        self.tree_ram = ttk.Treeview(frame_cache, columns=("source", "type", "time", "size"), show="headings")
        for col, text in zip(("source", "type", "time", "size"), ["Source", "Type", "Timestamp", "Size (bytes)"]):
            self.tree_ram.heading(col, text=text)
        self.tree_ram.column("source", width=140, anchor="w")
        self.tree_ram.column("type", width=80, anchor="w")
        self.tree_ram.column("time", width=200, anchor="w")
        self.tree_ram.column("size", width=100, anchor="e")

        self.tree_disk = ttk.Treeview(frame_cache, columns=("path", "size"), show="headings")
        self.tree_disk.heading("path", text="Path")
        self.tree_disk.heading("size", text="Size (bytes)")
        self.tree_disk.column("path", width=300, anchor="w")
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
        """
        Button handler: "Change Cache Drive"
        - Takes selected drive (C:, D:, etc.)
        - Builds a cache root path on that drive
        - Updates STATE and persists to boot_config
        """
        drive = self.drive_choice_var.get().strip()
        if not drive:
            messagebox.showerror("Cache Drive", "Please select a drive.")
            return

        # Normalize drive root (e.g., 'C:\\' -> 'C:\\DominionDeckCache')
        if os.name == "nt":
            # ensure trailing backslash
            if not drive.endswith("\\"):
                drive = drive + "\\"
            new_root = os.path.join(drive, "DominionDeckCache")
        else:
            # on non-Windows, treat drive as mount point
            new_root = os.path.join(drive, "DominionDeckCache")

        try:
            os.makedirs(new_root, exist_ok=True)
        except Exception as e:
            messagebox.showerror("Cache Drive", f"Unable to create cache folder on {drive}:\n{e}")
            return

        STATE.set_cache_drive_root(new_root)
        self.cache_drive_var.set(new_root)
        self._refresh_cache_usage()
        messagebox.showinfo("Cache Drive", f"Cache drive changed to: {new_root}\nThis will be remembered after reboot.")

    def _fix_bootloader_and_upgrade(self):
        STATE.restore_boot_config_from_backup()
        STATE.apply_boot_upgrade_safely()
        self.lbl_boot.config(
            text=f"Boot Mode: {STATE.boot_config.get('boot_mode', 'unknown')} | Upgraded: {STATE.boot_config.get('upgraded', False)}"
        )
        messagebox.showinfo("Bootloader", "Bootloader restored to known-good state and upgrade applied.")

    def _refresh_cache_usage(self):
        usage_bytes = STATE._cache_usage_bytes()
        limit_bytes = STATE.cache_limit_gb * (1024 ** 3)
        usage_ratio = usage_bytes / limit_bytes if limit_bytes > 0 else 0.0
        percent = usage_ratio * 100.0

        if percent < 60:
            color = "green"
        elif percent < 90:
            color = "orange"
            # still fine, just getting fuller
        else:
            color = "red"

        text = f"Cache: {usage_bytes/1024/1024:.2f} MB / {STATE.cache_limit_gb} GB ({percent:.1f}%)"
        self.lbl_cache_usage.config(text=text, foreground=color)

        self.after(1000, self._refresh_cache_usage)

    def _poll_gui_queue(self):
        try:
            while True:
                event_type, payload = STATE.gui_queue.get_nowait()
                if event_type in ("peer_update", "peer_health"):
                    self._refresh_peers()
                elif event_type in ("cache_update", "cache_expanded", "cache_drive_changed"):
                    self._refresh_cache_lists()
                elif event_type in ("boot_restored", "boot_upgrade_applied", "boot_restore_phase"):
                    self.lbl_boot.config(
                        text=f"Boot Mode: {STATE.boot_config.get('boot_mode', 'unknown')} | Upgraded: {STATE.boot_config.get('upgraded', False)}"
                    )
        except queue.Empty:
            pass
        self.after(200, self._poll_gui_queue)

    def _refresh_peers(self):
        for item in self.tree_peers.get_children():
            self.tree_peers.delete(item)
        peers = STATE.get_peers_sorted_predictive()
        for p in peers:
            health = "OK" if p.is_healthy else "Unknown" if p.last_health_ok is None else "Fail"
            role = "MAIN" if p.is_main else "PEER"
            last_seen = p.last_seen.isoformat()
            self.tree_peers.insert("", "end", values=(p.addr, last_seen, health, role))

    def _refresh_cache_lists(self):
        for item in self.tree_ram.get_children():
            self.tree_ram.delete(item)
        for item in self.tree_disk.get_children():
            self.tree_disk.delete(item)

        ram_summary = STATE.list_cache_summary()
        for e in ram_summary:
            self.tree_ram.insert(
                "",
                "end",
                values=(
                    e["source_ip"],
                    e["source_type"],
                    e["timestamp"].isoformat(),
                    e["size"],
                ),
            )

        disk_summary = STATE.list_disk_cache_summary()
        for e in disk_summary:
            self.tree_disk.insert(
                "",
                "end",
                values=(
                    e["path"],
                    e["size"],
                ),
            )

###############################################################################
# MAIN
###############################################################################

def main():
    # mark current boot as good (simulated)
    STATE.mark_boot_good()

    t_beacon_send = threading.Thread(target=beacon_sender, daemon=True)
    t_beacon_listen = threading.Thread(target=beacon_listener, daemon=True)
    t_health = threading.Thread(target=periodic_health_manager, daemon=True)
    t_drive_cache = threading.Thread(target=periodic_main_drive_cache, daemon=True)

    t_beacon_send.start()
    t_beacon_listen.start()
    t_health.start()
    t_drive_cache.start()

    gui = BorgGUI()
    gui.mainloop()


if __name__ == "__main__":
    main()
