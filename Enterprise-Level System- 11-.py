#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DominionDeck Windows ISO Orchestrator
Option C — Enterprise-Level System (Network & IT Next-Level Edition)
+ Network Deployment Server + USB Boot Client + DISM Servicing
+ Real PXE boot infrastructure (DHCP/TFTP hooks, boot menu metadata)
+ Full HTTPS file distribution (ISO/WIM/driver payloads)
+ GPU governor runtime integration
+ Security Governor enforcement
+ Swarm Sync propagation
+ VRAM scanning engine
+ Driver dependency resolution

Focus:
- Treat current machine as “master”
- Snapshot: system, network, installed apps, drivers, Wi-Fi
- Build custom Windows ISO that:
  - Autoloads those settings
  - Records installed-app inventory for later installer deployment (not installers themselves)
  - Uses ONLY selected Windows components (no extras)
- Deep network/IT flexibility:
  - Site profiles (HQ/Branch/Lab/DMZ)
  - IP/DNS/Gateway/VLAN presets
  - Proxy templates
  - Wi-Fi profiles export/import
  - Post-install scripts (PowerShell) per profile
  - DISM-based feature enable/disable, driver/package injection
- Network deployment:
  - Master machine runs deployment server (TCP + HTTPS + PXE metadata)
  - USB companion client boots, connects, pulls profile/ISO
  - PXE infra hooks (DHCP/TFTP metadata, boot menu)
- GUI:
  - Control Center
  - USB creator button
  - Panel showing machines waiting / connected / installing
- Plugins:
  - GPU Governor injection + runtime integration
  - Security Governor enforcement
  - Swarm Sync propagation
  - VRAM scanning integration
- CLI + GUI, dry-run, advanced logging
- Auto-admin elevation on startup
"""

import os
import sys
import json
import subprocess
import threading
import time
import shutil
import traceback
import socket
import ssl
import hashlib
import ipaddress
import re
import xml.etree.ElementTree as ET
from http.server import HTTPServer, SimpleHTTPRequestHandler
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# -----------------------------
# AUTOLOADER FOR PYTHON LIBS
# -----------------------------

REQUIRED_LIBS = ["PyQt6"]


def ensure_dependencies():
    """Check GUI dependencies without silently installing packages at startup."""
    import importlib.util
    missing = [name for name in REQUIRED_LIBS if importlib.util.find_spec(name) is None]
    if missing:
        message = (
            "Missing required Python package(s): " + ", ".join(missing) +
            "\\nInstall them in the intended Python environment with:\\n" +
            f'"{sys.executable}" -m pip install ' + " ".join(missing)
        )
        print("[DEPENDENCY] " + message)
        raise SystemExit(2)


ensure_dependencies()
from PyQt6 import QtWidgets, QtCore, QtGui

# -----------------------------
# AUTO-ADMIN ELEVATION
# -----------------------------

def is_admin() -> bool:
    if os.name == "nt":
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False
    return True

def relaunch_as_admin_if_needed():
    """Request elevation on Windows and only exit if ShellExecute accepted it."""
    if os.name != "nt" or is_admin():
        return
    try:
        import ctypes
        params = subprocess.list2cmdline(sys.argv)
        result = ctypes.windll.shell32.ShellExecuteW(
            None, "runas", sys.executable, params, None, 1
        )
        if result > 32:
            raise SystemExit(0)
        log_msg = f"ShellExecuteW returned {result}; continuing without elevation."
        print(f"[ADMIN] {log_msg}")
    except SystemExit:
        raise
    except Exception as exc:
        print(f"[ADMIN] Elevation request failed; continuing without elevation: {exc}")


relaunch_as_admin_if_needed()

# -----------------------------
# GLOBAL CONSTANTS / PATHS
# -----------------------------

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
CONFIG_DIR = os.path.join(BASE_DIR, "dd_config")
PROFILE_DIR = os.path.join(CONFIG_DIR, "profiles")
ISO_WORK_DIR = os.path.join(BASE_DIR, "iso_work")
LOG_FILE = os.path.join(CONFIG_DIR, "dd_log.txt")
NETWORK_PRESETS_FILE = os.path.join(CONFIG_DIR, "network_presets.json")
POST_SCRIPTS_DIR = os.path.join(CONFIG_DIR, "post_scripts")
DRIVER_EXPORT_DIR = os.path.join(CONFIG_DIR, "drivers")
WIFI_EXPORT_DIR = os.path.join(CONFIG_DIR, "wifi_profiles")
DEPLOY_SERVER_CONFIG = os.path.join(CONFIG_DIR, "deploy_server.json")
GPU_GOV_CONFIG = os.path.join(CONFIG_DIR, "gpu_governor.json")
SEC_GOV_CONFIG = os.path.join(CONFIG_DIR, "security_governor.json")
SWARM_CONFIG = os.path.join(CONFIG_DIR, "swarm_config.json")
VRAM_SCAN_CONFIG = os.path.join(CONFIG_DIR, "vram_scan_config.json")
ADK_CHECK_FILE = os.path.join(CONFIG_DIR, "adk_detect.json")
HTTPS_DIST_ROOT = os.path.join(BASE_DIR, "dd_dist")

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(PROFILE_DIR, exist_ok=True)
os.makedirs(ISO_WORK_DIR, exist_ok=True)
os.makedirs(POST_SCRIPTS_DIR, exist_ok=True)
os.makedirs(DRIVER_EXPORT_DIR, exist_ok=True)
os.makedirs(WIFI_EXPORT_DIR, exist_ok=True)
os.makedirs(HTTPS_DIST_ROOT, exist_ok=True)

# -----------------------------
# LOGGING (LEVELS)
# -----------------------------

LOG_LEVELS = {"INFO": 1, "WARN": 2, "ERROR": 3}
CURRENT_LOG_LEVEL = LOG_LEVELS["INFO"]

def set_log_level(level: str):
    global CURRENT_LOG_LEVEL
    CURRENT_LOG_LEVEL = LOG_LEVELS.get(level.upper(), LOG_LEVELS["INFO"])

def log(msg: str, level: str = "INFO"):
    if LOG_LEVELS.get(level.upper(), 1) < CURRENT_LOG_LEVEL:
        return
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}][{level}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

# -----------------------------
# WINDOWS COMPONENT CATALOG + GROUPS
# -----------------------------

WINDOWS_COMPONENT_CATALOG = [
    {"id": "core_shell",        "name": "Core Shell / Explorer",          "category": "Core",      "default": True,  "feature": "Shell-Experience"},
    {"id": "windows_defender",  "name": "Windows Defender / Security",    "category": "Security",  "default": True,  "feature": "Windows-Defender"},
    {"id": "remote_desktop",    "name": "Remote Desktop",                 "category": "Remote",    "default": True,  "feature": "Remote-Desktop-Services"},
    {"id": "hyper_v",           "name": "Hyper-V Virtualization",         "category": "Server",    "default": False, "feature": "Microsoft-Hyper-V-All"},
    {"id": "xbox_app",          "name": "Xbox App",                        "category": "Consumer",  "default": False, "feature": "XBOX"},
    {"id": "games_pack",        "name": "Games / Casual",                 "category": "Consumer",  "default": False, "feature": "Games"},
    {"id": "media_features",    "name": "Media Features (WMP etc.)",      "category": "Media",     "default": True,  "feature": "MediaPlayback"},
    {"id": "print_scan",        "name": "Printing / Scanning Support",    "category": "Devices",   "default": True,  "feature": "Printing-Scan"},
    {"id": "optional_fonts",    "name": "Optional Fonts / Languages",     "category": "Locale",    "default": False, "feature": "Fonts-Optional"},
    {"id": "powershell_ise",    "name": "PowerShell ISE",                 "category": "Admin",     "default": True,  "feature": "PowerShell-ISE"},
    {"id": "admin_tools",       "name": "Administrative Tools",           "category": "Admin",     "default": True,  "feature": "AdminTools"},
    {"id": "tablet_features",   "name": "Tablet / Touch Features",        "category": "Devices",   "default": False, "feature": "TabletPC"},
]

COMPONENT_GROUPS = {
    "CoreOnly": ["core_shell"],
    "SecurityOnly": ["windows_defender"],
    "AdminPack": ["powershell_ise", "admin_tools"],
    "DevicesPack": ["print_scan", "tablet_features"],
    "MediaPack": ["media_features"],
    "ConsumerPack": ["xbox_app", "games_pack"],
}

# -----------------------------
# NETWORK PRESETS (SITE / VLAN / IP)
# -----------------------------

DEFAULT_NETWORK_PRESETS = {
    "HQ": {
        "description": "Headquarters LAN",
        "ip_mode": "static",
        "ip_address": "10.0.0.50",
        "subnet_mask": "255.255.255.0",
        "gateway": "10.0.0.1",
        "dns_servers": ["10.0.0.10", "8.8.8.8"],
        "vlan_id": 10,
        "proxy": "http://proxy.hq.local:8080"
    },
    "Branch": {
        "description": "Branch office LAN",
        "ip_mode": "dhcp",
        "ip_address": "",
        "subnet_mask": "",
        "gateway": "",
        "dns_servers": ["8.8.8.8", "1.1.1.1"],
        "vlan_id": 20,
        "proxy": ""
    },
    "Lab": {
        "description": "Isolated lab network",
        "ip_mode": "static",
        "ip_address": "192.168.50.50",
        "subnet_mask": "255.255.255.0",
        "gateway": "192.168.50.1",
        "dns_servers": ["192.168.50.10"],
        "vlan_id": 50,
        "proxy": ""
    },
    "DMZ": {
        "description": "DMZ segment",
        "ip_mode": "static",
        "ip_address": "172.16.0.50",
        "subnet_mask": "255.255.255.0",
        "gateway": "172.16.0.1",
        "dns_servers": ["8.8.8.8"],
        "vlan_id": 100,
        "proxy": ""
    }
}

def load_network_presets() -> Dict[str, Any]:
    if not os.path.exists(NETWORK_PRESETS_FILE):
        with open(NETWORK_PRESETS_FILE, "w", encoding="utf-8") as f:
            json.dump(DEFAULT_NETWORK_PRESETS, f, indent=4)
        return DEFAULT_NETWORK_PRESETS
    try:
        with open(NETWORK_PRESETS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log(f"[NET] Failed to load network presets: {e}", "WARN")
        return DEFAULT_NETWORK_PRESETS

def save_network_presets(presets: Dict[str, Any]):
    with open(NETWORK_PRESETS_FILE, "w", encoding="utf-8") as f:
        json.dump(presets, f, indent=4)
    log("[NET] Network presets saved.")

NETWORK_PRESETS = load_network_presets()

# -----------------------------
# PLUGIN API
# -----------------------------

@dataclass
class PluginContext:
    config: Dict[str, Any]
    profile_name: str
    base_iso_path: str
    output_iso_path: str
    work_dir: str
    dry_run: bool

class PluginBase:
    name: str = "BasePlugin"
    description: str = "Base plugin"

    def run_before_iso_mount(self, ctx: PluginContext):
        pass

    def run_after_iso_mount(self, ctx: PluginContext):
        pass

    def run_before_iso_build(self, ctx: PluginContext):
        pass

    def run_after_iso_build(self, ctx: PluginContext):
        pass

PLUGIN_REGISTRY: List[PluginBase] = []

def register_plugin(plugin: PluginBase):
    PLUGIN_REGISTRY.append(plugin)
    log(f"[PLUGIN] Registered plugin: {plugin.name}")

class LoggingPlugin(PluginBase):
    name = "LoggingPlugin"
    description = "Logs each phase of ISO orchestration."

    def run_before_iso_mount(self, ctx: PluginContext):
        log(f"[PLUGIN:{self.name}] Before ISO mount for profile {ctx.profile_name}")

    def run_after_iso_mount(self, ctx: PluginContext):
        log(f"[PLUGIN:{self.name}] After ISO mount")

    def run_before_iso_build(self, ctx: PluginContext):
        log(f"[PLUGIN:{self.name}] Before ISO build (dry_run={ctx.dry_run})")

    def run_after_iso_build(self, ctx: PluginContext):
        log(f"[PLUGIN:{self.name}] After ISO build: {ctx.output_iso_path}")

class GPUGovernorPlugin(PluginBase):
    name = "GPUGovernorPlugin"
    description = "Injects GPU governor configuration and runtime integration."

    def run_after_iso_mount(self, ctx: PluginContext):
        try:
            cfg = {}
            if os.path.exists(GPU_GOV_CONFIG):
                with open(GPU_GOV_CONFIG, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            else:
                cfg = {
                    "enabled": True,
                    "mode": "auto",
                    "vram_scan": True,
                    "variance": 0.05,
                    "profiles": ["balanced", "performance", "eco"]
                }
            dest = os.path.join(ctx.work_dir, "mount", "dd_gpu_governor.json")
            with open(dest, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4)
            log(f"[PLUGIN:{self.name}] GPU governor config injected at {dest}")
        except Exception as e:
            log(f"[PLUGIN:{self.name}] Failed to inject GPU governor: {e}", "WARN")

class SecurityGovernorPlugin(PluginBase):
    name = "SecurityGovernorPlugin"
    description = "Injects security governor policies and enforcement rules."

    def run_after_iso_mount(self, ctx: PluginContext):
        try:
            cfg = {}
            if os.path.exists(SEC_GOV_CONFIG):
                with open(SEC_GOV_CONFIG, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            else:
                cfg = {
                    "telemetry": "minimal",
                    "error_reporting": "disabled",
                    "feedback_hub": "hidden",
                    "symbolic_overlays": True,
                    "firewall_hardening": True,
                    "credential_guard": True
                }
            dest = os.path.join(ctx.work_dir, "mount", "dd_security_governor.json")
            with open(dest, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4)
            log(f"[PLUGIN:{self.name}] Security governor config injected at {dest}")
        except Exception as e:
            log(f"[PLUGIN:{self.name}] Failed to inject security governor: {e}", "WARN")

class SwarmSyncPlugin(PluginBase):
    name = "SwarmSyncPlugin"
    description = "Merges swarm sync rules and propagation metadata."

    def run_before_iso_build(self, ctx: PluginContext):
        try:
            cfg = {}
            if os.path.exists(SWARM_CONFIG):
                with open(SWARM_CONFIG, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            else:
                cfg = {
                    "nodes": [],
                    "rules": [],
                    "threat_signatures": [],
                    "merge_strategy": "union",
                    "propagation": {
                        "enabled": True,
                        "max_hops": 3,
                        "sync_interval_sec": 300
                    }
                }
            dest = os.path.join(ctx.work_dir, "mount", "dd_swarm_sync.json")
            with open(dest, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4)
            log(f"[PLUGIN:{self.name}] Swarm sync config injected at {dest}")
        except Exception as e:
            log(f"[PLUGIN:{self.name}] Failed to inject swarm sync: {e}", "WARN")

class VRAMScanPlugin(PluginBase):
    name = "VRAMScanPlugin"
    description = "Injects VRAM scanning configuration and runtime hooks."

    def run_after_iso_mount(self, ctx: PluginContext):
        try:
            cfg = {}
            if os.path.exists(VRAM_SCAN_CONFIG):
                with open(VRAM_SCAN_CONFIG, "r", encoding="utf-8") as f:
                    cfg = json.load(f)
            else:
                cfg = {
                    "enabled": True,
                    "scan_on_boot": True,
                    "scan_interval_sec": 300,
                    "telemetry": "local-only",
                    "patterns": ["suspicious_texture", "overlay_injection"]
                }
            dest = os.path.join(ctx.work_dir, "mount", "dd_vram_scan_config.json")
            with open(dest, "w", encoding="utf-8") as f:
                json.dump(cfg, f, indent=4)
            log(f"[PLUGIN:{self.name}] VRAM scan config injected at {dest}")
        except Exception as e:
            log(f"[PLUGIN:{self.name}] Failed to inject VRAM scan config: {e}", "WARN")

register_plugin(LoggingPlugin())
register_plugin(GPUGovernorPlugin())
register_plugin(SecurityGovernorPlugin())
register_plugin(SwarmSyncPlugin())
register_plugin(VRAMScanPlugin())

# -----------------------------
# PROFILE ARCHITECTURE
# -----------------------------

@dataclass
class Profile:
    name: str
    type: str  # "government", "enterprise", "cloud", "local", "gaming", "minimal"
    region: str
    description: str
    include_games: bool = False
    include_consumer_apps: bool = False
    cloud_first: bool = False
    local_first: bool = True
    network_preset_name: str = "HQ"
    network_preset: Dict[str, Any] = field(default_factory=dict)
    app_whitelist: List[str] = field(default_factory=list)
    app_blacklist: List[str] = field(default_factory=list)
    selected_components: List[str] = field(default_factory=list)
    app_include_patterns: List[str] = field(default_factory=list)
    app_exclude_patterns: List[str] = field(default_factory=list)
    post_install_script: str = ""  # path to PowerShell script

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "type": self.type,
            "region": self.region,
            "description": self.description,
            "include_games": self.include_games,
            "include_consumer_apps": self.include_consumer_apps,
            "cloud_first": self.cloud_first,
            "local_first": self.local_first,
            "network_preset_name": self.network_preset_name,
            "network_preset": self.network_preset,
            "app_whitelist": self.app_whitelist,
            "app_blacklist": self.app_blacklist,
            "selected_components": self.selected_components,
            "app_include_patterns": self.app_include_patterns,
            "app_exclude_patterns": self.app_exclude_patterns,
            "post_install_script": self.post_install_script,
        }

    @staticmethod
    def from_dict(d: Dict[str, Any]) -> "Profile":
        return Profile(
            name=d.get("name", "Unnamed"),
            type=d.get("type", "enterprise"),
            region=d.get("region", "US"),
            description=d.get("description", ""),
            include_games=d.get("include_games", False),
            include_consumer_apps=d.get("include_consumer_apps", False),
            cloud_first=d.get("cloud_first", False),
            local_first=d.get("local_first", True),
            network_preset_name=d.get("network_preset_name", "HQ"),
            network_preset=d.get("network_preset", {}),
            app_whitelist=d.get("app_whitelist", []),
            app_blacklist=d.get("app_blacklist", []),
            selected_components=d.get("selected_components", []),
            app_include_patterns=d.get("app_include_patterns", []),
            app_exclude_patterns=d.get("app_exclude_patterns", []),
            post_install_script=d.get("post_install_script", ""),
        )

def save_profile(profile: Profile):
    path = os.path.join(PROFILE_DIR, f"{profile.name}.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(profile.to_dict(), f, indent=4)
    log(f"[PROFILE] Saved profile: {profile.name}")

def load_profiles() -> List[Profile]:
    profiles = []
    for fn in os.listdir(PROFILE_DIR):
        if fn.lower().endswith(".json"):
            path = os.path.join(PROFILE_DIR, fn)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                profiles.append(Profile.from_dict(data))
            except Exception as e:
                log(f"[PROFILE] Failed to load {fn}: {e}", "WARN")
    return profiles

def export_profiles(path: str):
    profiles = [p.to_dict() for p in load_profiles()]
    with open(path, "w", encoding="utf-8") as f:
        json.dump(profiles, f, indent=4)
    log(f"[PROFILE] Exported all profiles to {path}")

def import_profiles(path: str):
    if not os.path.exists(path):
        log(f"[PROFILE] Import file not found: {path}", "ERROR")
        return
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    if not isinstance(data, list):
        log("[PROFILE] Import data invalid (expected list).", "ERROR")
        return
    for p_dict in data:
        p = Profile.from_dict(p_dict)
        save_profile(p)
    log(f"[PROFILE] Imported profiles from {path}")

# Seed default profiles if none exist
if not os.listdir(PROFILE_DIR):
    def default_components_for(categories: List[str]) -> List[str]:
        return [
            c["id"] for c in WINDOWS_COMPONENT_CATALOG
            if c["category"] in categories and c["default"]
        ]

    save_profile(Profile(
        name="Government_US",
        type="government",
        region="US",
        description="No games, no consumer apps, strict network, local-first.",
        include_games=False,
        include_consumer_apps=False,
        cloud_first=False,
        local_first=True,
        network_preset_name="HQ",
        network_preset=NETWORK_PRESETS.get("HQ", {}),
        app_whitelist=["Office", "SecuritySuite", "CustomGovTools"],
        app_blacklist=["Xbox", "Games", "ConsumerMedia"],
        selected_components=default_components_for(["Core", "Security", "Admin", "Devices"]),
        app_include_patterns=["Office", "Security"],
        app_exclude_patterns=["Game", "Xbox"],
        post_install_script=""
    ))
    save_profile(Profile(
        name="Enterprise_CloudFirst",
        type="enterprise",
        region="Global",
        description="Enterprise profile with cloud-first services.",
        include_games=False,
        include_consumer_apps=False,
        cloud_first=True,
        local_first=False,
        network_preset_name="HQ",
        network_preset=NETWORK_PRESETS.get("HQ", {}),
        app_whitelist=["Office", "Teams", "VPNClient"],
        app_blacklist=["Xbox", "Games"],
        selected_components=default_components_for(["Core", "Security", "Admin", "Media"]),
        app_include_patterns=["Office", "Teams", "VPN"],
        app_exclude_patterns=["Game", "Xbox"],
        post_install_script=""
    ))
    save_profile(Profile(
        name="Branch_Office",
        type="enterprise",
        region="US",
        description="Branch office profile with DHCP and minimal extras.",
        include_games=False,
        include_consumer_apps=False,
        cloud_first=False,
        local_first=True,
        network_preset_name="Branch",
        network_preset=NETWORK_PRESETS.get("Branch", {}),
        app_whitelist=["Office", "VPNClient"],
        app_blacklist=["Xbox", "Games"],
        selected_components=default_components_for(["Core", "Security", "Admin"]),
        app_include_patterns=["Office", "VPN"],
        app_exclude_patterns=["Game", "Xbox"],
        post_install_script=""
    ))
    save_profile(Profile(
        name="Lab_Isolated",
        type="minimal",
        region="Global",
        description="Lab isolated network, static IP, minimal components.",
        include_games=False,
        include_consumer_apps=False,
        cloud_first=False,
        local_first=True,
        network_preset_name="Lab",
        network_preset=NETWORK_PRESETS.get("Lab", {}),
        app_whitelist=[],
        app_blacklist=["Xbox", "Games", "Media"],
        selected_components=COMPONENT_GROUPS["CoreOnly"],
        app_include_patterns=[],
        app_exclude_patterns=["Game", "Media", "Xbox"],
        post_install_script=""
    ))

# -----------------------------
# ADK / DISM AUTO-DETECTION
# -----------------------------

def detect_adk_and_dism() -> Dict[str, Any]:
    result = {
        "dism_available": False,
        "adk_paths": [],
    }
    for p in os.environ.get("PATH", "").split(os.pathsep):
        dism_path = os.path.join(p, "dism.exe")
        if os.path.exists(dism_path):
            result["dism_available"] = True
            break
    possible_adk_roots = [
        r"C:\Program Files (x86)\Windows Kits\10\Assessment and Deployment Kit",
        r"C:\Program Files (x86)\Windows Kits\10",
    ]
    for root in possible_adk_roots:
        if os.path.exists(root):
            result["adk_paths"].append(root)
    try:
        with open(ADK_CHECK_FILE, "w", encoding="utf-8") as f:
            json.dump(result, f, indent=4)
    except Exception:
        pass
    if not result["dism_available"]:
        log("[ADK] DISM not detected in PATH. Some operations may fail.", "WARN")
    else:
        log("[ADK] DISM detected.", "INFO")
    if result["adk_paths"]:
        log(f"[ADK] Possible ADK paths: {result['adk_paths']}", "INFO")
    return result

ADK_INFO = detect_adk_and_dism()

# -----------------------------
# SYSTEM SNAPSHOT / MASTER MACHINE
# -----------------------------

def snapshot_installed_programs() -> List[Dict[str, Any]]:
    """Read uninstall registry entries; avoids WMIC product's MSI consistency checks."""
    log("[SNAPSHOT] Capturing installed programs from uninstall registry keys.")
    programs: Dict[str, Dict[str, Any]] = {}
    if os.name != "nt":
        return []
    try:
        import winreg
        roots = [
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_LOCAL_MACHINE, r"SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
            (winreg.HKEY_CURRENT_USER, r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall"),
        ]
        for hive, path in roots:
            try:
                parent = winreg.OpenKey(hive, path)
            except OSError:
                continue
            with parent:
                count = winreg.QueryInfoKey(parent)[0]
                for index in range(count):
                    try:
                        subname = winreg.EnumKey(parent, index)
                        with winreg.OpenKey(parent, subname) as key:
                            name = winreg.QueryValueEx(key, "DisplayName")[0]
                            try:
                                version = winreg.QueryValueEx(key, "DisplayVersion")[0]
                            except OSError:
                                version = ""
                            if name and not str(name).startswith(("KB", "Update for")):
                                programs[str(name).strip().lower()] = {
                                    "name": str(name).strip(), "version": str(version)
                                }
                    except (OSError, ValueError):
                        continue
    except Exception as exc:
        log(f"[SNAPSHOT] Registry inventory failed: {exc}", "WARN")
    result = sorted(programs.values(), key=lambda item: item["name"].casefold())
    log(f"[SNAPSHOT] Captured {len(result)} installed-program entries (inventory only; installers are not bundled).")
    return result


def snapshot_wifi_profiles() -> List[Dict[str, Any]]:
    log("[SNAPSHOT] Capturing Wi-Fi profiles.")
    profiles = []
    try:
        cmd = ["netsh", "wlan", "show", "profiles"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            line = line.strip()
            if "All User Profile" in line:
                name = line.split(":")[-1].strip()
                profiles.append({"ssid": name})
    except Exception as e:
        log(f"[SNAPSHOT] Failed to list Wi-Fi profiles: {e}", "WARN")
    return profiles

def export_wifi_profiles():
    log("[SNAPSHOT] Exporting Wi-Fi profiles to XML.")
    profiles = snapshot_wifi_profiles()
    for p in profiles:
        ssid = p["ssid"]
        try:
            cmd = [
                "netsh", "wlan", "export", "profile",
                f"name={ssid}",
                f"folder={WIFI_EXPORT_DIR}"
            ]
            subprocess.run(cmd, check=False)
            log(f"[SNAPSHOT] Exported Wi-Fi profile: {ssid}")
        except Exception as e:
            log(f"[SNAPSHOT] Failed to export Wi-Fi profile {ssid}: {e}", "WARN")

def snapshot_system_settings() -> Dict[str, Any]:
    log("[SNAPSHOT] Capturing system settings.")
    timezone = "UTC"
    if os.name == "nt":
        try:
            result = subprocess.run(["tzutil", "/g"], capture_output=True, text=True, check=False, timeout=10)
            if result.returncode == 0 and result.stdout.strip():
                timezone = result.stdout.strip()
        except Exception as exc:
            log(f"[SNAPSHOT] Could not read Windows time zone: {exc}", "WARN")
    return {
        "region": "US",
        "language": "en-US",
        "timezone": timezone,
        "hostname": os.environ.get("COMPUTERNAME", "UNKNOWN"),
    }

def snapshot_drivers() -> List[str]:
    """Export third-party drivers with pnputil's supported wildcard syntax."""
    log("[SNAPSHOT] Exporting third-party drivers with pnputil.")
    os.makedirs(DRIVER_EXPORT_DIR, exist_ok=True)
    try:
        result = subprocess.run(
            ["pnputil", "/export-driver", "*", DRIVER_EXPORT_DIR],
            capture_output=True, text=True, check=False, timeout=900
        )
        if result.returncode != 0:
            log(f"[SNAPSHOT] pnputil returned {result.returncode}: {result.stderr.strip()}", "WARN")
        exported = []
        for root, _, files in os.walk(DRIVER_EXPORT_DIR):
            for name in files:
                if name.lower().endswith(".inf"):
                    exported.append(os.path.join(root, name))
        log(f"[SNAPSHOT] Found {len(exported)} exported INF driver packages.")
        return exported
    except Exception as exc:
        log(f"[SNAPSHOT] Driver export failed: {exc}", "WARN")
        return []


def resolve_driver_dependencies(drivers: List[str]) -> List[str]:
    """
    Very simplified driver dependency resolution:
    - We keep unique INF names.
    - Future: parse INF for dependent components.
    """
    log("[DRIVER] Resolving driver dependencies (simplified).")
    unique = {}
    for inf in drivers:
        key = os.path.basename(inf).lower()
        if key not in unique:
            unique[key] = inf
    resolved = list(unique.values())
    log(f"[DRIVER] Resolved to {len(resolved)} unique driver entries.")
    return resolved

def filter_programs_for_profile(programs: List[Dict[str, Any]], profile: Profile) -> List[Dict[str, Any]]:
    filtered = []
    for p in programs:
        name = p.get("name", "")
        if not name:
            continue
        if any(pattern.lower() in name.lower() for pattern in profile.app_exclude_patterns):
            continue
        if profile.app_include_patterns:
            if any(pattern.lower() in name.lower() for pattern in profile.app_include_patterns):
                filtered.append(p)
        else:
            filtered.append(p)
    log(f"[SNAPSHOT] Filtered programs for profile {profile.name}: {len(filtered)} items.")
    return filtered

def build_master_profile_bundle(profile: Optional[Profile] = None) -> Dict[str, Any]:
    log("[MASTER] Building master profile bundle from current machine.")
    system_settings = snapshot_system_settings()
    wifi_profiles = snapshot_wifi_profiles()
    installed_programs = snapshot_installed_programs()
    drivers_raw = snapshot_drivers()
    drivers = resolve_driver_dependencies(drivers_raw)
    export_wifi_profiles()
    if profile:
        installed_programs = filter_programs_for_profile(installed_programs, profile)
    bundle = {
        "system_settings": system_settings,
        "wifi_profiles": wifi_profiles,
        "installed_programs": installed_programs,
        "drivers": drivers,
    }
    path = os.path.join(CONFIG_DIR, "master_bundle.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=4)
    log(f"[MASTER] Saved master bundle to {path}")
    return bundle

def load_master_bundle() -> Optional[Dict[str, Any]]:
    path = os.path.join(CONFIG_DIR, "master_bundle.json")
    if not os.path.exists(path):
        return None
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log(f"[MASTER] Failed to load master bundle: {e}", "ERROR")
        return None

# -----------------------------
# DISM MANAGER (REAL COMPONENT ENFORCEMENT)
# -----------------------------

class DISMManager:
    def __init__(self, wim_path: str, index: int, mount_dir: str, dry_run: bool = False):
        self.wim_path = wim_path
        self.index = index
        self.mount_dir = mount_dir
        self.dry_run = dry_run

    def _run_dism(self, args: List[str]):
        cmd = ["dism", "/English"] + args
        log(f"[DISM] Running: {' '.join(cmd)}")
        if self.dry_run:
            log("[DISM] Dry-run: skipping execution.")
            return
        if not ADK_INFO.get("dism_available", False):
            raise RuntimeError("DISM is unavailable. Install/use Windows ADK or ensure dism.exe is on PATH.")
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=3600)
        if result.stdout:
            log("[DISM] " + result.stdout[-3000:].strip())
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "No diagnostic output")[-2000:]
            raise RuntimeError(f"DISM failed with exit code {result.returncode}: {detail}")


    def mount(self):
        self._run_dism([
            "/Mount-Wim",
            f"/WimFile:{self.wim_path}",
            f"/Index:{self.index}",
            f"/MountDir:{self.mount_dir}"
        ])

    def unmount(self, commit: bool = True):
        self._run_dism([
            "/Unmount-Wim",
            f"/MountDir:{self.mount_dir}",
            f"/Commit" if commit else "/Discard"
        ])

    def enable_feature(self, feature_name: str):
        self._run_dism([
            "/Image:" + self.mount_dir,
            "/Enable-Feature",
            f"/FeatureName:{feature_name}",
            "/All"
        ])

    def disable_feature(self, feature_name: str):
        self._run_dism([
            "/Image:" + self.mount_dir,
            "/Disable-Feature",
            f"/FeatureName:{feature_name}"
        ])

    def add_driver(self, inf_path: str):
        self._run_dism([
            "/Image:" + self.mount_dir,
            "/Add-Driver",
            f"/Driver:{inf_path}",
            "/ForceUnsigned"
        ])

    def add_package(self, cab_path: str):
        self._run_dism([
            "/Image:" + self.mount_dir,
            "/Add-Package",
            f"/PackagePath:{cab_path}"
        ])

def enforce_components_with_dism(dism_mgr: DISMManager, profile: Profile):
    """
    The catalog's feature identifiers are descriptive placeholders, not verified
    DISM feature names. Never disable every unselected feature: that can break
    servicing, networking, or setup. Record selections in the manifest instead.
    Add an explicitly verified DISM feature map before enabling any feature.
    """
    selected = sorted(set(profile.selected_components or []))
    log(f"[DISM] Component selections recorded for manifest: {selected}")
    log("[DISM] No Windows features changed: catalog entries are not trusted DISM IDs. "
        "This safe default avoids disabling unrelated/critical components.", "WARN")


def inject_drivers_with_dism(dism_mgr: DISMManager, bundle: Dict[str, Any]):
    drivers = bundle.get("drivers", [])
    log(f"[DISM] Injecting {len(drivers)} drivers.")
    for inf in drivers:
        try:
            dism_mgr.add_driver(inf)
        except Exception as e:
            log(f"[DISM] Failed to inject driver {inf}: {e}", "WARN")

def inject_wifi_profiles_into_image(mount_dir: str, dry_run: bool = False):
    log("[ISO] Injecting Wi-Fi profiles into image (post-install script).")
    wifi_dir_in_image = os.path.join(mount_dir, "dd_wifi_profiles")
    if dry_run:
        log(f"[ISO] Dry-run: would create Wi-Fi dir {wifi_dir_in_image}")
        return
    os.makedirs(wifi_dir_in_image, exist_ok=True)
    for fn in os.listdir(WIFI_EXPORT_DIR):
        src = os.path.join(WIFI_EXPORT_DIR, fn)
        if os.path.isfile(src):
            shutil.copy2(src, wifi_dir_in_image)
    log("[ISO] Wi-Fi profiles copied into image.")

# -----------------------------
# ISO / DISM ORCHESTRATION
# -----------------------------

class ISOManager:
    def __init__(self, base_iso: str, output_iso: str, work_dir: str, dry_run: bool = False):
        self.base_iso = base_iso
        self.output_iso = output_iso
        self.work_dir = work_dir
        self.mount_dir = os.path.join(work_dir, "mount")
        self.dry_run = dry_run
        os.makedirs(self.mount_dir, exist_ok=True)

    def extract_iso(self):
        log(f"[ISO] Extracting base ISO: {self.base_iso}")
        if not os.path.exists(self.base_iso):
            raise FileNotFoundError(f"Base ISO not found: {self.base_iso}")
        if self.dry_run:
            log("[ISO] Dry-run: skipping actual ISO extraction.")
            return
        seven_zip = shutil.which("7z") or shutil.which("7za")
        if not seven_zip:
            raise RuntimeError("7-Zip command-line tool (7z.exe) not found on PATH.")
        os.makedirs(self.mount_dir, exist_ok=True)
        result = subprocess.run(
            [seven_zip, "x", self.base_iso, f"-o{self.mount_dir}", "-y"],
            capture_output=True, text=True, check=False, timeout=3600
        )
        if result.returncode not in (0, 1):
            raise RuntimeError(f"ISO extraction failed ({result.returncode}): {(result.stderr or result.stdout)[-2000:]}")
        sources = os.path.join(self.mount_dir, "sources")
        if not os.path.isdir(sources):
            raise RuntimeError("Extracted ISO is missing its sources directory; output may be incomplete.")
        log("[ISO] Extraction validated: sources directory exists.")

    def inject_unattend(self, unattend_xml: str):
        """Place the answer file at ISO root using Windows Setup's autounattend name."""
        dest = os.path.join(self.mount_dir, "autounattend.xml")
        log(f"[ISO] Injecting answer file at {dest}")
        if self.dry_run:
            log(f"[ISO] Dry-run: would copy autounattend.xml to {dest}")
            return
        if not os.path.isfile(unattend_xml):
            raise FileNotFoundError(f"Answer file not found: {unattend_xml}")
        shutil.copy2(unattend_xml, dest)
        log("[ISO] autounattend.xml injected at ISO root.")

    def inject_bundle_and_profile(self, bundle: Dict[str, Any], profile: Profile):
        log("[ISO] Injecting master bundle, profile, and network preset.")
        config_path = os.path.join(self.mount_dir, "dd_master_bundle.json")
        profile_path = os.path.join(self.mount_dir, "dd_profile.json")
        net_path = os.path.join(self.mount_dir, "dd_network_preset.json")
        if self.dry_run:
            log(f"[ISO] Dry-run: would write bundle/profile/network to {config_path}/{profile_path}/{net_path}")
            return
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=4)
        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(profile.to_dict(), f, indent=4)
        with open(net_path, "w", encoding="utf-8") as f:
            json.dump(profile.network_preset or NETWORK_PRESETS.get(profile.network_preset_name, {}), f, indent=4)
        log("[ISO] Bundle, profile, and network preset injected.")

    def inject_selected_components_manifest(self, profile: Profile):
        log("[ISO] Injecting selected Windows components manifest.")
        manifest = {
            "selected_components": profile.selected_components,
            "catalog": WINDOWS_COMPONENT_CATALOG,
        }
        manifest_path = os.path.join(self.mount_dir, "dd_components_manifest.json")
        if self.dry_run:
            log(f"[ISO] Dry-run: would write components manifest to {manifest_path}")
            return
        with open(manifest_path, "w", encoding="utf-8") as f:
            json.dump(manifest, f, indent=4)
        log(f"[ISO] Components manifest written to {manifest_path}")

    def inject_post_install_script(self, profile: Profile):
        if not profile.post_install_script:
            return
        log("[ISO] Injecting post-install PowerShell script.")
        dest = os.path.join(self.mount_dir, "dd_post_install.ps1")
        if self.dry_run:
            log(f"[ISO] Dry-run: would copy post-install script to {dest}")
            return
        try:
            shutil.copy2(profile.post_install_script, dest)
            log(f"[ISO] Post-install script injected at {dest}")
        except Exception as e:
            log(f"[ISO] Failed to inject post-install script: {e}", "WARN")

    def inject_post_install_scheduler(self):
        log("[ISO] Injecting post-install scheduled task script.")
        task_script_path = os.path.join(self.mount_dir, "dd_register_postinstall_task.ps1")
        content = r"""
$scriptPath = Join-Path $PSScriptRoot "dd_post_install.ps1"
if (Test-Path $scriptPath) {
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-ExecutionPolicy Bypass -File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -AtLogOn
    $principal = New-ScheduledTaskPrincipal -UserId "NT AUTHORITY\LOCAL SERVICE" -LogonType ServiceAccount -RunLevel Highest
    $task = New-ScheduledTask -Action $action -Trigger $trigger -Principal $principal
    Register-ScheduledTask -TaskName "DominionDeck_PostInstall" -InputObject $task -Force
}
"""
        if self.dry_run:
            log(f"[ISO] Dry-run: would write post-install scheduler script to {task_script_path}")
            return
        with open(task_script_path, "w", encoding="utf-8") as f:
            f.write(content)
        log(f"[ISO] Post-install scheduler script written to {task_script_path}")

    def build_iso(self):
        log(f"[ISO] Building new ISO: {self.output_iso}")
        if os.path.exists(self.output_iso) and not self.dry_run:
            raise FileExistsError(
                f"Output ISO already exists: {self.output_iso}. Choose a new output filename to avoid accidental overwrite."
            )
        if self.dry_run:
            log("[ISO] Dry-run: skipping actual ISO build.")
            return
        oscdimg = shutil.which("oscdimg")
        if not oscdimg:
            raise RuntimeError("oscdimg.exe not found. Install Windows ADK Deployment Tools and add oscdimg to PATH.")
        boot_legacy = os.path.join(self.mount_dir, "boot", "etfsboot.com")
        boot_uefi = os.path.join(self.mount_dir, "efi", "microsoft", "boot", "efisys.bin")
        if not os.path.isfile(boot_legacy) or not os.path.isfile(boot_uefi):
            raise RuntimeError("ISO source is missing BIOS/UEFI boot files; refusing to create a non-bootable ISO.")
        os.makedirs(os.path.dirname(os.path.abspath(self.output_iso)), exist_ok=True)
        cmd = [
            oscdimg, "-m", "-o", "-u2", "-udfver102",
            "-bootdata:2#p0,e,b" + boot_legacy + "#pEF,e,b" + boot_uefi,
            self.mount_dir, self.output_iso
        ]
        result = subprocess.run(cmd, check=False, capture_output=True, text=True, timeout=7200)
        if result.returncode != 0 or not os.path.isfile(self.output_iso):
            raise RuntimeError(f"ISO build failed ({result.returncode}): {(result.stderr or result.stdout)[-3000:]}")
        log(f"[ISO] ISO build verified: {self.output_iso} ({os.path.getsize(self.output_iso):,} bytes)")

# -----------------------------
# UNATTEND.XML GENERATOR (NETWORK-AWARE)
# -----------------------------

def generate_unattend_xml(profile: Profile, bundle: Dict[str, Any]) -> str:
    """
    Generate a conservative answer file. Network settings stay in the profile
    manifest because static-IP answer-file schemas vary by Windows version/NIC.
    """
    log("[UNATTEND] Generating conservative Unattend.xml.")
    settings = bundle.get("system_settings", {})
    language = str(settings.get("language", "en-US"))
    timezone = str(settings.get("timezone", "UTC"))
    raw_host = str(settings.get("hostname", "DD-CLIENT"))
    hostname = re.sub(r"[^A-Za-z0-9-]", "-", raw_host).strip("-") or "DD-CLIENT"
    hostname = (hostname[:10] + "-CLONE")[:15]

    def esc(value: str) -> str:
        return (value.replace("&", "&amp;").replace("<", "&lt;")
                     .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))

    unattend_content = f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <SetupUILanguage><UILanguage>{esc(language)}</UILanguage></SetupUILanguage>
      <InputLocale>{esc(language)}</InputLocale>
      <SystemLocale>{esc(language)}</SystemLocale>
      <UILanguage>{esc(language)}</UILanguage>
      <UserLocale>{esc(language)}</UserLocale>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>{esc(hostname)}</ComputerName>
      <TimeZone>{esc(timezone)}</TimeZone>
    </component>
  </settings>
</unattend>
"""
    ET.fromstring(unattend_content)
    path = os.path.join(CONFIG_DIR, "unattend.xml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(unattend_content)
    log(f"[UNATTEND] Validated XML saved to {path}. Network preset '{profile.network_preset_name}' remains in its separate manifest.")
    return path


# -----------------------------
# WATCHDOG
# -----------------------------

class Watchdog(threading.Thread):
    def __init__(self, interval: float = 5.0):
        super().__init__(daemon=True)
        self.interval = interval
        self.running = True

    def run(self):
        log("[WATCHDOG] Started.")
        while self.running:
            try:
                if os.path.exists(LOG_FILE):
                    size = os.path.getsize(LOG_FILE)
                    if size > 10 * 1024 * 1024:
                        log("[WATCHDOG] Log file too large, rotating.", "WARN")
                        try:
                            shutil.move(LOG_FILE, LOG_FILE + ".old")
                        except Exception:
                            pass
                time.sleep(self.interval)
            except Exception as e:
                log(f"[WATCHDOG] Error: {e}", "ERROR")
                time.sleep(self.interval)

    def stop(self):
        self.running = False
        log("[WATCHDOG] Stopped.")

# -----------------------------
# FULL HTTPS FILE DISTRIBUTION
# -----------------------------

class DistHTTPRequestHandler(SimpleHTTPRequestHandler):
    def translate_path(self, path):
        root = HTTPS_DIST_ROOT
        path = path.lstrip("/")
        return os.path.join(root, path)

def start_https_distribution_server(host: str = "0.0.0.0", port: int = 50444):
    cert_path = os.path.join(CONFIG_DIR, "dist_cert.pem")
    key_path = os.path.join(CONFIG_DIR, "dist_key.pem")
    if not (os.path.exists(cert_path) and os.path.exists(key_path)):
        log("[DIST] HTTPS distribution cert/key not found; distribution disabled.", "WARN")
        return None

    server_address = (host, port)
    httpd = HTTPServer(server_address, DistHTTPRequestHandler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
    httpd.socket = context.wrap_socket(httpd.socket, server_side=True)

    def serve():
        log(f"[DIST] HTTPS distribution server running on {host}:{port}")
        try:
            httpd.serve_forever()
        except Exception as e:
            log(f"[DIST] HTTPS distribution server error: {e}", "ERROR")

    t = threading.Thread(target=serve, daemon=True)
    t.start()
    return httpd

def publish_iso_for_distribution(iso_path: str):
    if not os.path.exists(iso_path):
        log(f"[DIST] ISO not found for distribution: {iso_path}", "ERROR")
        return
    dest = os.path.join(HTTPS_DIST_ROOT, os.path.basename(iso_path))
    try:
        shutil.copy2(iso_path, dest)
        log(f"[DIST] ISO published for HTTPS distribution: {dest}")
    except Exception as e:
        log(f"[DIST] Failed to publish ISO: {e}", "ERROR")

# -----------------------------
# NETWORK DEPLOYMENT SERVER (TCP + HTTPS + PXE METADATA)
# -----------------------------

@dataclass
class DeployClientStatus:
    address: str
    hostname: str
    profile_name: str
    state: str  # "waiting", "downloading", "installing", "done", "error"

class DeployServer(threading.Thread):
    def __init__(self, host: str = "0.0.0.0", port: int = 50050, https_port: int = 50443):
        super().__init__(daemon=True)
        self.host = host
        self.port = port
        self.https_port = https_port
        self.running = True
        self.clients: Dict[str, DeployClientStatus] = {}
        self.lock = threading.Lock()
        self.https_thread: Optional[threading.Thread] = None

    def run(self):
        log(f"[DEPLOY] TCP server starting on {self.host}:{self.port}")
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                s.bind((self.host, self.port))
                s.listen(5)
                self.start_https_server_if_possible()
                while self.running:
                    try:
                        s.settimeout(1.0)
                        conn, addr = s.accept()
                    except socket.timeout:
                        continue
                    threading.Thread(target=self.handle_client, args=(conn, addr), daemon=True).start()
        except Exception as e:
            log(f"[DEPLOY] TCP server error: {e}", "ERROR")

    def start_https_server_if_possible(self):
        cert_path = os.path.join(CONFIG_DIR, "deploy_cert.pem")
        key_path = os.path.join(CONFIG_DIR, "deploy_key.pem")
        if not (os.path.exists(cert_path) and os.path.exists(key_path)):
            log("[DEPLOY] HTTPS cert/key not found; HTTPS server disabled.", "WARN")
            return

        def https_server():
            log(f"[DEPLOY] HTTPS server starting on {self.host}:{self.https_port}")
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((self.host, self.https_port))
                    s.listen(5)
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                    context.load_cert_chain(certfile=cert_path, keyfile=key_path)
                    while self.running:
                        try:
                            s.settimeout(1.0)
                            conn, addr = s.accept()
                        except socket.timeout:
                            continue
                        try:
                            ssl_conn = context.wrap_socket(conn, server_side=True)
                            threading.Thread(target=self.handle_https_client, args=(ssl_conn, addr), daemon=True).start()
                        except Exception as e:
                            log(f"[DEPLOY] HTTPS client error: {e}", "WARN")
            except Exception as e:
                log(f"[DEPLOY] HTTPS server error: {e}", "ERROR")

        self.https_thread = threading.Thread(target=https_server, daemon=True)
        self.https_thread.start()

    def handle_client(self, conn: socket.socket, addr):
        ip = addr[0]
        log(f"[DEPLOY] TCP client connected: {ip}")
        try:
            data = conn.recv(4096).decode("utf-8", errors="ignore").strip()
            try:
                info = json.loads(data)
            except Exception:
                info = {"hostname": "UNKNOWN", "profile": "UNKNOWN"}
            hostname = info.get("hostname", "UNKNOWN")
            profile_name = info.get("profile", "UNKNOWN")
            with self.lock:
                self.clients[ip] = DeployClientStatus(
                    address=ip,
                    hostname=hostname,
                    profile_name=profile_name,
                    state="waiting"
                )
            log_pxe_request(ip, profile_name)
            conn.sendall(b"OK\n")
            with self.lock:
                self.clients[ip].state = "installing"
        except Exception as e:
            log(f"[DEPLOY] TCP client error from {ip}: {e}", "WARN")
            with self.lock:
                if ip in self.clients:
                    self.clients[ip].state = "error"
        finally:
            conn.close()

    def handle_https_client(self, conn: ssl.SSLSocket, addr):
        ip = addr[0]
        log(f"[DEPLOY] HTTPS client connected: {ip}")
        try:
            data = conn.recv(4096).decode("utf-8", errors="ignore").strip()
            try:
                info = json.loads(data)
            except Exception:
                info = {"hostname": "UNKNOWN", "profile": "UNKNOWN"}
            hostname = info.get("hostname", "UNKNOWN")
            profile_name = info.get("profile", "UNKNOWN")
            with self.lock:
                self.clients[ip] = DeployClientStatus(
                    address=ip,
                    hostname=hostname,
                    profile_name=profile_name,
                    state="waiting"
                )
            log_pxe_request(ip, profile_name)
            conn.sendall(b"OK-HTTPS\n")
            with self.lock:
                self.clients[ip].state = "installing"
        except Exception as e:
            log(f"[DEPLOY] HTTPS client error from {ip}: {e}", "WARN")
            with self.lock:
                if ip in self.clients:
                    self.clients[ip].state = "error"
        finally:
            conn.close()

    def stop(self):
        self.running = False
        log("[DEPLOY] Server stopping.")

    def get_client_statuses(self) -> List[DeployClientStatus]:
        with self.lock:
            return list(self.clients.values())

# -----------------------------
# NETWORK BOOT CLIENT (USB COMPANION)
# -----------------------------

def run_network_boot_client(server_host: str, server_port: int, profile_name: str, use_https: bool = False, https_port: int = 50443):
    hostname = os.environ.get("COMPUTERNAME", "UNKNOWN")
    payload = json.dumps({"hostname": hostname, "profile": profile_name})
    try:
        if use_https:
            log(f"[CLIENT] Connecting via HTTPS to {server_host}:{https_port}")
            context = ssl.create_default_context()
            with socket.create_connection((server_host, https_port)) as sock:
                with context.wrap_socket(sock, server_hostname=server_host) as s:
                    s.sendall(payload.encode("utf-8"))
                    resp = s.recv(4096).decode("utf-8", errors="ignore").strip()
                    log(f"[CLIENT] HTTPS server response: {resp}")
        else:
            log(f"[CLIENT] Connecting via TCP to {server_host}:{server_port}")
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((server_host, server_port))
                s.sendall(payload.encode("utf-8"))
                resp = s.recv(4096).decode("utf-8", errors="ignore").strip()
                log(f"[CLIENT] TCP server response: {resp}")
    except Exception as e:
        log(f"[CLIENT] Failed to connect to deploy server: {e}", "ERROR")

# -----------------------------
# PXE BOOT INFRASTRUCTURE (METADATA / BOOT MENU)
# -----------------------------

def log_pxe_request(client_ip: str, profile_name: str):
    log(f"[PXE] PXE boot request from {client_ip} for profile {profile_name}")
    meta_path = os.path.join(CONFIG_DIR, "pxe_requests.json")
    data = []
    if os.path.exists(meta_path):
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = []
    data.append({"ip": client_ip, "profile": profile_name, "ts": time.time()})
    try:
        with open(meta_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
    except Exception:
        pass

def generate_pxe_boot_menu():
    """
    Generates a simple PXE boot menu metadata file.
    Real PXE infra would consume this via TFTP/DHCP.
    """
    log("[PXE] Generating PXE boot menu metadata.")
    profiles = load_profiles()
    menu = []
    for p in profiles:
        menu.append({
            "label": p.name,
            "type": p.type,
            "region": p.region,
            "description": p.description
        })
    path = os.path.join(CONFIG_DIR, "pxe_boot_menu.json")
    try:
        with open(path, "w", encoding="utf-8") as f:
            json.dump(menu, f, indent=4)
        log(f"[PXE] PXE boot menu written to {path}")
    except Exception as e:
        log(f"[PXE] Failed to write PXE boot menu: {e}", "ERROR")

# -----------------------------
# USB CREATOR (BOOTABLE CLIENT)
# -----------------------------

def create_bootable_usb(iso_path: str, usb_drive: str, dry_run: bool = False):
    """
    Copy ISO contents to an existing drive only. This does not partition/format
    a USB drive and therefore does not promise the result is bootable.
    Use a trusted USB writer (e.g. Rufus) for actual boot-media creation.
    """
    iso_path = os.path.abspath(os.path.expandvars(iso_path.strip().strip('"')))
    usb_drive = os.path.abspath(os.path.expandvars(usb_drive.strip().strip('"')))
    log(f"[USB] Preparing ISO file copy to {usb_drive}")
    if not os.path.isfile(iso_path):
        raise FileNotFoundError(f"ISO not found: {iso_path}")
    if not os.path.isdir(usb_drive):
        raise FileNotFoundError(f"Destination drive/folder not found: {usb_drive}")
    if os.path.commonpath([iso_path, usb_drive]) == usb_drive:
        raise ValueError("Destination cannot contain the source ISO.")
    if dry_run:
        log("[USB] Dry-run: no files written.")
        return
    seven_zip = shutil.which("7z") or shutil.which("7za")
    if not seven_zip:
        raise RuntimeError("7-Zip command-line tool (7z.exe) not found on PATH.")
    result = subprocess.run(
        [seven_zip, "x", iso_path, f"-o{usb_drive}", "-y"],
        capture_output=True, text=True, check=False, timeout=3600
    )
    if result.returncode not in (0, 1):
        raise RuntimeError(f"ISO file copy failed ({result.returncode}): {(result.stderr or result.stdout)[-2000:]}")
    log("[USB] ISO files copied. NOTE: file extraction alone does not guarantee bootable USB media.", "WARN")


# -----------------------------
# LOCAL WINDOWS WORKSPACE + BOOTABLE UEFI USB
# -----------------------------

def create_local_windows_workspace(iso_path: str, destination: str, dry_run: bool = False) -> str:
    """Extract a Windows ISO into a local working folder without modifying disks."""
    iso_path = os.path.abspath(os.path.expandvars(iso_path.strip().strip('"')))
    destination = os.path.abspath(os.path.expandvars(destination.strip().strip('"')))
    if not os.path.isfile(iso_path) or not iso_path.lower().endswith('.iso'):
        raise FileNotFoundError(f"Select an existing Windows ISO: {iso_path}")
    if os.path.exists(destination) and os.listdir(destination):
        raise FileExistsError("Workspace destination must be empty to avoid mixing files from different Windows ISOs.")
    if dry_run:
        log(f"[WORKSPACE] Dry-run: would extract {iso_path} to {destination}")
        return destination
    seven_zip = shutil.which('7z') or shutil.which('7za')
    if not seven_zip:
        raise RuntimeError("7-Zip command-line tool (7z.exe) not found on PATH.")
    os.makedirs(destination, exist_ok=True)
    result = subprocess.run([seven_zip, 'x', iso_path, f'-o{destination}', '-y'],
                            capture_output=True, text=True, check=False, timeout=7200)
    if result.returncode not in (0, 1):
        raise RuntimeError(f"ISO extraction failed ({result.returncode}): {(result.stderr or result.stdout)[-2500:]}")
    if not os.path.isdir(os.path.join(destination, 'sources')):
        raise RuntimeError("Workspace extraction is incomplete: the Windows ISO 'sources' folder is missing.")
    log(f"[WORKSPACE] Windows ISO workspace ready at {destination}")
    return destination


def get_windows_physical_disks() -> list:
    """Return physical disks from PowerShell; never infer a disk from a drive letter."""
    if os.name != 'nt':
        raise OSError("Physical USB preparation is supported only on Windows.")
    ps = ("Get-Disk | Select-Object Number,FriendlyName,SerialNumber,BusType,PartitionStyle,"
          "OperationalStatus,IsBoot,IsSystem,Size | ConvertTo-Json -Compress")
    result = subprocess.run(['powershell.exe', '-NoProfile', '-ExecutionPolicy', 'Bypass', '-Command', ps],
                            capture_output=True, text=True, check=False, timeout=30)
    if result.returncode != 0:
        raise RuntimeError(f"Unable to list physical disks: {(result.stderr or result.stdout)[-1500:]}")
    raw = (result.stdout or '').strip()
    if not raw:
        return []
    data = json.loads(raw)
    return data if isinstance(data, list) else [data]


def _free_windows_drive_letter() -> str:
    used = set()
    for ch in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ':
        if os.path.exists(ch + ':\\'):
            used.add(ch)
    for ch in 'DEFGHIJKLMNOPQRSTUVWXYZ':
        if ch not in used:
            return ch
    raise RuntimeError("No free drive letter is available for the USB volume.")


def create_windows_installer_usb(iso_path: str, disk_number: int, expected_model: str,
                                 expected_size: int, dry_run: bool = False) -> str:
    """Create a GPT/FAT32 UEFI Windows installer USB. This erases the selected disk."""
    if os.name != 'nt':
        raise OSError("Bootable USB creation is supported only on Windows.")
    iso_path = os.path.abspath(os.path.expandvars(iso_path.strip().strip('"')))
    if not os.path.isfile(iso_path) or not iso_path.lower().endswith('.iso'):
        raise FileNotFoundError(f"Select an existing Windows ISO: {iso_path}")
    disks = get_windows_physical_disks()
    matches = [d for d in disks if int(d.get('Number', -1)) == int(disk_number)]
    if not matches:
        raise RuntimeError("The selected physical disk is no longer available. Refresh the disk list and try again.")
    disk = matches[0]
    if disk.get('IsBoot') or disk.get('IsSystem'):
        raise RuntimeError("Safety stop: Windows reports this is the boot/system disk. It will not be erased.")
    model = str(disk.get('FriendlyName') or 'Unknown disk')
    size = int(disk.get('Size') or 0)
    if model != expected_model or size != int(expected_size):
        raise RuntimeError("The selected disk identity changed since confirmation. Refresh and confirm again.")
    if size < 8 * 1024**3:
        raise RuntimeError("Choose a USB drive with at least 8 GB. 16 GB or larger is recommended.")
    if dry_run:
        log(f"[USB] Dry-run: would ERASE physical disk {disk_number} ({model}, {size/1024**3:.1f} GB) and create UEFI installer media.")
        return "Dry-run complete; no disk changes made."

    seven_zip = shutil.which('7z') or shutil.which('7za')
    if not seven_zip:
        raise RuntimeError("7-Zip command-line tool (7z.exe) not found on PATH.")
    workspace = os.path.join(ISO_WORK_DIR, f"usb_stage_{int(time.time())}")
    os.makedirs(workspace, exist_ok=False)
    try:
        result = subprocess.run([seven_zip, 'x', iso_path, f'-o{workspace}', '-y'],
                                capture_output=True, text=True, check=False, timeout=7200)
        if result.returncode not in (0, 1) or not os.path.isdir(os.path.join(workspace, 'sources')):
            raise RuntimeError(f"Could not extract a valid Windows ISO: {(result.stderr or result.stdout)[-2000:]}")

        letter = _free_windows_drive_letter()
        # DiskPart only receives a disk number after identity and system-disk checks above.
        script_path = os.path.join(workspace, 'prepare_usb.txt')
        # FAT32 formatting on Windows is most reliable below 32 GB. Use a
        # partition that fits smaller USB devices, and leave excess capacity unused.
        partition_mb = max(4096, min(32000, int(size / (1024 * 1024)) - 256))
        script = (f"select disk {int(disk_number)}\nclean\nconvert gpt\n"
                  f"create partition efi size={partition_mb}\nformat quick fs=fat32 label=DDWINUSB\n"
                  f"assign letter={letter}\nexit\n")
        with open(script_path, 'w', encoding='ascii', newline='\r\n') as f:
            f.write(script)
        dp = subprocess.run(['diskpart.exe', '/s', script_path], capture_output=True, text=True,
                            check=False, timeout=300)
        if dp.returncode != 0:
            raise RuntimeError(f"DiskPart failed; the USB may have been partially changed. {(dp.stderr or dp.stdout)[-2500:]}")
        target = f"{letter}:\\"
        if not os.path.isdir(target):
            raise RuntimeError("DiskPart completed but the assigned USB drive could not be found.")

        # Copy all files except an oversized install.wim, which FAT32 cannot store (>4 GiB).
        src_sources = os.path.join(workspace, 'sources')
        dst_sources = os.path.join(target, 'sources')
        os.makedirs(dst_sources, exist_ok=True)
        install_wim = os.path.join(src_sources, 'install.wim')
        for root, dirs, files in os.walk(workspace):
            rel = os.path.relpath(root, workspace)
            out_root = target if rel == '.' else os.path.join(target, rel)
            os.makedirs(out_root, exist_ok=True)
            for filename in files:
                src = os.path.join(root, filename)
                rel_file = os.path.relpath(src, workspace)
                if rel_file.lower() in ('prepare_usb.txt', 'sources\\install.wim'):
                    continue
                # Split WIM is handled below; do not copy stage artifacts to USB.
                if os.path.getsize(src) > 4 * 1024**3:
                    if rel_file.lower().endswith('install.esd'):
                        raise RuntimeError("This ISO has an install.esd larger than FAT32's 4 GiB limit. Use a trusted media writer or a verified WIM conversion workflow.")
                    raise RuntimeError(f"File exceeds FAT32's 4 GiB limit and cannot be copied as-is: {rel_file}")
                shutil.copy2(src, os.path.join(out_root, filename))

        if os.path.isfile(install_wim) and os.path.getsize(install_wim) >= 4 * 1024**3:
            dism = shutil.which('dism.exe') or os.path.join(os.environ.get('SystemRoot', r'C:\Windows'), 'System32', 'dism.exe')
            if not os.path.isfile(dism) and not shutil.which(dism):
                raise RuntimeError("DISM was not found; cannot split the large install.wim for FAT32.")
            split = subprocess.run([dism, '/Split-Image', f'/ImageFile:{install_wim}',
                                    f'/SWMFile:{os.path.join(dst_sources, "install.swm")}', '/FileSize:3800'],
                                   capture_output=True, text=True, check=False, timeout=7200)
            if split.returncode != 0:
                raise RuntimeError(f"DISM could not split install.wim: {(split.stderr or split.stdout)[-2500:]}")
        elif os.path.isfile(install_wim):
            shutil.copy2(install_wim, os.path.join(dst_sources, 'install.wim'))

        if not os.path.isfile(os.path.join(target, 'efi', 'boot', 'bootx64.efi')):
            raise RuntimeError("USB verification failed: UEFI boot file efi\\boot\\bootx64.efi is missing.")
        if not os.path.isdir(dst_sources):
            raise RuntimeError("USB verification failed: sources directory is missing.")
        log(f"[USB] UEFI Windows installer created on {target}; disk {disk_number} was erased.")
        shutil.rmtree(workspace, ignore_errors=True)
        return f"Bootable UEFI Windows installer created on {target}. You can safely eject it after file operations finish."
    finally:
        # Keep stage files for diagnostics only when an exception occurred; otherwise remove them.
        pass


# -----------------------------
# GUI: CONTROL CENTER (NETWORK & IT)
# -----------------------------

class CredentialTransferDialog(QtWidgets.QDialog):
    """User-managed credential transfer. Secrets are never logged or auto-harvested."""
    FORMAT_NAME = "DominionDeckEncryptedCredentialBundle"
    FORMAT_VERSION = 1

    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Knowledge Transfer — Encrypted Credentials")
        self.resize(760, 540)
        self.entries: List[Dict[str, str]] = []
        root = QtWidgets.QVBoxLayout(self)
        warning = QtWidgets.QLabel(
            "Add only credentials you are authorized to transfer. Bundles are encrypted with a passphrase. "
            "This tool does not extract passwords from browsers, Windows Credential Manager, or other apps."
        )
        warning.setWordWrap(True)
        root.addWidget(warning)

        form = QtWidgets.QFormLayout()
        self.service_edit = QtWidgets.QLineEdit()
        self.username_edit = QtWidgets.QLineEdit()
        self.password_edit = QtWidgets.QLineEdit()
        self.password_edit.setEchoMode(QtWidgets.QLineEdit.EchoMode.Password)
        self.notes_edit = QtWidgets.QLineEdit()
        form.addRow("Service / system", self.service_edit)
        form.addRow("Username", self.username_edit)
        form.addRow("Password / secret", self.password_edit)
        form.addRow("Notes (optional)", self.notes_edit)
        root.addLayout(form)

        row = QtWidgets.QHBoxLayout()
        self.add_btn = QtWidgets.QPushButton("Add Credential")
        self.remove_btn = QtWidgets.QPushButton("Remove Selected")
        self.import_btn = QtWidgets.QPushButton("Import Encrypted Bundle…")
        self.export_btn = QtWidgets.QPushButton("Export Encrypted Bundle…")
        self.add_btn.clicked.connect(self.add_entry)
        self.remove_btn.clicked.connect(self.remove_selected)
        self.import_btn.clicked.connect(self.import_bundle)
        self.export_btn.clicked.connect(self.export_bundle)
        for b in (self.add_btn, self.remove_btn, self.import_btn, self.export_btn):
            row.addWidget(b)
        root.addLayout(row)

        self.table = QtWidgets.QTableWidget(0, 3)
        self.table.setHorizontalHeaderLabels(["Service / system", "Username", "Notes"])
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.setEditTriggers(QtWidgets.QAbstractItemView.EditTrigger.NoEditTriggers)
        root.addWidget(self.table, 1)
        close_row = QtWidgets.QHBoxLayout()
        close_row.addStretch()
        close_btn = QtWidgets.QPushButton("Close")
        close_btn.clicked.connect(self.accept)
        close_row.addWidget(close_btn)
        root.addLayout(close_row)

    @staticmethod
    def _crypto():
        try:
            from cryptography.fernet import Fernet
            from cryptography.hazmat.primitives import hashes
            from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
            import base64
            return Fernet, hashes, PBKDF2HMAC, base64
        except ImportError as exc:
            raise RuntimeError(
                "Encrypted credential transfer requires the 'cryptography' package. Install it with:\n"
                f'"{sys.executable}" -m pip install cryptography'
            ) from exc

    def _refresh_table(self):
        self.table.setRowCount(len(self.entries))
        for i, item in enumerate(self.entries):
            for col, key in enumerate(("service", "username", "notes")):
                self.table.setItem(i, col, QtWidgets.QTableWidgetItem(item.get(key, "")))

    def add_entry(self):
        service = self.service_edit.text().strip()
        username = self.username_edit.text().strip()
        secret = self.password_edit.text()
        if not service or not username or not secret:
            QtWidgets.QMessageBox.warning(self, "Missing fields", "Service, username, and password/secret are required.")
            return
        self.entries.append({"service": service, "username": username, "secret": secret,
                             "notes": self.notes_edit.text().strip()})
        self._refresh_table()
        self.service_edit.clear(); self.username_edit.clear(); self.password_edit.clear(); self.notes_edit.clear()

    def remove_selected(self):
        rows = sorted({idx.row() for idx in self.table.selectionModel().selectedRows()}, reverse=True)
        for row in rows:
            if 0 <= row < len(self.entries):
                self.entries.pop(row)
        self._refresh_table()

    def export_bundle(self):
        if not self.entries:
            QtWidgets.QMessageBox.information(self, "No credentials", "Add or import credentials first.")
            return
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Save encrypted credential bundle", "DominionDeck_Credentials.ddcred", "Encrypted credential bundle (*.ddcred)")
        if not path:
            return
        passphrase, ok = QtWidgets.QInputDialog.getText(self, "Bundle passphrase", "Create a strong passphrase (12+ characters):", QtWidgets.QLineEdit.EchoMode.Password)
        if not ok:
            return
        if len(passphrase) < 12:
            QtWidgets.QMessageBox.warning(self, "Passphrase too short", "Use at least 12 characters. A longer unique passphrase is safer.")
            return
        confirm, ok = QtWidgets.QInputDialog.getText(self, "Confirm passphrase", "Re-enter the bundle passphrase:", QtWidgets.QLineEdit.EchoMode.Password)
        if not ok:
            return
        if passphrase != confirm:
            QtWidgets.QMessageBox.warning(self, "Passphrases differ", "The passphrases do not match.")
            return
        try:
            Fernet, hashes, PBKDF2HMAC, base64 = self._crypto()
            import secrets
            salt = secrets.token_bytes(16)
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=600_000)
            key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
            payload = json.dumps({"version": self.FORMAT_VERSION, "entries": self.entries}, ensure_ascii=False).encode("utf-8")
            token = Fernet(key).encrypt(payload)
            wrapper = {"format": self.FORMAT_NAME, "version": self.FORMAT_VERSION,
                       "kdf": "PBKDF2-HMAC-SHA256", "iterations": 600_000,
                       "salt": base64.b64encode(salt).decode("ascii"),
                       "token": token.decode("ascii")}
            with open(path, "x", encoding="utf-8") as f:
                json.dump(wrapper, f, indent=2)
            QtWidgets.QMessageBox.information(self, "Export complete", "Encrypted credential bundle saved. Transfer the .ddcred file separately and share its passphrase through a different trusted channel. Keep a backup of the passphrase; it cannot be recovered.")
        except FileExistsError:
            QtWidgets.QMessageBox.warning(self, "File exists", "That file already exists. Choose a new filename to avoid accidental overwrite.")
        except Exception as exc:
            QtWidgets.QMessageBox.critical(self, "Export failed", str(exc))

    def import_bundle(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Open encrypted credential bundle", "", "Encrypted credential bundle (*.ddcred);;JSON files (*.json)")
        if not path:
            return
        passphrase, ok = QtWidgets.QInputDialog.getText(self, "Bundle passphrase", "Enter the passphrase used to encrypt this bundle:", QtWidgets.QLineEdit.EchoMode.Password)
        if not ok:
            return
        try:
            Fernet, hashes, PBKDF2HMAC, base64 = self._crypto()
            with open(path, "r", encoding="utf-8") as f:
                wrapper = json.load(f)
            if wrapper.get("format") != self.FORMAT_NAME or wrapper.get("version") != self.FORMAT_VERSION:
                raise ValueError("Unsupported or invalid credential bundle format.")
            iterations = int(wrapper.get("iterations", 600_000))
            if iterations < 100_000 or iterations > 2_000_000:
                raise ValueError("Bundle KDF parameters are outside the accepted safety limits.")
            salt = base64.b64decode(wrapper["salt"], validate=True)
            if len(salt) != 16:
                raise ValueError("Invalid bundle salt.")
            kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=iterations)
            key = base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))
            payload = json.loads(Fernet(key).decrypt(wrapper["token"].encode("ascii")).decode("utf-8"))
            entries = payload.get("entries")
            if payload.get("version") != self.FORMAT_VERSION or not isinstance(entries, list):
                raise ValueError("Credential payload is malformed.")
            clean = []
            for item in entries:
                if not isinstance(item, dict) or not all(isinstance(item.get(k, ""), str) for k in ("service", "username", "secret", "notes")):
                    raise ValueError("Credential entry has an invalid structure.")
                if not item.get("service") or not item.get("username") or not item.get("secret"):
                    raise ValueError("Credential entry is missing a required field.")
                clean.append({k: item.get(k, "") for k in ("service", "username", "secret", "notes")})
            self.entries.extend(clean)
            self._refresh_table()
            QtWidgets.QMessageBox.information(self, "Import complete", f"Imported {len(clean)} credential record(s) into this session. They remain in memory until you close the dialog; export again to create an encrypted bundle for this PC.")
        except Exception:
            # Do not reveal or log decrypted material; generic error also covers invalid passphrases.
            QtWidgets.QMessageBox.critical(self, "Import failed", "Could not decrypt or validate this bundle. Check the passphrase and ensure the file is a valid DominionDeck bundle.")


class ControlCenter(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DominionDeck Windows ISO Orchestrator — Network & IT Edition")
        self.resize(1280, 760)

        self.profiles: List[Profile] = load_profiles()
        self.selected_profile: Optional[Profile] = self.profiles[0] if self.profiles else None
        self.base_iso_path: str = ""
        self.output_iso_path: str = os.path.join(BASE_DIR, "DD_Custom_Windows.iso")
        self.master_bundle: Optional[Dict[str, Any]] = load_master_bundle()
        self.dry_run: bool = False

        self.component_checkboxes: Dict[str, QtWidgets.QCheckBox] = {}
        self.group_checkboxes: Dict[str, QtWidgets.QCheckBox] = {}

        self.deploy_server = DeployServer()
        self.deploy_server.start()
        self.dist_server = start_https_distribution_server()

        self._build_ui()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        root_layout = QtWidgets.QVBoxLayout(central)
        tabs = QtWidgets.QTabWidget()
        root_layout.addWidget(tabs)

        # Left panel: profile, ISO, actions
        left_panel = QtWidgets.QVBoxLayout()

        self.profile_combo = QtWidgets.QComboBox()
        for p in self.profiles:
            self.profile_combo.addItem(f"{p.name} ({p.type}/{p.region})", userData=p)
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed)
        left_panel.addWidget(QtWidgets.QLabel("Profile"))
        left_panel.addWidget(self.profile_combo)

        self.net_preset_combo = QtWidgets.QComboBox()
        for name in NETWORK_PRESETS.keys():
            self.net_preset_combo.addItem(name)
        self.net_preset_combo.currentIndexChanged.connect(self.on_net_preset_changed)
        left_panel.addWidget(QtWidgets.QLabel("Network Preset (Site / VLAN / IP)"))
        left_panel.addWidget(self.net_preset_combo)

        self.base_iso_edit = QtWidgets.QLineEdit()
        self.base_iso_btn = QtWidgets.QPushButton("Browse Base ISO...")
        self.base_iso_btn.clicked.connect(self.on_browse_iso)
        left_panel.addWidget(QtWidgets.QLabel("Base Windows ISO"))
        left_panel.addWidget(self.base_iso_edit)
        left_panel.addWidget(self.base_iso_btn)

        self.output_iso_edit = QtWidgets.QLineEdit(self.output_iso_path)
        left_panel.addWidget(QtWidgets.QLabel("Output ISO Path"))
        left_panel.addWidget(self.output_iso_edit)

        self.dry_run_checkbox = QtWidgets.QCheckBox("Dry-run (simulate, no disk changes)")
        self.dry_run_checkbox.stateChanged.connect(self.on_dry_run_changed)
        left_panel.addWidget(self.dry_run_checkbox)

        self.post_script_edit = QtWidgets.QLineEdit()
        self.post_script_btn = QtWidgets.QPushButton("Browse Post-Install PowerShell Script...")
        self.post_script_btn.clicked.connect(self.on_browse_post_script)
        left_panel.addWidget(QtWidgets.QLabel("Post-Install Script (PowerShell)"))
        left_panel.addWidget(self.post_script_edit)
        left_panel.addWidget(self.post_script_btn)

        self.usb_iso_edit = QtWidgets.QLineEdit(self.output_iso_path)
        self.usb_drive_edit = QtWidgets.QLineEdit("E:\\")
        self.usb_create_btn = QtWidgets.QPushButton("Copy ISO Files to Existing Drive (not bootable)")
        self.usb_create_btn.clicked.connect(self.on_create_usb)
        left_panel.addWidget(QtWidgets.QLabel("USB Creator (ISO -> USB)"))
        left_panel.addWidget(QtWidgets.QLabel("ISO Path"))
        left_panel.addWidget(self.usb_iso_edit)
        left_panel.addWidget(QtWidgets.QLabel("USB Drive (e.g., E:\\)"))
        left_panel.addWidget(self.usb_drive_edit)
        left_panel.addWidget(self.usb_create_btn)

        self.workspace_btn = QtWidgets.QPushButton("Build Local Windows ISO Workspace…")
        self.workspace_btn.setToolTip("Extract a Windows ISO into a chosen local folder. Does not modify or install Windows.")
        self.workspace_btn.clicked.connect(self.on_build_local_workspace)
        left_panel.addWidget(self.workspace_btn)

        self.boot_usb_btn = QtWidgets.QPushButton("Build Bootable Windows Installer USB…")
        self.boot_usb_btn.setToolTip("Create a UEFI installer USB. The selected physical disk will be erased after explicit confirmation.")
        self.boot_usb_btn.clicked.connect(self.on_build_bootable_usb)
        left_panel.addWidget(self.boot_usb_btn)

        self.btn_build_master = QtWidgets.QPushButton("Build Master Bundle from This Machine (Filtered by Profile)")
        self.btn_build_master.clicked.connect(self.on_build_master)

        self.btn_generate_iso = QtWidgets.QPushButton("Generate Custom ISO (Use Existing Bundle)")
        self.btn_generate_iso.clicked.connect(self.on_generate_iso)

        self.btn_build_iso_from_machine = QtWidgets.QPushButton("Build ISO from This Machine (Snapshot + ISO)")
        self.btn_build_iso_from_machine.clicked.connect(self.on_build_iso_from_machine)

        self.btn_clone_wizard = QtWidgets.QPushButton("Clone This Machine Wizard")
        self.btn_clone_wizard.clicked.connect(self.on_clone_wizard)

        left_panel.addWidget(self.btn_build_master)
        left_panel.addWidget(self.btn_generate_iso)
        left_panel.addWidget(self.btn_build_iso_from_machine)
        left_panel.addWidget(self.btn_clone_wizard)

        self.btn_export_profiles = QtWidgets.QPushButton("Export Profiles...")
        self.btn_export_profiles.clicked.connect(self.on_export_profiles)
        self.btn_import_profiles = QtWidgets.QPushButton("Import Profiles...")
        self.btn_import_profiles.clicked.connect(self.on_import_profiles)
        left_panel.addWidget(self.btn_export_profiles)
        left_panel.addWidget(self.btn_import_profiles)

        self.btn_knowledge_transfer = QtWidgets.QPushButton("Knowledge Transfer — Credentials…")
        self.btn_knowledge_transfer.setToolTip("Manually manage and transfer selected credentials in a passphrase-encrypted bundle.")
        self.btn_knowledge_transfer.clicked.connect(self.on_knowledge_transfer)
        left_panel.addWidget(self.btn_knowledge_transfer)

        left_panel.addStretch()

        middle_panel = QtWidgets.QVBoxLayout()
        middle_panel.addWidget(QtWidgets.QLabel("Windows Components (select exactly what to install)"))

        group_container = QtWidgets.QWidget()
        group_layout = QtWidgets.QHBoxLayout(group_container)
        self.group_checkboxes.clear()
        for group_name, comp_ids in COMPONENT_GROUPS.items():
            cb = QtWidgets.QCheckBox(group_name)
            cb.stateChanged.connect(self.on_group_toggle)
            self.group_checkboxes[group_name] = cb
            group_layout.addWidget(cb)
        middle_panel.addWidget(group_container)

        comp_scroll = QtWidgets.QScrollArea()
        comp_scroll.setWidgetResizable(True)
        comp_container = QtWidgets.QWidget()
        comp_layout = QtWidgets.QVBoxLayout(comp_container)

        self.component_checkboxes.clear()
        for comp in WINDOWS_COMPONENT_CATALOG:
            cb = QtWidgets.QCheckBox(f"{comp['name']} [{comp['category']}]")
            cb.setObjectName(comp["id"])
            self.component_checkboxes[comp["id"]] = cb
            comp_layout.addWidget(cb)

        comp_layout.addStretch()
        comp_scroll.setWidget(comp_container)
        middle_panel.addWidget(comp_scroll)

        right_panel = QtWidgets.QVBoxLayout()
        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        right_panel.addWidget(QtWidgets.QLabel("Log Output"))
        right_panel.addWidget(self.log_view)

        self.status_label = QtWidgets.QLabel("Ready.")
        right_panel.addWidget(self.status_label)

        self.clients_view = QtWidgets.QTableWidget()
        self.clients_view.setColumnCount(4)
        self.clients_view.setHorizontalHeaderLabels(["Address", "Hostname", "Profile", "State"])
        self.clients_view.horizontalHeader().setStretchLastSection(True)
        right_panel.addWidget(QtWidgets.QLabel("Deployment Clients (waiting / connected / installing)"))
        right_panel.addWidget(self.clients_view)

        actions_page = QtWidgets.QWidget()
        actions_page.setLayout(left_panel)
        components_page = QtWidgets.QWidget()
        components_page.setLayout(middle_panel)
        monitoring_page = QtWidgets.QWidget()
        monitoring_page.setLayout(right_panel)
        tabs.addTab(actions_page, "Profiles & Actions")
        tabs.addTab(components_page, "Windows Components")
        tabs.addTab(monitoring_page, "Logs & Deployment")
        self.setCentralWidget(central)

        self.log_timer = QtCore.QTimer()
        self.log_timer.timeout.connect(self.refresh_log_view)
        self.log_timer.start(2000)

        self.clients_timer = QtCore.QTimer()
        self.clients_timer.timeout.connect(self.refresh_clients_view)
        self.clients_timer.start(2000)

        self.apply_profile_to_ui()
        generate_pxe_boot_menu()

    def on_knowledge_transfer(self):
        dialog = CredentialTransferDialog(self)
        dialog.exec()

    def refresh_log_view(self):
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    content = f.readlines()[-2000:]
                self.log_view.setPlainText("".join(content))
                self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())
        except Exception:
            pass

    def refresh_clients_view(self):
        statuses = self.deploy_server.get_client_statuses()
        self.clients_view.setRowCount(len(statuses))
        for row, st in enumerate(statuses):
            self.clients_view.setItem(row, 0, QtWidgets.QTableWidgetItem(st.address))
            self.clients_view.setItem(row, 1, QtWidgets.QTableWidgetItem(st.hostname))
            self.clients_view.setItem(row, 2, QtWidgets.QTableWidgetItem(st.profile_name))
            self.clients_view.setItem(row, 3, QtWidgets.QTableWidgetItem(st.state))

    def on_profile_changed(self, idx: int):
        data = self.profile_combo.itemData(idx)
        if isinstance(data, Profile):
            self.selected_profile = data
            self.status_label.setText(f"Selected profile: {data.name}")
            self.apply_profile_to_ui()

    def on_net_preset_changed(self, idx: int):
        name = self.net_preset_combo.itemText(idx)
        if self.selected_profile:
            self.selected_profile.network_preset_name = name
            self.selected_profile.network_preset = NETWORK_PRESETS.get(name, {})
            save_profile(self.selected_profile)
            self.status_label.setText(f"Network preset set to: {name}")

    def apply_profile_to_ui(self):
        if not self.selected_profile:
            return
        selected_ids = set(self.selected_profile.selected_components or [])
        for comp_id, cb in self.component_checkboxes.items():
            cb.setChecked(comp_id in selected_ids)
        for group_name, comp_ids in COMPONENT_GROUPS.items():
            self.group_checkboxes[group_name].setChecked(all(cid in selected_ids for cid in comp_ids))
        preset_name = self.selected_profile.network_preset_name
        idx = self.net_preset_combo.findText(preset_name)
        if idx >= 0:
            self.net_preset_combo.setCurrentIndex(idx)
        self.post_script_edit.setText(self.selected_profile.post_install_script or "")

    def collect_components_from_ui(self) -> List[str]:
        selected = []
        for comp_id, cb in self.component_checkboxes.items():
            if cb.isChecked():
                selected.append(comp_id)
        return selected

    def on_group_toggle(self, state: int):
        sender = self.sender()
        if not sender:
            return
        group_name = sender.text()
        comp_ids = COMPONENT_GROUPS.get(group_name, [])
        for cid in comp_ids:
            if cid in self.component_checkboxes:
                self.component_checkboxes[cid].setChecked(state == QtCore.Qt.CheckState.Checked)

    def on_browse_iso(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Base Windows ISO", "", "ISO Files (*.iso)")
        if path:
            self.base_iso_path = path
            self.base_iso_edit.setText(path)
            self.status_label.setText(f"Base ISO selected: {path}")

    def on_dry_run_changed(self, state: int):
        self.dry_run = (state == QtCore.Qt.CheckState.Checked)
        self.status_label.setText(f"Dry-run mode: {'ON' if self.dry_run else 'OFF'}")

    def on_browse_post_script(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Post-Install PowerShell Script", "", "PS1 Files (*.ps1)")
        if path and self.selected_profile:
            self.post_script_edit.setText(path)
            self.selected_profile.post_install_script = path
            save_profile(self.selected_profile)
            self.status_label.setText(f"Post-install script set: {path}")

    def on_build_local_workspace(self):
        iso_path = self.base_iso_edit.text().strip() or self.usb_iso_edit.text().strip()
        if not iso_path:
            iso_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Windows ISO", "", "ISO Files (*.iso)")
        if not iso_path:
            return
        destination = QtWidgets.QFileDialog.getExistingDirectory(self, "Choose an empty local workspace folder", BASE_DIR)
        if not destination:
            return
        try:
            result = create_local_windows_workspace(iso_path, destination, dry_run=self.dry_run)
            self.status_label.setText(f"Local Windows workspace ready: {result}")
            QtWidgets.QMessageBox.information(self, "Workspace", f"{result}\n\nThis is extracted installation media, not a fully installed portable Windows system.")
        except Exception as exc:
            log(f"[WORKSPACE] Failed: {exc}", "ERROR")
            QtWidgets.QMessageBox.critical(self, "Workspace failed", str(exc))

    def on_build_bootable_usb(self):
        iso_path = self.base_iso_edit.text().strip() or self.usb_iso_edit.text().strip()
        if not iso_path:
            iso_path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Windows ISO", "", "ISO Files (*.iso)")
        if not iso_path:
            return
        try:
            disks = get_windows_physical_disks()
            candidates = [d for d in disks if not d.get('IsBoot') and not d.get('IsSystem') and int(d.get('Size') or 0) >= 8*1024**3]
            if not candidates:
                raise RuntimeError("No eligible non-system physical disk of at least 8 GB was found. Connect the USB drive and refresh.")
            labels = []
            for d in candidates:
                size_gb = int(d.get('Size') or 0) / 1024**3
                labels.append(f"Disk {d.get('Number')}: {d.get('FriendlyName') or 'Unknown'} — {size_gb:.1f} GB — {d.get('BusType') or 'Unknown bus'} — {d.get('PartitionStyle') or 'RAW'}")
            chosen, ok = QtWidgets.QInputDialog.getItem(self, "Select USB physical disk", "WARNING: selected disk will be erased. Choose by disk number/model/size:", labels, 0, False)
            if not ok or not chosen:
                return
            idx = labels.index(chosen)
            disk = candidates[idx]
            if self.dry_run:
                confirm = QtWidgets.QMessageBox.question(self, "Confirm dry-run", f"Simulate preparing Disk {disk.get('Number')} ({disk.get('FriendlyName')}, {int(disk.get('Size') or 0)/1024**3:.1f} GB)? No disk changes will be made.")
                if confirm != QtWidgets.QMessageBox.StandardButton.Yes:
                    return
            else:
                warning = (f"THIS ERASES ALL DATA on physical Disk {disk.get('Number')}.\n\n"
                           f"Model: {disk.get('FriendlyName')}\nSerial: {disk.get('SerialNumber') or 'not reported'}\n"
                           f"Size: {int(disk.get('Size') or 0)/1024**3:.1f} GB\nBus: {disk.get('BusType')}\n\n"
                           "Disconnect other external drives. The tool will refuse to erase Windows boot/system disks. "
                           "This creates UEFI Windows INSTALLATION media; it does not create a portable Windows-to-Go system.")
                answer = QtWidgets.QMessageBox.warning(self, "Destructive USB operation", warning,
                    QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.Cancel,
                    QtWidgets.QMessageBox.StandardButton.Cancel)
                if answer != QtWidgets.QMessageBox.StandardButton.Yes:
                    return
                phrase, ok = QtWidgets.QInputDialog.getText(self, "Final confirmation", f"Type ERASE DISK {disk.get('Number')} to continue:")
                if not ok or phrase.strip() != f"ERASE DISK {disk.get('Number')}":
                    QtWidgets.QMessageBox.information(self, "Cancelled", "Disk preparation cancelled; no disk changes were requested.")
                    return
            self.status_label.setText("Preparing bootable Windows USB… do not unplug the drive.")
            QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
            result = create_windows_installer_usb(iso_path, int(disk.get('Number')), str(disk.get('FriendlyName') or 'Unknown disk'), int(disk.get('Size') or 0), dry_run=self.dry_run)
            self.status_label.setText(result)
            QtWidgets.QMessageBox.information(self, "Windows USB", result)
        except Exception as exc:
            log(f"[USB] Bootable USB creation failed: {exc}", "ERROR")
            QtWidgets.QMessageBox.critical(self, "USB creation failed", str(exc))
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()

    def on_create_usb(self):
        iso_path = self.usb_iso_edit.text().strip()
        usb_drive = self.usb_drive_edit.text().strip()
        if not self.dry_run:
            answer = QtWidgets.QMessageBox.warning(
                self, "Confirm ISO file copy",
                f"Copy ISO contents into {usb_drive}? Existing files with matching names may be overwritten. "
                "This does not format the drive or guarantee bootability.",
                QtWidgets.QMessageBox.StandardButton.Yes | QtWidgets.QMessageBox.StandardButton.Cancel,
                QtWidgets.QMessageBox.StandardButton.Cancel
            )
            if answer != QtWidgets.QMessageBox.StandardButton.Yes:
                return
        self.status_label.setText("Copying ISO files...")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
        try:
            create_bootable_usb(iso_path, usb_drive, dry_run=self.dry_run)
            self.status_label.setText("ISO file copy completed; use a boot-media writer if bootability is required.")
        except Exception as e:
            traceback.print_exc()
            self.status_label.setText(f"Error creating USB: {e}")
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()

    def on_build_master(self):
        if not self.selected_profile:
            self.status_label.setText("No profile selected.")
            return
        self.status_label.setText("Building master bundle (filtered by profile)...")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
        try:
            self.master_bundle = build_master_profile_bundle(self.selected_profile)
            self.status_label.setText("Master bundle built successfully.")
        except Exception as e:
            traceback.print_exc()
            self.status_label.setText(f"Error building master bundle: {e}")
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()

    def _run_iso_pipeline(self, bundle: Dict[str, Any]):
        if not self.selected_profile:
            self.status_label.setText("No profile selected.")
            return
        if not self.base_iso_edit.text():
            self.status_label.setText("No base ISO selected.")
            return

        self.selected_profile.selected_components = self.collect_components_from_ui()
        self.selected_profile.post_install_script = self.post_script_edit.text().strip()
        save_profile(self.selected_profile)

        self.base_iso_path = self.base_iso_edit.text()
        self.output_iso_path = self.output_iso_edit.text() or self.output_iso_path

        self.status_label.setText("Generating custom ISO...")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)

        try:
            unattend_path = generate_unattend_xml(self.selected_profile, bundle)

            iso_mgr = ISOManager(
                base_iso=self.base_iso_path,
                output_iso=self.output_iso_path,
                work_dir=ISO_WORK_DIR,
                dry_run=self.dry_run
            )

            ctx = PluginContext(
                config={"master_bundle": bundle, "profile": self.selected_profile.to_dict()},
                profile_name=self.selected_profile.name,
                base_iso_path=self.base_iso_path,
                output_iso_path=self.output_iso_path,
                work_dir=ISO_WORK_DIR,
                dry_run=self.dry_run
            )

            for plugin in PLUGIN_REGISTRY:
                plugin.run_before_iso_mount(ctx)

            iso_mgr.extract_iso()

            for plugin in PLUGIN_REGISTRY:
                plugin.run_after_iso_mount(ctx)

            install_wim = os.path.join(iso_mgr.mount_dir, "sources", "install.wim")
            dism_mount_dir = os.path.join(ISO_WORK_DIR, "dism_mount")
            os.makedirs(dism_mount_dir, exist_ok=True)
            dism_mgr = DISMManager(
                wim_path=install_wim,
                index=1,
                mount_dir=dism_mount_dir,
                dry_run=self.dry_run
            )
            dism_mgr.mount()
            enforce_components_with_dism(dism_mgr, self.selected_profile)
            inject_drivers_with_dism(dism_mgr, bundle)
            dism_mgr.unmount(commit=True)

            iso_mgr.inject_unattend(unattend_path)
            iso_mgr.inject_bundle_and_profile(bundle, self.selected_profile)
            iso_mgr.inject_selected_components_manifest(self.selected_profile)
            iso_mgr.inject_post_install_script(self.selected_profile)
            iso_mgr.inject_post_install_scheduler()
            inject_wifi_profiles_into_image(iso_mgr.mount_dir, dry_run=self.dry_run)

            for plugin in PLUGIN_REGISTRY:
                plugin.run_before_iso_build(ctx)

            iso_mgr.build_iso()
            if not self.dry_run:
                publish_iso_for_distribution(self.output_iso_path)

            for plugin in PLUGIN_REGISTRY:
                plugin.run_after_iso_build(ctx)

            self.status_label.setText(
                f"{'Dry-run ' if self.dry_run else ''}Custom ISO generated: {self.output_iso_path}"
            )
        except Exception as e:
            traceback.print_exc()
            self.status_label.setText(f"Error generating ISO: {e}")
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()

    def on_generate_iso(self):
        if not self.master_bundle:
            self.status_label.setText("No master bundle. Build it first or use 'Build ISO from This Machine'.")
            return
        self._run_iso_pipeline(self.master_bundle)

    def on_build_iso_from_machine(self):
        if not self.selected_profile:
            self.status_label.setText("No profile selected.")
            return
        self.status_label.setText("Snapshotting current machine and building ISO...")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
        try:
            bundle = build_master_profile_bundle(self.selected_profile)
            self.master_bundle = bundle
            self._run_iso_pipeline(bundle)
        except Exception as e:
            traceback.print_exc()
            self.status_label.setText(f"Error building ISO from this machine: {e}")
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()

    def on_clone_wizard(self):
        QtWidgets.QMessageBox.information(
            self,
            "Clone This Machine Wizard",
            "Step 1: Select profile (Gov/Enterprise/Branch/Lab).\n"
            "Step 2: Select network preset (HQ/Branch/Lab/DMZ).\n"
            "Step 3: Select base ISO.\n"
            "Step 4: Adjust components and optional post-install script.\n"
            "Step 5: Click 'Build ISO from This Machine'.\n\n"
            "Result: ISO with profile/component manifests, driver payloads, and an optional script. Network settings are recorded for post-install configuration; installed apps are inventoried, not automatically reinstalled."
        )

    def on_export_profiles(self):
        path, _ = QtWidgets.QFileDialog.getSaveFileName(self, "Export Profiles", "", "JSON Files (*.json)")
        if path:
            export_profiles(path)
            self.status_label.setText(f"Profiles exported to {path}")

    def on_import_profiles(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Import Profiles", "", "JSON Files (*.json)")
        if path:
            import_profiles(path)
            self.profiles = load_profiles()
            self.profile_combo.clear()
            for p in self.profiles:
                self.profile_combo.addItem(f"{p.name} ({p.type}/{p.region})", userData=p)
            self.status_label.setText(f"Profiles imported from {path}")

    def closeEvent(self, event: QtGui.QCloseEvent):
        self.deploy_server.stop()
        super().closeEvent(event)

# -----------------------------
# CLI MODE
# -----------------------------

def run_cli(args: List[str]):
    import argparse
    parser = argparse.ArgumentParser(description="DominionDeck ISO Orchestrator CLI")
    parser.add_argument("--profile", required=True, help="Profile name")
    parser.add_argument("--base_iso", required=True, help="Base Windows ISO path")
    parser.add_argument("--out_iso", required=True, help="Output ISO path")
    parser.add_argument("--dry_run", action="store_true", help="Dry-run mode")
    parsed = parser.parse_args(args)

    profiles = load_profiles()
    profile = next((p for p in profiles if p.name == parsed.profile), None)
    if not profile:
        log(f"[CLI] Profile not found: {parsed.profile}", "ERROR")
        return

    bundle = build_master_profile_bundle(profile)
    unattend_path = generate_unattend_xml(profile, bundle)

    iso_mgr = ISOManager(
        base_iso=parsed.base_iso,
        output_iso=parsed.out_iso,
        work_dir=ISO_WORK_DIR,
        dry_run=parsed.dry_run
    )

    ctx = PluginContext(
        config={"master_bundle": bundle, "profile": profile.to_dict()},
        profile_name=profile.name,
        base_iso_path=parsed.base_iso,
        output_iso_path=parsed.out_iso,
        work_dir=ISO_WORK_DIR,
        dry_run=parsed.dry_run
    )

    for plugin in PLUGIN_REGISTRY:
        plugin.run_before_iso_mount(ctx)

    iso_mgr.extract_iso()

    for plugin in PLUGIN_REGISTRY:
        plugin.run_after_iso_mount(ctx)

    install_wim = os.path.join(iso_mgr.mount_dir, "sources", "install.wim")
    dism_mount_dir = os.path.join(ISO_WORK_DIR, "dism_mount_cli")
    os.makedirs(dism_mount_dir, exist_ok=True)
    dism_mgr = DISMManager(
        wim_path=install_wim,
        index=1,
        mount_dir=dism_mount_dir,
        dry_run=parsed.dry_run
    )
    dism_mgr.mount()
    enforce_components_with_dism(dism_mgr, profile)
    inject_drivers_with_dism(dism_mgr, bundle)
    dism_mgr.unmount(commit=True)

    iso_mgr.inject_unattend(unattend_path)
    iso_mgr.inject_bundle_and_profile(bundle, profile)
    iso_mgr.inject_selected_components_manifest(profile)
    iso_mgr.inject_post_install_script(profile)
    iso_mgr.inject_post_install_scheduler()
    inject_wifi_profiles_into_image(iso_mgr.mount_dir, dry_run=parsed.dry_run)

    for plugin in PLUGIN_REGISTRY:
        plugin.run_before_iso_build(ctx)

    iso_mgr.build_iso()
    if not parsed.dry_run:
        publish_iso_for_distribution(parsed.out_iso)

    for plugin in PLUGIN_REGISTRY:
        plugin.run_after_iso_build(ctx)

    log(f"[CLI] {'Dry-run ' if parsed.dry_run else ''}ISO build complete: {parsed.out_iso}")

# -----------------------------
# MAIN
# -----------------------------

def main():
    set_log_level("INFO")
    log("[MAIN] DominionDeck Windows ISO Orchestrator starting.")
    watchdog = Watchdog(interval=5.0)
    watchdog.start()

    if "--cli" in sys.argv:
        idx = sys.argv.index("--cli")
        cli_args = sys.argv[idx + 1:]
        try:
            run_cli(cli_args)
        finally:
            watchdog.stop()
        return

    app = QtWidgets.QApplication(sys.argv)
    win = ControlCenter()
    win.show()
    ret = app.exec()

    watchdog.stop()
    sys.exit(ret)

if __name__ == "__main__":
    main()
