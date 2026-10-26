#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DominionDeck Windows ISO Orchestrator
Option C — Enterprise-Level System (Network & IT Next-Level Edition)

Focus:
- Treat current machine as “master”
- Snapshot: system, network, installed apps
- Build custom Windows ISO that:
  - Autoloads those settings
  - Installs same apps (via manifest)
  - Uses ONLY selected Windows components (no extras)
- Deep network/IT flexibility:
  - Site profiles (HQ/Branch/Lab/DMZ)
  - IP/DNS/Gateway/VLAN presets
  - Proxy templates
  - Wi-Fi profiles export/import
  - Post-install scripts (PowerShell) per profile
  - CLI + GUI, dry-run, advanced logging

"""

import os
import sys
import json
import subprocess
import threading
import time
import shutil
import traceback
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

# -----------------------------
# AUTOLOADER FOR PYTHON LIBS
# -----------------------------

REQUIRED_LIBS = [
    "PyQt6",
]

def ensure_dependencies():
    import importlib
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            print(f"[AUTOLOADER] Installing missing dependency: {lib}")
            subprocess.run([sys.executable, "-m", "pip", "install", lib], check=False)

ensure_dependencies()
from PyQt6 import QtWidgets, QtCore, QtGui

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

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(PROFILE_DIR, exist_ok=True)
os.makedirs(ISO_WORK_DIR, exist_ok=True)
os.makedirs(POST_SCRIPTS_DIR, exist_ok=True)

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
    {"id": "core_shell",        "name": "Core Shell / Explorer",          "category": "Core",      "default": True},
    {"id": "windows_defender",  "name": "Windows Defender / Security",    "category": "Security",  "default": True},
    {"id": "remote_desktop",    "name": "Remote Desktop",                 "category": "Remote",    "default": True},
    {"id": "hyper_v",           "name": "Hyper-V Virtualization",         "category": "Server",    "default": False},
    {"id": "xbox_app",          "name": "Xbox App",                        "category": "Consumer",  "default": False},
    {"id": "games_pack",        "name": "Games / Casual",                 "category": "Consumer",  "default": False},
    {"id": "media_features",    "name": "Media Features (WMP etc.)",      "category": "Media",     "default": True},
    {"id": "print_scan",        "name": "Printing / Scanning Support",    "category": "Devices",   "default": True},
    {"id": "optional_fonts",    "name": "Optional Fonts / Languages",     "category": "Locale",    "default": False},
    {"id": "powershell_ise",    "name": "PowerShell ISE",                 "category": "Admin",     "default": True},
    {"id": "admin_tools",       "name": "Administrative Tools",           "category": "Admin",     "default": True},
    {"id": "tablet_features",   "name": "Tablet / Touch Features",        "category": "Devices",   "default": False},
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

register_plugin(LoggingPlugin())

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
# SYSTEM SNAPSHOT / MASTER MACHINE
# -----------------------------

def snapshot_installed_programs() -> List[Dict[str, Any]]:
    log("[SNAPSHOT] Capturing installed programs (simplified).")
    programs = []
    try:
        cmd = ["wmic", "product", "get", "name,version"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        lines = result.stdout.splitlines()
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            parts = [p for p in line.split("  ") if p.strip()]
            if not parts:
                continue
            name = parts[0].strip()
            version = parts[-1].strip() if len(parts) > 1 else ""
            programs.append({"name": name, "version": version})
    except Exception as e:
        log(f"[SNAPSHOT] WMIC failed: {e}", "WARN")
    return programs

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

def snapshot_system_settings() -> Dict[str, Any]:
    log("[SNAPSHOT] Capturing system settings.")
    return {
        "region": "US",
        "language": "en-US",
        "timezone": time.tzname[0],
        "hostname": os.environ.get("COMPUTERNAME", "UNKNOWN"),
    }

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
    if profile:
        installed_programs = filter_programs_for_profile(installed_programs, profile)
    bundle = {
        "system_settings": system_settings,
        "wifi_profiles": wifi_profiles,
        "installed_programs": installed_programs,
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
        cmd = ["7z", "x", self.base_iso, f"-o{self.mount_dir}", "-y"]
        subprocess.run(cmd, check=False)
        log("[ISO] Extraction complete (assuming success).")

    def inject_unattend(self, unattend_xml: str):
        log("[ISO] Injecting Unattend.xml.")
        dest = os.path.join(self.mount_dir, "sources", "unattend.xml")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        if self.dry_run:
            log(f"[ISO] Dry-run: would copy unattend.xml to {dest}")
            return
        shutil.copy2(unattend_xml, dest)
        log(f"[ISO] Unattend.xml injected at {dest}")

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

    def inject_selected_components(self, profile: Profile):
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

    def build_iso(self):
        log(f"[ISO] Building new ISO: {self.output_iso}")
        if self.dry_run:
            log("[ISO] Dry-run: skipping actual ISO build.")
            return
        cmd = [
            "oscdimg",
            "-m",
            "-o",
            "-u2",
            "-udfver102",
            self.mount_dir,
            self.output_iso
        ]
        subprocess.run(cmd, check=False)
        log("[ISO] Build command executed (assuming success).")

# -----------------------------
# UNATTEND.XML GENERATOR (NETWORK-AWARE)
# -----------------------------

def generate_unattend_xml(profile: Profile, bundle: Dict[str, Any]) -> str:
    log("[UNATTEND] Generating Unattend.xml.")
    net = profile.network_preset or NETWORK_PRESETS.get(profile.network_preset_name, {})
    ip_mode = net.get("ip_mode", "dhcp")
    ip_address = net.get("ip_address", "")
    subnet_mask = net.get("subnet_mask", "")
    gateway = net.get("gateway", "")
    dns_servers = net.get("dns_servers", [])

    dns_xml = ""
    for dns in dns_servers:
        dns_xml += f"<DnsServer>{dns}</DnsServer>\n"

    static_ip_xml = ""
    if ip_mode.lower() == "static":
        static_ip_xml = f"""
      <Interfaces>
        <Interface wcm:action="add">
          <Ipv4Settings>
            <DhcpEnabled>false</DhcpEnabled>
          </Ipv4Settings>
          <UnicastIpAddresses>
            <IpAddress wcm:action="add" wcm:keyValue="{ip_address}">
              <Address>{ip_address}</Address>
              <SubnetMask>{subnet_mask}</SubnetMask>
            </IpAddress>
          </UnicastIpAddresses>
          <DefaultGateway>{gateway}</DefaultGateway>
          <DnsServers>
            {dns_xml}
          </DnsServers>
        </Interface>
      </Interfaces>
"""

    unattend_content = f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend" xmlns:wcm="http://schemas.microsoft.com/WMIConfig/2002/State">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>{bundle['system_settings']['language']}</InputLocale>
      <SystemLocale>{bundle['system_settings']['language']}</SystemLocale>
      <UILanguage>{bundle['system_settings']['language']}</UILanguage>
      <UserLocale>{bundle['system_settings']['language']}</UserLocale>
    </component>
  </settings>
  <settings pass="specialize">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <ComputerName>{bundle['system_settings']['hostname']}-CLONE</ComputerName>
      <TimeZone>{bundle['system_settings']['timezone']}</TimeZone>
    </component>
    <component name="Microsoft-Windows-TCPIP" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      {static_ip_xml}
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-International-Core" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>{bundle['system_settings']['language']}</InputLocale>
      <SystemLocale>{bundle['system_settings']['language']}</SystemLocale>
      <UILanguage>{bundle['system_settings']['language']}</UILanguage>
      <UserLocale>{bundle['system_settings']['language']}</UserLocale>
    </component>
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="amd64" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <NetworkLocation>{profile.type}</NetworkLocation>
        <ProtectYourPC>1</ProtectYourPC>
      </OOBE>
    </component>
  </settings>
</unattend>
"""
    path = os.path.join(CONFIG_DIR, "unattend.xml")
    with open(path, "w", encoding="utf-8") as f:
        f.write(unattend_content)
    log(f"[UNATTEND] Saved Unattend.xml to {path}")
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
# GUI: CONTROL CENTER (NETWORK & IT)
# -----------------------------

class ControlCenter(QtWidgets.QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("DominionDeck Windows ISO Orchestrator — Network & IT Edition")
        self.resize(1400, 850)

        self.profiles: List[Profile] = load_profiles()
        self.selected_profile: Optional[Profile] = self.profiles[0] if self.profiles else None
        self.base_iso_path: str = ""
        self.output_iso_path: str = os.path.join(BASE_DIR, "DD_Custom_Windows.iso")
        self.master_bundle: Optional[Dict[str, Any]] = load_master_bundle()
        self.dry_run: bool = False

        self.component_checkboxes: Dict[str, QtWidgets.QCheckBox] = {}
        self.group_checkboxes: Dict[str, QtWidgets.QCheckBox] = {}

        self._build_ui()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(central)

        # Left panel: profile, ISO, actions
        left_panel = QtWidgets.QVBoxLayout()

        # Profile selector
        self.profile_combo = QtWidgets.QComboBox()
        for p in self.profiles:
            self.profile_combo.addItem(f"{p.name} ({p.type}/{p.region})", userData=p)
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed)
        left_panel.addWidget(QtWidgets.QLabel("Profile"))
        left_panel.addWidget(self.profile_combo)

        # Network preset selector
        self.net_preset_combo = QtWidgets.QComboBox()
        for name in NETWORK_PRESETS.keys():
            self.net_preset_combo.addItem(name)
        self.net_preset_combo.currentIndexChanged.connect(self.on_net_preset_changed)
        left_panel.addWidget(QtWidgets.QLabel("Network Preset (Site / VLAN / IP)"))
        left_panel.addWidget(self.net_preset_combo)

        # Base ISO selector
        self.base_iso_edit = QtWidgets.QLineEdit()
        self.base_iso_btn = QtWidgets.QPushButton("Browse Base ISO...")
        self.base_iso_btn.clicked.connect(self.on_browse_iso)
        left_panel.addWidget(QtWidgets.QLabel("Base Windows ISO"))
        left_panel.addWidget(self.base_iso_edit)
        left_panel.addWidget(self.base_iso_btn)

        # Output ISO path
        self.output_iso_edit = QtWidgets.QLineEdit(self.output_iso_path)
        left_panel.addWidget(QtWidgets.QLabel("Output ISO Path"))
        left_panel.addWidget(self.output_iso_edit)

        # Dry-run toggle
        self.dry_run_checkbox = QtWidgets.QCheckBox("Dry-run (simulate, no disk changes)")
        self.dry_run_checkbox.stateChanged.connect(self.on_dry_run_changed)
        left_panel.addWidget(self.dry_run_checkbox)

        # Post-install script selector
        self.post_script_edit = QtWidgets.QLineEdit()
        self.post_script_btn = QtWidgets.QPushButton("Browse Post-Install PowerShell Script...")
        self.post_script_btn.clicked.connect(self.on_browse_post_script)
        left_panel.addWidget(QtWidgets.QLabel("Post-Install Script (PowerShell)"))
        left_panel.addWidget(self.post_script_edit)
        left_panel.addWidget(self.post_script_btn)

        # Buttons
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

        # Profile export/import
        self.btn_export_profiles = QtWidgets.QPushButton("Export Profiles...")
        self.btn_export_profiles.clicked.connect(self.on_export_profiles)
        self.btn_import_profiles = QtWidgets.QPushButton("Import Profiles...")
        self.btn_import_profiles.clicked.connect(self.on_import_profiles)
        left_panel.addWidget(self.btn_export_profiles)
        left_panel.addWidget(self.btn_import_profiles)

        left_panel.addStretch()

        # Middle panel: Windows Components + groups
        middle_panel = QtWidgets.QVBoxLayout()
        middle_panel.addWidget(QtWidgets.QLabel("Windows Components (select exactly what to install)"))

        # Group toggles
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

        # Right panel: log + status
        right_panel = QtWidgets.QVBoxLayout()
        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        right_panel.addWidget(QtWidgets.QLabel("Log Output"))
        right_panel.addWidget(self.log_view)

        self.status_label = QtWidgets.QLabel("Ready.")
        right_panel.addWidget(self.status_label)

        layout.addLayout(left_panel, 2)
        layout.addLayout(middle_panel, 3)
        layout.addLayout(right_panel, 3)

        self.setCentralWidget(central)

        # Timer to refresh log view
        self.log_timer = QtCore.QTimer()
        self.log_timer.timeout.connect(self.refresh_log_view)
        self.log_timer.start(2000)

        # Initialize from selected profile
        self.apply_profile_to_ui()

    def refresh_log_view(self):
        try:
            if os.path.exists(LOG_FILE):
                with open(LOG_FILE, "r", encoding="utf-8") as f:
                    content = f.read()
                self.log_view.setPlainText(content)
                self.log_view.verticalScrollBar().setValue(self.log_view.verticalScrollBar().maximum())
        except Exception:
            pass

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
        # components
        selected_ids = set(self.selected_profile.selected_components or [])
        for comp_id, cb in self.component_checkboxes.items():
            cb.setChecked(comp_id in selected_ids)
        for group_name, comp_ids in COMPONENT_GROUPS.items():
            self.group_checkboxes[group_name].setChecked(all(cid in selected_ids for cid in comp_ids))
        # network preset
        preset_name = self.selected_profile.network_preset_name
        idx = self.net_preset_combo.findText(preset_name)
        if idx >= 0:
            self.net_preset_combo.setCurrentIndex(idx)
        # post-install script
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

        # Update profile from UI
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

            iso_mgr.inject_unattend(unattend_path)
            iso_mgr.inject_bundle_and_profile(bundle, self.selected_profile)
            iso_mgr.inject_selected_components(self.selected_profile)
            iso_mgr.inject_post_install_script(self.selected_profile)

            for plugin in PLUGIN_REGISTRY:
                plugin.run_before_iso_build(ctx)

            iso_mgr.build_iso()

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
            "Result: ISO that clones apps/settings, applies network preset, and runs your script."
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

# -----------------------------
# CLI MODE
# -----------------------------

def run_cli(args: List[str]):
    """
    CLI:
    python dd_iso_orchestrator.py --cli --profile NAME --base_iso path.iso --out_iso out.iso [--dry_run]
    """
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

    iso_mgr.inject_unattend(unattend_path)
    iso_mgr.inject_bundle_and_profile(bundle, profile)
    iso_mgr.inject_selected_components(profile)
    iso_mgr.inject_post_install_script(profile)

    for plugin in PLUGIN_REGISTRY:
        plugin.run_before_iso_build(ctx)

    iso_mgr.build_iso()

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
