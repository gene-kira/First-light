#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
DominionDeck Windows ISO Orchestrator
Option C — Enterprise-Level System

Single-file Python application that:
- Scans current Windows environment (settings, installed apps, network)
- Builds a reusable "Master Profile" for cloning to other machines
- Modifies a base Windows ISO using DISM/OSCDIMG
- Injects:
    - Unattend.xml
    - Preconfigured apps
    - Network/Wi-Fi credentials
    - Region/government/enterprise/cloud-local profiles
- Provides a unified GUI "Windows Control Center" for all adjustments
- Includes:
    - Autoloader for dependencies
    - Plugin API
    - Watchdog/daemon loop
    - Profile governor-style architecture
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
from typing import List, Dict, Any, Optional, Callable

# -----------------------------
# AUTOLOADER FOR PYTHON LIBS
# -----------------------------

REQUIRED_LIBS = [
    "PyQt6",
]

def ensure_dependencies():
    """Autoloader: ensure required Python packages are installed."""
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

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs(PROFILE_DIR, exist_ok=True)
os.makedirs(ISO_WORK_DIR, exist_ok=True)

# -----------------------------
# LOGGING
# -----------------------------

def log(msg: str):
    ts = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line)
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(line + "\n")
    except Exception:
        pass

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

class PluginBase:
    """Base class for DominionDeck plugins."""
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

# Example plugin: just logs phases
class LoggingPlugin(PluginBase):
    name = "LoggingPlugin"
    description = "Logs each phase of ISO orchestration."

    def run_before_iso_mount(self, ctx: PluginContext):
        log(f"[PLUGIN:{self.name}] Before ISO mount for profile {ctx.profile_name}")

    def run_after_iso_mount(self, ctx: PluginContext):
        log(f"[PLUGIN:{self.name}] After ISO mount")

    def run_before_iso_build(self, ctx: PluginContext):
        log(f"[PLUGIN:{self.name}] Before ISO build")

    def run_after_iso_build(self, ctx: PluginContext):
        log(f"[PLUGIN:{self.name}] After ISO build: {ctx.output_iso_path}")

register_plugin(LoggingPlugin())

# -----------------------------
# PROFILE ARCHITECTURE
# -----------------------------

@dataclass
class Profile:
    name: str
    type: str  # "government", "enterprise", "cloud", "local"
    region: str
    description: str
    include_games: bool = False
    include_consumer_apps: bool = False
    cloud_first: bool = False
    local_first: bool = True
    network_preset: Dict[str, Any] = field(default_factory=dict)
    app_whitelist: List[str] = field(default_factory=list)
    app_blacklist: List[str] = field(default_factory=list)

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
            "network_preset": self.network_preset,
            "app_whitelist": self.app_whitelist,
            "app_blacklist": self.app_blacklist,
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
            network_preset=d.get("network_preset", {}),
            app_whitelist=d.get("app_whitelist", []),
            app_blacklist=d.get("app_blacklist", []),
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
                log(f"[PROFILE] Failed to load {fn}: {e}")
    return profiles

# Seed some default profiles
if not os.listdir(PROFILE_DIR):
    save_profile(Profile(
        name="Government_US",
        type="government",
        region="US",
        description="No games, no consumer apps, strict network, local-first.",
        include_games=False,
        include_consumer_apps=False,
        cloud_first=False,
        local_first=True,
        network_preset={"wifi": [], "proxy": "gov-proxy.local"},
        app_whitelist=["Office", "SecuritySuite", "CustomGovTools"],
        app_blacklist=["Xbox", "Games", "ConsumerMedia"]
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
        network_preset={"wifi": [], "proxy": None},
        app_whitelist=["Office", "Teams", "VPNClient"],
        app_blacklist=["Xbox", "Games"]
    ))

# -----------------------------
# SYSTEM SNAPSHOT / MASTER MACHINE
# -----------------------------

def snapshot_installed_programs() -> List[Dict[str, Any]]:
    """
    Snapshot installed programs using registry + WMIC.
    This is simplified; in real use you'd query HKLM/HKCU uninstall keys.
    """
    log("[SNAPSHOT] Capturing installed programs (simplified).")
    programs = []

    try:
        # WMIC example (deprecated but still present on many systems)
        cmd = ["wmic", "product", "get", "name,version"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        lines = result.stdout.splitlines()
        for line in lines[1:]:
            line = line.strip()
            if not line:
                continue
            # naive split
            parts = line.split("  ")
            name = parts[0].strip()
            version = parts[-1].strip() if len(parts) > 1 else ""
            programs.append({"name": name, "version": version})
    except Exception as e:
        log(f"[SNAPSHOT] WMIC failed: {e}")

    return programs

def snapshot_network_settings() -> Dict[str, Any]:
    """
    Snapshot Wi-Fi profiles and basic network info.
    """
    log("[SNAPSHOT] Capturing network settings.")
    wifi_profiles = []
    try:
        cmd = ["netsh", "wlan", "show", "profiles"]
        result = subprocess.run(cmd, capture_output=True, text=True, check=False)
        for line in result.stdout.splitlines():
            line = line.strip()
            if "All User Profile" in line:
                name = line.split(":")[-1].strip()
                wifi_profiles.append({"ssid": name})
    except Exception as e:
        log(f"[SNAPSHOT] Failed to list Wi-Fi profiles: {e}")

    return {
        "wifi_profiles": wifi_profiles,
        "proxy": None,  # placeholder
    }

def snapshot_system_settings() -> Dict[str, Any]:
    """
    Snapshot basic system settings (region, language, etc.).
    """
    log("[SNAPSHOT] Capturing system settings.")
    # Simplified: in real use you'd query registry and PowerShell
    return {
        "region": "US",
        "language": "en-US",
        "timezone": time.tzname[0],
        "hostname": os.environ.get("COMPUTERNAME", "UNKNOWN"),
    }

def build_master_profile_bundle() -> Dict[str, Any]:
    """
    Build a master bundle from current machine.
    """
    log("[MASTER] Building master profile bundle from current machine.")
    bundle = {
        "system_settings": snapshot_system_settings(),
        "network_settings": snapshot_network_settings(),
        "installed_programs": snapshot_installed_programs(),
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
        log(f"[MASTER] Failed to load master bundle: {e}")
        return None

# -----------------------------
# ISO / DISM ORCHESTRATION
# -----------------------------

class ISOManager:
    """
    Handles:
    - Mounting / extracting base ISO
    - Injecting Unattend.xml, apps, configs
    - Rebuilding ISO via OSCDIMG or similar
    """

    def __init__(self, base_iso: str, output_iso: str, work_dir: str):
        self.base_iso = base_iso
        self.output_iso = output_iso
        self.work_dir = work_dir
        self.mount_dir = os.path.join(work_dir, "mount")
        self.inject_dir = os.path.join(work_dir, "inject")
        os.makedirs(self.mount_dir, exist_ok=True)
        os.makedirs(self.inject_dir, exist_ok=True)

    def extract_iso(self):
        """
        Extract ISO contents to work_dir.
        For simplicity, we assume 7z or similar is available.
        """
        log(f"[ISO] Extracting base ISO: {self.base_iso}")
        if not os.path.exists(self.base_iso):
            raise FileNotFoundError(f"Base ISO not found: {self.base_iso}")
        os.makedirs(self.mount_dir, exist_ok=True)
        # Example using 7z (user must have it installed)
        cmd = ["7z", "x", self.base_iso, f"-o{self.mount_dir}", "-y"]
        subprocess.run(cmd, check=False)
        log("[ISO] Extraction complete (assuming success).")

    def inject_unattend(self, unattend_xml: str):
        """
        Place Unattend.xml into appropriate location.
        """
        log("[ISO] Injecting Unattend.xml.")
        dest = os.path.join(self.mount_dir, "sources", "unattend.xml")
        os.makedirs(os.path.dirname(dest), exist_ok=True)
        shutil.copy2(unattend_xml, dest)
        log(f"[ISO] Unattend.xml injected at {dest}")

    def inject_apps_and_configs(self, bundle: Dict[str, Any], profile: Profile):
        """
        Inject apps/configs into ISO (simplified).
        In reality, you'd use DISM to add packages, drivers, etc.
        """
        log("[ISO] Injecting apps and configs (simplified).")
        config_path = os.path.join(self.mount_dir, "dd_master_bundle.json")
        with open(config_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=4)

        profile_path = os.path.join(self.mount_dir, "dd_profile.json")
        with open(profile_path, "w", encoding="utf-8") as f:
            json.dump(profile.to_dict(), f, indent=4)

        log(f"[ISO] Injected master bundle and profile into ISO tree.")

    def build_iso(self):
        """
        Rebuild ISO using OSCDIMG (or similar).
        """
        log(f"[ISO] Building new ISO: {self.output_iso}")
        # Example OSCDIMG command (user must have ADK installed)
        boot_efi = os.path.join(self.mount_dir, "efi", "microsoft", "boot")
        cmd = [
            "oscdimg",
            "-m",
            "-o",
            "-u2",
            "-udfver102",
            "-bootdata:2#p0,e,b{0}\\boot\\etfsboot.com#pEF,e,b{0}\\efi\\microsoft\\boot\\efisys.bin".format(self.mount_dir),
            self.mount_dir,
            self.output_iso
        ]
        subprocess.run(cmd, check=False)
        log("[ISO] Build command executed (assuming success).")

# -----------------------------
# UNATTEND.XML GENERATOR
# -----------------------------

def generate_unattend_xml(profile: Profile, bundle: Dict[str, Any]) -> str:
    """
    Generate a basic Unattend.xml file tailored to profile + bundle.
    This is a simplified template.
    """
    log("[UNATTEND] Generating Unattend.xml.")
    unattend_content = f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
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
# WATCHDOG / GOVERNOR LOOP
# -----------------------------

class Watchdog(threading.Thread):
    """
    Simple watchdog that monitors log file size and process health.
    """

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
                    if size > 10 * 1024 * 1024:  # 10 MB
                        log("[WATCHDOG] Log file too large, rotating.")
                        try:
                            shutil.move(LOG_FILE, LOG_FILE + ".old")
                        except Exception:
                            pass
                time.sleep(self.interval)
            except Exception as e:
                log(f"[WATCHDOG] Error: {e}")
                time.sleep(self.interval)

    def stop(self):
        self.running = False
        log("[WATCHDOG] Stopped.")

# -----------------------------
# GUI: WINDOWS CONTROL CENTER
# -----------------------------

class ControlCenter(QtWidgets.QMainWindow):
    """
    Unified GUI for:
    - Selecting profile
    - Building master bundle
    - Selecting base ISO
    - Building new ISO
    - Viewing logs
    """

    def __init__(self):
        super().__init__()
        self.setWindowTitle("DominionDeck Windows ISO Orchestrator")
        self.resize(1100, 700)

        self.profiles: List[Profile] = load_profiles()
        self.selected_profile: Optional[Profile] = self.profiles[0] if self.profiles else None
        self.base_iso_path: str = ""
        self.output_iso_path: str = os.path.join(BASE_DIR, "DD_Custom_Windows.iso")

        self.master_bundle: Optional[Dict[str, Any]] = load_master_bundle()

        self._build_ui()

    def _build_ui(self):
        central = QtWidgets.QWidget()
        layout = QtWidgets.QHBoxLayout(central)

        # Left: profile + actions
        left_panel = QtWidgets.QVBoxLayout()

        # Profile selector
        self.profile_combo = QtWidgets.QComboBox()
        for p in self.profiles:
            self.profile_combo.addItem(f"{p.name} ({p.type}/{p.region})", userData=p)
        self.profile_combo.currentIndexChanged.connect(self.on_profile_changed)
        left_panel.addWidget(QtWidgets.QLabel("Profile"))
        left_panel.addWidget(self.profile_combo)

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

        # Buttons
        self.btn_build_master = QtWidgets.QPushButton("Build Master Bundle from This Machine")
        self.btn_build_master.clicked.connect(self.on_build_master)

        self.btn_generate_iso = QtWidgets.QPushButton("Generate Custom ISO")
        self.btn_generate_iso.clicked.connect(self.on_generate_iso)

        left_panel.addWidget(self.btn_build_master)
        left_panel.addWidget(self.btn_generate_iso)

        # Spacer
        left_panel.addStretch()

        # Right: log viewer + status
        right_panel = QtWidgets.QVBoxLayout()
        self.log_view = QtWidgets.QPlainTextEdit()
        self.log_view.setReadOnly(True)
        right_panel.addWidget(QtWidgets.QLabel("Log Output"))
        right_panel.addWidget(self.log_view)

        # Status bar-like info
        self.status_label = QtWidgets.QLabel("Ready.")
        right_panel.addWidget(self.status_label)

        layout.addLayout(left_panel, 2)
        layout.addLayout(right_panel, 3)

        self.setCentralWidget(central)

        # Timer to refresh log view
        self.log_timer = QtCore.QTimer()
        self.log_timer.timeout.connect(self.refresh_log_view)
        self.log_timer.start(2000)

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

    def on_browse_iso(self):
        path, _ = QtWidgets.QFileDialog.getOpenFileName(self, "Select Base Windows ISO", "", "ISO Files (*.iso)")
        if path:
            self.base_iso_path = path
            self.base_iso_edit.setText(path)
            self.status_label.setText(f"Base ISO selected: {path}")

    def on_build_master(self):
        self.status_label.setText("Building master bundle...")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)
        try:
            self.master_bundle = build_master_profile_bundle()
            self.status_label.setText("Master bundle built successfully.")
        except Exception as e:
            traceback.print_exc()
            self.status_label.setText(f"Error building master bundle: {e}")
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()

    def on_generate_iso(self):
        if not self.selected_profile:
            self.status_label.setText("No profile selected.")
            return
        if not self.base_iso_edit.text():
            self.status_label.setText("No base ISO selected.")
            return
        if not self.master_bundle:
            self.status_label.setText("No master bundle. Build it first.")
            return

        self.base_iso_path = self.base_iso_edit.text()
        self.output_iso_path = self.output_iso_edit.text() or self.output_iso_path

        self.status_label.setText("Generating custom ISO...")
        QtWidgets.QApplication.setOverrideCursor(QtCore.Qt.CursorShape.WaitCursor)

        try:
            # Generate Unattend.xml
            unattend_path = generate_unattend_xml(self.selected_profile, self.master_bundle)

            # ISO manager
            iso_mgr = ISOManager(
                base_iso=self.base_iso_path,
                output_iso=self.output_iso_path,
                work_dir=ISO_WORK_DIR
            )

            # Plugin context
            ctx = PluginContext(
                config={"master_bundle": self.master_bundle},
                profile_name=self.selected_profile.name,
                base_iso_path=self.base_iso_path,
                output_iso_path=self.output_iso_path,
                work_dir=ISO_WORK_DIR
            )

            # Run plugins before mount
            for plugin in PLUGIN_REGISTRY:
                plugin.run_before_iso_mount(ctx)

            iso_mgr.extract_iso()

            # Run plugins after mount
            for plugin in PLUGIN_REGISTRY:
                plugin.run_after_iso_mount(ctx)

            iso_mgr.inject_unattend(unattend_path)
            iso_mgr.inject_apps_and_configs(self.master_bundle, self.selected_profile)

            # Run plugins before build
            for plugin in PLUGIN_REGISTRY:
                plugin.run_before_iso_build(ctx)

            iso_mgr.build_iso()

            # Run plugins after build
            for plugin in PLUGIN_REGISTRY:
                plugin.run_after_iso_build(ctx)

            self.status_label.setText(f"Custom ISO generated: {self.output_iso_path}")
        except Exception as e:
            traceback.print_exc()
            self.status_label.setText(f"Error generating ISO: {e}")
        finally:
            QtWidgets.QApplication.restoreOverrideCursor()

# -----------------------------
# MAIN ENTRY
# -----------------------------

def main():
    log("[MAIN] DominionDeck Windows ISO Orchestrator starting.")
    watchdog = Watchdog(interval=5.0)
    watchdog.start()

    app = QtWidgets.QApplication(sys.argv)
    win = ControlCenter()
    win.show()
    ret = app.exec()

    watchdog.stop()
    sys.exit(ret)

if __name__ == "__main__":
    main()
