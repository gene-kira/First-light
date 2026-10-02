#!/usr/bin/env python3
"""DominionWinDeck Command Center v7.2 Overlord++ Edition

Full Windows deployment & recovery ecosystem:

- Multi-mode Workbench: Beginner, Advanced, Expert, Recovery, Technician.
- Custom Windows ISO builder (drivers, apps, autounattend, OEM payload, optional system image).
- Hardware-agnostic backup & restore (user data + drivers, any drive, any system).
- System driver capture and reuse for deployment payloads.
- Optional OS image capture (WIM) using DISM or wimlib-imagex (if present).
- Optional ISO build using captured system image as install.wim.
- App auto-install scripts via SetupComplete (safe, script-based).
- Backup versioning, listing, integrity checks.
- Recovery USB builder (WinPE-style folder layout, payload staging).
- Offline tools launcher (DISM, SFC, boot repair, driver injection stubs).
- Deployment presets (Gaming, Workstation, Minimal, OEM).
- Plugin system: drop .py files into "plugins" to extend the workbench.
- Smart diagnostics and environment checks.
- Startup protection, self-diagnostics, and auto tool installer for oscdimg.exe and wimlib-imagex.exe.
- No disk wipe automation, no OS overwrite, no destructive defaults.

Important: Test generated media in a VM before using it on physical hardware.
"""

from __future__ import annotations
import os
import sys
import json
import shutil
import subprocess
import threading
import queue
import traceback
import hashlib
import platform
import zipfile
import importlib
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse

import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

APP = "DominionWinDeck Command Center"
VERSION = "7.2 Overlord++"

# Portable mode support: default to local data dir, allow override via env
BASE_DIR = Path(__file__).resolve().parent
DEFAULT_DATA_DIR = BASE_DIR / "DominionWinDeckData"
PORTABLE_ENV = os.environ.get("DOMINION_WINDECK_PORTABLE", "0").lower() in ("1", "true", "yes")

if PORTABLE_ENV:
    DATA_DIR = DEFAULT_DATA_DIR
else:
    home = Path(os.environ.get("USERPROFILE") or Path.home())
    DATA_DIR = home / "DominionWinDeckData"
DATA_DIR.mkdir(parents=True, exist_ok=True)

CONFIG_FILE = DATA_DIR / "settings.json"
LOG_FILE = DATA_DIR / "dominion.log"
PROFILES_DIR = DATA_DIR / "profiles"
PROFILES_DIR.mkdir(exist_ok=True)
BACKUP_DIR = DATA_DIR / "backups"
BACKUP_DIR.mkdir(exist_ok=True)
PLUGINS_DIR = BASE_DIR / "plugins"
PLUGINS_DIR.mkdir(exist_ok=True)
RECOVERY_USB_DIR = DATA_DIR / "recovery_usb"
RECOVERY_USB_DIR.mkdir(exist_ok=True)
JOBS_DIR = DATA_DIR / "jobs"
JOBS_DIR.mkdir(exist_ok=True)
DIAG_DIR = DATA_DIR / "diagnostics"
DIAG_DIR.mkdir(exist_ok=True)
TOOLS_DIR = DATA_DIR / "tools"
TOOLS_DIR.mkdir(exist_ok=True)

STARTUP_LOG = DATA_DIR / "startup.log"
ERROR_LOG = DATA_DIR / "startup_errors.log"
PLUGIN_MANIFEST = DATA_DIR / "plugins_manifest.json"
PROFILE_MANIFEST = DATA_DIR / "profiles_manifest.json"
JOB_HISTORY_FILE = DATA_DIR / "job_history.json"

OFFLINE_ENV = os.environ.get("DOMINION_WINDECK_OFFLINE", "0").lower() in ("1", "true", "yes")

# Tool installer configuration (Option A: official Microsoft ADK for oscdimg.exe)
ADK_URL = "https://download.microsoft.com/download/1/5/0/150F3C2E-ADK-PLACEHOLDER/ADKSetup.exe"  # replace with real URL when known
ADK_SETUP_NAME = "ADKSetup.exe"
ADK_INSTALL_ROOT = Path(os.environ.get("ProgramFiles(x86)", "C:\\Program Files (x86)")) / "Windows Kits" / "10"
ADK_OSCDIMG_PATHS = [
    ADK_INSTALL_ROOT / "Assessment and Deployment Kit" / "Deployment Tools" / "amd64" / "Oscdimg" / "oscdimg.exe",
    ADK_INSTALL_ROOT / "Assessment and Deployment Kit" / "Deployment Tools" / "x86" / "Oscdimg" / "oscdimg.exe",
]

WIMLIB_URL = "https://wimlib.net/downloads/wimlib-PLACEHOLDER.zip"  # replace with real URL when known
WIMLIB_ZIP_NAME = "wimlib-imagex.zip"

try:
    import pycdlib  # optional ISO metadata inspection
except Exception:
    pycdlib = None
try:
    import requests  # optional URL download
except Exception:
    requests = None


def stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def stamp_compact() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def log_line(message: str) -> str:
    line = f"[{stamp()}] {message}"
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    return line


def startup_log(message: str) -> None:
    line = f"[{stamp()}] {message}"
    try:
        with STARTUP_LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def startup_error(message: str) -> None:
    line = f"[{stamp()}] {message}"
    try:
        with ERROR_LOG.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass


def find_tool(*names: str) -> str | None:
    # First check tools dir, then PATH
    for name in names:
        local = TOOLS_DIR / name
        if local.exists():
            return str(local)
    for name in names:
        found = shutil.which(name)
        if found:
            return found
    return None


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def safe_label(value: str) -> str:
    value = "".join(c for c in value.upper() if c.isalnum() or c in "_-")
    return (value or "DOMINION_WIN")[:32]


def validate_computer_name(value: str) -> bool:
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?", value)) and len(value) <= 15


def validate_config(cfg: dict) -> list[str]:
    issues = []
    if not cfg.get("full_name", "").strip():
        issues.append("Full name is empty.")
    if not cfg.get("username", "").strip():
        issues.append("Username is empty.")
    if not validate_computer_name(cfg.get("computer_name", "")):
        issues.append("Computer name must be 1–15 letters, digits, or hyphens; it cannot start/end with a hyphen.")
    try:
        if int(cfg.get("image_index", "1")) < 1:
            issues.append("Image index must be at least 1.")
    except (ValueError, TypeError):
        issues.append("Image index must be a positive integer.")
    if not cfg.get("timezone", "").strip():
        issues.append("Time zone is empty.")
    if not cfg.get("iso_source", "").strip():
        issues.append("Source ISO/URL is empty.")
    if not cfg.get("iso_output", "").strip():
        issues.append("Output ISO path is empty.")
    return issues


def xml_escape(value: str) -> str:
    return (
        str(value)
        .replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&apos;")
    )


def generate_unattend(cfg: dict) -> str:
    arch = cfg.get("architecture", "amd64")
    preset = cfg.get("preset", "Custom")
    locale = cfg.get("locale", "en-US")
    tz = cfg.get("timezone", "Central Standard Time")
    owner = cfg.get("full_name", "User")
    org = cfg.get("organization", "")
    cname = cfg.get("computer_name", "WIN-AUTO")
    return f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="{xml_escape(arch)}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>{xml_escape(locale)}</InputLocale>
      <SystemLocale>{xml_escape(locale)}</SystemLocale>
      <UILanguage>{xml_escape(locale)}</UILanguage>
      <UserLocale>{xml_escape(locale)}</UserLocale>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="{xml_escape(arch)}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RegisteredOwner>{xml_escape(owner)}</RegisteredOwner>
      <RegisteredOrganization>{xml_escape(org)}</RegisteredOrganization>
      <TimeZone>{xml_escape(tz)}</TimeZone>
      <ComputerName>{xml_escape(cname)}</ComputerName>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
      <Display>
        <ColorDepth>32</ColorDepth>
        <HorizontalResolution>1024</HorizontalResolution>
        <VerticalResolution>768</VerticalResolution>
      </Display>
      <ProductKey></ProductKey>
    </component>
  </settings>
  <cpi:offlineImage cpi:source="wim:install.wim#Dominion-{xml_escape(preset)}" xmlns:cpi="urn:schemas-microsoft-com:cpi" />
</unattend>
"""


class ToolInstaller:
    """Auto installer for oscdimg.exe (via Microsoft ADK) and wimlib-imagex.exe."""

    def __init__(self, emit):
        self.emit = emit

    def say(self, text: str):
        self.emit(("log", text))

    def _download_file(self, url: str, target: Path):
        if OFFLINE_ENV:
            raise RuntimeError("Offline mode is enabled; cannot download tools.")
        if not requests:
            # Fallback to PowerShell Invoke-WebRequest
            self.say("requests not available; using PowerShell Invoke-WebRequest to download.")
            cmd = [
                "powershell",
                "-NoProfile",
                "-ExecutionPolicy",
                "Bypass",
                "Invoke-WebRequest",
                "-Uri",
                url,
                "-OutFile",
                str(target),
            ]
            proc = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                errors="replace",
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            output, _ = proc.communicate()
            if output:
                for line in output.splitlines()[-50:]:
                    self.say(line)
            if proc.returncode != 0:
                raise RuntimeError(f"Download failed with exit code {proc.returncode}.")
        else:
            self.say(f"Downloading {url} -> {target} ...")
            with requests.get(url, stream=True, timeout=(20, 300)) as response:
                response.raise_for_status()
                total = int(response.headers.get("content-length", "0") or 0)
                done = 0
                target.parent.mkdir(parents=True, exist_ok=True)
                with target.open("wb") as f:
                    for chunk in response.iter_content(1024 * 1024):
                        if chunk:
                            f.write(chunk)
                            done += len(chunk)
                            if total:
                                self.emit(("status", f"Downloading tool: {done * 100 // total}%"))
            self.say("Download completed.")

    def ensure_oscdimg(self) -> str | None:
        existing = find_tool("oscdimg.exe", "oscdimg")
        if existing:
            self.say(f"oscdimg already present: {existing}")
            return existing
        self.say("oscdimg.exe not found; attempting installation via Microsoft ADK.")
        adk_setup = TOOLS_DIR / ADK_SETUP_NAME
        if not adk_setup.exists():
            self._download_file(ADK_URL, adk_setup)
        self.say("Running ADK setup (Deployment Tools only, silent)...")
        # Note: real ADK command line may differ; this is a placeholder pattern.
        cmd = [
            str(adk_setup),
            "/quiet",
            "/norestart",
        ]
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output, _ = proc.communicate()
        if output:
            for line in output.splitlines()[-50:]:
                self.say(line)
        if proc.returncode != 0:
            raise RuntimeError(f"ADK installation failed with exit code {proc.returncode}.")
        self.say("ADK installation completed; searching for oscdimg.exe...")
        for p in ADK_OSCDIMG_PATHS:
            if p.is_file():
                dest = TOOLS_DIR / "oscdimg.exe"
                shutil.copy2(p, dest)
                self.say(f"oscdimg.exe installed to: {dest}")
                return str(dest)
        self.say("oscdimg.exe not found in expected ADK paths.")
        return None

    def ensure_wimlib(self) -> str | None:
        existing = find_tool("wimlib-imagex.exe", "wimlib-imagex")
        if existing:
            self.say(f"wimlib-imagex already present: {existing}")
            return existing
        self.say("wimlib-imagex.exe not found; attempting download from official wimlib site.")
        zip_path = TOOLS_DIR / WIMLIB_ZIP_NAME
        if not zip_path.exists():
            self._download_file(WIMLIB_URL, zip_path)
        self.say("Extracting wimlib-imagex from ZIP...")
        with zipfile.ZipFile(zip_path, "r") as zf:
            for name in zf.namelist():
                if name.lower().endswith("wimlib-imagex.exe"):
                    zf.extract(name, TOOLS_DIR)
                    src = TOOLS_DIR / name
                    dest = TOOLS_DIR / "wimlib-imagex.exe"
                    shutil.move(src, dest)
                    self.say(f"wimlib-imagex.exe installed to: {dest}")
                    return str(dest)
        self.say("wimlib-imagex.exe not found in ZIP archive.")
        return None


class StartupGuard:
    """Startup protection and self-diagnostics."""

    def __init__(self):
        self.safe_mode = False
        self.missing_tools: dict[str, bool] = {}
        self._run_startup_checks()

    def _run_startup_checks(self):
        startup_log(f"{APP} {VERSION} starting...")
        try:
            self._check_paths()
            self._check_optional_tools()
            self._check_config_sanity()
        except Exception as e:
            startup_error(f"Startup failure: {e}")
            self.safe_mode = True

    def _check_paths(self):
        for p in (DATA_DIR, PROFILES_DIR, BACKUP_DIR, PLUGINS_DIR, RECOVERY_USB_DIR, JOBS_DIR, DIAG_DIR, TOOLS_DIR):
            if not p.exists():
                p.mkdir(parents=True, exist_ok=True)
        startup_log("Core directories validated.")

    def _check_optional_tools(self):
        for name in ("oscdimg.exe", "oscdimg", "7z.exe", "7z", "pnputil.exe", "pnputil", "dism.exe", "dism", "wimlib-imagex.exe", "wimlib-imagex"):
            self.missing_tools[name] = find_tool(name) is None
        startup_log("Optional tool presence recorded.")

    def _check_config_sanity(self):
        if CONFIG_FILE.exists():
            try:
                cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                issues = validate_config(cfg)
                if issues:
                    startup_log("Config validation warnings: " + "; ".join(issues))
            except Exception as e:
                startup_error(f"Config load error: {e}")

    def get_summary(self) -> dict:
        return {
            "safe_mode": self.safe_mode,
            "missing_tools": {k: v for k, v in self.missing_tools.items() if v},
        }


class PreflightChecker:
    """Deployment preflight checker."""

    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.report: dict = {
            "errors": [],
            "warnings": [],
            "info": [],
        }

    def check(self) -> dict:
        self._check_source()
        self._check_output()
        self._check_workspace()
        self._check_tools()
        self._check_config()
        return self.report

    def _add(self, kind: str, msg: str):
        self.report[kind].append(msg)

    def _check_source(self):
        src = self.cfg.get("iso_source", "").strip()
        if not src:
            self._add("errors", "No source ISO or URL specified.")
            return
        parsed = urlparse(src)
        if parsed.scheme in ("http", "https"):
            if OFFLINE_ENV or self.cfg.get("offline"):
                self._add("errors", "Offline mode is enabled; URL sources are not allowed.")
            elif requests is None:
                self._add("errors", "requests package not available; cannot download ISO from URL.")
            else:
                self._add("info", "Source is an HTTP/HTTPS URL; will be downloaded to workspace.")
        else:
            p = Path(src).expanduser()
            if not p.is_file():
                self._add("errors", f"Source ISO not found: {p}")
            elif p.suffix.lower() != ".iso":
                self._add("warnings", f"Source file does not have .iso extension: {p}")
            else:
                self._add("info", f"Source ISO: {p} ({p.stat().st_size:,} bytes)")

    def _check_output(self):
        out = Path(self.cfg.get("iso_output", "")).expanduser()
        if not out.name.lower().endswith(".iso"):
            self._add("errors", "Output filename must end in .iso.")
        if out.exists():
            self._add("warnings", f"Output ISO already exists and will not be overwritten: {out}")

    def _check_workspace(self):
        work = Path(self.cfg.get("work_dir", "")).expanduser()
        base = work if work.exists() else work.parent
        try:
            usage = shutil.disk_usage(base)
            src = self.cfg.get("iso_source", "").strip()
            size_est = 2 * 1024 * 1024 * 1024
            if src and Path(src).expanduser().is_file():
                size_est = Path(src).expanduser().stat().st_size * 3
            if usage.free < size_est:
                self._add("warnings", "Workspace free space may be insufficient for ISO extraction and rebuild.")
            else:
                self._add("info", f"Workspace free space: {usage.free:,} bytes.")
        except Exception as e:
            self._add("warnings", f"Could not determine workspace free space: {e}")

    def _check_tools(self):
        oscdimg = find_tool("oscdimg.exe", "oscdimg")
        sevenzip = find_tool("7z.exe", "7z")
        if not sevenzip:
            self._add("errors", "7-Zip command-line tool (7z.exe) was not found. Install 7-Zip and add it to PATH.")
        if not oscdimg:
            self._add("errors", "oscdimg.exe was not found. Use Settings → Install missing tools to install ADK.")
        if os.name != "nt":
            self._add("errors", "ISO creation is supported only on Windows in this build.")

    def _check_config(self):
        issues = validate_config(self.cfg)
        for i in issues:
            self._add("errors", i)
        if not issues:
            self._add("info", "Configuration values passed basic validation.")


class JobManager:
    """Background job manager with history and predictive diagnostics."""

    def __init__(self, emit):
        self.emit = emit
        self.jobs: dict[str, dict] = {}
        self.lock = threading.Lock()
        self._load_history()

    def _load_history(self):
        if JOB_HISTORY_FILE.exists():
            try:
                self.jobs = json.loads(JOB_HISTORY_FILE.read_text(encoding="utf-8"))
            except Exception:
                self.jobs = {}
        else:
            self.jobs = {}

    def _save_history(self):
        try:
            JOB_HISTORY_FILE.write_text(json.dumps(self.jobs, indent=2), encoding="utf-8")
        except Exception:
            pass

    def start_job(self, name: str, target, args=(), kwargs=None) -> str:
        if kwargs is None:
            kwargs = {}
        job_id = f"{stamp_compact()}_{name}"
        record = {
            "id": job_id,
            "name": name,
            "start": stamp(),
            "end": None,
            "status": "running",
            "error": None,
        }
        with self.lock:
            self.jobs[job_id] = record
            self._save_history()
        t = threading.Thread(target=self._run_job, args=(job_id, target, args, kwargs), daemon=True)
        t.start()
        return job_id

    def _run_job(self, job_id: str, target, args, kwargs):
        try:
            target(*args, **kwargs)
            status = "success"
            error = None
        except Exception as e:
            status = "failed"
            error = str(e)
            self.emit(("log", f"Job {job_id} failed: {e}"))
            self.emit(("log", traceback.format_exc()))
        with self.lock:
            rec = self.jobs.get(job_id, {})
            rec["end"] = stamp()
            rec["status"] = status
            rec["error"] = error
            self.jobs[job_id] = rec
            self._save_history()
        self.emit(("job_done", job_id))

    def get_jobs(self) -> list[dict]:
        with self.lock:
            return sorted(self.jobs.values(), key=lambda r: r.get("start") or "")

    def predict_requirements(self) -> dict:
        durations = []
        failures = 0
        for rec in self.jobs.values():
            if rec["name"] == "build_iso" and rec["status"] in ("success", "failed") and rec["start"] and rec["end"]:
                try:
                    s = datetime.strptime(rec["start"], "%Y-%m-%d %H:%M:%S")
                    e = datetime.strptime(rec["end"], "%Y-%m-%d %H:%M:%S")
                    durations.append((e - s).total_seconds())
                except Exception:
                    continue
            if rec["status"] == "failed":
                failures += 1
        avg = sum(durations) / len(durations) if durations else None
        return {
            "avg_build_seconds_estimate": avg,
            "total_failures": failures,
            "note": "Estimates are based on previous jobs and are not guarantees.",
        }


class ProfileManager:
    """Flexible deployment profiles."""

    def __init__(self):
        self.profiles: dict[str, dict] = {}
        self._load_profiles()

    def _load_profiles(self):
        if PROFILE_MANIFEST.exists():
            try:
                self.profiles = json.loads(PROFILE_MANIFEST.read_text(encoding="utf-8"))
            except Exception:
                self.profiles = {}
        else:
            self.profiles = {}

    def _save_profiles(self):
        try:
            PROFILE_MANIFEST.write_text(json.dumps(self.profiles, indent=2), encoding="utf-8")
        except Exception:
            pass

    def list_profiles(self) -> list[str]:
        return sorted(self.profiles.keys())

    def get_profile(self, name: str) -> dict | None:
        return self.profiles.get(name)

    def save_profile(self, name: str, cfg: dict):
        self.profiles[name] = cfg
        self._save_profiles()

    def delete_profile(self, name: str):
        if name in self.profiles:
            del self.profiles[name]
            self._save_profiles()

    def export_profile(self, name: str, path: Path):
        cfg = self.get_profile(name)
        if not cfg:
            raise ValueError("Profile not found.")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(cfg, indent=2), encoding="utf-8")

    def import_profile(self, path: Path, name: str | None = None):
        data = json.loads(path.read_text(encoding="utf-8"))
        if not name:
            name = path.stem
        self.save_profile(name, data)


class PluginManager:
    """Safer plugin and tool integration."""

    def __init__(self, emit):
        self.emit = emit
        self.plugins: dict[str, dict] = {}
        self._load_manifest()
        self._scan_plugins()

    def _load_manifest(self):
        if PLUGIN_MANIFEST.exists():
            try:
                self.plugins = json.loads(PLUGIN_MANIFEST.read_text(encoding="utf-8"))
            except Exception:
                self.plugins = {}
        else:
            self.plugins = {}

    def _save_manifest(self):
        try:
            PLUGIN_MANIFEST.write_text(json.dumps(self.plugins, indent=2), encoding="utf-8")
        except Exception:
            pass

    def _scan_plugins(self):
        for py in PLUGINS_DIR.glob("*.py"):
            name = py.stem
            meta = self.plugins.get(name, {})
            meta.setdefault("path", str(py))
            meta.setdefault("enabled", True)
            meta.setdefault("permissions", ["logs"])
            meta.setdefault("last_error", None)
            self.plugins[name] = meta
        self._save_manifest()

    def list_plugins(self) -> list[dict]:
        return [
            {"name": name, **meta}
            for name, meta in sorted(self.plugins.items(), key=lambda kv: kv[0])
        ]

    def set_enabled(self, name: str, enabled: bool):
        if name in self.plugins:
            self.plugins[name]["enabled"] = enabled
            self._save_manifest()

    def run_plugin_hook(self, hook: str, context: dict):
        for name, meta in self.plugins.items():
            if not meta.get("enabled", True):
                continue
            path = Path(meta.get("path", ""))
            if not path.is_file():
                continue
            try:
                spec = importlib.util.spec_from_file_location(name, path)
                if not spec or not spec.loader:
                    continue
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                func = getattr(mod, hook, None)
                if callable(func):
                    func(context)
            except Exception as e:
                meta["last_error"] = str(e)
                self.plugins[name] = meta
                self._save_manifest()
                self.emit(("log", f"Plugin {name} error: {e}"))


class DeploymentBuilder:
    def __init__(self, cfg: dict, emit, cancel_event: threading.Event, offline: bool = False, installer: ToolInstaller | None = None):
        self.cfg, self.emit, self.cancel = cfg, emit, cancel_event
        self.work = Path(cfg["work_dir"]).expanduser().resolve()
        self.source_text = cfg["iso_source"].strip()
        self.output = Path(cfg["iso_output"]).expanduser().resolve()
        self.offline = offline
        self.installer = installer

    def say(self, text: str):
        self.emit(("log", text))

    def check_cancel(self):
        if self.cancel.is_set():
            raise RuntimeError("Build cancelled by user.")

    def run(self, preview_only: bool = False):
        preflight = PreflightChecker(self.cfg).check()
        for kind in ("errors", "warnings", "info"):
            for msg in preflight[kind]:
                self.say(f"[{kind.upper()}] {msg}")
        if preflight["errors"]:
            raise RuntimeError("Preflight check failed; see errors above.")
        if preview_only:
            self.say("Preview-only mode: build will not be executed.")
            return None

        if os.name != "nt":
            raise RuntimeError("ISO creation is supported only on Windows in this build.")
        if not self.source_text:
            raise ValueError("Choose a Windows ISO first.")
        if not self.output.name.lower().endswith(".iso"):
            raise ValueError("Output filename must end in .iso.")

        # Ensure tools via auto installer if missing
        sevenzip = find_tool("7z.exe", "7z")
        oscdimg = find_tool("oscdimg.exe", "oscdimg")
        if not sevenzip:
            raise RuntimeError("7-Zip command-line tool (7z.exe) was not found. Install 7-Zip and add it to PATH.")
        if not oscdimg and self.installer:
            self.say("oscdimg.exe missing; attempting auto-install via ADK...")
            oscdimg = self.installer.ensure_oscdimg()
            if not oscdimg:
                raise RuntimeError("Auto-install of oscdimg.exe failed; cannot proceed.")
        elif not oscdimg:
            raise RuntimeError("oscdimg.exe was not found. Install Windows ADK Deployment Tools and add oscdimg to PATH.")

        source = self._get_source()
        if source.resolve() == self.output:
            raise ValueError("Output ISO cannot overwrite the source ISO.")
        issues = validate_config(self.cfg)
        if issues:
            raise ValueError("Configuration needs attention:\n- " + "\n- ".join(issues))

        free = shutil.disk_usage(self.work if self.work.exists() else self.work.parent).free
        if free < source.stat().st_size * 3:
            raise RuntimeError("Low workspace disk space. Allow roughly three times the source ISO size free.")
        self.work.mkdir(parents=True, exist_ok=True)
        stage = self.work / "media_stage"
        if stage.exists():
            shutil.rmtree(stage)
        stage.mkdir(parents=True)
        self.say(f"Source ISO: {source}")
        self.say(f"Source size: {source.stat().st_size:,} bytes; SHA-256: {sha256_file(source)}")
        self.say("Extracting source ISO with 7-Zip...")
        self._run([sevenzip, "x", "-y", f"-o{stage}", str(source)])
        self.check_cancel()
        boot_bios = stage / "boot" / "etfsboot.com"
        boot_uefi = stage / "efi" / "microsoft" / "boot" / "efisys.bin"
        if not boot_bios.exists() and not boot_uefi.exists():
            raise RuntimeError("Expected BIOS/UEFI boot image files were not found. This does not look like supported Windows installation media.")
        (stage / "autounattend.xml").write_text(generate_unattend(self.cfg), encoding="utf-8")
        self.say("Generated conservative autounattend.xml (no disk wipe or embedded password).")
        self._apply_system_image(stage)
        self._prepare_oem_payload(stage)
        self._apply_preset_tweaks(stage)
        self.check_cancel()
        self.output.parent.mkdir(parents=True, exist_ok=True)
        if self.output.exists():
            raise RuntimeError(f"Output already exists; choose a new filename or move it first: {self.output}")
        label = safe_label(self.cfg.get("volume_label", "DOMINION_WIN"))
        cmd = [oscdimg, "-m", "-o", "-u2", "-udfver102", "-l" + label]
        if boot_bios.exists() and boot_uefi.exists():
            cmd += ["-bootdata:2#p0,e,b" + str(boot_bios) + "#pEF,e,b" + str(boot_uefi)]
        elif boot_bios.exists():
            cmd += ["-b" + str(boot_bios)]
        else:
            cmd += ["-b" + str(boot_uefi)]
        cmd += [str(stage), str(self.output)]
        self.say("Rebuilding ISO with oscdimg; boot metadata is included where detected...")
        try:
            self._run(cmd)
            self.check_cancel()
            if not self.output.exists() or self.output.stat().st_size == 0:
                raise RuntimeError("ISO builder did not produce a non-empty output file.")
            digest = sha256_file(self.output)
            manifest = {
                "application": APP,
                "version": VERSION,
                "created": stamp(),
                "source_iso": str(source),
                "source_sha256": sha256_file(source),
                "output_iso": str(self.output),
                "output_sha256": digest,
                "volume_label": label,
                "configuration": {k: v for k, v in self.cfg.items() if k not in ("password",)},
                "system_image_used": bool(self.cfg.get("use_system_image")),
                "system_image_path": self.cfg.get("system_image_path", ""),
                "preset": self.cfg.get("preset", "Custom"),
                "mode": self.cfg.get("mode", "Advanced"),
            }
            manifest_path = self.output.with_suffix(self.output.suffix + ".manifest.json")
            manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
            self.say(f"Output ISO: {self.output}")
            self.say(f"Output SHA-256: {digest}")
            self.say(f"Manifest: {manifest_path}")
            self.say("Build finished. Bootability still needs a VM test before production use.")
            return str(self.output)
        except Exception:
            try:
                if self.output.exists():
                    self.output.unlink()
            except OSError:
                pass
            raise

    def _get_source(self) -> Path:
        parsed = urlparse(self.source_text)
        if parsed.scheme in ("http", "https"):
            if self.offline or OFFLINE_ENV:
                raise RuntimeError("Offline mode is enabled; URL sources are not allowed.")
            if not requests:
                raise RuntimeError("URL downloads require the optional 'requests' package. Install it manually or use a local ISO.")
            name = Path(parsed.path).name or "downloaded_windows.iso"
            if not name.lower().endswith(".iso"):
                name += ".iso"
            target = self.work / name
            self.work.mkdir(parents=True, exist_ok=True)
            self.say("Downloading ISO to workspace (large downloads may take time)...")
            with requests.get(self.source_text, stream=True, timeout=(20, 120)) as response:
                response.raise_for_status()
                total = int(response.headers.get("content-length", "0") or 0)
                done = 0
                with target.open("wb") as f:
                    for chunk in response.iter_content(1024 * 1024):
                        self.check_cancel()
                        if chunk:
                            f.write(chunk)
                            done += len(chunk)
                            if total:
                                self.emit(("status", f"Downloading ISO: {done * 100 // total}%"))
            return target
        source = Path(self.source_text).expanduser().resolve()
        if not source.is_file():
            raise FileNotFoundError(f"ISO not found: {source}")
        if source.suffix.lower() != ".iso":
            raise ValueError("Source must be an .iso file or an HTTPS/HTTP URL to an ISO.")
        return source

    def _run(self, command: list[str]):
        self.check_cancel()
        self.say("Running: " + subprocess.list2cmdline(command))
        proc = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        while True:
            if self.cancel.is_set():
                proc.terminate()
                try:
                    proc.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                raise RuntimeError("Build cancelled by user.")
            try:
                output, _ = proc.communicate(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                continue
        if output:
            for line in output.splitlines()[-100:]:
                self.say(line)
        if proc.returncode != 0:
            raise RuntimeError(f"External command failed with exit code {proc.returncode}.")

    def _apply_system_image(self, stage: Path):
        if not self.cfg.get("use_system_image"):
            return
        img_path = self.cfg.get("system_image_path", "").strip()
        if not img_path:
            self.say("System image use requested but no path set.")
            return
        img = Path(img_path).expanduser().resolve()
        if not img.is_file():
            self.say(f"System image not found: {img}")
            return
        sources = stage / "sources"
        if not sources.exists():
            self.say("sources folder not found in ISO; cannot apply system image.")
            return
        target_wim = sources / "install.wim"
        if not target_wim.exists():
            target_wim = sources / "install.esd"
        self.say(f"Applying captured system image as install.wim: {img} -> {target_wim}")
        shutil.copy2(img, target_wim)
        self.say("System image applied. This ISO now deploys the captured system image (test in VM first).")

    def _prepare_oem_payload(self, stage: Path):
        drivers = Path(self.cfg.get("drivers_dir", "")).expanduser() if self.cfg.get("drivers_dir") else None
        apps = Path(self.cfg.get("apps_dir", "")).expanduser() if self.cfg.get("apps_dir") else None
        auto_apps = bool(self.cfg.get("auto_install_apps"))
        if not (drivers and drivers.is_dir()) and not (apps and apps.is_dir()):
            return
        target = stage / "sources" / "$OEM$" / "$1" / "DominionDeploy"
        scripts = []
        if drivers and drivers.is_dir():
            dest = target / "Drivers"
            shutil.copytree(drivers, dest, dirs_exist_ok=True)
            scripts.append('for /r "%SystemDrive%\\DominionDeploy\\Drivers" %%F in (*.inf) do pnputil.exe /add-driver "%%F" /install')
            self.say(f"Copied driver payload: {drivers}")
        if apps and apps.is_dir():
            dest = target / "Apps"
            shutil.copytree(apps, dest, dirs_exist_ok=True)
            self.say(f"Copied application payload: {apps}")
            if auto_apps:
                scripts.append('for /r "%SystemDrive%\\DominionDeploy\\Apps" %%F in (*.cmd *.bat) do call "%%F"')
                self.say("App auto-install enabled: .cmd/.bat scripts in Apps will run during SetupComplete.")
            else:
                self.say("Application installers are staged only; they are not run automatically. Install them after deployment.")
        if scripts:
            setup = stage / "sources" / "$OEM$" / "$$" / "Setup" / "Scripts"
            setup.mkdir(parents=True, exist_ok=True)
            body = "@echo off\r\nsetlocal\r\n" + "\r\n".join(scripts) + "\r\nexit /b %errorlevel%\r\n"
            (setup / "SetupComplete.cmd").write_text(body, encoding="utf-8")
            self.say("Added SetupComplete script. Review driver packages and app scripts before deployment.")

    def _apply_preset_tweaks(self, stage: Path):
        preset = self.cfg.get("preset", "Custom")
        self.say(f"Applying deployment preset: {preset}")
        marker = stage / "sources" / "dominion_preset.txt"
        marker.write_text(f"Preset={preset}\nMode={self.cfg.get('mode','Advanced')}\n", encoding="utf-8")
        self.say("Preset marker written for reference.")


class SystemCaptureManager:
    def __init__(self, emit):
        self.emit = emit

    def say(self, text: str):
        self.emit(("log", text))

    def _export_drivers(self, target: Path):
        pnputil = find_tool("pnputil.exe", "pnputil")
        if not pnputil:
            raise RuntimeError("pnputil.exe was not found. Driver export requires pnputil (Windows Vista+).")
        target.mkdir(parents=True, exist_ok=True)
        cmd = [pnputil, "/export-driver", "*", str(target)]
        self.say("Exporting drivers from this system with pnputil...")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output, _ = proc.communicate()
        if output:
            for line in output.splitlines()[-100:]:
                self.say(line)
        if proc.returncode != 0:
            raise RuntimeError(f"Driver export failed with exit code {proc.returncode}.")
        self.say(f"Driver export completed: {target}")

    def capture_drivers_only(self, work_root: Path) -> Path:
        drivers_root = work_root / "system_drivers"
        self._export_drivers(drivers_root)
        return drivers_root

    def create_backup(self, backup_path: Path):
        backup_root = BACKUP_DIR / "system_snapshot"
        if backup_root.exists():
            shutil.rmtree(backup_root)
        backup_root.mkdir(parents=True, exist_ok=True)
        self.say(f"Creating system backup in: {backup_root}")
        meta = {
            "application": APP,
            "version": VERSION,
            "created": stamp(),
            "platform": platform.platform(),
            "os_name": os.name,
            "user": os.environ.get("USERNAME") or os.environ.get("USER") or "",
        }
        (backup_root / "manifest.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        userprofile = os.environ.get("USERPROFILE")
        if userprofile:
            up = Path(userprofile)
            self.say(f"Capturing user profile: {up}")
            for name in ("Desktop", "Documents", "Downloads", "Pictures"):
                src = up / name
                if src.exists() and src.is_dir():
                    dest = backup_root / "UserData" / name
                    shutil.copytree(src, dest, dirs_exist_ok=True)
                    self.say(f"Copied: {src} -> {dest}")
        try:
            drivers_dest = backup_root / "Drivers"
            self._export_drivers(drivers_dest)
        except Exception as e:
            self.say(f"Driver export skipped/failed: {e}")
        backup_path.parent.mkdir(parents=True, exist_ok=True)
        self.say(f"Compressing backup to: {backup_path}")
        with zipfile.ZipFile(backup_path, "w", compression=zipfile.ZIP_DEFLATED) as zf:
            for root, dirs, files in os.walk(backup_root):
                root_path = Path(root)
                for f in files:
                    full = root_path / f
                    rel = full.relative_to(backup_root)
                    zf.write(full, rel.as_posix())
        self.say("System backup archive created.")
        return backup_path

    def restore_backup(self, backup_path: Path, target_root: Path):
        if not backup_path.is_file():
            raise FileNotFoundError(f"Backup archive not found: {backup_path}")
        target_root.mkdir(parents=True, exist_ok=True)
        self.say(f"Restoring backup {backup_path} into {target_root}")
        with zipfile.ZipFile(backup_path, "r") as zf:
            zf.extractall(target_root)
        self.say("Backup restored. Review files and drivers before applying them to the system.")

    def list_backups(self) -> list[Path]:
        backups = []
        for p in BACKUP_DIR.glob("system_backup_*.zip"):
            backups.append(p)
        return sorted(backups)

    def verify_backup(self, backup_path: Path) -> bool:
        if not backup_path.is_file():
            self.say(f"Backup not found: {backup_path}")
            return False
        try:
            with zipfile.ZipFile(backup_path, "r") as zf:
                bad = zf.testzip()
                if bad:
                    self.say(f"Backup integrity issue: {bad}")
                    return False
            self.say("Backup integrity verified.")
            return True
        except Exception as e:
            self.say(f"Backup verification failed: {e}")
            return False


class SystemImageManager:
    def __init__(self, emit):
        self.emit = emit

    def say(self, text: str):
        self.emit(("log", text))

    def capture_system_image(self, image_path: Path, volume: str = "C:\\"):
        dism = find_tool("dism.exe", "dism")
        wimlib = find_tool("wimlib-imagex.exe", "wimlib-imagex")
        if not dism and not wimlib:
            raise RuntimeError("No imaging tool found. Install DISM (Windows) or wimlib-imagex and add it to PATH.")
        image_path.parent.mkdir(parents=True, exist_ok=True)
        if dism:
            cmd = [
                dism,
                "/Capture-Image",
                f"/ImageFile:{image_path}",
                f"/CaptureDir:{volume}",
                "/Name:SystemImage",
                "/Compress:Max",
            ]
            self.say(f"Capturing system image with DISM from {volume} to {image_path}...")
        else:
            cmd = [
                wimlib,
                "capture",
                volume,
                str(image_path),
                "SystemImage",
                "--compress=LZMS",
            ]
            self.say(f"Capturing system image with wimlib-imagex from {volume} to {image_path}...")
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            errors="replace",
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
        output, _ = proc.communicate()
        if output:
            for line in output.splitlines()[-100:]:
                self.say(line)
        if proc.returncode != 0:
            raise RuntimeError(f"System image capture failed with exit code {proc.returncode}.")
        self.say(f"System image created: {image_path}")
        return image_path


class RecoveryUSBManager:
    def __init__(self, emit):
        self.emit = emit

    def say(self, text: str):
        self.emit(("log", text))

    def build_structure(self, root: Path):
        root.mkdir(parents=True, exist_ok=True)
        (root / "sources").mkdir(exist_ok=True)
        (root / "boot").mkdir(exist_ok=True)
        (root / "DominionTools").mkdir(exist_ok=True)
        marker = root / "DominionRecovery.txt"
        marker.write_text(f"{APP} {VERSION} Recovery USB\nCreated: {stamp()}\n", encoding="utf-8")
        self.say(f"Recovery USB structure created at: {root}")

    def stage_backup(self, backup_path: Path, root: Path):
        if not backup_path.is_file():
            raise FileNotFoundError(f"Backup archive not found: {backup_path}")
        dest = root / "DominionTools" / backup_path.name
        shutil.copy2(backup_path, dest)
        self.say(f"Staged backup archive on recovery USB: {dest}")

    def stage_drivers(self, drivers_dir: Path, root: Path):
        if not drivers_dir.is_dir():
            raise FileNotFoundError(f"Drivers folder not found: {drivers_dir}")
        dest = root / "DominionTools" / "Drivers"
        shutil.copytree(drivers_dir, dest, dirs_exist_ok=True)
        self.say(f"Staged drivers on recovery USB: {dest}")

    def stage_system_image(self, image_path: Path, root: Path):
        if not image_path.is_file():
            raise FileNotFoundError(f"System image not found: {image_path}")
        dest = root / "sources" / "boot.wim"
        shutil.copy2(image_path, dest)
        self.say(f"Staged system image (boot.wim) on recovery USB: {dest}")


class WorkbenchApp:
    def __init__(self, root: tk.Tk, startup_guard: StartupGuard):
        self.root = root
        self.startup_guard = startup_guard
        root.title(f"{APP} v{VERSION}")
        root.geometry("1180x820")
        root.minsize(900, 640)
        self.events: queue.Queue = queue.Queue()
        self.busy = False
        self.cancel_event = threading.Event()
        self.mode = tk.StringVar(value="Advanced")
        self.preset = tk.StringVar(value="Custom")
        self.preview_only = tk.BooleanVar(value=False)
        self.offline_mode = tk.BooleanVar(value=OFFLINE_ENV)
        self.portable_mode = tk.BooleanVar(value=PORTABLE_ENV)
        self.vars = {
            "iso_source": tk.StringVar(),
            "iso_output": tk.StringVar(value=str(Path.home() / "dominion_windows.iso")),
            "work_dir": tk.StringVar(value=str(DATA_DIR / "work")),
            "volume_label": tk.StringVar(value="DOMINION_WIN"),
            "full_name": tk.StringVar(value="User"),
            "organization": tk.StringVar(value=""),
            "username": tk.StringVar(value="User"),
            "computer_name": tk.StringVar(value="WIN-AUTO"),
            "timezone": tk.StringVar(value="Central Standard Time"),
            "locale": tk.StringVar(value="en-US"),
            "architecture": tk.StringVar(value="amd64"),
            "image_index": tk.StringVar(value="1"),
            "drivers_dir": tk.StringVar(value=""),
            "apps_dir": tk.StringVar(value=""),
            "backup_path": tk.StringVar(value=str(BACKUP_DIR / f"system_backup_{stamp_compact()}.zip")),
            "restore_target": tk.StringVar(value=str(Path.home() / "DominionRecovery")),
            "system_image_path": tk.StringVar(value=str(BACKUP_DIR / "system_image.wim")),
            "recovery_usb_root": tk.StringVar(value=str(RECOVERY_USB_DIR)),
        }
        self.use_system_image = tk.BooleanVar(value=False)
        self.auto_install_apps = tk.BooleanVar(value=False)
        self.status = tk.StringVar(value="Ready")
        self.job_manager = JobManager(self._emit)
        self.profile_manager = ProfileManager()
        self.plugin_manager = PluginManager(self._emit)
        self.capture_manager = SystemCaptureManager(self._emit)
        self.image_manager = SystemImageManager(self._emit)
        self.recovery_manager = RecoveryUSBManager(self._emit)
        self.tool_installer = ToolInstaller(self._emit)
        self._build_ui()
        self._load_settings()
        self._apply_startup_guard()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(100, self._poll_events)

    def _emit(self, event):
        self.events.put(event)

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="DominionWinDeck", font=("Segoe UI", 18, "bold")).pack(side="left")
        ttk.Label(header, text=f"Command Center {VERSION}").pack(side="right", anchor="s")

        mode_frame = ttk.Frame(outer)
        mode_frame.pack(fill="x", pady=(6, 4))
        ttk.Label(mode_frame, text="Mode:").pack(side="left")
        for m in ("Beginner", "Advanced", "Expert", "Recovery", "Technician"):
            ttk.Radiobutton(mode_frame, text=m, value=m, variable=self.mode, command=self._mode_changed).pack(side="left", padx=4)
        ttk.Label(mode_frame, text="Preset:").pack(side="left", padx=(18, 4))
        ttk.Combobox(
            mode_frame,
            textvariable=self.preset,
            values=("Custom", "Gaming", "Workstation", "Minimal", "OEM"),
            state="readonly",
            width=14,
        ).pack(side="left")
        ttk.Checkbutton(mode_frame, text="Preview-only", variable=self.preview_only).pack(side="left", padx=(18, 4))
        ttk.Checkbutton(mode_frame, text="Offline mode", variable=self.offline_mode).pack(side="left", padx=4)

        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True, pady=(10, 8))

        self.dashboard_tab = ttk.Frame(self.tabs, padding=12)
        self.deployment_tab = ttk.Frame(self.tabs, padding=12)
        self.backups_tab = ttk.Frame(self.tabs, padding=12)
        self.recovery_tab = ttk.Frame(self.tabs, padding=12)
        self.diagnostics_tab = ttk.Frame(self.tabs, padding=12)
        self.profiles_tab = ttk.Frame(self.tabs, padding=12)
        self.plugins_tab = ttk.Frame(self.tabs, padding=12)
        self.settings_tab = ttk.Frame(self.tabs, padding=12)

        self.tabs.add(self.dashboard_tab, text="Dashboard")
        self.tabs.add(self.deployment_tab, text="Deployment")
        self.tabs.add(self.backups_tab, text="Backups")
        self.tabs.add(self.recovery_tab, text="Recovery USB")
        self.tabs.add(self.diagnostics_tab, text="Diagnostics")
        self.tabs.add(self.profiles_tab, text="Profiles")
        self.tabs.add(self.plugins_tab, text="Plugins")
        self.tabs.add(self.settings_tab, text="Settings")

        self._build_dashboard_tab()
        self._build_deployment_tab()
        self._build_backups_tab()
        self._build_recovery_tab()
        self._build_diagnostics_tab()
        self._build_profiles_tab()
        self._build_plugins_tab()
        self._build_settings_tab()

        controls = ttk.Frame(outer)
        controls.pack(fill="x")
        self.progress = ttk.Progressbar(controls, mode="indeterminate")
        self.progress.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.start_btn = ttk.Button(controls, text="Build ISO", command=self.start_build)
        self.start_btn.pack(side="left")
        self.cancel_btn = ttk.Button(controls, text="Cancel", command=self.cancel_build, state="disabled")
        self.cancel_btn.pack(side="left", padx=(4, 0))
        ttk.Label(controls, textvariable=self.status).pack(side="right")

        log_frame = ttk.Frame(outer)
        log_frame.pack(fill="both", expand=True)
        ttk.Label(log_frame, text="Log:").pack(anchor="w")
        self.log_text = tk.Text(log_frame, height=8, wrap="none")
        self.log_text.pack(fill="both", expand=True)
        self.log_text.configure(state="disabled")

    def _build_dashboard_tab(self):
        f = self.dashboard_tab
        ttk.Label(f, text="System Overview", font=("Segoe UI", 12, "bold")).pack(anchor="w")
        self.overview_text = tk.Text(f, height=10, wrap="word")
        self.overview_text.pack(fill="both", expand=True)
        self.overview_text.configure(state="disabled")
        ttk.Button(f, text="Refresh Overview", command=self._refresh_overview).pack(anchor="e", pady=(6, 0))

    def _build_deployment_tab(self):
        f = self.deployment_tab
        ttk.Label(f, text="Source & Output", font=("Segoe UI", 11, "bold")).grid(row=0, column=0, columnspan=4, sticky="w", pady=(0, 4))

        ttk.Label(f, text="Source ISO / URL:").grid(row=1, column=0, sticky="e")
        ttk.Entry(f, textvariable=self.vars["iso_source"], width=60).grid(row=1, column=1, columnspan=2, sticky="we")
        ttk.Button(f, text="Browse...", command=self._browse_iso_source).grid(row=1, column=3, sticky="w")

        ttk.Label(f, text="Output ISO:").grid(row=2, column=0, sticky="e")
        ttk.Entry(f, textvariable=self.vars["iso_output"], width=60).grid(row=2, column=1, columnspan=2, sticky="we")
        ttk.Button(f, text="Browse...", command=self._browse_iso_output).grid(row=2, column=3, sticky="w")

        ttk.Label(f, text="Work directory:").grid(row=3, column=0, sticky="e")
        ttk.Entry(f, textvariable=self.vars["work_dir"], width=60).grid(row=3, column=1, columnspan=2, sticky="we")
        ttk.Button(f, text="Browse...", command=self._browse_work_dir).grid(row=3, column=3, sticky="w")

        ttk.Label(f, text="Volume label:").grid(row=4, column=0, sticky="e")
        ttk.Entry(f, textvariable=self.vars["volume_label"], width=20).grid(row=4, column=1, sticky="w")

        ttk.Separator(f, orient="horizontal").grid(row=5, column=0, columnspan=4, sticky="we", pady=6)

        ttk.Label(f, text="Windows Setup", font=("Segoe UI", 11, "bold")).grid(row=6, column=0, columnspan=4, sticky="w")

        ttk.Label(f, text="Full name:").grid(row=7, column=0, sticky="e")
        ttk.Entry(f, textvariable=self.vars["full_name"]).grid(row=7, column=1, sticky="we")
        ttk.Label(f, text="Organization:").grid(row=7, column=2, sticky="e")
        ttk.Entry(f, textvariable=self.vars["organization"]).grid(row=7, column=3, sticky="we")

        ttk.Label(f, text="Username:").grid(row=8, column=0, sticky="e")
        ttk.Entry(f, textvariable=self.vars["username"]).grid(row=8, column=1, sticky="we")
        ttk.Label(f, text="Computer name:").grid(row=8, column=2, sticky="e")
        ttk.Entry(f, textvariable=self.vars["computer_name"]).grid(row=8, column=3, sticky="we")

        ttk.Label(f, text="Time zone:").grid(row=9, column=0, sticky="e")
        ttk.Entry(f, textvariable=self.vars["timezone"]).grid(row=9, column=1, sticky="we")
        ttk.Label(f, text="Locale:").grid(row=9, column=2, sticky="e")
        ttk.Entry(f, textvariable=self.vars["locale"]).grid(row=9, column=3, sticky="we")

        ttk.Label(f, text="Architecture:").grid(row=10, column=0, sticky="e")
        ttk.Combobox(f, textvariable=self.vars["architecture"], values=("amd64", "x86"), state="readonly").grid(row=10, column=1, sticky="we")
        ttk.Label(f, text="Image index:").grid(row=10, column=2, sticky="e")
        ttk.Entry(f, textvariable=self.vars["image_index"], width=6).grid(row=10, column=3, sticky="w")

        for i in range(0, 11):
            f.grid_rowconfigure(i, pad=2)
        for j in range(0, 4):
            f.grid_columnconfigure(j, weight=1)

    def _build_backups_tab(self):
        f = self.backups_tab
        ttk.Label(f, text="Backups & Restore", font=("Segoe UI", 11, "bold")).pack(anchor="w")

        frame_top = ttk.Frame(f)
        frame_top.pack(fill="x", pady=(4, 4))
        ttk.Label(frame_top, text="Backup path:").pack(side="left")
        ttk.Entry(frame_top, textvariable=self.vars["backup_path"], width=50).pack(side="left", fill="x", expand=True, padx=(4, 4))
        ttk.Button(frame_top, text="Browse...", command=self._browse_backup_path).pack(side="left")

        frame_mid = ttk.Frame(f)
        frame_mid.pack(fill="x", pady=(4, 4))
        ttk.Button(frame_mid, text="Create backup", command=self._create_backup).pack(side="left")
        ttk.Button(frame_mid, text="List backups", command=self._list_backups).pack(side="left", padx=(4, 4))
        ttk.Button(frame_mid, text="Verify backup", command=self._verify_backup).pack(side="left", padx=(4, 4))

        frame_restore = ttk.Frame(f)
        frame_restore.pack(fill="x", pady=(4, 4))
        ttk.Label(frame_restore, text="Restore target:").pack(side="left")
        ttk.Entry(frame_restore, textvariable=self.vars["restore_target"], width=50).pack(side="left", fill="x", expand=True, padx=(4, 4))
        ttk.Button(frame_restore, text="Browse...", command=self._browse_restore_target).pack(side="left")
        ttk.Button(frame_restore, text="Restore backup (preview)", command=self._restore_backup_preview).pack(side="left", padx=(4, 4))

        self.backup_list = tk.Text(f, height=10, wrap="none")
        self.backup_list.pack(fill="both", expand=True)
        self.backup_list.configure(state="disabled")

    def _build_recovery_tab(self):
        f = self.recovery_tab
        ttk.Label(f, text="Recovery USB Builder", font=("Segoe UI", 11, "bold")).pack(anchor="w")

        frame_root = ttk.Frame(f)
        frame_root.pack(fill="x", pady=(4, 4))
        ttk.Label(frame_root, text="Recovery USB root:").pack(side="left")
        ttk.Entry(frame_root, textvariable=self.vars["recovery_usb_root"], width=50).pack(side="left", fill="x", expand=True, padx=(4, 4))
        ttk.Button(frame_root, text="Browse...", command=self._browse_recovery_root).pack(side="left")

        frame_actions = ttk.Frame(f)
        frame_actions.pack(fill="x", pady=(4, 4))
        ttk.Button(frame_actions, text="Build structure", command=self._build_recovery_structure).pack(side="left")
        ttk.Button(frame_actions, text="Stage backup", command=self._stage_backup_to_recovery).pack(side="left", padx=(4, 4))
        ttk.Button(frame_actions, text="Stage drivers", command=self._stage_drivers_to_recovery).pack(side="left", padx=(4, 4))
        ttk.Button(frame_actions, text="Stage system image", command=self._stage_image_to_recovery).pack(side="left", padx=(4, 4))

    def _build_diagnostics_tab(self):
        f = self.diagnostics_tab
        ttk.Label(f, text="Diagnostics & Job History", font=("Segoe UI", 11, "bold")).pack(anchor="w")

        frame_top = ttk.Frame(f)
        frame_top.pack(fill="x", pady=(4, 4))
        ttk.Button(frame_top, text="Show job history", command=self._show_job_history).pack(side="left")
        ttk.Button(frame_top, text="Predict requirements", command=self._show_predictions).pack(side="left", padx=(4, 4))
        ttk.Button(frame_top, text="Open startup log", command=self._open_startup_log).pack(side="left", padx=(4, 4))
        ttk.Button(frame_top, text="Open startup errors", command=self._open_startup_errors).pack(side="left", padx=(4, 4))

        self.diag_text = tk.Text(f, height=12, wrap="word")
        self.diag_text.pack(fill="both", expand=True)
        self.diag_text.configure(state="disabled")

    def _build_profiles_tab(self):
        f = self.profiles_tab
        ttk.Label(f, text="Deployment Profiles", font=("Segoe UI", 11, "bold")).pack(anchor="w")

        frame_top = ttk.Frame(f)
        frame_top.pack(fill="x", pady=(4, 4))
        ttk.Button(frame_top, text="Save current as profile", command=self._save_profile).pack(side="left")
        ttk.Button(frame_top, text="Load selected profile", command=self._load_profile).pack(side="left", padx=(4, 4))
        ttk.Button(frame_top, text="Delete selected profile", command=self._delete_profile).pack(side="left", padx=(4, 4))
        ttk.Button(frame_top, text="Export selected profile", command=self._export_profile).pack(side="left", padx=(4, 4))
        ttk.Button(frame_top, text="Import profile", command=self._import_profile).pack(side="left", padx=(4, 4))

        self.profile_listbox = tk.Listbox(f, height=10)
        self.profile_listbox.pack(fill="both", expand=True)
        self._refresh_profile_list()

    def _build_plugins_tab(self):
        f = self.plugins_tab
        ttk.Label(f, text="Plugins", font=("Segoe UI", 11, "bold")).pack(anchor="w")

        frame_top = ttk.Frame(f)
        frame_top.pack(fill="x", pady=(4, 4))
        ttk.Button(frame_top, text="Refresh plugins", command=self._refresh_plugins).pack(side="left")

        self.plugins_tree = ttk.Treeview(f, columns=("path", "enabled", "permissions", "last_error"), show="headings")
        self.plugins_tree.heading("path", text="Path")
        self.plugins_tree.heading("enabled", text="Enabled")
        self.plugins_tree.heading("permissions", text="Permissions")
        self.plugins_tree.heading("last_error", text="Last error")
        self.plugins_tree.pack(fill="both", expand=True)

        frame_bottom = ttk.Frame(f)
        frame_bottom.pack(fill="x", pady=(4, 4))
        ttk.Button(frame_bottom, text="Enable", command=lambda: self._set_plugin_enabled(True)).pack(side="left")
        ttk.Button(frame_bottom, text="Disable", command=lambda: self._set_plugin_enabled(False)).pack(side="left", padx=(4, 4))

        self._refresh_plugins()

    def _build_settings_tab(self):
        f = self.settings_tab
        ttk.Label(f, text="Settings & Tools", font=("Segoe UI", 11, "bold")).pack(anchor="w")

        ttk.Checkbutton(f, text="Portable mode (keep config/logs with application)", variable=self.portable_mode, state="disabled").pack(anchor="w", pady=(4, 2))
        ttk.Checkbutton(f, text="Offline mode (avoid network calls)", variable=self.offline_mode).pack(anchor="w", pady=(2, 2))

        ttk.Button(f, text="Install missing tools (ADK + wimlib)", command=self._install_missing_tools).pack(anchor="w", pady=(8, 2))
        ttk.Button(f, text="Save settings", command=self._save_settings).pack(anchor="e", pady=(8, 0))

    def _apply_startup_guard(self):
        summary = self.startup_guard.get_summary()
        if summary["safe_mode"]:
            self._append_log("Startup entered safe mode due to previous errors. Nonessential features may be disabled.")
        if summary["missing_tools"]:
            self._append_log("Missing tools: " + ", ".join(summary["missing_tools"].keys()))
        self._refresh_overview()

    def _mode_changed(self):
        m = self.mode.get()
        if m == "Beginner":
            self.status.set("Beginner mode: guided steps and explanations.")
        elif m == "Technician":
            self.status.set("Technician mode: advanced configuration and detailed logs.")
        elif m == "Recovery":
            self.status.set("Recovery mode: prioritize backup verification and recovery tools.")
        else:
            self.status.set(f"{m} mode selected.")

    def _browse_iso_source(self):
        path = filedialog.askopenfilename(title="Select Windows ISO", filetypes=[("ISO files", "*.iso"), ("All files", "*.*")])
        if path:
            self.vars["iso_source"].set(path)

    def _browse_iso_output(self):
        path = filedialog.asksaveasfilename(title="Output ISO", defaultextension=".iso", filetypes=[("ISO files", "*.iso")])
        if path:
            self.vars["iso_output"].set(path)

    def _browse_work_dir(self):
        path = filedialog.askdirectory(title="Work directory")
        if path:
            self.vars["work_dir"].set(path)

    def _browse_backup_path(self):
        path = filedialog.asksaveasfilename(title="Backup archive", defaultextension=".zip", filetypes=[("ZIP files", "*.zip")])
        if path:
            self.vars["backup_path"].set(path)

    def _browse_restore_target(self):
        path = filedialog.askdirectory(title="Restore target")
        if path:
            self.vars["restore_target"].set(path)

    def _browse_recovery_root(self):
        path = filedialog.askdirectory(title="Recovery USB root")
        if path:
            self.vars["recovery_usb_root"].set(path)

    def _create_backup(self):
        if not messagebox.askyesno("Confirm backup", "Create a system backup now?"):
            return
        backup_path = Path(self.vars["backup_path"].get()).expanduser()
        def job():
            self.capture_manager.create_backup(backup_path)
        self._start_background("backup", job)

    def _list_backups(self):
        backups = self.capture_manager.list_backups()
        self.backup_list.configure(state="normal")
        self.backup_list.delete("1.0", "end")
        for b in backups:
            self.backup_list.insert("end", f"{b} ({b.stat().st_size:,} bytes)\n")
        self.backup_list.configure(state="disabled")

    def _verify_backup(self):
        path = filedialog.askopenfilename(title="Select backup archive", filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")])
        if not path:
            return
        backup_path = Path(path).expanduser()
        def job():
            ok = self.capture_manager.verify_backup(backup_path)
            self._append_log(f"Backup verification result: {'OK' if ok else 'FAILED'}")
        self._start_background("verify_backup", job)

    def _restore_backup_preview(self):
        path = filedialog.askopenfilename(title="Select backup archive", filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")])
        if not path:
            return
        backup_path = Path(path).expanduser()
        target_root = Path(self.vars["restore_target"].get()).expanduser()
        if not messagebox.askyesno("Preview restore", f"Restore backup into {target_root} (files only, no system changes)?"):
            return
        def job():
            self.capture_manager.restore_backup(backup_path, target_root)
        self._start_background("restore_backup", job)

    def _build_recovery_structure(self):
        root = Path(self.vars["recovery_usb_root"].get()).expanduser()
        def job():
            self.recovery_manager.build_structure(root)
        self._start_background("recovery_structure", job)

    def _stage_backup_to_recovery(self):
        path = filedialog.askopenfilename(title="Select backup archive", filetypes=[("ZIP files", "*.zip"), ("All files", "*.*")])
        if not path:
            return
        backup_path = Path(path).expanduser()
        root = Path(self.vars["recovery_usb_root"].get()).expanduser()
        def job():
            self.recovery_manager.stage_backup(backup_path, root)
        self._start_background("stage_backup", job)

    def _stage_drivers_to_recovery(self):
        path = filedialog.askdirectory(title="Select drivers folder")
        if not path:
            return
        drivers_dir = Path(path).expanduser()
        root = Path(self.vars["recovery_usb_root"].get()).expanduser()
        def job():
            self.recovery_manager.stage_drivers(drivers_dir, root)
        self._start_background("stage_drivers", job)

    def _stage_image_to_recovery(self):
        path = filedialog.askopenfilename(title="Select system image", filetypes=[("WIM files", "*.wim"), ("All files", "*.*")])
        if not path:
            return
        image_path = Path(path).expanduser()
        root = Path(self.vars["recovery_usb_root"].get()).expanduser()
        def job():
            self.recovery_manager.stage_system_image(image_path, root)
        self._start_background("stage_system_image", job)

    def _refresh_overview(self):
        self.overview_text.configure(state="normal")
        self.overview_text.delete("1.0", "end")
        self.overview_text.insert("end", f"{APP} {VERSION}\n")
        self.overview_text.insert("end", f"Data directory: {DATA_DIR}\n")
        self.overview_text.insert("end", f"Portable mode: {self.portable_mode.get()}\n")
        self.overview_text.insert("end", f"Offline mode: {self.offline_mode.get()}\n")
        summary = self.startup_guard.get_summary()
        self.overview_text.insert("end", f"Safe mode: {summary['safe_mode']}\n")
        if summary["missing_tools"]:
            self.overview_text.insert("end", "Missing tools:\n")
            for t in summary["missing_tools"].keys():
                self.overview_text.insert("end", f"  - {t}\n")
        else:
            self.overview_text.insert("end", "All optional tools appear present or not checked.\n")
        self.overview_text.configure(state="disabled")

    def _show_job_history(self):
        jobs = self.job_manager.get_jobs()
        self.diag_text.configure(state="normal")
        self.diag_text.delete("1.0", "end")
        for j in jobs:
            self.diag_text.insert("end", f"{j['id']} [{j['name']}] {j['status']} start={j['start']} end={j['end']} error={j['error']}\n")
        self.diag_text.configure(state="disabled")

    def _show_predictions(self):
        pred = self.job_manager.predict_requirements()
        self.diag_text.configure(state="normal")
        self.diag_text.delete("1.0", "end")
        self.diag_text.insert("end", "Predictive diagnostics (estimates only):\n")
        self.diag_text.insert("end", f"Average build duration (seconds): {pred['avg_build_seconds_estimate']}\n")
        self.diag_text.insert("end", f"Total failures recorded: {pred['total_failures']}\n")
        self.diag_text.insert("end", pred["note"] + "\n")
        self.diag_text.configure(state="disabled")

    def _open_startup_log(self):
        if STARTUP_LOG.exists():
            os.startfile(str(STARTUP_LOG))

    def _open_startup_errors(self):
        if ERROR_LOG.exists():
            os.startfile(str(ERROR_LOG))

    def _refresh_profile_list(self):
        self.profile_listbox.delete(0, "end")
        for name in self.profile_manager.list_profiles():
            self.profile_listbox.insert("end", name)

    def _save_profile(self):
        name = simpledialog.askstring("Profile name", "Enter profile name:")
        if not name:
            return
        cfg = self._collect_config()
        self.profile_manager.save_profile(name, cfg)
        self._refresh_profile_list()
        self._append_log(f"Profile saved: {name}")

    def _load_profile(self):
        sel = self.profile_listbox.curselection()
        if not sel:
            return
        name = self.profile_listbox.get(sel[0])
        cfg = self.profile_manager.get_profile(name)
        if not cfg:
            return
        self._apply_config(cfg)
        self._append_log(f"Profile loaded: {name}")

    def _delete_profile(self):
        sel = self.profile_listbox.curselection()
        if not sel:
            return
        name = self.profile_listbox.get(sel[0])
        if not messagebox.askyesno("Delete profile", f"Delete profile '{name}'?"):
            return
        self.profile_manager.delete_profile(name)
        self._refresh_profile_list()
        self._append_log(f"Profile deleted: {name}")

    def _export_profile(self):
        sel = self.profile_listbox.curselection()
        if not sel:
            return
        name = self.profile_listbox.get(sel[0])
        path = filedialog.asksaveasfilename(title="Export profile", defaultextension=".json", filetypes=[("JSON files", "*.json")])
        if not path:
            return
        self.profile_manager.export_profile(name, Path(path).expanduser())
        self._append_log(f"Profile exported: {name} -> {path}")

    def _import_profile(self):
        path = filedialog.askopenfilename(title="Import profile", filetypes=[("JSON files", "*.json"), ("All files", "*.*")])
        if not path:
            return
        name = simpledialog.askstring("Profile name", "Enter profile name (blank to use file name):")
        self.profile_manager.import_profile(Path(path).expanduser(), name)
        self._refresh_profile_list()
        self._append_log(f"Profile imported from: {path}")

    def _refresh_plugins(self):
        self.plugin_manager._scan_plugins()
        for i in self.plugins_tree.get_children():
            self.plugins_tree.delete(i)
        for p in self.plugin_manager.list_plugins():
            self.plugins_tree.insert("", "end", values=(p["path"], p["enabled"], ",".join(p["permissions"]), p["last_error"]))

    def _set_plugin_enabled(self, enabled: bool):
        sel = self.plugins_tree.selection()
        if not sel:
            return
        item = self.plugins_tree.item(sel[0])
        path = item["values"][0]
        name = Path(path).stem
        self.plugin_manager.set_enabled(name, enabled)
        self._refresh_plugins()
        self._append_log(f"Plugin {name} {'enabled' if enabled else 'disabled'}.")

    def _collect_config(self) -> dict:
        cfg = {k: v.get() for k, v in self.vars.items()}
        cfg["mode"] = self.mode.get()
        cfg["preset"] = self.preset.get()
        cfg["use_system_image"] = self.use_system_image.get()
        cfg["auto_install_apps"] = self.auto_install_apps.get()
        cfg["offline"] = self.offline_mode.get()
        return cfg

    def _apply_config(self, cfg: dict):
        for k, v in self.vars.items():
            if k in cfg:
                v.set(str(cfg[k]))
        self.mode.set(cfg.get("mode", "Advanced"))
        self.preset.set(cfg.get("preset", "Custom"))
        self.use_system_image.set(bool(cfg.get("use_system_image")))
        self.auto_install_apps.set(bool(cfg.get("auto_install_apps")))
        self.offline_mode.set(bool(cfg.get("offline", OFFLINE_ENV)))

    def _save_settings(self):
        cfg = self._collect_config()
        try:
            CONFIG_FILE.write_text(json.dumps(cfg, indent=2), encoding="utf-8")
            self._append_log("Settings saved.")
        except Exception as e:
            self._append_log(f"Failed to save settings: {e}")

    def _load_settings(self):
        if CONFIG_FILE.exists():
            try:
                cfg = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                self._apply_config(cfg)
                self._append_log("Settings loaded.")
            except Exception as e:
                self._append_log(f"Failed to load settings: {e}")

    def _install_missing_tools(self):
        if OFFLINE_ENV or self.offline_mode.get():
            messagebox.showerror("Offline mode", "Offline mode is enabled; cannot download tools.")
            return
        if not messagebox.askyesno("Install tools", "Install missing tools (Microsoft ADK for oscdimg.exe and wimlib-imagex)?"):
            return
        def job():
            try:
                self.tool_installer.ensure_oscdimg()
                self.tool_installer.ensure_wimlib()
                self._append_log("Tool installation completed.")
            except Exception as e:
                self._append_log(f"Tool installation failed: {e}")
        self._start_background("install_tools", job)

    def start_build(self):
        if self.busy:
            return
        cfg = self._collect_config()
        issues = validate_config(cfg)
        if issues and self.mode.get() == "Beginner":
            messagebox.showerror("Configuration issues", "Please fix these before building:\n\n- " + "\n- ".join(issues))
            return
        self.cancel_event.clear()
        self.busy = True
        self.progress.start(10)
        self.start_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.status.set("Building ISO...")
        def job():
            builder = DeploymentBuilder(cfg, self._emit, self.cancel_event, offline=self.offline_mode.get(), installer=self.tool_installer)
            builder.run(preview_only=self.preview_only.get())
        self.job_manager.start_job("build_iso", job)

    def cancel_build(self):
        if not self.busy:
            return
        if messagebox.askyesno("Cancel build", "Cancel the current build?"):
            self.cancel_event.set()
            self.status.set("Cancelling...")

    def _start_background(self, name: str, func):
        self.job_manager.start_job(name, func)

    def _append_log(self, text: str):
        self.log_text.configure(state="normal")
        self.log_text.insert("end", f"[{stamp()}] {text}\n")
        self.log_text.see("end")
        self.log_text.configure(state="disabled")

    def _poll_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                kind, payload = event
                if kind == "log":
                    self._append_log(payload)
                elif kind == "status":
                    self.status.set(payload)
                elif kind == "job_done":
                    self._on_job_done(payload)
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def _on_job_done(self, job_id: str):
        self.progress.stop()
        self.busy = False
        self.start_btn.configure(state="normal")
        self.cancel_btn.configure(state="disabled")
        self.status.set(f"Job {job_id} finished.")
        self.plugin_manager.run_plugin_hook("on_job_done", {"job_id": job_id})

    def _close(self):
        self.root.destroy()


def main():
    guard = StartupGuard()
    root = tk.Tk()
    app = WorkbenchApp(root, guard)
    root.mainloop()


if __name__ == "__main__":
    main()
