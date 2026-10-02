#!/usr/bin/env python3
"""DominionWinDeck Deployment Workbench v5.0

A safer Windows deployment-media workbench plus system capture & recovery.

- Standard-library-only startup; optional tools are detected, never installed automatically.
- ISO rebuilding requires Microsoft's oscdimg (Windows ADK) to preserve BIOS/UEFI boot support.
- New: system backup/capture helpers and driver export from the live system, designed to be
  hardware-agnostic (no bare-metal restore, no disk wipe automation).

Important: Test generated media in a VM before using it on physical hardware.
"""
from __future__ import annotations
import os, sys, json, shutil, subprocess, threading, queue, traceback, hashlib, platform, zipfile
from pathlib import Path
from datetime import datetime
from urllib.parse import urlparse
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

APP = "DominionWinDeck Deployment Workbench"
VERSION = "5.0"
BASE_DIR = Path(__file__).resolve().parent
DATA_DIR = BASE_DIR / "DominionWinDeckData"
DATA_DIR.mkdir(parents=True, exist_ok=True)
CONFIG_FILE = DATA_DIR / "settings.json"
LOG_FILE = DATA_DIR / "dominion.log"
PROFILES_DIR = DATA_DIR / "profiles"
PROFILES_DIR.mkdir(exist_ok=True)
BACKUP_DIR = DATA_DIR / "backups"
BACKUP_DIR.mkdir(exist_ok=True)

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


def log_line(message: str) -> str:
    line = f"[{stamp()}] {message}"
    try:
        with LOG_FILE.open("a", encoding="utf-8") as f:
            f.write(line + "\n")
    except OSError:
        pass
    return line


def find_tool(*names: str) -> str | None:
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
    return (value or "CUSTOM_WIN")[:32]


def validate_computer_name(value: str) -> bool:
    import re
    return bool(re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,13}[A-Za-z0-9])?", value)) and len(value) <= 15


def validate_config(cfg: dict) -> list[str]:
    issues = []
    if not cfg.get("full_name", "").strip(): issues.append("Full name is empty.")
    if not cfg.get("username", "").strip(): issues.append("Username is empty.")
    if not validate_computer_name(cfg.get("computer_name", "")):
        issues.append("Computer name must be 1–15 letters, digits, or hyphens; it cannot start/end with a hyphen.")
    try:
        if int(cfg.get("image_index", "1")) < 1: issues.append("Image index must be at least 1.")
    except (ValueError, TypeError): issues.append("Image index must be a positive integer.")
    if not cfg.get("timezone", "").strip(): issues.append("Time zone is empty.")
    # Intentionally no password/autologon or automatic disk-wipe fields.
    return issues


def xml_escape(value: str) -> str:
    return (str(value).replace("&", "&amp;").replace("<", "&lt;")
            .replace(">", "&gt;").replace('"', "&quot;").replace("'", "&apos;"))


def generate_unattend(cfg: dict) -> str:
    """Generate a conservative answer file; leaves disk selection to Setup."""
    arch = cfg.get("architecture", "amd64")
    return f"""<?xml version="1.0" encoding="utf-8"?>
<unattend xmlns="urn:schemas-microsoft-com:unattend">
  <settings pass="windowsPE">
    <component name="Microsoft-Windows-International-Core-WinPE" processorArchitecture="{xml_escape(arch)}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <InputLocale>{xml_escape(cfg.get('locale','en-US'))}</InputLocale>
      <SystemLocale>{xml_escape(cfg.get('locale','en-US'))}</SystemLocale>
      <UILanguage>{xml_escape(cfg.get('locale','en-US'))}</UILanguage>
      <UserLocale>{xml_escape(cfg.get('locale','en-US'))}</UserLocale>
    </component>
  </settings>
  <settings pass="oobeSystem">
    <component name="Microsoft-Windows-Shell-Setup" processorArchitecture="{xml_escape(arch)}" publicKeyToken="31bf3856ad364e35" language="neutral" versionScope="nonSxS">
      <RegisteredOwner>{xml_escape(cfg.get('full_name','User'))}</RegisteredOwner>
      <RegisteredOrganization>{xml_escape(cfg.get('organization',''))}</RegisteredOrganization>
      <TimeZone>{xml_escape(cfg.get('timezone','Central Standard Time'))}</TimeZone>
      <ComputerName>{xml_escape(cfg.get('computer_name','WIN-AUTO'))}</ComputerName>
      <OOBE>
        <HideEULAPage>true</HideEULAPage>
        <ProtectYourPC>3</ProtectYourPC>
      </OOBE>
    </component>
  </settings>
</unattend>
"""


class DeploymentBuilder:
    def __init__(self, cfg: dict, emit, cancel_event: threading.Event):
        self.cfg, self.emit, self.cancel = cfg, emit, cancel_event
        self.work = Path(cfg["work_dir"]).expanduser().resolve()
        self.source_text = cfg["iso_source"].strip()
        self.output = Path(cfg["iso_output"]).expanduser().resolve()

    def say(self, text: str): self.emit(("log", text))
    def check_cancel(self):
        if self.cancel.is_set(): raise RuntimeError("Build cancelled by user.")

    def run(self):
        if os.name != "nt":
            raise RuntimeError("ISO creation is supported only on Windows in this build.")
        if not self.source_text: raise ValueError("Choose a Windows ISO first.")
        if not self.output.name.lower().endswith(".iso"): raise ValueError("Output filename must end in .iso.")
        source = self._get_source()
        if source.resolve() == self.output:
            raise ValueError("Output ISO cannot overwrite the source ISO.")
        issues = validate_config(self.cfg)
        if issues: raise ValueError("Configuration needs attention:\n- " + "\n- ".join(issues))
        oscdimg = find_tool("oscdimg.exe", "oscdimg")
        sevenzip = find_tool("7z.exe", "7z")
        if not sevenzip: raise RuntimeError("7-Zip command-line tool (7z.exe) was not found. Install 7-Zip and add it to PATH.")
        if not oscdimg: raise RuntimeError("oscdimg.exe was not found. Install Windows ADK Deployment Tools and add oscdimg to PATH.")
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
        # The generated answer file deliberately does not configure disk partitions,
        # wipe disks, set a password, or enable automatic logon.
        (stage / "autounattend.xml").write_text(generate_unattend(self.cfg), encoding="utf-8")
        self.say("Generated conservative autounattend.xml (no disk wipe or embedded password).")
        self._prepare_oem_payload(stage)
        self.check_cancel()
        self.output.parent.mkdir(parents=True, exist_ok=True)
        if self.output.exists():
            raise RuntimeError(f"Output already exists; choose a new filename or move it first: {self.output}")
        label = safe_label(self.cfg.get("volume_label", "CUSTOM_WIN"))
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
                if self.output.exists(): self.output.unlink()
            except OSError:
                pass
            raise

    def _get_source(self) -> Path:
        parsed = urlparse(self.source_text)
        if parsed.scheme in ("http", "https"):
            if not requests:
                raise RuntimeError("URL downloads require the optional 'requests' package. Install it manually or use a local ISO.")
            name = Path(parsed.path).name or "downloaded_windows.iso"
            if not name.lower().endswith(".iso"): name += ".iso"
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

    def _prepare_oem_payload(self, stage: Path):
        drivers = Path(self.cfg.get("drivers_dir", "")).expanduser() if self.cfg.get("drivers_dir") else None
        apps = Path(self.cfg.get("apps_dir", "")).expanduser() if self.cfg.get("apps_dir") else None
        if not (drivers and drivers.is_dir()) and not (apps and apps.is_dir()):
            return
        # $OEM$ payload is copied to the installed OS by Windows Setup.
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
            self.say("Application installers are staged only; they are not run automatically. Review and install them after deployment.")
        if scripts:
            # SetupComplete runs elevated near the end of Windows Setup.
            setup = stage / "sources" / "$OEM$" / "$$" / "Setup" / "Scripts"
            setup.mkdir(parents=True, exist_ok=True)
            body = "@echo off\r\nsetlocal\r\n" + "\r\n".join(scripts) + "\r\nexit /b %errorlevel%\r\n"
            (setup / "SetupComplete.cmd").write_text(body, encoding="utf-8")
            self.say("Added SetupComplete driver installation script. Review driver packages before deployment.")


class SystemCaptureManager:
    """Hardware-agnostic system backup and driver capture.

    This does NOT perform bare-metal disk imaging or automatic restore over the OS.
    It focuses on:
    - Exporting drivers from the current system.
    - Capturing user data and basic system metadata into a zip archive.
    - Restoring that archive into a chosen folder on a new machine.
    """

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
        # Capture basic metadata
        meta = {
            "application": APP,
            "version": VERSION,
            "created": stamp(),
            "platform": platform.platform(),
            "os_name": os.name,
            "user": os.environ.get("USERNAME") or os.environ.get("USER") or "",
        }
        (backup_root / "manifest.json").write_text(json.dumps(meta, indent=2), encoding="utf-8")
        # Capture user profile folders (non-destructive, copy only)
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
        # Export drivers
        try:
            drivers_dest = backup_root / "Drivers"
            self._export_drivers(drivers_dest)
        except Exception as e:
            self.say(f"Driver export skipped/failed: {e}")
        # Zip it
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


class WorkbenchApp:
    def __init__(self, root: tk.Tk):
        self.root = root
        root.title(f"{APP} v{VERSION}")
        root.geometry("1040x740")
        root.minsize(820, 580)
        self.events: queue.Queue = queue.Queue()
        self.busy = False
        self.cancel_event = threading.Event()
        self.vars = {
            "iso_source": tk.StringVar(),
            "iso_output": tk.StringVar(value=str(Path.home() / "custom_windows.iso")),
            "work_dir": tk.StringVar(value=str(DATA_DIR / "work")),
            "volume_label": tk.StringVar(value="CUSTOM_WIN"),
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
            "backup_path": tk.StringVar(value=str(BACKUP_DIR / "system_backup.zip")),
            "restore_target": tk.StringVar(value=str(Path.home() / "DominionRecovery")),
        }
        self.status = tk.StringVar(value="Ready")
        self._build_ui()
        self._load_settings()
        self.root.protocol("WM_DELETE_WINDOW", self._close)
        self.root.after(100, self._poll_events)

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=10)
        outer.pack(fill="both", expand=True)
        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="DominionWinDeck", font=("Segoe UI", 17, "bold")).pack(side="left")
        ttk.Label(header, text=f"Deployment Workbench {VERSION}").pack(side="right", anchor="s")
        self.tabs = ttk.Notebook(outer)
        self.tabs.pack(fill="both", expand=True, pady=(10, 8))
        self.source_tab = ttk.Frame(self.tabs, padding=12)
        self.config_tab = ttk.Frame(self.tabs, padding=12)
        self.payload_tab = ttk.Frame(self.tabs, padding=12)
        self.tools_tab = ttk.Frame(self.tabs, padding=12)
        self.capture_tab = ttk.Frame(self.tabs, padding=12)
        self.tabs.add(self.source_tab, text="Source & Output")
        self.tabs.add(self.config_tab, text="Windows Setup")
        self.tabs.add(self.payload_tab, text="Drivers & Apps")
        self.tabs.add(self.capture_tab, text="System Capture & Recovery")
        self.tabs.add(self.tools_tab, text="Profiles & Diagnostics")
        self._build_source_tab()
        self._build_config_tab()
        self._build_payload_tab()
        self._build_capture_tab()
        self._build_tools_tab()
        controls = ttk.Frame(outer)
        controls.pack(fill="x")
        self.progress = ttk.Progressbar(controls, mode="indeterminate")
        self.progress.pack(side="left", fill="x", expand=True, padx=(0, 8))
        self.start_btn = ttk.Button(controls, text="Build ISO", command=self.start_build)
        self.start_btn.pack(side="left")
        self.cancel_btn = ttk.Button(controls, text="Cancel", command=self.cancel_build, state="disabled")
        self.cancel_btn.pack(side="left", padx=(6, 0))
        ttk.Label(outer, textvariable=self.status, relief="sunken", anchor="w", padding=5).pack(fill="x", pady=(8, 0))
        log_frame = ttk.LabelFrame(outer, text="Live log", padding=5)
        log_frame.pack(fill="both", expand=True, pady=(8, 0))
        self.logbox = tk.Text(log_frame, height=9, wrap="word", font=("Consolas", 9), state="disabled")
        scroll = ttk.Scrollbar(log_frame, command=self.logbox.yview)
        self.logbox.configure(yscrollcommand=scroll.set)
        self.logbox.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self._log(f"{APP} v{VERSION} ready. Optional tools are not installed automatically.")

    def _entry(self, parent, row, label, key, browse=None, width=62):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=5)
        ttk.Entry(parent, textvariable=self.vars[key], width=width).grid(row=row, column=1, sticky="ew", padx=8, pady=5)
        if browse:
            ttk.Button(parent, text="Browse…", command=browse).grid(row=row, column=2, pady=5)
        parent.columnconfigure(1, weight=1)

    def _build_source_tab(self):
        self._entry(self.source_tab, 0, "Windows ISO (local file or direct URL):", "iso_source", self._pick_iso)
        self._entry(self.source_tab, 1, "Output ISO:", "iso_output", self._pick_output)
        self._entry(self.source_tab, 2, "Workspace folder:", "work_dir", self._pick_work)
        self._entry(self.source_tab, 3, "ISO volume label:", "volume_label")
        note = (
            "Requirements: Windows, 7-Zip CLI, and oscdimg.exe from Windows ADK.\n"
            "The original ISO is never overwritten. Existing output files are not overwritten.\n"
            "Test the finished ISO in a virtual machine before deploying to real hardware."
        )
        ttk.Label(self.source_tab, text=note, justify="left", foreground="#555555").grid(
            row=4, column=0, columnspan=3, sticky="w", pady=18
        )

    def _build_config_tab(self):
        for row, (label, key) in enumerate(
            [
                ("Registered owner:", "full_name"),
                ("Organization:", "organization"),
                ("Computer name:", "computer_name"),
                ("Time zone:", "timezone"),
                ("Locale:", "locale"),
                ("Architecture:", "architecture"),
                ("Windows image index (recorded for profile):", "image_index"),
            ]
        ):
            ttk.Label(self.config_tab, text=label).grid(row=row, column=0, sticky="w", pady=6)
            if key == "architecture":
                ttk.Combobox(
                    self.config_tab,
                    textvariable=self.vars[key],
                    values=("amd64", "x86", "arm64"),
                    state="readonly",
                    width=20,
                ).grid(row=row, column=1, sticky="w", padx=8)
            else:
                ttk.Entry(self.config_tab, textvariable=self.vars[key], width=38).grid(
                    row=row, column=1, sticky="w", padx=8
                )
        ttk.Label(
            self.config_tab,
            text=(
                "Safety: this generator does not configure disk partitions, erase disks, embed passwords, "
                "or enable automatic logon. Windows Setup will ask you to select the target disk."
            ),
            wraplength=650,
            foreground="#8a4b08",
        ).grid(row=8, column=0, columnspan=2, sticky="w", pady=18)

    def _build_payload_tab(self):
        self._entry(self.payload_tab, 0, "Driver folder (optional):", "drivers_dir", self._pick_drivers)
        self._entry(self.payload_tab, 1, "Application folder (optional):", "apps_dir", self._pick_apps)
        ttk.Label(
            self.payload_tab,
            text=(
                "Drivers are staged under $OEM$ and installed through pnputil during SetupComplete. "
                "Only trusted, compatible driver packages should be used. Applications are staged, "
                "not automatically executed; install them after deployment."
            ),
            wraplength=700,
            justify="left",
        ).grid(row=2, column=0, columnspan=3, sticky="w", pady=18)

    def _build_capture_tab(self):
        # Backup path and restore target
        self._entry(self.capture_tab, 0, "System backup archive:", "backup_path", self._pick_backup, width=70)
        self._entry(self.capture_tab, 1, "Restore target folder:", "restore_target", self._pick_restore_target, width=70)
        row = ttk.Frame(self.capture_tab)
        row.grid(row=2, column=0, columnspan=3, sticky="w", pady=10)
        ttk.Button(row, text="Create backup from this system", command=self.system_backup).pack(side="left")
        ttk.Button(row, text="Restore backup to this system", command=self.system_restore).pack(side="left", padx=6)
        ttk.Button(row, text="Capture drivers from this system", command=self.capture_drivers).pack(side="left", padx=6)
        ttk.Label(
            self.capture_tab,
            text=(
                "System backup is hardware-agnostic: it captures user data and exported drivers into a zip archive.\n"
                "Restoring places files into a chosen folder on the new machine; it does not overwrite the OS or wipe disks.\n"
                "Captured drivers can be reused as OEM payload for new ISOs or manually installed."
            ),
            wraplength=780,
            justify="left",
        ).grid(row=3, column=0, columnspan=3, sticky="w", pady=18)

    def _build_tools_tab(self):
        row = ttk.Frame(self.tools_tab)
        row.pack(fill="x", anchor="w")
        ttk.Button(row, text="Run diagnostics", command=self.diagnostics).pack(side="left")
        ttk.Button(row, text="Save profile", command=self.save_profile).pack(side="left", padx=6)
        ttk.Button(row, text="Load profile", command=self.load_profile).pack(side="left")
        ttk.Button(row, text="Open log folder", command=lambda: self._open_path(DATA_DIR)).pack(side="left", padx=6)
        ttk.Label(
            self.tools_tab,
            text=(
                "Profiles store deployment settings, not passwords. Diagnostics check available tools and environment. "
                "Build logs and backups are also written to disk."
            ),
            wraplength=700,
        ).pack(anchor="w", pady=18)

    def _pick_iso(self):
        p = filedialog.askopenfilename(title="Select Windows ISO", filetypes=[("ISO files", "*.iso"), ("All files", "*.*")])
        if p:
            self.vars["iso_source"].set(p)

    def _pick_output(self):
        p = filedialog.asksaveasfilename(
            title="Output ISO", defaultextension=".iso", filetypes=[("ISO files", "*.iso")]
        )
        if p:
            self.vars["iso_output"].set(p)

    def _pick_work(self):
        p = filedialog.askdirectory(title="Workspace folder")
        if p:
            self.vars["work_dir"].set(p)

    def _pick_drivers(self):
        p = filedialog.askdirectory(title="Driver folder")
        if p:
            self.vars["drivers_dir"].set(p)

    def _pick_apps(self):
        p = filedialog.askdirectory(title="Application folder")
        if p:
            self.vars["apps_dir"].set(p)

    def _pick_backup(self):
        p = filedialog.asksaveasfilename(
            title="System backup archive",
            defaultextension=".zip",
            initialdir=str(BACKUP_DIR),
            filetypes=[("Zip archives", "*.zip"), ("All files", "*.*")],
        )
        if p:
            self.vars["backup_path"].set(p)

    def _pick_restore_target(self):
        p = filedialog.askdirectory(title="Restore target folder")
        if p:
            self.vars["restore_target"].set(p)

    def _collect(self) -> dict:
        return {k: v.get().strip() for k, v in self.vars.items()}

    def _log(self, message: str):
        line = log_line(message)
        self.logbox.configure(state="normal")
        self.logbox.insert("end", line + "\n")
        self.logbox.see("end")
        self.logbox.configure(state="disabled")

    def _open_path(self, path):
        path = Path(path)
        path.mkdir(parents=True, exist_ok=True)
        try:
            os.startfile(str(path))
        except Exception as e:
            messagebox.showerror("Open folder", str(e))

    def start_build(self):
        if self.busy:
            return
        cfg = self._collect()
        if not cfg["iso_source"]:
            messagebox.showwarning("Source required", "Choose a Windows ISO or provide a direct URL.")
            return
        issues = validate_config(cfg)
        if issues:
            messagebox.showwarning("Check configuration", "\n".join(issues))
            return
        if not messagebox.askyesno(
            "Confirm build",
            "Build customized Windows installation media?\n\n"
            "The source ISO will not be changed. Review the answer file and test the output in a VM before deployment.",
        ):
            return
        self._save_settings()
        self.busy = True
        self.cancel_event.clear()
        self.progress.start(10)
        self.start_btn.configure(state="disabled")
        self.cancel_btn.configure(state="normal")
        self.status.set("Build running…")

        def worker():
            try:
                result = DeploymentBuilder(cfg, self.events.put, self.cancel_event).run()
                self.events.put(("status", "Build finished; VM boot test recommended."))
                self.events.put(("success", result))
            except Exception as e:
                self.events.put(("status", f"Build failed: {e}"))
                self.events.put(("error", str(e) + "\n\n" + traceback.format_exc()))
            finally:
                self.events.put(("done",))

        threading.Thread(target=worker, daemon=True).start()

    def cancel_build(self):
        if self.busy:
            self.cancel_event.set()
            self.status.set("Cancellation requested…")
            self._log("Cancellation requested.")

    def _poll_events(self):
        try:
            while True:
                kind, value = self.events.get_nowait()
                if kind == "log":
                    self._log(value)
                elif kind == "status":
                    self.status.set(value)
                elif kind == "success":
                    messagebox.showinfo(
                        "Build complete",
                        f"Created:\n{value}\n\nTest this ISO in a VM before production use.",
                    )
                elif kind == "error":
                    self._log(value)
                elif kind == "done":
                    self.busy = False
                    self.progress.stop()
                    self.start_btn.configure(state="normal")
                    self.cancel_btn.configure(state="disabled")
        except queue.Empty:
            pass
        self.root.after(100, self._poll_events)

    def diagnostics(self):
        lines = [
            f"{APP} {VERSION}",
            f"Python: {sys.version.split()[0]}",
            f"Platform: {platform.platform()}",
            f"OS: {os.name}",
            f"7-Zip: {find_tool('7z.exe', '7z') or 'NOT FOUND'}",
            f"oscdimg: {find_tool('oscdimg.exe', 'oscdimg') or 'NOT FOUND'}",
            f"pycdlib (optional metadata): {'available' if pycdlib else 'not installed'}",
            f"requests (optional URL download): {'available' if requests else 'not installed'}",
            f"pnputil (driver export): {find_tool('pnputil.exe', 'pnputil') or 'NOT FOUND'}",
            f"Log: {LOG_FILE}",
            f"Workspace: {self.vars['work_dir'].get()}",
            f"Backups: {BACKUP_DIR}",
        ]
        self._log("Diagnostics:\n" + "\n".join(lines))
        messagebox.showinfo("Diagnostics", "\n".join(lines))

    def save_profile(self):
        name = simpledialog.askstring("Save profile", "Profile name:")
        if not name:
            return
        safe = "".join(c for c in name if c.isalnum() or c in " _-").strip()[:60]
        if not safe:
            messagebox.showwarning("Invalid name", "Enter a valid profile name.")
            return
        path = PROFILES_DIR / (safe + ".json")
        path.write_text(json.dumps(self._collect(), indent=2), encoding="utf-8")
        self._log(f"Saved profile: {path}")
        messagebox.showinfo("Profile saved", str(path))

    def load_profile(self):
        path = filedialog.askopenfilename(
            title="Load profile", initialdir=PROFILES_DIR, filetypes=[("JSON profiles", "*.json")]
        )
        if not path:
            return
        try:
            data = json.loads(Path(path).read_text(encoding="utf-8"))
            for key, var in self.vars.items():
                if key in data and isinstance(data[key], (str, int, float)):
                    var.set(str(data[key]))
            self._log(f"Loaded profile: {path}")
        except Exception as e:
            messagebox.showerror("Profile error", str(e))

    def system_backup(self):
        if self.busy:
            messagebox.showwarning("Busy", "A build is running. Wait for it to finish before creating a backup.")
            return
        backup_path = Path(self.vars["backup_path"].get()).expanduser().resolve()
        if not messagebox.askyesno(
            "Confirm backup",
            "Create a hardware-agnostic backup of this system's user data and drivers?\n\n"
            "This will NOT image disks or overwrite anything. It creates a zip archive you can restore on another machine.",
        ):
            return
        mgr = SystemCaptureManager(self.events.put)

        def worker():
            try:
                result = mgr.create_backup(backup_path)
                self.events.put(("status", f"Backup created: {result}"))
                self.events.put(("log", f"System backup archive: {result}"))
                messagebox.showinfo("Backup complete", f"Backup created:\n{result}")
            except Exception as e:
                self.events.put(("status", f"Backup failed: {e}"))
                self.events.put(("error", str(e) + "\n\n" + traceback.format_exc()))

        threading.Thread(target=worker, daemon=True).start()

    def system_restore(self):
        if self.busy:
            messagebox.showwarning("Busy", "A build is running. Wait for it to finish before restoring a backup.")
            return
        backup_path = filedialog.askopenfilename(
            title="Select backup archive",
            initialdir=str(BACKUP_DIR),
            filetypes=[("Zip archives", "*.zip"), ("All files", "*.*")],
        )
        if not backup_path:
            return
        target_root = Path(self.vars["restore_target"].get()).expanduser().resolve()
        if not messagebox.askyesno(
            "Confirm restore",
            "Restore the selected backup into the chosen folder?\n\n"
            "This will NOT overwrite the OS or wipe disks. Files and drivers are placed into the target folder for review.",
        ):
            return
        mgr = SystemCaptureManager(self.events.put)

        def worker():
            try:
                mgr.restore_backup(Path(backup_path), target_root)
                self.events.put(("status", f"Backup restored into: {target_root}"))
                self.events.put(("log", f"Backup restored into: {target_root}"))
                messagebox.showinfo(
                    "Restore complete",
                    f"Backup restored into:\n{target_root}\n\nReview files and drivers before applying them.",
                )
            except Exception as e:
                self.events.put(("status", f"Restore failed: {e}"))
                self.events.put(("error", str(e) + "\n\n" + traceback.format_exc()))

        threading.Thread(target=worker, daemon=True).start()

    def capture_drivers(self):
        if self.busy:
            messagebox.showwarning("Busy", "A build is running. Wait for it to finish before capturing drivers.")
            return
        work_dir = Path(self.vars["work_dir"].get()).expanduser().resolve()
        mgr = SystemCaptureManager(self.events.put)

        def worker():
            try:
                drivers_root = mgr.capture_drivers_only(work_dir)
                self.vars["drivers_dir"].set(str(drivers_root))
                self.events.put(("status", f"Drivers captured into: {drivers_root}"))
                self.events.put(("log", f"Drivers captured into: {drivers_root}"))
                messagebox.showinfo(
                    "Drivers captured",
                    f"Drivers exported into:\n{drivers_root}\n\nThis folder is now set as the driver payload for ISO builds.",
                )
            except Exception as e:
                self.events.put(("status", f"Driver capture failed: {e}"))
                self.events.put(("error", str(e) + "\n\n" + traceback.format_exc()))

        threading.Thread(target=worker, daemon=True).start()

    def _save_settings(self):
        try:
            CONFIG_FILE.write_text(json.dumps(self._collect(), indent=2), encoding="utf-8")
        except OSError as e:
            self._log(f"Could not save settings: {e}")

    def _load_settings(self):
        try:
            if CONFIG_FILE.exists():
                data = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
                for key, var in self.vars.items():
                    if key in data and isinstance(data[key], str):
                        var.set(data[key])
        except Exception as e:
            self._log(f"Settings were not loaded: {e}")

    def _close(self):
        if self.busy and not messagebox.askyesno(
            "Build running", "A build is running. Request cancellation and close?"
        ):
            return
        if self.busy:
            self.cancel_event.set()
        self._save_settings()
        self.root.destroy()


def main():
    root = tk.Tk()
    WorkbenchApp(root)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        traceback.print_exc()
        try:
            input("Application error. Press Enter to close...")
        except Exception:
            pass
