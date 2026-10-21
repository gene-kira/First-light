#!/usr/bin/env python3
# DominionDeck Patch Fortifier 3.3 – Single-File, Live Hybrid Security Dashboard
# Features:
# - Smart scan profiles (Quick / Deep / Threat / Integrity / Custom)
# - System + multi-directory + network + plugin scanning
# - Optional auto-scan on startup
# - Risk scoring with 5% AI variance
# - Real-time dashboard (CPU/RAM/ports/anomalies)
# - Alerts, advisory fortification, settings, plugins view
# - Admin / IT / User roles with controls + IT report export
# - CVE check (critical vulnerabilities via online API, advisory only)
# - Automatic CVE mode with configurable schedule (off / 6h / daily / weekly)
# - Admin/IT Windows settings panel (read-only advisory + launch helpers)
# - Extended IT/Admin toolbox: Group Policy, Local Security Policy, Event Viewer, Computer Management, Registry, etc.

import os, sys, importlib, threading, time, traceback, json, platform
import tkinter as tk
from tkinter import ttk
import subprocess

# ============================================================
# AUTOLOADER
# ============================================================

REQUIRED_LIBS = [
    "psutil",
    "numpy",
    "requests",
]

def autoload_libraries():
    missing = []
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            missing.append(lib)
    if missing:
        print("Installing missing libraries:", missing)
        for lib in missing:
            os.system(f"{sys.executable} -m pip install {lib}")
    for lib in REQUIRED_LIBS:
        globals()[lib] = importlib.import_module(lib)

autoload_libraries()
import psutil
import numpy
import requests

# ============================================================
# CONFIG
# ============================================================

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(BASE_DIR, "fortifier_config.json")
PLUGINS_DIR = os.path.join(BASE_DIR, "plugins")

DEFAULT_CONFIG = {
    "auto_scan_on_startup": False,
    "scan_system": True,
    "scan_directories": True,
    "scan_network": True,
    "scan_plugins": True,
    "scan_cve": True,
    "directories": [os.getcwd()],
    "profile": "Quick",
    "refresh_ms": 3000,
    "theme": "light",
    "cve_auto_mode": "off",      # off / 6h / daily / weekly
}

def load_config():
    if not os.path.exists(CONFIG_PATH):
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        cfg = DEFAULT_CONFIG.copy()
        cfg.update(data)
        return cfg
    except Exception:
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    try:
        with open(CONFIG_PATH, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
    except Exception:
        pass

CONFIG = load_config()

# ============================================================
# CORE INFO / AI BALANCE
# ============================================================

def detect_cores():
    try:
        physical = psutil.cpu_count(logical=False)
        logical = psutil.cpu_count(logical=True)
        return {
            "physical": physical,
            "logical": logical,
            "efficiency_estimate": max(logical - physical, 0),
            "performance_estimate": physical
        }
    except Exception:
        return {"physical": 0, "logical": 0, "efficiency_estimate": 0, "performance_estimate": 0}

CORE_INFO = detect_cores()

def ai_balance(score: float) -> float:
    return score * 1.05

# ============================================================
# RISK SCORING
# ============================================================

def classify_finding(f: str) -> str:
    fl = f.lower()
    if "high cpu process" in fl or "high memory usage" in fl:
        return "performance"
    if "low free space" in fl:
        return "storage"
    if "world-writable file" in fl or "stale config/log" in fl:
        return "filesystem"
    if "service listening" in fl:
        return "network"
    if "network scan error" in fl:
        return "error"
    if "[cve]" in fl:
        return "cve"
    return "info"

def base_risk_for_type(t: str) -> int:
    if t == "performance":
        return 60
    if t == "storage":
        return 70
    if t == "filesystem":
        return 75
    if t == "network":
        return 80
    if t == "error":
        return 50
    if t == "cve":
        return 85
    return 10

def compute_risk_score(findings):
    if not findings:
        return 0
    scores = []
    for f in findings:
        t = classify_finding(f)
        scores.append(base_risk_for_type(t))
    avg = sum(scores) / max(len(scores), 1)
    return int(ai_balance(avg))

# ============================================================
# SCANNERS
# ============================================================

class SystemScanner:
    def scan(self):
        findings = []
        os_name = platform.system()
        os_release = platform.release()
        findings.append(f"System: {os_name} {os_release}")
        for proc in psutil.process_iter(attrs=["pid", "name", "cpu_percent"]):
            try:
                cpu = proc.info["cpu_percent"]
                if cpu is None:
                    continue
                if cpu > 80:
                    findings.append(
                        f"High CPU process: {proc.info['name']} (PID {proc.info['pid']}) using {cpu}% CPU"
                    )
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
        vm = psutil.virtual_memory()
        if vm.percent > 85:
            findings.append(f"High memory usage: {vm.percent}% of RAM in use")
        for part in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(part.mountpoint)
                if usage.percent > 90:
                    findings.append(
                        f"Low free space on {part.mountpoint}: {usage.percent}% used"
                    )
            except PermissionError:
                continue
        if len(findings) == 1:
            findings.append("No obvious system pressure detected.")
        return findings

class DirectoryScanner:
    def __init__(self, roots=None):
        self.roots = roots or [os.getcwd()]

    def scan(self):
        findings = []
        max_files = 4000
        count = 0
        for root in self.roots:
            if not os.path.isdir(root):
                findings.append(f"Directory not found or inaccessible: {root}")
                continue
            for dirpath, dirnames, filenames in os.walk(root):
                for fname in filenames:
                    path = os.path.join(dirpath, fname)
                    count += 1
                    if count > max_files:
                        findings.append("Directory scan truncated for safety (too many files).")
                        return findings
                    try:
                        st = os.stat(path)
                        if st.st_mode & 0o002:
                            findings.append(f"World-writable file: {path}")
                        age_days = (time.time() - st.st_mtime) / 86400
                        if age_days > 365 and fname.lower().endswith((".conf", ".ini", ".cfg", ".log")):
                            findings.append(f"Stale config/log (>1 year): {path}")
                    except (PermissionError, FileNotFoundError):
                        continue
        if not findings:
            findings.append(f"No obvious file-permission or stale-config issues under: {', '.join(self.roots)}")
        return findings

class NetworkScanner:
    def scan(self):
        findings = []
        try:
            conns = psutil.net_connections(kind="inet")
            for c in conns:
                if c.status == psutil.CONN_LISTEN:
                    laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "unknown"
                    proc_name = "unknown"
                    if c.pid:
                        try:
                            proc_name = psutil.Process(c.pid).name()
                        except (psutil.NoSuchProcess, psutil.AccessDenied):
                            pass
                    if c.laddr and c.laddr.ip in ("0.0.0.0", "::"):
                        findings.append(
                            f"Service listening on all interfaces: {laddr} (process: {proc_name})"
                        )
                    else:
                        findings.append(
                            f"Service listening: {laddr} (process: {proc_name})"
                        )
        except Exception as e:
            findings.append(f"Network scan error: {e}")
        if not findings:
            findings.append("No listening services detected or unable to enumerate.")
        return findings

# ============================================================
# CVE CHECKER (CRITICAL ONLY, ADVISORY) + AUTO MODE
# ============================================================

class CVEChecker:
    def __init__(self):
        self.last_results = []

    def _query_nvd(self, keyword: str):
        url = "https://services.nvd.nist.gov/rest/json/cves/2.0"
        params = {
            "keywordSearch": keyword,
            "cvssV3Severity": "CRITICAL",
        }
        try:
            r = requests.get(url, params=params, timeout=5)
            if r.status_code != 200:
                return [f"[CVE] NVD query failed for '{keyword}' (HTTP {r.status_code})"]
            data = r.json()
            vulns = data.get("vulnerabilities", [])
            results = []
            for v in vulns[:10]:
                cve = v.get("cve", {})
                id_ = cve.get("id", "unknown")
                metrics = cve.get("metrics", {})
                cvss = metrics.get("cvssMetricV31", metrics.get("cvssMetricV30", []))
                score = "?"
                if cvss:
                    score = cvss[0].get("cvssData", {}).get("baseScore", "?")
                results.append(f"[CVE] {id_} (score {score}) for '{keyword}'")
            if not results:
                return [f"[CVE] No critical CVEs found for '{keyword}'"]
            return results
        except Exception as e:
            return [f"[CVE] Error querying NVD for '{keyword}': {e}"]

    def scan(self):
        findings = []
        os_name = platform.system()
        os_release = platform.release()
        keywords = [f"{os_name} {os_release}"]
        for kw in keywords:
            findings.extend(self._query_nvd(kw))
        self.last_results = findings
        return findings

CVE_CHECKER = CVEChecker()

def cve_interval_seconds(mode: str) -> int:
    if mode == "6h":
        return 6 * 3600
    if mode == "daily":
        return 24 * 3600
    if mode == "weekly":
        return 7 * 24 * 3600
    return 0

class CVEAutoThread(threading.Thread):
    def __init__(self, mode_getter, callback):
        super().__init__(daemon=True)
        self.mode_getter = mode_getter
        self.callback = callback

    def run(self):
        while True:
            mode = self.mode_getter()
            interval = cve_interval_seconds(mode)
            if interval <= 0:
                time.sleep(60)
                continue
            try:
                self.callback()
            except Exception:
                traceback.print_exc()
            time.sleep(interval)

# ============================================================
# PLUGINS
# ============================================================

class PluginManager:
    def __init__(self, plugins_dir):
        self.plugins_dir = plugins_dir
        self.plugins = []
        self.results = {}
        if not os.path.exists(self.plugins_dir):
            os.makedirs(self.plugins_dir, exist_ok=True)
        self.load_plugins()

    def load_plugins(self):
        self.plugins.clear()
        for fname in os.listdir(self.plugins_dir):
            if not fname.endswith(".py"):
                continue
            path = os.path.join(self.plugins_dir, fname)
            mod_name = f"plugin_{os.path.splitext(fname)[0]}"
            try:
                spec = importlib.util.spec_from_file_location(mod_name, path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                if hasattr(mod, "run_scan") and callable(mod.run_scan):
                    self.plugins.append((fname, mod))
            except Exception:
                traceback.print_exc()

    def scan(self):
        findings = []
        self.results.clear()
        for fname, mod in self.plugins:
            try:
                res = mod.run_scan()
                if isinstance(res, list):
                    findings.extend([f"[PLUGIN:{fname}] {r}" for r in res])
                    self.results[fname] = res
            except Exception as e:
                findings.append(f"[PLUGIN:{fname}] error: {e}")
        if not findings and not self.plugins:
            findings.append("No plugins loaded. Add .py files with run_scan() to /plugins.")
        return findings

PLUGIN_MANAGER = PluginManager(PLUGINS_DIR)

# ============================================================
# FORTIFIER CORE
# ============================================================

class PatchFortifier:
    def __init__(self):
        self.findings = []
        self.actions = []
        self.secure = False
        self.system_scanner = SystemScanner()
        self.dir_scanner = DirectoryScanner(CONFIG["directories"])
        self.net_scanner = NetworkScanner()
        self.plugin_manager = PLUGIN_MANAGER
        self.cve_checker = CVE_CHECKER

    def scan(self, profile="Quick", scan_system=True, scan_directories=True,
             scan_network=True, scan_plugins=True, scan_cve=True):
        self.findings.clear()
        if profile == "Quick":
            scan_system = True
            scan_directories = False
            scan_network = True
            scan_plugins = False
            scan_cve = False
        elif profile == "Deep":
            scan_system = True
            scan_directories = True
            scan_network = True
            scan_plugins = True
            scan_cve = True
        elif profile == "Threat":
            scan_system = True
            scan_directories = False
            scan_network = True
            scan_plugins = True
            scan_cve = True
        elif profile == "Integrity":
            scan_system = False
            scan_directories = True
            scan_network = False
            scan_plugins = True
            scan_cve = False
        elif profile == "Custom":
            pass
        if scan_system:
            self.findings.extend(self.system_scanner.scan())
        if scan_directories:
            self.dir_scanner.roots = CONFIG["directories"]
            self.findings.extend(self.dir_scanner.scan())
        if scan_network:
            self.findings.extend(self.net_scanner.scan())
        if scan_plugins:
            self.findings.extend(self.plugin_manager.scan())
        if scan_cve:
            self.findings.extend(self.cve_checker.scan())
        risk_score = compute_risk_score(self.findings)
        self.secure = risk_score < 30
        return self.findings, risk_score

    def fortify(self):
        self.actions.clear()
        if self.secure:
            self.actions.append("System appears secure based on current heuristic checks.")
            return self.actions
        for f in self.findings:
            fl = f.lower()
            if "high cpu process" in fl:
                self.actions.append(f"Recommend: Investigate high-CPU process -> {f}")
            elif "high memory usage" in fl:
                self.actions.append(f"Recommend: Close unused applications or add RAM -> {f}")
            elif "low free space" in fl:
                self.actions.append(f"Recommend: Clean up disk or move data off volume -> {f}")
            elif "world-writable file" in fl:
                self.actions.append(f"Recommend: Restrict permissions on world-writable file -> {f}")
            elif "stale config/log" in fl:
                self.actions.append(f"Recommend: Review or archive stale config/log -> {f}")
            elif "service listening" in fl:
                self.actions.append(f"Recommend: Restrict exposure or firewall listening service -> {f}")
            elif "[cve]" in fl:
                self.actions.append(f"Recommend: Review CVE and apply vendor patches -> {f}")
            elif "[plugin:" in fl:
                self.actions.append(f"Plugin finding: {f}")
            else:
                self.actions.append(f"Info: {f}")
        self.secure = True
        return self.actions

FORTIFIER = PatchFortifier()

# ============================================================
# WATCHDOG / TELEMETRY
# ============================================================

class Watchdog(threading.Thread):
    def __init__(self, callback, interval=5):
        super().__init__(daemon=True)
        self.callback = callback
        self.interval = interval

    def run(self):
        while True:
            try:
                self.callback()
            except Exception:
                traceback.print_exc()
            time.sleep(self.interval)

DASHBOARD_STATE = {
    "cpu": 0.0,
    "ram": 0.0,
    "ports": 0,
    "risk": 0,
    "last_alert": "",
}

def telemetry_tick():
    try:
        DASHBOARD_STATE["cpu"] = psutil.cpu_percent(interval=None)
        DASHBOARD_STATE["ram"] = psutil.virtual_memory().percent
        try:
            conns = psutil.net_connections(kind="inet")
            DASHBOARD_STATE["ports"] = sum(1 for c in conns if c.status == psutil.CONN_LISTEN)
        except Exception:
            DASHBOARD_STATE["ports"] = 0
    except Exception:
        pass

WATCHDOG = Watchdog(telemetry_tick, interval=3)
WATCHDOG.start()

# ============================================================
# WINDOWS SETTINGS HELPERS (ADMIN/IT)
# ============================================================

def open_windows_settings_page(page: str):
    try:
        subprocess.Popen(["start", f"ms-settings:{page}"], shell=True)
    except Exception:
        pass

def open_control_panel_item(item: str):
    try:
        subprocess.Popen(["control.exe", item], shell=True)
    except Exception:
        pass

def open_taskmgr():
    try:
        subprocess.Popen(["taskmgr"], shell=True)
    except Exception:
        pass

def open_services():
    try:
        subprocess.Popen(["services.msc"], shell=True)
    except Exception:
        pass

def open_firewall():
    try:
        subprocess.Popen(["control.exe", "firewall.cpl"], shell=True)
    except Exception:
        pass

def open_powercfg():
    try:
        subprocess.Popen(["powercfg.cpl"], shell=True)
    except Exception:
        pass

def open_eventvwr():
    try:
        subprocess.Popen(["eventvwr.msc"], shell=True)
    except Exception:
        pass

def open_compmgmt():
    try:
        subprocess.Popen(["compmgmt.msc"], shell=True)
    except Exception:
        pass

def open_gpedit():
    try:
        subprocess.Popen(["gpedit.msc"], shell=True)
    except Exception:
        pass

def open_secpol():
    try:
        subprocess.Popen(["secpol.msc"], shell=True)
    except Exception:
        pass

def open_regedit():
    try:
        subprocess.Popen(["regedit.exe"], shell=True)
    except Exception:
        pass

def open_sysdm():
    try:
        subprocess.Popen(["sysdm.cpl"], shell=True)
    except Exception:
        pass

def open_useraccounts():
    try:
        subprocess.Popen(["control.exe", "userpasswords2"], shell=True)
    except Exception:
        pass

# ============================================================
# GUI WITH ROLES + CVE VIEW + AUTO CVE MODE + EXTENDED ADMIN WINDOWS
# ============================================================

class FortifierGUI:
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("DominionDeck Patch Fortifier 3.3 – Live Hybrid Dashboard")

        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass

        role_frame = ttk.Frame(self.root)
        role_frame.pack(fill="x", pady=5)
        ttk.Label(role_frame, text="Role:").pack(side="left", padx=5)
        self.role_var = tk.StringVar(value="admin")
        self.role_combo = ttk.Combobox(
            role_frame,
            textvariable=self.role_var,
            values=["admin", "it", "user"],
            state="readonly",
            width=8,
        )
        self.role_combo.pack(side="left")
        ttk.Label(role_frame, text="(admin = full, it = ops/report, user = limited)").pack(side="left", padx=5)

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True)

        self.tab_dashboard = ttk.Frame(self.notebook)
        self.tab_scan = ttk.Frame(self.notebook)
        self.tab_settings = ttk.Frame(self.notebook)
        self.tab_plugins = ttk.Frame(self.notebook)
        self.tab_cve = ttk.Frame(self.notebook)
        self.tab_admin_win = ttk.Frame(self.notebook)

        self.notebook.add(self.tab_dashboard, text="Dashboard")
        self.notebook.add(self.tab_scan, text="Scan")
        self.notebook.add(self.tab_settings, text="Settings")
        self.notebook.add(self.tab_plugins, text="Plugins")
        self.notebook.add(self.tab_cve, text="CVE")
        self.notebook.add(self.tab_admin_win, text="Admin Windows")

        # Dashboard
        self.status_label = ttk.Label(self.tab_dashboard, text="Status: Idle")
        self.status_label.pack(pady=5)
        self.alert_label = ttk.Label(self.tab_dashboard, text="", foreground="red")
        self.alert_label.pack(pady=5)
        dash_frame = ttk.Frame(self.tab_dashboard)
        dash_frame.pack(fill="x", pady=5)
        self.cpu_label = ttk.Label(dash_frame, text="CPU: 0%")
        self.cpu_label.grid(row=0, column=0, sticky="w", padx=5)
        self.ram_label = ttk.Label(dash_frame, text="RAM: 0%")
        self.ram_label.grid(row=0, column=1, sticky="w", padx=5)
        self.ports_label = ttk.Label(dash_frame, text="Listening ports: 0")
        self.ports_label.grid(row=0, column=2, sticky="w", padx=5)
        self.risk_label = ttk.Label(dash_frame, text="Risk score: 0")
        self.risk_label.grid(row=0, column=3, sticky="w", padx=5)
        self.dashboard_text = tk.Text(self.tab_dashboard, height=20, width=100)
        self.dashboard_text.pack(pady=5)
        core_label = ttk.Label(
            self.tab_dashboard,
            text=f"Cores: P={CORE_INFO['performance_estimate']} "
                 f"E={CORE_INFO['efficiency_estimate']} "
                 f"(logical={CORE_INFO['logical']})"
        )
        core_label.pack(pady=5)

        # Scan
        scan_top = ttk.Frame(self.tab_scan)
        scan_top.pack(fill="x", pady=5)
        ttk.Label(scan_top, text="Profile:").grid(row=0, column=0, sticky="w")
        self.profile_var = tk.StringVar(value=CONFIG["profile"])
        self.profile_combo = ttk.Combobox(
            scan_top,
            textvariable=self.profile_var,
            values=["Quick", "Deep", "Threat", "Integrity", "Custom"],
            state="readonly",
            width=12,
        )
        self.profile_combo.grid(row=0, column=1, sticky="w", padx=5)

        scopes_frame = ttk.LabelFrame(self.tab_scan, text="Custom Scope (used when profile = Custom)")
        scopes_frame.pack(fill="x", pady=5)
        self.var_scan_system = tk.BooleanVar(value=CONFIG["scan_system"])
        self.var_scan_directories = tk.BooleanVar(value=CONFIG["scan_directories"])
        self.var_scan_network = tk.BooleanVar(value=CONFIG["scan_network"])
        self.var_scan_plugins = tk.BooleanVar(value=CONFIG["scan_plugins"])
        self.var_scan_cve = tk.BooleanVar(value=CONFIG["scan_cve"])
        ttk.Checkbutton(scopes_frame, text="System", variable=self.var_scan_system).grid(row=0, column=0, sticky="w")
        ttk.Checkbutton(scopes_frame, text="Directories", variable=self.var_scan_directories).grid(row=0, column=1, sticky="w")
        ttk.Checkbutton(scopes_frame, text="Network", variable=self.var_scan_network).grid(row=0, column=2, sticky="w")
        ttk.Checkbutton(scopes_frame, text="Plugins", variable=self.var_scan_plugins).grid(row=0, column=3, sticky="w")
        ttk.Checkbutton(scopes_frame, text="CVE", variable=self.var_scan_cve).grid(row=0, column=4, sticky="w")

        dirs_frame = ttk.LabelFrame(self.tab_scan, text="Directories to scan")
        dirs_frame.pack(fill="x", pady=5)
        self.dirs_listbox = tk.Listbox(dirs_frame, height=5, width=80)
        self.dirs_listbox.grid(row=0, column=0, columnspan=3, sticky="w")
        for d in CONFIG["directories"]:
            self.dirs_listbox.insert("end", d)
        ttk.Label(dirs_frame, text="Add directory:").grid(row=1, column=0, sticky="w")
        self.dir_entry = ttk.Entry(dirs_frame, width=60)
        self.dir_entry.grid(row=1, column=1, sticky="w")
        ttk.Button(dirs_frame, text="Add", command=self.add_directory).grid(row=1, column=2, sticky="w", padx=5)
        ttk.Button(dirs_frame, text="Remove selected", command=self.remove_directory).grid(row=2, column=2, sticky="w", padx=5)

        btn_frame = ttk.Frame(self.tab_scan)
        btn_frame.pack(fill="x", pady=5)
        self.scan_btn = ttk.Button(btn_frame, text="Run Scan", command=self.manual_scan)
        self.scan_btn.pack(side="left", padx=5)
        self.fortify_btn = ttk.Button(btn_frame, text="Fortify (Advisory)", command=self.manual_fortify)
        self.fortify_btn.pack(side="left", padx=5)
        self.export_btn = ttk.Button(btn_frame, text="Export Last Scan (IT)", command=self.export_report)
        self.export_btn.pack(side="left", padx=5)
        self.scan_output = tk.Text(self.tab_scan, height=20, width=100)
        self.scan_output.pack(pady=5)

        # Settings
        settings_frame = ttk.Frame(self.tab_settings)
        settings_frame.pack(fill="x", pady=5)
        self.var_auto_scan = tk.BooleanVar(value=CONFIG["auto_scan_on_startup"])
        self.auto_chk = ttk.Checkbutton(
            settings_frame,
            text="Auto-scan on startup (uses current profile)",
            variable=self.var_auto_scan,
            command=self.update_config_from_ui,
        )
        self.auto_chk.grid(row=0, column=0, sticky="w", padx=5, pady=5)
        ttk.Label(settings_frame, text="Dashboard refresh (ms):").grid(row=1, column=0, sticky="w", padx=5)
        self.refresh_var = tk.IntVar(value=CONFIG["refresh_ms"])
        self.refresh_spin = ttk.Spinbox(
            settings_frame,
            from_=1000,
            to=10000,
            increment=500,
            textvariable=self.refresh_var,
            width=8,
            command=self.update_config_from_ui,
        )
        self.refresh_spin.grid(row=1, column=1, sticky="w", padx=5)
        ttk.Label(settings_frame, text="Theme:").grid(row=2, column=0, sticky="w", padx=5)
        self.theme_var = tk.StringVar(value=CONFIG["theme"])
        self.theme_combo = ttk.Combobox(
            settings_frame,
            textvariable=self.theme_var,
            values=["light", "dark"],
            state="readonly",
            width=10,
        )
        self.theme_combo.grid(row=2, column=1, sticky="w", padx=5)
        self.theme_combo.bind("<<ComboboxSelected>>", lambda e: self.update_config_from_ui())
        ttk.Label(settings_frame, text="CVE auto mode:").grid(row=3, column=0, sticky="w", padx=5)
        self.cve_auto_var = tk.StringVar(value=CONFIG["cve_auto_mode"])
        self.cve_auto_combo = ttk.Combobox(
            settings_frame,
            textvariable=self.cve_auto_var,
            values=["off", "6h", "daily", "weekly"],
            state="readonly",
            width=10,
        )
        self.cve_auto_combo.grid(row=3, column=1, sticky="w", padx=5)
        self.cve_auto_combo.bind("<<ComboboxSelected>>", lambda e: self.update_config_from_ui())
        self.save_settings_btn = ttk.Button(settings_frame, text="Save Settings", command=self.update_config_from_ui)
        self.save_settings_btn.grid(row=4, column=0, sticky="w", padx=5, pady=5)

        # Plugins
        plugins_frame = ttk.Frame(self.tab_plugins)
        plugins_frame.pack(fill="both", expand=True, pady=5)
        self.reload_plugins_btn = ttk.Button(plugins_frame, text="Reload Plugins", command=self.reload_plugins)
        self.reload_plugins_btn.pack(pady=5)
        self.plugins_list = tk.Listbox(plugins_frame, height=10, width=50)
        self.plugins_list.pack(side="left", padx=5, pady=5)
        self.plugins_output = tk.Text(plugins_frame, height=20, width=60)
        self.plugins_output.pack(side="left", padx=5, pady=5)
        self.refresh_plugins_list()

        # CVE tab
        cve_frame = ttk.Frame(self.tab_cve)
        cve_frame.pack(fill="both", expand=True, pady=5)
        ttk.Label(cve_frame, text="CVE Results (critical only, advisory):").pack(anchor="w", padx=5, pady=5)
        self.cve_output = tk.Text(cve_frame, height=20, width=100)
        self.cve_output.pack(pady=5)
        ttk.Button(cve_frame, text="Run CVE Check Now", command=self.manual_cve_check).pack(pady=5)

        # Admin Windows tab (admin/IT)
        admin_frame = ttk.Frame(self.tab_admin_win)
        admin_frame.pack(fill="both", expand=True, pady=5)

        ttk.Label(admin_frame, text="Admin / IT Windows Controls (launch helpers, advisory only):").pack(anchor="w", padx=5, pady=5)

        # Core troubleshooting row
        row1 = ttk.Frame(admin_frame)
        row1.pack(fill="x", pady=2)
        ttk.Button(row1, text="Task Manager", command=self.launch_taskmgr_guarded).pack(side="left", padx=5)
        ttk.Button(row1, text="Services (services.msc)", command=self.launch_services_guarded).pack(side="left", padx=5)
        ttk.Button(row1, text="Event Viewer", command=self.launch_eventvwr_guarded).pack(side="left", padx=5)
        ttk.Button(row1, text="Computer Management", command=self.launch_compmgmt_guarded).pack(side="left", padx=5)

        # Security / policy row
        row2 = ttk.Frame(admin_frame)
        row2.pack(fill="x", pady=2)
        ttk.Button(row2, text="Group Policy (gpedit.msc)", command=self.launch_gpedit_guarded).pack(side="left", padx=5)
        ttk.Button(row2, text="Local Security Policy (secpol.msc)", command=self.launch_secpol_guarded).pack(side="left", padx=5)
        ttk.Button(row2, text="Firewall Settings", command=self.launch_firewall_guarded).pack(side="left", padx=5)

        # System / accounts row
        row3 = ttk.Frame(admin_frame)
        row3.pack(fill="x", pady=2)
        ttk.Button(row3, text="System Properties", command=self.launch_sysdm_guarded).pack(side="left", padx=5)
        ttk.Button(row3, text="User Accounts", command=self.launch_useraccounts_guarded).pack(side="left", padx=5)
        ttk.Button(row3, text="Registry Editor", command=self.launch_regedit_guarded).pack(side="left", padx=5)

        # Power / update / network / apps row
        row4 = ttk.Frame(admin_frame)
        row4.pack(fill="x", pady=2)
        ttk.Button(row4, text="Power Options", command=self.launch_powercfg_guarded).pack(side="left", padx=5)
        ttk.Button(row4, text="Windows Update Settings", command=self.launch_winupdate_guarded).pack(side="left", padx=5)
        ttk.Button(row4, text="Network Settings", command=self.launch_network_guarded).pack(side="left", padx=5)
        ttk.Button(row4, text="Apps & Features", command=self.launch_appsfeatures_guarded).pack(side="left", padx=5)

        self.admin_win_text = tk.Text(admin_frame, height=15, width=100)
        self.admin_win_text.pack(pady=5)
        self.admin_win_text.insert("end",
            "This panel is advisory and launches built-in Windows tools for IT/Admin:\n"
            "- Task Manager: correlate high-CPU processes and memory pressure from the Dashboard.\n"
            "- Services: manage listening services flagged by the Network scanner.\n"
            "- Event Viewer: investigate errors, warnings, and security events.\n"
            "- Computer Management: access disks, services, users, and more.\n"
            "- Group Policy / Local Security Policy: enforce organization-wide and local security baselines.\n"
            "- Firewall Settings: restrict exposed ports and inbound rules.\n"
            "- System Properties: computer name, performance, remote, environment.\n"
            "- User Accounts: manage local users and passwords.\n"
            "- Registry Editor: advanced configuration (use with extreme care).\n"
            "- Power Options: tune performance vs. efficiency.\n"
            "- Windows Update: ensure patches are applied for CVEs.\n"
            "- Network Settings / Apps & Features: connectivity and installed software management.\n"
        )

        self.last_scan_findings = []
        self.last_scan_risk = 0

        self.apply_role_restrictions()
        self.role_combo.bind("<<ComboboxSelected>>", lambda e: self.apply_role_restrictions())

        if CONFIG["auto_scan_on_startup"]:
            self.root.after(500, self.autonomous_startup)
        self.root.after(CONFIG["refresh_ms"], self.refresh_dashboard)

        # Auto CVE thread
        self.cve_auto_thread = CVEAutoThread(self.get_cve_auto_mode, self.auto_cve_tick)
        self.cve_auto_thread.start()

    # Role restrictions
    def apply_role_restrictions(self):
        role = self.role_var.get()
        state_admin = "normal" if role == "admin" else "disabled"
        self.auto_chk.configure(state=state_admin)
        self.refresh_spin.configure(state=state_admin)
        self.theme_combo.configure(state=state_admin)
        self.cve_auto_combo.configure(state=state_admin)
        self.save_settings_btn.configure(state=state_admin)
        state_dirs = "normal" if role in ("admin", "it") else "disabled"
        self.dir_entry.configure(state=state_dirs)
        self.export_btn.configure(state="normal" if role in ("admin", "it") else "disabled")
        self.reload_plugins_btn.configure(state="normal" if role in ("admin", "it") else "disabled")

        # Admin Windows tab: admin + it only
        for child in self.tab_admin_win.winfo_children():
            try:
                child.configure(state="normal" if role in ("admin", "it") else "disabled")
            except Exception:
                pass

        if role == "user":
            self.profile_var.set("Quick")
            self.profile_combo.configure(state="disabled")
        else:
            self.profile_combo.configure(state="readonly")

    # Config
    def update_config_from_ui(self):
        role = self.role_var.get()
        if role != "admin":
            return
        CONFIG["auto_scan_on_startup"] = self.var_auto_scan.get()
        CONFIG["scan_system"] = self.var_scan_system.get()
        CONFIG["scan_directories"] = self.var_scan_directories.get()
        CONFIG["scan_network"] = self.var_scan_network.get()
        CONFIG["scan_plugins"] = self.var_scan_plugins.get()
        CONFIG["scan_cve"] = self.var_scan_cve.get()
        CONFIG["profile"] = self.profile_var.get()
        CONFIG["refresh_ms"] = int(self.refresh_var.get())
        CONFIG["theme"] = self.theme_var.get()
        CONFIG["directories"] = list(self.dirs_listbox.get(0, "end"))
        CONFIG["cve_auto_mode"] = self.cve_auto_var.get()
        save_config(CONFIG)

    def get_cve_auto_mode(self):
        return CONFIG.get("cve_auto_mode", "off")

    # Directories
    def add_directory(self):
        role = self.role_var.get()
        if role not in ("admin", "it"):
            return
        d = self.dir_entry.get().strip()
        if d and d not in self.dirs_listbox.get(0, "end"):
            self.dirs_listbox.insert("end", d)
            if role == "admin":
                self.update_config_from_ui()

    def remove_directory(self):
        role = self.role_var.get()
        if role not in ("admin", "it"):
            return
        sel = list(self.dirs_listbox.curselection())
        sel.reverse()
        for idx in sel:
            self.dirs_listbox.delete(idx)
        if role == "admin":
            self.update_config_from_ui()

    # Plugins
    def refresh_plugins_list(self):
        self.plugins_list.delete(0, "end")
        for fname, _ in PLUGIN_MANAGER.plugins:
            self.plugins_list.insert("end", fname)

    def reload_plugins(self):
        role = self.role_var.get()
        if role not in ("admin", "it"):
            return
        PLUGIN_MANAGER.load_plugins()
        self.refresh_plugins_list()
        self.plugins_output.insert("end", "Plugins reloaded.\n")

    # CVE tab
    def manual_cve_check(self):
        findings = CVE_CHECKER.scan()
        self.cve_output.insert("end", "=== CVE Check (manual) ===\n")
        for r in findings:
            self.cve_output.insert("end", f"{r}\n")
        self.cve_output.insert("end", "\n")

    def auto_cve_tick(self):
        findings = CVE_CHECKER.scan()
        self.cve_output.insert("end", "=== CVE Check (auto) ===\n")
        for r in findings:
            self.cve_output.insert("end", f"{r}\n")
        self.cve_output.insert("end", "\n")

    # Admin Windows launch guards (role-aware)
    def launch_taskmgr_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_taskmgr()

    def launch_services_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_services()

    def launch_firewall_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_firewall()

    def launch_powercfg_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_powercfg()

    def launch_winupdate_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_windows_settings_page("windowsupdate")

    def launch_network_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_windows_settings_page("network")

    def launch_appsfeatures_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_windows_settings_page("appsfeatures")

    def launch_eventvwr_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_eventvwr()

    def launch_compmgmt_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_compmgmt()

    def launch_gpedit_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_gpedit()

    def launch_secpol_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_secpol()

    def launch_regedit_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_regedit()

    def launch_sysdm_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_sysdm()

    def launch_useraccounts_guarded(self):
        if self.role_var.get() not in ("admin", "it"):
            return
        open_useraccounts()

    # Startup scan
    def autonomous_startup(self):
        role = self.role_var.get()
        profile = self.profile_var.get()
        if role == "user":
            profile = "Quick"
        self.scan_output.insert("end", "=== Autonomous Startup Scan ===\n")
        findings, risk = FORTIFIER.scan(
            profile=profile,
            scan_system=self.var_scan_system.get(),
            scan_directories=self.var_scan_directories.get(),
            scan_network=self.var_scan_network.get(),
            scan_plugins=self.var_scan_plugins.get(),
            scan_cve=self.var_scan_cve.get(),
        )
        for r in findings:
            self.scan_output.insert("end", f"{r}\n")
        self.scan_output.insert("end", f"\nRisk score: {risk}\n\n")
        self.last_scan_findings = findings
        self.last_scan_risk = risk
        DASHBOARD_STATE["risk"] = risk
        self.update_status_and_alert(risk)

    # Manual scan / fortify
    def manual_scan(self):
        role = self.role_var.get()
        profile = self.profile_var.get()
        if role == "user":
            profile = "Quick"
        self.scan_output.insert("end", "=== Manual Scan ===\n")
        findings, risk = FORTIFIER.scan(
            profile=profile,
            scan_system=self.var_scan_system.get(),
            scan_directories=self.var_scan_directories.get(),
            scan_network=self.var_scan_network.get(),
            scan_plugins=self.var_scan_plugins.get(),
            scan_cve=self.var_scan_cve.get(),
        )
        for r in findings:
            self.scan_output.insert("end", f"{r}\n")
        self.scan_output.insert("end", f"\nRisk score: {risk}\n\n")
        self.last_scan_findings = findings
        self.last_scan_risk = risk
        DASHBOARD_STATE["risk"] = risk
        self.update_status_and_alert(risk)
        self.dashboard_text.insert("end", "=== Latest Scan ===\n")
        for r in findings:
            self.dashboard_text.insert("end", f"{r}\n")
        self.dashboard_text.insert("end", f"\nRisk score: {risk}\n\n")

    def manual_fortify(self):
        self.scan_output.insert("end", "=== Fortification (Advisory) ===\n")
        actions = FORTIFIER.fortify()
        for a in actions:
            self.scan_output.insert("end", f"{a}\n")
        self.scan_output.insert("end", "\n")
        self.update_status_and_alert(DASHBOARD_STATE.get("risk", 0))

    # IT report
    def export_report(self):
        role = self.role_var.get()
        if role not in ("admin", "it"):
            return
        report_path = os.path.join(BASE_DIR, "fortifier_report.txt")
        try:
            with open(report_path, "w", encoding="utf-8") as f:
                f.write("DominionDeck Fortifier Report\n")
                f.write(f"Role: {role}\n")
                f.write(f"Risk score: {self.last_scan_risk}\n\n")
                for r in self.last_scan_findings:
                    f.write(f"{r}\n")
            self.scan_output.insert("end", f"Report exported to {report_path}\n")
        except Exception as e:
            self.scan_output.insert("end", f"Failed to export report: {e}\n")

    # Dashboard
    def refresh_dashboard(self):
        cpu = DASHBOARD_STATE.get("cpu", 0.0)
        ram = DASHBOARD_STATE.get("ram", 0.0)
        ports = DASHBOARD_STATE.get("ports", 0)
        risk = DASHBOARD_STATE.get("risk", 0)
        self.cpu_label.config(text=f"CPU: {cpu:.1f}%")
        self.ram_label.config(text=f"RAM: {ram:.1f}%")
        self.ports_label.config(text=f"Listening ports: {ports}")
        self.risk_label.config(text=f"Risk score: {risk}")
        if cpu > 90 or ram > 90 or risk >= 70:
            self.alert_label.config(text="ALERT: High risk or resource pressure detected!")
        elif ports > 20 and risk >= 50:
            self.alert_label.config(text="ALERT: Many listening services + elevated risk.")
        else:
            if DASHBOARD_STATE.get("last_alert", "") == "":
                self.alert_label.config(text="")
        self.root.after(CONFIG["refresh_ms"], self.refresh_dashboard)

    def update_status_and_alert(self, risk):
        if risk < 30:
            self.status_label.config(text="Status: Secure (low risk)")
            self.alert_label.config(text="")
            DASHBOARD_STATE["last_alert"] = ""
        elif risk < 60:
            self.status_label.config(text="Status: Elevated risk")
            self.alert_label.config(text="Warning: Elevated risk detected.")
            DASHBOARD_STATE["last_alert"] = "warning"
        else:
            self.status_label.config(text="Status: High risk")
            self.alert_label.config(text="ALERT: High risk detected. Review fortification advice.")
            DASHBOARD_STATE["last_alert"] = "alert"

    def run(self):
        self.root.mainloop()

# ============================================================
# MAIN
# ============================================================

if __name__ == "__main__":
    gui = FortifierGUI()
    gui.run()
