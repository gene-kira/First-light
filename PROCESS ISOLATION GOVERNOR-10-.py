#!/usr/bin/env python3
# ======================================================================
# PROCESS RELATION MONITOR + AI ADVISORY + ENFORCEMENT + TUNABLE THRESHOLD + ISOLATION FOREST
# - Immediate scan & populate on startup
# - Background monitor loop (3s)
# - Auto-refresh every 5 minutes
# - Manual refresh button
# - Right-click Allow / Block / Monitor (policy, persisted)
# - Vertical + Horizontal scrollbars
# - ThreatScore (0–100) based on behavior + origin
# - AI-style verdict + isolation recommendation
# - Enforcement: Apply Enforcement terminates blocked processes above ThreatScore threshold
# - Threshold slider (0–100), persisted across reboots
# - Sorting: reds and yellows (red/shady) always at the top, then normal/green
# - Isolation Forest anomaly detection: outliers highlighted and sorted to the top
# ======================================================================

import os
import sys
import json
import time
import threading
import psutil
import tkinter as tk
from tkinter import ttk

from sklearn.ensemble import IsolationForest

# ======================================================================
# AUTOLOADER
# ======================================================================

REQUIRED_LIBS = ["psutil", "sklearn"]

def autoloader():
    for lib in REQUIRED_LIBS:
        try:
            __import__(lib)
        except ImportError:
            import subprocess
            subprocess.call([sys.executable, "-m", "pip", "install", lib])

autoloader()

# ======================================================================
# PATHS
# ======================================================================

APP_ROOT = os.path.join(os.path.expanduser("~"), "ProcessRelationMonitor")
os.makedirs(APP_ROOT, exist_ok=True)

LOG_FILE = os.path.join(APP_ROOT, "interactions.log.jsonl")
POLICY_FILE = os.path.join(APP_ROOT, "policy.json")
CONFIG_FILE = os.path.join(APP_ROOT, "config.json")

# ======================================================================
# CONFIG (THRESHOLD PERSISTENCE)
# ======================================================================

DEFAULT_CONFIG = {
    "enforcement_threshold": 40  # default ThreatScore threshold
}

def load_config():
    if not os.path.exists(CONFIG_FILE):
        return DEFAULT_CONFIG.copy()
    try:
        with open(CONFIG_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        cfg = DEFAULT_CONFIG.copy()
        cfg.update(data)
        return cfg
    except:
        return DEFAULT_CONFIG.copy()

def save_config(cfg):
    with open(CONFIG_FILE, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)

CONFIG = load_config()

# ======================================================================
# POLICY ENGINE
# ======================================================================

DEFAULT_POLICY = "monitor"  # allow | block | monitor

def load_policy():
    if not os.path.exists(POLICY_FILE):
        return {}
    try:
        with open(POLICY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        return {}

def save_policy(policy):
    with open(POLICY_FILE, "w", encoding="utf-8") as f:
        json.dump(policy, f, indent=2)

POLICY = load_policy()

def set_policy(exe, mode):
    POLICY[exe] = mode
    save_policy(POLICY)

def get_policy(exe):
    return POLICY.get(exe, DEFAULT_POLICY)

# ======================================================================
# CLASSIFICATION + THREAT SCORE + AI VERDICT
# ======================================================================

PYTHON_FREE_ZONE_NAMES = {"python.exe", "pythonw.exe"}

WINDOWS_ROOT_HINTS = [
    os.path.join(os.environ.get("SystemRoot", r"C:\Windows")),
]

NORMAL_INSTALL_HINTS = [
    os.path.join(os.environ.get("ProgramFiles", r"C:\Program Files")),
    os.path.join(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
]

SHADY_HINT_PATHS = [
    os.path.join(os.path.expanduser("~"), "Downloads"),
    os.path.join(os.path.expanduser("~"), "Desktop"),
    os.path.join(os.path.expanduser("~"), "AppData", "Local", "Temp"),
]

def is_under(path, root):
    try:
        path = os.path.abspath(path)
        root = os.path.abspath(root)
        return path.lower().startswith(root.lower())
    except:
        return False

def ai_verdict_from_threat(threat):
    if threat <= 10:
        return "Safe"
    elif threat <= 30:
        return "Watch"
    elif threat <= 60:
        return "Suspicious"
    else:
        return "Critical"

def isolation_hint_from_threat(threat):
    if threat <= 10:
        return "Not needed"
    elif threat <= 30:
        return "Optional"
    elif threat <= 60:
        return "Consider"
    else:
        return "Recommend"

def classify_process(name, exe, conn_count, cpu_pct, rss_mb, spawn_count):
    zone = "normal"
    color = "#CCCCCC"
    label = "Normal"
    base_risk = 1

    n_lower = (name or "").lower()

    # Python free zone
    if n_lower in PYTHON_FREE_ZONE_NAMES:
        threat = 0
        return {
            "zone": "python_free",
            "color": "#4A90E2",
            "label": "Python Free Zone",
            "risk_score": 0,
            "threat_score": threat,
            "ai_verdict": ai_verdict_from_threat(threat),
            "isolation": isolation_hint_from_threat(threat)
        }

    # Windows-origin
    for wroot in WINDOWS_ROOT_HINTS:
        if exe and is_under(exe, wroot):
            zone = "windows"
            color = "#4CAF50"
            label = "Windows Origin"
            base_risk = 1
            break

    # Normal install
    if zone == "normal":
        for nroot in NORMAL_INSTALL_HINTS:
            if exe and is_under(exe, nroot):
                zone = "normal"
                color = "#CCCCCC"
                label = "Normal Install"
                base_risk = 1
                break

    # Shady install
    if zone == "normal":
        shady_hit = False
        for sroot in SHADY_HINT_PATHS:
            if exe and is_under(exe, sroot):
                shady_hit = True
                break
        if (not exe) or shady_hit:
            zone = "shady"
            color = "#FFC107"
            label = "Shady / Non-standard"
            base_risk = 3

    # High activity → red zone
    if zone in ("shady", "normal") and conn_count >= 10:
        zone = "red"
        color = "#F44336"
        label = "High Activity / Red Zone"
        base_risk = 5

    # ThreatScore (0–100) heuristic
    threat = 0
    threat += base_risk * 10
    threat += min(conn_count * 3, 30)
    threat += min(int(cpu_pct / 5), 20)
    threat += min(int(rss_mb / 200), 15)
    threat += min(spawn_count * 5, 25)

    if zone == "windows":
        threat = max(threat - 20, 0)
    if zone == "python_free":
        threat = 0

    threat = max(0, min(threat, 100))

    return {
        "zone": zone,
        "color": color,
        "label": label,
        "risk_score": base_risk,
        "threat_score": threat,
        "ai_verdict": ai_verdict_from_threat(threat),
        "isolation": isolation_hint_from_threat(threat)
    }

# ======================================================================
# INTERACTION MODEL
# ======================================================================

class Interaction:
    def __init__(self, src_pid, src_name, src_exe,
                 dst_pid, dst_name, dst_exe,
                 kind, timestamp,
                 src_conn_count, dst_conn_count,
                 src_cpu_pct, dst_cpu_pct,
                 src_rss_mb, dst_rss_mb,
                 src_spawn_count, dst_spawn_count):

        self.src_pid = src_pid
        self.src_name = src_name
        self.src_exe = src_exe
        self.dst_pid = dst_pid
        self.dst_name = dst_name
        self.dst_exe = dst_exe
        self.kind = kind
        self.timestamp = timestamp

        self.src_conn_count = src_conn_count
        self.dst_conn_count = dst_conn_count
        self.src_cpu_pct = src_cpu_pct
        self.dst_cpu_pct = dst_cpu_pct
        self.src_rss_mb = src_rss_mb
        self.dst_rss_mb = dst_rss_mb
        self.src_spawn_count = src_spawn_count
        self.dst_spawn_count = dst_spawn_count

        self.src_class = classify_process(
            src_name, src_exe,
            src_conn_count, src_cpu_pct, src_rss_mb, src_spawn_count
        )
        self.dst_class = classify_process(
            dst_name, dst_exe,
            dst_conn_count, dst_cpu_pct, dst_rss_mb, dst_spawn_count
        )

        self.src_policy = get_policy(src_exe)
        self.dst_policy = get_policy(dst_exe)

        # Isolation Forest anomaly fields (per interaction)
        self.anomaly_score = 0.0
        self.anomaly_label = "Unknown"

    def to_dict(self):
        return {
            "src_pid": self.src_pid,
            "src_name": self.src_name,
            "src_exe": self.src_exe,
            "dst_pid": self.dst_pid,
            "dst_name": self.dst_name,
            "dst_exe": self.dst_exe,
            "kind": self.kind,
            "timestamp": self.timestamp,
            "src_conn_count": self.src_conn_count,
            "dst_conn_count": self.dst_conn_count,
            "src_cpu_pct": self.src_cpu_pct,
            "dst_cpu_pct": self.dst_cpu_pct,
            "src_rss_mb": self.src_rss_mb,
            "dst_rss_mb": self.dst_rss_mb,
            "src_spawn_count": self.src_spawn_count,
            "dst_spawn_count": self.dst_spawn_count,
            "src_class": self.src_class,
            "dst_class": self.dst_class,
            "src_policy": self.src_policy,
            "dst_policy": self.dst_policy,
            "anomaly_score": self.anomaly_score,
            "anomaly_label": self.anomaly_label
        }

# ======================================================================
# LOGGING
# ======================================================================

class InteractionLog:
    def __init__(self, path):
        self.path = path
        self.lock = threading.Lock()

    def append(self, interaction):
        line = json.dumps(interaction.to_dict())
        with self.lock:
            with open(self.path, "a", encoding="utf-8") as f:
                f.write(line + "\n")

# ======================================================================
# MONITOR CORE
# ======================================================================

class RelationMonitor:
    def __init__(self, log):
        self.log = log
        self.running = False
        self.thread = None
        self.latest_interactions = []
        self.latest_lock = threading.Lock()
        self.spawn_counts = {}  # pid -> spawn count

        self.iso_model = None

    def start(self):
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def stop(self):
        self.running = False

    def initial_scan(self):
        try:
            interactions = self._scan_once()
            with self.latest_lock:
                self.latest_interactions = interactions
            for inter in interactions:
                self.log.append(inter)
        except Exception as e:
            print(f"[ERROR] initial_scan: {e}")

    def _loop(self):
        while self.running:
            try:
                interactions = self._scan_once()
                if interactions:
                    with self.latest_lock:
                        self.latest_interactions = interactions
                    for inter in interactions:
                        self.log.append(inter)
            except Exception as e:
                print(f"[ERROR] monitor loop: {e}")
            time.sleep(3)

    def _scan_once(self):
        procs = {}
        conn_counts = {}
        cpu_pcts = {}
        rss_mbs = {}

        for p in psutil.process_iter(['pid', 'name', 'exe', 'ppid']):
            try:
                procs[p.pid] = p
            except:
                continue

        for pid, p in procs.items():
            try:
                cpu_pcts[pid] = p.cpu_percent(interval=0.0)
            except:
                cpu_pcts[pid] = 0.0

        for pid, p in procs.items():
            try:
                rss = p.memory_info().rss
                rss_mbs[pid] = rss / (1024 * 1024)
            except:
                rss_mbs[pid] = 0.0

            count = 0
            try:
                for c in p.connections(kind='tcp'):
                    if c.status == psutil.CONN_ESTABLISHED:
                        count += 1
            except:
                pass
            conn_counts[pid] = count

        interactions = []
        now = time.time()

        # Parent-child spawn
        for pid, p in procs.items():
            try:
                ppid = p.info.get('ppid')
                if ppid and ppid in procs:
                    parent = procs[ppid]
                    self.spawn_counts[pid] = self.spawn_counts.get(pid, 0) + 1

                    src_pid = parent.pid
                    dst_pid = p.pid

                    src_cpu = cpu_pcts.get(src_pid, 0.0)
                    dst_cpu = cpu_pcts.get(dst_pid, 0.0)
                    src_rss = rss_mbs.get(src_pid, 0.0)
                    dst_rss = rss_mbs.get(dst_pid, 0.0)
                    src_conn = conn_counts.get(src_pid, 0)
                    dst_conn = conn_counts.get(dst_pid, 0)
                    src_spawn = self.spawn_counts.get(src_pid, 0)
                    dst_spawn = self.spawn_counts.get(dst_pid, 0)

                    inter = Interaction(
                        src_pid, parent.info.get('name'), parent.info.get('exe'),
                        dst_pid, p.info.get('name'), p.info.get('exe'),
                        "spawn", now,
                        src_conn, dst_conn,
                        src_cpu, dst_cpu,
                        src_rss, dst_rss,
                        src_spawn, dst_spawn
                    )
                    interactions.append(inter)
            except:
                continue

        # Network relationships
        try:
            conns = psutil.net_connections(kind='tcp')
            port_to_pids = {}
            for pid, p in procs.items():
                try:
                    for c in p.connections(kind='tcp'):
                        if c.laddr and c.laddr.port:
                            port_to_pids.setdefault(c.laddr.port, set()).add(pid)
                except:
                    continue

            for c in conns:
                if not c.laddr or not c.raddr:
                    continue
                src_pid = c.pid
                if not src_pid:
                    continue
                dst_pids = port_to_pids.get(c.raddr.port, set())
                for dst_pid in dst_pids:
                    if dst_pid == src_pid:
                        continue
                    src = procs.get(src_pid)
                    dst = procs.get(dst_pid)
                    if not src or not dst:
                        continue

                    src_cpu = cpu_pcts.get(src_pid, 0.0)
                    dst_cpu = cpu_pcts.get(dst_pid, 0.0)
                    src_rss = rss_mbs.get(src_pid, 0.0)
                    dst_rss = rss_mbs.get(dst_pid, 0.0)
                    src_conn = conn_counts.get(src_pid, 0)
                    dst_conn = conn_counts.get(dst_pid, 0)
                    src_spawn = self.spawn_counts.get(src_pid, 0)
                    dst_spawn = self.spawn_counts.get(dst_pid, 0)

                    inter = Interaction(
                        src.pid, src.info.get('name'), src.info.get('exe'),
                        dst.pid, dst.info.get('name'), dst.info.get('exe'),
                        "network", now,
                        src_conn, dst_conn,
                        src_cpu, dst_cpu,
                        src_rss, dst_rss,
                        src_spawn, dst_spawn
                    )
                    interactions.append(inter)
        except:
            pass

        # Isolation Forest anomaly detection over interactions
        try:
            if len(interactions) >= 20:
                features = []
                for inter in interactions:
                    features.append([
                        inter.src_conn_count,
                        inter.dst_conn_count,
                        inter.src_cpu_pct,
                        inter.dst_cpu_pct,
                        inter.src_rss_mb,
                        inter.dst_rss_mb,
                        inter.src_spawn_count,
                        inter.dst_spawn_count
                    ])

                self.iso_model = IsolationForest(
                    contamination=0.1,
                    random_state=42
                )
                self.iso_model.fit(features)
                scores = self.iso_model.decision_function(features)
                preds = self.iso_model.predict(features)

                for inter, score, pred in zip(interactions, scores, preds):
                    inter.anomaly_score = float(-score)  # higher = more anomalous
                    inter.anomaly_label = "Outlier" if pred == -1 else "Normal"
            else:
                for inter in interactions:
                    inter.anomaly_score = 0.0
                    inter.anomaly_label = "Unknown"
        except Exception as e:
            print(f"[ERROR] isolation forest: {e}")
            for inter in interactions:
                inter.anomaly_score = 0.0
                inter.anomaly_label = "Unknown"

        return interactions

    def get_latest_interactions(self):
        with self.latest_lock:
            return list(self.latest_interactions)

# ======================================================================
# GUI
# ======================================================================

class MonitorGUI:
    def __init__(self, root, monitor):
        self.root = root
        self.monitor = monitor

        self.root.title("Process Relation Monitor - AI Advisory + Tunable Enforcement + Anomaly Detection")
        self.root.geometry("1600x840")

        frame = tk.Frame(root)
        frame.pack(fill=tk.BOTH, expand=True)

        vscroll = tk.Scrollbar(frame, orient=tk.VERTICAL)
        hscroll = tk.Scrollbar(frame, orient=tk.HORIZONTAL)

        self.tree = ttk.Treeview(
            frame,
            columns=(
                "src", "dst", "kind",
                "src_zone", "dst_zone",
                "src_pol", "dst_pol",
                "src_cpu", "dst_cpu",
                "src_mem", "dst_mem",
                "src_conn", "dst_conn",
                "src_threat", "dst_threat",
                "src_ai", "dst_ai",
                "src_iso", "dst_iso",
                "anomaly_label", "anomaly_score"
            ),
            show="headings",
            yscrollcommand=vscroll.set,
            xscrollcommand=hscroll.set
        )

        vscroll.config(command=self.tree.yview)
        hscroll.config(command=self.tree.xview)

        vscroll.pack(side=tk.RIGHT, fill=tk.Y)
        hscroll.pack(side=tk.BOTTOM, fill=tk.X)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        # Headings
        self.tree.heading("src", text="Source")
        self.tree.heading("dst", text="Target")
        self.tree.heading("kind", text="Type")
        self.tree.heading("src_zone", text="Source Zone")
        self.tree.heading("dst_zone", text="Target Zone")
        self.tree.heading("src_pol", text="Src Policy")
        self.tree.heading("dst_pol", text="Dst Policy")
        self.tree.heading("src_cpu", text="Src CPU%")
        self.tree.heading("dst_cpu", text="Dst CPU%")
        self.tree.heading("src_mem", text="Src Mem MB")
        self.tree.heading("dst_mem", text="Dst Mem MB")
        self.tree.heading("src_conn", text="Src Conn")
        self.tree.heading("dst_conn", text="Dst Conn")
        self.tree.heading("src_threat", text="Src ThreatScore")
        self.tree.heading("dst_threat", text="Dst ThreatScore")
        self.tree.heading("src_ai", text="Src AI Verdict")
        self.tree.heading("dst_ai", text="Dst AI Verdict")
        self.tree.heading("src_iso", text="Src Isolation")
        self.tree.heading("dst_iso", text="Dst Isolation")
        self.tree.heading("anomaly_label", text="Anomaly")
        self.tree.heading("anomaly_score", text="Anomaly Score")

        # Column widths
        self.tree.column("src", width=260)
        self.tree.column("dst", width=260)
        self.tree.column("kind", width=80)
        self.tree.column("src_zone", width=140)
        self.tree.column("dst_zone", width=140)
        self.tree.column("src_pol", width=90)
        self.tree.column("dst_pol", width=90)
        self.tree.column("src_cpu", width=90)
        self.tree.column("dst_cpu", width=90)
        self.tree.column("src_mem", width=100)
        self.tree.column("dst_mem", width=100)
        self.tree.column("src_conn", width=80)
        self.tree.column("dst_conn", width=80)
        self.tree.column("src_threat", width=120)
        self.tree.column("dst_threat", width=120)
        self.tree.column("src_ai", width=110)
        self.tree.column("dst_ai", width=110)
        self.tree.column("src_iso", width=110)
        self.tree.column("dst_iso", width=110)
        self.tree.column("anomaly_label", width=100)
        self.tree.column("anomaly_score", width=120)

        # Color tags
        self.tree.tag_configure("windows", background="#E8F5E9")
        self.tree.tag_configure("shady", background="#FFF8E1")
        self.tree.tag_configure("red", background="#FFEBEE")
        self.tree.tag_configure("python_free", background="#E3F2FD")
        self.tree.tag_configure("normal", background="#F5F5F5")
        self.tree.tag_configure("outlier", background="#FFCDD2")

        # Bottom bar
        bottom = tk.Frame(root)
        bottom.pack(fill=tk.X)

        self.refresh_btn = tk.Button(bottom, text="Refresh Now", command=self.refresh)
        self.refresh_btn.pack(side=tk.LEFT, padx=5, pady=5)

        self.enforce_btn = tk.Button(bottom, text="Apply Enforcement", command=self.apply_enforcement)
        self.enforce_btn.pack(side=tk.LEFT, padx=5, pady=5)

        # Threshold slider
        self.threshold_var = tk.IntVar(value=CONFIG.get("enforcement_threshold", 40))
        self.threshold_scale = tk.Scale(
            bottom,
            from_=0,
            to=100,
            orient=tk.HORIZONTAL,
            label="ThreatScore Threshold (Block + ≥)",
            variable=self.threshold_var,
            length=300
        )
        self.threshold_scale.pack(side=tk.LEFT, padx=10, pady=5)

        self.status_label = tk.Label(
            bottom,
            text=f"AI advisory + tunable enforcement + anomaly detection. Current threshold: {self.threshold_var.get()}."
        )
        self.status_label.pack(side=tk.LEFT, padx=10)

        # Right-click menu
        self.menu = tk.Menu(self.root, tearoff=0)
        self.menu.add_command(label="Allow", command=lambda: self._set_policy("allow"))
        self.menu.add_command(label="Block", command=lambda: self._set_policy("block"))
        self.menu.add_command(label="Monitor", command=lambda: self._set_policy("monitor"))

        self.tree.bind("<Button-3>", self._popup)

        self.refresh()
        self.root.after(300000, self.auto_refresh)

        # Update status when slider moves
        self.threshold_scale.bind("<ButtonRelease-1>", self._threshold_changed)

    def _threshold_changed(self, event=None):
        val = self.threshold_var.get()
        CONFIG["enforcement_threshold"] = val
        save_config(CONFIG)
        self.status_label.config(
            text=f"AI advisory + tunable enforcement + anomaly detection. Current threshold: {val}."
        )

    def auto_refresh(self):
        self.refresh()
        self.root.after(300000, self.auto_refresh)

    def refresh(self):
        interactions = self.monitor.get_latest_interactions()
        self._rebuild_tree(interactions)

    def _rebuild_tree(self, interactions):
        for i in self.tree.get_children():
            self.tree.delete(i)

        # Sort: outliers first, then reds, then shady, then others; within each, highest ThreatScore first
        def sort_key(inter):
            def zone_priority(z):
                if z == "red":
                    return 0
                if z == "shady":
                    return 1
                return 2

            src_z = inter.src_class["zone"]
            dst_z = inter.dst_class["zone"]
            src_t = inter.src_class["threat_score"]
            dst_t = inter.dst_class["threat_score"]

            worst_zone = src_z
            if zone_priority(dst_z) < zone_priority(src_z):
                worst_zone = dst_z

            max_threat = max(src_t, dst_t)

            anomaly_priority = 0 if inter.anomaly_label == "Outlier" else 1

            return (anomaly_priority, zone_priority(worst_zone), -max_threat)

        interactions_sorted = sorted(interactions, key=sort_key)

        for idx, inter in enumerate(interactions_sorted):
            src_label = f"{inter.src_name} ({inter.src_pid})"
            dst_label = f"{inter.dst_name} ({inter.dst_pid})"

            tag = self._pick_tag(inter.src_class["zone"], inter.dst_class["zone"], inter.anomaly_label)

            self.tree.insert(
                "",
                "end",
                iid=str(idx),
                values=(
                    src_label,
                    dst_label,
                    inter.kind,
                    inter.src_class["label"],
                    inter.dst_class["label"],
                    inter.src_policy,
                    inter.dst_policy,
                    f"{inter.src_cpu_pct:.1f}",
                    f"{inter.dst_cpu_pct:.1f}",
                    f"{inter.src_rss_mb:.1f}",
                    f"{inter.dst_rss_mb:.1f}",
                    inter.src_conn_count,
                    inter.dst_conn_count,
                    inter.src_class["threat_score"],
                    inter.dst_class["threat_score"],
                    inter.src_class["ai_verdict"],
                    inter.dst_class["ai_verdict"],
                    inter.src_class["isolation"],
                    inter.dst_class["isolation"],
                    inter.anomaly_label,
                    f"{inter.anomaly_score:.3f}"
                ),
                tags=(tag,)
            )

    def _pick_tag(self, src_zone, dst_zone, anomaly_label):
        if anomaly_label == "Outlier":
            return "outlier"
        zones = [src_zone, dst_zone]
        if "red" in zones:
            return "red"
        if "shady" in zones:
            return "shady"
        if "python_free" in zones:
            return "python_free"
        if "windows" in zones:
            return "windows"
        return "normal"

    def _popup(self, event):
        row = self.tree.identify_row(event.y)
        if row:
            self.tree.selection_set(row)
            self.menu.post(event.x_root, event.y_root)

    def _set_policy(self, mode):
        row_ids = self.tree.selection()
        if not row_ids:
            return
        row = row_ids[0]
        values = self.tree.item(row, "values")

        src_label = values[0]
        dst_label = values[1]

        try:
            src_pid = int(src_label.split("(")[-1].split(")")[0])
        except:
            src_pid = None
        try:
            dst_pid = int(dst_label.split("(")[-1].split(")")[0])
        except:
            dst_pid = None

        src_exe = None
        dst_exe = None
        if src_pid is not None:
            try:
                src_exe = psutil.Process(src_pid).exe()
            except:
                pass
        if dst_pid is not None:
            try:
                dst_exe = psutil.Process(dst_pid).exe()
            except:
                pass

        if src_exe:
            set_policy(src_exe, mode)
        if dst_exe:
            set_policy(dst_exe, mode)

        self.refresh()

    def apply_enforcement(self):
        threshold = self.threshold_var.get()
        interactions = self.monitor.get_latest_interactions()
        killed = []

        for inter in interactions:
            for side in ("src", "dst"):
                pid = inter.src_pid if side == "src" else inter.dst_pid
                exe = inter.src_exe if side == "src" else inter.dst_exe
                cls = inter.src_class if side == "src" else inter.dst_class
                pol = inter.src_policy if side == "src" else inter.dst_policy

                if not exe or not pid:
                    continue

                if pol == "block" and cls["threat_score"] >= threshold:
                    try:
                        p = psutil.Process(pid)
                        p.terminate()
                        killed.append((pid, exe))
                    except Exception:
                        continue

        if killed:
            msg = f"Enforcement applied (threshold {threshold}). Terminated {len(killed)} process(es)."
        else:
            msg = f"Enforcement applied (threshold {threshold}). No matching blocked high-threat processes."
        self.status_label.config(text=msg)
        self.refresh()

# ======================================================================
# MAIN
# ======================================================================

def main():
    log = InteractionLog(LOG_FILE)
    monitor = RelationMonitor(log)

    monitor.initial_scan()
    monitor.start()

    root = tk.Tk()
    gui = MonitorGUI(root, monitor)
    root.mainloop()

    monitor.stop()

if __name__ == "__main__":
    main()
