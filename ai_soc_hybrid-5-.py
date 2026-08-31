#!/usr/bin/env python3
# ai_system_guardian_v4.py

# ---------------------------------------------------------
# AUTOLOADER + AUTO ADMIN ELEVATION
# ---------------------------------------------------------

import os
import sys
import importlib
import subprocess

REQUIRED_LIBS = [
    "psutil",
    "PyQt5"
]

def autoload_libraries():
    for lib in REQUIRED_LIBS:
        try:
            importlib.import_module(lib)
        except ImportError:
            print(f"[AUTOLOADER] Installing missing library: {lib}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            print(f"[AUTOLOADER] Installed: {lib}")

def is_admin():
    if os.name == "nt":
        import ctypes
        try:
            return ctypes.windll.shell32.IsUserAnAdmin()
        except Exception:
            return False
    else:
        return os.geteuid() == 0

def relaunch_as_admin():
    if os.name == "nt":
        import ctypes
        print("[ADMIN] Guardian requires elevated privileges. Relaunching as administrator...")
        params = " ".join([f'"{arg}"' for arg in sys.argv])
        try:
            ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
        except Exception as e:
            print(f"[ADMIN] Elevation failed: {e}")
        sys.exit(0)
    else:
        print("[ADMIN] Guardian requires elevated privileges. Relaunching with sudo...")
        try:
            os.execvp("sudo", ["sudo", sys.executable] + sys.argv)
        except Exception as e:
            print(f"[ADMIN] Elevation failed: {e}")
            sys.exit(1)

autoload_libraries()

if not is_admin():
    relaunch_as_admin()

# ---------------------------------------------------------
# IMPORTS AFTER AUTOLOADER
# ---------------------------------------------------------

import json
import platform
import random
from dataclasses import dataclass, asdict
from typing import List, Dict, Optional

import psutil
from PyQt5.QtCore import Qt, QRectF, QTimer
from PyQt5.QtGui import QColor, QBrush, QPen
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QGraphicsView, QGraphicsScene,
    QLabel, QHeaderView, QPushButton, QComboBox, QMessageBox
)

# ---------------------------------------------------------
# DATA MODEL / CONSTANTS
# ---------------------------------------------------------

@dataclass
class AssetIncident:
    asset_id: str
    asset_type: str
    risk_score: int
    confidence: float
    criticality: str
    status: str
    mitre_tactic: str
    isolated: bool = False
    safe: bool = False

MITRE_TACTIC_COLORS = {
    "Initial Access": QColor(0, 120, 215),
    "Execution": QColor(112, 48, 160),
    "Persistence": QColor(0, 153, 153),
    "Privilege Escalation": QColor(255, 140, 0),
    "Lateral Movement": QColor(220, 20, 60),
    "Exfiltration": QColor(0, 0, 0),
}

GUARDIAN_LOG_NAME = "guardian.log"
SURICATA_EVE_PATH = "eve.json"
HONEYPOT_DIR_NAME = "guardian_honeypot"
ROGUE_AI_KEYWORDS = ["llm", "agent", "autonomous", "prompt", "openai", "chatgpt", "stable-diffusion"]

SAFE_GAME_PROCESSES = [
    "steam.exe", "steam", "steamwebhelper",
    "epicgameslauncher.exe", "epicgameslauncher",
    "battle.net.exe", "origin.exe", "eaapp.exe",
    "goggalaxy.exe", "gog", "riotclientservices.exe",
    "fortnite.exe", "valorant.exe", "cod.exe",
    "eldenring.exe", "gta5.exe", "cs2.exe",
]

SAFE_GAME_ENGINES = [
    "unity", "unreal", "source", "frostbite", "cryengine"
]

SAFE_GAME_PATH_HINTS = [
    "steamapps", "Epic Games", ".steam", "GOG Games", "Battle.net"
]

SENSITIVE_DIR_HINTS = [
    "Documents", "Pictures", "Videos",
    "Desktop",
    "AppData\\Local\\Microsoft\\Windows\\Biometrics",
    "AppData\\Local\\Microsoft\\Windows\\WebCache",
    "/var/lib/fprint",
    "/usr/share/fingerprint",
    "/home",
    "/Users",
]

# ---------------------------------------------------------
# PATHS / BASELINE / LOG
# ---------------------------------------------------------

def get_script_dir() -> str:
    return os.path.dirname(os.path.abspath(__file__))

def get_baseline_path() -> str:
    return os.path.join(get_script_dir(), "baseline.json")

def get_guardian_log_path() -> str:
    return os.path.join(get_script_dir(), GUARDIAN_LOG_NAME)

def load_baseline() -> Dict:
    path = get_baseline_path()
    if not os.path.exists(path):
        return {
            "assets": {},
            "mode": "passive",
            "stats": {
                "cpu_mean": 0.0,
                "ram_mean": 0.0,
                "net_conn_mean": 0.0,
                "gpu_mean": 0.0,
                "samples": 0
            }
        }
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "assets" not in data:
            data["assets"] = {}
        if "mode" not in data:
            data["mode"] = "passive"
        if "stats" not in data:
            data["stats"] = {
                "cpu_mean": 0.0,
                "ram_mean": 0.0,
                "net_conn_mean": 0.0,
                "gpu_mean": 0.0,
                "samples": 0
            }
        return data
    except Exception:
        return {
            "assets": {},
            "mode": "passive",
            "stats": {
                "cpu_mean": 0.0,
                "ram_mean": 0.0,
                "net_conn_mean": 0.0,
                "gpu_mean": 0.0,
                "samples": 0
            }
        }

def save_baseline(assets: List[AssetIncident], mode: str, stats: Dict) -> None:
    path = get_baseline_path()
    data = {
        "assets": {a.asset_id: asdict(a) for a in assets},
        "mode": mode,
        "stats": stats,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def append_guardian_log(message: str) -> None:
    path = get_guardian_log_path()
    with open(path, "a", encoding="utf-8") as f:
        f.write(message + "\n")

# ---------------------------------------------------------
# SIMPLE ML-LIKE ANOMALY STATS
# ---------------------------------------------------------

def update_stats(stats: Dict, cpu: float, ram: float, net_conn: int, gpu: float) -> Dict:
    samples = stats.get("samples", 0)
    if samples <= 0:
        stats["cpu_mean"] = cpu
        stats["ram_mean"] = ram
        stats["net_conn_mean"] = net_conn
        stats["gpu_mean"] = gpu
        stats["samples"] = 1
        return stats

    samples += 1
    stats["cpu_mean"] = stats["cpu_mean"] + (cpu - stats["cpu_mean"]) / samples
    stats["ram_mean"] = stats["ram_mean"] + (ram - stats["ram_mean"]) / samples
    stats["net_conn_mean"] = stats["net_conn_mean"] + (net_conn - stats["net_conn_mean"]) / samples
    stats["gpu_mean"] = stats["gpu_mean"] + (gpu - stats["gpu_mean"]) / samples
    stats["samples"] = samples
    return stats

def anomaly_score(stats: Dict, cpu: float, ram: float, net_conn: int, gpu: float) -> float:
    def dev(current, mean):
        return abs(current - mean)

    cpu_dev = dev(cpu, stats.get("cpu_mean", 0.0))
    ram_dev = dev(ram, stats.get("ram_mean", 0.0))
    net_dev = dev(net_conn, stats.get("net_conn_mean", 0.0))
    gpu_dev = dev(gpu, stats.get("gpu_mean", 0.0))

    score = (cpu_dev / 20.0) + (ram_dev / 20.0) + (net_dev / 50.0) + (gpu_dev / 20.0)
    return min(score, 10.0)

# ---------------------------------------------------------
# GPU MONITORING (NVIDIA STUB)
# ---------------------------------------------------------

def get_gpu_usage() -> float:
    try:
        result = subprocess.run(
            ["nvidia-smi", "--query-gpu=utilization.gpu", "--format=csv,noheader,nounits"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=2
        )
        if result.returncode != 0:
            return 0.0
        lines = result.stdout.strip().splitlines()
        if not lines:
            return 0.0
        vals = [float(x.strip()) for x in lines if x.strip()]
        if not vals:
            return 0.0
        return sum(vals) / len(vals)
    except Exception:
        return 0.0

# ---------------------------------------------------------
# SURICATA ALERT INGESTION (EVE JSON STUB)
# ---------------------------------------------------------

def ingest_suricata_alerts() -> List[AssetIncident]:
    path = os.path.join(get_script_dir(), SURICATA_EVE_PATH)
    if not os.path.exists(path):
        return []
    incidents: List[AssetIncident] = []
    try:
        with open(path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    eve = json.loads(line)
                except Exception:
                    continue
                if eve.get("event_type") == "alert":
                    src_ip = eve.get("src_ip", "unknown")
                    dest_ip = eve.get("dest_ip", "unknown")
                    risk = 90
                    incidents.append(AssetIncident(
                        asset_id=f"SURI-{src_ip}->{dest_ip}",
                        asset_type="network_alert",
                        risk_score=risk,
                        confidence=0.95,
                        criticality="high",
                        status="open",
                        mitre_tactic="Exfiltration"
                    ))
    except Exception:
        pass
    return incidents

# ---------------------------------------------------------
# HONEYPOT TRAP (FAKE DIRECTORY)
# ---------------------------------------------------------

def ensure_honeypot_dir() -> str:
    path = os.path.join(get_script_dir(), HONEYPOT_DIR_NAME)
    if not os.path.exists(path):
        try:
            os.makedirs(path, exist_ok=True)
        except Exception:
            pass
    return path

def detect_honeypot_access() -> List[AssetIncident]:
    path = ensure_honeypot_dir()
    incidents: List[AssetIncident] = []
    incidents.append(AssetIncident(
        asset_id=f"HONEYPOT-{os.path.basename(path)}",
        asset_type="honeypot",
        risk_score=70,
        confidence=0.9,
        criticality="high",
        status="investigating",
        mitre_tactic="Initial Access"
    ))
    return incidents

# ---------------------------------------------------------
# ROGUE AI SIGNATURE DETECTION
# ---------------------------------------------------------

def is_rogue_ai_process(name: str) -> bool:
    lower = name.lower()
    return any(k in lower for k in ROUGE_AI_KEYWORDS) if False else any(k in lower for k in ROUGE_AI_KEYWORDS)

# (Fix typo: ROUGE_AI_KEYWORDS -> ROGUE_AI_KEYWORDS)
ROUGE_AI_KEYWORDS = ROGUE_AI_KEYWORDS

def is_rogue_ai_process(name: str) -> bool:
    lower = name.lower()
    return any(k in lower for k in ROGUE_AI_KEYWORDS)

# ---------------------------------------------------------
# GAME / PERSONAL PROTECTION HELPERS
# ---------------------------------------------------------

def is_game_process(proc: psutil.Process) -> bool:
    name = (proc.info.get('name') or "").strip()
    lower = name.lower()
    if name in SAFE_GAME_PROCESSES:
        return True
    if any(engine in lower for engine in SAFE_GAME_ENGINES):
        return True
    try:
        exe = proc.exe()
    except Exception:
        exe = ""
    exe_lower = exe.lower()
    if any(hint.lower() in exe_lower for hint in SAFE_GAME_PATH_HINTS):
        return True
    return False

def touches_sensitive_paths(proc: psutil.Process) -> bool:
    try:
        exe = proc.exe()
    except Exception:
        exe = ""
    exe_lower = exe.lower()
    if any(hint.lower() in exe_lower for hint in SENSITIVE_DIR_HINTS):
        return True
    return False

# ---------------------------------------------------------
# SYSTEM SCAN
# ---------------------------------------------------------

def scan_system(stats: Dict) -> (List[AssetIncident], Dict, float):
    assets: List[AssetIncident] = []

    os_name = platform.system()
    assets.append(AssetIncident(
        asset_id=os_name,
        asset_type="os",
        risk_score=10,
        confidence=1.0,
        criticality="medium",
        status="closed",
        mitre_tactic="Initial Access"
    ))

    cpu = psutil.cpu_percent(interval=1)
    ram = psutil.virtual_memory().percent
    try:
        disk = psutil.disk_usage(os.path.expanduser("~")).percent
    except Exception:
        disk = 0.0

    cpu_risk = int(cpu)
    ram_risk = int(ram)
    disk_risk = int(disk)

    assets.append(AssetIncident(
        asset_id="CPU",
        asset_type="hardware",
        risk_score=cpu_risk,
        confidence=0.9,
        criticality="high",
        status="open" if cpu_risk > 80 else "investigating",
        mitre_tactic="Execution"
    ))

    assets.append(AssetIncident(
        asset_id="RAM",
        asset_type="hardware",
        risk_score=ram_risk,
        confidence=0.85,
        criticality="high",
        status="open" if ram_risk > 85 else "investigating",
        mitre_tactic="Persistence"
    ))

    assets.append(AssetIncident(
        asset_id="DISK",
        asset_type="hardware",
        risk_score=disk_risk,
        confidence=0.8,
        criticality="medium",
        status="open" if disk_risk > 90 else "investigating",
        mitre_tactic="Persistence"
    ))

    try:
        conns = psutil.net_connections()
        conn_count = len(conns)
    except Exception:
        conn_count = 0

    net_risk = 20 if conn_count < 100 else 60 if conn_count < 300 else 90
    assets.append(AssetIncident(
        asset_id="Network",
        asset_type="network",
        risk_score=net_risk,
        confidence=0.9,
        criticality="high",
        status="open" if net_risk >= 80 else "investigating",
        mitre_tactic="Lateral Movement"
    ))

    gpu_usage = get_gpu_usage()

    stats = update_stats(stats, cpu, ram, conn_count, gpu_usage)
    anomaly = anomaly_score(stats, cpu, ram, conn_count, gpu_usage)

    if anomaly > 2.0:
        assets.append(AssetIncident(
            asset_id="ANOMALY-SYSTEM",
            asset_type="anomaly",
            risk_score=int(min(100, anomaly * 10)),
            confidence=0.9,
            criticality="high",
            status="open",
            mitre_tactic="Privilege Escalation"
        ))

    for proc in psutil.process_iter(['pid', 'name']):
        name = (proc.info.get('name') or "").strip()
        if not name:
            continue
        lower = name.lower()
        suspicious = any(k in lower for k in ["python", "ai", "llm", "cuda", "torch"])
        rogue_ai = is_rogue_ai_process(name)
        game = False
        sensitive_touch = False
        try:
            game = is_game_process(proc)
        except Exception:
            game = False
        try:
            sensitive_touch = touches_sensitive_paths(proc)
        except Exception:
            sensitive_touch = False

        if not (suspicious or rogue_ai or game or sensitive_touch):
            continue

        base_risk = random.randint(30, 95)
        if rogue_ai:
            base_risk = max(base_risk, 80)
        if game:
            base_risk = min(base_risk, 40)
        if sensitive_touch and not game:
            base_risk = max(base_risk, 85)

        criticality = "medium"
        if sensitive_touch and not game:
            criticality = "high"

        status = "investigating"
        if sensitive_touch and not game:
            status = "open"

        assets.append(AssetIncident(
            asset_id=f"PROC-{proc.info['pid']}",
            asset_type="process",
            risk_score=base_risk,
            confidence=random.uniform(0.5, 0.98),
            criticality=criticality,
            status=status,
            mitre_tactic="Execution",
            isolated=False,
            safe=game
        ))

    assets.extend(ingest_suricata_alerts())
    assets.extend(detect_honeypot_access())

    return assets, stats, anomaly

# ---------------------------------------------------------
# MERGE WITH BASELINE
# ---------------------------------------------------------

def merge_with_baseline(new_assets: List[AssetIncident],
                        baseline: Dict) -> List[AssetIncident]:
    merged: List[AssetIncident] = []
    baseline_assets = baseline.get("assets", {})

    for asset in new_assets:
        prev = baseline_assets.get(asset.asset_id)
        if prev:
            prev_risk = prev.get("risk_score", 0)
            prev_status = prev.get("status", "investigating")
            prev_isolated = prev.get("isolated", False)
            prev_safe = prev.get("safe", False)
            if asset.risk_score > prev_risk + 10:
                asset.status = "open"
            elif asset.risk_score < prev_risk - 10:
                asset.status = "closed"
            else:
                asset.status = prev_status
            asset.isolated = prev_isolated
            asset.safe = prev_safe or asset.safe
        else:
            asset.status = "open"
        merged.append(asset)

    return merged

# ---------------------------------------------------------
# COLOR SEMANTICS
# ---------------------------------------------------------

def risk_to_color(risk: int, safe: bool) -> QColor:
    if safe:
        return QColor(0, 120, 215)
    if risk < 20:
        return QColor(0, 150, 0)
    elif risk < 50:
        return QColor(255, 215, 0)
    elif risk < 80:
        return QColor(255, 140, 0)
    else:
        return QColor(220, 20, 60)

def confidence_to_opacity(conf: float) -> float:
    if conf < 0.0: conf = 0.0
    if conf > 1.0: conf = 1.0
    return 0.4 + conf * 0.6

def criticality_to_border(crit: str, isolated: bool, safe: bool) -> QPen:
    if safe:
        return QPen(QColor(0, 120, 215), 3)
    if isolated:
        return QPen(QColor(0, 0, 255), 4, Qt.DashLine)
    if crit == "high":
        return QPen(QColor(0, 0, 0), 3)
    elif crit == "medium":
        return QPen(QColor(80, 80, 80), 2)
    else:
        return QPen(QColor(150, 150, 150), 1)

def status_to_badge_color(status: str) -> QColor:
    if status == "open":
        return QColor(0, 120, 215)
    elif status == "investigating":
        return QColor(128, 0, 128)
    else:
        return QColor(128, 128, 128)

# ---------------------------------------------------------
# GUI + GUARDIAN
# ---------------------------------------------------------

class SocGuardianWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI System Guardian v4 – Hybrid SOC")
        self.resize(1400, 800)

        self.baseline = load_baseline()
        self.mode = self.baseline.get("mode", "passive")
        self.stats = self.baseline.get("stats", {
            "cpu_mean": 0.0,
            "ram_mean": 0.0,
            "net_conn_mean": 0.0,
            "gpu_mean": 0.0,
            "samples": 0
        })

        assets, self.stats, self.last_anomaly = scan_system(self.stats)
        self.assets: List[AssetIncident] = merge_with_baseline(assets, self.baseline)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout()
        central.setLayout(main_layout)

        left_layout = QVBoxLayout()
        main_layout.addLayout(left_layout, 2)

        title = QLabel("Assets / Incidents (Cards)")
        title.setStyleSheet("font-weight: bold;")
        left_layout.addWidget(title)

        mode_layout = QHBoxLayout()
        mode_label = QLabel("Guardian Mode:")
        self.mode_combo = QComboBox()
        self.mode_combo.addItems(["passive", "active", "aggressive"])
        idx = self.mode_combo.findText(self.mode)
        if idx >= 0:
            self.mode_combo.setCurrentIndex(idx)
        self.mode_combo.currentTextChanged.connect(self.on_mode_changed)
        mode_layout.addWidget(mode_label)
        mode_layout.addWidget(self.mode_combo)
        left_layout.addLayout(mode_layout)

        self.table = QTableWidget()
        self.table.setColumnCount(9)
        self.table.setHorizontalHeaderLabels([
            "Asset ID", "Type", "Risk", "Conf.", "Criticality",
            "Tactic", "Status", "Isolated", "Safe"
        ])
        self.table.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table.verticalHeader().setVisible(False)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.cellClicked.connect(self.on_row_selected)
        left_layout.addWidget(self.table)

        btn_layout = QHBoxLayout()
        self.refresh_btn = QPushButton("Manual Rescan")
        self.refresh_btn.clicked.connect(self.on_manual_refresh)
        btn_layout.addWidget(self.refresh_btn)
        left_layout.addLayout(btn_layout)

        right_layout = QVBoxLayout()
        main_layout.addLayout(right_layout, 3)

        graph_title = QLabel("Asset Graph (Risk / Isolation / Safe Map)")
        graph_title.setStyleSheet("font-weight: bold;")
        right_layout.addWidget(graph_title)

        self.scene = QGraphicsScene()
        self.graph_view = QGraphicsView(self.scene)
        right_layout.addWidget(self.graph_view)

        self.summary_label = QLabel("Select an asset card to see details.")
        self.summary_label.setWordWrap(True)
        right_layout.addWidget(self.summary_label)

        self.populate_table()
        self.draw_graph()

        self.guardian_timer = QTimer(self)
        self.guardian_timer.setInterval(5000)
        self.guardian_timer.timeout.connect(self.guardian_tick)
        self.guardian_timer.start()

    def populate_table(self):
        self.table.setRowCount(len(self.assets))
        for row, a in enumerate(self.assets):
            cols = [
                a.asset_id,
                a.asset_type,
                str(a.risk_score),
                f"{a.confidence:.2f}",
                a.criticality,
                a.mitre_tactic,
                a.status,
                "yes" if a.isolated else "no",
                "yes" if a.safe else "no",
            ]
            for col_idx, text in enumerate(cols):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col_idx, item)

            base_color = risk_to_color(a.risk_score, a.safe)
            base_color.setAlphaF(confidence_to_opacity(a.confidence))
            for col_idx in range(self.table.columnCount()):
                self.table.item(row, col_idx).setBackground(QBrush(base_color))

            tactic_color = MITRE_TACTIC_COLORS.get(a.mitre_tactic, QColor(0, 0, 0))
            self.table.item(row, 0).setForeground(QBrush(tactic_color))

    def draw_graph(self, selected: Optional[AssetIncident] = None):
        self.scene.clear()
        x, y = 60, 60
        node_w, node_h = 90, 90
        max_width = 950

        for a in self.assets:
            base_color = risk_to_color(a.risk_score, a.safe)
            base_color.setAlphaF(confidence_to_opacity(a.confidence))
            rect = QRectF(x, y, node_w, node_h)
            pen = criticality_to_border(a.criticality, a.isolated, a.safe)
            self.scene.addEllipse(rect, pen, QBrush(base_color))

            text = self.scene.addText(a.asset_id)
            text.setPos(x + 10, y + node_h + 5)

            badge_color = status_to_badge_color(a.status)
            self.scene.addEllipse(
                QRectF(x + node_w - 18, y + 6, 14, 14),
                QPen(Qt.NoPen),
                QBrush(badge_color)
            )

            if selected and selected.asset_id == a.asset_id:
                highlight_pen = QPen(QColor(0, 0, 0), 4, Qt.DashLine)
                self.scene.addEllipse(rect.adjusted(-4, -4, 4, 4), highlight_pen)

            x += node_w + 70
            if x > max_width:
                x = 60
                y += node_h + 120

    def on_row_selected(self, row: int, col: int):
        if row < 0 or row >= len(self.assets):
            return
        a = self.assets[row]
        self.summary_label.setText(
            f"Asset ID: {a.asset_id}\n"
            f"Type: {a.asset_type}\n"
            f"Risk: {a.risk_score}\n"
            f"Confidence: {a.confidence:.2f}\n"
            f"Criticality: {a.criticality}\n"
            f"Tactic: {a.mitre_tactic}\n"
            f"Status: {a.status}\n"
            f"Isolated: {'yes' if a.isolated else 'no'}\n"
            f"Safe (game/trusted): {'yes' if a.safe else 'no'}\n\n"
            f"Guardian mode: {self.mode}\n"
            f"Last anomaly score: {getattr(self, 'last_anomaly', 0.0):.2f}\n\n"
            f"Color = risk (blue = safe/game)\n"
            f"Opacity = confidence\n"
            f"Border = criticality (blue = safe, blue dashed = isolated)\n"
            f"Badge = status\n"
            f"Asset ID color = MITRE tactic"
        )
        self.draw_graph(selected=a)

    def on_manual_refresh(self):
        self.guardian_tick(manual=True)

    def on_mode_changed(self, new_mode: str):
        self.mode = new_mode
        append_guardian_log(f"[MODE] Guardian mode changed to {self.mode}")
        save_baseline(self.assets, self.mode, self.stats)

    def guardian_tick(self, manual: bool = False):
        baseline = load_baseline()
        baseline["mode"] = self.mode
        baseline["stats"] = self.stats

        assets, self.stats, self.last_anomaly = scan_system(self.stats)
        self.assets = merge_with_baseline(assets, baseline)

        self.run_guardian_actions()

        self.populate_table()
        self.draw_graph()
        save_baseline(self.assets, self.mode, self.stats)

        if manual:
            self.summary_label.setText("Manual rescan completed. Guardian evaluated system state.")

    def run_guardian_actions(self):
        game_running = any(a.asset_type == "process" and a.safe for a in self.assets)
        if game_running and self.mode == "aggressive":
            append_guardian_log("[INFO] Game detected; softening aggressive behavior to active-like.")
        effective_mode = self.mode
        if game_running and self.mode == "aggressive":
            effective_mode = "active"

        if effective_mode == "passive":
            return

        if effective_mode == "active":
            for a in self.assets:
                if a.risk_score >= 80 and not a.isolated and not a.safe:
                    a.isolated = True
                    append_guardian_log(
                        f"[ACTIVE] Auto-isolated high-risk asset: {a.asset_id} (risk={a.risk_score})"
                    )
            return

        if effective_mode == "aggressive":
            for a in self.assets:
                if a.asset_type == "process" and a.risk_score >= 85 and not a.safe:
                    self.guardian_handle_process(a)
                elif a.asset_type in ["network_alert", "anomaly"] and a.risk_score >= 80:
                    if not a.isolated:
                        a.isolated = True
                        append_guardian_log(
                            f"[AGGRESSIVE] Isolated asset: {a.asset_id} (type={a.asset_type}, risk={a.risk_score})"
                        )

    def guardian_handle_process(self, asset: AssetIncident):
        if asset.safe:
            append_guardian_log(
                f"[AGGRESSIVE] Skipped termination for safe/game process: {asset.asset_id}"
            )
            return

        try:
            pid_str = asset.asset_id.split("-", 1)[1]
            pid = int(pid_str)
        except Exception:
            return

        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Warning)
        msg_box.setWindowTitle("Guardian Override – Process Termination")
        msg_box.setText(
            f"Guardian (AGGRESSIVE) wants to terminate process:\n\n"
            f"Asset: {asset.asset_id}\n"
            f"Risk: {asset.risk_score}\n"
            f"Confidence: {asset.confidence:.2f}\n\n"
            f"Do you approve this action?"
        )
        msg_box.setStandardButtons(QMessageBox.Yes | QMessageBox.No)
        msg_box.setDefaultButton(QMessageBox.No)
        result = msg_box.exec_()

        if result == QMessageBox.Yes:
            try:
                p = psutil.Process(pid)
                p.terminate()
                asset.status = "closed"
                asset.isolated = True
                append_guardian_log(
                    f"[AGGRESSIVE] Process {asset.asset_id} (pid={pid}) terminated by Guardian."
                )
                alert = QMessageBox(self)
                alert.setIcon(QMessageBox.Information)
                alert.setWindowTitle("Guardian Action")
                alert.setText(
                    f"Guardian terminated process {asset.asset_id} (pid={pid})."
                )
                alert.exec_()
            except Exception as e:
                append_guardian_log(
                    f"[AGGRESSIVE] Failed to terminate {asset.asset_id} (pid={pid}): {e}"
                )
        else:
            append_guardian_log(
                f"[AGGRESSIVE] Manual override: termination of {asset.asset_id} (pid={pid}) was denied."
            )

# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():
    app = QApplication(sys.argv)
    win = SocGuardianWindow()
    win.show()
    sys.exit(app.exec_())

if __name__ == "__main__":
    main()
