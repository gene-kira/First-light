#!/usr/bin/env python3
# ai_soc_guardian.py

import sys
import os
import json
import platform
import random
from dataclasses import dataclass, asdict
from typing import List, Dict

import psutil
from PyQt5.QtCore import Qt, QRectF, QTimer
from PyQt5.QtGui import QColor, QBrush, QPen
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QTableWidget, QTableWidgetItem, QGraphicsView, QGraphicsScene,
    QLabel, QHeaderView, QPushButton, QComboBox, QMessageBox
)

# ---------------------------------------------------------
# DATA MODEL
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


MITRE_TACTIC_COLORS = {
    "Initial Access": QColor(0, 120, 215),
    "Execution": QColor(112, 48, 160),
    "Persistence": QColor(0, 153, 153),
    "Privilege Escalation": QColor(255, 140, 0),
    "Lateral Movement": QColor(220, 20, 60),
    "Exfiltration": QColor(0, 0, 0),
}

GUARDIAN_LOG_NAME = "guardian.log"

# ---------------------------------------------------------
# BASELINE JSON HANDLING
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
        return {"assets": {}, "mode": "passive"}
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if "assets" not in data:
            data["assets"] = {}
        if "mode" not in data:
            data["mode"] = "passive"
        return data
    except Exception:
        return {"assets": {}, "mode": "passive"}

def save_baseline(assets: List[AssetIncident], mode: str) -> None:
    path = get_baseline_path()
    data = {
        "assets": {a.asset_id: asdict(a) for a in assets},
        "mode": mode,
    }
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def append_guardian_log(message: str) -> None:
    path = get_guardian_log_path()
    with open(path, "a", encoding="utf-8") as f:
        f.write(message + "\n")

# ---------------------------------------------------------
# SYSTEM SCAN (CROSS-PLATFORM)
# ---------------------------------------------------------

def scan_system() -> List[AssetIncident]:
    assets: List[AssetIncident] = []

    # OS asset
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

    # CPU
    cpu = psutil.cpu_percent(interval=1)
    cpu_risk = int(cpu)
    assets.append(AssetIncident(
        asset_id="CPU",
        asset_type="hardware",
        risk_score=cpu_risk,
        confidence=0.9,
        criticality="high",
        status="open" if cpu_risk > 80 else "investigating",
        mitre_tactic="Execution"
    ))

    # RAM
    ram = psutil.virtual_memory().percent
    ram_risk = int(ram)
    assets.append(AssetIncident(
        asset_id="RAM",
        asset_type="hardware",
        risk_score=ram_risk,
        confidence=0.85,
        criticality="high",
        status="open" if ram_risk > 85 else "investigating",
        mitre_tactic="Persistence"
    ))

    # Disk
    try:
        disk = psutil.disk_usage(os.path.expanduser("~")).percent
        disk_risk = int(disk)
        assets.append(AssetIncident(
            asset_id="DISK",
            asset_type="hardware",
            risk_score=disk_risk,
            confidence=0.8,
            criticality="medium",
            status="open" if disk_risk > 90 else "investigating",
            mitre_tactic="Persistence"
        ))
    except Exception:
        pass

    # Network connections
    try:
        conns = psutil.net_connections()
        conn_count = len(conns)
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
    except Exception:
        pass

    # Processes (highlight AI/LLM-ish)
    for proc in psutil.process_iter(['pid', 'name']):
        name = (proc.info.get('name') or "").strip()
        if not name:
            continue
        lower = name.lower()
        if any(k in lower for k in ["python", "ai", "llm", "cuda", "torch"]):
            risk = random.randint(30, 95)
            assets.append(AssetIncident(
                asset_id=f"PROC-{proc.info['pid']}",
                asset_type="process",
                risk_score=risk,
                confidence=random.uniform(0.4, 0.95),
                criticality="medium",
                status="investigating",
                mitre_tactic="Execution"
            ))

    return assets

# ---------------------------------------------------------
# MERGE SCAN WITH BASELINE (STATUS / CHANGE AWARENESS)
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
            if asset.risk_score > prev_risk + 10:
                asset.status = "open"
            elif asset.risk_score < prev_risk - 10:
                asset.status = "closed"
            else:
                asset.status = prev_status
        else:
            asset.status = "open"
        merged.append(asset)

    return merged

# ---------------------------------------------------------
# COLOR SEMANTICS
# ---------------------------------------------------------

def risk_to_color(risk: int) -> QColor:
    if risk < 20:
        return QColor(0, 150, 0)      # green
    elif risk < 50:
        return QColor(255, 215, 0)    # yellow
    elif risk < 80:
        return QColor(255, 140, 0)    # orange
    else:
        return QColor(220, 20, 60)    # red

def confidence_to_opacity(conf: float) -> float:
    if conf < 0.0: conf = 0.0
    if conf > 1.0: conf = 1.0
    return 0.4 + conf * 0.6

def criticality_to_border(crit: str) -> QPen:
    if crit == "high":
        return QPen(QColor(0, 0, 0), 3)
    elif crit == "medium":
        return QPen(QColor(80, 80, 80), 2)
    else:
        return QPen(QColor(150, 150, 150), 1)

def status_to_badge_color(status: str) -> QColor:
    if status == "open":
        return QColor(0, 120, 215)    # blue
    elif status == "investigating":
        return QColor(128, 0, 128)    # purple
    else:
        return QColor(128, 128, 128)  # grey

# ---------------------------------------------------------
# GUI + GUARDIAN
# ---------------------------------------------------------

class SocGuardianWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("AI System Guardian – Hybrid SOC")
        self.resize(1350, 780)

        self.baseline = load_baseline()
        self.mode = self.baseline.get("mode", "passive")
        self.assets: List[AssetIncident] = merge_with_baseline(scan_system(), self.baseline)

        central = QWidget()
        self.setCentralWidget(central)
        main_layout = QHBoxLayout()
        central.setLayout(main_layout)

        # Left: cards + controls
        left_layout = QVBoxLayout()
        main_layout.addLayout(left_layout, 2)

        title = QLabel("Assets / Incidents (Cards)")
        title.setStyleSheet("font-weight: bold;")
        left_layout.addWidget(title)

        # Guardian mode selector
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
        self.table.setColumnCount(7)
        self.table.setHorizontalHeaderLabels([
            "Asset ID", "Type", "Risk", "Conf.", "Criticality", "Tactic", "Status"
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

        # Right: graph + summary
        right_layout = QVBoxLayout()
        main_layout.addLayout(right_layout, 3)

        graph_title = QLabel("Asset Graph (Risk Map)")
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

        # Guardian timer (heartbeat)
        self.guardian_timer = QTimer(self)
        self.guardian_timer.setInterval(5000)  # 5 seconds
        self.guardian_timer.timeout.connect(self.guardian_tick)
        self.guardian_timer.start()

    # -------------------------
    # Table population
    # -------------------------

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
            ]
            for col_idx, text in enumerate(cols):
                item = QTableWidgetItem(text)
                item.setTextAlignment(Qt.AlignCenter)
                self.table.setItem(row, col_idx, item)

            base_color = risk_to_color(a.risk_score)
            base_color.setAlphaF(confidence_to_opacity(a.confidence))
            for col_idx in range(self.table.columnCount()):
                self.table.item(row, col_idx).setBackground(QBrush(base_color))

            tactic_color = MITRE_TACTIC_COLORS.get(a.mitre_tactic, QColor(0, 0, 0))
            self.table.item(row, 0).setForeground(QBrush(tactic_color))

    # -------------------------
    # Graph drawing
    # -------------------------

    def draw_graph(self, selected: AssetIncident = None):
        self.scene.clear()
        x, y = 60, 60
        node_w, node_h = 90, 90
        max_width = 950

        for a in self.assets:
            base_color = risk_to_color(a.risk_score)
            base_color.setAlphaF(confidence_to_opacity(a.confidence))
            rect = QRectF(x, y, node_w, node_h)
            pen = criticality_to_border(a.criticality)
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

    # -------------------------
    # Interaction
    # -------------------------

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
            f"Status: {a.status}\n\n"
            f"Guardian mode: {self.mode}\n"
            f"Visual semantics:\n"
            f"- Color = risk\n"
            f"- Opacity = confidence\n"
            f"- Border = criticality\n"
            f"- Badge = status\n"
            f"- Asset ID color = MITRE tactic"
        )
        self.draw_graph(selected=a)

    def on_manual_refresh(self):
        self.guardian_tick(manual=True)

    def on_mode_changed(self, new_mode: str):
        self.mode = new_mode
        append_guardian_log(f"[MODE] Guardian mode changed to {self.mode}")
        save_baseline(self.assets, self.mode)

    # -------------------------
    # Guardian heartbeat
    # -------------------------

    def guardian_tick(self, manual: bool = False):
        # Rescan system
        baseline = load_baseline()
        baseline["mode"] = self.mode
        new_assets = merge_with_baseline(scan_system(), baseline)
        self.assets = new_assets

        # Guardian actions based on mode
        self.run_guardian_actions()

        # Refresh GUI + baseline
        self.populate_table()
        self.draw_graph()
        save_baseline(self.assets, self.mode)

        if manual:
            self.summary_label.setText("Manual rescan completed. Guardian evaluated system state.")

    def run_guardian_actions(self):
        # Passive: monitor only
        if self.mode == "passive":
            return

        # Active: safe actions + logging
        if self.mode == "active":
            for a in self.assets:
                if a.risk_score >= 80:
                    msg = f"[ACTIVE] High risk asset observed: {a.asset_id} (risk={a.risk_score})"
                    append_guardian_log(msg)
            return

        # Aggressive: autonomous defense with manual override before kill
        if self.mode == "aggressive":
            for a in self.assets:
                if a.asset_type == "process" and a.risk_score >= 85:
                    self.guardian_handle_process(a)

    def guardian_handle_process(self, asset: AssetIncident):
        # Extract PID from asset_id like "PROC-1234"
        try:
            pid_str = asset.asset_id.split("-", 1)[1]
            pid = int(pid_str)
        except Exception:
            return

        # Manual override confirmation
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
                append_guardian_log(
                    f"[AGGRESSIVE] Process {asset.asset_id} (pid={pid}) terminated by Guardian."
                )
                # Alert popup
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
