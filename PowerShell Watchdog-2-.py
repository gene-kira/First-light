#!/usr/bin/env python3
# powershell_watchdog_pyqt5_advanced.py

import sys
import os
import subprocess
import base64
import time
import json

# ============================================================
# AUTOLOADER
# ============================================================

REQUIRED_LIBS = [
    "psutil",
    "PyQt5",
    "numpy",
    "sklearn",
    "scapy",
]

def ensure_lib(lib):
    try:
        __import__(lib)
        return True
    except ImportError:
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])
            __import__(lib)
            return True
        except Exception:
            return False

for lib in REQUIRED_LIBS:
    if not ensure_lib(lib):
        print(f"[FATAL] Could not load or install {lib}")
        sys.exit(1)

import psutil
import numpy as np
from sklearn.ensemble import IsolationForest
from scapy.all import sniff, IP, TCP, UDP

from PyQt5 import QtWidgets, QtCore, QtGui

# Optional GPU
try:
    import cupy as cp
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

# ============================================================
# CONFIG / LOGGING
# ============================================================

LOG_PATH = os.path.join(os.getcwd(), "powershell_watchdog.log")
SURICATA_RULES_PATH = os.path.join(os.getcwd(), "suricata_powershell_rules.json")  # simple JSON rule set

AUTO_BLOCK_ENABLED = True  # can be toggled in GUI

def log_event(level, msg, extra=None):
    ts = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime())
    line = {
        "time": ts,
        "level": level,
        "msg": msg,
        "extra": extra or {},
    }
    try:
        with open(LOG_PATH, "a", encoding="utf-8") as f:
            f.write(json.dumps(line) + "\n")
    except Exception:
        pass

# ============================================================
# SIMPLE SURICATA-LIKE RULES
# ============================================================

def load_suricata_rules():
    if not os.path.exists(SURICATA_RULES_PATH):
        # create a simple default rule set
        rules = [
            {
                "id": 1001,
                "name": "EncodedCommand",
                "pattern": "EncodedCommand",
                "severity": 8,
            },
            {
                "id": 1002,
                "name": "DownloadString",
                "pattern": "DownloadString",
                "severity": 7,
            },
            {
                "id": 1003,
                "name": "Invoke-Expression",
                "pattern": "Invoke-Expression",
                "severity": 9,
            },
        ]
        with open(SURICATA_RULES_PATH, "w", encoding="utf-8") as f:
            json.dump(rules, f, indent=2)
        return rules
    try:
        with open(SURICATA_RULES_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

SURICATA_RULES = load_suricata_rules()

def match_suricata(cmdline: str):
    hits = []
    for rule in SURICATA_RULES:
        if rule["pattern"].lower() in cmdline.lower():
            hits.append(rule)
    return hits

# ============================================================
# GPU / ML ANOMALY ENGINE
# ============================================================

class AnomalyEngine:
    def __init__(self):
        self.model = IsolationForest(n_estimators=100, contamination=0.1)
        self.trained = False
        self.buffer = []

    def features_from_proc(self, proc_info):
        cmd = proc_info.get("cmdline", "")
        length = len(cmd)
        encoded = "encodedcommand" in cmd.lower()
        download = "downloadstring" in cmd.lower()
        invoke = "invoke-expression" in cmd.lower()
        score = 0
        if encoded:
            score += 3
        if download:
            score += 2
        if invoke:
            score += 4
        return np.array([length, int(encoded), int(download), int(invoke), score], dtype=float)

    def update(self, proc_infos):
        if not proc_infos:
            return
        X = np.array([self.features_from_proc(p) for p in proc_infos])
        self.buffer.append(X)
        if len(self.buffer) >= 5:
            X_all = np.vstack(self.buffer)
            self.model.fit(X_all)
            self.trained = True
            self.buffer.clear()

    def score(self, proc_info):
        x = self.features_from_proc(proc_info).reshape(1, -1)
        if GPU_AVAILABLE:
            # simple GPU normalization
            cx = cp.asarray(x, dtype=cp.float32)
            cx = cx / (cp.linalg.norm(cx) + 1e-6)
            x = cp.asnumpy(cx)
        if not self.trained:
            return 0.5
        s = self.model.decision_function(x)[0]
        # map to 0..10
        return float(max(0.0, min(10.0, 5.0 - s * 10.0)))

ANOMALY_ENGINE = AnomalyEngine()

# ============================================================
# NETWORK SNAPSHOT (SCAPY)
# ============================================================

def get_proc_connections(pid):
    conns = []
    try:
        p = psutil.Process(pid)
        for c in p.connections(kind="inet"):
            laddr = f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else ""
            raddr = f"{c.raddr.ip}:{c.raddr.port}" if c.raddr else ""
            conns.append((c.status, laddr, raddr))
    except Exception:
        pass
    return conns

# ============================================================
# BASE64 DECODE HELPERS
# ============================================================

def try_decode_base64_from_cmd(cmdline: str):
    parts = cmdline.split()
    decoded_chunks = []
    for p in parts:
        if len(p) > 8 and all(ch.isalnum() or ch in "+/=" for ch in p):
            try:
                raw = base64.b64decode(p + "===")
                decoded_chunks.append(raw.decode("utf-8", errors="ignore"))
            except Exception:
                continue
    return "\n".join(decoded_chunks) if decoded_chunks else ""

# ============================================================
# TABLE MODEL
# ============================================================

class PowerShellModel(QtCore.QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.headers = [
            "PID",
            "Parent",
            "Name",
            "Severity",
            "Suricata Hits",
            "Command Line",
        ]
        self.rows = []
        self.proc_infos = []

    def update_data(self):
        rows = []
        proc_infos = []
        for proc in psutil.process_iter(['pid', 'name', 'cmdline', 'ppid']):
            try:
                name = proc.info['name'] or ""
                if "powershell" not in name.lower():
                    continue
                pid = proc.info['pid']
                cmdline = " ".join(proc.info['cmdline']) if proc.info['cmdline'] else ""
                parent_name = ""
                try:
                    parent = psutil.Process(proc.info['ppid'])
                    parent_name = parent.name()
                except Exception:
                    parent_name = "N/A"

                suri_hits = match_suricata(cmdline)
                suri_names = ",".join(r["name"] for r in suri_hits) if suri_hits else ""

                info = {
                    "pid": pid,
                    "parent": parent_name,
                    "name": name,
                    "cmdline": cmdline,
                    "suri_hits": suri_hits,
                }
                severity = ANOMALY_ENGINE.score(info)

                rows.append([pid, parent_name, name, severity, suri_names, cmdline])
                proc_infos.append(info)
            except Exception:
                continue

        ANOMALY_ENGINE.update(proc_infos)

        self.beginResetModel()
        self.rows = rows
        self.proc_infos = proc_infos
        self.endResetModel()

    def rowCount(self, parent=QtCore.QModelIndex()):
        return len(self.rows)

    def columnCount(self, parent=QtCore.QModelIndex()):
        return len(self.headers)

    def data(self, index, role=QtCore.Qt.DisplayRole):
        if not index.isValid():
            return None
        row = index.row()
        col = index.column()
        value = self.rows[row][col]

        if role == QtCore.Qt.DisplayRole:
            if col == 3:
                return f"{value:.1f}"
            return str(value)

        if role == QtCore.Qt.FontRole:
            f = QtGui.QFont("Consolas", 9)
            return f

        if role == QtCore.Qt.BackgroundRole and col == 3:
            sev = float(value)
            if sev >= 8.0:
                return QtGui.QBrush(QtGui.QColor(255, 64, 64))   # red
            elif sev >= 5.0:
                return QtGui.QBrush(QtGui.QColor(255, 192, 64)) # orange
            elif sev >= 2.5:
                return QtGui.QBrush(QtGui.QColor(255, 255, 128))# yellow
            else:
                return QtGui.QBrush(QtGui.QColor(128, 255, 128))# green

        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role != QtCore.Qt.DisplayRole:
            return None
        if orientation == QtCore.Qt.Horizontal:
            return self.headers[section]
        return str(section)

# ============================================================
# TOAST ALERT
# ============================================================

class Toast(QtWidgets.QWidget):
    def __init__(self, text, parent=None):
        super().__init__(parent)
        self.setWindowFlags(
            QtCore.Qt.ToolTip |
            QtCore.Qt.WindowStaysOnTopHint |
            QtCore.Qt.FramelessWindowHint
        )
        self.label = QtWidgets.QLabel(text, self)
        self.label.setStyleSheet("color: white; background-color: #202020; padding: 8px;")
        layout = QtWidgets.QVBoxLayout(self)
        layout.addWidget(self.label)
        self.adjustSize()
        QtCore.QTimer.singleShot(3000, self.close)

# ============================================================
# MAIN WINDOW
# ============================================================

class PowerShellWatchdog(QtWidgets.QMainWindow):
    WHITELIST = {
        "explorer.exe",
        "cmd.exe",
        "python.exe",
        "pythonw.exe",
        "System",
        "Registry",
    }

    def __init__(self):
        super().__init__()
        self.setWindowTitle("PowerShell Watchdog (PyQt5 Advanced)")
        self.resize(1300, 700)

        self.table = QtWidgets.QTableView()
        self.model = PowerShellModel(self)
        self.table.setModel(self.model)
        self.table.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)
        self.table.setAlternatingRowColors(True)
        self.table.setSortingEnabled(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.verticalHeader().setVisible(False)

        font = QtGui.QFont("Segoe UI", 9)
        self.table.setFont(font)

        self.setCentralWidget(self.table)

        toolbar = self.addToolBar("Actions")

        refresh_action = QtWidgets.QAction("Refresh", self)
        refresh_action.triggered.connect(self.refresh)
        toolbar.addAction(refresh_action)

        kill_action = QtWidgets.QAction("Kill Selected", self)
        kill_action.triggered.connect(self.kill_selected)
        toolbar.addAction(kill_action)

        net_action = QtWidgets.QAction("Show Net for Selected", self)
        net_action.triggered.connect(self.show_net_for_selected)
        toolbar.addAction(net_action)

        decode_action = QtWidgets.QAction("Decode Base64", self)
        decode_action.triggered.connect(self.decode_selected)
        toolbar.addAction(decode_action)

        self.auto_block_action = QtWidgets.QAction("Auto-Block: ON", self)
        self.auto_block_action.setCheckable(True)
        self.auto_block_action.setChecked(True)
        self.auto_block_action.triggered.connect(self.toggle_auto_block)
        toolbar.addAction(self.auto_block_action)

        self.status = self.statusBar()
        self.status.showMessage("Ready")

        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()

        self.refresh()

    def toast(self, text):
        t = Toast(text, self)
        geo = self.geometry()
        x = geo.x() + geo.width() - t.width() - 20
        y = geo.y() + 40
        t.move(x, y)
        t.show()

    def refresh(self):
        self.model.update_data()
        count = self.model.rowCount()
        self.status.showMessage(f"Found {count} PowerShell processes")
        # auto-block high severity if enabled
        if AUTO_BLOCK_ENABLED:
            self.auto_block_high_severity()

    def get_selected_index(self):
        idxs = self.table.selectionModel().selectedRows()
        if not idxs:
            return None
        return idxs[0].row()

    def get_proc_info_by_row(self, row):
        if row is None or row < 0 or row >= len(self.model.proc_infos):
            return None
        return self.model.proc_infos[row]

    def kill_selected(self):
        row = self.get_selected_index()
        info = self.get_proc_info_by_row(row)
        if info is None:
            self.status.showMessage("No process selected")
            return
        pid = info["pid"]
        try:
            proc = psutil.Process(pid)
            name = proc.name()
        except Exception:
            self.status.showMessage(f"PID {pid} no longer exists")
            return

        if name in self.WHITELIST:
            self.status.showMessage(f"{name} is whitelisted, not killing")
            return

        reply = QtWidgets.QMessageBox.question(
            self,
            "Confirm Kill",
            f"Kill PID {pid} ({name})?",
            QtWidgets.QMessageBox.Yes | QtWidgets.QMessageBox.No,
        )
        if reply != QtWidgets.QMessageBox.Yes:
            return

        try:
            proc.terminate()
            log_event("INFO", "Manual kill", {"pid": pid, "name": name})
            self.status.showMessage(f"Terminated PID {pid} ({name})")
            self.toast(f"Killed {pid} ({name})")
        except Exception as e:
            self.status.showMessage(f"Failed to kill PID {pid}: {e}")
        self.refresh()

    def show_net_for_selected(self):
        row = self.get_selected_index()
        info = self.get_proc_info_by_row(row)
        if info is None:
            self.status.showMessage("No process selected")
            return
        pid = info["pid"]
        conns = get_proc_connections(pid)
        if not conns:
            QtWidgets.QMessageBox.information(self, "Connections", "No active inet connections.")
            return
        text = ""
        for status, laddr, raddr in conns:
            text += f"{status}: {laddr} -> {raddr}\n"
        QtWidgets.QMessageBox.information(self, f"Connections for PID {pid}", text)
        log_event("INFO", "Net snapshot", {"pid": pid, "connections": conns})

    def decode_selected(self):
        row = self.get_selected_index()
        info = self.get_proc_info_by_row(row)
        if info is None:
            self.status.showMessage("No process selected")
            return
        cmdline = info["cmdline"]
        decoded = try_decode_base64_from_cmd(cmdline)
        if not decoded:
            QtWidgets.QMessageBox.information(self, "Base64 Decode", "No decodable Base64 chunks found.")
            return
        QtWidgets.QMessageBox.information(self, "Base64 Decode", decoded)
        log_event("INFO", "Base64 decoded", {"pid": info["pid"], "decoded": decoded})

    def toggle_auto_block(self):
        global AUTO_BLOCK_ENABLED
        AUTO_BLOCK_ENABLED = self.auto_block_action.isChecked()
        self.auto_block_action.setText(f"Auto-Block: {'ON' if AUTO_BLOCK_ENABLED else 'OFF'}")
        self.status.showMessage(f"Auto-Block {'enabled' if AUTO_BLOCK_ENABLED else 'disabled'}")

    def auto_block_high_severity(self):
        # auto-kill processes with severity >= 9 and Suricata hits, but log and toast
        for idx, info in enumerate(self.model.proc_infos):
            row = idx
            sev = float(self.model.rows[row][3])
            suri_hits = info["suri_hits"]
            if sev >= 9.0 and suri_hits:
                pid = info["pid"]
                try:
                    proc = psutil.Process(pid)
                    name = proc.name()
                except Exception:
                    continue
                if name in self.WHITELIST:
                    continue
                try:
                    proc.terminate()
                    log_event("WARN", "Auto-block kill", {
                        "pid": pid,
                        "name": name,
                        "severity": sev,
                        "rules": [r["id"] for r in suri_hits],
                    })
                    self.toast(f"AUTO-BLOCK: Killed {pid} ({name}) sev={sev:.1f}")
                except Exception:
                    continue
        self.model.update_data()

# ============================================================
# MAIN
# ============================================================

def main():
    app = QtWidgets.QApplication(sys.argv)
    app.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)
    app.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps)

    win = PowerShellWatchdog()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
