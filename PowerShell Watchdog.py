#!/usr/bin/env python3
# powershell_watchdog_pyqt5.py

import sys
import psutil

from PyQt5 import QtWidgets, QtCore, QtGui


class PowerShellModel(QtCore.QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.headers = ["PID", "Parent", "Name", "Command Line"]
        self.rows = []

    def update_data(self):
        rows = []
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
                rows.append([pid, parent_name, name, cmdline])
            except Exception:
                continue
        self.beginResetModel()
        self.rows = rows
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
        if role == QtCore.Qt.DisplayRole:
            return str(self.rows[row][col])
        if role == QtCore.Qt.FontRole:
            f = QtGui.QFont("Consolas", 9)
            return f
        return None

    def headerData(self, section, orientation, role=QtCore.Qt.DisplayRole):
        if role != QtCore.Qt.DisplayRole:
            return None
        if orientation == QtCore.Qt.Horizontal:
            return self.headers[section]
        return str(section)


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
        self.setWindowTitle("PowerShell Watchdog (PyQt5)")
        self.resize(1100, 600)

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

        self.status = self.statusBar()
        self.status.showMessage("Ready")

        self.timer = QtCore.QTimer(self)
        self.timer.setInterval(1000)
        self.timer.timeout.connect(self.refresh)
        self.timer.start()

        self.refresh()

    def refresh(self):
        self.model.update_data()
        self.status.showMessage(f"Found {self.model.rowCount()} PowerShell processes")

    def get_selected_pid(self):
        idxs = self.table.selectionModel().selectedRows()
        if not idxs:
            return None
        row = idxs[0].row()
        pid = self.model.rows[row][0]
        return pid

    def kill_selected(self):
        pid = self.get_selected_pid()
        if pid is None:
            self.status.showMessage("No process selected")
            return
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
            self.status.showMessage(f"Terminated PID {pid} ({name})")
        except Exception as e:
            self.status.showMessage(f"Failed to kill PID {pid}: {e}")
        self.refresh()


def main():
    try:
        import psutil  # just to ensure it exists
    except ImportError:
        QtWidgets.QMessageBox.critical(
            None,
            "Missing Dependency",
            "psutil is required. Install with: pip install psutil",
        )
        sys.exit(1)

    app = QtWidgets.QApplication(sys.argv)
    app.setAttribute(QtCore.Qt.AA_EnableHighDpiScaling)
    app.setAttribute(QtCore.Qt.AA_UseHighDpiPixmaps)

    win = PowerShellWatchdog()
    win.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
