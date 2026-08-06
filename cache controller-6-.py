#!/usr/bin/env python3
# unified_cache_brain_codex_full.py

import os
import threading
import time
import queue
import psutil
from typing import Dict, Tuple, Optional, List

# ---- Optional GPU (CuPy) ----
try:
    import cupy as cp
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

# ---- GUI (PyQt5) ----
from PyQt5 import QtWidgets, QtCore, QtGui

SCAN_BLOCK_SIZE = 64 * 1024
READ_BLOCK_SIZE = 128 * 1024
DEFAULT_RAM_LIMIT_GB = 2
DEFAULT_VRAM_LIMIT_MB = 512
FLUSH_WORKERS = 2
LANES_COUNT = 6


# ============================================================
#   CODEX EVENT BUS (C)
# ============================================================

class CodexEventBus:
    """
    Simple event bus for Codex integration.
    Codex can subscribe to events or read logs.
    """

    def __init__(self):
        self.lock = threading.Lock()
        self.events: List[Dict] = []

    def log(self, source: str, level: str, message: str, extra: Dict = None):
        evt = {
            "time": time.time(),
            "source": source,
            "level": level,
            "message": message,
            "extra": extra or {},
        }
        with self.lock:
            self.events.append(evt)

    def get_events(self, limit: int = 100):
        with self.lock:
            return self.events[-limit:]


# ============================================================
#   GPU PREDICTIVE CACHING (D)
# ============================================================

class GpuPredictiveLane:
    """
    GPU compute lane for predictive caching.
    Uses lane load to decide which lanes/files to prioritize.
    """

    def __init__(self, event_bus: CodexEventBus):
        self.event_bus = event_bus
        self.enabled = GPU_AVAILABLE

    def analyze_lanes(self, lanes: List[int]) -> List[float]:
        """
        Returns normalized scores per lane (0..1).
        """
        if not lanes:
            return []
        if not self.enabled:
            return [0.0 for _ in lanes]

        arr = cp.asarray(lanes, dtype=cp.float32)
        total = cp.sum(arr)
        if total == 0:
            return [0.0 for _ in lanes]
        scores = arr / total
        scores_cpu = scores.get()
        self.event_bus.log(
            "GpuPredictiveLane",
            "INFO",
            "Analyzed lanes for predictive caching",
            {"scores": [float(s) for s in scores_cpu]},
        )
        return [float(s) for s in scores_cpu]


# ============================================================
#   UNIFIED CACHE POOL (RAM + VRAM + Threat Lanes)
# ============================================================

class UnifiedCachePool:
    def __init__(self, event_bus: CodexEventBus,
                 ram_limit_gb: int = DEFAULT_RAM_LIMIT_GB,
                 vram_limit_mb: int = DEFAULT_VRAM_LIMIT_MB,
                 lanes: int = LANES_COUNT):

        self.event_bus = event_bus
        self.ram_limit = ram_limit_gb * (1024 ** 3)
        self.vram_limit = vram_limit_mb * (1024 ** 2)

        self.lock = threading.Lock()
        self.blocks: Dict[Tuple[str, int], bytes] = {}
        self.current_size = 0
        self.lru_list = []

        # RAM lanes
        self.lanes = [0 for _ in range(lanes)]
        self.lane_states: List[str] = ["COLD" for _ in range(lanes)]

        # per-drive cache sharing pool
        self.drive_pool: Dict[str, int] = {}

        # VRAM lanes
        self.vram_lanes = []
        self.vram_used = 0
        if GPU_AVAILABLE:
            self.vram_lanes = [
                cp.zeros(self.vram_limit // lanes, dtype=cp.uint8)
                for _ in range(lanes)
            ]

        # async flush
        self.flush_queue = queue.Queue()
        self.flush_threads = []
        self._start_flush_workers()

    def _start_flush_workers(self):
        for _ in range(FLUSH_WORKERS):
            t = threading.Thread(target=self._flush_worker, daemon=True)
            t.start()
            self.flush_threads.append(t)

    def _flush_worker(self):
        while True:
            try:
                path, offset, data = self.flush_queue.get()
                with open(path, "r+b") as fp:
                    fp.seek(offset)
                    fp.write(data)
                self.event_bus.log(
                    "UnifiedCachePool",
                    "DEBUG",
                    "Flushed block to disk",
                    {"path": path, "offset": offset, "size": len(data)},
                )
            except Exception:
                pass

    def _evict_if_needed(self, incoming_size: int):
        with self.lock:
            while self.current_size + incoming_size > self.ram_limit and self.lru_list:
                old_key = self.lru_list.pop(0)
                data = self.blocks.pop(old_key, None)
                if data is not None:
                    self.current_size -= len(data)

    def add_block(self, path: str, offset: int, data: bytes):
        if not data:
            return

        block_size = len(data)
        self._evict_if_needed(block_size)

        with self.lock:
            key = (path, offset)
            self.blocks[key] = data
            self.current_size += block_size

            if key in self.lru_list:
                self.lru_list.remove(key)
            self.lru_list.append(key)

            # lane distribution
            lane_idx = len(self.lru_list) % len(self.lanes)
            self.lanes[lane_idx] += block_size
            self._update_lane_state(lane_idx)

            # drive pool accounting
            drive = self._drive_from_path(path)
            if drive:
                self.drive_pool[drive] = self.drive_pool.get(drive, 0) + block_size

            # VRAM mirror
            if GPU_AVAILABLE and self.vram_lanes:
                v_lane_idx = lane_idx % len(self.vram_lanes)
                lane = self.vram_lanes[v_lane_idx]
                start = self.vram_used % lane.size
                end = start + min(block_size, lane.size - start)
                lane[start:end] = cp.asarray(list(data[:end - start]))
                self.vram_used += (end - start)

        self.event_bus.log(
            "UnifiedCachePool",
            "INFO",
            "Cached block",
            {"path": path, "offset": offset, "size": block_size},
        )

    def _drive_from_path(self, path: str) -> Optional[str]:
        if os.name == "nt":
            # "C:\\..."
            if len(path) >= 2 and path[1] == ":":
                return path[:2]
        return None

    def _update_lane_state(self, lane_idx: int):
        lane_val = self.lanes[lane_idx]
        per_lane_limit = self.ram_limit / len(self.lanes)

        if lane_val < per_lane_limit * 0.02:
            state = "COLD"
        elif lane_val < per_lane_limit * 0.08:
            state = "WARM"
        elif lane_val < per_lane_limit * 0.15:
            state = "HOT"
        else:
            state = "PRIORITY"

        self.lane_states[lane_idx] = state

    def get_block(self, path: str, offset: int, size: int) -> Optional[bytes]:
        with self.lock:
            key = (path, offset)
            data = self.blocks.get(key)
            if data is None:
                return None

            if key in self.lru_list:
                self.lru_list.remove(key)
            self.lru_list.append(key)

            return data[:size]

    def schedule_flush(self, path: str, offset: int, data: bytes):
        self.flush_queue.put((path, offset, data))

    def stats(self):
        with self.lock:
            return {
                "blocks": len(self.blocks),
                "size_bytes": self.current_size,
                "size_mb": self.current_size / (1024 ** 2),
                "ram_limit_mb": self.ram_limit / (1024 ** 2),
                "vram_used_mb": self.vram_used / (1024 ** 2),
                "vram_limit_mb": self.vram_limit / (1024 ** 2),
                "gpu_available": GPU_AVAILABLE,
                "lanes": list(self.lanes),
                "lane_states": list(self.lane_states),
                "drive_pool": dict(self.drive_pool),
            }


# ============================================================
#   DRIVE SCANNER
# ============================================================

class DriveScanner:
    def __init__(self, cache_pool: UnifiedCachePool, event_bus: CodexEventBus):
        self.cache = cache_pool
        self.event_bus = event_bus

    def list_drives(self):
        drives = []
        for part in psutil.disk_partitions(all=False):
            drives.append(part.device if os.name == "nt" else part.mountpoint)
        return drives

    def scan_drive(self, root: str, max_files: int = 200):
        self.event_bus.log("DriveScanner", "INFO", "Scanning drive", {"root": root})
        count = 0
        for r, d, f in os.walk(root):
            for file in f:
                path = os.path.join(r, file)
                try:
                    with open(path, "rb") as fp:
                        block = fp.read(SCAN_BLOCK_SIZE)
                        if block:
                            self.cache.add_block(path, 0, block)
                            count += 1
                except Exception:
                    continue
                if count >= max_files:
                    self.event_bus.log(
                        "DriveScanner", "INFO", "Scan limit reached", {"count": count}
                    )
                    return


# ============================================================
#   FORESIGHT ENGINE
# ============================================================

class ForesightEngine:
    def __init__(self, cache_pool: UnifiedCachePool, event_bus: CodexEventBus):
        self.cache = cache_pool
        self.event_bus = event_bus
        self.enabled = True

    def prefetch_file(self, path: str, max_blocks: int = 8):
        if not self.enabled:
            return
        try:
            with open(path, "rb") as fp:
                offset = 0
                for _ in range(max_blocks):
                    data = fp.read(READ_BLOCK_SIZE)
                    if not data:
                        break
                    self.cache.add_block(path, offset, data)
                    offset += len(data)
            self.event_bus.log(
                "ForesightEngine",
                "INFO",
                "Prefetched file",
                {"path": path, "blocks": max_blocks},
            )
        except Exception:
            pass

    def toggle(self):
        self.enabled = not self.enabled
        self.event_bus.log(
            "ForesightEngine",
            "INFO",
            "Foresight toggled",
            {"state": "ON" if self.enabled else "OFF"},
        )


# ============================================================
#   UNIFIED I/O
# ============================================================

class UnifiedIO:
    def __init__(self, cache_pool: UnifiedCachePool,
                 foresight: ForesightEngine,
                 event_bus: CodexEventBus):
        self.cache = cache_pool
        self.foresight = foresight
        self.event_bus = event_bus

    def read(self, path: str, offset: int = 0, size: int = READ_BLOCK_SIZE) -> bytes:
        cached = self.cache.get_block(path, offset, size)
        if cached is not None:
            self.event_bus.log(
                "UnifiedIO",
                "DEBUG",
                "Cache hit",
                {"path": path, "offset": offset, "size": size},
            )
            return cached

        try:
            with open(path, "rb") as fp:
                fp.seek(offset)
                data = fp.read(size)
                if data:
                    self.cache.add_block(path, offset, data)
                    self.foresight.prefetch_file(path, max_blocks=2)
                    self.event_bus.log(
                        "UnifiedIO",
                        "DEBUG",
                        "Cache miss, loaded from disk",
                        {"path": path, "offset": offset, "size": len(data)},
                    )
                    return data
                return b""
        except Exception:
            return b""

    def write(self, path: str, offset: int, data: bytes):
        if not data:
            return
        self.cache.add_block(path, offset, data)
        self.cache.schedule_flush(path, offset, data)
        self.event_bus.log(
            "UnifiedIO",
            "INFO",
            "Write scheduled",
            {"path": path, "offset": offset, "size": len(data)},
        )


# ============================================================
#   UNIFIED CACHE BRAIN (Codex API)
# ============================================================

class UnifiedCacheBrain:
    """
    Codex-facing brain: event bus, GPU predictive lane, cache pool, IO.
    """

    def __init__(self):
        self.event_bus = CodexEventBus()
        self.gpu_lane = GpuPredictiveLane(self.event_bus)
        self.pool = UnifiedCachePool(self.event_bus)
        self.scanner = DriveScanner(self.pool, self.event_bus)
        self.foresight = ForesightEngine(self.pool, self.event_bus)
        self.io = UnifiedIO(self.pool, self.foresight, self.event_bus)

    def seed_from_first_drive(self):
        drives = self.scanner.list_drives()
        if drives:
            self.scanner.scan_drive(drives[0], max_files=200)
            self.event_bus.log(
                "UnifiedCacheBrain",
                "INFO",
                "Seeded from first drive",
                {"drive": drives[0]},
            )

    def read(self, path: str, offset: int = 0, size: int = READ_BLOCK_SIZE):
        return self.io.read(path, offset, size)

    def write(self, path: str, offset: int, data: bytes):
        self.io.write(path, offset, data)

    def stats(self):
        s = self.pool.stats()
        # GPU lane analysis
        scores = self.gpu_lane.analyze_lanes(s["lanes"])
        s["lane_scores"] = scores
        return s

    def foresight_state(self):
        return "ON" if self.foresight.enabled else "OFF"

    def toggle_foresight(self):
        self.foresight.toggle()

    def get_events(self, limit: int = 100):
        return self.event_bus.get_events(limit=limit)


# ============================================================
#   GUI: Cache Brain Pane + Fluent SOC Console + Heatmap
# ============================================================

class CacheBrainPane(QtWidgets.QWidget):
    """
    Dockable pane for Codex.
    """

    def __init__(self, brain: UnifiedCacheBrain, parent=None):
        super().__init__(parent)
        self.brain = brain

        self.setWindowTitle("Codex - Cache Brain")
        self.resize(1000, 600)

        # Tabs (mock Codex tabs)
        self.tabs = QtWidgets.QTabWidget()
        self.cache_tab = QtWidgets.QWidget()
        self.tabs.addTab(self.cache_tab, "Cache Brain")

        # Ribbon (top)
        self.btn_rescan = QtWidgets.QPushButton("Rescan Drive")
        self.btn_toggle_foresight = QtWidgets.QPushButton("FORESIGHT: ON")
        self.btn_show_events = QtWidgets.QPushButton("Show Events")

        self.btn_rescan.clicked.connect(self.on_rescan)
        self.btn_toggle_foresight.clicked.connect(self.on_toggle_foresight)
        self.btn_show_events.clicked.connect(self.on_show_events)

        ribbon = QtWidgets.QHBoxLayout()
        ribbon.addWidget(self.btn_rescan)
        ribbon.addWidget(self.btn_toggle_foresight)
        ribbon.addWidget(self.btn_show_events)
        ribbon.addStretch()

        # SOC console inside tab
        self.console = FluentCacheConsole(brain)

        cache_layout = QtWidgets.QVBoxLayout()
        cache_layout.addLayout(ribbon)
        cache_layout.addWidget(self.console)
        self.cache_tab.setLayout(cache_layout)

        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addWidget(self.tabs)
        self.setLayout(main_layout)

        self.update_timer = QtCore.QTimer(self)
        self.update_timer.timeout.connect(self.update_ribbon)
        self.update_timer.start(1000)

    def on_rescan(self):
        threading.Thread(target=self.brain.seed_from_first_drive, daemon=True).start()

    def on_toggle_foresight(self):
        self.brain.toggle_foresight()
        self.update_ribbon()

    def on_show_events(self):
        events = self.brain.get_events(limit=50)
        text = ""
        for e in events:
            text += f"[{e['level']}] {e['source']}: {e['message']}\n"
        QtWidgets.QMessageBox.information(self, "Codex Event Bus", text or "No events.")

    def update_ribbon(self):
        self.btn_toggle_foresight.setText(f"FORESIGHT: {self.brain.foresight_state()}")


class FluentCacheConsole(QtWidgets.QWidget):
    def __init__(self, brain: UnifiedCacheBrain):
        super().__init__()
        self.brain = brain

        self.stats_label = QtWidgets.QLabel()
        self.lanes_view = LanesHeatmapGraph()

        split = QtWidgets.QHBoxLayout()
        split.addWidget(self.stats_label, 1)
        split.addWidget(self.lanes_view, 2)

        layout = QtWidgets.QVBoxLayout()
        layout.addLayout(split)
        self.setLayout(layout)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_view)
        self.timer.start(1000)

    def update_view(self):
        s = self.brain.stats()
        text = (
            f"Blocks: {s['blocks']}\n"
            f"RAM used: {s['size_mb']:.2f} MB / {s['ram_limit_mb']:.2f} MB\n"
            f"VRAM used: {s['vram_used_mb']:.2f} MB / {s['vram_limit_mb']:.2f} MB\n"
            f"GPU available: {s['gpu_available']}\n\n"
            f"Drive pool:\n"
        )
        for d, v in s["drive_pool"].items():
            text += f"  {d}: {v/1024/1024:.2f} MB\n"

        text += "\nLanes:\n"
        for i, (val, state, score) in enumerate(
            zip(s["lanes"], s["lane_states"], s["lane_scores"])
        ):
            text += (
                f"  Lane {i}: {val/1024/1024:.2f} MB "
                f"[{state}] score={score:.3f}\n"
            )

        self.stats_label.setText(text)
        self.lanes_view.update_lanes(s["lanes"], s["lane_states"], s["lane_scores"])


class LanesHeatmapGraph(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.lanes = []
        self.states = []
        self.scores = []
        self.setMinimumHeight(250)

    def update_lanes(self, lanes, states, scores):
        self.lanes = lanes
        self.states = states
        self.scores = scores
        self.update()

    def paintEvent(self, event):
        if not self.lanes:
            return

        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)

        w = self.width()
        h = self.height()
        n = len(self.lanes)
        max_val = max(self.lanes) if self.lanes else 1

        bar_width = w / (n * 1.5)

        for i, val in enumerate(self.lanes):
            x = (i + 0.5) * (w / n)
            height_ratio = val / max_val if max_val > 0 else 0
            bar_height = height_ratio * (h - 40)

            rect = QtCore.QRectF(
                x - bar_width / 2,
                h - bar_height - 20,
                bar_width,
                bar_height
            )

            state = self.states[i]
            score = self.scores[i] if i < len(self.scores) else 0.0

            # base color by state
            if state == "COLD":
                base = QtGui.QColor(80, 80, 80)
            elif state == "WARM":
                base = QtGui.QColor(0, 180, 255)
            elif state == "HOT":
                base = QtGui.QColor(255, 140, 0)
            else:
                base = QtGui.QColor(255, 0, 80)

            # heatmap intensity by score
            alpha = int(80 + 175 * min(max(score, 0.0), 1.0))
            base.setAlpha(alpha)

            painter.setBrush(base)
            painter.setPen(QtGui.QPen(QtGui.QColor(40, 40, 40)))
            painter.drawRect(rect)

            painter.setPen(QtGui.QPen(QtGui.QColor(200, 200, 200)))
            painter.drawText(
                QtCore.QRectF(x - bar_width / 2, h - 20, bar_width, 20),
                QtCore.Qt.AlignCenter,
                f"L{i}"
            )


# ============================================================
#   STANDALONE RUNNER
# ============================================================

def main():
    brain = UnifiedCacheBrain()
    brain.seed_from_first_drive()

    app = QtWidgets.QApplication([])
    pane = CacheBrainPane(brain)
    pane.show()
    app.exec_()


if __name__ == "__main__":
    main()
