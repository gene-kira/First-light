#!/usr/bin/env python3
# unified_cache_brain_fluent.py

import os
import threading
import time
import queue
import psutil
from typing import Dict, Tuple, Optional

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


class UnifiedCachePool:
    def __init__(self, ram_limit_gb: int = DEFAULT_RAM_LIMIT_GB,
                 vram_limit_mb: int = DEFAULT_VRAM_LIMIT_MB,
                 lanes: int = LANES_COUNT):
        self.ram_limit = ram_limit_gb * (1024 ** 3)
        self.vram_limit = vram_limit_mb * (1024 ** 2)

        self.lock = threading.Lock()
        self.blocks: Dict[Tuple[str, int], bytes] = {}
        self.current_size = 0
        self.lru_list = []

        # memory lanes (RAM)
        self.lanes = [0 for _ in range(lanes)]

        # VRAM lanes
        self.vram_lanes = []
        self.vram_used = 0
        if GPU_AVAILABLE:
            self.vram_lanes = [cp.zeros(self.vram_limit // lanes, dtype=cp.uint8)
                               for _ in range(lanes)]

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

            # distribute across RAM lanes
            lane_idx = len(self.lru_list) % len(self.lanes)
            self.lanes[lane_idx] += block_size

            # mirror into VRAM lanes if available
            if GPU_AVAILABLE and self.vram_used + block_size < self.vram_limit:
                v_lane_idx = lane_idx % len(self.vram_lanes)
                lane = self.vram_lanes[v_lane_idx]
                start = self.vram_used % lane.size
                end = start + min(block_size, lane.size - start)
                lane[start:end] = cp.asarray(list(data[:end - start]))
                self.vram_used += (end - start)

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
            }


class DriveScanner:
    def __init__(self, cache_pool: UnifiedCachePool):
        self.cache = cache_pool

    def list_drives(self):
        drives = []
        for part in psutil.disk_partitions(all=False):
            if os.name == "nt":
                drives.append(part.device)
            else:
                drives.append(part.mountpoint)
        return drives

    def scan_drive(self, root: str, max_files: int = 200):
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
                    return


class ForesightEngine:
    def __init__(self, cache_pool: UnifiedCachePool):
        self.cache = cache_pool
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
        except Exception:
            pass

    def toggle(self):
        self.enabled = not self.enabled


class UnifiedIO:
    def __init__(self, cache_pool: UnifiedCachePool, foresight: ForesightEngine):
        self.cache = cache_pool
        self.foresight = foresight

    def read(self, path: str, offset: int = 0, size: int = READ_BLOCK_SIZE) -> bytes:
        cached = self.cache.get_block(path, offset, size)
        if cached is not None:
            return cached
        try:
            with open(path, "rb") as fp:
                fp.seek(offset)
                data = fp.read(size)
                if data:
                    self.cache.add_block(path, offset, data)
                    self.foresight.prefetch_file(path, max_blocks=2)
                    return data
                return b""
        except Exception:
            return b""

    def write(self, path: str, offset: int, data: bytes):
        if not data:
            return
        self.cache.add_block(path, offset, data)
        self.cache.schedule_flush(path, offset, data)


# ===== Unified Cache Brain (for Codex import) =====

class UnifiedCacheBrain:
    """
    High-level wrapper you can import into Codex Control Console.
    """

    def __init__(self):
        self.pool = UnifiedCachePool()
        self.scanner = DriveScanner(self.pool)
        self.foresight = ForesightEngine(self.pool)
        self.io = UnifiedIO(self.pool, self.foresight)

    def seed_from_first_drive(self):
        drives = self.scanner.list_drives()
        if drives:
            self.scanner.scan_drive(drives[0], max_files=200)

    def read(self, path: str, offset: int = 0, size: int = READ_BLOCK_SIZE) -> bytes:
        return self.io.read(path, offset, size)

    def write(self, path: str, offset: int, data: bytes):
        self.io.write(path, offset, data)

    def stats(self):
        return self.pool.stats()

    def toggle_foresight(self):
        self.foresight.toggle()


# ===== Fluent SOC-style GUI =====

class FluentCacheConsole(QtWidgets.QWidget):
    def __init__(self, brain: UnifiedCacheBrain):
        super().__init__()
        self.brain = brain
        self.setWindowTitle("Codex Unified Cache Brain - SOC Console")
        self.resize(700, 400)

        self.setStyleSheet("""
            QWidget {
                background-color: #1e1e1e;
                color: #e0e0e0;
            }
            QPushButton {
                background-color: #3a3a3a;
                border: 1px solid #5a5a5a;
                padding: 6px;
            }
            QPushButton:hover {
                background-color: #505050;
            }
            QLabel {
                color: #e0e0e0;
            }
        """)

        # top controls
        self.btn_rescan = QtWidgets.QPushButton("Rescan Drive")
        self.btn_toggle_foresight = QtWidgets.QPushButton("Toggle Foresight")
        self.btn_flush = QtWidgets.QPushButton("Flush Hint (no-op)")

        self.btn_rescan.clicked.connect(self.on_rescan)
        self.btn_toggle_foresight.clicked.connect(self.on_toggle_foresight)

        controls_layout = QtWidgets.QHBoxLayout()
        controls_layout.addWidget(self.btn_rescan)
        controls_layout.addWidget(self.btn_toggle_foresight)
        controls_layout.addWidget(self.btn_flush)

        # stats label
        self.stats_label = QtWidgets.QLabel()
        self.stats_label.setAlignment(QtCore.Qt.AlignLeft | QtCore.Qt.AlignTop)

        # lanes graph
        self.lanes_view = LanesGraph(self.brain)

        main_layout = QtWidgets.QVBoxLayout()
        main_layout.addLayout(controls_layout)
        main_layout.addWidget(self.stats_label)
        main_layout.addWidget(self.lanes_view)
        self.setLayout(main_layout)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_view)
        self.timer.start(1000)

    def on_rescan(self):
        threading.Thread(target=self.brain.seed_from_first_drive, daemon=True).start()

    def on_toggle_foresight(self):
        self.brain.toggle_foresight()

    def update_view(self):
        s = self.brain.stats()
        text = (
            f"Blocks: {s['blocks']}\n"
            f"RAM used: {s['size_mb']:.2f} MB / {s['ram_limit_mb']:.2f} MB\n"
            f"VRAM used: {s['vram_used_mb']:.2f} MB / {s['vram_limit_mb']:.2f} MB\n"
            f"GPU available: {s['gpu_available']}\n"
        )
        self.stats_label.setText(text)
        self.lanes_view.update_lanes(s["lanes"])


class LanesGraph(QtWidgets.QWidget):
    def __init__(self, brain: UnifiedCacheBrain):
        super().__init__()
        self.brain = brain
        self.lanes = []
        self.setMinimumHeight(200)

    def update_lanes(self, lanes):
        self.lanes = lanes
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
            bar_height = height_ratio * (h - 20)

            rect = QtCore.QRectF(
                x - bar_width / 2,
                h - bar_height - 10,
                bar_width,
                bar_height
            )

            color = QtGui.QColor(0, 200, 255)  # cyan-ish SOC lane
            painter.setBrush(color)
            painter.setPen(QtGui.QPen(QtGui.QColor(50, 50, 50)))
            painter.drawRect(rect)


def main():
    brain = UnifiedCacheBrain()
    brain.seed_from_first_drive()

    app = QtWidgets.QApplication([])
    console = FluentCacheConsole(brain)
    console.show()
    app.exec_()


if __name__ == "__main__":
    main()
