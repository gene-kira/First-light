#!/usr/bin/env python3
# unified_cache_brain_codex_super.py

import os
import threading
import time
import queue
import psutil
from typing import Dict, Tuple, Optional, List

import zstandard as zstd  # pip install zstandard

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

zstd_compressor = zstd.ZstdCompressor()
zstd_decompressor = zstd.ZstdDecompressor()


# ============================================================
#   CODEX EVENT BUS
# ============================================================

class CodexEventBus:
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
#   GPU PREDICTIVE LANE + GPU EVICTION POLICY
# ============================================================

class GpuPredictiveLane:
    def __init__(self, event_bus: CodexEventBus):
        self.event_bus = event_bus
        self.enabled = GPU_AVAILABLE

    def analyze_lanes(self, lanes: List[int]) -> List[float]:
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

    def choose_eviction_candidates(self, lanes: List[int]) -> List[int]:
        """
        GPU-driven eviction: pick lowest-score lanes as candidates.
        """
        scores = self.analyze_lanes(lanes)
        indexed = list(enumerate(scores))
        indexed.sort(key=lambda x: x[1])  # lowest score first
        # return lane indices in eviction order
        return [idx for idx, _ in indexed]


# ============================================================
#   UNIFIED CACHE POOL (RAM + VRAM + FRAGMENTATION + COMPRESSION)
# ============================================================

class UnifiedCachePool:
    def __init__(self, event_bus: CodexEventBus,
                 gpu_lane: GpuPredictiveLane,
                 ram_limit_gb: int = DEFAULT_RAM_LIMIT_GB,
                 vram_limit_mb: int = DEFAULT_VRAM_LIMIT_MB,
                 lanes: int = LANES_COUNT):

        self.event_bus = event_bus
        self.gpu_lane = gpu_lane

        self.ram_limit = ram_limit_gb * (1024 ** 3)
        self.vram_limit = vram_limit_mb * (1024 ** 2)

        self.lock = threading.Lock()

        # compressed blocks: key -> compressed bytes
        self.blocks: Dict[Tuple[str, int], bytes] = {}
        self.current_size = 0
        self.lru_list = []

        # fragmentation map: drive -> list of (offset, size)
        self.fragmentation_map: Dict[str, List[Tuple[int, int]]] = {}

        # RAM lanes
        self.lanes = [0 for _ in range(lanes)]
        self.lane_states: List[str] = ["COLD" for _ in range(lanes)]

        # drive affinity: lane_idx -> drive
        self.lane_drive_affinity: Dict[int, Optional[str]] = {i: None for i in range(lanes)}

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
            if self.current_size + incoming_size <= self.ram_limit:
                return

            # GPU-driven eviction: get lane order
            eviction_order = self.gpu_lane.choose_eviction_candidates(self.lanes)

            for lane_idx in eviction_order:
                # evict blocks belonging to this lane first
                to_remove = []
                for key in self.blocks.keys():
                    # lane assignment is implicit via LRU index; we approximate
                    # by evicting oldest blocks first
                    pass

                # fallback: simple LRU eviction
                while self.current_size + incoming_size > self.ram_limit and self.lru_list:
                    old_key = self.lru_list.pop(0)
                    data = self.blocks.pop(old_key, None)
                    if data is not None:
                        self.current_size -= len(data)

                if self.current_size + incoming_size <= self.ram_limit:
                    break

    def add_block(self, path: str, offset: int, data: bytes):
        if not data:
            return

        # compression
        compressed = zstd_compressor.compress(data)
        block_size = len(compressed)

        self._evict_if_needed(block_size)

        with self.lock:
            key = (path, offset)
            self.blocks[key] = compressed
            self.current_size += block_size

            if key in self.lru_list:
                self.lru_list.remove(key)
            self.lru_list.append(key)

            # fragmentation map
            drive = self._drive_from_path(path)
            if drive:
                frag_list = self.fragmentation_map.setdefault(drive, [])
                frag_list.append((offset, len(data)))

            # lane distribution with drive affinity
            lane_idx = self._choose_lane_for_drive(drive)
            self.lanes[lane_idx] += block_size
            self._update_lane_state(lane_idx)

            # drive pool accounting
            if drive:
                self.drive_pool[drive] = self.drive_pool.get(drive, 0) + block_size

            # VRAM mirror
            if GPU_AVAILABLE and self.vram_lanes:
                v_lane_idx = lane_idx % len(self.vram_lanes)
                lane = self.vram_lanes[v_lane_idx]
                start = self.vram_used % lane.size
                end = start + min(block_size, lane.size - start)
                lane[start:end] = cp.asarray(list(compressed[:end - start]))
                self.vram_used += (end - start)

        self.event_bus.log(
            "UnifiedCachePool",
            "INFO",
            "Cached block (compressed)",
            {"path": path, "offset": offset, "size": len(data), "compressed": block_size},
        )

    def _drive_from_path(self, path: str) -> Optional[str]:
        if os.name == "nt":
            if len(path) >= 2 and path[1] == ":":
                return path[:2]
        return None

    def _choose_lane_for_drive(self, drive: Optional[str]) -> int:
        if drive is None:
            # no drive affinity, round-robin via LRU length
            return len(self.lru_list) % len(self.lanes)

        # try to find lane already bound to this drive
        for idx, d in self.lane_drive_affinity.items():
            if d == drive:
                return idx

        # bind least-used lane to this drive
        min_idx = min(range(len(self.lanes)), key=lambda i: self.lanes[i])
        self.lane_drive_affinity[min_idx] = drive
        return min_idx

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
            compressed = self.blocks.get(key)
            if compressed is None:
                return None

            if key in self.lru_list:
                self.lru_list.remove(key)
            self.lru_list.append(key)

        try:
            data = zstd_decompressor.decompress(compressed)
            return data[:size]
        except Exception:
            return None

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
                "lane_drive_affinity": dict(self.lane_drive_affinity),
                "drive_pool": dict(self.drive_pool),
                "fragmentation_map": {
                    d: list(v) for d, v in self.fragmentation_map.items()
                },
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
#   UNIFIED CACHE BRAIN (SUPER CACHE)
# ============================================================

class UnifiedCacheBrain:
    def __init__(self):
        self.event_bus = CodexEventBus()
        self.gpu_lane = GpuPredictiveLane(self.event_bus)
        self.pool = UnifiedCachePool(self.event_bus, self.gpu_lane)
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
        scores = self.gpu_lane.analyze_lanes(s["lanes"])
        s["lane_scores"] = scores

        drive_total = sum(s["drive_pool"].values())
        s["super_cache_total_mb"] = (
            s["size_mb"] +
            s["vram_used_mb"] +
            (drive_total / (1024**2))
        )

        return s

    def foresight_state(self):
        return "ON" if self.foresight.enabled else "OFF"

    def toggle_foresight(self):
        self.foresight.toggle()

    def get_events(self, limit: int = 100):
        return self.event_bus.get_events(limit=limit)


# ============================================================
#   GUI: Super Cache Console
# ============================================================

class DriveHeatmapGraph(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.drive_pool = {}
        self.setMinimumHeight(200)

    def update_drives(self, drive_pool):
        self.drive_pool = drive_pool
        self.update()

    def paintEvent(self, event):
        if not self.drive_pool:
            return

        painter = QtGui.QPainter(self)
        painter.setRenderHint(QtGui.QPainter.Antialiasing)

        w = self.width()
        h = self.height()

        drives = list(self.drive_pool.keys())
        values = list(self.drive_pool.values())

        max_val = max(values) if values else 1
        bar_width = w / (len(drives) * 1.5)

        for i, (drive, val) in enumerate(zip(drives, values)):
            x = (i + 0.5) * (w / len(drives))
            height_ratio = val / max_val
            bar_height = height_ratio * (h - 40)

            rect = QtCore.QRectF(
                x - bar_width / 2,
                h - bar_height - 20,
                bar_width,
                bar_height
            )

            color = QtGui.QColor(0, 255, 120)
            color.setAlpha(int(80 + 175 * height_ratio))

            painter.setBrush(color)
            painter.setPen(QtGui.QPen(QtGui.QColor(40, 40, 40)))
            painter.drawRect(rect)

            painter.setPen(QtGui.QPen(QtGui.QColor(200, 200, 200)))
            painter.drawText(
                QtCore.QRectF(x - bar_width / 2, h - 20, bar_width, 20),
                QtCore.Qt.AlignCenter,
                drive
            )


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

            if state == "COLD":
                base = QtGui.QColor(80, 80, 80)
            elif state == "WARM":
                base = QtGui.QColor(0, 180, 255)
            elif state == "HOT":
                base = QtGui.QColor(255, 140, 0)
            else:
                base = QtGui.QColor(255, 0, 80)

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


class FluentCacheConsole(QtWidgets.QWidget):
    def __init__(self, brain: UnifiedCacheBrain):
        super().__init__()
        self.brain = brain

        self.super_label = QtWidgets.QLabel()
        self.super_label.setAlignment(QtCore.Qt.AlignCenter)
        font = self.super_label.font()
        font.setPointSize(14)
        font.setBold(True)
        self.super_label.setFont(font)

        self.drive_view = DriveHeatmapGraph()
        self.lanes_view = LanesHeatmapGraph()
        self.stats_label = QtWidgets.QLabel()

        top_layout = QtWidgets.QVBoxLayout()
        top_layout.addWidget(self.super_label)
        top_layout.addWidget(self.drive_view)

        split = QtWidgets.QHBoxLayout()
        split.addLayout(top_layout, 1)
        split.addWidget(self.lanes_view, 2)

        layout = QtWidgets.QVBoxLayout()
        layout.addLayout(split)
        layout.addWidget(self.stats_label)
        self.setLayout(layout)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_view)
        self.timer.start(1000)

    def update_view(self):
        s = self.brain.stats()

        self.super_label.setText(
            f"SUPER CACHE: {s['super_cache_total_mb']:.2f} MB"
        )

        self.drive_view.update_drives(s["drive_pool"])
        self.lanes_view.update_lanes(s["lanes"], s["lane_states"], s["lane_scores"])

        text = (
            f"Blocks: {s['blocks']}\n"
            f"RAM used: {s['size_mb']:.2f} MB / {s['ram_limit_mb']:.2f} MB\n"
            f"VRAM used: {s['vram_used_mb']:.2f} MB / {s['vram_limit_mb']:.2f} MB\n"
            f"GPU available: {s['gpu_available']}\n\n"
            f"Drive pool:\n"
        )
        for d, v in s["drive_pool"].items():
            text += f"  {d}: {v/1024/1024:.2f} MB\n"

        text += "\nLane affinity:\n"
        for i, d in s["lane_drive_affinity"].items():
            text += f"  Lane {i} -> {d}\n"

        text += "\nFragmentation map:\n"
        for d, frags in s["fragmentation_map"].items():
            text += f"  {d}: {len(frags)} fragments\n"

        self.stats_label.setText(text)


class CacheBrainPane(QtWidgets.QWidget):
    def __init__(self, brain: UnifiedCacheBrain, parent=None):
        super().__init__(parent)
        self.brain = brain

        self.setWindowTitle("Codex - Super Cache Brain")
        self.resize(1100, 650)

        self.tabs = QtWidgets.QTabWidget()
        self.cache_tab = QtWidgets.QWidget()
        self.tabs.addTab(self.cache_tab, "Super Cache")

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
