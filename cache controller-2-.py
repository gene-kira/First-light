#!/usr/bin/env python3
# unified_cache_vram_gui.py

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

# ---- Optional GUI (PyQt5) ----
try:
    from PyQt5 import QtWidgets, QtCore
    GUI_AVAILABLE = True
except ImportError:
    GUI_AVAILABLE = False

SCAN_BLOCK_SIZE = 64 * 1024
READ_BLOCK_SIZE = 128 * 1024
DEFAULT_RAM_LIMIT_GB = 2
DEFAULT_VRAM_LIMIT_MB = 512
FLUSH_WORKERS = 2


class UnifiedCachePool:
    def __init__(self, ram_limit_gb: int = DEFAULT_RAM_LIMIT_GB,
                 vram_limit_mb: int = DEFAULT_VRAM_LIMIT_MB):
        self.ram_limit = ram_limit_gb * (1024 ** 3)
        self.vram_limit = vram_limit_mb * (1024 ** 2)

        self.lock = threading.Lock()
        self.blocks: Dict[Tuple[str, int], bytes] = {}
        self.current_size = 0
        self.lru_list = []

        self.vram_lanes = []
        self.vram_used = 0
        if GPU_AVAILABLE:
            # simple: one VRAM lane as big chunk
            self.vram_lanes.append(cp.zeros(self.vram_limit, dtype=cp.uint8))

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

            # optional: mirror some data into VRAM
            if GPU_AVAILABLE and self.vram_used + block_size < self.vram_limit:
                # naive: copy into first lane
                lane = self.vram_lanes[0]
                start = self.vram_used
                end = start + block_size
                lane[start:end] = cp.asarray(list(data))
                self.vram_used += block_size

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

    def prefetch_file(self, path: str, max_blocks: int = 8):
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


# ---- GUI Console ----

class CacheConsole(QtWidgets.QWidget):
    def __init__(self, cache_pool: UnifiedCachePool):
        super().__init__()
        self.cache = cache_pool
        self.setWindowTitle("Unified Cache Console")
        self.resize(400, 250)

        self.label = QtWidgets.QLabel(self)
        self.label.setAlignment(QtCore.Qt.AlignTop)
        font = self.label.font()
        font.setPointSize(10)
        self.label.setFont(font)

        layout = QtWidgets.QVBoxLayout()
        layout.addWidget(self.label)
        self.setLayout(layout)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_stats)
        self.timer.start(1000)

    def update_stats(self):
        s = self.cache.stats()
        text = (
            f"Blocks: {s['blocks']}\n"
            f"RAM used: {s['size_mb']:.2f} MB / {s['ram_limit_mb']:.2f} MB\n"
            f"VRAM used: {s['vram_used_mb']:.2f} MB / {s['vram_limit_mb']:.2f} MB\n"
            f"GPU available: {s['gpu_available']}\n"
        )
        self.label.setText(text)


def main():
    cache = UnifiedCachePool()
    scanner = DriveScanner(cache)
    foresight = ForesightEngine(cache)
    uio = UnifiedIO(cache, foresight)

    drives = scanner.list_drives()
    if drives:
        scanner.scan_drive(drives[0], max_files=200)

    # simple test read
    test_path = None
    for root, dirs, files in os.walk(os.path.expanduser("~")):
        if files:
            test_path = os.path.join(root, files[0])
            break
    if test_path:
        _ = uio.read(test_path, 0, 4096)

    print("Initial stats:", cache.stats())

    if GUI_AVAILABLE:
        app = QtWidgets.QApplication([])
        console = CacheConsole(cache)
        console.show()
        app.exec_()
    else:
        print("GUI not available. Running headless. Press Ctrl+C to exit.")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
