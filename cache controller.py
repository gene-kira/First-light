#!/usr/bin/env python3
# unified_cache.py
#
#  "cache controller" that unifies all drives
# into a single RAM-backed cache layer, with a simple API for cached reads/writes.

import os
import threading
import time
import queue
import psutil
from typing import Dict, Tuple, Optional

# =========================
# Config
# =========================

SCAN_BLOCK_SIZE = 64 * 1024      # 64 KB per sample block
READ_BLOCK_SIZE = 128 * 1024     # 128 KB per cached read
DEFAULT_RAM_LIMIT_GB = 4         # total RAM cache limit
FLUSH_WORKERS = 2                # async flush threads


# =========================
# Unified Cache Pool
# =========================

class UnifiedCachePool:
    """
    RAM-backed unified cache pool.
    Acts like a fake SSD cache layer over all drives.
    """

    def __init__(self, ram_limit_gb: int = DEFAULT_RAM_LIMIT_GB):
        self.ram_limit = ram_limit_gb * (1024 ** 3)
        self.lock = threading.Lock()

        # key: (path, offset) -> bytes
        self.blocks: Dict[Tuple[str, int], bytes] = {}
        self.current_size = 0

        # simple LRU tracking: list of keys in access order
        self.lru_list = []

        # async flush queue
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
                # basic append/overwrite flush
                with open(path, "r+b") as fp:
                    fp.seek(offset)
                    fp.write(data)
            except FileNotFoundError:
                # file disappeared, ignore
                pass
            except Exception:
                # ignore errors for now
                pass

    def _evict_if_needed(self, incoming_size: int):
        """
        Evict blocks until we have room for incoming_size.
        Simple LRU eviction.
        """
        with self.lock:
            while self.current_size + incoming_size > self.ram_limit and self.lru_list:
                old_key = self.lru_list.pop(0)
                data = self.blocks.pop(old_key, None)
                if data is not None:
                    self.current_size -= len(data)

    def add_block(self, path: str, offset: int, data: bytes):
        """
        Add a block to the cache.
        """
        if not data:
            return

        block_size = len(data)
        self._evict_if_needed(block_size)

        with self.lock:
            key = (path, offset)
            self.blocks[key] = data
            self.current_size += block_size

            # LRU update
            if key in self.lru_list:
                self.lru_list.remove(key)
            self.lru_list.append(key)

    def get_block(self, path: str, offset: int, size: int) -> Optional[bytes]:
        """
        Retrieve a block from cache, or None if not present.
        """
        with self.lock:
            key = (path, offset)
            data = self.blocks.get(key)
            if data is None:
                return None

            # LRU bump
            if key in self.lru_list:
                self.lru_list.remove(key)
            self.lru_list.append(key)

            return data[:size]

    def schedule_flush(self, path: str, offset: int, data: bytes):
        """
        Schedule a block to be flushed back to disk.
        """
        self.flush_queue.put((path, offset, data))

    def stats(self):
        with self.lock:
            return {
                "blocks": len(self.blocks),
                "size_bytes": self.current_size,
                "size_mb": self.current_size / (1024 ** 2),
                "ram_limit_mb": self.ram_limit / (1024 ** 2),
            }


# =========================
# Drive Scanner
# =========================

class DriveScanner:
    """
    Scans drives and seeds the unified cache with sample blocks.
    """

    def __init__(self, cache_pool: UnifiedCachePool):
        self.cache = cache_pool

    def list_drives(self):
        drives = []
        for part in psutil.disk_partitions(all=False):
            if os.name == "nt":
                # Windows: device like 'C:\\'
                drives.append(part.device)
            else:
                # Linux: mountpoint
                drives.append(part.mountpoint)
        return drives

    def scan_drive(self, root: str, max_files: int = 1000):
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


# =========================
# Foresight Engine
# =========================

class ForesightEngine:
    """
    Very simple "foresight" engine:
    - watches access patterns
    - prefetches nearby blocks into cache
    """

    def __init__(self, cache_pool: UnifiedCachePool):
        self.cache = cache_pool

    def prefetch_file(self, path: str, max_blocks: int = 16):
        """
        Prefetch first N blocks of a file into cache.
        """
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


# =========================
# Unified I/O API
# =========================

class UnifiedIO:
    """
    Public API:
    - read(path, offset, size) -> bytes (served from cache if possible)
    - write(path, offset, data) -> cached + scheduled flush
    """

    def __init__(self, cache_pool: UnifiedCachePool, foresight: ForesightEngine):
        self.cache = cache_pool
        self.foresight = foresight

    def read(self, path: str, offset: int = 0, size: int = READ_BLOCK_SIZE) -> bytes:
        """
        Read data via unified cache.
        """
        # try cache first
        cached = self.cache.get_block(path, offset, size)
        if cached is not None:
            return cached

        # miss: read from disk, then cache
        try:
            with open(path, "rb") as fp:
                fp.seek(offset)
                data = fp.read(size)
                if data:
                    self.cache.add_block(path, offset, data)
                    # simple foresight: prefetch next block
                    self.foresight.prefetch_file(path, max_blocks=2)
                    return data
                return b""
        except Exception:
            return b""

    def write(self, path: str, offset: int, data: bytes):
        """
        Write via unified cache:
        - update cache
        - schedule async flush
        """
        if not data:
            return

        # update cache
        self.cache.add_block(path, offset, data)

        # schedule flush
        self.cache.schedule_flush(path, offset, data)


# =========================
# Demo / Sandbox Runner
# =========================

def main():
    cache = UnifiedCachePool(ram_limit_gb=2)
    scanner = DriveScanner(cache)
    foresight = ForesightEngine(cache)
    uio = UnifiedIO(cache, foresight)

    print("[*] Listing drives...")
    drives = scanner.list_drives()
    for d in drives:
        print("  -", d)

    # seed cache from first drive
    if drives:
        print(f"[*] Scanning drive: {drives[0]}")
        scanner.scan_drive(drives[0], max_files=200)

    print("[*] Cache stats after scan:", cache.stats())

    # demo: read a file through unified cache
    test_path = None
    # try to find a small file
    for root, dirs, files in os.walk(os.path.expanduser("~")):
        if files:
            test_path = os.path.join(root, files[0])
            break

    if test_path:
        print(f"[*] Test read from: {test_path}")
        data1 = uio.read(test_path, 0, 4096)
        print("    First read len:", len(data1))

        # second read should hit cache
        data2 = uio.read(test_path, 0, 4096)
        print("    Second read len (cache):", len(data2))

    print("[*] Final cache stats:", cache.stats())
    print("[*] Unified cache sandbox running. Press Ctrl+C to exit.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[*] Exiting.")

if __name__ == "__main__":
    main()
