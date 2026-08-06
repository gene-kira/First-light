#!/usr/bin/env python3
# codex_super_cache_fs_v3_ai.py

import os
import threading
import time
import queue
import socket
import json
import psutil
import subprocess
import hashlib
from typing import Dict, Tuple, Optional, List

import zstandard as zstd  # pip install zstandard
import numpy as np        # pip install numpy
from sklearn.linear_model import SGDRegressor  # pip install scikit-learn

# ---- Optional GPU (CuPy) ----
try:
    import cupy as cp
    GPU_AVAILABLE = True
except ImportError:
    GPU_AVAILABLE = False

# ---- Deep Learning (PyTorch) ----
try:
    import torch
    import torch.nn as nn
    import torch.optim as optim
    TORCH_AVAILABLE = True
except ImportError:
    TORCH_AVAILABLE = False

# ---- Encryption (cryptography) ----
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False

# ---- GUI (PyQt5) ----
from PyQt5 import QtWidgets, QtCore, QtGui

SCAN_BLOCK_SIZE = 64 * 1024
READ_BLOCK_SIZE = 128 * 1024
DEFAULT_RAM_LIMIT_GB = 2
DEFAULT_VRAM_LIMIT_MB = 512
FLUSH_WORKERS = 2
LANES_COUNT = 6

PERSIST_DIR = os.path.join(os.getcwd(), "super_cache_persist_v3_ai")
os.makedirs(PERSIST_DIR, exist_ok=True)

zstd_compressor = zstd.ZstdCompressor()
zstd_decompressor = zstd.ZstdDecompressor()


# ============================================================
#   EVENT BUS
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
#   KERNEL STUB (FILTER DRIVER PLACEHOLDER)
# ============================================================

class KernelStubFilterDriver:
    def __init__(self, event_bus: CodexEventBus):
        self.event_bus = event_bus
        self.enabled = False

    def attach(self):
        self.enabled = True
        self.event_bus.log("KernelStubFilterDriver", "INFO", "Attached (stub)")

    def detach(self):
        self.enabled = False
        self.event_bus.log("KernelStubFilterDriver", "INFO", "Detached (stub)")

    def intercept_read(self, path: str, offset: int, size: int):
        if not self.enabled:
            return
        self.event_bus.log(
            "KernelStubFilterDriver",
            "DEBUG",
            "Intercept read (stub)",
            {"path": path, "offset": offset, "size": size},
        )

    def intercept_write(self, path: str, offset: int, size: int):
        if not self.enabled:
            return
        self.event_bus.log(
            "KernelStubFilterDriver",
            "DEBUG",
            "Intercept write (stub)",
            {"path": path, "offset": offset, "size": size},
        )


# ============================================================
#   GPU PREDICTIVE LANE + ADAPTIVE MERGING
# ============================================================

class GpuPredictiveLane:
    def __init__(self, event_bus: CodexEventBus):
        self.event_bus = event_bus
        self.enabled = GPU_AVAILABLE

    def analyze_lanes(self, lanes: List[int]) -> List[float]:
        if not lanes:
            return []
        if not self.enabled:
            total = sum(lanes) or 1
            return [l / total for l in lanes]

        arr = cp.asarray(lanes, dtype=cp.float32)
        total = cp.sum(arr)
        if total == 0:
            return [0.0 for _ in lanes]
        scores = arr / total
        scores_cpu = scores.get()
        self.event_bus.log(
            "GpuPredictiveLane",
            "INFO",
            "Analyzed lanes",
            {"scores": [float(s) for s in scores_cpu]},
        )
        return [float(s) for s in scores_cpu]

    def choose_eviction_candidates(self, lanes: List[int]) -> List[int]:
        scores = self.analyze_lanes(lanes)
        indexed = list(enumerate(scores))
        indexed.sort(key=lambda x: x[1])
        return [idx for idx, _ in indexed]

    def adaptive_merge(self, lanes: List[int]) -> List[int]:
        if len(lanes) <= 2:
            return lanes
        total = sum(lanes) or 1
        norm = [l / total for l in lanes]
        cold_indices = [i for i, v in enumerate(norm) if v < 0.05]
        if len(cold_indices) <= 1:
            return lanes
        merged = []
        skip = set()
        for i in range(len(lanes)):
            if i in skip:
                continue
            if i in cold_indices:
                partner = next((c for c in cold_indices if c > i and c not in skip), None)
                if partner is not None:
                    merged.append(lanes[i] + lanes[partner])
                    skip.add(partner)
                else:
                    merged.append(lanes[i])
            else:
                merged.append(lanes[i])
        self.event_bus.log(
            "GpuPredictiveLane",
            "INFO",
            "Adaptive lane merge",
            {"original": lanes, "merged": merged},
        )
        return merged


# ============================================================
#   ML + DEEP + LSTM-LIKE PREDICTIVE ENGINE
# ============================================================

class MlPredictiveEngine:
    def __init__(self, event_bus: CodexEventBus, lanes_count: int):
        self.event_bus = event_bus
        self.lanes_count = lanes_count
        self.model = SGDRegressor(max_iter=1000, tol=1e-3)
        self.trained = False
        self.history_X = []
        self.history_y = []

    def update(self, lanes: List[int]):
        if len(lanes) != self.lanes_count:
            return
        total = sum(lanes) or 1
        features = [l / total for l in lanes]
        target = max(features)
        self.history_X.append(features)
        self.history_y.append(target)
        if len(self.history_X) >= 20:
            X = np.array(self.history_X)
            y = np.array(self.history_y)
            self.model.partial_fit(X, y)
            self.trained = True
            self.history_X.clear()
            self.history_y.clear()
            self.event_bus.log(
                "MlPredictiveEngine",
                "INFO",
                "Model updated",
                {"lanes_count": self.lanes_count},
            )

    def suggest_prefetch_blocks(self, lanes: List[int]) -> int:
        if not self.trained or len(lanes) != self.lanes_count:
            return 2
        total = sum(lanes) or 1
        features = np.array([[l / total for l in lanes]])
        pred = self.model.predict(features)[0]
        if pred < 0.1:
            return 1
        elif pred < 0.3:
            return 2
        elif pred < 0.6:
            return 4
        else:
            return 8


class DeepPredictiveEngine:
    class LaneNet(nn.Module):
        def __init__(self, lanes_count: int):
            super().__init__()
            self.fc1 = nn.Linear(lanes_count, 32)
            self.fc2 = nn.Linear(32, 16)
            self.fc3 = nn.Linear(16, 1)

        def forward(self, x):
            x = torch.relu(self.fc1(x))
            x = torch.relu(self.fc2(x))
            x = torch.sigmoid(self.fc3(x))
            return x

    def __init__(self, event_bus: CodexEventBus, lanes_count: int):
        self.event_bus = event_bus
        self.lanes_count = lanes_count
        self.enabled = TORCH_AVAILABLE
        if not self.enabled:
            self.model = None
            self.optimizer = None
            self.loss_fn = None
            return
        self.model = self.LaneNet(lanes_count)
        self.optimizer = optim.Adam(self.model.parameters(), lr=1e-3)
        self.loss_fn = nn.MSELoss()
        self.buffer_X = []
        self.buffer_y = []
        self.trained = False

    def update(self, lanes: List[int]):
        if not self.enabled or len(lanes) != self.lanes_count:
            return
        total = sum(lanes) or 1
        features = [l / total for l in lanes]
        target = max(features)
        self.buffer_X.append(features)
        self.buffer_y.append(target)
        if len(self.buffer_X) >= 32:
            X = torch.tensor(self.buffer_X, dtype=torch.float32)
            y = torch.tensor(self.buffer_y, dtype=torch.float32).unsqueeze(1)
            self.optimizer.zero_grad()
            pred = self.model(X)
            loss = self.loss_fn(pred, y)
            loss.backward()
            self.optimizer.step()
            self.buffer_X.clear()
            self.buffer_y.clear()
            self.trained = True
            self.event_bus.log(
                "DeepPredictiveEngine",
                "INFO",
                "Deep model updated",
                {"lanes_count": self.lanes_count},
            )

    def suggest_prefetch_blocks(self, lanes: List[int]) -> int:
        if not self.enabled or not self.trained or len(lanes) != self.lanes_count:
            return 2
        total = sum(lanes) or 1
        features = torch.tensor([[l / total for l in lanes]], dtype=torch.float32)
        with torch.no_grad():
            pred = float(self.model(features)[0].item())
        if pred < 0.1:
            return 1
        elif pred < 0.3:
            return 2
        elif pred < 0.6:
            return 4
        else:
            return 8


class SequencePredictiveEngine:
    class SeqNet(nn.Module):
        def __init__(self, lanes_count: int, seq_len: int = 8):
            super().__init__()
            self.lanes_count = lanes_count
            self.seq_len = seq_len
            self.lstm = nn.LSTM(lanes_count, 32, batch_first=True)
            self.fc = nn.Linear(32, 1)

        def forward(self, x):
            out, _ = self.lstm(x)
            last = out[:, -1, :]
            return torch.sigmoid(self.fc(last))

    def __init__(self, event_bus: CodexEventBus, lanes_count: int, seq_len: int = 8):
        self.event_bus = event_bus
        self.lanes_count = lanes_count
        self.seq_len = seq_len
        self.enabled = TORCH_AVAILABLE
        if not self.enabled:
            self.model = None
            self.optimizer = None
            self.loss_fn = None
            return
        self.model = self.SeqNet(lanes_count, seq_len)
        self.optimizer = optim.Adam(self.model.parameters(), lr=1e-3)
        self.loss_fn = nn.MSELoss()
        self.buffer_seq = []
        self.buffer_y = []
        self.trained = False

    def update(self, lanes: List[int]):
        if not self.enabled or len(lanes) != self.lanes_count:
            return
        total = sum(lanes) or 1
        features = [l / total for l in lanes]
        self.buffer_seq.append(features)
        if len(self.buffer_seq) >= self.seq_len:
            seq = self.buffer_seq[-self.seq_len:]
            target = max(features)
            self.buffer_y.append(target)
            if len(self.buffer_y) >= 16:
                X = torch.tensor([self.buffer_seq[-self.seq_len:] for _ in range(len(self.buffer_y))],
                                 dtype=torch.float32)
                y = torch.tensor(self.buffer_y, dtype=torch.float32).unsqueeze(1)
                self.optimizer.zero_grad()
                pred = self.model(X)
                loss = self.loss_fn(pred, y)
                loss.backward()
                self.optimizer.step()
                self.buffer_y.clear()
                self.trained = True
                self.event_bus.log(
                    "SequencePredictiveEngine",
                    "INFO",
                    "Sequence model updated",
                    {"lanes_count": self.lanes_count},
                )

    def suggest_prefetch_blocks(self, lanes: List[int]) -> int:
        if not self.enabled or not self.trained or len(lanes) != self.lanes_count:
            return 2
        total = sum(lanes) or 1
        features = [l / total for l in lanes]
        seq = [features for _ in range(self.seq_len)]
        X = torch.tensor([seq], dtype=torch.float32)
        with torch.no_grad():
            pred = float(self.model(X)[0].item())
        if pred < 0.1:
            return 1
        elif pred < 0.3:
            return 2
        elif pred < 0.6:
            return 4
        else:
            return 8


# ============================================================
#   DISTRIBUTED CONSISTENCY GROUPS + BLOCK REPLICATION
# ============================================================

class SuperCacheClusterNode:
    def __init__(self, event_bus: CodexEventBus, host: str = "0.0.0.0", port: int = 9099):
        self.event_bus = event_bus
        self.host = host
        self.port = port
        self.peers: List[Tuple[str, int]] = []
        self.running = False
        self.block_callback = None
        self.group_callback = None

    def add_peer(self, host: str, port: int):
        self.peers.append((host, port))

    def start_server(self):
        self.running = True
        t = threading.Thread(target=self._server_loop, daemon=True)
        t.start()
        self.event_bus.log("SuperCacheClusterNode", "INFO", "Cluster server started", {"port": self.port})

    def _server_loop(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.bind((self.host, self.port))
        s.listen(5)
        while self.running:
            try:
                conn, addr = s.accept()
                threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except Exception:
                continue

    def _handle_client(self, conn: socket.socket, addr):
        try:
            data = conn.recv(65536)
            if not data:
                conn.close()
                return
            msg = json.loads(data.decode("utf-8"))
            mtype = msg.get("type")
            if mtype == "stats":
                self.event_bus.log(
                    "SuperCacheClusterNode",
                    "INFO",
                    "Cluster stats",
                    {"from": addr, "data": msg.get("data")},
                )
            elif mtype == "block":
                key = tuple(msg.get("key", []))
                block_bytes = bytes.fromhex(msg.get("data_hex", ""))
                if self.block_callback:
                    self.block_callback(key, block_bytes)
            elif mtype == "group":
                group_id = msg.get("group_id")
                version = msg.get("version")
                keys = [tuple(k) for k in msg.get("keys", [])]
                if self.group_callback:
                    self.group_callback(group_id, version, keys)
        except Exception:
            pass
        finally:
            conn.close()

    def broadcast_stats(self, stats: Dict):
        payload = json.dumps({"type": "stats", "data": stats}).encode("utf-8")
        for host, port in self.peers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((host, port))
                s.sendall(payload)
                s.close()
            except Exception:
                continue

    def broadcast_block(self, key: Tuple[str, int], compressed: bytes):
        payload = json.dumps({
            "type": "block",
            "key": list(key),
            "data_hex": compressed.hex(),
        }).encode("utf-8")
        for host, port in self.peers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((host, port))
                s.sendall(payload)
                s.close()
            except Exception:
                continue

    def broadcast_group(self, group_id: str, version: int, keys: List[Tuple[str, int]]):
        payload = json.dumps({
            "type": "group",
            "group_id": group_id,
            "version": version,
            "keys": [list(k) for k in keys],
        }).encode("utf-8")
        for host, port in self.peers:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.5)
                s.connect((host, port))
                s.sendall(payload)
                s.close()
            except Exception:
                continue


# ============================================================
#   JOURNALING + WAL + ENCRYPTION + METADATA + DEDUP STORE
# ============================================================

class UnifiedCachePool:
    def __init__(self, event_bus: CodexEventBus,
                 gpu_lane: GpuPredictiveLane,
                 ml_engine: MlPredictiveEngine,
                 deep_engine: DeepPredictiveEngine,
                 seq_engine: SequencePredictiveEngine,
                 cluster: SuperCacheClusterNode,
                 ram_limit_gb: int = DEFAULT_RAM_LIMIT_GB,
                 vram_limit_mb: int = DEFAULT_VRAM_LIMIT_MB,
                 lanes: int = LANES_COUNT):

        self.event_bus = event_bus
        self.gpu_lane = gpu_lane
        self.ml_engine = ml_engine
        self.deep_engine = deep_engine
        self.seq_engine = seq_engine
        self.cluster = cluster

        self.ram_limit = ram_limit_gb * (1024 ** 3)
        self.vram_limit = vram_limit_mb * (1024 ** 2)

        self.lock = threading.Lock()

        self.blocks: Dict[Tuple[str, int], str] = {}
        self.block_store: Dict[str, bytes] = {}
        self.current_size = 0
        self.lru_list = []

        self.fragmentation_map: Dict[str, List[Tuple[int, int]]] = {}
        self.metadata: Dict[str, Dict] = {}

        self.lanes = [0 for _ in range(lanes)]
        self.lane_states: List[str] = ["COLD" for _ in range(lanes)]
        self.lane_drive_affinity: Dict[int, Optional[str]] = {i: None for i in range(lanes)}

        self.drive_pool: Dict[str, int] = {}

        self.vram_lanes = []
        self.vram_used = 0
        if GPU_AVAILABLE:
            self.vram_lanes = [
                cp.zeros(self.vram_limit // lanes, dtype=cp.uint8)
                for _ in range(lanes)
            ]

        self.flush_queue = queue.Queue()
        self.flush_threads = []
        self._start_flush_workers()

        self.crypto_key = None
        if CRYPTO_AVAILABLE:
            self.crypto_key = AESGCM.generate_key(bit_length=128)

        self.cluster.block_callback = self._cluster_block_received
        self.cluster.group_callback = self._cluster_group_received

        self.consistency_groups: Dict[str, Dict] = {}

        self._load_persistent_cache()

    def _journal_path(self) -> str:
        return os.path.join(PERSIST_DIR, "journal.log")

    def _index_path(self) -> str:
        return os.path.join(PERSIST_DIR, "cache_index.json")

    def _write_journal_entry(self, entry: Dict):
        try:
            with open(self._journal_path(), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry) + "\n")
        except Exception:
            pass

    def _replay_journal(self):
        if not os.path.exists(self._journal_path()):
            return
        try:
            with open(self._journal_path(), "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    entry = json.loads(line)
                    etype = entry.get("type")
                    if etype == "meta":
                        path = entry["path"]
                        self.metadata[path] = entry["meta"]
        except Exception:
            pass

    def _encrypt(self, data: bytes) -> bytes:
        if not CRYPTO_AVAILABLE or self.crypto_key is None:
            return data
        aesgcm = AESGCM(self.crypto_key)
        nonce = os.urandom(12)
        ct = aesgcm.encrypt(nonce, data, None)
        return nonce + ct

    def _decrypt(self, data: bytes) -> bytes:
        if not CRYPTO_AVAILABLE or self.crypto_key is None:
            return data
        aesgcm = AESGCM(self.crypto_key)
        nonce = data[:12]
        ct = data[12:]
        return aesgcm.decrypt(nonce, ct, None)

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
                    "Flushed block",
                    {"path": path, "offset": offset, "size": len(data)},
                )
            except Exception:
                pass

    def _hash_block(self, data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()

    def _evict_if_needed(self, incoming_size: int):
        with self.lock:
            if self.current_size + incoming_size <= self.ram_limit:
                return
            eviction_order = self.gpu_lane.choose_eviction_candidates(self.lanes)
            while self.current_size + incoming_size > self.ram_limit and self.lru_list:
                old_key = self.lru_list.pop(0)
                h = self.blocks.pop(old_key, None)
                if h is not None:
                    enc = self.block_store.pop(h, None)
                    if enc is not None:
                        self.current_size -= len(enc)

    def add_block(self, path: str, offset: int, data: bytes, replicate: bool = True):
        if not data:
            return
        compressed = zstd_compressor.compress(data)
        enc = self._encrypt(compressed)
        block_size = len(enc)
        h = self._hash_block(enc)

        self._evict_if_needed(block_size)

        with self.lock:
            key = (path, offset)
            if h not in self.block_store:
                self.block_store[h] = enc
                self.current_size += block_size
            self.blocks[key] = h
            if key in self.lru_list:
                self.lru_list.remove(key)
            self.lru_list.append(key)

            drive = self._drive_from_path(path)
            if drive:
                self.fragmentation_map.setdefault(drive, []).append((offset, len(data)))

            lane_idx = self._choose_lane_for_drive(drive)
            self.lanes[lane_idx] += block_size
            self._update_lane_state(lane_idx)

            if drive:
                self.drive_pool[drive] = self.drive_pool.get(drive, 0) + block_size

            if GPU_AVAILABLE and self.vram_lanes:
                v_lane_idx = lane_idx % len(self.vram_lanes)
                lane = self.vram_lanes[v_lane_idx]
                start = self.vram_used % lane.size
                end = start + min(block_size, lane.size - start)
                lane[start:end] = cp.asarray(list(enc[:end - start]))
                self.vram_used += (end - start)

            self.ml_engine.update(self.lanes)
            self.deep_engine.update(self.lanes)
            self.seq_engine.update(self.lanes)

            self.metadata[path] = {
                "size": os.path.getsize(path) if os.path.exists(path) else len(data),
                "mtime": time.time(),
                "flags": {"cached": True},
            }
            self._write_journal_entry({"type": "meta", "path": path, "meta": self.metadata[path]})

        self.event_bus.log(
            "UnifiedCachePool",
            "INFO",
            "Cached block (dedup+enc)",
            {"path": path, "offset": offset, "size": len(data), "compressed": block_size},
        )

        if replicate:
            self.cluster.broadcast_block(key, enc)

        self._save_persistent_cache_index()

    def _cluster_block_received(self, key: Tuple[str, int], enc: bytes):
        try:
            path, offset = key
        except Exception:
            return
        self.event_bus.log(
            "UnifiedCachePool",
            "INFO",
            "Cluster block integrated",
            {"path": path, "offset": offset},
        )
        dec = self._decrypt(enc)
        data = zstd_decompressor.decompress(dec)
        self.add_block(path, offset, data, replicate=False)

    def _cluster_group_received(self, group_id: str, version: int, keys: List[Tuple[str, int]]):
        with self.lock:
            self.consistency_groups[group_id] = {"version": version, "keys": keys}
        self.event_bus.log(
            "UnifiedCachePool",
            "INFO",
            "Consistency group received",
            {"group_id": group_id, "version": version, "keys": keys},
        )

    def create_consistency_group(self, group_id: str, keys: List[Tuple[str, int]]):
        with self.lock:
            version = self.consistency_groups.get(group_id, {}).get("version", 0) + 1
            self.consistency_groups[group_id] = {"version": version, "keys": keys}
        self.cluster.broadcast_group(group_id, version, keys)

    def _drive_from_path(self, path: str) -> Optional[str]:
        if os.name == "nt" and len(path) >= 2 and path[1] == ":":
            return path[:2]
        return None

    def _choose_lane_for_drive(self, drive: Optional[str]) -> int:
        if drive is None:
            return len(self.lru_list) % len(self.lanes)
        for idx, d in self.lane_drive_affinity.items():
            if d == drive:
                return idx
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
            h = self.blocks.get(key)
            if h is None:
                return None
            enc = self.block_store.get(h)
            if enc is None:
                return None
            if key in self.lru_list:
                self.lru_list.remove(key)
            self.lru_list.append(key)
        try:
            dec = self._decrypt(enc)
            data = zstd_decompressor.decompress(dec)
            return data[:size]
        except Exception:
            return None

    def schedule_flush(self, path: str, offset: int, data: bytes):
        self.flush_queue.put((path, offset, data))

    def stats(self):
        with self.lock:
            return {
                "blocks": len(self.blocks),
                "unique_blocks": len(self.block_store),
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
                "fragmentation_map": {d: list(v) for d, v in self.fragmentation_map.items()},
                "metadata_count": len(self.metadata),
                "consistency_groups": {gid: dict(v) for gid, v in self.consistency_groups.items()},
            }

    def _save_persistent_cache_index(self):
        try:
            with self.lock:
                index = {
                    "blocks": [[p, o, h] for (p, o), h in self.blocks.items()],
                    "lane_drive_affinity": self.lane_drive_affinity,
                    "drive_pool": self.drive_pool,
                    "metadata": self.metadata,
                    "consistency_groups": self.consistency_groups,
                }
            tmp_path = self._index_path() + ".tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(index, f)
            os.replace(tmp_path, self._index_path())
        except Exception:
            pass

    def _load_persistent_cache(self):
        self._replay_journal()
        try:
            if not os.path.exists(self._index_path()):
                return
            with open(self._index_path(), "r", encoding="utf-8") as f:
                index = json.load(f)
            with self.lock:
                self.blocks.clear()
                self.block_store.clear()
                self.lru_list.clear()
                for p, o, h in index.get("blocks", []):
                    self.blocks[(p, o)] = h
                self.lane_drive_affinity.update(index.get("lane_drive_affinity", {}))
                self.drive_pool.update(index.get("drive_pool", {}))
                self.metadata.update(index.get("metadata", {}))
                self.consistency_groups.update(index.get("consistency_groups", {}))
            self.event_bus.log(
                "UnifiedCachePool",
                "INFO",
                "Persistent cache index loaded",
                {"blocks": len(self.blocks)},
            )
        except Exception:
            pass


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
#   FORESIGHT ENGINE (ML + DEEP + SEQ)
# ============================================================

class ForesightEngine:
    def __init__(self, cache_pool: UnifiedCachePool,
                 event_bus: CodexEventBus,
                 ml_engine: MlPredictiveEngine,
                 deep_engine: DeepPredictiveEngine,
                 seq_engine: SequencePredictiveEngine):
        self.cache = cache_pool
        self.event_bus = event_bus
        self.ml_engine = ml_engine
        self.deep_engine = deep_engine
        self.seq_engine = seq_engine
        self.enabled = True

    def prefetch_file(self, path: str, max_blocks: Optional[int] = None):
        if not self.enabled:
            return
        lanes = self.cache.lanes
        ml_blocks = self.ml_engine.suggest_prefetch_blocks(lanes)
        deep_blocks = self.deep_engine.suggest_prefetch_blocks(lanes)
        seq_blocks = self.seq_engine.suggest_prefetch_blocks(lanes)
        suggested_blocks = max(ml_blocks, deep_blocks, seq_blocks)
        blocks_to_read = max_blocks if max_blocks is not None else suggested_blocks
        try:
            with open(path, "rb") as fp:
                offset = 0
                for _ in range(blocks_to_read):
                    data = fp.read(READ_BLOCK_SIZE)
                    if not data:
                        break
                    self.cache.add_block(path, offset, data)
                    offset += len(data)
            self.event_bus.log(
                "ForesightEngine",
                "INFO",
                "Prefetched file (ML+Deep+Seq)",
                {"path": path, "blocks": blocks_to_read},
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
                 event_bus: CodexEventBus,
                 kernel_stub: KernelStubFilterDriver):
        self.cache = cache_pool
        self.foresight = foresight
        self.event_bus = event_bus
        self.kernel_stub = kernel_stub

    def read(self, path: str, offset: int = 0, size: int = READ_BLOCK_SIZE) -> bytes:
        self.kernel_stub.intercept_read(path, offset, size)
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
                    self.foresight.prefetch_file(path)
                    self.event_bus.log(
                        "UnifiedIO",
                        "DEBUG",
                        "Cache miss",
                        {"path": path, "offset": offset, "size": len(data)},
                    )
                    return data
                return b""
        except Exception:
            return b""

    def write(self, path: str, offset: int, data: bytes):
        if not data:
            return
        self.kernel_stub.intercept_write(path, offset, len(data))
        self.cache.add_block(path, offset, data)
        self.cache.schedule_flush(path, offset, data)
        self.event_bus.log(
            "UnifiedIO",
            "INFO",
            "Write scheduled",
            {"path": path, "offset": offset, "size": len(data)},
        )


# ============================================================
#   VIRTUAL FILESYSTEM + FUSE/Dokan STUB
# ============================================================

class VirtualFilesystem:
    def __init__(self, letter: str, root: str):
        self.letter = letter.upper()
        self.root = os.path.abspath(root)

    def real_path(self, vpath: str) -> str:
        vpath = vpath.replace("\\", "/")
        if vpath.upper().startswith(self.letter + ":/"):
            rel = vpath[3:]
            return os.path.join(self.root, rel.replace("/", os.sep))
        return vpath

    def virtual_path(self, real_path: str) -> str:
        rp = os.path.abspath(real_path)
        if rp.startswith(self.root):
            rel = os.path.relpath(rp, self.root)
            return f"{self.letter}:\\" + rel.replace("/", "\\")
        return real_path

    def mount_stub(self):
        pass


# ============================================================
#   PID ROUTER
# ============================================================

class ProcessRouter:
    def __init__(self, event_bus: CodexEventBus):
        self.event_bus = event_bus
        self.lock = threading.Lock()
        self.routes: Dict[int, Dict] = {}

    def register_pid(self, pid: int, label: str = "", notes: Dict = None):
        with self.lock:
            self.routes[pid] = {
                "label": label or f"PID {pid}",
                "notes": notes or {},
                "time": time.time(),
            }
        self.event_bus.log(
            "ProcessRouter",
            "INFO",
            "PID registered",
            {"pid": pid, "label": label},
        )

    def unregister_pid(self, pid: int):
        with self.lock:
            if pid in self.routes:
                self.routes.pop(pid, None)
        self.event_bus.log(
            "ProcessRouter",
            "INFO",
            "PID unregistered",
            {"pid": pid},
        )

    def list_pids(self) -> Dict[int, Dict]:
        with self.lock:
            return dict(self.routes)


class ProcessLauncher:
    def __init__(self, router: ProcessRouter, event_bus: CodexEventBus):
        self.router = router
        self.event_bus = event_bus

    def launch(self, cmd: List[str], label: str = "") -> Optional[int]:
        try:
            proc = subprocess.Popen(cmd)
            pid = proc.pid
            self.router.register_pid(pid, label=label or "routed_process")
            self.event_bus.log(
                "ProcessLauncher",
                "INFO",
                "Process launched",
                {"pid": pid, "cmd": cmd},
            )
            return pid
        except Exception as e:
            self.event_bus.log(
                "ProcessLauncher",
                "ERROR",
                "Launch failed",
                {"cmd": cmd, "error": str(e)},
            )
            return None


# ============================================================
#   AI ASSISTANT (LLM-LIKE LOCAL ENGINE)
# ============================================================

class AiAssistant:
    """
    Local, rule-based "LLM-style" explainer and policy engine.
    No external calls; uses stats + heuristics to generate text.
    """

    def explain_super_cache(self, stats: Dict) -> str:
        total_mb = stats.get("super_cache_total_mb", 0.0)
        blocks = stats.get("blocks", 0)
        unique = stats.get("unique_blocks", 0)
        meta = stats.get("metadata_count", 0)
        return (
            f"Super Cache FS is acting as a unified storage brain.\n\n"
            f"- Total effective cache: {total_mb:.2f} MB\n"
            f"- Total blocks tracked: {blocks} (unique: {unique})\n"
            f"- Metadata entries: {meta}\n\n"
            f"It pools RAM, VRAM, and drive-backed blocks into one logical cache, "
            f"with deduplication, encryption, journaling, and predictive prefetching. "
            f"This gives you SSD-like behavior on repeated workloads and a global view "
            f"of how your drives are being used."
        )

    def explain_lanes(self, stats: Dict) -> str:
        lanes = stats.get("lanes", [])
        states = stats.get("lane_states", [])
        scores = stats.get("lane_scores", [])
        text = "Lane heatmap represents how cache pressure is distributed across logical lanes.\n\n"
        for i, val in enumerate(lanes):
            st = states[i] if i < len(states) else "UNKNOWN"
            sc = scores[i] if i < len(scores) else 0.0
            text += f"- Lane {i}: {val/1024/1024:.2f} MB, state={st}, score={sc:.2f}\n"
        text += (
            "\nCold lanes are underutilized; hot/priority lanes are carrying most of the cache load. "
            "Adaptive merging can combine cold lanes to simplify scheduling and free resources."
        )
        return text

    def explain_drives(self, stats: Dict) -> str:
        pool = stats.get("drive_pool", {})
        if not pool:
            return "No drives currently contributing to the Super Cache pool."
        text = "Drive pool shows how much cache is associated with each physical drive.\n\n"
        for d, v in pool.items():
            text += f"- {d}: {v/1024/1024:.2f} MB cached\n"
        text += (
            "\nDrives with higher cached MB are more active or have more hot data. "
            "This helps you see which drives are critical for performance and where "
            "to focus optimization or hardware upgrades."
        )
        return text

    def explain_consistency_groups(self, stats: Dict) -> str:
        groups = stats.get("consistency_groups", {})
        if not groups:
            return "No consistency groups defined yet. They represent versioned sets of blocks replicated across nodes."
        text = "Consistency groups are versioned collections of blocks used for distributed replication.\n\n"
        for gid, info in groups.items():
            text += f"- Group {gid}: version {info.get('version', 0)}, blocks={len(info.get('keys', []))}\n"
        text += (
            "\nEach group can be used to keep related data in sync across nodes, enabling "
            "cluster-aware caching and resilience. Higher versions indicate more recent updates."
        )
        return text

    def explain_pids(self, routed_pids: Dict[int, Dict]) -> str:
        if not routed_pids:
            return "No routed PIDs. Routed processes are those explicitly launched through the cache brain."
        text = "Routed PIDs are processes whose I/O is being tracked and labeled.\n\n"
        for pid, meta in routed_pids.items():
            text += f"- PID {pid}: label={meta.get('label', '')}\n"
        text += (
            "\nBy routing processes, you can apply per-workload policies, observe their impact on cache, "
            "and tune behavior for specific applications (e.g., games, databases, IDEs)."
        )
        return text

    def generate_policy(self, stats: Dict) -> str:
        lanes = stats.get("lanes", [])
        states = stats.get("lane_states", [])
        drive_pool = stats.get("drive_pool", {})
        gpu = stats.get("gpu_available", False)
        policy = "AI Policy Proposal:\n\n"
        if gpu:
            policy += "- Enable GPU-accelerated eviction scoring for all lanes.\n"
        hot_lanes = [i for i, st in enumerate(states) if st in ("HOT", "PRIORITY")]
        if hot_lanes:
            policy += f"- Prioritize prefetching on lanes {hot_lanes}.\n"
        if drive_pool:
            heavy = max(drive_pool.items(), key=lambda x: x[1])[0]
            policy += f"- Mark drive {heavy} as high-affinity for hot workloads.\n"
        if len(lanes) > 4:
            policy += "- Merge cold lanes with very low usage to reduce scheduling overhead.\n"
        policy += (
            "- Use journaling aggressively for metadata-heavy workloads.\n"
            "- Keep encryption enabled for all cached blocks to maintain security.\n"
        )
        return policy

    def detect_anomalies(self, stats: Dict) -> str:
        lanes = stats.get("lanes", [])
        drive_pool = stats.get("drive_pool", {})
        anomalies = []
        if lanes:
            avg = sum(lanes) / len(lanes)
            for i, v in enumerate(lanes):
                if v > avg * 3 and avg > 0:
                    anomalies.append(f"Lane {i} is disproportionately loaded ({v/1024/1024:.2f} MB).")
        if drive_pool:
            values = list(drive_pool.values())
            avg_d = sum(values) / len(values)
            for d, v in drive_pool.items():
                if v > avg_d * 3 and avg_d > 0:
                    anomalies.append(f"Drive {d} has unusually high cached MB ({v/1024/1024:.2f} MB).")
        if not anomalies:
            return "No obvious anomalies detected. Cache distribution appears balanced."
        return "Detected anomalies:\n\n" + "\n".join(f"- {a}" for a in anomalies)

    def suggest_optimizations(self, stats: Dict) -> str:
        lanes = stats.get("lanes", [])
        states = stats.get("lane_states", [])
        vram_used = stats.get("vram_used_mb", 0.0)
        vram_limit = stats.get("vram_limit_mb", 0.0)
        text = "Optimization suggestions:\n\n"
        if lanes:
            cold = [i for i, st in enumerate(states) if st == "COLD"]
            if cold:
                text += "- Merge or repurpose cold lanes to reduce overhead and focus on hot workloads.\n"
        if vram_limit > 0 and vram_used < vram_limit * 0.2:
            text += "- Increase VRAM usage for hot blocks to accelerate repeated reads.\n"
        if stats.get("metadata_count", 0) > 1000:
            text += "- Consider pruning or compressing metadata for rarely accessed files.\n"
        if not lanes and not stats.get("drive_pool", {}):
            text += "- Seed drives to populate the cache and give the predictive models more data.\n"
        if text.strip() == "Optimization suggestions:":
            text += "\nNo specific optimizations identified; system appears well-balanced."
        return text


# ============================================================
#   UNIFIED CACHE BRAIN
# ============================================================

class UnifiedCacheBrain:
    def __init__(self, cluster_port: int = 9099):
        self.event_bus = CodexEventBus()
        self.kernel_stub = KernelStubFilterDriver(self.event_bus)
        self.gpu_lane = GpuPredictiveLane(self.event_bus)
        self.ml_engine = MlPredictiveEngine(self.event_bus, LANES_COUNT)
        self.deep_engine = DeepPredictiveEngine(self.event_bus, LANES_COUNT)
        self.seq_engine = SequencePredictiveEngine(self.event_bus, LANES_COUNT)

        self.cluster = SuperCacheClusterNode(self.event_bus, port=cluster_port)
        self.cluster.start_server()

        self.pool = UnifiedCachePool(
            self.event_bus,
            self.gpu_lane,
            self.ml_engine,
            self.deep_engine,
            self.seq_engine,
            self.cluster,
        )
        self.scanner = DriveScanner(self.pool, self.event_bus)
        self.foresight = ForesightEngine(self.pool, self.event_bus,
                                         self.ml_engine, self.deep_engine, self.seq_engine)
        self.io = UnifiedIO(self.pool, self.foresight, self.event_bus, self.kernel_stub)

        self.vfs = VirtualFilesystem("V", os.path.join(os.getcwd(), "vfs_root_v3_ai"))
        os.makedirs(self.vfs.root, exist_ok=True)

        self.router = ProcessRouter(self.event_bus)
        self.launcher = ProcessLauncher(self.router, self.event_bus)

        self.ai = AiAssistant()

    def seed_all_drives(self):
        drives = self.scanner.list_drives()
        for d in drives:
            self.scanner.scan_drive(d, max_files=200)
            self.event_bus.log(
                "UnifiedCacheBrain",
                "INFO",
                "Seeded drive",
                {"drive": d},
            )

    def read(self, vpath: str, offset: int = 0, size: int = READ_BLOCK_SIZE):
        real = self.vfs.real_path(vpath)
        return self.io.read(real, offset, size)

    def write(self, vpath: str, offset: int, data: bytes):
        real = self.vfs.real_path(vpath)
        self.io.write(real, offset, data)

    def stats(self):
        s = self.pool.stats()
        merged_lanes = self.gpu_lane.adaptive_merge(s["lanes"])
        scores = self.gpu_lane.analyze_lanes(s["lanes"])
        s["lane_scores"] = scores
        s["merged_lanes"] = merged_lanes
        drive_total = sum(s["drive_pool"].values()) if s["drive_pool"] else 0
        s["super_cache_total_mb"] = (
            s["size_mb"] +
            s["vram_used_mb"] +
            (drive_total / (1024**2))
        )
        self.cluster.broadcast_stats({
            "super_cache_total_mb": s["super_cache_total_mb"],
            "drive_pool": s["drive_pool"],
            "lanes": s["lanes"],
            "lane_states": s["lane_states"],
        })
        return s

    def foresight_state(self):
        return "ON" if self.foresight.enabled else "OFF"

    def toggle_foresight(self):
        self.foresight.toggle()

    def attach_kernel_stub(self):
        self.kernel_stub.attach()

    def detach_kernel_stub(self):
        self.kernel_stub.detach()

    def get_events(self, limit: int = 100):
        return self.event_bus.get_events(limit=limit)

    def launch_routed_process(self, cmd: List[str], label: str = "") -> Optional[int]:
        return self.launcher.launch(cmd, label=label)

    def list_routed_pids(self) -> Dict[int, Dict]:
        return self.router.list_pids()


# ============================================================
#   GUI
# ============================================================

class DriveHeatmapGraph(QtWidgets.QWidget):
    def __init__(self):
        super().__init__()
        self.drive_pool = {}
        self.setMinimumHeight(200)

    def update_drives(self, drive_pool):
        self.drive_pool = dict(sorted(drive_pool.items(), key=lambda x: x[0]))
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
        max_val = max(values) if values and max(values) > 0 else 1
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
        self.stats_label.setWordWrap(True)
        self.pid_label = QtWidgets.QLabel()
        self.pid_label.setWordWrap(True)

        # AI output panel
        self.ai_output = QtWidgets.QTextEdit()
        self.ai_output.setReadOnly(True)
        self.ai_output.setMinimumHeight(160)

        # AI buttons
        self.btn_explain_super = QtWidgets.QPushButton("Explain Super Cache (AI)")
        self.btn_explain_lanes = QtWidgets.QPushButton("Explain Lanes (AI)")
        self.btn_explain_drives = QtWidgets.QPushButton("Explain Drives (AI)")
        self.btn_explain_groups = QtWidgets.QPushButton("Explain Consistency Groups (AI)")
        self.btn_explain_pids = QtWidgets.QPushButton("Explain Routed PIDs (AI)")
        self.btn_policy = QtWidgets.QPushButton("Generate Policy (AI)")
        self.btn_anomaly = QtWidgets.QPushButton("Detect Anomalies (AI)")
        self.btn_optimize = QtWidgets.QPushButton("Suggest Optimizations (AI)")

        self.btn_explain_super.clicked.connect(self.on_explain_super)
        self.btn_explain_lanes.clicked.connect(self.on_explain_lanes)
        self.btn_explain_drives.clicked.connect(self.on_explain_drives)
        self.btn_explain_groups.clicked.connect(self.on_explain_groups)
        self.btn_explain_pids.clicked.connect(self.on_explain_pids)
        self.btn_policy.clicked.connect(self.on_policy)
        self.btn_anomaly.clicked.connect(self.on_anomaly)
        self.btn_optimize.clicked.connect(self.on_optimize)

        ai_buttons_layout = QtWidgets.QHBoxLayout()
        ai_buttons_layout.addWidget(self.btn_explain_super)
        ai_buttons_layout.addWidget(self.btn_explain_lanes)
        ai_buttons_layout.addWidget(self.btn_explain_drives)
        ai_buttons_layout.addWidget(self.btn_explain_groups)
        ai_buttons_layout.addWidget(self.btn_explain_pids)

        ai_buttons_layout2 = QtWidgets.QHBoxLayout()
        ai_buttons_layout2.addWidget(self.btn_policy)
        ai_buttons_layout2.addWidget(self.btn_anomaly)
        ai_buttons_layout2.addWidget(self.btn_optimize)
        ai_buttons_layout2.addStretch()

        top_layout = QtWidgets.QVBoxLayout()
        top_layout.addWidget(self.super_label)
        top_layout.addWidget(self.drive_view)

        split = QtWidgets.QHBoxLayout()
        split.addLayout(top_layout, 1)
        split.addWidget(self.lanes_view, 2)

        layout = QtWidgets.QVBoxLayout()
        layout.addLayout(split)
        layout.addWidget(self.stats_label)
        layout.addWidget(self.pid_label)
        layout.addLayout(ai_buttons_layout)
        layout.addLayout(ai_buttons_layout2)
        layout.addWidget(self.ai_output)

        self.setLayout(layout)

        self.timer = QtCore.QTimer(self)
        self.timer.timeout.connect(self.update_view)
        self.timer.start(1000)

    def update_view(self):
        s = self.brain.stats()
        self.super_label.setText(
            f"SUPER CACHE FS v3 AI: {s['super_cache_total_mb']:.2f} MB | Unique blocks: {s['unique_blocks']} | Metadata: {s['metadata_count']}"
        )
        self.drive_view.update_drives(s["drive_pool"])
        self.lanes_view.update_lanes(s["lanes"], s["lane_states"], s["lane_scores"])
        text = (
            f"Blocks: {s['blocks']} (unique: {s['unique_blocks']})\n"
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
        text += "\nConsistency groups:\n"
        for gid, info in s["consistency_groups"].items():
            text += f"  {gid}: v{info['version']} ({len(info['keys'])} blocks)\n"
        self.stats_label.setText(text)

        routed = self.brain.list_routed_pids()
        pid_text = "Routed PIDs:\n"
        for pid, meta in routed.items():
            pid_text += f"  {pid}: {meta['label']}\n"
        self.pid_label.setText(pid_text)

    def _set_ai_output(self, text: str):
        self.ai_output.setPlainText(text)

    def on_explain_super(self):
        s = self.brain.stats()
        text = self.brain.ai.explain_super_cache(s)
        self._set_ai_output(text)

    def on_explain_lanes(self):
        s = self.brain.stats()
        text = self.brain.ai.explain_lanes(s)
        self._set_ai_output(text)

    def on_explain_drives(self):
        s = self.brain.stats()
        text = self.brain.ai.explain_drives(s)
        self._set_ai_output(text)

    def on_explain_groups(self):
        s = self.brain.stats()
        text = self.brain.ai.explain_consistency_groups(s)
        self._set_ai_output(text)

    def on_explain_pids(self):
        routed = self.brain.list_routed_pids()
        text = self.brain.ai.explain_pids(routed)
        self._set_ai_output(text)

    def on_policy(self):
        s = self.brain.stats()
        text = self.brain.ai.generate_policy(s)
        self._set_ai_output(text)

    def on_anomaly(self):
        s = self.brain.stats()
        text = self.brain.ai.detect_anomalies(s)
        self._set_ai_output(text)

    def on_optimize(self):
        s = self.brain.stats()
        text = self.brain.ai.suggest_optimizations(s)
        self._set_ai_output(text)


class CacheBrainPane(QtWidgets.QWidget):
    def __init__(self, brain: UnifiedCacheBrain, parent=None):
        super().__init__(parent)
        self.brain = brain
        self.setWindowTitle("Codex - Super Cache FS v3 AI Brain")
        self.resize(1300, 780)

        self.tabs = QtWidgets.QTabWidget()
        self.cache_tab = QtWidgets.QWidget()
        self.tabs.addTab(self.cache_tab, "Super Cache FS v3 AI")

        self.btn_rescan = QtWidgets.QPushButton("Rescan All Drives")
        self.btn_toggle_foresight = QtWidgets.QPushButton("FORESIGHT: ON")
        self.btn_attach_kernel = QtWidgets.QPushButton("Attach Kernel Stub")
        self.btn_launch_notepad = QtWidgets.QPushButton("Launch Routed Notepad")
        self.btn_show_events = QtWidgets.QPushButton("Show Events")

        self.btn_rescan.clicked.connect(self.on_rescan)
        self.btn_toggle_foresight.clicked.connect(self.on_toggle_foresight)
        self.btn_attach_kernel.clicked.connect(self.on_attach_kernel)
        self.btn_launch_notepad.clicked.connect(self.on_launch_notepad)
        self.btn_show_events.clicked.connect(self.on_show_events)

        ribbon = QtWidgets.QHBoxLayout()
        ribbon.addWidget(self.btn_rescan)
        ribbon.addWidget(self.btn_toggle_foresight)
        ribbon.addWidget(self.btn_attach_kernel)
        ribbon.addWidget(self.btn_launch_notepad)
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
        threading.Thread(target=self.brain.seed_all_drives, daemon=True).start()

    def on_toggle_foresight(self):
        self.brain.toggle_foresight()
        self.update_ribbon()

    def on_attach_kernel(self):
        self.brain.attach_kernel_stub()
        QtWidgets.QMessageBox.information(self, "Kernel Stub", "Kernel stub attached (simulated).")

    def on_launch_notepad(self):
        if os.name == "nt":
            pid = self.brain.launch_routed_process(["notepad.exe"], label="Notepad (routed)")
            if pid:
                QtWidgets.QMessageBox.information(self, "Routed Process", f"Notepad launched with PID {pid}.")
        else:
            QtWidgets.QMessageBox.information(self, "Routed Process", "Notepad routing demo is Windows-only.")

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
    brain = UnifiedCacheBrain(cluster_port=9099)
    brain.seed_all_drives()
    app = QtWidgets.QApplication([])
    pane = CacheBrainPane(brain)
    pane.show()
    app.exec_()


if __name__ == "__main__":
    main()
