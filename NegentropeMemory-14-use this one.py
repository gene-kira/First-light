import argparse
from collections import OrderedDict
import gc
import importlib
import json
import math
import os
import string
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import zlib


CHUNK_SIZE = 65536
STATE_FILE = "memory_zip_state.json"


# =====================================================================
# 1. Self-Bootstrapping Library Autoloader & Self-Healing Codec Layer
# =====================================================================
class LibraryAutoloader:
    """Automatically verifies and installs optional acceleration libraries."""

    def __init__(self):
        self.logs: list[str] = []
        self.lz4_module = None
        self.lz4_available = False
        self.psutil_module = None
        self.psutil_available = False

    def ensure_package(self, import_name: str, pip_name: str | None = None):
        pkg = pip_name or import_name
        try:
            mod = importlib.import_module(import_name)
            self.logs.append(f"[Autoloader] '{import_name}' is already available.")
            return mod
        except ImportError:
            self.logs.append(f"[Autoloader] '{import_name}' missing. Attempting pip install '{pkg}'...")
            try:
                subprocess.check_call(
                    [sys.executable, "-m", "pip", "install", "--quiet", pkg],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                )
                mod = importlib.import_module(import_name)
                self.logs.append(f"[Autoloader] Successfully installed and loaded '{import_name}'.")
                return mod
            except Exception as exc:
                self.logs.append(
                    f"[Autoloader][Self-Heal] Could not auto-install '{pkg}' ({exc}). "
                    f"Using built-in fallback."
                )
                return None

    def bootstrap(self):
        self.lz4_module = self.ensure_package("lz4.frame", "lz4")
        self.lz4_available = self.lz4_module is not None

        self.psutil_module = self.ensure_package("psutil", "psutil")
        self.psutil_available = self.psutil_module is not None
        return self.lz4_available


# =====================================================================
# 2. Directed Memory Placement Planner (Slot & Zone Assignment)
# =====================================================================
class MemoryPlacementPlanner:
    """
    Assigns incoming payloads to dedicated placement zones and logical slots
    instead of leaving placement unsorted.
    """

    def __init__(self):
        self.next_slot_id = 1
        self.zone_cursors = {
            "FAST_SMALL": 0,
            "STREAM_MED": 0,
            "BULK_COLD": 0,
        }

    def choose_zone(self, active_bytes: int) -> str:
        if active_bytes <= 4096:
            return "FAST_SMALL"
        if active_bytes <= 262144:
            return "STREAM_MED"
        return "BULK_COLD"

    def assign_slot(self, active_bytes: int, harmonic_align: bool = False) -> tuple[str, str, int]:
        zone = self.choose_zone(active_bytes)
        slot_id = f"SLOT-{self.next_slot_id:04d}"
        self.next_slot_id += 1
        offset = self.zone_cursors[zone]
        align = 256 if harmonic_align else 64
        span = max(align, ((active_bytes + align - 1) // align) * align)
        self.zone_cursors[zone] = offset + span
        return zone, slot_id, offset


# =====================================================================
# 3. Compact Slot-Based Memory Entry & Streaming I/O Helpers
# =====================================================================
class CompressedEntry:
    """Compact __slots__ record with placement slot, CRC, relevance, and tier info."""

    __slots__ = (
        "name",
        "source",
        "codec",
        "zone",
        "slot_id",
        "slot_offset",
        "crc32",
        "tier",
        "raw_len",
        "zipped",
        "hot_bytes",
        "raw_cached",
        "pred_ratio",
        "ai_confidence",
        "hits",
        "last_used",
    )

    def __init__(
        self,
        name: str,
        source: str,
        codec: str,
        zone: str,
        slot_id: str,
        slot_offset: int,
        crc32: int,
        raw_len: int,
        zipped: bytes,
        pred_ratio: float,
        ai_confidence: float = 0.5,
        tier: str = "COLD",
        hot_bytes: bytes | None = None,
        raw_cached: bytes | None = None,
    ):
        self.name = name
        self.source = source
        self.codec = codec
        self.zone = zone
        self.slot_id = slot_id
        self.slot_offset = slot_offset
        self.crc32 = crc32
        self.tier = tier
        self.raw_len = raw_len
        self.zipped = zipped
        self.hot_bytes = hot_bytes
        self.raw_cached = raw_cached
        self.pred_ratio = pred_ratio
        self.ai_confidence = ai_confidence
        self.hits = 1
        self.last_used = time.time()

    @property
    def active_bytes_len(self) -> int:
        if self.tier == "HOT" and self.hot_bytes is not None:
            return len(self.hot_bytes)
        return len(self.zipped)

    @property
    def ratio(self) -> float:
        denom = max(1, self.active_bytes_len)
        return self.raw_len / denom

    @property
    def saved_bytes(self) -> int:
        return self.raw_len - self.active_bytes_len

    @property
    def saved_pct(self) -> float:
        return (self.saved_bytes / self.raw_len * 100.0) if self.raw_len > 0 else 0.0

    def relevance_score(self, now: float | None = None) -> float:
        ts = now if now is not None else time.time()
        age_sec = max(0.1, ts - self.last_used)
        return (math.log1p(self.hits) * 10.0) / math.sqrt(age_sec)


def read_file_chunked(path: str, max_bytes: int) -> bytes:
    """Reads a file in bounded chunks rather than one giant allocation."""
    chunks: list[bytes] = []
    total = 0
    with open(path, "rb") as f:
        while total < max_bytes:
            piece = f.read(min(CHUNK_SIZE, max_bytes - total))
            if not piece:
                break
            chunks.append(piece)
            total += len(piece)
    return b"".join(chunks)


# =====================================================================
# 4. Persistent Session & Drive Memory Store
# =====================================================================
class SessionMemoryStore:
    """Persists user drive selections, scope, and preferences across reboots."""

    DEFAULTS = {
        "last_drive": "",
        "selected_drives": [],
        "drive_scope": "Selected Folder",
        "target_path": "",
        "interval": "3.0",
        "max_file_mb": "16",
        "skip_exts": ".iso,.bin,.img,.zip,.gz,.7z,.mp4,.mkv,.avi",
        "strategy": "Auto (AI + Harmonic)",
        "skip_expansion": True,
        "auto_rebalance": True,
        "lean_mode": True,
        "show_hex": False,
        "auto_running": True,
        "predictive_lookahead": True,
        "counterfactual_probe": True,
        "auto_heal_daemon": True,
        "auto_save_weights": True,
    }

    def __init__(self, state_path: str = STATE_FILE):
        self.state_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), state_path)
        self.data = dict(self.DEFAULTS)

    def load(self) -> str:
        if not os.path.exists(self.state_path):
            return "No saved session state yet; target path starts blank until selected."
        try:
            with open(self.state_path, "r", encoding="utf-8") as f:
                raw = json.load(f)
            if isinstance(raw, dict):
                for k, default_val in self.DEFAULTS.items():
                    if k in raw and isinstance(raw[k], type(default_val)):
                        self.data[k] = raw[k]
            return f"Restored saved session state from {self.state_path}."
        except Exception as exc:
            self.data = dict(self.DEFAULTS)
            return f"[Self-Heal] Session state reset after read issue ({exc})."

    def save(self, updates: dict) -> str:
        self.data.update(updates)
        try:
            with open(self.state_path, "w", encoding="utf-8") as f:
                json.dump(self.data, f, indent=2)
            return f"Saved session state to {self.state_path}."
        except Exception as exc:
            return f"[Self-Heal] Failed saving session state ({exc})."


# =====================================================================
# 5. System-Wide Drive & Process Memory Backbone Discovery
# =====================================================================
class SystemBackbone:
    """Discovers drives across the OS (including A-Z letter slots) and reads RAM stats."""

    def __init__(self, autoloader: LibraryAutoloader):
        self.autoloader = autoloader

    def list_drives(self) -> list[str]:
        drives: list[str] = []
        if self.autoloader.psutil_available and self.autoloader.psutil_module is not None:
            try:
                for part in self.autoloader.psutil_module.disk_partitions(all=False):
                    if part.mountpoint and os.path.isdir(part.mountpoint):
                        drives.append(part.mountpoint)
            except Exception:
                pass

        if not drives:
            if os.name == "nt":
                for letter in string.ascii_uppercase:
                    root = f"{letter}:\\"
                    if os.path.exists(root):
                        drives.append(root)
            else:
                for candidate in ["/", "/mnt", "/media", "/Volumes"]:
                    if os.path.isdir(candidate):
                        drives.append(candidate)

        seen = set()
        unique = []
        for d in drives:
            norm = os.path.abspath(d)
            if norm not in seen:
                seen.add(norm)
                unique.append(d)
        return unique or [os.path.abspath(os.sep)]

    def get_az_catalog(self) -> list[str]:
        """
        Returns all A-Z drive roots (A:\\ .. Z:\\ on Windows, or detected OS
        drives on POSIX) so users can toggle any A-Z drive combination.
        """
        detected = self.list_drives()
        if os.name == "nt":
            az_letters = [f"{ch}:\\" for ch in string.ascii_uppercase]
            extras = [d for d in detected if d.upper() not in {x.upper() for x in az_letters}]
            return az_letters + extras
        return detected

    def get_process_rss_bytes(self) -> int | None:
        if self.autoloader.psutil_available and self.autoloader.psutil_module is not None:
            try:
                proc = self.autoloader.psutil_module.Process(os.getpid())
                return int(proc.memory_info().rss)
            except Exception:
                pass
        if os.path.exists("/proc/self/statm"):
            try:
                with open("/proc/self/statm", "r", encoding="utf-8") as f:
                    parts = f.read().split()
                if len(parts) >= 2:
                    rss_pages = int(parts[1])
                    page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
                    return rss_pages * page_size
            except Exception:
                pass
        return None

    def get_ram_summary(self) -> str:
        parts = []
        rss = self.get_process_rss_bytes()
        if rss is not None:
            parts.append(f"App RSS: {rss / (1024 ** 2):.1f} MB")

        if self.autoloader.psutil_available and self.autoloader.psutil_module is not None:
            try:
                vm = self.autoloader.psutil_module.virtual_memory()
                used_gb = vm.used / (1024 ** 3)
                total_gb = vm.total / (1024 ** 3)
                parts.append(f"System RAM: {used_gb:.1f} / {total_gb:.1f} GB ({vm.percent:.0f}%)")
            except Exception:
                pass

        return "  |  ".join(parts) if parts else "RAM Telemetry: standard runtime"

    def get_drive_free_text(self, path: str) -> str:
        if not path:
            return "Free on target: (none selected)"
        target = path if os.path.exists(path) else os.path.abspath(os.sep)
        try:
            st = os.statvfs(target) if hasattr(os, "statvfs") else None
            if st is not None:
                free_gb = (st.f_bavail * st.f_frsize) / (1024 ** 3)
                return f"Free on target: {free_gb:.1f} GB"
        except Exception:
            pass
        if os.name == "nt":
            try:
                import ctypes
                free_bytes = ctypes.c_ulonglong(0)
                total_bytes = ctypes.c_ulonglong(0)
                avail_bytes = ctypes.c_ulonglong(0)
                ctypes.windll.kernel32.GetDiskFreeSpaceExW(
                    ctypes.c_wchar_p(target),
                    ctypes.byref(avail_bytes),
                    ctypes.byref(total_bytes),
                    ctypes.byref(free_bytes),
                )
                return f"Free on target: {avail_bytes.value / (1024 ** 3):.1f} GB"
            except Exception:
                pass
        return "Free on target: N/A"

    def create_backbone_launcher(self, watch_path: str) -> str:
        script_path = os.path.abspath(__file__)
        py_exe = sys.executable
        base_dir = os.path.dirname(script_path)
        watch_arg = f' --watch "{watch_path}"' if watch_path else ""

        if os.name == "nt":
            launcher_path = os.path.join(base_dir, "start_memory_zip_backbone.bat")
            content = (
                "@echo off\r\n"
                f'cd /d "{base_dir}"\r\n'
                f'"{py_exe}" "{script_path}" --daemon{watch_arg}\r\n'
            )
        else:
            launcher_path = os.path.join(base_dir, "start_memory_zip_backbone.sh")
            content = (
                "#!/usr/bin/env bash\n"
                "set -e\n"
                f'cd "{base_dir}"\n'
                f'exec "{py_exe}" "{script_path}" --daemon{watch_arg}\n'
            )

        with open(launcher_path, "w", encoding="utf-8") as f:
            f.write(content)

        if os.name != "nt":
            os.chmod(launcher_path, 0o755)

        return launcher_path


# =====================================================================
# 6. Harmonic Phase, Momentum, Regret & Counterfactual AI Engine
# =====================================================================
class HarmonicPhaseEngine:
    """
    Combines real-time momentum-smoothed weights with coupled multi-channel
    harmonic phase oscillators, multi-horizon trajectory forecasting,
    counterfactual regret tracking, and shadow codec evaluation.
    """

    DEFAULT_WEIGHTS = {
        "intercept": 2.40,
        "entropy_penalty": -0.26,
        "repetition_bonus": 1.35,
        "log_size_bonus": 0.12,
        "harmonic_weight": 0.35,
        "gain_sensitivity": 0.45,
        "base_lr": 0.12,
        "coupling_strength": 0.28,
        "lookahead_gain": 0.22,
    }

    ADAPTABLE_KEYS = (
        "intercept",
        "entropy_penalty",
        "repetition_bonus",
        "log_size_bonus",
        "harmonic_weight",
        "coupling_strength",
    )

    def __init__(self, weights_path: str = "memory_zip_weights.json"):
        self.weights_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), weights_path)
        self.weights = dict(self.DEFAULT_WEIGHTS)
        self.momentum: dict[str, float] = {k: 0.0 for k in self.ADAPTABLE_KEYS}
        self.observations = 0
        self.mae_history: list[float] = []
        self.last_deltas: dict[str, float] = {k: 0.0 for k in self.DEFAULT_WEIGHTS}
        self.dynamic_min_ratio = 1.00

        self.phase_angle = 0.0
        self.entropy_phase = 0.35
        self.repetition_phase = 0.70
        self.phase_velocity = 0.45
        self.order_parameter = 0.50
        self.coherence = 0.50
        self.prev_entropy = 4.0
        self.prev_ratio = 1.0
        self.arrival_times: list[float] = []
        self.size_history: list[int] = []
        self.ratio_history: list[float] = []
        self.codec_yield_scores: dict[str, float] = {
            "lz4-default (level 0)": 1.0,
            "lz4-hc (level 9)": 1.0,
            "zlib (level 6)": 1.0,
        }
        self.cumulative_regret = 0.0
        self.last_regret = 0.0
        self.self_heal_events = 0
        self.load_weights()

    def load_weights(self) -> str:
        if os.path.exists(self.weights_path):
            try:
                with open(self.weights_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                w = data.get("weights", {})
                for k in self.DEFAULT_WEIGHTS:
                    if k in w and isinstance(w[k], (int, float)):
                        self.weights[k] = float(w[k])
                mom = data.get("momentum", {})
                for k in self.ADAPTABLE_KEYS:
                    if k in mom and isinstance(mom[k], (int, float)):
                        self.momentum[k] = float(mom[k])
                self.observations = int(data.get("observations", 0))
                self.mae_history = [float(x) for x in data.get("mae_history", [])[-50:]]
                self.dynamic_min_ratio = float(data.get("dynamic_min_ratio", 1.00))
                self.phase_angle = float(data.get("phase_angle", 0.0))
                self.entropy_phase = float(data.get("entropy_phase", 0.35))
                self.repetition_phase = float(data.get("repetition_phase", 0.70))
                self.phase_velocity = float(data.get("phase_velocity", 0.45))
                self.coherence = float(data.get("coherence", 0.50))
                self.order_parameter = float(data.get("order_parameter", self.coherence))
                self.cumulative_regret = float(data.get("cumulative_regret", 0.0))
                scores = data.get("codec_yield_scores", {})
                if isinstance(scores, dict):
                    for k, v in scores.items():
                        if isinstance(v, (int, float)):
                            self.codec_yield_scores[str(k)] = float(v)
                return (
                    f"Loaded AI + Phase-Lock weights ({self.observations} updates, "
                    f"coh={self.coherence:.2f}, R={self.order_parameter:.2f}, regret={self.cumulative_regret:.2f})."
                )
            except Exception as exc:
                self.self_heal_events += 1
                return f"[Self-Heal] Corrupted weights file ignored ({exc}); using fresh defaults."
        return "Initialized Real-Time AI + Phase-Lock Harmonic Engine."

    def save_weights(self) -> str:
        payload = {
            "weights": self.weights,
            "momentum": self.momentum,
            "observations": self.observations,
            "mae_history": self.mae_history[-50:],
            "dynamic_min_ratio": self.dynamic_min_ratio,
            "phase_angle": self.phase_angle,
            "entropy_phase": self.entropy_phase,
            "repetition_phase": self.repetition_phase,
            "phase_velocity": self.phase_velocity,
            "coherence": self.coherence,
            "order_parameter": self.order_parameter,
            "cumulative_regret": self.cumulative_regret,
            "codec_yield_scores": self.codec_yield_scores,
        }
        try:
            with open(self.weights_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            return f"Saved AI + Phase-Lock weights to {self.weights_path}."
        except Exception as exc:
            self.self_heal_events += 1
            return f"[Self-Heal] Failed to save AI weights ({exc})."

    def reset_weights(self) -> str:
        self.weights = dict(self.DEFAULT_WEIGHTS)
        self.momentum = {k: 0.0 for k in self.ADAPTABLE_KEYS}
        self.observations = 0
        self.mae_history.clear()
        self.last_deltas = {k: 0.0 for k in self.DEFAULT_WEIGHTS}
        self.dynamic_min_ratio = 1.00
        self.phase_angle = 0.0
        self.entropy_phase = 0.35
        self.repetition_phase = 0.70
        self.phase_velocity = 0.45
        self.coherence = 0.50
        self.order_parameter = 0.50
        self.size_history.clear()
        self.ratio_history.clear()
        self.cumulative_regret = 0.0
        self.last_regret = 0.0
        self.codec_yield_scores = {
            "lz4-default (level 0)": 1.0,
            "lz4-hc (level 9)": 1.0,
            "zlib (level 6)": 1.0,
        }
        return "Reset AI + Phase-Lock weights & momentum state to baseline priors."

    @staticmethod
    def analyze_features(data: bytes) -> dict[str, float]:
        n = len(data)
        if n == 0:
            return {
                "entropy": 0.0,
                "repetition": 0.0,
                "log_size": 0.0,
                "bigram_run": 0.0,
                "spectral_balance": 0.0,
            }

        counts = [0] * 256
        nibble_low = [0] * 16
        repeats = 0
        bigram_matches = 0
        prev = data[0]
        prev2 = -1
        counts[prev] += 1
        nibble_low[prev & 0x0F] += 1

        limit = min(n, CHUNK_SIZE)
        for i in range(1, limit):
            b = data[i]
            counts[b] += 1
            nibble_low[b & 0x0F] += 1
            if b == prev:
                repeats += 1
            if prev2 >= 0 and b == prev2:
                bigram_matches += 1
            prev2 = prev
            prev = b

        denom = float(limit)
        entropy = 0.0
        for c in counts:
            if c > 0:
                p = c / denom
                entropy -= p * math.log2(p)

        expected_nib = denom / 16.0
        nib_dev = sum(abs(x - expected_nib) for x in nibble_low) / max(1.0, 2.0 * denom)
        spectral_balance = max(0.0, min(1.0, nib_dev * 1.15))

        repetition = repeats / max(1.0, float(limit - 1))
        bigram_run = bigram_matches / max(1.0, float(max(1, limit - 2)))
        log_size = math.log10(max(1.0, float(n)))

        return {
            "entropy": entropy,
            "repetition": repetition,
            "log_size": log_size,
            "bigram_run": bigram_run,
            "spectral_balance": spectral_balance,
        }

    def kuramoto_order_parameter(self) -> float:
        phases = (self.phase_angle, self.entropy_phase, self.repetition_phase)
        mean_cos = sum(math.cos(p) for p in phases) / len(phases)
        mean_sin = sum(math.sin(p) for p in phases) / len(phases)
        return max(0.0, min(1.0, math.hypot(mean_cos, mean_sin)))

    def harmonic_term(self, features: dict[str, float]) -> float:
        r_sync = self.kuramoto_order_parameter()
        phase_wave = (0.65 * math.cos(self.phase_angle) + 0.35 * math.cos(self.repetition_phase - self.entropy_phase)) * (
            0.5 * self.coherence + 0.5 * r_sync
        )
        bigram_bonus = features.get("bigram_run", 0.0) * 0.65
        spectral_bonus = features.get("spectral_balance", 0.0) * 0.40
        redundancy_lock = (
            (features["repetition"] * 2.0)
            + bigram_bonus
            + spectral_bonus
            - max(0.0, (features["entropy"] - 6.5) * 0.25)
        )
        return self.weights["harmonic_weight"] * (phase_wave + redundancy_lock)

    def forecast_burst(self) -> str:
        now = time.time()
        recent = [t for t in self.arrival_times if now - t <= 15.0]
        if len(recent) < 2:
            return "CALM"
        rate = len(recent) / 15.0
        if rate >= 0.8 or self.coherence >= 0.78 or self.order_parameter >= 0.82:
            return "BURST-LOCK"
        if rate >= 0.35:
            return "ACTIVE"
        return "STEADY"

    def predict_next_trajectory(self, features: dict[str, float]) -> dict[str, float]:
        base_pred = self.predict_ratio(features)
        if len(self.ratio_history) >= 2:
            recent_ratios = self.ratio_history[-5:]
            slope = (recent_ratios[-1] - recent_ratios[0]) / max(1, len(recent_ratios) - 1)
        else:
            slope = 0.0

        phase_lead = math.cos(self.phase_angle + 0.5 * self.phase_velocity)
        lookahead_ratio = max(
            0.85,
            min(64.0, base_pred + self.weights["lookahead_gain"] * slope * phase_lead),
        )

        if len(self.size_history) >= 2:
            s_prev, s_curr = self.size_history[-2], self.size_history[-1]
            growth_factor = max(0.25, min(4.0, (s_curr + 1.0) / max(1.0, float(s_prev))))
            next_size_est = float(s_curr * growth_factor)
        else:
            next_size_est = float(10 ** max(0.0, features.get("log_size", 1.0)))

        if len(self.arrival_times) >= 2:
            deltas = [self.arrival_times[i] - self.arrival_times[i - 1] for i in range(1, len(self.arrival_times))]
            avg_dt = max(0.5, min(60.0, sum(deltas[-6:]) / len(deltas[-6:])))
        else:
            avg_dt = 3.0

        return {
            "next_ratio": lookahead_ratio,
            "ratio_slope": slope,
            "next_size_bytes": next_size_est,
            "eta_sec": avg_dt,
        }

    def predict_ratio(self, features: dict[str, float]) -> float:
        raw_pred = (
            self.weights["intercept"]
            + self.weights["entropy_penalty"] * features["entropy"]
            + self.weights["repetition_bonus"] * features["repetition"]
            + self.weights["log_size_bonus"] * features["log_size"]
            + self.harmonic_term(features)
        )
        return max(0.85, min(64.0, raw_pred))

    def confidence_score(self, features: dict[str, float], pred_ratio: float) -> float:
        sample_factor = min(1.0, self.observations / 15.0)
        recent_mae = (sum(self.mae_history[-10:]) / len(self.mae_history[-10:])) if self.mae_history else 0.6
        error_factor = 1.0 / (1.0 + recent_mae)
        harmonic_factor = 0.4 * self.coherence + 0.3 * self.order_parameter + 0.3
        signal_factor = 0.65 + 0.35 * min(1.0, abs(pred_ratio - 1.0) / 3.0 + features["repetition"])
        return max(
            0.10,
            min(0.99, 0.25 * sample_factor + 0.35 * error_factor + 0.20 * harmonic_factor + 0.20 * signal_factor),
        )

    def counterfactual_evaluate(
        self, raw_bytes: bytes, features: dict[str, float], lz4_module, lz4_available: bool
    ) -> tuple[str, dict[str, tuple[float, int]], str]:
        if not raw_bytes:
            return "lz4-default (level 0)", {}, "Empty payload; default codec selected."

        sample = raw_bytes[: min(len(raw_bytes), 32768)]
        sample_len = len(sample)
        candidates: list[tuple[str, int | None]] = [("zlib (level 6)", None)]
        if lz4_available and lz4_module is not None:
            candidates.insert(0, ("lz4-hc (level 9)", 9))
            candidates.insert(0, ("lz4-default (level 0)", 0))

        scores: dict[str, tuple[float, int]] = {}
        best_codec = candidates[0][0]
        best_utility = -1e9
        best_sample_ratio = 1.0

        for name, level in candidates:
            t0 = time.perf_counter()
            try:
                if level is not None:
                    out = lz4_module.compress(sample, compression_level=level)
                else:
                    out = zlib.compress(sample, level=6)
                dt_ms = max(0.01, (time.perf_counter() - t0) * 1000.0)
                ratio = sample_len / max(1, len(out))
                learned_prior = self.codec_yield_scores.get(name, 1.0)
                latency_penalty = (dt_ms * 0.03) if features["entropy"] > 7.2 else (dt_ms * 0.008)
                utility = (ratio * 0.75) + (learned_prior * 0.35) - latency_penalty
                scores[name] = (ratio, len(out))
                if ratio > best_sample_ratio:
                    best_sample_ratio = ratio
                if utility > best_utility:
                    best_utility = utility
                    best_codec = name
            except Exception:
                self.self_heal_events += 1
                continue

        chosen_ratio = scores.get(best_codec, (1.0, sample_len))[0]
        self.last_regret = max(0.0, best_sample_ratio - chosen_ratio)
        self.cumulative_regret += self.last_regret

        summary = ", ".join(f"{k}:{v[0]:.2f}x" for k, v in scores.items())
        return (
            best_codec,
            scores,
            f"Counterfactual probe [{summary}] -> '{best_codec}' (regret={self.last_regret:.2f}x).",
        )

    def recommend_mode(self, features: dict[str, float], lz4_available: bool) -> tuple[str, str]:
        pred = self.predict_ratio(features)
        traj = self.predict_next_trajectory(features)
        if not lz4_available:
            return "zlib (level 6)", "LZ4 unavailable; using zlib fallback."
        if features["entropy"] >= 7.65 and features["repetition"] < 0.03:
            return "lz4-fast (level 0)", "High-entropy stream; fast low-overhead LZ4 pass."
        if (
            pred >= 2.2
            or traj["next_ratio"] >= 2.35
            or features["repetition"] >= 0.18
            or self.coherence >= 0.75
        ):
            return "lz4-hc (level 9)", "High redundancy / predictive or phase lock; deep LZ4 matching."
        return "lz4-default (level 0)", "Balanced payload; standard inline LZ4 frame."

    def think_and_adapt(
        self,
        features: dict[str, float],
        predicted_ratio: float,
        actual_ratio: float,
        used_codec: str | None = None,
    ) -> str:
        now = time.time()
        self.arrival_times.append(now)
        self.arrival_times = self.arrival_times[-30:]

        raw_est = int(10 ** max(0.0, features.get("log_size", 0.0)))
        self.size_history.append(raw_est)
        self.size_history = self.size_history[-30:]
        self.ratio_history.append(actual_ratio)
        self.ratio_history = self.ratio_history[-30:]

        delta_ent = abs(features["entropy"] - self.prev_entropy)
        self.prev_entropy = features["entropy"]
        k_coup = self.weights["coupling_strength"]

        d_ent_phase = 0.30 + min(0.8, delta_ent * 0.15) + k_coup * math.sin(self.phase_angle - self.entropy_phase)
        d_rep_phase = 0.40 + min(1.1, features["repetition"] * 2.8) + k_coup * math.sin(self.phase_angle - self.repetition_phase)
        raw_step = (
            0.45
            + min(1.2, features["repetition"] * 3.0)
            - min(0.5, delta_ent * 0.12)
            + 0.5 * k_coup * (math.sin(self.entropy_phase - self.phase_angle) + math.sin(self.repetition_phase - self.phase_angle))
        )
        self.phase_velocity = 0.7 * self.phase_velocity + 0.3 * raw_step

        self.entropy_phase = (self.entropy_phase + d_ent_phase) % (2.0 * math.pi)
        self.repetition_phase = (self.repetition_phase + d_rep_phase) % (2.0 * math.pi)
        self.phase_angle = (self.phase_angle + self.phase_velocity) % (2.0 * math.pi)
        self.order_parameter = self.kuramoto_order_parameter()

        clamped_actual = max(0.85, min(64.0, actual_ratio))
        error = clamped_actual - predicted_ratio
        abs_err = abs(error)
        self.mae_history.append(abs_err)
        self.observations += 1

        accuracy_signal = 1.0 / (1.0 + abs_err)
        sync_signal = 0.7 * accuracy_signal + 0.3 * self.order_parameter
        self.coherence = max(0.10, min(0.99, 0.76 * self.coherence + 0.24 * sync_signal))

        if used_codec:
            clean_codec = used_codec.replace(" [healed]", "")
            prev_score = self.codec_yield_scores.get(clean_codec, 1.0)
            self.codec_yield_scores[clean_codec] = max(0.25, min(8.0, 0.8 * prev_score + 0.2 * clamped_actual))

        regret_boost = min(0.5, self.last_regret * 0.25)
        error_boost = 1.0 + min(1.5, abs_err * self.weights["gain_sensitivity"]) + regret_boost
        eff_lr = (self.weights["base_lr"] * error_boost) / (1.0 + 0.015 * self.observations)

        grads = {
            "intercept": max(-0.6, min(0.6, eff_lr * error)),
            "entropy_penalty": max(-0.25, min(0.25, eff_lr * error * (features["entropy"] / 8.0))),
            "repetition_bonus": max(-0.4, min(0.4, eff_lr * error * min(1.5, features["repetition"] * 2.5))),
            "log_size_bonus": max(-0.15, min(0.15, eff_lr * error * min(1.0, features["log_size"] / 6.0))),
            "harmonic_weight": max(-0.2, min(0.2, eff_lr * error * math.cos(self.phase_angle))),
            "coupling_strength": max(-0.1, min(0.1, eff_lr * (self.order_parameter - 0.5) * 0.4)),
        }

        beta = 0.65
        for k, g in grads.items():
            self.momentum[k] = beta * self.momentum[k] + (1.0 - beta) * g

        self.weights["intercept"] = max(0.5, min(8.0, self.weights["intercept"] + self.momentum["intercept"]))
        self.weights["entropy_penalty"] = max(-1.8, min(0.2, self.weights["entropy_penalty"] + self.momentum["entropy_penalty"]))
        self.weights["repetition_bonus"] = max(0.0, min(6.0, self.weights["repetition_bonus"] + self.momentum["repetition_bonus"]))
        self.weights["log_size_bonus"] = max(-0.5, min(1.5, self.weights["log_size_bonus"] + self.momentum["log_size_bonus"]))
        self.weights["harmonic_weight"] = max(0.05, min(1.5, self.weights["harmonic_weight"] + self.momentum["harmonic_weight"]))
        self.weights["coupling_strength"] = max(0.05, min(0.9, self.weights["coupling_strength"] + self.momentum["coupling_strength"]))

        self.last_deltas = dict(self.momentum)

        if actual_ratio >= 1.25:
            self.dynamic_min_ratio = max(0.95, self.dynamic_min_ratio - 0.01)
        elif actual_ratio < 1.0:
            self.dynamic_min_ratio = min(1.15, self.dynamic_min_ratio + 0.02)

        self.prev_ratio = actual_ratio

        return (
            f"err={error:+.2f}x, coh={self.coherence:.2f}, R={self.order_parameter:.2f}, "
            f"φ={self.phase_angle:.2f}rad (v={self.phase_velocity:+.2f}), "
            f"Δw=[int:{self.momentum['intercept']:+.3f}, ent:{self.momentum['entropy_penalty']:+.3f}, "
            f"rep:{self.momentum['repetition_bonus']:+.3f}, harm:{self.momentum['harmonic_weight']:+.3f}], "
            f"min_ratio->{self.dynamic_min_ratio:.2f}x"
        )


# =====================================================================
# 6B. Structured Chain-of-Thought Trace Builder
# =====================================================================
class ReasoningTraceBuilder:
    """Formats transparent multi-step Chain-of-Thought traces for inspection and export."""

    @staticmethod
    def build_ingest_trace(
        mode_tag: str,
        name: str,
        slot_id: str,
        zone: str,
        slot_offset: int,
        harmonic_align: bool,
        feats: dict[str, float],
        pred_ratio: float,
        actual_ratio: float,
        conf: float,
        burst: str,
        traj: dict[str, float],
        adapt_summary: str,
        codec_trace: list[str],
    ) -> list[str]:
        lines = [
            f"[CoT 1 - Perceive '{name}'] entropy={feats['entropy']:.2f} b/B, "
            f"rep={feats['repetition']*100:.1f}%, bigram={feats.get('bigram_run', 0.0)*100:.1f}%, "
            f"nibble_skew={feats.get('spectral_balance', 0.0):.2f}, log10(size)={feats['log_size']:.2f}",
            f"[CoT 2 - Predict] pred={pred_ratio:.2f}x (conf={conf*100:.0f}%), "
            f"next_ratio~{traj['next_ratio']:.2f}x (slope={traj['ratio_slope']:+.2f}), "
            f"cadence={burst} (eta~{traj['eta_sec']:.1f}s)",
        ]
        for step in codec_trace:
            lines.append(f"[CoT 3 - Counterfactual/Codec] {step}")
        lines.append(
            f"[CoT 4 - Synthesize & Adapt -> {mode_tag} {slot_id} ({zone} @ {slot_offset:,}B, "
            f"align={'256B' if harmonic_align else '64B'})] actual={actual_ratio:.2f}x | {adapt_summary}"
        )
        return lines


# =====================================================================
# 7. 24/7 Autonomous + Predictive + Self-Healing Background Worker
# =====================================================================
class AutonomousBackplaneWorker:
    """
    Runs continuously in the background on a daemon thread with predictive
    cadence lookahead, stale-signature self-healing, and manual scan support.
    """

    def __init__(self, app: "MemoryZipGUI"):
        self.app = app
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen_signatures: dict[str, tuple[int, float]] = {}
        self.cycles = 0
        self.healed_count = 0

    @property
    def is_running(self) -> bool:
        return self._thread is not None and self._thread.is_alive()

    def start(self):
        if self.is_running:
            return
        self._stop_event.clear()
        self._wake_event.clear()
        self._thread = threading.Thread(target=self._run_loop, name="AutonomousBackplane", daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_event.set()
        self._wake_event.set()

    def trigger_manual_scan(self):
        self.cycles += 1
        try:
            self._tick(source_tag="MANUAL-SCAN")
        except Exception as exc:
            self.healed_count += 1
            self.app.post_log(f"[Manual Scan][Self-Heal] Recovered from error: {exc}")

    def _prune_deleted_signatures(self):
        if len(self._seen_signatures) < 100:
            return
        stale = [p for p in list(self._seen_signatures.keys())[:150] if not os.path.exists(p)]
        for p in stale:
            self._seen_signatures.pop(p, None)
        if stale:
            self.healed_count += len(stale)
            self.app.post_log(f"[Auto-Heal Daemon] Pruned {len(stale)} deleted/moved file signatures.")

    def _run_loop(self):
        self.app.post_log("[Autonomous AI] 24/7 predictive & self-healing background loop active.")
        while not self._stop_event.is_set():
            self.cycles += 1
            try:
                self._tick(source_tag="AUTO-AI")
                if self.app.is_auto_heal_daemon_enabled():
                    self._prune_deleted_signatures()
            except Exception as exc:
                self.healed_count += 1
                self.app.post_log(f"[Autonomous AI][Self-Heal] Cycle #{self.cycles} recovered: {exc}")

            interval = self.app.get_poll_interval()
            if self.app.is_predictive_lookahead_enabled():
                burst = self.app.ai_engine.forecast_burst()
                if burst == "BURST-LOCK":
                    interval = max(0.5, interval * 0.65)
                elif burst == "CALM" and self.cycles > 2:
                    interval = min(3600.0, interval * 1.15)
            self._wake_event.wait(timeout=interval)
            self._wake_event.clear()
        self.app.post_log("[Autonomous AI] Background loop paused.")

    def _iter_candidate_files(self, roots: list[str], max_files_per_cycle: int = 25):
        found = 0
        skip_dirs = {
            ".git", "__pycache__", "node_modules", "$Recycle.Bin",
            "System Volume Information", "Windows", "Library", "proc", "sys", "dev"
        }
        skip_exts = self.app.get_skip_extensions()
        for root_path in roots:
            if not root_path or not os.path.isdir(root_path):
                continue
            for current_dir, dirnames, filenames in os.walk(root_path):
                if self._stop_event.is_set():
                    return
                dirnames[:] = [d for d in dirnames if d not in skip_dirs]
                for fname in sorted(filenames):
                    if self._stop_event.is_set():
                        return
                    if skip_exts and os.path.splitext(fname)[1].lower() in skip_exts:
                        continue
                    fpath = os.path.join(current_dir, fname)
                    yield fpath
                    found += 1
                    if found >= max_files_per_cycle:
                        return

    def _tick(self, source_tag: str = "AUTO-AI"):
        roots = self.app.get_scan_roots()
        if not roots:
            return

        max_file_bytes = self.app.get_max_file_bytes()
        ingested_any = False
        for fpath in self._iter_candidate_files(roots):
            if self._stop_event.is_set():
                break

            try:
                st = os.stat(fpath)
            except OSError:
                continue

            sig = (st.st_size, st.st_mtime)
            if source_tag == "AUTO-AI" and self._seen_signatures.get(fpath) == sig:
                continue

            if st.st_size == 0 or st.st_size > max_file_bytes:
                self._seen_signatures[fpath] = sig
                continue

            try:
                data = read_file_chunked(fpath, max_file_bytes)
            except Exception:
                self.healed_count += 1
                continue

            self._seen_signatures[fpath] = sig
            ingested_any = True
            label = f"{'auto' if source_tag == 'AUTO-AI' else 'scan'}:{os.path.basename(fpath)}"
            self.app.post_ui_ingest(label, data, autonomous=(source_tag == "AUTO-AI"))

        if ingested_any and source_tag == "AUTO-AI":
            self.app.post_auto_rebalance_if_enabled()


# =====================================================================
# 8. Main GUI Application (Tabbed Compact Layout + Phase-Lock AI)
# =====================================================================
class MemoryZipGUI:
    HOT_TIER_MAX_ITEMS = 5

    def __init__(self, root: tk.Tk, initial_watch_dir: str | None = None):
        self.root = root
        self.root.title("On-the-Fly Memory Zip Store — Phase-Lock AI, CoT Reasoning & Self-Heal")
        self.root.geometry("1120x820")

        self.state_lock = threading.Lock()

        self.autoloader = LibraryAutoloader()
        self.lz4_ready = self.autoloader.bootstrap()
        self.backbone = SystemBackbone(self.autoloader)
        self.planner = MemoryPlacementPlanner()
        self.ai_engine = HarmonicPhaseEngine()
        self.session = SessionMemoryStore()
        self.session_msg = self.session.load()

        self.store: OrderedDict[str, CompressedEntry] = OrderedDict()
        self.counter = 1
        self.initial_watch_dir = initial_watch_dir
        self.az_vars: dict[str, tk.BooleanVar] = {}
        self.az_checks: dict[str, ttk.Checkbutton] = {}

        self.worker = AutonomousBackplaneWorker(self)

        self._build_ui()
        self._apply_saved_session()
        self._refresh_drives()
        self._seed_startup_reasoning()
        self._refresh_stats()
        self._update_live_prediction()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        # Always start autonomous mode immediately on program startup
        self.worker.start()
        self._sync_auto_status_ui()
        self._save_session_now()

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.front_tab = ttk.Frame(self.notebook, padding=8)
        self.drives_tab = ttk.Frame(self.notebook, padding=8)
        self.ai_tab = ttk.Frame(self.notebook, padding=8)

        self.notebook.add(self.front_tab, text="Memory & Actions")
        self.notebook.add(self.drives_tab, text="Drives & Scan Filters")
        self.notebook.add(self.ai_tab, text="AI, CoT & Self-Heal")

        self._build_front_tab(self.front_tab)
        self._build_drives_tab(self.drives_tab)
        self._build_ai_tab(self.ai_tab)

    def _build_front_tab(self, parent: ttk.Frame):
        # Compact top bar: 24/7 status + scope + target path
        top_frame = ttk.LabelFrame(parent, text="Autonomous & Target Scope", padding=8)
        top_frame.pack(fill=tk.X, pady=(0, 8))

        r1 = ttk.Frame(top_frame)
        r1.pack(fill=tk.X)

        self.auto_status_lbl = ttk.Label(r1, text="Status: STARTING...")
        self.auto_status_lbl.pack(side=tk.LEFT, padx=(0, 8))

        self.toggle_auto_btn = ttk.Button(r1, text="Pause Autonomous", command=self._toggle_autonomous)
        self.toggle_auto_btn.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(r1, text="Manual Scan Now", command=self._manual_scan_now).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(r1, text="Scope:").pack(side=tk.LEFT, padx=(0, 4))
        self.drive_scope_var = tk.StringVar(value="Selected Folder")
        scope_combo = ttk.Combobox(
            r1,
            textvariable=self.drive_scope_var,
            values=["Selected Folder", "Selected Drive", "Custom Drive Combo (A-Z)", "All Detected Drives"],
            state="readonly",
            width=22,
        )
        scope_combo.pack(side=tk.LEFT, padx=(0, 8))
        scope_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_pref_changed())

        ttk.Label(r1, text="Drive:").pack(side=tk.LEFT, padx=(0, 4))
        self.drive_var = tk.StringVar(value="")
        self.drive_combo = ttk.Combobox(r1, textvariable=self.drive_var, values=[], state="readonly", width=10)
        self.drive_combo.pack(side=tk.LEFT)
        self.drive_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_drive_selected())

        r2 = ttk.Frame(top_frame)
        r2.pack(fill=tk.X, pady=(6, 0))

        ttk.Label(r2, text="Target Path:").pack(side=tk.LEFT, padx=(0, 6))
        self.watch_dir_var = tk.StringVar(value="")
        watch_entry = ttk.Entry(r2, textvariable=self.watch_dir_var, width=44)
        watch_entry.pack(side=tk.LEFT, padx=(0, 6))
        watch_entry.bind("<FocusOut>", lambda _e: self._on_target_path_changed())

        ttk.Button(r2, text="Browse...", command=self._browse_watch_dir).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(r2, text="Item Name:").pack(side=tk.LEFT, padx=(0, 4))
        self.name_var = tk.StringVar(value="entry_1")
        ttk.Entry(r2, textvariable=self.name_var, width=16).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(r2, text="Load File...", command=self._load_file).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(r2, text="Zip Into Memory", command=self._zip_into_memory_manual).pack(side=tk.LEFT)

        # Compact manual input + unzipped output side-by-side
        io_pane = ttk.PanedWindow(parent, orient=tk.HORIZONTAL)
        io_pane.pack(fill=tk.BOTH, expand=False, pady=(0, 8))

        in_frame = ttk.Frame(io_pane, padding=(0, 0, 5, 0))
        ttk.Label(in_frame, text="Manual Data Input:").pack(anchor=tk.W)
        self.input_box = scrolledtext.ScrolledText(in_frame, height=4, wrap=tk.WORD, font=("Consolas", 10))
        self.input_box.pack(fill=tk.BOTH, expand=True, pady=(3, 0))
        self.input_box.bind("<KeyRelease>", lambda _e: self._update_live_prediction())
        io_pane.add(in_frame, weight=1)

        out_frame = ttk.Frame(io_pane, padding=(5, 0, 0, 0))
        ttk.Label(out_frame, text="Accessed / Unzipped Output:").pack(anchor=tk.W)
        self.output_box = scrolledtext.ScrolledText(out_frame, height=4, wrap=tk.WORD, font=("Consolas", 10))
        self.output_box.pack(fill=tk.BOTH, expand=True, pady=(3, 0))
        io_pane.add(out_frame, weight=1)

        # Memory slots table
        ttk.Label(parent, text="Assigned Memory Slots & Zones:").pack(anchor=tk.W)
        columns = ("slot", "zone", "offset", "name", "tier", "relevance", "raw_bytes", "active_bytes", "saved")
        self.tree = ttk.Treeview(parent, columns=columns, show="headings", height=9)
        self.tree.heading("slot", text="Slot")
        self.tree.heading("zone", text="Placement Zone")
        self.tree.heading("offset", text="Offset")
        self.tree.heading("name", text="Name")
        self.tree.heading("tier", text="Tier")
        self.tree.heading("relevance", text="Relevance")
        self.tree.heading("raw_bytes", text="Original")
        self.tree.heading("active_bytes", text="Active RAM")
        self.tree.heading("saved", text="Space Saved")

        self.tree.column("slot", width=95)
        self.tree.column("zone", width=115)
        self.tree.column("offset", width=85, anchor=tk.E)
        self.tree.column("name", width=165)
        self.tree.column("tier", width=60, anchor=tk.CENTER)
        self.tree.column("relevance", width=95, anchor=tk.E)
        self.tree.column("raw_bytes", width=100, anchor=tk.E)
        self.tree.column("active_bytes", width=105, anchor=tk.E)
        self.tree.column("saved", width=135, anchor=tk.E)
        self.tree.pack(fill=tk.BOTH, expand=True, pady=(4, 8))

        # Core memory action bar
        action_bar = ttk.Frame(parent)
        action_bar.pack(fill=tk.X, pady=(0, 8))

        ttk.Button(action_bar, text="Access / Unzip", command=self._unzip_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(action_bar, text="Delete Selected", command=self._delete_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(action_bar, text="Clear All Memory", command=self._clear_all).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(action_bar, text="Tier & Optimize RAM", command=self._tier_and_optimize_memory).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(action_bar, text="Integrity Scrub & Heal", command=self._scrub_and_heal_entries).pack(
            side=tk.LEFT
        )

        # Memory totals bar
        totals_frame = ttk.LabelFrame(parent, text="Memory Totals & Zone Layout", padding=8)
        totals_frame.pack(fill=tk.X)
        self.totals_lbl = ttk.Label(
            totals_frame,
            text="Items: 0 (HOT: 0 / COLD: 0)  |  Original: 0 B  |  Active RAM: 0 B  |  Ratio: 1.00x  |  Saved: 0 B (0.0%)",
        )
        self.totals_lbl.pack(anchor=tk.W)

    def _build_drives_tab(self, parent: ttk.Frame):
        az_frame = ttk.LabelFrame(parent, text="A-Z Drive Multi-Select Combination", padding=10)
        az_frame.pack(fill=tk.X, pady=(0, 10))

        az_top = ttk.Frame(az_frame)
        az_top.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(az_top, text="Toggle any combination of drives from A to Z:").pack(side=tk.LEFT)
        ttk.Button(az_top, text="Refresh Drives", command=self._refresh_drives).pack(side=tk.RIGHT)
        ttk.Button(az_top, text="Clear A-Z", command=self._clear_az_drives, width=9).pack(side=tk.RIGHT, padx=(0, 6))
        ttk.Button(az_top, text="All A-Z", command=self._select_all_az_drives, width=8).pack(
            side=tk.RIGHT, padx=(0, 6)
        )

        self.az_grid_frame = ttk.Frame(az_frame)
        self.az_grid_frame.pack(fill=tk.X)

        scan_frame = ttk.LabelFrame(parent, text="Scan Cadence, Size Limits & File Filters", padding=10)
        scan_frame.pack(fill=tk.X, pady=(0, 10))

        sr1 = ttk.Frame(scan_frame)
        sr1.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(sr1, text="Interval (s):").pack(side=tk.LEFT, padx=(0, 4))
        self.interval_var = tk.StringVar(value="3.0")
        interval_entry = ttk.Entry(sr1, textvariable=self.interval_var, width=8)
        interval_entry.pack(side=tk.LEFT, padx=(0, 16))
        interval_entry.bind("<FocusOut>", lambda _e: self._save_session_now())

        ttk.Label(sr1, text="Max File Size (MB):").pack(side=tk.LEFT, padx=(0, 4))
        self.max_file_mb_var = tk.StringVar(value="16")
        max_mb_entry = ttk.Entry(sr1, textvariable=self.max_file_mb_var, width=8)
        max_mb_entry.pack(side=tk.LEFT, padx=(0, 16))
        max_mb_entry.bind("<FocusOut>", lambda _e: self._save_session_now())

        ttk.Button(sr1, text="Create Backbone Launcher", command=self._create_launcher).pack(side=tk.LEFT)

        sr2 = ttk.Frame(scan_frame)
        sr2.pack(fill=tk.X)
        ttk.Label(sr2, text="Skip Extensions (comma-separated):").pack(side=tk.LEFT, padx=(0, 6))
        self.skip_exts_var = tk.StringVar(value=".iso,.bin,.img,.zip,.gz,.7z,.mp4,.mkv,.avi")
        skip_exts_entry = ttk.Entry(sr2, textvariable=self.skip_exts_var, width=48)
        skip_exts_entry.pack(side=tk.LEFT)
        skip_exts_entry.bind("<FocusOut>", lambda _e: self._save_session_now())

        tele_frame = ttk.LabelFrame(parent, text="System RAM & Drive Backbone Telemetry", padding=10)
        tele_frame.pack(fill=tk.X)
        self.backbone_lbl = ttk.Label(
            tele_frame,
            text="App RSS: -  |  System RAM: -  |  Free on target: -  |  Drives: -",
            wraplength=1020,
            justify=tk.LEFT,
        )
        self.backbone_lbl.pack(anchor=tk.W)

    def _build_ai_tab(self, parent: ttk.Frame):
        pred_frame = ttk.LabelFrame(
            parent, text="Phase-Lock Harmonic Engine, Real-Time AI Weights & Trajectory Forecast", padding=10
        )
        pred_frame.pack(fill=tk.X, pady=(0, 8))

        self.pred_lbl = ttk.Label(
            pred_frame,
            text="Entropy: 0.00 b/B  |  Repetition: 0.0%  |  Predicted: 1.00x  |  Next~1.00x  |  Conf: 0%  |  Burst: CALM  |  Policy: -",
        )
        self.pred_lbl.pack(anchor=tk.W)

        self.weights_lbl = ttk.Label(
            pred_frame,
            text="Weights -> int: 0.00, ent: 0.00, rep: 0.00, harm: 0.00 | Coh: 0.50 | Sync R: 0.50 | Regret: 0.00x | MinRatio: 1.00x | Updates: 0 | MAE: -",
        )
        self.weights_lbl.pack(anchor=tk.W, pady=(4, 0))

        ctrl_frame = ttk.LabelFrame(parent, text="Strategy, Display & Autonomous AI Switches", padding=10)
        ctrl_frame.pack(fill=tk.X, pady=(0, 8))

        cr1 = ttk.Frame(ctrl_frame)
        cr1.pack(fill=tk.X, pady=(0, 6))

        ttk.Label(cr1, text="Strategy:").pack(side=tk.LEFT, padx=(0, 6))
        self.strategy_var = tk.StringVar(value="Auto (AI + Harmonic)")
        strategies = [
            "Auto (AI + Harmonic)",
            "lz4-default (level 0)",
            "lz4-hc (level 9)",
            "zlib (level 6)",
        ]
        strategy_combo = ttk.Combobox(
            cr1, textvariable=self.strategy_var, values=strategies, state="readonly", width=22
        )
        strategy_combo.pack(side=tk.LEFT, padx=(0, 12))
        strategy_combo.bind("<<ComboboxSelected>>", lambda _e: self._save_session_now())

        self.lean_mode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr1, text="Lean Mode", variable=self.lean_mode_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.show_hex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            cr1, text="Hex View", variable=self.show_hex_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 14))

        ttk.Button(cr1, text="Save Weights", command=self._save_weights_ui).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(cr1, text="Reset Weights", command=self._reset_weights_ui).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(cr1, text="Export CoT Trace", command=self._export_cot_trace).pack(side=tk.LEFT)

        cr2 = ttk.Frame(ctrl_frame)
        cr2.pack(fill=tk.X)

        self.skip_expansion_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr2, text="AI Expansion Guard", variable=self.skip_expansion_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.auto_rebalance_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr2, text="Auto Tier/Heal", variable=self.auto_rebalance_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.predictive_lookahead_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr2, text="Predictive Cadence", variable=self.predictive_lookahead_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.counterfactual_probe_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr2, text="Counterfactual Probe", variable=self.counterfactual_probe_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.auto_heal_daemon_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr2, text="Auto-Heal Daemon", variable=self.auto_heal_daemon_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.auto_save_weights_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr2, text="Auto-Save AI", variable=self.auto_save_weights_var, command=self._save_session_now
        ).pack(side=tk.LEFT)

        ttk.Label(parent, text="Chain-of-Thought Reasoning, Phase-Lock AI & Self-Heal Log:").pack(anchor=tk.W)
        self.reason_box = scrolledtext.ScrolledText(parent, height=14, wrap=tk.WORD, font=("Consolas", 9))
        self.reason_box.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

    # --- A-Z Multi-Drive Helpers ---
    def _rebuild_az_checkboxes(self, detected_drives: list[str], saved_selected: list[str]):
        for child in self.az_grid_frame.winfo_children():
            child.destroy()
        self.az_vars.clear()
        self.az_checks.clear()

        detected_norms = {os.path.abspath(d).upper() for d in detected_drives}
        saved_norms = {os.path.abspath(d).upper() for d in saved_selected if d}
        catalog = self.backbone.get_az_catalog()

        for idx, drv in enumerate(catalog):
            norm = os.path.abspath(drv).upper()
            is_present = norm in detected_norms
            default_on = norm in saved_norms if saved_norms else (is_present and os.name == "nt")
            var = tk.BooleanVar(value=default_on)
            self.az_vars[drv] = var

            short_lbl = drv[0] if (len(drv) >= 2 and drv[1] == ":") else drv
            chk = ttk.Checkbutton(
                self.az_grid_frame,
                text=short_lbl,
                variable=var,
                command=self._on_az_toggled,
            )
            if not is_present:
                chk.state(["disabled"])
            row_idx = idx // 13
            col_idx = idx % 13
            chk.grid(row=row_idx, column=col_idx, padx=(0, 6), pady=2, sticky=tk.W)
            self.az_checks[drv] = chk

    def get_selected_az_drives(self) -> list[str]:
        return [drv for drv, var in self.az_vars.items() if var.get() and os.path.isdir(drv)]

    def _on_az_toggled(self):
        chosen = self.get_selected_az_drives()
        if chosen and self.drive_scope_var.get() not in ("Custom Drive Combo (A-Z)", "All Detected Drives"):
            self.drive_scope_var.set("Custom Drive Combo (A-Z)")
        self._refresh_backbone_telemetry()
        self._save_session_now()
        self._log_reasoning(
            f"[A-Z Drives] Active custom combination ({len(chosen)}): {', '.join(chosen) if chosen else '(none)'}."
        )

    def _select_all_az_drives(self):
        for drv, var in self.az_vars.items():
            if os.path.isdir(drv):
                var.set(True)
        self.drive_scope_var.set("Custom Drive Combo (A-Z)")
        self._refresh_backbone_telemetry()
        self._save_session_now()
        self._log_reasoning(f"[A-Z Drives] Selected all available A-Z drives: {', '.join(self.get_selected_az_drives())}.")

    def _clear_az_drives(self):
        for var in self.az_vars.values():
            var.set(False)
        self._refresh_backbone_telemetry()
        self._save_session_now()
        self._log_reasoning("[A-Z Drives] Cleared A-Z drive selection.")

    # --- Helper Accessors for Worker ---
    def is_predictive_lookahead_enabled(self) -> bool:
        return bool(self.predictive_lookahead_var.get())

    def is_auto_heal_daemon_enabled(self) -> bool:
        return bool(self.auto_heal_daemon_var.get())

    def get_max_file_bytes(self) -> int:
        try:
            mb = float(self.max_file_mb_var.get().strip())
            return int(max(0.1, min(512.0, mb)) * 1024 * 1024)
        except Exception:
            return 16 * 1024 * 1024

    def get_skip_extensions(self) -> set[str]:
        raw = self.skip_exts_var.get().strip()
        if not raw:
            return set()
        exts = set()
        for token in raw.split(","):
            cleaned = token.strip().lower()
            if not cleaned:
                continue
            if not cleaned.startswith("."):
                cleaned = "." + cleaned
            exts.add(cleaned)
        return exts

    # --- Manual Scan, Integrity Scrub & Auto Rebalance ---
    def _manual_scan_now(self):
        self._log_reasoning("[CoT Manual Scan] Triggering immediate scan pass across configured roots...")
        threading.Thread(target=self.worker.trigger_manual_scan, name="ManualScanThread", daemon=True).start()

    def _scrub_and_heal_entries(self):
        repaired = 0
        checked = 0
        with self.state_lock:
            for name, entry in list(self.store.items()):
                checked += 1
                try:
                    raw, trace = self._decompress_with_heal(entry.zipped, entry.codec, entry.crc32)
                    actual_crc = zlib.crc32(raw) & 0xFFFFFFFF
                    if actual_crc != entry.crc32 or trace:
                        entry.crc32 = actual_crc
                        repaired += 1
                        self.ai_engine.self_heal_events += 1
                        for step in trace:
                            self._log_reasoning(f"[Integrity Scrub '{name}'] {step}")
                    if entry.tier == "HOT":
                        entry.hot_bytes = raw
                except Exception as exc:
                    repaired += 1
                    self.ai_engine.self_heal_events += 1
                    self.store.pop(name, None)
                    self._log_reasoning(f"[Integrity Scrub][Self-Heal] Evicted unrecoverable entry '{name}': {exc}")

        self._refresh_table()
        self._refresh_stats()
        self._log_reasoning(
            f"[Integrity Scrub] Verified {checked} entries, healed/evicted {repaired} anomalies."
        )

    def post_auto_rebalance_if_enabled(self):
        self.root.after(0, self._auto_rebalance_tick)

    def _auto_rebalance_tick(self):
        if self.auto_rebalance_var.get() and len(self.store) > self.HOT_TIER_MAX_ITEMS:
            with self.state_lock:
                promoted, demoted = self._rebalance_tiers_locked()
            if promoted or demoted:
                self._refresh_table()
                self._refresh_stats()
                self._log_reasoning(
                    f"[Auto Tier/Heal] Balanced tiers (promoted={promoted}, demoted={demoted}) to keep RAM lean."
                )

    # --- Session Persistence ---
    def _apply_saved_session(self):
        d = self.session.data
        self.drive_scope_var.set(d.get("drive_scope", "Selected Folder"))
        self.interval_var.set(str(d.get("interval", "3.0")))
        self.max_file_mb_var.set(str(d.get("max_file_mb", "16")))
        self.skip_exts_var.set(str(d.get("skip_exts", ".iso,.bin,.img,.zip,.gz,.7z,.mp4,.mkv,.avi")))
        strat = d.get("strategy", "Auto (AI + Harmonic)")
        if strat in ("Auto (Predictive + Learned)", "Auto (AI Autonomous)"):
            strat = "Auto (AI + Harmonic)"
        self.strategy_var.set(strat)
        self.skip_expansion_var.set(bool(d.get("skip_expansion", True)))
        self.auto_rebalance_var.set(bool(d.get("auto_rebalance", True)))
        self.lean_mode_var.set(bool(d.get("lean_mode", True)))
        self.show_hex_var.set(bool(d.get("show_hex", False)))
        self.predictive_lookahead_var.set(bool(d.get("predictive_lookahead", True)))
        self.counterfactual_probe_var.set(bool(d.get("counterfactual_probe", True)))
        self.auto_heal_daemon_var.set(bool(d.get("auto_heal_daemon", True)))
        self.auto_save_weights_var.set(bool(d.get("auto_save_weights", True)))
        self.session.data["auto_running"] = True

        if self.initial_watch_dir is not None:
            self.watch_dir_var.set(self.initial_watch_dir)
        else:
            self.watch_dir_var.set(d.get("target_path", ""))

    def _collect_session_updates(self) -> dict:
        return {
            "last_drive": self.drive_var.get().strip(),
            "selected_drives": self.get_selected_az_drives(),
            "drive_scope": self.drive_scope_var.get(),
            "target_path": self.watch_dir_var.get().strip(),
            "interval": self.interval_var.get().strip() or "3.0",
            "max_file_mb": self.max_file_mb_var.get().strip() or "16",
            "skip_exts": self.skip_exts_var.get().strip(),
            "strategy": self.strategy_var.get(),
            "skip_expansion": bool(self.skip_expansion_var.get()),
            "auto_rebalance": bool(self.auto_rebalance_var.get()),
            "lean_mode": bool(self.lean_mode_var.get()),
            "show_hex": bool(self.show_hex_var.get()),
            "auto_running": bool(self.worker.is_running),
            "predictive_lookahead": bool(self.predictive_lookahead_var.get()),
            "counterfactual_probe": bool(self.counterfactual_probe_var.get()),
            "auto_heal_daemon": bool(self.auto_heal_daemon_var.get()),
            "auto_save_weights": bool(self.auto_save_weights_var.get()),
        }

    def _save_session_now(self):
        self.session.save(self._collect_session_updates())

    def _on_pref_changed(self):
        self._refresh_backbone_telemetry()
        self._save_session_now()

    def _on_target_path_changed(self):
        self._refresh_backbone_telemetry()
        self._save_session_now()

    def _on_close(self):
        self._save_session_now()
        self.ai_engine.save_weights()
        self.worker.stop()
        self.root.destroy()

    # --- Hot/Cold Tiering & Memory Optimization ---
    def _rebalance_tiers_locked(self) -> tuple[int, int]:
        now = time.time()
        ranked = sorted(
            self.store.values(),
            key=lambda e: e.relevance_score(now),
            reverse=True,
        )
        hot_names = {e.name for e in ranked[: self.HOT_TIER_MAX_ITEMS]}
        promoted = 0
        demoted = 0

        for entry in self.store.values():
            if entry.name in hot_names:
                if entry.tier != "HOT":
                    try:
                        raw_data, _ = self._decompress_with_heal(entry.zipped, entry.codec, entry.crc32)
                        entry.hot_bytes = raw_data
                        entry.tier = "HOT"
                        promoted += 1
                    except Exception:
                        self.ai_engine.self_heal_events += 1
                elif entry.hot_bytes is None:
                    try:
                        raw_data, _ = self._decompress_with_heal(entry.zipped, entry.codec, entry.crc32)
                        entry.hot_bytes = raw_data
                    except Exception:
                        self.ai_engine.self_heal_events += 1
            else:
                if entry.tier != "COLD" or entry.hot_bytes is not None:
                    entry.hot_bytes = None
                    entry.tier = "COLD"
                    demoted += 1
                if self.lean_mode_var.get() and entry.raw_cached is not None:
                    entry.raw_cached = None

        return promoted, demoted

    def _tier_and_optimize_memory(self):
        before_rss = self.backbone.get_process_rss_bytes()
        with self.state_lock:
            promoted, demoted = self._rebalance_tiers_locked()

        collected = gc.collect()
        after_rss = self.backbone.get_process_rss_bytes()

        self._refresh_table()
        self._refresh_stats()
        self._refresh_backbone_telemetry()

        rss_msg = ""
        if before_rss is not None and after_rss is not None:
            delta_mb = (after_rss - before_rss) / (1024 ** 2)
            rss_msg = f" RSS: {before_rss / (1024 ** 2):.1f} MB -> {after_rss / (1024 ** 2):.1f} MB ({delta_mb:+.1f} MB)."

        self._log_reasoning(
            f"[Tier & Optimize] Promoted {promoted} to HOT fast tier, demoted {demoted} to COLD compressed tier, "
            f"GC reclaimed {collected} objects (heals={self.ai_engine.self_heal_events + self.worker.healed_count}).{rss_msg}"
        )

    # --- Drive & Backbone helpers ---
    def _refresh_drives(self):
        drives = self.backbone.list_drives()
        self.drive_combo["values"] = drives
        saved_drive = self.session.data.get("last_drive", "")
        saved_selected = self.session.data.get("selected_drives", [])
        current = self.drive_var.get().strip()

        if current in drives:
            pass
        elif saved_drive in drives:
            self.drive_var.set(saved_drive)
            if not self.watch_dir_var.get().strip() and self.drive_scope_var.get() == "Selected Drive":
                self.watch_dir_var.set(saved_drive)
        elif drives:
            self.drive_var.set(drives[0])

        self._rebuild_az_checkboxes(drives, saved_selected if isinstance(saved_selected, list) else [])
        self._refresh_backbone_telemetry()
        self._save_session_now()

    def _on_drive_selected(self):
        drv = self.drive_var.get().strip()
        if drv:
            self.watch_dir_var.set(drv)
            self._log_reasoning(f"[Backbone] Selected drive '{drv}' and saved for future sessions.")
        self._refresh_backbone_telemetry()
        self._save_session_now()

    def _refresh_backbone_telemetry(self):
        drives = self.backbone.list_drives()
        combo = self.get_selected_az_drives()
        ram_txt = self.backbone.get_ram_summary()
        free_txt = self.backbone.get_drive_free_text(self.watch_dir_var.get().strip())
        combo_txt = f"A-Z Combo ({len(combo)}): {', '.join(combo) if combo else 'none'}"
        self.backbone_lbl.config(
            text=f"{ram_txt}  |  {free_txt}  |  {combo_txt}  |  Detected: {', '.join(drives)}"
        )

    def _create_launcher(self):
        combo = self.get_selected_az_drives()
        watch_target = self.watch_dir_var.get().strip()
        if self.drive_scope_var.get() == "Custom Drive Combo (A-Z)" and combo:
            watch_target = ",".join(combo)
        elif self.drive_scope_var.get() == "All Detected Drives":
            watch_target = "__ALL_DRIVES__"
        try:
            launcher = self.backbone.create_backbone_launcher(watch_target)
            self._log_reasoning(f"[Backbone] Created startup/background launcher at '{launcher}'.")
            messagebox.showinfo(
                "Backbone Launcher Created",
                f"Created launcher:\n{launcher}\n\n"
                "You can add it to your OS startup items or run it anytime for headless 24/7 operation.",
            )
        except Exception as exc:
            self.ai_engine.self_heal_events += 1
            self._log_reasoning(f"[Backbone][Self-Heal] Failed to create launcher: {exc}")
            messagebox.showerror("Launcher Error", str(exc))

    def get_scan_roots(self) -> list[str]:
        scope = self.drive_scope_var.get()
        if scope == "All Detected Drives":
            return self.backbone.list_drives()
        if scope == "Custom Drive Combo (A-Z)":
            return self.get_selected_az_drives()
        if scope == "Selected Drive":
            drv = self.drive_var.get().strip()
            return [drv] if drv else []
        folder = self.watch_dir_var.get().strip()
        return [folder] if folder else []

    def get_poll_interval(self) -> float:
        try:
            val = float(self.interval_var.get().strip())
            return max(0.5, min(3600.0, val))
        except Exception:
            return 3.0

    def post_log(self, message: str):
        self.root.after(0, lambda m=message: self._log_reasoning(m))

    def post_ui_ingest(self, requested_name: str, raw_bytes: bytes, autonomous: bool):
        self.root.after(0, lambda: self._ingest_payload(requested_name, raw_bytes, autonomous=autonomous))

    def _sync_auto_status_ui(self):
        if self.worker.is_running:
            self.auto_status_lbl.config(text="Status: RUNNING 24/7 (Phase-Lock AI)")
            self.toggle_auto_btn.config(text="Pause Autonomous")
        else:
            self.auto_status_lbl.config(text="Status: PAUSED (Manual Ready)")
            self.toggle_auto_btn.config(text="Resume Autonomous")

    def _toggle_autonomous(self):
        if self.worker.is_running:
            self.worker.stop()
        else:
            self.worker.start()
        self._sync_auto_status_ui()
        self._save_session_now()

    def _browse_watch_dir(self):
        start_dir = self.watch_dir_var.get().strip() or self.drive_var.get().strip() or os.path.abspath(os.sep)
        chosen = filedialog.askdirectory(initialdir=start_dir)
        if chosen:
            self.watch_dir_var.set(chosen)
            self._refresh_backbone_telemetry()
            self._save_session_now()
            self._log_reasoning(f"[Backbone] Target path set to '{chosen}' and persisted.")

    # --- Logging & Harmonic AI Engine ---
    def _log_reasoning(self, message: str):
        self.reason_box.insert(tk.END, message.rstrip() + "\n")
        self.reason_box.see(tk.END)

    def _seed_startup_reasoning(self):
        for line in self.autoloader.logs:
            self._log_reasoning(line)
        self._log_reasoning(f"[Session] {self.session_msg}")
        self._log_reasoning(f"[Phase-Lock AI] {self.ai_engine.load_weights()}")
        self._refresh_weights_label()

    def _refresh_weights_label(self):
        w = self.ai_engine.weights
        mae = (
            f"{sum(self.ai_engine.mae_history)/len(self.ai_engine.mae_history):.2f}x"
            if self.ai_engine.mae_history
            else "-"
        )
        self.weights_lbl.config(
            text=(
                f"Weights -> int: {w['intercept']:.2f}, ent: {w['entropy_penalty']:.2f}, "
                f"rep: {w['repetition_bonus']:.2f}, harm: {w['harmonic_weight']:.2f}  |  "
                f"Coh: {self.ai_engine.coherence:.2f}  |  Sync R: {self.ai_engine.order_parameter:.2f}  |  "
                f"Regret: {self.ai_engine.cumulative_regret:.2f}x  |  "
                f"MinRatio: {self.ai_engine.dynamic_min_ratio:.2f}x  |  Updates: {self.ai_engine.observations}  |  MAE: {mae}"
            )
        )

    def _get_current_input_bytes(self) -> bytes:
        raw_text = self.input_box.get("1.0", tk.END)
        if raw_text.endswith("\n"):
            raw_text = raw_text[:-1]
        return raw_text.encode("utf-8")

    def _update_live_prediction(self):
        data = self._get_current_input_bytes()
        feats = self.ai_engine.analyze_features(data)
        pred = self.ai_engine.predict_ratio(feats)
        traj = self.ai_engine.predict_next_trajectory(feats)
        conf = self.ai_engine.confidence_score(feats, pred) * 100.0
        burst = self.ai_engine.forecast_burst()
        rec_codec, _ = self.ai_engine.recommend_mode(feats, self.lz4_ready)
        self.pred_lbl.config(
            text=(
                f"Entropy: {feats['entropy']:.2f} b/B  |  Repetition: {feats['repetition']*100:.1f}%  |  "
                f"Predicted: {pred:.2f}x  |  Next~{traj['next_ratio']:.2f}x  |  Conf: {conf:.0f}%  |  "
                f"Burst: {burst}  |  Policy: {rec_codec}"
            )
        )

    def _compress_with_strategy(
        self, raw_bytes: bytes, chosen_strategy: str, feats: dict
    ) -> tuple[bytes, str, list[str]]:
        trace: list[str] = []
        if chosen_strategy.startswith("Auto"):
            codec, why = self.ai_engine.recommend_mode(feats, self.lz4_ready)
            trace.append(f"Hypothesis -> '{codec}': {why}")
            if self.counterfactual_probe_var.get():
                cf_codec, _, cf_summary = self.ai_engine.counterfactual_evaluate(
                    raw_bytes, feats, self.autoloader.lz4_module, self.lz4_ready
                )
                trace.append(cf_summary)
                if cf_codec != codec and feats["repetition"] < 0.25:
                    codec = cf_codec
                    trace.append(f"Counterfactual refinement -> selected '{codec}'.")
        else:
            codec = chosen_strategy
            trace.append(f"Manual override -> '{codec}'.")

        try:
            if codec.startswith("lz4"):
                if not self.lz4_ready or self.autoloader.lz4_module is None:
                    raise RuntimeError("lz4 module unavailable")
                level = 9 if "level 9" in codec else 0
                compressed = self.autoloader.lz4_module.compress(raw_bytes, compression_level=level)
                return compressed, codec, trace
            compressed = zlib.compress(raw_bytes, level=6)
            return compressed, "zlib (level 6)", trace
        except Exception as exc:
            self.ai_engine.self_heal_events += 1
            trace.append(
                f"[Self-Heal] Primary codec '{codec}' failed ({exc}); healed via zlib level 6."
            )
            compressed = zlib.compress(raw_bytes, level=6)
            return compressed, "zlib (level 6) [healed]", trace

    def _decompress_with_heal(
        self, zipped_bytes: bytes, codec: str, expected_crc: int | None = None
    ) -> tuple[bytes, list[str]]:
        trace: list[str] = []
        raw_out: bytes | None = None

        if codec.startswith("lz4") and self.lz4_ready and self.autoloader.lz4_module is not None:
            try:
                raw_out = self.autoloader.lz4_module.decompress(zipped_bytes)
            except Exception as exc:
                self.ai_engine.self_heal_events += 1
                trace.append(f"[Self-Heal] LZ4 decompress failed ({exc}); trying zlib fallback.")
                raw_out = zlib.decompress(zipped_bytes)
        else:
            try:
                raw_out = zlib.decompress(zipped_bytes)
            except Exception as exc:
                if self.lz4_ready and self.autoloader.lz4_module is not None:
                    self.ai_engine.self_heal_events += 1
                    trace.append(f"[Self-Heal] zlib decompress failed ({exc}); trying LZ4 fallback.")
                    raw_out = self.autoloader.lz4_module.decompress(zipped_bytes)
                else:
                    raise

        if expected_crc is not None and raw_out is not None:
            actual_crc = zlib.crc32(raw_out) & 0xFFFFFFFF
            if actual_crc != expected_crc:
                self.ai_engine.self_heal_events += 1
                trace.append(
                    f"[Self-Heal] CRC32 mismatch (got {actual_crc:08x}, expected {expected_crc:08x}); "
                    f"re-anchoring entry integrity."
                )

        return raw_out, trace

    def _load_file(self):
        start_dir = self.watch_dir_var.get().strip() or self.drive_var.get().strip() or os.path.abspath(os.sep)
        path = filedialog.askopenfilename(initialdir=start_dir)
        if not path:
            return
        try:
            data = read_file_chunked(path, self.get_max_file_bytes())
        except Exception as exc:
            self.ai_engine.self_heal_events += 1
            self._log_reasoning(f"[Self-Heal] File read error on '{path}': {exc}")
            messagebox.showerror("File Error", f"Could not read file:\n{exc}")
            return

        text = data.decode("utf-8", errors="replace")
        self.input_box.delete("1.0", tk.END)
        self.input_box.insert("1.0", text)

        base = os.path.basename(path)
        self.name_var.set(base)
        self._log_reasoning(f"[Manual Input] Loaded '{path}' ({len(data):,} bytes via chunked reader).")
        self._update_live_prediction()

    def _zip_into_memory_manual(self):
        raw_bytes = self._get_current_input_bytes()
        if not raw_bytes:
            messagebox.showwarning("Empty Input", "Enter text or load a file before zipping into memory.")
            return

        requested_name = self.name_var.get().strip() or f"entry_{self.counter}"
        self._ingest_payload(requested_name, raw_bytes, autonomous=False)
        self.name_var.set(f"entry_{self.counter}")
        self._update_live_prediction()

    def _export_cot_trace(self):
        content = self.reason_box.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Empty Log", "No Chain-of-Thought reasoning log entries to export yet.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt",
            initialfile="memory_zip_cot_trace.txt",
            filetypes=[("Text Log", "*.txt"), ("All Files", "*.*")],
        )
        if not path:
            return
        try:
            with open(path, "w", encoding="utf-8") as f:
                f.write(content + "\n")
            self._log_reasoning(f"[Export] Saved Chain-of-Thought reasoning trace to '{path}'.")
        except Exception as exc:
            self.ai_engine.self_heal_events += 1
            self._log_reasoning(f"[Self-Heal] Failed exporting CoT trace: {exc}")
            messagebox.showerror("Export Error", str(exc))

    def _ingest_payload(self, requested_name: str, raw_bytes: bytes, autonomous: bool):
        mode_tag = "AUTO-AI" if autonomous else "MANUAL"
        feats = self.ai_engine.analyze_features(raw_bytes)
        pred_ratio = self.ai_engine.predict_ratio(feats)
        traj = self.ai_engine.predict_next_trajectory(feats)
        conf = self.ai_engine.confidence_score(feats, pred_ratio)
        burst = self.ai_engine.forecast_burst()
        strategy = "Auto (AI + Harmonic)" if autonomous else self.strategy_var.get()

        zipped_bytes, used_codec, codec_trace = self._compress_with_strategy(raw_bytes, strategy, feats)

        raw_len = len(raw_bytes)
        zip_len = len(zipped_bytes)
        actual_ratio = (raw_len / zip_len) if zip_len > 0 else 1.0
        crc = zlib.crc32(raw_bytes) & 0xFFFFFFFF

        adapt_summary = self.ai_engine.think_and_adapt(feats, pred_ratio, actual_ratio, used_codec=used_codec)
        self._refresh_weights_label()

        if autonomous and self.auto_save_weights_var.get() and (self.ai_engine.observations % 10 == 0):
            self.ai_engine.save_weights()

        threshold = self.ai_engine.dynamic_min_ratio if self.skip_expansion_var.get() else 0.0
        if autonomous and actual_ratio < threshold:
            self._log_reasoning(
                f"[{mode_tag} Guard] Skipped '{requested_name}' ({raw_len:,}B -> {zip_len:,}B, "
                f"ratio {actual_ratio:.2f}x < {threshold:.2f}x) | {adapt_summary}"
            )
            return

        keep_raw = None if self.lean_mode_var.get() else raw_bytes
        harmonic_align = (
            self.ai_engine.coherence >= 0.72
            or self.ai_engine.order_parameter >= 0.78
            or burst == "BURST-LOCK"
        )

        with self.state_lock:
            name = requested_name
            if name in self.store:
                name = f"{requested_name}_{self.counter}"
                self.ai_engine.self_heal_events += 1
                self._log_reasoning(
                    f"[Self-Heal] Name collision for '{requested_name}'; auto-renamed to '{name}'."
                )
            self.counter += 1

            zone, slot_id, slot_offset = self.planner.assign_slot(zip_len, harmonic_align=harmonic_align)

            self.store[name] = CompressedEntry(
                name=name,
                source=mode_tag,
                codec=used_codec,
                zone=zone,
                slot_id=slot_id,
                slot_offset=slot_offset,
                crc32=crc,
                raw_len=raw_len,
                zipped=zipped_bytes,
                pred_ratio=pred_ratio,
                ai_confidence=conf,
                tier="HOT",
                hot_bytes=raw_bytes,
                raw_cached=keep_raw,
            )
            self.store.move_to_end(name, last=True)

            hot_entries = [e for e in self.store.values() if e.tier == "HOT"]
            if len(hot_entries) > self.HOT_TIER_MAX_ITEMS:
                for oldest in hot_entries[: len(hot_entries) - self.HOT_TIER_MAX_ITEMS]:
                    oldest.tier = "COLD"
                    oldest.hot_bytes = None
                    if self.lean_mode_var.get():
                        oldest.raw_cached = None

        cot_lines = ReasoningTraceBuilder.build_ingest_trace(
            mode_tag=mode_tag,
            name=name,
            slot_id=slot_id,
            zone=zone,
            slot_offset=slot_offset,
            harmonic_align=harmonic_align,
            feats=feats,
            pred_ratio=pred_ratio,
            actual_ratio=actual_ratio,
            conf=conf,
            burst=burst,
            traj=traj,
            adapt_summary=adapt_summary,
            codec_trace=codec_trace,
        )
        for line in cot_lines:
            self._log_reasoning(line)

        self._refresh_table()
        self._refresh_stats()
        self._refresh_backbone_telemetry()

    def _unzip_selected(self):
        selected = self.tree.selection()
        if not selected:
            messagebox.showinfo("Select Item", "Select an entry from the table first.")
            return

        name = self.tree.item(selected[0], "values")[3]
        heal_trace: list[str] = []

        with self.state_lock:
            entry = self.store.get(name)
            if not entry:
                return
            entry.hits += 1
            entry.last_used = time.time()
            self.store.move_to_end(name, last=True)

            if entry.tier == "HOT" and entry.hot_bytes is not None:
                unzipped_bytes = entry.hot_bytes
                fast_path = True
            else:
                fast_path = False
                try:
                    unzipped_bytes, heal_trace = self._decompress_with_heal(
                        entry.zipped, entry.codec, entry.crc32
                    )
                except Exception as exc:
                    self.ai_engine.self_heal_events += 1
                    self._log_reasoning(f"[Self-Heal][Error] Failed to access '{name}': {exc}")
                    messagebox.showerror("Decompression Error", f"Could not access '{name}':\n{exc}")
                    return
                if entry.hits >= 2:
                    entry.tier = "HOT"
                    entry.hot_bytes = unzipped_bytes
                    hot_entries = [e for e in self.store.values() if e.tier == "HOT"]
                    if len(hot_entries) > self.HOT_TIER_MAX_ITEMS:
                        for oldest in hot_entries[: len(hot_entries) - self.HOT_TIER_MAX_ITEMS]:
                            oldest.tier = "COLD"
                            oldest.hot_bytes = None

        for step in heal_trace:
            self._log_reasoning(f"[Access '{name}'] {step}")

        if self.show_hex_var.get():
            display_text = " ".join(f"{b:02x}" for b in unzipped_bytes)
        else:
            display_text = unzipped_bytes.decode("utf-8", errors="replace")

        self.output_box.delete("1.0", tk.END)
        self.output_box.insert("1.0", display_text)
        tier_label = "HOT fast-tier hit" if fast_path else "COLD compressed read"
        self._log_reasoning(
            f"[Access '{name}' @ {entry.slot_id}] {tier_label} (hits={entry.hits}) -> {len(unzipped_bytes):,} bytes."
        )
        self._refresh_table()
        self._refresh_stats()

    def _delete_selected(self):
        selected = self.tree.selection()
        if not selected:
            return
        with self.state_lock:
            for item_id in selected:
                name = self.tree.item(item_id, "values")[3]
                self.store.pop(name, None)
                self._log_reasoning(f"[Memory] Removed '{name}' from assigned slot.")
        gc.collect()
        self._refresh_table()
        self._refresh_stats()
        self._refresh_backbone_telemetry()

    def _clear_all(self):
        with self.state_lock:
            count = len(self.store)
            self.store.clear()
        gc.collect()
        self._refresh_table()
        self._refresh_stats()
        self._refresh_backbone_telemetry()
        self.output_box.delete("1.0", tk.END)
        self._log_reasoning(f"[Memory] Cleared all {count} slots and ran GC.")

    def _save_weights_ui(self):
        msg = self.ai_engine.save_weights()
        self._log_reasoning(f"[Phase-Lock AI] {msg}")

    def _reset_weights_ui(self):
        msg = self.ai_engine.reset_weights()
        self._refresh_weights_label()
        self._update_live_prediction()
        self._log_reasoning(f"[Phase-Lock AI] {msg}")

    def _refresh_table(self):
        for row in self.tree.get_children():
            self.tree.delete(row)

        now = time.time()
        with self.state_lock:
            entries = sorted(
                self.store.values(),
                key=lambda e: e.relevance_score(now),
                reverse=True,
            )

        for entry in entries:
            rel = entry.relevance_score(now)
            self.tree.insert(
                "",
                tk.END,
                values=(
                    entry.slot_id,
                    entry.zone,
                    f"{entry.slot_offset:,} B",
                    entry.name,
                    entry.tier,
                    f"{rel:.2f} (x{entry.hits})",
                    f"{entry.raw_len:,} B",
                    f"{entry.active_bytes_len:,} B",
                    f"{entry.saved_bytes:+,} B ({entry.saved_pct:.1f}%)",
                ),
            )

    def _refresh_stats(self):
        with self.state_lock:
            entries = list(self.store.values())
            total_raw = sum(e.raw_len for e in entries)
            total_active = sum(e.active_bytes_len for e in entries)
            hot_count = sum(1 for e in entries if e.tier == "HOT")
            cold_count = sum(1 for e in entries if e.tier == "COLD")
            count = len(entries)

        ratio = (total_raw / total_active) if total_active > 0 else 1.0
        saved_bytes = total_raw - total_active
        saved_pct = (saved_bytes / total_raw * 100.0) if total_raw > 0 else 0.0

        self.totals_lbl.config(
            text=(
                f"Items: {count} (HOT: {hot_count} / COLD: {cold_count})  |  "
                f"Original: {total_raw:,} B  |  Active RAM: {total_active:,} B  |  "
                f"Ratio: {ratio:.2f}x  |  Saved: {saved_bytes:+,} B ({saved_pct:.1f}%)"
            )
        )


# =====================================================================
# 9. Headless Backbone Daemon Mode (--daemon)
# =====================================================================
def _resolve_daemon_roots(watch_arg: str, backbone: SystemBackbone, session: SessionMemoryStore) -> list[str]:
    if watch_arg == "__ALL_DRIVES__":
        return backbone.list_drives()
    if watch_arg:
        return [part.strip() for part in watch_arg.split(",") if part.strip()]
    scope = session.data.get("drive_scope", "Selected Folder")
    if scope == "All Detected Drives":
        return backbone.list_drives()
    if scope == "Custom Drive Combo (A-Z)":
        saved = session.data.get("selected_drives", [])
        if isinstance(saved, list) and saved:
            return [d for d in saved if os.path.isdir(d)]
    target = session.data.get("target_path", "")
    return [target] if target else []


def run_headless_daemon(watch_dir: str, interval: float = 3.0):
    autoloader = LibraryAutoloader()
    lz4_ready = autoloader.bootstrap()
    backbone = SystemBackbone(autoloader)
    planner = MemoryPlacementPlanner()
    ai_engine = HarmonicPhaseEngine()
    session = SessionMemoryStore()
    session.load()

    seen: dict[str, tuple[int, float]] = {}
    memory_store: dict[str, tuple[str, bytes]] = {}
    max_file_bytes = int(max(0.1, min(512.0, float(session.data.get("max_file_mb", "16") or 16))) * 1024 * 1024)
    skip_exts = {
        (ext.strip().lower() if ext.strip().startswith(".") else "." + ext.strip().lower())
        for ext in str(session.data.get("skip_exts", "")).split(",")
        if ext.strip()
    }

    print("[Daemon] Starting headless Phase-Lock AI memory-zip backbone loop. Press Ctrl+C to stop.")
    for log in autoloader.logs:
        print(log)

    try:
        while True:
            roots = _resolve_daemon_roots(watch_dir, backbone, session)
            for root_path in roots:
                if not root_path or not os.path.isdir(root_path):
                    continue
                for cur_dir, _, files in os.walk(root_path):
                    for fname in files:
                        if skip_exts and os.path.splitext(fname)[1].lower() in skip_exts:
                            continue
                        fpath = os.path.join(cur_dir, fname)
                        try:
                            st = os.stat(fpath)
                        except OSError:
                            continue
                        sig = (st.st_size, st.st_mtime)
                        if seen.get(fpath) == sig or st.st_size == 0 or st.st_size > max_file_bytes:
                            seen[fpath] = sig
                            continue
                        try:
                            raw = read_file_chunked(fpath, max_file_bytes)
                        except Exception:
                            ai_engine.self_heal_events += 1
                            continue
                        seen[fpath] = sig
                        feats = ai_engine.analyze_features(raw)
                        pred = ai_engine.predict_ratio(feats)
                        codec, _ = ai_engine.recommend_mode(feats, lz4_ready)
                        try:
                            zipped = (
                                autoloader.lz4_module.compress(
                                    raw, compression_level=(9 if "level 9" in codec else 0)
                                )
                                if (codec.startswith("lz4") and lz4_ready and autoloader.lz4_module is not None)
                                else zlib.compress(raw, level=6)
                            )
                        except Exception:
                            ai_engine.self_heal_events += 1
                            codec = "zlib (level 6) [healed]"
                            zipped = zlib.compress(raw, level=6)
                        ratio = len(raw) / max(1, len(zipped))
                        summary = ai_engine.think_and_adapt(feats, pred, ratio, used_codec=codec)
                        if ratio >= ai_engine.dynamic_min_ratio:
                            align = (
                                ai_engine.coherence >= 0.72
                                or ai_engine.order_parameter >= 0.78
                                or ai_engine.forecast_burst() == "BURST-LOCK"
                            )
                            zone, slot_id, offset = planner.assign_slot(len(zipped), harmonic_align=align)
                            memory_store[fpath] = (slot_id, zipped)
                            print(
                                f"[Daemon] {slot_id} ({zone} @ {offset:,}B) '{fpath}': "
                                f"{len(raw):,}B -> {len(zipped):,}B ({ratio:.2f}x) | {summary}"
                            )
            gc.collect()
            sleep_sec = max(0.5, interval)
            if session.data.get("predictive_lookahead", True):
                burst = ai_engine.forecast_burst()
                if burst == "BURST-LOCK":
                    sleep_sec = max(0.5, sleep_sec * 0.65)
                elif burst == "CALM":
                    sleep_sec = min(3600.0, sleep_sec * 1.15)
            time.sleep(sleep_sec)
    except KeyboardInterrupt:
        ai_engine.save_weights()
        print("\n[Daemon] Stopped cleanly and saved Phase-Lock AI weights.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Memory Zip Store — GUI & Backbone Daemon")
    parser.add_argument("--daemon", action="store_true", help="Run headless background loop")
    parser.add_argument("--watch", type=str, default=None, help="Folder/drive path, comma list, or __ALL_DRIVES__")
    parser.add_argument("--interval", type=float, default=3.0, help="Scan interval in seconds")
    args, _unknown = parser.parse_known_args()

    if args.daemon:
        run_headless_daemon(args.watch or "", interval=args.interval)
    else:
        root = tk.Tk()
        app = MemoryZipGUI(root, initial_watch_dir=args.watch)
        root.mainloop()