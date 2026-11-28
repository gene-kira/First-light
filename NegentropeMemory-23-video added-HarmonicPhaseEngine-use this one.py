import argparse
from collections import OrderedDict, deque
import ctypes
import gc
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import importlib
import json
import math
import os
import platform
import socket
import string
import subprocess
import sys
import threading
import time
import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
from urllib.parse import urlparse
import zlib


CHUNK_SIZE = 65536
STATE_FILE = "memory_zip_state.json"
WEIGHTS_FILE = "memory_zip_weights.json"
ORACLE_FILE = "memory_zip_oracle.json"
ELEVATION_GUARD_ENV = "MEMORY_ZIP_ELEVATION_ATTEMPTED"
NO_ELEVATE_ENV = "MEMORY_ZIP_NO_ELEVATE"


# =====================================================================
# 0. Auto-Elevation Check & Privilege Sentinel (Loop-Guarded + Self-Heal)
# =====================================================================
class PrivilegeSentinel:
    """
    Checks administrator/root status, performs guarded Windows UAC relaunch
    when requested, tracks elevation outcomes for adaptive weights, and provides
    graceful standard-user fallback without infinite relaunch loops.
    """

    def __init__(self):
        self.is_admin = False
        self.platform_os = os.name
        self.elevation_attempted = os.environ.get(ELEVATION_GUARD_ENV) == "1"
        self.status_message = "Privilege check pending."
        self.logs: list[str] = []
        self.elevation_attempts_count = 1 if self.elevation_attempted else 0
        self.fallback_mode = False

    def detect_admin(self) -> bool:
        if os.name == "nt" and hasattr(ctypes, "windll") and hasattr(ctypes.windll, "shell32"):
            try:
                self.is_admin = bool(ctypes.windll.shell32.IsUserAnAdmin())
                return self.is_admin
            except Exception as exc:
                self.fallback_mode = True
                self.logs.append(
                    f"[PrivilegeSentinel][Self-Heal] IsUserAnAdmin check error ({exc}); assuming standard user."
                )
                self.is_admin = False
                return False
        if hasattr(os, "geteuid"):
            try:
                self.is_admin = os.geteuid() == 0
                return self.is_admin
            except Exception:
                pass
        self.is_admin = False
        return False

    def ensure_admin(self, exit_on_relaunch: bool = True) -> bool:
        """
        Ensures administrator privileges on Windows via UAC 'runas', guarded
        against infinite relaunch loops and gracefully degrading on failure.
        """
        if self.detect_admin():
            self.status_message = "Running with elevated Administrator privileges."
            self.logs.append("[Codex Sentinel] Verified Administrator elevation: ACTIVE.")
            return True

        if os.environ.get(NO_ELEVATE_ENV) == "1":
            self.fallback_mode = True
            self.status_message = "Auto-elevation suppressed via environment flag; running in standard mode."
            self.logs.append("[Codex Sentinel] Elevation suppressed by environment policy; standard mode active.")
            return False

        if os.name != "nt" or not hasattr(ctypes, "windll"):
            self.fallback_mode = True
            self.status_message = f"Standard user context ({platform.system()}); continuing without UAC."
            self.logs.append(
                f"[Codex Sentinel] Non-Windows or no windll ({platform.system()}); continuing in standard mode."
            )
            return False

        if self.elevation_attempted:
            self.fallback_mode = True
            self.status_message = "Elevation already attempted or declined; running in standard/healed mode."
            self.logs.append(
                "[Codex Sentinel][Self-Heal] Elevation guard active after prior attempt; "
                "continuing with standard privileges to prevent relaunch loop."
            )
            return False

        try:
            os.environ[ELEVATION_GUARD_ENV] = "1"
            self.elevation_attempted = True
            self.elevation_attempts_count += 1
            script = os.path.abspath(sys.argv[0])
            extra_args = [f'"{arg.replace(chr(34), chr(92) + chr(34))}"' for arg in sys.argv[1:]]
            params = " ".join(extra_args)
            self.logs.append(f"[Codex Sentinel] Requesting UAC elevation for '{script}'...")
            rc = ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{script}" {params}'.strip(),
                None,
                1,
            )
            if rc is not None and int(rc) > 32:
                self.status_message = "Relaunched elevated process; exiting unprivileged instance."
                if exit_on_relaunch:
                    sys.exit(0)
                return True
            else:
                self.fallback_mode = True
                self.status_message = f"UAC elevation declined or returned code {rc}; continuing in standard mode."
                self.logs.append(f"[Codex Sentinel][Self-Heal] Elevation returned code {rc}; continuing unprivileged.")
                return False
        except SystemExit:
            raise
        except Exception as exc:
            self.fallback_mode = True
            self.status_message = f"Elevation failed ({exc}); continuing in standard/healed mode."
            self.logs.append(f"[Codex Sentinel][Self-Heal] Elevation failed ({exc}); continuing without elevation.")
            return False

    def predict_privilege_readiness(self, vram_pressure: float = 0.0, burst_mode: str = "CALM") -> dict:
        """
        Predictive reasoning helper estimating how current privilege posture
        interacts with multi-drive scans and hardware telemetry queries.
        """
        if self.is_admin:
            score = min(0.99, 0.78 + 0.15 * vram_pressure + (0.06 if burst_mode == "BURST-LOCK" else 0.0))
            recommendation = "ELEVATED_OPTIMAL"
            reason = "Admin token active; broad filesystem and system telemetry visibility available."
        elif self.fallback_mode:
            score = max(0.25, 0.55 - 0.20 * vram_pressure)
            recommendation = "USER_SPACE_HEALED"
            reason = "Operating in self-healed standard user mode; scoped folder/drive scanning active."
        else:
            score = 0.50
            recommendation = "STANDARD_READY"
            reason = "Standard privileges active."
        return {
            "is_admin": self.is_admin,
            "fallback_mode": self.fallback_mode,
            "readiness_score": score,
            "recommendation": recommendation,
            "reason": reason,
        }


def ensure_admin(sentinel: PrivilegeSentinel | None = None) -> PrivilegeSentinel:
    """Entry-point helper for auto-elevation check."""
    active_sentinel = sentinel or PrivilegeSentinel()
    active_sentinel.ensure_admin(exit_on_relaunch=True)
    return active_sentinel


# =====================================================================
# 1. Safe Optional Library Loader & Self-Healing Codec Layer
# =====================================================================
class LibraryAutoloader:
    """
    Safely probes optional acceleration libraries (lz4, psutil, cupy, pyopencl)
    without running unattended network package installations during startup.
    """

    def __init__(self):
        self.logs: list[str] = []
        self.lz4_module = None
        self.lz4_available = False
        self.psutil_module = None
        self.psutil_available = False
        self.cupy_module = None
        self.cupy_available = False
        self.opencl_module = None
        self.opencl_available = False

    def ensure_package(self, import_name: str, pip_name: str | None = None):
        pkg = pip_name or import_name
        try:
            mod = importlib.import_module(import_name)
            self.logs.append(f"[Loader] Optional module '{import_name}' loaded.")
            return mod
        except Exception:
            self.logs.append(
                f"[Loader][Self-Heal] Optional module '{import_name}' not available (package '{pkg}'); "
                f"using standard-library/fallback path."
            )
            return None

    def bootstrap(self) -> bool:
        self.lz4_module = self.ensure_package("lz4.frame", "lz4")
        self.lz4_available = self.lz4_module is not None

        self.psutil_module = self.ensure_package("psutil", "psutil")
        self.psutil_available = self.psutil_module is not None

        self.cupy_module = self.ensure_package("cupy", "cupy")
        self.cupy_available = self.cupy_module is not None

        self.opencl_module = self.ensure_package("pyopencl", "pyopencl")
        self.opencl_available = self.opencl_module is not None
        return self.lz4_available


# =====================================================================
# 1B. Real Video Card (GPU) Hardware & VRAM Inspector (TTL-Cached)
# =====================================================================
class GPUHardwareInspector:
    """
    Detects installed display/GPU hardware, queries VRAM/load where supported
    with TTL caching to avoid repeated subprocess spawns, and computes staging
    profile parameters for host-side metadata ring buffers.
    """

    def __init__(self, cache_ttl_sec: float = 4.0):
        self.cache_ttl_sec = max(0.5, cache_ttl_sec)
        self._last_probe_ts: float = 0.0
        self.last_snapshot: dict = {
            "gpu_name": "Detecting...",
            "vendor": "Unknown",
            "vram_total_bytes": 0,
            "vram_used_bytes": 0,
            "vram_free_bytes": 0,
            "gpu_util_pct": None,
            "mem_util_pct": None,
            "compute_apps": [],
            "profile": "STANDARD",
            "max_ring_slots": 32,
            "ring_span_bytes": 16 * 1024 * 1024,
            "vram_pressure": 0.0,
            "source": "init",
        }

    def _query_nvidia_smi(self) -> dict | None:
        try:
            proc = subprocess.run(
                [
                    "nvidia-smi",
                    "--query-gpu=name,memory.total,memory.used,memory.free,utilization.gpu,utilization.memory",
                    "--format=csv,noheader,nounits",
                ],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                return None
            first_line = proc.stdout.strip().splitlines()[0]
            parts = [p.strip() for p in first_line.split(",")]
            if len(parts) < 4:
                return None

            name = parts[0] or "NVIDIA GPU"
            total_mib = float(parts[1])
            used_mib = float(parts[2])
            free_mib = float(parts[3])
            gpu_util = float(parts[4]) if len(parts) > 4 and parts[4].replace(".", "", 1).isdigit() else None
            mem_util = float(parts[5]) if len(parts) > 5 and parts[5].replace(".", "", 1).isdigit() else None

            apps: list[str] = []
            try:
                app_proc = subprocess.run(
                    [
                        "nvidia-smi",
                        "--query-compute-apps=pid,process_name,used_memory",
                        "--format=csv,noheader,nounits",
                    ],
                    capture_output=True,
                    text=True,
                    timeout=1.5,
                    check=False,
                )
                if app_proc.returncode == 0 and app_proc.stdout.strip():
                    for line in app_proc.stdout.strip().splitlines()[:6]:
                        ap = [x.strip() for x in line.split(",")]
                        if len(ap) >= 2 and ap[1] and ap[1].upper() != "[N/A]":
                            mem_str = f" ({ap[2]} MiB)" if len(ap) >= 3 and ap[2].isdigit() else ""
                            apps.append(f"{ap[1]}:{ap[0]}{mem_str}")
            except Exception:
                pass

            return {
                "gpu_name": name,
                "vendor": "NVIDIA",
                "vram_total_bytes": int(total_mib * 1024 * 1024),
                "vram_used_bytes": int(used_mib * 1024 * 1024),
                "vram_free_bytes": int(free_mib * 1024 * 1024),
                "gpu_util_pct": gpu_util,
                "mem_util_pct": mem_util,
                "compute_apps": apps,
                "source": "nvidia-smi",
            }
        except Exception:
            return None

    def _query_windows_wmi(self) -> dict | None:
        if os.name != "nt":
            return None
        try:
            cmd = (
                "Get-CimInstance Win32_VideoController | "
                "Select-Object -First 1 Name,AdapterRAM | ConvertTo-Json -Compress"
            )
            proc = subprocess.run(
                ["powershell", "-NoProfile", "-Command", cmd],
                capture_output=True,
                text=True,
                timeout=2.5,
                check=False,
            )
            if proc.returncode != 0 or not proc.stdout.strip():
                return None
            obj = json.loads(proc.stdout.strip())
            if isinstance(obj, list):
                obj = obj[0] if obj else {}
            name = str(obj.get("Name") or "Windows Display Adapter")
            raw_ram = obj.get("AdapterRAM")
            total_b = int(raw_ram) if isinstance(raw_ram, (int, float)) and raw_ram > 0 else 0
            vendor = (
                "NVIDIA"
                if "nvidia" in name.lower()
                else (
                    "AMD"
                    if ("amd" in name.lower() or "radeon" in name.lower())
                    else ("Intel" if "intel" in name.lower() else "Display")
                )
            )
            return {
                "gpu_name": name,
                "vendor": vendor,
                "vram_total_bytes": total_b,
                "vram_used_bytes": 0,
                "vram_free_bytes": total_b,
                "gpu_util_pct": None,
                "mem_util_pct": None,
                "compute_apps": [],
                "source": "Win32_VideoController",
            }
        except Exception:
            return None

    def _query_linux_pci(self) -> dict | None:
        if os.name == "nt" or platform.system() == "Darwin":
            return None
        try:
            proc = subprocess.run(
                ["lspci"],
                capture_output=True,
                text=True,
                timeout=2.0,
                check=False,
            )
            if proc.returncode == 0 and proc.stdout:
                for line in proc.stdout.splitlines():
                    low = line.lower()
                    if (
                        "vga compatible controller" in low
                        or "3d controller" in low
                        or "display controller" in low
                    ):
                        desc = line.split(":", 2)[-1].strip() if ":" in line else line.strip()
                        vendor = (
                            "NVIDIA"
                            if "nvidia" in low
                            else (
                                "AMD"
                                if ("amd" in low or "ati" in low or "radeon" in low)
                                else ("Intel" if "intel" in low else "GPU")
                            )
                        )
                        return {
                            "gpu_name": desc,
                            "vendor": vendor,
                            "vram_total_bytes": 0,
                            "vram_used_bytes": 0,
                            "vram_free_bytes": 0,
                            "gpu_util_pct": None,
                            "mem_util_pct": None,
                            "compute_apps": [],
                            "source": "lspci",
                        }
        except Exception:
            pass
        return None

    def inspect(self, force: bool = False) -> dict:
        now = time.time()
        if not force and self._last_probe_ts > 0 and (now - self._last_probe_ts) < self.cache_ttl_sec:
            return dict(self.last_snapshot)

        info = self._query_nvidia_smi() or self._query_windows_wmi() or self._query_linux_pci()
        if info is None:
            info = {
                "gpu_name": f"System Graphics ({platform.system()})",
                "vendor": "Host",
                "vram_total_bytes": 0,
                "vram_used_bytes": 0,
                "vram_free_bytes": 0,
                "gpu_util_pct": None,
                "mem_util_pct": None,
                "compute_apps": [],
                "source": "fallback",
            }

        total_b = info.get("vram_total_bytes", 0)
        used_b = info.get("vram_used_bytes", 0)
        free_b = info.get("vram_free_bytes", 0)
        gpu_util = info.get("gpu_util_pct")

        if total_b > 0:
            used_ratio = max(0.0, min(1.0, used_b / total_b))
            free_ratio = max(0.0, min(1.0, free_b / total_b))
        else:
            used_ratio = 0.0
            free_ratio = 0.5

        load_ratio = (gpu_util / 100.0) if isinstance(gpu_util, (int, float)) else 0.0
        pressure = max(0.0, min(1.0, 0.7 * used_ratio + 0.3 * load_ratio))

        if total_b >= 16 * 1024**3 and pressure < 0.75:
            profile = "HIGH_VRAM"
            max_slots = 64
            ring_span = 64 * 1024 * 1024
        elif total_b >= 6 * 1024**3 and pressure < 0.85:
            profile = "MID_VRAM"
            max_slots = 32
            ring_span = 16 * 1024 * 1024
        elif total_b > 0:
            profile = "TIGHT_VRAM"
            max_slots = 12
            ring_span = 4 * 1024 * 1024
        else:
            profile = "HOST_FALLBACK"
            max_slots = 16
            ring_span = 8 * 1024 * 1024

        info.update(
            {
                "profile": profile,
                "max_ring_slots": max_slots,
                "ring_span_bytes": ring_span,
                "vram_pressure": pressure,
                "free_ratio": free_ratio,
            }
        )
        self.last_snapshot = info
        self._last_probe_ts = now
        return dict(info)

    def format_summary(self, snap: dict | None = None) -> str:
        s = snap or self.last_snapshot
        name = s.get("gpu_name", "Unknown GPU")
        total_b = s.get("vram_total_bytes", 0)
        used_b = s.get("vram_used_bytes", 0)
        free_b = s.get("vram_free_bytes", 0)
        util = s.get("gpu_util_pct")
        profile = s.get("profile", "STANDARD")
        apps = s.get("compute_apps") or []

        if total_b > 0:
            vram_txt = (
                f"VRAM: {used_b / (1024**2):.0f}/{total_b / (1024**2):.0f} MiB "
                f"(Free: {free_b / (1024**2):.0f} MiB)"
            )
        else:
            vram_txt = "VRAM: N/A (driver/host fallback)"

        util_txt = f"GPU Load: {util:.0f}%" if isinstance(util, (int, float)) else "GPU Load: N/A"
        apps_txt = f"On Card: {', '.join(apps[:3])}" if apps else "On Card: active display/runtime"
        return f"{name} [{profile}] | {vram_txt} | {util_txt} | {apps_txt}"


# =====================================================================
# 1C. Self-Healing Fault Watchdog & Quarantine Manager
# =====================================================================
class SelfHealWatchdog:
    """
    Tracks per-source fault streaks and temporarily quarantines unstable paths
    with automatic cooldown recovery so one bad file or path cannot stall scans.
    """

    def __init__(self, fault_threshold: int = 3, base_cooldown_sec: float = 20.0):
        self.lock = threading.RLock()
        self.fault_threshold = max(1, fault_threshold)
        self.base_cooldown_sec = max(2.0, base_cooldown_sec)
        self.streaks: dict[str, int] = {}
        self.quarantine_until: dict[str, float] = {}
        self.quarantine_count = 0
        self.recovered_count = 0

    def is_quarantined(self, key: str) -> bool:
        with self.lock:
            until = self.quarantine_until.get(key)
            if until is None:
                return False
            now = time.time()
            if now >= until:
                self.quarantine_until.pop(key, None)
                self.streaks[key] = 0
                self.recovered_count += 1
                return False
            return True

    def record_success(self, key: str) -> bool:
        with self.lock:
            had_faults = self.streaks.pop(key, 0) > 0
            if key in self.quarantine_until:
                self.quarantine_until.pop(key, None)
                self.recovered_count += 1
            return had_faults

    def record_fault(self, key: str) -> tuple[int, float | None]:
        with self.lock:
            streak = self.streaks.get(key, 0) + 1
            self.streaks[key] = streak
            if streak >= self.fault_threshold:
                cooldown = min(300.0, self.base_cooldown_sec * (2 ** min(4, streak - self.fault_threshold)))
                until = time.time() + cooldown
                self.quarantine_until[key] = until
                self.quarantine_count += 1
                return streak, cooldown
            return streak, None

    def active_quarantine_count(self) -> int:
        with self.lock:
            now = time.time()
            expired = [k for k, u in self.quarantine_until.items() if now >= u]
            for k in expired:
                self.quarantine_until.pop(k, None)
                self.streaks[k] = 0
                self.recovered_count += 1
            return len(self.quarantine_until)


# =====================================================================
# 2. Directed Memory Placement Planner (Slot & Zone Assignment)
# =====================================================================
class MemoryPlacementPlanner:
    """
    Assigns incoming payloads to dedicated host-RAM placement zones and logical
    slots with alignment and speculative slot reservation hints.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.next_slot_id = 1
        self.zone_cursors = {
            "FAST_SMALL": 0,
            "STREAM_MED": 0,
            "BULK_COLD": 0,
        }
        self.speculative_reservations: dict[str, dict] = {}

    def choose_zone(self, active_bytes: int) -> str:
        if active_bytes <= 4096:
            return "FAST_SMALL"
        if active_bytes <= 262144:
            return "STREAM_MED"
        return "BULK_COLD"

    def reserve_speculative_slot(self, signature: str, expected_bytes: int, harmonic_align: bool = False) -> dict:
        with self.lock:
            zone = self.choose_zone(max(64, expected_bytes))
            align = 256 if harmonic_align else 64
            span = max(align, ((max(64, expected_bytes) + align - 1) // align) * align)
            rec = {
                "signature": signature,
                "zone": zone,
                "span": span,
                "align": align,
                "ts": time.time(),
            }
            self.speculative_reservations[signature] = rec
            if len(self.speculative_reservations) > 128:
                oldest_key = next(iter(self.speculative_reservations))
                self.speculative_reservations.pop(oldest_key, None)
            return rec

    def assign_slot(
        self, active_bytes: int, harmonic_align: bool = False, signature: str | None = None
    ) -> tuple[str, str, int]:
        with self.lock:
            zone = self.choose_zone(active_bytes)
            slot_id = f"SLOT-{self.next_slot_id:04d}"
            self.next_slot_id += 1
            offset = self.zone_cursors[zone]
            align = 256 if harmonic_align else 64
            span = max(align, ((active_bytes + align - 1) // align) * align)
            if signature and signature in self.speculative_reservations:
                self.speculative_reservations.pop(signature, None)
            self.zone_cursors[zone] = offset + span
            return zone, slot_id, offset


# =====================================================================
# 2B. Host-Side GPU Staging & Compute Offload Engine (CUDA/OpenCL/Host)
# =====================================================================
class GPUCardPipeline:
    """
    Maintains a bounded host-side transfer/staging ledger, stride plan, and
    real GPU compute offloading when CuPy (CUDA) or PyOpenCL is present, with
    deterministic vectorized host fallback when GPU runtimes are absent.
    """

    def __init__(self, inspector: GPUHardwareInspector | None = None, autoloader: LibraryAutoloader | None = None):
        self.lock = threading.RLock()
        self.inspector = inspector or GPUHardwareInspector()
        self.autoloader = autoloader
        self.enabled = True
        self.target_fps = 60.0
        self.frame_cursor = 0
        self.dispatched_frames = 0
        self.staged_bytes = 0
        self.saved_transfer_bytes = 0
        self.heal_repairs = 0
        self.offload_ops = 0
        self.last_compute_backend = "HOST-VECTOR"
        self.ring_buffer: OrderedDict[str, dict] = OrderedDict()
        self.last_hw: dict = self.inspector.inspect(force=True)

    @property
    def max_ring_slots(self) -> int:
        with self.lock:
            return int(self.last_hw.get("max_ring_slots", 32))

    def refresh_hardware(self, force: bool = False) -> dict:
        snap = self.inspector.inspect(force=force)
        with self.lock:
            self.last_hw = snap
            limit = int(self.last_hw.get("max_ring_slots", 32))
            while len(self.ring_buffer) > limit:
                self.ring_buffer.popitem(last=False)
            return dict(self.last_hw)

    def choose_gpu_bank(self, payload_bytes: int, hw: dict) -> str:
        profile = hw.get("profile", "MID_VRAM")
        const_limit = 4096 if profile == "TIGHT_VRAM" else 8192
        tex_limit = 262144 if profile == "TIGHT_VRAM" else (1048576 if profile == "HIGH_VRAM" else 524288)
        if payload_bytes <= const_limit:
            return "SHADER_CONST_PLAN"
        if payload_bytes <= tex_limit:
            return "TEX_STREAM_PLAN"
        return "VRAM_SCANOUT_PLAN"

    def offload_entropy_and_xor_kernel(self, data: bytes) -> dict:
        """
        Offloads parallel byte-histogram / XOR-fold scoring to CuPy (CUDA) or
        PyOpenCL when installed; falls back cleanly to Python/bytearray math.
        """
        sample = data[: min(len(data), 65536)]
        if not sample:
            return {"backend": "NONE", "xor_fold": 0, "high_byte_ratio": 0.0, "elapsed_ms": 0.0}
        t0 = time.perf_counter()
        backend = "HOST-FAST"
        xor_fold = 0
        high_bytes = 0

        if self.autoloader and self.autoloader.cupy_available and self.autoloader.cupy_module is not None:
            try:
                cp = self.autoloader.cupy_module
                arr = cp.frombuffer(sample, dtype=cp.uint8)
                high_bytes = int(cp.sum(arr >= 128).item())
                xor_fold = int(cp.bitwise_xor.reduce(arr).item())
                backend = "CUDA-CUPY"
            except Exception:
                backend = "HOST-HEALED"

        if backend.startswith("HOST"):
            acc = 0
            hi = 0
            for b in sample:
                acc ^= b
                if b >= 128:
                    hi += 1
            xor_fold = acc
            high_bytes = hi

        elapsed_ms = (time.perf_counter() - t0) * 1000.0
        with self.lock:
            self.offload_ops += 1
            self.last_compute_backend = backend
        return {
            "backend": backend,
            "xor_fold": xor_fold,
            "high_byte_ratio": high_bytes / max(1, len(sample)),
            "elapsed_ms": elapsed_ms,
        }

    def stage_to_video_card(
        self,
        name: str,
        raw_len: int,
        zipped_bytes: bytes,
        conjugate_phase: float,
        coherence: float,
    ) -> dict:
        hw = self.refresh_hardware()
        with self.lock:
            if not self.enabled:
                return {
                    "active": False,
                    "bank": "BYPASSED",
                    "stride_bytes": 0,
                    "conjugate_phase": conjugate_phase,
                    "frame_id": self.dispatched_frames,
                    "profile": hw.get("profile", "STANDARD"),
                }

            total_b = hw.get("vram_total_bytes", 0)
            free_b = hw.get("vram_free_bytes", 0)
            if total_b > 0 and free_b < max(16 * 1024 * 1024, len(zipped_bytes) * 2):
                return {
                    "active": False,
                    "bank": "HEADROOM_GUARD",
                    "stride_bytes": 0,
                    "conjugate_phase": conjugate_phase,
                    "frame_id": self.dispatched_frames,
                    "profile": hw.get("profile", "TIGHT_VRAM"),
                }

            bank = self.choose_gpu_bank(len(zipped_bytes), hw)
            base_stride = 256 if (coherence >= 0.72 or abs(math.cos(conjugate_phase)) >= 0.70) else 128
            if hw.get("profile") == "HIGH_VRAM":
                base_stride *= 2
            stride_bytes = max(128, ((len(zipped_bytes) + base_stride - 1) // base_stride) * base_stride)
            ring_span = max(1024 * 1024, int(hw.get("ring_span_bytes", 16 * 1024 * 1024)))

            self.dispatched_frames += 1
            self.frame_cursor = (self.frame_cursor + stride_bytes) % ring_span
            self.staged_bytes += len(zipped_bytes)
            self.saved_transfer_bytes += max(0, raw_len - len(zipped_bytes))

            frame_id = f"GPUF-{self.dispatched_frames:04d}"
            crc = zlib.crc32(zipped_bytes) & 0xFFFFFFFF

            if name in self.ring_buffer:
                self.heal_repairs += 1
                self.ring_buffer.pop(name, None)

            self.ring_buffer[name] = {
                "frame_id": frame_id,
                "bank": bank,
                "offset": self.frame_cursor,
                "stride": stride_bytes,
                "zip_len": len(zipped_bytes),
                "raw_len": raw_len,
                "crc32": crc,
                "conjugate_phase": conjugate_phase,
                "ts": time.time(),
            }
            self.ring_buffer.move_to_end(name, last=True)

            while len(self.ring_buffer) > self.max_ring_slots:
                self.ring_buffer.popitem(last=False)

            return {
                "active": True,
                "frame_id": frame_id,
                "bank": bank,
                "offset": self.frame_cursor,
                "stride_bytes": stride_bytes,
                "conjugate_phase": conjugate_phase,
                "profile": hw.get("profile", "STANDARD"),
            }

    def scrub_video_ring(self) -> tuple[int, int]:
        self.refresh_hardware()
        with self.lock:
            checked = 0
            repaired = 0
            for _name, rec in list(self.ring_buffer.items()):
                checked += 1
                if rec.get("stride", 0) <= 0 or rec.get("offset", -1) < 0:
                    rec["stride"] = 256
                    rec["offset"] = 0
                    repaired += 1
                    self.heal_repairs += 1
            return checked, repaired

    def clear_ring(self):
        with self.lock:
            self.ring_buffer.clear()


# =====================================================================
# 2C. Event Bus / Broker, Plugin Loader, Mesh Sync, Graph DB, LLM & Threats
# =====================================================================
class EventBrokerBus:
    """Thread-safe pub/sub event bus with bounded history for internal and external subscribers."""

    def __init__(self, history_limit: int = 256):
        self.lock = threading.RLock()
        self.subscribers: dict[str, list] = {}
        self.history: deque[dict] = deque(maxlen=history_limit)
        self.published_count = 0

    def subscribe(self, topic: str, handler):
        with self.lock:
            self.subscribers.setdefault(topic, []).append(handler)

    def publish(self, topic: str, payload: dict):
        with self.lock:
            self.published_count += 1
            evt = {"id": self.published_count, "topic": topic, "ts": time.time(), "payload": payload}
            self.history.append(evt)
            handlers = list(self.subscribers.get(topic, [])) + list(self.subscribers.get("*", []))
        for h in handlers:
            try:
                h(evt)
            except Exception:
                pass
        return evt

    def recent(self, limit: int = 25) -> list[dict]:
        with self.lock:
            return list(self.history)[-limit:]


class PluginRegistry:
    """
    Loads user/extension Python plugins from a local `plugins/` directory.
    Each plugin may expose `register(ctx)` or `transform_payload(name, data, meta)`.
    """

    def __init__(self, plugins_dir: str | None = None):
        base_dir = os.path.dirname(os.path.abspath(__file__))
        self.plugins_dir = plugins_dir or os.path.join(base_dir, "plugins")
        self.lock = threading.RLock()
        self.loaded_plugins: dict[str, object] = {}
        self.errors: list[str] = []

    def discover_and_load(self, context: dict | None = None) -> list[str]:
        loaded_names: list[str] = []
        with self.lock:
            self.errors.clear()
            if not os.path.isdir(self.plugins_dir):
                return loaded_names
            if self.plugins_dir not in sys.path:
                sys.path.insert(0, self.plugins_dir)
            for fname in sorted(os.listdir(self.plugins_dir)):
                if not fname.endswith(".py") or fname.startswith("_"):
                    continue
                mod_name = fname[:-3]
                try:
                    if mod_name in sys.modules:
                        mod = importlib.reload(sys.modules[mod_name])
                    else:
                        mod = importlib.import_module(mod_name)
                    if hasattr(mod, "register") and callable(mod.register) and context is not None:
                        mod.register(context)
                    self.loaded_plugins[mod_name] = mod
                    loaded_names.append(mod_name)
                except Exception as exc:
                    self.errors.append(f"{mod_name}: {exc}")
        return loaded_names

    def run_transforms(self, name: str, data: bytes, meta: dict) -> bytes:
        out = data
        with self.lock:
            mods = list(self.loaded_plugins.values())
        for mod in mods:
            fn = getattr(mod, "transform_payload", None)
            if callable(fn):
                try:
                    res = fn(name, out, meta)
                    if isinstance(res, (bytes, bytearray)):
                        out = bytes(res)
                except Exception:
                    pass
        return out

    def summary(self) -> str:
        with self.lock:
            return f"Plugins:{len(self.loaded_plugins)} (err:{len(self.errors)})"


class MultiNodeMeshSync:
    """
    Real UDP gossip / state-vector mesh synchronization across LAN/peers
    with thread-safe peer state table and optional active UDP broadcast.
    """

    def __init__(self, node_id: str | None = None, udp_port: int = 38942, enable_socket: bool = False):
        self.lock = threading.RLock()
        self.node_id = node_id or f"{platform.node()}-{os.getpid()}"
        self.udp_port = udp_port
        self.enable_socket = enable_socket
        self.peers: dict[str, dict] = {}
        self.last_sync_ts: float = 0.0
        self.sync_packets_sent: int = 0

    def ingest_peer_gossip(self, peer_payload: dict):
        pid = str(peer_payload.get("node_id") or "").strip()
        if not pid or pid == self.node_id:
            return
        with self.lock:
            self.peers[pid] = {
                "codec": str(peer_payload.get("codec", "lz4-default (level 0)")),
                "confidence": float(peer_payload.get("confidence", 0.6)),
                "coherence": float(peer_payload.get("coherence", 0.5)),
                "entries": int(peer_payload.get("entries", 0)),
                "ts": time.time(),
            }
            if len(self.peers) > 64:
                oldest = next(iter(self.peers))
                self.peers.pop(oldest, None)

    def broadcast_state(self, state_summary: dict) -> int:
        packet = {
            "node_id": self.node_id,
            "codec": state_summary.get("codec", "lz4-default (level 0)"),
            "confidence": state_summary.get("confidence", 0.6),
            "coherence": state_summary.get("coherence", 0.5),
            "entries": state_summary.get("entries", 0),
            "ts": time.time(),
        }
        with self.lock:
            self.last_sync_ts = time.time()
            self.sync_packets_sent += 1
        if self.enable_socket:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
                sock.settimeout(0.25)
                raw = json.dumps(packet).encode("utf-8")[:4096]
                sock.sendto(raw, ("255.255.255.255", self.udp_port))
                sock.close()
            except Exception:
                pass
        return self.sync_packets_sent

    def peer_votes(self) -> dict[str, dict]:
        with self.lock:
            now = time.time()
            active = {k: v for k, v in self.peers.items() if (now - v.get("ts", now)) <= 120.0}
            self.peers = active
            return dict(active)

    def summary(self) -> str:
        with self.lock:
            return f"Mesh:{self.node_id} peers={len(self.peers)} tx={self.sync_packets_sent}"


class DistributedMemoryGraphDB:
    """
    Partitioned graph store indexing memory entries, structural/holographic keys,
    and semantic/access edges across virtual shards for fast neighbor & RAG queries.
    """

    def __init__(self, shards: int = 4):
        self.shards = max(1, shards)
        self.lock = threading.RLock()
        self.nodes: dict[str, dict] = {}
        self.edges: dict[str, dict[str, dict]] = {}

    def shard_for(self, key: str) -> int:
        h = zlib.crc32(key.encode("utf-8")) & 0xFFFFFFFF
        return h % self.shards

    def upsert_node(self, node_id: str, attrs: dict):
        with self.lock:
            rec = self.nodes.get(node_id, {"attrs": {}, "shard": self.shard_for(node_id)})
            rec["attrs"].update(attrs)
            rec["updated_ts"] = time.time()
            self.nodes[node_id] = rec
            self.edges.setdefault(node_id, {})

    def link(self, src: str, dst: str, relation: str = "co_access", weight: float = 1.0):
        if src == dst:
            return
        with self.lock:
            self.nodes.setdefault(src, {"attrs": {}, "shard": self.shard_for(src)})
            self.nodes.setdefault(dst, {"attrs": {}, "shard": self.shard_for(dst)})
            e1 = self.edges.setdefault(src, {}).setdefault(dst, {"weight": 0.0, "relation": relation})
            e1["weight"] = round(e1["weight"] + weight, 4)
            e1["relation"] = relation
            e2 = self.edges.setdefault(dst, {}).setdefault(src, {"weight": 0.0, "relation": relation})
            e2["weight"] = round(e2["weight"] + weight, 4)

    def query_neighborhood(self, node_id: str, depth: int = 1, top_k: int = 5) -> list[dict]:
        with self.lock:
            if node_id not in self.edges:
                return []
            visited = {node_id}
            frontier = [(node_id, 1.0, 0)]
            results: list[dict] = []
            while frontier:
                cur, path_w, d = frontier.pop(0)
                if d >= depth:
                    continue
                for nbr, edata in sorted(
                    self.edges.get(cur, {}).items(), key=lambda kv: kv[1].get("weight", 0.0), reverse=True
                ):
                    w = path_w * float(edata.get("weight", 1.0))
                    results.append(
                        {
                            "node": nbr,
                            "weight": w,
                            "depth": d + 1,
                            "relation": edata.get("relation", "link"),
                            "shard": self.nodes.get(nbr, {}).get("shard", 0),
                        }
                    )
                    if nbr not in visited:
                        visited.add(nbr)
                        frontier.append((nbr, w, d + 1))
            results.sort(key=lambda r: r["weight"], reverse=True)
            return results[:top_k]

    def remove_node(self, node_id: str):
        with self.lock:
            self.nodes.pop(node_id, None)
            self.edges.pop(node_id, None)
            for nbrs in self.edges.values():
                nbrs.pop(node_id, None)

    def clear(self):
        with self.lock:
            self.nodes.clear()
            self.edges.clear()

    def summary(self) -> str:
        with self.lock:
            edge_cnt = sum(len(v) for v in self.edges.values()) // 2
            return f"GraphDB:{len(self.nodes)}n/{edge_cnt}e/{self.shards}sh"


class LocalLLMRAGBridge:
    """
    Connects memory entries and graph neighbors to a local OpenAI-compatible or
    Ollama endpoint (e.g., http://localhost:11434) when reachable, with an
    offline extractive RAG synthesizer fallback so queries always succeed.
    """

    def __init__(self, endpoint_url: str = "http://127.0.0.1:11434/api/generate", model: str = "llama3.2"):
        self.endpoint_url = endpoint_url
        self.model = model
        self.last_mode = "EXTRACTIVE-FALLBACK"

    def query_rag(self, prompt: str, context_snippets: list[tuple[str, str]], timeout_sec: float = 1.5) -> dict:
        snippets = context_snippets[:4]
        try:
            import urllib.request

            ctx_block = "\n\n".join(f"[{k}] {v[:400]}" for k, v in snippets)
            full_prompt = f"Context:\n{ctx_block}\n\nQuestion: {prompt}\nAnswer concisely:"
            req_body = json.dumps({"model": self.model, "prompt": full_prompt, "stream": False}).encode("utf-8")
            req = urllib.request.Request(
                self.endpoint_url,
                data=req_body,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=timeout_sec) as resp:
                body = json.loads(resp.read().decode("utf-8", errors="replace"))
                ans = str(body.get("response") or body.get("text") or "").strip()
                if ans:
                    self.last_mode = f"LOCAL-LLM:{self.model}"
                    return {"mode": self.last_mode, "answer": ans, "sources": [k for k, _ in snippets]}
        except Exception:
            pass

        self.last_mode = "EXTRACTIVE-FALLBACK"
        terms = [t.lower() for t in prompt.split() if len(t) > 2]
        scored: list[tuple[int, str, str]] = []
        for doc_name, txt in snippets:
            low = txt.lower()
            hit_score = sum(1 for t in terms if t in low)
            scored.append((hit_score, doc_name, txt.strip()))
        scored.sort(key=lambda x: x[0], reverse=True)
        if not scored:
            return {"mode": self.last_mode, "answer": "No indexed memory context available yet.", "sources": []}
        top_hits = [f"({name}) {excerpt[:180]}" for _sc, name, excerpt in scored[:2]]
        return {
            "mode": self.last_mode,
            "answer": "Relevant memory context: " + " | ".join(top_hits),
            "sources": [name for _sc, name, _ex in scored[:2]],
        }


class ThreatAnomalyMatrix:
    """
    Tracks security/operational anomalies (high-entropy spikes, rapid fault streaks,
    CRC mismatches, or phase/divergence alarms) and computes a structured threat matrix.
    """

    def __init__(self, history_limit: int = 128):
        self.lock = threading.RLock()
        self.events: deque[dict] = deque(maxlen=history_limit)
        self.scores: dict[str, float] = {
            "ENTROPY_ANOMALY": 0.0,
            "IO_FAULT_SPIKE": 0.0,
            "INTEGRITY_DRIFT": 0.0,
            "REGIME_DIVERGENCE": 0.0,
        }

    def record(self, category: str, severity: float, detail: str):
        cat = category if category in self.scores else "INTEGRITY_DRIFT"
        sev = max(0.0, min(1.0, float(severity)))
        with self.lock:
            self.scores[cat] = max(0.0, min(1.0, 0.72 * self.scores[cat] + 0.28 * sev))
            self.events.append({"ts": time.time(), "category": cat, "severity": sev, "detail": detail})

    def decay(self, factor: float = 0.92):
        with self.lock:
            for k in self.scores:
                self.scores[k] = round(self.scores[k] * factor, 4)

    def overall_level(self) -> tuple[str, float]:
        with self.lock:
            peak = max(self.scores.values()) if self.scores else 0.0
            if peak >= 0.75:
                return "ELEVATED", peak
            if peak >= 0.45:
                return "GUARDED", peak
            return "NOMINAL", peak

    def matrix_rows(self) -> list[tuple[str, str, str]]:
        with self.lock:
            rows = []
            for cat, sc in self.scores.items():
                lvl = "HIGH" if sc >= 0.75 else ("MED" if sc >= 0.45 else "LOW")
                rows.append((cat, lvl, f"{sc*100:.0f}%"))
            return rows

    def summary(self) -> str:
        lvl, peak = self.overall_level()
        return f"Threat:{lvl} ({peak*100:.0f}%)"


class WorkflowAutomationEngine:
    """
    Evaluates declarative rule triggers against live telemetry and executes
    automated actions (tier rebalance, integrity scrub, weight save, or alert).
    """

    def __init__(self, broker: EventBrokerBus | None = None):
        self.lock = threading.RLock()
        self.broker = broker
        self.rules: list[dict] = [
            {
                "id": "rule_high_vram_tier",
                "metric": "vram_pressure",
                "op": ">=",
                "threshold": 0.85,
                "action": "TIER_OPTIMIZE",
                "fired": 0,
            },
            {
                "id": "rule_high_divergence_heal",
                "metric": "divergence",
                "op": ">=",
                "threshold": 0.65,
                "action": "SCRUB_AND_HEAL",
                "fired": 0,
            },
            {
                "id": "rule_checkpoint_weights",
                "metric": "observations",
                "op": "mod15",
                "threshold": 0.0,
                "action": "SAVE_STATE",
                "fired": 0,
            },
        ]
        self.execution_log: deque[str] = deque(maxlen=64)

    def evaluate(self, telemetry: dict, action_handlers: dict[str, callable]) -> list[str]:
        triggered: list[str] = []
        with self.lock:
            for r in self.rules:
                m_val = float(telemetry.get(r["metric"], 0.0))
                th = float(r["threshold"])
                op = r["op"]
                matched = False
                if op == ">=" and m_val >= th:
                    matched = True
                elif op == ">" and m_val > th:
                    matched = True
                elif op == "mod15" and int(m_val) > 0 and int(m_val) % 15 == 0:
                    matched = True
                if matched:
                    r["fired"] = int(r.get("fired", 0)) + 1
                    act = r["action"]
                    triggered.append(f"{r['id']}->{act}")
                    msg = f"[Workflow] Fired '{r['id']}' ({r['metric']}={m_val:.2f}) => {act}"
                    self.execution_log.append(msg)
                    if self.broker:
                        self.broker.publish("workflow.fired", {"rule": r["id"], "action": act, "value": m_val})
                    cb = action_handlers.get(act)
                    if callable(cb):
                        try:
                            cb()
                        except Exception:
                            pass
        return triggered

    def summary(self) -> str:
        with self.lock:
            total_fires = sum(int(r.get("fired", 0)) for r in self.rules)
            return f"Workflows:{len(self.rules)} rules / {total_fires} fires"


class WebControlPanelServer:
    """
    Lightweight threaded HTTP JSON/HTML control panel serving live telemetry,
    graph/threat/workflow snapshots, RAG queries, and trigger endpoints.
    """

    def __init__(self, state_provider: callable, command_handler: callable, host: str = "127.0.0.1", port: int = 8765):
        self.state_provider = state_provider
        self.command_handler = command_handler
        self.host = host
        self.port = port
        self._server: ThreadingHTTPServer | None = None
        self._thread: threading.Thread | None = None
        self.running = False

    def start(self) -> bool:
        if self.running:
            return True
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, _format, *_args):
                return

            def _send_json(self, code: int, payload: dict):
                raw = json.dumps(payload, default=str).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.end_headers()
                self.wfile.write(raw)

            def do_GET(self):
                parsed = urlparse(self.path)
                if parsed.path == "/api/status":
                    self._send_json(200, outer.state_provider())
                elif parsed.path == "/":
                    html = (
                        "<html><head><title>Memory Zip Control Panel</title></head>"
                        "<body style='font-family:monospace;background:#111;color:#eee;padding:20px;'>"
                        "<h2>On-the-Fly Memory Zip Control Panel</h2>"
                        "<p>Live JSON endpoint: <a href='/api/status' style='color:#6cf;'>/api/status</a></p>"
                        "<pre id='out'>Loading...</pre>"
                        "<script>fetch('/api/status').then(r=>r.json()).then(d=>"
                        "document.getElementById('out').textContent=JSON.stringify(d,null,2));</script>"
                        "</body></html>"
                    ).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html; charset=utf-8")
                    self.send_header("Content-Length", str(len(html)))
                    self.end_headers()
                    self.wfile.write(html)
                else:
                    self._send_json(404, {"error": "not_found"})

            def do_POST(self):
                parsed = urlparse(self.path)
                length = int(self.headers.get("Content-Length", "0") or "0")
                raw = self.rfile.read(min(length, 65536)) if length > 0 else b"{}"
                try:
                    body = json.loads(raw.decode("utf-8", errors="replace")) if raw else {}
                except Exception:
                    body = {}
                res = outer.command_handler(parsed.path, body)
                self._send_json(200, res)

        try:
            self._server = ThreadingHTTPServer((self.host, self.port), Handler)
            self.running = True
            self._thread = threading.Thread(target=self._server.serve_forever, name="WebControlPanel", daemon=True)
            self._thread.start()
            return True
        except Exception:
            self.running = False
            return False

    def stop(self):
        self.running = False
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None


# =====================================================================
# 2D. Novel Mechanism: Chrono-Causal Entanglement & Self-Evolving Policy
# =====================================================================
class ChronoEntanglementEngine:
    """
    Original mechanism ('Chrono-Causal Entanglement'):
    Entangles circadian/hourly workload cadence phase with structural causal
    intervention deltas and mutating policy genes to forecast future working-set
    shifts and pre-tune tier/compression biases before workload spikes hit.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.entanglement_phase: float = 0.0
        self.entanglement_coupling: float = 0.50
        self.policy_genes: dict[str, float] = {
            "prestage_aggression": 0.50,
            "causal_trust": 0.65,
            "mutation_rate": 0.04,
        }
        self.cycles: int = 0
        self.last_forecast: dict = {"horizon_shift": 0.0, "prestage_hot_delta": 0, "regime_tag": "CHRONO-SYNC"}

    def step_entanglement(
        self,
        features: dict[str, float],
        causal_delta_gain: float,
        actual_ratio: float,
        predicted_ratio: float,
        now: float | None = None,
    ) -> dict:
        ts = now if now is not None else time.time()
        with self.lock:
            self.cycles += 1
            # Circadian + minute harmonic phase
            sec_of_day = ts % 86400.0
            circadian_theta = (2.0 * math.pi * sec_of_day) / 86400.0
            ent_norm = max(0.0, min(1.0, features.get("entropy", 4.0) / 8.0))
            rep_norm = max(0.0, min(1.0, features.get("repetition", 0.0)))

            d_phi = 0.25 * math.cos(circadian_theta) + 0.35 * rep_norm - 0.15 * ent_norm + 0.20 * causal_delta_gain
            self.entanglement_phase = (self.entanglement_phase + d_phi) % (2.0 * math.pi)

            err = abs(actual_ratio - predicted_ratio)
            reward = max(-1.0, min(1.0, (1.0 / (1.0 + err)) - 0.35 + 0.5 * causal_delta_gain))
            self.entanglement_coupling = max(0.10, min(0.99, 0.80 * self.entanglement_coupling + 0.20 * (0.5 + 0.5 * reward)))

            mut = self.policy_genes["mutation_rate"] * reward
            self.policy_genes["prestage_aggression"] = max(
                0.10, min(0.95, self.policy_genes["prestage_aggression"] + mut)
            )
            self.policy_genes["causal_trust"] = max(
                0.20, min(0.95, self.policy_genes["causal_trust"] + 0.5 * mut)
            )

            horizon_shift = math.sin(self.entanglement_phase) * self.entanglement_coupling * self.policy_genes["prestage_aggression"]
            prestage_delta = 1 if horizon_shift > 0.22 else (-1 if horizon_shift < -0.22 else 0)
            regime = (
                "ENTANGLED-SURGE"
                if horizon_shift > 0.22
                else ("ENTANGLED-EASE" if horizon_shift < -0.22 else "CHRONO-SYNC")
            )
            self.last_forecast = {
                "horizon_shift": horizon_shift,
                "prestage_hot_delta": prestage_delta,
                "regime_tag": regime,
                "coupling": self.entanglement_coupling,
            }
            return dict(self.last_forecast)

    def summary(self) -> str:
        with self.lock:
            return (
                f"ChronoEntangle({self.last_forecast['regime_tag']}, "
                f"ψ={self.entanglement_phase:.2f}rad, c={self.entanglement_coupling*100:.0f}%, "
                f"pre={self.policy_genes['prestage_aggression']:.2f})"
            )


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
    """Persists user drive selections, scope, video toggle, and preferences across reboots."""

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
        "video_enabled": True,
        "causal_tiering": True,
        "auto_policy_tune": True,
        "predictive_horizon": True,
        "web_panel_enabled": True,
    }

    def __init__(self, state_path: str = STATE_FILE):
        self.lock = threading.RLock()
        self.state_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), state_path)
        self.data = dict(self.DEFAULTS)

    def load(self) -> str:
        with self.lock:
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
        with self.lock:
            self.data.update(updates)
            snapshot = dict(self.data)
        try:
            tmp_path = f"{self.state_path}.{os.getpid()}.{threading.get_ident()}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(snapshot, f, indent=2)
            os.replace(tmp_path, self.state_path)
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
# 6. Harmonic Phase, Holographic Interference, Echo & Regret Engine
# =====================================================================
class ResonantEchoLedger:
    """
    Signature-echo & drift tracker: hashes payload structure/prefix/suffix
    fingerprints to detect recurring templates or regime shifts and estimate
    expected repeat compression ratios without storing raw payloads.
    """

    def __init__(self, capacity: int = 256):
        self.capacity = capacity
        self.records: OrderedDict[str, dict] = OrderedDict()

    @staticmethod
    def fingerprint(data: bytes) -> str:
        if not data:
            return "empty:0"
        head = data[: min(len(data), 512)]
        tail = data[-min(len(data), 512) :]
        h1 = zlib.crc32(head) & 0xFFFFFFFF
        h2 = zlib.adler32(tail) & 0xFFFFFFFF
        bucket = int(math.log2(max(1, len(data))))
        return f"b{bucket}:{h1:08x}:{h2:08x}"

    def observe(self, sig: str, ratio: float, raw_len: int) -> dict:
        if sig in self.records:
            rec = self.records.pop(sig)
            rec["count"] += 1
            rec["ema_ratio"] = 0.65 * rec["ema_ratio"] + 0.35 * ratio
            rec["avg_bytes"] = int(0.65 * rec["avg_bytes"] + 0.35 * raw_len)
            rec["last_ts"] = time.time()
        else:
            rec = {
                "count": 1,
                "ema_ratio": ratio,
                "avg_bytes": raw_len,
                "last_ts": time.time(),
            }
        self.records[sig] = rec
        self.records.move_to_end(sig, last=True)
        while len(self.records) > self.capacity:
            self.records.popitem(last=False)
        return dict(rec)

    def lookup(self, sig: str) -> dict | None:
        rec = self.records.get(sig)
        return dict(rec) if rec else None


class HolographicInterferenceLedger:
    """
    Phase-Locked Holographic Interference Ledger: builds a coarse structural
    interference key from sampled block CRCs, entropy deciles, and conjugate
    phase bins so near-duplicate or structurally similar payloads (such as
    evolving logs or config files) share learned compression expectations.
    """

    def __init__(self, capacity: int = 256):
        self.capacity = capacity
        self.cells: OrderedDict[str, dict] = OrderedDict()

    @staticmethod
    def interference_key(data: bytes, features: dict[str, float], conjugate_phase: float) -> str:
        if not data:
            return "holo:empty"
        n = len(data)
        q1 = data[: min(n, 256)]
        mid_start = max(0, (n // 2) - 128)
        q2 = data[mid_start : min(n, mid_start + 256)]
        c1 = zlib.crc32(q1) & 0xFFFF
        c2 = zlib.crc32(q2) & 0xFFFF
        ent_bin = int(max(0, min(15, features.get("entropy", 0.0) * 2.0)))
        rep_bin = int(max(0, min(9, features.get("repetition", 0.0) * 10.0)))
        conj_bin = int(((conjugate_phase % (2.0 * math.pi)) / (2.0 * math.pi)) * 8.0) % 8
        return f"H{ent_bin:x}R{rep_bin:x}P{conj_bin}:{c1:04x}{c2:04x}"

    def register_and_measure(self, key: str, ratio: float) -> tuple[float, int]:
        if key in self.cells:
            cell = self.cells.pop(key)
            interference_score = max(
                0.0,
                min(1.0, 1.0 - abs(cell["ema_ratio"] - ratio) / max(1.0, cell["ema_ratio"] + ratio)),
            )
            cell["hits"] += 1
            cell["ema_ratio"] = 0.60 * cell["ema_ratio"] + 0.40 * ratio
            cell["last_interference"] = interference_score
            cell["ts"] = time.time()
        else:
            interference_score = 0.0
            cell = {
                "hits": 1,
                "ema_ratio": ratio,
                "last_interference": 0.0,
                "ts": time.time(),
            }
        self.cells[key] = cell
        self.cells.move_to_end(key, last=True)
        while len(self.cells) > self.capacity:
            self.cells.popitem(last=False)
        return interference_score, int(cell["hits"])

    def peek_similarity(self, key: str) -> tuple[float, float, int]:
        cell = self.cells.get(key)
        if not cell:
            return 0.0, 1.0, 0
        return float(cell.get("last_interference", 0.5)), float(cell.get("ema_ratio", 1.0)), int(cell.get("hits", 1))


# =====================================================================
# 6X. Novel Algorithmic Mechanism: Epistemic Phase-Fold & Resonance Ledger
# =====================================================================
class EpistemicResonanceLedger:
    """
    Original multi-scale resonance & epistemic calibration engine:
    Computes constructive vs. destructive phase interference between payload
    byte-nibble geometry and harmonic phase velocity, tracks epistemic entropy
    (uncertainty vs. overconfidence), and synthesizes self-healing rollback
    directives when model predictions drift sharply from observed reality.
    """

    def __init__(self, history_limit: int = 128):
        self.lock = threading.RLock()
        self.history: deque[dict] = deque(maxlen=history_limit)
        self.resonance_index: float = 0.50
        self.epistemic_uncertainty: float = 0.45
        self.rollback_triggers: int = 0
        self.last_directive: str = "NOMINAL_LOCK"

    @staticmethod
    def compute_payload_phase(data: bytes, features: dict[str, float]) -> float:
        if not data:
            return 0.0
        digest = hashlib.blake2b(data[: min(len(data), 4096)], digest_size=8).digest()
        seed_val = int.from_bytes(digest, "little") / float(2**64)
        ent_term = (features.get("entropy", 4.0) / 8.0) * math.pi
        rep_term = features.get("repetition", 0.0) * (0.5 * math.pi)
        return (2.0 * math.pi * seed_val + ent_term + rep_term) % (2.0 * math.pi)

    def evaluate_and_update(
        self,
        data: bytes,
        features: dict[str, float],
        phase_angle: float,
        conjugate_phase: float,
        predicted_ratio: float,
        actual_ratio: float,
        confidence: float,
    ) -> dict:
        with self.lock:
            payload_phi = self.compute_payload_phase(data, features)
            constructive = math.cos(payload_phi - phase_angle)
            conjugate_alignment = math.cos(payload_phi + conjugate_phase)
            interference_gain = max(-1.0, min(1.0, 0.65 * constructive + 0.35 * conjugate_alignment))

            rel_err = abs(actual_ratio - predicted_ratio) / max(0.5, actual_ratio)
            clamped_err = max(0.0, min(2.0, rel_err))
            epistemic_tension = max(0.0, min(1.0, confidence * clamped_err))

            self.resonance_index = max(
                0.0, min(1.0, 0.72 * self.resonance_index + 0.28 * (0.5 + 0.5 * interference_gain))
            )
            self.epistemic_uncertainty = max(
                0.05, min(0.95, 0.75 * self.epistemic_uncertainty + 0.25 * max(clamped_err * 0.6, epistemic_tension))
            )

            rollback_recommended = epistemic_tension >= 0.55 and clamped_err >= 0.45
            if rollback_recommended:
                self.rollback_triggers += 1
                self.last_directive = "SHADOW_ROLLBACK_ADVISED"
            elif interference_gain >= 0.55 and self.epistemic_uncertainty < 0.45:
                self.last_directive = "CONSTRUCTIVE_HARMONIC_LOCK"
            elif interference_gain <= -0.55:
                self.last_directive = "DESTRUCTIVE_INTERFERENCE_GUARD"
            else:
                self.last_directive = "NOMINAL_LOCK"

            record = {
                "payload_phi": payload_phi,
                "interference_gain": interference_gain,
                "resonance_index": self.resonance_index,
                "epistemic_uncertainty": self.epistemic_uncertainty,
                "epistemic_tension": epistemic_tension,
                "rollback_recommended": rollback_recommended,
                "directive": self.last_directive,
                "ts": time.time(),
            }
            self.history.append(record)
            return dict(record)

    def status_summary(self) -> str:
        with self.lock:
            return (
                f"Epistemic -> res:{self.resonance_index:.2f} | unc:{self.epistemic_uncertainty*100:.0f}% | "
                f"dir:{self.last_directive} | rollbacks:{self.rollback_triggers}"
            )


# =====================================================================
# 6Z. Original Standout Mechanism: Temporal-Harmonic Phase-Fold Engine
# =====================================================================
class ChronoHarmonicPhaseFoldEngine:
    """
    Original temporal-harmonic phase-folding mechanism:
    Maps payload entropy/repetition harmonics and arrival phase intervals onto
    a folded phase angle (theta_fold in [0, 2*pi)), measures constructive vs.
    destructive phase resonance against the engine's harmonic phase, and
    modulates learning step damping + phase-slip detection.
    """

    def __init__(self, history_limit: int = 96):
        self.lock = threading.RLock()
        self.folded_phase: float = 0.0
        self.resonance_score: float = 0.0
        self.phase_slips: int = 0
        self.fold_order: int = 3
        self.trace_history: deque[dict] = deque(maxlen=history_limit)

    def fold_and_measure(
        self,
        features: dict[str, float],
        phase_angle: float,
        conjugate_phase: float,
        arrival_dt: float,
        epistemic_tension: float,
    ) -> dict:
        with self.lock:
            ent_norm = max(0.0, min(1.0, features.get("entropy", 4.0) / 8.0))
            rep_norm = max(0.0, min(1.0, features.get("repetition", 0.0)))
            cadence_phase = (2.0 * math.pi * (max(0.1, min(60.0, arrival_dt)) / 10.0)) % (2.0 * math.pi)
            raw_theta = (
                self.fold_order * (ent_norm * math.pi + rep_norm * (0.5 * math.pi))
                + 0.5 * cadence_phase
                + 0.25 * epistemic_tension * math.pi
            )
            self.folded_phase = raw_theta % (2.0 * math.pi)

            d_primary = math.cos(self.folded_phase - phase_angle)
            d_conj = math.cos(self.folded_phase + conjugate_phase)
            res = max(-1.0, min(1.0, 0.7 * d_primary + 0.3 * d_conj))
            self.resonance_score = 0.75 * self.resonance_score + 0.25 * res

            phase_slip = self.resonance_score <= -0.55
            if phase_slip:
                self.phase_slips += 1

            lr_scale = max(0.45, min(1.30, 1.0 + 0.25 * self.resonance_score - (0.20 if phase_slip else 0.0)))
            info = {
                "folded_phase": self.folded_phase,
                "resonance_score": self.resonance_score,
                "phase_slip": phase_slip,
                "phase_slips": self.phase_slips,
                "lr_scale": lr_scale,
            }
            self.trace_history.append(info)
            return dict(info)

    def summary(self) -> str:
        with self.lock:
            mode = "SLIP_GUARD" if self.resonance_score <= -0.55 else ("LOCK" if self.resonance_score >= 0.50 else "DRIFT")
            return (
                f"PhaseFold(θ={self.folded_phase:.2f}rad,res={self.resonance_score:+.2f},"
                f"slips={self.phase_slips},{mode})"
            )


# =====================================================================
# 6C. Causal Memory Simulation Engine (SCM + do-Calculus Counterfactuals)
# =====================================================================
class CausalMemorySimulationEngine:
    """
    Structural Causal Model (SCM) & counterfactual simulator for memory
    compression, HOT/COLD tiering, and GPU ring staging.
    """

    CAUSAL_EDGES: tuple[tuple[str, str], ...] = (
        ("repetition", "compression_ratio"),
        ("entropy", "compression_ratio"),
        ("vram_pressure", "stage_latency_ms"),
        ("vram_pressure", "eviction_pressure"),
        ("burst_rate", "eviction_pressure"),
        ("hot_tier_cap", "eviction_pressure"),
        ("compression_ratio", "net_ram_gain"),
        ("eviction_pressure", "net_ram_gain"),
    )

    DEFAULT_EDGE_WEIGHTS: dict[tuple[str, str], float] = {
        ("repetition", "compression_ratio"): 0.78,
        ("entropy", "compression_ratio"): -0.62,
        ("vram_pressure", "stage_latency_ms"): 0.70,
        ("vram_pressure", "eviction_pressure"): 0.55,
        ("burst_rate", "eviction_pressure"): 0.65,
        ("hot_tier_cap", "eviction_pressure"): -0.50,
        ("compression_ratio", "net_ram_gain"): 0.80,
        ("eviction_pressure", "net_ram_gain"): -0.60,
    }

    def __init__(self, history_limit: int = 128):
        self.lock = threading.RLock()
        self.edge_weights: dict[tuple[str, str], float] = dict(self.DEFAULT_EDGE_WEIGHTS)
        self.baseline_state: dict[str, float] = {
            "repetition": 0.05,
            "entropy": 4.50,
            "vram_pressure": 0.25,
            "burst_rate": 0.20,
            "hot_tier_cap": 5.0,
            "compression_ratio": 1.40,
            "stage_latency_ms": 2.0,
            "eviction_pressure": 0.20,
            "net_ram_gain": 0.30,
        }
        self.observations: deque[dict] = deque(maxlen=history_limit)
        self.interventions_run: int = 0
        self.beneficial_interventions: int = 0
        self.last_simulation: dict = {}

    @staticmethod
    def _clamp(val: float, lo: float, hi: float) -> float:
        return max(lo, min(hi, val))

    def observe_outcome(
        self,
        features: dict[str, float],
        actual_ratio: float,
        vram_pressure: float = 0.0,
        burst_mode: str = "CALM",
        hot_tier_cap: int = 5,
        stage_latency_ms: float = 2.0,
    ) -> dict:
        with self.lock:
            rep = self._clamp(float(features.get("repetition", 0.0)), 0.0, 1.0)
            ent = self._clamp(float(features.get("entropy", 4.0)), 0.0, 8.0)
            vram = self._clamp(float(vram_pressure), 0.0, 1.0)
            burst_val = {"CALM": 0.15, "STEADY": 0.35, "ACTIVE": 0.65, "BURST-LOCK": 0.92}.get(
                burst_mode, 0.25
            )
            cap_val = max(1.0, float(hot_tier_cap))
            ratio_val = self._clamp(float(actual_ratio), 0.5, 64.0)
            lat_val = max(0.05, float(stage_latency_ms))

            evict = self._clamp(0.35 * vram + 0.45 * burst_val - 0.04 * cap_val + 0.20, 0.0, 1.0)
            net_gain = self._clamp((ratio_val - 1.0) * 0.35 - evict * 0.40, -2.0, 5.0)

            curr = {
                "repetition": rep,
                "entropy": ent,
                "vram_pressure": vram,
                "burst_rate": burst_val,
                "hot_tier_cap": cap_val,
                "compression_ratio": ratio_val,
                "stage_latency_ms": lat_val,
                "eviction_pressure": evict,
                "net_ram_gain": net_gain,
            }

            lr = 0.12
            for parent, child in self.CAUSAL_EDGES:
                p_delta = curr[parent] - self.baseline_state.get(parent, curr[parent])
                c_delta = curr[child] - self.baseline_state.get(child, curr[child])
                if abs(p_delta) > 1e-4:
                    implied = self._clamp(c_delta / (abs(p_delta) + 0.25), -1.5, 1.5)
                    old_w = self.edge_weights[(parent, child)]
                    self.edge_weights[(parent, child)] = self._clamp(
                        (1.0 - lr) * old_w + lr * implied, -1.5, 1.5
                    )

            for k, v in curr.items():
                self.baseline_state[k] = 0.80 * self.baseline_state.get(k, v) + 0.20 * v

            rec = dict(curr)
            rec["ts"] = time.time()
            self.observations.append(rec)
            return rec

    def simulate_intervention(
        self,
        do_interventions: dict[str, float],
        features: dict[str, float] | None = None,
        vram_pressure: float | None = None,
        burst_mode: str = "CALM",
        hot_tier_cap: int = 5,
    ) -> dict:
        with self.lock:
            self.interventions_run += 1
            state = dict(self.baseline_state)
            if features is not None:
                state["repetition"] = self._clamp(float(features.get("repetition", state["repetition"])), 0.0, 1.0)
                state["entropy"] = self._clamp(float(features.get("entropy", state["entropy"])), 0.0, 8.0)
            if vram_pressure is not None:
                state["vram_pressure"] = self._clamp(float(vram_pressure), 0.0, 1.0)
            state["burst_rate"] = {"CALM": 0.15, "STEADY": 0.35, "ACTIVE": 0.65, "BURST-LOCK": 0.92}.get(
                burst_mode, state["burst_rate"]
            )
            state["hot_tier_cap"] = max(1.0, float(hot_tier_cap))

            baseline_gain = state["net_ram_gain"]
            fixed_vars = set(do_interventions.keys())

            for var, val in do_interventions.items():
                state[var] = float(val)

            for _ in range(2):
                if "compression_ratio" not in fixed_vars:
                    rep_eff = (state["repetition"] - self.baseline_state["repetition"]) * self.edge_weights[
                        ("repetition", "compression_ratio")
                    ]
                    ent_eff = ((state["entropy"] - self.baseline_state["entropy"]) / 8.0) * self.edge_weights[
                        ("entropy", "compression_ratio")
                    ]
                    state["compression_ratio"] = self._clamp(
                        self.baseline_state["compression_ratio"] + rep_eff * 3.0 + ent_eff * 2.5,
                        0.85,
                        64.0,
                    )

                if "stage_latency_ms" not in fixed_vars:
                    vram_eff = (state["vram_pressure"] - self.baseline_state["vram_pressure"]) * self.edge_weights[
                        ("vram_pressure", "stage_latency_ms")
                    ]
                    state["stage_latency_ms"] = max(
                        0.1, self.baseline_state["stage_latency_ms"] + vram_eff * 12.0
                    )

                if "eviction_pressure" not in fixed_vars:
                    v_ev = (state["vram_pressure"] - self.baseline_state["vram_pressure"]) * self.edge_weights[
                        ("vram_pressure", "eviction_pressure")
                    ]
                    b_ev = (state["burst_rate"] - self.baseline_state["burst_rate"]) * self.edge_weights[
                        ("burst_rate", "eviction_pressure")
                    ]
                    c_ev = (
                        (state["hot_tier_cap"] - self.baseline_state["hot_tier_cap"]) / 8.0
                    ) * self.edge_weights[("hot_tier_cap", "eviction_pressure")]
                    state["eviction_pressure"] = self._clamp(
                        self.baseline_state["eviction_pressure"] + v_ev + b_ev + c_ev,
                        0.0,
                        1.0,
                    )

                if "net_ram_gain" not in fixed_vars:
                    r_gain = (
                        (state["compression_ratio"] - self.baseline_state["compression_ratio"])
                        * self.edge_weights[("compression_ratio", "net_ram_gain")]
                        * 0.35
                    )
                    e_gain = (
                        (state["eviction_pressure"] - self.baseline_state["eviction_pressure"])
                        * self.edge_weights[("eviction_pressure", "net_ram_gain")]
                        * 0.50
                    )
                    state["net_ram_gain"] = self._clamp(
                        self.baseline_state["net_ram_gain"] + r_gain + e_gain,
                        -2.0,
                        5.0,
                    )

            delta_gain = state["net_ram_gain"] - baseline_gain
            if delta_gain > 0.02:
                self.beneficial_interventions += 1

            result = {
                "interventions": dict(do_interventions),
                "simulated_state": state,
                "baseline_net_ram_gain": baseline_gain,
                "delta_net_ram_gain": delta_gain,
                "recommended": delta_gain > 0.02,
            }
            self.last_simulation = result
            return result

    def recommend_action(
        self,
        features: dict[str, float],
        vram_pressure: float = 0.0,
        burst_mode: str = "CALM",
        current_hot_cap: int = 5,
    ) -> tuple[str, dict]:
        candidates: list[tuple[str, dict[str, float]]] = [
            ("KEEP_BASELINE", {}),
            ("SHRINK_HOT_CAP", {"hot_tier_cap": max(2.0, float(current_hot_cap - 2))}),
            ("EXPAND_HOT_CAP", {"hot_tier_cap": min(12.0, float(current_hot_cap + 2))}),
            ("DEEP_COMPRESSION_PUSH", {"compression_ratio": max(2.2, self.baseline_state["compression_ratio"] * 1.25)}),
        ]

        best_label = "KEEP_BASELINE"
        best_sim = self.simulate_intervention(
            {}, features=features, vram_pressure=vram_pressure, burst_mode=burst_mode, hot_tier_cap=current_hot_cap
        )
        best_score = best_sim["simulated_state"]["net_ram_gain"]

        for label, do_map in candidates[1:]:
            sim = self.simulate_intervention(
                do_map,
                features=features,
                vram_pressure=vram_pressure,
                burst_mode=burst_mode,
                hot_tier_cap=current_hot_cap,
            )
            score = sim["simulated_state"]["net_ram_gain"]
            if score > best_score + 0.02:
                best_score = score
                best_label = label
                best_sim = sim

        return best_label, best_sim

    def status_summary(self) -> str:
        with self.lock:
            delta = self.last_simulation.get("delta_net_ram_gain", 0.0)
            return (
                f"CausalSim -> runs:{self.interventions_run} | helpful:{self.beneficial_interventions} | "
                f"last_Δgain:{delta:+.2f} | obs:{len(self.observations)}"
            )


# =====================================================================
# 6D. Multi-Horizon Predictor & Adaptive Self-Healing Policy Controller
# =====================================================================
class PredictiveHorizonSynthesizer:
    """
    Produces multi-step (+1, +3, +5 observation) compression ratio and
    working-set decay forecasts so tiering and pre-compression can prepare ahead.
    """

    @staticmethod
    def forecast_horizons(
        current_ratio: float,
        slope: float,
        coherence: float,
        drift: float,
        turbulence: float,
    ) -> dict[str, float]:
        damping = max(0.35, min(0.95, 0.85 * coherence - 0.35 * drift - 0.25 * turbulence))
        h1 = max(0.85, min(64.0, current_ratio + slope * damping))
        h3 = max(0.85, min(64.0, h1 + 2.0 * slope * (damping**2)))
        h5 = max(0.85, min(64.0, h3 + 2.0 * slope * (damping**3)))
        return {"h1": h1, "h3": h3, "h5": h5, "damping": damping}


class AdaptivePolicyController:
    """
    Automatically tunes HOT tier slot count and minimum ratio threshold based
    on divergence alerts, self-heal counts, causal recommendations, and
    chrono-entanglement pre-staging hints.
    """

    def __init__(self, default_hot_cap: int = 5):
        self.lock = threading.RLock()
        self.default_hot_cap = max(2, default_hot_cap)
        self.current_hot_cap = self.default_hot_cap
        self.adjustments: int = 0
        self.last_note: str = "INITIAL_CAP"

    def tune_policy(
        self,
        causal_action: str,
        causal_sim: dict,
        divergence_alert: bool,
        vram_pressure: float,
        dynamic_min_ratio: float,
        chrono_delta: int = 0,
    ) -> tuple[int, float, str]:
        with self.lock:
            prev_cap = self.current_hot_cap
            new_min_ratio = dynamic_min_ratio

            if vram_pressure >= 0.85 or divergence_alert or causal_action == "SHRINK_HOT_CAP":
                self.current_hot_cap = max(2, self.current_hot_cap - 1)
                new_min_ratio = min(1.35, dynamic_min_ratio + 0.02)
                self.last_note = "TIGHTENED_FOR_PRESSURE_OR_DRIFT"
            elif causal_action == "EXPAND_HOT_CAP" and not divergence_alert and vram_pressure < 0.65:
                self.current_hot_cap = min(10, self.current_hot_cap + 1)
                self.last_note = "EXPANDED_HOT_FOR_CAUSAL_GAIN"
            else:
                sim_cap = int(round(causal_sim.get("simulated_state", {}).get("hot_tier_cap", self.current_hot_cap)))
                self.current_hot_cap = max(2, min(10, sim_cap + chrono_delta))
                self.last_note = "CHRONO_CAUSAL_STEADY" if chrono_delta else "CAUSAL_STEADY"

            if self.current_hot_cap != prev_cap or abs(new_min_ratio - dynamic_min_ratio) > 1e-6:
                self.adjustments += 1

            return self.current_hot_cap, new_min_ratio, self.last_note

    def summary(self) -> str:
        with self.lock:
            return f"PolicyCtrl(hot_cap={self.current_hot_cap},adj={self.adjustments},{self.last_note})"


# =====================================================================
# 6N. Next-Generation Cognitive, Temporal, Swarm & Graph Modules
# =====================================================================
class TemporalRealityForkEngine:
    """
    Maintains lightweight speculative branches (OPTIMISTIC_COMPRESS,
    CONSERVATIVE_LOW_OVERHEAD, BURST_PREFETCH) and scores which branch
    aligns best with observed ratios and cadence.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.branches: dict[str, dict] = {
            "OPTIMISTIC_COMPRESS": {"score": 0.55, "mult": 1.12, "forks": 0},
            "CONSERVATIVE_LOW_OVERHEAD": {"score": 0.52, "mult": 0.94, "forks": 0},
            "BURST_PREFETCH": {"score": 0.50, "mult": 1.05, "forks": 0},
        }
        self.active_fork: str = "OPTIMISTIC_COMPRESS"

    def fork_trajectories(self, base_ratio: float, features: dict[str, float], burst: str) -> dict[str, float]:
        with self.lock:
            rep = features.get("repetition", 0.0)
            ent = features.get("entropy", 4.0)
            opt = max(0.85, min(64.0, base_ratio * (1.12 + 0.25 * rep)))
            cons = max(0.85, min(64.0, base_ratio * (0.95 - max(0.0, ent - 6.8) * 0.05)))
            burst_f = max(0.85, min(64.0, base_ratio * (1.10 if burst == "BURST-LOCK" else 1.0)))
            for k in self.branches:
                self.branches[k]["forks"] += 1
            return {
                "OPTIMISTIC_COMPRESS": opt,
                "CONSERVATIVE_LOW_OVERHEAD": cons,
                "BURST_PREFETCH": burst_f,
            }

    def observe_outcome(self, actual_ratio: float, forecasts: dict[str, float]) -> str:
        with self.lock:
            best_name = self.active_fork
            best_err = float("inf")
            for name, est in forecasts.items():
                err = abs(actual_ratio - est)
                b = self.branches.setdefault(name, {"score": 0.5, "mult": 1.0, "forks": 0})
                acc = 1.0 / (1.0 + err)
                b["score"] = max(0.05, min(0.99, 0.75 * b["score"] + 0.25 * acc))
                if err < best_err:
                    best_err = err
                    best_name = name
            self.active_fork = best_name
            return best_name

    def summary(self) -> str:
        with self.lock:
            sc = self.branches.get(self.active_fork, {}).get("score", 0.5)
            return f"Fork:{self.active_fork} ({sc*100:.0f}%)"


class CognitiveShadowMemory:
    """
    Stores compact shadow snapshots of engine weights and recent observations so
    self-healing can roll back unstable weight shifts after severe prediction errors.
    """

    def __init__(self, max_snapshots: int = 16):
        self.lock = threading.RLock()
        self.snapshots: deque[dict] = deque(maxlen=max_snapshots)
        self.restores: int = 0

    def capture(self, weights: dict[str, float], coherence: float, drift: float, reason: str):
        with self.lock:
            self.snapshots.append(
                {
                    "ts": time.time(),
                    "weights": dict(weights),
                    "coherence": coherence,
                    "drift": drift,
                    "reason": reason,
                }
            )

    def rollback_if_needed(self, current_weights: dict[str, float], drift: float, error_mag: float) -> bool:
        with self.lock:
            if not self.snapshots or (drift < 0.72 and error_mag < 3.5):
                return False
            snap = self.snapshots[-1]
            for k, val in snap.get("weights", {}).items():
                if k in current_weights:
                    current_weights[k] = 0.70 * float(val) + 0.30 * float(current_weights[k])
            self.restores += 1
            return True

    def summary(self) -> str:
        with self.lock:
            return f"Shadow:{len(self.snapshots)}snaps/restores:{self.restores}"


class ConvergenceAttractorEngine:
    """
    Tracks whether adaptive learning weights and compression ratios are converging
    toward a stable attractor basin or oscillating/diverging.
    """

    def __init__(self, window: int = 24):
        self.lock = threading.RLock()
        self.errors: deque[float] = deque(maxlen=window)
        self.state: str = "SEEKING_BASIN"
        self.convergence_score: float = 0.5

    def update(self, abs_err: float) -> dict:
        with self.lock:
            self.errors.append(abs_err)
            if len(self.errors) < 4:
                return {"state": self.state, "score": self.convergence_score}
            seq = list(self.errors)
            first_half = sum(seq[: len(seq) // 2]) / max(1, len(seq) // 2)
            second_half = sum(seq[len(seq) // 2 :]) / max(1, len(seq) - len(seq) // 2)
            deltas = [seq[i] - seq[i - 1] for i in range(1, len(seq))]
            flips = sum(1 for i in range(1, len(deltas)) if deltas[i] * deltas[i - 1] < 0)
            osc_ratio = flips / max(1, len(deltas) - 1)

            if second_half <= first_half * 0.92 and osc_ratio < 0.65:
                self.state = "CONVERGING"
                self.convergence_score = min(0.99, self.convergence_score + 0.08)
            elif osc_ratio >= 0.75 and second_half > first_half:
                self.state = "OSCILLATING"
                self.convergence_score = max(0.10, self.convergence_score - 0.10)
            else:
                self.state = "STEADY_ORBIT"
                self.convergence_score = 0.5 * self.convergence_score + 0.5 * (1.0 / (1.0 + second_half))

            return {"state": self.state, "score": self.convergence_score}

    def summary(self) -> str:
        with self.lock:
            return f"Attractor:{self.state} ({self.convergence_score*100:.0f}%)"


class MemoryWeatherSystem:
    """
    Translates telemetry (file arrival cadence, entropy shifts, VRAM pressure,
    and drift) into an operational 'weather' regime that guides scan pacing and
    tier aggressiveness.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.regime: str = "CLEAR_BREEZE"
        self.turbulence: float = 0.15

    def assess(self, burst: str, vram_pressure: float, drift: float, avg_entropy: float) -> dict:
        with self.lock:
            turb = max(0.0, min(1.0, 0.35 * drift + 0.35 * vram_pressure + 0.30 * min(1.0, avg_entropy / 8.0)))
            self.turbulence = 0.65 * self.turbulence + 0.35 * turb
            if vram_pressure >= 0.85 or drift >= 0.75:
                self.regime = "THERMAL_GALE"
                interval_mult = 1.25
            elif burst == "BURST-LOCK":
                self.regime = "DATA_SQUALL"
                interval_mult = 0.75
            elif self.turbulence < 0.30:
                self.regime = "CLEAR_BREEZE"
                interval_mult = 1.0
            else:
                self.regime = "VARIABLE_FRONT"
                interval_mult = 0.95
            return {"regime": self.regime, "turbulence": self.turbulence, "interval_mult": interval_mult}

    def summary(self) -> str:
        with self.lock:
            return f"Weather:{self.regime} (turb:{self.turbulence*100:.0f}%)"


class RegretGenome:
    """
    Evolves a compact 'genome' of strategy hyperparameters (compression bias,
    prefetch aggressiveness, tier retention bias) across episodes based on
    realized compression yield minus counterfactual regret.
    """

    def __init__(self):
        self.lock = threading.RLock()
        self.genome: dict[str, float] = {
            "compression_bias": 0.55,
            "prefetch_bias": 0.50,
            "tier_retention_bias": 0.50,
        }
        self.generation: int = 0
        self.fitness: float = 0.50

    def evolve(self, actual_ratio: float, regret: float, oracle_hit: bool) -> dict:
        with self.lock:
            self.generation += 1
            reward = max(-1.0, min(1.5, (actual_ratio - 1.0) * 0.25 - regret * 0.4 + (0.2 if oracle_hit else -0.05)))
            self.fitness = max(0.05, min(0.99, 0.82 * self.fitness + 0.18 * (0.5 + 0.4 * reward)))
            step = 0.03 * reward
            self.genome["compression_bias"] = max(0.1, min(0.95, self.genome["compression_bias"] + step))
            self.genome["prefetch_bias"] = max(0.1, min(0.95, self.genome["prefetch_bias"] + (0.02 if oracle_hit else -0.01)))
            self.genome["tier_retention_bias"] = max(0.1, min(0.95, self.genome["tier_retention_bias"] + 0.5 * step))
            return {"generation": self.generation, "fitness": self.fitness, "genome": dict(self.genome)}

    def summary(self) -> str:
        with self.lock:
            return (
                f"Genome#G{self.generation} fit:{self.fitness*100:.0f}% "
                f"[c:{self.genome['compression_bias']:.2f},p:{self.genome['prefetch_bias']:.2f}]"
            )


class SyntheticCuriosityEngine:
    """
    Scores novelty (unseen structural/entropy/echo patterns) so autonomous scans
    and probes prioritize informative new payloads rather than redundant noise.
    """

    def __init__(self, seen_limit: int = 512):
        self.lock = threading.RLock()
        self.seen_keys: OrderedDict[str, int] = OrderedDict()
        self.seen_limit = seen_limit
        self.last_curiosity: float = 0.50

    def score_novelty(self, echo_sig: str, holo_key: str, features: dict[str, float]) -> float:
        with self.lock:
            composite = f"{echo_sig}|{holo_key}"
            hits = self.seen_keys.get(composite, 0) + 1
            self.seen_keys[composite] = hits
            self.seen_keys.move_to_end(composite, last=True)
            while len(self.seen_keys) > self.seen_limit:
                self.seen_keys.popitem(last=False)

            familiarity_decay = 1.0 / math.sqrt(hits)
            mid_entropy_bonus = 1.0 - abs(features.get("entropy", 4.0) - 4.5) / 4.5
            score = max(0.05, min(0.99, 0.70 * familiarity_decay + 0.30 * max(0.0, mid_entropy_bonus)))
            self.last_curiosity = score
            return score

    def summary(self) -> str:
        with self.lock:
            return f"Curiosity:{self.last_curiosity*100:.0f}% (seen:{len(self.seen_keys)})"


class MemoryConstellationGraph:
    """
    Maintains an adjacency graph linking entries that share structural keys,
    co-access sequences, or similar compression ratios, enabling neighborhood
    prefetching and cluster inspection.
    """

    def __init__(self, max_nodes: int = 256):
        self.lock = threading.RLock()
        self.max_nodes = max_nodes
        self.adj: dict[str, dict[str, float]] = {}
        self.key_to_nodes: dict[str, deque[str]] = {}

    def link_entry(self, name: str, cluster_key: str, weight: float = 1.0):
        with self.lock:
            peers = self.key_to_nodes.setdefault(cluster_key, deque(maxlen=12))
            for peer in list(peers):
                if peer != name:
                    self.adj.setdefault(name, {})[peer] = self.adj.get(name, {}).get(peer, 0.0) + weight
                    self.adj.setdefault(peer, {})[name] = self.adj.get(peer, {}).get(name, 0.0) + weight
            peers.append(name)
            while len(self.adj) > self.max_nodes:
                oldest = next(iter(self.adj))
                self.adj.pop(oldest, None)
                for nbrs in self.adj.values():
                    nbrs.pop(oldest, None)

    def neighbors(self, name: str, top_k: int = 3) -> list[tuple[str, float]]:
        with self.lock:
            nbrs = self.adj.get(name, {})
            return sorted(nbrs.items(), key=lambda kv: kv[1], reverse=True)[:top_k]

    def remove_node(self, name: str):
        with self.lock:
            self.adj.pop(name, None)
            for nbrs in self.adj.values():
                nbrs.pop(name, None)

    def clear(self):
        with self.lock:
            self.adj.clear()
            self.key_to_nodes.clear()

    def summary(self) -> str:
        with self.lock:
            edges = sum(len(v) for v in self.adj.values()) // 2
            return f"Constellation:{len(self.adj)}nodes/{edges}edges"


class SwarmConsensusEngine:
    """
    Coordinates local node telemetry with real MultiNodeMeshSync peer proposals
    and local sub-ensemble votes to reach a consensus compression/tiering stance.
    """

    def __init__(self, node_id: str | None = None, mesh_sync: MultiNodeMeshSync | None = None):
        self.lock = threading.RLock()
        self.node_id = node_id or f"node-{os.getpid()}"
        self.mesh_sync = mesh_sync
        self.peer_votes: dict[str, dict] = {}
        self.last_consensus: str = "AGREE_DEEP_LZ4"

    def submit_vote(self, peer_id: str, recommended_codec: str, confidence: float):
        with self.lock:
            self.peer_votes[peer_id] = {
                "codec": recommended_codec,
                "confidence": max(0.05, min(0.99, confidence)),
                "ts": time.time(),
            }
            if len(self.peer_votes) > 32:
                oldest = next(iter(self.peer_votes))
                self.peer_votes.pop(oldest, None)

    def resolve_consensus(self, local_codec: str, local_conf: float) -> tuple[str, float]:
        with self.lock:
            self.submit_vote(self.node_id, local_codec, local_conf)
            if self.mesh_sync is not None:
                for pid, pinfo in self.mesh_sync.peer_votes().items():
                    self.peer_votes[pid] = {
                        "codec": pinfo.get("codec", local_codec),
                        "confidence": max(0.05, min(0.99, float(pinfo.get("confidence", 0.5)))),
                        "ts": float(pinfo.get("ts", time.time())),
                    }
            tally: dict[str, float] = {}
            for vote in self.peer_votes.values():
                c = vote["codec"]
                tally[c] = tally.get(c, 0.0) + vote["confidence"]
            winner = max(tally.items(), key=lambda kv: kv[1])[0] if tally else local_codec
            total_w = sum(tally.values()) or 1.0
            agreement = tally.get(winner, local_conf) / total_w
            self.last_consensus = f"{winner} ({agreement*100:.0f}%)"
            return winner, agreement

    def summary(self) -> str:
        with self.lock:
            return f"Swarm:{self.last_consensus} [peers:{len(self.peer_votes)}]"


class RealityDivergenceMonitor:
    """
    Detects sustained divergence between predicted trajectories/ratios and actual
    runtime behavior, flagging anomalies for self-healing and logging.
    """

    def __init__(self, threshold: float = 0.65):
        self.lock = threading.RLock()
        self.threshold = threshold
        self.divergence_score: float = 0.0
        self.alerts: int = 0

    def observe(self, predicted_ratio: float, actual_ratio: float, drift_index: float) -> dict:
        with self.lock:
            norm_err = min(1.5, abs(actual_ratio - predicted_ratio) / max(0.5, predicted_ratio))
            inst = max(0.0, min(1.0, 0.60 * (norm_err / 1.5) + 0.40 * drift_index))
            self.divergence_score = max(0.0, min(1.0, 0.70 * self.divergence_score + 0.30 * inst))
            alert = self.divergence_score >= self.threshold
            if alert:
                self.alerts += 1
            return {"divergence": self.divergence_score, "alert": alert, "alerts": self.alerts}

    def summary(self) -> str:
        with self.lock:
            flag = "ALERT" if self.divergence_score >= self.threshold else "OK"
            return f"Divergence:{self.divergence_score*100:.0f}% [{flag}/a:{self.alerts}]"


# =====================================================================
# 6P. Reusable AI Pipeline Helpers (VRAM Throttle, RAG, Chat, Dedup)
# =====================================================================
class VRAMThrottleAdvisor:
    """Translates GPUHardwareInspector telemetry into safe AI context/batch scaling."""

    @staticmethod
    def recommend_limits(hw: dict, base_context_tokens: int = 8192, base_batch_size: int = 8) -> dict:
        pressure = float(hw.get("vram_pressure", 0.0))
        profile = hw.get("profile", "HOST_FALLBACK")
        if pressure >= 0.85 or profile == "TIGHT_VRAM":
            scale = 0.5
            batch = max(1, base_batch_size // 4)
            action = "THROTTLE_AGGRESSIVE"
        elif pressure >= 0.65:
            scale = 0.75
            batch = max(1, base_batch_size // 2)
            action = "THROTTLE_MODERATE"
        else:
            scale = 1.0
            batch = base_batch_size
            action = "NOMINAL"
        return {
            "action": action,
            "context_tokens": max(512, int(base_context_tokens * scale)),
            "batch_size": batch,
            "vram_pressure": pressure,
        }


class RAGPrefetchPlanner:
    """Uses PredictiveWorkingSetOracle + DistributedMemoryGraphDB to rank prefetch docs."""

    def __init__(self, oracle: "PredictiveWorkingSetOracle", graph: DistributedMemoryGraphDB):
        self.oracle = oracle
        self.graph = graph

    def plan_prefetch(self, current_doc: str | None = None, limit: int = 3) -> list[str]:
        suggestions: list[str] = []
        pred_name, _prob, top_k = self.oracle.predict_next_entry()
        if pred_name:
            suggestions.append(pred_name)
        for cand, _sc in top_k:
            if cand not in suggestions:
                suggestions.append(cand)
        if current_doc:
            for item in self.graph.query_neighborhood(current_doc, depth=1, top_k=limit):
                nbr = item.get("node")
                if nbr and nbr not in suggestions:
                    suggestions.append(nbr)
        return suggestions[:limit]


class ConversationTierManager:
    """Keeps recent turns uncompressed while compressing older turns with zlib/lz4."""

    def __init__(self, keep_recent_turns: int = 6, lz4_module=None, lz4_available: bool = False):
        self.keep_recent_turns = max(1, keep_recent_turns)
        self.lz4_module = lz4_module
        self.lz4_available = lz4_available
        self.turns: list[dict] = []

    def add_turn(self, role: str, content: str):
        raw = content.encode("utf-8")
        self.turns.append({"role": role, "raw": raw, "zipped": None, "codec": "RAW"})
        self._tier_turns()

    def _tier_turns(self):
        cutoff = max(0, len(self.turns) - self.keep_recent_turns)
        for i, t in enumerate(self.turns):
            if i < cutoff and t["zipped"] is None and len(t["raw"]) > 256:
                if self.lz4_available and self.lz4_module is not None:
                    t["zipped"] = self.lz4_module.compress(t["raw"], compression_level=0)
                    t["codec"] = "lz4"
                else:
                    t["zipped"] = zlib.compress(t["raw"], level=6)
                    t["codec"] = "zlib"
                t["raw"] = b""

    def stats(self) -> dict:
        hot_b = sum(len(t["raw"]) for t in self.turns if t["zipped"] is None)
        cold_b = sum(len(t["zipped"]) for t in self.turns if t["zipped"] is not None)
        return {"turns": len(self.turns), "hot_bytes": hot_b, "cold_bytes": cold_b}


class DatasetDeduplicator:
    """Filters near-duplicate payloads using ResonantEchoLedger and HolographicInterferenceLedger."""

    def __init__(self, echo_ledger: ResonantEchoLedger, holo_ledger: HolographicInterferenceLedger):
        self.echo_ledger = echo_ledger
        self.holo_ledger = holo_ledger

    def is_near_duplicate(
        self, data: bytes, features: dict[str, float], conjugate_phase: float, sim_threshold: float = 0.85
    ) -> tuple[bool, str]:
        sig = self.echo_ledger.fingerprint(data)
        echo_hit = self.echo_ledger.lookup(sig)
        holo_key = self.holo_ledger.interference_key(data, features, conjugate_phase)
        sim, _ema, hits = self.holo_ledger.peek_similarity(holo_key)
        if echo_hit and echo_hit.get("count", 0) >= 2 and sim >= sim_threshold:
            return True, f"Echo+Holo duplicate (hits={echo_hit['count']}, sim={sim*100:.0f}%)"
        if hits >= 3 and sim >= 0.92:
            return True, f"High holographic similarity (hits={hits}, sim={sim*100:.0f}%)"
        return False, "Unique / novel payload"


# =====================================================================
# 6R. HarmonicPhaseEngine (Causal + Phase-Fold + ChronoEntangle + Suite)
# =====================================================================
class HarmonicPhaseEngine:
    """
    Combines momentum-smoothed adaptive weights, coupled phase oscillators,
    phase-conjugate stride forecasting, resonant signature echo memory,
    holographic interference similarity, counterfactual regret tracking,
    causal do-calculus simulation, multi-horizon forecasting, policy tuning,
    temporal-harmonic phase folding, and chrono-causal entanglement.
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
        "video_stride_gain": 0.30,
        "privilege_gain": 0.20,
        "interference_gain": 0.25,
        "stability_gain": 0.18,
    }

    ADAPTABLE_KEYS = (
        "intercept",
        "entropy_penalty",
        "repetition_bonus",
        "log_size_bonus",
        "harmonic_weight",
        "coupling_strength",
        "video_stride_gain",
        "privilege_gain",
        "interference_gain",
        "stability_gain",
    )

    def __init__(self, weights_path: str = WEIGHTS_FILE, mesh_sync: MultiNodeMeshSync | None = None):
        self.lock = threading.RLock()
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
        self.conjugate_phase = 0.0
        self.phase_velocity = 0.45
        self.order_parameter = 0.50
        self.coherence = 0.50
        self.drift_index = 0.0
        self.last_interference = 0.0
        self.prev_entropy = 4.0
        self.prev_ratio = 1.0
        self.arrival_times: list[float] = []
        self.size_history: list[int] = []
        self.ratio_history: list[float] = []

        self.echo_ledger = ResonantEchoLedger()
        self.holo_ledger = HolographicInterferenceLedger()
        self.epistemic_ledger = EpistemicResonanceLedger()
        self.phase_fold_engine = ChronoHarmonicPhaseFoldEngine()
        self.causal_engine = CausalMemorySimulationEngine()
        self.chrono_entangler = ChronoEntanglementEngine()
        self.horizon_synthesizer = PredictiveHorizonSynthesizer()
        self.policy_controller = AdaptivePolicyController(default_hot_cap=5)
        self.fork_engine = TemporalRealityForkEngine()
        self.shadow_memory = CognitiveShadowMemory()
        self.attractor_engine = ConvergenceAttractorEngine()
        self.weather_system = MemoryWeatherSystem()
        self.regret_genome = RegretGenome()
        self.curiosity_engine = SyntheticCuriosityEngine()
        self.constellation_graph = MemoryConstellationGraph()
        self.graph_db = DistributedMemoryGraphDB(shards=4)
        self.swarm_consensus = SwarmConsensusEngine(mesh_sync=mesh_sync)
        self.divergence_monitor = RealityDivergenceMonitor()

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
        with self.lock:
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
                    self.conjugate_phase = float(
                        data.get("conjugate_phase", (-self.phase_angle) % (2.0 * math.pi))
                    )
                    self.phase_velocity = float(data.get("phase_velocity", 0.45))
                    self.coherence = float(data.get("coherence", 0.50))
                    self.order_parameter = float(data.get("order_parameter", self.coherence))
                    self.drift_index = float(data.get("drift_index", 0.0))
                    self.last_interference = float(data.get("last_interference", 0.0))
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
        with self.lock:
            payload = {
                "weights": dict(self.weights),
                "momentum": dict(self.momentum),
                "observations": self.observations,
                "mae_history": self.mae_history[-50:],
                "dynamic_min_ratio": self.dynamic_min_ratio,
                "phase_angle": self.phase_angle,
                "entropy_phase": self.entropy_phase,
                "repetition_phase": self.repetition_phase,
                "conjugate_phase": self.conjugate_phase,
                "phase_velocity": self.phase_velocity,
                "coherence": self.coherence,
                "order_parameter": self.order_parameter,
                "drift_index": self.drift_index,
                "last_interference": self.last_interference,
                "cumulative_regret": self.cumulative_regret,
                "codec_yield_scores": dict(self.codec_yield_scores),
            }
            target = self.weights_path
        try:
            tmp_path = f"{target}.{os.getpid()}.{threading.get_ident()}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_path, target)
            return f"Saved AI + Phase-Lock weights to {target}."
        except Exception as exc:
            with self.lock:
                self.self_heal_events += 1
            return f"[Self-Heal] Failed to save AI weights ({exc})."

    def reset_weights(self) -> str:
        with self.lock:
            self.weights = dict(self.DEFAULT_WEIGHTS)
            self.momentum = {k: 0.0 for k in self.ADAPTABLE_KEYS}
            self.observations = 0
            self.mae_history.clear()
            self.last_deltas = {k: 0.0 for k in self.DEFAULT_WEIGHTS}
            self.dynamic_min_ratio = 1.00
            self.phase_angle = 0.0
            self.entropy_phase = 0.35
            self.repetition_phase = 0.70
            self.conjugate_phase = 0.0
            self.phase_velocity = 0.45
            self.coherence = 0.50
            self.order_parameter = 0.50
            self.drift_index = 0.0
            self.last_interference = 0.0
            self.size_history.clear()
            self.ratio_history.clear()
            self.echo_ledger.records.clear()
            self.holo_ledger.cells.clear()
            self.constellation_graph.clear()
            self.graph_db.clear()
            self.cumulative_regret = 0.0
            self.last_regret = 0.0
            self.codec_yield_scores = {
                "lz4-default (level 0)": 1.0,
                "lz4-hc (level 9)": 1.0,
                "zlib (level 6)": 1.0,
            }
            return "Reset AI + Phase-Lock weights, holographic ledger & momentum state to baseline priors."

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
        with self.lock:
            phases = (self.phase_angle, self.entropy_phase, self.repetition_phase)
            mean_cos = sum(math.cos(p) for p in phases) / len(phases)
            mean_sin = sum(math.sin(p) for p in phases) / len(phases)
            return max(0.0, min(1.0, math.hypot(mean_cos, mean_sin)))

    def harmonic_term(self, features: dict[str, float]) -> float:
        with self.lock:
            r_sync = self.kuramoto_order_parameter()
            phase_wave = (
                0.65 * math.cos(self.phase_angle) + 0.35 * math.cos(self.repetition_phase - self.entropy_phase)
            ) * (0.5 * self.coherence + 0.5 * r_sync)
            conjugate_lock = (
                0.15
                + self.weights.get("video_stride_gain", 0.30) * math.cos(self.phase_angle + self.conjugate_phase)
            )
            holo_term = self.weights.get("interference_gain", 0.25) * self.last_interference * math.cos(
                self.conjugate_phase
            )
            fold_term = 0.12 * self.phase_fold_engine.resonance_score
            chrono_term = 0.10 * self.chrono_entangler.last_forecast.get("horizon_shift", 0.0)
            bigram_bonus = features.get("bigram_run", 0.0) * 0.65
            spectral_bonus = features.get("spectral_balance", 0.0) * 0.40
            redundancy_lock = (
                (features["repetition"] * 2.0)
                + bigram_bonus
                + spectral_bonus
                - max(0.0, (features["entropy"] - 6.5) * 0.25)
            )
            return self.weights["harmonic_weight"] * (
                phase_wave + redundancy_lock + conjugate_lock + holo_term + fold_term + chrono_term
            )

    def forecast_burst(self) -> str:
        with self.lock:
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

    def predict_next_trajectory(
        self,
        features: dict[str, float],
        echo_sig: str | None = None,
        holo_key: str | None = None,
    ) -> dict[str, float]:
        with self.lock:
            base_pred = self.predict_ratio(features)
            if len(self.ratio_history) >= 2:
                recent_ratios = self.ratio_history[-5:]
                slope = (recent_ratios[-1] - recent_ratios[0]) / max(1, len(recent_ratios) - 1)
            else:
                slope = 0.0

            echo_rec = self.echo_ledger.lookup(echo_sig) if echo_sig else None
            echo_hint = 0.0
            if echo_rec and echo_rec["count"] >= 2:
                echo_hint = 0.25 * (echo_rec["ema_ratio"] - base_pred)

            holo_sim, holo_ema, holo_hits = (
                self.holo_ledger.peek_similarity(holo_key) if holo_key else (0.0, base_pred, 0)
            )
            holo_hint = 0.18 * holo_sim * (holo_ema - base_pred) if holo_hits >= 1 else 0.0

            phase_lead = math.cos(self.phase_angle + 0.5 * self.phase_velocity)
            conjugate_assist = 0.12 * self.weights.get("video_stride_gain", 0.30) * math.sin(self.conjugate_phase)
            chrono_shift = self.chrono_entangler.last_forecast.get("horizon_shift", 0.0) * 0.45
            lookahead_ratio = max(
                0.85,
                min(
                    64.0,
                    base_pred
                    + self.weights["lookahead_gain"] * slope * phase_lead
                    + conjugate_assist
                    + echo_hint
                    + holo_hint
                    + chrono_shift,
                ),
            )

            if echo_rec and echo_rec["count"] >= 2:
                next_size_est = float(echo_rec["avg_bytes"])
            elif len(self.size_history) >= 2:
                s_prev, s_curr = self.size_history[-2], self.size_history[-1]
                growth_factor = max(0.25, min(4.0, (s_curr + 1.0) / max(1.0, float(s_prev))))
                next_size_est = float(s_curr * growth_factor)
            else:
                next_size_est = float(10 ** max(0.0, features.get("log_size", 1.0)))

            if len(self.arrival_times) >= 2:
                deltas = [
                    self.arrival_times[i] - self.arrival_times[i - 1] for i in range(1, len(self.arrival_times))
                ]
                avg_dt = max(0.5, min(60.0, sum(deltas[-6:]) / len(deltas[-6:])))
            else:
                avg_dt = 3.0

            horizons = self.horizon_synthesizer.forecast_horizons(
                current_ratio=lookahead_ratio,
                slope=slope,
                coherence=self.coherence,
                drift=self.drift_index,
                turbulence=self.weather_system.turbulence,
            )

            return {
                "next_ratio": lookahead_ratio,
                "h3_ratio": horizons["h3"],
                "h5_ratio": horizons["h5"],
                "ratio_slope": slope,
                "next_size_bytes": next_size_est,
                "eta_sec": avg_dt,
                "conjugate_phase": self.conjugate_phase,
                "echo_hits": float(echo_rec["count"]) if echo_rec else 0.0,
                "holo_similarity": holo_sim,
                "holo_hits": float(holo_hits),
            }

    def predict_ratio(self, features: dict[str, float]) -> float:
        with self.lock:
            raw_pred = (
                self.weights["intercept"]
                + self.weights["entropy_penalty"] * features["entropy"]
                + self.weights["repetition_bonus"] * features["repetition"]
                + self.weights["log_size_bonus"] * features["log_size"]
                + self.harmonic_term(features)
            )
            return max(0.85, min(64.0, raw_pred))

    def confidence_score(self, features: dict[str, float], pred_ratio: float) -> float:
        with self.lock:
            sample_factor = min(1.0, self.observations / 15.0)
            recent_mae = (sum(self.mae_history[-10:]) / len(self.mae_history[-10:])) if self.mae_history else 0.6
            error_factor = 1.0 / (1.0 + recent_mae)
            harmonic_factor = 0.4 * self.coherence + 0.3 * self.order_parameter + 0.3
            drift_penalty = max(0.0, 1.0 - 0.5 * self.drift_index)
            epistemic_damp = max(0.5, 1.0 - 0.35 * self.epistemic_ledger.epistemic_uncertainty)
            holo_boost = 0.08 * self.last_interference
            signal_factor = 0.65 + 0.35 * min(1.0, abs(pred_ratio - 1.0) / 3.0 + features["repetition"])
            raw_conf = (
                0.25 * sample_factor
                + 0.35 * error_factor
                + 0.20 * harmonic_factor
                + 0.20 * signal_factor
                + holo_boost
            ) * drift_penalty * epistemic_damp
            return max(0.10, min(0.99, raw_conf))

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

        with self.lock:
            yield_snapshot = dict(self.codec_yield_scores)

        for name, level in candidates:
            t0 = time.perf_counter()
            try:
                if level is not None:
                    out = lz4_module.compress(sample, compression_level=level)
                else:
                    out = zlib.compress(sample, level=6)
                dt_ms = max(0.01, (time.perf_counter() - t0) * 1000.0)
                ratio = sample_len / max(1, len(out))
                learned_prior = yield_snapshot.get(name, 1.0)
                latency_penalty = (dt_ms * 0.03) if features["entropy"] > 7.2 else (dt_ms * 0.008)
                utility = (ratio * 0.75) + (learned_prior * 0.35) - latency_penalty
                scores[name] = (ratio, len(out))
                if ratio > best_sample_ratio:
                    best_sample_ratio = ratio
                if utility > best_utility:
                    best_utility = utility
                    best_codec = name
            except Exception:
                with self.lock:
                    self.self_heal_events += 1
                continue

        chosen_ratio = scores.get(best_codec, (1.0, sample_len))[0]
        regret = max(0.0, best_sample_ratio - chosen_ratio)
        with self.lock:
            self.last_regret = regret
            self.cumulative_regret += regret

        summary = ", ".join(f"{k}:{v[0]:.2f}x" for k, v in scores.items())
        return (
            best_codec,
            scores,
            f"Counterfactual probe [{summary}] -> '{best_codec}' (regret={regret:.2f}x).",
        )

    def recommend_mode(
        self,
        features: dict[str, float],
        lz4_available: bool,
        vram_pressure: float = 0.0,
        echo_sig: str | None = None,
        holo_key: str | None = None,
        confidence: float = 0.65,
    ) -> tuple[str, str]:
        pred = self.predict_ratio(features)
        traj = self.predict_next_trajectory(features, echo_sig=echo_sig, holo_key=holo_key)
        with self.lock:
            coh = self.coherence
            comp_bias = self.regret_genome.genome.get("compression_bias", 0.55)
        if not lz4_available:
            local_codec, local_why = "zlib (level 6)", "LZ4 unavailable; using zlib fallback."
        elif vram_pressure >= 0.80 and features["entropy"] < 7.4:
            local_codec, local_why = (
                "lz4-hc (level 9)",
                f"High VRAM pressure ({vram_pressure*100:.0f}%); deeper compression to save transfer.",
            )
        elif features["entropy"] >= 7.65 and features["repetition"] < 0.03:
            local_codec, local_why = "lz4-fast (level 0)", "High-entropy stream; fast low-overhead LZ4 pass."
        elif (
            pred >= (2.35 - 0.35 * comp_bias)
            or traj["next_ratio"] >= 2.35
            or traj.get("h3_ratio", 0.0) >= 2.40
            or traj.get("echo_hits", 0.0) >= 2.0
            or traj.get("holo_similarity", 0.0) >= 0.78
            or features["repetition"] >= 0.18
            or coh >= 0.75
        ):
            local_codec, local_why = "lz4-hc (level 9)", "High redundancy / holographic echo or phase lock; deep LZ4 matching."
        else:
            local_codec, local_why = "lz4-default (level 0)", "Balanced payload; standard inline LZ4 frame."

        consensus_codec, agree_ratio = self.swarm_consensus.resolve_consensus(local_codec, confidence)
        return consensus_codec, f"{local_why} | Swarm={consensus_codec} ({agree_ratio*100:.0f}%)."

    def think_and_adapt(
        self,
        features: dict[str, float],
        predicted_ratio: float,
        actual_ratio: float,
        used_codec: str | None = None,
        vram_pressure: float = 0.0,
        is_elevated: bool = False,
        raw_len: int = 0,
        echo_sig: str | None = None,
        holo_key: str | None = None,
        raw_bytes: bytes = b"",
        entry_name: str = "",
        oracle_hit: bool = False,
        auto_policy_tune: bool = True,
    ) -> str:
        with self.lock:
            now = time.time()
            arrival_dt = (now - self.arrival_times[-1]) if self.arrival_times else 3.0
            self.arrival_times.append(now)
            self.arrival_times = self.arrival_times[-30:]

            raw_est = raw_len if raw_len > 0 else int(10 ** max(0.0, features.get("log_size", 0.0)))
            self.size_history.append(raw_est)
            self.size_history = self.size_history[-30:]
            self.ratio_history.append(actual_ratio)
            self.ratio_history = self.ratio_history[-30:]

            if echo_sig:
                self.echo_ledger.observe(echo_sig, actual_ratio, raw_est)

            clamped_actual = max(0.85, min(64.0, actual_ratio))
            if holo_key:
                holo_sim, _holo_hits = self.holo_ledger.register_and_measure(holo_key, clamped_actual)
            else:
                holo_sim = 0.0
            self.last_interference = holo_sim

            curiosity_val = self.curiosity_engine.score_novelty(
                echo_sig or "", holo_key or "", features
            )
            if entry_name and holo_key:
                self.constellation_graph.link_entry(entry_name, holo_key, weight=max(0.2, 1.0 - abs(holo_sim - 0.5)))
                self.graph_db.upsert_node(
                    entry_name,
                    {
                        "holo_key": holo_key,
                        "ratio": round(clamped_actual, 2),
                        "entropy": round(features.get("entropy", 0.0), 2),
                    },
                )

            delta_ent = abs(features["entropy"] - self.prev_entropy)
            self.prev_entropy = features["entropy"]
            k_coup = self.weights["coupling_strength"]

            d_ent_phase = 0.30 + min(0.8, delta_ent * 0.15) + k_coup * math.sin(self.phase_angle - self.entropy_phase)
            d_rep_phase = 0.40 + min(1.1, features["repetition"] * 2.8) + k_coup * math.sin(
                self.phase_angle - self.repetition_phase
            )
            raw_step = (
                0.45
                + min(1.2, features["repetition"] * 3.0)
                - min(0.5, delta_ent * 0.12)
                + 0.5 * k_coup * (
                    math.sin(self.entropy_phase - self.phase_angle)
                    + math.sin(self.repetition_phase - self.phase_angle)
                )
            )
            self.phase_velocity = 0.7 * self.phase_velocity + 0.3 * raw_step

            self.entropy_phase = (self.entropy_phase + d_ent_phase) % (2.0 * math.pi)
            self.repetition_phase = (self.repetition_phase + d_rep_phase) % (2.0 * math.pi)
            self.phase_angle = (self.phase_angle + self.phase_velocity) % (2.0 * math.pi)
            self.conjugate_phase = (-self.phase_angle) % (2.0 * math.pi)
            self.order_parameter = self.kuramoto_order_parameter()

            error = clamped_actual - predicted_ratio
            abs_err = abs(error)
            self.mae_history.append(abs_err)
            self.observations += 1

            if len(self.mae_history) >= 8:
                recent_m = sum(self.mae_history[-5:]) / 5.0
                prior_m = sum(self.mae_history[:-5]) / max(1, len(self.mae_history) - 5)
                self.drift_index = max(0.0, min(1.0, (recent_m - prior_m) / max(0.25, prior_m + 0.25)))
            else:
                self.drift_index = max(0.0, min(1.0, abs_err / 4.0))

            accuracy_signal = 1.0 / (1.0 + abs_err)
            sync_signal = 0.7 * accuracy_signal + 0.3 * self.order_parameter
            self.coherence = max(0.10, min(0.99, 0.76 * self.coherence + 0.24 * sync_signal))

            burst_mode = self.forecast_burst()
            forks = self.fork_engine.fork_trajectories(predicted_ratio, features, burst_mode)
            self.fork_engine.observe_outcome(clamped_actual, forks)
            self.attractor_engine.update(abs_err)
            self.weather_system.assess(burst_mode, vram_pressure, self.drift_index, features.get("entropy", 4.0))
            self.regret_genome.evolve(clamped_actual, self.last_regret, oracle_hit=oracle_hit)
            div_info = self.divergence_monitor.observe(predicted_ratio, clamped_actual, self.drift_index)

            self.causal_engine.observe_outcome(
                features=features,
                actual_ratio=clamped_actual,
                vram_pressure=vram_pressure,
                burst_mode=burst_mode,
                hot_tier_cap=self.policy_controller.current_hot_cap,
            )
            c_action, c_sim = self.causal_engine.recommend_action(
                features=features,
                vram_pressure=vram_pressure,
                burst_mode=burst_mode,
                current_hot_cap=self.policy_controller.current_hot_cap,
            )
            chrono_info = self.chrono_entangler.step_entanglement(
                features=features,
                causal_delta_gain=float(c_sim.get("delta_net_ram_gain", 0.0)),
                actual_ratio=clamped_actual,
                predicted_ratio=predicted_ratio,
                now=now,
            )

            conf_now = self.confidence_score(features, predicted_ratio)
            epistemic_rec = self.epistemic_ledger.evaluate_and_update(
                data=raw_bytes,
                features=features,
                phase_angle=self.phase_angle,
                conjugate_phase=self.conjugate_phase,
                predicted_ratio=predicted_ratio,
                actual_ratio=clamped_actual,
                confidence=conf_now,
            )

            fold_info = self.phase_fold_engine.fold_and_measure(
                features=features,
                phase_angle=self.phase_angle,
                conjugate_phase=self.conjugate_phase,
                arrival_dt=arrival_dt,
                epistemic_tension=epistemic_rec.get("epistemic_tension", 0.0),
            )
            if fold_info.get("phase_slip"):
                self.self_heal_events += 1

            if self.coherence >= 0.65 and self.drift_index < 0.35 and (self.observations % 5 == 0):
                self.shadow_memory.capture(
                    self.weights, self.coherence, self.drift_index, reason=f"obs#{self.observations}"
                )

            if used_codec:
                clean_codec = used_codec.replace(" [healed]", "")
                prev_score = self.codec_yield_scores.get(clean_codec, 1.0)
                self.codec_yield_scores[clean_codec] = max(0.25, min(8.0, 0.8 * prev_score + 0.2 * clamped_actual))

            regret_boost = min(0.5, self.last_regret * 0.25)
            drift_boost = 0.4 * self.drift_index
            error_boost = 1.0 + min(1.5, abs_err * self.weights["gain_sensitivity"]) + regret_boost + drift_boost
            eff_lr = (
                (self.weights["base_lr"] * error_boost * fold_info["lr_scale"])
                / (1.0 + 0.015 * self.observations)
            )

            priv_delta_signal = (0.15 if is_elevated else -0.05) + 0.20 * vram_pressure
            stability_signal = (1.0 - self.drift_index) * accuracy_signal - 0.25
            grads = {
                "intercept": max(-0.6, min(0.6, eff_lr * error)),
                "entropy_penalty": max(-0.25, min(0.25, eff_lr * error * (features["entropy"] / 8.0))),
                "repetition_bonus": max(-0.4, min(0.4, eff_lr * error * min(1.5, features["repetition"] * 2.5))),
                "log_size_bonus": max(-0.15, min(0.15, eff_lr * error * min(1.0, features["log_size"] / 6.0))),
                "harmonic_weight": max(-0.2, min(0.2, eff_lr * error * math.cos(self.phase_angle))),
                "coupling_strength": max(-0.1, min(0.1, eff_lr * (self.order_parameter - 0.5) * 0.4)),
                "video_stride_gain": max(
                    -0.15, min(0.15, eff_lr * (error + 0.5 * vram_pressure) * math.cos(self.conjugate_phase))
                ),
                "privilege_gain": max(-0.12, min(0.12, eff_lr * priv_delta_signal)),
                "interference_gain": max(
                    -0.12, min(0.12, eff_lr * (holo_sim - 0.35) * math.cos(self.conjugate_phase))
                ),
                "stability_gain": max(-0.10, min(0.10, eff_lr * stability_signal)),
            }

            beta = 0.65
            for k, g in grads.items():
                self.momentum[k] = beta * self.momentum[k] + (1.0 - beta) * g

            self.weights["intercept"] = max(0.5, min(8.0, self.weights["intercept"] + self.momentum["intercept"]))
            self.weights["entropy_penalty"] = max(
                -1.8, min(0.2, self.weights["entropy_penalty"] + self.momentum["entropy_penalty"])
            )
            self.weights["repetition_bonus"] = max(
                0.0, min(6.0, self.weights["repetition_bonus"] + self.momentum["repetition_bonus"])
            )
            self.weights["log_size_bonus"] = max(
                -0.5, min(1.5, self.weights["log_size_bonus"] + self.momentum["log_size_bonus"])
            )
            self.weights["harmonic_weight"] = max(
                0.05, min(1.5, self.weights["harmonic_weight"] + self.momentum["harmonic_weight"])
            )
            self.weights["coupling_strength"] = max(
                0.05, min(0.9, self.weights["coupling_strength"] + self.momentum["coupling_strength"])
            )
            self.weights["video_stride_gain"] = max(
                0.05, min(1.5, self.weights["video_stride_gain"] + self.momentum["video_stride_gain"])
            )
            self.weights["privilege_gain"] = max(
                0.05, min(1.5, self.weights["privilege_gain"] + self.momentum["privilege_gain"])
            )
            self.weights["interference_gain"] = max(
                0.05, min(1.5, self.weights["interference_gain"] + self.momentum["interference_gain"])
            )
            self.weights["stability_gain"] = max(
                0.05, min(1.5, self.weights["stability_gain"] + self.momentum["stability_gain"])
            )

            if epistemic_rec.get("rollback_recommended") or div_info.get("alert"):
                if self.shadow_memory.rollback_if_needed(self.weights, self.drift_index, abs_err):
                    self.self_heal_events += 1

            self.last_deltas = dict(self.momentum)

            if actual_ratio >= 1.25:
                self.dynamic_min_ratio = max(0.95, self.dynamic_min_ratio - 0.01)
            elif actual_ratio < 1.0:
                self.dynamic_min_ratio = min(1.15, self.dynamic_min_ratio + 0.02)

            if auto_policy_tune:
                _cap, tuned_min_r, _note = self.policy_controller.tune_policy(
                    causal_action=c_action,
                    causal_sim=c_sim,
                    divergence_alert=bool(div_info.get("alert")),
                    vram_pressure=vram_pressure,
                    dynamic_min_ratio=self.dynamic_min_ratio,
                    chrono_delta=int(chrono_info.get("prestage_hot_delta", 0)),
                )
                self.dynamic_min_ratio = tuned_min_r

            self.prev_ratio = actual_ratio

            return (
                f"err={error:+.2f}x, coh={self.coherence:.2f}, R={self.order_parameter:.2f}, "
                f"drift={self.drift_index:.2f}, holo={holo_sim:.2f}, φ={self.phase_angle:.2f}rad "
                f"(φ*={self.conjugate_phase:.2f}rad, v={self.phase_velocity:+.2f}), "
                f"cur={curiosity_val*100:.0f}%, {self.chrono_entangler.summary()}, {self.phase_fold_engine.summary()}, "
                f"{self.causal_engine.status_summary()} [do->{c_action}], {self.policy_controller.summary()}, "
                f"{self.epistemic_ledger.status_summary()}, {self.fork_engine.summary()}, "
                f"{self.attractor_engine.summary()}, {self.weather_system.summary()}, "
                f"{self.regret_genome.summary()}, {self.graph_db.summary()}, "
                f"{self.swarm_consensus.summary()}, {self.divergence_monitor.summary()}, "
                f"{self.shadow_memory.summary()}, min_ratio->{self.dynamic_min_ratio:.2f}x"
            )


# =====================================================================
# 6A. Predictive Working-Set Oracle (Sequence, Cadence & HOT-RAM Scorer)
# =====================================================================
class PredictiveWorkingSetOracle:
    """
    Works alongside HarmonicPhaseEngine to learn entry access sequences,
    co-access windows, access frequency, recency, and recurring intervals.
    """

    def __init__(self, oracle_path: str = ORACLE_FILE):
        self.lock = threading.RLock()
        self.oracle_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), oracle_path)
        self.entry_profiles: dict[str, dict] = {}
        self.transitions: dict[str, dict[str, float]] = {}
        self.recent_window: list[str] = []
        self.last_accessed_name: str | None = None
        self.last_predicted_name: str | None = None
        self.last_predicted_prob: float = 0.0
        self.predictions_made: int = 0
        self.predictions_hit: int = 0
        self.predictions_miss: int = 0
        self.oracle_confidence: float = 0.55
        self.blend_weights: dict[str, float] = {
            "seq_weight": 0.42,
            "interval_weight": 0.25,
            "recency_weight": 0.18,
            "frequency_weight": 0.15,
        }
        self.load_oracle()

    def load_oracle(self) -> str:
        with self.lock:
            if not os.path.exists(self.oracle_path):
                return "Initialized Predictive Working-Set Oracle (fresh sequence & interval model)."
            try:
                with open(self.oracle_path, "r", encoding="utf-8") as f:
                    raw = json.load(f)
                if not isinstance(raw, dict):
                    return "Oracle state format unexpected; using fresh priors."

                prof = raw.get("entry_profiles", {})
                if isinstance(prof, dict):
                    self.entry_profiles = {
                        str(k): {
                            "count": int(v.get("count", 1)),
                            "last_ts": float(v.get("last_ts", time.time())),
                            "ema_interval_sec": float(v.get("ema_interval_sec", 5.0)),
                            "interval_samples": int(v.get("interval_samples", 0)),
                            "co_hits": float(v.get("co_hits", 0.0)),
                        }
                        for k, v in prof.items()
                        if isinstance(v, dict)
                    }

                trans = raw.get("transitions", {})
                if isinstance(trans, dict):
                    cleaned_trans: dict[str, dict[str, float]] = {}
                    for src, dsts in trans.items():
                        if isinstance(dsts, dict):
                            cleaned_trans[str(src)] = {
                                str(dk): float(dv) for dk, dv in dsts.items() if isinstance(dv, (int, float))
                            }
                    self.transitions = cleaned_trans

                win = raw.get("recent_window", [])
                if isinstance(win, list):
                    self.recent_window = [str(x) for x in win[-16:]]

                self.last_accessed_name = raw.get("last_accessed_name")
                self.last_predicted_name = raw.get("last_predicted_name")
                self.last_predicted_prob = float(raw.get("last_predicted_prob", 0.0))
                self.predictions_made = int(raw.get("predictions_made", 0))
                self.predictions_hit = int(raw.get("predictions_hit", 0))
                self.predictions_miss = int(raw.get("predictions_miss", 0))
                self.oracle_confidence = max(0.10, min(0.99, float(raw.get("oracle_confidence", 0.55))))

                bw = raw.get("blend_weights", {})
                if isinstance(bw, dict):
                    for k in self.blend_weights:
                        if k in bw and isinstance(bw[k], (int, float)):
                            self.blend_weights[k] = max(0.05, min(0.85, float(bw[k])))

                acc = (self.predictions_hit / max(1, self.predictions_made)) * 100.0
                return (
                    f"Loaded Working-Set Oracle ({len(self.entry_profiles)} entries, "
                    f"acc={acc:.0f}%, conf={self.oracle_confidence*100:.0f}%)."
                )
            except Exception as exc:
                return f"[Self-Heal] Oracle state reset after load error ({exc})."

    def save_oracle(self) -> str:
        with self.lock:
            payload = {
                "entry_profiles": dict(self.entry_profiles),
                "transitions": {k: dict(v) for k, v in self.transitions.items()},
                "recent_window": list(self.recent_window[-16:]),
                "last_accessed_name": self.last_accessed_name,
                "last_predicted_name": self.last_predicted_name,
                "last_predicted_prob": self.last_predicted_prob,
                "predictions_made": self.predictions_made,
                "predictions_hit": self.predictions_hit,
                "predictions_miss": self.predictions_miss,
                "oracle_confidence": self.oracle_confidence,
                "blend_weights": dict(self.blend_weights),
            }
            target = self.oracle_path
        try:
            tmp_path = f"{target}.{os.getpid()}.{threading.get_ident()}.tmp"
            with open(tmp_path, "w", encoding="utf-8") as f:
                json.dump(payload, f, indent=2)
            os.replace(tmp_path, target)
            return f"Saved Working-Set Oracle state to {target}."
        except Exception as exc:
            return f"[Self-Heal] Failed saving Working-Set Oracle state ({exc})."

    def reset_oracle(self) -> str:
        with self.lock:
            self.entry_profiles.clear()
            self.transitions.clear()
            self.recent_window.clear()
            self.last_accessed_name = None
            self.last_predicted_name = None
            self.last_predicted_prob = 0.0
            self.predictions_made = 0
            self.predictions_hit = 0
            self.predictions_miss = 0
            self.oracle_confidence = 0.55
            self.blend_weights = {
                "seq_weight": 0.42,
                "interval_weight": 0.25,
                "recency_weight": 0.18,
                "frequency_weight": 0.15,
            }
            return "Reset Predictive Working-Set Oracle sequence, interval & confidence priors."

    def register_entry(self, name: str, now: float | None = None):
        ts = now if now is not None else time.time()
        with self.lock:
            if name not in self.entry_profiles:
                self.entry_profiles[name] = {
                    "count": 1,
                    "last_ts": ts,
                    "ema_interval_sec": 5.0,
                    "interval_samples": 0,
                    "co_hits": 0.0,
                }
            else:
                self.entry_profiles[name]["last_ts"] = ts

    def remove_entry(self, name: str):
        with self.lock:
            self.entry_profiles.pop(name, None)
            self.transitions.pop(name, None)
            for _src, dsts in self.transitions.items():
                dsts.pop(name, None)
            self.recent_window = [x for x in self.recent_window if x != name]
            if self.last_accessed_name == name:
                self.last_accessed_name = None
            if self.last_predicted_name == name:
                self.last_predicted_name = None

    def clear_entries(self):
        with self.lock:
            self.entry_profiles.clear()
            self.transitions.clear()
            self.recent_window.clear()
            self.last_accessed_name = None
            self.last_predicted_name = None

    def _interval_due_score_locked(self, name: str, now: float) -> float:
        prof = self.entry_profiles.get(name)
        if not prof:
            return 0.2
        samples = int(prof.get("interval_samples", 0))
        ema_iv = max(0.5, float(prof.get("ema_interval_sec", 5.0)))
        elapsed = max(0.0, now - float(prof.get("last_ts", now)))
        if samples <= 0:
            return math.exp(-elapsed / 12.0)
        rel_diff = abs(elapsed - ema_iv) / max(1.0, ema_iv)
        return max(0.05, min(1.0, math.exp(-0.85 * rel_diff)))

    def predict_next_entry(
        self,
        candidates: list[str] | None = None,
        harmonic_engine: HarmonicPhaseEngine | None = None,
        now: float | None = None,
    ) -> tuple[str | None, float, list[tuple[str, float]]]:
        ts = now if now is not None else time.time()
        with self.lock:
            pool = list(candidates) if candidates is not None else list(self.entry_profiles.keys())
            pool = [c for c in pool if c in self.entry_profiles]
            if not pool:
                return None, 0.0, []

            prev = self.last_accessed_name
            next_map = self.transitions.get(prev, {}) if prev else {}
            total_trans = sum(next_map.values()) if next_map else 0.0
            max_count = max((float(self.entry_profiles[c].get("count", 1)) for c in pool), default=1.0)

            coh_boost = 0.0
            if harmonic_engine is not None:
                with harmonic_engine.lock:
                    coh_boost = 0.12 * (harmonic_engine.coherence - 0.5)

            scored: list[tuple[str, float]] = []
            for name in pool:
                prof = self.entry_profiles[name]
                seq_prob = (next_map.get(name, 0.0) / total_trans) if total_trans > 0.0 else 0.0
                win_bonus = 0.15 if name in self.recent_window[-4:] and name != prev else 0.0
                iv_score = self._interval_due_score_locked(name, ts)
                elapsed = max(0.0, ts - float(prof.get("last_ts", ts)))
                rec_score = math.exp(-elapsed / 15.0)
                freq_score = math.log1p(float(prof.get("count", 1))) / max(0.693, math.log1p(max_count))

                bw = self.blend_weights
                raw_score = (
                    bw["seq_weight"] * (seq_prob + win_bonus)
                    + bw["interval_weight"] * iv_score
                    + bw["recency_weight"] * rec_score
                    + bw["frequency_weight"] * freq_score
                    + coh_boost
                )
                scored.append((name, max(0.0, min(1.0, raw_score))))

            scored.sort(key=lambda item: item[1], reverse=True)
            best_name, best_score = scored[0]
            return best_name, best_score, scored[:3]

    def record_access(
        self,
        name: str,
        harmonic_engine: HarmonicPhaseEngine | None = None,
        now: float | None = None,
    ) -> dict:
        ts = now if now is not None else time.time()
        with self.lock:
            outcome = "NO_PRIOR_PRED"
            if self.last_predicted_name is not None and self.predictions_made > 0:
                if self.last_predicted_name == name:
                    self.predictions_hit += 1
                    outcome = "HIT"
                    step = 0.045 * (1.1 - self.oracle_confidence)
                    self.oracle_confidence = max(0.15, min(0.99, self.oracle_confidence + step))
                    self.blend_weights["seq_weight"] = min(0.65, self.blend_weights["seq_weight"] + 0.015)
                else:
                    self.predictions_miss += 1
                    outcome = "MISS"
                    penalty = 0.06 * max(0.35, self.last_predicted_prob)
                    self.oracle_confidence = max(0.12, min(0.99, self.oracle_confidence - penalty))
                    self.blend_weights["seq_weight"] = max(0.15, self.blend_weights["seq_weight"] - 0.015)
                    self.blend_weights["interval_weight"] = min(0.45, self.blend_weights["interval_weight"] + 0.01)

            prof = self.entry_profiles.get(name)
            if prof is None:
                prof = {
                    "count": 1,
                    "last_ts": ts,
                    "ema_interval_sec": 5.0,
                    "interval_samples": 0,
                    "co_hits": 0.0,
                }
                self.entry_profiles[name] = prof
            else:
                prev_ts = float(prof.get("last_ts", ts))
                dt = max(0.05, min(3600.0, ts - prev_ts))
                if int(prof.get("count", 0)) >= 1:
                    if int(prof.get("interval_samples", 0)) == 0:
                        prof["ema_interval_sec"] = dt
                    else:
                        prof["ema_interval_sec"] = 0.70 * float(prof["ema_interval_sec"]) + 0.30 * dt
                    prof["interval_samples"] = int(prof.get("interval_samples", 0)) + 1
                prof["count"] = int(prof.get("count", 0)) + 1
                prof["last_ts"] = ts

            if self.last_accessed_name is not None and self.last_accessed_name != name:
                src = self.last_accessed_name
                dst_map = self.transitions.setdefault(src, {})
                dst_map[name] = dst_map.get(name, 0.0) + 1.0
                if len(dst_map) > 32:
                    weakest = min(dst_map.items(), key=lambda kv: kv[1])[0]
                    dst_map.pop(weakest, None)
                prof["co_hits"] = float(prof.get("co_hits", 0.0)) + 1.0
                if harmonic_engine is not None:
                    harmonic_engine.constellation_graph.link_entry(src, name, weight=1.0)
                    harmonic_engine.graph_db.link(src, name, relation="oracle_transition", weight=1.0)

            self.recent_window.append(name)
            self.recent_window = self.recent_window[-16:]
            self.last_accessed_name = name

            next_name, next_prob, top_k = self.predict_next_entry(
                candidates=list(self.entry_profiles.keys()),
                harmonic_engine=harmonic_engine,
                now=ts,
            )
            if next_name is not None:
                self.last_predicted_name = next_name
                self.last_predicted_prob = next_prob
                self.predictions_made += 1
            else:
                self.last_predicted_name = None
                self.last_predicted_prob = 0.0

            acc = (self.predictions_hit / max(1, self.predictions_made)) * 100.0
            return {
                "outcome": outcome,
                "oracle_conf": self.oracle_confidence,
                "accuracy_pct": acc,
                "next_name": next_name,
                "next_prob": next_prob,
                "top_k": top_k,
                "ema_interval_sec": float(prof.get("ema_interval_sec", 5.0)),
                "count": int(prof.get("count", 1)),
            }

    def rank_hot_candidates(
        self,
        entries: list[CompressedEntry],
        harmonic_engine: HarmonicPhaseEngine | None = None,
        now: float | None = None,
    ) -> list[tuple[CompressedEntry, float]]:
        ts = now if now is not None else time.time()
        with self.lock:
            _pred_name, _pred_prob, top_k = self.predict_next_entry(
                candidates=[e.name for e in entries],
                harmonic_engine=harmonic_engine,
                now=ts,
            )
            pred_map = dict(top_k)
            max_hits = max((e.hits for e in entries), default=1)
            phase_sync = 0.0
            if harmonic_engine is not None:
                with harmonic_engine.lock:
                    phase_sync = 0.15 * harmonic_engine.coherence * math.cos(harmonic_engine.phase_angle)

            ranked: list[tuple[CompressedEntry, float]] = []
            for e in entries:
                prof = self.entry_profiles.get(e.name, {})
                next_boost = pred_map.get(e.name, 0.0) * (0.6 + 0.6 * self.oracle_confidence)
                iv_due = self._interval_due_score_locked(e.name, ts) * 0.35
                age = max(0.1, ts - float(prof.get("last_ts", e.last_used)))
                recency = 1.0 / (1.0 + math.log1p(age))
                freq = math.log1p(max(1, e.hits)) / max(0.693, math.log1p(max(1, max_hits)))
                base_rel = min(1.0, e.relevance_score(ts) / 12.0)

                score = (
                    0.32 * base_rel
                    + 0.28 * next_boost
                    + 0.16 * iv_due
                    + 0.14 * recency
                    + 0.10 * freq
                    + phase_sync
                )
                ranked.append((e, score))

            ranked.sort(key=lambda pair: pair[1], reverse=True)
            return ranked

    def status_summary(self) -> str:
        with self.lock:
            acc = (self.predictions_hit / max(1, self.predictions_made)) * 100.0
            nxt = f"{self.last_predicted_name} ({self.last_predicted_prob*100:.0f}%)" if self.last_predicted_name else "none"
            return (
                f"Oracle -> next:{nxt} | conf:{self.oracle_confidence*100:.0f}% | "
                f"acc:{acc:.0f}% ({self.predictions_hit}/{self.predictions_miss}) | tracked:{len(self.entry_profiles)}"
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
        video_info: dict | None = None,
        hw_summary: str = "",
        priv_summary: str = "",
        echo_hits: float = 0.0,
        holo_sim: float = 0.0,
        oracle_summary: str = "",
        compute_info: dict | None = None,
    ) -> list[str]:
        comp_txt = ""
        if compute_info:
            comp_txt = f" | Offload:{compute_info.get('backend','HOST')}({compute_info.get('elapsed_ms',0.0):.2f}ms)"
        lines = [
            f"[CoT 1 - Perceive '{name}'] entropy={feats['entropy']:.2f} b/B, "
            f"rep={feats['repetition']*100:.1f}%, bigram={feats.get('bigram_run', 0.0)*100:.1f}%, "
            f"nibble_skew={feats.get('spectral_balance', 0.0):.2f}, log10(size)={feats['log_size']:.2f}, "
            f"echo_hits={int(echo_hits)}, holo_sim={holo_sim*100:.0f}% | {priv_summary}{comp_txt}",
            f"[CoT 2 - Multi-Horizon & Fork Forecast] pred={pred_ratio:.2f}x (conf={conf*100:.0f}%), "
            f"h+1~{traj['next_ratio']:.2f}x, h+3~{traj.get('h3_ratio', traj['next_ratio']):.2f}x, "
            f"h+5~{traj.get('h5_ratio', traj['next_ratio']):.2f}x (slope={traj['ratio_slope']:+.2f}), "
            f"φ*={traj.get('conjugate_phase', 0.0):.2f}rad, cadence={burst} (eta~{traj['eta_sec']:.1f}s)"
            + (f" | {oracle_summary}" if oracle_summary else ""),
        ]
        for step in codec_trace:
            lines.append(f"[CoT 3 - Counterfactual/Swarm/Codec] {step}")
        if video_info and video_info.get("active"):
            lines.append(
                f"[CoT 3B - Video Ring Stage] {video_info['frame_id']} -> {video_info['bank']} "
                f"@ {video_info['offset']:,}B (stride={video_info['stride_bytes']}B, "
                f"profile={video_info.get('profile', 'STANDARD')}, Video=ON) | {hw_summary}"
            )
        else:
            bank_reason = video_info.get("bank", "BYPASSED") if video_info else "BYPASSED"
            lines.append(
                f"[CoT 3B - Video Ring Stage] {bank_reason} (Video={'ON' if video_info else 'OFF'}) | {hw_summary}"
            )
        lines.append(
            f"[CoT 4 - Chrono-Causal, Phase-Fold & Self-Heal Synthesis -> {mode_tag} {slot_id} ({zone} @ {slot_offset:,}B, "
            f"align={'256B' if harmonic_align else '64B'})] actual={actual_ratio:.2f}x | {adapt_summary}"
        )
        return lines


# =====================================================================
# 7. 24/7 Autonomous + Predictive + Self-Healing Background Worker
# =====================================================================
class AutonomousBackplaneWorker:
    """
    Runs continuously in the background on a daemon thread using immutable
    config snapshots from the UI thread, predictive cadence & weather pacing,
    fault quarantine & recovery, workflow rules, mesh sync, and cleanup.
    """

    def __init__(self, app: "MemoryZipGUI"):
        self.app = app
        self._stop_event = threading.Event()
        self._wake_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._seen_signatures: OrderedDict[str, tuple[int, float]] = OrderedDict()
        self._sig_lock = threading.RLock()
        self.watchdog = SelfHealWatchdog(fault_threshold=3, base_cooldown_sec=20.0)
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
            snap = self.app.get_worker_config_snapshot()
            self._tick(snap=snap, source_tag="MANUAL-SCAN")
        except Exception as exc:
            self.healed_count += 1
            self.app.threat_matrix.record("IO_FAULT_SPIKE", 0.55, str(exc))
            self.app.post_log(f"[Manual Scan][Self-Heal] Recovered from error: {exc}")

    def _prune_deleted_signatures(self):
        with self._sig_lock:
            if len(self._seen_signatures) < 100:
                return
            stale = [p for p in list(self._seen_signatures.keys())[:150] if not os.path.exists(p)]
            for p in stale:
                self._seen_signatures.pop(p, None)
            while len(self._seen_signatures) > 2048:
                self._seen_signatures.popitem(last=False)
        if stale:
            self.healed_count += len(stale)
            self.app.post_log(f"[Auto-Heal Daemon] Pruned {len(stale)} deleted/moved file signatures.")

    def _run_loop(self):
        self.app.post_log("[Autonomous AI] 24/7 predictive, causal, workflow & self-healing loop active.")
        while not self._stop_event.is_set():
            self.cycles += 1
            snap = self.app.get_worker_config_snapshot()
            try:
                self._tick(snap=snap, source_tag="AUTO-AI")
                if snap["auto_heal_daemon"]:
                    self._prune_deleted_signatures()
                    self.watchdog.active_quarantine_count()
                    self.app.threat_matrix.decay(0.95)
                self.app.run_workflow_and_mesh_tick()
            except Exception as exc:
                self.healed_count += 1
                self.app.threat_matrix.record("IO_FAULT_SPIKE", 0.65, str(exc))
                self.app.post_log(f"[Autonomous AI][Self-Heal] Cycle #{self.cycles} recovered: {exc}")

            interval = snap["poll_interval"]
            if snap["predictive_lookahead"]:
                burst = self.app.ai_engine.forecast_burst()
                weather_mult = self.app.ai_engine.weather_system.assess(
                    burst,
                    float(self.app.gpu_pipeline.last_hw.get("vram_pressure", 0.0)),
                    self.app.ai_engine.drift_index,
                    self.app.ai_engine.prev_entropy,
                )["interval_mult"]
                if burst == "BURST-LOCK":
                    interval = max(0.5, interval * 0.65 * weather_mult)
                elif burst == "CALM" and self.cycles > 2:
                    interval = min(3600.0, interval * 1.15 * weather_mult)
                else:
                    interval = max(0.5, min(3600.0, interval * weather_mult))
            self._wake_event.wait(timeout=interval)
            self._wake_event.clear()
        self.app.post_log("[Autonomous AI] Background loop paused.")

    def _iter_candidate_files(self, roots: list[str], skip_exts: set[str], auto_heal: bool, max_files_per_cycle: int = 25):
        found = 0
        skip_dirs = {
            ".git",
            "__pycache__",
            "node_modules",
            "$Recycle.Bin",
            "System Volume Information",
            "Windows",
            "Library",
            "proc",
            "sys",
            "dev",
        }
        for root_path in roots:
            if not root_path or not os.path.isdir(root_path):
                continue
            if auto_heal and self.watchdog.is_quarantined(root_path):
                continue
            try:
                walker = os.walk(root_path, onerror=lambda _e: None)
            except Exception:
                self.healed_count += 1
                self.app.threat_matrix.record("IO_FAULT_SPIKE", 0.55, f"Walk fault on {root_path}")
                if auto_heal:
                    streak, cd = self.watchdog.record_fault(root_path)
                    if cd is not None:
                        self.app.post_log(
                            f"[Self-Heal Watchdog] Quarantined path '{root_path}' for {cd:.0f}s after {streak} walk faults."
                        )
                continue
            for current_dir, dirnames, filenames in walker:
                if self._stop_event.is_set():
                    return
                dirnames[:] = [d for d in dirnames if d not in skip_dirs]
                for fname in sorted(filenames):
                    if self._stop_event.is_set():
                        return
                    if skip_exts and os.path.splitext(fname)[1].lower() in skip_exts:
                        continue
                    fpath = os.path.join(current_dir, fname)
                    if auto_heal and self.watchdog.is_quarantined(fpath):
                        continue
                    yield fpath
                    found += 1
                    if found >= max_files_per_cycle:
                        return

    def _tick(self, snap: dict, source_tag: str = "AUTO-AI"):
        roots = snap["roots"]
        if not roots:
            return

        max_file_bytes = snap["max_file_bytes"]
        skip_exts = snap["skip_exts"]
        auto_heal = snap["auto_heal_daemon"]
        ingested_any = False

        for fpath in self._iter_candidate_files(roots, skip_exts=skip_exts, auto_heal=auto_heal):
            if self._stop_event.is_set():
                break

            try:
                st = os.stat(fpath)
            except OSError:
                continue

            sig = (st.st_size, st.st_mtime)
            with self._sig_lock:
                already_seen = self._seen_signatures.get(fpath) == sig
            if source_tag == "AUTO-AI" and already_seen:
                continue

            if st.st_size == 0 or st.st_size > max_file_bytes:
                with self._sig_lock:
                    self._seen_signatures[fpath] = sig
                continue

            try:
                data = read_file_chunked(fpath, max_file_bytes)
                if auto_heal and self.watchdog.record_success(fpath):
                    self.healed_count += 1
                    self.app.post_log(f"[Self-Heal Watchdog] Recovered readable file '{fpath}'.")
            except Exception:
                self.healed_count += 1
                self.app.threat_matrix.record("IO_FAULT_SPIKE", 0.60, f"Read fault on {fpath}")
                if auto_heal:
                    streak, cd = self.watchdog.record_fault(fpath)
                    if cd is not None:
                        self.app.post_log(
                            f"[Self-Heal Watchdog] Quarantined '{fpath}' for {cd:.0f}s after {streak} read faults."
                        )
                continue

            with self._sig_lock:
                self._seen_signatures[fpath] = sig
            ingested_any = True
            label = f"{'auto' if source_tag == 'AUTO-AI' else 'scan'}:{os.path.basename(fpath)}"
            self.app.post_ui_ingest(label, data, autonomous=(source_tag == "AUTO-AI"))

        if ingested_any and source_tag == "AUTO-AI":
            self.app.post_auto_rebalance_if_enabled()


# =====================================================================
# 8. Main GUI Application (Tabbed Compact Layout + All Next-Gen Systems)
# =====================================================================
class MemoryZipGUI:
    HOT_TIER_MAX_ITEMS = 5

    def __init__(
        self,
        root: tk.Tk,
        initial_watch_dir: str | None = None,
        privilege_sentinel: PrivilegeSentinel | None = None,
    ):
        self.root = root
        self.privilege_sentinel = privilege_sentinel or PrivilegeSentinel()
        self.privilege_sentinel.detect_admin()

        priv_badge = "ADMIN" if self.privilege_sentinel.is_admin else "USER"
        self.root.title(
            f"On-the-Fly Memory Zip Store [{priv_badge}] — Phase-Lock AI, ChronoEntangle, Mesh, GraphDB, RAG, Threat & Web"
        )
        self.root.geometry("1240x900")

        self.state_lock = threading.RLock()

        self.autoloader = LibraryAutoloader()
        self.lz4_ready = self.autoloader.bootstrap()
        self.backbone = SystemBackbone(self.autoloader)
        self.planner = MemoryPlacementPlanner()
        self.gpu_inspector = GPUHardwareInspector(cache_ttl_sec=4.0)
        self.gpu_pipeline = GPUCardPipeline(self.gpu_inspector, self.autoloader)

        self.event_bus = EventBrokerBus()
        self.mesh_sync = MultiNodeMeshSync(enable_socket=False)
        self.threat_matrix = ThreatAnomalyMatrix()
        self.workflow_engine = WorkflowAutomationEngine(broker=self.event_bus)
        self.llm_rag = LocalLLMRAGBridge()
        self.plugin_registry = PluginRegistry()

        self.ai_engine = HarmonicPhaseEngine(mesh_sync=self.mesh_sync)
        self.oracle = PredictiveWorkingSetOracle()
        self.rag_prefetcher = RAGPrefetchPlanner(self.oracle, self.ai_engine.graph_db)
        self.deduplicator = DatasetDeduplicator(self.ai_engine.echo_ledger, self.ai_engine.holo_ledger)
        self.session = SessionMemoryStore()
        self.session_msg = self.session.load()

        self.store: OrderedDict[str, CompressedEntry] = OrderedDict()
        self.counter = 1
        self.initial_watch_dir = initial_watch_dir
        self.az_vars: dict[str, tk.BooleanVar] = {}
        self.az_checks: dict[str, ttk.Checkbutton] = {}

        self.web_panel = WebControlPanelServer(
            state_provider=self.get_web_status_snapshot,
            command_handler=self.handle_web_command,
            host="127.0.0.1",
            port=8765,
        )
        self.web_panel_started = self.web_panel.start() if bool(self.session.data.get("web_panel_enabled", True)) else False

        self.worker = AutonomousBackplaneWorker(self)

        self._build_ui()
        loaded_plugins = self.plugin_registry.discover_and_load(
            {"app": self, "bus": self.event_bus, "graph_db": self.ai_engine.graph_db}
        )
        if loaded_plugins:
            self._log_reasoning(f"[Plugins] Loaded: {', '.join(loaded_plugins)}")

        self._apply_saved_session()
        self._refresh_drives()
        self._seed_startup_reasoning()
        self._refresh_threat_ui()
        self._refresh_stats()
        self._update_live_prediction()

        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

        self.worker.start()
        self._sync_auto_status_ui()
        self._sync_video_toggle_ui()
        self._save_session_now()

    def get_web_status_snapshot(self) -> dict:
        with self.state_lock:
            entries = list(self.store.values())
            total_raw = sum(e.raw_len for e in entries)
            total_active = sum(e.active_bytes_len for e in entries)
        with self.ai_engine.lock:
            coh = self.ai_engine.coherence
            obs = self.ai_engine.observations
            chrono_txt = self.ai_engine.chrono_entangler.summary()
        return {
            "entries": len(entries),
            "raw_bytes": total_raw,
            "active_bytes": total_active,
            "coherence": round(coh, 3),
            "observations": obs,
            "chrono_entanglement": chrono_txt,
            "threat": self.threat_matrix.summary(),
            "workflow": self.workflow_engine.summary(),
            "mesh": self.mesh_sync.summary(),
            "graph_db": self.ai_engine.graph_db.summary(),
            "events_published": self.event_bus.published_count,
        }

    def handle_web_command(self, path: str, body: dict) -> dict:
        if path == "/api/scan":
            self.root.after(0, self._manual_scan_now)
            return {"ok": True, "queued": "manual_scan"}
        if path == "/api/tier":
            self.root.after(0, self._tier_and_optimize_memory)
            return {"ok": True, "queued": "tier_optimize"}
        if path == "/api/rag":
            q = str(body.get("query") or "memory compression state")
            snippets = self._collect_rag_snippets()
            return {"ok": True, "rag": self.llm_rag.query_rag(q, snippets)}
        return {"ok": False, "error": "unknown_command", "path": path}

    def _collect_rag_snippets(self) -> list[tuple[str, str]]:
        out: list[tuple[str, str]] = []
        with self.state_lock:
            for e in list(self.store.values())[-6:]:
                try:
                    raw, _ = self._decompress_with_heal(e.zipped, e.codec, e.crc32)
                    out.append((e.name, raw.decode("utf-8", errors="replace")[:400]))
                except Exception:
                    out.append((e.name, f"slot={e.slot_id} zone={e.zone} codec={e.codec}"))
        return out

    def run_workflow_and_mesh_tick(self):
        with self.ai_engine.lock:
            obs = self.ai_engine.observations
            coh = self.ai_engine.coherence
            div = self.ai_engine.divergence_monitor.divergence_score
            codec = self.ai_engine.swarm_consensus.last_consensus.split(" ")[0]
            conf = self.oracle.oracle_confidence
        with self.state_lock:
            ent_cnt = len(self.store)
        pressure = float(self.gpu_pipeline.last_hw.get("vram_pressure", 0.0))
        self.mesh_sync.broadcast_state(
            {"codec": codec, "confidence": conf, "coherence": coh, "entries": ent_cnt}
        )
        self.workflow_engine.evaluate(
            {"vram_pressure": pressure, "divergence": div, "observations": obs},
            {
                "TIER_OPTIMIZE": lambda: self.root.after(0, self._tier_and_optimize_memory),
                "SCRUB_AND_HEAL": lambda: self.root.after(0, self._scrub_and_heal_entries),
                "SAVE_STATE": lambda: self.ai_engine.save_weights(),
            },
        )
        self.root.after(0, self._refresh_threat_ui)

    def get_active_hot_cap(self) -> int:
        if hasattr(self, "causal_tiering_var") and self.causal_tiering_var.get():
            return max(2, min(10, int(self.ai_engine.policy_controller.current_hot_cap)))
        return self.HOT_TIER_MAX_ITEMS

    def get_worker_config_snapshot(self) -> dict:
        """Thread-safe snapshot of UI scan configuration for background workers."""
        return {
            "roots": self.get_scan_roots(),
            "poll_interval": self.get_poll_interval(),
            "max_file_bytes": self.get_max_file_bytes(),
            "skip_exts": self.get_skip_extensions(),
            "predictive_lookahead": bool(self.predictive_lookahead_var.get()),
            "auto_heal_daemon": bool(self.auto_heal_daemon_var.get()),
        }

    def _build_ui(self):
        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(main)
        self.notebook.pack(fill=tk.BOTH, expand=True)

        self.front_tab = ttk.Frame(self.notebook, padding=8)
        self.drives_tab = ttk.Frame(self.notebook, padding=8)
        self.ai_tab = ttk.Frame(self.notebook, padding=8)
        self.ops_tab = ttk.Frame(self.notebook, padding=8)

        self.notebook.add(self.front_tab, text="Memory & Actions")
        self.notebook.add(self.drives_tab, text="Drives & Scan Filters")
        self.notebook.add(self.ai_tab, text="AI, Causal, Oracle, CoT & Self-Heal")
        self.notebook.add(self.ops_tab, text="Threat Matrix, RAG, Mesh & Workflow")

        self._build_front_tab(self.front_tab)
        self._build_drives_tab(self.drives_tab)
        self._build_ai_tab(self.ai_tab)
        self._build_ops_tab(self.ops_tab)

    def _build_ops_tab(self, parent: ttk.Frame):
        tm_frame = ttk.LabelFrame(parent, text="Threat Matrix & Anomaly Detection Dashboard", padding=10)
        tm_frame.pack(fill=tk.X, pady=(0, 8))

        self.threat_summary_lbl = ttk.Label(tm_frame, text="Threat:NOMINAL (0%)  |  Workflows: 3 rules / 0 fires")
        self.threat_summary_lbl.pack(anchor=tk.W, pady=(0, 6))

        t_cols = ("category", "level", "score")
        self.threat_tree = ttk.Treeview(tm_frame, columns=t_cols, show="headings", height=4)
        self.threat_tree.heading("category", text="Anomaly Vector")
        self.threat_tree.heading("level", text="Severity")
        self.threat_tree.heading("score", text="Risk Score")
        self.threat_tree.column("category", width=260)
        self.threat_tree.column("level", width=120, anchor=tk.CENTER)
        self.threat_tree.column("score", width=120, anchor=tk.E)
        self.threat_tree.pack(fill=tk.X)

        rag_frame = ttk.LabelFrame(parent, text="Local LLM / Extractive RAG & Distributed Graph Query", padding=10)
        rag_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 8))

        q_row = ttk.Frame(rag_frame)
        q_row.pack(fill=tk.X, pady=(0, 6))
        ttk.Label(q_row, text="RAG Prompt:").pack(side=tk.LEFT, padx=(0, 6))
        self.rag_query_var = tk.StringVar(value="Summarize high-ratio entries and recent anomalies")
        ttk.Entry(q_row, textvariable=self.rag_query_var, width=56).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(q_row, text="Run RAG Query", command=self._run_rag_ui).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(q_row, text="Broadcast Mesh Sync", command=self._broadcast_mesh_ui).pack(side=tk.LEFT)

        self.rag_out_box = scrolledtext.ScrolledText(rag_frame, height=8, wrap=tk.WORD, font=("Consolas", 9))
        self.rag_out_box.pack(fill=tk.BOTH, expand=True)

        sys_frame = ttk.LabelFrame(parent, text="Event Bus, Mesh Sync, Plugins & Web Control Panel", padding=8)
        sys_frame.pack(fill=tk.X)
        web_url = f"http://{self.web_panel.host}:{self.web_panel.port}/api/status" if self.web_panel_started else "OFF"
        self.mesh_web_lbl = ttk.Label(
            sys_frame,
            text=f"Web Panel: {web_url}  |  {self.mesh_sync.summary()}  |  {self.plugin_registry.summary()}  |  {self.ai_engine.graph_db.summary()}",
        )
        self.mesh_web_lbl.pack(anchor=tk.W)

    def _refresh_threat_ui(self):
        if not hasattr(self, "threat_tree"):
            return
        for iid in self.threat_tree.get_children():
            self.threat_tree.delete(iid)
        for row in self.threat_matrix.matrix_rows():
            self.threat_tree.insert("", tk.END, values=row)
        if hasattr(self, "threat_summary_lbl"):
            self.threat_summary_lbl.config(
                text=f"{self.threat_matrix.summary()}  |  {self.workflow_engine.summary()}  |  {self.ai_engine.chrono_entangler.summary()}"
            )
        if hasattr(self, "mesh_web_lbl"):
            web_url = f"http://{self.web_panel.host}:{self.web_panel.port}/api/status" if self.web_panel_started else "OFF"
            self.mesh_web_lbl.config(
                text=(
                    f"Web Panel: {web_url}  |  {self.mesh_sync.summary()}  |  "
                    f"{self.plugin_registry.summary()}  |  {self.ai_engine.graph_db.summary()}  |  "
                    f"Events:{self.event_bus.published_count}"
                )
            )

    def _run_rag_ui(self):
        q = self.rag_query_var.get().strip() or "memory state"
        snippets = self._collect_rag_snippets()
        res = self.llm_rag.query_rag(q, snippets)
        self.rag_out_box.insert(tk.END, f"[{res['mode']}] {res['answer']}\n")
        self.rag_out_box.see(tk.END)

    def _broadcast_mesh_ui(self):
        tx = self.mesh_sync.broadcast_state(self.get_web_status_snapshot())
        self._refresh_threat_ui()
        self._log_reasoning(f"[Mesh Sync] Dispatched state packet #{tx} ({self.mesh_sync.summary()}).")

    def _build_front_tab(self, parent: ttk.Frame):
        top_frame = ttk.LabelFrame(parent, text="Autonomous, Video Ring & Target Scope", padding=8)
        top_frame.pack(fill=tk.X, pady=(0, 8))

        r1 = ttk.Frame(top_frame)
        r1.pack(fill=tk.X)

        self.auto_status_lbl = ttk.Label(r1, text="Status: STARTING...")
        self.auto_status_lbl.pack(side=tk.LEFT, padx=(0, 6))

        self.toggle_auto_btn = ttk.Button(r1, text="Pause Autonomous", command=self._toggle_autonomous)
        self.toggle_auto_btn.pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(r1, text="Manual Scan Now", command=self._manual_scan_now).pack(side=tk.LEFT, padx=(0, 8))

        self.video_enabled_var = tk.BooleanVar(value=True)
        self.video_toggle_btn = ttk.Button(r1, text="Video: ON", command=self._toggle_video_card, width=11)
        self.video_toggle_btn.pack(side=tk.LEFT, padx=(0, 10))

        ttk.Label(r1, text="Scope:").pack(side=tk.LEFT, padx=(0, 4))
        self.drive_scope_var = tk.StringVar(value="Selected Folder")
        scope_combo = ttk.Combobox(
            r1,
            textvariable=self.drive_scope_var,
            values=["Selected Folder", "Selected Drive", "Custom Drive Combo (A-Z)", "All Detected Drives"],
            state="readonly",
            width=21,
        )
        scope_combo.pack(side=tk.LEFT, padx=(0, 6))
        scope_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_pref_changed())

        ttk.Label(r1, text="Drive:").pack(side=tk.LEFT, padx=(0, 4))
        self.drive_var = tk.StringVar(value="")
        self.drive_combo = ttk.Combobox(r1, textvariable=self.drive_var, values=[], state="readonly", width=9)
        self.drive_combo.pack(side=tk.LEFT)
        self.drive_combo.bind("<<ComboboxSelected>>", lambda _e: self._on_drive_selected())

        r2 = ttk.Frame(top_frame)
        r2.pack(fill=tk.X, pady=(6, 0))

        ttk.Label(r2, text="Target Path:").pack(side=tk.LEFT, padx=(0, 6))
        self.watch_dir_var = tk.StringVar(value="")
        watch_entry = ttk.Entry(r2, textvariable=self.watch_dir_var, width=42)
        watch_entry.pack(side=tk.LEFT, padx=(0, 6))
        watch_entry.bind("<FocusOut>", lambda _e: self._on_target_path_changed())

        ttk.Button(r2, text="Browse...", command=self._browse_watch_dir).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Label(r2, text="Item Name:").pack(side=tk.LEFT, padx=(0, 4))
        self.name_var = tk.StringVar(value="entry_1")
        ttk.Entry(r2, textvariable=self.name_var, width=16).pack(side=tk.LEFT, padx=(0, 6))

        ttk.Button(r2, text="Load File...", command=self._load_file).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(r2, text="Zip Into Memory", command=self._zip_into_memory_manual).pack(side=tk.LEFT)

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

        ttk.Label(parent, text="Assigned Host Memory Slots & Zones:").pack(anchor=tk.W)
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

        action_bar = ttk.Frame(parent)
        action_bar.pack(fill=tk.X, pady=(0, 8))

        ttk.Button(action_bar, text="Access / Unzip", command=self._unzip_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(action_bar, text="Delete Selected", command=self._delete_selected).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(action_bar, text="Clear All Memory", command=self._clear_all).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(action_bar, text="Tier & Optimize RAM", command=self._tier_and_optimize_memory).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(action_bar, text="Integrity Scrub & Heal", command=self._scrub_and_heal_entries).pack(
            side=tk.LEFT, padx=(0, 6)
        )
        ttk.Button(action_bar, text="Probe Video Card", command=self._probe_video_card_now).pack(side=tk.LEFT)

        totals_frame = ttk.LabelFrame(parent, text="Host Memory Totals, Zone Layout & Video Ring Ledger", padding=8)
        totals_frame.pack(fill=tk.X)
        self.totals_lbl = ttk.Label(
            totals_frame,
            text="Items: 0 (HOT: 0 / COLD: 0)  |  Original: 0 B  |  Active RAM: 0 B  |  Ratio: 1.00x  |  Saved: 0 B (0.0%)",
        )
        self.totals_lbl.pack(anchor=tk.W)

        self.video_status_lbl = ttk.Label(
            totals_frame,
            text="Video Ring: ON  |  Detecting GPU...",
        )
        self.video_status_lbl.pack(anchor=tk.W, pady=(3, 0))

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

        tele_frame = ttk.LabelFrame(parent, text="System RAM, GPU, Privilege & Drive Backbone Telemetry", padding=10)
        tele_frame.pack(fill=tk.X)
        self.backbone_lbl = ttk.Label(
            tele_frame,
            text="App RSS: -  |  System RAM: -  |  Free on target: -  |  Drives: -",
            wraplength=1080,
            justify=tk.LEFT,
        )
        self.backbone_lbl.pack(anchor=tk.W)

    def _build_ai_tab(self, parent: ttk.Frame):
        pred_frame = ttk.LabelFrame(
            parent, text="Phase-Lock Harmonic Engine, Causal Sim, Working-Set Oracle & Trajectory Forecast", padding=10
        )
        pred_frame.pack(fill=tk.X, pady=(0, 8))

        self.pred_lbl = ttk.Label(
            pred_frame,
            text="Entropy: 0.00 b/B  |  Repetition: 0.0%  |  Predicted: 1.00x  |  Next~1.00x  |  Conf: 0%  |  Burst: CALM  |  Policy: -",
        )
        self.pred_lbl.pack(anchor=tk.W)

        self.weights_lbl = ttk.Label(
            pred_frame,
            text="Weights -> int: 0.00, ent: 0.00, rep: 0.00, harm: 0.00, vid: 0.00, priv: 0.00, holo: 0.00 | Coh: 0.50 | Sync R: 0.50 | Drift: 0.00 | Regret: 0.00x | MinRatio: 1.00x | Updates: 0 | MAE: -",
        )
        self.weights_lbl.pack(anchor=tk.W, pady=(4, 0))

        self.oracle_lbl = ttk.Label(
            pred_frame,
            text="Oracle -> next:none | conf:55% | acc:0% (0/0) | tracked:0",
        )
        self.oracle_lbl.pack(anchor=tk.W, pady=(4, 0))

        ctrl_frame = ttk.LabelFrame(parent, text="Strategy, Video Ring, Causal/Policy & Autonomous AI Switches", padding=10)
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
        strategy_combo.pack(side=tk.LEFT, padx=(0, 10))
        strategy_combo.bind("<<ComboboxSelected>>", lambda _e: self._save_session_now())

        self.ai_video_toggle_btn = ttk.Button(cr1, text="Video: ON", command=self._toggle_video_card, width=11)
        self.ai_video_toggle_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.lean_mode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr1, text="Lean Mode", variable=self.lean_mode_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 8))

        self.show_hex_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            cr1, text="Hex View", variable=self.show_hex_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 12))

        ttk.Button(cr1, text="Run Causal Sim", command=self._run_causal_sim_now).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(cr1, text="Save Weights", command=self._save_weights_ui).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(cr1, text="Reset Weights", command=self._reset_weights_ui).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(cr1, text="Export CoT Trace", command=self._export_cot_trace).pack(side=tk.LEFT)

        cr2 = ttk.Frame(ctrl_frame)
        cr2.pack(fill=tk.X, pady=(0, 4))

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

        cr3 = ttk.Frame(ctrl_frame)
        cr3.pack(fill=tk.X)

        self.causal_tiering_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr3, text="Causal Tiering", variable=self.causal_tiering_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.auto_policy_tune_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr3, text="Auto Policy Tune", variable=self.auto_policy_tune_var, command=self._save_session_now
        ).pack(side=tk.LEFT, padx=(0, 10))

        self.predictive_horizon_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            cr3, text="Predictive Horizon (+1/+3/+5)", variable=self.predictive_horizon_var, command=self._save_session_now
        ).pack(side=tk.LEFT)

        ttk.Label(parent, text="Chain-of-Thought Reasoning, Causal Sim, Phase-Lock AI, Oracle & Self-Heal Log:").pack(
            anchor=tk.W
        )
        self.reason_box = scrolledtext.ScrolledText(parent, height=14, wrap=tk.WORD, font=("Consolas", 9))
        self.reason_box.pack(fill=tk.BOTH, expand=True, pady=(4, 0))

    # --- Causal Simulation Trigger ---
    def _run_causal_sim_now(self):
        data = self._get_current_input_bytes()
        feats = self.ai_engine.analyze_features(data)
        pressure = float(self.gpu_pipeline.last_hw.get("vram_pressure", 0.0))
        burst = self.ai_engine.forecast_burst()
        action, sim = self.ai_engine.causal_engine.recommend_action(
            features=feats,
            vram_pressure=pressure,
            burst_mode=burst,
            current_hot_cap=self.get_active_hot_cap(),
        )
        s_state = sim.get("simulated_state", {})
        self._log_reasoning(
            f"[Causal Sim] action={action} | Δnet_ram_gain={sim.get('delta_net_ram_gain', 0.0):+.2f} | "
            f"sim_ratio={s_state.get('compression_ratio', 1.0):.2f}x | "
            f"sim_evict={s_state.get('eviction_pressure', 0.0)*100:.0f}% | "
            f"sim_lat={s_state.get('stage_latency_ms', 0.0):.1f}ms | {self.ai_engine.causal_engine.status_summary()}"
        )
        self._refresh_weights_label()

    # --- Video Ring ON/OFF Toggle & Hardware Probe ---
    def _sync_video_toggle_ui(self):
        enabled = bool(self.video_enabled_var.get())
        self.gpu_pipeline.enabled = enabled
        label = "Video: ON" if enabled else "Video: OFF"
        if hasattr(self, "video_toggle_btn"):
            self.video_toggle_btn.config(text=label)
        if hasattr(self, "ai_video_toggle_btn"):
            self.ai_video_toggle_btn.config(text=label)
        self._refresh_video_status_label()

    def _toggle_video_card(self):
        new_state = not bool(self.video_enabled_var.get())
        self.video_enabled_var.set(new_state)
        self._sync_video_toggle_ui()
        self._save_session_now()
        self._log_reasoning(
            f"[Video Ring] Switched {'ON' if new_state else 'OFF'}; setting saved for reboot."
        )

    def _probe_video_card_now(self):
        hw = self.gpu_pipeline.refresh_hardware(force=True)
        self._refresh_video_status_label()
        self._refresh_backbone_telemetry()
        self._update_live_prediction()
        self._log_reasoning(
            f"[Video Probe] {self.gpu_inspector.format_summary(hw)} -> "
            f"ring_slots={hw.get('max_ring_slots')}, span={hw.get('ring_span_bytes', 0)//(1024*1024)} MiB."
        )

    def _refresh_video_status_label(self):
        if not hasattr(self, "video_status_lbl"):
            return
        with self.gpu_pipeline.lock:
            state_str = "ON" if self.gpu_pipeline.enabled else "OFF"
            hw_txt = self.gpu_inspector.format_summary(self.gpu_pipeline.last_hw)
            frames = self.gpu_pipeline.dispatched_frames
            ring_len = len(self.gpu_pipeline.ring_buffer)
            max_slots = self.gpu_pipeline.max_ring_slots
            staged = self.gpu_pipeline.staged_bytes
            saved = self.gpu_pipeline.saved_transfer_bytes
            backend = self.gpu_pipeline.last_compute_backend
            ops = self.gpu_pipeline.offload_ops
        self.video_status_lbl.config(
            text=(
                f"Video Ring: {state_str}  |  {hw_txt}  |  Compute:{backend}({ops})  |  "
                f"Frames: {frames}  |  Ring: {ring_len}/{max_slots}  |  "
                f"Staged: {staged:,} B  |  Saved: {saved:,} B"
            )
        )

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
        self._log_reasoning(
            f"[A-Z Drives] Selected all available A-Z drives: {', '.join(self.get_selected_az_drives())}."
        )

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
                        self.threat_matrix.record("INTEGRITY_DRIFT", 0.55, f"Healed CRC on {name}")
                        with self.ai_engine.lock:
                            self.ai_engine.self_heal_events += 1
                        for step in trace:
                            self._log_reasoning(f"[Integrity Scrub '{name}'] {step}")
                    if entry.tier == "HOT":
                        entry.hot_bytes = raw
                except Exception as exc:
                    repaired += 1
                    self.threat_matrix.record("INTEGRITY_DRIFT", 0.85, f"Evicted corrupt {name}: {exc}")
                    with self.ai_engine.lock:
                        self.ai_engine.self_heal_events += 1
                    self.store.pop(name, None)
                    self.oracle.remove_entry(name)
                    self.ai_engine.constellation_graph.remove_node(name)
                    self.ai_engine.graph_db.remove_node(name)
                    self._log_reasoning(f"[Integrity Scrub][Self-Heal] Evicted unrecoverable entry '{name}': {exc}")

            v_checked, v_repaired = self.gpu_pipeline.scrub_video_ring()

        self._refresh_table()
        self._refresh_stats()
        self._refresh_video_status_label()
        self._refresh_oracle_label()
        self._refresh_threat_ui()
        self._log_reasoning(
            f"[Integrity Scrub] Verified {checked} RAM entries (healed/evicted {repaired}) "
            f"and {v_checked} video ring slots (healed {v_repaired})."
        )

    def post_auto_rebalance_if_enabled(self):
        self.root.after(0, self._auto_rebalance_tick)

    def _auto_rebalance_tick(self):
        hot_cap = self.get_active_hot_cap()
        if self.auto_rebalance_var.get() and len(self.store) > hot_cap:
            with self.state_lock:
                promoted, demoted = self._rebalance_tiers_locked()
                self.gpu_pipeline.refresh_hardware()
            if promoted or demoted:
                self._refresh_table()
                self._refresh_stats()
                self._refresh_video_status_label()
                self._log_reasoning(
                    f"[Auto Tier/Heal] Balanced tiers (cap={hot_cap}, promoted={promoted}, demoted={demoted}) to keep RAM lean."
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
        self.video_enabled_var.set(bool(d.get("video_enabled", True)))
        self.causal_tiering_var.set(bool(d.get("causal_tiering", True)))
        self.auto_policy_tune_var.set(bool(d.get("auto_policy_tune", True)))
        self.predictive_horizon_var.set(bool(d.get("predictive_horizon", True)))
        self.gpu_pipeline.enabled = bool(self.video_enabled_var.get())
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
            "video_enabled": bool(self.video_enabled_var.get()),
            "causal_tiering": bool(self.causal_tiering_var.get()),
            "auto_policy_tune": bool(self.auto_policy_tune_var.get()),
            "predictive_horizon": bool(self.predictive_horizon_var.get()),
            "web_panel_enabled": bool(self.web_panel_started),
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
        self.oracle.save_oracle()
        self.worker.stop()
        self.web_panel.stop()
        self.root.destroy()

    # --- Hot/Cold Tiering & Memory Optimization (Oracle + Harmonic + Causal) ---
    def _rebalance_tiers_locked(self) -> tuple[int, int]:
        now = time.time()
        hot_cap = self.get_active_hot_cap()
        ranked_pairs = self.oracle.rank_hot_candidates(
            list(self.store.values()),
            harmonic_engine=self.ai_engine,
            now=now,
        )
        hot_names = {entry.name for entry, _score in ranked_pairs[:hot_cap]}
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
                        with self.ai_engine.lock:
                            self.ai_engine.self_heal_events += 1
                elif entry.hot_bytes is None:
                    try:
                        raw_data, _ = self._decompress_with_heal(entry.zipped, entry.codec, entry.crc32)
                        entry.hot_bytes = raw_data
                    except Exception:
                        with self.ai_engine.lock:
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
            self.gpu_pipeline.scrub_video_ring()

        collected = gc.collect()
        after_rss = self.backbone.get_process_rss_bytes()

        self._refresh_table()
        self._refresh_stats()
        self._refresh_backbone_telemetry()
        self._refresh_video_status_label()
        self._refresh_oracle_label()

        rss_msg = ""
        if before_rss is not None and after_rss is not None:
            delta_mb = (after_rss - before_rss) / (1024 ** 2)
            rss_msg = f" RSS: {before_rss / (1024 ** 2):.1f} MB -> {after_rss / (1024 ** 2):.1f} MB ({delta_mb:+.1f} MB)."

        total_heals = (
            self.ai_engine.self_heal_events + self.worker.healed_count + self.gpu_pipeline.heal_repairs
        )
        self._log_reasoning(
            f"[Tier & Optimize] cap={self.get_active_hot_cap()}, promoted {promoted} to HOT fast tier, "
            f"demoted {demoted} to COLD compressed tier, GC reclaimed {collected} objects "
            f"(heals={total_heals}, q={self.worker.watchdog.active_quarantine_count()}) | "
            f"{self.oracle.status_summary()}.{rss_msg}"
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

    def get_scan_roots(self) -> list[str]:
        scope = self.drive_scope_var.get()
        chosen = self.watch_dir_var.get().strip()
        drv = self.drive_var.get().strip()
        az_combo = self.get_selected_az_drives()

        if scope == "All Detected Drives":
            roots = self.backbone.list_drives()
            return roots or ([chosen] if chosen else [])
        if scope == "Custom Drive Combo (A-Z)":
            if az_combo:
                return az_combo
            return [drv] if drv and os.path.isdir(drv) else ([chosen] if chosen else [])
        if scope == "Selected Drive":
            if drv and os.path.isdir(drv):
                return [drv]
            return [chosen] if chosen else []
        return [chosen] if chosen else ([drv] if drv else [])

    def _refresh_backbone_telemetry(self):
        if not hasattr(self, "backbone_lbl"):
            return
        ram_txt = self.backbone.get_ram_summary()
        roots = self.get_scan_roots()
        target_for_free = roots[0] if roots else self.watch_dir_var.get().strip()
        free_txt = self.backbone.get_drive_free_text(target_for_free)
        drives_txt = ", ".join(self.backbone.list_drives()) or "none"
        az_txt = ", ".join(self.get_selected_az_drives()) or "none"
        hw_txt = self.gpu_inspector.format_summary(self.gpu_pipeline.last_hw)
        priv_txt = self.privilege_sentinel.status_message
        self.backbone_lbl.config(
            text=f"{ram_txt}  |  {free_txt}  |  Roots: {len(roots)}  |  A-Z: [{az_txt}]  |  Drives: [{drives_txt}]  |  {hw_txt}  |  {priv_txt}"
        )

    def _create_launcher(self):
        watch_path = self.watch_dir_var.get().strip()
        path = self.backbone.create_backbone_launcher(watch_path)
        self._log_reasoning(f"[Backbone] Created persistent daemon launcher at: {path}")
        messagebox.showinfo("Backbone Launcher Created", f"Launcher script saved to:\n{path}")

    # --- Autonomous control ---
    def _sync_auto_status_ui(self):
        interval = self.get_poll_interval()
        roots = self.get_scan_roots()
        scope = self.drive_scope_var.get()
        if self.worker.is_running:
            self.auto_status_lbl.config(text=f"Status: AUTO-AI ON ({interval:.1f}s | {scope} | {len(roots)} root(s))")
            self.toggle_auto_btn.config(text="Pause Autonomous")
        else:
            self.auto_status_lbl.config(text="Status: PAUSED")
            self.toggle_auto_btn.config(text="Resume Autonomous")

    def _toggle_autonomous(self):
        if self.worker.is_running:
            self.worker.stop()
            self._log_reasoning("[Autonomous AI] Paused by user.")
        else:
            self.worker.start()
            self._log_reasoning("[Autonomous AI] Resumed 24/7 background loop.")
        self._sync_auto_status_ui()
        self._save_session_now()

    def get_poll_interval(self) -> float:
        try:
            val = float(self.interval_var.get().strip())
            return max(0.5, min(3600.0, val))
        except Exception:
            return 3.0

    # --- Thread-safe bridging from worker thread to UI thread ---
    def post_log(self, msg: str):
        self.root.after(0, lambda m=msg: self._log_reasoning(m))

    def post_ui_ingest(self, name: str, data: bytes, autonomous: bool = False):
        self.root.after(0, lambda n=name, d=data, a=autonomous: self._ingest_payload(n, d, autonomous=a))

    def _seed_startup_reasoning(self):
        priv_pred = self.privilege_sentinel.predict_privilege_readiness(
            vram_pressure=float(self.gpu_pipeline.last_hw.get("vram_pressure", 0.0)),
            burst_mode=self.ai_engine.forecast_burst(),
        )
        web_url = f"http://{self.web_panel.host}:{self.web_panel.port}/" if self.web_panel_started else "disabled"
        self._log_reasoning(
            f"[CoT Startup] {self.session_msg} | {self.ai_engine.load_weights()} | {self.oracle.load_oracle()} | "
            f"{self.privilege_sentinel.status_message} | PrivilegeScore={priv_pred['readiness_score']*100:.0f}% "
            f"({priv_pred['recommendation']}) | WebPanel={web_url} | {self.ai_engine.chrono_entangler.summary()}"
        )
        for line in self.privilege_sentinel.logs:
            self._log_reasoning(line)
        for line in self.autoloader.logs:
            self._log_reasoning(line)

    def _log_reasoning(self, msg: str):
        if not hasattr(self, "reason_box"):
            return
        ts = time.strftime("%H:%M:%S")
        self.reason_box.insert(tk.END, f"[{ts}] {msg}\n")
        self.reason_box.see(tk.END)

    def _export_cot_trace(self):
        content = self.reason_box.get("1.0", tk.END).strip()
        if not content:
            messagebox.showinfo("Export CoT Trace", "No Chain-of-Thought trace entries to export yet.")
            return
        path = filedialog.asksaveasfilename(
            title="Export Chain-of-Thought Reasoning Trace",
            defaultextension=".txt",
            initialfile="memory_zip_cot_trace.txt",
            filetypes=[("Text files", "*.txt"), ("Log files", "*.log"), ("All files", "*.*")],
        )
        if not path:
            return
        with open(path, "w", encoding="utf-8") as f:
            f.write(content + "\n")
        self._log_reasoning(f"[CoT Export] Saved reasoning trace to '{path}'.")

    def _browse_watch_dir(self):
        start_dir = self.watch_dir_var.get().strip() or os.path.expanduser("~")
        chosen = filedialog.askdirectory(title="Select Folder to Watch", initialdir=start_dir)
        if chosen:
            self.watch_dir_var.set(chosen)
            self.drive_scope_var.set("Selected Folder")
            self._refresh_backbone_telemetry()
            self._sync_auto_status_ui()
            self._save_session_now()
            self._log_reasoning(f"[Target Path] Updated to '{chosen}' (scope: Selected Folder).")

    def _load_file(self):
        path = filedialog.askopenfilename(title="Select a file to zip into memory")
        if not path:
            return
        try:
            data = read_file_chunked(path, self.get_max_file_bytes())
        except Exception as exc:
            self.threat_matrix.record("IO_FAULT_SPIKE", 0.55, str(exc))
            messagebox.showerror("Read Error", f"Could not read file:\n{exc}")
            return

        base = os.path.basename(path)
        self.name_var.set(base)
        self.input_box.delete("1.0", tk.END)
        try:
            self.input_box.insert("1.0", data.decode("utf-8", errors="replace"))
        except Exception:
            self.input_box.insert("1.0", f"<binary file: {len(data)} bytes>")
        self._update_live_prediction()
        self._ingest_payload(base, data, autonomous=False)

    def _get_current_input_bytes(self) -> bytes:
        text = self.input_box.get("1.0", tk.END)
        if text.endswith("\n"):
            text = text[:-1]
        return text.encode("utf-8")

    def _update_live_prediction(self):
        if not hasattr(self, "pred_lbl"):
            return
        data = self._get_current_input_bytes()
        feats = self.ai_engine.analyze_features(data)
        pred = self.ai_engine.predict_ratio(feats)
        conf = self.ai_engine.confidence_score(feats, pred)
        burst = self.ai_engine.forecast_burst()
        echo_sig = ResonantEchoLedger.fingerprint(data)
        conj_phase = self.ai_engine.conjugate_phase
        holo_key = HolographicInterferenceLedger.interference_key(data, feats, conj_phase)
        traj = self.ai_engine.predict_next_trajectory(feats, echo_sig=echo_sig, holo_key=holo_key)
        next_size_kb = traj["next_size_bytes"] / 1024.0
        hot_cap = self.get_active_hot_cap()
        horizon_txt = ""
        if hasattr(self, "predictive_horizon_var") and self.predictive_horizon_var.get():
            horizon_txt = f"  |  +3:{traj.get('h3_ratio', pred):.2f}x / +5:{traj.get('h5_ratio', pred):.2f}x"
        self.pred_lbl.config(
            text=(
                f"Entropy: {feats['entropy']:.2f} b/B  |  Repetition: {feats['repetition']*100:.1f}%  |  "
                f"Predicted: {pred:.2f}x  |  Next~{traj['next_ratio']:.2f}x (~{next_size_kb:.1f}KB in ~{traj['eta_sec']:.1f}s){horizon_txt}  |  "
                f"Conf: {conf*100:.0f}%  |  Burst: {burst}  |  HOT Cap: {hot_cap}"
            )
        )
        self._refresh_weights_label()
        self._refresh_oracle_label()

    def _refresh_weights_label(self):
        if not hasattr(self, "weights_lbl"):
            return
        with self.ai_engine.lock:
            w = self.ai_engine.weights
            obs = self.ai_engine.observations
            mae = (sum(self.ai_engine.mae_history[-10:]) / len(self.ai_engine.mae_history[-10:])) if self.ai_engine.mae_history else None
            coh = self.ai_engine.coherence
            sync_r = self.ai_engine.order_parameter
            drift = self.ai_engine.drift_index
            regret = self.ai_engine.cumulative_regret
            min_r = self.ai_engine.dynamic_min_ratio
            causal_txt = self.ai_engine.causal_engine.status_summary()
            chrono_txt = self.ai_engine.chrono_entangler.summary()
        mae_str = f"{mae:.2f}x" if mae is not None else "-"
        self.weights_lbl.config(
            text=(
                f"Weights -> int:{w['intercept']:.2f}, ent:{w['entropy_penalty']:.2f}, rep:{w['repetition_bonus']:.2f}, "
                f"harm:{w['harmonic_weight']:.2f}, vid:{w.get('video_stride_gain', 0.30):.2f}, "
                f"priv:{w.get('privilege_gain', 0.20):.2f}, holo:{w.get('interference_gain', 0.25):.2f} | "
                f"Coh:{coh:.2f} | R:{sync_r:.2f} | Drift:{drift:.2f} | Regret:{regret:.2f}x | "
                f"MinR:{min_r:.2f}x | {causal_txt} | {chrono_txt} | Upd:{obs} | MAE:{mae_str}"
            )
        )

    def _refresh_oracle_label(self):
        if not hasattr(self, "oracle_lbl"):
            return
        self.oracle_lbl.config(text=self.oracle.status_summary())

    def _save_weights_ui(self):
        msg = self.ai_engine.save_weights()
        omsg = self.oracle.save_oracle()
        self._save_session_now()
        self._log_reasoning(f"[AI Save] {msg} | {omsg}")

    def _reset_weights_ui(self):
        msg = self.ai_engine.reset_weights()
        omsg = self.oracle.reset_oracle()
        self._refresh_weights_label()
        self._refresh_oracle_label()
        self._update_live_prediction()
        self._log_reasoning(f"[AI Reset] {msg} | {omsg}")

    def _compress_with_strategy(
        self, raw_bytes: bytes, features: dict[str, float], vram_pressure: float = 0.0
    ) -> tuple[bytes, str, list[str]]:
        strategy = self.strategy_var.get()
        trace: list[str] = []
        echo_sig = ResonantEchoLedger.fingerprint(raw_bytes)
        conj_phase = self.ai_engine.conjugate_phase
        holo_key = HolographicInterferenceLedger.interference_key(raw_bytes, features, conj_phase)
        conf = self.ai_engine.confidence_score(features, self.ai_engine.predict_ratio(features))

        if strategy == "Auto (AI + Harmonic)":
            chosen_codec, reason = self.ai_engine.recommend_mode(
                features,
                self.lz4_ready,
                vram_pressure=vram_pressure,
                echo_sig=echo_sig,
                holo_key=holo_key,
                confidence=conf,
            )
            trace.append(f"AI + Harmonic + Swarm selected '{chosen_codec}' ({reason}).")
            if self.counterfactual_probe_var.get() and len(raw_bytes) >= 64:
                cf_codec, _scores, cf_msg = self.ai_engine.counterfactual_evaluate(
                    raw_bytes, features, self.autoloader.lz4_module, self.lz4_ready
                )
                trace.append(cf_msg)
                if cf_codec != chosen_codec and (
                    features["repetition"] >= 0.12
                    or features["entropy"] >= 7.2
                    or self.ai_engine.drift_index >= 0.45
                ):
                    trace.append(f"Overriding '{chosen_codec}' -> '{cf_codec}' based on counterfactual utility & regret.")
                    chosen_codec = cf_codec
        else:
            chosen_codec = strategy
            trace.append(f"User pinned strategy '{chosen_codec}'.")

        if chosen_codec.startswith("lz4") and self.lz4_ready and self.autoloader.lz4_module is not None:
            level = 9 if "level 9" in chosen_codec else 0
            try:
                return self.autoloader.lz4_module.compress(raw_bytes, compression_level=level), chosen_codec, trace
            except Exception as exc:
                self.threat_matrix.record("IO_FAULT_SPIKE", 0.50, f"LZ4 fault: {exc}")
                with self.ai_engine.lock:
                    self.ai_engine.self_heal_events += 1
                trace.append(f"[Self-Heal] LZ4 compress failed ({exc}); falling back to zlib (level 6).")
                return zlib.compress(raw_bytes, level=6), "zlib (level 6) [healed]", trace

        if chosen_codec.startswith("lz4") and not self.lz4_ready:
            trace.append("[Self-Heal] LZ4 library not active; using zlib (level 6) fallback.")
            return zlib.compress(raw_bytes, level=6), "zlib (level 6) [healed]", trace

        return zlib.compress(raw_bytes, level=6), "zlib (level 6)", trace

    def _decompress_with_heal(self, zipped_bytes: bytes, codec: str, expected_crc: int | None = None) -> tuple[bytes, list[str]]:
        trace: list[str] = []
        raw: bytes | None = None

        if codec.startswith("lz4"):
            if self.lz4_ready and self.autoloader.lz4_module is not None:
                try:
                    raw = self.autoloader.lz4_module.decompress(zipped_bytes)
                except Exception as exc:
                    trace.append(f"[Self-Heal] LZ4 decompress failed ({exc}); trying zlib fallback.")
            if raw is None:
                try:
                    raw = zlib.decompress(zipped_bytes)
                    trace.append("[Self-Heal] Recovered payload via zlib decompression.")
                except Exception as exc:
                    raise RuntimeError(f"Both LZ4 and zlib decompression failed: {exc}") from exc
        else:
            try:
                raw = zlib.decompress(zipped_bytes)
            except Exception as exc:
                if self.lz4_ready and self.autoloader.lz4_module is not None:
                    try:
                        raw = self.autoloader.lz4_module.decompress(zipped_bytes)
                        trace.append("[Self-Heal] Recovered payload via LZ4 fallback.")
                    except Exception:
                        raise RuntimeError(f"Decompression failed: {exc}") from exc
                else:
                    raise RuntimeError(f"zlib decompression failed: {exc}") from exc

        if expected_crc is not None and raw is not None:
            actual_crc = zlib.crc32(raw) & 0xFFFFFFFF
            if actual_crc != expected_crc:
                self.threat_matrix.record("INTEGRITY_DRIFT", 0.70, "CRC32 mismatch during decompress")
                trace.append(
                    f"[Self-Heal] CRC32 mismatch detected (expected {expected_crc:08x}, got {actual_crc:08x}); "
                    f"re-anchoring checksum."
                )

        return raw, trace

    def _zip_into_memory_manual(self):
        raw_bytes = self._get_current_input_bytes()
        if not raw_bytes:
            messagebox.showwarning("Empty Input", "Enter some text or load a file first.")
            return

        custom_name = self.name_var.get().strip()
        if custom_name:
            name = custom_name
        else:
            name = f"entry_{self.counter}"
            self.counter += 1

        self._ingest_payload(name, raw_bytes, autonomous=False)

    def _ingest_payload(self, name: str, raw_bytes: bytes, autonomous: bool = False):
        if not raw_bytes:
            return

        raw_bytes = self.plugin_registry.run_transforms(name, raw_bytes, {"autonomous": autonomous})

        hw_snap = self.gpu_pipeline.refresh_hardware()
        vram_pressure = float(hw_snap.get("vram_pressure", 0.0))
        hw_summary = self.gpu_inspector.format_summary(hw_snap)
        is_elevated = bool(self.privilege_sentinel.is_admin)
        priv_summary = f"Priv:{'ADMIN' if is_elevated else 'USER'}"

        feats = self.ai_engine.analyze_features(raw_bytes)
        if feats["entropy"] >= 7.85 and feats["repetition"] < 0.02:
            self.threat_matrix.record("ENTROPY_ANOMALY", 0.65, f"High-entropy payload '{name}' ({feats['entropy']:.2f} b/B)")

        compute_info = self.gpu_pipeline.offload_entropy_and_xor_kernel(raw_bytes)

        echo_sig = ResonantEchoLedger.fingerprint(raw_bytes)
        conj_phase = self.ai_engine.conjugate_phase
        holo_key = HolographicInterferenceLedger.interference_key(raw_bytes, feats, conj_phase)

        pred_ratio = self.ai_engine.predict_ratio(feats)
        conf = self.ai_engine.confidence_score(feats, pred_ratio)
        burst = self.ai_engine.forecast_burst()
        traj = self.ai_engine.predict_next_trajectory(feats, echo_sig=echo_sig, holo_key=holo_key)
        self.planner.reserve_speculative_slot(
            echo_sig, int(traj["next_size_bytes"]), harmonic_align=(self.ai_engine.coherence >= 0.72)
        )

        zipped, used_codec, codec_trace = self._compress_with_strategy(
            raw_bytes, feats, vram_pressure=vram_pressure
        )
        raw_len = len(raw_bytes)
        actual_ratio = raw_len / max(1, len(zipped))
        threshold = self.ai_engine.dynamic_min_ratio if self.skip_expansion_var.get() else 0.0

        with self.ai_engine.lock:
            echo_rec = self.ai_engine.echo_ledger.lookup(echo_sig)
            echo_hits = float(echo_rec["count"]) if echo_rec else 0.0
            holo_sim, _h_ema, _h_cnt = self.ai_engine.holo_ledger.peek_similarity(holo_key)

        oracle_pred_name, _oracle_prob, _top_k = self.oracle.predict_next_entry(
            candidates=list(self.store.keys()) + [name],
            harmonic_engine=self.ai_engine,
        )
        oracle_hit_flag = oracle_pred_name == name

        adapt_summary = self.ai_engine.think_and_adapt(
            feats,
            pred_ratio,
            actual_ratio,
            used_codec=used_codec,
            vram_pressure=vram_pressure,
            is_elevated=is_elevated,
            raw_len=raw_len,
            echo_sig=echo_sig,
            holo_key=holo_key,
            raw_bytes=raw_bytes,
            entry_name=name,
            oracle_hit=oracle_hit_flag,
            auto_policy_tune=bool(self.auto_policy_tune_var.get()),
        )

        if autonomous and actual_ratio < threshold:
            self._log_reasoning(
                f"[CoT Skip '{name}'] actual={actual_ratio:.2f}x < min_ratio={threshold:.2f}x "
                f"(pred={pred_ratio:.2f}x, conf={conf*100:.0f}%) -> skipped storing in RAM. | {adapt_summary}"
            )
            self._refresh_weights_label()
            self._refresh_threat_ui()
            return

        with self.state_lock:
            unique_name = name
            if unique_name in self.store:
                unique_name = f"{name}#{self.counter}"
                self.counter += 1

            harmonic_align = self.ai_engine.coherence >= 0.72
            zone, slot_id, slot_offset = self.planner.assign_slot(
                len(zipped), harmonic_align=harmonic_align, signature=echo_sig
            )
            crc = zlib.crc32(raw_bytes) & 0xFFFFFFFF

            video_info = self.gpu_pipeline.stage_to_video_card(
                name=unique_name,
                raw_len=raw_len,
                zipped_bytes=zipped,
                conjugate_phase=self.ai_engine.conjugate_phase,
                coherence=self.ai_engine.coherence,
            )

            hot_cap = self.get_active_hot_cap()
            initial_tier = "HOT" if len(self.store) < hot_cap else "COLD"
            hot_buf = raw_bytes if initial_tier == "HOT" else None
            raw_buf = None if self.lean_mode_var.get() else raw_bytes

            entry = CompressedEntry(
                name=unique_name,
                source="autonomous" if autonomous else "manual",
                codec=used_codec,
                zone=zone,
                slot_id=slot_id,
                slot_offset=slot_offset,
                crc32=crc,
                raw_len=raw_len,
                zipped=zipped,
                pred_ratio=pred_ratio,
                ai_confidence=conf,
                tier=initial_tier,
                hot_bytes=hot_buf,
                raw_cached=raw_buf,
            )
            self.store[unique_name] = entry
            self.store.move_to_end(unique_name, last=True)
            self.oracle.register_entry(unique_name)
            self.ai_engine.graph_db.upsert_node(
                unique_name,
                {
                    "slot": slot_id,
                    "zone": zone,
                    "tier": initial_tier,
                    "ratio": round(actual_ratio, 2),
                },
            )

            if self.auto_rebalance_var.get() and len(self.store) > hot_cap:
                self._rebalance_tiers_locked()

        self.event_bus.publish(
            "entry.ingested",
            {"name": unique_name, "slot": slot_id, "ratio": round(actual_ratio, 2), "codec": used_codec},
        )

        if self.auto_save_weights_var.get() and (self.ai_engine.observations % 5 == 0):
            self.ai_engine.save_weights()
            self.oracle.save_oracle()

        mode_tag = "AUTO-AI" if autonomous else "MANUAL-AI"
        cot_lines = ReasoningTraceBuilder.build_ingest_trace(
            mode_tag=mode_tag,
            name=unique_name,
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
            video_info=video_info,
            hw_summary=hw_summary,
            priv_summary=priv_summary,
            echo_hits=echo_hits,
            holo_sim=holo_sim,
            oracle_summary=self.oracle.status_summary(),
            compute_info=compute_info,
        )
        for line in cot_lines:
            self._log_reasoning(line)

        self._refresh_table()
        self._refresh_stats()
        self._refresh_backbone_telemetry()
        self._refresh_video_status_label()
        self._refresh_weights_label()
        self._refresh_oracle_label()
        self._refresh_threat_ui()
        self._update_live_prediction()

    def _get_selected_name(self) -> str | None:
        sel = self.tree.selection()
        if not sel:
            messagebox.showinfo("Select Item", "Select a memory slot row in the table first.")
            return None
        vals = self.tree.item(sel[0], "values")
        return vals[3] if vals and len(vals) >= 4 else None

    def _unzip_selected(self):
        name = self._get_selected_name()
        if not name:
            return

        with self.state_lock:
            entry = self.store.get(name)
            if not entry:
                return
            entry.hits += 1
            entry.last_used = time.time()
            self.store.move_to_end(name, last=True)
            tier_used = entry.tier
            zipped_copy = entry.zipped
            codec_copy = entry.codec
            crc_copy = entry.crc32
            hot_copy = entry.hot_bytes

        oracle_fb = self.oracle.record_access(name, harmonic_engine=self.ai_engine)
        prefetch_hints = self.rag_prefetcher.plan_prefetch(current_doc=name, limit=2)

        try:
            if tier_used == "HOT" and hot_copy is not None:
                raw_bytes = hot_copy
                heal_trace: list[str] = []
                path_label = "HOT fast-tier direct read"
            else:
                raw_bytes, heal_trace = self._decompress_with_heal(zipped_copy, codec_copy, crc_copy)
                path_label = f"COLD compressed-tier decompress ({codec_copy})"
                if self.auto_rebalance_var.get():
                    with self.state_lock:
                        if name in self.store:
                            self.store[name].hot_bytes = raw_bytes
                            self.store[name].tier = "HOT"
                            self._rebalance_tiers_locked()
        except Exception as exc:
            self.threat_matrix.record("INTEGRITY_DRIFT", 0.80, f"Access fault on {name}: {exc}")
            with self.ai_engine.lock:
                self.ai_engine.self_heal_events += 1
            self._log_reasoning(f"[Access][Self-Heal] Failed accessing '{name}': {exc}")
            messagebox.showerror("Decompress Error", f"Failed to access '{name}':\n{exc}")
            return

        if self.show_hex_var.get():
            display_text = raw_bytes.hex(" ")
        else:
            display_text = raw_bytes.decode("utf-8", errors="replace")

        self.output_box.delete("1.0", tk.END)
        self.output_box.insert("1.0", display_text)
        for h_line in heal_trace:
            self._log_reasoning(f"[Access '{name}'] {h_line}")

        nxt_txt = (
            f"{oracle_fb['next_name']} ({oracle_fb['next_prob']*100:.0f}%)"
            if oracle_fb.get("next_name")
            else "none"
        )
        self._log_reasoning(
            f"[CoT Access '{name}'] {path_label}, rel={entry.relevance_score():.2f}, hits={entry.hits} | "
            f"Oracle {oracle_fb['outcome']} -> next:{nxt_txt} (conf:{oracle_fb['oracle_conf']*100:.0f}%, "
            f"acc:{oracle_fb['accuracy_pct']:.0f}%) | Prefetch:{prefetch_hints}"
        )

        self.event_bus.publish("entry.accessed", {"name": name, "tier": tier_used, "hits": entry.hits})
        self._refresh_table()
        self._refresh_stats()
        self._refresh_oracle_label()
        self._refresh_threat_ui()
        self._update_live_prediction()

    def _delete_selected(self):
        name = self._get_selected_name()
        if not name:
            return
        with self.state_lock:
            self.store.pop(name, None)
            self.gpu_pipeline.ring_buffer.pop(name, None)
            self.oracle.remove_entry(name)
            self.ai_engine.constellation_graph.remove_node(name)
            self.ai_engine.graph_db.remove_node(name)
        self._refresh_table()
        self._refresh_stats()
        self._refresh_video_status_label()
        self._refresh_oracle_label()
        self._log_reasoning(f"[Memory] Deleted '{name}' from host RAM, video ring, oracle & graph.")

    def _clear_all(self):
        with self.state_lock:
            self.store.clear()
            self.gpu_pipeline.clear_ring()
            self.oracle.clear_entries()
            self.ai_engine.constellation_graph.clear()
            self.ai_engine.graph_db.clear()
        self.output_box.delete("1.0", tk.END)
        self._refresh_table()
        self._refresh_stats()
        self._refresh_video_status_label()
        self._refresh_oracle_label()
        self._log_reasoning("[Memory] Cleared all in-memory compressed entries, video ring & graph.")

    def _refresh_table(self):
        if not hasattr(self, "tree"):
            return
        for row_id in self.tree.get_children():
            self.tree.delete(row_id)

        now = time.time()
        with self.state_lock:
            entries = list(self.store.values())

        for e in entries:
            saved = e.saved_bytes
            sign = "+" if saved >= 0 else "-"
            saved_str = f"{sign}{abs(saved):,} B ({e.saved_pct:+.1f}%)"
            self.tree.insert(
                "",
                tk.END,
                values=(
                    e.slot_id,
                    e.zone,
                    f"{e.slot_offset:,}",
                    e.name,
                    e.tier,
                    f"{e.relevance_score(now):.2f}",
                    f"{e.raw_len:,} B",
                    f"{e.active_bytes_len:,} B",
                    saved_str,
                ),
            )

    def _refresh_stats(self):
        if not hasattr(self, "totals_lbl"):
            return
        with self.state_lock:
            entries = list(self.store.values())

        total_raw = sum(e.raw_len for e in entries)
        total_active = sum(e.active_bytes_len for e in entries)
        hot_count = sum(1 for e in entries if e.tier == "HOT")
        cold_count = len(entries) - hot_count

        zone_counts: dict[str, int] = {}
        for e in entries:
            zone_counts[e.zone] = zone_counts.get(e.zone, 0) + 1
        zones_str = ", ".join(f"{z}:{c}" for z, c in zone_counts.items()) if zone_counts else "none"

        total_saved = total_raw - total_active
        ratio = (total_raw / total_active) if total_active > 0 else 1.0
        saved_pct = (total_saved / total_raw * 100.0) if total_raw > 0 else 0.0
        sign = "+" if total_saved >= 0 else "-"

        self.totals_lbl.config(
            text=(
                f"Items: {len(entries)} (HOT: {hot_count} / COLD: {cold_count} | Zones: {zones_str})  |  "
                f"Original: {total_raw:,} B  |  Active RAM: {total_active:,} B  |  "
                f"Ratio: {ratio:.2f}x  |  Saved: {sign}{abs(total_saved):,} B ({saved_pct:+.1f}%)"
            )
        )


def run_headless_daemon(watch_dir: str | None = None, interval_sec: float = 3.0, privilege_sentinel: PrivilegeSentinel | None = None):
    """Runs the 24/7 AI + ChronoEntangle + Causal + Oracle + Threat + Mesh + Web daemon without a GUI window."""
    sentinel = privilege_sentinel or PrivilegeSentinel()
    sentinel.detect_admin()

    loader = LibraryAutoloader()
    loader.bootstrap()
    backbone = SystemBackbone(loader)
    planner = MemoryPlacementPlanner()
    gpu_inspector = GPUHardwareInspector(cache_ttl_sec=4.0)
    gpu_pipeline = GPUCardPipeline(gpu_inspector, loader)
    event_bus = EventBrokerBus()
    mesh_sync = MultiNodeMeshSync(enable_socket=True)
    threat_matrix = ThreatAnomalyMatrix()
    workflow_engine = WorkflowAutomationEngine(broker=event_bus)
    plugin_registry = PluginRegistry()
    plugin_registry.discover_and_load({"bus": event_bus, "mesh": mesh_sync})

    ai_engine = HarmonicPhaseEngine(mesh_sync=mesh_sync)
    oracle = PredictiveWorkingSetOracle()
    session = SessionMemoryStore()
    session.load()
    watchdog = SelfHealWatchdog(fault_threshold=3, base_cooldown_sec=20.0)

    web_server = WebControlPanelServer(
        state_provider=lambda: {
            "mode": "headless-daemon",
            "observations": ai_engine.observations,
            "coherence": round(ai_engine.coherence, 3),
            "chrono": ai_engine.chrono_entangler.summary(),
            "threat": threat_matrix.summary(),
            "mesh": mesh_sync.summary(),
            "graph_db": ai_engine.graph_db.summary(),
        },
        command_handler=lambda path, _body: {"ok": True, "path": path},
        host="127.0.0.1",
        port=8766,
    )
    web_server.start()

    roots = [watch_dir] if watch_dir else (backbone.list_drives() or [os.path.abspath(os.sep)])
    seen: OrderedDict[str, tuple[int, float]] = OrderedDict()
    max_daemon_entries = 128
    entries_store: OrderedDict[str, CompressedEntry] = OrderedDict()

    print(f"[Headless AI Daemon] Started | {sentinel.status_message} | {ai_engine.load_weights()} | {oracle.load_oracle()}")
    print(f"[Headless AI Daemon] Watching roots: {roots} every {interval_sec:.1f}s. Press Ctrl+C to stop.")

    try:
        while True:
            hw = gpu_pipeline.refresh_hardware()
            pressure = float(hw.get("vram_pressure", 0.0))
            for root_path in roots:
                if not root_path or not os.path.isdir(root_path) or watchdog.is_quarantined(root_path):
                    continue
                for current_dir, _dirs, files in os.walk(root_path, onerror=lambda _e: None):
                    for fname in sorted(files):
                        fpath = os.path.join(current_dir, fname)
                        if watchdog.is_quarantined(fpath):
                            continue
                        try:
                            st = os.stat(fpath)
                        except OSError:
                            continue
                        sig = (st.st_size, st.st_mtime)
                        if seen.get(fpath) == sig or st.st_size <= 0 or st.st_size > 16 * 1024 * 1024:
                            continue
                        try:
                            raw = read_file_chunked(fpath, 16 * 1024 * 1024)
                            watchdog.record_success(fpath)
                        except Exception as exc:
                            threat_matrix.record("IO_FAULT_SPIKE", 0.55, str(exc))
                            watchdog.record_fault(fpath)
                            continue
                        seen[fpath] = sig
                        seen.move_to_end(fpath, last=True)
                        while len(seen) > max_daemon_entries * 4:
                            seen.popitem(last=False)

                        raw = plugin_registry.run_transforms(fname, raw, {"headless": True})
                        feats = ai_engine.analyze_features(raw)
                        pred = ai_engine.predict_ratio(feats)
                        echo_sig = ResonantEchoLedger.fingerprint(raw)
                        holo_key = HolographicInterferenceLedger.interference_key(raw, feats, ai_engine.conjugate_phase)
                        if loader.lz4_available and loader.lz4_module is not None:
                            zipped = loader.lz4_module.compress(raw, compression_level=0)
                            codec = "lz4-default (level 0)"
                        else:
                            zipped = zlib.compress(raw, level=6)
                            codec = "zlib (level 6)"
                        ratio = len(raw) / max(1, len(zipped))
                        oracle.register_entry(fname)
                        summary = ai_engine.think_and_adapt(
                            feats,
                            pred,
                            ratio,
                            used_codec=codec,
                            vram_pressure=pressure,
                            is_elevated=sentinel.is_admin,
                            raw_len=len(raw),
                            echo_sig=echo_sig,
                            holo_key=holo_key,
                            raw_bytes=raw,
                            entry_name=fname,
                        )
                        zone, slot_id, slot_off = planner.assign_slot(len(zipped), signature=echo_sig)
                        entries_store[fname] = CompressedEntry(
                            name=fname,
                            source="daemon",
                            codec=codec,
                            zone=zone,
                            slot_id=slot_id,
                            slot_offset=slot_off,
                            crc32=zlib.crc32(raw) & 0xFFFFFFFF,
                            raw_len=len(raw),
                            zipped=zipped,
                            pred_ratio=pred,
                            tier="COLD",
                        )
                        while len(entries_store) > max_daemon_entries:
                            evicted_k, _evicted_v = entries_store.popitem(last=False)
                            oracle.remove_entry(evicted_k)
                            ai_engine.graph_db.remove_node(evicted_k)
                        print(f"[Daemon] {fname} -> {ratio:.2f}x ({codec}) | {summary}")

            mesh_sync.broadcast_state(
                {
                    "codec": "lz4-default (level 0)" if loader.lz4_available else "zlib (level 6)",
                    "confidence": oracle.oracle_confidence,
                    "coherence": ai_engine.coherence,
                    "entries": len(entries_store),
                }
            )
            workflow_engine.evaluate(
                {
                    "vram_pressure": pressure,
                    "divergence": ai_engine.divergence_monitor.divergence_score,
                    "observations": ai_engine.observations,
                },
                {"SAVE_STATE": lambda: (ai_engine.save_weights(), oracle.save_oracle())},
            )
            time.sleep(max(0.5, interval_sec))
    except KeyboardInterrupt:
        ai_engine.save_weights()
        oracle.save_oracle()
        web_server.stop()
        print("\n[Headless AI Daemon] Stopped cleanly.")


def main():
    parser = argparse.ArgumentParser(description="On-the-Fly Memory Zip Store + Phase-Lock AI & ChronoEntanglement")
    parser.add_argument("--daemon", action="store_true", help="Run 24/7 autonomous daemon without GUI")
    parser.add_argument("--watch", type=str, default=None, help="Directory path to watch")
    parser.add_argument("--interval", type=float, default=3.0, help="Scan interval in seconds")
    parser.add_argument("--no-elevate", action="store_true", help="Skip Windows UAC auto-elevation prompt")
    args = parser.parse_args()

    if args.no_elevate:
        os.environ[NO_ELEVATE_ENV] = "1"

    sentinel = PrivilegeSentinel()
    sentinel.detect_admin()
    if os.name == "nt" and not sentinel.is_admin and os.environ.get(NO_ELEVATE_ENV) != "1":
        ensure_admin(sentinel)

    if args.daemon:
        run_headless_daemon(watch_dir=args.watch, interval_sec=args.interval, privilege_sentinel=sentinel)
        return

    root = tk.Tk()
    MemoryZipGUI(root, initial_watch_dir=args.watch, privilege_sentinel=sentinel)
    root.mainloop()


if __name__ == "__main__":
    main()