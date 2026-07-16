#!/usr/bin/env python3
"""
AI Static Background Lock Upscaler (Borg Edition, CPU-Only Kill Switch)
-----------------------------------------------------------------------

Mode: A) Full GPU Kill Switch (CPU-only, guaranteed no WinError 1114)

Features:
    - Built-in bootstrap (auto-install dependencies)
    - Optical flow motion detection
    - Deep segmentation stubs (RVM / MODNet style via plugins)
    - Background AI reconstruction (bilateral filtering)
    - ONNX SR (CPUExecutionProvider only, no GPU providers)
    - FFmpeg raw pipe export (MP4)
    - Batch processing mode (folder of videos)
    - Borg read-ahead tech (lookahead buffer for better background/motion foresight)
    - Mirror Scanner panel (FFmpeg / ONNX / Real-ESRGAN / PyPI / ONNX SR)
    - Plugin system for SR models and segmenters

Run (GUI):
    python borg_upscaler_cpu_only.py

Run (batch mode):
    python borg_upscaler_cpu_only.py --batch input_folder --export_folder output_folder
"""

import sys
import os
import importlib
import subprocess
import argparse
from typing import Tuple, Optional, List, Dict, Callable

# ---------------------------------------------------------
# BOOTSTRAP (CPU-only, no GPU deps)
# ---------------------------------------------------------

REQUIRED_PKGS = [
    "opencv-python",
    "numpy",
    "PyQt5",
    "requests",
    "onnxruntime",
]

def bootstrap():
    print("[BOOTSTRAP] Checking dependencies (CPU-only)...")
    missing = []

    pkg_to_import = {
        "opencv-python": "cv2",
        "numpy": "numpy",
        "PyQt5": "PyQt5",
        "requests": "requests",
        "onnxruntime": "onnxruntime",
    }

    for pkg in REQUIRED_PKGS:
        mod_name = pkg_to_import.get(pkg, pkg.replace("-", "_"))
        try:
            importlib.import_module(mod_name)
        except ImportError:
            missing.append(pkg)

    if missing:
        print("[BOOTSTRAP] Missing packages detected:")
        for m in missing:
            print("  -", m)

        print("[BOOTSTRAP] Installing missing packages via pip...")
        for m in missing:
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", m])
            except Exception as e:
                print(f"[BOOTSTRAP] Failed to install {m}: {e}")
                print("[BOOTSTRAP] Continuing; some features may be limited.")

    print("[BOOTSTRAP] Dependencies check complete (CPU-only).")
    print("[BOOTSTRAP] Launching Borg Upscaler...")

bootstrap()

import cv2
import numpy as np
import requests

from PyQt5.QtWidgets import (
    QApplication, QWidget, QLabel, QPushButton, QLineEdit, QComboBox,
    QFileDialog, QHBoxLayout, QVBoxLayout, QCheckBox, QTextEdit, QGroupBox,
    QListWidget, QListWidgetItem, QScrollArea
)
from PyQt5.QtCore import QTimer, Qt
from PyQt5.QtGui import QImage, QPixmap


def log(msg: str) -> None:
    print(f"[BORG-UPSCALE] {msg}")


# ---------------------------------------------------------
# ONNX PROVIDERS (CPU-only Kill Switch)
# ---------------------------------------------------------

def cpu_only_onnx_providers():
    """
    Returns CPUExecutionProvider only.
    No CUDA, no TensorRT, no DirectML, no GPU enumeration.
    """
    try:
        import onnxruntime as ort
        log(f"[ONNX] Available providers (raw): {ort.get_available_providers()}")
    except Exception as e:
        log(f"[ONNX] Failed to import onnxruntime: {e}")
    log("[ONNX] Using CPUExecutionProvider ONLY (GPU Kill Switch).")
    return ["CPUExecutionProvider"]


# ---------------------------------------------------------
# CONFIG / PROFILES
# ---------------------------------------------------------

class UpscaleConfig:
    def __init__(
        self,
        target_scale: float = 2.0,
        motion_threshold: float = 25.0,
        min_motion_area: int = 64,
        background_build_frames: int = 60,
        background_update_alpha: float = 0.02,
        use_gray_for_motion: bool = True,
        profile_name: str = "auto",
        use_optical_flow: bool = True,
        borg_read_ahead_frames: int = 15,
    ):
        self.target_scale = target_scale
        self.motion_threshold = motion_threshold
        self.min_motion_area = min_motion_area
        self.background_build_frames = background_build_frames
        self.background_update_alpha = background_update_alpha
        self.use_gray_for_motion = use_gray_for_motion
        self.profile_name = profile_name
        self.use_optical_flow = use_optical_flow
        self.borg_read_ahead_frames = borg_read_ahead_frames


def make_profile(profile: str) -> UpscaleConfig:
    profile = profile.lower()
    if profile == "movies":
        return UpscaleConfig(
            target_scale=2.0,
            motion_threshold=20.0,
            min_motion_area=80,
            background_build_frames=80,
            background_update_alpha=0.01,
            use_gray_for_motion=True,
            profile_name="movies",
            use_optical_flow=True,
            borg_read_ahead_frames=20,
        )
    elif profile == "youtube":
        return UpscaleConfig(
            target_scale=2.0,
            motion_threshold=25.0,
            min_motion_area=64,
            background_build_frames=60,
            background_update_alpha=0.02,
            use_gray_for_motion=True,
            profile_name="youtube",
            use_optical_flow=True,
            borg_read_ahead_frames=10,
        )
    elif profile == "surveillance":
        return UpscaleConfig(
            target_scale=2.0,
            motion_threshold=15.0,
            min_motion_area=32,
            background_build_frames=120,
            background_update_alpha=0.005,
            use_gray_for_motion=True,
            profile_name="surveillance",
            use_optical_flow=True,
            borg_read_ahead_frames=30,
        )
    else:
        return UpscaleConfig(profile_name="auto", use_optical_flow=True, borg_read_ahead_frames=15)


def auto_select_profile(fps: float, width: int, height: int, is_stream: bool) -> UpscaleConfig:
    if not is_stream and fps >= 23 and fps <= 26 and width >= 1280 and height >= 720:
        log("Auto profile: movies")
        return make_profile("movies")
    if not is_stream and fps >= 25 and fps <= 60:
        log("Auto profile: youtube")
        return make_profile("youtube")
    if is_stream or width <= 960:
        log("Auto profile: surveillance")
        return make_profile("surveillance")
    log("Auto profile: default")
    return make_profile("auto")


# ---------------------------------------------------------
# MIRROR SCANNER / DOWNLOAD MANAGER
# ---------------------------------------------------------

class MirrorScanner:
    def __init__(self, log_widget: Optional[QTextEdit] = None):
        self.log_widget = log_widget

    def _log(self, msg: str):
        log(msg)
        if self.log_widget is not None:
            self.log_widget.append(msg)

    def _safe_get_json(self, url: str) -> Optional[dict]:
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                return resp.json()
            self._log(f"[MirrorScanner] HTTP {resp.status_code} for {url}")
        except Exception as e:
            self._log(f"[MirrorScanner] Error fetching {url}: {e}")
        return None

    def scan_ffmpeg_sites(self) -> List[str]:
        sites = [
            "https://www.gyan.dev/ffmpeg/builds/",
            "https://ffmpeg.org/download.html",
            "https://johnvansickle.com/ffmpeg/",
        ]
        self._log("[MirrorScanner] FFmpeg candidate sites listed.")
        return sites

    def scan_onnxruntime_sites(self) -> List[str]:
        sites = []
        api_url = "https://api.github.com/repos/microsoft/onnxruntime/releases"
        data = self._safe_get_json(api_url)
        if data:
            for rel in data:
                for asset in rel.get("assets", []):
                    dl_url = asset.get("browser_download_url")
                    if dl_url:
                        sites.append(dl_url)
            self._log(f"[MirrorScanner] Found {len(sites)} ONNX Runtime assets via GitHub.")
        else:
            self._log("[MirrorScanner] Failed to query ONNX Runtime GitHub releases.")
        return sites

    def scan_realesrgan_sites(self) -> List[str]:
        sites = []
        api_url = "https://api.github.com/repos/xinntao/Real-ESRGAN/releases"
        data = self._safe_get_json(api_url)
        if data:
            for rel in data:
                for asset in rel.get("assets", []):
                    dl_url = asset.get("browser_download_url")
                    if dl_url:
                        sites.append(dl_url)
            self._log(f"[MirrorScanner] Found {len(sites)} Real-ESRGAN assets via GitHub.")
        else:
            self._log("[MirrorScanner] Failed to query Real-ESRGAN GitHub releases.")
        return sites

    def scan_pypi_sites(self, package: str) -> List[str]:
        sites = []
        api_url = f"https://pypi.org/pypi/{package}/json"
        data = self._safe_get_json(api_url)
        if data:
            urls = data.get("urls", [])
            for u in urls:
                dl_url = u.get("url")
                if dl_url:
                    sites.append(dl_url)
            self._log(f"[MirrorScanner] Found {len(sites)} PyPI files for {package}.")
        else:
            self._log(f"[MirrorScanner] Failed to query PyPI for {package}.")
        return sites

    def scan_onnx_sr_model_sites(self) -> List[str]:
        sites = []
        api_url = "https://api.github.com/repos/xinntao/Real-ESRGAN/releases"
        data = self._safe_get_json(api_url)
        if data:
            for rel in data:
                for asset in rel.get("assets", []):
                    dl_url = asset.get("browser_download_url")
                    if dl_url and dl_url.endswith(".onnx"):
                        sites.append(dl_url)
            self._log(f"[MirrorScanner] Found {len(sites)} ONNX SR model candidates via Real-ESRGAN GitHub.")
        else:
            self._log("[MirrorScanner] Failed to query Real-ESRGAN GitHub for ONNX SR models.")
        return sites


class DownloadManager:
    def __init__(self, log_widget: Optional[QTextEdit] = None, mirror_scanner: Optional[MirrorScanner] = None):
        self.log_widget = log_widget
        self.mirror_scanner = mirror_scanner or MirrorScanner(log_widget=log_widget)

    def _log(self, msg: str):
        log(msg)
        if self.log_widget is not None:
            self.log_widget.append(msg)

    def ensure_dir(self, path: str):
        os.makedirs(path, exist_ok=True)

    def download_from_url(self, url: str, dest_dir: str):
        self.ensure_dir(dest_dir)
        local_name = os.path.join(dest_dir, os.path.basename(url))
        self._log(f"[Downloader] Downloading from {url} -> {local_name}")
        resp = requests.get(url, stream=True, timeout=30)
        if resp.status_code != 200:
            raise RuntimeError(f"HTTP {resp.status_code}")
        downloaded = 0
        with open(local_name, "wb") as f:
            for chunk in resp.iter_content(chunk_size=8192):
                if not chunk:
                    continue
                f.write(chunk)
                downloaded += len(chunk)
        self._log(f"[Downloader] Downloaded {downloaded} bytes to {local_name}")
        return local_name

    def install_pip_package(self, package: str):
        self._log(f"[Downloader] Installing pip package: {package}")
        try:
            subprocess.check_call([sys.executable, "-m", "pip", "install", package])
            self._log(f"[Downloader] pip install {package} completed.")
        except Exception as e:
            self._log(f"[Downloader] pip install {package} failed: {e}")

    def auto_download_default_onnx_sr(self) -> Optional[str]:
        sites = self.mirror_scanner.scan_onnx_sr_model_sites()
        if not sites:
            self._log("[Downloader] No ONNX SR model sites found.")
            return None
        url = sites[0]
        self._log(f"[Downloader] Auto-downloading default ONNX SR model from: {url}")
        path = self.download_from_url(url, "models")
        return path


# ---------------------------------------------------------
# PLUGIN SYSTEM
# ---------------------------------------------------------

class SRModelPlugin:
    def __init__(self, name: str, onnx_path: str):
        self.name = name
        self.onnx_path = onnx_path


class SegmenterPlugin:
    def __init__(self, name: str, segment_fn: Callable[[np.ndarray], np.ndarray]):
        self.name = name
        self.segment_fn = segment_fn


class PluginRegistry:
    def __init__(self):
        self.sr_models: Dict[str, SRModelPlugin] = {}
        self.segmenters: Dict[str, SegmenterPlugin] = {}

    def register_sr_model(self, plugin: SRModelPlugin):
        self.sr_models[plugin.name] = plugin

    def register_segmenter(self, plugin: SegmenterPlugin):
        self.segmenters[plugin.name] = plugin

    def get_sr_model(self, name: str) -> Optional[SRModelPlugin]:
        return self.sr_models.get(name)

    def get_segmenter(self, name: str) -> Optional[SegmenterPlugin]:
        return self.segmenters.get(name)


PLUGIN_REGISTRY = PluginRegistry()

PLUGIN_REGISTRY.register_sr_model(
    SRModelPlugin(name="default_sr", onnx_path=os.path.join("models", "sr_default_sr.onnx"))
)


# ---------------------------------------------------------
# DEEP SEGMENTATION STUBS (RVM / MODNet style)
# ---------------------------------------------------------

def rvm_segment_stub(frame: np.ndarray) -> np.ndarray:
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    _, mask = cv2.threshold(gray, 128, 255, cv2.THRESH_BINARY)
    return mask


def modnet_segment_stub(frame: np.ndarray) -> np.ndarray:
    gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
    _, mask = cv2.threshold(gray, 100, 255, cv2.THRESH_BINARY)
    return mask


PLUGIN_REGISTRY.register_segmenter(
    SegmenterPlugin(name="rvm_stub", segment_fn=rvm_segment_stub)
)
PLUGIN_REGISTRY.register_segmenter(
    SegmenterPlugin(name="modnet_stub", segment_fn=modnet_segment_stub)
)


# ---------------------------------------------------------
# BACKGROUND UPSCALER (ONNX CPU-only)
# ---------------------------------------------------------

class BackgroundUpscaler:
    def __init__(
        self,
        scale: float = 2.0,
        use_onnx: bool = False,
        onnx_path: Optional[str] = None,
        auto: bool = True,
        plugin_model_name: Optional[str] = "default_sr",
        downloader: Optional[DownloadManager] = None,
    ):
        self.scale = scale
        self.use_onnx = use_onnx
        self.onnx_path = onnx_path
        self.auto = auto
        self.plugin_model_name = plugin_model_name
        self._onnx_session = None
        self.downloader = downloader

        if self.auto:
            self._auto_init_onnx()
        elif self.use_onnx and self.onnx_path:
            self._init_onnx()

    def _auto_init_onnx(self) -> None:
        plugin = PLUGIN_REGISTRY.get_sr_model(self.plugin_model_name) if self.plugin_model_name else None
        candidate = plugin.onnx_path if plugin else None
        if candidate and os.path.isfile(candidate):
            self.use_onnx = True
            self.onnx_path = candidate
            log(f"Auto-detected ONNX SR model via plugin: {candidate}")
            self._init_onnx()
            return

        default_path = os.path.join("models", "sr_model.onnx")
        if os.path.isfile(default_path):
            self.use_onnx = True
            self.onnx_path = default_path
            log(f"Auto-detected ONNX SR model at: {default_path}")
            self._init_onnx()
            return

        if self.downloader is not None:
            log("No local ONNX SR model found; attempting auto-download...")
            dl_path = self.downloader.auto_download_default_onnx_sr()
            if dl_path and os.path.isfile(dl_path):
                self.use_onnx = True
                self.onnx_path = dl_path
                log(f"Auto-downloaded ONNX SR model: {dl_path}")
                self._init_onnx()
                return

        log("No ONNX SR model available; using INTER_CUBIC fallback.")
        self.use_onnx = False

    def _init_onnx(self) -> None:
        try:
            import onnxruntime as ort
            providers = cpu_only_onnx_providers()
            self._onnx_session = ort.InferenceSession(
                self.onnx_path,
                providers=providers
            )
            log("ONNX SR model loaded (CPUExecutionProvider only).")
        except Exception as e:
            log(f"Failed to load ONNX model, falling back to INTER_CUBIC: {e}")
            self._onnx_session = None
            self.use_onnx = False

    def _run_model(self, bg: np.ndarray) -> np.ndarray:
        if self._onnx_session is None:
            raise RuntimeError("ONNX session not initialized.")

        img = bg.astype(np.float32) / 255.0
        img = np.transpose(img, (2, 0, 1))
        img = np.expand_dims(img, axis=0)

        input_name = self._onnx_session.get_inputs()[0].name
        outputs = self._onnx_session.run(None, {input_name: img})
        out = outputs[0]

        out = np.squeeze(out, axis=0)
        out = np.transpose(out, (1, 2, 0))
        out = np.clip(out * 255.0, 0, 255).astype(np.uint8)
        return out

    def upscale(self, bg: np.ndarray) -> np.ndarray:
        if self.use_onnx and self._onnx_session is not None:
            log("Upscaling background via ONNX SR model (CPU-only)...")
            return self._run_model(bg)

        h, w = bg.shape[:2]
        new_w = int(w * self.scale)
        new_h = int(h * self.scale)
        log(f"Upscaling background via INTER_CUBIC from {w}x{h} to {new_w}x{new_h}")
        up_bg = cv2.resize(bg, (new_w, new_h), interpolation=cv2.INTER_CUBIC)
        return up_bg


# ---------------------------------------------------------
# BACKGROUND MODELER + BORG READ-AHEAD
# ---------------------------------------------------------

class BackgroundModeler:
    def __init__(self, config: UpscaleConfig):
        self.config = config
        self._frames_buffer = []
        self.background: Optional[np.ndarray] = None
        self.initial_built = False

    def accumulate_initial(self, frame: np.ndarray) -> None:
        if not self.initial_built:
            self._frames_buffer.append(frame.copy())

    def borg_read_ahead(self, vin, max_frames: int) -> None:
        count = 0
        while count < max_frames:
            ret, frame = vin.read()
            if not ret:
                break
            self._frames_buffer.append(frame.copy())
            count += 1
        log(f"[BorgReadAhead] Buffered {count} future frames for foresight.")

    def build_initial_background(self) -> None:
        if not self._frames_buffer:
            raise RuntimeError("No frames accumulated for background model.")
        log(f"Building initial background from {len(self._frames_buffer)} frames (profile={self.config.profile_name})...")
        stack = np.stack(self._frames_buffer, axis=3)
        bg = np.median(stack, axis=3).astype(np.uint8)
        bg = self.reconstruct_background(bg)
        self.background = bg
        self._frames_buffer = []
        self.initial_built = True
        log("Initial background model built.")

    def reconstruct_background(self, bg: np.ndarray) -> np.ndarray:
        log("[BackgroundReconstruction] Applying bilateral filter to background.")
        bg_rec = cv2.bilateralFilter(bg, d=9, sigmaColor=75, sigmaSpace=75)
        return bg_rec

    def update_background_slow(self, frame: np.ndarray, motion_mask: np.ndarray) -> None:
        if self.background is None:
            return

        static_mask = (motion_mask == 0)
        alpha = self.config.background_update_alpha

        bg = self.background.astype(np.float32)
        fr = frame.astype(np.float32)

        for c in range(3):
            bg_channel = bg[:, :, c]
            fr_channel = fr[:, :, c]
            bg_channel[static_mask] = (
                (1.0 - alpha) * bg_channel[static_mask] + alpha * fr_channel[static_mask]
            )

        self.background = bg.astype(np.uint8)


# ---------------------------------------------------------
# MOTION DETECTOR (OPTICAL FLOW + SEGMENTATION STUBS)
# ---------------------------------------------------------

class MotionDetector:
    def __init__(self, config: UpscaleConfig, segmenter_name: Optional[str] = None):
        self.config = config
        self.prev_frame_gray: Optional[np.ndarray] = None
        self.segmenter_name = segmenter_name

    def _to_gray(self, frame: np.ndarray) -> np.ndarray:
        return cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)

    def _compute_optical_flow_mask(self, prev_gray: np.ndarray, curr_gray: np.ndarray) -> np.ndarray:
        flow = cv2.calcOpticalFlowFarneback(
            prev_gray, curr_gray,
            None,
            0.5, 3, 15, 3, 5, 1.2, 0
        )
        mag, _ = cv2.cartToPolar(flow[..., 0], flow[..., 1])
        mask = np.zeros_like(prev_gray, dtype=np.uint8)
        mask[mag > self.config.motion_threshold] = 255
        kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
        mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel, iterations=1)
        mask = cv2.dilate(mask, kernel, iterations=1)
        return mask

    def _apply_segmenter(self, frame: np.ndarray, motion_mask: np.ndarray) -> np.ndarray:
        if not self.segmenter_name:
            return motion_mask
        plugin = PLUGIN_REGISTRY.get_segmenter(self.segmenter_name)
        if not plugin:
            return motion_mask
        seg_mask = plugin.segment_fn(frame)
        combined = np.where((motion_mask > 0) | (seg_mask > 0), 255, 0).astype(np.uint8)
        return combined

    def compute_motion_mask(self, frame: np.ndarray) -> np.ndarray:
        curr_gray = self._to_gray(frame)

        if self.prev_frame_gray is None:
            self.prev_frame_gray = curr_gray
            return np.zeros_like(curr_gray, dtype=np.uint8)

        if self.config.use_optical_flow:
            mask = self._compute_optical_flow_mask(self.prev_frame_gray, curr_gray)
        else:
            diff = cv2.absdiff(curr_gray, self.prev_frame_gray)
            _, mask = cv2.threshold(
                diff,
                self.config.motion_threshold,
                255,
                cv2.THRESH_BINARY
            )
            kernel = cv2.getStructuringElement(cv2.MORPH_ELLIPSE, (3, 3))
            mask = cv2.morphologyEx(mask, cv2.MORPH_OPEN, kernel, iterations=1)
            mask = cv2.dilate(mask, kernel, iterations=1)

        mask = self._filter_small_components(mask)
        mask = self._apply_segmenter(frame, mask)

        self.prev_frame_gray = curr_gray
        return mask

    def _filter_small_components(self, mask: np.ndarray) -> np.ndarray:
        num_labels, labels, stats, _ = cv2.connectedComponentsWithStats(mask, connectivity=8)
        cleaned = np.zeros_like(mask)
        for i in range(1, num_labels):
            area = stats[i, cv2.CC_STAT_AREA]
            if area >= self.config.min_motion_area:
                cleaned[labels == i] = 255
        return cleaned


# ---------------------------------------------------------
# COMPOSITOR
# ---------------------------------------------------------

class Compositor:
    def __init__(self, upscaled_background: np.ndarray, original_size: Tuple[int, int]):
        self.bg_up = upscaled_background
        self.orig_w, self.orig_h = original_size

    def composite(self, frame: np.ndarray, motion_mask: np.ndarray) -> np.ndarray:
        h, w = frame.shape[:2]
        if (w, h) != (self.orig_w, self.orig_h):
            raise RuntimeError("Frame size mismatch with original_size.")

        bg_h, bg_w = self.bg_up.shape[:2]
        frame_up = cv2.resize(frame, (bg_w, bg_h), interpolation=cv2.INTER_LINEAR)
        mask_up = cv2.resize(motion_mask, (bg_w, bg_h), interpolation=cv2.INTER_NEAREST)

        mask_3c = np.stack([mask_up] * 3, axis=2)

        fg = np.where(mask_3c == 255, frame_up, 0)
        bg = np.where(mask_3c == 0, self.bg_up, 0)

        out = np.clip(fg + bg, 0, 255).astype(np.uint8)
        return out


# ---------------------------------------------------------
# VIDEO INPUT
# ---------------------------------------------------------

class VideoInput:
    def __init__(self, source: str, webcam_index: int = 0):
        self.source = source
        self.webcam_index = webcam_index
        self.cap: Optional[cv2.VideoCapture] = None
        self.is_stream = False

    def open(self) -> None:
        if self.source == "webcam":
            log(f"Opening webcam index {self.webcam_index}...")
            self.cap = cv2.VideoCapture(self.webcam_index)
            self.is_stream = True
        elif self.source.startswith("rtsp://"):
            log(f"Opening RTSP stream: {self.source}")
            self.cap = cv2.VideoCapture(self.source)
            self.is_stream = True
        else:
            log(f"Opening video file: {self.source}")
            self.cap = cv2.VideoCapture(self.source)
            self.is_stream = False

        if not self.cap or not self.cap.isOpened():
            raise RuntimeError(f"Failed to open video source: {self.source}")

    def read(self):
        return self.cap.read()

    def get_props(self):
        fps = self.cap.get(cv2.CAP_PROP_FPS)
        if fps <= 0 or np.isnan(fps):
            fps = 30.0
        w = int(self.cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        h = int(self.cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        frame_count = int(self.cap.get(cv2.CAP_PROP_FRAME_COUNT)) if not self.is_stream else -1
        return fps, w, h, frame_count

    def release(self):
        if self.cap:
            self.cap.release()


# ---------------------------------------------------------
# FFmpeg RAW PIPE EXPORT
# ---------------------------------------------------------

class FFmpegRawPipeExporter:
    def __init__(self, out_path: str, fps: float, width: int, height: int):
        self.out_path = out_path
        self.fps = fps
        self.width = width
        self.height = height
        cmd = [
            "ffmpeg",
            "-y",
            "-f", "rawvideo",
            "-pix_fmt", "bgr24",
            "-s", f"{width}x{height}",
            "-r", str(fps),
            "-i", "-",
            "-c:v", "libx264",
            "-pix_fmt", "yuv420p",
            out_path
        ]
        log(f"[FFmpegRawPipe] Starting ffmpeg: {' '.join(cmd)}")
        self.proc = subprocess.Popen(cmd, stdin=subprocess.PIPE)

    def write(self, frame: np.ndarray):
        self.proc.stdin.write(frame.tobytes())

    def close(self):
        try:
            self.proc.stdin.close()
            self.proc.wait()
            log("[FFmpegRawPipe] ffmpeg export completed.")
        except Exception as e:
            log(f"[FFmpegRawPipe] ffmpeg export failed: {e}")


# ---------------------------------------------------------
# PIPELINE
# ---------------------------------------------------------

class StaticBackgroundUpscalerPipeline:
    def __init__(
        self,
        config: UpscaleConfig,
        auto_profile: bool = True,
        use_onnx: bool = False,
        onnx_path: Optional[str] = None,
        auto_onnx: bool = True,
        segmenter_name: Optional[str] = None,
        downloader: Optional[DownloadManager] = None,
    ):
        self.config = config
        self.auto_profile = auto_profile
        self.bg_modeler = BackgroundModeler(config)
        self.motion_detector = MotionDetector(config, segmenter_name=segmenter_name)
        self.bg_upscaler = BackgroundUpscaler(
            scale=config.target_scale,
            use_onnx=use_onnx,
            onnx_path=onnx_path,
            auto=auto_onnx,
            downloader=downloader,
        )
        self.compositor: Optional[Compositor] = None
        self.initialized = False

    def initialize(self, vin: VideoInput) -> None:
        fps, orig_w, orig_h, frame_count = vin.get_props()
        if self.auto_profile and self.config.profile_name == "auto":
            self.config = auto_select_profile(fps, orig_w, orig_h, vin.is_stream)
            self.bg_modeler = BackgroundModeler(self.config)
            self.motion_detector = MotionDetector(self.config)

        log(f"Profile: {self.config.profile_name}")
        log(f"Resolution: {orig_w}x{orig_h}, FPS: {fps}, Frames: {frame_count if frame_count >= 0 else 'stream'}")

        frame_idx = 0
        while frame_idx < self.config.background_build_frames:
            ret, frame = vin.read()
            if not ret:
                break
            self.bg_modeler.accumulate_initial(frame)
            frame_idx += 1

        if frame_idx == 0:
            raise RuntimeError("No frames read from source for background build.")

        self.bg_modeler.borg_read_ahead(vin, self.config.borg_read_ahead_frames)
        self.bg_modeler.build_initial_background()
        background = self.bg_modeler.background
        if background is None:
            raise RuntimeError("Background model not built.")

        bg_up = self.bg_upscaler.upscale(background)
        self.compositor = Compositor(bg_up, (orig_w, orig_h))
        self.initialized = True

    def process_frame(self, frame: np.ndarray) -> Tuple[np.ndarray, np.ndarray]:
        if not self.initialized or self.compositor is None:
            raise RuntimeError("Pipeline not initialized.")

        motion_mask = self.motion_detector.compute_motion_mask(frame)
        self.bg_modeler.update_background_slow(frame, motion_mask)
        enhanced = self.compositor.composite(frame, motion_mask)
        return frame, enhanced


# ---------------------------------------------------------
# GUI
# ---------------------------------------------------------

class UpscalerGUI(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Borg AI Static Background Upscaler (CPU-Only Kill Switch)")
        self.resize(1280, 720)

        self.input_source = ""
        self.webcam_index = 0
        self.profile = "auto"
        self.scale = 2.0
        self.use_onnx = False
        self.onnx_path = None
        self.auto_profile = True
        self.auto_onnx = True
        self.segmenter_name = None

        self.vin: Optional[VideoInput] = None
        self.pipeline: Optional[StaticBackgroundUpscalerPipeline] = None
        self.exporter_ffmpeg: Optional[FFmpegRawPipeExporter] = None

        self.timer = QTimer()
        self.timer.timeout.connect(self.update_frame)

        self.log_widget = QTextEdit()
        self.log_widget.setReadOnly(True)
        self.log_widget.setMaximumHeight(150)

        self.mirror_scanner = MirrorScanner(log_widget=self.log_widget)
        self.downloader = DownloadManager(log_widget=self.log_widget, mirror_scanner=self.mirror_scanner)

        self.ffmpeg_sites_list = QListWidget()
        self.ffmpeg_sites_list.setMaximumHeight(80)
        self.onnx_sites_list = QListWidget()
        self.onnx_sites_list.setMaximumHeight(80)
        self.realesrgan_sites_list = QListWidget()
        self.realesrgan_sites_list.setMaximumHeight(80)
        self.pypi_sites_list = QListWidget()
        self.pypi_sites_list.setMaximumHeight(80)
        self.onnx_sr_sites_list = QListWidget()
        self.onnx_sr_sites_list.setMaximumHeight(80)

        self._build_ui()

    def _build_ui(self):
        self.input_edit = QLineEdit()
        self.input_edit.setPlaceholderText("Video file path, 'webcam', or RTSP URL")

        self.browse_btn = QPushButton("Browse")
        self.browse_btn.setMaximumWidth(80)
        self.browse_btn.clicked.connect(self.browse_file)

        input_row = QHBoxLayout()
        input_row.addWidget(self.input_edit)
        input_row.addWidget(self.browse_btn)

        self.profile_combo = QComboBox()
        self.profile_combo.addItems(["auto", "movies", "youtube", "surveillance"])

        self.scale_edit = QLineEdit("2.0")
        self.scale_edit.setMaximumWidth(80)

        self.webcam_edit = QLineEdit("0")
        self.webcam_edit.setMaximumWidth(60)

        self.use_onnx_check = QCheckBox("Use ONNX SR")
        self.auto_onnx_check = QCheckBox("Auto ONNX")
        self.auto_onnx_check.setChecked(True)

        self.onnx_edit = QLineEdit()
        self.onnx_edit.setPlaceholderText("ONNX model path")
        self.onnx_edit.setMaximumHeight(24)

        self.auto_profile_check = QCheckBox("Auto profile")
        self.auto_profile_check.setChecked(True)

        self.segmenter_combo = QComboBox()
        self.segmenter_combo.addItem("none")
        self.segmenter_combo.addItem("rvm_stub")
        self.segmenter_combo.addItem("modnet_stub")

        self.export_path_edit = QLineEdit()
        self.export_path_edit.setPlaceholderText("Export path (MP4 via FFmpeg raw pipe)")

        self.start_btn = QPushButton("Start")
        self.stop_btn = QPushButton("Stop")
        self.start_btn.clicked.connect(self.start_processing)
        self.stop_btn.clicked.connect(self.stop_processing)

        start_row = QHBoxLayout()
        start_row.addWidget(self.start_btn)
        start_row.addWidget(self.stop_btn)

        controls_box = QGroupBox("Core Controls")
        controls_layout = QVBoxLayout()
        controls_layout.addLayout(input_row)

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Profile"))
        row1.addWidget(self.profile_combo)
        controls_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Scale"))
        row2.addWidget(self.scale_edit)
        row2.addWidget(QLabel("Webcam"))
        row2.addWidget(self.webcam_edit)
        controls_layout.addLayout(row2)

        controls_layout.addWidget(self.auto_profile_check)
        controls_layout.addWidget(self.auto_onnx_check)
        controls_layout.addWidget(self.use_onnx_check)
        controls_layout.addWidget(self.onnx_edit)

        seg_row = QHBoxLayout()
        seg_row.addWidget(QLabel("Segmenter"))
        seg_row.addWidget(self.segmenter_combo)
        controls_layout.addLayout(seg_row)

        controls_layout.addWidget(QLabel("Export MP4 path (FFmpeg raw pipe)"))
        controls_layout.addWidget(self.export_path_edit)

        controls_layout.addLayout(start_row)
        controls_box.setLayout(controls_layout)

        mirror_box = QGroupBox("Mirror Scanner")
        mirror_layout = QVBoxLayout()

        scan_ffmpeg_btn = QPushButton("Scan FFmpeg")
        scan_ffmpeg_btn.clicked.connect(self.scan_ffmpeg_sites)

        scan_onnx_btn = QPushButton("Scan ONNX Runtime")
        scan_onnx_btn.clicked.connect(self.scan_onnx_sites)

        scan_realesrgan_btn = QPushButton("Scan Real-ESRGAN")
        scan_realesrgan_btn.clicked.connect(self.scan_realesrgan_sites)

        scan_pypi_btn = QPushButton("Scan PyPI (onnxruntime)")
        scan_pypi_btn.clicked.connect(self.scan_pypi_sites)

        scan_onnx_sr_btn = QPushButton("Scan ONNX SR Models")
        scan_onnx_sr_btn.clicked.connect(self.scan_onnx_sr_sites)

        dl_ffmpeg_selected_btn = QPushButton("Download selected FFmpeg")
        dl_ffmpeg_selected_btn.clicked.connect(self.download_selected_ffmpeg)

        dl_onnx_selected_btn = QPushButton("Download selected ONNX Runtime")
        dl_onnx_selected_btn.clicked.connect(self.download_selected_onnx)

        dl_realesrgan_selected_btn = QPushButton("Download selected Real-ESRGAN")
        dl_realesrgan_selected_btn.clicked.connect(self.download_selected_realesrgan)

        dl_pypi_selected_btn = QPushButton("Download selected PyPI")
        dl_pypi_selected_btn.clicked.connect(self.download_selected_pypi)

        dl_onnx_sr_selected_btn = QPushButton("Download selected ONNX SR Model")
        dl_onnx_sr_selected_btn.clicked.connect(self.download_selected_onnx_sr)

        mirror_layout.addWidget(scan_ffmpeg_btn)
        mirror_layout.addWidget(self.ffmpeg_sites_list)
        mirror_layout.addWidget(dl_ffmpeg_selected_btn)

        mirror_layout.addWidget(scan_onnx_btn)
        mirror_layout.addWidget(self.onnx_sites_list)
        mirror_layout.addWidget(dl_onnx_selected_btn)

        mirror_layout.addWidget(scan_realesrgan_btn)
        mirror_layout.addWidget(self.realesrgan_sites_list)
        mirror_layout.addWidget(dl_realesrgan_selected_btn)

        mirror_layout.addWidget(scan_pypi_btn)
        mirror_layout.addWidget(self.pypi_sites_list)
        mirror_layout.addWidget(dl_pypi_selected_btn)

        mirror_layout.addWidget(scan_onnx_sr_btn)
        mirror_layout.addWidget(self.onnx_sr_sites_list)
        mirror_layout.addWidget(dl_onnx_sr_selected_btn)

        mirror_box.setLayout(mirror_layout)

        dl_box = QGroupBox("Download Manager")
        dl_layout = QVBoxLayout()
        dl_pip_onnxruntime_btn = QPushButton("pip install onnxruntime")
        dl_pip_onnxruntime_btn.clicked.connect(lambda: self.downloader.install_pip_package("onnxruntime"))
        dl_layout.addWidget(dl_pip_onnxruntime_btn)
        dl_box.setLayout(dl_layout)

        left_container = QWidget()
        left_layout = QVBoxLayout()
        left_layout.addWidget(controls_box)
        left_layout.addWidget(mirror_box)
        left_layout.addWidget(dl_box)
        left_layout.addWidget(QLabel("Log"))
        left_layout.addWidget(self.log_widget)
        left_layout.addStretch()
        left_container.setLayout(left_layout)

        left_scroll = QScrollArea()
        left_scroll.setWidgetResizable(True)
        left_scroll.setWidget(left_container)
        left_scroll.setMinimumWidth(420)

        self.original_label = QLabel("Original")
        self.original_label.setAlignment(Qt.AlignCenter)
        self.enhanced_label = QLabel("Enhanced")
        self.enhanced_label.setAlignment(Qt.AlignCenter)

        self.original_label.setStyleSheet("background-color: #202020; color: #ffffff;")
        self.enhanced_label.setStyleSheet("background-color: #202020; color: #ffffff;")

        video_layout = QHBoxLayout()
        video_layout.addWidget(self.original_label)
        video_layout.addWidget(self.enhanced_label)

        right_container = QWidget()
        right_layout = QVBoxLayout()
        right_layout.addLayout(video_layout)
        right_layout.addStretch()
        right_container.setLayout(right_layout)

        main_layout = QHBoxLayout()
        main_layout.addWidget(left_scroll, 1)
        main_layout.addWidget(right_container, 2)

        self.setLayout(main_layout)

    # Mirror scanner hooks
    def scan_ffmpeg_sites(self):
        self.ffmpeg_sites_list.clear()
        sites = self.mirror_scanner.scan_ffmpeg_sites()
        for s in sites:
            self.ffmpeg_sites_list.addItem(QListWidgetItem(s))

    def scan_onnx_sites(self):
        self.onnx_sites_list.clear()
        sites = self.mirror_scanner.scan_onnxruntime_sites()
        for s in sites:
            self.onnx_sites_list.addItem(QListWidgetItem(s))

    def scan_realesrgan_sites(self):
        self.realesrgan_sites_list.clear()
        sites = self.mirror_scanner.scan_realesrgan_sites()
        for s in sites:
            self.realesrgan_sites_list.addItem(QListWidgetItem(s))

    def scan_pypi_sites(self):
        self.pypi_sites_list.clear()
        sites = self.mirror_scanner.scan_pypi_sites("onnxruntime")
        for s in sites:
            self.pypi_sites_list.addItem(QListWidgetItem(s))

    def scan_onnx_sr_sites(self):
        self.onnx_sr_sites_list.clear()
        sites = self.mirror_scanner.scan_onnx_sr_model_sites()
        for s in sites:
            self.onnx_sr_sites_list.addItem(QListWidgetItem(s))

    def download_selected_ffmpeg(self):
        item = self.ffmpeg_sites_list.currentItem()
        if item:
            url = item.text()
            self.downloader.download_from_url(url, "downloads/ffmpeg")

    def download_selected_onnx(self):
        item = self.onnx_sites_list.currentItem()
        if item:
            url = item.text()
            self.downloader.download_from_url(url, "downloads/onnxruntime")

    def download_selected_realesrgan(self):
        item = self.realesrgan_sites_list.currentItem()
        if item:
            url = item.text()
            self.downloader.download_from_url(url, "models")

    def download_selected_pypi(self):
        item = self.pypi_sites_list.currentItem()
        if item:
            url = item.text()
            self.downloader.download_from_url(url, "downloads/pypi")

    def download_selected_onnx_sr(self):
        item = self.onnx_sr_sites_list.currentItem()
        if item:
            url = item.text()
            path = self.downloader.download_from_url(url, "models")
            PLUGIN_REGISTRY.register_sr_model(
                SRModelPlugin(name="default_sr", onnx_path=path)
            )
            self.log_widget.append(f"Registered ONNX SR model plugin at: {path}")

    # Core pipeline hooks
    def browse_file(self):
        fname, _ = QFileDialog.getOpenFileName(self, "Select Video File", "", "Video Files (*.mp4 *.avi *.mkv *.mov)")
        if fname:
            self.input_edit.setText(fname)

    def start_processing(self):
        self.input_source = self.input_edit.text().strip()
        if not self.input_source:
            self.input_source = "webcam"

        self.profile = self.profile_combo.currentText()
        try:
            self.scale = float(self.scale_edit.text().strip())
        except ValueError:
            self.scale = 2.0

        try:
            self.webcam_index = int(self.webcam_edit.text().strip())
        except ValueError:
            self.webcam_index = 0

        self.auto_profile = self.auto_profile_check.isChecked()
        self.auto_onnx = self.auto_onnx_check.isChecked()
        self.use_onnx = self.use_onnx_check.isChecked()
        self.onnx_path = self.onnx_edit.text().strip() if self.use_onnx else None

        seg_choice = self.segmenter_combo.currentText()
        self.segmenter_name = None if seg_choice == "none" else seg_choice

        export_path = self.export_path_edit.text().strip()

        if self.profile != "auto":
            config = make_profile(self.profile)
        else:
            config = make_profile("auto")
        config.target_scale = self.scale

        if self.use_onnx and not self.onnx_path:
            log("ONNX requested but no path provided; disabling manual ONNX.")
            self.use_onnx = False

        self.vin = VideoInput(self.input_source, webcam_index=self.webcam_index)
        try:
            self.vin.open()
        except Exception as e:
            log(f"Failed to open input: {e}")
            self.log_widget.append(f"Failed to open input: {e}")
            return

        self.pipeline = StaticBackgroundUpscalerPipeline(
            config=config,
            auto_profile=self.auto_profile,
            use_onnx=self.use_onnx,
            onnx_path=self.onnx_path,
            auto_onnx=self.auto_onnx,
            segmenter_name=self.segmenter_name,
            downloader=self.downloader,
        )

        try:
            self.pipeline.initialize(self.vin)
        except Exception as e:
            log(f"Failed to initialize pipeline: {e}")
            self.log_widget.append(f"Failed to initialize pipeline: {e}")
            self.vin.release()
            self.vin = None
            self.pipeline = None
            return

        if export_path:
            fps, w, h, _ = self.vin.get_props()
            self.exporter_ffmpeg = FFmpegRawPipeExporter(export_path, fps, w, h)
        else:
            self.exporter_ffmpeg = None

        self.timer.start(30)

    def stop_processing(self):
        self.timer.stop()
        if self.vin:
            self.vin.release()
            self.vin = None
        if self.exporter_ffmpeg:
            self.exporter_ffmpeg.close()
            self.exporter_ffmpeg = None
        self.pipeline = None

    def update_frame(self):
        if not self.vin or not self.pipeline:
            return

        ret, frame = self.vin.read()
        if not ret:
            self.stop_processing()
            return

        try:
            original, enhanced = self.pipeline.process_frame(frame)
        except Exception as e:
            log(f"Error processing frame: {e}")
            self.log_widget.append(f"Error processing frame: {e}")
            self.stop_processing()
            return

        self._show_image(self.original_label, original)
        self._show_image(self.enhanced_label, enhanced)

        if self.exporter_ffmpeg:
            self.exporter_ffmpeg.write(enhanced)

    def _show_image(self, label: QLabel, img: np.ndarray):
        h, w, ch = img.shape
        bytes_per_line = ch * w
        qimg = QImage(img.data, w, h, bytes_per_line, QImage.Format_BGR888)
        pix = QPixmap.fromImage(qimg)
        label.setPixmap(pix.scaled(label.width(), label.height(), Qt.KeepAspectRatio, Qt.SmoothTransformation))


# ---------------------------------------------------------
# BATCH PROCESSING (NO GUI)
# ---------------------------------------------------------

def process_video_batch(input_path: str, output_path: str):
    log(f"[Batch] Processing {input_path} -> {output_path}")
    vin = VideoInput(input_path)
    vin.open()
    fps, w, h, _ = vin.get_props()

    config = make_profile("auto")
    pipeline = StaticBackgroundUpscalerPipeline(
        config=config,
        auto_profile=True,
        use_onnx=True,
        onnx_path=None,
        auto_onnx=True,
        segmenter_name="rvm_stub",
        downloader=DownloadManager(),
    )
    pipeline.initialize(vin)

    exporter = FFmpegRawPipeExporter(output_path, fps, w, h)

    while True:
        ret, frame = vin.read()
        if not ret:
            break
        _, enhanced = pipeline.process_frame(frame)
        exporter.write(enhanced)

    exporter.close()
    vin.release()
    log(f"[Batch] Completed {input_path}")


def run_batch_mode(input_folder: str, export_folder: str):
    os.makedirs(export_folder, exist_ok=True)
    for fname in os.listdir(input_folder):
        if not fname.lower().endswith((".mp4", ".mkv", ".avi", ".mov")):
            continue
        in_path = os.path.join(input_folder, fname)
        out_path = os.path.join(export_folder, f"borg_{fname}")
        process_video_batch(in_path, out_path)


# ---------------------------------------------------------
# MAIN
# ---------------------------------------------------------

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--batch", type=str, default=None, help="Input folder for batch mode")
    parser.add_argument("--export_folder", type=str, default=None, help="Output folder for batch mode")
    args, _ = parser.parse_known_args()

    if args.batch and args.export_folder:
        run_batch_mode(args.batch, args.export_folder)
        return

    app = QApplication(sys.argv)
    gui = UpscalerGUI()
    gui.show()
    sys.exit(app.exec_())


if __name__ == "__main__":
    main()
