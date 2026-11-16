"""
DominionDeck Studio Video Mixer v6.0
A practical, predictive video-processing workstation for Windows and other
Python desktop platforms.

Core features:
- Camera discovery/selection with synthetic preview fallback.
- Live brightness, saturation, denoise, contrast and sharpening controls.
- Optional adaptive auto-enhancement with a clear ON/OFF control.
- Lightweight trend forecasting and explainable health recommendations.
- Temporal visual-change alerts (not a security/threat detector).
- Before/after preview, snapshots, MP4 recording, presets and persistent settings.
- Responsive tabbed studio UI, bounded logs, safe shutdown and error handling.

Install:
    py -m pip install opencv-python numpy pillow psutil

Optional AI super-resolution:
    Place a compatible custom_sr_model.onnx beside this script and enable
    "Use ONNX super-resolution". The model must accept a 320x180 RGB blob
    and return an image tensor. If unavailable, the app uses high-quality
    interpolation when upscaling is requested.

This application does not expose hidden chain-of-thought. Its "Decision
Rationale" panel provides concise, auditable observations, forecasts and
reasons for each recommendation.
"""

from __future__ import annotations

import json
import os
import queue
import sys
import threading
import time
from collections import deque
from datetime import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

try:
    import cv2
    import numpy as np
    from PIL import Image, ImageTk
except ImportError as exc:
    root = tk.Tk()
    root.withdraw()
    messagebox.showerror(
        "Missing dependency",
        "The Studio Video Mixer needs OpenCV, NumPy and Pillow.\n\n"
        "Install them with:\n"
        "py -m pip install opencv-python numpy pillow\n\n"
        f"Details: {exc}",
    )
    raise SystemExit(1)

try:
    import psutil
except ImportError:
    psutil = None


APP_NAME = "DominionDeck Studio Video Mixer"
APP_VERSION = "6.0"
BASE_DIR = Path(__file__).resolve().parent
CONFIG_FILE = BASE_DIR / "studio_mixer_config_v6.json"
CAPTURE_DIR = BASE_DIR / "captures"
MODEL_FILE = BASE_DIR / "custom_sr_model.onnx"
LOG_LIMIT = 500


class TrendForecaster:
    """Small, dependency-free trend model using recent observations."""

    def __init__(self, size: int = 45):
        self.values = deque(maxlen=size)

    def update(self, value: float) -> tuple[float, str, float]:
        value = float(value)
        self.values.append(value)
        if len(self.values) < 6:
            return value, "Collecting baseline", 0.0

        y = np.asarray(self.values, dtype=np.float64)
        x = np.arange(len(y), dtype=np.float64)
        slope = float(np.polyfit(x, y, 1)[0])
        # Forecast a short horizon, not a long-range promise.
        forecast = float(np.clip(y[-1] + slope * 5.0, 0.0, 240.0))
        if slope < -0.35:
            label = "Declining"
        elif slope > 0.35:
            label = "Improving"
        else:
            label = "Stable"
        return forecast, label, slope


class VisualChangeMonitor:
    """Detects unusual changes in frame brightness/edge density over time."""

    def __init__(self, history_size: int = 90):
        self.history = deque(maxlen=history_size)

    def inspect(self, frame: np.ndarray) -> tuple[bool, float, str]:
        small = cv2.resize(frame, (96, 54), interpolation=cv2.INTER_AREA)
        gray = cv2.cvtColor(small, cv2.COLOR_BGR2GRAY)
        brightness = float(np.mean(gray))
        edges = float(np.mean(cv2.Canny(gray, 60, 140) > 0))
        feature = np.array([brightness, edges], dtype=np.float32)

        if len(self.history) < 12:
            self.history.append(feature)
            return False, 0.0, "Learning visual baseline"

        history = np.asarray(self.history)
        mean = history.mean(axis=0)
        std = np.maximum(history.std(axis=0), np.array([5.0, 0.025]))
        score = float(np.sqrt(np.mean(((feature - mean) / std) ** 2)))
        self.history.append(feature)
        unusual = score >= 3.0
        note = "Unusual visual change" if unusual else "Visual pattern normal"
        return unusual, score, note


class AdaptiveEnhancer:
    """Conservative auto settings derived from measured frame characteristics."""

    @staticmethod
    def suggest(frame: np.ndarray) -> dict:
        gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
        brightness = float(np.mean(gray))
        contrast = float(np.std(gray))
        # Bounded adjustments avoid aggressive oscillation.
        brightness_offset = int(np.clip((118.0 - brightness) * 0.22, -18, 22))
        saturation = float(np.clip(1.12 if brightness < 75 else 1.04, 0.95, 1.15))
        denoise = int(np.clip(3 + (22.0 - contrast) / 7.0, 1, 7))
        clahe = float(np.clip(1.5 + (38.0 - contrast) / 35.0, 1.2, 2.4))
        sharpen = int(np.clip(3 + contrast / 24.0, 2, 5))
        return {
            "brightness": brightness_offset,
            "saturation": saturation,
            "denoise": denoise,
            "clahe": clahe,
            "sharpen": sharpen,
        }


class StudioVideoMixer:
    def __init__(self, root: tk.Tk):
        self.root = root
        self.root.title(f"{APP_NAME}  |  v{APP_VERSION}")
        self.root.geometry("1380x850")
        self.root.minsize(980, 650)
        self.root.configure(bg="#111827")
        self.root.protocol("WM_DELETE_WINDOW", self.close)

        self.running = True
        self.cap = None
        self.camera_index = 0
        self.synthetic_mode = True
        self.latest_raw = None
        self.latest_processed = None
        self.preview_photo = None
        self.writer = None
        self.recording = False
        self.record_path = None
        self.frame_times = deque(maxlen=30)
        self.fps_forecaster = TrendForecaster()
        self.visual_monitor = VisualChangeMonitor()
        self.last_anomaly_log = 0.0
        self.last_settings_save = 0.0
        self.ui_events = queue.Queue()
        self.onnx_net = None
        self.onnx_enabled = False
        self.cuda_available = self._detect_cuda()
        self.frame_count = 0
        self.last_rationale = ""

        self._configure_style()
        self._build_ui()
        self._load_settings()
        self._load_onnx_model()
        self._open_camera()
        self._log("SYSTEM", f"{APP_NAME} v{APP_VERSION} initialized.")
        self._log("SYSTEM", "Predictive analysis uses local frame and performance trends.")
        self._schedule_tick()
        self._schedule_event_drain()

    def _configure_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure(".", font=("Segoe UI", 9))
        style.configure("TFrame", background="#111827")
        style.configure("Panel.TFrame", background="#1f2937")
        style.configure("TLabel", background="#111827", foreground="#e5e7eb")
        style.configure("Panel.TLabel", background="#1f2937", foreground="#e5e7eb")
        style.configure("Title.TLabel", font=("Segoe UI", 17, "bold"),
                        foreground="#f9fafb", background="#111827")
        style.configure("Sub.TLabel", foreground="#9ca3af", background="#111827")
        style.configure("TButton", padding=(10, 6))
        style.configure("Accent.TButton", background="#2563eb", foreground="white")
        style.map("Accent.TButton", background=[("active", "#1d4ed8")])
        style.configure("TNotebook", background="#111827", borderwidth=0)
        style.configure("TNotebook.Tab", padding=(13, 8), background="#273449",
                        foreground="#dbeafe")
        style.map("TNotebook.Tab", background=[("selected", "#2563eb")],
                  foreground=[("selected", "#ffffff")])
        style.configure("TLabelframe", background="#1f2937", foreground="#e5e7eb")
        style.configure("TLabelframe.Label", background="#1f2937",
                        foreground="#93c5fd", font=("Segoe UI", 9, "bold"))

    def _build_ui(self):
        header = ttk.Frame(self.root, padding=(16, 12))
        header.pack(fill=tk.X)
        ttk.Label(header, text="DOMINIONDECK  /  STUDIO MIXER",
                  style="Title.TLabel").pack(side=tk.LEFT)
        ttk.Label(header, text="LIVE VIDEO  •  ADAPTIVE IMAGE PIPELINE  •  PREDICTIVE MONITOR",
                  style="Sub.TLabel").pack(side=tk.LEFT, padx=18, pady=(7, 0))
        self.status_var = tk.StringVar(value="INITIALIZING")
        ttk.Label(header, textvariable=self.status_var).pack(side=tk.RIGHT)

        body = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        body.pack(fill=tk.BOTH, expand=True, padx=12, pady=(0, 12))

        left = ttk.Frame(body, padding=8)
        right = ttk.Frame(body, padding=8)
        body.add(left, weight=3)
        body.add(right, weight=5)

        self.tabs = ttk.Notebook(left)
        self.tabs.pack(fill=tk.BOTH, expand=True)
        self.mix_tab = ttk.Frame(self.tabs, padding=12)
        self.hardware_tab = ttk.Frame(self.tabs, padding=12)
        self.pipeline_tab = ttk.Frame(self.tabs, padding=12)
        self.ai_tab = ttk.Frame(self.tabs, padding=12)
        self.output_tab = ttk.Frame(self.tabs, padding=12)
        self.logs_tab = ttk.Frame(self.tabs, padding=8)
        for tab, name in [
            (self.mix_tab, "Mixer"), (self.hardware_tab, "Hardware"),
            (self.pipeline_tab, "Pipeline"), (self.ai_tab, "AI & Forecast"),
            (self.output_tab, "Record / Export"), (self.logs_tab, "Logs"),
        ]:
            self.tabs.add(tab, text=name)

        self._build_mixer_tab()
        self._build_hardware_tab()
        self._build_pipeline_tab()
        self._build_ai_tab()
        self._build_output_tab()
        self._build_logs_tab()

        preview_panel = ttk.Frame(right, style="Panel.TFrame", padding=10)
        preview_panel.pack(fill=tk.BOTH, expand=True)
        preview_head = ttk.Frame(preview_panel, style="Panel.TFrame")
        preview_head.pack(fill=tk.X)
        ttk.Label(preview_head, text="PROGRAM MONITOR",
                  style="Panel.TLabel", font=("Segoe UI", 11, "bold")).pack(side=tk.LEFT)
        self.preview_mode_var = tk.StringVar(value="PROCESSED")
        ttk.Label(preview_head, textvariable=self.preview_mode_var,
                  style="Panel.TLabel").pack(side=tk.RIGHT)

        self.preview = tk.Canvas(preview_panel, bg="#030712", highlightthickness=0,
                                 width=800, height=450)
        self.preview.pack(fill=tk.BOTH, expand=True, pady=10)
        self.preview.bind("<Configure>", lambda _e: self._render_preview())

        metrics = ttk.Frame(preview_panel, style="Panel.TFrame")
        metrics.pack(fill=tk.X)
        self.fps_var = tk.StringVar(value="FPS  --")
        self.cpu_var = tk.StringVar(value="CPU  --")
        self.forecast_var = tk.StringVar(value="FORECAST  collecting")
        self.camera_var = tk.StringVar(value="SOURCE  synthetic preview")
        for var in (self.fps_var, self.cpu_var, self.forecast_var, self.camera_var):
            ttk.Label(metrics, textvariable=var, style="Panel.TLabel",
                      font=("Consolas", 9)).pack(side=tk.LEFT, padx=(0, 18), pady=4)

        bottom = ttk.Frame(self.root, padding=(14, 5))
        bottom.pack(fill=tk.X)
        self.footer_var = tk.StringVar(value="Ready")
        ttk.Label(bottom, textvariable=self.footer_var, style="Sub.TLabel").pack(side=tk.LEFT)
        ttk.Button(bottom, text="Save Settings", command=self.save_settings).pack(side=tk.RIGHT)

    def _build_mixer_tab(self):
        ttk.Label(self.mix_tab, text="IMAGE CONTROL", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.vars = {}
        self._add_slider(self.mix_tab, "Brightness", "brightness", -50, 50, 0)
        self._add_slider(self.mix_tab, "Saturation", "saturation", 0.0, 2.0, 1.0, resolution=0.05)
        self._add_slider(self.mix_tab, "Denoise strength", "denoise", 0, 10, 3)
        self._add_slider(self.mix_tab, "CLAHE contrast", "contrast", 1.0, 4.0, 1.8, resolution=0.1)
        self._add_slider(self.mix_tab, "Sharpen strength", "sharpen", 0, 5, 1)
        ttk.Separator(self.mix_tab).pack(fill=tk.X, pady=12)
        self.auto_var = tk.BooleanVar(value=False)
        self.auto_button = ttk.Button(self.mix_tab, text="AI AUTO-ENHANCE: OFF",
                                      command=self.toggle_auto, style="Accent.TButton")
        self.auto_button.pack(fill=tk.X, pady=4)
        ttk.Label(self.mix_tab, text="Auto mode analyzes each frame and gently adjusts\n"
                  "image controls. It does not train a remote model.",
                  style="Sub.TLabel", justify=tk.LEFT).pack(anchor="w", pady=5)
        self.compare_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.mix_tab, text="Before / after split preview",
                        variable=self.compare_var).pack(anchor="w", pady=6)
        self._add_slider(self.mix_tab, "Temporal blend (0 = off)", "blend", 0, 8, 0)

    def _build_hardware_tab(self):
        ttk.Label(self.hardware_tab, text="VIDEO INPUT", font=("Segoe UI", 11, "bold")).pack(anchor="w")
        ttk.Label(self.hardware_tab, text="Camera index").pack(anchor="w", pady=(12, 2))
        row = ttk.Frame(self.hardware_tab)
        row.pack(fill=tk.X)
        self.camera_var_select = tk.StringVar(value="0")
        ttk.Entry(row, textvariable=self.camera_var_select, width=8).pack(side=tk.LEFT)
        ttk.Button(row, text="Connect", command=self._open_camera).pack(side=tk.LEFT, padx=6)
        ttk.Button(row, text="Scan cameras", command=self._scan_cameras).pack(side=tk.LEFT)
        ttk.Label(self.hardware_tab, text="Output resolution").pack(anchor="w", pady=(14, 2))
        self.resolution_var = tk.StringVar(value="1280x720")
        ttk.Combobox(self.hardware_tab, textvariable=self.resolution_var,
                     values=["640x480", "1280x720", "1920x1080", "3840x2160"],
                     state="readonly").pack(fill=tk.X)
        ttk.Button(self.hardware_tab, text="Apply resolution",
                   command=self._apply_resolution).pack(fill=tk.X, pady=8)
        self.hw_info = tk.StringVar(value="Checking capture hardware…")
        ttk.Label(self.hardware_tab, textvariable=self.hw_info,
                  style="Sub.TLabel", wraplength=300).pack(anchor="w", pady=12)
        ttk.Label(self.hardware_tab, text="A synthetic test pattern is shown if no camera\n"
                  "can be opened. Camera access depends on Windows privacy settings.",
                  style="Sub.TLabel", wraplength=300).pack(anchor="w")

    def _build_pipeline_tab(self):
        ttk.Label(self.pipeline_tab, text="PROCESSING MODULES",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.module_vars = {}
        for key, label, default in [
            ("denoise_on", "Denoise filter", True),
            ("clahe_on", "Local contrast enhancement", True),
            ("sharpen_on", "Edge sharpening", True),
            ("upscale_on", "2× output upscale", False),
            ("onnx_on", "Use ONNX super-resolution model", False),
            ("anomaly_on", "Visual-change monitor", True),
        ]:
            var = tk.BooleanVar(value=default)
            self.module_vars[key] = var
            ttk.Checkbutton(self.pipeline_tab, text=label, variable=var).pack(anchor="w", pady=5)
        ttk.Separator(self.pipeline_tab).pack(fill=tk.X, pady=10)
        ttk.Label(self.pipeline_tab, text="Pipeline presets").pack(anchor="w")
        self.preset_var = tk.StringVar(value="Balanced Studio")
        ttk.Combobox(self.pipeline_tab, textvariable=self.preset_var,
                     values=["Balanced Studio", "Cinematic Detail", "Low Latency Stream",
                             "Low Light", "Clean / Natural"],
                     state="readonly").pack(fill=tk.X, pady=5)
        ttk.Button(self.pipeline_tab, text="Apply preset",
                   command=self._apply_preset).pack(fill=tk.X)
        ttk.Label(self.pipeline_tab, text="Processing is performed locally. Heavy\n"
                  "filters may reduce frame rate on older CPUs.",
                  style="Sub.TLabel", wraplength=300).pack(anchor="w", pady=12)

    def _build_ai_tab(self):
        ttk.Label(self.ai_tab, text="PREDICTIVE ASSISTANT",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.predict_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(self.ai_tab, text="Enable performance forecasting",
                        variable=self.predict_var).pack(anchor="w", pady=5)
        self.adapt_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(self.ai_tab, text="Allow conservative auto buffer adjustment",
                        variable=self.adapt_var).pack(anchor="w", pady=5)
        self.anomaly_sensitivity = tk.DoubleVar(value=3.0)
        ttk.Label(self.ai_tab, text="Visual-change sensitivity (lower = more alerts)").pack(anchor="w", pady=(12, 2))
        ttk.Scale(self.ai_tab, from_=1.5, to=6.0, variable=self.anomaly_sensitivity,
                  orient=tk.HORIZONTAL).pack(fill=tk.X)
        self.prediction_text = tk.Text(self.ai_tab, height=13, wrap=tk.WORD,
                                       bg="#0b1220", fg="#cbd5e1",
                                       insertbackground="white", relief=tk.FLAT,
                                       font=("Consolas", 9))
        self.prediction_text.pack(fill=tk.BOTH, expand=True, pady=8)
        self.prediction_text.insert("end", "Waiting for performance samples…")
        self.prediction_text.configure(state=tk.DISABLED)

    def _build_output_tab(self):
        ttk.Label(self.output_tab, text="CAPTURE & EXPORT",
                  font=("Segoe UI", 11, "bold")).pack(anchor="w")
        self.record_button = ttk.Button(self.output_tab, text="●  Start recording",
                                         command=self._toggle_recording, style="Accent.TButton")
        self.record_button.pack(fill=tk.X, pady=(12, 6))
        ttk.Button(self.output_tab, text="Capture snapshot",
                   command=self._snapshot).pack(fill=tk.X, pady=5)
        ttk.Button(self.output_tab, text="Choose capture folder",
                   command=self._choose_capture_folder).pack(fill=tk.X, pady=5)
        self.capture_folder_var = tk.StringVar(value=str(CAPTURE_DIR))
        ttk.Label(self.output_tab, textvariable=self.capture_folder_var,
                  style="Sub.TLabel", wraplength=300).pack(anchor="w", pady=8)
        ttk.Label(self.output_tab, text="Recording uses the processed output frame.\n"
                  "The writer is configured to the actual output dimensions.",
                  style="Sub.TLabel", wraplength=300).pack(anchor="w", pady=8)

    def _build_logs_tab(self):
        self.log_text = tk.Text(self.logs_tab, wrap=tk.WORD, bg="#0b1220",
                                fg="#a7f3d0", insertbackground="white",
                                font=("Consolas", 8), relief=tk.FLAT)
        scroll = ttk.Scrollbar(self.logs_tab, command=self.log_text.yview)
        self.log_text.configure(yscrollcommand=scroll.set)
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scroll.pack(side=tk.RIGHT, fill=tk.Y)

    def _add_slider(self, parent, label, key, low, high, default, resolution=1):
        line = ttk.Frame(parent)
        line.pack(fill=tk.X, pady=5)
        ttk.Label(line, text=label, width=22).pack(side=tk.LEFT)
        var = tk.DoubleVar(value=default)
        self.vars[key] = var
        scale = tk.Scale(line, from_=low, to=high, resolution=resolution,
                         orient=tk.HORIZONTAL, variable=var, showvalue=True,
                         bg="#111827", fg="#e5e7eb", troughcolor="#374151",
                         highlightthickness=0, activebackground="#60a5fa",
                         length=190)
        scale.pack(side=tk.RIGHT, fill=tk.X, expand=True)

    def _detect_cuda(self):
        try:
            return hasattr(cv2, "cuda") and cv2.cuda.getCudaEnabledDeviceCount() > 0
        except Exception:
            return False

    def _load_onnx_model(self):
        if not MODEL_FILE.exists():
            self._log("AI", "No custom_sr_model.onnx found; ONNX super-resolution is unavailable.")
            return
        try:
            self.onnx_net = cv2.dnn.readNetFromONNX(str(MODEL_FILE))
            if self.cuda_available:
                try:
                    self.onnx_net.setPreferableBackend(cv2.dnn.DNN_BACKEND_CUDA)
                    self.onnx_net.setPreferableTarget(cv2.dnn.DNN_TARGET_CUDA)
                except Exception:
                    self._log("AI", "CUDA backend unavailable for ONNX; using OpenCV CPU backend.")
            self.onnx_enabled = True
            self._log("AI", "Custom ONNX model loaded. Verify compatibility with your model's input/output shape.")
        except Exception as exc:
            self._log("AI", f"ONNX model could not be loaded: {exc}")

    def _open_camera(self):
        try:
            index = max(0, int(self.camera_var_select.get().strip()))
        except (ValueError, AttributeError):
            index = 0
        if self.cap is not None:
            self.cap.release()
            self.cap = None
        self.camera_index = index
        for backend in (cv2.CAP_DSHOW, cv2.CAP_MSMF, cv2.CAP_ANY):
            candidate = None
            try:
                candidate = cv2.VideoCapture(index, backend)
                candidate.set(cv2.CAP_PROP_BUFFERSIZE, 1)
                if candidate.isOpened():
                    ok, frame = candidate.read()
                    if ok and frame is not None:
                        self.cap = candidate
                        break
            except Exception:
                pass
            if candidate is not None and candidate is not self.cap:
                candidate.release()
        self.synthetic_mode = self.cap is None
        if self.synthetic_mode:
            self.camera_var.set("SOURCE  synthetic test pattern")
            self.hw_info.set("No camera opened. Synthetic preview is active.")
            self._log("CAMERA", f"Camera {index} unavailable; synthetic preview enabled.")
        else:
            self.camera_var.set(f"SOURCE  camera {index}")
            self.hw_info.set(f"Camera {index} connected. CUDA: {'available' if self.cuda_available else 'not available'}")
            self._log("CAMERA", f"Connected to camera {index}.")
        self._apply_resolution(silent=True)

    def _scan_cameras(self):
        found = []
        for idx in range(8):
            test = cv2.VideoCapture(idx, cv2.CAP_DSHOW)
            if test.isOpened():
                ok, _ = test.read()
                if ok:
                    found.append(str(idx))
            test.release()
        if found:
            self.camera_var_select.set(found[0])
            messagebox.showinfo("Camera scan", "Available camera indices: " + ", ".join(found))
        else:
            messagebox.showinfo("Camera scan", "No camera was detected. Synthetic preview remains available.")

    def _apply_resolution(self, silent=False):
        try:
            width, height = [int(x) for x in self.resolution_var.get().split("x")]
        except Exception:
            width, height = 1280, 720
        if self.cap is not None:
            self.cap.set(cv2.CAP_PROP_FRAME_WIDTH, width)
            self.cap.set(cv2.CAP_PROP_FRAME_HEIGHT, height)
        self.output_size = (width, height)
        if not silent:
            self._log("CAMERA", f"Requested capture resolution {width}x{height}.")

    def _synthetic_frame(self):
        width, height = getattr(self, "output_size", (1280, 720))
        width, height = min(width, 1920), min(height, 1080)
        frame = np.zeros((height, width, 3), dtype=np.uint8)
        frame[:] = (18, 28, 43)
        t = time.time()
        cx = int(width * (0.5 + 0.25 * np.sin(t * 0.7)))
        cy = int(height * (0.5 + 0.18 * np.cos(t * 0.9)))
        cv2.circle(frame, (cx, cy), max(20, height // 9), (190, 95, 35), -1)
        cv2.circle(frame, (cx, cy), max(10, height // 16), (245, 190, 90), -1)
        for x in range(0, width, max(40, width // 16)):
            cv2.line(frame, (x, 0), (x, height), (35, 48, 65), 1)
        for y in range(0, height, max(40, height // 9)):
            cv2.line(frame, (0, y), (width, y), (35, 48, 65), 1)
        cv2.putText(frame, "STUDIO MIXER  /  SYNTHETIC INPUT",
                    (max(20, width // 18), height // 2),
                    cv2.FONT_HERSHEY_SIMPLEX, max(0.6, width / 1800),
                    (230, 240, 250), 2, cv2.LINE_AA)
        return frame

    def _get_frame(self):
        if self.cap is not None and self.cap.isOpened():
            ok, frame = self.cap.read()
            if ok and frame is not None and frame.size:
                return frame
            self._log("CAMERA", "Frame read failed; switching to synthetic preview.")
            self.cap.release()
            self.cap = None
            self.synthetic_mode = True
        return self._synthetic_frame()

    def _process_frame(self, frame):
        result = frame.copy()
        if self.auto_var.get():
            values = AdaptiveEnhancer.suggest(frame)
            brightness = values["brightness"]
            saturation = values["saturation"]
            denoise = values["denoise"]
            clahe_clip = values["clahe"]
            sharpen = values["sharpen"]
        else:
            brightness = int(self.vars["brightness"].get())
            saturation = float(self.vars["saturation"].get())
            denoise = int(self.vars["denoise"].get())
            clahe_clip = float(self.vars["contrast"].get())
            sharpen = int(self.vars["sharpen"].get())

        if brightness:
            result = cv2.convertScaleAbs(result, alpha=1.0, beta=brightness)
        if abs(saturation - 1.0) > 0.01:
            hsv = cv2.cvtColor(result, cv2.COLOR_BGR2HSV).astype(np.float32)
            hsv[:, :, 1] = np.clip(hsv[:, :, 1] * saturation, 0, 255)
            result = cv2.cvtColor(hsv.astype(np.uint8), cv2.COLOR_HSV2BGR)

        if self.module_vars["denoise_on"].get() and denoise > 0:
            # Bilateral filter is faster than non-local means for interactive use.
            diameter = 5 if denoise <= 4 else 7
            result = cv2.bilateralFilter(result, diameter, 18 + denoise * 3, 18 + denoise * 3)

        if self.module_vars["clahe_on"].get():
            lab = cv2.cvtColor(result, cv2.COLOR_BGR2LAB)
            l, a, b = cv2.split(lab)
            clahe = cv2.createCLAHE(clipLimit=clahe_clip, tileGridSize=(8, 8))
            result = cv2.cvtColor(cv2.merge((clahe.apply(l), a, b)), cv2.COLOR_LAB2BGR)

        if self.module_vars["onnx_on"].get() and self.onnx_enabled and self.onnx_net is not None:
            try:
                blob = cv2.dnn.blobFromImage(cv2.resize(result, (320, 180)),
                                             1.0 / 255.0, (320, 180), swapRB=True)
                self.onnx_net.setInput(blob)
                out = self.onnx_net.forward()
                out = np.asarray(out)
                if out.ndim == 4:
                    out = out[0]
                if out.ndim == 3 and out.shape[0] in (1, 3, 4):
                    out = out[:3].transpose(1, 2, 0)
                if out.ndim == 3 and out.shape[2] >= 3:
                    if out.max() <= 1.5:
                        out = out * 255.0
                    out = np.clip(out[:, :, :3], 0, 255).astype(np.uint8)
                    out = cv2.cvtColor(out, cv2.COLOR_RGB2BGR)
                    result = cv2.resize(out, (frame.shape[1], frame.shape[0]))
            except Exception as exc:
                self.module_vars["onnx_on"].set(False)
                self._log("AI", f"ONNX inference disabled after model error: {exc}")

        if self.module_vars["upscale_on"].get():
            result = cv2.resize(result, None, fx=2, fy=2, interpolation=cv2.INTER_LANCZOS4)

        if self.module_vars["sharpen_on"].get() and sharpen > 0:
            blurred = cv2.GaussianBlur(result, (0, 0), 1.2)
            result = cv2.addWeighted(result, 1.0 + 0.18 * sharpen,
                                     blurred, -0.18 * sharpen, 0)

        return result

    def _schedule_tick(self):
        if self.running:
            self._tick()

    def _tick(self):
        if not self.running:
            return
        started = time.perf_counter()
        try:
            raw = self._get_frame()
            processed = self._process_frame(raw)
            self.latest_raw = raw
            self.latest_processed = processed
            self.frame_count += 1

            now = time.perf_counter()
            self.frame_times.append(now)
            fps = (len(self.frame_times) - 1) / max(
                self.frame_times[-1] - self.frame_times[0], 1e-6
            ) if len(self.frame_times) > 1 else 0.0

            cpu = psutil.cpu_percent(interval=None) if psutil else 0.0
            forecast, trend, slope = self.fps_forecaster.update(fps)
            self.fps_var.set(f"FPS  {fps:5.1f}")
            self.cpu_var.set(f"CPU  {cpu:4.0f}%")
            self.forecast_var.set(f"5-SAMPLE TREND  {forecast:4.1f} ({trend})")
            self.camera_var.set("SOURCE  synthetic" if self.synthetic_mode else f"SOURCE  camera {self.camera_index}")
            self.status_var.set("● RECORDING" if self.recording else "● LIVE")
            self._update_rationale(fps, forecast, trend, slope, cpu, processed)

            if self.recording and self.writer is not None:
                frame_to_write = processed
                if (frame_to_write.shape[1], frame_to_write.shape[0]) != self.record_size:
                    frame_to_write = cv2.resize(frame_to_write, self.record_size)
                self.writer.write(frame_to_write)

            if self.module_vars["anomaly_on"].get():
                unusual, score, note = self.visual_monitor.inspect(raw)
                if unusual and score >= float(self.anomaly_sensitivity.get()):
                    if time.time() - self.last_anomaly_log > 5:
                        self._log("VISUAL", f"{note}; deviation score {score:.2f}. This is not a threat verdict.")
                        self.last_anomaly_log = time.time()

            self._render_preview()
            self.footer_var.set(
                f"Frame {self.frame_count:,}  |  Processing {((time.perf_counter()-started)*1000):.1f} ms  |  Local analysis"
            )
        except Exception as exc:
            self._log("ERROR", f"Frame pipeline error: {exc}")
            self.footer_var.set(f"Pipeline warning: {exc}")
        # Adaptive cadence: target around 30 FPS, avoid a busy 10 ms loop.
        self.root.after(15, self._schedule_tick)

    def _update_rationale(self, fps, forecast, trend, slope, cpu, frame):
        if not self.predict_var.get():
            return
        reasons = []
        if fps < 12:
            recommendation = "Reduce denoise/upscale or lower camera resolution."
            reasons.append("Measured frame rate is below 12 FPS.")
        elif cpu > 85:
            recommendation = "CPU headroom is limited; disable expensive filters."
            reasons.append(f"CPU utilization is elevated at {cpu:.0f}%.")
        elif trend == "Declining":
            recommendation = "Watch the next samples; consider a lighter pipeline."
            reasons.append(f"Recent FPS slope is {slope:.2f} FPS/sample.")
        elif trend == "Improving":
            recommendation = "Pipeline performance is improving."
            reasons.append(f"Recent FPS slope is +{slope:.2f} FPS/sample.")
        else:
            recommendation = "No performance intervention is currently indicated."
            reasons.append("Recent performance trend is stable or still baselining.")
        if self.auto_var.get():
            reasons.append("Adaptive enhancement is ON; image controls are selected from current frame statistics.")
        else:
            reasons.append("Adaptive enhancement is OFF; manual controls are active.")
        content = (
            f"OBSERVATIONS\n"
            f"  Measured FPS: {fps:.1f}\n"
            f"  Short-horizon estimate: {forecast:.1f} ({trend})\n"
            f"  CPU load: {cpu:.0f}%\n\n"
            f"DECISION RATIONALE\n"
            + "\n".join("  • " + item for item in reasons)
            + f"\n\nRECOMMENDATION\n  {recommendation}\n\n"
            "Forecasts are estimates from recent local samples, not guarantees."
        )
        self.prediction_text.configure(state=tk.NORMAL)
        self.prediction_text.delete("1.0", tk.END)
        self.prediction_text.insert("1.0", content)
        self.prediction_text.configure(state=tk.DISABLED)

    def _render_preview(self):
        if self.latest_processed is None:
            return
        frame = self.latest_processed
        if self.compare_var.get() and self.latest_raw is not None:
            raw = cv2.resize(self.latest_raw, (frame.shape[1], frame.shape[0]))
            frame = np.hstack((raw, frame))
            self.preview_mode_var.set("BEFORE  |  AFTER")
        else:
            self.preview_mode_var.set("PROCESSED")
        width = max(1, self.preview.winfo_width())
        height = max(1, self.preview.winfo_height())
        h, w = frame.shape[:2]
        scale = min(width / w, height / h)
        display = cv2.resize(frame, (max(1, int(w * scale)), max(1, int(h * scale))),
                             interpolation=cv2.INTER_AREA if scale < 1 else cv2.INTER_LINEAR)
        display = cv2.cvtColor(display, cv2.COLOR_BGR2RGB)
        self.preview_photo = ImageTk.PhotoImage(Image.fromarray(display))
        self.preview.delete("all")
        self.preview.create_image(width // 2, height // 2, image=self.preview_photo, anchor=tk.CENTER)

    def toggle_auto(self):
        self.auto_var.set(not self.auto_var.get())
        self.auto_button.configure(
            text=f"AI AUTO-ENHANCE: {'ON' if self.auto_var.get() else 'OFF'}"
        )
        self._log("AI", f"Adaptive auto-enhancement {'enabled' if self.auto_var.get() else 'disabled'}.")
        self.save_settings(silent=True)

    def _apply_preset(self):
        preset = self.preset_var.get()
        profiles = {
            "Balanced Studio": (0, 1.0, 3, 1.8, 1, True, True, True, False),
            "Cinematic Detail": (2, 1.08, 4, 2.2, 3, True, True, True, False),
            "Low Latency Stream": (0, 1.0, 0, 1.3, 1, False, False, True, False),
            "Low Light": (15, 1.12, 6, 2.5, 2, True, True, True, False),
            "Clean / Natural": (0, 1.0, 2, 1.5, 0, True, False, False, False),
        }
        b, s, d, c, sh, den, clahe, sharp, upscale = profiles.get(
            preset, profiles["Balanced Studio"]
        )
        for key, value in [("brightness", b), ("saturation", s), ("denoise", d),
                           ("contrast", c), ("sharpen", sh)]:
            self.vars[key].set(value)
        self.module_vars["denoise_on"].set(den)
        self.module_vars["clahe_on"].set(clahe)
        self.module_vars["sharpen_on"].set(sharp)
        self.module_vars["upscale_on"].set(upscale)
        self.auto_var.set(False)
        self.auto_button.configure(text="AI AUTO-ENHANCE: OFF")
        self._log("PRESET", f"Applied '{preset}'.")

    def _toggle_recording(self):
        if not self.recording:
            if self.latest_processed is None:
                messagebox.showwarning("Recording", "No video frame is available yet.")
                return
            CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
            filename = CAPTURE_DIR / f"studio_{datetime.now():%Y%m%d_%H%M%S}.mp4"
            frame = self.latest_processed
            self.record_size = (frame.shape[1], frame.shape[0])
            fourcc = cv2.VideoWriter_fourcc(*"mp4v")
            writer = cv2.VideoWriter(str(filename), fourcc, 30.0, self.record_size)
            if not writer.isOpened():
                writer.release()
                messagebox.showerror("Recording", "Could not create the MP4 file. Check the capture folder and codec support.")
                return
            self.writer = writer
            self.record_path = filename
            self.recording = True
            self.record_button.configure(text="■  Stop recording")
            self._log("RECORD", f"Recording started: {filename}")
        else:
            self._stop_recording()

    def _stop_recording(self):
        if self.writer is not None:
            self.writer.release()
            self.writer = None
        self.recording = False
        self.record_button.configure(text="●  Start recording")
        if self.record_path:
            self._log("RECORD", f"Recording saved: {self.record_path}")
            self.record_path = None

    def _snapshot(self):
        if self.latest_processed is None:
            messagebox.showwarning("Snapshot", "No frame is available yet.")
            return
        CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
        path = CAPTURE_DIR / f"snapshot_{datetime.now():%Y%m%d_%H%M%S}.jpg"
        if cv2.imwrite(str(path), self.latest_processed):
            self._log("CAPTURE", f"Snapshot saved: {path}")
            self.footer_var.set(f"Snapshot saved: {path}")
        else:
            messagebox.showerror("Snapshot", "Could not save the snapshot.")

    def _choose_capture_folder(self):
        global CAPTURE_DIR
        selected = filedialog.askdirectory(initialdir=str(CAPTURE_DIR))
        if selected:
            CAPTURE_DIR = Path(selected)
            self.capture_folder_var.set(str(CAPTURE_DIR))
            self._log("CAPTURE", f"Capture folder set to {CAPTURE_DIR}")

    def _log(self, category, message):
        stamp = datetime.now().strftime("%H:%M:%S")
        line = f"[{stamp}] [{category}] {message}\n"
        if hasattr(self, "log_text"):
            self.log_text.insert(tk.END, line)
            # Bound widget memory.
            line_count = int(self.log_text.index("end-1c").split(".")[0])
            if line_count > LOG_LIMIT:
                self.log_text.delete("1.0", f"{line_count-LOG_LIMIT}.0")
            self.log_text.see(tk.END)

    def _schedule_event_drain(self):
        if not self.running:
            return
        while True:
            try:
                callback, args = self.ui_events.get_nowait()
            except queue.Empty:
                break
            try:
                callback(*args)
            except Exception:
                pass
        self.root.after(100, self._schedule_event_drain)

    def save_settings(self, silent=False):
        config = {
            "version": APP_VERSION,
            "camera_index": self.camera_var_select.get(),
            "resolution": self.resolution_var.get(),
            "capture_folder": str(CAPTURE_DIR),
            "auto_enhance": self.auto_var.get(),
            "compare": self.compare_var.get(),
            "predictive": self.predict_var.get(),
            "adaptive_buffer": self.adapt_var.get(),
            "anomaly_sensitivity": self.anomaly_sensitivity.get(),
            "controls": {key: var.get() for key, var in self.vars.items()},
            "modules": {key: var.get() for key, var in self.module_vars.items()},
            "preset": self.preset_var.get(),
        }
        try:
            temp = CONFIG_FILE.with_suffix(".tmp")
            temp.write_text(json.dumps(config, indent=2), encoding="utf-8")
            temp.replace(CONFIG_FILE)
            if not silent:
                self._log("CONFIG", f"Settings saved to {CONFIG_FILE.name}")
                self.footer_var.set("Settings saved.")
        except Exception as exc:
            self._log("ERROR", f"Could not save settings: {exc}")
            if not silent:
                messagebox.showerror("Settings", f"Could not save settings:\n{exc}")

    def _load_settings(self):
        global CAPTURE_DIR
        if not CONFIG_FILE.exists():
            return
        try:
            config = json.loads(CONFIG_FILE.read_text(encoding="utf-8"))
            self.camera_var_select.set(str(config.get("camera_index", "0")))
            self.resolution_var.set(config.get("resolution", "1280x720"))
            self.auto_var.set(bool(config.get("auto_enhance", False)))
            self.auto_button.configure(text=f"AI AUTO-ENHANCE: {'ON' if self.auto_var.get() else 'OFF'}")
            self.compare_var.set(bool(config.get("compare", False)))
            self.predict_var.set(bool(config.get("predictive", True)))
            self.adapt_var.set(bool(config.get("adaptive_buffer", False)))
            self.anomaly_sensitivity.set(float(config.get("anomaly_sensitivity", 3.0)))
            for key, value in config.get("controls", {}).items():
                if key in self.vars:
                    self.vars[key].set(value)
            for key, value in config.get("modules", {}).items():
                if key in self.module_vars:
                    self.module_vars[key].set(bool(value))
            self.preset_var.set(config.get("preset", "Balanced Studio"))
            folder = config.get("capture_folder")
            if folder:
                CAPTURE_DIR = Path(folder)
                self.capture_folder_var.set(str(CAPTURE_DIR))
            self._log("CONFIG", "Saved settings loaded.")
        except Exception as exc:
            self._log("CONFIG", f"Settings could not be loaded; defaults retained: {exc}")

    def close(self):
        if not self.running:
            return
        self.running = False
        try:
            self.save_settings(silent=True)
            self._stop_recording()
            if self.cap is not None:
                self.cap.release()
            if self.onnx_net is not None:
                self.onnx_net = None
        except Exception:
            pass
        self.root.destroy()


def main():
    root = tk.Tk()
    StudioVideoMixer(root)
    root.mainloop()


if __name__ == "__main__":
    main()
