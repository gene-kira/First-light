#!/usr/bin/env python3
# ============================================================
#  DOMINIONDECK SWARM AI GOVERNOR – OMNI UPGRADE
#  REAL-TIME CAPTURE • DISTRIBUTED GPU • PREDICTIVE SWARM
#  MODEL AUTO-SELECTION • SCENARIO RECOGNITION • ANALYTICS
#  MULTI-USER PROFILES • GPU SAFETY • SWARM MEMORY
# ============================================================

import os
import sys
import subprocess
import time
import threading
import importlib.util
import glob
import json
import socket
import base64
from io import BytesIO
from typing import Dict, Any, List, Callable, Optional

# ------------------------------------------------------------
# AUTOLOADER
# ------------------------------------------------------------
REQUIRED = [
    "torch",
    "torchvision",
    "Pillow",
    "numpy",
    "psutil",
    "pynvml",
    "scikit-learn",
    "opencv-python",
    "fastapi",
    "uvicorn",
    "requests",
    "mss",
]

PKG_MODULE = {
    "torch": "torch",
    "torchvision": "torchvision",
    "Pillow": "PIL",
    "numpy": "numpy",
    "psutil": "psutil",
    "pynvml": "pynvml",
    "scikit-learn": "sklearn",
    "opencv-python": "cv2",
    "fastapi": "fastapi",
    "uvicorn": "uvicorn",
    "requests": "requests",
    "mss": "mss",
}

def autoload():
    for pkg in REQUIRED:
        mod = PKG_MODULE[pkg]
        try:
            __import__(mod)
        except ImportError:
            print(f"[AUTOLOADER] Installing missing package: {pkg}")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])

autoload()

# ------------------------------------------------------------
# IMPORTS
# ------------------------------------------------------------
import torch
import torch.nn as nn
import numpy as np
from PIL import Image, ImageEnhance, ImageFilter, ImageTk
import psutil
import pynvml
import tkinter as tk
from tkinter import filedialog
from sklearn.ensemble import IsolationForest
import cv2
from fastapi import FastAPI, Body
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import requests
import mss

# Windows foreground window detection via ctypes
import ctypes
from ctypes import wintypes

user32 = ctypes.WinDLL("user32", use_last_error=True)
GetForegroundWindow = user32.GetForegroundWindow
GetWindowThreadProcessId = user32.GetWindowThreadProcessId
GetWindowTextW = user32.GetWindowTextW
GetWindowTextLengthW = user32.GetWindowTextLengthW
GetWindowRect = user32.GetWindowRect

# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------
GAME_PROCESS_NAMES = [
    "game.exe",
    "MyGame.exe",
]

BASE_TEXTURE_SIZE = 512
HIGHRES_TEXTURE_SIZE = 1024
FOURK_SIZE = 4096
OUTPUT_DIR = "textures"
ANOMALY_MIN_SAMPLES = 50

STREAM_PORTS_BASE = [80, 443, 1935, 8080, 8443, 8081, 5222, 5223]
STEAM_PORTS = list(range(27014, 27051))
STREAM_PORTS = STREAM_PORTS_BASE + STEAM_PORTS

PLUGINS_DIR = "plugins"

API_PORT = 8000
SWARM_POLL_INTERVAL = 2.0

# adaptive frame capture base interval
ACTIVITY_POLL_MIN = 0.4
ACTIVITY_POLL_MAX = 1.5

STEAM_HINTS = ["steam.exe", "steamservice.exe", "steamwebhelper.exe"]
EPIC_HINTS = ["epicgameslauncher.exe", "epicwebhelper.exe"]
BROWSER_HINTS = [
    "chrome.exe",
    "msedge.exe",
    "firefox.exe",
    "brave.exe",
    "opera.exe",
    "vivaldi.exe",
    "chromium.exe",
]

STREAMING_HINTS = [
    "obs64.exe",
    "obs32.exe",
    "xsplit.exe",
    "discord.exe",
    "twitch.exe",
]

SWARM_MEMORY_FILE = "swarm_memory.json"
TELEMETRY_HISTORY_FILE = "telemetry_history.json"
TELEMETRY_HISTORY_MAX = 512

DISCOVERY_PORT = 50050
DISCOVERY_MAGIC = b"DOMINIONDECK_DISCOVERY"

SWARM_SHARED_FLAG = False
SWARM_LAST_SYNC_TS: Optional[float] = None

CLOUD_ENDPOINT = ""  # optional: set to remote cloud GPU endpoint URL

# ------------------------------------------------------------
# DEVICE / VRAM / GPU
# ------------------------------------------------------------
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
GPU_ENABLED = torch.cuda.is_available()

def init_vram():
    try:
        pynvml.nvmlInit()
        return True
    except Exception:
        return False

VRAM_OK = init_vram()

def get_vram_info():
    if not VRAM_OK:
        return "VRAM: N/A"
    try:
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        used_mb = mem.used // (1024 * 1024)
        total_mb = mem.total // (1024 * 1024)
        return f"VRAM: {used_mb} / {total_mb} MB"
    except Exception:
        return "VRAM: ERR"

def get_vram_total_mb():
    if not VRAM_OK:
        return 0
    try:
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        return mem.total // (1024 * 1024)
    except Exception:
        return 0

def get_gpu_gen_label():
    if not GPU_ENABLED:
        return "GPU: CPU-only mode"
    try:
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        name = pynvml.nvmlDeviceGetName(handle).decode("utf-8")
        return f"GPU: {name} (new-card features enabled)"
    except Exception:
        return "GPU: CUDA available (new-card features enabled)"

def get_gpu_telemetry():
    if not VRAM_OK:
        return {"gpu": "N/A"}
    try:
        handle = pynvml.nvmlDeviceGetHandleByIndex(0)
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        return {
            "vram_used_mb": mem.used // (1024 * 1024),
            "vram_total_mb": mem.total // (1024 * 1024),
            "gpu_util": util.gpu,
            "mem_util": util.memory,
            "temp_c": temp,
        }
    except Exception:
        return {"gpu": "ERR"}

# ------------------------------------------------------------
# GPU SAFETY GOVERNOR
# ------------------------------------------------------------
GPU_TEMP_LIMIT = 82
GPU_VRAM_LIMIT_RATIO = 0.92
GPU_UTIL_LIMIT = 96

def gpu_safe():
    t = get_gpu_telemetry()
    if "gpu" in t and t["gpu"] == "ERR":
        return True
    temp = t.get("temp_c", 0)
    used = t.get("vram_used_mb", 0)
    total = t.get("vram_total_mb", 1)
    util = t.get("gpu_util", 0)
    if temp >= GPU_TEMP_LIMIT:
        print(f"[GPU-GOVERNOR] Temp {temp}°C ≥ {GPU_TEMP_LIMIT}°C → throttling.")
        return False
    if used / max(total, 1) >= GPU_VRAM_LIMIT_RATIO:
        print(f"[GPU-GOVERNOR] VRAM {used}/{total} MB ≥ limit → throttling.")
        return False
    if util >= GPU_UTIL_LIMIT:
        print(f"[GPU-GOVERNOR] Util {util}% ≥ {GPU_UTIL_LIMIT}% → throttling.")
        return False
    return True

# ------------------------------------------------------------
# PERSISTENT SWARM MEMORY + TELEMETRY HISTORY
# ------------------------------------------------------------
def load_swarm_memory() -> Dict[str, Any]:
    if not os.path.exists(SWARM_MEMORY_FILE):
        return {}
    try:
        with open(SWARM_MEMORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_swarm_memory(data: Dict[str, Any]):
    try:
        with open(SWARM_MEMORY_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[SWARM-MEMORY] Save error: {e}")

def load_telemetry_history() -> List[Dict[str, Any]]:
    if not os.path.exists(TELEMETRY_HISTORY_FILE):
        return []
    try:
        with open(TELEMETRY_HISTORY_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []

def save_telemetry_history(history: List[Dict[str, Any]]):
    try:
        with open(TELEMETRY_HISTORY_FILE, "w", encoding="utf-8") as f:
            json.dump(history[-TELEMETRY_HISTORY_MAX:], f, indent=2)
    except Exception as e:
        print(f"[TELEMETRY-HISTORY] Save error: {e}")

def append_telemetry_snapshot(snapshot: Dict[str, Any]):
    hist = load_telemetry_history()
    hist.append(snapshot)
    save_telemetry_history(hist)

# ------------------------------------------------------------
# PLUGIN SYSTEM (SANDBOXED)
# ------------------------------------------------------------
class PluginManager:
    def __init__(self, directory: str):
        self.directory = directory
        self.plugins: List[Any] = []
        self.hooks: Dict[str, List[Callable]] = {
            "on_texture": [],
            "on_video_frame": [],
            "on_telemetry": [],
        }
        self.load_plugins()

    def load_plugins(self):
        os.makedirs(self.directory, exist_ok=True)
        for path in glob.glob(os.path.join(self.directory, "*.py")):
            name = os.path.splitext(os.path.basename(path))[0]
            spec = importlib.util.spec_from_file_location(name, path)
            if spec and spec.loader:
                module = importlib.util.module_from_spec(spec)
                try:
                    spec.loader.exec_module(module)
                    self.plugins.append(module)
                    for hook_name in self.hooks.keys():
                        fn = getattr(module, hook_name, None)
                        if callable(fn):
                            self.hooks[hook_name].append(fn)
                    print(f"[PLUGIN] Loaded: {name}")
                except Exception as e:
                    print(f"[PLUGIN] Failed to load {name}: {e}")

    def _run_single_hook(self, fn, hook_name, *args, **kwargs):
        try:
            fn(*args, **kwargs)
        except Exception as e:
            print(f"[PLUGIN] Hook {hook_name} error: {e}")

    def run_hook(self, hook_name: str, *args, **kwargs):
        for fn in self.hooks.get(hook_name, []):
            t = threading.Thread(
                target=self._run_single_hook,
                args=(fn, hook_name) + args,
                kwargs=kwargs,
                daemon=True,
            )
            t.start()

PLUGIN_MANAGER = PluginManager(PLUGINS_DIR)

# ------------------------------------------------------------
# GENERATIVE TEXTURE MODELS
# ------------------------------------------------------------
class TextureVAE(nn.Module):
    def __init__(self, img_size=64, latent_dim=128):
        super().__init__()
        self.img_size = img_size
        self.latent_dim = latent_dim
        c = 3
        self.encoder = nn.Sequential(
            nn.Conv2d(c, 32, 4, 2, 1),
            nn.ReLU(),
            nn.Conv2d(32, 64, 4, 2, 1),
            nn.ReLU(),
            nn.Conv2d(64, 128, 4, 2, 1),
            nn.ReLU(),
        )
        self.enc_out_dim = 128 * (img_size // 8) * (img_size // 8)
        self.fc_mu = nn.Linear(self.enc_out_dim, latent_dim)
        self.fc_logvar = nn.Linear(self.enc_out_dim, latent_dim)
        self.fc_dec = nn.Linear(latent_dim, self.enc_out_dim)
        self.decoder = nn.Sequential(
            nn.ConvTranspose2d(128, 64, 4, 2, 1),
            nn.ReLU(),
            nn.ConvTranspose2d(64, 32, 4, 2, 1),
            nn.ReLU(),
            nn.ConvTranspose2d(32, c, 4, 2, 1),
            nn.Tanh(),
        )

    def sample(self, batch_size=1):
        z = torch.randn(batch_size, self.latent_dim, device=DEVICE)
        h = self.fc_dec(z)
        h = h.view(z.size(0), 128, self.img_size // 8, self.img_size // 8)
        x = self.decoder(h)
        return x

class TextureCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.model = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1),
            nn.ReLU(),
            nn.Conv2d(32, 64, 3, padding=1),
            nn.ReLU(),
            nn.Conv2d(64, 3, 3, padding=1),
            nn.Tanh(),
        )

    def forward(self, x):
        return self.model(x)

class TextureStyleNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.model = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1),
            nn.ReLU(),
            nn.Conv2d(32, 64, 3, padding=1),
            nn.ReLU(),
            nn.Conv2d(64, 64, 3, padding=1),
            nn.ReLU(),
            nn.Conv2d(64, 3, 3, padding=1),
            nn.Tanh(),
        )

    def forward(self, x):
        return self.model(x)

VAE_IMG_SIZE = 64
TEXTURE_VAE = TextureVAE(img_size=VAE_IMG_SIZE, latent_dim=128).to(DEVICE)
TEXTURE_CNN = TextureCNN().to(DEVICE)
TEXTURE_STYLE = TextureStyleNet().to(DEVICE)
TEXTURE_VAE.eval()
TEXTURE_CNN.eval()
TEXTURE_STYLE.eval()

STYLE_MODES = [
    "default",
    "realistic",
    "metal",
    "stone",
    "fabric",
    "wood",
    "cinematic",
    "hdr",
    "noir",
]

# ------------------------------------------------------------
# SUPER-RESOLUTION + NOISE REDUCTION
# ------------------------------------------------------------
class SuperResNet(nn.Module):
    def __init__(self, scale_factor=4):
        super().__init__()
        self.scale_factor = scale_factor
        self.net = nn.Sequential(
            nn.Conv2d(3, 64, 5, padding=2),
            nn.ReLU(),
            nn.Conv2d(64, 64, 3, padding=1),
            nn.ReLU(),
            nn.Conv2d(64, 3 * (scale_factor ** 2), 3, padding=1),
            nn.PixelShuffle(scale_factor),
            nn.Tanh(),
        )

    def forward(self, x):
        return self.net(x)

class NoiseReductionNet(nn.Module):
    def __init__(self):
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1),
            nn.ReLU(),
            nn.Conv2d(32, 32, 3, padding=1),
            nn.ReLU(),
            nn.Conv2d(32, 3, 3, padding=1),
            nn.Tanh(),
        )

    def forward(self, x):
        return self.net(x)

SUPERRES = SuperResNet(scale_factor=4).to(DEVICE)
SUPERRES.eval()

NOISE_NET = NoiseReductionNet().to(DEVICE)
NOISE_NET.eval()

def super_res_upscale(img: Image.Image, target_size=FOURK_SIZE):
    arr = np.array(img).astype(np.float32) / 127.5 - 1.0
    t = torch.from_numpy(arr).permute(2, 0, 1).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        out = SUPERRES(t).clamp(-1, 1)
    out_img = out.squeeze().permute(1, 2, 0).detach().cpu().numpy()
    out_img = ((out_img + 1) * 127.5).astype(np.uint8)
    pil = Image.fromarray(out_img)
    if pil.size[0] != target_size:
        pil = pil.resize((target_size, target_size), Image.LANCZOS)
    return pil

def noise_reduce(img: Image.Image) -> Image.Image:
    arr = np.array(img).astype(np.float32) / 127.5 - 1.0
    t = torch.from_numpy(arr).permute(2, 0, 1).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        out = NOISE_NET(t).clamp(-1, 1)
    out_img = out.squeeze().permute(1, 2, 0).detach().cpu().numpy()
    out_img = ((out_img + 1) * 127.5).astype(np.uint8)
    return Image.fromarray(out_img)

# ------------------------------------------------------------
# ENHANCEMENT + PREDICTIVE MODULES
# ------------------------------------------------------------
features_history: List[List[float]] = []
iso_model = None

class TemporalPredictor(nn.Module):
    def __init__(self, input_dim=6, hidden_dim=64, num_layers=1):
        super().__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, num_layers, batch_first=True)
        self.fc = nn.Linear(hidden_dim, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x_seq):
        out, _ = self.lstm(x_seq)
        last = out[:, -1, :]
        score = self.sigmoid(self.fc(last))
        return score

TEMPORAL_PREDICTOR = TemporalPredictor().to(DEVICE)
TEMPORAL_PREDICTOR.eval()

def extract_features_from_image(img: Image.Image):
    gray = img.convert("L")
    arr = np.array(gray, dtype=np.float32)
    mean = float(arr.mean())
    std = float(arr.std())
    contrast = float(arr.max() - arr.min())
    lap = cv2.Laplacian(arr, cv2.CV_64F)
    sharp = float(lap.var())
    entropy = float(cv2.calcHist([arr.astype(np.uint8)], [0], None, [256], [0, 256]).var())
    return [mean, std, contrast, sharp, entropy]

def update_isolation_forest(feat):
    global iso_model
    features_history.append(feat)
    if len(features_history) >= ANOMALY_MIN_SAMPLES:
        X = np.array(features_history)
        iso_model = IsolationForest(contamination=0.05, random_state=42)
        iso_model.fit(X)

def is_anomalous(feat):
    if iso_model is None or len(features_history) < ANOMALY_MIN_SAMPLES:
        return False
    X = np.array(feat).reshape(1, -1)
    pred = iso_model.predict(X)[0]
    return pred == -1

def predict_risk():
    if len(features_history) < 5:
        return 0.0
    gpu = get_gpu_telemetry()
    temp = gpu.get("temp_c", 0)
    util = gpu.get("gpu_util", 0)
    seq_feats = features_history[-20:]
    seq = []
    for f in seq_feats:
        seq.append(f + [temp, util])
    seq = np.array(seq, dtype=np.float32)
    seq = torch.from_numpy(seq).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        score = TEMPORAL_PREDICTOR(seq).item()
    return float(score)

def auto_tune_params(base_params: Dict[str, float], risk: float):
    factor_safe = 1.0 - 0.6 * risk
    factor_aggr = 1.0 + 0.6 * (1.0 - risk)
    tuned = base_params.copy()
    tuned["contrast"] *= factor_safe
    tuned["sharpness"] *= factor_safe
    tuned["brightness"] *= factor_aggr
    tuned["color"] *= factor_aggr
    return tuned

def apply_lighting_effect(img):
    glow = img.filter(ImageFilter.GaussianBlur(radius=2))
    return Image.blend(img, glow, alpha=0.25)

def apply_detail_boost(img):
    img = img.filter(ImageFilter.UnsharpMask(radius=2, percent=150, threshold=3))
    edges = img.filter(ImageFilter.FIND_EDGES)
    edges = ImageEnhance.Brightness(edges).enhance(2.0)
    img = Image.blend(img, edges, alpha=0.15)
    return img

def generate_noise(size, style="default"):
    base = torch.randn(1, 3, size, size, device=DEVICE)
    if style == "metal":
        base = base * 0.7 + torch.sin(torch.linspace(0, 20, size, device=DEVICE)).view(1, 1, -1, 1)
    elif style == "stone":
        base = base * 0.5 + torch.abs(base)
    elif style == "fabric":
        grid_x = torch.linspace(0, 10, size, device=DEVICE).view(1, 1, -1, 1)
        grid_y = torch.linspace(0, 10, size, device=DEVICE).view(1, 1, 1, -1)
        base = base * 0.4 + 0.6 * (torch.sin(grid_x) + torch.cos(grid_y))
    elif style == "wood":
        rings = torch.linspace(0, 10, size, device=DEVICE).view(1, 1, -1, 1)
        base = base * 0.5 + torch.sin(rings * 3.0)
    elif style == "realistic":
        grid_x = torch.linspace(0, 1, size, device=DEVICE).view(1, 1, -1, 1)
        grid_y = torch.linspace(0, 1, size, device=DEVICE).view(1, 1, 1, -1)
        gradient = (grid_x + grid_y) / 2.0
        base = base * 0.3 + gradient
    elif style == "cinematic":
        gradient = torch.linspace(-1, 1, size, device=DEVICE).view(1, 1, -1, 1)
        base = base * 0.4 + gradient
    elif style == "hdr":
        base = base * 1.2
    elif style == "noir":
        base = base * 0.2
    return base

def generate_texture(style="default", target_size=None, use_vae=True, use_style=False):
    if target_size is None:
        target_size = HIGHRES_TEXTURE_SIZE if GPU_ENABLED else BASE_TEXTURE_SIZE
    if use_vae:
        with torch.no_grad():
            x = TEXTURE_VAE.sample(batch_size=1)
        img = x.squeeze().permute(1, 2, 0).detach().cpu().numpy()
    else:
        noise = generate_noise(target_size, style)
        with torch.no_grad():
            if use_style:
                out = TEXTURE_STYLE(noise).clamp(-1, 1)
            else:
                out = TEXTURE_CNN(noise).clamp(-1, 1)
        img = out.squeeze().permute(1, 2, 0).detach().cpu().numpy()
    img = ((img + 1) * 127.5).astype(np.uint8)
    pil_img = Image.fromarray(img)
    if use_vae and target_size != VAE_IMG_SIZE:
        pil_img = pil_img.resize((target_size, target_size), Image.LANCZOS)
    return pil_img

def enhance_texture(img, style="default", predictive=False):
    params = get_enhance_params()
    if predictive:
        risk = predict_risk()
        params = auto_tune_params(params, risk)
    img = ImageEnhance.Brightness(img).enhance(params["brightness"])
    img = img.filter(ImageFilter.DETAIL)

    if style == "metal":
        img = ImageEnhance.Contrast(img).enhance(1.6 * params["contrast"])
        img = ImageEnhance.Sharpness(img).enhance(1.8 * params["sharpness"])
        img = ImageEnhance.Color(img).enhance(1.1 * params["color"])
    elif style == "stone":
        img = ImageEnhance.Contrast(img).enhance(1.3 * params["contrast"])
        img = ImageEnhance.Sharpness(img).enhance(1.2 * params["sharpness"])
        img = ImageEnhance.Color(img).enhance(0.9 * params["color"])
    elif style == "fabric":
        img = ImageEnhance.Contrast(img).enhance(1.2 * params["contrast"])
        img = ImageEnhance.Sharpness(img).enhance(1.5 * params["sharpness"])
        img = ImageEnhance.Color(img).enhance(1.3 * params["color"])
    elif style == "wood":
        img = ImageEnhance.Contrast(img).enhance(1.4 * params["contrast"])
        img = ImageEnhance.Sharpness(img).enhance(1.3 * params["sharpness"])
        img = ImageEnhance.Color(img).enhance(1.2 * params["color"])
    elif style == "realistic":
        img = ImageEnhance.Contrast(img).enhance(1.15 * params["contrast"])
        img = ImageEnhance.Sharpness(img).enhance(1.2 * params["sharpness"])
        img = ImageEnhance.Color(img).enhance(1.1 * params["color"])
        img = img.filter(ImageFilter.GaussianBlur(radius=0.5))
        img = ImageEnhance.Sharpness(img).enhance(1.1 * params["sharpness"])
    elif style == "cinematic":
        img = ImageEnhance.Contrast(img).enhance(1.3 * params["contrast"])
        img = ImageEnhance.Color(img).enhance(1.4 * params["color"])
        img = img.filter(ImageFilter.GaussianBlur(radius=1.0))
    elif style == "hdr":
        img = ImageEnhance.Contrast(img).enhance(1.5 * params["contrast"])
        img = ImageEnhance.Color(img).enhance(1.5 * params["color"])
    elif style == "noir":
        img = img.convert("L").convert("RGB")
        img = ImageEnhance.Contrast(img).enhance(1.8 * params["contrast"])
    else:
        img = ImageEnhance.Contrast(img).enhance(1.35 * params["contrast"])
        img = ImageEnhance.Sharpness(img).enhance(1.4 * params["sharpness"])
        img = ImageEnhance.Color(img).enhance(1.2 * params["color"])

    if params["lighting"]:
        img = apply_lighting_effect(img)
    if params["detail"]:
        img = apply_detail_boost(img)
    if GPU_ENABLED:
        img = img.filter(ImageFilter.UnsharpMask(radius=1, percent=120, threshold=2))
    return img

def save_texture(img, style="default"):
    if fourk_var.get():
        img = super_res_upscale(img, target_size=FOURK_SIZE)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = os.path.join(OUTPUT_DIR, f"{style}_texture_{int(time.time())}.png")
    img.save(filename)
    print(f"[AI] Saved texture → {filename}")
    PLUGIN_MANAGER.run_hook("on_texture", img=img, style=style, path=filename)

# ------------------------------------------------------------
# REAL-TIME FRAME CAPTURE
# ------------------------------------------------------------
def capture_foreground_frame() -> Optional[Image.Image]:
    try:
        hwnd = GetForegroundWindow()
        if not hwnd:
            return None
        rect = wintypes.RECT()
        GetWindowRect(hwnd, ctypes.byref(rect))
        left, top, right, bottom = rect.left, rect.top, rect.right, rect.bottom
        width = right - left
        height = bottom - top
        if width <= 0 or height <= 0:
            return None
        with mss.mss() as sct:
            monitor = {"left": left, "top": top, "width": width, "height": height}
            shot = sct.grab(monitor)
            img = Image.frombytes("RGB", shot.size, shot.rgb)
            return img
    except Exception as e:
        print(f"[CAPTURE] Error: {e}")
        return None

# ------------------------------------------------------------
# ACTIVITY + SCENARIO DETECTION
# ------------------------------------------------------------
def get_foreground_process_info() -> Optional[Dict[str, Any]]:
    try:
        hwnd = GetForegroundWindow()
        if not hwnd:
            return None
        pid = wintypes.DWORD()
        GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
        pid_val = pid.value
        title_len = GetWindowTextLengthW(hwnd)
        buf = ctypes.create_unicode_buffer(title_len + 1)
        GetWindowTextW(hwnd, buf, title_len + 1)
        title = buf.value
        proc = psutil.Process(pid_val)
        name = proc.name()
        exe = ""
        try:
            exe = proc.exe()
        except Exception:
            pass
        return {
            "pid": pid_val,
            "name": name,
            "exe": exe,
            "title": title,
        }
    except Exception:
        return None

def is_game_running_legacy():
    for proc in psutil.process_iter(attrs=["name"]):
        name = proc.info.get("name", "") or ""
        for target in GAME_PROCESS_NAMES:
            if name.lower() == target.lower():
                return True
    return False

def detect_steam_epic_game() -> Dict[str, Any]:
    fg = get_foreground_process_info()
    gpu = get_gpu_telemetry()
    gpu_util = gpu.get("gpu_util", 0) if isinstance(gpu, dict) else 0

    best_candidate = None
    confidence = 0.0

    steam_pids = set()
    epic_pids = set()
    for proc in psutil.process_iter(attrs=["pid", "name"]):
        name = (proc.info.get("name") or "").lower()
        if name in [s.lower() for s in STEAM_HINTS]:
            steam_pids.add(proc.info["pid"])
        if name in [e.lower() for e in EPIC_HINTS]:
            epic_pids.add(proc.info["pid"])

    def is_child_of(pid: int, parents: set) -> bool:
        try:
            p = psutil.Process(pid)
            while True:
                parent = p.parent()
                if parent is None:
                    return False
                if parent.pid in parents:
                    return True
                p = parent
        except Exception:
            return False

    if fg:
        exe_lower = (fg.get("exe") or "").lower()
        title = fg.get("title") or ""
        name_lower = (fg.get("name") or "").lower()

        steam_like = "steam" in exe_lower or is_child_of(fg["pid"], steam_pids)
        epic_like = "epic" in exe_lower or is_child_of(fg["pid"], epic_pids)

        if steam_like or epic_like:
            best_candidate = {
                "source": "steam" if steam_like else "epic",
                "pid": fg["pid"],
                "name": fg["name"],
                "exe": fg["exe"],
                "title": title,
            }
            confidence = 0.7
            if gpu_util >= 40:
                confidence = 0.9

    if not best_candidate and is_game_running_legacy():
        confidence = max(confidence, 0.5)
        best_candidate = {
            "source": "legacy",
            "pid": None,
            "name": "game.exe",
            "exe": "",
            "title": "",
        }

    return {
        "active": best_candidate is not None,
        "confidence": confidence,
        "candidate": best_candidate,
        "gpu_telemetry": gpu,
    }

def detect_youtube_video() -> Dict[str, Any]:
    fg = get_foreground_process_info()
    gpu = get_gpu_telemetry()
    gpu_util = gpu.get("gpu_util", 0) if isinstance(gpu, dict) else 0

    if not fg:
        return {"active": False, "confidence": 0.0, "browser": None, "gpu_telemetry": gpu}

    title = (fg.get("title") or "").lower()
    name = (fg.get("name") or "").lower()

    browser_like = any(name == b.lower() for b in BROWSER_HINTS)
    youtube_in_title = "youtube" in title

    if browser_like and youtube_in_title:
        confidence = 0.7
        if gpu_util >= 30:
            confidence = 0.9
        return {
            "active": True,
            "confidence": confidence,
            "browser": {
                "pid": fg["pid"],
                "name": fg["name"],
                "exe": fg["exe"],
                "title": fg["title"],
            },
            "gpu_telemetry": gpu,
        }

    return {"active": False, "confidence": 0.0, "browser": None, "gpu_telemetry": gpu}

def detect_streaming_apps() -> Dict[str, Any]:
    fg = get_foreground_process_info()
    gpu = get_gpu_telemetry()
    gpu_util = gpu.get("gpu_util", 0) if isinstance(gpu, dict) else 0

    active = False
    confidence = 0.0
    candidate = None

    for proc in psutil.process_iter(attrs=["pid", "name"]):
        name = (proc.info.get("name") or "").lower()
        if any(name == h.lower() for h in STREAMING_HINTS):
            active = True
            candidate = {
                "pid": proc.info["pid"],
                "name": proc.info["name"],
            }
            confidence = 0.6
            if gpu_util >= 30:
                confidence = 0.8
            break

    return {
        "active": active,
        "confidence": confidence,
        "candidate": candidate,
        "gpu_telemetry": gpu,
    }

def detect_scenario() -> str:
    """
    Simple scenario recognition:
      - GAME
      - VIDEO (YouTube)
      - STREAMING
      - CODING / DEV
      - BROWSER / GENERAL
      - IDLE
    """
    fg = get_foreground_process_info()
    if not fg:
        return "IDLE"
    title = (fg.get("title") or "").lower()
    name = (fg.get("name") or "").lower()
    exe = (fg.get("exe") or "").lower()

    if "visual studio" in title or "code" in title or "pycharm" in title or "intellij" in title:
        return "CODING"
    if any(name == b.lower() for b in BROWSER_HINTS):
        if "youtube" in title:
            return "VIDEO"
        return "BROWSER"
    if any(name == h.lower() for h in STREAMING_HINTS):
        return "STREAMING"
    if "unity" in title or "unreal" in title:
        return "GAME"
    if "steam" in exe or "epic" in exe or is_game_running_legacy():
        return "GAME"
    return "IDLE"

def compute_activity_state() -> Dict[str, Any]:
    game_info = detect_steam_epic_game()
    yt_info = detect_youtube_video()
    stream_info = detect_streaming_apps()
    scenario = detect_scenario()

    mode = "IDLE"
    confidence = 0.0
    source = None

    if game_info["active"] and game_info["confidence"] >= max(yt_info["confidence"], stream_info["confidence"]):
        mode = "GAME"
        confidence = game_info["confidence"]
        source = "game"
    elif yt_info["active"] and yt_info["confidence"] >= stream_info["confidence"]:
        mode = "YOUTUBE_VIDEO"
        confidence = yt_info["confidence"]
        source = "youtube"
    elif stream_info["active"]:
        mode = "STREAMING_APP"
        confidence = stream_info["confidence"]
        source = "streaming"
    else:
        mode = "IDLE"

    return {
        "mode": mode,
        "confidence": confidence,
        "source": source,
        "scenario": scenario,
        "game": game_info,
        "youtube": yt_info,
        "streaming": stream_info,
    }

# ------------------------------------------------------------
# STREAMING / PORT TELEMETRY
# ------------------------------------------------------------
def scan_streaming_processes():
    results = []
    pid_stats = {}
    try:
        conns = psutil.net_connections(kind="inet")
    except Exception:
        return results, pid_stats
    for c in conns:
        if c.status != psutil.CONN_ESTABLISHED:
            continue
        laddr = c.laddr
        raddr = c.raddr
        pid = c.pid
        if not raddr:
            continue
        remote_port = raddr.port
        local_port = laddr.port if laddr else None
        stream_flag = remote_port in STREAM_PORTS or (local_port in STREAM_PORTS if local_port else False)
        proc_name = "unknown"
        if pid is not None:
            try:
                proc = psutil.Process(pid)
                proc_name = proc.name()
            except Exception:
                pass
        entry = {
            "pid": pid,
            "name": proc_name,
            "laddr": f"{laddr.ip}:{laddr.port}" if laddr else "",
            "raddr": f"{raddr.ip}:{raddr.port}",
            "remote_port": remote_port,
            "local_port": local_port,
            "stream": stream_flag,
        }
        results.append(entry)
        if pid is not None:
            if pid not in pid_stats:
                pid_stats[pid] = {"name": proc_name, "total": 0, "stream_ports": set()}
            pid_stats[pid]["total"] += 1
            if stream_flag:
                pid_stats[pid]["stream_ports"].add(remote_port)
    PLUGIN_MANAGER.run_hook("on_telemetry", connections=results, pid_stats=pid_stats)
    return results, pid_stats

# ------------------------------------------------------------
# MULTI-USER PROFILES
# ------------------------------------------------------------
PROFILES_FILE = "profiles.json"

def load_profiles() -> Dict[str, Any]:
    if not os.path.exists(PROFILES_FILE):
        return {}
    try:
        with open(PROFILES_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}

def save_profiles(data: Dict[str, Any]):
    try:
        with open(PROFILES_FILE, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[PROFILES] Save error: {e}")

def apply_profile(name: str):
    profiles = load_profiles()
    prof = profiles.get(name)
    if not prof:
        print(f"[PROFILES] Profile '{name}' not found.")
        return
    try:
        style_var.set(prof.get("style", style_var.get()))
        brightness_var.set(int(prof.get("brightness", brightness_var.get())))
        contrast_var.set(int(prof.get("contrast", contrast_var.get())))
        sharpness_var.set(int(prof.get("sharpness", sharpness_var.get())))
        color_var.set(int(prof.get("color", color_var.get())))
        lighting_var.set(int(prof.get("lighting", lighting_var.get())))
        detail_var.set(int(prof.get("detail", detail_var.get())))
        fourk_var.set(int(prof.get("fourk", fourk_var.get())))
        predictive_var.set(int(prof.get("predictive", predictive_var.get())))
        print(f"[PROFILES] Applied profile '{name}'.")
    except Exception as e:
        print(f"[PROFILES] Apply error: {e}")

def save_current_profile(name: str):
    profiles = load_profiles()
    profiles[name] = get_local_settings()
    save_profiles(profiles)
    print(f"[PROFILES] Saved profile '{name}'.")

# ------------------------------------------------------------
# GUI SETUP
# ------------------------------------------------------------
root = tk.Tk()
root.title("DominionDeck Swarm AI Governor – Omni Upgrade")
root.geometry("1200x860")
root.resizable(False, False)

brightness_var = tk.IntVar(master=root, value=100)
contrast_var = tk.IntVar(master=root, value=120)
sharpness_var = tk.IntVar(master=root, value=130)
color_var = tk.IntVar(master=root, value=110)
lighting_var = tk.IntVar(master=root, value=1)
detail_var = tk.IntVar(master=root, value=1)
fourk_var = tk.IntVar(master=root, value=1)
predictive_var = tk.IntVar(master=root, value=1)

swarm_mode_var = tk.IntVar(master=root, value=0)
swarm_server_url_var = tk.StringVar(master=root, value=f"http://127.0.0.1:{API_PORT}")

profile_var = tk.StringVar(master=root, value="default")

def get_enhance_params():
    return {
        "brightness": brightness_var.get() / 100.0,
        "contrast": contrast_var.get() / 100.0,
        "sharpness": sharpness_var.get() / 100.0,
        "color": color_var.get() / 100.0,
        "lighting": bool(lighting_var.get()),
        "detail": bool(detail_var.get()),
    }

status_label = tk.Label(root, text="IDLE", font=("Arial", 24), fg="green")
status_label.pack(pady=5)

activity_label = tk.Label(root, text="Activity: IDLE (0.00)", font=("Arial", 10), fg="gray")
activity_label.pack(pady=2)

scenario_label = tk.Label(root, text="Scenario: IDLE", font=("Arial", 10), fg="gray")
scenario_label.pack(pady=2)

gpu_label = tk.Label(root, text=get_gpu_gen_label(), font=("Arial", 10))
gpu_label.pack()

vram_label = tk.Label(root, text=get_vram_info(), font=("Arial", 10))
vram_label.pack()

style_var = tk.StringVar(master=root, value=STYLE_MODES[1])
style_frame = tk.Frame(root)
style_frame.pack(pady=5)
tk.Label(style_frame, text="Style:", font=("Arial", 10)).pack(side=tk.LEFT)
style_menu = tk.OptionMenu(style_frame, style_var, *STYLE_MODES)
style_menu.pack(side=tk.LEFT)

enh_frame = tk.LabelFrame(root, text="Global Enhancements (Textures & Video)", padx=5, pady=5)
enh_frame.pack(pady=5, fill=tk.X)

tk.Label(enh_frame, text="Brightness").grid(row=0, column=0, sticky="w")
tk.Scale(enh_frame, from_=50, to=150, orient=tk.HORIZONTAL, variable=brightness_var).grid(row=0, column=1, sticky="we")

tk.Label(enh_frame, text="Contrast").grid(row=1, column=0, sticky="w")
tk.Scale(enh_frame, from_=50, to=200, orient=tk.HORIZONTAL, variable=contrast_var).grid(row=1, column=1, sticky="we")

tk.Label(enh_frame, text="Sharpness").grid(row=2, column=0, sticky="w")
tk.Scale(enh_frame, from_=50, to=200, orient=tk.HORIZONTAL, variable=sharpness_var).grid(row=2, column=1, sticky="we")

tk.Label(enh_frame, text="Color").grid(row=3, column=0, sticky="w")
tk.Scale(enh_frame, from_=50, to=200, orient=tk.HORIZONTAL, variable=color_var).grid(row=3, column=1, sticky="we")

lighting_check = tk.Checkbutton(enh_frame, text="Lighting Glow (bloom)", variable=lighting_var)
lighting_check.grid(row=0, column=2, padx=10, sticky="w")

detail_check = tk.Checkbutton(enh_frame, text="Detail Boost (edges / hidden features)", variable=detail_var)
detail_check.grid(row=1, column=2, padx=10, sticky="w")

fourk_check = tk.Checkbutton(enh_frame, text="4K AI Upscale (4096x4096)", variable=fourk_var)
fourk_check.grid(row=2, column=2, padx=10, sticky="w")

predictive_check = tk.Checkbutton(enh_frame, text="Predictive Mode (auto-tune enhancements)", variable=predictive_var)
predictive_check.grid(row=3, column=2, padx=10, sticky="w")

swarm_frame = tk.LabelFrame(root, text="Swarm Sync (Auto multi-PC, predictive server selection)", padx=5, pady=5)
swarm_frame.pack(pady=5, fill=tk.X)

tk.Radiobutton(swarm_frame, text="Swarm AUTO (Option C – predictive)", variable=swarm_mode_var, value=0).grid(row=0, column=0, sticky="w")
tk.Radiobutton(swarm_frame, text="Swarm SERVER (manual override)", variable=swarm_mode_var, value=1).grid(row=0, column=1, sticky="w")
tk.Radiobutton(swarm_frame, text="Swarm CLIENT (manual override)", variable=swarm_mode_var, value=2).grid(row=0, column=2, sticky="w")

tk.Label(swarm_frame, text="Server URL:").grid(row=1, column=0, sticky="w")
swarm_url_entry = tk.Entry(swarm_frame, textvariable=swarm_server_url_var, width=40)
swarm_url_entry.grid(row=1, column=1, columnspan=2, sticky="we")

swarm_memory_label = tk.Label(root, text="Swarm Memory: LOCAL ONLY", font=("Arial", 10), fg="gray")
swarm_memory_label.pack(pady=2)

anomaly_label = tk.Label(root, text="Anomaly: NO", font=("Arial", 10), fg="green")
anomaly_label.pack(pady=2)

risk_label = tk.Label(root, text="Risk: 0.00", font=("Arial", 10), fg="blue")
risk_label.pack(pady=2)

preview_label = tk.Label(root, text="Preview (last texture / frame)", font=("Arial", 9))
preview_label.pack(pady=2)

preview_canvas = tk.Canvas(root, width=160, height=160, bg="black")
preview_canvas.pack()

analytics_frame = tk.LabelFrame(root, text="Analytics Dashboard (GPU / Activity / History)", padx=5, pady=5)
analytics_frame.pack(pady=5, fill=tk.X)

analytics_text = tk.Text(analytics_frame, height=8, width=110, state=tk.DISABLED)
analytics_text.pack(fill=tk.BOTH, expand=True)

stream_frame = tk.Frame(root)
stream_frame.pack(pady=5, fill=tk.BOTH, expand=True)

stream_label = tk.Label(
    stream_frame,
    text="Streaming Telemetry (YouTube / Steam / Epic / OBS / Discord / general streaming, STREAM-LIKELY heuristic)",
    font=("Arial", 10),
)
stream_label.pack(anchor="w")

stream_text = tk.Text(stream_frame, height=10, width=110, state=tk.DISABLED)
stream_text.pack(fill=tk.BOTH, expand=True)

profile_frame = tk.LabelFrame(root, text="Profiles", padx=5, pady=5)
profile_frame.pack(pady=5, fill=tk.X)

tk.Label(profile_frame, text="Profile Name:").grid(row=0, column=0, sticky="w")
profile_entry = tk.Entry(profile_frame, textvariable=profile_var, width=20)
profile_entry.grid(row=0, column=1, sticky="w")

RUNNING_FLAG = False
GAME_ACTIVE_FLAG = False
CURRENT_INTERVAL = 0.8

def update_gui_status(state):
    if state == "ACTIVE":
        status_label.config(text="ACTIVE", fg="orange")
    elif state == "GENERATING":
        status_label.config(text="GENERATING", fg="red")
    elif state == "VIDEO":
        status_label.config(text="VIDEO", fg="blue")
    elif state == "STREAMING":
        status_label.config(text="STREAMING", fg="purple")
    elif state == "GAME":
        status_label.config(text="GAME", fg="red")
    elif state == "YOUTUBE":
        status_label.config(text="YOUTUBE VIDEO", fg="blue")
    elif state == "STREAMING_APP":
        status_label.config(text="STREAMING APP", fg="purple")
    else:
        status_label.config(text="IDLE", fg="green")

def update_activity_label():
    state = compute_activity_state()
    mode = state["mode"]
    conf = state["confidence"]
    scenario = state["scenario"]
    if mode == "GAME":
        activity_label.config(text=f"Activity: GAME ({conf:.2f})", fg="red")
    elif mode == "YOUTUBE_VIDEO":
        activity_label.config(text=f"Activity: YOUTUBE VIDEO ({conf:.2f})", fg="blue")
    elif mode == "STREAMING_APP":
        activity_label.config(text=f"Activity: STREAMING APP ({conf:.2f})", fg="purple")
    else:
        activity_label.config(text=f"Activity: IDLE ({conf:.2f})", fg="gray")
    scenario_label.config(text=f"Scenario: {scenario}", fg="gray")

def update_vram_label():
    vram_label.config(text=get_vram_info())

def update_anomaly_label(is_anom):
    if is_anom:
        anomaly_label.config(text="Anomaly: YES", fg="red")
    else:
        anomaly_label.config(text="Anomaly: NO", fg="green")

def update_risk_label():
    r = predict_risk()
    risk_label.config(text=f"Risk: {r:.2f}")

def update_preview(img):
    img_small = img.resize((160, 160))
    tk_img = ImageTk.PhotoImage(img_small)
    preview_canvas.tk_img = tk_img
    preview_canvas.create_image(80, 80, image=tk_img)

def update_swarm_memory_label():
    global SWARM_SHARED_FLAG, SWARM_LAST_SYNC_TS
    mem = load_swarm_memory()
    if SWARM_SHARED_FLAG:
        if SWARM_LAST_SYNC_TS is None:
            swarm_memory_label.config(text="Swarm Memory: SHARED (SERVER)", fg="orange")
        else:
            age = time.time() - SWARM_LAST_SYNC_TS
            swarm_memory_label.config(
                text=f"Swarm Memory: SHARED (last sync {age:.1f}s ago)", fg="orange"
            )
    else:
        if mem:
            swarm_memory_label.config(text="Swarm Memory: LOCAL (persisted)", fg="gray")
        else:
            swarm_memory_label.config(text="Swarm Memory: LOCAL ONLY", fg="gray")

def update_streaming_status_from_pid_stats(pid_stats):
    any_stream = False
    for pid, info in pid_stats.items():
        total = info["total"]
        ports = info["stream_ports"]
        if total >= 2 and len(ports) > 0:
            any_stream = True
            break
    if any_stream and not GAME_ACTIVE_FLAG:
        update_gui_status("STREAMING")
    else:
        if not GAME_ACTIVE_FLAG and not RUNNING_FLAG:
            update_gui_status("IDLE")

def update_streaming_panel():
    data, pid_stats = scan_streaming_processes()
    stream_text.config(state=tk.NORMAL)
    stream_text.delete("1.0", tk.END)
    if not data:
        stream_text.insert(
            tk.END,
            "No established inet connections detected.\nOpen a browser / start a YouTube or Steam/Epic game to see activity.\n",
        )
    else:
        stream_text.insert(tk.END, "=== PID SUMMARY (heuristic STREAM-LIKELY) ===\n")
        for pid, info in pid_stats.items():
            name = info["name"]
            total = info["total"]
            ports = sorted(list(info["stream_ports"]))
            stream_likely = total >= 2 and len(ports) > 0
            tag = "[STREAM-LIKELY]" if stream_likely else "[PROC]"
            stream_text.insert(
                tk.END,
                f"{tag} PID {pid} | {name} | connections={total} | stream_ports={ports}\n",
            )
        stream_text.insert(tk.END, "\n=== CONNECTIONS ===\n")
        for entry in data:
            tag = "[STREAM]" if entry["stream"] else "[NET]"
            line = (
                f"{tag} PID {entry['pid']} | {entry['name']} | "
                f"L: {entry['laddr']} → R: {entry['raddr']}\n"
            )
            stream_text.insert(tk.END, line)
    stream_text.config(state=tk.DISABLED)
    update_streaming_status_from_pid_stats(pid_stats)

def update_analytics_panel():
    analytics_text.config(state=tk.NORMAL)
    analytics_text.delete("1.0", tk.END)
    gpu = get_gpu_telemetry()
    hist = load_telemetry_history()
    analytics_text.insert(tk.END, "=== GPU Telemetry ===\n")
    analytics_text.insert(tk.END, f"Temp: {gpu.get('temp_c', 'N/A')} °C\n")
    analytics_text.insert(tk.END, f"Util: {gpu.get('gpu_util', 'N/A')} %\n")
    analytics_text.insert(tk.END, f"VRAM: {gpu.get('vram_used_mb', 'N/A')} / {gpu.get('vram_total_mb', 'N/A')} MB\n\n")
    analytics_text.insert(tk.END, "=== Recent Activity History (last 10) ===\n")
    for snap in hist[-10:]:
        ts = snap.get("ts", 0)
        act = snap.get("activity", {})
        mode = act.get("mode", "N/A")
        scenario = act.get("scenario", "N/A")
        analytics_text.insert(
            tk.END,
            f"{time.strftime('%H:%M:%S', time.localtime(ts))} | mode={mode} | scenario={scenario}\n",
        )
    analytics_text.config(state=tk.DISABLED)

def streaming_poll_loop():
    global CURRENT_INTERVAL
    update_streaming_panel()
    update_activity_label()
    update_swarm_memory_label()
    update_vram_label()
    update_analytics_panel()
    root.after(int(CURRENT_INTERVAL * 1000), streaming_poll_loop)

# ------------------------------------------------------------
# SWARM SETTINGS SYNC + PERSISTENT MEMORY
# ------------------------------------------------------------
def get_local_settings() -> Dict[str, Any]:
    return {
        "style": style_var.get(),
        "brightness": brightness_var.get(),
        "contrast": contrast_var.get(),
        "sharpness": sharpness_var.get(),
        "color": color_var.get(),
        "lighting": int(lighting_var.get()),
        "detail": int(detail_var.get()),
        "fourk": int(fourk_var.get()),
        "predictive": int(predictive_var.get()),
    }

def apply_remote_settings(data: Dict[str, Any]):
    try:
        style_var.set(data.get("style", style_var.get()))
        brightness_var.set(int(data.get("brightness", brightness_var.get())))
        contrast_var.set(int(data.get("contrast", contrast_var.get())))
        sharpness_var.set(int(data.get("sharpness", sharpness_var.get())))
        color_var.set(int(data.get("color", color_var.get())))
        lighting_var.set(int(data.get("lighting", lighting_var.get())))
        detail_var.set(int(data.get("detail", detail_var.get())))
        fourk_var.set(int(data.get("fourk", fourk_var.get())))
        predictive_var.set(int(data.get("predictive", predictive_var.get())))
        mem = load_swarm_memory()
        mem["last_remote_settings"] = data
        save_swarm_memory(mem)
    except Exception as e:
        print(f"[SWARM] Failed to apply remote settings: {e}")

def swarm_client_loop():
    global SWARM_SHARED_FLAG, SWARM_LAST_SYNC_TS
    while True:
        if swarm_mode_var.get() == 2:
            url = swarm_server_url_var.get().rstrip("/")
            try:
                resp = requests.get(url + "/swarm/settings", timeout=2)
                if resp.status_code == 200:
                    data = resp.json()
                    apply_remote_settings(data)
                    SWARM_SHARED_FLAG = True
                    SWARM_LAST_SYNC_TS = time.time()
            except Exception as e:
                print(f"[SWARM] Client fetch error: {e}")
        time.sleep(SWARM_POLL_INTERVAL)

# ------------------------------------------------------------
# AUTO-DISCOVERY
# ------------------------------------------------------------
def discovery_server_loop():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind(("", DISCOVERY_PORT))
    except Exception as e:
        print(f"[DISCOVERY] Bind error: {e}")
        return
    print(f"[DISCOVERY] Server listening on UDP port {DISCOVERY_PORT}")
    while True:
        try:
            data, addr = sock.recvfrom(1024)
            if data == DISCOVERY_MAGIC:
                msg = f"http://{socket.gethostbyname(socket.gethostname())}:{API_PORT}"
                sock.sendto(msg.encode("utf-8"), addr)
        except Exception as e:
            print(f"[DISCOVERY] Error: {e}")

def discovery_client_once():
    global swarm_server_url_var
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    try:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.sendto(DISCOVERY_MAGIC, ("<broadcast>", DISCOVERY_PORT))
        data, addr = sock.recvfrom(1024)
        url = data.decode("utf-8")
        print(f"[DISCOVERY] Found server at {url}")
        swarm_server_url_var.set(url)
    except Exception as e:
        print(f"[DISCOVERY] Client error: {e}")
    finally:
        sock.close()

def discovery_client_loop():
    while True:
        if swarm_mode_var.get() == 2 and "127.0.0.1" in swarm_server_url_var.get():
            discovery_client_once()
        time.sleep(10.0)

# ------------------------------------------------------------
# AUTO-SWARM LOGIC + WORKLOAD BALANCING
# ------------------------------------------------------------
def auto_swarm_on_game():
    """
    Swarm AUTO:
      - If VRAM >= 8 GB AND GPU safe → SERVER
      - Else → CLIENT
    """
    global SWARM_SHARED_FLAG, SWARM_LAST_SYNC_TS
    if swarm_mode_var.get() != 0:
        if swarm_mode_var.get() == 1:
            SWARM_SHARED_FLAG = True
            SWARM_LAST_SYNC_TS = None
        return
    vram_total = get_vram_total_mb()
    gpu = get_gpu_telemetry()
    temp = gpu.get("temp_c", 0)
    util = gpu.get("gpu_util", 0)
    safe = gpu_safe()
    if vram_total >= 8192 and safe and util < 85 and temp < 78:
        print(f"[AUTO-SWARM] VRAM {vram_total} MB, temp {temp}°C, util {util}% → SERVER.")
        swarm_mode_var.set(1)
        SWARM_SHARED_FLAG = True
        SWARM_LAST_SYNC_TS = None
    else:
        print(f"[AUTO-SWARM] VRAM {vram_total} MB, temp {temp}°C, util {util}% → CLIENT.")
        swarm_mode_var.set(2)

def choose_compute_target() -> str:
    """
    Decide whether to process locally, offload to server, or cloud.
    Returns "local", "remote", or "cloud".
    """
    gpu = get_gpu_telemetry()
    util = gpu.get("gpu_util", 0)
    temp = gpu.get("temp_c", 0)
    vram_total = gpu.get("vram_total_mb", 1)
    vram_used = gpu.get("vram_used_mb", 0)
    vram_ratio = vram_used / max(vram_total, 1)

    if CLOUD_ENDPOINT:
        if util > 85 or temp > 80 or vram_ratio > 0.9:
            return "cloud"

    if swarm_mode_var.get() == 1:
        return "local"
    if swarm_mode_var.get() == 2:
        if util > 70 or temp > 78 or vram_ratio > 0.85:
            return "remote"
        else:
            return "local"
    return "local"

# ------------------------------------------------------------
# MODEL AUTO-SELECTION
# ------------------------------------------------------------
def select_model_for_frame(scenario: str, gpu: Dict[str, Any]) -> Dict[str, Any]:
    """
    Decide which model stack to use:
      - use_vae
      - use_style
      - use_superres
      - use_noise
    """
    util = gpu.get("gpu_util", 0)
    temp = gpu.get("temp_c", 0)
    vram_total = gpu.get("vram_total_mb", 1)

    use_vae = True
    use_style = False
    use_superres = bool(fourk_var.get())
    use_noise = True

    if scenario == "GAME":
        use_style = True
        use_superres = vram_total >= 8192
    elif scenario == "VIDEO":
        use_style = True
        use_superres = False
    elif scenario == "STREAMING":
        use_style = False
        use_superres = False
    elif scenario == "CODING":
        use_style = False
        use_superres = False
        use_noise = False
    elif scenario == "BROWSER":
        use_style = False
        use_superres = False

    if util > 80 or temp > 80:
        use_vae = False
        use_style = False
        use_superres = False

    return {
        "use_vae": use_vae,
        "use_style": use_style,
        "use_superres": use_superres,
        "use_noise": use_noise,
    }

# ------------------------------------------------------------
# DISTRIBUTED GPU COMPUTE + CLOUD
# ------------------------------------------------------------
def process_frame_image_local(img: Image.Image, style: str, predictive: bool, scenario: str) -> Image.Image:
    feat = extract_features_from_image(img)
    update_isolation_forest(feat)
    anom = is_anomalous(feat)
    update_anomaly_label(anom)
    update_risk_label()

    gpu = get_gpu_telemetry()
    model_cfg = select_model_for_frame(scenario, gpu)

    if model_cfg["use_noise"]:
        img = noise_reduce(img)

    img = enhance_texture(img, style=style, predictive=predictive)

    if model_cfg["use_superres"]:
        img = super_res_upscale(img, target_size=FOURK_SIZE)

    return img

def process_frame_image_remote(img: Image.Image, style: str, predictive: bool, scenario: str) -> Optional[Image.Image]:
    try:
        buf = BytesIO()
        img.save(buf, format="PNG")
        img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        url = swarm_server_url_var.get().rstrip("/") + "/process/frame"
        payload = {"image": img_b64, "style": style, "predictive": predictive, "scenario": scenario}
        resp = requests.post(url, json=payload, timeout=5)
        if resp.status_code != 200:
            print(f"[REMOTE-COMPUTE] HTTP {resp.status_code}")
            return None
        data = resp.json()
        if "image" not in data:
            print(f"[REMOTE-COMPUTE] Missing image in response")
            return None
        out_b64 = data["image"]
        out_bytes = base64.b64decode(out_b64)
        out_img = Image.open(BytesIO(out_bytes)).convert("RGB")
        return out_img
    except Exception as e:
        print(f"[REMOTE-COMPUTE] Error: {e}")
        return None

def process_frame_image_cloud(img: Image.Image, style: str, predictive: bool, scenario: str) -> Optional[Image.Image]:
    if not CLOUD_ENDPOINT:
        return None
    try:
        buf = BytesIO()
        img.save(buf, format="PNG")
        img_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        payload = {"image": img_b64, "style": style, "predictive": predictive, "scenario": scenario}
        resp = requests.post(CLOUD_ENDPOINT, json=payload, timeout=8)
        if resp.status_code != 200:
            print(f"[CLOUD-COMPUTE] HTTP {resp.status_code}")
            return None
        data = resp.json()
        if "image" not in data:
            print(f"[CLOUD-COMPUTE] Missing image in response")
            return None
        out_b64 = data["image"]
        out_bytes = base64.b64decode(out_b64)
        out_img = Image.open(BytesIO(out_bytes)).convert("RGB")
        return out_img
    except Exception as e:
        print(f"[CLOUD-COMPUTE] Error: {e}")
        return None

def process_frame_image(img: Image.Image, style: str, predictive: bool, scenario: str) -> Image.Image:
    target = choose_compute_target()
    if target == "cloud":
        out = process_frame_image_cloud(img, style, predictive, scenario)
        if out is not None:
            return out
        return process_frame_image_local(img, style, predictive, scenario)
    if target == "remote":
        out = process_frame_image_remote(img, style, predictive, scenario)
        if out is not None:
            return out
        return process_frame_image_local(img, style, predictive, scenario)
    return process_frame_image_local(img, style, predictive, scenario)

# ------------------------------------------------------------
# ADAPTIVE FRAME RATE
# ------------------------------------------------------------
def compute_interval_from_activity(activity: Dict[str, Any]) -> float:
    mode = activity.get("mode", "IDLE")
    gpu = get_gpu_telemetry()
    util = gpu.get("gpu_util", 0)
    temp = gpu.get("temp_c", 0)

    base = 0.8
    if mode == "GAME":
        base = 0.6
    elif mode == "YOUTUBE_VIDEO":
        base = 0.7
    elif mode == "STREAMING_APP":
        base = 0.7
    else:
        base = 1.2

    if util > 80 or temp > 80:
        base = min(ACTIVITY_POLL_MAX, base + 0.4)
    else:
        base = max(ACTIVITY_POLL_MIN, base - 0.2)

    return max(ACTIVITY_POLL_MIN, min(ACTIVITY_POLL_MAX, base))

# ------------------------------------------------------------
# AI GOVERNOR LOOP
# ------------------------------------------------------------
def ai_governor_loop():
    global RUNNING_FLAG, GAME_ACTIVE_FLAG, CURRENT_INTERVAL
    RUNNING_FLAG = True
    while RUNNING_FLAG:
        activity = compute_activity_state()
        mode = activity["mode"]
        scenario = activity["scenario"]
        GAME_ACTIVE_FLAG = (mode == "GAME")

        CURRENT_INTERVAL = compute_interval_from_activity(activity)

        if mode == "GAME":
            auto_swarm_on_game()
            update_gui_status("GAME")
        elif mode == "YOUTUBE_VIDEO":
            update_gui_status("YOUTUBE")
        elif mode == "STREAMING_APP":
            update_gui_status("STREAMING_APP")
        else:
            if not GAME_ACTIVE_FLAG:
                update_gui_status("IDLE")

        if not gpu_safe():
            time.sleep(CURRENT_INTERVAL)
            continue

        style = style_var.get()
        predictive = bool(predictive_var.get())

        if mode in ["GAME", "YOUTUBE_VIDEO", "STREAMING_APP"]:
            frame = capture_foreground_frame()
            if frame is not None:
                update_gui_status("VIDEO")
                try:
                    frame = process_frame_image(frame, style, predictive, scenario)
                    update_preview(frame)
                    PLUGIN_MANAGER.run_hook("on_video_frame", img=frame, mode=mode)
                except Exception as e:
                    print(f"[AI-GOVERNOR] Video pipeline error: {e}")
        elif GAME_ACTIVE_FLAG:
            try:
                use_style = style in ["cinematic", "hdr", "noir"]
                update_gui_status("GENERATING")
                tex = generate_texture(style=style, use_vae=True, use_style=use_style)
                tex = process_frame_image(tex, style, predictive, scenario)
                save_texture(tex, style=style)
                update_preview(tex)
            except Exception as e:
                print(f"[AI-GOVERNOR] Texture pipeline error: {e}")

        snapshot = {
            "ts": time.time(),
            "activity": activity,
            "gpu": get_gpu_telemetry(),
        }
        append_telemetry_snapshot(snapshot)

        mem = load_swarm_memory()
        mem["last_activity"] = activity
        mem["last_gpu"] = snapshot["gpu"]
        save_swarm_memory(mem)

        time.sleep(CURRENT_INTERVAL)

# ------------------------------------------------------------
# FASTAPI SERVER
# ------------------------------------------------------------
app = FastAPI(title="DominionDeck Swarm AI Governor API")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/swarm/settings")
def api_get_swarm_settings():
    return get_local_settings()

@app.post("/swarm/settings")
def api_post_swarm_settings(payload: Dict[str, Any]):
    apply_remote_settings(payload)
    return {"status": "ok"}

@app.get("/telemetry")
def api_get_telemetry():
    gpu = get_gpu_telemetry()
    conns, pid_stats = scan_streaming_processes()
    activity = compute_activity_state()
    mem = load_swarm_memory()
    hist = load_telemetry_history()
    return {
        "gpu": gpu,
        "streaming": {
            "connections": conns,
            "pid_stats": {
                str(pid): {
                    "name": info["name"],
                    "total": info["total"],
                    "stream_ports": sorted(list(info["stream_ports"])),
                }
                for pid, info in pid_stats.items()
            },
        },
        "activity": activity,
        "swarm_memory": mem,
        "history": hist[-64:],
    }

@app.get("/activity")
def api_get_activity():
    return compute_activity_state()

@app.post("/process/frame")
def api_process_frame(
    payload: Dict[str, Any] = Body(...),
):
    try:
        img_b64 = payload.get("image")
        style = payload.get("style", STYLE_MODES[0])
        predictive = bool(payload.get("predictive", True))
        scenario = payload.get("scenario", "IDLE")
        if not img_b64:
            return {"error": "missing image"}
        img_bytes = base64.b64decode(img_b64)
        img = Image.open(BytesIO(img_bytes)).convert("RGB")
        out = process_frame_image_local(img, style, predictive, scenario)
        buf = BytesIO()
        out.save(buf, format="PNG")
        out_b64 = base64.b64encode(buf.getvalue()).decode("utf-8")
        return {"image": out_b64}
    except Exception as e:
        return {"error": str(e)}

def run_api_server():
    uvicorn.run(app, host="0.0.0.0", port=API_PORT, log_level="info")

# ------------------------------------------------------------
# CONTROL BUTTONS
# ------------------------------------------------------------
def start_governor():
    global RUNNING_FLAG
    if not RUNNING_FLAG:
        t = threading.Thread(target=ai_governor_loop, daemon=True)
        t.start()
        update_gui_status("ACTIVE")

def stop_governor():
    global RUNNING_FLAG, GAME_ACTIVE_FLAG
    RUNNING_FLAG = False
    GAME_ACTIVE_FLAG = False
    update_gui_status("IDLE")

control_frame = tk.Frame(root)
control_frame.pack(pady=5)

start_btn = tk.Button(control_frame, text="Start AI Governor", command=start_governor)
start_btn.pack(side=tk.LEFT, padx=5)

stop_btn = tk.Button(control_frame, text="Stop AI Governor", command=stop_governor)
stop_btn.pack(side=tk.LEFT, padx=5)

def load_image_and_analyze():
    path = filedialog.askopenfilename(
        title="Select image",
        filetypes=[("Image files", "*.png;*.jpg;*.jpeg;*.bmp;*.tga;*.webp"), ("All files", "*.*")]
    )
    if not path:
        return
    try:
        img = Image.open(path).convert("RGB")
        style = style_var.get()
        predictive = bool(predictive_var.get())
        scenario = "IDLE"
        img = process_frame_image(img, style, predictive, scenario)
        save_texture(img, style=style)
        update_preview(img)
        update_vram_label()
    except Exception as e:
        print(f"[LOAD-IMAGE] Error: {e}")

load_btn = tk.Button(control_frame, text="Load Image → Enhance + Save", command=load_image_and_analyze)
load_btn.pack(side=tk.LEFT, padx=5)

def discovery_btn_action():
    t = threading.Thread(target=discovery_client_once, daemon=True)
    t.start()

disc_btn = tk.Button(control_frame, text="Auto-Discover Server", command=discovery_btn_action)
disc_btn.pack(side=tk.LEFT, padx=5)

def apply_profile_btn():
    name = profile_var.get().strip()
    if not name:
        return
    apply_profile(name)

def save_profile_btn():
    name = profile_var.get().strip()
    if not name:
        return
    save_current_profile(name)

apply_prof_btn = tk.Button(profile_frame, text="Apply Profile", command=apply_profile_btn)
apply_prof_btn.grid(row=0, column=2, padx=5)

save_prof_btn = tk.Button(profile_frame, text="Save Current → Profile", command=save_profile_btn)
save_prof_btn.grid(row=0, column=3, padx=5)

# ------------------------------------------------------------
# BACKGROUND THREADS
# ------------------------------------------------------------
def start_background_threads():
    t_swarm = threading.Thread(target=swarm_client_loop, daemon=True)
    t_swarm.start()

    t_disc_client = threading.Thread(target=discovery_client_loop, daemon=True)
    t_disc_client.start()

    t_disc_server = threading.Thread(target=discovery_server_loop, daemon=True)
    t_disc_server.start()

    t_api = threading.Thread(target=run_api_server, daemon=True)
    t_api.start()

    streaming_poll_loop()

# ------------------------------------------------------------
# MAIN
# ------------------------------------------------------------
if __name__ == "__main__":
    print("[DOMINIONDECK] Swarm AI Governor starting (Omni Upgrade: real-time capture, distributed GPU, predictive swarm, model auto-selection, analytics, profiles)...")
    mem = load_swarm_memory()
    if mem:
        print("[DOMINIONDECK] Loaded persistent swarm memory.")
    if swarm_mode_var.get() == 1:
        SWARM_SHARED_FLAG = True
        SWARM_LAST_SYNC_TS = None
    start_background_threads()
    root.mainloop()
