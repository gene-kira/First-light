#!/usr/bin/env python3
# ============================================================
#  DOMINIONDECK SWARM AI GOVERNOR – AUTO-GAME, AUTO-SWARM, 4K
#  OPTION C: HIGHEST GPU (VRAM) BECOMES SERVER
# ============================================================

import os
import sys
import subprocess
import time
import threading
import importlib.util
import glob
from typing import Dict, Any, List, Callable

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
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import requests

# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------
GAME_PROCESS_NAMES = [
    "game.exe",          # TODO: replace with your actual game executable name
    "MyGame.exe",
]

BASE_TEXTURE_SIZE = 512
HIGHRES_TEXTURE_SIZE = 1024
FOURK_SIZE = 4096
OUTPUT_DIR = "textures"
VIDEO_FRAME_STEP = 15
ANOMALY_MIN_SAMPLES = 50

STREAM_PORTS_BASE = [80, 443, 1935, 8080, 8443, 8081, 5222, 5223]
STEAM_PORTS = list(range(27014, 27051))
STREAM_PORTS = STREAM_PORTS_BASE + STEAM_PORTS

PLUGINS_DIR = "plugins"

API_PORT = 8000
SWARM_POLL_INTERVAL = 2.0  # seconds

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
# PLUGIN SYSTEM
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

    def run_hook(self, hook_name: str, *args, **kwargs):
        for fn in self.hooks.get(hook_name, []):
            try:
                fn(*args, **kwargs)
            except Exception as e:
                print(f"[PLUGIN] Hook {hook_name} error: {e}")

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

VAE_IMG_SIZE = 64
TEXTURE_VAE = TextureVAE(img_size=VAE_IMG_SIZE, latent_dim=128).to(DEVICE)
TEXTURE_CNN = TextureCNN().to(DEVICE)
TEXTURE_VAE.eval()
TEXTURE_CNN.eval()

STYLE_MODES = ["default", "realistic", "metal", "stone", "fabric", "wood"]

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
    return base

def generate_texture(style="default", target_size=None, use_vae=True):
    if target_size is None:
        target_size = HIGHRES_TEXTURE_SIZE if GPU_ENABLED else BASE_TEXTURE_SIZE
    if use_vae:
        with torch.no_grad():
            x = TEXTURE_VAE.sample(batch_size=1)
        img = x.squeeze().permute(1, 2, 0).detach().cpu().numpy()
    else:
        noise = generate_noise(target_size, style)
        with torch.no_grad():
            out = TEXTURE_CNN(noise).clamp(-1, 1)
        img = out.squeeze().permute(1, 2, 0).detach().cpu().numpy()
    img = ((img + 1) * 127.5).astype(np.uint8)
    pil_img = Image.fromarray(img)
    if use_vae and target_size != VAE_IMG_SIZE:
        pil_img = pil_img.resize((target_size, target_size), Image.LANCZOS)
    return pil_img

# ------------------------------------------------------------
# AI SUPER-RESOLUTION (4K UPSCALE)
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

SUPERRES = SuperResNet(scale_factor=4).to(DEVICE)
SUPERRES.eval()

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

# ------------------------------------------------------------
# ENHANCEMENT + PREDICTIVE MODULES
# ------------------------------------------------------------
features_history = []
iso_model = None

class TemporalPredictor(nn.Module):
    def __init__(self, input_dim=4, hidden_dim=32, num_layers=1):
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
    return [mean, std, contrast, sharp]

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
    seq = np.array(features_history[-20:], dtype=np.float32)
    seq = torch.from_numpy(seq).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        score = TEMPORAL_PREDICTOR(seq).item()
    return float(score)

def auto_tune_params(base_params: Dict[str, float], risk: float):
    factor_safe = 1.0 - 0.5 * risk
    factor_aggr = 1.0 + 0.5 * (1.0 - risk)
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
# GAME DETECTION
# ------------------------------------------------------------
def is_game_running():
    for proc in psutil.process_iter(attrs=["name"]):
        name = proc.info.get("name", "") or ""
        for target in GAME_PROCESS_NAMES:
            if name.lower() == target.lower():
                return True
    return False

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
# GUI SETUP
# ------------------------------------------------------------
root = tk.Tk()
root.title("DominionDeck Swarm AI Governor – Auto Game & Swarm (Option C)")
root.geometry("1040x720")
root.resizable(False, False)

brightness_var = tk.IntVar(master=root, value=100)
contrast_var = tk.IntVar(master=root, value=120)
sharpness_var = tk.IntVar(master=root, value=130)
color_var = tk.IntVar(master=root, value=110)
lighting_var = tk.IntVar(master=root, value=1)
detail_var = tk.IntVar(master=root, value=1)
fourk_var = tk.IntVar(master=root, value=1)
predictive_var = tk.IntVar(master=root, value=1)

# Swarm: 0 = auto, 1 = server, 2 = client
swarm_mode_var = tk.IntVar(master=root, value=0)
swarm_server_url_var = tk.StringVar(master=root, value=f"http://127.0.0.1:{API_PORT}")

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

swarm_frame = tk.LabelFrame(root, text="Swarm Sync (4-PC shared settings)", padx=5, pady=5)
swarm_frame.pack(pady=5, fill=tk.X)

tk.Radiobutton(swarm_frame, text="Swarm AUTO (Option C)", variable=swarm_mode_var, value=0).grid(row=0, column=0, sticky="w")
tk.Radiobutton(swarm_frame, text="Swarm SERVER (manual override)", variable=swarm_mode_var, value=1).grid(row=0, column=1, sticky="w")
tk.Radiobutton(swarm_frame, text="Swarm CLIENT (manual override)", variable=swarm_mode_var, value=2).grid(row=0, column=2, sticky="w")

tk.Label(swarm_frame, text="Server URL:").grid(row=1, column=0, sticky="w")
swarm_url_entry = tk.Entry(swarm_frame, textvariable=swarm_server_url_var, width=40)
swarm_url_entry.grid(row=1, column=1, columnspan=2, sticky="we")

anomaly_label = tk.Label(root, text="Anomaly: NO", font=("Arial", 10), fg="green")
anomaly_label.pack(pady=2)

risk_label = tk.Label(root, text="Risk: 0.00", font=("Arial", 10), fg="blue")
risk_label.pack(pady=2)

preview_label = tk.Label(root, text="Preview (last texture / frame)", font=("Arial", 9))
preview_label.pack(pady=2)

preview_canvas = tk.Canvas(root, width=128, height=128, bg="black")
preview_canvas.pack()

stream_frame = tk.Frame(root)
stream_frame.pack(pady=5, fill=tk.BOTH, expand=True)

stream_label = tk.Label(
    stream_frame,
    text="Streaming Telemetry (YouTube / Steam / Epic / general streaming, STREAM-LIKELY heuristic)",
    font=("Arial", 10),
)
stream_label.pack(anchor="w")

stream_text = tk.Text(stream_frame, height=10, width=100, state=tk.DISABLED)
stream_text.pack(fill=tk.BOTH, expand=True)

RUNNING_FLAG = False
GAME_ACTIVE_FLAG = False

def update_gui_status(state):
    if state == "ACTIVE":
        status_label.config(text="ACTIVE", fg="orange")
    elif state == "GENERATING":
        status_label.config(text="GENERATING", fg="red")
    elif state == "VIDEO":
        status_label.config(text="VIDEO", fg="blue")
    elif state == "STREAMING":
        status_label.config(text="STREAMING", fg="purple")
    else:
        status_label.config(text="IDLE", fg="green")

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
    img_small = img.resize((128, 128))
    tk_img = ImageTk.PhotoImage(img_small)
    preview_canvas.tk_img = tk_img
    preview_canvas.create_image(64, 64, image=tk_img)

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

def streaming_poll_loop():
    update_streaming_panel()
    root.after(1000, streaming_poll_loop)

# ------------------------------------------------------------
# SWARM SETTINGS SYNC
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
    except Exception as e:
        print(f"[SWARM] Failed to apply remote settings: {e}")

def swarm_client_loop():
    while True:
        if swarm_mode_var.get() == 2:  # client
            url = swarm_server_url_var.get().rstrip("/")
            try:
                resp = requests.get(url + "/swarm/settings", timeout=2)
                if resp.status_code == 200:
                    data = resp.json()
                    apply_remote_settings(data)
            except Exception as e:
                print(f"[SWARM] Client fetch error: {e}")
        time.sleep(SWARM_POLL_INTERVAL)

# ------------------------------------------------------------
# AUTO-SWARM LOGIC (OPTION C: HIGHEST GPU)
# ------------------------------------------------------------
def auto_swarm_on_game():
    """
    Option C: Highest GPU becomes SERVER.
    Here we approximate:
      - If swarm mode is AUTO (0):
          * If VRAM >= 8 GB → SERVER
          * Else → CLIENT
      - Manual overrides (1/2) are respected.
    """
    if swarm_mode_var.get() != 0:
        return
    vram_total = get_vram_total_mb()
    if vram_total >= 8192:
        print(f"[AUTO-SWARM] VRAM {vram_total} MB → acting as SERVER.")
        swarm_mode_var.set(1)
    else:
        print(f"[AUTO-SWARM] VRAM {vram_total} MB → acting as CLIENT.")
        swarm_mode_var.set(2)

# ------------------------------------------------------------
# AI GOVERNOR LOOP (GAME + TEXTURES)
# ------------------------------------------------------------
def ai_governor_loop():
    global RUNNING_FLAG, GAME_ACTIVE_FLAG
    RUNNING_FLAG = True
    while RUNNING_FLAG:
        game_running = is_game_running()
        GAME_ACTIVE_FLAG = game_running
        if game_running:
            auto_swarm_on_game()
            update_gui_status("ACTIVE")
            update_vram_label()
            update_gui_status("GENERATING")
            style = style_var.get()
            img = generate_texture(style=style, use_vae=True)
            img = enhance_texture(img, style=style, predictive=bool(predictive_var.get()))
            feat = extract_features_from_image(img)
            update_isolation_forest(feat)
            anomalous = is_anomalous(feat)
            update_anomaly_label(anomalous)
            update_risk_label()
            if anomalous:
                print("[ANOMALY] Texture flagged as unusual by Isolation Forest.")
            save_texture(img, style=style)
            update_preview(img)
            update_gui_status("ACTIVE")
            time.sleep(3)
        else:
            update_vram_label()
            update_anomaly_label(False)
            update_risk_label()
            time.sleep(2)

def start_governor():
    global RUNNING_FLAG
    if not RUNNING_FLAG:
        t = threading.Thread(target=ai_governor_loop, daemon=True)
        t.start()

def stop_governor():
    global RUNNING_FLAG
    RUNNING_FLAG = False
    update_gui_status("IDLE")

# ------------------------------------------------------------
# VIDEO ANALYSIS (LOCAL FILES)
# ------------------------------------------------------------
def analyze_video(path):
    if not os.path.isfile(path):
        print(f"[VIDEO] File not found: {path}")
        return
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        print(f"[VIDEO] Cannot open video: {path}")
        return
    update_gui_status("VIDEO")
    frame_idx = 0
    anomalies = 0
    total_samples = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frame_idx += 1
        if frame_idx % VIDEO_FRAME_STEP != 0:
            continue
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img = Image.fromarray(frame_rgb)
        img_enh = enhance_texture(img, style="realistic", predictive=bool(predictive_var.get()))
        feat = extract_features_from_image(img_enh)
        update_isolation_forest(feat)
        anomalous = is_anomalous(feat)
        total_samples += 1
        if anomalous:
            anomalies += 1
            print(f"[VIDEO ANOMALY] Frame {frame_idx} flagged as unusual.")
        update_preview(img_enh)
        update_anomaly_label(anomalous)
        update_risk_label()
        PLUGIN_MANAGER.run_hook("on_video_frame", img=img_enh, frame_index=frame_idx)
        root.update_idletasks()
    cap.release()
    update_gui_status("IDLE")
    update_anomaly_label(False)
    update_risk_label()
    print(f"[VIDEO] Analysis complete. Samples: {total_samples}, anomalies: {anomalies}")

def choose_video_and_analyze():
    path = filedialog.askopenfilename(
        title="Select video file",
        filetypes=[
            ("Video files", "*.mp4 *.mkv *.avi *.mov *.webm"),
            ("All files", "*.*"),
        ],
    )
    if path:
        threading.Thread(target=analyze_video, args=(path,), daemon=True).start()

# ------------------------------------------------------------
# CONTROLS
# ------------------------------------------------------------
control_frame = tk.Frame(root)
control_frame.pack(pady=10)

start_button = tk.Button(control_frame, text="Start Governor", font=("Arial", 12), command=start_governor)
start_button.pack(side=tk.LEFT, padx=5)

stop_button = tk.Button(control_frame, text="Stop Governor", font=("Arial", 12), command=stop_governor)
stop_button.pack(side=tk.LEFT, padx=5)

video_button = tk.Button(control_frame, text="Analyze Video", font=("Arial", 12), command=choose_video_and_analyze)
video_button.pack(side=tk.LEFT, padx=5)

# ------------------------------------------------------------
# REST API MODE (FastAPI) + SWARM ENDPOINTS
# ------------------------------------------------------------
app = FastAPI(title="DominionDeck Swarm AI Governor API", version="1.0.0")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/telemetry")
def api_telemetry():
    gpu = get_gpu_telemetry()
    data, pid_stats = scan_streaming_processes()
    return {"gpu": gpu, "streaming": {"connections": data, "pid_stats": pid_stats}}

@app.get("/swarm/settings")
def api_swarm_settings():
    return get_local_settings()

@app.post("/swarm/settings")
def api_swarm_set_settings(settings: Dict[str, Any]):
    apply_remote_settings(settings)
    return {"status": "ok"}

@app.post("/generate_texture")
def api_generate_texture(style: str = "realistic", fourk: bool = True, predictive: bool = True):
    style = style if style in STYLE_MODES else "realistic"
    img = generate_texture(style=style, use_vae=True)
    img = enhance_texture(img, style=style, predictive=predictive)
    feat = extract_features_from_image(img)
    update_isolation_forest(feat)
    anomalous = is_anomalous(feat)
    risk = predict_risk()
    if fourk:
        img = super_res_upscale(img, target_size=FOURK_SIZE)
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    filename = os.path.join(OUTPUT_DIR, f"api_{style}_{int(time.time())}.png")
    img.save(filename)
    PLUGIN_MANAGER.run_hook("on_texture", img=img, style=style, path=filename)
    return {"path": filename, "style": style, "anomaly": anomalous, "risk": risk}

@app.post("/enhance_image")
def api_enhance_image(path: str, style: str = "realistic", predictive: bool = True, fourk: bool = False):
    if not os.path.isfile(path):
        return {"error": "file_not_found"}
    img = Image.open(path).convert("RGB")
    img = enhance_texture(img, style=style, predictive=predictive)
    feat = extract_features_from_image(img)
    update_isolation_forest(feat)
    anomalous = is_anomalous(feat)
    risk = predict_risk()
    if fourk:
        img = super_res_upscale(img, target_size=FOURK_SIZE)
    out_path = os.path.join(OUTPUT_DIR, f"enh_{int(time.time())}.png")
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    img.save(out_path)
    PLUGIN_MANAGER.run_hook("on_texture", img=img, style=style, path=out_path)
    return {"path": out_path, "anomaly": anomalous, "risk": risk}

@app.post("/analyze_video")
def api_analyze_video(path: str):
    if not os.path.isfile(path):
        return {"error": "file_not_found"}
    cap = cv2.VideoCapture(path)
    if not cap.isOpened():
        return {"error": "cannot_open_video"}
    frame_idx = 0
    anomalies = 0
    total_samples = 0
    while True:
        ret, frame = cap.read()
        if not ret:
            break
        frame_idx += 1
        if frame_idx % VIDEO_FRAME_STEP != 0:
            continue
        frame_rgb = cv2.cvtColor(frame, cv2.COLOR_BGR2RGB)
        img = Image.fromarray(frame_rgb)
        img_enh = enhance_texture(img, style="realistic", predictive=True)
        feat = extract_features_from_image(img_enh)
        update_isolation_forest(feat)
        anomalous = is_anomalous(feat)
        total_samples += 1
        if anomalous:
            anomalies += 1
        PLUGIN_MANAGER.run_hook("on_video_frame", img=img_enh, frame_index=frame_idx)
    cap.release()
    risk = predict_risk()
    return {"samples": total_samples, "anomalies": anomalies, "risk": risk}

def run_api_server():
    uvicorn.run(app, host="0.0.0.0", port=API_PORT)

# ------------------------------------------------------------
# MAIN ENTRY
# ------------------------------------------------------------
def main():
    api_thread = threading.Thread(target=run_api_server, daemon=True)
    api_thread.start()
    swarm_thread = threading.Thread(target=swarm_client_loop, daemon=True)
    swarm_thread.start()
    streaming_poll_loop()
    root.mainloop()

if __name__ == "__main__":
    main()
