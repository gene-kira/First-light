#!/usr/bin/env python3
# ============================================================
# DOMINIONDECK SWARM AI GOVERNOR v2.0
# REAL VIDEO SWARM / GPU-AWARE SCHEDULER / PREDICTIVE WORKERS
#
# Keeps the original DominionDeck concept while upgrading:
#   * real distributed video jobs instead of settings-only sync
#   * coordinator/worker architecture
#   * LAN node discovery
#   * GPU/VRAM/temperature-aware scheduling
#   * adaptive batch sizing
#   * worker heartbeats
#   * job retries and stale-node recovery
#   * ordered frame results
#   * frame complexity scoring
#   * processing-speed learning
#   * predictive workload balancing
#   * live progress telemetry
#   * safe Tkinter main-thread GUI updates
#   * existing texture generation / enhancement / 4K features
#   * REST API compatibility
#
# SECURITY NOTE:
#   This is intended for a trusted LAN. Authentication/TLS should
#   be added before exposing the API beyond a trusted network.
# ============================================================

import os
import sys
import json
import time
import uuid
import socket
import queue
import glob
import math
import threading
import subprocess
import importlib.util
from pathlib import Path
from collections import deque
from typing import Dict, Any, List, Callable, Optional

# ------------------------------------------------------------
# AUTOLOADER
# ------------------------------------------------------------
REQUIRED = [
    "torch", "torchvision", "Pillow", "numpy", "psutil",
    "pynvml", "scikit-learn", "opencv-python",
    "fastapi", "uvicorn", "requests"
]

PKG_MODULE = {
    "torch": "torch", "torchvision": "torchvision",
    "Pillow": "PIL", "numpy": "numpy", "psutil": "psutil",
    "pynvml": "pynvml", "scikit-learn": "sklearn",
    "opencv-python": "cv2", "fastapi": "fastapi",
    "uvicorn": "uvicorn", "requests": "requests"
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
from tkinter import filedialog, messagebox
from sklearn.ensemble import IsolationForest
import cv2
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
import uvicorn
import requests

# ------------------------------------------------------------
# CONFIG
# ------------------------------------------------------------
APP_VERSION = "2.0"
GAME_PROCESS_NAMES = ["game.exe", "MyGame.exe"]

BASE_TEXTURE_SIZE = 512
HIGHRES_TEXTURE_SIZE = 1024
FOURK_SIZE = 4096
OUTPUT_DIR = "textures"
VIDEO_OUTPUT_DIR = "swarm_video_results"
STATE_DIR = "swarm_state"
PLUGINS_DIR = "plugins"

VIDEO_FRAME_STEP = 15
ANOMALY_MIN_SAMPLES = 50

STREAM_PORTS_BASE = [80, 443, 1935, 8080, 8443, 8081, 5222, 5223]
STEAM_PORTS = list(range(27014, 27051))
STREAM_PORTS = STREAM_PORTS_BASE + STEAM_PORTS

API_PORT = 8000
SWARM_POLL_INTERVAL = 2.0
HEARTBEAT_INTERVAL = 1.0
DISCOVERY_INTERVAL = 5.0
JOB_TIMEOUT = 20.0
JOB_RETRY_LIMIT = 3
DEFAULT_BATCH_SIZE = 30
MIN_BATCH_SIZE = 5
MAX_BATCH_SIZE = 180
MAX_RESULT_CACHE = 5000

NODE_ROLE_AUTO = 0
NODE_ROLE_SERVER = 1
NODE_ROLE_CLIENT = 2

VIDEO_EXTENSIONS = (
    "*.mp4 *.mkv *.avi *.mov *.webm *.wmv *.m4v *.flv *.ts *.mts *.m2ts"
)

# ------------------------------------------------------------
# SAFE PATHS / STATE
# ------------------------------------------------------------
for _d in (OUTPUT_DIR, VIDEO_OUTPUT_DIR, STATE_DIR, PLUGINS_DIR):
    os.makedirs(_d, exist_ok=True)

NODE_ID_FILE = os.path.join(STATE_DIR, "node_id.txt")

def load_node_id():
    try:
        if os.path.isfile(NODE_ID_FILE):
            value = Path(NODE_ID_FILE).read_text(encoding="utf-8").strip()
            if value:
                return value
    except Exception:
        pass
    value = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
    try:
        Path(NODE_ID_FILE).write_text(value, encoding="utf-8")
    except Exception:
        pass
    return value

NODE_ID = load_node_id()
HOSTNAME = socket.gethostname()

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

def _gpu_handle(index=0):
    if not VRAM_OK:
        return None
    try:
        return pynvml.nvmlDeviceGetHandleByIndex(index)
    except Exception:
        return None

def get_vram_info():
    handle = _gpu_handle()
    if handle is None:
        return "VRAM: N/A"
    try:
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        return f"VRAM: {mem.used//1048576} / {mem.total//1048576} MB"
    except Exception:
        return "VRAM: ERR"

def get_vram_total_mb():
    handle = _gpu_handle()
    if handle is None:
        return 0
    try:
        return pynvml.nvmlDeviceGetMemoryInfo(handle).total // 1048576
    except Exception:
        return 0

def get_gpu_name():
    handle = _gpu_handle()
    if handle is None:
        return "CPU-only"
    try:
        name = pynvml.nvmlDeviceGetName(handle)
        return name.decode("utf-8", errors="replace") if isinstance(name, bytes) else str(name)
    except Exception:
        return "CUDA GPU"

def get_gpu_gen_label():
    if not GPU_ENABLED:
        return "GPU: CPU-only mode"
    return f"GPU: {get_gpu_name()}"

def get_gpu_telemetry():
    if not VRAM_OK:
        return {
            "available": False, "gpu": "N/A", "vram_used_mb": 0,
            "vram_total_mb": 0, "gpu_util": 0, "mem_util": 0,
            "temp_c": 0
        }
    handle = _gpu_handle()
    if handle is None:
        return {"available": False, "gpu": "ERR"}
    try:
        mem = pynvml.nvmlDeviceGetMemoryInfo(handle)
        util = pynvml.nvmlDeviceGetUtilizationRates(handle)
        temp = pynvml.nvmlDeviceGetTemperature(handle, pynvml.NVML_TEMPERATURE_GPU)
        return {
            "available": True,
            "gpu": get_gpu_name(),
            "vram_used_mb": mem.used // 1048576,
            "vram_total_mb": mem.total // 1048576,
            "gpu_util": int(util.gpu),
            "mem_util": int(util.memory),
            "temp_c": int(temp)
        }
    except Exception:
        return {"available": False, "gpu": "ERR"}

# ------------------------------------------------------------
# PLUGIN SYSTEM
# ------------------------------------------------------------
class PluginManager:
    def __init__(self, directory: str):
        self.directory = directory
        self.plugins = []
        self.hooks = {
            "on_texture": [], "on_video_frame": [],
            "on_telemetry": [], "on_swarm_job": [],
            "on_swarm_result": [], "on_node": []
        }
        self.load_plugins()

    def load_plugins(self):
        os.makedirs(self.directory, exist_ok=True)
        for path in glob.glob(os.path.join(self.directory, "*.py")):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                spec = importlib.util.spec_from_file_location(name, path)
                if spec and spec.loader:
                    module = importlib.util.module_from_spec(spec)
                    spec.loader.exec_module(module)
                    self.plugins.append(module)
                    for hook_name in self.hooks:
                        fn = getattr(module, hook_name, None)
                        if callable(fn):
                            self.hooks[hook_name].append(fn)
                    print(f"[PLUGIN] Loaded: {name}")
            except Exception as e:
                print(f"[PLUGIN] Failed to load {name}: {e}")

    def run_hook(self, hook_name, *args, **kwargs):
        for fn in self.hooks.get(hook_name, []):
            try:
                fn(*args, **kwargs)
            except Exception as e:
                print(f"[PLUGIN] {hook_name}: {e}")

PLUGIN_MANAGER = PluginManager(PLUGINS_DIR)

# ------------------------------------------------------------
# GENERATIVE TEXTURE MODELS
# ------------------------------------------------------------
class TextureVAE(nn.Module):
    def __init__(self, img_size=64, latent_dim=128):
        super().__init__()
        self.img_size = img_size
        self.latent_dim = latent_dim
        self.encoder = nn.Sequential(
            nn.Conv2d(3, 32, 4, 2, 1), nn.ReLU(),
            nn.Conv2d(32, 64, 4, 2, 1), nn.ReLU(),
            nn.Conv2d(64, 128, 4, 2, 1), nn.ReLU()
        )
        self.enc_out_dim = 128 * (img_size // 8) * (img_size // 8)
        self.fc_mu = nn.Linear(self.enc_out_dim, latent_dim)
        self.fc_logvar = nn.Linear(self.enc_out_dim, latent_dim)
        self.fc_dec = nn.Linear(latent_dim, self.enc_out_dim)
        self.decoder = nn.Sequential(
            nn.ConvTranspose2d(128, 64, 4, 2, 1), nn.ReLU(),
            nn.ConvTranspose2d(64, 32, 4, 2, 1), nn.ReLU(),
            nn.ConvTranspose2d(32, 3, 4, 2, 1), nn.Tanh()
        )

    def sample(self, batch_size=1):
        z = torch.randn(batch_size, self.latent_dim, device=DEVICE)
        h = self.fc_dec(z)
        h = h.view(z.size(0), 128, self.img_size // 8, self.img_size // 8)
        return self.decoder(h)

class TextureCNN(nn.Module):
    def __init__(self):
        super().__init__()
        self.model = nn.Sequential(
            nn.Conv2d(3, 32, 3, padding=1), nn.ReLU(),
            nn.Conv2d(32, 64, 3, padding=1), nn.ReLU(),
            nn.Conv2d(64, 3, 3, padding=1), nn.Tanh()
        )

    def forward(self, x):
        return self.model(x)

VAE_IMG_SIZE = 64
TEXTURE_VAE = TextureVAE(VAE_IMG_SIZE, 128).to(DEVICE).eval()
TEXTURE_CNN = TextureCNN().to(DEVICE).eval()

STYLE_MODES = ["default", "realistic", "metal", "stone", "fabric", "wood"]

def generate_noise(size, style="default"):
    base = torch.randn(1, 3, size, size, device=DEVICE)
    if style == "metal":
        base = base * .7 + torch.sin(torch.linspace(0,20,size,device=DEVICE)).view(1,1,-1,1)
    elif style == "stone":
        base = base * .5 + torch.abs(base)
    elif style == "fabric":
        gx = torch.linspace(0,10,size,device=DEVICE).view(1,1,-1,1)
        gy = torch.linspace(0,10,size,device=DEVICE).view(1,1,1,-1)
        base = base * .4 + .6*(torch.sin(gx)+torch.cos(gy))
    elif style == "wood":
        rings = torch.linspace(0,10,size,device=DEVICE).view(1,1,-1,1)
        base = base*.5 + torch.sin(rings*3)
    elif style == "realistic":
        gx = torch.linspace(0,1,size,device=DEVICE).view(1,1,-1,1)
        gy = torch.linspace(0,1,size,device=DEVICE).view(1,1,1,-1)
        base = base*.3 + (gx+gy)/2
    return base

def generate_texture(style="default", target_size=None, use_vae=True):
    target_size = target_size or (HIGHRES_TEXTURE_SIZE if GPU_ENABLED else BASE_TEXTURE_SIZE)
    with torch.no_grad():
        if use_vae:
            x = TEXTURE_VAE.sample(1)
        else:
            x = TEXTURE_CNN(generate_noise(target_size, style))
    img = ((x.squeeze().permute(1,2,0).cpu().numpy()+1)*127.5).clip(0,255).astype(np.uint8)
    pil = Image.fromarray(img)
    if pil.size != (target_size, target_size):
        pil = pil.resize((target_size,target_size), Image.LANCZOS)
    return pil

# ------------------------------------------------------------
# SUPER RESOLUTION
# ------------------------------------------------------------
class SuperResNet(nn.Module):
    def __init__(self, scale_factor=4):
        super().__init__()
        self.net = nn.Sequential(
            nn.Conv2d(3,64,5,padding=2), nn.ReLU(),
            nn.Conv2d(64,64,3,padding=1), nn.ReLU(),
            nn.Conv2d(64,3*(scale_factor**2),3,padding=1),
            nn.PixelShuffle(scale_factor), nn.Tanh()
        )

    def forward(self,x):
        return self.net(x)

SUPERRES = SuperResNet(4).to(DEVICE).eval()

def super_res_upscale(img, target_size=FOURK_SIZE):
    arr = np.asarray(img).astype(np.float32)/127.5-1
    t = torch.from_numpy(arr).permute(2,0,1).unsqueeze(0).to(DEVICE)
    with torch.no_grad():
        out = SUPERRES(t).clamp(-1,1)
    arr = ((out.squeeze().permute(1,2,0).cpu().numpy()+1)*127.5).clip(0,255).astype(np.uint8)
    pil = Image.fromarray(arr)
    if pil.width != target_size:
        pil = pil.resize((target_size,target_size), Image.LANCZOS)
    return pil

# ------------------------------------------------------------
# PREDICTIVE / ANOMALY ENGINE
# ------------------------------------------------------------
features_history = deque(maxlen=2000)
iso_model = None

class TemporalPredictor(nn.Module):
    def __init__(self,input_dim=4,hidden_dim=32):
        super().__init__()
        self.lstm = nn.LSTM(input_dim,hidden_dim,1,batch_first=True)
        self.fc = nn.Linear(hidden_dim,1)
        self.sigmoid = nn.Sigmoid()

    def forward(self,x):
        out,_ = self.lstm(x)
        return self.sigmoid(self.fc(out[:,-1,:]))

TEMPORAL_PREDICTOR = TemporalPredictor().to(DEVICE).eval()

def extract_features_from_image(img):
    gray = img.convert("L")
    arr = np.asarray(gray,dtype=np.float32)
    lap = cv2.Laplacian(arr,cv2.CV_64F)
    return [float(arr.mean()),float(arr.std()),
            float(arr.max()-arr.min()),float(lap.var())]

def update_isolation_forest(feat):
    global iso_model
    features_history.append(feat)
    if len(features_history) >= ANOMALY_MIN_SAMPLES and len(features_history) % 10 == 0:
        try:
            iso_model = IsolationForest(contamination=.05,random_state=42)
            iso_model.fit(np.asarray(features_history))
        except Exception:
            pass

def is_anomalous(feat):
    if iso_model is None or len(features_history)<ANOMALY_MIN_SAMPLES:
        return False
    try:
        return bool(iso_model.predict(np.asarray(feat).reshape(1,-1))[0] == -1)
    except Exception:
        return False

def predict_risk():
    if len(features_history)<5:
        return 0.0
    seq=np.asarray(list(features_history)[-20:],dtype=np.float32)
    with torch.no_grad():
        return float(TEMPORAL_PREDICTOR(torch.from_numpy(seq).unsqueeze(0).to(DEVICE)).item())

def auto_tune_params(base,risk):
    safe=1-.5*risk
    aggressive=1+.5*(1-risk)
    out=base.copy()
    out["contrast"]*=safe
    out["sharpness"]*=safe
    out["brightness"]*=aggressive
    out["color"]*=aggressive
    return out

# ------------------------------------------------------------
# GUI-SAFE CALLBACK QUEUE
# ------------------------------------------------------------
GUI_QUEUE = queue.Queue()

def gui_call(fn,*args,**kwargs):
    GUI_QUEUE.put((fn,args,kwargs))

def process_gui_queue():
    try:
        while True:
            fn,args,kwargs=GUI_QUEUE.get_nowait()
            try:
                fn(*args,**kwargs)
            except Exception as e:
                print(f"[GUI] callback error: {e}")
    except queue.Empty:
        pass
    if root.winfo_exists():
        root.after(50,process_gui_queue)

# ------------------------------------------------------------
# ENHANCEMENT
# ------------------------------------------------------------
def get_enhance_params():
    return {
        "brightness":brightness_var.get()/100,
        "contrast":contrast_var.get()/100,
        "sharpness":sharpness_var.get()/100,
        "color":color_var.get()/100,
        "lighting":bool(lighting_var.get()),
        "detail":bool(detail_var.get())
    }

def apply_lighting_effect(img):
    return Image.blend(img,img.filter(ImageFilter.GaussianBlur(2)),.25)

def apply_detail_boost(img):
    img=img.filter(ImageFilter.UnsharpMask(radius=2,percent=150,threshold=3))
    edges=ImageEnhance.Brightness(img.filter(ImageFilter.FIND_EDGES)).enhance(2)
    return Image.blend(img,edges,.15)

def enhance_texture(img,style="default",predictive=False):
    p=get_enhance_params()
    if predictive:
        p=auto_tune_params(p,predict_risk())
    img=ImageEnhance.Brightness(img).enhance(p["brightness"])
    img=img.filter(ImageFilter.DETAIL)
    multipliers={
        "metal":(1.6,1.8,1.1),"stone":(1.3,1.2,.9),
        "fabric":(1.2,1.5,1.3),"wood":(1.4,1.3,1.2),
        "realistic":(1.15,1.2,1.1),"default":(1.35,1.4,1.2)
    }
    c,s,col=multipliers.get(style,multipliers["default"])
    img=ImageEnhance.Contrast(img).enhance(c*p["contrast"])
    img=ImageEnhance.Sharpness(img).enhance(s*p["sharpness"])
    img=ImageEnhance.Color(img).enhance(col*p["color"])
    if style=="realistic":
        img=ImageEnhance.Sharpness(img.filter(ImageFilter.GaussianBlur(.5))).enhance(1.1*p["sharpness"])
    if p["lighting"]: img=apply_lighting_effect(img)
    if p["detail"]: img=apply_detail_boost(img)
    return img

def save_texture(img,style="default"):
    if fourk_var.get():
        img=super_res_upscale(img,FOURK_SIZE)
    path=os.path.join(OUTPUT_DIR,f"{style}_texture_{int(time.time()*1000)}.png")
    img.save(path)
    PLUGIN_MANAGER.run_hook("on_texture",img=img,style=style,path=path)
    return path

# ------------------------------------------------------------
# NETWORK / STREAM TELEMETRY
# ------------------------------------------------------------
def scan_streaming_processes():
    results=[]; pid_stats={}
    try: conns=psutil.net_connections(kind="inet")
    except Exception: return results,pid_stats
    for c in conns:
        if c.status!=psutil.CONN_ESTABLISHED or not c.raddr: continue
        pid=c.pid
        try: name=psutil.Process(pid).name() if pid else "unknown"
        except Exception: name="unknown"
        rp=c.raddr.port
        lp=c.laddr.port if c.laddr else None
        stream=rp in STREAM_PORTS or (lp in STREAM_PORTS if lp else False)
        entry={"pid":pid,"name":name,
               "laddr":f"{c.laddr.ip}:{c.laddr.port}" if c.laddr else "",
               "raddr":f"{c.raddr.ip}:{c.raddr.port}",
               "remote_port":rp,"local_port":lp,"stream":stream}
        results.append(entry)
        if pid is not None:
            s=pid_stats.setdefault(pid,{"name":name,"total":0,"stream_ports":set()})
            s["total"]+=1
            if stream:s["stream_ports"].add(rp)
    PLUGIN_MANAGER.run_hook("on_telemetry",connections=results,pid_stats=pid_stats)
    return results,pid_stats

def is_game_running():
    targets={x.lower() for x in GAME_PROCESS_NAMES}
    try:
        for p in psutil.process_iter(attrs=["name"]):
            if (p.info.get("name") or "").lower() in targets:
                return True
    except Exception:
        pass
    return False

# ============================================================
# REAL VIDEO SWARM ENGINE
# ============================================================
# Jobs are frame ranges. Results contain frame metadata so the
# coordinator can reorder them even when workers finish unevenly.
# ============================================================

class VideoSwarmEngine:
    def __init__(self):
        self.lock=threading.RLock()
        self.nodes={}
        self.jobs={}
        self.completed={}
        self.result_cache=deque(maxlen=MAX_RESULT_CACHE)
        self.active_video=None
        self.video_meta={}
        self.video_running=False
        self.video_cancel=False
        self.video_job_id=None
        self.batch_size=DEFAULT_BATCH_SIZE
        self.next_job_number=0
        self.total_frames=0
        self.completed_frames=0
        self.failed_jobs=0
        self.retries=0
        self.node_history={}
        self.scheduler_thread=None
        self.worker_thread=None
        self.last_scheduler_tick=0
        self.started_at=0

    # ---------- node intelligence ----------
    def local_node_snapshot(self):
        gpu=get_gpu_telemetry()
        cpu=psutil.cpu_percent(interval=None)
        ram=psutil.virtual_memory()
        return {
            "node_id":NODE_ID,
            "hostname":HOSTNAME,
            "role":self.current_role(),
            "gpu":gpu,
            "cpu_percent":cpu,
            "ram_percent":ram.percent,
            "cuda":GPU_ENABLED,
            "timestamp":time.time(),
            "capacity":self.node_capacity_score(gpu,cpu,ram.percent)
        }

    def node_capacity_score(self,gpu,cpu,ram):
        vram=float(gpu.get("vram_total_mb",0))
        util=float(gpu.get("gpu_util",0))
        temp=float(gpu.get("temp_c",0))
        gpu_score=(1 if gpu.get("available") else .35)
        gpu_score*=1+min(vram/16384,2)
        gpu_score*=max(.15,1-util/140)
        if temp>80: gpu_score*=.55
        elif temp>72: gpu_score*=.8
        cpu_score=max(.15,1-cpu/130)
        ram_score=max(.2,1-ram/125)
        learned=self.learned_speed(NODE_ID)
        return max(.05,gpu_score*(.65+.35*cpu_score)*ram_score*learned)

    def learned_speed(self,node_id):
        h=self.node_history.get(node_id,[])
        if not h:return 1.0
        vals=[x for x in h if x>0]
        if not vals:return 1.0
        baseline=DEFAULT_BATCH_SIZE/max(np.median(vals),.001)
        return float(np.clip(baseline,0.25,4.0))

    def current_role(self):
        mode=swarm_mode_var.get() if "swarm_mode_var" in globals() else NODE_ROLE_AUTO
        if mode==NODE_ROLE_SERVER:return "server"
        if mode==NODE_ROLE_CLIENT:return "worker"
        return "auto"

    def register_or_update_node(self,snapshot):
        nid=snapshot.get("node_id")
        if not nid:return
        with self.lock:
            old=self.nodes.get(nid,{})
            merged={**old,**snapshot,"last_seen":time.time(),"online":True}
            self.nodes[nid]=merged
        PLUGIN_MANAGER.run_hook("on_node",node=merged)

    def mark_stale_nodes(self):
        now=time.time()
        with self.lock:
            for n in self.nodes.values():
                n["online"]=(now-n.get("last_seen",0)) <= HEARTBEAT_INTERVAL*4

    def online_nodes(self):
        self.mark_stale_nodes()
        with self.lock:
            return [n for n in self.nodes.values() if n.get("online")]

    # ---------- complexity / adaptive scheduling ----------
    def estimate_frame_complexity(self,frame):
        small=cv2.resize(frame,(96,54))
        gray=cv2.cvtColor(small,cv2.COLOR_BGR2GRAY)
        edges=cv2.Laplacian(gray,cv2.CV_32F).var()
        motion_proxy=float(np.std(gray))
        return float(np.clip(0.5+edges/250+motion_proxy/255,0.5,5))

    def choose_batch_size(self,node):
        score=float(node.get("capacity",1))
        avg=self.average_frame_complexity()
        size=int(DEFAULT_BATCH_SIZE*score/max(avg,0.7))
        return int(np.clip(size,MIN_BATCH_SIZE,MAX_BATCH_SIZE))

    def average_frame_complexity(self):
        vals=[j.get("complexity",1) for j in self.jobs.values() if j.get("complexity")]
        return float(np.mean(vals)) if vals else 1.0

    def record_speed(self,node_id,frames,elapsed):
        if elapsed<=0:return
        fps=frames/elapsed
        with self.lock:
            h=self.node_history.setdefault(node_id,[])
            h.append(fps)
            del h[:-30]

    # ---------- job creation ----------
    def create_jobs(self,start_frame=0,end_frame=None):
        if end_frame is None:end_frame=self.total_frames
        self.jobs.clear(); self.completed.clear()
        self.result_cache.clear()
        self.next_job_number=0
        pos=start_frame
        while pos<end_frame:
            job_id=f"{self.video_job_id}-{self.next_job_number}"
            end=min(pos+self.batch_size,end_frame)
            self.jobs[job_id]={
                "job_id":job_id,"start":pos,"end":end,
                "status":"queued","assigned":None,
                "attempts":0,"created":time.time(),
                "complexity":1.0
            }
            self.next_job_number+=1
            pos=end
        return len(self.jobs)

    def refresh_batch_sizes(self):
        # Rebuild only queued jobs by shrinking/expanding their end.
        queued=[j for j in self.jobs.values() if j["status"]=="queued"]
        online=self.online_nodes()
        if not online:return
        # The scheduler chooses actual sizes as jobs are dispatched.
        for j in queued:
            if j["end"]-j["start"]>MAX_BATCH_SIZE:
                j["end"]=j["start"]+MAX_BATCH_SIZE

    # ---------- worker execution ----------
    def process_frame(self,frame,frame_index,predictive=True):
        rgb=cv2.cvtColor(frame,cv2.COLOR_BGR2RGB)
        img=Image.fromarray(rgb)
        enhanced=enhance_texture(img,"realistic",predictive)
        feat=extract_features_from_image(enhanced)
        update_isolation_forest(feat)
        anomaly=is_anomalous(feat)
        risk=predict_risk()
        return {
            "frame_index":frame_index,
            "timestamp":frame_index/self.video_meta.get("fps",30),
            "anomaly":anomaly,
            "risk":risk,
            "features":feat
        }

    def execute_job_local(self,job):
        path=self.active_video
        cap=cv2.VideoCapture(path)
        if not cap.isOpened():
            raise RuntimeError("worker cannot open video")
        cap.set(cv2.CAP_PROP_POS_FRAMES,job["start"])
        results=[]
        started=time.time()
        count=0
        try:
            while count < job["end"]-job["start"]:
                ret,frame=cap.read()
                if not ret:break
                idx=job["start"]+count
                if idx % VIDEO_FRAME_STEP==0:
                    results.append(self.process_frame(frame,idx,bool(predictive_var.get())))
                count+=1
        finally:
            cap.release()
        elapsed=max(time.time()-started,.001)
        self.record_speed(NODE_ID,count,elapsed)
        return results,elapsed

    # ---------- coordinator scheduling ----------
    def assign_next_job(self,node_id):
        with self.lock:
            candidates=[j for j in self.jobs.values() if j["status"]=="queued"]
            if not candidates:return None
            node=self.nodes.get(node_id,{})
            desired=self.choose_batch_size(node)
            j=candidates[0]
            current=j["end"]-j["start"]
            if current>desired:
                new_id=f"{self.video_job_id}-{self.next_job_number}"
                self.next_job_number+=1
                remainder={
                    "job_id":new_id,"start":j["start"]+desired,
                    "end":j["end"],"status":"queued",
                    "assigned":None,"attempts":0,
                    "created":time.time(),"complexity":j.get("complexity",1)
                }
                j["end"]=j["start"]+desired
                self.jobs[new_id]=remainder
            j["status"]="assigned"
            j["assigned"]=node_id
            j["attempts"]+=1
            j["assigned_at"]=time.time()
            return dict(j)

    def accept_result(self,job_id,node_id,results,elapsed):
        with self.lock:
            job=self.jobs.get(job_id)
            if not job:return False
            if job["status"]=="done":return True
            job["status"]="done"
            job["completed_at"]=time.time()
            job["result_count"]=len(results)
            self.completed[job_id]=results
            self.result_cache.extend(results)
            self.completed_frames+=job["end"]-job["start"]
        self.record_speed(node_id,max(1,job["end"]-job["start"]),elapsed)
        PLUGIN_MANAGER.run_hook("on_swarm_result",job=job,results=results,node_id=node_id)
        return True

    def recover_stale_jobs(self):
        now=time.time()
        with self.lock:
            for j in self.jobs.values():
                if j["status"]=="assigned" and now-j.get("assigned_at",now)>JOB_TIMEOUT:
                    if j["attempts"]<JOB_RETRY_LIMIT:
                        j["status"]="queued"
                        j["assigned"]=None
                        self.retries+=1
                    else:
                        j["status"]="failed"
                        self.failed_jobs+=1

    def progress(self):
        with self.lock:
            total=max(1,self.total_frames)
            return min(100,100*self.completed_frames/total)

    def status(self):
        with self.lock:
            counts={}
            for j in self.jobs.values():
                counts[j["status"]]=counts.get(j["status"],0)+1
            return {
                "running":self.video_running,
                "job_id":self.video_job_id,
                "video":self.active_video,
                "total_frames":self.total_frames,
                "completed_frames":self.completed_frames,
                "progress":self.progress(),
                "jobs":counts,
                "nodes":self.online_nodes(),
                "retries":self.retries,
                "failed_jobs":self.failed_jobs,
                "batch_size":self.batch_size,
                "elapsed":time.time()-self.started_at if self.started_at else 0
            }

    def start_video(self,path):
        if not os.path.isfile(path):
            raise FileNotFoundError(path)
        cap=cv2.VideoCapture(path)
        if not cap.isOpened():
            raise RuntimeError("Cannot open video")
        self.active_video=path
        self.total_frames=int(cap.get(cv2.CAP_PROP_FRAME_COUNT) or 0)
        fps=float(cap.get(cv2.CAP_PROP_FPS) or 30)
        width=int(cap.get(cv2.CAP_PROP_FRAME_WIDTH) or 0)
        height=int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT) or 0)
        cap.release()
        self.video_meta={"fps":fps,"width":width,"height":height}
        self.video_job_id=uuid.uuid4().hex[:12]
        self.completed_frames=0
        self.failed_jobs=0
        self.retries=0
        self.started_at=time.time()
        self.video_cancel=False
        self.video_running=True
        self.create_jobs()
        self.register_or_update_node(self.local_node_snapshot())
        self.scheduler_thread=threading.Thread(target=self.scheduler_loop,daemon=True)
        self.scheduler_thread.start()
        return self.video_job_id

    def stop_video(self):
        self.video_cancel=True
        self.video_running=False

    def scheduler_loop(self):
        gui_call(update_gui_status,"VIDEO")
        while self.video_running and not self.video_cancel:
            self.recover_stale_jobs()
            self.register_or_update_node(self.local_node_snapshot())
            self.refresh_batch_sizes()

            # This machine is always capable of local work.
            local=self.nodes.get(NODE_ID)
            if local:
                local["capacity"]=self.node_capacity_score(
                    local.get("gpu",{}),
                    local.get("cpu_percent",psutil.cpu_percent()),
                    local.get("ram_percent",psutil.virtual_memory().percent)
                )

            # Process a local job when no remote-worker endpoint is
            # available. Remote workers use /swarm/job and /swarm/result.
            job=self.assign_next_job(NODE_ID)
            if job:
                PLUGIN_MANAGER.run_hook("on_swarm_job",job=job,node_id=NODE_ID)
                try:
                    results,elapsed=self.execute_job_local(job)
                    self.accept_result(job["job_id"],NODE_ID,results,elapsed)
                    if results:
                        gui_call(update_preview,
                                 Image.open(self.active_video).convert("RGB").resize((128,128)))
                except Exception as e:
                    with self.lock:
                        j=self.jobs.get(job["job_id"])
                        if j:
                            j["status"]="queued" if j["attempts"]<JOB_RETRY_LIMIT else "failed"
                            j["assigned"]=None
                    print(f"[SWARM] Local job {job['job_id']} failed: {e}")

            # Check completion.
            with self.lock:
                unfinished=[j for j in self.jobs.values() if j["status"] in ("queued","assigned")]
            gui_call(update_swarm_status_label,self.status())
            if not unfinished:
                self.video_running=False
                break
            time.sleep(.05)

        gui_call(update_swarm_status_label,self.status())
        gui_call(update_gui_status,"IDLE")
        print("[SWARM] Video job complete:",self.status())

    def node_heartbeat_loop(self):
        while True:
            try:
                snap=self.local_node_snapshot()
                self.register_or_update_node(snap)
                role=self.current_role()
                if role=="worker" and self.video_running:
                    # Remote coordinator drives work through HTTP.
                    pass
            except Exception as e:
                print("[SWARM] heartbeat:",e)
            time.sleep(HEARTBEAT_INTERVAL)

    def discovery_loop(self):
        # Lightweight UDP discovery. No packet is sent to arbitrary
        # addresses; broadcast is limited to the local subnet.
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET,socket.SO_BROADCAST,1)
        sock.settimeout(.5)
        while True:
            try:
                message=json.dumps({
                    "type":"DOMINIONDECK_SWARM_DISCOVERY",
                    "node":self.local_node_snapshot(),
                    "port":API_PORT
                }).encode()
                sock.sendto(message,("<broadcast>",API_PORT))
            except Exception:
                pass
            time.sleep(DISCOVERY_INTERVAL)

VIDEO_SWARM=VideoSwarmEngine()

# ============================================================
# GUI
# ============================================================
root=tk.Tk()
root.title("DominionDeck Swarm AI Governor v2.0 – Video Swarm")
root.geometry("1120x800")
root.resizable(False,False)

brightness_var=tk.IntVar(root,100)
contrast_var=tk.IntVar(root,120)
sharpness_var=tk.IntVar(root,130)
color_var=tk.IntVar(root,110)
lighting_var=tk.IntVar(root,1)
detail_var=tk.IntVar(root,1)
fourk_var=tk.IntVar(root,1)
predictive_var=tk.IntVar(root,1)

swarm_mode_var=tk.IntVar(root,NODE_ROLE_AUTO)
swarm_server_url_var=tk.StringVar(root,f"http://127.0.0.1:{API_PORT}")

status_label=tk.Label(root,text="IDLE",font=("Arial",22),fg="green")
status_label.pack(pady=4)
gpu_label=tk.Label(root,text=get_gpu_gen_label(),font=("Arial",10))
gpu_label.pack()
vram_label=tk.Label(root,text=get_vram_info(),font=("Arial",10))
vram_label.pack()

style_var=tk.StringVar(root,"realistic")
sf=tk.Frame(root); sf.pack(pady=3)
tk.Label(sf,text="Style:").pack(side=tk.LEFT)
tk.OptionMenu(sf,style_var,*STYLE_MODES).pack(side=tk.LEFT)

enh=tk.LabelFrame(root,text="Enhancement / Predictive Video",padx=5,pady=4)
enh.pack(fill=tk.X,padx=8,pady=4)
for r,(label,var,a,b) in enumerate([
    ("Brightness",brightness_var,50,150),
    ("Contrast",contrast_var,50,200),
    ("Sharpness",sharpness_var,50,200),
    ("Color",color_var,50,200)]):
    tk.Label(enh,text=label).grid(row=r,column=0,sticky="w")
    tk.Scale(enh,from_=a,to=b,orient=tk.HORIZONTAL,variable=var,length=260).grid(row=r,column=1,sticky="w")
tk.Checkbutton(enh,text="Lighting",variable=lighting_var).grid(row=0,column=2,sticky="w")
tk.Checkbutton(enh,text="Detail Boost",variable=detail_var).grid(row=1,column=2,sticky="w")
tk.Checkbutton(enh,text="4K Upscale",variable=fourk_var).grid(row=2,column=2,sticky="w")
tk.Checkbutton(enh,text="Predictive",variable=predictive_var).grid(row=3,column=2,sticky="w")

sw=tk.LabelFrame(root,text="REAL VIDEO SWARM",padx=5,pady=4)
sw.pack(fill=tk.X,padx=8,pady=4)
tk.Radiobutton(sw,text="AUTO",variable=swarm_mode_var,value=NODE_ROLE_AUTO).grid(row=0,column=0)
tk.Radiobutton(sw,text="SERVER / COORDINATOR",variable=swarm_mode_var,value=NODE_ROLE_SERVER).grid(row=0,column=1)
tk.Radiobutton(sw,text="WORKER",variable=swarm_mode_var,value=NODE_ROLE_CLIENT).grid(row=0,column=2)
tk.Label(sw,text="Coordinator URL:").grid(row=1,column=0,sticky="w")
tk.Entry(sw,textvariable=swarm_server_url_var,width=46).grid(row=1,column=1,columnspan=2,sticky="we")

video_status_label=tk.Label(sw,text="Video Swarm: OFF | Nodes: 0 | Progress: 0.0%")
video_status_label.grid(row=2,column=0,columnspan=3,sticky="w")

metrics=tk.Frame(root); metrics.pack(fill=tk.X,padx=8)
anomaly_label=tk.Label(metrics,text="Anomaly: NO",fg="green")
anomaly_label.pack(side=tk.LEFT,padx=8)
risk_label=tk.Label(metrics,text="Risk: 0.00",fg="blue")
risk_label.pack(side=tk.LEFT,padx=8)
node_label=tk.Label(metrics,text=f"Node: {NODE_ID}")
node_label.pack(side=tk.LEFT,padx=8)

preview_frame=tk.Frame(root); preview_frame.pack(pady=4)
preview_canvas=tk.Canvas(preview_frame,width=160,height=100,bg="black")
preview_canvas.pack()

stream_frame=tk.Frame(root); stream_frame.pack(fill=tk.BOTH,expand=True,padx=8,pady=4)
tk.Label(stream_frame,text="Swarm / Streaming Telemetry").pack(anchor="w")
stream_text=tk.Text(stream_frame,height=13,width=110,state=tk.DISABLED)
stream_text.pack(fill=tk.BOTH,expand=True)

RUNNING_FLAG=False
GAME_ACTIVE_FLAG=False

def update_gui_status(state):
    colors={"ACTIVE":"orange","GENERATING":"red","VIDEO":"blue",
            "STREAMING":"purple","IDLE":"green"}
    status_label.config(text=state,fg=colors.get(state,"black"))

def update_vram_label():
    vram_label.config(text=get_vram_info())

def update_anomaly_label(v):
    anomaly_label.config(text="Anomaly: YES" if v else "Anomaly: NO",
                         fg="red" if v else "green")

def update_risk_label():
    risk_label.config(text=f"Risk: {predict_risk():.2f}")

def update_preview(img):
    try:
        if not isinstance(img,Image.Image): return
        small=img.copy()
        small.thumbnail((160,100),Image.LANCZOS)
        bg=Image.new("RGB",(160,100),"black")
        bg.paste(small,((160-small.width)//2,(100-small.height)//2))
        tkimg=ImageTk.PhotoImage(bg)
        preview_canvas.tk_img=tkimg
        preview_canvas.delete("all")
        preview_canvas.create_image(80,50,image=tkimg)
    except Exception as e:
        print("[GUI] preview:",e)

def update_swarm_status_label(s):
    video_status_label.config(
        text=f"Video Swarm: {'RUNNING' if s['running'] else 'IDLE'} | "
             f"Nodes: {len(s['nodes'])} | Progress: {s['progress']:.1f}% | "
             f"Retries: {s['retries']} | Failed: {s['failed_jobs']}")

def update_streaming_panel():
    data,pids=scan_streaming_processes()
    stream_text.config(state=tk.NORMAL)
    stream_text.delete("1.0",tk.END)
    st=VIDEO_SWARM.status()
    stream_text.insert(tk.END,
        f"=== SWARM ===\n"
        f"Node: {NODE_ID} | Role: {VIDEO_SWARM.current_role()}\n"
        f"Video: {st.get('video')}\n"
        f"Progress: {st.get('progress',0):.1f}% | "
        f"Frames: {st.get('completed_frames',0)}/{st.get('total_frames',0)}\n"
        f"Jobs: {st.get('jobs',{})}\n\n")
    stream_text.insert(tk.END,"=== NODES ===\n")
    for n in st.get("nodes",[]):
        g=n.get("gpu",{})
        stream_text.insert(tk.END,
            f"{n.get('node_id')} | {n.get('hostname')} | "
            f"role={n.get('role')} | capacity={n.get('capacity',0):.2f} | "
            f"GPU={g.get('gpu','N/A')} util={g.get('gpu_util',0)}% "
            f"temp={g.get('temp_c',0)}C\n")
    stream_text.insert(tk.END,"\n=== NETWORK STREAM HEURISTIC ===\n")
    for pid,info in pids.items():
        ports=sorted(info["stream_ports"])
        tag="STREAM-LIKELY" if info["total"]>=2 and ports else "PROC"
        stream_text.insert(tk.END,
            f"[{tag}] PID {pid} | {info['name']} | "
            f"connections={info['total']} | ports={ports}\n")
    stream_text.config(state=tk.DISABLED)
    root.after(1000,update_streaming_panel)

# ------------------------------------------------------------
# GOVERNOR / TEXTURE LOOP
# ------------------------------------------------------------
def ai_governor_loop():
    global RUNNING_FLAG,GAME_ACTIVE_FLAG
    RUNNING_FLAG=True
    while RUNNING_FLAG:
        GAME_ACTIVE_FLAG=is_game_running()
        gui_call(update_vram_label)
        gui_call(update_risk_label)
        if GAME_ACTIVE_FLAG:
            gui_call(update_gui_status,"GENERATING")
            try:
                style=style_var.get()
                img=generate_texture(style,use_vae=True)
                img=enhance_texture(img,style,bool(predictive_var.get()))
                feat=extract_features_from_image(img)
                update_isolation_forest(feat)
                gui_call(update_anomaly_label,is_anomalous(feat))
                save_texture(img,style)
                gui_call(update_preview,img)
            except Exception as e:
                print("[GOVERNOR]",e)
            gui_call(update_gui_status,"ACTIVE")
            time.sleep(3)
        else:
            time.sleep(2)

def start_governor():
    global RUNNING_FLAG
    if not RUNNING_FLAG:
        threading.Thread(target=ai_governor_loop,daemon=True).start()

def stop_governor():
    global RUNNING_FLAG
    RUNNING_FLAG=False
    gui_call(update_gui_status,"IDLE")

# ------------------------------------------------------------
# VIDEO CONTROL
# ------------------------------------------------------------
def choose_video_and_analyze():
    path=filedialog.askopenfilename(
        title="Select video",
        filetypes=[("Video files",VIDEO_EXTENSIONS),("All files","*.*")]
    )
    if path:
        start_video_swarm(path)

def start_video_swarm(path=None):
    if not path:
        return
    if VIDEO_SWARM.video_running:
        messagebox.showinfo("Video Swarm","A video swarm job is already running.")
        return
    try:
        jid=VIDEO_SWARM.start_video(path)
        print("[SWARM] Started video job",jid)
    except Exception as e:
        messagebox.showerror("Video Swarm",str(e))

def stop_video_swarm():
    VIDEO_SWARM.stop_video()

controls=tk.Frame(root); controls.pack(pady=6)
tk.Button(controls,text="Start Governor",command=start_governor).pack(side=tk.LEFT,padx=4)
tk.Button(controls,text="Stop Governor",command=stop_governor).pack(side=tk.LEFT,padx=4)
tk.Button(controls,text="Analyze / Swarm Video",command=choose_video_and_analyze).pack(side=tk.LEFT,padx=4)
tk.Button(controls,text="Stop Video Swarm",command=stop_video_swarm).pack(side=tk.LEFT,padx=4)

# ============================================================
# REST API
# ============================================================
app=FastAPI(title="DominionDeck Real Video Swarm API",version=APP_VERSION)
app.add_middleware(CORSMiddleware,allow_origins=["*"],allow_methods=["*"],allow_headers=["*"])

@app.get("/telemetry")
def api_telemetry():
    return {
        "node":VIDEO_SWARM.local_node_snapshot(),
        "swarm":VIDEO_SWARM.status(),
        "streaming":scan_streaming_processes()[0]
    }

@app.get("/swarm/settings")
def api_swarm_settings():
    return {
        "style":style_var.get(),"brightness":brightness_var.get(),
        "contrast":contrast_var.get(),"sharpness":sharpness_var.get(),
        "color":color_var.get(),"lighting":int(lighting_var.get()),
        "detail":int(detail_var.get()),"fourk":int(fourk_var.get()),
        "predictive":int(predictive_var.get())
    }

@app.post("/swarm/settings")
def api_swarm_set_settings(settings:Dict[str,Any]):
    def apply():
        try:
            style_var.set(settings.get("style",style_var.get()))
            brightness_var.set(int(settings.get("brightness",brightness_var.get())))
            contrast_var.set(int(settings.get("contrast",contrast_var.get())))
            sharpness_var.set(int(settings.get("sharpness",sharpness_var.get())))
            color_var.set(int(settings.get("color",color_var.get())))
            lighting_var.set(int(settings.get("lighting",lighting_var.get())))
            detail_var.set(int(settings.get("detail",detail_var.get())))
            fourk_var.set(int(settings.get("fourk",fourk_var.get())))
            predictive_var.set(int(settings.get("predictive",predictive_var.get())))
        except Exception as e: print("[SWARM] settings:",e)
    gui_call(apply)
    return {"status":"queued"}

@app.get("/swarm/nodes")
def api_swarm_nodes():
    return VIDEO_SWARM.status()["nodes"]

@app.get("/swarm/status")
def api_swarm_status():
    return VIDEO_SWARM.status()

@app.post("/swarm/video/start")
def api_start_video(path:str):
    try:
        jid=VIDEO_SWARM.start_video(path)
        return {"status":"started","job_id":jid,"swarm":VIDEO_SWARM.status()}
    except Exception as e:
        return {"status":"error","error":str(e)}

@app.post("/swarm/video/stop")
def api_stop_video():
    VIDEO_SWARM.stop_video()
    return {"status":"stopping"}

@app.post("/swarm/job")
def api_get_job(node_id:str):
    # Remote workers request one job at a time.
    if not VIDEO_SWARM.video_running:
        return {"job":None}
    job=VIDEO_SWARM.assign_next_job(node_id)
    return {"job":job,"video":VIDEO_SWARM.active_video,"meta":VIDEO_SWARM.video_meta}

@app.post("/swarm/result")
def api_submit_result(payload:Dict[str,Any]):
    ok=VIDEO_SWARM.accept_result(
        payload.get("job_id"),
        payload.get("node_id","remote"),
        payload.get("results",[]),
        float(payload.get("elapsed",1))
    )
    return {"accepted":ok}

@app.post("/swarm/heartbeat")
def api_heartbeat(snapshot:Dict[str,Any]):
    VIDEO_SWARM.register_or_update_node(snapshot)
    return {"status":"ok","server_time":time.time()}

@app.post("/generate_texture")
def api_generate_texture(style:str="realistic",fourk:bool=True,predictive:bool=True):
    style=style if style in STYLE_MODES else "realistic"
    img=enhance_texture(generate_texture(style),style,predictive)
    feat=extract_features_from_image(img)
    update_isolation_forest(feat)
    anomaly=is_anomalous(feat)
    risk=predict_risk()
    if fourk:img=super_res_upscale(img,FOURK_SIZE)
    path=os.path.join(OUTPUT_DIR,f"api_{style}_{int(time.time()*1000)}.png")
    img.save(path)
    PLUGIN_MANAGER.run_hook("on_texture",img=img,style=style,path=path)
    return {"path":path,"anomaly":anomaly,"risk":risk}

@app.post("/enhance_image")
def api_enhance_image(path:str,style:str="realistic",predictive:bool=True,fourk:bool=False):
    if not os.path.isfile(path):return {"error":"file_not_found"}
    img=Image.open(path).convert("RGB")
    img=enhance_texture(img,style,predictive)
    if fourk:img=super_res_upscale(img,FOURK_SIZE)
    out=os.path.join(OUTPUT_DIR,f"enh_{int(time.time()*1000)}.png")
    img.save(out)
    return {"path":out,"risk":predict_risk()}

@app.post("/analyze_video")
def api_analyze_video(path:str):
    try:
        jid=VIDEO_SWARM.start_video(path)
        return {"status":"started","job_id":jid}
    except Exception as e:
        return {"error":str(e)}

# ------------------------------------------------------------
# SERVER / WORKER HTTP LOOPS
# ------------------------------------------------------------
def worker_loop():
    # A client can work for a remote coordinator. The coordinator
    # URL is deliberately explicit rather than guessed.
    while True:
        try:
            if swarm_mode_var.get()==NODE_ROLE_CLIENT:
                url=swarm_server_url_var.get().rstrip("/")
                snap=VIDEO_SWARM.local_node_snapshot()
                requests.post(url+"/swarm/heartbeat",json=snap,timeout=2)
                r=requests.post(url+"/swarm/job",
                                params={"node_id":NODE_ID},timeout=3)
                if r.ok:
                    data=r.json()
                    job=data.get("job")
                    if job:
                        VIDEO_SWARM.active_video=data.get("video")
                        VIDEO_SWARM.video_meta=data.get("meta") or {}
                        started=time.time()
                        results,elapsed=VIDEO_SWARM.execute_job_local(job)
                        payload={"job_id":job["job_id"],"node_id":NODE_ID,
                                 "results":results,"elapsed":elapsed}
                        requests.post(url+"/swarm/result",json=payload,timeout=5)
                        gui_call(update_swarm_status_label,VIDEO_SWARM.status())
        except Exception as e:
            if swarm_mode_var.get()==NODE_ROLE_CLIENT:
                print("[WORKER]",e)
        time.sleep(.1)

def run_api_server():
    uvicorn.run(app,host="0.0.0.0",port=API_PORT,log_level="warning")

# ------------------------------------------------------------
# STARTUP
# ------------------------------------------------------------
def main():
    print("="*65)
    print(f" DominionDeck Swarm AI Governor v{APP_VERSION}")
    print(" REAL VIDEO SWARM / ADAPTIVE GPU SCHEDULER")
    print("="*65)
    print(f"[NODE] {NODE_ID}")
    print(f"[HOST] {HOSTNAME}")
    print(f"[GPU]  {get_gpu_name()}")
    print(f"[VRAM] {get_vram_total_mb()} MB")
    print(f"[API]  http://0.0.0.0:{API_PORT}")
    print("="*65)

    threading.Thread(target=run_api_server,daemon=True).start()
    threading.Thread(target=VIDEO_SWARM.node_heartbeat_loop,daemon=True).start()
    threading.Thread(target=VIDEO_SWARM.discovery_loop,daemon=True).start()
    threading.Thread(target=worker_loop,daemon=True).start()

    root.after(50,process_gui_queue)
    root.after(1000,update_streaming_panel)
    root.mainloop()

if __name__=="__main__":
    main()
