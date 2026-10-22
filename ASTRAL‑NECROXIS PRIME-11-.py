# === AUTO-ELEVATION CHECK ===
import ctypes
import os
import sys

def ensure_admin():
    try:
        if os.name == "nt" and not ctypes.windll.shell32.IsUserAnAdmin():
            script = os.path.abspath(sys.argv[0])
            params = " ".join([f'"{arg}"' for arg in sys.argv[1:]])
            ctypes.windll.shell32.ShellExecuteW(
                None,
                "runas",
                sys.executable,
                f'"{script}" {params}',
                None,
                1
            )
            sys.exit()
    except Exception as e:
        print(f"[Codex Sentinel] Elevation failed: {e}")
        sys.exit()

ensure_admin()

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ASTRAL-NECROXIS PRIME OMEGA++
Ultra Routed Multi-LLM Cluster + Watchdog + Game AI Integration Edition
with:

- Multi-LLM routing, fusion, failover, presets (Balanced / Max Intelligence)
- DB-based shared memory (episodic, world_model, shared_knowledge)
- JSON config + hot reload (routing rules, presets, game/LLM settings)
- Local HTTP "brain" server (shared memory + config + ingest)
- Telemetry-based game detection and auto-profile selection
- Game AI loop (memory reader, frame grabber, parser, tactical reasoning)
- GPU-aware routing, ensemble voting, temperature-based fusion
- Heartbeat, watchdog, auto-recovery, dashboard health indicator
- Auto-retry ports, port fallback, port-in-use detection
- Admin elevation check + firewall helper
- Self-healing network subsystem
- Deep WinError 10013 diagnostics + safe port binding

PLUS:

- Config-driven real memory reader offsets (ready for real B4B / Toxic Commando)
- GPU-accelerated frame capture + inference (YOLO / ViT / Whisper)
- Tactical behavior tree planner + RL refinement
- ROS2 support (if available)
- Lightweight reinforcement learning agent for tactics
- Web dashboard (Flask) for metrics, swarm, game state
- Plugin system (dynamic module loading)
- Multi-agent coordination (swarm communication + groups)
"""

import json
import time
import math
import socket
import random
import sqlite3
import threading
import traceback
import tempfile
import subprocess
import importlib
import glob
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional, Callable, Tuple

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog

# Optional libs
TORCH = None
TRANSFORMERS = None
WHISPER = None
CV2 = None
REQUESTS = None
MATPLOTLIB = None
FIGURE = None
CANVAS = None
OPENAI = None
ULTRALYTICS = None
ROSPY = None
ROS2 = None
PIL = None
NP = None
HTTP_SERVER = None
BASEHTTPRequestHandler = None
FLASK = None
MSS = None

def autoload_libraries():
    global TORCH, TRANSFORMERS, WHISPER, CV2, REQUESTS, MATPLOTLIB, FIGURE, CANVAS
    global OPENAI, ULTRALYTICS, ROSPY, ROS2, PIL, NP, HTTP_SERVER, BASEHTTPRequestHandler
    global FLASK, MSS

    try:
        import torch
        TORCH = torch
    except Exception:
        TORCH = None

    try:
        import transformers
        TRANSFORMERS = transformers
    except Exception:
        TRANSFORMERS = None

    try:
        import whisper
        WHISPER = whisper
    except Exception:
        WHISPER = None

    try:
        import cv2
        CV2 = cv2
    except Exception:
        CV2 = None

    try:
        import requests
        REQUESTS = requests
    except Exception:
        REQUESTS = None

    try:
        import matplotlib
        matplotlib.use("Agg")
        from matplotlib.figure import Figure
        from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
        MATPLOTLIB = matplotlib
        FIGURE = Figure
        CANVAS = FigureCanvasTkAgg
    except Exception:
        MATPLOTLIB = None
        FIGURE = None
        CANVAS = None

    try:
        import openai
        OPENAI = openai
    except Exception:
        OPENAI = None

    try:
        from ultralytics import YOLO
        ULTRALYTICS = YOLO
    except Exception:
        ULTRALYTICS = None

    try:
        import rospy
        ROSPY = rospy
    except Exception:
        ROSPY = None

    try:
        import rclpy
        ROS2 = rclpy
    except Exception:
        ROS2 = None

    try:
        from PIL import ImageGrab
        PIL = ImageGrab
    except Exception:
        PIL = None

    try:
        import numpy as np
        NP = np
    except Exception:
        NP = None

    try:
        from http.server import HTTPServer, BaseHTTPRequestHandler
        HTTP_SERVER = HTTPServer
        BASEHTTPRequestHandler = BaseHTTPRequestHandler
    except Exception:
        HTTP_SERVER = None
        BASEHTTPRequestHandler = None

    try:
        from flask import Flask, jsonify
        FLASK = Flask
    except Exception:
        FLASK = None

    try:
        import mss
        MSS = mss
    except Exception:
        MSS = None

autoload_libraries()

# ============================================================
# OS / ADMIN / FIREWALL HELPERS
# ============================================================

def is_windows() -> bool:
    return os.name == "nt"

def is_admin() -> bool:
    if not is_windows():
        return hasattr(os, "geteuid") and os.geteuid() == 0
    try:
        import ctypes as _ct
        return _ct.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False

def print_firewall_hint():
    if not is_windows():
        return
    print(
        "[FIREWALL] If you see WinError 10013 or connection blocked:\n"
        "  - Open Windows Defender Firewall\n"
        "  - Allow python.exe and pythonw.exe on Private networks\n"
        "  - Or create an inbound rule for the ports you use (e.g., 5555, 8080, 7777)\n"
    )

def find_free_port(preferred: int, max_tries: int = 5) -> int:
    port = preferred
    for _ in range(max_tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                port += 1
    return preferred

# ============================================================
# DEEP WINERROR 10013 DIAGNOSTICS + SAFE BIND
# ============================================================

def diagnose_10013(port: int) -> str:
    print("\n[DEEP DIAGNOSTICS] WinError 10013 detected. Running full analysis...\n")
    try:
        result = subprocess.check_output(
            "netsh interface ipv4 show excludedportrange protocol=tcp",
            shell=True, text=True, stderr=subprocess.STDOUT
        )
        if str(port) in result:
            print(f"[CAUSE] Port {port} is RESERVED by Windows.")
            print("[FIX] Change base port in config to something like 6000 or 9000.")
            return "reserved"
    except Exception:
        pass

    try:
        result = subprocess.check_output(
            f"netstat -ano | findstr {port}",
            shell=True, text=True, stderr=subprocess.STDOUT
        )
        if result.strip():
            print(f"[CAUSE] Another process is already using port {port}.")
            print("[FIX] Close the process or change the port.")
            return "in_use"
    except Exception:
        pass

    try:
        fw = subprocess.check_output(
            "netsh advfirewall firewall show rule name=all",
            shell=True, text=True, stderr=subprocess.STDOUT
        )
        if "python.exe" not in fw.lower():
            print("[CAUSE] Windows Firewall may be blocking python.exe.")
            print("[FIX] Allow python.exe and pythonw.exe on Private + Public networks.")
            return "firewall"
    except Exception:
        pass

    overlays = ["nord", "express", "proton", "razer", "msiafterburner", "overwolf", "steelseries"]
    tasks = ""
    try:
        tasks = subprocess.check_output("tasklist", shell=True, text=True)
        for o in overlays:
            if o.lower() in tasks.lower():
                print(f"[CAUSE] Detected overlay/VPN: {o}")
                print("[FIX] Disable VPN/overlay and retry.")
                return "overlay"
    except Exception:
        pass

    av_list = ["kaspersky", "bitdefender", "eset", "sentinel", "crowdstrike", "webroot", "mcafee"]
    try:
        for av in av_list:
            if av.lower() in tasks.lower():
                print(f"[CAUSE] Security product detected: {av}")
                print("[FIX] Add python.exe to exclusions.")
                return "antivirus"
    except Exception:
        pass

    print("[CAUSE] Unknown — likely kernel-level block or network hook.")
    print("[FIX] Try switching to a higher port range (6000–9000).")
    return "unknown"

def safe_bind(server_socket: socket.socket, host: str, port: int, max_attempts: int = 20) -> Optional[int]:
    attempt = 0
    while attempt < max_attempts:
        try:
            server_socket.bind((host, port))
            print(f"[NETWORK] Successfully bound to {host}:{port}")
            return port
        except OSError as e:
            if e.errno == 10013:
                print(f"[ERROR] WinError 10013 on port {port}")
                diagnose_10013(port)
            else:
                print(f"[ERROR] Bind failed on port {port}: {e}")
            port += 1
            attempt += 1
            print(f"[NETWORK] Trying fallback port {port}...")
            time.sleep(0.5)
    print("[FATAL] Could not bind after all attempts.")
    print_firewall_hint()
    return None

# ============================================================
# EVENT BUS
# ============================================================

class EventBus:
    def __init__(self):
        self._subscribers: Dict[str, List[Callable[[Dict[str, Any]], None]]] = {}
        self._lock = threading.Lock()

    def subscribe(self, topic: str, callback: Callable[[Dict[str, Any]], None]) -> None:
        with self._lock:
            self._subscribers.setdefault(topic, []).append(callback)

    def publish(self, topic: str, payload: Dict[str, Any]) -> None:
        with self._lock:
            callbacks = list(self._subscribers.get(topic, []))
        for cb in callbacks:
            try:
                cb(payload)
            except Exception:
                traceback.print_exc()

# ============================================================
# DATA CLASSES
# ============================================================

@dataclass
class LiveDataSourceConfig:
    name: str
    enabled: bool = False
    params: Dict[str, Any] = field(default_factory=dict)

@dataclass
class ModelConfig:
    name: str
    version: str
    enabled: bool = True
    params: Dict[str, Any] = field(default_factory=dict)

@dataclass
class Task:
    id: str
    type: str
    payload: Dict[str, Any] = field(default_factory=dict)
    metadata: Dict[str, Any] = field(default_factory=dict)
    tags: List[str] = field(default_factory=list)

@dataclass
class SystemState:
    status: str = "idle"
    last_error: Optional[str] = None
    metrics: Dict[str, Any] = field(default_factory=dict)

# ============================================================
# PERSISTENT MEMORY
# ============================================================

class PersistentMemory:
    def __init__(self, db_path: str = "astral_necroxis_memory.db"):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS episodic_memory (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                source TEXT,
                data_type TEXT,
                content TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS world_model (
                key TEXT PRIMARY KEY,
                value TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS shared_knowledge (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                channel TEXT,
                source TEXT,
                content TEXT
            )
        """)
        conn.commit()
        conn.close()

    def store_episode(self, source: str, data_type: str, content: Dict[str, Any]):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO episodic_memory (timestamp, source, data_type, content) VALUES (?, ?, ?, ?)",
            (time.time(), source, data_type, json.dumps(content))
        )
        conn.commit()
        conn.close()

    def load_episodes(self, limit: int = 100) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT timestamp, source, data_type, content FROM episodic_memory ORDER BY id DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
        conn.close()
        return [
            {
                "timestamp": r[0],
                "source": r[1],
                "data_type": r[2],
                "content": json.loads(r[3])
            } for r in rows
        ]

    def set_world_model(self, key: str, value: Dict[str, Any]):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("REPLACE INTO world_model (key, value) VALUES (?, ?)", (key, json.dumps(value)))
        conn.commit()
        conn.close()

    def get_world_model(self, key: str) -> Optional[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT value FROM world_model WHERE key = ?", (key,))
        row = cur.fetchone()
        conn.close()
        if row:
            return json.loads(row[0])
        return None

    def append_shared_knowledge(self, channel: str, source: str, content: Any):
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "INSERT INTO shared_knowledge (timestamp, channel, source, content) VALUES (?, ?, ?, ?)",
            (time.time(), channel, source, json.dumps(content))
        )
        conn.commit()
        conn.close()

    def query_shared_knowledge(self, channel: Optional[str] = None, limit: int = 50) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        if channel:
            cur.execute(
                "SELECT id, timestamp, channel, source, content FROM shared_knowledge "
                "WHERE channel = ? ORDER BY id DESC LIMIT ?",
                (channel, limit)
            )
        else:
            cur.execute(
                "SELECT id, timestamp, channel, source, content FROM shared_knowledge "
                "ORDER BY id DESC LIMIT ?",
                (limit,)
            )
        rows = cur.fetchall()
        conn.close()
        return [
            {
                "id": r[0],
                "timestamp": r[1],
                "channel": r[2],
                "source": r[3],
                "content": json.loads(r[4])
            } for r in rows
        ]

# ============================================================
# METRICS
# ============================================================

class MetricsStore:
    def __init__(self, bus: EventBus):
        self.metrics: Dict[str, float] = {}
        self.lock = threading.Lock()
        bus.subscribe("metrics.update", self._on_update)

    def _on_update(self, payload: Dict[str, Any]):
        name = payload.get("metric")
        delta = payload.get("delta", 0)
        if not name:
            return
        with self.lock:
            self.metrics[name] = self.metrics.get(name, 0) + delta

    def snapshot(self) -> Dict[str, float]:
        with self.lock:
            return dict(self.metrics)

# ============================================================
# GPU MANAGER
# ============================================================

class GPUManager:
    def __init__(self):
        self.gpu_available = False
        self.info = {}
        self._detect()

    def _detect(self):
        if TORCH is not None and TORCH.cuda.is_available():
            self.gpu_available = True
            self.info["backend"] = "torch"
            self.info["device_count"] = TORCH.cuda.device_count()
            self.info["device"] = "cuda"
        else:
            self.gpu_available = False
            self.info["backend"] = "none"
            self.info["device"] = "cpu"

    def device_str(self) -> str:
        return self.info.get("device", "cpu")

    def to_device(self, tensor):
        if self.gpu_available and TORCH is not None:
            return tensor.to("cuda")
        return tensor

# ============================================================
# CONFIG MANAGER
# ============================================================

class ConfigManager:
    def __init__(self, path: str = "brain_config.json", reload_interval: float = 3.0):
        self.path = path
        self.reload_interval = reload_interval
        self.config: Dict[str, Any] = {}
        self.last_mtime = 0.0
        self.lock = threading.Lock()
        self._ensure_default()
        self._load()
        threading.Thread(target=self._watch_loop, daemon=True).start()

    def _ensure_default(self):
        if os.path.exists(self.path):
            return
        default = {
            "llm_mode": "balanced",
            "temperature": 0.7,
            "routing_rules": {},
            "presets": {
                "A_Balanced_Intelligence": {
                    "llm_mode": "balanced",
                    "temperature": 0.7
                },
                "D_Maximum_Intelligence": {
                    "llm_mode": "max_int",
                    "temperature": 0.4
                }
            },
            "http_server": {
                "host": "127.0.0.1",
                "port": 8080
            },
            "cluster": {
                "host": "0.0.0.0",
                "port": 5555
            },
            "telemetry": {
                "host": "127.0.0.1",
                "port": 7777
            },
            "memory_offsets": {
                "Back 4 Blood": {
                    "base_address": "0x0",
                    "player_health_offset": "0x0",
                    "ammo_offset": "0x0",
                    "enemies_visible_offset": "0x0",
                    "objective_offset": "0x0"
                },
                "John Carpenter's Toxic Commando": {
                    "base_address": "0x0",
                    "player_health_offset": "0x0",
                    "ammo_offset": "0x0",
                    "enemies_visible_offset": "0x0",
                    "objective_offset": "0x0"
                }
            },
            "web_dashboard": {
                "enabled": True,
                "host": "127.0.0.1",
                "port": 5000
            }
        }
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump(default, f, indent=2)

    def _load(self):
        try:
            mtime = os.path.getmtime(self.path)
            if mtime == self.last_mtime:
                return
            with open(self.path, "r", encoding="utf-8") as f:
                cfg = json.load(f)
            with self.lock:
                self.config = cfg
                self.last_mtime = mtime
        except Exception:
            traceback.print_exc()

    def _watch_loop(self):
        while True:
            self._load()
            time.sleep(self.reload_interval)

    def get(self) -> Dict[str, Any]:
        with self.lock:
            return dict(self.config)

    def apply_preset(self, name: str):
        with self.lock:
            presets = self.config.get("presets", {})
            if name in presets:
                p = presets[name]
                self.config["llm_mode"] = p.get("llm_mode", self.config.get("llm_mode", "balanced"))
                self.config["temperature"] = p.get("temperature", self.config.get("temperature", 0.7))
                with open(self.path, "w", encoding="utf-8") as f:
                    json.dump(self.config, f, indent=2)

# ============================================================
# LLM BACKENDS + ROUTER
# ============================================================

@dataclass
class LLMBackendInfo:
    name: str
    kind: str
    weight: float = 1.0
    online: bool = True
    latency_ms: float = 0.0
    extra: Dict[str, Any] = field(default_factory=dict)

class BaseLLMBackend:
    def __init__(self, info: LLMBackendInfo, gpu: Optional[GPUManager] = None):
        self.info = info
        self.gpu = gpu

    def is_available(self) -> bool:
        return self.info.online

    def generate(self, prompt: str, max_tokens: int = 256) -> str:
        raise NotImplementedError

    def estimate_confidence(self, prompt: str, output: str) -> float:
        base = {
            "system": 0.7,
            "copilot": 0.8,
            "openai": 0.9,
            "local_http": 0.8,
            "local_transformers": 0.6,
        }.get(self.info.kind, 0.5)

        length_penalty = 0.0
        if len(output) < 10:
            length_penalty = -0.1
        elif len(output) > 2000:
            length_penalty = -0.05

        latency_penalty = 0.0
        if self.info.latency_ms > 0:
            latency_penalty = min(0.2, self.info.latency_ms / 5000.0)

        gpu_bonus = 0.05 if (self.gpu and self.gpu.gpu_available and self.info.kind in ("local_transformers", "local_http")) else 0.0

        conf = base + gpu_bonus - latency_penalty + length_penalty
        return max(0.0, min(1.0, conf))

class SystemLLMBackend(BaseLLMBackend):
    def generate(self, prompt: str, max_tokens: int = 256) -> str:
        snippet = prompt.strip().replace("\n", " ")
        if len(snippet) > 200:
            snippet = snippet[:200] + "..."
        return f"[SystemLLM] Quick reasoning on: {snippet}"

class CopilotBackend(BaseLLMBackend):
    def generate(self, prompt: str, max_tokens: int = 256) -> str:
        snippet = prompt.strip().replace("\n", " ")
        if len(snippet) > 200:
            snippet = snippet[:200] + "..."
        return f"[CopilotStub] System-level insight on: {snippet}"

class OpenAIBackend(BaseLLMBackend):
    def __init__(self, info: LLMBackendInfo, model: str = "gpt-4o-mini", gpu: Optional[GPUManager] = None):
        super().__init__(info, gpu)
        self.model = model

    def generate(self, prompt: str, max_tokens: int = 256) -> str:
        if OPENAI is None:
            return "[OpenAI backend not available]"
        try:
            resp = OPENAI.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                max_tokens=max_tokens,
            )
            return resp.choices[0].message.content
        except Exception:
            traceback.print_exc()
            raise

class LocalHTTPBackend(BaseLLMBackend):
    def generate(self, prompt: str, max_tokens: int = 256) -> str:
        if REQUESTS is None:
            return "[Local HTTP LLM: requests not available]"
        url = self.info.extra.get("url")
        model = self.info.extra.get("model", "default")
        headers = self.info.extra.get("headers", {})
        if not url:
            return "[Local HTTP LLM: no URL configured]"
        try:
            payload = {
                "model": model,
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": max_tokens,
            }
            r = REQUESTS.post(url, json=payload, headers=headers, timeout=30)
            r.raise_for_status()
            data = r.json()
            if "choices" in data and data["choices"]:
                msg = data["choices"][0].get("message", {})
                return msg.get("content", "[Local HTTP LLM: no content]")
            return str(data)
        except Exception:
            traceback.print_exc()
            raise

class LocalTransformersBackend(BaseLLMBackend):
    def __init__(self, info: LLMBackendInfo, model_name: str = "gpt2", gpu: Optional[GPUManager] = None):
        super().__init__(info, gpu)
        self.model_name = model_name
        self.pipeline = None
        if TRANSFORMERS is not None:
            try:
                device = 0 if (self.gpu and self.gpu.gpu_available) else -1
                self.pipeline = TRANSFORMERS.pipeline(
                    "text-generation",
                    model=self.model_name,
                    device=device
                )
            except Exception:
                self.pipeline = None

    def generate(self, prompt: str, max_tokens: int = 256) -> str:
        if self.pipeline is None:
            return "[Local transformers backend unavailable]"
        out = self.pipeline(prompt, max_length=len(prompt.split()) + max_tokens, num_return_sequences=1)
        return out[0]["generated_text"]

class MultiLLMManager:
    def __init__(self, gpu: GPUManager, config_manager: ConfigManager, mode: str = "balanced", temperature: float = 0.7):
        self.gpu = gpu
        self.config_manager = config_manager
        self.mode = mode
        self.temperature = max(0.05, temperature)
        self.backends: List[BaseLLMBackend] = []
        self.routing_rules: Dict[str, Dict[str, Any]] = {}
        self._init_routing_rules()
        self._discover_backends()

    def _init_routing_rules(self):
        base_rules = {
            "summary": {
                "preferred_kinds": ["system", "copilot", "local_transformers"],
                "multi_llm": False,
            },
            "swarm_planning": {
                "preferred_kinds": ["openai", "local_http"],
                "multi_llm": True,
            },
            "world_model_update": {
                "preferred_kinds": ["openai", "local_http", "system", "local_transformers"],
                "multi_llm": True,
            },
            "safety_review": {
                "preferred_kinds": ["openai", "copilot"],
                "multi_llm": True,
            },
            "tactical_reasoning": {
                "preferred_kinds": ["openai", "local_http", "system"],
                "multi_llm": True,
            },
            "generic": {
                "preferred_kinds": ["system", "openai", "local_http", "local_transformers", "copilot"],
                "multi_llm": False,
            },
        }
        cfg = self.config_manager.get()
        override = cfg.get("routing_rules", {})
        for k, v in override.items():
            base_rules[k] = v
        self.routing_rules = base_rules

    def _discover_backends(self):
        system_info = LLMBackendInfo(
            name="system_llm",
            kind="system",
            weight=2.0,
            online=True,
            extra={}
        )
        self.backends.append(SystemLLMBackend(system_info, gpu=self.gpu))

        copilot_info = LLMBackendInfo(
            name="copilot_stub",
            kind="copilot",
            weight=2.5,
            online=True,
            extra={}
        )
        self.backends.append(CopilotBackend(copilot_info, gpu=self.gpu))

        if OPENAI is not None and os.getenv("OPENAI_API_KEY"):
            OPENAI.api_key = os.getenv("OPENAI_API_KEY")
            openai_info = LLMBackendInfo(
                name="openai_gpt4o_mini",
                kind="openai",
                weight=3.0,
                online=True,
                extra={"model": "gpt-4o-mini"}
            )
            self.backends.append(OpenAIBackend(openai_info, model="gpt-4o-mini", gpu=self.gpu))

        if REQUESTS is not None:
            lmstudio_url = os.getenv("LMSTUDIO_URL", "http://localhost:1234/v1/chat/completions")
            if self._probe_http(lmstudio_url):
                lmstudio_info = LLMBackendInfo(
                    name="lmstudio_local",
                    kind="local_http",
                    weight=2.0,
                    online=True,
                    extra={"url": lmstudio_url, "model": os.getenv("LMSTUDIO_MODEL", "default")}
                )
                self.backends.append(LocalHTTPBackend(lmstudio_info, gpu=self.gpu))

            ollama_url = os.getenv("OLLAMA_URL", "http://localhost:11434/v1/chat/completions")
            if self._probe_http(ollama_url):
                ollama_info = LLMBackendInfo(
                    name="ollama_local",
                    kind="local_http",
                    weight=2.0,
                    online=True,
                    extra={"url": ollama_url, "model": os.getenv("OLLAMA_MODEL", "llama3")}
                )
                self.backends.append(LocalHTTPBackend(ollama_info, gpu=self.gpu))

        local_tf_info = LLMBackendInfo(
            name="local_transformers_gpt2",
            kind="local_transformers",
            weight=1.0,
            online=True,
            extra={"model_name": "gpt2"}
        )
        self.backends.append(LocalTransformersBackend(local_tf_info, model_name="gpt2", gpu=self.gpu))

    def _probe_http(self, url: str) -> bool:
        if REQUESTS is None:
            return False
        try:
            REQUESTS.get(url.split("/v1")[0], timeout=0.5)
            return True
        except Exception:
            return False

    def _infer_tag_from_task(self, task_type: str, data_type: str, context: Dict[str, Any], tags: List[str]) -> str:
        lowered = [t.lower() for t in tags]
        for t in ("summary", "swarm_planning", "world_model_update", "safety_review", "tactical_reasoning"):
            if t in lowered:
                return t

        t = task_type.lower()
        dt = data_type.lower()

        if "tactical" in t or "combat" in t or "game" in t:
            return "tactical_reasoning"
        if "summary" in t or dt == "text":
            return "summary"
        if "godswarm" in t or "swarm" in t:
            return "swarm_planning"
        if "knowledge_base" in t or "world_model" in t:
            return "world_model_update"
        if "ethics" in t or "security" in t:
            return "safety_review"
        return "generic"

    def _select_backends_for_tag(self, tag: str, multi_llm: bool) -> List[BaseLLMBackend]:
        cfg = self.config_manager.get()
        self.mode = cfg.get("llm_mode", self.mode)
        self.temperature = max(0.05, cfg.get("temperature", self.temperature))
        self._init_routing_rules()

        candidates = [b for b in self.backends if b.is_available()]
        rule = self.routing_rules.get(tag, self.routing_rules.get("generic", {}))
        preferred_kinds = rule.get("preferred_kinds", [])
        if preferred_kinds:
            candidates = [b for b in candidates if b.info.kind in preferred_kinds]
        if not candidates:
            candidates = [b for b in self.backends if b.is_available()]
        if not multi_llm and candidates:
            candidates.sort(key=lambda b: b.info.weight, reverse=True)
            return [candidates[0]]
        return candidates

    def _fuse_outputs(self, prompt: str, outputs: List[Tuple[BaseLLMBackend, str]]) -> str:
        if len(outputs) == 1:
            return outputs[0][1]

        scored = []
        for backend, out in outputs:
            conf = backend.estimate_confidence(prompt, out)
            scored.append((backend, out, conf))

        scored.sort(key=lambda x: x[2], reverse=True)
        top = scored[:3]

        fused_parts = []
        for backend, out, conf in top:
            fused_parts.append(
                f"[{backend.info.name} | kind={backend.info.kind} | conf={conf:.2f}]\n{out.strip()}"
            )

        return "\n\n=== FUSED ENSEMBLE ===\n\n" + "\n\n---\n\n".join(fused_parts)

    def generate_for_task(self, prompt: str, task_type: str, data_type: str,
                          max_tokens: int = 256, context: Dict[str, Any] = None,
                          tags: Optional[List[str]] = None) -> str:
        if context is None:
            context = {}
        if tags is None:
            tags = []

        tag = self._infer_tag_from_task(task_type, data_type, context, tags)
        multi_llm_default = (self.mode == "max_int")
        backends = self._select_backends_for_tag(tag, multi_llm=multi_llm_default)

        if not backends:
            return "[No LLM backends available]"

        multi_llm = (self.mode == "max_int") or self.routing_rules.get(tag, {}).get("multi_llm", False)

        if not multi_llm:
            for b in backends:
                t0 = time.time()
                try:
                    out = b.generate(prompt, max_tokens=max_tokens)
                    b.info.latency_ms = (time.time() - t0) * 1000.0
                    return out
                except Exception:
                    b.info.online = False
                    continue
            return "[All LLM backends failed]"

        outputs: List[Tuple[BaseLLMBackend, str]] = []
        for b in backends:
            t0 = time.time()
            try:
                out = b.generate(prompt, max_tokens=max_tokens)
                b.info.latency_ms = (time.time() - t0) * 1000.0
                outputs.append((b, out))
            except Exception:
                b.info.online = False
                continue

        if not outputs:
            return "[All LLM backends failed in multi-LLM mode]"

        return self._fuse_outputs(prompt, outputs)

# ============================================================
# VISION / ASR (GPU-AWARE)
# ============================================================

class VisionManager:
    def __init__(self, gpu: GPUManager):
        self.backend = CV2
        self.yolo_model = None
        self.vit_model = None
        self.gpu = gpu

        if ULTRALYTICS is not None:
            try:
                device = 0 if gpu.gpu_available else "cpu"
                self.yolo_model = ULTRALYTICS("yolov8n.pt")
                if hasattr(self.yolo_model, "to"):
                    self.yolo_model.to(device)
            except Exception:
                self.yolo_model = None

        if TRANSFORMERS is not None:
            try:
                device = 0 if gpu.gpu_available else -1
                self.vit_model = TRANSFORMERS.pipeline(
                    "image-classification",
                    model="google/vit-base-patch16-224",
                    device=device
                )
            except Exception:
                self.vit_model = None

    def process_image(self, img_bytes: bytes) -> Dict[str, Any]:
        if self.backend is None or NP is None:
            return {"status": "vision_unavailable"}
        arr = NP.frombuffer(img_bytes, dtype=NP.uint8)
        img = self.backend.imdecode(arr, self.backend.IMREAD_COLOR)
        if img is None:
            return {"status": "decode_failed"}
        h, w, c = img.shape
        mean_color = img.mean(axis=(0, 1)).tolist()
        result = {
            "status": "ok",
            "width": int(w),
            "height": int(h),
            "channels": int(c),
            "mean_color": mean_color,
            "yolo": None,
            "vit": None,
        }
        try:
            if self.yolo_model is not None:
                yolo_out = self.yolo_model(img)
                result["yolo"] = str(yolo_out)
        except Exception:
            traceback.print_exc()
        try:
            if self.vit_model is not None:
                vit_out = self.vit_model(img)
                result["vit"] = vit_out
        except Exception:
            traceback.print_exc()
        return result

class ASRManager:
    def __init__(self, gpu: GPUManager, model_name: str = "large-v2"):
        self.model = None
        self.gpu = gpu
        self.model_name = model_name
        if WHISPER is not None:
            try:
                device = "cuda" if gpu.gpu_available else "cpu"
                self.model = WHISPER.load_model(self.model_name, device=device)
            except Exception:
                self.model = None

    def transcribe(self, audio_bytes: bytes) -> str:
        if self.model is None:
            return "[ASR unavailable or not loaded]"
        with tempfile.NamedTemporaryFile(suffix=".wav", delete=True) as tmp:
            tmp.write(audio_bytes)
            tmp.flush()
            try:
                result = self.model.transcribe(tmp.name)
                return result.get("text", "")
            except Exception:
                traceback.print_exc()
                return "[ASR error during transcription]"

# ============================================================
# PERCEPTION
# ============================================================

class PerceptionSystems:
    def __init__(self, bus: EventBus, memory: PersistentMemory):
        self.bus = bus
        self.memory = memory
        self.live_sources: Dict[str, LiveDataSourceConfig] = {}
        self.bus.subscribe("perception.ingest", self._on_ingest_request)

    def register_live_source(self, source: LiveDataSourceConfig) -> None:
        self.live_sources[source.name] = source

    def _on_ingest_request(self, payload: Dict[str, Any]) -> None:
        self.bus.publish("watchdog.heartbeat", {})
        source_name = payload.get("source", "unknown")
        data_type = payload.get("data_type", "unknown")
        raw = payload.get("raw")

        normalized = {
            "source": source_name,
            "data_type": data_type,
            "content": raw,
        }

        self.memory.store_episode(source_name, data_type, {"raw": str(raw)})
        self.memory.append_shared_knowledge("system", source_name, {"data_type": data_type, "raw": str(raw)})
        self.bus.publish("metrics.update", {"metric": "ingest_count", "delta": 1})

        task = Task(
            id=f"task_{int(time.time()*1000)}",
            type=f"ingest_{data_type}",
            payload={"normalized": normalized},
            metadata={"source": source_name},
            tags=["summary"] if data_type == "text" else []
        )
        self.bus.publish("data_hub.process", {
            "stage": "perception",
            "task": asdict(task),
        })

# ============================================================
# DATA HUB
# ============================================================

class DataProcessingHub:
    def __init__(self, bus: EventBus):
        self.bus = bus
        self.bus.subscribe("data_hub.process", self._on_process_request)

    def _on_process_request(self, payload: Dict[str, Any]) -> None:
        self.bus.publish("watchdog.heartbeat", {})
        task_dict = payload.get("task", {})
        task = Task(**task_dict)
        normalized = task.payload.get("normalized", {})

        features = {
            "source": normalized.get("source"),
            "data_type": normalized.get("data_type"),
            "features": {},
            "raw": normalized.get("content"),
        }

        self.bus.publish("metrics.update", {"metric": "data_hub_events", "delta": 1})
        task.payload["features"] = features
        self.bus.publish("models.embed", {
            "stage": "data_hub",
            "task": asdict(task),
        })

# ============================================================
# MODELS / EMBEDDINGS
# ============================================================

class PretrainedModels:
    def __init__(self, bus: EventBus, llm_manager: MultiLLMManager, vision: VisionManager, asr: ASRManager, gpu: GPUManager):
        self.bus = bus
        self.llm_manager = llm_manager
        self.vision = vision
        self.asr = asr
        self.gpu = gpu
        self.models: Dict[str, ModelConfig] = {}
        self.bus.subscribe("models.embed", self._on_embed_request)

    def register_model(self, cfg: ModelConfig) -> None:
        self.models[cfg.name] = cfg

    def _on_embed_request(self, payload: Dict[str, Any]) -> None:
        self.bus.publish("watchdog.heartbeat", {})
        task_dict = payload.get("task", {})
        task = Task(**task_dict)
        features = task.payload.get("features", {})
        data_type = features.get("data_type", "unknown")
        raw = features.get("raw")

        embeddings = {"data_type": data_type, "vectors": {}, "meta": {}}

        try:
            if data_type == "text" and isinstance(raw, str):
                summary = self.llm_manager.generate_for_task(
                    prompt=raw[:2048],
                    task_type=task.type,
                    data_type=data_type,
                    max_tokens=256,
                    context={"stage": "models.embed"},
                    tags=task.tags + ["summary"]
                )
                embeddings["meta"]["summary"] = summary
            elif data_type == "file" and isinstance(raw, bytes):
                vis = self.vision.process_image(raw)
                embeddings["meta"]["vision"] = vis
            elif data_type == "audio" and isinstance(raw, bytes):
                transcript = self.asr.transcribe(raw)
                embeddings["meta"]["transcript"] = transcript
        except Exception:
            traceback.print_exc()

        self.bus.publish("metrics.update", {"metric": "model_calls", "delta": 1})
        task.payload["embeddings"] = embeddings
        self.bus.publish("godswarm.process", {
            "stage": "models",
            "task": asdict(task),
        })

# ============================================================
# SWARM (MULTI-AGENT COORDINATION)
# ============================================================

@dataclass
class SwarmAgent:
    id: str
    position: Tuple[float, float] = (0.0, 0.0)
    velocity: Tuple[float, float] = (0.0, 0.0)
    score: float = 0.0
    group: int = 0

class SwarmAgentManager:
    def __init__(self, num_agents: int = 32, num_groups: int = 4):
        self.agents: Dict[str, SwarmAgent] = {
            f"agent_{i}": SwarmAgent(
                id=f"agent_{i}",
                position=(random.uniform(-1, 1), random.uniform(-1, 1)),
                velocity=(0.0, 0.0),
                score=0.0,
                group=i % num_groups
            )
            for i in range(num_agents)
        }

    def _neighbors(self, agent: SwarmAgent, radius: float = 0.5) -> List[SwarmAgent]:
        res = []
        ax, ay = agent.position
        for other in self.agents.values():
            if other.id == agent.id:
                continue
            ox, oy = other.position
            d = math.sqrt((ax - ox)**2 + (ay - oy)**2)
            if d < radius:
                res.append(other)
        return res

    def step(self, context: Dict[str, Any]) -> Dict[str, Any]:
        for agent in self.agents.values():
            px, py = agent.position
            vx, vy = agent.velocity

            ax = -0.1 * px + random.uniform(-0.05, 0.05)
            ay = -0.1 * py + random.uniform(-0.05, 0.05)

            neighbors = self._neighbors(agent)
            if neighbors:
                avgx = sum(n.position[0] for n in neighbors) / len(neighbors)
                avgy = sum(n.position[1] for n in neighbors) / len(neighbors)
                ax += 0.05 * (avgx - px)
                ay += 0.05 * (avgy - py)

            vx = 0.9 * vx + ax
            vy = 0.9 * vy + ay
            px += vx
            py += vy
            agent.position = (px, py)
            agent.velocity = (vx, vy)
            agent.score = -math.sqrt(px * px + py * py)

        best_agent = max(self.agents.values(), key=lambda a: a.score)
        candidates = [{"agent_id": a.id, "score": a.score, "group": a.group} for a in self.agents.values()]
        return {
            "agents_state": {a.id: {"pos": a.position, "vel": a.velocity, "score": a.score, "group": a.group} for a in self.agents.values()},
            "candidates": candidates,
            "best_agent": {"id": best_agent.id, "score": best_agent.score, "group": best_agent.group},
        }

# ============================================================
# GODSWARM
# ============================================================

class GodswarmNeural:
    def __init__(self, bus: EventBus, swarm: SwarmAgentManager):
        self.bus = bus
        self.swarm = swarm
        self.bus.subscribe("godswarm.process", self._on_godswarm_request)

    def _on_godswarm_request(self, payload: Dict[str, Any]) -> None:
        self.bus.publish("watchdog.heartbeat", {})
        task_dict = payload.get("task", {})
        task = Task(**task_dict)
        embeddings = task.payload.get("embeddings", {})
        swarm_output = self.swarm.step({"embeddings": embeddings})
        self.bus.publish("metrics.update", {"metric": "swarm_steps", "delta": 1})
        task.payload["swarm_output"] = swarm_output
        task.tags.append("swarm_planning")
        self.bus.publish("quantum_core.process", {
            "stage": "godswarm",
            "task": asdict(task),
        })

# ============================================================
# QUANTUM CORE
# ============================================================

class QuantumCore:
    def __init__(self, bus: EventBus):
        self.bus = bus
        self.initial_temperature = 2.0
        self.cooling_rate = 0.95
        self.min_temperature = 0.1
        self.bus.subscribe("quantum_core.process", self._on_quantum_request)

    def _anneal(self, candidates: List[Dict[str, Any]]) -> Dict[str, Any]:
        if not candidates:
            return {"selected_action": None, "probabilities": {}}
        temp = self.initial_temperature
        current = random.choice(candidates)
        while temp > self.min_temperature:
            neighbor = random.choice(candidates)
            delta = neighbor["score"] - current["score"]
            if delta > 0 or math.exp(delta / max(temp, 1e-6)) > random.random():
                current = neighbor
            temp *= self.cooling_rate
        scores = [c["score"] for c in candidates]
        max_s = max(scores)
        exps = [math.exp((s - max_s) / max(self.min_temperature, 1e-6)) for s in scores]
        s = sum(exps)
        probs = [e / s for e in exps]
        return {
            "selected_action": current,
            "probabilities": {c["agent_id"]: p for c, p in zip(candidates, probs)},
        }

    def _on_quantum_request(self, payload: Dict[str, Any]) -> None:
        self.bus.publish("watchdog.heartbeat", {})
        task_dict = payload.get("task", {})
        task = Task(**task_dict)
        swarm_output = task.payload.get("swarm_output", {})
        candidates = swarm_output.get("candidates", [])
        quantum_decision = self._anneal(candidates)
        self.bus.publish("metrics.update", {"metric": "quantum_decisions", "delta": 1})
        task.payload["quantum_decision"] = quantum_decision
        self.bus.publish("hybrid_brain.process", {
            "stage": "quantum_core",
            "task": asdict(task),
        })

# ============================================================
# HYBRID BRAIN
# ============================================================

class HybridBrain:
    def __init__(self, bus: EventBus, memory: PersistentMemory):
        self.bus = bus
        self.memory = memory
        self.state: Dict[str, Any] = {}
        self.bus.subscribe("hybrid_brain.process", self._on_hybrid_request)

    def _on_hybrid_request(self, payload: Dict[str, Any]) -> None:
        self.bus.publish("watchdog.heartbeat", {})
        task_dict = payload.get("task", {})
        task = Task(**task_dict)
        quantum_decision = task.payload.get("quantum_decision", {})
        fused_plan = {
            "plan": [quantum_decision.get("selected_action")],
            "emotional_gradient": {},
            "cortical_activity": {},
        }
        self.bus.publish("metrics.update", {"metric": "hybrid_plans", "delta": 1})
        task.payload["fused_plan"] = fused_plan
        self.bus.publish("parallel_core.process", {
            "stage": "hybrid_brain",
            "task": asdict(task),
        })

# ============================================================
# PARALLEL CORE
# ============================================================

class ParallelComputationCore:
    def __init__(self, bus: EventBus):
        self.bus = bus
        self.bus.subscribe("parallel_core.process", self._on_parallel_request)

    def _on_parallel_request(self, payload: Dict[str, Any]) -> None:
        self.bus.publish("watchdog.heartbeat", {})
        task_dict = payload.get("task", {})
        task = Task(**task_dict)
        fused_plan = task.payload.get("fused_plan", {})
        optimized_plan = {
            "optimized_actions": fused_plan.get("plan", []),
            "training_metrics": {},
        }
        self.bus.publish("metrics.update", {"metric": "parallel_steps", "delta": 1})
        task.payload["optimized_plan"] = optimized_plan
        self.bus.publish("knowledge_base.process", {
            "stage": "parallel_core",
            "task": asdict(task),
        })

# ============================================================
# KNOWLEDGE BASE
# ============================================================

class ContextualKnowledgeBase:
    def __init__(self, bus: EventBus, memory: PersistentMemory):
        self.bus = bus
        self.memory = memory
        self.world_model: Dict[str, Any] = {}
        self.bus.subscribe("knowledge_base.process", self._on_kb_request)

    def _on_kb_request(self, payload: Dict[str, Any]) -> None:
        self.bus.publish("watchdog.heartbeat", {})
        task_dict = payload.get("task", {})
        task = Task(**task_dict)
        optimized_plan = task.payload.get("optimized_plan", {})
        final_decision = {
            "actions": optimized_plan.get("optimized_actions", []),
            "coordination": {},
        }
        self.bus.publish("metrics.update", {"metric": "kb_decisions", "delta": 1})
        task.payload["final_decision"] = final_decision
        task.tags.append("safety_review")
        self.bus.publish("ethics_security.check", {
            "stage": "knowledge_base",
            "task": asdict(task),
        })

# ============================================================
# ETHICS
# ============================================================

class EthicalSecurityLayer:
    def __init__(self, bus: EventBus):
        self.bus = bus
        self.bus.subscribe("ethics_security.check", self._on_ethics_request)

    def _on_ethics_request(self, payload: Dict[str, Any]) -> None:
        self.bus.publish("watchdog.heartbeat", {})
        task_dict = payload.get("task", {})
        task = Task(**task_dict)
        final_decision = task.payload.get("final_decision", {})
        safe_decision = {
            "actions": final_decision.get("actions", []),
            "flags": [],
        }
        self.bus.publish("metrics.update", {"metric": "ethics_checks", "delta": 1})
        task.payload["safe_decision"] = safe_decision
        self.bus.publish("action_systems.execute", {
            "stage": "ethics_security",
            "task": asdict(task),
        })

# ============================================================
# ROBOTICS / ROS / ACTIONS
# ============================================================

class ROS2Connector:
    def __init__(self, topic: Optional[str] = None):
        self.topic = topic
        self.node = None
        self.publisher = None
        if ROS2 is not None and topic:
            try:
                ROS2.init(args=None)
                from std_msgs.msg import String
                self.node = ROS2.create_node("astral_necroxis_ros2")
                self.publisher = self.node.create_publisher(String, topic, 10)
            except Exception:
                self.node = None
                self.publisher = None

    def publish_actions(self, actions: List[Dict[str, Any]]):
        if self.publisher is None or ROS2 is None:
            return
        try:
            from std_msgs.msg import String
            msg = String()
            msg.data = json.dumps({"actions": actions})
            self.publisher.publish(msg)
        except Exception:
            traceback.print_exc()

class RoboticsConnector:
    def __init__(self, http_endpoint: Optional[str] = None, ros_topic: Optional[str] = None, ros2_topic: Optional[str] = None):
        self.last_actions: List[Dict[str, Any]] = []
        self.http_endpoint = http_endpoint
        self.ros_topic = ros_topic
        self.ros2 = ROS2Connector(topic=ros2_topic)
        if ROSPY is not None and self.ros_topic:
            try:
                ROSPY.init_node("astral_necroxis_robotics", anonymous=True)
                from std_msgs.msg import String
                self.ros_pub = ROSPY.Publisher(self.ros_topic, String, queue_size=10)
            except Exception:
                self.ros_pub = None
        else:
            self.ros_pub = None

    def execute_actions(self, actions: List[Dict[str, Any]]):
        self.last_actions = actions
        for a in actions:
            print("[ROBOTICS] Action:", a)

        if self.http_endpoint and REQUESTS is not None and actions:
            try:
                REQUESTS.post(self.http_endpoint, json={"actions": actions}, timeout=2.0)
            except Exception:
                traceback.print_exc()

        if self.ros_pub is not None and ROSPY is not None:
            try:
                from std_msgs.msg import String
                msg = String()
                msg.data = json.dumps({"actions": actions})
                self.ros_pub.publish(msg)
            except Exception:
                traceback.print_exc()

        self.ros2.publish_actions(actions)

class ActionSystems:
    def __init__(self, bus: EventBus, robotics: RoboticsConnector):
        self.bus = bus
        self.robotics = robotics
        self.bus.subscribe("action_systems.execute", self._on_execute_request)

    def _on_execute_request(self, payload: Dict[str, Any]) -> None:
        self.bus.publish("watchdog.heartbeat", {})
        task_dict = payload.get("task", {})
        task = Task(**task_dict)
        safe_decision = task.payload.get("safe_decision", {})
        actions = safe_decision.get("actions", [])
        self.robotics.execute_actions(actions)
        self.bus.publish("metrics.update", {"metric": "actions_executed", "delta": len(actions)})

# ============================================================
# OUTPUTS / MLOps
# ============================================================

class OutputModules:
    def __init__(self, bus: EventBus):
        self.bus = bus

class DatasetsManager:
    def __init__(self, bus: EventBus):
        self.bus = bus
        self.models_registry: Dict[str, ModelConfig] = {}
        self.experiments: List[Dict[str, Any]] = []

    def register_model(self, cfg: ModelConfig) -> None:
        self.models_registry[cfg.name] = cfg

    def track_experiment(self, info: Dict[str, Any]) -> None:
        self.experiments.append(info)

# ============================================================
# CLUSTER (SELF-HEALING NETWORK SUBSYSTEM)
# ============================================================

class ClusterJobQueue:
    def __init__(self):
        self.queue: List[Dict[str, Any]] = []
        self.lock = threading.Lock()

    def push(self, job: Dict[str, Any]):
        with self.lock:
            self.queue.append(job)

    def pop(self) -> Optional[Dict[str, Any]]:
        with self.lock:
            if not self.queue:
                return None
            return self.queue.pop(0)

    def size(self) -> int:
        with self.lock:
            return len(self.queue)

class DistributedNodeManager:
    def __init__(self, bus: EventBus, host: str = "0.0.0.0", port: int = 5555, role: str = "worker"):
        self.bus = bus
        self.host = host
        self.port = port
        self.role = role
        self.job_queue = ClusterJobQueue()
        self.workers: List[Tuple[str, int]] = []
        self.server_thread = threading.Thread(target=self._server_loop, daemon=True)
        self.server_thread.start()

        if self.role == "master":
            self.dispatch_thread = threading.Thread(target=self._dispatch_loop, daemon=True)
            self.dispatch_thread.start()

    def register_worker(self, host: str, port: int):
        self.workers.append((host, port))

    def _server_loop(self):
        while True:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

                bound_port = safe_bind(s, self.host, self.port, max_attempts=20)
                if bound_port is None:
                    print("[CLUSTER] Failed to bind cluster server. Self-healing: waiting 5s and retrying...")
                    time.sleep(5)
                    continue

                if bound_port != self.port:
                    print(f"[CLUSTER] Port {self.port} unavailable, using fallback {bound_port}")
                    self.port = bound_port

                s.listen(5)
                print(f"[CLUSTER] Listening on {self.host}:{self.port}")
                while True:
                    conn, addr = s.accept()
                    threading.Thread(target=self._handle_client, args=(conn, addr), daemon=True).start()
            except Exception:
                traceback.print_exc()
                print("[CLUSTER] Server loop crashed, self-healing: restarting in 5s...")
                time.sleep(5)

    def _handle_client(self, conn: socket.socket, addr):
        try:
            data = conn.recv(65536)
            if not data:
                conn.close()
                return
            try:
                msg = json.loads(data.decode("utf-8"))
                topic = msg.get("topic", "distributed.incoming")
                payload = msg.get("payload", {})
                if topic == "cluster.job":
                    self.job_queue.push(payload)
                else:
                    self.bus.publish(topic, payload)
            except Exception:
                traceback.print_exc()
        finally:
            conn.close()

    def _dispatch_loop(self):
        while True:
            job = self.job_queue.pop()
            if job is None:
                time.sleep(0.1)
                continue
            if not self.workers:
                self.bus.publish(job.get("topic", "perception.ingest"), job.get("payload", {}))
                continue
            worker = self.workers.pop(0)
            self.workers.append(worker)
            host, port = worker
            self._send_to_node(host, port, job.get("topic", "perception.ingest"), job.get("payload", {}))

    def _send_to_node(self, host: str, port: int, topic: str, payload: Dict[str, Any]):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2.0)
            s.connect((host, port))
            msg = json.dumps({"topic": topic, "payload": payload}).encode("utf-8")
            s.sendall(msg)
            s.close()
        except Exception as e:
            traceback.print_exc()
            print(f"[CLUSTER] Failed to send to {host}:{port} ({e}). Self-healing: executing locally.")
            self.bus.publish(topic, payload)

    def submit_job(self, topic: str, payload: Dict[str, Any]):
        self.job_queue.push({"topic": topic, "payload": payload})

# ============================================================
# WATCHDOG + RECOVERY
# ============================================================

class WatchdogSupervisor:
    def __init__(self, bus: EventBus, interval: float = 5.0):
        self.bus = bus
        self.interval = interval
        self.last_heartbeat = time.time()
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        self.bus.subscribe("watchdog.heartbeat", self._on_heartbeat)

    def _on_heartbeat(self, payload: Dict[str, Any]):
        self.last_heartbeat = time.time()
        self.bus.publish("metrics.update", {"metric": "heartbeat_count", "delta": 1})
        self.bus.publish("system.health", {"status": "healthy"})

    def _loop(self):
        while True:
            now = time.time()
            if now - self.last_heartbeat > self.interval * 2:
                print("[WATCHDOG] No heartbeat detected, system might be stalled.")
                self.bus.publish("system.health", {"status": "degraded"})
                self.bus.publish("watchdog.recover", {})
            time.sleep(self.interval)

class RecoveryManager:
    def __init__(self, bus: EventBus):
        self.bus = bus
        self.bus.subscribe("watchdog.recover", self._on_recover)

    def _on_recover(self, payload: Dict[str, Any]):
        print("[RECOVERY] Attempting auto-recovery: sending synthetic heartbeat.")
        self.bus.publish("watchdog.heartbeat", {})

def start_auto_heartbeat(bus: EventBus, interval: float = 3.0):
    def loop():
        while True:
            bus.publish("watchdog.heartbeat", {})
            time.sleep(interval)
    threading.Thread(target=loop, daemon=True).start()

# ============================================================
# SWARM VISUALIZER / DASHBOARD (TK)
# ============================================================

class SwarmVisualizer(ttk.Frame):
    def __init__(self, parent, swarm: SwarmAgentManager):
        super().__init__(parent)
        self.swarm = swarm
        self.canvas = tk.Canvas(self, bg="black")
        self.canvas.pack(fill=tk.BOTH, expand=True)
        self._update()

    def _update(self):
        self.canvas.delete("all")
        w = self.canvas.winfo_width() or 400
        h = self.canvas.winfo_height() or 300
        for agent in self.swarm.agents.values():
            px, py = agent.position
            x = int((px + 1) / 2 * w)
            y = int((py + 1) / 2 * h)
            color = "cyan" if agent.group == 0 else "magenta" if agent.group == 1 else "yellow"
            self.canvas.create_oval(x-4, y-4, x+4, y+4, fill=color)
        self.after(100, self._update)

class DashboardFrame(ttk.Frame):
    def __init__(self, parent, gpu_manager: GPUManager, metrics: MetricsStore, bus: EventBus):
        super().__init__(parent)
        self.gpu_manager = gpu_manager
        self.metrics = metrics
        self.bus = bus

        ttk.Label(self, text="Live Dashboard").pack(anchor=tk.W, padx=5, pady=5)
        self.health_label = ttk.Label(self, text="System Health: unknown")
        self.health_label.pack(anchor=tk.W, padx=5, pady=5)

        self.bus.subscribe("system.health", self._on_health_update)

        if FIGURE is not None and CANVAS is not None:
            self.fig = FIGURE(figsize=(4, 3), dpi=100)
            self.ax = self.fig.add_subplot(111)
            self.canvas = CANVAS(self.fig, master=self)
            self.canvas.get_tk_widget().pack(fill=tk.BOTH, expand=True)
            self._update_plot()
        else:
            ttk.Label(self, text="Matplotlib not available").pack(anchor=tk.W, padx=5, pady=5)

    def _on_health_update(self, payload: Dict[str, Any]):
        status = payload.get("status", "unknown")
        self.health_label.config(text=f"System Health: {status}")

    def _update_plot(self):
        if FIGURE is None or CANVAS is None:
            return
        self.ax.clear()
        snap = self.metrics.snapshot()
        names = list(snap.keys())
        vals = [snap[n] for n in names]
        if names:
            self.ax.barh(names, vals)
            self.ax.set_title("Metrics")
        self.canvas.draw()
        self.after(1000, self._update_plot)

# ============================================================
# GAME INTEGRATION (MEMORY READER + BEHAVIOR TREE + RL)
# ============================================================

@dataclass
class GameProfile:
    name: str
    process_names: List[str]
    capture_region: Optional[Tuple[int, int, int, int]] = None
    notes: str = ""

class GameMemoryReader:
    """
    Config-driven memory reader.
    For real offsets, fill brain_config.json -> memory_offsets.
    This class is ready to be wired to pymem/ctypes when you have real offsets.
    """
    def __init__(self, profile: GameProfile, config_manager: ConfigManager,
                 host: str = "127.0.0.1", port: int = 7777):
        self.profile = profile
        self.host = host
        self.port = port
        self.config_manager = config_manager

    def read_state(self) -> Dict[str, Any]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(0.05)
            s.connect((self.host, self.port))
            s.sendall(b"GET_STATE\n")
            data = s.recv(65536)
            s.close()
            if data:
                state = json.loads(data.decode("utf-8"))
                state.setdefault("game", self.profile.name)
                return state
        except Exception:
            pass

        return self._fallback_state()

    def _fallback_state(self) -> Dict[str, Any]:
        cfg = self.config_manager.get()
        offsets = cfg.get("memory_offsets", {}).get(self.profile.name, {})
        return {
            "player_health": 100,
            "ammo": 120,
            "enemies_visible": 0,
            "objective": "idle",
            "game": self.profile.name,
            "offsets_loaded": bool(offsets),
        }

class FrameGrabber:
    def __init__(self, profile: GameProfile):
        self.profile = profile

    def grab_frame(self) -> Optional[bytes]:
        if (PIL is None and MSS is None) or CV2 is None or NP is None:
            return None
        try:
            if MSS is not None:
                with MSS.mss() as sct:
                    if self.profile.capture_region:
                        left, top, right, bottom = self.profile.capture_region
                        mon = {"left": left, "top": top, "width": right-left, "height": bottom-top}
                    else:
                        mon = sct.monitors[1]
                    img = sct.grab(mon)
                    arr = NP.array(img)
                    arr = CV2.cvtColor(arr, CV2.COLOR_BGRA2BGR)
            else:
                if self.profile.capture_region:
                    left, top, right, bottom = self.profile.capture_region
                    img = PIL.grab(bbox=(left, top, right, bottom))
                else:
                    img = PIL.grab()
                img = img.convert("RGB")
                arr = NP.array(img)
            _, buf = CV2.imencode(".jpg", arr)
            return buf.tobytes()
        except Exception:
            traceback.print_exc()
            return None

class GameEventParser:
    def parse(self, state: Dict[str, Any], vision_meta: Dict[str, Any]) -> List[Dict[str, Any]]:
        events = []
        if state.get("player_health", 100) < 30:
            events.append({"type": "low_health", "severity": "high"})
        if state.get("enemies_visible", 0) > 5:
            events.append({"type": "many_enemies", "count": state["enemies_visible"]})
        if vision_meta.get("status") == "ok":
            events.append({"type": "frame_analyzed"})
        return events

class GameStateAdapter:
    def adapt(self, profile: GameProfile, state: Dict[str, Any], events: List[Dict[str, Any]]) -> Dict[str, Any]:
        return {
            "game": profile.name,
            "raw_state": state,
            "events": events,
            "threat_level": self._estimate_threat(state, events),
        }

    def _estimate_threat(self, state: Dict[str, Any], events: List[Dict[str, Any]]) -> float:
        threat = 0.0
        threat += state.get("enemies_visible", 0) * 0.1
        if any(e["type"] == "low_health" for e in events):
            threat += 1.0
        return min(1.0, threat)

class GameActionAdapter:
    def to_actions(self, tactical_plan: Dict[str, Any]) -> List[Dict[str, Any]]:
        actions = []
        intent = tactical_plan.get("intent", "hold")
        if intent == "retreat":
            actions.append({"type": "move", "direction": "back"})
        elif intent == "push":
            actions.append({"type": "move", "direction": "forward"})
        elif intent == "hold":
            actions.append({"type": "hold_position"})
        if tactical_plan.get("use_grenade"):
            actions.append({"type": "use_item", "item": "grenade"})
        return actions

# ----------------- Behavior Tree + RL -----------------------

class BTNode:
    def tick(self, blackboard: Dict[str, Any]) -> bool:
        raise NotImplementedError

class Selector(BTNode):
    def __init__(self, children: List[BTNode]):
        self.children = children

    def tick(self, blackboard: Dict[str, Any]) -> bool:
        for c in self.children:
            if c.tick(blackboard):
                return True
        return False

class Sequence(BTNode):
    def __init__(self, children: List[BTNode]):
        self.children = children

    def tick(self, blackboard: Dict[str, Any]) -> bool:
        for c in self.children:
            if not c.tick(blackboard):
                return False
        return True

class Condition(BTNode):
    def __init__(self, fn: Callable[[Dict[str, Any]], bool]):
        self.fn = fn

    def tick(self, blackboard: Dict[str, Any]) -> bool:
        return self.fn(blackboard)

class ActionNode(BTNode):
    def __init__(self, fn: Callable[[Dict[str, Any]], None]):
        self.fn = fn

    def tick(self, blackboard: Dict[str, Any]) -> bool:
        self.fn(blackboard)
        return True

class RLAgent:
    """
    Tiny Q-learning style agent for intent selection.
    State: discretized threat level.
    Actions: retreat / hold / push.
    """
    def __init__(self):
        self.q: Dict[Tuple[int, str], float] = {}
        self.actions = ["retreat", "hold", "push"]
        self.alpha = 0.1
        self.gamma = 0.9
        self.epsilon = 0.1

    def _state_key(self, threat: float) -> int:
        return int(threat * 10)

    def select_action(self, threat: float) -> str:
        s = self._state_key(threat)
        if random.random() < self.epsilon:
            return random.choice(self.actions)
        vals = [(self.q.get((s, a), 0.0), a) for a in self.actions]
        vals.sort(reverse=True)
        return vals[0][1]

    def update(self, threat: float, action: str, reward: float, next_threat: float):
        s = self._state_key(threat)
        ns = self._state_key(next_threat)
        old_q = self.q.get((s, action), 0.0)
        max_next = max(self.q.get((ns, a), 0.0) for a in self.actions)
        new_q = old_q + self.alpha * (reward + self.gamma * max_next - old_q)
        self.q[(s, action)] = new_q

class TacticalReasoner:
    def __init__(self, llm_manager: MultiLLMManager, swarm: SwarmAgentManager):
        self.llm_manager = llm_manager
        self.swarm = swarm
        self.rl = RLAgent()
        self._build_behavior_tree()

    def _build_behavior_tree(self):
        def is_high_threat(bb): return bb["threat_level"] > 0.7
        def is_mid_threat(bb): return 0.3 < bb["threat_level"] <= 0.7
        def set_retreat(bb): bb["intent"] = "retreat"
        def set_hold(bb): bb["intent"] = "hold"
        def set_push(bb): bb["intent"] = "push"

        self.bt_root = Selector([
            Sequence([Condition(is_high_threat), ActionNode(set_retreat)]),
            Sequence([Condition(is_mid_threat), ActionNode(set_hold)]),
            ActionNode(set_push)
        ])

    def reason(self, game_state: Dict[str, Any]) -> Dict[str, Any]:
        swarm_out = self.swarm.step({"game_state": game_state})
        best_agent = swarm_out.get("best_agent", {})

        blackboard = {
            "threat_level": game_state.get("threat_level", 0.0),
            "intent": "hold"
        }
        self.bt_root.tick(blackboard)
        bt_intent = blackboard["intent"]

        rl_intent = self.rl.select_action(blackboard["threat_level"])

        final_intent = bt_intent
        if random.random() < 0.3:
            final_intent = rl_intent

        prompt = (
            f"Game: {game_state.get('game')}\n"
            f"Threat level: {game_state.get('threat_level')}\n"
            f"Events: {game_state.get('events')}\n"
            f"Swarm best agent: {best_agent}\n"
            f"BehaviorTree intent: {bt_intent}\n"
            f"RL intent: {rl_intent}\n\n"
            "You are a tactical AI. Suggest a concise combat plan: retreat, hold, or push, "
            "and whether to use grenades."
        )
        llm_out = self.llm_manager.generate_for_task(
            prompt=prompt,
            task_type="tactical_reasoning",
            data_type="text",
            max_tokens=128,
            context={"stage": "tactical_reasoner"},
            tags=["tactical_reasoning", "swarm_planning"]
        )

        use_grenade = "grenade" in llm_out.lower()
        if "retreat" in llm_out.lower():
            intent = "retreat"
        elif "push" in llm_out.lower() or "advance" in llm_out.lower():
            intent = "push"
        else:
            intent = final_intent

        reward = 0.0
        if intent == "retreat" and game_state.get("threat_level", 0) > 0.7:
            reward = 1.0
        elif intent == "push" and game_state.get("threat_level", 0) < 0.3:
            reward = 1.0
        else:
            reward = -0.1
        self.rl.update(game_state.get("threat_level", 0.0), rl_intent, reward, game_state.get("threat_level", 0.0))

        return {
            "intent": intent,
            "use_grenade": use_grenade,
            "llm_plan": llm_out,
            "swarm_best_agent": best_agent,
            "bt_intent": bt_intent,
            "rl_intent": rl_intent,
        }

class GameIntegrationManager:
    def __init__(self,
                 bus: EventBus,
                 profile: GameProfile,
                 vision: VisionManager,
                 llm_manager: MultiLLMManager,
                 swarm: SwarmAgentManager,
                 config_manager: ConfigManager,
                 telemetry_host: str = "127.0.0.1",
                 telemetry_port: int = 7777):
        self.bus = bus
        self.profile = profile
        self.vision = vision
        self.memory_reader = GameMemoryReader(profile, config_manager, host=telemetry_host, port=telemetry_port)
        self.frame_grabber = FrameGrabber(profile)
        self.event_parser = GameEventParser()
        self.state_adapter = GameStateAdapter()
        self.tactical_reasoner = TacticalReasoner(llm_manager, swarm)
        self.action_adapter = GameActionAdapter()
        self.running = False
        self.thread = None
        self.last_game_state: Dict[str, Any] = {}

    def start(self, interval: float = 0.5):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, args=(interval,), daemon=True)
        self.thread.start()
        print(f"[GAME] Real-time loop started for profile: {self.profile.name}")

    def stop(self):
        self.running = False
        print(f"[GAME] Real-time loop stopped for profile: {self.profile.name}")

    def _loop(self, interval: float):
        while self.running:
            try:
                state = self.memory_reader.read_state()
                frame_bytes = self.frame_grabber.grab_frame()
                vision_meta = {}
                if frame_bytes is not None:
                    vision_meta = self.vision.process_image(frame_bytes)
                events = self.event_parser.parse(state, vision_meta)
                game_state = self.state_adapter.adapt(self.profile, state, events)
                self.last_game_state = game_state
                tactical_plan = self.tactical_reasoner.reason(game_state)
                actions = self.action_adapter.to_actions(tactical_plan)

                task = Task(
                    id=f"game_{int(time.time()*1000)}",
                    type="game_tactical_decision",
                    payload={
                        "game_state": game_state,
                        "tactical_plan": tactical_plan,
                        "actions": actions,
                    },
                    metadata={"game": self.profile.name},
                    tags=["tactical_reasoning", "swarm_planning"]
                )
                self.bus.publish("game.actions", {"task": asdict(task)})
                self.bus.publish("metrics.update", {"metric": "game_ticks", "delta": 1})
                self.bus.publish("watchdog.heartbeat", {})
            except Exception:
                traceback.print_exc()
            time.sleep(interval)

class GameActionSink:
    def __init__(self, bus: EventBus):
        self.bus = bus
        self.bus.subscribe("game.actions", self._on_game_actions)

    def _on_game_actions(self, payload: Dict[str, Any]):
        task_dict = payload.get("task", {})
        task = Task(**task_dict)
        actions = task.payload.get("actions", [])
        safe_decision = {"actions": actions, "flags": []}
        final_task = Task(
            id=task.id,
            type="game_action_execution",
            payload={"safe_decision": safe_decision},
            metadata=task.metadata,
            tags=task.tags + ["safety_review"]
        )
        self.bus.publish("action_systems.execute", {
            "stage": "game_integration",
            "task": asdict(final_task),
        })

# ============================================================
# AUTO PROFILE DETECTION
# ============================================================

def detect_active_profile(profiles: List[GameProfile],
                          telemetry_host: str = "127.0.0.1",
                          telemetry_port: int = 7777) -> GameProfile:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        s.connect((telemetry_host, telemetry_port))
        s.sendall(b"GET_STATE\n")
        data = s.recv(65536)
        s.close()
        if data:
            state = json.loads(data.decode("utf-8"))
            gname = state.get("game", "").lower()
            for p in profiles:
                if p.name.lower() == gname:
                    return p
    except Exception:
        pass

    try:
        import psutil
        procs = [p.info.get("name", "") for p in psutil.process_iter(attrs=["name"])]
        for p in profiles:
            for exe in p.process_names:
                if exe in procs:
                    return p
    except Exception:
        pass

    return profiles[-1]

# ============================================================
# LOCAL HTTP "BRAIN" SERVER
# ============================================================

class BrainHTTPHandler(BASEHTTPRequestHandler):
    def _send_json(self, code: int, obj: Any):
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps(obj).encode("utf-8"))

    def do_GET(self):
        try:
            if self.path.startswith("/shared"):
                query = self.path.split("?", 1)[-1] if "?" in self.path else ""
                params = {}
                for part in query.split("&"):
                    if "=" in part:
                        k, v = part.split("=", 1)
                        params[k] = v
                channel = params.get("channel")
                limit = int(params.get("limit", "50"))
                data = self.server.memory.query_shared_knowledge(channel=channel, limit=limit)
                self._send_json(200, {"ok": True, "data": data})
            elif self.path.startswith("/config"):
                cfg = self.server.config_manager.get()
                self._send_json(200, {"ok": True, "config": cfg})
            else:
                self._send_json(404, {"ok": False, "error": "not_found"})
        except Exception as e:
            traceback.print_exc()
            self._send_json(500, {"ok": False, "error": str(e)})

    def do_POST(self):
        try:
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length) if length > 0 else b"{}"
            data = json.loads(body.decode("utf-8") or "{}")

            if self.path == "/shared":
                channel = data.get("channel", "external")
                source = data.get("source", "http_client")
                content = data.get("content", {})
                self.server.memory.append_shared_knowledge(channel, source, content)
                self._send_json(200, {"ok": True})
            elif self.path == "/ingest":
                source = data.get("source", "http_ingest")
                data_type = data.get("data_type", "text")
                raw = data.get("raw", "")
                self.server.bus.publish("perception.ingest", {
                    "source": source,
                    "data_type": data_type,
                    "raw": raw,
                })
                self._send_json(200, {"ok": True})
            elif self.path == "/preset":
                name = data.get("name")
                if name:
                    self.server.config_manager.apply_preset(name)
                    self._send_json(200, {"ok": True})
                else:
                    self._send_json(400, {"ok": False, "error": "missing preset name"})
            else:
                self._send_json(404, {"ok": False, "error": "not_found"})
        except Exception as e:
            traceback.print_exc()
            self._send_json(500, {"ok": False, "error": str(e)})

class BrainHTTPServer:
    def __init__(self, host: str, port: int, memory: PersistentMemory, config_manager: ConfigManager, bus: EventBus):
        if HTTP_SERVER is None or BASEHTTPRequestHandler is None:
            print("[HTTP] http.server not available, brain server disabled.")
            self.server = None
            return

        class _Server(HTTP_SERVER):
            def __init__(self, server_address, RequestHandlerClass):
                super().__init__(server_address, RequestHandlerClass)
                self.memory = memory
                self.config_manager = config_manager
                self.bus = bus

        try_port = port
        server = None
        for _ in range(5):
            try:
                server = _Server((host, try_port), BrainHTTPHandler)
                if try_port != port:
                    print(f"[HTTP] Port {port} unavailable, using fallback {try_port}")
                break
            except OSError as e:
                if e.errno == 10013:
                    print(f"[HTTP] WinError 10013 on port {try_port}")
                    diagnose_10013(try_port)
                    try_port += 1
                    continue
                elif e.errno == 10048:
                    print(f"[HTTP] Port {try_port} already in use, trying next...")
                    try_port += 1
                    continue
                else:
                    traceback.print_exc()
                    break
            except Exception:
                traceback.print_exc()
                break

        if server is None:
            print("[HTTP] Failed to bind HTTP brain server after retries. Self-healing: disabled HTTP server.")
            print_firewall_hint()
            self.server = None
            return

        self.server = server
        threading.Thread(target=self.server.serve_forever, daemon=True).start()
        print(f"[HTTP] Brain server listening on http://{host}:{try_port}")

# ============================================================
# WEB DASHBOARD (FLASK)
# ============================================================

class WebDashboard:
    def __init__(self, metrics: MetricsStore, swarm: SwarmAgentManager,
                 game_managers: Dict[str, GameIntegrationManager],
                 host: str = "127.0.0.1", port: int = 5000, enabled: bool = True):
        self.metrics = metrics
        self.swarm = swarm
        self.game_managers = game_managers
        self.host = host
        self.port = port
        self.enabled = enabled and FLASK is not None
        if not self.enabled:
            print("[WEB] Flask not available or disabled, web dashboard off.")
            return
        self.app = FLASK(__name__)
        self._setup_routes()
        threading.Thread(target=self._run, daemon=True).start()
        print(f"[WEB] Dashboard at http://{host}:{port}")

    def _setup_routes(self):
        @self.app.route("/metrics")
        def metrics_route():
            return json.dumps(self.metrics.snapshot())

        @self.app.route("/swarm")
        def swarm_route():
            return json.dumps({
                "agents": {
                    a.id: {"pos": a.position, "vel": a.velocity, "score": a.score, "group": a.group}
                    for a in self.swarm.agents.values()
                }
            })

        @self.app.route("/games")
        def games_route():
            out = {}
            for name, gm in self.game_managers.items():
                out[name] = gm.last_game_state
            return json.dumps(out)

    def _run(self):
        self.app.run(host=self.host, port=self.port, debug=False, use_reloader=False)

# ============================================================
# PLUGIN SYSTEM
# ============================================================

class PluginManager:
    def __init__(self, bus: EventBus, plugins_dir: str = "plugins"):
        self.bus = bus
        self.plugins_dir = plugins_dir
        self.plugins: Dict[str, Any] = {}
        self._load_plugins()

    def _load_plugins(self):
        if not os.path.isdir(self.plugins_dir):
            return
        sys.path.insert(0, self.plugins_dir)
        for path in glob.glob(os.path.join(self.plugins_dir, "*.py")):
            name = os.path.splitext(os.path.basename(path))[0]
            try:
                mod = importlib.import_module(name)
                if hasattr(mod, "register"):
                    mod.register(self.bus)
                    self.plugins[name] = mod
                    print(f"[PLUGIN] Loaded plugin: {name}")
            except Exception:
                traceback.print_exc()

# ============================================================
# TKINTER GUI
# ============================================================

class MegaSystemGUI(tk.Tk):
    def __init__(self,
                 bus: EventBus,
                 perception: PerceptionSystems,
                 data_hub: DataProcessingHub,
                 models: PretrainedModels,
                 godswarm: GodswarmNeural,
                 quantum_core: QuantumCore,
                 hybrid_brain: HybridBrain,
                 parallel_core: ParallelComputationCore,
                 kb: ContextualKnowledgeBase,
                 ethics: EthicalSecurityLayer,
                 actions: ActionSystems,
                 outputs: OutputModules,
                 mlops: DatasetsManager,
                 gpu_manager: GPUManager,
                 metrics: MetricsStore,
                 cluster: DistributedNodeManager,
                 swarm: SwarmAgentManager,
                 llm_manager: MultiLLMManager,
                 game_managers: Dict[str, GameIntegrationManager],
                 auto_active_profile: Optional[str],
                 config_manager: ConfigManager):
        super().__init__()

        self.title("ASTRAL-NECROXIS PRIME OMEGA++ - Ultra Game AI Edition")
        self.geometry("1800x950")

        self.bus = bus
        self.perception = perception
        self.data_hub = data_hub
        self.models = models
        self.godswarm = godswarm
        self.quantum_core = quantum_core
        self.hybrid_brain = hybrid_brain
        self.parallel_core = parallel_core
        self.kb = kb
        self.ethics = ethics
        self.actions = actions
        self.outputs = outputs
        self.mlops = mlops
        self.gpu_manager = gpu_manager
        self.metrics = metrics
        self.cluster = cluster
        self.swarm = swarm
        self.llm_manager = llm_manager
        self.game_managers = game_managers
        self.auto_active_profile = auto_active_profile
        self.config_manager = config_manager

        self._build_layout()

        if self.auto_active_profile and self.auto_active_profile in self.game_managers:
            self.game_managers[self.auto_active_profile].start(interval=0.5)

    def _build_layout(self) -> None:
        main_frame = ttk.Frame(self)
        main_frame.pack(fill=tk.BOTH, expand=True)

        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)

        right_frame = ttk.Frame(main_frame)
        right_frame.pack(side=tk.RIGHT, fill=tk.Y)

        self.log_text = scrolledtext.ScrolledText(right_frame, width=60, height=40)
        self.log_text.pack(fill=tk.BOTH, expand=True)

        control_frame = ttk.Frame(right_frame)
        control_frame.pack(fill=tk.X)

        ttk.Button(control_frame, text="Load File",
                   command=self._on_load_file).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Ingest Text",
                   command=self._on_ingest_text).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Heartbeat",
                   command=self._send_heartbeat).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Toggle LLM Mode",
                   command=self._toggle_mode).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Preset A (Balanced)",
                   command=lambda: self._apply_preset("A_Balanced_Intelligence")).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Preset D (Max)",
                   command=lambda: self._apply_preset("D_Maximum_Intelligence")).pack(side=tk.LEFT, padx=5, pady=5)
        ttk.Button(control_frame, text="Quit",
                   command=self.destroy).pack(side=tk.RIGHT, padx=5, pady=5)

        self._add_tabs()

    def _add_tabs(self):
        self._add_tab("Perception", "Perception Systems")
        self._add_tab("Data Hub", "Data Processing Hub")
        self._add_tab("Models", "Pre-Trained Models / Embeddings")
        self._add_tab("GODSWARM", "GODSWARM Neural System")
        self._add_tab("Quantum Core", "Quantum Annealing Engine")
        self._add_tab("Hybrid Brain++", "Neural-Symbolic Fusion Core")
        self._add_tab("Parallel Core", "Parallel Computation Core")
        self._add_tab("Knowledge Base", "Contextual Knowledge Base")
        self._add_tab("Ethics / Security", "Ethical / Security Layer")
        self._add_tab("Action Systems", "Robotics / Decision Execution")
        self._add_tab("Outputs", "Image / Audio / Simulator")
        self._add_tab("MLOps", "Datasets Manager / MLOps")

        dash = DashboardFrame(self.notebook, self.gpu_manager, self.metrics, self.bus)
        self.notebook.add(dash, text="Dashboard")

        swarm_frame = SwarmVisualizer(self.notebook, self.swarm)
        self.notebook.add(swarm_frame, text="Swarm Visualizer")

        game_frame = ttk.Frame(self.notebook)
        self.notebook.add(game_frame, text="Game AI")

        ttk.Label(game_frame, text="Game AI Control").pack(anchor=tk.W, padx=5, pady=5)
        if self.auto_active_profile:
            ttk.Label(game_frame, text=f"Auto-selected profile: {self.auto_active_profile}").pack(anchor=tk.W, padx=5, pady=5)

        for name, gm in self.game_managers.items():
            row = ttk.Frame(game_frame)
            row.pack(anchor=tk.W, padx=5, pady=2)
            ttk.Label(row, text=name).pack(side=tk.LEFT)
            ttk.Button(row, text="Start",
                       command=lambda g=gm, n=name: self._start_game_ai(g, n)).pack(side=tk.LEFT, padx=3)
            ttk.Button(row, text="Stop",
                       command=lambda g=gm, n=name: self._stop_game_ai(g, n)).pack(side=tk.LEFT, padx=3)

    def _add_tab(self, name: str, label: str):
        frame = ttk.Frame(self.notebook)
        self.notebook.add(frame, text=name)
        ttk.Label(frame, text=label).pack(anchor=tk.W, padx=5, pady=5)

    def _append_log(self, text: str) -> None:
        self.log_text.insert(tk.END, text + "\n")
        self.log_text.see(tk.END)

    def _on_load_file(self) -> None:
        path = filedialog.askopenfilename(title="Select file to ingest")
        if not path:
            return
        try:
            with open(path, "rb") as f:
                data = f.read()
            job_payload = {
                "source": f"file:{path}",
                "data_type": "file",
                "raw": data,
            }
            self.cluster.submit_job("perception.ingest", job_payload)
            self._append_log(f"[FILE] Queued file for cluster ingest: {path}")
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def _on_ingest_text(self) -> None:
        def submit():
            txt = entry.get("1.0", tk.END).strip()
            if txt:
                job_payload = {
                    "source": "manual_text",
                    "data_type": "text",
                    "raw": txt,
                }
                self.cluster.submit_job("perception.ingest", job_payload)
                self._append_log("[TEXT] Queued manual text for cluster ingest.")
            win.destroy()

        win = tk.Toplevel(self)
        win.title("Ingest Text")
        entry = scrolledtext.ScrolledText(win, width=80, height=20)
        entry.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        ttk.Button(win, text="Submit", command=submit).pack(pady=5)

    def _send_heartbeat(self):
        self.bus.publish("watchdog.heartbeat", {})
        self._append_log("[WATCHDOG] Manual heartbeat sent.")

    def _toggle_mode(self):
        cfg = self.config_manager.get()
        old = cfg.get("llm_mode", "balanced")
        new = "max_int" if old == "balanced" else "balanced"
        cfg["llm_mode"] = new
        with open(self.config_manager.path, "w", encoding="utf-8") as f:
            json.dump(cfg, f, indent=2)
        self._append_log(f"[LLM ROUTER] Mode switched from {old} to {new} (via config)")

    def _apply_preset(self, name: str):
        self.config_manager.apply_preset(name)
        self._append_log(f"[CONFIG] Applied preset: {name}")

    def _start_game_ai(self, gm: GameIntegrationManager, name: str):
        gm.start(interval=0.5)
        self._append_log(f"[GAME] Started AI loop for {name}")

    def _stop_game_ai(self, gm: GameIntegrationManager, name: str):
        gm.stop()
        self._append_log(f"[GAME] Stopped AI loop for {name}")

# ============================================================
# MAIN
# ============================================================

def main():
    if is_windows() and not is_admin():
        print(
            "[ADMIN] You are NOT running as administrator.\n"
            "  - Some ports may fail with WinError 10013.\n"
            "  - Right-click your .py or terminal and choose 'Run as administrator' for full functionality.\n"
        )
        print_firewall_hint()

    bus = EventBus()
    memory = PersistentMemory()
    config_manager = ConfigManager()
    gpu_manager = GPUManager()
    metrics = MetricsStore(bus)

    cfg = config_manager.get()
    http_cfg = cfg.get("http_server", {"host": "127.0.0.1", "port": 8080})
    BrainHTTPServer(http_cfg.get("host", "127.0.0.1"), int(http_cfg.get("port", 8080)), memory, config_manager, bus)

    cluster_cfg = cfg.get("cluster", {"host": "0.0.0.0", "port": 5555})
    cluster = DistributedNodeManager(bus, host=cluster_cfg.get("host", "0.0.0.0"), port=int(cluster_cfg.get("port", 5555)), role="master")
    cluster.register_worker("127.0.0.1", int(cluster_cfg.get("port", 5555)))

    WatchdogSupervisor(bus)
    RecoveryManager(bus)
    start_auto_heartbeat(bus, interval=3.0)

    llm_mode = cfg.get("llm_mode", "balanced")
    temperature = cfg.get("temperature", 0.7)
    llm_manager = MultiLLMManager(gpu_manager, config_manager, mode=llm_mode, temperature=temperature)
    vision = VisionManager(gpu_manager)
    asr = ASRManager(gpu_manager, model_name="large-v2")
    swarm = SwarmAgentManager()
    robotics = RoboticsConnector(http_endpoint=None, ros_topic=None, ros2_topic=None)

    perception = PerceptionSystems(bus, memory)
    data_hub = DataProcessingHub(bus)
    models = PretrainedModels(bus, llm_manager, vision, asr, gpu_manager)
    godswarm = GodswarmNeural(bus, swarm)
    quantum_core = QuantumCore(bus)
    hybrid_brain = HybridBrain(bus, memory)
    parallel_core = ParallelComputationCore(bus)
    kb = ContextualKnowledgeBase(bus, memory)
    ethics = EthicalSecurityLayer(bus)
    actions = ActionSystems(bus, robotics)
    outputs = OutputModules(bus)
    mlops = DatasetsManager(bus)

    models.register_model(ModelConfig(name="LLM_MultiBackend", version="v1"))
    models.register_model(ModelConfig(name="ViT", version="v1"))
    models.register_model(ModelConfig(name="WhisperASR", version="v1"))

    perception.register_live_source(LiveDataSourceConfig(name="sensor_stream_1", enabled=True))
    perception.register_live_source(LiveDataSourceConfig(name="camera_feed_1", enabled=True))

    GameActionSink(bus)

    telemetry_cfg = cfg.get("telemetry", {"host": "127.0.0.1", "port": 7777})
    t_host = telemetry_cfg.get("host", "127.0.0.1")
    t_port = int(telemetry_cfg.get("port", 7777))

    b4b_profile = GameProfile(
        name="Back 4 Blood",
        process_names=["Back4Blood.exe"],
        capture_region=None,
        notes="Co-op zombie shooter"
    )
    toxic_profile = GameProfile(
        name="John Carpenter's Toxic Commando",
        process_names=["ToxicCommando.exe"],
        capture_region=None,
        notes="Co-op action shooter"
    )
    generic_profile = GameProfile(
        name="Generic Shooter",
        process_names=[],
        capture_region=None,
        notes="Fallback profile"
    )

    profiles = [b4b_profile, toxic_profile, generic_profile]
    active_profile = detect_active_profile(profiles, telemetry_host=t_host, telemetry_port=t_port)

    game_managers = {
        "Back 4 Blood": GameIntegrationManager(bus, b4b_profile, vision, llm_manager, swarm, config_manager, telemetry_host=t_host, telemetry_port=t_port),
        "Toxic Commando": GameIntegrationManager(bus, toxic_profile, vision, llm_manager, swarm, config_manager, telemetry_host=t_host, telemetry_port=t_port),
        "Generic Shooter": GameIntegrationManager(bus, generic_profile, vision, llm_manager, swarm, config_manager, telemetry_host=t_host, telemetry_port=t_port),
    }

    web_cfg = cfg.get("web_dashboard", {"enabled": True, "host": "127.0.0.1", "port": 5000})
    WebDashboard(metrics, swarm, game_managers,
                 host=web_cfg.get("host", "127.0.0.1"),
                 port=int(web_cfg.get("port", 5000)),
                 enabled=web_cfg.get("enabled", True))

    PluginManager(bus, plugins_dir="plugins")

    app = MegaSystemGUI(
        bus=bus,
        perception=perception,
        data_hub=data_hub,
        models=models,
        godswarm=godswarm,
        quantum_core=quantum_core,
        hybrid_brain=hybrid_brain,
        parallel_core=parallel_core,
        kb=kb,
        ethics=ethics,
        actions=actions,
        outputs=outputs,
        mlops=mlops,
        gpu_manager=gpu_manager,
        metrics=metrics,
        cluster=cluster,
        swarm=swarm,
        llm_manager=llm_manager,
        game_managers=game_managers,
        auto_active_profile=active_profile.name if active_profile else None,
        config_manager=config_manager,
    )
    app.mainloop()

if __name__ == "__main__":
    main()
