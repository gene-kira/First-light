#!/usr/bin/env python3
# ================================================================
#  PREEMPTIVE STRIKE AI — ULTRA NEXT-GEN v9 (Qt Edition)
#  Reasoning Engine: RL + Uncertainty + Planning + Self-Eval + World Model
#  Intelligent "Water" Data Physics Engine + Altered States Modes
#  GPU/VRAM Preloader + Transformer Predictor + Plugin System
#  DominionDeck Bridge + Persistent Memory + PySide6 (Qt) Frontend
#  Day-Phased Behavior: Day 1 Observe, Day 2 Predict (no act), Day 3+ Act
#  Event-Driven Observation + Color Indicators (🟢 OBS, 🟡 PRED, 🔴 ACT)
#  Telemetry logs ONLY when CPU/RAM change ≥ 5% or phase changes
#  Smart PID-based app/game/email detection
#  Memory usage observer: tracks which processes hammer RAM the most
# ================================================================

import os
import sys
import time
import json
import threading
import traceback
import platform
import subprocess
import importlib.util
import inspect

# ------------------------------------------------
# AUTOLOADER
# ------------------------------------------------

REQUIRED_LIBS = [
    "psutil",
    "pynvml",
    "torch",
    "pyautogui",
    "PySide6",
]

def autoload_libraries():
    import pkg_resources
    installed = {pkg.key for pkg in pkg_resources.working_set}
    for lib in REQUIRED_LIBS:
        if lib.lower() not in installed:
            subprocess.check_call([sys.executable, "-m", "pip", "install", lib])

autoload_libraries()

import psutil
import pynvml
import pyautogui
import torch
import torch.nn as nn

from PySide6.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QLineEdit, QPushButton, QTextEdit
)
from PySide6.QtCore import Qt, QTimer

# ================================================================
# PERSISTENT MEMORY STORE
# ================================================================

class MemoryStore:
    def __init__(self, path="preemptive_memory.json"):
        self.path = path
        self.data = {}
        self.load()
        if "start_time" not in self.data:
            self.data["start_time"] = time.time()
            self.save()

    def load(self):
        if os.path.exists(self.path):
            try:
                with open(self.path, "r") as f:
                    self.data = json.load(f)
            except:
                self.data = {}
        else:
            self.data = {}

    def save(self):
        with open(self.path, "w") as f:
            json.dump(self.data, f, indent=4)

    def append_event(self, category: str, payload: dict):
        if category not in self.data:
            self.data[category] = []
        self.data[category].append({"ts": time.time(), "payload": payload})
        self.save()

    def set_section(self, section: str, payload: dict):
        self.data[section] = payload
        self.save()

    def get_section(self, section: str, default=None):
        return self.data.get(section, default)

    def days_since_start(self) -> float:
        start = self.data.get("start_time", time.time())
        return (time.time() - start) / 86400.0

# ================================================================
# PLUGIN SYSTEM
# ================================================================

class PluginManager:
    def __init__(self, memory: MemoryStore, plugins_dir="plugins"):
        self.plugins_dir = plugins_dir
        self.memory = memory
        self.actions = {}
        self.load_plugins()

    def load_plugins(self):
        if not os.path.isdir(self.plugins_dir):
            os.makedirs(self.plugins_dir, exist_ok=True)
            return
        for fname in os.listdir(self.plugins_dir):
            if not fname.endswith(".py"):
                continue
            path = os.path.join(self.plugins_dir, fname)
            try:
                spec = importlib.util.spec_from_file_location(fname[:-3], path)
                mod = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(mod)
                for name, obj in inspect.getmembers(mod):
                    if callable(obj) and hasattr(obj, "_preemptive_action"):
                        action_name = getattr(obj, "_preemptive_action")
                        self.actions[action_name] = obj
                        print(f"[PLUGIN] Registered action: {action_name} from {fname}")
            except Exception as e:
                print(f"[PLUGIN] Failed to load {fname}: {e}")

    def execute(self, action_name: str, context: dict):
        func = self.actions.get(action_name)
        if not func:
            return False
        try:
            func(context)
            self.memory.append_event("plugin_action", {"action": action_name, "context": context})
            return True
        except Exception as e:
            print(f"[PLUGIN] Error executing {action_name}: {e}")
            return False

# ================================================================
# DOMINIONDECK BRIDGE
# ================================================================

class DominionDeckBridge:
    def __init__(self, memory: MemoryStore, config_path="dominiondeck_bridge.json"):
        self.config_path = config_path
        self.state = {}
        self.memory = memory
        self.load_state()

    def load_state(self):
        if os.path.exists(self.config_path):
            try:
                with open(self.config_path, "r") as f:
                    self.state = json.load(f)
            except:
                self.state = {}
        else:
            self.state = {}

    def save_state(self):
        with open(self.config_path, "w") as f:
            json.dump(self.state, f, indent=4)

    def push_telemetry(self, payload: dict):
        self.state["last_telemetry"] = payload
        self.save_state()
        self.memory.append_event("telemetry", payload)

    def push_event(self, event_type: str, data: dict):
        if "events" not in self.state:
            self.state["events"] = []
        evt = {"type": event_type, "data": data, "ts": time.time()}
        self.state["events"].append(evt)
        self.save_state()
        self.memory.append_event("events", evt)

# ================================================================
# GPU GOVERNOR / VRAM PRELOADER (Conceptual)
# ================================================================

class GPUPreloader:
    def __init__(self):
        self.gpu_available = False
        self.device_handles = []
        self.init_gpu()

    def init_gpu(self):
        try:
            pynvml.nvmlInit()
            count = pynvml.nvmlDeviceGetCount()
            for i in range(count):
                self.device_handles.append(pynvml.nvmlDeviceGetHandleByIndex(i))
            self.gpu_available = count > 0
        except Exception:
            self.gpu_available = False

    def get_vram_info(self):
        if not self.gpu_available:
            return []
        info = []
        for h in self.device_handles:
            mem = pynvml.nvmlDeviceGetMemoryInfo(h)
            name = pynvml.nvmlDeviceGetName(h).decode("utf-8")
            info.append({
                "name": name,
                "total": mem.total,
                "used": mem.used,
                "free": mem.free,
            })
        return info

    def can_preload_to_vram(self, size_bytes: int):
        if not self.gpu_available:
            return False
        infos = self.get_vram_info()
        for inf in infos:
            if size_bytes < inf["free"] * 0.8:
                return True
        return False

    def preload_blob_to_vram(self, blob: bytes):
        if not self.gpu_available:
            return False
        return True

# ================================================================
# GAME RAM + VRAM HYBRID PRELOADER + OPTIMIZER (optional)
# ================================================================

class GameProfile:
    def __init__(self, name, folder, priority=1, preload_mode="hybrid"):
        self.name = name
        self.folder = folder
        self.priority = priority
        self.preload_mode = preload_mode

class GameRAMPreloader:
    def __init__(self, gpu_preloader: GPUPreloader, memory: MemoryStore):
        self.max_ram = psutil.virtual_memory().total
        self.gpu = gpu_preloader
        self.profiles = {}
        self.cache = {}
        self.memory = memory
        self.load_profiles()

    def load_profiles(self):
        stored = self.memory.get_section("game_profiles", {})
        for name, payload in stored.items():
            self.profiles[name] = GameProfile(
                name=name,
                folder=payload["folder"],
                priority=payload.get("priority", 1),
                preload_mode=payload.get("preload_mode", "hybrid"),
            )

    def persist_profiles(self):
        payload = {}
        for name, p in self.profiles.items():
            payload[name] = {
                "folder": p.folder,
                "priority": p.priority,
                "preload_mode": p.preload_mode,
            }
        self.memory.set_section("game_profiles", payload)

    def add_profile(self, profile: GameProfile):
        self.profiles[profile.name] = profile
        self.persist_profiles()

    def scan_game_folder(self, game_folder):
        file_paths = []
        total_size = 0
        for root, dirs, files in os.walk(game_folder):
            for f in files:
                fp = os.path.join(root, f)
                try:
                    size = os.path.getsize(fp)
                    file_paths.append((fp, size))
                    total_size += size
                except:
                    continue
        return file_paths, total_size

    def optimize_system_for_game(self, profile_name: str):
        print(f"[OPTIMIZER] Optimizing system for game: {profile_name}")
        self.memory.append_event("game_optimize", {"profile": profile_name})

    def preload_game(self, profile_name: str):
        if profile_name not in self.profiles:
            print(f"[GAME-PRELOAD] Unknown profile: {profile_name}")
            return False

        profile = self.profiles[profile_name]
        file_paths, total_size = self.scan_game_folder(profile.folder)

        print(f"[GAME-PRELOAD] Profile: {profile.name}")
        print(f"[GAME-PRELOAD] Total size: {total_size/1024/1024:.2f} MB")
        print(f"[GAME-PRELOAD] System RAM: {self.max_ram/1024/1024:.2f} MB")

        if total_size > self.max_ram * 0.90:
            print("[GAME-PRELOAD] Too large for full RAM preload.")
            return False

        use_vram = self.gpu.can_preload_to_vram(total_size) and profile.preload_mode in ("vram", "hybrid")

        ram_cache = {}
        for fp, size in file_paths:
            try:
                with open(fp, "rb") as f:
                    blob = f.read()
                ram_cache[fp] = blob
            except Exception as e:
                print(f"[GAME-PRELOAD] Failed to load {fp}: {e}")

        self.cache[profile.name] = ram_cache
        print("[GAME-PRELOAD] Game fully loaded into RAM.")

        if use_vram:
            print("[GAME-PRELOAD] Attempting VRAM preload (hybrid)...")
            combined = b"".join(list(ram_cache.values())[:50])
            if self.gpu.preload_blob_to_vram(combined):
                print("[GAME-PRELOAD] VRAM preload simulated OK.")
            else:
                print("[GAME-PRELOAD] VRAM preload failed or not available.")

        self.optimize_system_for_game(profile_name)
        self.memory.append_event("game_preload", {"profile": profile_name, "size": total_size})
        return True

# ================================================================
# CREDENTIAL INJECTOR
# ================================================================

class CredentialInjector:
    def __init__(self, memory: MemoryStore, store_path="credentials.json"):
        self.store_path = store_path
        self.creds = {}
        self.memory = memory
        self.load()

    def load(self):
        if os.path.exists(self.store_path):
            try:
                with open(self.store_path, "r") as f:
                    self.creds = json.load(f)
            except:
                self.creds = {}
        else:
            self.creds = {}
        mem_creds = self.memory.get_section("credentials", {})
        self.creds.update(mem_creds)

    def save(self):
        with open(self.store_path, "w") as f:
            json.dump(self.creds, f, indent=4)
        self.memory.set_section("credentials", self.creds)

    def set_credentials(self, service_name: str, username: str, password: str):
        self.creds[service_name] = {"username": username, "password": password}
        self.save()

    def get_credentials(self, service_name: str):
        return self.creds.get(service_name)

    def auto_login_email(self):
        creds = self.get_credentials("email")
        if not creds:
            print("[CRED] No email credentials configured.")
            return False
        print(f"[CRED] Auto-login email as {creds['username']} (password hidden).")
        self.memory.append_event("auto_login", {"service": "email", "user": creds["username"]})
        return True

# ================================================================
# INPUT GOVERNOR (CURVES)
# ================================================================

class InputGovernor:
    def __init__(self, memory: MemoryStore):
        self.memory = memory

    def perform_preemptive_curve(self, profile_name: str):
        print(f"[INPUT] Preemptive movement curve for profile: {profile_name}")
        try:
            for dx in [10, 20, 30, 20, 10, 0, -10, -20, -30, -20, -10]:
                pyautogui.moveRel(dx, 0, duration=0.05)
        except Exception as e:
            print("[INPUT] Error performing curve:", e)
        self.memory.append_event("input_curve", {"profile": profile_name})

# ================================================================
# INTELLIGENT "WATER" DATA PHYSICS ENGINE
# ================================================================

class WaterPhysicsEngine:
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.last_flows = None

    def sample_state(self):
        vm = psutil.virtual_memory()
        cpu = psutil.cpu_percent()
        flows = {
            "ram_level": vm.used / vm.total,
            "cpu_level": cpu / 100.0,
        }
        if self.last_flows is None or self._changed(flows, self.last_flows, threshold=0.05):
            self.memory.append_event("water_state", flows)
            self.last_flows = flows
        return flows

    def _changed(self, new, old, threshold=0.05):
        return (abs(new["ram_level"] - old["ram_level"]) > threshold or
                abs(new["cpu_level"] - old["cpu_level"]) > threshold)

    def compute_pressure(self, flows):
        return (flows["ram_level"] + flows["cpu_level"]) / 2.0

    def is_stable(self, flows):
        return self.compute_pressure(flows) < 0.75

# ================================================================
# ALTERED STATES MANAGER
# ================================================================

class AlteredStatesManager:
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.state = "idle"

    def update_state(self, flows):
        if flows["cpu_level"] > 0.8 or flows["ram_level"] > 0.8:
            new_state = "high_load"
        elif flows["cpu_level"] > 0.5:
            new_state = "gaming"
        elif flows["ram_level"] < 0.3 and flows["cpu_level"] < 0.3:
            new_state = "idle"
        else:
            new_state = "focus"
        if new_state != self.state:
            self.state = new_state
            self.memory.append_event("altered_state", {"state": self.state})

    def get_aggressiveness(self):
        if self.state == "idle":
            return 0.3
        if self.state == "focus":
            return 0.5
        if self.state == "gaming":
            return 0.7
        if self.state == "high_load":
            return 0.2
        return 0.5

# ================================================================
# WORLD MODEL (TRANSITION GRAPH)
# ================================================================

class WorldModel:
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.graph = {}
        self.load()

    def load(self):
        stored = self.memory.get_section("world_model", {})
        self.graph = stored if stored else {}

    def save(self):
        self.memory.set_section("world_model", self.graph)

    def record_transition(self, prev_action: str, next_action: str):
        if prev_action not in self.graph:
            self.graph[prev_action] = {}
        if next_action not in self.graph[prev_action]:
            self.graph[prev_action][next_action] = 0
        self.graph[prev_action][next_action] += 1
        self.save()

    def get_next_actions(self, action: str):
        if action not in self.graph:
            return []
        transitions = self.graph[action]
        total = sum(transitions.values())
        if total == 0:
            return []
        return sorted(
            [(a, c / total) for a, c in transitions.items()],
            key=lambda x: x[1],
            reverse=True
        )

# ================================================================
# TRANSFORMER-BASED PREDICTOR + RL + UNCERTAINTY
# ================================================================

class SimpleTransformer(nn.Module):
    def __init__(self, num_actions: int, d_model=32, nhead=4, num_layers=2):
        super().__init__()
        self.d_model = d_model
        self.embed = nn.Linear(3, d_model)
        encoder_layer = nn.TransformerEncoderLayer(d_model=d_model, nhead=nhead)
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.fc = nn.Linear(d_model, num_actions)

    def forward(self, x):
        x = self.embed(x)
        out = self.encoder(x)
        out = out[-1]
        logits = self.fc(out)
        return logits

class TransformerPredictor:
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.actions = []
        self.history = []
        self.model = None
        self.trained = False
        self.action_values = {}
        self.load_from_memory()

    def _encode_time(self, ts: float):
        lt = time.localtime(ts)
        return [lt.tm_hour, lt.tm_min, lt.tm_wday]

    def load_from_memory(self):
        hist = self.memory.get_section("transformer_history", [])
        for item in hist:
            self.history.append((item["x"], item["y"]))
            if item["y_name"] not in self.actions:
                self.actions.append(item["y_name"])
        self.action_values = self.memory.get_section("action_values", {})
        if len(self.history) >= 10:
            self._build_model()
            self._train_model()

    def persist_history(self):
        hist = []
        for x, y_idx in self.history:
            hist.append({"x": x, "y": y_idx, "y_name": self.actions[y_idx]})
        self.memory.set_section("transformer_history", hist)
        self.memory.set_section("action_values", self.action_values)

    def record_action(self, action_name: str, ts: float = None):
        if ts is None:
            ts = time.time()
        x = self._encode_time(ts)
        if action_name not in self.actions:
            self.actions.append(action_name)
        y_idx = self.actions.index(action_name)
        self.history.append((x, y_idx))
        if action_name not in self.action_values:
            self.action_values[action_name] = 0.0
        self.persist_history()

    def _build_model(self):
        num_actions = max(1, len(self.actions))
        self.model = SimpleTransformer(num_actions=num_actions)
        self.trained = False

    def _train_model(self):
        if not self.model or len(self.history) < 10:
            return False
        xs = [torch.tensor(h[0], dtype=torch.float32) for h in self.history]
        ys = [h[1] for h in self.history]
        xs = torch.stack(xs).unsqueeze(1)
        ys = torch.tensor(ys, dtype=torch.long)
        optimizer = torch.optim.Adam(self.model.parameters(), lr=0.01)
        loss_fn = nn.CrossEntropyLoss()
        for _ in range(50):
            optimizer.zero_grad()
            logits = self.model(xs)
            loss = loss_fn(logits.unsqueeze(0), ys.unsqueeze(0))
            loss.backward()
            optimizer.step()
        self.trained = True
        self.memory.append_event("transformer_train", {"samples": len(self.history)})
        return True

    def train(self):
        if not self.model:
            self._build_model()
        return self._train_model()

    def predict_with_uncertainty(self):
        if not self.trained or not self.model or not self.actions:
            return None, 0.0
        x = self._encode_time(time.time())
        x_t = torch.tensor(x, dtype=torch.float32).unsqueeze(0).unsqueeze(1)
        logits = self.model(x_t)
        probs = torch.softmax(logits, dim=-1)
        idx = torch.argmax(probs).item()
        confidence = probs[0, idx].item()
        return self.actions[idx], confidence

    def update_reward(self, action_name: str, reward: float):
        if action_name not in self.action_values:
            self.action_values[action_name] = 0.0
        alpha = 0.1
        self.action_values[action_name] = (1 - alpha) * self.action_values[action_name] + alpha * reward
        self.persist_history()

    def best_actions(self, top_k=3):
        if not self.actions:
            return []
        scored = [(a, self.action_values.get(a, 0.0)) for a in self.actions]
        return sorted(scored, key=lambda x: x[1], reverse=True)[:top_k]

# ================================================================
# MULTI-STEP PLANNER + SELF-EVALUATION
# ================================================================

class Planner:
    def __init__(self, world_model: WorldModel, predictor: TransformerPredictor, memory: MemoryStore):
        self.world_model = world_model
        self.predictor = predictor
        self.memory = memory
        self.last_action = None

    def plan_sequence(self, start_action: str, length: int = 3):
        sequence = [start_action]
        current = start_action
        for _ in range(length - 1):
            next_actions = self.world_model.get_next_actions(current)
            if not next_actions:
                break
            current = next_actions[0][0]
            sequence.append(current)
        return sequence

    def record_execution(self, executed_action: str, user_action: str | None):
        if self.last_action:
            self.world_model.record_transition(self.last_action, executed_action)
        self.last_action = executed_action
        if user_action is None:
            reward = -0.05
        elif user_action == executed_action:
            reward = 1.0
        else:
            reward = -0.2
        self.predictor.update_reward(executed_action, reward)
        self.memory.append_event("self_eval", {
            "executed": executed_action,
            "user_action": user_action,
            "reward": reward
        })

# ================================================================
# PROCESS OBSERVER (PID-based smart app/game/email detection)
# ================================================================

class ProcessObserver:
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.last_active = None
        self.is_windows = (platform.system().lower() == "windows")
        if self.is_windows:
            import ctypes
            self.ctypes = ctypes
        else:
            self.ctypes = None

    def _get_foreground_pid_windows(self):
        user32 = self.ctypes.windll.user32
        kernel32 = self.ctypes.windll.kernel32
        hwnd = user32.GetForegroundWindow()
        if not hwnd:
            return None
        pid = self.ctypes.c_ulong()
        user32.GetWindowThreadProcessId(hwnd, self.ctypes.byref(pid))
        return pid.value or None

    def _get_active_process(self):
        if self.is_windows and self.ctypes is not None:
            pid = self._get_foreground_pid_windows()
            if pid is None:
                return None
            try:
                p = psutil.Process(pid)
                return {
                    "pid": pid,
                    "name": p.name(),
                    "exe": p.exe() if p.exe() else "",
                }
            except Exception:
                return None
        else:
            procs = list(psutil.process_iter(attrs=["pid", "name", "exe", "cpu_percent"]))
            if not procs:
                return None
            procs.sort(key=lambda x: x.info.get("cpu_percent", 0.0), reverse=True)
            p = procs[0]
            return {
                "pid": p.info["pid"],
                "name": p.info.get("name", ""),
                "exe": p.info.get("exe", ""),
            }

    def _classify_app(self, proc_info: dict):
        name = (proc_info.get("name") or "").lower()
        exe = (proc_info.get("exe") or "").lower()

        if any(x in name for x in ["outlook", "thunderbird", "mail"]):
            return "email"
        if any(x in name for x in ["chrome", "edge", "firefox", "brave", "opera"]):
            return "browser"
        if any(x in name for x in ["steam", "epic", "battle.net", "origin"]):
            return "launcher"
        if any(x in exe for x in ["\\steamapps\\", "\\epic games\\", "\\origin games\\", "\\gog games\\"]):
            return "game"
        try:
            p = psutil.Process(proc_info["pid"])
            cpu = p.cpu_percent(interval=0.05)
            if cpu > 30.0:
                return "game_or_heavy"
        except Exception:
            pass
        return "app"

    def sample_active_app(self):
        proc = self._get_active_process()
        if not proc:
            return None

        app_type = self._classify_app(proc)
        active = {
            "pid": proc["pid"],
            "name": proc["name"],
            "exe": proc["exe"],
            "type": app_type,
        }

        if self.last_active is None or self._changed(active, self.last_active):
            self.last_active = active
            self.memory.append_event("active_app", active)
            return active
        return None

    def _changed(self, new, old):
        return new["pid"] != old["pid"] or new["type"] != old["type"]

# ================================================================
# MEMORY USAGE OBSERVER (who is hammering RAM, over time)
# ================================================================

class MemoryUsageObserver:
    def __init__(self, memory: MemoryStore):
        self.memory = memory
        self.last_snapshot = None
        self.top_history = []  # rolling history of top RAM users

    def sample_memory_usage(self):
        vm = psutil.virtual_memory()
        total = vm.total
        procs_info = []
        for p in psutil.process_iter(attrs=["pid", "name", "memory_info"]):
            try:
                mi = p.info.get("memory_info")
                if not mi:
                    continue
                rss = mi.rss
                if rss < 10 * 1024 * 1024:
                    continue
                procs_info.append({
                    "pid": p.info["pid"],
                    "name": p.info.get("name", ""),
                    "rss": rss,
                    "ratio": rss / total,
                })
            except Exception:
                continue

        procs_info.sort(key=lambda x: x["rss"], reverse=True)
        top = procs_info[:10]

        if self._changed(top):
            snapshot = {
                "ts": time.time(),
                "total": total,
                "top": top,
            }
            self.last_snapshot = snapshot
            self.top_history.append(snapshot)
            if len(self.top_history) > 50:
                self.top_history.pop(0)
            self.memory.append_event("memory_usage", snapshot)

    def _changed(self, new_top):
        if self.last_snapshot is None:
            return True
        old_top = self.last_snapshot["top"]
        if not old_top and new_top:
            return True
        old_names = {(p["pid"], p["name"]) for p in old_top}
        new_names = {(p["pid"], p["name"]) for p in new_top}
        if old_names != new_names:
            return True
        def total_ratio(lst):
            return sum(p["ratio"] for p in lst)
        return abs(total_ratio(new_top) - total_ratio(old_top)) > 0.05

    def summarize_hotspots(self):
        agg = {}
        for snap in self.top_history:
            for p in snap["top"]:
                key = (p["pid"], p["name"])
                agg.setdefault(key, 0.0)
                agg[key] += p["ratio"]
        ranked = sorted(agg.items(), key=lambda x: x[1], reverse=True)
        summary = [{"pid": pid, "name": name, "score": score} for (pid, name), score in ranked[:10]]
        self.memory.set_section("memory_hotspots", summary)
        return summary

# ================================================================
# PREEMPTIVE STRIKE AI CORE
# ================================================================

class PreemptiveStrikeAI:
    def __init__(self, injector: CredentialInjector, preloader: GameRAMPreloader,
                 predictor: TransformerPredictor, deck: DominionDeckBridge,
                 input_gov: InputGovernor, memory: MemoryStore,
                 plugins: PluginManager, water: WaterPhysicsEngine,
                 states: AlteredStatesManager, world: WorldModel,
                 planner: Planner, proc_observer: ProcessObserver,
                 mem_observer: MemoryUsageObserver):
        self.injector = injector
        self.preloader = preloader
        self.predictor = predictor
        self.deck = deck
        self.input_gov = input_gov
        self.memory = memory
        self.plugins = plugins
        self.water = water
        self.states = states
        self.world = world
        self.planner = planner
        self.proc_observer = proc_observer
        self.mem_observer = mem_observer
        self.lock = threading.Lock()
        self.running = True
        self.last_phase = None
        self.last_telemetry = None

    def track_action(self, action_name: str):
        with self.lock:
            self.predictor.record_action(action_name)
            trained = self.predictor.train()
            if trained:
                print("[TRANSFORMER] Model trained/updated.")
            self.deck.push_event("action_recorded", {"action": action_name})
            self.memory.append_event("actions", {"action": action_name})

    def execute_preemptive(self, action: str):
        print(f"[PREEMPTIVE] Executing predicted action: {action}")
        self.deck.push_event("preemptive_execute", {"action": action})

        if self.plugins.execute(action, {"memory": self.memory}):
            self.planner.record_execution(action, None)
            return

        if action == "open_email":
            self.injector.auto_login_email()

        elif action.startswith("launch_game:"):
            profile_name = action.split(":", 1)[1]
            self.preloader.preload_game(profile_name)
            self.input_gov.perform_preemptive_curve(profile_name)

        self.planner.record_execution(action, None)

    def _should_push_telemetry(self, phase: str, cpu: float, ram_used: float) -> bool:
        vm = psutil.virtual_memory()
        total_ram = vm.total
        if self.last_telemetry is None:
            return True
        last_phase = self.last_telemetry.get("phase")
        last_cpu = self.last_telemetry.get("cpu", 0.0)
        last_ram = self.last_telemetry.get("ram_used", 0.0)

        phase_changed = (phase != last_phase)
        cpu_changed = abs(cpu - last_cpu) >= 5.0
        ram_changed = abs(ram_used - last_ram) / total_ram >= 0.05

        return phase_changed or cpu_changed or ram_changed

    def _push_phase_telemetry(self, phase: str):
        vm = psutil.virtual_memory()
        cpu = psutil.cpu_percent()
        ram_used = vm.used

        if not self._should_push_telemetry(phase, cpu, ram_used):
            return

        payload = {
            "ts": time.time(),
            "ram_used": ram_used,
            "cpu": cpu,
            "state": self.states.state,
            "phase": phase,
        }
        self.last_phase = phase
        self.last_telemetry = payload
        self.deck.push_telemetry(payload)

    def _observe_active_app(self):
        active = self.proc_observer.sample_active_app()
        if not active:
            return

        self.deck.push_event("active_app_detected", active)

        app_type = active["type"]
        name = active["name"].lower()

        if app_type == "email":
            self.track_action("open_email")
        elif app_type in ("game", "game_or_heavy"):
            game_id = name or f"pid_{active['pid']}"
            self.track_action(f"launch_game:{game_id}")
        elif app_type == "browser":
            self.track_action("browse_web")
        else:
            self.track_action(f"use_app:{name or 'unknown'}")

    def loop(self):
        while self.running:
            try:
                flows = self.water.sample_state()
                self.states.update_state(flows)
                aggressiveness = self.states.get_aggressiveness()
                days = self.memory.days_since_start()

                self._observe_active_app()
                self.mem_observer.sample_memory_usage()
                self.mem_observer.summarize_hotspots()

                if days < 1.0:
                    self._push_phase_telemetry("observe")

                elif days < 2.0:
                    prediction, confidence = self.predictor.predict_with_uncertainty()
                    if prediction is not None:
                        self.deck.push_event("prediction", {
                            "prediction": prediction,
                            "confidence": confidence
                        })
                    self._push_phase_telemetry("predict")

                else:
                    prediction, confidence = self.predictor.predict_with_uncertainty()
                    self._push_phase_telemetry("act")
                    if prediction and confidence > (0.5 * aggressiveness):
                        sequence = self.planner.plan_sequence(prediction, length=3)
                        for act in sequence:
                            self.execute_preemptive(act)

                time.sleep(5)
            except Exception as e:
                print("[CORE] Loop error:", e)
                traceback.print_exc()
                time.sleep(5)

    def stop(self):
        self.running = False

# ================================================================
# BACKEND SERVICE
# ================================================================

class BackendService:
    def __init__(self):
        self.memory = MemoryStore()
        self.gpu = GPUPreloader()
        self.preloader = GameRAMPreloader(self.gpu, self.memory)
        self.injector = CredentialInjector(self.memory)
        self.predictor = TransformerPredictor(self.memory)
        self.deck = DominionDeckBridge(self.memory)
        self.input_gov = InputGovernor(self.memory)
        self.plugins = PluginManager(self.memory)
        self.water = WaterPhysicsEngine(self.memory)
        self.states = AlteredStatesManager(self.memory)
        self.world = WorldModel(self.memory)
        self.planner = Planner(self.world, self.predictor, self.memory)
        self.proc_observer = ProcessObserver(self.memory)
        self.mem_observer = MemoryUsageObserver(self.memory)
        self.core = PreemptiveStrikeAI(
            self.injector, self.preloader, self.predictor,
            self.deck, self.input_gov, self.memory,
            self.plugins, self.water, self.states,
            self.world, self.planner, self.proc_observer,
            self.mem_observer
        )
        self.thread = threading.Thread(target=self.core.loop, daemon=True)

    def start(self):
        print("[SERVICE] Starting backend loop...")
        self.thread.start()

    def stop(self):
        print("[SERVICE] Stopping backend loop...")
        self.core.stop()
        self.thread.join(timeout=5)

# ================================================================
# PYSIDE6 (QT) FRONTEND
# ================================================================

class PreemptiveMainWindow(QMainWindow):
    def __init__(self, service: BackendService):
        super().__init__()
        self.service = service
        self.setWindowTitle("Preemptive Strike AI Command Center (Qt)")
        self.resize(900, 600)
        self.last_telemetry_ts = None
        self._build_ui()
        self._setup_timer()

    def _build_ui(self):
        central = QWidget()
        layout = QVBoxLayout()

        status_row = QHBoxLayout()
        self.phase_label = QLabel("🟢 Observing")
        self.phase_label.setStyleSheet("color: green; font-weight: bold;")
        status_row.addWidget(QLabel("Phase:"))
        status_row.addWidget(self.phase_label)
        layout.addLayout(status_row)

        email_label = QLabel("Email Credentials")
        layout.addWidget(email_label)

        email_row = QHBoxLayout()
        self.email_user = QLineEdit()
        self.email_user.setPlaceholderText("Username")
        self.email_pass = QLineEdit()
        self.email_pass.setPlaceholderText("Password")
        self.email_pass.setEchoMode(QLineEdit.Password)
        save_email_btn = QPushButton("Save Email Credentials")
        save_email_btn.clicked.connect(self.save_email_creds)
        email_row.addWidget(self.email_user)
        email_row.addWidget(self.email_pass)
        email_row.addWidget(save_email_btn)
        layout.addLayout(email_row)

        actions_label = QLabel("Manual Actions / Training")
        layout.addWidget(actions_label)

        actions_row = QHBoxLayout()
        record_email_btn = QPushButton("Record: Open Email")
        record_email_btn.clicked.connect(lambda: self.record_action("open_email"))
        record_game_btn = QPushButton("Record: Launch Game (generic)")
        record_game_btn.clicked.connect(lambda: self.record_action("launch_game:generic"))
        actions_row.addWidget(record_email_btn)
        actions_row.addWidget(record_game_btn)
        layout.addLayout(actions_row)

        gpu_label = QLabel("GPU Info")
        layout.addWidget(gpu_label)
        gpu_btn = QPushButton("Show GPU Info")
        gpu_btn.clicked.connect(self.show_gpu_info)
        layout.addWidget(gpu_btn)

        mem_label = QLabel("Memory Hotspots (who hits RAM the most)")
        layout.addWidget(mem_label)
        self.mem_hotspots_box = QTextEdit()
        self.mem_hotspots_box.setReadOnly(True)
        layout.addWidget(self.mem_hotspots_box)

        tele_label = QLabel("Telemetry / Reasoning (Event-driven, ≥5% change)")
        layout.addWidget(tele_label)
        self.telemetry_box = QTextEdit()
        self.telemetry_box.setReadOnly(True)
        layout.addWidget(self.telemetry_box)

        exit_btn = QPushButton("Exit")
        exit_btn.clicked.connect(self.on_exit)
        layout.addWidget(exit_btn)

        central.setLayout(layout)
        self.setCentralWidget(central)

    def _setup_timer(self):
        self.timer = QTimer(self)
        self.timer.timeout.connect(self.poll_telemetry)
        self.timer.start(3000)

    def log(self, msg: str):
        self.telemetry_box.append(msg)

    def log_mem(self, msg: str):
        self.mem_hotspots_box.append(msg)

    def save_email_creds(self):
        user = self.email_user.text().strip()
        pwd = self.email_pass.text().strip()
        if not user or not pwd:
            self.log("[GUI] Error: Username and password required.")
            return
        self.service.injector.set_credentials("email", user, pwd)
        self.log("[GUI] Email credentials saved.")

    def record_action(self, action_name: str):
        self.service.core.track_action(action_name)
        self.log(f"[GUI] Recorded action: {action_name}")

    def show_gpu_info(self):
        infos = self.service.gpu.get_vram_info()
        if not infos:
            self.log("[GUI] No GPU / VRAM info available.")
            return
        for inf in infos:
            self.log(f"[GPU] {inf['name']} — total {inf['total']/1024/1024:.1f} MB, free {inf['free']/1024/1024:.1f} MB")

    def _update_phase_indicator(self, phase: str):
        if phase == "observe":
            self.phase_label.setText("🟢 Observing")
            self.phase_label.setStyleSheet("color: green; font-weight: bold;")
        elif phase == "predict":
            self.phase_label.setText("🟡 Predicting")
            self.phase_label.setStyleSheet("color: orange; font-weight: bold;")
        elif phase == "act":
            self.phase_label.setText("🔴 Acting")
            self.phase_label.setStyleSheet("color: red; font-weight: bold;")
        else:
            self.phase_label.setText("⚪ Unknown")
            self.phase_label.setStyleSheet("color: gray; font-weight: bold;")

    def poll_telemetry(self):
        state = self.service.deck.state
        tele = state.get("last_telemetry")
        if tele:
            ts = tele.get("ts")
            if self.last_telemetry_ts is not None and ts == self.last_telemetry_ts:
                return
            self.last_telemetry_ts = ts

            phase = tele.get("phase", "?")
            self._update_phase_indicator(phase)
            self.log(
                f"[Telemetry] Phase {phase} | CPU {tele['cpu']:.1f}% | "
                f"RAM used {tele['ram_used']/1024/1024:.1f} MB | State {tele.get('state','?')}"
            )

        hotspots = self.service.memory.get_section("memory_hotspots", [])
        self.mem_hotspots_box.clear()
        for h in hotspots:
            self.log_mem(f"[Hot RAM] PID {h['pid']} | {h['name']} | score {h['score']:.3f}")

    def on_exit(self):
        self.service.stop()
        QApplication.instance().quit()

# ================================================================
# ENTRY POINT
# ================================================================

def main():
    print("[SYSTEM] OS:", platform.system(), platform.release())
    service = BackendService()
    service.start()

    app = QApplication(sys.argv)
    window = PreemptiveMainWindow(service)
    window.show()
    try:
        app.exec()
    finally:
        service.stop()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[SYSTEM] Shutdown requested.")
    except Exception:
        traceback.print_exc()
